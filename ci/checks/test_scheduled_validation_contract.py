#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Executable contract for the scheduled validation source of the heavy workflows.

The nightly CI, IBD perf and RPC perf workflows resolve their validation source
once per run (job ``resolve-source``) and every source job checks out, verifies
and reports that resolved commit. These tests read the real workflow files,
evaluate the expressions that wire the jobs together, and execute the actual
inline step scripts against temporary Git fixtures:

* a scheduled run resolves the maintained branch to its tip commit and every
  checkout uses that commit rather than the workflow's default-branch commit;
* metadata and verification report the commit that is actually checked out, so
  the triggering commit cannot masquerade as the validated source;
* a manual run keeps the selected ref and its event commit;
* resolver and post-checkout mismatches fail instead of continuing.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOWS = {
    "nightly": WORKFLOW_DIR / "ci-nightly-heavy.yml",
    "ibd": WORKFLOW_DIR / "ibd-perf-manual.yml",
    "rpc": WORKFLOW_DIR / "rpc-perf-manual.yml",
}
SOURCE_JOBS = {
    "nightly": {"nightly-matrix", "scanner-readiness"},
    "ibd": {"ibd-perf"},
    "rpc": {"rpc-perf"},
}
METADATA_WORKFLOWS = ("ibd", "rpc")
RESOLVER_JOB = "resolve-source"
RESOLVER_STEP = "Resolve source"
GUARD_STEP = "Require resolved source"
CHECKOUT_STEP = "Checkout"
VERIFY_STEP = "Verify checked-out source"
METADATA_STEP = "Capture host metadata"
MAINTAINED_BRANCH = "1.x.x"
MAINTAINED_REF = f"refs/heads/{MAINTAINED_BRANCH}"
RETIRED_BRANCH = "0.1.x"
MANIFEST_PATH = Path("test/functional/data/rpc_perf_manifest.json")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


class WorkflowLoader(yaml.SafeLoader):
    """SafeLoader with GitHub's YAML 1.2 booleans: ``on`` stays a string key."""


WorkflowLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def load_workflow(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf8") as handle:
        return yaml.load(handle, Loader=WorkflowLoader)


# ---------------------------------------------------------------------------
# Expression evaluation for the subset of ``${{ }}`` syntax the workflows use
# ---------------------------------------------------------------------------


_TOKEN = re.compile(
    r"\s*(?:"
    r"(?P<string>'(?:[^']|'')*')"
    r"|(?P<number>-?\d+(?:\.\d+)?)"
    r"|(?P<op>==|!=|&&|\|\||!|\(|\)|,)"
    r"|(?P<path>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*)"
    r")"
)


class ExpressionError(ValueError):
    pass


def _tokenize(expression: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(expression):
        if expression[position].isspace():
            position += 1
            continue
        match = _TOKEN.match(expression, position)
        if match is None:
            raise ExpressionError(f"unsupported syntax near {expression[position:]!r}")
        kind = match.lastgroup
        assert kind is not None
        tokens.append((kind, match.group(kind)))
        position = match.end()
    return tokens


def _truthy(value: Any) -> bool:
    return value not in (None, "", False, 0)


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, str) or isinstance(right, str) or left is None or right is None:
        return _to_text(left).casefold() == _to_text(right).casefold()
    return left == right


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]], context: dict[str, Any]) -> None:
        self.tokens = tokens
        self.position = 0
        self.context = context

    def _peek(self) -> tuple[str, str] | None:
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return None

    def _take(self, expected: str | None = None) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise ExpressionError("unexpected end of expression")
        if expected is not None and token[1] != expected:
            raise ExpressionError(f"expected {expected!r}, found {token[1]!r}")
        self.position += 1
        return token

    def parse(self) -> Any:
        value = self._parse_or()
        if self._peek() is not None:
            raise ExpressionError(f"trailing tokens {self.tokens[self.position:]!r}")
        return value

    def _parse_or(self) -> Any:
        value = self._parse_and()
        while self._peek() == ("op", "||"):
            self._take()
            right = self._parse_and()
            value = value if _truthy(value) else right
        return value

    def _parse_and(self) -> Any:
        value = self._parse_equality()
        while self._peek() == ("op", "&&"):
            self._take()
            right = self._parse_equality()
            value = right if _truthy(value) else value
        return value

    def _parse_equality(self) -> Any:
        value = self._parse_unary()
        while self._peek() in (("op", "=="), ("op", "!=")):
            operator = self._take()[1]
            right = self._parse_unary()
            equal = _equal(value, right)
            value = equal if operator == "==" else not equal
        return value

    def _parse_unary(self) -> Any:
        if self._peek() == ("op", "!"):
            self._take()
            return not _truthy(self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        kind, text = self._take()
        if kind == "op" and text == "(":
            value = self._parse_or()
            self._take(")")
            return value
        if kind == "string":
            return text[1:-1].replace("''", "'")
        if kind == "number":
            return float(text) if "." in text else int(text)
        if kind == "path":
            if self._peek() == ("op", "("):
                raise ExpressionError(f"function calls are not supported: {text}")
            if text == "true":
                return True
            if text == "false":
                return False
            if text == "null":
                return None
            return self._lookup(text)
        raise ExpressionError(f"unexpected token {text!r}")

    def _lookup(self, path: str) -> Any:
        value: Any = self.context
        for part in path.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value


_EXPRESSION = re.compile(r"\$\{\{((?:(?!\}\}).)*)\}\}", re.DOTALL)


def evaluate(expression: str, context: dict[str, Any]) -> Any:
    return _Parser(_tokenize(expression), context).parse()


def render(template: Any, context: dict[str, Any]) -> Any:
    """Evaluate a workflow value; a lone expression keeps its native type."""
    if not isinstance(template, str):
        return template
    whole = _EXPRESSION.fullmatch(template.strip())
    if whole is not None:
        return evaluate(whole.group(1), context)
    return _EXPRESSION.sub(lambda match: _to_text(evaluate(match.group(1), context)), template)


def render_env(mapping: dict[str, Any] | None, context: dict[str, Any]) -> dict[str, str]:
    rendered: dict[str, str] = {}
    for name, value in (mapping or {}).items():
        rendered[name] = _to_text(render(value, context))
    return rendered


def job_env(workflow: dict[str, Any], job: dict[str, Any], context: dict[str, Any]) -> dict[str, str]:
    env = render_env(workflow.get("env"), context)
    context = dict(context, env=env)
    env.update(render_env(job.get("env"), context))
    return env


def step_env(
    workflow: dict[str, Any], job: dict[str, Any], step: dict[str, Any], context: dict[str, Any]
) -> dict[str, str]:
    env = job_env(workflow, job, context)
    context = dict(context, env=env)
    env.update(render_env(step.get("env"), context))
    return env


def find_step(job: dict[str, Any], name: str) -> dict[str, Any]:
    for step in job["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"job has no step named {name!r}")


def step_index(job: dict[str, Any], name: str) -> int:
    for index, step in enumerate(job["steps"]):
        if step.get("name") == name:
            return index
    raise AssertionError(f"job has no step named {name!r}")


# ---------------------------------------------------------------------------
# Git fixtures and real step execution
# ---------------------------------------------------------------------------


class Fixture:
    """Temporary repositories: a remote with several refs and a working clone."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="scheduled-validation-")
        self.root = Path(self._tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.remotes = self.root / "remotes"
        self.remotes.mkdir()
        seed = self.root / "seed"
        seed.mkdir()
        self.git("init", "-q", "-b", "main", cwd=seed)
        (seed / "README.md").write_text("seed\n", encoding="utf8")
        manifest = seed / MANIFEST_PATH
        manifest.parent.mkdir(parents=True)
        shutil.copyfile(REPO_ROOT / MANIFEST_PATH, manifest)
        self.git("add", ".", cwd=seed)
        self.git("commit", "-q", "-m", "default branch commit", cwd=seed)
        self.default_sha = self.rev_parse("HEAD", cwd=seed)

        self.git("checkout", "-q", "-b", MAINTAINED_BRANCH, cwd=seed)
        (seed / "README.md").write_text("maintained\n", encoding="utf8")
        self.git("commit", "-q", "-am", "maintained branch commit", cwd=seed)
        self.maintained_sha = self.rev_parse("HEAD", cwd=seed)

        self.manual_branch = "feature/perf-experiment"
        self.manual_tag = "v0.2.0-rc1"
        self.git("checkout", "-q", "-b", self.manual_branch, "main", cwd=seed)
        (seed / "README.md").write_text("manual\n", encoding="utf8")
        self.git("commit", "-q", "-am", "manual selection commit", cwd=seed)
        self.manual_sha = self.rev_parse("HEAD", cwd=seed)
        self.git("tag", self.manual_tag, cwd=seed)
        self.git("checkout", "-q", "main", cwd=seed)

        self.remote = self.remotes / "source.git"
        self.git("clone", "-q", "--bare", str(seed), str(self.remote), cwd=self.root)
        self.remote_without_maintained = self.remotes / "unmaintained.git"
        self.git("clone", "-q", "--bare", str(seed), str(self.remote_without_maintained), cwd=self.root)
        self.git("branch", "-D", MAINTAINED_BRANCH, cwd=self.remote_without_maintained)
        self.work = self.root / "work"
        self.git("clone", "-q", str(self.remote), str(self.work), cwd=self.root)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

        assert len({self.default_sha, self.maintained_sha, self.manual_sha}) == 3

    def close(self) -> None:
        self._tmp.cleanup()

    def base_env(self) -> dict[str, str]:
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "LC_ALL": "C",
            "RUNNER_NAME": "local-fixture",
            "RUNNER_ARCH": "X64",
        }
        for passthrough in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "TMPDIR"):
            if passthrough in os.environ:
                env[passthrough] = os.environ[passthrough]
        return env

    def git(self, *args: str, cwd: Path) -> str:
        result = subprocess.run(
            [
                "git",
                "-c", "user.name=fixture",
                "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false",
                "-c", "tag.gpgsign=false",
                *args,
            ],
            cwd=cwd,
            env=self.base_env(),
            check=True,
            text=True,
            capture_output=True,
        )
        return result.stdout

    def rev_parse(self, rev: str, cwd: Path) -> str:
        return self.git("rev-parse", "--verify", f"{rev}^{{commit}}", cwd=cwd).strip()

    def checkout_work(self, sha: str) -> None:
        self.git("checkout", "-q", "--detach", sha, cwd=self.work)
        assert self.rev_parse("HEAD", cwd=self.work) == sha

    def remote_url(self, remote: Path) -> str:
        return remote.as_uri()

    def github_context(self, event_name: str, ref: str, sha: str, remote: Path | None = None) -> dict[str, Any]:
        remote = self.remote if remote is None else remote
        server_url = self.remotes.as_uri()
        repository = remote.name[: -len(".git")]
        assert self.remote_url(remote) == f"{server_url}/{repository}.git"
        ref_name = ref.removeprefix("refs/heads/").removeprefix("refs/tags/")
        return {
            "event_name": event_name,
            "ref": ref,
            "ref_name": ref_name,
            "sha": sha,
            "workflow_sha": sha,
            "repository": repository,
            "server_url": server_url,
            "workspace": str(self.workspace),
            "run_id": "424242",
            "token": "fixture-token",
            "job": "",
        }


def schedule_context(fixture: Fixture, remote: Path | None = None) -> dict[str, Any]:
    """A scheduled run: the workflow revision and event commit are the default branch tip."""
    return {
        "github": fixture.github_context("schedule", "refs/heads/main", fixture.default_sha, remote),
        "inputs": {},
        "needs": {},
        "matrix": {},
        "vars": {},
        "steps": {},
    }


def dispatch_context(fixture: Fixture, ref: str, sha: str, inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "github": fixture.github_context("workflow_dispatch", ref, sha),
        "inputs": inputs,
        "needs": {},
        "matrix": {},
        "vars": {},
        "steps": {},
    }


def dispatch_inputs(workflow: dict[str, Any]) -> dict[str, Any]:
    declared = workflow["on"]["workflow_dispatch"].get("inputs") or {}
    return {name: spec.get("default") for name, spec in declared.items()}


class StepResult:
    def __init__(self, completed: subprocess.CompletedProcess[str], outputs: dict[str, str], summary: str) -> None:
        self.completed = completed
        self.outputs = outputs
        self.summary = summary

    @property
    def returncode(self) -> int:
        return self.completed.returncode

    @property
    def stderr(self) -> str:
        return self.completed.stderr


def run_step(
    fixture: Fixture,
    step: dict[str, Any],
    env: dict[str, str],
    cwd: Path,
    github_env: dict[str, str],
) -> StepResult:
    """Execute a step's ``run`` script the way the runner does for its shell."""
    script = step["run"]
    assert isinstance(script, str) and script.strip(), "step has no run script"
    with tempfile.TemporaryDirectory(prefix="step-", dir=fixture.root) as tmp:
        script_path = Path(tmp) / "step.sh"
        script_path.write_text(script, encoding="utf8")
        output_path = Path(tmp) / "github-output"
        summary_path = Path(tmp) / "step-summary"
        output_path.touch()
        summary_path.touch()
        full_env = fixture.base_env()
        full_env.update(github_env)
        full_env.update(env)
        full_env["GITHUB_OUTPUT"] = str(output_path)
        full_env["GITHUB_STEP_SUMMARY"] = str(summary_path)
        if step.get("shell") == "bash":
            command = ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script_path)]
        else:
            assert "shell" not in step, f"unsupported shell {step.get('shell')!r}"
            command = ["bash", "-e", str(script_path)]
        completed = subprocess.run(command, cwd=cwd, env=full_env, text=True, capture_output=True)
        outputs = parse_key_values(output_path.read_text(encoding="utf8"))
        summary = summary_path.read_text(encoding="utf8")
    return StepResult(completed, outputs, summary)


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    return values


def github_env_for(context: dict[str, Any], job_id: str, workflow_name: str) -> dict[str, str]:
    github = context["github"]
    return {
        "GITHUB_EVENT_NAME": github["event_name"],
        "GITHUB_REF": github["ref"],
        "GITHUB_REF_NAME": github["ref_name"],
        "GITHUB_SHA": github["sha"],
        "GITHUB_WORKFLOW_SHA": github["workflow_sha"],
        "GITHUB_REPOSITORY": github["repository"],
        "GITHUB_SERVER_URL": github["server_url"],
        "GITHUB_WORKSPACE": github["workspace"],
        "GITHUB_RUN_ID": github["run_id"],
        "GITHUB_RUN_NUMBER": "7",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": job_id,
        "GITHUB_WORKFLOW": workflow_name,
    }


# ---------------------------------------------------------------------------
# Contract helpers shared by the tests
# ---------------------------------------------------------------------------


def run_resolver(
    fixture: Fixture,
    workflow: dict[str, Any],
    context: dict[str, Any],
    env_override: dict[str, str] | None = None,
) -> StepResult:
    job = workflow["jobs"][RESOLVER_JOB]
    step = find_step(job, RESOLVER_STEP)
    assert step.get("id") == "resolve"
    env = step_env(workflow, job, step, context)
    env.update(env_override or {})
    return run_step(fixture, step, env, fixture.root, github_env_for(context, RESOLVER_JOB, workflow["name"]))


def resolver_job_outputs(workflow: dict[str, Any], step_outputs: dict[str, str]) -> dict[str, str]:
    """Evaluate the resolver job's ``outputs`` mapping from its step outputs."""
    job = workflow["jobs"][RESOLVER_JOB]
    context = {"steps": {"resolve": {"outputs": step_outputs}}}
    return {name: _to_text(render(value, context)) for name, value in job["outputs"].items()}


def with_needs(context: dict[str, Any], outputs: dict[str, str]) -> dict[str, Any]:
    return dict(context, needs={RESOLVER_JOB: {"outputs": outputs, "result": "success"}})


def source_job_ids(workflow: dict[str, Any]) -> set[str]:
    ids = set()
    for job_id, job in workflow["jobs"].items():
        if job_id == RESOLVER_JOB:
            continue
        if any("actions/checkout@" in str(step.get("uses", "")) for step in job.get("steps", [])):
            ids.add(job_id)
    return ids


def check_source_wiring(workflow: dict[str, Any], context: dict[str, Any]) -> dict[str, str]:
    """Assert every source job checks out the resolved commit; return job -> ref."""
    resolved_sha = context["needs"][RESOLVER_JOB]["outputs"]["resolved_sha"]
    assert FULL_SHA.match(resolved_sha), resolved_sha
    refs: dict[str, str] = {}
    for job_id in sorted(source_job_ids(workflow)):
        job = workflow["jobs"][job_id]
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else list(needs or [])
        assert RESOLVER_JOB in needs, f"{job_id} must depend on {RESOLVER_JOB}"
        checkout_steps = [step for step in job["steps"] if "actions/checkout@" in str(step.get("uses", ""))]
        assert len(checkout_steps) == 1, f"{job_id} must check out exactly once"
        checkout = checkout_steps[0]
        assert checkout.get("name") == CHECKOUT_STEP, job_id
        checkout_context = dict(context, env=job_env(workflow, job, context))
        ref = _to_text(render(checkout["with"].get("ref"), checkout_context))
        assert ref == resolved_sha, f"{job_id} checks out {ref!r}, expected resolved {resolved_sha}"
        guard = step_index(job, GUARD_STEP)
        verify = step_index(job, VERIFY_STEP)
        checkout_position = step_index(job, CHECKOUT_STEP)
        assert guard < checkout_position < verify, f"{job_id} guard/checkout/verify order"
        assert all(job["steps"][index].get("uses") is None for index in range(0, checkout_position)), (
            f"{job_id} runs an action before the checkout guard"
        )
        refs[job_id] = ref
    return refs


def run_job_step(
    fixture: Fixture,
    workflow: dict[str, Any],
    job_id: str,
    step_name: str,
    context: dict[str, Any],
    cwd: Path,
) -> StepResult:
    job = workflow["jobs"][job_id]
    step = find_step(job, step_name)
    env = step_env(workflow, job, step, context)
    return run_step(fixture, step, env, cwd, github_env_for(context, job_id, workflow["name"]))


def matrix_context(workflow: dict[str, Any], job_id: str, context: dict[str, Any]) -> dict[str, Any]:
    strategy = workflow["jobs"][job_id].get("strategy") or {}
    include = (strategy.get("matrix") or {}).get("include") or []
    if not include:
        return context
    return dict(context, matrix=include[-1])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class ScheduledValidationContractTest(unittest.TestCase):
    fixture: Fixture
    workflows: dict[str, dict[str, Any]]
    workflow_text: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = Fixture()
        cls.workflows = {key: load_workflow(path) for key, path in WORKFLOWS.items()}
        cls.workflow_text = {key: path.read_text(encoding="utf8") for key, path in WORKFLOWS.items()}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def tearDown(self) -> None:
        for key, path in WORKFLOWS.items():
            self.assertEqual(path.read_text(encoding="utf8"), self.workflow_text[key], f"{path} was modified")

    def resolve_schedule(self, key: str, remote: Path | None = None) -> tuple[dict[str, Any], dict[str, str]]:
        workflow = self.workflows[key]
        context = schedule_context(self.fixture, remote)
        result = run_resolver(self.fixture, workflow, context)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = resolver_job_outputs(workflow, result.outputs)
        return with_needs(context, outputs), outputs

    def test_workflow_triggers_are_preserved(self) -> None:
        for key, workflow in self.workflows.items():
            with self.subTest(workflow=key):
                self.assertIn("on", workflow, "YAML loader must keep the 'on' trigger key")
                self.assertNotIn(True, workflow)
                self.assertIn("schedule", workflow["on"])
                self.assertIn("workflow_dispatch", workflow["on"])
                self.assertNotIn(RETIRED_BRANCH, self.workflow_text[key])
                self.assertEqual(
                    workflow["jobs"][RESOLVER_JOB]["steps"][0]["env"]["MAINTAINED_BRANCH"], MAINTAINED_BRANCH
                )

    def test_scheduled_jobs_use_approved_source(self) -> None:
        fixture = self.fixture
        for key, workflow in self.workflows.items():
            with self.subTest(workflow=key):
                context = schedule_context(fixture)
                resolver_job = workflow["jobs"][RESOLVER_JOB]
                self.assertNotIn("needs", resolver_job)
                self.assertFalse(
                    any("uses" in step for step in resolver_job["steps"]),
                    "resolution must run inline before any checkout or local action",
                )
                resolver_step = find_step(resolver_job, RESOLVER_STEP)
                env = step_env(workflow, resolver_job, resolver_step, context)
                self.assertEqual(env["SOURCE_MODE"], "maintained")
                self.assertEqual(env["REQUESTED_REF"], "")
                self.assertEqual(env["SOURCE_REPOSITORY_URL"], fixture.remote_url(fixture.remote))

                result = run_resolver(fixture, workflow, context)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs = resolver_job_outputs(workflow, result.outputs)
                self.assertEqual(outputs["source_mode"], "maintained")
                self.assertEqual(outputs["requested_ref"], MAINTAINED_REF)
                self.assertEqual(outputs["requested_ref_name"], MAINTAINED_BRANCH)
                self.assertEqual(outputs["resolved_sha"], fixture.maintained_sha)
                self.assertNotEqual(outputs["resolved_sha"], context["github"]["sha"])
                self.assertIn(f"| resolved_sha | {fixture.maintained_sha} |", result.summary)
                self.assertIn(f"| workflow_sha | {fixture.default_sha} |", result.summary)

                context = with_needs(context, outputs)
                refs = check_source_wiring(workflow, context)
                self.assertEqual(set(refs), SOURCE_JOBS[key])
                self.assertEqual(set(refs.values()), {fixture.maintained_sha})

                fixture.checkout_work(fixture.maintained_sha)
                for job_id in sorted(refs):
                    job_context = matrix_context(workflow, job_id, context)
                    guard = run_job_step(fixture, workflow, job_id, GUARD_STEP, job_context, fixture.root)
                    self.assertEqual(guard.returncode, 0, guard.stderr)
                    verify = run_job_step(fixture, workflow, job_id, VERIFY_STEP, job_context, fixture.work)
                    self.assertEqual(verify.returncode, 0, verify.stderr)
                    self.assertIn(f"- actual_head: {fixture.maintained_sha}", verify.summary)
                    self.assertIn(f"- requested_ref: {MAINTAINED_REF}", verify.summary)
                    self.assertIn(f"- workflow_sha: {fixture.default_sha}", verify.summary)

                self.assert_wiring_mutations_rejected(workflow, context)

    def assert_wiring_mutations_rejected(self, workflow: dict[str, Any], context: dict[str, Any]) -> None:
        """Every mutation is applied to a deep copy; the loaded workflow stays intact."""
        job_id = sorted(source_job_ids(workflow))[0]
        retired_expression = "${{ github.event_name == 'schedule' && '" + RETIRED_BRANCH + "' || github.ref }}"
        mutations = {
            "retired branch literal": lambda job: job["steps"][step_index(job, CHECKOUT_STEP)]["with"].__setitem__(
                "ref", retired_expression
            ),
            "trigger commit instead of resolved output": lambda job: job["steps"][
                step_index(job, CHECKOUT_STEP)
            ]["with"].__setitem__("ref", "${{ github.sha }}"),
            "requested ref instead of resolved sha": lambda job: job["steps"][step_index(job, CHECKOUT_STEP)][
                "with"
            ].__setitem__("ref", "${{ needs.resolve-source.outputs.requested_ref }}"),
            "checkout ref removed": lambda job: job["steps"][step_index(job, CHECKOUT_STEP)]["with"].pop("ref"),
            "needs removed": lambda job: job.pop("needs"),
            "guard removed": lambda job: job["steps"].pop(step_index(job, GUARD_STEP)),
            "verify removed": lambda job: job["steps"].pop(step_index(job, VERIFY_STEP)),
        }
        for label, mutate in mutations.items():
            mutated = copy.deepcopy(workflow)
            mutate(mutated["jobs"][job_id])
            with self.subTest(mutation=label, job=job_id):
                with self.assertRaises(AssertionError):
                    check_source_wiring(mutated, context)
        check_source_wiring(workflow, context)

    def test_reports_checked_out_head(self) -> None:
        fixture = self.fixture
        for key in METADATA_WORKFLOWS:
            workflow = self.workflows[key]
            with self.subTest(workflow=key):
                context, outputs = self.resolve_schedule(key)
                (job_id,) = SOURCE_JOBS[key]
                trigger_sha = context["github"]["sha"]
                self.assertNotEqual(trigger_sha, outputs["resolved_sha"])

                fixture.checkout_work(outputs["resolved_sha"])
                metadata = self.run_metadata(workflow, job_id, context)
                self.assertEqual(metadata["git_commit"], outputs["resolved_sha"])
                self.assertEqual(metadata["resolved_sha"], outputs["resolved_sha"])
                self.assertEqual(metadata["checkout_ref"], outputs["resolved_sha"])
                self.assertEqual(metadata["requested_ref"], MAINTAINED_REF)
                self.assertEqual(metadata["benchmark_ref_name"], MAINTAINED_BRANCH)
                self.assertEqual(metadata["source_mode"], "maintained")
                self.assertEqual(metadata["github_sha"], trigger_sha)
                self.assertEqual(metadata["workflow_sha"], trigger_sha)
                self.assertEqual(metadata["benchmark_mode"], "nightly")
                self.assertNotEqual(metadata["git_commit"], metadata["github_sha"])
                self.assertNotEqual(metadata["git_commit"], metadata["workflow_sha"])

                # A checkout of the triggering commit is reported as such, never as the resolved source.
                fixture.checkout_work(trigger_sha)
                metadata = self.run_metadata(workflow, job_id, context)
                self.assertEqual(metadata["git_commit"], trigger_sha)
                self.assertEqual(metadata["resolved_sha"], outputs["resolved_sha"])
                verify = run_job_step(fixture, workflow, job_id, VERIFY_STEP, context, fixture.work)
                self.assertNotEqual(verify.returncode, 0)
                self.assertIn("does not match resolved source", verify.stderr)
                self.assertEqual(verify.summary, "")

    def run_metadata(self, workflow: dict[str, Any], job_id: str, context: dict[str, Any]) -> dict[str, str]:
        fixture = self.fixture
        job = workflow["jobs"][job_id]
        artifact_root = Path(job_env(workflow, job, context)["PERF_ARTIFACT_ROOT"])
        self.assertTrue(artifact_root.is_relative_to(fixture.workspace))
        shutil.rmtree(artifact_root, ignore_errors=True)
        result = run_job_step(fixture, workflow, job_id, METADATA_STEP, context, fixture.work)
        self.assertEqual(result.returncode, 0, result.stderr)
        host_env = artifact_root / "summary" / "host.env"
        return parse_key_values(host_env.read_text(encoding="utf8"))

    def test_nightly_scanner_keeps_independent_main_comparison(self) -> None:
        workflow = self.workflows["nightly"]
        context, outputs = self.resolve_schedule("nightly")
        scanner = workflow["jobs"]["scanner-readiness"]
        script = find_step(scanner, "Run scanner evidence")["run"]
        self.assertIn("git fetch --no-tags origin +main:refs/remotes/origin/main", script)
        self.assertIn('source_commit="$(git rev-parse HEAD)"', script)
        self.assertIn('history_diff_base_ref="origin/main"', script)
        self.assertIn('--source-commit "$source_commit"', script)
        self.assertIn('--history-diff-base-ref "$history_diff_base_ref"', script)
        # The verify step guarantees the scanner's HEAD-derived source commit is the resolved one.
        self.assertLess(step_index(scanner, VERIFY_STEP), step_index(scanner, "Run scanner evidence"))
        self.fixture.checkout_work(outputs["resolved_sha"])
        for job_id in sorted(SOURCE_JOBS["nightly"]):
            job_context = matrix_context(workflow, job_id, context)
            verify = run_job_step(self.fixture, workflow, job_id, VERIFY_STEP, job_context, self.fixture.work)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertIn(f"- actual_head: {outputs['resolved_sha']}", verify.summary)
        self.fixture.checkout_work(context["github"]["sha"])
        for job_id in sorted(SOURCE_JOBS["nightly"]):
            job_context = matrix_context(workflow, job_id, context)
            verify = run_job_step(self.fixture, workflow, job_id, VERIFY_STEP, job_context, self.fixture.work)
            self.assertNotEqual(verify.returncode, 0)

    def test_manual_selection_is_preserved(self) -> None:
        fixture = self.fixture
        selections = (
            (f"refs/heads/{fixture.manual_branch}", fixture.manual_branch),
            (f"refs/tags/{fixture.manual_tag}", fixture.manual_tag),
        )
        self.assertNotEqual(fixture.manual_sha, fixture.maintained_sha)
        for key, workflow in self.workflows.items():
            for ref, ref_name in selections:
                with self.subTest(workflow=key, ref=ref):
                    self.assertNotEqual(ref, MAINTAINED_REF)
                    context = dispatch_context(fixture, ref, fixture.manual_sha, dispatch_inputs(workflow))
                    resolver_job = workflow["jobs"][RESOLVER_JOB]
                    env = step_env(workflow, resolver_job, find_step(resolver_job, RESOLVER_STEP), context)
                    self.assertEqual(env["SOURCE_MODE"], "manual")
                    self.assertEqual(env["REQUESTED_REF"], ref)
                    self.assertEqual(env["EVENT_SHA"], fixture.manual_sha)

                    # A manual run must not depend on the maintained branch or the remote.
                    unreachable = fixture.root / "missing-remote.git"
                    result = run_resolver(
                        fixture, workflow, context, {"SOURCE_REPOSITORY_URL": unreachable.as_uri()}
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    outputs = resolver_job_outputs(workflow, result.outputs)
                    self.assertEqual(outputs["source_mode"], "manual")
                    self.assertEqual(outputs["requested_ref"], ref)
                    self.assertEqual(outputs["requested_ref_name"], ref_name)
                    self.assertEqual(outputs["resolved_sha"], fixture.manual_sha)

                    context = with_needs(context, outputs)
                    refs = check_source_wiring(workflow, context)
                    self.assertEqual(set(refs.values()), {fixture.manual_sha})
                    self.assertEqual(
                        render(workflow["concurrency"]["group"], context),
                        workflow["concurrency"]["group"].split("${{")[0] + ref,
                    )
                    if "run-name" in workflow:
                        self.assertIn(f"branch={ref_name}", render(workflow["run-name"], context))

                    fixture.checkout_work(fixture.manual_sha)
                    for job_id in sorted(refs):
                        job_context = matrix_context(workflow, job_id, context)
                        verify = run_job_step(fixture, workflow, job_id, VERIFY_STEP, job_context, fixture.work)
                        self.assertEqual(verify.returncode, 0, verify.stderr)
                        self.assertIn(f"- requested_ref: {ref}", verify.summary)
                        self.assertIn(f"- actual_head: {fixture.manual_sha}", verify.summary)

                    if key in METADATA_WORKFLOWS:
                        (job_id,) = SOURCE_JOBS[key]
                        job = workflow["jobs"][job_id]
                        env = job_env(workflow, job, context)
                        self.assertEqual(env["RUN_MODE"], "manual")
                        self.assertEqual(env["BENCHMARK_REF_NAME"], ref_name)
                        self.assertEqual(env["RESOLVED_SHA"], fixture.manual_sha)
                        if key == "ibd":
                            self.assertEqual(env["SELECTED_PROFILE"], context["inputs"]["profile"])
                        else:
                            self.assertEqual(env["RUN_SCALE"], context["inputs"]["run_scale"])
                        metadata = self.run_metadata(workflow, job_id, context)
                        self.assertEqual(metadata["benchmark_mode"], "manual")
                        self.assertEqual(metadata["source_mode"], "manual")
                        self.assertEqual(metadata["requested_ref"], ref)
                        self.assertEqual(metadata["benchmark_ref_name"], ref_name)
                        self.assertEqual(metadata["git_commit"], fixture.manual_sha)
                        self.assertEqual(metadata["resolved_sha"], fixture.manual_sha)
                        self.assertEqual(metadata["github_ref"], ref)

    def test_scheduled_run_rejects_incomplete_manual_context(self) -> None:
        """A scheduled context that lost its resolver output cannot reach a checkout."""
        for key, workflow in self.workflows.items():
            with self.subTest(workflow=key):
                context = with_needs(schedule_context(self.fixture), {"resolved_sha": "", "requested_ref": ""})
                with self.assertRaises(AssertionError):
                    check_source_wiring(workflow, context)

    def test_resolver_rejects_missing_or_malformed_inputs(self) -> None:
        fixture = self.fixture
        workflow = self.workflows["ibd"]
        for key in self.workflows:
            self.assertEqual(
                find_step(self.workflows[key]["jobs"][RESOLVER_JOB], RESOLVER_STEP)["run"],
                find_step(workflow["jobs"][RESOLVER_JOB], RESOLVER_STEP)["run"],
                f"{key}: resolver script must be identical across workflows",
            )
        schedule = schedule_context(fixture)
        manual_ref = f"refs/heads/{fixture.manual_branch}"
        manual = dispatch_context(fixture, manual_ref, fixture.manual_sha, dispatch_inputs(workflow))
        failures: list[tuple[str, dict[str, Any], dict[str, str]]] = [
            ("maintained branch missing from remote", schedule_context(fixture, fixture.remote_without_maintained), {}),
            ("unreachable remote", schedule, {"SOURCE_REPOSITORY_URL": (fixture.root / "absent.git").as_uri()}),
            ("empty maintained branch", schedule, {"MAINTAINED_BRANCH": ""}),
            ("malformed maintained branch", schedule, {"MAINTAINED_BRANCH": "bad..branch"}),
            ("unsupported source mode", schedule, {"SOURCE_MODE": "nightly"}),
            ("malformed workflow revision", schedule, {"WORKFLOW_SHA": "main"}),
            ("manual empty event sha", manual, {"EVENT_SHA": ""}),
            ("manual short event sha", manual, {"EVENT_SHA": fixture.manual_sha[:12]}),
            ("manual symbolic event sha", manual, {"EVENT_SHA": "HEAD"}),
            ("manual uppercase event sha", manual, {"EVENT_SHA": fixture.manual_sha.upper()}),
            ("manual empty requested ref", manual, {"REQUESTED_REF": ""}),
            ("manual unqualified requested ref", manual, {"REQUESTED_REF": fixture.manual_branch}),
            ("manual pull request ref", manual, {"REQUESTED_REF": "refs/pull/1/merge"}),
            ("manual bare heads prefix", manual, {"REQUESTED_REF": "refs/heads/"}),
            ("manual invalid ref name", manual, {"REQUESTED_REF": "refs/heads/bad..name"}),
            ("manual ref with whitespace", manual, {"REQUESTED_REF": "refs/heads/bad name"}),
        ]
        for label, context, override in failures:
            with self.subTest(case=label):
                result = run_resolver(fixture, workflow, context, override)
                self.assertNotEqual(result.returncode, 0, label)
                self.assertNotIn("resolved_sha", result.outputs, label)
                self.assertIn("::error::", result.stderr, label)
                self.assertEqual(result.summary, "", label)
        # Resolution without a token still works; the token only adds an auth header.
        result = run_resolver(fixture, workflow, schedule, {"GITHUB_TOKEN": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.outputs["resolved_sha"], fixture.maintained_sha)

    def test_checkout_guard_rejects_unresolved_source(self) -> None:
        fixture = self.fixture
        for key, workflow in self.workflows.items():
            context, outputs = self.resolve_schedule(key)
            for job_id in sorted(SOURCE_JOBS[key]):
                bad_values = ["", RETIRED_BRANCH, MAINTAINED_BRANCH, MAINTAINED_REF, "HEAD", outputs["resolved_sha"][:20]]
                for bad in bad_values:
                    with self.subTest(workflow=key, job=job_id, resolved_sha=bad):
                        broken = with_needs(context, dict(outputs, resolved_sha=bad))
                        guard = run_job_step(fixture, workflow, job_id, GUARD_STEP, broken, fixture.root)
                        self.assertNotEqual(guard.returncode, 0)
                        self.assertIn("::error::", guard.stderr)
                with self.subTest(workflow=key, job=job_id, requested_ref=""):
                    broken = with_needs(context, dict(outputs, requested_ref=""))
                    guard = run_job_step(fixture, workflow, job_id, GUARD_STEP, broken, fixture.root)
                    self.assertNotEqual(guard.returncode, 0)

    def test_nightly_mutation_env_only_on_native_fuzz_matrix(self) -> None:
        """Only the native fuzz nightly entry requests the seeded mutation phase."""
        workflow = self.workflows["nightly"]
        context, _outputs = self.resolve_schedule("nightly")
        job = workflow["jobs"]["nightly-matrix"]
        include = job["strategy"]["matrix"]["include"]
        native_fuzz = [entry for entry in include if entry["file-env"].endswith("/00_setup_env_native_fuzz.sh")]
        self.assertEqual(len(native_fuzz), 1)
        for entry in include:
            with self.subTest(matrix=entry["name"]):
                env = job_env(workflow, job, dict(context, matrix=entry))
                expected = "120" if entry in native_fuzz else ""
                self.assertEqual(env["QBIT_FUZZ_MUTATE_MIN_TIME"], expected)
        for job_id, other in workflow["jobs"].items():
            if job_id != "nightly-matrix":
                self.assertNotIn("QBIT_FUZZ_MUTATE_MIN_TIME", other.get("env") or {}, job_id)
        for key in ("ibd", "rpc"):
            self.assertNotIn("QBIT_FUZZ_MUTATE_MIN_TIME", self.workflow_text[key])

    def test_expression_evaluator_matches_actions_semantics(self) -> None:
        context = {"github": {"event_name": "schedule", "ref": "refs/heads/main"}, "inputs": {}}
        self.assertEqual(evaluate("github.event_name == 'schedule' && 'a' || 'b'", context), "a")
        self.assertEqual(evaluate("github.event_name != 'schedule' && github.ref || ''", context), "")
        self.assertEqual(evaluate("inputs.missing || 'fallback'", context), "fallback")
        self.assertIs(evaluate("!inputs.missing", context), True)
        self.assertIs(evaluate("(github.event_name == 'SCHEDULE')", context), True)
        self.assertEqual(render("x-${{ github.ref }}-${{ inputs.missing }}", context), "x-refs/heads/main-")
        self.assertEqual(json.dumps(render("${{ inputs.missing }}", context)), "null")
        with self.assertRaises(ExpressionError):
            evaluate("fromJSON('[]')", context)


if __name__ == "__main__":
    unittest.main()
