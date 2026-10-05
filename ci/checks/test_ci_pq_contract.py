#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Executable contract for the PQ CI entry points (#184 part 2, work item C1).

``ci-pq.yml`` and ``ci-nightly-heavy.yml`` are reusable and job-selectable, and
the PQ unit job proves which suites ran. These tests read the real workflow
files and scripts and execute their inline steps and shell blocks:

* job selection: the ``jobs`` input of a call or dispatch becomes the matrix,
  and only the selected jobs pass their ``if``. On-demand PQ runs reach
  ``ci-pq.yml`` through main's caller (C4), which forwards ``source_ref`` and
  ``jobs``; GitHub dispatches only workflows whose file is on the default
  branch, so ``gh workflow run ci-pq.yml --ref <branch>`` is not the path;
* an unknown, repeated or empty job name fails the run;
* the source is resolved once to a full commit (branch, peeled tag, commit or
  the triggering commit), every job checks out and verifies exactly that
  commit, and a scheduled call from main still validates the maintained branch;
* a called nightly run gets its caller's github context, so it is recognized by
  its ``source_ref`` input: it validates that source (resolved by the same
  function as ``ci-pq.yml``) and honors its inputs whatever the caller's event,
  while direct runs keep their source, the repository variables of a schedule
  and their concurrency groups; callers for different sources never share one;
* suites really ran: ``CI_BUILD_TARGET`` and ``CTEST_REGEX`` reach the build and
  ctest commands of ``ci/test/03_test_script.sh``, and ``ctest_evidence.py``
  fails a skipped, failed, missing or unselected expected suite.

ctest and cmake are replaced by recording stubs; GitHub itself is not called.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import ctest_evidence
import test_scheduled_validation_contract as svc

REPO_ROOT = svc.REPO_ROOT
PQ = "pq"
NIGHTLY = "nightly"
WORKFLOWS = {
    PQ: svc.WORKFLOW_DIR / "ci-pq.yml",
    NIGHTLY: svc.WORKFLOW_DIR / "ci-nightly-heavy.yml",
}
GATE_WORKFLOW = svc.WORKFLOW_DIR / "required-merge-gate.yml"
TEST_SCRIPT = REPO_ROOT / "ci" / "test" / "03_test_script.sh"
RESOLVER_JOB = svc.RESOLVER_JOB
TRIGGER_STEP = "Check how the run started"
REQUESTED_STEP = "Resolve requested source"
SHARED_RESOLVER = "resolve_source_ref"
SELECT_STEP = "Select jobs"
REPORT_STEP = "Report unit-test evidence"
PQ_UNIT_JOB = "unit"
AARCH64_JOB = "aarch64-unit"
AARCH64_SUITES = ["bip324_tests", "net_tests"]
NIGHTLY_MATRIX_JOBS = ["arm32-unit-1", "arm32-unit-2", "previous-releases", "fuzz"]
NIGHTLY_ALL_JOBS: dict[str, list[str]] = {"nightly-matrix": NIGHTLY_MATRIX_JOBS, "scanner-readiness": []}
NIGHTLY_VARS_OFF = {"CI_NIGHTLY_HEAVY_RUN_TEST_MATRIX": "false", "CI_NIGHTLY_HEAVY_RUN_SCANNERS": "false"}
SCANNER_SETTINGS = ("SCANNER_SET", "SCANNER_FAIL_POLICY", "SKIP_BUILD_SCANNERS", "SCANNER_MODE")
CALLER_EVENTS = ("schedule", "workflow_dispatch")
CALLER_WORKFLOW = "ci-maintained-heavy.yml"  # main's heavy caller (C4)
MATRIX_EXPRESSION = "${{ fromJSON(needs." + RESOLVER_JOB + ".outputs.matrix) }}"
ANNOTATED_TAG = "v9.9.9-annotated"
AMBIGUOUS_NAME = "dup"
SUITE_INVENTORY = ["addrman_tests", "bip324_tests", "bip324_tests_extra", "net_tests", "netbase_tests", "util_tests"]


# ---------------------------------------------------------------------------
# Workflow helpers
# ---------------------------------------------------------------------------


def run_python_step(fixture: svc.Fixture, step: dict[str, Any], env: dict[str, str], cwd: Path) -> svc.StepResult:
    """Execute a ``shell: python3 {0}`` step the way the runner does."""
    assert step.get("shell") == "python3 {0}", step.get("shell")
    with tempfile.TemporaryDirectory(prefix="step-", dir=fixture.root) as tmp:
        script = Path(tmp) / "step.py"
        script.write_text(step["run"], encoding="utf8")
        output_path = Path(tmp) / "github-output"
        summary_path = Path(tmp) / "step-summary"
        output_path.touch()
        summary_path.touch()
        full_env = fixture.base_env()
        full_env.update(env)
        full_env["GITHUB_OUTPUT"] = str(output_path)
        full_env["GITHUB_STEP_SUMMARY"] = str(summary_path)
        completed = subprocess.run([sys.executable, str(script)], cwd=cwd, env=full_env, text=True, capture_output=True)
        outputs = svc.parse_key_values(output_path.read_text(encoding="utf8"))
        summary = summary_path.read_text(encoding="utf8")
    return svc.StepResult(completed, outputs, summary)


def resolver_outputs(workflow: dict[str, Any], steps: dict[str, dict[str, str]]) -> dict[str, str]:
    """Evaluate the resolver job's ``outputs`` from the outputs of the steps that ran, by step id."""
    context = {"steps": {step_id: {"outputs": outputs} for step_id, outputs in steps.items()}}
    job = workflow["jobs"][RESOLVER_JOB]
    return {name: svc._to_text(svc.render(value, context)) for name, value in job["outputs"].items()}


def call_inputs(workflow: dict[str, Any]) -> dict[str, Any]:
    """A called run's inputs: GitHub gives every input the caller does not pass its default."""
    declared = workflow["on"]["workflow_call"].get("inputs") or {}
    return {name: spec.get("default") for name, spec in declared.items()}


def workflow_ref(github: dict[str, Any], file: str, ref: str) -> str:
    """A workflow_ref as GitHub writes it: <owner/repo>/.github/workflows/<file>@<ref>."""
    return f"{github['repository']}/.github/workflows/{file}@{ref}"


def shell_function(script: str, name: str) -> str:
    """The definition of a top-level shell function in a step script."""
    lines = script.splitlines()
    first = next(index for index, line in enumerate(lines) if line.startswith(f"{name}() {{"))
    last = next(index for index in range(first, len(lines)) if lines[index] == "}")
    return "\n".join(lines[first:last + 1])


def catalog(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    step = svc.find_step(workflow["jobs"][RESOLVER_JOB], SELECT_STEP)
    return json.loads(step["env"]["JOB_CATALOG"])


def running_jobs(workflow: dict[str, Any], context: dict[str, Any]) -> dict[str, list[str]]:
    """Jobs whose ``if`` passes, with the matrix entries each one would run."""
    outputs = context["needs"][RESOLVER_JOB]["outputs"]
    running: dict[str, list[str]] = {}
    for job_id, job in workflow["jobs"].items():
        if job_id == RESOLVER_JOB:
            continue
        condition = job.get("if")
        if condition is not None and not svc._truthy(svc.render(condition, context)):
            continue
        matrix = (job.get("strategy") or {}).get("matrix")
        if matrix is None:
            running[job_id] = []
            continue
        assert matrix == MATRIX_EXPRESSION, f"{job_id} matrix must come from the resolver: {matrix!r}"
        running[job_id] = [entry["job"] for entry in json.loads(outputs["matrix"])["include"]]
    return running


def source_env(env_file: str, names: list[str], extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Source a ci/test env file in bash and return the effective values of names."""
    script = f"set -e\nsource {env_file}\n" + "".join(f'printf "%s=%s\\n" {name} "${{{name}:-}}"\n' for name in names)
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")}
    env.update(extra_env or {})
    completed = subprocess.run(["bash", "-c", script], cwd=REPO_ROOT, env=env, text=True, capture_output=True, check=True)
    return svc.parse_key_values(completed.stdout)


def shell_block(text: str, start: str, end_line: str) -> str:
    """The lines of text from the line starting with start through the next line equal to end_line."""
    lines = text.splitlines()
    first = next(index for index, line in enumerate(lines) if line.startswith(start))
    last = next(index for index in range(first + 1, len(lines)) if lines[index] == end_line)
    return "\n".join(lines[first:last + 1]) + "\n"


STUB_CTEST = r'''#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a", encoding="utf8") as log:
    log.write(json.dumps(["ctest"] + args) + "\n")
selected = os.environ["STUB_INVENTORY"].split()
junit = None
for flag, value in zip(args, args[1:]):
    if flag == "-I":
        start, end = (int(part) for part in value.split(","))
        selected = selected[start - 1:end]
    elif flag == "-R":
        selected = [name for name in selected if re.search(value, name)]
    elif flag == "--output-junit":
        junit = value
if "--show-only=json-v1" in args:
    print(json.dumps({"kind": "ctestInfo", "version": {"major": 1, "minor": 0}, "tests": [{"name": n} for n in selected]}))
    sys.exit(0)
if "--show-only" in args:
    print("\n".join(selected))
    sys.exit(0)
if not selected and "--no-tests=error" in args:
    print("No tests were found!!!")
    sys.exit(8)
outcomes = json.loads(os.environ.get("STUB_OUTCOMES") or "{}")
cases = []
for name in selected:
    status = outcomes.get(name, "run")
    body = {"notrun": '<skipped message="SKIP_REGULAR_EXPRESSION_MATCHED"/>', "fail": '<failure message="Failed"/>'}.get(status, "")
    cases.append(f'<testcase name="{name}" classname="{name}" time="0.5" status="{status}">{body}<system-out/></testcase>')
if junit:
    with open(junit, "w", encoding="utf8") as out:
        out.write(f'<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="(empty)" tests="{len(cases)}">' + "".join(cases) + "</testsuite>\n")
sys.exit(8 if "fail" in outcomes.values() else 0)
'''

STUB_CMAKE = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a", encoding="utf8") as log:
    log.write(json.dumps(["cmake"] + sys.argv[1:]) + "\n")
counter = os.environ["STUB_LOG"] + ".cmake-calls"
calls = int(open(counter).read()) if os.path.exists(counter) else 0
open(counter, "w").write(str(calls + 1))
sys.exit(1 if os.environ.get("STUB_FAIL_FIRST") == "1" and calls == 0 else 0)
'''


class ScriptRun:
    def __init__(self, completed: subprocess.CompletedProcess[str], calls: list[list[str]], files: dict[str, str]) -> None:
        self.completed = completed
        self.calls = calls
        self.files = files  # ctest-evidence/<name> -> contents

    @property
    def returncode(self) -> int:
        return self.completed.returncode


def run_test_script_block(block: str, env: dict[str, str]) -> ScriptRun:
    """Run a block of 03_test_script.sh under its own shell options with stub cmake and ctest."""
    with tempfile.TemporaryDirectory(prefix="ci-test-script-") as tmp:
        root = Path(tmp)
        stubs = root / "stubs"
        stubs.mkdir()
        for name, body in (("ctest", STUB_CTEST), ("cmake", STUB_CMAKE)):
            (stubs / name).write_text(body, encoding="utf8")
            (stubs / name).chmod(0o755)
        build = root / "build"
        build.mkdir()
        log = root / "calls.jsonl"
        log.touch()
        full_env = {
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "HOME": str(root),
            "LC_ALL": "C",
            "BASE_ROOT_DIR": str(REPO_ROOT),
            "BASE_BUILD_DIR": str(build),
            "DEPENDS_DIR": str(root / "depends"),
            "HOST": "x86_64-pc-linux-gnu",
            "MAKEJOBS": "-j2",
            "CTEST_JOBS": "2",
            "TEST_RUNNER_TIMEOUT_FACTOR": "1",
            "RUN_UNIT_TESTS": "true",
            "DIR_UNIT_TEST_DATA": "",
            "GOAL": "install",
            "STUB_LOG": str(log),
            "STUB_INVENTORY": " ".join(SUITE_INVENTORY),
        }
        full_env.update(env)
        script = root / "block.sh"
        script.write_text("set -ex\n" + block, encoding="utf8")
        completed = subprocess.run(["bash", str(script)], env=full_env, text=True, capture_output=True)
        calls = [json.loads(line) for line in log.read_text(encoding="utf8").splitlines()]
        evidence = build / "ctest-evidence"
        files = {path.name: path.read_text(encoding="utf8") for path in evidence.glob("*")} if evidence.is_dir() else {}
    return ScriptRun(completed, calls, files)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class PQWorkflowContractTest(unittest.TestCase):
    fixture: svc.Fixture
    tag_object: str
    workflows: dict[str, dict[str, Any]]
    workflow_text: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = svc.Fixture()
        fixture = cls.fixture
        # An annotated tag and a name that is both a branch and a tag.
        fixture.git("tag", "-a", ANNOTATED_TAG, "-m", "annotated", fixture.maintained_sha, cwd=fixture.work)
        fixture.git("tag", AMBIGUOUS_NAME, fixture.manual_sha, cwd=fixture.work)
        fixture.git("push", "-q", "origin", f"refs/tags/{ANNOTATED_TAG}", f"refs/tags/{AMBIGUOUS_NAME}", cwd=fixture.work)
        fixture.git("push", "-q", "origin", f"{fixture.default_sha}:refs/heads/{AMBIGUOUS_NAME}", cwd=fixture.work)
        cls.tag_object = fixture.git("rev-parse", ANNOTATED_TAG, cwd=fixture.work).strip()
        cls.workflows = {key: svc.load_workflow(path) for key, path in WORKFLOWS.items()}
        cls.workflow_text = {key: path.read_text(encoding="utf8") for key, path in WORKFLOWS.items()}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def tearDown(self) -> None:
        for key, path in WORKFLOWS.items():
            self.assertEqual(path.read_text(encoding="utf8"), self.workflow_text[key], f"{path} was modified")

    # -- contexts and step runs ------------------------------------------------

    def direct(self, key: str, context: dict[str, Any]) -> dict[str, Any]:
        """A direct run: the job is defined in the workflow file that runs, so job.workflow_ref is github.workflow_ref."""
        github = dict(context["github"])
        github["workflow_ref"] = workflow_ref(github, WORKFLOWS[key].name, github["ref"])
        return dict(context, github=github, job={"status": "success", "workflow_ref": github["workflow_ref"]})

    def dispatch(self, key: str, **inputs: Any) -> dict[str, Any]:
        declared = svc.dispatch_inputs(self.workflows[key])
        unknown = set(inputs) - set(declared)
        self.assertFalse(unknown, f"{key} has no workflow_dispatch input(s) {unknown}")
        declared.update(inputs)
        return self.direct(key, svc.dispatch_context(self.fixture, f"refs/heads/{self.fixture.manual_branch}", self.fixture.manual_sha, declared))

    def scheduled(self, key: str, **context: Any) -> dict[str, Any]:
        """A direct scheduled run on main."""
        return self.direct(key, dict(svc.schedule_context(self.fixture), **context))

    def call(self, key: str, caller_event: str, *, variables: dict[str, str] | None = None, remote: Path | None = None,
             caller_workflow: str = CALLER_WORKFLOW, **inputs: Any) -> dict[str, Any]:
        """A run called by main's caller: the github context is the caller's event and
        workflow on main, job.workflow_ref is this file at 1.x.x, and every input the
        caller does not pass has its default."""
        declared = call_inputs(self.workflows[key])
        unknown = set(inputs) - set(declared)
        self.assertFalse(unknown, f"{key} has no workflow_call input(s) {unknown}")
        declared.update(inputs)
        github = self.fixture.github_context(caller_event, "refs/heads/main", self.fixture.default_sha, remote)
        github["workflow_ref"] = workflow_ref(github, caller_workflow, "refs/heads/main")
        job = {"status": "success", "workflow_ref": workflow_ref(github, WORKFLOWS[key].name, svc.MAINTAINED_REF)}
        return {"github": github, "inputs": declared, "needs": {}, "matrix": {}, "vars": dict(variables or {}), "steps": {}, "job": job}

    def run_resolver_step(self, key: str, name: str, context: dict[str, Any]) -> svc.StepResult:
        """Run one bash step of the resolver job, whatever its if."""
        workflow = self.workflows[key]
        job = workflow["jobs"][RESOLVER_JOB]
        step = svc.find_step(job, name)
        env = svc.step_env(workflow, job, step, context)
        return svc.run_step(self.fixture, step, env, self.fixture.root, svc.github_env_for(context, RESOLVER_JOB, workflow["name"]))

    def run_resolver(self, key: str, context: dict[str, Any]) -> svc.StepResult:
        return self.run_resolver_step(key, svc.RESOLVER_STEP, context)

    def run_resolver_job(self, key: str, context: dict[str, Any]) -> tuple[list[str], dict[str, svc.StepResult]]:
        """Run the resolver job's steps the way the runner does: a step whose if is
        false is skipped, and a failed step ends the job. Returns the names of the
        steps that ran and their results by step id."""
        workflow = self.workflows[key]
        job = workflow["jobs"][RESOLVER_JOB]
        ran: list[str] = []
        results: dict[str, svc.StepResult] = {}
        step_context = dict(context, steps={})
        for step in job["steps"]:
            condition = step.get("if")
            if condition is not None and not svc._truthy(svc.render(condition, step_context)):
                continue
            env = svc.step_env(workflow, job, step, step_context)
            if step.get("shell") == "python3 {0}":
                result = run_python_step(self.fixture, step, env, self.fixture.root)
            else:
                github_env = svc.github_env_for(context, RESOLVER_JOB, workflow["name"])
                result = svc.run_step(self.fixture, step, env, self.fixture.root, github_env)
            ran.append(step["name"])
            results[step["id"]] = result
            if result.returncode != 0:
                break
            step_context["steps"] = dict(step_context["steps"], **{step["id"]: {"outputs": result.outputs}})
        return ran, results

    def run_select(self, key: str, context: dict[str, Any]) -> svc.StepResult:
        workflow = self.workflows[key]
        job = workflow["jobs"][RESOLVER_JOB]
        step = svc.find_step(job, SELECT_STEP)
        return run_python_step(self.fixture, step, svc.step_env(workflow, job, step, context), self.fixture.root)

    def resolve(self, key: str, context: dict[str, Any]) -> dict[str, Any]:
        """Run the resolver job; return the context with its outputs as ``needs``."""
        _ran, results = self.run_resolver_job(key, context)
        for result in results.values():
            self.assertEqual(result.returncode, 0, result.stderr)
        steps = {step_id: result.outputs for step_id, result in results.items()}
        return svc.with_needs(context, resolver_outputs(self.workflows[key], steps))

    def nightly_run(self, context: dict[str, Any]) -> dict[str, Any]:
        """What a nightly run does with a context: the resolver step that ran, the
        source, the jobs that run, the scanner settings and the concurrency group."""
        workflow = self.workflows[NIGHTLY]
        ran, results = self.run_resolver_job(NIGHTLY, context)
        for result in results.values():
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(ran[-1], SELECT_STEP)
        context = svc.with_needs(context, resolver_outputs(workflow, {step_id: result.outputs for step_id, result in results.items()}))
        outputs = context["needs"][RESOLVER_JOB]["outputs"]
        scanner_env = svc.job_env(workflow, workflow["jobs"]["scanner-readiness"], context)
        self.assertEqual(ran[0], TRIGGER_STEP)
        return {
            "resolvers": ran[1:-1],
            "source": (outputs["source_mode"], outputs["requested_ref"], outputs["resolved_sha"]),
            "jobs": running_jobs(workflow, context),
            "scanner": {name: scanner_env[name] for name in SCANNER_SETTINGS},
            "group": svc.render(workflow["concurrency"]["group"], context),
            "summary": "".join(result.summary for result in results.values()),
            "context": context,
        }

    # -- entry points ------------------------------------------------------------

    def test_entry_points(self) -> None:
        pq = self.workflows[PQ]
        for trigger in ("workflow_call", "workflow_dispatch"):
            with self.subTest(workflow=PQ, trigger=trigger):
                inputs = pq["on"][trigger]["inputs"]
                self.assertEqual(set(inputs), {"source_ref", "jobs"})
                for spec in inputs.values():
                    self.assertEqual((spec["type"], spec["default"], spec["required"]), ("string", "", False))

        nightly = self.workflows[NIGHTLY]
        self.assertIn("schedule", nightly["on"])
        call = nightly["on"]["workflow_call"]["inputs"]
        dispatch = nightly["on"]["workflow_dispatch"]["inputs"]
        # Only a call names its source, so a direct dispatch validates the ref it was dispatched on.
        self.assertNotIn("source_ref", dispatch)
        source = call["source_ref"]
        self.assertEqual((source["type"], source["default"], source["required"]), ("string", svc.MAINTAINED_BRANCH, False))
        self.assertIn("must not be empty", source["description"])
        self.assertEqual([name for name in call if name != "source_ref"], list(dispatch),
                         "the other workflow_call inputs must mirror workflow_dispatch")
        self.assertIn("jobs", call)
        for name, spec in dispatch.items():
            with self.subTest(workflow=NIGHTLY, input=name):
                mirrored = call[name]
                expected_type = "string" if spec["type"] == "choice" else spec["type"]
                self.assertEqual(mirrored["type"], expected_type)
                self.assertEqual(mirrored["default"], spec["default"])
                self.assertEqual(mirrored["required"], spec["required"])
                if spec["type"] == "choice":
                    self.assertIn(spec["default"], spec["options"])
        # The scanner's secret reaches a called run.
        self.assertEqual(set(nightly["on"]["workflow_call"]["secrets"]), {"LIBBITCOINPQC_READ_TOKEN"})
        self.assertIn("secrets.LIBBITCOINPQC_READ_TOKEN", self.workflow_text[NIGHTLY])

    def test_selection_scripts_are_identical(self) -> None:
        scripts = {key: svc.find_step(workflow["jobs"][RESOLVER_JOB], SELECT_STEP)["run"] for key, workflow in self.workflows.items()}
        self.assertEqual(scripts[PQ], scripts[NIGHTLY])
        for key, workflow in self.workflows.items():
            resolver = workflow["jobs"][RESOLVER_JOB]
            self.assertFalse(any("uses" in step for step in resolver["steps"]), f"{key}: selection must run inline")
            names = [entry["job"] for entry in catalog(workflow)]
            self.assertEqual(len(names), len(set(names)), key)

    # -- named-dispatch selection --------------------------------------------------

    def test_named_dispatch_runs_only_selected_jobs(self) -> None:
        cases: list[tuple[str, dict[str, Any], dict[str, list[str]]]] = [
            (PQ, {"jobs": AARCH64_JOB}, {PQ_UNIT_JOB: [AARCH64_JOB]}),
            (PQ, {"jobs": ""}, {PQ_UNIT_JOB: [AARCH64_JOB]}),
            (NIGHTLY, {"run_test_matrix": True, "run_scanners": False, "jobs": "previous-releases"},
             {"nightly-matrix": ["previous-releases"]}),
            (NIGHTLY, {"jobs": ""}, {"nightly-matrix": NIGHTLY_MATRIX_JOBS, "scanner-readiness": []}),
            (NIGHTLY, {"jobs": " fuzz , previous-releases "}, {"nightly-matrix": ["previous-releases", "fuzz"]}),
            (NIGHTLY, {"jobs": "scanner"}, {"scanner-readiness": []}),
            (NIGHTLY, {"run_test_matrix": False, "jobs": "previous-releases"}, {}),
        ]
        for key, inputs, expected in cases:
            with self.subTest(workflow=key, inputs=inputs):
                context = self.resolve(key, self.dispatch(key, **inputs))
                self.assertEqual(running_jobs(self.workflows[key], context), expected)

        # The nightly run keeps its entries' settings, such as the shard ranges and the fuzz mutation time.
        entries = {entry["job"]: entry for entry in catalog(self.workflows[NIGHTLY])}
        self.assertEqual(entries["arm32-unit-2"]["ctest_include_range"], "140,99999")
        self.assertEqual(entries["fuzz"]["fuzz-mutate-min-time"], "120")

    def test_scheduled_call_from_main_runs_everything_on_the_maintained_branch(self) -> None:
        context = self.resolve(NIGHTLY, self.call(NIGHTLY, "schedule"))
        outputs = context["needs"][RESOLVER_JOB]["outputs"]
        self.assertEqual(outputs["resolved_sha"], self.fixture.maintained_sha)
        self.assertEqual(outputs["requested_ref"], svc.MAINTAINED_REF)
        self.assertEqual(running_jobs(self.workflows[NIGHTLY], context),
                         {"nightly-matrix": NIGHTLY_MATRIX_JOBS, "scanner-readiness": []})
        refs = svc.check_source_wiring(self.workflows[NIGHTLY], context)
        self.assertEqual(set(refs.values()), {self.fixture.maintained_sha})

        # The PQ workflow is told which branch to validate.
        context = self.resolve(PQ, self.call(PQ, "schedule", source_ref=svc.MAINTAINED_BRANCH))
        outputs = context["needs"][RESOLVER_JOB]["outputs"]
        self.assertEqual(outputs["resolved_sha"], self.fixture.maintained_sha)
        self.assertNotEqual(outputs["resolved_sha"], context["github"]["sha"])
        self.assertEqual(running_jobs(self.workflows[PQ], context), {PQ_UNIT_JOB: [AARCH64_JOB]})

    # -- called and direct nightly runs ---------------------------------------------

    def test_called_nightly_run_validates_source_ref_whatever_the_caller(self) -> None:
        fixture = self.fixture
        workflow = self.workflows[NIGHTLY]
        defaults = {"SCANNER_SET": "minimum", "SCANNER_FAIL_POLICY": "infra-and-secrets", "SKIP_BUILD_SCANNERS": "false"}
        for event in CALLER_EVENTS:
            mode = "nightly" if event == "schedule" else "manual_dry_run"
            with self.subTest(caller=event):
                # The repository variables that switch a direct scheduled run off do not apply to a called one.
                run = self.nightly_run(self.call(NIGHTLY, event, variables=NIGHTLY_VARS_OFF))
                github = run["context"]["github"]
                self.assertEqual((github["ref"], github["sha"]), ("refs/heads/main", fixture.default_sha))
                self.assertEqual(run["resolvers"], [REQUESTED_STEP])
                self.assertEqual(run["source"], ("maintained", svc.MAINTAINED_REF, fixture.maintained_sha))
                self.assertEqual(run["jobs"], NIGHTLY_ALL_JOBS)
                self.assertEqual(run["scanner"], dict(defaults, SCANNER_MODE=mode))
                for row in ("| source_ref input | 1.x.x |", "| source_mode | maintained |", f"| caller_event | {event} |",
                            f"| resolved_sha | {fixture.maintained_sha} |"):
                    self.assertIn(row, run["summary"])
                refs = svc.check_source_wiring(workflow, run["context"])
                self.assertEqual(set(refs.values()), {fixture.maintained_sha})
                fixture.checkout_work(fixture.maintained_sha)
                for job_id in sorted(refs):
                    job_context = svc.matrix_context(workflow, job_id, run["context"])
                    verify = svc.run_job_step(fixture, workflow, job_id, svc.VERIFY_STEP, job_context, fixture.work)
                    self.assertEqual(verify.returncode, 0, verify.stderr)
                    self.assertIn("- source_ref input: 1.x.x\n- source_mode: maintained\n", verify.summary)

                # The default source is looked up on the remote, never taken from the caller.
                ran, results = self.run_resolver_job(NIGHTLY, self.call(NIGHTLY, event, remote=fixture.remote_without_maintained))
                self.assertEqual(ran, [TRIGGER_STEP, REQUESTED_STEP])
                self.assertNotEqual(results["requested"].returncode, 0)
                self.assertIn(f"::error::no branch or tag '{svc.MAINTAINED_BRANCH}'", results["requested"].stderr)

                # Every input is honored.
                honored: list[tuple[dict[str, Any], dict[str, list[str]], dict[str, str]]] = [
                    ({"run_test_matrix": False}, {"scanner-readiness": []}, {}),
                    ({"run_scanners": False}, {"nightly-matrix": NIGHTLY_MATRIX_JOBS}, {}),
                    ({"run_test_matrix": False, "run_scanners": False}, {}, {}),
                    ({"jobs": "fuzz"}, {"nightly-matrix": ["fuzz"]}, {}),
                    ({"scanner_set": "secrets-only", "scanner_fail_policy": "never", "skip_build_scanners": True}, NIGHTLY_ALL_JOBS,
                     {"SCANNER_SET": "secrets-only", "SCANNER_FAIL_POLICY": "never", "SKIP_BUILD_SCANNERS": "true"}),
                ]
                for inputs, jobs, scanner in honored:
                    with self.subTest(caller=event, inputs=inputs):
                        run = self.nightly_run(self.call(NIGHTLY, event, **inputs))
                        self.assertEqual(run["source"][2], fixture.maintained_sha)
                        self.assertEqual(run["jobs"], jobs)
                        self.assertEqual(run["scanner"], dict(defaults, SCANNER_MODE=mode, **scanner))

    def test_called_nightly_run_resolves_each_kind_of_source(self) -> None:
        fixture = self.fixture
        manual_ref = f"refs/heads/{fixture.manual_branch}"
        cases = [
            (fixture.manual_branch, manual_ref, fixture.manual_sha, "requested"),
            (manual_ref, manual_ref, fixture.manual_sha, "requested"),
            (fixture.manual_tag, f"refs/tags/{fixture.manual_tag}", fixture.manual_sha, "requested"),
            (ANNOTATED_TAG, f"refs/tags/{ANNOTATED_TAG}", fixture.maintained_sha, "requested"),
            (fixture.manual_sha, fixture.manual_sha, fixture.manual_sha, "requested"),
            # A hash never names the maintained branch, even at its tip.
            (fixture.maintained_sha, fixture.maintained_sha, fixture.maintained_sha, "requested"),
            (svc.MAINTAINED_REF, svc.MAINTAINED_REF, fixture.maintained_sha, "maintained"),
            (f" {svc.MAINTAINED_BRANCH} ", svc.MAINTAINED_REF, fixture.maintained_sha, "maintained"),
        ]
        # A dispatched caller: github.ref and github.sha are main's.
        for source_ref, requested_ref, resolved_sha, mode in cases:
            with self.subTest(source_ref=source_ref):
                run = self.nightly_run(self.call(NIGHTLY, "workflow_dispatch", source_ref=source_ref))
                self.assertEqual(run["resolvers"], [REQUESTED_STEP])
                self.assertEqual(run["source"], (mode, requested_ref, resolved_sha))
                self.assertIn(f"| source_ref input | {source_ref.strip()} |", run["summary"])
                self.assertIn(f"| source_mode | {mode} |", run["summary"])
                self.assertEqual(set(svc.check_source_wiring(self.workflows[NIGHTLY], run["context"]).values()), {resolved_sha})

        rejected = {
            "no-such-branch": "::error::no branch or tag 'no-such-branch'",
            fixture.default_sha[:12]: "::error::no branch or tag",
            AMBIGUOUS_NAME: f"::error::source_ref '{AMBIGUOUS_NAME}' must name exactly one branch or tag",
            "refs/pull/1/head": "::error::source_ref 'refs/pull/1/head' must be a branch, a tag or a full commit hash",
            "bad..name": "::error::source_ref 'bad..name' is not a valid ref name",
            "  ": "::error::source_ref is empty",
        }
        for source_ref, message in rejected.items():
            with self.subTest(rejected=source_ref):
                ran, results = self.run_resolver_job(NIGHTLY, self.call(NIGHTLY, "workflow_dispatch", source_ref=source_ref))
                self.assertEqual(ran, [TRIGGER_STEP, REQUESTED_STEP], "a failed resolution ends the job")
                self.assertNotEqual(results["requested"].returncode, 0)
                self.assertIn(message, results["requested"].stderr)
                self.assertNotIn("resolved_sha", results["requested"].outputs)

    def test_nightly_run_cross_checks_how_it_started(self) -> None:
        fixture = self.fixture
        direct = self.dispatch(NIGHTLY)
        cases: list[tuple[str, dict[str, Any], list[str], str]] = []
        for event in CALLER_EVENTS:
            cases += [
                (f"called by a {event} caller with a source_ref", self.call(NIGHTLY, event),
                 [TRIGGER_STEP, REQUESTED_STEP, SELECT_STEP], "| cross-check | passed: called |"),
                # Only @ref tells main's own ci-nightly-heavy.yml calling this copy from a direct run.
                (f"called by main's own copy on {event}", self.call(NIGHTLY, event, caller_workflow=WORKFLOWS[NIGHTLY].name),
                 [TRIGGER_STEP, REQUESTED_STEP, SELECT_STEP], "| cross-check | passed: called |"),
                (f"called by a {event} caller with an empty source_ref", self.call(NIGHTLY, event, source_ref=""),
                 [TRIGGER_STEP], "with an empty source_ref; the caller must pass the branch, tag or commit to validate"),
            ]
        cases += [
            ("direct without a source_ref", direct, [TRIGGER_STEP, svc.RESOLVER_STEP, SELECT_STEP], "| cross-check | passed: direct |"),
            ("direct schedule without a source_ref", self.scheduled(NIGHTLY), [TRIGGER_STEP, svc.RESOLVER_STEP, SELECT_STEP],
             "| cross-check | passed: direct |"),
            ("direct with a source_ref", dict(direct, inputs=dict(direct["inputs"], source_ref=svc.MAINTAINED_BRANCH)),
             [TRIGGER_STEP], f"source_ref '{svc.MAINTAINED_BRANCH}' is set, but this run was not called"),
        ]
        for label, context, steps, expected in cases:
            with self.subTest(label):
                ran, results = self.run_resolver_job(NIGHTLY, context)
                self.assertEqual(ran, steps)
                check = results["trigger"]
                if steps == [TRIGGER_STEP]:
                    self.assertNotEqual(check.returncode, 0)
                    self.assertIn("::error::", check.stderr)
                    self.assertIn(expected, check.stderr)
                    self.assertNotIn(fixture.default_sha, json.dumps({key: result.outputs for key, result in results.items()}))
                else:
                    self.assertEqual(check.returncode, 0, check.stderr)
                    self.assertIn(expected, check.summary)
                    self.assertIn(f"| job.workflow_ref | {context['job']['workflow_ref']} |", check.summary)

        # Without job.workflow_ref the check is skipped and says so, and the
        # source_ref rule alone decides: then a caller's empty source_ref is a
        # direct run on main's ref, which is the gap the check closes.
        for label, context, source in (
            ("called with a source_ref", self.call(NIGHTLY, "workflow_dispatch"),
             ("maintained", svc.MAINTAINED_REF, fixture.maintained_sha)),
            ("direct", self.dispatch(NIGHTLY), ("manual", f"refs/heads/{fixture.manual_branch}", fixture.manual_sha)),
            ("called with an empty source_ref", self.call(NIGHTLY, "workflow_dispatch", source_ref=""),
             ("manual", "refs/heads/main", fixture.default_sha)),
        ):
            for job in ({"status": "success"}, None):
                with self.subTest(f"{label}, job.workflow_ref unavailable", job=job):
                    run = self.nightly_run(dict(context, job=job))
                    self.assertEqual(run["source"], source)
                    self.assertIn("| job.workflow_ref | (not available) |", run["summary"])
                    self.assertIn("| cross-check | skipped: job.workflow_ref is not available |", run["summary"])

    def test_called_nightly_and_pq_resolve_source_ref_alike(self) -> None:
        nightly_step = svc.find_step(self.workflows[NIGHTLY]["jobs"][RESOLVER_JOB], REQUESTED_STEP)
        pq_step = svc.find_step(self.workflows[PQ]["jobs"][RESOLVER_JOB], svc.RESOLVER_STEP)
        self.assertEqual(shell_function(nightly_step["run"], SHARED_RESOLVER), shell_function(pq_step["run"], SHARED_RESOLVER))
        # The caller's ref and commit never reach the called run's resolver.
        for name, value in nightly_step["env"].items():
            self.assertNotRegex(str(value), r"github\.(ref|sha)\b", name)
        self.assertNotRegex(nightly_step["run"], r"GITHUB_(REF|SHA)\b")
        sources = [svc.MAINTAINED_BRANCH, f"refs/tags/{self.fixture.manual_tag}", ANNOTATED_TAG, self.fixture.manual_sha,
                   "no-such-branch", AMBIGUOUS_NAME, "refs/pull/1/head", "bad..name", self.fixture.manual_sha[:12]]
        for source_ref in sources:
            with self.subTest(source_ref=source_ref):
                pq = self.run_resolver(PQ, self.dispatch(PQ, source_ref=source_ref))
                nightly = self.run_resolver_step(NIGHTLY, REQUESTED_STEP, self.call(NIGHTLY, "workflow_dispatch", source_ref=source_ref))
                self.assertEqual(pq.returncode == 0, nightly.returncode == 0, pq.stderr + nightly.stderr)
                if pq.returncode == 0:
                    for output in ("requested_ref", "resolved_sha"):
                        self.assertEqual(pq.outputs[output], nightly.outputs[output])
                else:
                    self.assertEqual(pq.stderr.strip().splitlines()[-1], nightly.stderr.strip().splitlines()[-1])

    def test_direct_nightly_runs_keep_their_source_and_settings(self) -> None:
        fixture = self.fixture
        # A direct scheduled run: the maintained branch, the repository variables and the scheduled defaults.
        scheduled = {"SCANNER_SET": "minimum", "SCANNER_FAIL_POLICY": "infra-and-secrets", "SKIP_BUILD_SCANNERS": "true",
                     "SCANNER_MODE": "nightly"}
        scheduled_cases: tuple[tuple[dict[str, str], dict[str, list[str]]], ...] = (
            ({}, NIGHTLY_ALL_JOBS),
            ({"CI_NIGHTLY_HEAVY_RUN_TEST_MATRIX": "true", "CI_NIGHTLY_HEAVY_RUN_SCANNERS": "true"}, NIGHTLY_ALL_JOBS),
            ({"CI_NIGHTLY_HEAVY_RUN_TEST_MATRIX": "false"}, {"scanner-readiness": []}),
            ({"CI_NIGHTLY_HEAVY_RUN_SCANNERS": "false"}, {"nightly-matrix": NIGHTLY_MATRIX_JOBS}),
            (NIGHTLY_VARS_OFF, {}),
        )
        for variables, jobs in scheduled_cases:
            with self.subTest(trigger="schedule", variables=variables):
                run = self.nightly_run(self.scheduled(NIGHTLY, vars=variables))
                self.assertEqual(run["resolvers"], [svc.RESOLVER_STEP])
                self.assertEqual(run["source"], ("maintained", svc.MAINTAINED_REF, fixture.maintained_sha))
                self.assertEqual(run["jobs"], jobs)
                self.assertEqual(run["scanner"], scheduled)
                self.assertEqual(run["group"], "nightly-heavy-nightly-1.x.x")

        # A direct dispatch: manual mode on the selected ref and its commit, following its inputs, not the variables.
        manual = ("manual", f"refs/heads/{fixture.manual_branch}", fixture.manual_sha)
        dispatched = {"SCANNER_SET": "minimum", "SCANNER_FAIL_POLICY": "infra-and-secrets", "SKIP_BUILD_SCANNERS": "false",
                      "SCANNER_MODE": "manual_dry_run"}
        dispatched_cases: tuple[tuple[dict[str, Any], dict[str, list[str]], dict[str, str]], ...] = (
            ({}, NIGHTLY_ALL_JOBS, {}),
            ({"run_test_matrix": False, "skip_build_scanners": True}, {"scanner-readiness": []}, {"SKIP_BUILD_SCANNERS": "true"}),
            ({"run_scanners": False, "jobs": "previous-releases"}, {"nightly-matrix": ["previous-releases"]}, {}),
        )
        for inputs, jobs, scanner in dispatched_cases:
            with self.subTest(trigger="workflow_dispatch", inputs=inputs):
                run = self.nightly_run(dict(self.dispatch(NIGHTLY, **inputs), vars=NIGHTLY_VARS_OFF))
                self.assertEqual(run["resolvers"], [svc.RESOLVER_STEP])
                self.assertEqual(run["source"], manual)
                self.assertEqual(run["jobs"], jobs)
                self.assertEqual(run["scanner"], dict(dispatched, **scanner))
                self.assertEqual(run["group"], f"nightly-heavy-refs/heads/{fixture.manual_branch}")

        # The verify step records that no source_ref was given.
        run = self.nightly_run(self.scheduled(NIGHTLY))
        fixture.checkout_work(fixture.maintained_sha)
        context = svc.matrix_context(self.workflows[NIGHTLY], "nightly-matrix", run["context"])
        verify = svc.run_job_step(fixture, self.workflows[NIGHTLY], "nightly-matrix", svc.VERIFY_STEP, context, fixture.work)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn("- source_ref input: (none)\n- source_mode: maintained\n", verify.summary)

    def test_nightly_concurrency_keeps_sources_and_callers_apart(self) -> None:
        fixture = self.fixture
        workflow = self.workflows[NIGHTLY]

        def group(context: dict[str, Any]) -> str:
            return svc._to_text(svc.render(workflow["concurrency"]["group"], context))

        groups = {
            "direct schedule": group(self.scheduled(NIGHTLY)),
            "direct dispatch": group(self.dispatch(NIGHTLY)),
            "scheduled caller": group(self.call(NIGHTLY, "schedule")),
            "dispatched caller, maintained branch": group(self.call(NIGHTLY, "workflow_dispatch")),
            "dispatched caller, branch": group(self.call(NIGHTLY, "workflow_dispatch", source_ref=fixture.manual_branch)),
            "dispatched caller, tag": group(self.call(NIGHTLY, "workflow_dispatch", source_ref=fixture.manual_tag)),
            "dispatched caller, commit": group(self.call(NIGHTLY, "workflow_dispatch", source_ref=fixture.manual_sha)),
        }
        self.assertEqual(len(set(groups.values())), len(groups), groups)
        self.assertEqual(groups["scheduled caller"], "nightly-heavy-call-schedule-1.x.x")
        self.assertEqual(groups["dispatched caller, branch"], f"nightly-heavy-call-workflow_dispatch-{fixture.manual_branch}")
        # A second call for the same source still replaces the one in progress.
        self.assertEqual(group(self.call(NIGHTLY, "workflow_dispatch", source_ref=fixture.manual_branch, jobs="fuzz")),
                         groups["dispatched caller, branch"])
        # The group is evaluated before any job runs, from the contexts GitHub allows there.
        self.assertNotRegex(workflow["concurrency"]["group"], r"\b(needs|steps|env|job)\.")

    def test_rejects_unknown_repeated_and_empty_job_names(self) -> None:
        bad = {
            PQ: ["aarch64", "AARCH64-UNIT", f"{AARCH64_JOB},{AARCH64_JOB}", f"{AARCH64_JOB},", ",", "s390x-unit"],
            NIGHTLY: ["previous_releases", "previous-releases,previous-releases", "previous-releases,,fuzz", "unit"],
        }
        for key, values in bad.items():
            for value in values:
                with self.subTest(workflow=key, jobs=value):
                    result = self.run_select(key, self.dispatch(key, jobs=value))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("::error::", result.stderr)
                    self.assertNotIn("matrix", result.outputs)

    # -- source resolution ---------------------------------------------------------

    def test_source_ref_resolves_once_to_a_commit(self) -> None:
        fixture = self.fixture
        cases = [
            ("", f"refs/heads/{fixture.manual_branch}", fixture.manual_sha, "event"),
            (svc.MAINTAINED_BRANCH, svc.MAINTAINED_REF, fixture.maintained_sha, "ref"),
            (f"  {svc.MAINTAINED_BRANCH} ", svc.MAINTAINED_REF, fixture.maintained_sha, "ref"),
            (svc.MAINTAINED_REF, svc.MAINTAINED_REF, fixture.maintained_sha, "ref"),
            (ANNOTATED_TAG, f"refs/tags/{ANNOTATED_TAG}", fixture.maintained_sha, "ref"),
            (fixture.manual_tag, f"refs/tags/{fixture.manual_tag}", fixture.manual_sha, "ref"),
            (fixture.default_sha, fixture.default_sha, fixture.default_sha, "commit"),
        ]
        for source_ref, requested_ref, resolved_sha, mode in cases:
            with self.subTest(source_ref=source_ref):
                result = self.run_resolver(PQ, self.dispatch(PQ, source_ref=source_ref))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.outputs["requested_ref"], requested_ref)
                self.assertEqual(result.outputs["resolved_sha"], resolved_sha)
                self.assertEqual(result.outputs["source_mode"], mode)
                self.assertIn(f"| resolved_sha | {resolved_sha} |", result.summary)
        # The annotated tag is peeled: its tag object is not what gets checked out.
        self.assertNotEqual(self.tag_object, fixture.maintained_sha)

        rejected = {
            "no-such-branch": "no branch or tag 'no-such-branch'",
            fixture.default_sha[:12]: "no branch or tag",
            AMBIGUOUS_NAME: "must name exactly one branch or tag",
            "refs/pull/1/head": "must be a branch, a tag or a full commit hash",
            "bad..name": "is not a valid ref name",
        }
        for source_ref, message in rejected.items():
            with self.subTest(rejected=source_ref):
                result = self.run_resolver(PQ, self.dispatch(PQ, source_ref=source_ref))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"::error::source_ref '{source_ref}' " if "source_ref" in message else "::error::", result.stderr)
                self.assertIn(message, result.stderr)
                self.assertNotIn("resolved_sha", result.outputs)

    def test_every_pq_job_checks_out_the_resolved_commit(self) -> None:
        fixture = self.fixture
        workflow = self.workflows[PQ]
        context = self.resolve(PQ, self.dispatch(PQ, source_ref=svc.MAINTAINED_BRANCH, jobs=AARCH64_JOB))
        refs = svc.check_source_wiring(workflow, context)
        self.assertEqual(refs, {PQ_UNIT_JOB: fixture.maintained_sha})

        mutated = copy.deepcopy(workflow)
        checkout = svc.find_step(mutated["jobs"][PQ_UNIT_JOB], svc.CHECKOUT_STEP)
        checkout["with"]["ref"] = "${{ github.sha }}"
        with self.assertRaises(AssertionError):
            svc.check_source_wiring(mutated, context)

        job_context = dict(context, matrix=catalog(workflow)[0])
        fixture.checkout_work(fixture.maintained_sha)
        guard = svc.run_job_step(fixture, workflow, PQ_UNIT_JOB, svc.GUARD_STEP, job_context, fixture.root)
        self.assertEqual(guard.returncode, 0, guard.stderr)
        verify = svc.run_job_step(fixture, workflow, PQ_UNIT_JOB, svc.VERIFY_STEP, job_context, fixture.work)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn(f"- actual_head: {fixture.maintained_sha}", verify.summary)

        # A checkout that moved (for example a branch push between jobs) is refused.
        fixture.checkout_work(fixture.manual_sha)
        verify = svc.run_job_step(fixture, workflow, PQ_UNIT_JOB, svc.VERIFY_STEP, job_context, fixture.work)
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("does not match resolved source", verify.stderr)

    # -- the aarch64 job and its suites ----------------------------------------------

    def test_aarch64_job_runs_on_a_public_arm_runner(self) -> None:
        workflow = self.workflows[PQ]
        (entry,) = [entry for entry in catalog(workflow) if entry["job"] == AARCH64_JOB]
        self.assertEqual(entry["runs-on"], "ubuntu-24.04-arm")
        self.assertIn("pre-library", entry["name"])
        env_file = entry["file-env"]
        self.assertTrue(os.access(REPO_ROOT / env_file, os.X_OK), env_file)

        context = dict(self.resolve(PQ, self.dispatch(PQ, jobs=AARCH64_JOB)), matrix=entry)
        env = svc.job_env(workflow, workflow["jobs"][PQ_UNIT_JOB], context)
        self.assertEqual(env["FILE_ENV"], env_file)
        self.assertEqual(env["CI_IMAGE_REGISTRY_PREFIX"], "docker.io/library")
        self.assertEqual(env["CI_ENFORCE_INTERNAL_REGISTRY"], "0")
        self.assertEqual(env["CI_PROFILE"], "public")
        self.assertNotIn("100.100.100.100", env["CI_BUILDKIT_DNS_NAMESERVERS"])
        self.assertNotIn("ts.net", env["CI_BUILDKIT_DNS_SEARCH_DOMAINS"])
        self.assertEqual(env["DANGER_CI_ON_HOST_FOLDERS"], "1", "the evidence must reach the host through BASE_BUILD_DIR")

        names = ["CI_BUILD_TARGET", "CTEST_REGEX", "CTEST_EXPECTED_SUITES", "CTEST_INCLUDE_RANGE", "CI_IMAGE_NAME_TAG", "RUN_FUNCTIONAL_TESTS"]
        effective = source_env(env_file, names, {key: env[key] for key in ("CI_IMAGE_REGISTRY_PREFIX", "CI_ENFORCE_INTERNAL_REGISTRY")})
        self.assertEqual(effective["CI_BUILD_TARGET"], "test_bitcoin")
        self.assertEqual(effective["CTEST_EXPECTED_SUITES"].split(), AARCH64_SUITES)
        self.assertEqual(effective["CTEST_INCLUDE_RANGE"], "")
        self.assertEqual(effective["CI_IMAGE_NAME_TAG"], "docker.io/library/ubuntu:24.04")
        self.assertEqual(effective["RUN_FUNCTIONAL_TESTS"], "false")
        regex = re.compile(effective["CTEST_REGEX"])
        self.assertEqual([name for name in SUITE_INVENTORY if regex.search(name)], AARCH64_SUITES)

        # 02_run_container.py passes only variables exported by some ci/test/00_setup_env*.sh into the container.
        exported = set()
        for path in (REPO_ROOT / "ci" / "test").glob("00_setup_env*.sh"):
            exported.update(re.findall(r"^\s*export ([A-Z_][A-Z0-9_]*)=", path.read_text(encoding="utf8"), re.M))
        for name in ("CI_BUILD_TARGET", "CTEST_REGEX", "CTEST_EXPECTED_SUITES", "CTEST_INCLUDE_RANGE"):
            self.assertIn(name, exported)

    def test_build_target_reaches_both_build_commands(self) -> None:
        block = shell_block(TEST_SCRIPT.read_text(encoding="utf8"), "CI_BUILD_TARGET=${CI_BUILD_TARGET:-all}", ")")
        for target, expected in (("test_bitcoin", ["test_bitcoin"]), ("", ["all", "install"])):
            with self.subTest(CI_BUILD_TARGET=target):
                run = run_test_script_block(block, {"CI_BUILD_TARGET": target, "STUB_FAIL_FIRST": "1"})
                self.assertNotEqual(run.returncode, 0, "the verbose retry still fails the build")
                builds = [call for call in run.calls if call[:2] == ["cmake", "--build"]]
                self.assertEqual(len(builds), 2, run.completed.stderr)
                for call in builds:
                    targets = call[call.index("--target") + 1:]
                    self.assertEqual([t for t in targets if t != "--verbose"], expected)
                self.assertIn("--verbose", builds[1])

    def test_ctest_selection_reaches_listing_run_and_evidence(self) -> None:
        block = shell_block(TEST_SCRIPT.read_text(encoding="utf8"), 'if [ "$RUN_UNIT_TESTS" = "true" ]; then', "fi")
        regex = "^(bip324_tests|net_tests)$"
        expected = " ".join(AARCH64_SUITES)

        run = run_test_script_block(block, {"CTEST_REGEX": regex, "CTEST_EXPECTED_SUITES": expected})
        self.assertEqual(run.returncode, 0, run.completed.stderr)
        ctest_calls = [call[1:] for call in run.calls if call[0] == "ctest"]
        self.assertEqual(len(ctest_calls), 3)
        listing, human, ran = ctest_calls
        self.assertIn("--show-only=json-v1", listing)
        self.assertIn("--show-only", human)
        for call in ctest_calls:
            self.assertEqual(call[call.index("-R") + 1], regex)
            self.assertNotIn("-I", call)
        self.assertIn("--no-tests=error", ran)
        self.assertIn("--output-junit", ran)
        summary = run.files["summary.md"]
        for suite in AARCH64_SUITES:
            self.assertIn(f"| {suite} | passed |", summary)

        failures = {
            "skipped suite": ({"CTEST_REGEX": regex, "CTEST_EXPECTED_SUITES": expected,
                               "STUB_OUTCOMES": json.dumps({"bip324_tests": "notrun"})}, "bip324_tests: skipped"),
            "regex selects too little": ({"CTEST_REGEX": "^(net_tests)$", "CTEST_EXPECTED_SUITES": expected},
                                         "did not select expected suite(s): bip324_tests"),
            "regex selects too much": ({"CTEST_REGEX": "^bip324_tests|^net_tests$", "CTEST_EXPECTED_SUITES": expected},
                                       "not expected: bip324_tests_extra"),
            "suite missing from the build": ({"CTEST_REGEX": "^(bip324_tests|net_tests|mlkem_tests)$",
                                              "CTEST_EXPECTED_SUITES": expected + " mlkem_tests"}, "mlkem_tests"),
            "range and regex together": ({"CTEST_REGEX": regex, "CTEST_INCLUDE_RANGE": "1,2"}, "set only one"),
            "nothing selected": ({"CTEST_REGEX": "^nothing$"}, "No tests were found"),
        }
        for label, (env, message) in failures.items():
            with self.subTest(label):
                run = run_test_script_block(block, env)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(message, run.completed.stderr + run.completed.stdout)
        run = run_test_script_block(block, {"CTEST_REGEX": regex, "CTEST_INCLUDE_RANGE": "1,2"})
        self.assertEqual(run.calls, [], "conflicting selections are rejected before ctest runs")

        # A job without expected suites, such as a range shard, keeps its old behavior.
        run = run_test_script_block(block, {"CTEST_INCLUDE_RANGE": "1,3", "STUB_OUTCOMES": json.dumps({"addrman_tests": "notrun"})})
        self.assertEqual(run.returncode, 0, run.completed.stderr)
        ran = [call[1:] for call in run.calls if call[0] == "ctest"][-1]
        self.assertEqual(ran[ran.index("-I") + 1], "1,3")
        self.assertNotIn("summary.md", run.files)

    def test_report_step_publishes_source_and_suites(self) -> None:
        fixture = self.fixture
        workflow = self.workflows[PQ]
        context = self.resolve(PQ, self.dispatch(PQ, jobs=AARCH64_JOB))
        entry = catalog(workflow)[0]
        job_context = dict(context, matrix=entry)
        step = svc.find_step(workflow["jobs"][PQ_UNIT_JOB], REPORT_STEP)
        self.assertEqual(step.get("if"), "${{ always() }}")
        # The step reads the file 03_test_script.sh writes.
        self.assertIn('CTEST_EVIDENCE_DIR="${BASE_BUILD_DIR}/ctest-evidence"', TEST_SCRIPT.read_text(encoding="utf8"))
        self.assertIn('--summary "${CTEST_EVIDENCE_DIR}/summary.md"', TEST_SCRIPT.read_text(encoding="utf8"))
        with tempfile.TemporaryDirectory(dir=fixture.root) as tmp:
            build = Path(tmp)
            env = svc.step_env(workflow, workflow["jobs"][PQ_UNIT_JOB], step, job_context)
            env["BASE_BUILD_DIR"] = str(build)
            github_env = svc.github_env_for(job_context, PQ_UNIT_JOB, workflow["name"])
            missing = svc.run_step(fixture, step, env, fixture.root, github_env)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("No unit-test evidence was produced.", missing.summary)

            (build / "ctest-evidence").mkdir()
            (build / "ctest-evidence" / "summary.md").write_text("| bip324_tests | passed | 0.5 |\n", encoding="utf8")
            report = svc.run_step(fixture, step, env, fixture.root, github_env)
            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertIn(f"- source: {fixture.manual_sha} (refs/heads/{fixture.manual_branch})", report.summary)
            self.assertIn("Pre-library phase", report.summary)
            self.assertIn("| bip324_tests | passed | 0.5 |", report.summary)

    def test_required_gate_runs_the_contracts(self) -> None:
        gate = svc.load_workflow(GATE_WORKFLOW)
        commands = [step.get("run", "") for step in gate["jobs"]["classify-changes"]["steps"]]
        for contract in ("ci/checks/test_ci_pq_contract.py", "ci/checks/test_scheduled_validation_contract.py"):
            self.assertTrue(any(contract in command for command in commands), contract)


class CtestEvidenceTest(unittest.TestCase):
    """ctest_evidence.py against JUnit in the format ctest --output-junit writes."""

    @staticmethod
    def junit(*cases: tuple[str, str, str]) -> str:
        body = "".join(f'<testcase name="{name}" classname="{name}" time="0.1" status="{status}">{inner}</testcase>'
                       for name, status, inner in cases)
        return f'<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="(empty)">{body}</testsuite>\n'

    def test_outcomes(self) -> None:
        outcomes = ctest_evidence.junit_outcomes(self.junit(
            ("passed_suite", "run", "<system-out/>"),
            ("skipped_suite", "notrun", '<skipped message="SKIP_REGULAR_EXPRESSION_MATCHED"/>'),
            ("failed_suite", "fail", '<failure message="Failed"/>'),
            ("disabled_suite", "disabled", "<system-out>Disabled</system-out>"),
            ("odd_suite", "weird", ""),
        ))
        self.assertEqual({name: outcome for name, (outcome, _) in outcomes.items()}, {
            "passed_suite": "passed",
            "skipped_suite": "skipped",
            "failed_suite": "failed",
            "disabled_suite": "disabled",
            "odd_suite": "unknown status 'weird'",
        })
        twice = ctest_evidence.junit_outcomes(self.junit(("a", "run", ""), ("a", "run", "")))
        self.assertEqual(twice["a"][0], "reported more than once")

    def test_check(self) -> None:
        passed = {"a": ("passed", "1"), "b": ("passed", "2")}
        self.assertEqual(ctest_evidence.check(["a", "b"], ["a", "b"], passed), [])
        self.assertEqual(ctest_evidence.check(["a", "b"], ["a"], {"a": ("passed", "1")}),
                         ["ctest did not select expected suite(s): b", "b: missing from the JUnit results"])
        self.assertEqual(ctest_evidence.check(["a"], ["a", "c"], passed), ["ctest selected suite(s) that are not expected: c"])
        self.assertEqual(ctest_evidence.check(["a"], ["a"], {"a": ("skipped", "0")}), ["a: skipped"])
        with self.assertRaises(ValueError):
            ctest_evidence.parse_expected("")
        with self.assertRaises(ValueError):
            ctest_evidence.parse_expected("a b a")

    def test_main_reports_unreadable_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            listing = root / "selected.json"
            junit = root / "junit.xml"
            summary = root / "summary.md"
            listing.write_text(json.dumps({"tests": [{"name": "a"}]}), encoding="utf8")
            junit.write_text("<testsuite><testcase", encoding="utf8")
            args = ["--expected", "a", "--listing", str(listing), "--junit", str(junit), "--summary", str(summary)]

            def main() -> int:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    return ctest_evidence.main(args)

            self.assertEqual(main(), 1)
            self.assertIn("unreadable JUnit results", summary.read_text(encoding="utf8"))
            junit.write_text(self.junit(("a", "run", "")), encoding="utf8")
            self.assertEqual(main(), 0)
            self.assertIn("| a | passed | 0.1 |", summary.read_text(encoding="utf8"))
            listing.unlink()
            self.assertEqual(main(), 1)
            self.assertIn("unreadable ctest test listing", summary.read_text(encoding="utf8"))



class FuzzReplayContractTest(unittest.TestCase):
    """The fuzz phase of 03_test_script.sh replays the ML-KEM targets on portable C too (#190 D5)."""

    STUB_RUNNER = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a", encoding="utf8") as log:
    log.write(json.dumps({"args": sys.argv[1:], "MLKEM_FORCE_PORTABLE": os.environ.get("MLKEM_FORCE_PORTABLE")}) + "\n")
'''

    @staticmethod
    def fuzz_block() -> str:
        """The last RUN_FUZZ_TESTS block of 03_test_script.sh: the replay and mutation phase."""
        lines = TEST_SCRIPT.read_text(encoding="utf8").splitlines()
        first = max(index for index, line in enumerate(lines) if line == 'if [ "$RUN_FUZZ_TESTS" = "true" ]; then')
        last = next(index for index in range(first + 1, len(lines)) if lines[index] == "fi")
        return "\n".join(lines[first:last + 1]) + "\n"

    @staticmethod
    def required_targets() -> list[str]:
        """QBIT_REQUIRED_CORPUS_TARGETS from test/fuzz/test_runner.py, read without importing it."""
        import ast
        tree = ast.parse((REPO_ROOT / "test" / "fuzz" / "test_runner.py").read_text(encoding="utf8"))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "QBIT_REQUIRED_CORPUS_TARGETS" for t in node.targets):
                return list(ast.literal_eval(node.value))
        raise AssertionError("QBIT_REQUIRED_CORPUS_TARGETS not found")

    def run_block(self, mutate_min_time: str) -> list[dict[str, Any]]:
        with tempfile.TemporaryDirectory(prefix="ci-fuzz-") as tmp:
            root = Path(tmp)
            runner = root / "build" / "test" / "fuzz" / "test_runner.py"
            runner.parent.mkdir(parents=True)
            runner.write_text(self.STUB_RUNNER, encoding="utf8")
            runner.chmod(0o755)
            log = root / "calls.jsonl"
            log.touch()
            env = {"PATH": os.environ["PATH"], "HOME": tmp, "LC_ALL": "C", "RUN_FUZZ_TESTS": "true",
                   "BASE_BUILD_DIR": str(root / "build"), "DEPENDS_DIR": str(root / "depends"), "HOST": "x86_64-pc-linux-gnu",
                   "MAKEJOBS": "-j2", "DIR_FUZZ_IN": str(root / "corpora"), "FUZZ_TESTS_CONFIG": "",
                   "QBIT_FUZZ_MUTATE_MIN_TIME": mutate_min_time, "STUB_LOG": str(log)}
            script = root / "block.sh"
            script.write_text("set -ex\n" + self.fuzz_block(), encoding="utf8")
            completed = subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return [json.loads(line) for line in log.read_text(encoding="utf8").splitlines()]

    def test_mlkem_targets_replay_on_portable_c(self) -> None:
        replay, portable = self.run_block(mutate_min_time="")
        self.assertIn("--require_qbit_corpus", replay["args"])
        self.assertIsNone(replay["MLKEM_FORCE_PORTABLE"])
        self.assertEqual(portable["MLKEM_FORCE_PORTABLE"], "1")
        self.assertEqual(portable["args"][-2:], ["mlkem", "mlkem_backend_diff"])
        corpus = [arg for arg in replay["args"] if arg.endswith("/corpora")]
        self.assertEqual(len(corpus), 1, replay["args"])
        self.assertIn(corpus[0], portable["args"], "the portable replay uses the same corpus")

    def test_mutation_phase_covers_every_required_target(self) -> None:
        calls = self.run_block(mutate_min_time="60")
        self.assertEqual(len(calls), 3)
        mutate = calls[2]
        self.assertIn("--mutate_min_time=60", mutate["args"])
        self.assertIsNone(mutate["MLKEM_FORCE_PORTABLE"])
        targets = self.required_targets()
        self.assertIn("mlkem", targets)
        self.assertEqual(mutate["args"][-len(targets):], targets)


if __name__ == "__main__":
    unittest.main()
