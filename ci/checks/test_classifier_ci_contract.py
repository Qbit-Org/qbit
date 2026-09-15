#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract tests: the Required Merge Gate runs the classifier's own tests.

The merge-profile classifier decides which validation profile routes a
change.  These tests prove, against the actual workflow file, that:

* the ``classify-changes`` job executes every method of
  ``test_classify_merge_profile.py`` before it produces routing outputs, and
* a failing classifier suite fails that job, which the gate shell turns into
  a failed Required Merge Gate rather than a lightweight routing decision.

Only the ``gh`` check-run polling is simulated.  Whether the hosted check is
attached to a branch ruleset cannot be proven here.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github/workflows/required-merge-gate.yml"
CHECKS_DIR = Path("ci/checks")
CLASSIFIER = CHECKS_DIR / "classify_merge_profile.py"
CLASSIFIER_SUITE = CHECKS_DIR / "test_classify_merge_profile.py"
CLASSIFY_JOB = "classify-changes"
GATE_JOB = "required-merge-gate"
INJECTED_FAILURE = "injected classifier contract failure"
SUBPROCESS_TIMEOUT_SECONDS = 120

# ``unittest -v`` reports ``<method> (<class>) ... <result>`` per executed
# method.  A test that writes to stderr while running pushes the result word
# onto a later line, so the header and result are matched separately.
VERBOSE_HEADER = re.compile(r"^(?P<name>test_\w+) \([\w.]+\) \.\.\. ")
VERBOSE_RESULT = re.compile(r"^(?:ok|FAIL|ERROR|skipped(?: .*)?|expected failure|unexpected success)$")
RAN_LINE = re.compile(r"^Ran (?P<count>\d+) tests? in ")


class WorkflowLoader(yaml.SafeLoader):
    """SafeLoader that keeps the ``on:`` trigger key as the string ``"on"``.

    YAML 1.1 resolves ``on``/``off``/``yes``/``no`` to booleans; GitHub
    workflows need ``on`` verbatim.  Only ``true``/``false`` stay booleans.
    """


WorkflowLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def load_workflow() -> dict:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf8"), Loader=WorkflowLoader)
    if "on" not in workflow:
        raise AssertionError(f"{WORKFLOW}: trigger key 'on' was not preserved: {sorted(workflow)}")
    return workflow


def run_bash_step(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Execute a workflow ``run:`` block the way GitHub's ``shell: bash`` does."""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf8") as handle:
        handle.write(script)
        script_path = handle.name
    try:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", script_path],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    finally:
        os.unlink(script_path)


def executed_methods(stderr: str) -> dict[str, str]:
    """Map every test method reported by unittest -v to its result word.

    A method whose result never appears (for example the process died) is
    recorded as ``unknown`` so it is never mistaken for a pass.
    """
    results: dict[str, str] = {}
    pending: str | None = None
    for line in stderr.splitlines():
        header = VERBOSE_HEADER.match(line)
        if header:
            pending = header.group("name")
            results[pending] = "unknown"
            line = line[header.end():]
        if pending is not None and VERBOSE_RESULT.match(line.strip()):
            results[pending] = line.strip().split(" ")[0]
            pending = None
    return results


def ran_count(stderr: str) -> int | None:
    for line in stderr.splitlines():
        match = RAN_LINE.match(line)
        if match:
            return int(match.group("count"))
    return None


def expected_suite_methods() -> set[str]:
    """Discover the classifier suite's methods with the real unittest loader."""
    checks_dir = str(REPO_ROOT / CHECKS_DIR)
    if checks_dir not in sys.path:
        sys.path.insert(0, checks_dir)
    import test_classify_merge_profile  # sibling module, path-dependent

    names: set[str] = set()
    stack = [unittest.defaultTestLoader.loadTestsFromModule(test_classify_merge_profile)]
    while stack:
        item = stack.pop()
        if isinstance(item, unittest.TestSuite):
            stack.extend(item)
        else:
            names.add(item._testMethodName)
    return names


class ClassifierCiContractTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.workflow = load_workflow()
        self.assertEqual(
            self.workflow.get("defaults", {}).get("run", {}).get("shell"),
            "bash",
            "contract assumes workflow default shell is bash",
        )
        self.assertIn("pull_request", self.workflow["on"])
        self.jobs = self.workflow["jobs"]
        self.assertIn(CLASSIFY_JOB, self.jobs)
        self.assertIn(GATE_JOB, self.jobs)

    # -- helpers -----------------------------------------------------------

    def classifier_test_step(self) -> tuple[int, dict]:
        steps = self.jobs[CLASSIFY_JOB]["steps"]
        matches = [
            (index, step)
            for index, step in enumerate(steps)
            if str(CLASSIFIER_SUITE) in str(step.get("run", ""))
        ]
        self.assertEqual(
            len(matches),
            1,
            f"{CLASSIFY_JOB} must invoke {CLASSIFIER_SUITE} in exactly one run step, "
            f"found {[step.get('name') for _, step in matches]}",
        )
        return matches[0]

    def routing_step_indexes(self) -> list[int]:
        """Indexes of steps whose outputs feed the job-level routing outputs."""
        job = self.jobs[CLASSIFY_JOB]
        ids = set()
        for expression in job["outputs"].values():
            ids.update(re.findall(r"steps\.([\w-]+)\.outputs\.", str(expression)))
        self.assertTrue(ids, f"{CLASSIFY_JOB} outputs reference no steps")
        indexes = [i for i, step in enumerate(job["steps"]) if step.get("id") in ids]
        self.assertEqual(len(indexes), len(ids), f"routing steps {sorted(ids)} not all present")
        return indexes

    def gate_step(self) -> dict:
        job = self.jobs[GATE_JOB]
        self.assertIn(
            "always()",
            str(job.get("if", "")),
            f"{GATE_JOB} must run even when classification fails",
        )
        self.assertIn(CLASSIFY_JOB, job["needs"])
        matches = [step for step in job["steps"] if "CLASSIFY_CHANGES_RESULT" in step.get("env", {})]
        self.assertEqual(len(matches), 1, "expected one gate step reading CLASSIFY_CHANGES_RESULT")
        self.assertNotIn("shell", matches[0])
        return matches[0]

    def gate_env(self, fake_gh_dir: Path, modeled: dict[str, str]) -> dict[str, str]:
        step_env_keys = set(self.gate_step()["env"])
        unknown = set(modeled) - step_env_keys
        self.assertFalse(unknown, f"modeled gate inputs not read by the gate step: {sorted(unknown)}")
        env = {key: "" for key in step_env_keys}
        env.update(modeled)
        env["PATH"] = f"{fake_gh_dir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["HOME"] = os.environ.get("HOME", "")
        return env

    def modeled_dependency_results(self, classification: str) -> dict[str, str]:
        """Dependency results as GitHub reports them when classification is not a success.

        Every lightweight validation job is gated on
        ``needs.classify-changes.result == 'success'`` so it is reported as
        ``skipped`` and the job-level outputs are empty strings.
        """
        for name, job in self.jobs.items():
            if name in (CLASSIFY_JOB, GATE_JOB):
                continue
            self.assertIn(
                f"needs.{CLASSIFY_JOB}.result == 'success'",
                str(job.get("if", "")),
                f"{name} must be conditioned on a successful classification",
            )
        return {
            "CLASSIFY_CHANGES_RESULT": classification,
            "OPERATOR_KEY_POLICY_VALIDATION_RESULT": "skipped",
            "RELEASE_POLICY_VALIDATION_RESULT": "skipped",
            "RPC_DOCS_VALIDATION_RESULT": "skipped",
            "PUBLIC_DOCS_VALIDATION_RESULT": "skipped",
            "GITHUB_METADATA_VALIDATION_RESULT": "skipped",
            "VALIDATION_PROFILE": "",
            "SOURCE_VALIDATION_REQUIRED": "",
            "TOUCHED_OPERATOR_KEYS": "",
        }

    @staticmethod
    def write_fake_gh(directory: Path, *, conclusion: str | None) -> Path:
        """Simulate only the check-run polling API used by the gate shell.

        ``conclusion=None`` makes any call a hard error, proving the gate
        failed before it polled anything.  Each call is appended to ``calls``.
        """
        calls = directory / "calls"
        gh = directory / "gh"
        if conclusion is None:
            body = 'echo "gh must not be called: $*" >&2\nexit 99\n'
        else:
            body = f'printf "completed\\t{conclusion}\\n"\n'
        gh.write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "{calls}"\n{body}', encoding="utf8")
        gh.chmod(0o755)
        return calls

    # -- contract ----------------------------------------------------------

    def test_workflow_executes_all_classifier_tests(self) -> None:
        index, step = self.classifier_test_step()
        self.assertNotIn("uses", step, "classifier suite must run as a plain run step")
        self.assertNotIn("if", step, "classifier suite step must be unconditional")
        self.assertNotIn("shell", step, "classifier suite step must use the workflow default bash shell")
        self.assertNotIn(
            "continue-on-error",
            step,
            "classifier suite step must not swallow failures with continue-on-error",
        )
        for routing_index in self.routing_step_indexes():
            self.assertLess(
                index,
                routing_index,
                "classifier suite must run before the step that produces routing outputs",
            )

        expected = expected_suite_methods()
        self.assertGreaterEqual(len(expected), 24, "classifier suite lost existing test methods")

        completed = run_bash_step(step["run"], cwd=REPO_ROOT, env=dict(os.environ))
        observed = executed_methods(completed.stderr)
        self.assertEqual(
            completed.returncode,
            0,
            f"workflow step failed against the checked-out classifier\n{completed.stderr}",
        )
        self.assertEqual(set(observed), expected, "workflow step did not execute every suite method")
        self.assertEqual({result for result in observed.values()}, {"ok"}, observed)
        self.assertEqual(ran_count(completed.stderr), len(expected), completed.stderr)

    def test_suite_failure_reaches_required_gate(self) -> None:
        _, step = self.classifier_test_step()
        expected = expected_suite_methods()

        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir) / "checkout"
            (sandbox / CHECKS_DIR).mkdir(parents=True)
            shutil.copy(REPO_ROOT / CLASSIFIER, sandbox / CLASSIFIER)
            shutil.copy(REPO_ROOT / CLASSIFIER_SUITE, sandbox / CLASSIFIER_SUITE)

            # The unmodified copy must pass in the sandbox, so a later failure
            # is attributable to the injected assertion and nothing else.
            control = run_bash_step(step["run"], cwd=sandbox, env=dict(os.environ))
            self.assertEqual(control.returncode, 0, f"sandbox control run failed\n{control.stderr}")
            self.assertEqual(set(executed_methods(control.stderr)), expected)

            suite_copy = sandbox / CLASSIFIER_SUITE
            source = suite_copy.read_text(encoding="utf8")
            mutated, injections = re.subn(
                r"^(    def (test_\w+)\(self\) -> None:\n)",
                rf'\1        self.fail("{INJECTED_FAILURE}")\n',
                source,
                count=1,
                flags=re.MULTILINE,
            )
            self.assertEqual(injections, 1, "could not inject a failure into an existing test")
            suite_copy.write_text(mutated, encoding="utf8")

            failed = run_bash_step(step["run"], cwd=sandbox, env=dict(os.environ))
            observed = executed_methods(failed.stderr)
            self.assertNotEqual(failed.returncode, 0, "workflow step swallowed a failing classifier test")
            self.assertIn(INJECTED_FAILURE, failed.stderr)
            self.assertEqual(set(observed), expected, "failure must not stop the remaining methods")
            self.assertEqual([r for r in observed.values() if r != "ok"], ["FAIL"], observed)

            # GitHub reports the job as failure/cancelled, or skipped on a
            # cancelled dependency; the gate shell must reject all of them
            # before any check-run polling.
            gate = self.gate_step()
            for classification in ("failure", "skipped", "cancelled"):
                with self.subTest(classification=classification):
                    fake = Path(tmpdir) / f"gh-{classification}"
                    fake.mkdir()
                    calls = self.write_fake_gh(fake, conclusion=None)
                    env = self.gate_env(fake, self.modeled_dependency_results(classification))
                    completed = run_bash_step(gate["run"], cwd=sandbox, env=env)
                    self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                    self.assertIn(
                        f"Change classification result was {classification}.",
                        completed.stdout,
                    )
                    self.assertFalse(calls.exists(), "gate polled checks despite failed classification")

            # A successful classification still routes a lightweight profile
            # to success: one profile with no polling, one with polling.
            fake = Path(tmpdir) / "gh-success"
            fake.mkdir()
            calls = self.write_fake_gh(fake, conclusion="success")
            metadata = self.modeled_dependency_results("success")
            metadata.update(
                VALIDATION_PROFILE="github-metadata",
                GITHUB_METADATA_VALIDATION_RESULT="success",
            )
            completed = run_bash_step(gate["run"], cwd=sandbox, env=self.gate_env(fake, metadata))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertFalse(calls.exists(), "github-metadata profile must not poll checks")

            rpc_docs = self.modeled_dependency_results("success")
            rpc_docs.update(
                VALIDATION_PROFILE="rpc-docs",
                RPC_DOCS_VALIDATION_RESULT="success",
                REPOSITORY="example/repo",
                SHA="0" * 40,
            )
            completed = run_bash_step(gate["run"], cwd=sandbox, env=self.gate_env(fake, rpc_docs))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(calls.exists(), "rpc-docs profile must poll the simulated check API")
            self.assertIn("rpc-docs: status=completed conclusion=success", completed.stdout)


if __name__ == "__main__":
    unittest.main()
