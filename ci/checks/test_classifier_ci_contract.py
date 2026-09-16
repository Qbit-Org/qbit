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

# ``unittest -v`` reports ``<method> (<class>[.<method>]) ... <result>``
# depending on the Python version.  Stderr written while a test runs pushes
# the result onto a later line, so match the header and result separately.
VERBOSE_HEADER = re.compile(r"^(?P<name>test_\w+) \((?P<qualified>[\w.]+)\) \.\.\. ")
VERBOSE_RESULT = re.compile(r"^(?:ok|FAIL|ERROR|skipped(?: .*)?|expected failure|unexpected success)$")
RAN_LINE = re.compile(r"^Ran (?P<count>\d+) tests? in ")

# The gate step may learn dependency results and classifier outputs only
# through ``needs`` bindings.  A literal or any other expression would let the
# gate pass without consulting the classifier, so nothing else is accepted.
NEEDS_BINDING = re.compile(
    r"^\$\{\{ needs\.(?P<job>[\w-]+)\.(?:result|outputs\.(?P<output>\w+)) \}\}$"
)
GATE_DEPENDENCY_INPUTS = frozenset(
    {
        "CLASSIFY_CHANGES_RESULT",
        "OPERATOR_KEY_POLICY_VALIDATION_RESULT",
        "RELEASE_POLICY_VALIDATION_RESULT",
        "RPC_DOCS_VALIDATION_RESULT",
        "PUBLIC_DOCS_VALIDATION_RESULT",
        "GITHUB_METADATA_VALIDATION_RESULT",
        "VALIDATION_PROFILE",
        "SOURCE_VALIDATION_REQUIRED",
        "TOUCHED_OPERATOR_KEYS",
    }
)


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


def executed_test_ids(stderr: str) -> dict[str, str]:
    """Map each full test ID reported by unittest -v to its result word.

    A method whose result never appears (for example the process died) is
    recorded as ``unknown`` so it is never mistaken for a pass.
    """
    results: dict[str, str] = {}
    pending: str | None = None
    for line in stderr.splitlines():
        header = VERBOSE_HEADER.match(line)
        if header:
            method = header.group("name")
            pending = header.group("qualified")
            if not pending.endswith(f".{method}"):
                pending = f"{pending}.{method}"
            # Direct script execution uses __main__; discovery imports the module.
            if pending.startswith("__main__."):
                pending = CLASSIFIER_SUITE.stem + pending[len("__main__"):]
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


def expected_suite_ids() -> set[str]:
    """Discover the classifier suite's full test IDs with the real unittest loader."""
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
            names.add(item.id())
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

    def gate_env(self, fake_gh_dir: Path, needs: dict[str, dict], **github: str) -> dict[str, str]:
        """Evaluate the gate step's env bindings against a fake ``needs`` context.

        Values are never assigned directly: each modeled input must be bound
        to ``needs.<job>.result`` or ``needs.<job>.outputs.<name>`` of a
        modeled dependency, and takes the value that binding yields.
        """
        step_env = self.gate_step()["env"]
        missing = GATE_DEPENDENCY_INPUTS - set(step_env)
        self.assertFalse(missing, f"modeled gate inputs not read by the gate step: {sorted(missing)}")
        env = {}
        for key, binding in step_env.items():
            if key not in GATE_DEPENDENCY_INPUTS:
                env[key] = github.get(key, "")
                continue
            match = NEEDS_BINDING.match(str(binding))
            self.assertIsNotNone(
                match,
                f"gate env {key} must be exactly a needs.<job>.result or "
                f"needs.<job>.outputs.<name> binding, got {binding!r}",
            )
            job, output = match.group("job"), match.group("output")
            self.assertIn(job, needs, f"gate env {key} is bound to {binding!r}, not a modeled dependency")
            if output is None:
                env[key] = needs[job]["result"]
            else:
                self.assertIn(output, self.jobs[job].get("outputs", {}), f"gate env {key}: {binding!r} reads an undeclared output")
                env[key] = needs[job]["outputs"].get(output, "")
        env["PATH"] = f"{fake_gh_dir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["HOME"] = os.environ.get("HOME", "")
        return env

    def modeled_needs(self, classification: str) -> dict[str, dict]:
        """Fake ``needs`` context as GitHub reports it when classification is not a success.

        Every lightweight validation job is gated on
        ``needs.classify-changes.result == 'success'`` so it is reported as
        ``skipped``; job-level outputs that were never written read as empty.
        """
        needs: dict[str, dict] = {CLASSIFY_JOB: {"result": classification, "outputs": {}}}
        for name, job in self.jobs.items():
            if name in (CLASSIFY_JOB, GATE_JOB):
                continue
            self.assertIn(
                f"needs.{CLASSIFY_JOB}.result == 'success'",
                str(job.get("if", "")),
                f"{name} must be conditioned on a successful classification",
            )
            needs[name] = {"result": "skipped", "outputs": {}}
        return needs

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

        expected = expected_suite_ids()
        self.assertGreaterEqual(len(expected), 24, "classifier suite lost existing test methods")

        completed = run_bash_step(step["run"], cwd=REPO_ROOT, env=dict(os.environ))
        observed = executed_test_ids(completed.stderr)
        self.assertEqual(
            completed.returncode,
            0,
            f"workflow step failed against the checked-out classifier\n{completed.stderr}",
        )
        self.assertEqual(set(observed), expected, "workflow step did not execute every suite method")
        self.assertEqual({result for result in observed.values()}, {"ok"}, observed)
        self.assertEqual(ran_count(completed.stderr), len(expected), completed.stderr)

    def test_job_level_gating_cannot_bypass_classifier_failure(self) -> None:
        classify = self.jobs[CLASSIFY_JOB]
        self.assertNotIn(
            "continue-on-error",
            classify,
            f"{CLASSIFY_JOB} job must not report success when its steps fail (job-level continue-on-error)",
        )
        self.assertNotIn("if", classify, f"{CLASSIFY_JOB} job must run unconditionally")

        # A job skipped by its own condition is reported as a success, so the
        # gate may never be conditioned on a dependency result.
        gate_if = str(self.jobs[GATE_JOB].get("if", ""))
        self.assertIn("always()", gate_if, f"{GATE_JOB} must run even when classification fails")
        self.assertNotIn(
            "needs.",
            gate_if,
            f"{GATE_JOB} 'if' must not depend on a dependency result, got {gate_if!r}",
        )

    def test_suite_failure_reaches_required_gate(self) -> None:
        _, step = self.classifier_test_step()
        expected = expected_suite_ids()

        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir) / "checkout"
            (sandbox / CHECKS_DIR).mkdir(parents=True)
            shutil.copy(REPO_ROOT / CLASSIFIER, sandbox / CLASSIFIER)
            shutil.copy(REPO_ROOT / CLASSIFIER_SUITE, sandbox / CLASSIFIER_SUITE)

            # The unmodified copy must pass in the sandbox, so a later failure
            # is attributable to the injected assertion and nothing else.
            control = run_bash_step(step["run"], cwd=sandbox, env=dict(os.environ))
            self.assertEqual(control.returncode, 0, f"sandbox control run failed\n{control.stderr}")
            self.assertEqual(set(executed_test_ids(control.stderr)), expected)

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
            observed = executed_test_ids(failed.stderr)
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
                    env = self.gate_env(fake, self.modeled_needs(classification))
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
            metadata = self.modeled_needs("success")
            metadata[CLASSIFY_JOB]["outputs"]["profile"] = "github-metadata"
            metadata["github-metadata-validation"]["result"] = "success"
            completed = run_bash_step(gate["run"], cwd=sandbox, env=self.gate_env(fake, metadata))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertFalse(calls.exists(), "github-metadata profile must not poll checks")

            rpc_docs = self.modeled_needs("success")
            rpc_docs[CLASSIFY_JOB]["outputs"]["profile"] = "rpc-docs"
            rpc_docs["rpc-docs-validation"]["result"] = "success"
            env = self.gate_env(fake, rpc_docs, REPOSITORY="example/repo", SHA="0" * 40)
            completed = run_bash_step(gate["run"], cwd=sandbox, env=env)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(calls.exists(), "rpc-docs profile must poll the simulated check API")
            self.assertIn("rpc-docs: status=completed conclusion=success", completed.stdout)


class ClassifierSuiteIdentityTest(unittest.TestCase):
    def test_verbose_ids_preserve_classes_and_results(self) -> None:
        for module in ("__main__", CLASSIFIER_SUITE.stem):
            for suffix in ("", ".test_shared"):
                with self.subTest(module=module, suffix=suffix):
                    output = (
                        f"test_shared ({module}.First{suffix}) ... ok\n"
                        f"test_shared ({module}.Second{suffix}) ... diagnostic\nFAIL\n"
                        f"test_shared ({module}.Third{suffix}) ... interrupted\n"
                    )
                    self.assertEqual(executed_test_ids(output), {
                        f"{CLASSIFIER_SUITE.stem}.First.test_shared": "ok",
                        f"{CLASSIFIER_SUITE.stem}.Second.test_shared": "FAIL",
                        f"{CLASSIFIER_SUITE.stem}.Third.test_shared": "unknown",
                    })

    def test_contract_accepts_duplicate_methods_but_rejects_omitted_class(self) -> None:
        contract = Path(__file__).relative_to(REPO_ROOT)
        workflow_path = WORKFLOW.relative_to(REPO_ROOT)
        method = sorted(expected_suite_ids())[0].rsplit(".", 1)[-1]
        extra_class = (
            "class DuplicateMethodNamesTest(unittest.TestCase):\n"
            f"    def {method}(self) -> None:\n"
            "        pass\n\n\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            for relative in (CLASSIFIER, CLASSIFIER_SUITE, contract, workflow_path):
                target = sandbox / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(REPO_ROOT / relative, target)
            suite = sandbox / CLASSIFIER_SUITE
            source = suite.read_text(encoding="utf8")
            entrypoint = 'if __name__ == "__main__":'
            self.assertEqual(source.count(entrypoint), 1)
            suite.write_text(source.replace(entrypoint, extra_class + entrypoint), encoding="utf8")

            command = [
                sys.executable, str(contract),
                "ClassifierCiContractTest.test_workflow_executes_all_classifier_tests", "-v",
            ]
            completed = subprocess.run(
                command, cwd=sandbox, text=True, capture_output=True,
                timeout=SUBPROCESS_TIMEOUT_SECONDS, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            # Running only the original class must still fail the completeness check.
            workflow = load_workflow()
            for step in workflow["jobs"][CLASSIFY_JOB]["steps"]:
                if str(CLASSIFIER_SUITE) in str(step.get("run", "")):
                    step["run"] = step["run"].rstrip() + " -k ClassifyMergeProfileTest\n"
            (sandbox / workflow_path).write_text(yaml.safe_dump(workflow), encoding="utf8")
            completed = subprocess.run(
                command, cwd=sandbox, text=True, capture_output=True,
                timeout=SUBPROCESS_TIMEOUT_SECONDS, check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("workflow step did not execute every suite method", completed.stderr)
            self.assertIn("DuplicateMethodNamesTest", completed.stderr)


if __name__ == "__main__":
    unittest.main()
