#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract for the PQ jobs in Full Validation (#184 part 3, work item C3; #222).

Pull requests that touch the ML-KEM library, the v2 transport, or their build
and CI wiring must pass the aarch64-unit, macos-arm64-unit and
macos-x86_64-unit jobs of ci-pq.yml before they merge; others skip all three.
Those, and the pull requests that can break hybrid post-quantum v2 transport
without touching what those jobs build, must also pass ci-pq.yml's
pq-functional job, the whole functional suite with hybrid transport. These
tests run the real pieces of that chain:

* ci/checks/classify_merge_profile.py, as the classify-changes job runs it,
  reports pq_unit_required and pq_functional_required;
* the pq-unit job of ci.yml calls ci-pq.yml with those three jobs on the
  change's own commit (a pull request's merge commit) exactly when
  pq_unit_required is true, and ci-pq.yml then runs exactly those three, so one
  output and one call make each of them required exactly when the others are;
  the pq-functional job of ci.yml does the same with pq-functional alone and
  pq_functional_required;
* full-validation-gate's shell accepts a skipped call only when the classifier
  says it is not required, and fails on a missing classifier output;
* a pull request's changed files reach each job's if and the gate's env
  through classify-changes' outputs;
* Full Validation, the Required Merge Gate and Core Checks list the changed
  files for the classifier with the same git commands, and every list of
  changed files in those workflows names both sides of a rename;
* every CMake file, workflow or ci/ file that mentions ML-KEM classifies as
  requiring the jobs, so new wiring cannot be missed silently, and every path
  the classifier names exists;
* every document that a source check reads classifies as source, so that a
  change to it alone runs the check.

GitHub itself is not called.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import classify_merge_profile
import test_scheduled_validation_contract as svc

REPO_ROOT = svc.REPO_ROOT
CI_WORKFLOW = svc.WORKFLOW_DIR / "ci.yml"
PQ_WORKFLOW = svc.WORKFLOW_DIR / "ci-pq.yml"
GATE_WORKFLOW = svc.WORKFLOW_DIR / "required-merge-gate.yml"
CORE_CHECKS_WORKFLOW = svc.WORKFLOW_DIR / "core-checks.yml"
CLASSIFIER = REPO_ROOT / "ci" / "checks" / "classify_merge_profile.py"
CLASSIFY_JOB = "classify-changes"
CLASSIFY_STEP_ID = "classify"
PQ_JOB = "pq-unit"
FUNCTIONAL_JOB = "pq-functional"
GATE_JOB = "full-validation-gate"
GATE_STEP = "Check validation results"
AARCH64_JOB = "aarch64-unit"
# The ci-pq.yml jobs Full Validation requires: matrix entries of its unit job,
# and jobs of their own (the macOS ones and pq-functional), by the name the
# jobs input uses.
REQUIRED_PQ_JOBS = [AARCH64_JOB, "macos-arm64-unit", "macos-x86_64-unit"]
PQ_UNIT_MATRIX_JOB = "unit"
PQ_FUNCTIONAL_JOB = "pq-functional"
OUTPUT = "pq_unit_required"
FUNCTIONAL_OUTPUT = "pq_functional_required"
MERGE_SHA = "1234567890abcdef1234567890abcdef12345678"
HEAD_SHA = "fedcba0987654321fedcba0987654321fedcba09"
CHANGED_FILES_STEP = "Write changed file list"
# The workflows whose classify-changes job lists the changed files for the classifier. The Required Merge
# Gate trusts Core Checks Gate and Full Validation Gate for the checks only they run, so all three must list
# the same files: Core Checks seeing only the new side of a rename into public docs would skip all its jobs.
CHANGED_FILES_WORKFLOWS = (CI_WORKFLOW, GATE_WORKFLOW, CORE_CHECKS_WORKFLOW)
# Core Checks' release validator tests list the changed files again, for release paths.
RELEASE_TESTS_JOB = "release-validator-tests"
RELEASE_CHANGES_STEP = "Detect release file changes"
# Every list of changed files in those workflows known today, by workflow and (job, step): the classify-changes
# jobs, the Required Merge Gate's jobs that confirm a lightweight profile, and the release-file detector.
KNOWN_FILE_LISTS = {
    CI_WORKFLOW: [(CLASSIFY_JOB, CHANGED_FILES_STEP)],
    GATE_WORKFLOW: [(job_id, CHANGED_FILES_STEP) for job_id in (
        CLASSIFY_JOB, "release-policy-validation", "rpc-docs-validation", "public-docs-validation",
        "github-metadata-validation")],
    CORE_CHECKS_WORKFLOW: [(CLASSIFY_JOB, CHANGED_FILES_STEP), (RELEASE_TESTS_JOB, RELEASE_CHANGES_STEP)],
}
# A git command, and the options that make it list files. git diff, log and show detect renames unless given
# --no-renames; the plumbing commands only when asked to.
GIT_COMMAND_RE = re.compile(r"\bgit\s+(diff(?:-tree|-index|-files)?|log|show|whatchanged)\b[^\n]*")
FILE_LIST_OPTIONS = {"--name-only", "--name-status"}
RENAME_DETECTING_COMMANDS = {"diff", "log", "show", "whatchanged"}
RENAME_OPTIONS = ("-M", "-C", "--find-renames", "--find-copies")
# Renames that a changed-file list without --no-renames reduces to their new path, and what the classifier
# reports for both sides: out of the PQ unit jobs' paths, and out of source and release policy into public
# docs, whose profile alone runs no Core Checks job.
RENAMES = [
    ("src/crypto/mlkem.cpp", "src/crypto/kem/kyber.cpp", {OUTPUT: "true", FUNCTIONAL_OUTPUT: "true"}),
    ("src/foo.cpp", "doc/user/foo.cpp", {"profile": "source", "source_validation_required": "true"}),
    ("ci/release/mainnet_ci_posture.json", "doc/reference/mainnet_ci_posture.json",
     {"profile": "source", "source_validation_required": "true"}),
]
# Markers that a source check reads from a document, with the check and a document known to have them. A
# document with one must classify as source, so that a change to it alone runs the check.
CHECKED_DOC_MARKERS = {
    # In the lint job.
    "<!-- pq-transport-vectors: ": ("contrib/devtools/generate-pq-transport-vectors.py", "doc/design/pq-transport.md"),
    # In the functional tests of the CI matrix.
    "<!-- quickstart: ": ("test/functional/feature_pq_quickstart.py", "doc/user/network/pq-transport.md"),
}
# Files that can wire ML-KEM into the build or CI: CMake files, workflows and
# composite actions, and everything under ci/.
WIRING_PATH_RE = re.compile(r"(^|/)CMakeLists[.]txt$|[.]cmake([.]in)?$|^cmake/|^[.]github/(workflows|actions)/|^ci/")
MLKEM_RE = re.compile(rb"ml[-_]?kem", re.IGNORECASE)

MATCHING_PR = ["src/bip324.cpp"]
HYBRID_ONLY_PR = ["src/init.cpp"]
DOCS_ONLY_PR = ["doc/user/README.md"]
OTHER_SOURCE_PR = ["src/wallet/wallet.cpp"]


@dataclass(frozen=True)
class Caller:
    """A job of ci.yml that calls ci-pq.yml when the classifier requires it."""
    output: str          # the classifier output that requires it
    required_env: str    # the gate's env for that output
    result_env: str      # the gate's env for the job's result
    name: str            # its name, and the gate's
    jobs: list[str]      # the jobs input it passes
    running: dict[str, list[str]]  # the ci-pq.yml jobs that then run, with their matrix entries


CALLERS = {
    PQ_JOB: Caller(OUTPUT, "PQ_UNIT_REQUIRED", "PQ_UNIT_RESULT", "PQ unit tests", REQUIRED_PQ_JOBS,
                   # aarch64-unit as the unit job's only entry, each macOS job as
                   # itself, and nothing else (s390x-unit stays on demand).
                   {PQ_UNIT_MATRIX_JOB: [AARCH64_JOB], "macos-arm64-unit": [], "macos-x86_64-unit": []}),
    FUNCTIONAL_JOB: Caller(FUNCTIONAL_OUTPUT, "PQ_FUNCTIONAL_REQUIRED", "PQ_FUNCTIONAL_RESULT", "PQ functional tests",
                           [PQ_FUNCTIONAL_JOB], {PQ_FUNCTIONAL_JOB: []}),
}

# Every other job the gate checks, passing.
OTHER_GATE_RESULTS = {
    "RUNNERS_RESULT": "success",
    "WINDOWS_NATIVE_DLL_RESULT": "success",
    "WINDOWS_CROSS_RESULT": "success",
    "WINDOWS_NATIVE_TEST_RESULT": "success",
    "CI_MATRIX_RESULT": "success",
    "LINT_RESULT": "success",
    "PUBLIC_DOCS_LINT_RESULT": "success",
    "RPC_DOCS_RESULT": "success",
}
# The PQ jobs, not required and skipped.
PQ_GATE_DEFAULTS = {env: value for caller in CALLERS.values()
                    for env, value in ((caller.required_env, "false"), (caller.result_env, "skipped"))}


def classify(paths: list[str]) -> dict[str, str]:
    """Run the classifier the way classify-changes does and return its GitHub outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        changed = Path(tmp) / "changed-files.txt"
        changed.write_text("".join(f"{path}\n" for path in paths), encoding="utf8")
        output = Path(tmp) / "github-output"
        output.touch()
        completed = subprocess.run(
            [sys.executable, str(CLASSIFIER), "--changed-files", str(changed), "--github-output", str(output)],
            cwd=REPO_ROOT, text=True, capture_output=True, check=False,
        )
        assert completed.returncode == 0, completed.stderr
        return svc.parse_key_values(output.read_text(encoding="utf8"))


def pull_request_context(outputs: dict[str, str], *, draft: bool = False) -> dict[str, Any]:
    return {
        "github": {
            "event_name": "pull_request",
            "sha": MERGE_SHA,
            # The pull request's head differs from the merge commit the job must validate.
            "event": {"pull_request": {"draft": draft, "head": {"sha": HEAD_SHA}}},
        },
        "needs": {CLASSIFY_JOB: {"outputs": outputs, "result": "success"}},
    }


def changed_files_steps() -> dict[tuple[str, str], dict[str, Any]]:
    """Every step that writes a changed-file list for the classifier, by workflow and job."""
    return {(workflow_path.name, job_id): step
            for workflow_path in CHANGED_FILES_WORKFLOWS
            for job_id, job in svc.load_workflow(workflow_path)["jobs"].items()
            for step in job.get("steps", []) if step.get("name") == CHANGED_FILES_STEP}


def release_changes_step() -> dict[str, Any]:
    return svc.find_step(svc.load_workflow(CORE_CHECKS_WORKFLOW)["jobs"][RELEASE_TESTS_JOB], RELEASE_CHANGES_STEP)


def file_lists(workflow_path: Path) -> dict[tuple[str, str], list[str]]:
    """The git commands that list files in each step of a workflow, by (job, step), with spaces normalized."""
    lists = {}
    for job_id, job in svc.load_workflow(workflow_path)["jobs"].items():
        for step in job.get("steps", []):
            script = step.get("run", "").replace("\\\n", " ")
            commands = [" ".join(match.group(0).split()) for match in GIT_COMMAND_RE.finditer(script)]
            commands = [command for command in commands if FILE_LIST_OPTIONS & set(command.split())]
            if commands:
                lists[(job_id, step.get("name", ""))] = commands
    return lists


def rename_repo(tmp: str, old: str, new: str) -> tuple[Path, dict[str, str], str]:
    """A repository, its own origin, whose main branch has old and whose HEAD renames and edits it to new.
    Returns the repository, an environment to run git in, and main's commit."""
    repo = Path(tmp) / "repo"
    repo.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": tmp, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

    def git(*args: str) -> str:
        return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, env=env, text=True,
                              capture_output=True, check=True).stdout.strip()

    git("init", "-q", "-b", "main")
    (repo / old).parent.mkdir(parents=True, exist_ok=True)
    (repo / old).write_text("".join(f"line {i}\n" for i in range(50)), encoding="utf8")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    base = git("rev-parse", "HEAD")
    git("remote", "add", "origin", str(repo))
    git("checkout", "-q", "-b", "topic")
    (repo / new).parent.mkdir(parents=True, exist_ok=True)
    git("mv", old, new)
    with open(repo / new, "a", encoding="utf8") as handle:
        handle.write("edited\n")
    git("commit", "-q", "-am", "rename")
    assert git("diff", "--name-only", f"{base}...HEAD") == new, "git detects the rename"
    return repo, env, base


def run_step(step: dict[str, Any], repo: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run a step in repo as GitHub runs a bash step, with each variable of its env set, empty unless given."""
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "step.sh"
        script.write_text(step["run"], encoding="utf8")
        return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)], cwd=repo,
                              env={**{key: "" for key in step.get("env", {})}, **env},
                              text=True, capture_output=True, check=False)


class PQMergeGateContractTest(unittest.TestCase):
    ci: dict[str, Any]
    pq: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.ci = svc.load_workflow(CI_WORKFLOW)
        cls.pq = svc.load_workflow(PQ_WORKFLOW)

    def job_runs(self, job_id: str, context: dict[str, Any]) -> bool:
        return svc._truthy(svc.render(self.ci["jobs"][job_id]["if"], context))

    def run_gate(self, **env: str) -> subprocess.CompletedProcess[str]:
        step = svc.find_step(self.ci["jobs"][GATE_JOB], GATE_STEP)
        full_env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "CLASSIFY_CHANGES_RESULT": "success",
                    "VALIDATION_PROFILE": "source", "SOURCE_VALIDATION_REQUIRED": "true", "CI_PROFILE": "internal"}
        full_env.update(OTHER_GATE_RESULTS)
        full_env.update(PQ_GATE_DEFAULTS)
        full_env.update(env)
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "gate.sh"
            script.write_text(step["run"], encoding="utf8")
            return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
                                  env=full_env, text=True, capture_output=True, check=False)

    def select_pq_jobs(self, jobs: str) -> dict[str, str]:
        """Run ci-pq.yml's selection step with the jobs input the caller passes."""
        step = svc.find_step(self.pq["jobs"][svc.RESOLVER_JOB], "Select jobs")
        env = {key: str(value) for key, value in step["env"].items() if key != "JOBS_INPUT"}
        env.update({"PATH": os.environ["PATH"], "JOBS_INPUT": jobs})
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "select.py"
            script.write_text(step["run"], encoding="utf8")
            output = Path(tmp) / "github-output"
            output.touch()
            env["GITHUB_OUTPUT"] = str(output)
            env["GITHUB_STEP_SUMMARY"] = os.devnull
            completed = subprocess.run([sys.executable, str(script)], env=env, text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return svc.parse_key_values(output.read_text(encoding="utf8"))

    # -- wiring ----------------------------------------------------------------------

    def test_classify_changes_exposes_the_outputs(self) -> None:
        job = self.ci["jobs"][CLASSIFY_JOB]
        for caller in CALLERS.values():
            with self.subTest(output=caller.output):
                self.assertEqual(job["outputs"][caller.output], "${{ steps." + CLASSIFY_STEP_ID + ".outputs." + caller.output + " }}")
        classify_step = svc.find_step(job, "Classify validation profile")
        self.assertEqual(classify_step["id"], CLASSIFY_STEP_ID)
        self.assertIn("ci/checks/classify_merge_profile.py", classify_step["run"])
        self.assertIn('--github-output "$GITHUB_OUTPUT"', classify_step["run"])

    def running_pq_jobs(self, outputs: dict[str, str]) -> dict[str, list[str]]:
        """The ci-pq.yml jobs whose if passes with these selection outputs, with their matrix entries."""
        context = {"needs": {svc.RESOLVER_JOB: {"outputs": outputs, "result": "success"}}}
        running: dict[str, list[str]] = {}
        for job_id, job in self.pq["jobs"].items():
            if job_id == svc.RESOLVER_JOB or not svc._truthy(svc.render(job["if"], context)):
                continue
            matrix = (job.get("strategy") or {}).get("matrix")
            running[job_id] = [entry["job"] for entry in json.loads(outputs["matrix"])["include"]] if matrix else []
        return running

    def test_pq_jobs_call_the_required_jobs_on_the_change_itself(self) -> None:
        for job_id, caller in CALLERS.items():
            with self.subTest(job=job_id):
                job = self.ci["jobs"][job_id]
                self.assertEqual(job["name"], caller.name)
                self.assertEqual(job["uses"], "./.github/workflows/ci-pq.yml")
                self.assertEqual(job["needs"], CLASSIFY_JOB)
                context = pull_request_context({caller.output: "true"})
                rendered = {key: svc._to_text(svc.render(value, context)) for key, value in job["with"].items()}
                self.assertEqual(rendered, {"source_ref": MERGE_SHA, "jobs": ",".join(caller.jobs)})
                self.assertEqual(set(job["with"]), set(self.pq["on"]["workflow_call"]["inputs"]))

                outputs = self.select_pq_jobs(rendered["jobs"])
                self.assertEqual(json.loads(outputs["selected"]), caller.jobs)
                # Exactly these run, and nothing else.
                self.assertEqual(self.running_pq_jobs(outputs), caller.running)

    def test_functional_job_runs_on_a_github_hosted_runner(self) -> None:
        """Not on the self-hosted runners, whose shared disk fills."""
        self.assertEqual(self.pq["jobs"][PQ_FUNCTIONAL_JOB]["runs-on"], "ubuntu-24.04")

    def test_required_merge_gate_runs_this_contract(self) -> None:
        gate = svc.load_workflow(GATE_WORKFLOW)
        commands = "\n".join(step.get("run", "") for step in gate["jobs"][CLASSIFY_JOB]["steps"])
        self.assertIn(f"ci/checks/{Path(__file__).name}", commands)

    def test_changed_file_lists_use_the_same_git_commands(self) -> None:
        """Each workflow classifies the change from its own list of the changed files; listed differently, they
        could pick different profiles, and the Required Merge Gate would trust a gate that skipped its checks."""
        reference = file_lists(CI_WORKFLOW)[(CLASSIFY_JOB, CHANGED_FILES_STEP)]
        for workflow_path in CHANGED_FILES_WORKFLOWS:
            with self.subTest(workflow=workflow_path.name):
                self.assertEqual(file_lists(workflow_path)[(CLASSIFY_JOB, CHANGED_FILES_STEP)], reference)

    def test_every_changed_file_list_turns_rename_detection_off(self) -> None:
        """Every git command in these workflows that lists files names both sides of a rename, so that a new list
        cannot reintroduce the gap."""
        for workflow_path, known in KNOWN_FILE_LISTS.items():
            lists = file_lists(workflow_path)
            with self.subTest(workflow=workflow_path.name):
                # The scan proves nothing unless it finds the lists known today.
                self.assertLessEqual(set(known), set(lists))
            for (job_id, step_name), commands in lists.items():
                for command in commands:
                    with self.subTest(workflow=workflow_path.name, job=job_id, step=step_name, command=command):
                        options = command.split()
                        if options[1] in RENAME_DETECTING_COMMANDS:
                            self.assertIn("--no-renames", options)
                        self.assertFalse(any(option.startswith(RENAME_OPTIONS) for option in options))

    def test_changed_files_name_both_sides_of_a_rename(self) -> None:
        """A rename out of a gated path must still require its checks: git diff lists only the new path by default."""
        steps = changed_files_steps()
        self.assertLessEqual({(workflow_path.name, job_id) for workflow_path, known in KNOWN_FILE_LISTS.items()
                              for job_id, step_name in known if step_name == CHANGED_FILES_STEP}, set(steps))
        for old, new, expected in RENAMES:
            with tempfile.TemporaryDirectory() as tmp:
                repo, git_env, base = rename_repo(tmp, old, new)
                events = {
                    "pull_request": {"EVENT_NAME": "pull_request", "BASE_SHA": base},
                    "merge_group": {"EVENT_NAME": "merge_group", "BASE_REF": "refs/heads/main"},
                    "push": {"EVENT_NAME": "push", "BEFORE_SHA": base},
                    "push of a new branch": {"EVENT_NAME": "push", "BEFORE_SHA": "0" * 40, "DEFAULT_BRANCH": "main"},
                    "other": {"EVENT_NAME": "schedule"},
                }
                for (workflow, job_id), step in steps.items():
                    for event, event_env in events.items():
                        with self.subTest(rename=old, workflow=workflow, job=job_id, event=event):
                            output = Path(tmp) / "github-output"
                            output.write_text("", encoding="utf8")
                            completed = run_step(step, repo, dict(git_env, **event_env, RUNNER_TEMP=tmp, GITHUB_OUTPUT=str(output)))
                            self.assertEqual(completed.returncode, 0, completed.stderr)
                            changed = Path(svc.parse_key_values(output.read_text(encoding="utf8"))["changed_files"])
                            self.assertEqual(sorted(changed.read_text(encoding="utf8").split()), sorted([old, new]))
            with self.subTest(rename=old):
                outputs = classify([old, new])
                self.assertEqual({key: outputs[key] for key in expected}, expected)

    def test_release_file_detection_names_both_sides_of_a_rename(self) -> None:
        """Core Checks' release validator tests run for a change that moves a release file away, and only then."""
        for old, new, changed in (("ci/release/mainnet_ci_posture.json", "doc/reference/mainnet_ci_posture.json", "true"),
                                  ("src/foo.cpp", "doc/user/foo.cpp", "false")):
            with tempfile.TemporaryDirectory() as tmp:
                repo, git_env, base = rename_repo(tmp, old, new)
                events = {
                    "pull_request": {"EVENT_NAME": "pull_request", "RELEASE_BASE_REF": "main"},
                    "merge_group": {"EVENT_NAME": "merge_group", "RELEASE_BASE_REF": "refs/heads/main"},
                    "push": {"EVENT_NAME": "push", "EVENT_BEFORE": base},
                    "push of a new branch": {"EVENT_NAME": "push", "EVENT_BEFORE": "0" * 40},
                }
                for event, event_env in events.items():
                    with self.subTest(rename=old, event=event):
                        output = Path(tmp) / "github-output"
                        output.write_text("", encoding="utf8")
                        completed = run_step(release_changes_step(), repo, dict(git_env, **event_env, GITHUB_OUTPUT=str(output)))
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        # From the list itself, not the fallback for a range that cannot be diffed.
                        self.assertNotIn("Could not", completed.stdout)
                        self.assertEqual(svc.parse_key_values(output.read_text(encoding="utf8")), {"changed": changed})

    def test_gate_reads_the_jobs_and_the_classifier(self) -> None:
        gate = self.ci["jobs"][GATE_JOB]
        self.assertIn("always()", gate["if"])
        env = svc.find_step(gate, GATE_STEP)["env"]
        for job_id, caller in CALLERS.items():
            with self.subTest(job=job_id):
                self.assertIn(job_id, gate["needs"])
                self.assertEqual(env[caller.required_env], "${{ needs." + CLASSIFY_JOB + ".outputs." + caller.output + " }}")
                self.assertEqual(env[caller.result_env], "${{ needs." + job_id + ".result }}")

    def test_job_conditions(self) -> None:
        for job_id, caller in CALLERS.items():
            with self.subTest(job=job_id):
                self.assertTrue(self.job_runs(job_id, pull_request_context({caller.output: "true"})))
                self.assertFalse(self.job_runs(job_id, pull_request_context({caller.output: "false"})))
                self.assertFalse(self.job_runs(job_id, pull_request_context({})), "a missing output never starts the job")
                self.assertFalse(self.job_runs(job_id, pull_request_context({caller.output: "true"}, draft=True)))
                push = pull_request_context({caller.output: "true"})
                push["github"] = {"event_name": "push", "sha": MERGE_SHA, "event": {}}
                self.assertTrue(self.job_runs(job_id, push))

        # Each job follows its own output: a hybrid-only change starts no unit job, and the reverse.
        hybrid_only = pull_request_context({OUTPUT: "false", FUNCTIONAL_OUTPUT: "true"})
        self.assertEqual({job_id: self.job_runs(job_id, hybrid_only) for job_id in CALLERS}, {PQ_JOB: False, FUNCTIONAL_JOB: True})
        unit_only = pull_request_context({OUTPUT: "true", FUNCTIONAL_OUTPUT: "false"})
        self.assertEqual({job_id: self.job_runs(job_id, unit_only) for job_id in CALLERS}, {PQ_JOB: True, FUNCTIONAL_JOB: False})

    # -- the gate ----------------------------------------------------------------------

    def test_gate_outcomes(self) -> None:
        for job_id, caller in CALLERS.items():
            cases = [
                ("required and passed", "true", "success", True, ""),
                ("required but skipped", "true", "skipped", False, f"{caller.name} result was skipped"),
                ("required but failed", "true", "failure", False, f"{caller.name} result was failure"),
                ("required but cancelled", "true", "cancelled", False, f"{caller.name} result was cancelled"),
                ("required but never reported", "true", "", False, f"{caller.name} result was ."),
                ("not required, skipped", "false", "skipped", True, ""),
                ("not required, failed anyway", "false", "failure", False, f"{caller.name} result was failure"),
                ("classifier output missing", "", "skipped", False, f"did not report whether {caller.name} are required ({caller.output}='')"),
                ("classifier output garbled", "yes", "success", False, f"did not report whether {caller.name} are required ({caller.output}='yes')"),
            ]
            for label, required, result, ok, message in cases:
                with self.subTest(job=job_id, case=label):
                    run = self.run_gate(**{caller.required_env: required, caller.result_env: result})
                    self.assertEqual(run.returncode == 0, ok, run.stdout + run.stderr)
                    if message:
                        self.assertIn(message, run.stdout)

            with self.subTest(job=job_id, case="classifier output missing, no source validation"):
                # A missing output fails even a change that needs no source validation.
                run = self.run_gate(**{caller.required_env: "", caller.result_env: "skipped"},
                                    SOURCE_VALIDATION_REQUIRED="false", VALIDATION_PROFILE="public-docs")
                self.assertNotEqual(run.returncode, 0)

    # -- end to end ----------------------------------------------------------------------

    def trace(self, paths: list[str], **results: str) -> tuple[dict[str, bool], subprocess.CompletedProcess[str]]:
        """Follow a pull request's changed files from the classifier through classify-changes' outputs to each PQ
        job's if and the gate step's env, and run the gate. Each PQ job passes if it ran and is skipped if not,
        unless results (job id: result) says otherwise; the other jobs pass when source validation runs."""
        step_outputs = classify(paths)
        classify_job = self.ci["jobs"][CLASSIFY_JOB]
        outputs = {name: svc._to_text(svc.render(value, {"steps": {CLASSIFY_STEP_ID: {"outputs": step_outputs}}}))
                   for name, value in classify_job["outputs"].items()}
        context = pull_request_context(outputs)
        runs = {job_id: self.job_runs(job_id, context) for job_id in CALLERS}

        source = outputs["source_validation_required"] == "true"
        gate = self.ci["jobs"][GATE_JOB]
        needs: dict[str, dict[str, Any]] = {CLASSIFY_JOB: {"outputs": outputs, "result": "success"}}
        for job_id in gate["needs"]:
            if job_id in CALLERS:
                needs[job_id] = {"outputs": {}, "result": "success" if runs[job_id] else "skipped"}
            elif job_id != CLASSIFY_JOB:
                needs[job_id] = {"outputs": {}, "result": "success" if source else "skipped"}
        for job_id, result in results.items():
            needs[job_id]["result"] = result
        env = svc.render_env(svc.find_step(gate, GATE_STEP)["env"], dict(context, needs=needs))
        return runs, self.run_gate(**env)

    def test_matching_pull_request_requires_and_runs_both_jobs(self) -> None:
        runs, gate = self.trace(MATCHING_PR)
        self.assertEqual(runs, {PQ_JOB: True, FUNCTIONAL_JOB: True})
        self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)
        self.assertIn("PQ unit tests: success", gate.stdout)
        self.assertIn("PQ functional tests: success", gate.stdout)
        # Skipping either would fail the gate.
        for job_id in CALLERS:
            with self.subTest(skipped=job_id):
                self.assertNotEqual(self.trace(MATCHING_PR, **{job_id: "skipped"})[1].returncode, 0)

    def test_hybrid_transport_pull_request_requires_and_runs_only_the_functional_job(self) -> None:
        runs, gate = self.trace(HYBRID_ONLY_PR)
        self.assertEqual(runs, {PQ_JOB: False, FUNCTIONAL_JOB: True})
        self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)
        self.assertIn("PQ unit tests: skipped (not required for this change)", gate.stdout)
        self.assertIn("PQ functional tests: success", gate.stdout)
        for result in ("skipped", "failure", "cancelled", ""):
            with self.subTest(result=result):
                gate = self.trace(HYBRID_ONLY_PR, **{FUNCTIONAL_JOB: result})[1]
                self.assertNotEqual(gate.returncode, 0)
                self.assertIn(f"PQ functional tests result was {result}.", gate.stdout)

    def test_other_pull_requests_skip_the_jobs_and_pass(self) -> None:
        for paths in (DOCS_ONLY_PR, OTHER_SOURCE_PR):
            with self.subTest(paths=paths):
                runs, gate = self.trace(paths)
                self.assertEqual(runs, {PQ_JOB: False, FUNCTIONAL_JOB: False})
                self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)


def repository_files() -> list[str]:
    """Tracked files, and new ones git does not ignore."""
    completed = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                               cwd=REPO_ROOT, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return sorted({path for path in completed.stdout.decode("utf8").split("\0") if (REPO_ROOT / path).is_file()})


class MlkemWiringContractTest(unittest.TestCase):
    """The classifier knows every file that wires ML-KEM into the build or CI."""

    def test_wiring_that_mentions_mlkem_requires_the_job(self) -> None:
        wiring = [path for path in repository_files()
                  if WIRING_PATH_RE.search(path) and MLKEM_RE.search((REPO_ROOT / path).read_bytes())]
        # The scan proves nothing unless it finds the wiring known today.
        for known in ("CMakeLists.txt", "src/CMakeLists.txt", "cmake/mlkem-native.cmake", ".github/workflows/ci.yml",
                      "ci/checks/classify_merge_profile.py", "ci/test/03_test_script.sh"):
            self.assertIn(known, wiring)
        missing = [path for path in wiring if classify([path])[OUTPUT] != "true"]
        self.assertEqual(missing, [],
            "FAIL: these files mention ML-KEM but do not require the PQ unit jobs\n"
            "Cause: a change to only one of them would skip pq-unit, and Full Validation accepts the skip\n"
            "Fix: add them to PQ_UNIT_FILES in ci/checks/classify_merge_profile.py")


class CheckedDocsContractTest(unittest.TestCase):
    """A change to only a document that a source check reads runs that check."""

    def test_documents_a_source_check_reads_classify_as_source(self) -> None:
        files = repository_files()
        for marker, (check, known) in CHECKED_DOC_MARKERS.items():
            with self.subTest(marker=marker):
                # The check still reads this marker, and the scan finds the document known to have it.
                self.assertIn(marker, (REPO_ROOT / check).read_text(encoding="utf8"))
                docs = [path for path in files if path.endswith(".md") and marker.encode() in (REPO_ROOT / path).read_bytes()]
                self.assertIn(known, docs)
                wrong = {path: profile for path in docs if (profile := classify([path])["profile"]) != "source"}
                self.assertEqual(wrong, {},
                    f"FAIL: these documents have {marker.strip()}, which {check} checks, but do not classify as source\n"
                    "Cause: a change to only them would skip the check, and the next source change would fail it\n"
                    "Fix: add them to CHECKED_DOCS_FILES in ci/checks/classify_merge_profile.py")


class PQPathsContractTest(unittest.TestCase):
    """Every path the classifier names for the PQ jobs and checked documents exists, so a rename cannot silently stop
    requiring their checks."""

    def test_classifier_paths_exist(self) -> None:
        files = repository_files()
        for path in sorted(classify_merge_profile.PQ_UNIT_FILES | classify_merge_profile.PQ_FUNCTIONAL_FILES
                           | classify_merge_profile.CHECKED_DOCS_FILES):
            with self.subTest(path=path):
                self.assertIn(path, files)
        for prefix in classify_merge_profile.PQ_UNIT_PREFIXES + classify_merge_profile.PQ_FUNCTIONAL_PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertTrue(any(path.startswith(prefix) for path in files), f"no file starts with {prefix}")


if __name__ == "__main__":
    unittest.main()
