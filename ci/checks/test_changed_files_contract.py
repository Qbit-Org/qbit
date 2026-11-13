#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract tests: changed-file lists name both sides of a rename.

Required Merge Gate, Full Validation and Core Checks route a change by the
files it touches.  With git's default rename detection, ``git diff
--name-only`` names only the destination of a rename, so moving a source file
into ``doc/`` would look like a docs-only change and skip source validation.

These tests run every changed-file step of those workflows, lifted out of
the workflow files, in a scratch repository whose head renames a source file
and a release validator into ``doc/reference/``, for every event the steps
handle.  The lists they write are then routed by the real classifier.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

from test_classifier_ci_contract import (  # noqa: E402  sibling module, path-dependent
    CLASSIFIER,
    REPO_ROOT,
    SUBPROCESS_TIMEOUT_SECONDS,
    WorkflowLoader,
    run_bash_step,
)

# The workflows that route changes by the files they touch.
ROUTING_WORKFLOWS = (
    ".github/workflows/required-merge-gate.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/core-checks.yml",
)

# The head commit's renames: each source path moves to a docs path.
RENAMES = {
    "src/validation.cpp": "doc/reference/validation.md",
    "ci/release/verify_release.py": "doc/reference/verify_release.md",
}

# Values of the expressions the steps bind in ``env``, per event.  A binding
# not listed here fails the test, so a new input cannot default to empty.
ZERO_SHA = "0" * 40
EXPRESSIONS = {
    "${{ github.event_name }}": lambda event: event["name"],
    "${{ github.event.before }}": lambda event: event.get("before", ""),
    "${{ github.base_ref || github.event.merge_group.base_ref }}": lambda event: event.get("base_ref", ""),
    "${{ github.event.pull_request.base.sha || '' }}": lambda event: event.get("base_sha", ""),
    "${{ github.event.repository.default_branch || 'main' }}": lambda event: "main",
}


def events(base: str) -> dict[str, dict[str, str]]:
    """The events the steps diff for, each with the context GitHub gives it."""
    return {
        "pull_request": {"name": "pull_request", "base_ref": "main", "base_sha": base},
        "push": {"name": "push", "before": base},
        "push of a new branch": {"name": "push", "before": ZERO_SHA},
        "merge_group": {"name": "merge_group", "base_ref": "refs/heads/main"},
        "any other event": {"name": "schedule"},
    }


def changed_file_steps(workflows: tuple[str, ...] = ROUTING_WORKFLOWS) -> list[tuple[str, str, dict]]:
    """Every step of ``workflows`` that lists changed files with git."""
    found = []
    for workflow in workflows:
        data = yaml.load((REPO_ROOT / workflow).read_text(encoding="utf8"), Loader=WorkflowLoader)
        for job_id, job in data["jobs"].items():
            for step in job.get("steps", []):
                if re.search(r"--name-(only|status)", str(step.get("run", ""))):
                    found.append((workflow, job_id, step))
    return found


class ChangedFilesContractTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory()
        root = Path(cls._tmpdir.name)
        cls.root = root
        # Nothing from the developer's or runner's git configuration applies:
        # rename detection stays at git's default, and nothing is signed.
        cls.git_env = {
            "PATH": os.environ.get("PATH", ""),
            "TMPDIR": os.environ.get("TMPDIR", tempfile.gettempdir()),
            "HOME": str(root),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "contract",
            "GIT_AUTHOR_EMAIL": "contract@example.invalid",
            "GIT_COMMITTER_NAME": "contract",
            "GIT_COMMITTER_EMAIL": "contract@example.invalid",
        }
        origin = root / "origin.git"
        cls.checkout = root / "checkout"
        cls.git(root, "init", "--quiet", "--bare", "--initial-branch=main", str(origin))
        cls.git(root, "init", "--quiet", "--initial-branch=main", str(cls.checkout))
        for path in (*RENAMES, "doc/README.md"):
            target = cls.checkout / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"contents of {path}\n" * 20, encoding="utf8")
        cls.git(cls.checkout, "add", ".")
        cls.git(cls.checkout, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "base")
        cls.base = cls.git(cls.checkout, "rev-parse", "HEAD")
        cls.git(cls.checkout, "remote", "add", "origin", str(origin))
        cls.git(cls.checkout, "push", "--quiet", "origin", "main")
        cls.git(cls.checkout, "switch", "--quiet", "-c", "topic")
        for source, destination in RENAMES.items():
            (cls.checkout / destination).parent.mkdir(parents=True, exist_ok=True)
            cls.git(cls.checkout, "mv", source, destination)
        cls.git(cls.checkout, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "move into docs")

        # The scenario, checked once: git's defaults hide the source side.
        detected = cls.git(cls.checkout, "diff", "--name-only", f"{cls.base}...HEAD").splitlines()
        if sorted(detected) != sorted(RENAMES.values()):
            raise AssertionError(f"git did not detect the renames by default: {detected}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir.cleanup()

    @classmethod
    def git(cls, cwd: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=cls.git_env,
            text=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"git {shlex.join(args)} failed\n{completed.stderr}")
        return completed.stdout.strip()

    def run_step(self, step: dict, event: dict[str, str], name: str) -> dict[str, str]:
        """Run one step for one event and return the outputs it wrote."""
        env = dict(self.git_env)
        for key, expression in step.get("env", {}).items():
            self.assertIn(expression, EXPRESSIONS, f"step input {key} is bound to an unmodelled {expression!r}")
            env[key] = EXPRESSIONS[expression](event)
        runner_temp = self.root / f"runner-{name}"
        runner_temp.mkdir()
        output = runner_temp / "github-output"
        env.update({"RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(output)})
        completed = run_bash_step(step["run"], cwd=self.checkout, env=env)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return dict(
            line.split("=", 1) for line in output.read_text(encoding="utf8").splitlines() if "=" in line
        )

    def classify(self, changed_files: str, name: str) -> dict[str, str]:
        output = self.root / f"classified-{name}"
        completed = subprocess.run(
            [
                sys.executable, str(REPO_ROOT / CLASSIFIER),
                "--changed-files", changed_files,
                "--github-output", str(output),
            ],
            text=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return dict(line.split("=", 1) for line in output.read_text(encoding="utf8").splitlines())

    # -- contract ----------------------------------------------------------

    def test_every_changed_file_diff_turns_rename_detection_off(self) -> None:
        # Every workflow is scanned, not only the routing ones, so a new
        # changed-file step anywhere is held to the same rule.
        every_workflow = tuple(
            str(path.relative_to(REPO_ROOT)) for path in sorted((REPO_ROOT / ".github/workflows").glob("*.yml"))
        )
        scanned = set()
        for workflow, job_id, step in changed_file_steps(every_workflow):
            for line in step["run"].splitlines():
                if re.search(r"\bgit (diff|log|show)\s.*--name-(only|status)", line):
                    scanned.add(workflow)
                    with self.subTest(workflow=workflow, job=job_id, line=line.strip()):
                        self.assertIn("--no-renames", line)
        self.assertLessEqual(set(ROUTING_WORKFLOWS), scanned, "a routing workflow's changed-file diffs went missing")

    def test_a_rename_out_of_source_routes_as_source(self) -> None:
        listed = 0
        for workflow, job_id, step in changed_file_steps():
            if step.get("id") != "changed-files":
                continue
            listed += 1
            for label, event in events(self.base).items():
                with self.subTest(workflow=workflow, job=job_id, event=label):
                    name = re.sub(r"\W+", "-", f"{workflow}-{job_id}-{label}")
                    outputs = self.run_step(step, event, name)
                    changed = Path(outputs["changed_files"]).read_text(encoding="utf8").splitlines()
                    for source, destination in RENAMES.items():
                        self.assertIn(source, changed)
                        self.assertIn(destination, changed)
                    classified = self.classify(outputs["changed_files"], name)
                    self.assertEqual(classified["profile"], "source")
                    self.assertEqual(classified["source_validation_required"], "true")
        self.assertTrue(listed, "changed-file list steps went missing")

    def test_a_rename_out_of_release_validators_runs_their_tests(self) -> None:
        steps = [
            (workflow, job_id, step)
            for workflow, job_id, step in changed_file_steps()
            if step.get("id") == "release_changes"
        ]
        self.assertEqual(len(steps), 1, [step.get("name") for _, _, step in steps])
        _, _, step = steps[0]
        for label, event in events(self.base).items():
            if event["name"] == "schedule":
                continue  # the step treats every event but push as a branch diff
            with self.subTest(event=label):
                outputs = self.run_step(step, event, re.sub(r"\W+", "-", f"release-{label}"))
                self.assertEqual(outputs.get("changed"), "true", outputs)


if __name__ == "__main__":
    unittest.main()
