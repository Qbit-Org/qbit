#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract tests: the base-only Key Policy Gate runs the base's code only.

The `pull_request_target` job's check step is lifted out of
.github/workflows/key-policy-gate.yml and run in a checkout of a scratch
repository's base commit, with the pull request's commits present only as git
objects. A pull request that changes the gate's own code, the classifier or a
validator is checked by the base's copies, and needs approvals by the base
policy's signers over a manifest of the gate's files.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

import test_key_policy_gate_contract as contract  # noqa: E402
from test_classifier_ci_contract import REPO_ROOT, WorkflowLoader, run_bash_step  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "ci" / "release"))
import key_policy_gate  # noqa: E402

TARGET_WORKFLOW = REPO_ROOT / ".github/workflows/key-policy-gate.yml"
TARGET_STEP = "Check gated changes with the base's code"
KEYS = contract.KEYS


def target_step() -> tuple[str, dict[str, str]]:
    workflow = yaml.load(TARGET_WORKFLOW.read_text(encoding="utf8"), Loader=WorkflowLoader)
    steps = workflow["jobs"]["key-policy-gate"]["steps"]
    step = next(step for step in steps if step.get("name") == TARGET_STEP)
    return step["run"], step.get("env", {})


class KeyPolicyGateTargetTest(contract.KeyPolicyGateContractTest):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.target_script, cls.target_env = target_step()

    def run_target(self) -> subprocess.CompletedProcess[str]:
        """Run the job's step from a checkout of the base, reading HEAD as objects only."""

        head = self.git("rev-parse", "HEAD")
        checkout = self.root / f"base-checkout-{head[:12]}"
        if not checkout.exists():
            self.git("worktree", "add", "--quiet", "--detach", str(checkout), self.base)
        runner_temp = self.root / "target-runner-temp"
        runner_temp.mkdir(exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "GIT_CONFIG_GLOBAL": os.environ["GIT_CONFIG_GLOBAL"],
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GNUPGHOME": str(self.root / "unused-gnupg"),
            "RUNNER_TEMP": str(runner_temp),
            "BASE_SHA": self.base,
            "HEAD_SHA": head,
        }
        for name in self.target_env:
            self.assertIn(name, env, f"the job step binds {name}, which this test does not set")
        return run_bash_step(self.target_script, checkout, env)

    def assert_target_accepted(self, expected: str) -> None:
        result = self.run_target()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout)

    def assert_target_refused(self, expected: str) -> None:
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stdout + result.stderr)

    def edit(self, path: str, text: str = "# local change\n") -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf8") as handle:
            handle.write(text)

    def approve_gate_change(self, approvers: list[str], *, manifest: bytes | None = None) -> str:
        """Sign the gate manifest of HEAD and commit the approvals; return the approvals directory."""

        if manifest is None:
            previous = os.getcwd()
            os.chdir(self.repo)
            try:
                manifest = key_policy_gate.gate_manifest(self.base, "HEAD")
            finally:
                os.chdir(previous)
        directory = self.repo / key_policy_gate.GATE_APPROVALS_DIR / hashlib.sha256(manifest).hexdigest()
        directory.mkdir(parents=True)
        (directory / "gate.SHA256").write_bytes(manifest)
        (directory / "approval-note.md").write_text("Gate change approval.\n", encoding="utf8")
        for approver in approvers:
            self.gpg(
                "--yes", "--armor", "--detach-sign", "--local-user", f"{self.signers[approver]['signing']}!",
                "--output", str(directory / f"{approver}.asc"), str(directory / "gate.SHA256"),
            )
        self.commit("gate change approvals")
        return directory.relative_to(self.repo).as_posix()

    # The base's code decides --------------------------------------------

    def test_target_passes_a_change_outside_gated_paths(self) -> None:
        self.edit("doc/notes.md", "Notes.\n")
        self.commit("notes")
        self.assert_target_accepted("No key policy or gate code path changed")

    def test_target_requires_approvals_for_a_validator_change(self) -> None:
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.assert_target_refused("this change to the gate's code needs contrib/keys/gate-approvals/")

    def test_target_requires_approvals_for_a_classifier_change(self) -> None:
        self.edit("ci/checks/classify_merge_profile.py")
        self.commit("change the classifier")
        self.assert_target_refused("Gate code changed: ci/checks/classify_merge_profile.py")

    def test_target_requires_approvals_for_a_workflow_change(self) -> None:
        self.edit(".github/workflows/required-merge-gate.yml", "name: Required Merge Gate\npermissions: {}\n")
        self.commit("change the workflow")
        self.assert_target_refused("this change to the gate's code needs")

    def test_target_refuses_the_first_of_two_pull_requests_weakening_the_validator(self) -> None:
        # A validator that accepts any policy change: the base's code refuses the change itself.
        (self.repo / contract.VALIDATOR).write_text("print('Base policy: unchanged')\n", encoding="utf8")
        self.commit("simplify the validator")
        self.assert_target_refused("Gate code changed: ci/release/validate_key_metadata.py")

    def test_target_ignores_the_pull_requests_copy_of_the_gate(self) -> None:
        # The head's gate script accepts anything; the base's copy still checks the policy.
        (self.repo / contract.GATE_SCRIPT).write_text("print('No key policy or gate code path changed')\n", encoding="utf8")
        (self.repo / KEYS / "keys.json").write_bytes(self.policies[1])
        self.commit("sequence 1 policy and an accepting gate")
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Key policy paths changed", result.stdout)

    def test_target_accepts_a_gate_change_approved_by_the_base_quorum(self) -> None:
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_counts_only_base_signers_with_good_signatures(self) -> None:
        for approvers, expected in (
            (["operator-01"], "needs 2 approval(s) over"),
            (["operator-01", "operator-05"], "operator-05 is not an active signer of the base policy"),
        ):
            with self.subTest(approvers=approvers):
                self.git("checkout", "--quiet", "-B", f"approvers-{len(approvers)}-{approvers[-1]}", self.base)
                self.edit("ci/release/validate_key_metadata.py")
                self.commit("change the validator")
                self.approve_gate_change(approvers)
                self.assert_target_refused(expected)

    def test_target_counts_only_the_policys_signing_keys(self) -> None:
        # operator-01's base certificate also holds a second signing subkey the policy does not name.
        self.replace_certificate("operator-01", self.extra_subkey_merged)
        self.land()
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        directory = self.approve_gate_change(["operator-02"])
        self.gpg(
            "--yes", "--armor", "--detach-sign", "--local-user", f"{self.extra_subkey_fingerprint}!",
            "--output", str(self.repo / directory / "operator-01.asc"), str(self.repo / directory / "gate.SHA256"),
        )
        self.commit("approval by another subkey")
        self.assert_target_refused("operator-01.asc: not a good signature by operator-01 over gate.SHA256")

    def test_target_runs_isolated_from_files_beside_the_gate(self) -> None:
        # A module beside the gate in the base must not stand in for one it imports.
        (self.repo / "ci" / "release" / "json.py").write_text("raise SystemExit('json.py was imported')\n", encoding="utf8")
        self.commit("a file beside the gate")
        self.land()
        (self.repo / KEYS / "keys.json").write_bytes(self.policies[1])
        self.commit("sequence 1 policy")
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("json.py was imported", result.stdout + result.stderr)
        self.assertIn("validate_key_metadata.py refused the change", result.stdout)

    def test_target_loads_its_modules_from_their_own_files(self) -> None:
        # A file named like one of the gate's modules, in the other module's
        # directory in the base, must not be loaded instead.
        for directory, name in (("ci/release", "classify_merge_profile.py"), ("ci/checks", "validate_key_metadata.py")):
            (self.repo / directory / name).write_text("raise SystemExit(0)\n", encoding="utf8")
        self.commit("files named like the gate's modules")
        self.land()
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.assert_target_refused("this change to the gate's code needs contrib/keys/gate-approvals/")

    def test_gate_refuses_to_run_without_isolation(self) -> None:
        # Without -I, a module beside the gate would be imported before the
        # standard library's; without -B and a pycache prefix outside the
        # checkout, a committed bytecode cache could be read. The gate must
        # refuse before importing anything, whether the import sits above the
        # check (__future__) or below it (re).
        for name in ("__future__.py", "re.py"):
            (self.repo / "ci" / "release" / name).write_text("raise SystemExit(0)\n", encoding="utf8")
        empty, full = self.root / "pycache-empty", self.root / "pycache-full"
        empty.mkdir()
        (self.repo / "pycache").mkdir()  # empty, so only its place in the checkout refuses it
        (self.root / "pycache-without-isolation").mkdir()
        (full / "cached").mkdir(parents=True)
        work = self.root / "unisolated"

        def gate(*flags: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, *flags, str(self.repo / contract.GATE_SCRIPT), "policy", "--base", self.base,
                 "--head", self.base, "--work", str(work)],
                cwd=self.repo, capture_output=True, text=True, check=False,
            )

        for flags in (
            (),
            ("-I",),
            ("-I", "-B"),
            ("-I", "-X", f"pycache_prefix={empty}"),
            ("-I", "-B", "-X", "pycache_prefix=relative"),
            ("-I", "-B", "-X", f"pycache_prefix={self.repo / 'pycache'}"),
            ("-I", "-B", "-X", f"pycache_prefix={self.repo}/../repo/pycache"),
            ("-I", "-B", "-X", f"pycache_prefix={full}"),
            ("-I", "-B", "-X", f"pycache_prefix={self.root / 'not-made-yet'}"),
            # Its own empty prefix: a run without -B above writes into `empty`.
            ("-B", "-X", f"pycache_prefix={self.root / 'pycache-without-isolation'}"),
        ):
            with self.subTest(flags=flags):
                result = gate(*flags)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("run the key-policy gate as: python3 -I -B -X pycache_prefix=", result.stdout)
                self.assertFalse(work.exists())
        # Without -B, Python writes caches for its own start-up into a prefix,
        # so the run that should pass gets a new empty one.
        fresh = self.root / "pycache-fresh"
        fresh.mkdir()
        # Nor may the prefix overlap the work directory, whose files come from the pull request.
        for prefix, work_dir in ((work / "pycache", work), (work, work), (work, work / "inner")):
            with self.subTest(prefix=prefix, work=work_dir):
                if work.exists():
                    shutil.rmtree(work)
                prefix.mkdir(parents=True)
                result = subprocess.run(
                    [sys.executable, "-I", "-B", "-X", f"pycache_prefix={prefix}", str(self.repo / contract.GATE_SCRIPT),
                     "policy", "--base", self.base, "--head", self.base, "--work", str(work_dir)],
                    cwd=self.repo, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("outside the checkout and --work", result.stdout)
        shutil.rmtree(work)
        result = gate("-I", "-B", "-X", f"pycache_prefix={fresh}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(fresh.iterdir()), [])
        self.assertIn("Base policy: unchanged", result.stdout)

    def plant_bytecode(self, module: str, source: str) -> Path:
        """Commit a bytecode cache for ci/release/<module>.py, compiled from `source`, that Python
        would use without checking it against the module's source (an unchecked hash-based .pyc)."""

        # The interpreter the job step runs, so the cache is one it would read.
        python = ["/usr/bin/python3", "-c", "import sys; print(sys.implementation.cache_tag)"]
        tag = subprocess.run(python, capture_output=True, text=True, check=True).stdout.strip()
        poison = self.root / "poison.py"
        poison.write_text(source, encoding="utf8")
        cache = self.repo / "ci" / "release" / "__pycache__" / f"{module}.{tag}.pyc"
        cache.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["/usr/bin/python3", "-c",
             "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True, "
             "invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)", str(poison), str(cache)],
            check=True,
        )
        return cache

    def test_target_never_reads_a_committed_bytecode_cache(self) -> None:
        self.plant_bytecode("validate_key_metadata", "print('a committed bytecode cache ran')\nraise SystemExit(0)\n")
        self.commit("a bytecode cache beside the validator")
        self.land()
        load = (
            "import importlib.util; spec = importlib.util.spec_from_file_location("
            "'validate_key_metadata', 'ci/release/validate_key_metadata.py'); "
            "spec.loader.exec_module(importlib.util.module_from_spec(spec)); print('the source was imported')"
        )
        # The cache is real: -I alone still reads it.
        result = subprocess.run(["/usr/bin/python3", "-I", "-c", load], cwd=self.repo, capture_output=True, text=True, check=False)
        self.assertIn("a committed bytecode cache ran", result.stdout)
        # The gate's flags never read it.
        empty = self.root / "pycache-empty"
        empty.mkdir()
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", "-X", f"pycache_prefix={empty}", "-c", load],
            cwd=self.repo, capture_output=True, text=True, check=False,
        )
        self.assertNotIn("a committed bytecode cache ran", result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("the source was imported", result.stdout)
        self.edit("doc/notes.md", "Notes.\n")
        self.commit("notes")
        result = self.run_target()
        self.assertNotIn("a committed bytecode cache ran", result.stdout + result.stderr)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Python bytecode caches may not be committed: ci/release/__pycache__/", result.stdout)

    def test_target_refuses_committed_bytecode_anywhere(self) -> None:
        for path in ("doc/__pycache__/notes.cpython-312.pyc", "tools/helper.PYC", "ci/release/__pycache__/x.cpython-312.pyc"):
            with self.subTest(path=path):
                self.git("checkout", "--quiet", "-B", f"bytecode-{len(path)}", self.base)
                self.edit(path, "bytecode")
                self.commit("bytecode")
                self.assert_target_refused(f"Python bytecode caches may not be committed: {path}")

    def test_target_treats_any_file_under_the_gate_directories_as_gate_code(self) -> None:
        for path in ("ci/release/notes.txt", "ci/checks/data/fixture.json", ".github/actions/setup/script.sh"):
            with self.subTest(path=path):
                self.git("checkout", "--quiet", "-B", f"gate-file-{len(path)}", self.base)
                self.edit(path, "data\n")
                self.commit("a file under the gate's directories")
                self.assert_target_refused(f"Gate code changed: {path}")

    def test_target_needs_each_release_lines_quorum_for_a_gate_change(self) -> None:
        data = self.policy_data(3, ["operator-01", "operator-02", "operator-04"], self.policies[2])
        data["release_lines"]["mainnet"] = dict(data["release_lines"]["testnet"], active_signer_set_size=1, release_signature_quorum=1, builder_attestation_quorum=1, policy_change_quorum=1)
        data["signers"].append(dict(data["signers"][0], alias="operator-05", signing_fingerprint=self.signers["operator-05"]["signing"],
                                    public_key_file="public-keys/operator-05-release.asc", release_lines=["mainnet"]))
        self.write_raw_policy(data, ["operator-01", "operator-02"])
        self.commit("a base with a mainnet line")
        self.land()
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("needs 1 approval(s) over")
        self.assertIn("active mainnet signers, got 0", self.run_target().stdout)

    def test_target_approvals_hold_only_for_the_base_they_name(self) -> None:
        self.edit("ci/release/validate_key_metadata.py", "# first\n")
        self.commit("first gate change")
        first = (self.repo / contract.VALIDATOR).read_bytes()
        self.approve_gate_change(["operator-01", "operator-02"])
        self.land()
        self.edit("ci/release/validate_key_metadata.py", "# second\n")
        self.commit("second gate change")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.land()
        # Restoring the first version needs approvals for this change, not the old ones.
        (self.repo / contract.VALIDATOR).write_bytes(first)
        self.commit("restore the first version")
        self.assert_target_refused("this change to the gate's code needs contrib/keys/gate-approvals/")

    def test_target_refuses_approvals_replayed_after_a_revert(self) -> None:
        original = (self.repo / contract.VALIDATOR).read_bytes()
        self.edit("ci/release/validate_key_metadata.py", "# gate change\n")
        self.commit("change the validator")
        first = self.approve_gate_change(["operator-01", "operator-02"])
        self.land()
        (self.repo / contract.VALIDATOR).write_bytes(original)
        self.commit("revert the change")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.land()
        # The same change from the same gate code: the first approvals, still in
        # the base, were for the change from another state.
        self.edit("ci/release/validate_key_metadata.py", "# gate change\n")
        self.commit("apply the change again")
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("this change to the gate's code needs contrib/keys/gate-approvals/", result.stdout)
        self.assertNotIn(f"{first}/gate.SHA256", result.stdout)
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_treats_attribute_files_as_gate_code(self) -> None:
        for path, rule in ((".gitattributes", "doc/*.md text eol=lf\n"), ("doc/.gitattributes", "*.md text eol=lf\n")):
            with self.subTest(path=path):
                self.git("checkout", "--quiet", "-B", f"attributes-{len(path)}", self.base)
                self.edit(path, rule)
                self.commit("attributes for documents")
                self.assert_target_refused(f"Gate code changed: {path}")
                self.approve_gate_change(["operator-01", "operator-02"])
                self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_leaves_attribute_files_own_attributes_alone(self) -> None:
        # A subtree's .gitattributes may match itself: it is approved, not checked out by the gate.
        self.edit("src/vendored/.gitattributes", "* text=auto\n")
        self.commit("a vendored tree's attributes")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_refuses_attributes_on_case_variants_of_the_gates_code(self) -> None:
        self.edit("CI/release/x.py", "print('x')\n")
        self.edit(".gitattributes", "CI/** eol=crlf\n")
        self.commit("attributes for gate code in other letters")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("CI/release/x.py has the eol attribute (crlf)")

    def test_target_refuses_attributes_on_the_gates_code(self) -> None:
        self.edit(".gitattributes", "ci/release/*.py working-tree-encoding=UTF-16LE\n")
        self.commit("attributes for the gate's code")
        self.assert_target_refused("Gate code changed: .gitattributes")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("has the working-tree-encoding attribute (UTF-16LE)")
        self.assertIn("No .gitattributes rule may set this attribute for the gate's code", self.run_target().stdout)

    def test_target_refuses_the_gates_name_in_any_yaml_form(self) -> None:
        forms = {
            "folded": "jobs:\n  other:\n    name: >-\n      Key Policy\n      Gate\n",
            "flow": "jobs: {other: {name: Key Policy Gate, runs-on: ubuntu-24.04}}\n",
            "escape": 'jobs:\n  other:\n    name: "Key Policy \\x47ate"\n',
            "quoted key": 'jobs:\n  other:\n    "name": Key Policy Gate\n',
            "matrix": "jobs:\n  other:\n    name: ${{ matrix.check }}\n    strategy:\n      matrix:\n        check: [Key Policy Gate]\n",
            "a base's check name": "jobs:\n  other:\n    name: Key Policy Gate (1.x.x)\n",
            "a base's check name from the matrix": "jobs:\n  other:\n    name: Key Policy Gate (${{ matrix.base }})\n    strategy:\n      matrix:\n        base: [main]\n",
            "matrix pieces": "jobs:\n  other:\n    name: Key ${{ matrix.a }} ${{ matrix.b }}\n    strategy:\n      matrix:\n        a: [Policy]\n        b: [Gate]\n",
            "case and spacing": "jobs:\n  other:\n    name: key  policy GATE\n",
            "anchor": "x: &gate Key Policy Gate\njobs:\n  other:\n    name: *gate\n",
            "workflow name": "name: Key Policy Gate\njobs: {}\n",
        }
        refusals = {
            "duplicate key": ("jobs:\n  other:\n    name: Other\n    name: Key Policy Gate\n", "appears twice in one mapping"),
            "checks write": ("permissions:\n  checks: write\njobs: {}\n", "asks to post checks or statuses"),
            "statuses write": ("jobs:\n  other:\n    permissions:\n      statuses: write\n", "asks to post checks or statuses"),
            "write-all job": ("jobs:\n  other:\n    permissions: write-all\n", "asks to post checks or statuses"),
            "expression literal": ("jobs:\n  other:\n    name: ${{ 'Key Policy Gate' }}\n", "may read only matrix values"),
            "expression piece": ("jobs:\n  other:\n    name: Key Policy ${{ 'Gate' }}\n", "may read only matrix values"),
            "expression function": ("jobs:\n  other:\n    name: ${{ format('{0} Gate', 'Key Policy') }}\n", "may read only matrix values"),
            "pull request title": ("jobs:\n  other:\n    name: ${{ github.event.pull_request.title }}\n", "may read only matrix values"),
            "input": ("jobs:\n  other:\n    name: ${{ inputs.check }}\n", "may read only matrix values"),
            "matrix from a setting value": ("jobs:\n  other:\n    name: ${{ matrix.c }}\n    strategy:\n      matrix:\n        c: ['${{ vars.CHECK }}']\n", "names something 'Key Policy Gate'"),
            "matrix from a setting": ("jobs:\n  other:\n    name: ${{ matrix.c }}\n    strategy:\n      matrix: ${{ fromJSON(vars.M) }}\n", "names something 'Key Policy Gate'"),
            "matrix from a function": ("jobs:\n  other:\n    name: ${{ matrix.c }}\n    strategy:\n      matrix:\n        c: [\"${{ format('{0}ey', 'K') }}\"]\n", "names something 'Key Policy Gate'"),
            "matrix number": ("jobs:\n  other:\n    name: Key Policy Gate (${{ matrix.v }}.x.x)\n    strategy:\n      matrix:\n        v: [1.0]\n", "names something 'Key Policy Gate'"),
            "matrix octal text": ("jobs:\n  other:\n    name: Key Policy Gate (${{ matrix.v }}.x.x)\n    strategy:\n      matrix:\n        v: [0o1]\n", "names something 'Key Policy Gate'"),
            "matrix pieces split inside words": ("jobs:\n  other:\n    name: ${{ matrix.a }}${{ matrix.b }}\n    strategy:\n      matrix:\n        include:\n          - {a: Key Pol, b: icy Gate}\n", "names something 'Key Policy Gate'"),
            "matrix with a computed include": ("jobs:\n  other:\n    name: ${{ matrix.n }}\n    strategy:\n      matrix:\n        n: [x]\n        include: ${{ fromJSON(needs.a.outputs.include) }}\n", "names something 'Key Policy Gate'"),
            "null job keys": ("permissions: {}\njobs: {~: {name: Key Policy Gate (main)}, null: {name: other}}\n", "a mapping key that is null"),
            "matrix from job outputs": ("jobs:\n  other:\n    name: ${{ matrix.n }}\n    strategy:\n      matrix:\n        n: ${{ fromJSON(needs.a.outputs.n) }}\n", "names something 'Key Policy Gate'"),
            "empty matrix value": ("permissions: {}\njobs:\n  other:\n    name: Key Policy Gate${{ matrix.suffix }}\n    strategy:\n      matrix:\n        os: [a, b]\n        include:\n          - {os: a, suffix: ' x'}\n", "names something 'Key Policy Gate'"),
            "recursive alias": ("x: &a [*a]\njobs:\n  other:\n    name: *a\n", "must declare its token permissions"),
            "matrix key YAML 1.1 reads as a boolean": ("permissions: {}\njobs:\n  other:\n    name: ${{ matrix.on }}\n    strategy:\n      matrix:\n        on: [Key Policy Gate]\n", "names something 'Key Policy Gate'"),
            "matrix key in another case": ("permissions: {}\njobs:\n  other:\n    name: ${{ matrix.CHECK }}\n    strategy:\n      matrix:\n        include:\n          - {check: Key Policy Gate}\n", "names something 'Key Policy Gate'"),
            "job as a tagged set": ("permissions: {}\njobs: {other: !!set {name: Key Policy Gate, runs-on: x}}\n", "uses an explicit YAML tag"),
            "permissions as a tagged set": ("jobs:\n  other:\n    permissions: !!set {checks: write}\n", "uses an explicit YAML tag"),
            "empty permissions": ("permissions:\njobs:\n  other:\n    name: Other\n", "must declare its token permissions"),
            "null permissions": ("permissions: ~\njobs:\n  other:\n    name: Other\n", "must declare its token permissions"),
            "binary matrix value": ("permissions: {}\njobs:\n  other:\n    name: ${{ matrix.a }}\n    strategy:\n      matrix:\n        a: [!!binary S2V5IFBvbGljeSBHYXRl]\n", "uses an explicit YAML tag"),
            "binary permission": ("jobs:\n  other:\n    permissions:\n      checks: !!binary d3JpdGU=\n", "uses an explicit YAML tag"),
            "null tag": ("permissions: {}\njobs:\n  other:\n    name: !!null Key Policy Gate (main)\n", "uses an explicit YAML tag"),
            "null tag on a permission": ("jobs:\n  other:\n    permissions: {checks: !!null write}\n", "uses an explicit YAML tag"),
            "str tag": ("permissions: {}\njobs:\n  other:\n    name: !!str Other\n", "uses an explicit YAML tag"),
            "tagged scalar": ("permissions: {}\njobs:\n  other:\n    name: !!bool Key Policy Gate\n", "uses an explicit YAML tag"),
            "tagged timestamp": ("permissions: {}\njobs:\n  other:\n    name: !!timestamp foo\n", "uses an explicit YAML tag"),
            "line separator": ("permissions: {}\njobs:\n  other:\n    runs-on: x #\u2028    name: Key Policy Gate\n", "holds a control or separator character"),
            "byte-order mark in a key": ("permissions: {}\njobs: {other: {runs-on: x,\n\ufeffname: Key Policy Gate}}\n", "holds a control or separator character: \\ufeff"),
            "many aliased matrix entries": ("permissions: {}\nl: &l [" + ", ".join(["x"] * 300) + "]\ne: &e {a: *l}\njobs:\n  other:\n    name: Key Policy Gate${{ matrix.a }}\n    strategy:\n      matrix:\n        include: [" + ", ".join(["*e"] * 300) + "]\n", "names something 'Key Policy Gate'"),
            "no permissions": ("jobs:\n  other:\n    name: Other\n    runs-on: ubuntu-24.04\n", "must declare its token permissions"),
            "a job without permissions": ("jobs:\n  a:\n    permissions: {}\n  b:\n    name: Other\n", "must declare its token permissions"),
            "not YAML": ("jobs: [\n", "cannot be read as YAML"),
        }
        cases = {name: (text, "names something 'Key Policy Gate'") for name, text in forms.items()} | refusals
        for index, (name, (text, expected)) in enumerate(sorted(cases.items())):
            with self.subTest(form=name):
                self.git("checkout", "--quiet", "-B", f"name-form-{index}", self.base)
                workflow = self.repo / ".github" / "workflows" / ("other.YML" if index % 2 else "other.yml")
                workflow.parent.mkdir(parents=True, exist_ok=True)
                workflow.write_text(text, encoding="utf8")
                self.commit(f"another workflow: {name}")
                self.approve_gate_change(["operator-01", "operator-02"])
                self.assert_target_refused(expected)

    def test_target_accepts_other_names_and_read_only_permissions(self) -> None:
        workflow = self.repo / ".github" / "workflows" / "other.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text(
            "name: Monkey Policy Gateway\u00a0\U0001fae8 \U0001f468\u200d\U0001f4bb soft\u00adhyphen\npermissions:\n  contents: read\n  checks: read\n"
            "env:\n  CUTOFF: 2026-01-01\n  ODD: 2001-13-45\n  EQUALS: =\n"
            "jobs:\n  build:\n    name: Build ${{ matrix.name }} (${{ matrix.os }})\n"
            "    strategy:\n      matrix:\n        name: [Gate keeper, Lint]\n        os: [linux]\n"
            "    steps:\n      - run: echo 'the Key Policy Gate check is required'\n      - uses: ./.github/actions/setup\n"
            "  plain:\n    name: Key Policy ${{ matrix.s }}\n    strategy:\n      matrix:\n        s: ['', '-', '_', e1, lint]\n"
            "    steps:\n      - run: echo plain\n"
            "  docs:\n    needs: build\n    name: docs (${{ matrix.id }})\n"
            "    strategy:\n      matrix: ${{ fromJSON(needs.build.outputs.matrix) }}\n",
            encoding="utf8",
        )
        self.commit("another workflow")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_leaves_unchanged_workflows_permissions_to_the_base(self) -> None:
        # A workflow already in the base keeps the default token permissions it had.
        self.edit(".github/workflows/old.yml", "name: Old\njobs:\n  old:\n    runs-on: ubuntu-24.04\n")
        self.commit("a workflow without permissions")
        self.land()
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_checks_names_in_unchanged_workflows_too(self) -> None:
        self.edit(".github/workflows/old.yml", "permissions: {}\njobs:\n  old:\n    name: >-\n      Key Policy\n      Gate\n")
        self.commit("a workflow named like the gate, from before the check read YAML")
        self.land()
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused(".github/workflows/old.yml names something 'Key Policy Gate'")

    def test_target_treats_every_codeowners_file_as_gate_code(self) -> None:
        for path in ("CODEOWNERS", "docs/CODEOWNERS", ".github/CODEOWNERS"):
            with self.subTest(path=path):
                self.git("checkout", "--quiet", "-B", f"codeowners-{len(path)}", self.base)
                self.edit(path, "* @someone\n")
                self.commit("code owners")
                self.assert_target_refused(f"Gate code changed: {path}")

    def test_target_allows_archive_attributes_on_the_gates_code(self) -> None:
        # export-ignore changes git archive output, not the gate's checkout.
        self.edit(".gitattributes", "ci/** export-ignore\n.github/** export-ignore\n")
        self.commit("keep CI files out of archives")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_reads_only_top_level_workflows(self) -> None:
        # GitHub reads workflows only from the top of .github/workflows/.
        self.edit(".github/workflows/data/matrix.yml", "- one\n- two\n")
        self.commit("data beside the workflows")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_handles_gate_paths_that_are_not_utf8(self) -> None:
        (self.repo / "ci" / "checks").mkdir(parents=True, exist_ok=True)
        with open(os.path.join(os.fsencode(self.repo), b"ci", b"checks", b"data-\xff.txt"), "wb") as handle:
            handle.write(b"data\n")
        self.commit("a file with a name that is not UTF-8")
        # Refused, not crashed: a signer could not read such a path in the manifest.
        self.assert_target_refused("a gate path may hold only printable characters")

    def test_target_matches_names_of_many_computed_pieces_quickly(self) -> None:
        # Forty computed pieces and a letter the check's name does not end with.
        workflow = self.repo / ".github" / "workflows" / "other.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text(
            "permissions: {}\njobs:\n  other:\n    name: " + "${{ matrix.a }}" * 40 + "x\n"
            "    strategy:\n      matrix: ${{ fromJSON(needs.a.outputs.m) }}\n",
            encoding="utf8",
        )
        self.commit("a long computed name")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_refuses_two_directory_entries_of_one_name(self) -> None:
        # A second ci/ entry with other files: no file path repeats, but a checkout holds only one.
        self.edit("ci/release/extra.py", "print('extra')\n")
        self.commit("an extra gate file")
        extra = self.git("rev-parse", "HEAD:ci")
        self.git("checkout", "--quiet", self.base)
        root = self.splice_tree(self.git("rev-parse", f"{self.base}^{{tree}}"), "ci", self.git("rev-parse", f"{self.base}:ci"), duplicate=extra)
        self.git("update-ref", "HEAD", self.git("commit-tree", root, "-p", self.base, "-m", "two ci entries"))
        self.git("checkout", "--quiet", "HEAD")
        self.assert_target_refused(":ci has more than one tree entry")

    def test_target_reads_merge_keys_in_any_order(self) -> None:
        workflow = self.repo / ".github" / "workflows" / "other.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("permissions: {}\nlist: [&b {<<: {x: 1}, x: 2}]\nc: {<<: *b}\njobs: {}\n", encoding="utf8")
        self.commit("a workflow with merge keys")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_refuses_format_characters_in_gate_paths(self) -> None:
        # A right-to-left override shows a signer another name than the file's.
        self.edit("ci/release/\u202eyp.etag", "data\n")
        self.commit("a gate path with a format character")
        self.approve_gate_change(["operator-01", "operator-02"], manifest=b"base  0\n")
        self.assert_target_refused("a gate path may hold only printable characters")

    def test_target_prints_no_workflow_command_from_paths(self) -> None:
        self.edit("doc/__pycache__/a\n::add-mask::Key Policy Gate\n.pyc", "bytecode")
        self.commit("bytecode with a line break in its name")
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        lines = result.stdout.splitlines()
        self.assertTrue(lines[0].startswith("::stop-commands::"), lines[:2])
        self.assertFalse(any(line.startswith("::add-mask::") for line in lines), result.stdout)
        self.assertEqual([line for line in lines if line.startswith("::error::")],
                         [lines[-1]], result.stdout)
        # Commands resume, with the token that stopped them, just before the summary.
        self.assertEqual(lines[-2], "::" + lines[0][len("::stop-commands::"):] + "::")
        self.assertIn("\\u000a::add-mask::", lines[-1])

    def test_target_escapes_percent_in_its_summary(self) -> None:
        # The runner decodes %0A in a command's text as a line break.
        self.edit("doc/__pycache__/x%0Ay.pyc", "bytecode")
        self.commit("bytecode with an escape in its name")
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("x%250Ay.pyc", result.stdout.splitlines()[-1])

    def test_target_keeps_a_validators_errors_inside_the_stopped_commands(self) -> None:
        # A field name with a line break comes back in the validator's error message.
        data = json.loads((self.repo / KEYS / "keys.json").read_text(encoding="utf8"))
        data["x\n::add-mask::secret"] = 1
        (self.repo / KEYS / "keys.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf8")
        self.commit("a policy with a strange field")
        result = self.run_target()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        lines = result.stdout.splitlines()
        resume = lines.index("::" + lines[0][len("::stop-commands::"):] + "::")
        injected = [index for index, line in enumerate(lines) if line.startswith("::add-mask::")]
        self.assertTrue(injected, result.stdout + result.stderr)
        self.assertTrue(all(index < resume for index in injected), result.stdout)

    def test_target_is_not_blocked_by_a_bad_entry_in_the_base(self) -> None:
        # The base state is hashed as git lists it, so the change that removes the entry can land.
        self.edit("ci/release/\u202eyp.etag", "data\n")
        self.commit("a gate path a signer could not read, landed without the gate")
        self.land()
        (self.repo / "ci" / "release" / "\u202eyp.etag").unlink()
        self.commit("remove it")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_a_repeated_entry_outside_a_directory_does_not_stop_reading_it(self) -> None:
        # A base with two doc/ entries: its policy can still be read (and so a
        # gate change that removes the extra entry can land); doc/ itself cannot.
        self.edit("doc/notes.md", "Notes.\n")
        self.commit("notes")
        notes = self.git("rev-parse", "HEAD:doc")
        root = self.splice_tree(self.git("rev-parse", "HEAD^{tree}"), "doc", notes, duplicate=notes)
        commit = self.git("commit-tree", root, "-p", "HEAD", "-m", "two doc entries")
        previous = os.getcwd()
        os.chdir(self.repo)
        try:
            self.assertTrue(key_policy_gate.blob_entries(commit, str(KEYS)))
            with self.assertRaisesRegex(key_policy_gate.GateError, ":doc has more than one tree entry"):
                key_policy_gate.blob_entries(commit, "doc")
        finally:
            os.chdir(previous)

    def test_target_allows_attributes_that_unset_a_conversion(self) -> None:
        # -text and binary leave the checkout's bytes as they are.
        self.edit(".gitattributes", "ci/** -text\n*.png binary\n")
        self.commit("no conversion for gate files")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_accepted("gate change approved by operator-01, operator-02")

    def test_target_refuses_attributes_beside_the_policy(self) -> None:
        self.edit("contrib/keys/.gitattributes", "README.md text eol=crlf\n")
        self.commit("attributes beside the policy")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("contrib/keys holds only the policy, its README and gate approvals")

    def test_target_refuses_a_gate_change_that_removes_earlier_approvals(self) -> None:
        # Approvals only accumulate: removing one would let the base return to an earlier state.
        self.edit("ci/release/validate_key_metadata.py", "# first\n")
        self.commit("first gate change")
        first = self.approve_gate_change(["operator-01", "operator-02"])
        self.land()
        self.edit("ci/release/validate_key_metadata.py", "# second\n")
        shutil.rmtree(self.repo / first)
        self.commit("second gate change, without the first approvals")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused(f"may change with this gate change, not {first}/")

    def test_target_refuses_a_symlink_in_place_of_a_gate_directory(self) -> None:
        # Gate code moved behind a symlink would leave the gate for good.
        for path in (".github/actions", "ci/checks", "ci"):
            with self.subTest(path=path):
                self.git("checkout", "--quiet", "-B", f"symlink-{len(path)}", self.base)
                target = self.repo / path
                if target.is_dir():
                    shutil.rmtree(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to("../tools" if "/" in path else "tools")
                self.commit("a gate directory as a symlink")
                self.assert_target_refused(f"{path} is not a regular file (mode 120000)")

    def test_the_gates_own_workflow_passes_its_own_check(self) -> None:
        key_policy_gate.check_gate_workflow(key_policy_gate.GATE_WORKFLOW, TARGET_WORKFLOW.read_bytes())

    def test_target_checks_the_gates_own_workflow(self) -> None:
        good = (
            "on:\n  pull_request_target:\n    types: [opened, synchronize, reopened, edited, ready_for_review]\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  key-policy-gate:\n    name: Key Policy Gate (${{ github.event.pull_request.base.ref }})\n    runs-on: ubuntu-24.04\n"
            "    steps:\n      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
            "        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n          fetch-depth: 0\n          persist-credentials: false\n"
            "      - name: Gate\n        env:\n          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n        run: echo gate\n"
        )
        cases = {
            "pull request trigger": (good.replace("pull_request_target:", "pull_request:"), "may run only on pull_request_target"),
            "a second trigger": (good.replace("on:\n", "on:\n  push:\n"), "may run only on pull_request_target"),
            "a second job": (good + "  other:\n    name: Key Policy Gate\n", "must hold exactly one job"),
            "one name for every base": (good.replace("name: Key Policy Gate (${{ github.event.pull_request.base.ref }})", "name: Key Policy Gate"), "must be named exactly"),
            "checks write": (good.replace("contents: read", "checks: write"), "may not ask to post checks or statuses"),
            "a job condition": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    if: github.event.pull_request.base.ref != 'x'\n"), "its job may not use if"),
            "a step condition": (good.replace("      - name: Gate\n", "      - name: Gate\n        if: false\n"), "a step may not use if"),
            "an ignored failure": (good.replace("      - name: Gate\n", "      - name: Gate\n        continue-on-error: true\n"), "a step may not use continue-on-error"),
            "another checkout": (good.replace("ref: ${{ github.event.pull_request.base.sha }}", "ref: ${{ github.sha }}"), "must check out exactly the pull request's base commit"),
            "a job that ignores failure": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    continue-on-error: true\n"), "its job may not use continue-on-error"),
            "a job strategy": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    strategy: {matrix: {a: [1]}}\n"), "its job may not use strategy"),
            "a job that needs another": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    needs: [other]\n"), "its job may not use needs"),
            "a reusable workflow job": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    uses: ./.github/workflows/other.yml\n"), "its job may not use uses"),
            "no checkout": (good.replace("      - uses: actions/checkout@0000000000000000000000000000000000000000\n        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n          fetch-depth: 0\n          persist-credentials: false\n", ""), "must check out exactly the pull request's base commit"),
            "two checkouts": (good.replace("      - name: Gate\n", "      - uses: actions/checkout@0000000000000000000000000000000000000000\n        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n          fetch-depth: 0\n          persist-credentials: false\n      - name: Gate\n"), "must check out exactly the pull request's base commit"),
            "a moving checkout ref": (good.replace("actions/checkout@0000000000000000000000000000000000000000", "actions/checkout@main"), "pinned to a commit"),
            "persisted credentials": (good.replace("          persist-credentials: false\n", ""), "must not persist credentials"),
            "a checkout of another repository": (good.replace("          persist-credentials: false\n", "          persist-credentials: false\n          repository: someone/else\n"), "its checkout may set only"),
            "checkout settings as text": (good.replace("        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n          fetch-depth: 0\n          persist-credentials: false\n", "        with: x\n"), "must check out exactly the pull request's base commit"),
            "another shell by default": (good.replace("jobs:\n", "defaults:\n  run:\n    shell: 'true {0}'\njobs:\n"), "its workflow may not use defaults"),
            "a job in a container": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    container: someone/image\n"), "its job may not use container"),
            "a step with another shell": (good.replace("      - name: Gate\n", "      - name: Gate\n        shell: 'true {0}'\n"), "a step may not use shell"),
            "a step that sets BASH_ENV": (good.replace("          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n          BASH_ENV: /tmp/x\n"), "a step's env may set only the gate's inputs"),
            "the base taken from the head": (good.replace("          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "          BASE_SHA: ${{ github.event.pull_request.head.sha }}\n"), "a step's env may set only the gate's inputs"),
            "a token in a step's env": (good.replace("          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n          PR_TOKEN: ${{ github.token }}\n"), "a step's env may set only the gate's inputs"),
            "env as a list": (good.replace("        env:\n          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "        env: []\n"), "a step's env must be a mapping"),
            "another runner": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: self-hosted\n"), "must run on ubuntu-24.04"),
            "a runner the pull request picks": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ${{ github.event.pull_request.head.ref }}\n"), "must run on ubuntu-24.04"),
            "write permissions": (good.replace("  contents: read\n", "  contents: write\n", 1), "may only read contents"),
            "only some event types": (good.replace("[opened, synchronize, reopened, edited, ready_for_review]", "[opened]"), "may run only on pull_request_target"),
            "a shared concurrency group": (good.replace("jobs:\n", "concurrency:\n  group: shared\njobs:\n"), "its concurrency must be"),
            "the expected concurrency": (good.replace("jobs:\n", "concurrency:\n  group: key-policy-gate-${{ github.event.pull_request.number }}\n  cancel-in-progress: true\njobs:\n"), None),
            "no time to run": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    timeout-minutes: 0\n"), "timeout-minutes must be"),
            "a pin in capitals": (good.replace("actions/checkout@0000000000000000000000000000000000000000", "actions/checkout@" + "A" * 40), "pinned to a commit"),
            "a pinned checkout spelled otherwise": (good.replace("actions/checkout@0000000000000000000000000000000000000000", "Actions/Checkout@0000000000000000000000000000000000000000"), None),
            "a fullwidth action": (good.replace("actions/checkout@0000000000000000000000000000000000000000", "\uff41ctions/checkout@0000000000000000000000000000000000000000"), "pinned to a commit"),
            "services": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    services: {db: {image: x}}\n"), "its job may not use services"),
            "a step id": (good.replace("      - name: Gate\n", "      - name: Gate\n        id: gate\n"), "a step may not use id"),
            "a shallow checkout": (good.replace("          fetch-depth: 0\n", ""), "must fetch the full history"),
            "a checkout depth of one": (good.replace("          fetch-depth: 0\n", "          fetch-depth: 1\n"), "must fetch the full history"),
            "a checkout depth the pull request picks": (good.replace("          fetch-depth: 0\n", "          fetch-depth: ${{ github.event.pull_request.commits }}\n"), "must fetch the full history"),
            "a long timeout": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    timeout-minutes: 361\n"), "timeout-minutes must be"),
            "a timeout in words": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    timeout-minutes: twenty\n"), "timeout-minutes must be"),
            "job permissions beyond the workflow's": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n"), "may only read contents"),
            "a branch filter": (good.replace("    types: [opened, synchronize, reopened, edited, ready_for_review]\n", "    types: [opened, synchronize, reopened, edited, ready_for_review]\n    branches: [main]\n"), "may run only on pull_request_target"),
            "null spelled otherwise": (good.replace("permissions:\n  contents: read\n", "permissions: NuLl\n"), "may only read contents"),
            "a step that runs and uses": (good.replace("        run: echo gate\n", "        run: echo gate\n        uses: actions/checkout@0000000000000000000000000000000000000000\n"), "either run a command or use an action"),
            "a step with only a name": (good.replace("      - name: Gate\n", "      - name: Nothing\n      - name: Gate\n"), "either run a command or use an action"),
            "settings on a run step": (good.replace("        run: echo gate\n", "        run: echo gate\n        with: {a: b}\n"), "settings only for an action"),
            "null written as text": (good.replace("permissions:\n  contents: read\n", "permissions: 'null'\n"), "may only read contents"),
            "null on the workflow, permissions on the job": (good.replace("permissions:\n  contents: read\n", "permissions: Null\n").replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n", 1), "its permissions may not be null"),
            "a null step env": (good.replace("        env:\n          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "        env: NULL\n"), "a step's env must be a mapping"),
            "a null env name": (good.replace("          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n          ~: ~\n"), "a mapping key that is null"),
            "a step env written as text": (good.replace("        env:\n          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n", "        env: 'null'\n"), "a step's env must be a mapping"),
            "an anchor": (good.replace("    runs-on: ubuntu-24.04\n", "    runs-on: &runner ubuntu-24.04\n"), "may not use YAML anchors, aliases or merge keys"),
            "a merge key": (good.replace("      - name: Gate\n", "      - <<: {name: Gate}\n        name: Gate\n"), "may not use YAML anchors, aliases or merge keys"),
            "a run that is not a command": (good.replace("        run: echo gate\n", "        run: {a: b}\n"), "a step's run must be a command"),
            "an empty run": (good.replace("        run: echo gate\n", "        run: ''\n"), "a step's run must be a command"),
            "a step name that is a list": (good.replace("      - name: Gate\n", "      - name: [Gate]\n"), "a step's name must be text"),
            "a workflow name that is a mapping": ("name: {a: b}\n" + good, "its name must be text"),
            "permissions on the job": (good.replace("permissions:\n  contents: read\n", "").replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n", 1), None),
            "a checkout spelled otherwise": (good.replace("      - name: Gate\n", "      - uses: Actions/Checkout@v5\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - name: Gate\n"), "pinned to a commit"),
            "another action": (good.replace("      - name: Gate\n", "      - uses: ./.github/actions/setup\n      - name: Gate\n"), "may use no action but actions/checkout"),
            "default permissions": (good.replace("permissions:\n  contents: read\n", ""), "must declare its token permissions"),
            "the gate's workflow": (good, None),
        }
        for index, (name, (text, expected)) in enumerate(sorted(cases.items())):
            with self.subTest(case=name):
                self.git("checkout", "--quiet", "-B", f"gate-workflow-{index}", self.base)
                workflow = self.repo / ".github" / "workflows" / "key-policy-gate.yml"
                workflow.parent.mkdir(parents=True, exist_ok=True)
                workflow.write_text(text, encoding="utf8")
                self.commit(f"the gate's workflow: {name}")
                self.approve_gate_change(["operator-01", "operator-02"])
                if expected is None:
                    self.assert_target_accepted("gate change approved by operator-01, operator-02")
                else:
                    self.assert_target_refused(expected)

    def run_base_step(self, base_ref: str, base_sha: str) -> subprocess.CompletedProcess[str]:
        """The job's first step, with the repository under test as the remote."""

        workflow = yaml.load(TARGET_WORKFLOW.read_text(encoding="utf8"), Loader=WorkflowLoader)
        step = next(step for step in workflow["jobs"]["key-policy-gate"]["steps"] if step.get("name") == "Check the base branch")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "GIT_CONFIG_GLOBAL": os.environ["GIT_CONFIG_GLOBAL"],
            "GIT_CONFIG_NOSYSTEM": "1",
            "BASE_REF": base_ref,
            "BASE_SHA": base_sha,
            "REPOSITORY_URL": str(self.repo),
        }
        for name in step.get("env", {}):
            self.assertIn(name, env, f"the step binds {name}, which this test does not set")
        return run_bash_step(step["run"], self.root, env)

    def test_the_job_checks_only_main_and_1xx_at_their_tips(self) -> None:
        self.git("branch", "--force", "main", self.base)
        self.git("branch", "--force", "1.x.x", self.base)
        self.git("branch", "--force", "feature", self.base)
        older = self.git("rev-parse", f"{self.base}^")
        # Refs that only end in refs/heads/<base> must not stand in for the branch.
        self.git("update-ref", "refs/heads/a/refs/heads/1.x.x", older)
        self.git("update-ref", "refs/heads/0/refs/heads/main", older)
        for base_ref, base_sha, expected in (
            ("main", self.base, None),
            ("1.x.x", self.base, None),
            ("feature", self.base, "checks pull requests into main and 1.x.x only"),
            ("1.x.x", older, f"is at {self.base}, not {older}: update the pull request with its base branch"),
            ("1.x.x ", self.base, "checks pull requests into main and 1.x.x only"),
        ):
            with self.subTest(base_ref=base_ref, base_sha=base_sha):
                result = self.run_base_step(base_ref, base_sha)
                if expected is None:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(expected, result.stdout + result.stderr)
        self.git("branch", "--delete", "--force", "main")
        result = self.run_base_step("main", self.base)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("The base branch was not found", result.stdout + result.stderr)

    def test_the_bases_agree_everywhere(self) -> None:
        # The job's allowlist, GATE_BASES, the ruleset self-check and the templates name the same branches.
        workflow = yaml.load(TARGET_WORKFLOW.read_text(encoding="utf8"), Loader=WorkflowLoader)
        step = next(step for step in workflow["jobs"]["key-policy-gate"]["steps"] if step.get("name") == "Check the base branch")
        self.assertIn(f"\n  {' | '.join(key_policy_gate.GATE_BASES)}) ;;\n", step["run"])
        merge_gate = (REPO_ROOT / ".github/workflows/required-merge-gate.yml").read_text(encoding="utf8")
        for base in key_policy_gate.GATE_BASES:
            self.assertIn(f'"{base}.json": "{key_policy_gate.GATE_CHECK_NAME} ({base})"', merge_gate)

    def test_each_base_has_its_own_check_name_and_ruleset(self) -> None:
        # The job is named for its base; each protected branch's ruleset requires
        # that name, so a run for one base cannot satisfy another's.
        workflow = yaml.load(TARGET_WORKFLOW.read_text(encoding="utf8"), Loader=WorkflowLoader)
        self.assertEqual(workflow["jobs"]["key-policy-gate"]["name"], key_policy_gate.GATE_JOB_NAME)
        required = {}
        for path in sorted((REPO_ROOT / ".github" / "rulesets").glob("*.json")):
            data = json.loads(path.read_text(encoding="utf8"))
            checks = [
                check["context"]
                for rule in data["rules"] if rule["type"] == "required_status_checks"
                for check in rule["parameters"]["required_status_checks"]
                if check["context"].startswith(key_policy_gate.GATE_CHECK_NAME)
            ]
            for ref in data["conditions"]["ref_name"]["include"]:
                if checks:
                    required[ref.removeprefix("refs/heads/")] = checks
        self.assertEqual(
            required,
            {base: [f"{key_policy_gate.GATE_CHECK_NAME} ({base})"] for base in key_policy_gate.GATE_BASES},
        )

    def test_target_accepts_a_head_that_merged_its_base(self) -> None:
        self.edit("doc/notes.md", "Notes.\n")
        self.commit("notes")
        head = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "--detach", self.base)
        self.edit("doc/other.md", "Other.\n")
        self.base = self.commit("the base moves on")
        self.git("checkout", "--quiet", "--detach", head)
        self.git("merge", "--quiet", "--no-edit", self.base)
        self.assert_target_accepted("No key policy or gate code path changed")

    def test_target_refuses_a_head_behind_its_base(self) -> None:
        # Even without a gate path in its own diff: the merge could bring one (a rename on the base, say).
        self.edit("doc/notes.md", "Notes.\n")
        self.commit("notes")
        head = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "--detach", self.base)
        self.edit("doc/other.md", "Other.\n")
        self.base = self.commit("the base moves on")
        self.git("checkout", "--quiet", "--detach", head)
        self.assert_target_refused("bring the pull request up to date with its base branch")

    def test_target_refuses_a_head_with_two_merge_bases(self) -> None:
        # Criss-cross history: git's diff and GitHub's merge could start from different commits.
        tree = self.git("rev-parse", f"{self.base}^{{tree}}")
        first = self.git("commit-tree", tree, "-p", self.base, "-m", "first")
        second = self.git("commit-tree", tree, "-p", self.base, "-m", "second")
        self.base = self.git("commit-tree", tree, "-p", first, "-p", second, "-m", "base merges both")
        self.edit("doc/notes.md", "Notes.\n")
        self.git("add", "-A")
        head_tree = self.git("write-tree")
        self.git("update-ref", "HEAD", self.git("commit-tree", head_tree, "-p", second, "-p", first, "-m", "head merges both"))
        self.git("reset", "--quiet", "--hard", "HEAD")
        self.assert_target_refused("bring the pull request up to date with its base branch")

    def test_target_refuses_control_characters_in_gate_paths(self) -> None:
        # A line break in a path could make two different file sets share a manifest.
        self.edit("ci/checks/x.py\n0000  ci/release/y.py", "data\n")
        self.commit("a gate path with a line break")
        self.approve_gate_change(["operator-01", "operator-02"], manifest=b"base  0\n")
        self.assert_target_refused("a gate path may hold only printable characters")

    def test_target_treats_case_variants_of_gate_paths_as_gate_code(self) -> None:
        for path in ("CI/release/validate_release_artifacts.py", "ci/relea\u017fe/validate_release_artifacts.py", ".GitHub/Workflows/x.yml"):
            with self.subTest(path=path):
                self.git("checkout", "--quiet", "-B", f"case-variant-{len(path)}-{ord(path[1])}", self.base)
                self.edit(path, "data\n")
                self.commit("a gate path in other letters")
                self.assert_target_refused("Gate code changed:")

    def test_target_refuses_another_check_under_the_gates_name(self) -> None:
        workflow = self.repo / ".github" / "workflows" / "other.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("jobs:\n  other:\n    name: Key Policy Gate\n    runs-on: ubuntu-24.04\n", encoding="utf8")
        self.commit("another workflow")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("names something 'Key Policy Gate'")

    def test_target_treats_composite_actions_as_gate_code(self) -> None:
        self.edit(".github/actions/setup/action.yml", "runs:\n  using: composite\n  steps: []\n")
        self.commit("add a composite action")
        self.assert_target_refused("Gate code changed: .github/actions/setup/action.yml")

    def test_target_refuses_the_gates_name_with_a_trailing_comment(self) -> None:
        self.edit(".github/workflows/other.yml", "jobs:\n  other:\n    name: Key Policy Gate  # required\n")
        self.commit("another workflow")
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("names something 'Key Policy Gate'")

    def test_target_needs_an_up_to_date_branch_for_a_gate_change(self) -> None:
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.approve_gate_change(["operator-01", "operator-02"])
        head = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", self.base)
        self.edit("doc/notes.md", "Notes.\n")
        self.base = self.commit("the base moves on")
        self.git("checkout", "--quiet", head)
        self.assert_target_refused("bring the pull request up to date with its base branch")

    def test_target_refuses_approvals_of_another_manifest(self) -> None:
        self.edit("ci/release/validate_key_metadata.py")
        self.commit("change the validator")
        self.approve_gate_change(["operator-01", "operator-02"], manifest=b"0" * 64 + b"  ci/release/validate_key_metadata.py\n")
        self.assert_target_refused("only contrib/keys/gate-approvals/")

    def test_target_refuses_gate_approvals_without_a_gate_change(self) -> None:
        self.approve_gate_change(["operator-01", "operator-02"])
        self.assert_target_refused("gate approvals arrive only with the change to the gate's code they approve")

    def test_target_refuses_other_files_under_contrib_keys(self) -> None:
        self.edit("contrib/keys/notes.md", "Notes.\n")
        self.commit("notes")
        self.assert_target_refused("contrib/keys holds only the policy, its README and gate approvals")

    def test_target_accepts_a_rotation_and_a_certificate_refresh(self) -> None:
        self.write_policy(
            3,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        self.commit("sequence 3 policy")
        self.assert_target_accepted("Base policy: follows qbit-release-keys-testnet-000002")
        self.git("checkout", "--quiet", "-B", "refresh", self.base)
        self.replace_certificate("operator-01", self.merged_refresh)
        self.assert_target_accepted("Base policy: certificates updated: operator-01")

    def test_target_refuses_a_policy_change_without_approvals(self) -> None:
        self.write_policy(1, ["operator-04", "operator-05", "operator-06"], policy_id="qbit-release-keys-testnet-100001")
        self.commit("sequence 1 policy")
        self.assert_target_refused("policy_sequence 1 must follow the base policy")


# Only the base-only job's tests run here; the contract tests run in their own module.
for _name in dir(contract.KeyPolicyGateContractTest):
    if _name.startswith("test_") and not _name.startswith("test_target_"):
        setattr(KeyPolicyGateTargetTest, _name, None)


class BranchRulesetStepTest(unittest.TestCase):
    """The required-merge-gate step that checks the branch ruleset templates."""

    STEP_NAME = "Check branch ruleset aggregate gate"

    @classmethod
    def setUpClass(cls) -> None:
        workflow = yaml.load((REPO_ROOT / ".github/workflows/required-merge-gate.yml").read_text(encoding="utf8"), Loader=WorkflowLoader)
        steps = [step for job in workflow["jobs"].values() for step in job.get("steps", [])]
        cls.script = next(step["run"] for step in steps if step.get("name") == cls.STEP_NAME)

    def run_step(self, rulesets: Path) -> subprocess.CompletedProcess[str]:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(rulesets.parent)}
        return run_bash_step(self.script, rulesets.parent.parent, env)

    def copy_rulesets(self, root: Path) -> Path:
        rulesets = root / ".github" / "rulesets"
        shutil.copytree(REPO_ROOT / ".github" / "rulesets", rulesets)
        return rulesets

    def test_the_templates_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_step(self.copy_rulesets(Path(tmp)))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_template_without_extra_approval_for_unattributed_changes_fails(self) -> None:
        for name in ("main.json", "1.x.x.json", "1.0.0.json", "0.1.x.json"):
            with self.subTest(template=name), tempfile.TemporaryDirectory() as tmp:
                rulesets = self.copy_rulesets(Path(tmp))
                data = json.loads((rulesets / name).read_text(encoding="utf8"))
                for rule in data["rules"]:
                    if rule["type"] == "pull_request":
                        del rule["parameters"]["require_extra_approval_for_unattributed_changes"]
                (rulesets / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf8")
                result = self.run_step(rulesets)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("require_extra_approval_for_unattributed_changes must be true", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
