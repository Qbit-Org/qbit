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
import os
import subprocess
import sys
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
        self.edit(".github/workflows/required-merge-gate.yml", "name: Required Merge Gate\n")
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
        # standard library's; the gate must refuse before importing one, whether
        # the import sits above the check (__future__) or below it (re).
        for name in ("__future__.py", "re.py"):
            (self.repo / "ci" / "release" / name).write_text("raise SystemExit(0)\n", encoding="utf8")
        result = subprocess.run(
            [sys.executable, str(self.repo / contract.GATE_SCRIPT), "policy", "--base", self.base, "--head", self.base,
             "--work", str(self.root / "unisolated")],
            cwd=self.repo, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("run the key-policy gate isolated: python3 -I", result.stdout)
        self.assertFalse((self.root / "unisolated").exists())

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


if __name__ == "__main__":
    unittest.main()
