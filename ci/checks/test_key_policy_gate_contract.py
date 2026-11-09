#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract tests: the merge gate checks key-policy continuity against the base.

The Required Merge Gate's operator-key step is lifted out of the workflow and
run, with this checkout's validator, in scratch repositories whose base holds a
sequence 1 policy and its approved sequence 2 successor. A pull request may
change contrib/keys/operator-keys only by following the base policy directly,
with approvals by its signers, or by changing certificates in ways that keep
their keys and signature records.
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

from test_classifier_ci_contract import REPO_ROOT, WorkflowLoader, run_bash_step  # noqa: E402

WORKFLOW = REPO_ROOT / ".github/workflows/required-merge-gate.yml"
JOB = "operator-key-policy-validation"
STEP = "Validate current policy and transition approvals"
VALIDATOR = Path("ci/release/validate_key_metadata.py")
KEYS = Path("contrib/keys/operator-keys")
GPG = shutil.which("gpg")
ALIASES = [f"operator-{index:02d}" for index in range(1, 7)]


def gate_step() -> tuple[str, dict[str, str]]:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf8"), Loader=WorkflowLoader)
    steps = workflow["jobs"][JOB]["steps"]
    step = next(step for step in steps if step.get("name") == STEP)
    return step["run"], step.get("env", {})


@unittest.skipUnless(GPG, "gpg is required")
class KeyPolicyGateContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_tmp = tempfile.TemporaryDirectory()
        cls.class_root = Path(cls.class_tmp.name)
        cls.home = cls.class_root / "gnupg"
        cls.home.mkdir(mode=0o700)
        cls.script, cls.step_env = gate_step()
        # Each signer: a certify-only primary key with an ed25519 signing subkey.
        cls.signers = {alias: cls.make_signer(alias) for alias in ALIASES}
        cls.certificates = {alias: cls.export(signer["primary"]) for alias, signer in cls.signers.items()}

        # operator-01's certificate over time: an expiry refresh, merged into the
        # base certificate, keeps the old self-signature and adds a new one; a
        # plain re-export of the refreshed key drops the old one; a new subkey
        # adds a key.
        primary = cls.signers["operator-01"]["primary"]
        cls.gpg("--quick-set-expire", primary, "3y")
        refreshed = cls.export(primary)
        merge_home = cls.class_root / "merge"
        merge_home.mkdir(mode=0o700)
        for name, data in (("base.asc", cls.certificates["operator-01"]), ("refreshed.asc", refreshed)):
            (cls.class_root / name).write_bytes(data)
            cls.gpg("--import", str(cls.class_root / name), home=merge_home)
        cls.merged_refresh = cls.export(primary, home=merge_home)
        cls.reexported_refresh = refreshed
        cls.gpg("--quick-add-key", primary, "ed25519", "sign", "never")
        cls.extra_subkey = cls.export(primary)

    @classmethod
    def tearDownClass(cls) -> None:
        for home in (cls.home, cls.class_root / "merge"):
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], check=False, capture_output=True)
        cls.class_tmp.cleanup()

    @classmethod
    def gpg(cls, *args: str, home: Path | None = None) -> str:
        result = subprocess.run(
            [GPG, "--homedir", str(home or cls.home), "--batch", "--pinentry-mode", "loopback", "--passphrase", "", *args],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(f"gpg {' '.join(args)} failed:\n{result.stderr}")
        return result.stdout

    @classmethod
    def make_signer(cls, alias: str) -> dict[str, str]:
        uid = f"{alias} <{alias}@example.invalid>"
        cls.gpg("--quick-gen-key", uid, "ed25519", "cert", "1y")
        listing = cls.gpg("--with-colons", "--fingerprint", "--list-keys", uid)
        primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.gpg("--quick-add-key", primary, "ed25519", "sign", "never")
        listing = cls.gpg("--with-colons", "--fingerprint", "--list-keys", primary)
        signing = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")][1]
        return {"primary": primary, "signing": signing}

    @classmethod
    def export(cls, primary: str, home: Path | None = None) -> bytes:
        return cls.gpg("--armor", "--export", primary, home=home).encode("utf8")

    # Scratch repositories -------------------------------------------------

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Key policy fixture")
        self.git("config", "user.email", "key-policy-fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.repo / VALIDATOR).parent.mkdir(parents=True)
        shutil.copy2(REPO_ROOT / VALIDATOR, self.repo / VALIDATOR)
        self.policies: dict[int, bytes] = {}
        self.write_policy(1, ["operator-01", "operator-02", "operator-03"])
        self.commit("sequence 1 policy")
        self.write_policy(
            2,
            ["operator-01", "operator-02", "operator-04"],
            previous=self.policies[1],
            approvers=["operator-01", "operator-02"],
        )
        self.base = self.commit("sequence 2 policy")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=self.repo, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed:\n{result.stderr}")
        return result.stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def policy_data(self, sequence: int, aliases: list[str], previous: bytes | None, policy_id: str | None = None) -> dict:
        return {
            "schema_version": 2,
            "policy_id": policy_id or f"qbit-release-keys-testnet-{sequence:06d}",
            "policy_sequence": sequence,
            "previous_policy_sha256": None if previous is None else hashlib.sha256(previous).hexdigest(),
            "effective_from_tag": "v1.0.0-testnet1",
            "release_lines": {
                "testnet": {
                    "active_signer_set_size": len(aliases),
                    "release_signature_quorum": 2,
                    "builder_attestation_quorum": 2,
                    "policy_change_quorum": 2,
                }
            },
            "signers": [
                {
                    "alias": alias,
                    "status": "active",
                    "key_origin": "external-gpg",
                    "public_key_file": f"public-keys/{alias}-release.asc",
                    "signing_fingerprint": self.signers[alias]["signing"],
                    "release_lines": ["testnet"],
                    "capabilities": ["release-signing", "builder-attestation"],
                    "artifact_sets": ["core", "photon"],
                }
                for alias in aliases
            ],
        }

    def write_policy(
        self,
        sequence: int,
        aliases: list[str],
        *,
        previous: bytes | None = None,
        approvers: list[str] | None = None,
        policy_id: str | None = None,
    ) -> bytes:
        keys_dir = self.repo / KEYS
        (keys_dir / "public-keys").mkdir(parents=True, exist_ok=True)
        data = self.policy_data(sequence, aliases, previous, policy_id)
        policy = (json.dumps(data, indent=2) + "\n").encode("utf8")
        (keys_dir / "keys.json").write_bytes(policy)
        for alias in aliases:
            (keys_dir / "public-keys" / f"{alias}-release.asc").write_bytes(self.certificates[alias])
        if approvers:
            approval_dir = keys_dir / "approvals" / data["policy_id"]
            approval_dir.mkdir(parents=True)
            (approval_dir / "approval-note.md").write_text("Policy change approval.\n", encoding="utf8")
            policy_hash = approval_dir / "policy.SHA256"
            policy_hash.write_text(f"{hashlib.sha256(policy).hexdigest()}  keys.json\n", encoding="utf8")
            for approver in approvers:
                self.gpg(
                    "--yes",
                    "--armor",
                    "--detach-sign",
                    "--local-user",
                    f"{self.signers[approver]['signing']}!",
                    "--output",
                    str(approval_dir / f"{approver}.asc"),
                    str(policy_hash),
                )
        self.policies[sequence] = policy
        return policy

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir(exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "GNUPGHOME": str(self.root / "unused-gnupg"),
            "RUNNER_TEMP": str(runner_temp),
            "EVENT_NAME": "pull_request",
            "BASE_SHA": self.base,
            "BEFORE_SHA": "",
        }
        for name in self.step_env:
            self.assertIn(name, env, f"the gate step binds {name}, which this test does not set")
        return run_bash_step(self.script, self.repo, env)

    def assert_accepted(self, expected: str) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout)

    def assert_refused(self, expected: str) -> None:
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    # Policy changes ------------------------------------------------------

    def test_unchanged_policy_passes(self) -> None:
        (self.repo / KEYS / "KEYS.md").write_text("Signer index.\n", encoding="utf8")
        self.commit("document the signers")
        self.assert_accepted("Base policy: unchanged")

    def test_next_policy_with_approvals_from_base_signers_passes(self) -> None:
        self.write_policy(
            3,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        self.commit("sequence 3 policy")
        self.assert_accepted("Base policy: follows qbit-release-keys-testnet-000002")

    def test_next_policy_needs_approvals_from_base_signers(self) -> None:
        # operator-03 signed sequence 1, but is not a signer of the base policy.
        self.write_policy(
            3,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-03"],
        )
        self.commit("sequence 3 policy")
        self.assert_refused("approval signer is not active in previous policy")

    def test_returning_to_an_older_policy_is_refused(self) -> None:
        (self.repo / KEYS / "keys.json").write_bytes(self.policies[1])
        self.commit("sequence 1 policy again")
        self.assert_refused("policy_sequence 1 must follow the base policy qbit-release-keys-testnet-000002")

    def test_a_new_sequence_1_policy_over_an_existing_one_is_refused(self) -> None:
        self.write_policy(1, ["operator-04", "operator-05", "operator-06"], policy_id="qbit-release-keys-testnet-100001")
        self.commit("another sequence 1 policy")
        self.assert_refused("policy_sequence 1 must follow the base policy")

    def test_a_successor_to_an_older_policy_is_refused(self) -> None:
        self.write_policy(
            2,
            ["operator-01", "operator-02", "operator-05"],
            previous=self.policies[1],
            approvers=["operator-01", "operator-02"],
            policy_id="qbit-release-keys-testnet-200002",
        )
        self.commit("another sequence 2 policy")
        self.assert_refused("policy_sequence 2 must follow the base policy")

    def test_a_successor_naming_an_older_previous_policy_is_refused(self) -> None:
        self.write_policy(
            3,
            ["operator-01", "operator-02", "operator-05"],
            previous=self.policies[1],
            approvers=["operator-01", "operator-02"],
        )
        self.commit("sequence 3 policy chained to sequence 1")
        self.assert_refused("previous_policy_sha256 must be the base policy's digest")

    def test_skipping_a_sequence_is_refused(self) -> None:
        self.write_policy(
            4,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        self.commit("sequence 4 policy")
        self.assert_refused("policy_sequence 4 must follow the base policy qbit-release-keys-testnet-000002 (sequence 2) as 3")

    def test_landed_approvals_stay_unchanged(self) -> None:
        approval = self.repo / KEYS / "approvals" / "qbit-release-keys-testnet-000002" / "approval-note.md"
        approval.write_text("Edited note.\n", encoding="utf8")
        self.commit("edit a landed approval")
        self.assert_refused("approval material already at the base cannot change or be removed")

    def test_without_a_base_policy_only_a_bootstrap_is_added(self) -> None:
        self.git("checkout", "--quiet", "--orphan", "fresh")
        self.git("rm", "-r", "--quiet", "--cached", str(KEYS))
        shutil.rmtree(self.repo / KEYS)
        self.base = self.commit("no policy yet")
        self.write_policy(2, ["operator-01", "operator-02", "operator-03"], previous=b"older")
        self.commit("sequence 2 policy without a base")
        self.assert_refused("the base has no operator policy: only a sequence 1 bootstrap policy can be added")
        shutil.rmtree(self.repo / KEYS)
        self.write_policy(1, ["operator-01", "operator-02", "operator-03"])
        self.commit("sequence 1 policy")
        self.assert_accepted("Base policy: bootstrap")

    # Certificate changes under an unchanged keys.json -------------------

    def replace_certificate(self, alias: str, data: bytes) -> None:
        (self.repo / KEYS / "public-keys" / f"{alias}-release.asc").write_bytes(data)
        self.commit(f"update the {alias} certificate")

    def test_certificate_refresh_that_adds_a_self_signature_passes(self) -> None:
        self.replace_certificate("operator-01", self.merged_refresh)
        self.assert_accepted("Base policy: certificates updated: operator-01")

    def test_certificate_change_that_drops_a_signature_record_is_refused(self) -> None:
        self.replace_certificate("operator-01", self.merged_refresh)
        self.base = self.git("rev-parse", "HEAD")
        self.replace_certificate("operator-01", self.reexported_refresh)
        self.assert_refused("certificate change removes signature records of operator-01")

    def test_certificate_change_that_adds_a_subkey_is_refused(self) -> None:
        self.replace_certificate("operator-01", self.extra_subkey)
        self.assert_refused("certificate change adds or removes keys of operator-01")

    def test_certificates_swapped_between_signers_are_refused(self) -> None:
        public_keys = self.repo / KEYS / "public-keys"
        first, second = (public_keys / f"{alias}-release.asc" for alias in ("operator-01", "operator-02"))
        first_data, second_data = first.read_bytes(), second.read_bytes()
        first.write_bytes(second_data)
        second.write_bytes(first_data)
        self.commit("swap two certificates")
        self.assert_refused("certificate has no key")

    def test_two_signers_with_one_primary_key_are_refused(self) -> None:
        # A certificate holding another signer's primary key: the signing key is
        # present, but two signers would share one primary key.
        self.replace_certificate("operator-02", self.certificates["operator-02"] + self.certificates["operator-01"])
        self.assert_refused("certificate must hold exactly one primary key, got 2")


if __name__ == "__main__":
    unittest.main()
