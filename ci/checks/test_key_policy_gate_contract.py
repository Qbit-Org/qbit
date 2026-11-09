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

import base64
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

import classify_merge_profile  # noqa: E402

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


def dearmor(data: bytes) -> bytes:
    lines = data.decode("ascii").splitlines()
    begin = next(index for index, line in enumerate(lines) if line.startswith("-----BEGIN"))
    end = next(index for index, line in enumerate(lines) if line.startswith("-----END"))
    body = [line for line in lines[begin + 1 : end] if line and ":" not in line and not line.startswith("=")]
    return base64.b64decode("".join(body))


def armor(raw: bytes) -> bytes:
    encoded = base64.b64encode(raw).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + "\n".join(lines) + "\n-----END PGP PUBLIC KEY BLOCK-----\n").encode("ascii")


def packets(raw: bytes) -> list[tuple[int, int, bytes]]:
    """OpenPGP packets as (tag, signature type or -1, bytes); new-format and old-format lengths."""

    out = []
    index = 0
    while index < len(raw):
        start = index
        ctb = raw[index]
        index += 1
        if ctb & 0x40:
            tag = ctb & 0x3F
            first = raw[index]
            index += 1
            if first < 192:
                length = first
            elif first < 224:
                length = ((first - 192) << 8) + raw[index] + 192
                index += 1
            else:
                length = int.from_bytes(raw[index : index + 4], "big")
                index += 4
        else:
            tag = (ctb >> 2) & 0x0F
            size = {0: 1, 1: 2, 2: 4}[ctb & 3]
            length = int.from_bytes(raw[index : index + size], "big")
            index += size
        body = raw[index : index + length]
        index += length
        signature_type = body[1] if tag == 2 and body and body[0] in (4, 5, 6) else -1
        out.append((tag, signature_type, raw[start:index]))
    return out


# CI must run these tests: without gpg they fail there, and only skip locally.
@unittest.skipUnless(GPG or os.environ.get("CI"), "gpg is required (in CI these tests fail instead)")
class KeyPolicyGateContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not GPG:
            raise AssertionError("gpg is required for the key policy gate contract tests")
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
        cls.extra_subkey_fingerprint = cls.key_fingerprints(primary)[-1]
        (cls.class_root / "extra.asc").write_bytes(cls.extra_subkey)
        cls.gpg("--import", str(cls.class_root / "extra.asc"), home=merge_home)
        cls.extra_subkey_merged = cls.export(primary, home=merge_home)

        # operator-02: its signing subkey revoked, in a copy of the keyring, so
        # the main keyring can still sign with it.
        primary2 = cls.signers["operator-02"]["primary"]
        revoked_home = cls.class_root / "revoked"
        shutil.copytree(cls.home, revoked_home, ignore=shutil.ignore_patterns("S.*"))
        cls.edit_key(primary2, "key 1\nrevkey\ny\n0\n\ny\nsave\n", home=revoked_home)
        cls.op2_signing_revoked = cls.export(primary2, home=revoked_home)
        # operator-02: a signing and an encryption subkey more, then both revoked at once.
        cls.gpg("--quick-add-key", primary2, "ed25519", "sign", "never")
        cls.gpg("--quick-add-key", primary2, "cv25519", "encr", "never")
        cls.op2_extra_subkeys = cls.export(primary2)
        cls.op2_encryption_subkey = cls.key_fingerprints(primary2)[-1]
        cls.edit_key(primary2, "key 2\nkey 3\nrevkey\ny\n0\n\ny\nsave\n")
        cls.op2_extra_subkeys_revoked = cls.export(primary2)

    @classmethod
    def key_fingerprints(cls, primary: str, home: Path | None = None) -> list[str]:
        listing = cls.gpg("--with-colons", "--fingerprint", "--list-keys", primary, home=home)
        return [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]

    @classmethod
    def edit_key(cls, primary: str, script: str, home: Path | None = None) -> None:
        result = subprocess.run(
            [GPG, "--homedir", str(home or cls.home), "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--command-fd", "0", "--status-fd", "2", "--edit-key", primary],
            input=script, text=True, capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"gpg --edit-key {primary} failed:\n{result.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        for home in (cls.home, cls.class_root / "merge", cls.class_root / "revoked"):
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
        if (keys_dir / "public-keys").exists():
            shutil.rmtree(keys_dir / "public-keys")
        (keys_dir / "public-keys").mkdir(parents=True)
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
        self.assertIn(expected, result.stdout + result.stderr)

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
        (self.repo / KEYS / "public-keys" / "operator-03-release.asc").write_bytes(self.certificates["operator-03"])
        (self.repo / KEYS / "public-keys" / "operator-04-release.asc").unlink()
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


    # Reading the policy --------------------------------------------------

    def changed_paths(self) -> dict[str, str]:
        listing = self.root / "changed-files.txt"
        listing.write_text(self.git("diff", "--no-renames", "--name-only", f"{self.base}...HEAD") + "\n", encoding="utf8")
        paths = classify_merge_profile.load_changed_files(str(listing))
        return classify_merge_profile.github_outputs(classify_merge_profile.classify_paths(paths))

    def land(self) -> None:
        self.base = self.git("rev-parse", "HEAD")

    def test_attribute_files_are_routed_and_policy_attributes_refused(self) -> None:
        for pattern in ("contrib/keys/operator-keys/keys.json", "contrib/keys/operator-keys/**"):
            with self.subTest(pattern=pattern):
                self.git("checkout", "--quiet", "-B", f"attributes-{len(pattern)}", self.base)
                (self.repo / ".gitattributes").write_text(f"{pattern} export-ignore\n", encoding="utf8")
                self.commit("attributes")
                self.assertEqual(self.changed_paths()["touched_operator_keys"], "true")
                self.assert_refused("has the export-ignore attribute")

    def test_policy_read_from_git_objects_whatever_the_attributes(self) -> None:
        # Attributes at the base cannot hide its policy from the gate.
        (self.repo / ".gitattributes").write_text("contrib/keys/operator-keys/keys.json export-ignore\n", encoding="utf8")
        self.commit("attributes")
        self.land()
        (self.repo / ".gitattributes").unlink()
        self.write_policy(1, ["operator-04", "operator-05", "operator-06"], policy_id="qbit-release-keys-testnet-100001")
        self.commit("sequence 1 policy")
        self.assert_refused("policy_sequence 1 must follow the base policy")

    def test_a_base_whose_history_had_a_policy_cannot_start_over(self) -> None:
        self.git("rm", "-r", "--quiet", str(KEYS))
        self.commit("no policy")
        self.land()
        self.write_policy(1, ["operator-04", "operator-05", "operator-06"], policy_id="qbit-release-keys-testnet-100001")
        self.commit("sequence 1 policy")
        self.assert_refused("its history had one")

    def test_symlinked_policy_directory_is_refused(self) -> None:
        keys = self.repo / "contrib" / "keys"
        shutil.copytree(keys, self.repo / "doc" / "keys")
        shutil.rmtree(keys)
        os.symlink("../doc/keys", keys)
        self.commit("move the policy")
        self.assertEqual(self.changed_paths()["touched_operator_keys"], "true")
        self.assert_refused("HEAD:contrib/keys is not a directory: 120000")

    def test_symlinked_certificate_is_refused(self) -> None:
        certificate = self.repo / KEYS / "public-keys" / "operator-01-release.asc"
        (self.repo / "doc").mkdir()
        (self.repo / "doc" / "operator-01.asc").write_bytes(certificate.read_bytes())
        certificate.unlink()
        os.symlink("../../../../doc/operator-01.asc", certificate)
        self.commit("link a certificate")
        self.assert_refused("operator-01-release.asc is not a regular file (mode 120000)")

    def test_non_ascii_paths_are_routed_and_refused(self) -> None:
        directory = self.repo / KEYS / "approvals" / "qbit-release-keys-testnet-00000\u00e9"
        directory.mkdir(parents=True)
        (directory / "operator-01.asc").write_text("x\n", encoding="utf8")
        self.commit("non-ASCII approval directory")
        self.assertEqual(self.changed_paths()["touched_operator_keys"], "true")
        self.assert_refused("unexpected file(s) in the operator key directory")

    def test_files_outside_the_policy_file_set_are_refused(self) -> None:
        for name, data in (
            ("public-keys/operator-06-release.asc", self.certificates["operator-06"]),
            (".hidden", b"x\n"),
            ("keys.json.bak", self.policies[1]),
        ):
            with self.subTest(name=name):
                self.git("checkout", "--quiet", "-B", f"extra-{len(name)}", self.base)
                (self.repo / KEYS / name).write_bytes(data)
                self.commit(f"add {name}")
                self.assert_refused(f"unexpected file(s) in the operator key directory: {name}")

    def test_the_base_validator_checks_a_change_too(self) -> None:
        (self.repo / VALIDATOR).write_text("print('Base policy: unchanged')\n", encoding="utf8")
        self.write_policy(
            3,
            ["operator-01", "operator-02", "operator-05"],
            previous=self.policies[1],
            approvers=["operator-01", "operator-02"],
        )
        self.commit("sequence 3 policy chained to sequence 1, and a validator that accepts it")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Checking the change with the base's validator", result.stdout)
        self.assertIn("previous_policy_sha256 does not match", result.stderr)

    # Approval material ------------------------------------------------

    def test_approvals_for_another_policy_are_refused(self) -> None:
        self.write_policy(
            3,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        other = self.repo / KEYS / "approvals" / "qbit-release-keys-testnet-000009"
        other.mkdir()
        (other / "approval-note.md").write_text("Another policy.\n", encoding="utf8")
        self.commit("sequence 3 policy and another approvals directory")
        self.assert_refused("approvals/qbit-release-keys-testnet-000009 can only be added with that policy's keys.json")

    def test_approval_material_cannot_be_added_to_a_landed_directory(self) -> None:
        landed = self.repo / KEYS / "approvals" / "qbit-release-keys-testnet-000002"
        (landed / "operator-04.asc").write_bytes((landed / "operator-01.asc").read_bytes())
        self.commit("add an approval to a landed directory")
        self.assert_refused("cannot be added to approvals/qbit-release-keys-testnet-000002 after it landed")

    def test_a_policy_cannot_use_an_approvals_directory_that_landed_before_it(self) -> None:
        early = self.repo / KEYS / "approvals" / "qbit-release-keys-testnet-000003"
        early.mkdir()
        (early / "approval-note.md").write_text("Policy change approval.\n", encoding="utf8")
        self.commit("an approvals directory ahead of its policy")
        self.land()
        shutil.rmtree(early)
        self.write_policy(
            3,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        self.commit("sequence 3 policy")
        self.assert_refused("cannot be added to approvals/qbit-release-keys-testnet-000003 after it landed")

    def test_approvals_by_a_revoked_key_do_not_count(self) -> None:
        self.replace_certificate("operator-02", self.op2_signing_revoked)
        self.land()
        self.write_policy(
            3,
            ["operator-01", "operator-04", "operator-05"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-02"],
        )
        self.commit("sequence 3 policy")
        self.assert_refused("operator-02.asc: approval signature produced no good signature by a valid key")

    # Certificates --------------------------------------------------------

    def test_a_certificate_cannot_appear_under_an_unchanged_policy(self) -> None:
        self.git("rm", "--quiet", str(KEYS / "public-keys" / "operator-04-release.asc"))
        self.commit("a base without one certificate")
        self.land()
        (self.repo / KEYS / "public-keys" / "operator-04-release.asc").write_bytes(self.certificates["operator-04"])
        self.commit("add the certificate")
        self.assert_refused("certificate is new, but keys.json is unchanged")

    def test_two_active_signers_with_one_primary_key_are_refused(self) -> None:
        data = self.policy_data(3, ["operator-01", "operator-02", "operator-04"], self.policies[2])
        data["signers"][2]["signing_fingerprint"] = self.extra_subkey_fingerprint
        self.write_raw_policy(data, ["operator-01", "operator-04"])
        (self.repo / KEYS / "public-keys" / "operator-01-release.asc").write_bytes(self.extra_subkey)
        (self.repo / KEYS / "public-keys" / "operator-04-release.asc").write_bytes(self.extra_subkey)
        self.commit("sequence 3 policy")
        self.assert_refused("is also operator-01's primary key")

    def test_an_active_signer_needs_a_signing_capable_key(self) -> None:
        data = self.policy_data(3, ["operator-01", "operator-02", "operator-04"], self.policies[2])
        data["signers"][1]["signing_fingerprint"] = self.op2_encryption_subkey
        self.write_raw_policy(data, ["operator-01", "operator-04"])
        (self.repo / KEYS / "public-keys" / "operator-02-release.asc").write_bytes(self.op2_extra_subkeys)
        self.commit("sequence 3 policy")
        self.assert_refused("is not signing-capable")

    def test_an_active_signer_needs_an_unrevoked_key(self) -> None:
        self.replace_certificate("operator-02", self.op2_signing_revoked)
        self.assert_refused("of operator-02 is revoked")

    def test_a_revoked_signer_may_carry_its_key_revocation(self) -> None:
        data = self.policy_data(3, ["operator-01", "operator-02", "operator-04", "operator-05"], self.policies[2])
        data["signers"][1].update(status="revoked", release_lines=[], capabilities=[], artifact_sets=[])
        data["release_lines"]["testnet"]["active_signer_set_size"] = 3
        self.write_raw_policy(data, ["operator-01", "operator-04"])
        (self.repo / KEYS / "public-keys" / "operator-02-release.asc").write_bytes(self.op2_signing_revoked)
        self.commit("sequence 3 policy revokes operator-02")
        self.assert_accepted("Base policy: follows qbit-release-keys-testnet-000002")

    def test_a_signer_may_rotate_to_another_subkey_of_its_primary_key(self) -> None:
        data = self.policy_data(3, ["operator-01", "operator-02", "operator-04"], self.policies[2])
        replacement = dict(data["signers"][0], alias="operator-01-r2", signing_fingerprint=self.extra_subkey_fingerprint)
        data["signers"][0].update(
            status="rotated", release_lines=[], capabilities=[], artifact_sets=[],
            replacement_signing_fingerprint=self.extra_subkey_fingerprint,
        )
        data["signers"].append(replacement)
        self.write_raw_policy(data, ["operator-01", "operator-02"])
        (self.repo / KEYS / "public-keys" / "operator-01-release.asc").write_bytes(self.extra_subkey_merged)
        self.commit("sequence 3 policy rotates operator-01's signing subkey")
        self.assert_accepted("Base policy: follows qbit-release-keys-testnet-000002")

    def test_a_policy_change_keeps_continuing_signers_certificate_records(self) -> None:
        self.replace_certificate("operator-01", self.merged_refresh)
        self.land()
        self.write_policy(
            3,
            ["operator-01", "operator-02", "operator-04"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        (self.repo / KEYS / "public-keys" / "operator-01-release.asc").write_bytes(self.reexported_refresh)
        self.commit("sequence 3 policy")
        self.assert_refused("certificate change removes signature records of operator-01")

    def test_a_policy_change_keeps_subkey_revocations(self) -> None:
        self.replace_certificate("operator-02", self.op2_extra_subkeys_revoked)
        self.land()
        self.write_policy(
            3,
            ["operator-01", "operator-02", "operator-04"],
            previous=self.policies[2],
            approvers=["operator-01", "operator-04"],
        )
        (self.repo / KEYS / "public-keys" / "operator-02-release.asc").write_bytes(self.op2_extra_subkeys)
        self.commit("sequence 3 policy")
        self.assert_refused("certificate change removes signature records of operator-02")

    def test_revocations_made_together_are_counted_one_by_one(self) -> None:
        self.replace_certificate("operator-02", self.op2_extra_subkeys_revoked)
        self.land()
        raw = packets(dearmor(self.op2_extra_subkeys_revoked))
        revocations = [index for index, (tag, kind, _data) in enumerate(raw) if tag == 2 and kind == 0x28]
        self.assertEqual(len(revocations), 2)
        kept = b"".join(data for index, (_tag, _kind, data) in enumerate(raw) if index != revocations[0])
        self.replace_certificate("operator-02", armor(kept))
        self.assert_refused("certificate change removes signature records of operator-02")

    def test_a_revocation_stays_with_the_key_it_revokes(self) -> None:
        # Two revocations made in the same second print alike; each is tied to its subkey.
        raw = packets(dearmor(self.op2_extra_subkeys_revoked))
        revocations = [index for index, (tag, kind, _data) in enumerate(raw) if tag == 2 and kind == 0x28]
        first_only, second_only = (
            armor(b"".join(data for index, (_tag, _kind, data) in enumerate(raw) if index != dropped))
            for dropped in (revocations[1], revocations[0])
        )
        self.replace_certificate("operator-02", first_only)
        self.land()
        self.replace_certificate("operator-02", second_only)
        self.assert_refused("certificate change removes signature records of operator-02")

    def write_raw_policy(self, data: dict, approvers: list[str]) -> None:
        keys_dir = self.repo / KEYS
        policy = (json.dumps(data, indent=2) + "\n").encode("utf8")
        (keys_dir / "keys.json").write_bytes(policy)
        if (keys_dir / "public-keys").exists():
            shutil.rmtree(keys_dir / "public-keys")
        (keys_dir / "public-keys").mkdir()
        for signer in data["signers"]:
            path = keys_dir / signer["public_key_file"]
            if not path.exists():
                path.write_bytes(self.certificates[signer["alias"]])
        approval_dir = keys_dir / "approvals" / data["policy_id"]
        approval_dir.mkdir(parents=True)
        (approval_dir / "approval-note.md").write_text("Policy change approval.\n", encoding="utf8")
        policy_hash = approval_dir / "policy.SHA256"
        policy_hash.write_text(f"{hashlib.sha256(policy).hexdigest()}  keys.json\n", encoding="utf8")
        for approver in approvers:
            self.gpg(
                "--yes", "--armor", "--detach-sign", "--local-user", f"{self.signers[approver]['signing']}!",
                "--output", str(approval_dir / f"{approver}.asc"), str(policy_hash),
            )


if __name__ == "__main__":
    unittest.main()
