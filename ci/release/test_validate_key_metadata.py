#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for validate_key_metadata.py."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
METADATA_VALIDATOR = REPO_ROOT / "ci" / "release" / "validate_key_metadata.py"
GPG = shutil.which("gpg")
SIGNER_FPRS = ["B" * 40, "C" * 40, "D" * 40, "E" * 40]


def signer_entry(index: int, fingerprint: str, *, status: str = "active") -> dict[str, object]:
    return {
        "alias": f"operator-{index:02d}",
        "status": status,
        "key_origin": "qbit-generated",
        "public_key_file": f"public-keys/operator-{index:02d}-release.asc",
        "signing_fingerprint": fingerprint,
        "release_lines": ["testnet"] if status == "active" else [],
        "capabilities": ["release-signing", "builder-attestation"] if status == "active" else [],
        "artifact_sets": ["core", "photon"] if status == "active" else [],
        "created": "2026-06-05",
        "first_release": "v0.1.0-testnet1",
    }


def valid_policy(
    *,
    sequence: int = 1,
    previous_policy_sha256: str | None = None,
    fingerprints: list[str] | None = None,
) -> dict[str, object]:
    signer_fprs = fingerprints or SIGNER_FPRS
    return {
        "schema_version": 2,
        "policy_id": f"qbit-release-keys-testnet-{sequence:06d}",
        "policy_sequence": sequence,
        "previous_policy_sha256": previous_policy_sha256,
        "effective_from_tag": f"v0.1.0-testnet{sequence}",
        "release_lines": {
            "testnet": {
                "active_signer_set_size": 3,
                "release_signature_quorum": 2,
                "builder_attestation_quorum": 2,
                "policy_change_quorum": 2,
            }
        },
        "signers": [signer_entry(index, fingerprint) for index, fingerprint in enumerate(signer_fprs[:3], start=1)],
    }


class ValidateKeyMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_tmp = tempfile.TemporaryDirectory()
        cls.class_root = Path(cls.class_tmp.name)
        cls.secret_home = cls.class_root / "secret-gnupg"
        cls.gpg_signers: list[dict[str, str]] = []
        if GPG:
            cls.secret_home.mkdir(mode=0o700)
            cls.gpg_signers = [cls.generate_signer(index) for index in range(1, 5)]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_tmp.cleanup()

    @classmethod
    def gpg(cls, args: list[str], *, home: Path) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [GPG, "--homedir", str(home), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"gpg failed: {' '.join(args)}\nstdout={result.stdout}\nstderr={result.stderr}"
            )
        return result

    @classmethod
    def generate_signer(cls, index: int) -> dict[str, str]:
        batch = cls.class_root / f"signer-{index}.batch"
        batch.write_text(
            "\n".join(
                [
                    "Key-Type: eddsa",
                    "Key-Curve: ed25519",
                    "Key-Usage: sign",
                    f"Name-Real: qbit policy signer {index}",
                    f"Name-Email: policy-signer-{index}@example.invalid",
                    "Expire-Date: 0",
                    "%no-protection",
                    "%commit",
                    "",
                ]
            ),
            encoding="utf8",
        )
        cls.gpg(["--batch", "--generate-key", str(batch)], home=cls.secret_home)
        list_result = cls.gpg(
            [
                "--batch",
                "--with-colons",
                "--fingerprint",
                "--list-keys",
                f"policy-signer-{index}@example.invalid",
            ],
            home=cls.secret_home,
        )
        fingerprint = next(
            line.split(":")[9]
            for line in list_result.stdout.splitlines()
            if line.startswith("fpr:")
        )
        return {"alias": f"operator-{index:02d}", "fingerprint": fingerprint}

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.keys_dir = self.root / "operator-keys"
        self.keys_dir.mkdir()
        self.policy = self.keys_dir / "keys.json"
        self.previous_keys_dir = self.root / "previous-operator-keys"
        self.previous_keys_dir.mkdir()
        self.previous_policy = self.previous_keys_dir / "keys.json"
        self.mirror_keys_dir = self.root / "qbit-guix.sigs" / "operator-keys"
        self.mirror_keys_dir.mkdir(parents=True)
        self.mirror_policy = self.mirror_keys_dir / "keys.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, path: Path, data: dict[str, object]) -> None:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf8")

    def policy_sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_signer_files(self, data: dict[str, object], keys_dir: Path | None = None) -> None:
        keys_dir = keys_dir or self.keys_dir
        public_keys_dir = keys_dir / "public-keys"
        public_keys_dir.mkdir(exist_ok=True)
        for signer in data["signers"]:  # type: ignore[index]
            public_key_file = str(signer["public_key_file"])  # type: ignore[index]
            (keys_dir / public_key_file).write_text(
                f"public signer certificate placeholder for {signer['alias']}\n",  # type: ignore[index]
                encoding="utf8",
            )

    def export_signer_files(self, data: dict[str, object], keys_dir: Path) -> None:
        public_keys_dir = keys_dir / "public-keys"
        public_keys_dir.mkdir(exist_ok=True)
        for signer in data["signers"]:  # type: ignore[index]
            public_key_file = str(signer["public_key_file"])  # type: ignore[index]
            result = self.gpg(
                ["--batch", "--armor", "--export", str(signer["signing_fingerprint"])],  # type: ignore[index]
                home=self.secret_home,
            )
            (keys_dir / public_key_file).write_text(result.stdout, encoding="utf8")

    def write_policy(
        self,
        data: dict[str, object] | None = None,
        *,
        mirror_data: dict[str, object] | None = None,
        write_public_files: bool = True,
        export_public_files: bool = False,
    ) -> dict[str, object]:
        policy = data or valid_policy()
        self.write_json(self.policy, policy)
        self.write_json(self.mirror_policy, mirror_data or copy.deepcopy(policy))
        if write_public_files:
            if export_public_files:
                self.export_signer_files(policy, self.keys_dir)
                self.export_signer_files(mirror_data or policy, self.mirror_keys_dir)
            else:
                self.write_signer_files(policy, self.keys_dir)
                self.write_signer_files(mirror_data or policy, self.mirror_keys_dir)
        return policy

    def write_previous_policy(
        self,
        data: dict[str, object] | None = None,
        *,
        export_public_files: bool = False,
    ) -> dict[str, object]:
        policy = data or valid_policy()
        self.write_json(self.previous_policy, policy)
        if export_public_files:
            self.export_signer_files(policy, self.previous_keys_dir)
        return policy

    def write_approval_dir(
        self,
        data: dict[str, object],
        approvers: list[str],
        *,
        signer_fingerprints: dict[str, str] | None = None,
    ) -> Path:
        approval_dir = self.keys_dir / "approvals" / str(data["policy_id"])
        approval_dir.mkdir(parents=True)
        (approval_dir / "approval-note.md").write_text("Release policy transition approval.\n", encoding="utf8")
        policy_hash = approval_dir / "policy.SHA256"
        policy_hash.write_text(f"{self.policy_sha256(self.policy)}  keys.json\n", encoding="utf8")
        for approver in approvers:
            approval_file = approval_dir / f"{approver}.asc"
            if signer_fingerprints is None:
                approval_file.write_text("detached signature placeholder\n", encoding="utf8")
            else:
                self.gpg(
                    [
                        "--batch",
                        "--yes",
                        "--armor",
                        "--detach-sign",
                        "--local-user",
                        signer_fingerprints[approver],
                        "--output",
                        str(approval_file),
                        str(policy_hash),
                    ],
                    home=self.secret_home,
                )
        return approval_dir

    def run_validator(self, *extra_args: str, mirror: bool = True) -> subprocess.CompletedProcess[str]:
        args = [
            sys.executable,
            str(METADATA_VALIDATOR),
            "--operator-policy",
            str(self.policy),
            "--operator-keys-dir",
            str(self.keys_dir),
            *extra_args,
        ]
        if mirror:
            args.extend(
                [
                    "--operator-policy-mirror",
                    str(self.mirror_policy),
                    "--operator-keys-dir-mirror",
                    str(self.mirror_keys_dir),
                ]
            )
        return subprocess.run(args, check=False, capture_output=True, text=True)

    def rotation_policy(self) -> dict[str, object]:
        previous_hash = self.policy_sha256(self.previous_policy)
        policy = valid_policy(sequence=2, previous_policy_sha256=previous_hash)
        policy["signers"] = [  # type: ignore[index]
            signer_entry(1, SIGNER_FPRS[0]),
            signer_entry(2, SIGNER_FPRS[1]),
            signer_entry(3, SIGNER_FPRS[2], status="rotated"),
            signer_entry(4, SIGNER_FPRS[3]),
        ]
        return policy

    def gpg_fingerprints(self) -> list[str]:
        return [signer["fingerprint"] for signer in self.gpg_signers]

    def gpg_rotation_policy(self) -> dict[str, object]:
        previous_hash = self.policy_sha256(self.previous_policy)
        signer_fprs = self.gpg_fingerprints()
        policy = valid_policy(
            sequence=2,
            previous_policy_sha256=previous_hash,
            fingerprints=signer_fprs,
        )
        policy["signers"] = [  # type: ignore[index]
            signer_entry(1, signer_fprs[0]),
            signer_entry(2, signer_fprs[1]),
            signer_entry(3, signer_fprs[2], status="rotated"),
            signer_entry(4, signer_fprs[3]),
        ]
        return policy

    def multiline_signer(
        self,
        index: int,
        fingerprint: str,
        release_lines: list[str],
        *,
        artifact_sets: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "alias": f"operator-{index:02d}",
            "status": "active",
            "key_origin": "qbit-generated",
            "public_key_file": f"public-keys/operator-{index:02d}-release.asc",
            "signing_fingerprint": fingerprint,
            "release_lines": release_lines,
            "capabilities": ["release-signing", "builder-attestation"],
            "artifact_sets": artifact_sets or ["core", "photon"],
            "created": "2026-06-05",
            "first_release": "v0.1.0-testnet1",
        }

    def multiline_policy(
        self,
        *,
        sequence: int,
        previous_policy_sha256: str | None,
        mainnet_op4_artifact_sets: list[str],
    ) -> dict[str, object]:
        # operator-01 is testnet-only, operator-04 is mainnet-only, operator-02/03 span both.
        fprs = self.gpg_fingerprints()
        return {
            "schema_version": 2,
            "policy_id": f"qbit-release-keys-multiline-{sequence:06d}",
            "policy_sequence": sequence,
            "previous_policy_sha256": previous_policy_sha256,
            "effective_from_tag": f"v0.1.0-testnet{sequence}",
            "release_lines": {
                "testnet": {
                    "active_signer_set_size": 3,
                    "release_signature_quorum": 2,
                    "builder_attestation_quorum": 2,
                    "policy_change_quorum": 2,
                },
                "mainnet": {
                    "active_signer_set_size": 3,
                    "release_signature_quorum": 2,
                    "builder_attestation_quorum": 2,
                    "policy_change_quorum": 2,
                },
            },
            "signers": [
                self.multiline_signer(1, fprs[0], ["testnet"]),
                self.multiline_signer(2, fprs[1], ["mainnet", "testnet"]),
                self.multiline_signer(3, fprs[2], ["mainnet", "testnet"]),
                self.multiline_signer(4, fprs[3], ["mainnet"], artifact_sets=mainnet_op4_artifact_sets),
            ],
        }

    def new_release_line_policy(self) -> dict[str, object]:
        # testnet is unchanged from the previous policy; a brand-new mainnet line is added
        # with a deliberately weak self-declared policy_change_quorum of 1.
        previous_hash = self.policy_sha256(self.previous_policy)
        fprs = self.gpg_fingerprints()
        policy = valid_policy(sequence=2, previous_policy_sha256=previous_hash, fingerprints=fprs)
        policy["release_lines"]["mainnet"] = {  # type: ignore[index]
            "active_signer_set_size": 2,
            "release_signature_quorum": 2,
            "builder_attestation_quorum": 2,
            "policy_change_quorum": 1,
        }
        policy["signers"][0]["release_lines"] = ["mainnet", "testnet"]  # type: ignore[index]
        policy["signers"][1]["release_lines"] = ["mainnet", "testnet"]  # type: ignore[index]
        return policy

    def test_non_bootstrap_policy_requires_previous_policy_or_explicit_skip(self) -> None:
        # Policy rotation validation must fail closed unless previous-policy
        # approval material is supplied. Routine release-time checks can still
        # select the explicit shape-only mode with --skip-policy-transition-validation.
        policy = valid_policy(sequence=2, previous_policy_sha256="a" * 64)
        self.write_policy(policy, write_public_files=True)

        result = self.run_validator("--require-public-key-files", mirror=False)

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("policy_sequence > 1 requires --previous-operator-policy", result.stderr)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_new_release_line_requires_previous_quorum(self) -> None:
        previous = valid_policy(fingerprints=self.gpg_fingerprints())
        self.write_previous_policy(previous, export_public_files=True)
        policy = self.new_release_line_policy()
        self.write_policy(policy, write_public_files=True, export_public_files=True)
        # A single previous-signer approval must not satisfy the new mainnet line even
        # though mainnet self-declares policy_change_quorum: 1; the previous policy
        # required 2 for policy changes.
        approval_dir = self.write_approval_dir(
            policy,
            ["operator-01"],
            signer_fingerprints={"operator-01": self.gpg_signers[0]["fingerprint"]},
        )

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            "--require-public-key-files",
            mirror=False,
        )

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("mainnet", result.stderr)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_new_release_line_accepts_previous_quorum(self) -> None:
        previous = valid_policy(fingerprints=self.gpg_fingerprints())
        self.write_previous_policy(previous, export_public_files=True)
        policy = self.new_release_line_policy()
        self.write_policy(policy, write_public_files=True, export_public_files=True)
        approval_dir = self.write_approval_dir(
            policy,
            ["operator-01", "operator-02"],
            signer_fingerprints={
                "operator-01": self.gpg_signers[0]["fingerprint"],
                "operator-02": self.gpg_signers[1]["fingerprint"],
            },
        )

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            "--require-public-key-files",
            mirror=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_mirror_reuses_canonical_transition_inputs(self) -> None:
        previous = valid_policy(fingerprints=self.gpg_fingerprints())
        self.write_previous_policy(previous, export_public_files=True)
        policy = self.gpg_rotation_policy()
        self.write_policy(policy, write_public_files=True, export_public_files=True)
        approval_dir = self.write_approval_dir(
            policy,
            ["operator-01", "operator-02"],
            signer_fingerprints={
                "operator-01": self.gpg_signers[0]["fingerprint"],
                "operator-02": self.gpg_signers[1]["fingerprint"],
            },
        )
        # mirror=True but only canonical --previous-operator-policy/--approval-dir are
        # supplied; the mirror run must reuse them instead of looking under the mirror tree.
        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            "--require-public-key-files",
            mirror=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_bootstrap_policy_succeeds(self) -> None:
        self.write_policy()

        result = self.run_validator("--require-public-key-files")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Key metadata validated", result.stdout)
        self.assertIn(f"policy_sha256={self.policy_sha256(self.policy)}", result.stdout)

    def test_repo_default_metadata_validates(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(METADATA_VALIDATOR),
                "--require-public-key-files",
                "--skip-policy-transition-validation",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rotated_policy_without_previous_policy_fails_closed(self) -> None:
        policy = valid_policy(sequence=2, previous_policy_sha256="a" * 64)
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("policy_sequence > 1 requires --previous-operator-policy", result.stderr)

    def test_release_gate_can_skip_transition_validation_for_rotated_policy(self) -> None:
        policy = valid_policy(sequence=2, previous_policy_sha256="a" * 64)
        self.write_policy(policy)

        result = self.run_validator("--skip-policy-transition-validation", "--require-public-key-files")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Key metadata validated", result.stdout)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_valid_policy_rotation_uses_previous_quorum(self) -> None:
        previous = valid_policy(fingerprints=self.gpg_fingerprints())
        self.write_previous_policy(previous, export_public_files=True)
        policy = self.gpg_rotation_policy()
        self.write_policy(policy, write_public_files=True, export_public_files=True)
        approval_dir = self.write_approval_dir(
            policy,
            ["operator-01", "operator-02"],
            signer_fingerprints={
                "operator-01": self.gpg_signers[0]["fingerprint"],
                "operator-02": self.gpg_signers[1]["fingerprint"],
            },
        )

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            "--require-public-key-files",
            mirror=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_rejects_unverified_transition_approval_signature(self) -> None:
        previous = valid_policy(fingerprints=self.gpg_fingerprints())
        self.write_previous_policy(previous, export_public_files=True)
        policy = self.gpg_rotation_policy()
        self.write_policy(policy, write_public_files=True, export_public_files=True)
        approval_dir = self.write_approval_dir(
            policy,
            ["operator-01", "operator-02"],
            signer_fingerprints={
                "operator-01": self.gpg_signers[0]["fingerprint"],
                "operator-02": self.gpg_signers[0]["fingerprint"],
            },
        )

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            mirror=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("was signed by unexpected fingerprint", result.stderr)

    def test_rejects_stale_previous_policy_hash(self) -> None:
        self.write_previous_policy()
        policy = valid_policy(sequence=2, previous_policy_sha256="0" * 64)
        self.write_policy(policy, write_public_files=True)
        approval_dir = self.write_approval_dir(policy, ["operator-01", "operator-02"])

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            mirror=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("previous_policy_sha256 does not match", result.stderr)

    def test_rejects_missing_transition_approvals(self) -> None:
        self.write_previous_policy()
        policy = self.rotation_policy()
        self.write_policy(policy, write_public_files=True)

        result = self.run_validator("--previous-operator-policy", str(self.previous_policy), mirror=False)

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing policy approval directory", result.stderr)

    def test_rejects_new_signer_approving_themselves(self) -> None:
        self.write_previous_policy()
        policy = self.rotation_policy()
        self.write_policy(policy, write_public_files=True)
        approval_dir = self.write_approval_dir(policy, ["operator-01", "operator-04"])

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            mirror=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("newly added signer cannot approve", result.stderr)

    def test_rejects_malformed_policy_sha256_file(self) -> None:
        self.write_previous_policy()
        policy = self.rotation_policy()
        self.write_policy(policy, write_public_files=True)
        approval_dir = self.write_approval_dir(policy, ["operator-01", "operator-02"])
        (approval_dir / "policy.SHA256").write_text(f"{self.policy_sha256(self.policy)} keys.json\n", encoding="utf8")

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            mirror=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("expected '<64-hex>  keys.json\\n'", result.stderr)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_release_line_transition_rejects_other_line_signers(self) -> None:
        previous = self.multiline_policy(
            sequence=1, previous_policy_sha256=None, mainnet_op4_artifact_sets=["core", "photon"]
        )
        self.write_previous_policy(previous, export_public_files=True)
        current = self.multiline_policy(
            sequence=2,
            previous_policy_sha256=self.policy_sha256(self.previous_policy),
            mainnet_op4_artifact_sets=["core"],
        )
        self.write_policy(current, write_public_files=True, export_public_files=True)
        # Only mainnet changed; operator-01 is testnet-only and cannot help meet the
        # mainnet policy-change quorum, so two approvals fall one short for mainnet.
        approval_dir = self.write_approval_dir(
            current,
            ["operator-01", "operator-02"],
            signer_fingerprints={
                "operator-01": self.gpg_signers[0]["fingerprint"],
                "operator-02": self.gpg_signers[1]["fingerprint"],
            },
        )

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            "--require-public-key-files",
            mirror=False,
        )

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("release line 'mainnet'", result.stderr)

    @unittest.skipUnless(GPG, "gpg is required for policy approval signature tests")
    def test_release_line_transition_accepts_that_lines_signers(self) -> None:
        previous = self.multiline_policy(
            sequence=1, previous_policy_sha256=None, mainnet_op4_artifact_sets=["core", "photon"]
        )
        self.write_previous_policy(previous, export_public_files=True)
        current = self.multiline_policy(
            sequence=2,
            previous_policy_sha256=self.policy_sha256(self.previous_policy),
            mainnet_op4_artifact_sets=["core"],
        )
        self.write_policy(current, write_public_files=True, export_public_files=True)
        # operator-02 and operator-03 are active in mainnet in the previous policy.
        approval_dir = self.write_approval_dir(
            current,
            ["operator-02", "operator-03"],
            signer_fingerprints={
                "operator-02": self.gpg_signers[1]["fingerprint"],
                "operator-03": self.gpg_signers[2]["fingerprint"],
            },
        )

        result = self.run_validator(
            "--previous-operator-policy",
            str(self.previous_policy),
            "--approval-dir",
            str(approval_dir),
            "--require-public-key-files",
            mirror=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_invalid_key_origin(self) -> None:
        policy = valid_policy()
        policy["signers"][0]["key_origin"] = "external-hsm"  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("key_origin", result.stderr)

    def test_rejects_duplicate_alias(self) -> None:
        policy = valid_policy()
        policy["signers"][1]["alias"] = policy["signers"][0]["alias"]  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate alias", result.stderr)

    def test_rejects_invalid_alias(self) -> None:
        policy = valid_policy()
        policy["signers"][0]["alias"] = "Operator_01"  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("lowercase alphanumeric or hyphen", result.stderr)

    def test_allows_public_human_signer_identity_metadata(self) -> None:
        policy = valid_policy()
        policy["signers"][0]["notes"] = "Signer One <signer-one@example.invalid>; https://example.invalid/release-signer"  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_duplicate_signing_fingerprint(self) -> None:
        policy = valid_policy()
        policy["signers"][1]["signing_fingerprint"] = policy["signers"][0]["signing_fingerprint"]  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate signing fingerprint", result.stderr)

    def test_rejects_missing_public_cert(self) -> None:
        policy = valid_policy()
        self.write_policy(policy, write_public_files=False)

        result = self.run_validator("--require-public-key-files")

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing signer public certificate", result.stderr)

    def test_rejects_divergent_release_and_builder_signer_sets(self) -> None:
        policy = valid_policy()
        policy["signers"][2]["capabilities"] = ["release-signing"]  # type: ignore[index]
        policy["signers"][2]["artifact_sets"] = []  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("release-signing and builder-attestation signer sets must match", result.stderr)

    def test_rejects_bootstrap_previous_hash(self) -> None:
        policy = valid_policy(previous_policy_sha256="0" * 64)
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("bootstrap policy must use null", result.stderr)

    def test_rejects_missing_effective_from_tag(self) -> None:
        policy = valid_policy()
        del policy["effective_from_tag"]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("effective_from_tag", result.stderr)

    def test_rejects_primary_legacy_fields(self) -> None:
        policy = valid_policy()
        policy["offline_primary_fingerprint"] = "A" * 40
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("primary/root/certification", result.stderr)

    def test_rejects_root_and_certification_language(self) -> None:
        policy = valid_policy()
        policy["signers"][0]["notes"] = "private root certification language"  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("primary/root/certification", result.stderr)

    def test_rejects_primary_public_key_filename(self) -> None:
        policy = valid_policy()
        policy["signers"][0]["public_key_file"] = "public-keys/qbit-operator-primary-AAAAAAAA.asc"  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("primary public certificate files are not allowed", result.stderr)

    def test_rejects_legacy_primary_file_in_keys_dir(self) -> None:
        self.write_policy()
        (self.keys_dir / f"qbit-operator-primary-{'A' * 40}.asc").write_text(
            "legacy certificate placeholder\n",
            encoding="utf8",
        )

        result = self.run_validator("--require-public-key-files", mirror=False)

        self.assertEqual(result.returncode, 1)
        self.assertIn("primary public certificate files are not allowed", result.stderr)

    def test_rejects_operator_policy_mirror_mismatch(self) -> None:
        mirror = valid_policy()
        mirror["signers"][0]["artifact_sets"] = ["core"]  # type: ignore[index]
        self.write_policy(mirror_data=mirror)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror mismatch", result.stderr)

    def test_rejects_symlinked_operator_keys_mirror_root(self) -> None:
        self.write_policy()
        shutil.rmtree(self.mirror_keys_dir)
        self.mirror_keys_dir.symlink_to(self.keys_dir, target_is_directory=True)

        result = self.run_validator("--require-public-key-files")

        self.assertEqual(result.returncode, 1)
        self.assertIn("--operator-keys-dir-mirror must not be a symlink", result.stderr)

    def test_rejects_builder_quorum_unsatisfied_for_artifact_set(self) -> None:
        policy = valid_policy()
        policy["signers"][1]["artifact_sets"] = ["core"]  # type: ignore[index]
        policy["signers"][2]["artifact_sets"] = ["core"]  # type: ignore[index]
        self.write_policy(policy)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "builder-attestation quorum is not satisfiable for artifact set photon",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
