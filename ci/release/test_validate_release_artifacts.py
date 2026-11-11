#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for validate_release_artifacts.py."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "ci" / "release" / "validate_release_artifacts.py"
PUBLISH_LOCAL = REPO_ROOT / "contrib" / "release-process" / "publish-local-release.sh"
GPG = shutil.which("gpg")
GIT = shutil.which("git")

sys.path.insert(0, str(REPO_ROOT / "ci" / "release"))
import validate_release_artifacts  # noqa: E402


def forged_user_id(victim: str) -> str:
    """A user ID that, split at U+2028, reads as gpg status lines of a good signature by `victim`."""

    return "\u2028".join(
        [
            "forger",
            "[GNUPG:] NEWSIG",
            f"[GNUPG:] GOODSIG {victim[-16:]} victim",
            f"[GNUPG:] VALIDSIG {victim} 2026-11-10 1794344931 0 4 0 22 10 00 {victim}",
            "[GNUPG:] NEWSIG",
            "forger <forger@example.invalid>",
        ]
    )


@unittest.skipUnless(GPG and GIT, "gpg and git are required for release validation tests")
class ValidateReleaseArtifactsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_tmp = tempfile.TemporaryDirectory()
        cls.tmp_path = Path(cls.class_tmp.name)
        cls.secret_home = cls.tmp_path / "secret-gnupg"
        cls.secret_home.mkdir(mode=0o700)
        cls.signers = [
            cls.generate_signer(1, "operator-01"),
            cls.generate_signer(2, "operator-02"),
            cls.generate_signer(3, "operator-03"),
            cls.generate_signer(4, "external-01"),
            cls.generate_signer(5, "revoked-01"),
        ]
        cls.forger = cls.generate_forger(cls.signers[1]["fingerprint"], "operator-04")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_tmp.cleanup()

    @classmethod
    def generate_signer(
        cls, index: int, alias: str, *, faked_time: str | None = None, expire: str = "0"
    ) -> dict[str, str]:
        batch = cls.tmp_path / f"signer-{index}.batch"
        batch.write_text(
            "\n".join(
                [
                    "Key-Type: eddsa",
                    "Key-Curve: ed25519",
                    "Key-Usage: sign",
                    f"Name-Real: qbit release signer {index}",
                    f"Name-Email: release-signer-{index}@example.invalid",
                    f"Expire-Date: {expire}",
                    "%no-protection",
                    "%commit",
                    "",
                ]
            ),
            encoding="utf8",
        )
        faked = ["--faked-system-time", f"{faked_time}!"] if faked_time else []
        cls.gpg([*faked, "--batch", "--generate-key", str(batch)], home=cls.secret_home)
        list_result = cls.gpg(
            [
                *faked,
                "--batch",
                "--with-colons",
                "--fingerprint",
                "--list-keys",
                f"release-signer-{index}@example.invalid",
            ],
            home=cls.secret_home,
        )
        fingerprint = next(
            line.split(":")[9]
            for line in list_result.stdout.splitlines()
            if line.startswith("fpr:")
        )
        signer = {
            "alias": alias,
            "fingerprint": fingerprint,
            "public_key_file": f"public-keys/{alias}-release.asc",
        }
        if faked_time:
            signer["faked_time"] = faked_time
        return signer

    @classmethod
    def generate_forger(cls, victim: str, alias: str) -> dict[str, str]:
        """A signer whose user ID poses as gpg status lines of a good signature by `victim`."""

        def fingerprints() -> set[str]:
            listing = cls.gpg(["--batch", "--with-colons", "--fingerprint", "--list-keys"], home=cls.secret_home)
            return {line.split(":")[9] for line in listing.stdout.split("\n") if line.startswith("fpr:")}

        before = fingerprints()
        cls.gpg(
            ["--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
             forged_user_id(victim), "ed25519", "sign", "never"],
            home=cls.secret_home,
        )
        (fingerprint,) = fingerprints() - before
        return {"alias": alias, "fingerprint": fingerprint, "public_key_file": f"public-keys/{alias}-release.asc"}

    @classmethod
    def generate_shared_primary_signers(cls, name: str, aliases: list[str]) -> list[dict[str, str]]:
        """Signers whose signing subkeys all hang off one certify-only primary key."""

        loopback = ["--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        uid = f"{name} <{name}@example.invalid>"
        cls.gpg([*loopback, "--quick-gen-key", uid, "ed25519", "cert", "never"], home=cls.secret_home)
        listing = cls.gpg(["--batch", "--with-colons", "--fingerprint", "--list-keys", uid], home=cls.secret_home)
        primary = next(line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:"))
        for _alias in aliases:
            cls.gpg([*loopback, "--quick-add-key", primary, "ed25519", "sign", "never"], home=cls.secret_home)
        listing = cls.gpg(["--batch", "--with-colons", "--fingerprint", "--list-keys", primary], home=cls.secret_home)
        subkeys = [line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:")][1:]
        return [
            {"alias": alias, "fingerprint": subkey, "local_user": f"{subkey}!", "primary": primary}
            for alias, subkey in zip(aliases, subkeys)
        ]

    @classmethod
    def gpg(
        cls, args: list[str], *, home: Path
    ) -> subprocess.CompletedProcess[str]:
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

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifacts_dir = self.root / "artifacts"
        self.artifacts_dir.mkdir()
        self.keys_dir = self.root / "keys"
        self.keys_dir.mkdir()
        (self.keys_dir / "public-keys").mkdir()
        self.policy = self.keys_dir / "keys.json"
        self.tag = "v1.0.0-testnet1"
        self.version = self.tag[1:]
        self.export_public_keys(self.signers)
        self.write_policy(self.signers[:3], quorum=2, set_size=3)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def export_public_keys(self, signers: list[dict[str, str]]) -> None:
        for signer in signers:
            result = self.gpg(
                ["--batch", "--armor", "--export", signer["fingerprint"]],
                home=self.secret_home,
            )
            public_key_file = self.keys_dir / signer["public_key_file"]
            public_key_file.parent.mkdir(parents=True, exist_ok=True)
            public_key_file.write_text(result.stdout, encoding="utf8")

    def write_policy(
        self, signers: list[dict[str, str]], *, quorum: int, set_size: int
    ) -> None:
        signer_entries = []
        for signer in signers:
            status = signer.get("status", "active")
            capabilities = list(
                signer.get(
                    "capabilities",
                    ["release-signing", "builder-attestation"] if status == "active" else [],
                )
            )
            release_lines = list(
                signer.get("release_lines", ["testnet"] if status == "active" else [])
            )
            artifact_sets = list(
                signer.get(
                    "artifact_sets",
                    ["core", "photon"] if "builder-attestation" in capabilities else [],
                )
            )
            entry = {
                "alias": signer["alias"],
                "status": status,
                "key_origin": signer.get(
                    "key_origin",
                    "qbit-generated" if signer["alias"].startswith("operator-") else "external-gpg",
                ),
                "public_key_file": signer["public_key_file"],
                "signing_fingerprint": signer["fingerprint"],
                "release_lines": release_lines,
                "capabilities": capabilities,
                "artifact_sets": artifact_sets,
                "created": "2026-06-08",
                "first_release": "v1.0.0-testnet1",
            }
            if status in {"revoked", "lost"}:
                entry["revocation_date"] = "2026-06-09"
            signer_entries.append(entry)

        builder_count = sum(
            1
            for signer in signer_entries
            if signer["status"] == "active"
            and "testnet" in signer["release_lines"]
            and "builder-attestation" in signer["capabilities"]
        )
        self.policy.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "policy_id": "qbit-release-keys-testnet-000001",
                    "policy_sequence": 1,
                    "previous_policy_sha256": None,
                    "effective_from_tag": "v1.0.0-testnet1",
                    "release_lines": {
                        "testnet": {
                            "active_signer_set_size": set_size,
                            "release_signature_quorum": quorum,
                            "builder_attestation_quorum": max(1, min(2, builder_count)),
                            "policy_change_quorum": max(1, min(2, set_size)),
                        }
                    },
                    "signers": signer_entries,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf8",
        )

    def write_artifact(self, name: str, data: bytes = b"release artifact\n") -> None:
        (self.artifacts_dir / name).write_bytes(data)

    def write_sha256sums(self, names: list[str]) -> None:
        lines = []
        for name in sorted(names):
            digest = hashlib.sha256((self.artifacts_dir / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (self.artifacts_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf8")

    def sign_manifest(
        self,
        signers: list[dict[str, str]],
        *,
        output_aliases: list[str] | None = None,
    ) -> None:
        for index, signer in enumerate(signers):
            alias = output_aliases[index] if output_aliases else signer["alias"]
            output = self.artifacts_dir / f"SHA256SUMS.{alias}.asc"
            faked = ["--faked-system-time", f"{signer['faked_time']}!"] if signer.get("faked_time") else []
            self.gpg(
                [
                    *faked,
                    "--batch",
                    "--yes",
                    "--armor",
                    "--detach-sign",
                    "--local-user",
                    signer.get("local_user", signer["fingerprint"]),
                    "--output",
                    str(output),
                    str(self.artifacts_dir / "SHA256SUMS"),
                ],
                home=self.secret_home,
            )

    def write_combined_signature(self, aliases: list[str]) -> None:
        combined = b"".join(
            (self.artifacts_dir / f"SHA256SUMS.{alias}.asc").read_bytes()
            for alias in aliases
        )
        (self.artifacts_dir / "SHA256SUMS.asc").write_bytes(combined)

    def prepare_valid_staging(
        self, *, signers: list[dict[str, str]] | None = None, name: str | None = None
    ) -> str:
        active_signers = signers or self.signers[:2]
        artifact_name = name or f"qbit-{self.version}-x86_64-linux-gnu.tar.gz"
        self.write_artifact(artifact_name)
        self.write_sha256sums([artifact_name])
        self.sign_manifest(active_signers)
        self.write_combined_signature([signer["alias"] for signer in active_signers])
        return artifact_name

    def run_validator(
        self, *extra_args: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--artifacts-dir",
                str(self.artifacts_dir),
                "--tag",
                self.tag,
                "--release-line",
                "testnet",
                "--operator-key-policy",
                str(self.policy),
                "--operator-keys-dir",
                str(self.keys_dir),
                "--gpg",
                GPG,
                *extra_args,
            ],
            check=False,
            capture_output=True,
            cwd=cwd,
            text=True,
        )

    def policy_sha256(self) -> str:
        return hashlib.sha256(self.policy.read_bytes()).hexdigest()

    def create_signed_tag_repo(self, signer: dict[str, str]) -> Path:
        repo = self.root / "repo"
        repo.mkdir()
        env = os.environ.copy()
        env["GNUPGHOME"] = str(self.secret_home)
        subprocess.run([GIT, "init"], cwd=repo, check=True, capture_output=True, text=True)
        subprocess.run(
            [GIT, "config", "user.name", "qbit test"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [GIT, "config", "user.email", "qbit-test@example.invalid"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        # The fixture signs its release tag explicitly below. Keep the setup
        # commit independent of a developer's global commit.gpgsign setting.
        subprocess.run(
            [GIT, "config", "commit.gpgsign", "false"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        (repo / "README.md").write_text("qbit\n", encoding="utf8")
        subprocess.run([GIT, "add", "README.md"], cwd=repo, check=True, capture_output=True, text=True)
        subprocess.run(
            [GIT, "commit", "-m", "initial"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                GIT,
                "-c",
                f"gpg.program={GPG}",
                "-c",
                f"user.signingkey={signer['fingerprint']}",
                "tag",
                "-s",
                self.tag,
                "-m",
                "qbit test release",
            ],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return repo

    def test_valid_staging_succeeds_and_writes_github_output(self) -> None:
        self.prepare_valid_staging()
        github_output = self.root / "github-output.txt"

        result = self.run_validator("--github-output", str(github_output))

        self.assertEqual(result.returncode, 0, result.stderr)
        output = github_output.read_text(encoding="utf8")
        self.assertIn("release_signature_count=2", output)
        self.assertIn("release_signature_quorum=2", output)
        self.assertIn("release_signer_count=3", output)
        self.assertIn("release_signature_aliases=operator-01,operator-02", output)
        self.assertIn(f"keys_json_sha256={self.policy_sha256()}", output)
        self.assertIn(f"policy_sha256={self.policy_sha256()}", output)
        self.assertIn(str(self.artifacts_dir / "SHA256SUMS.operator-01.asc"), output)
        self.assertIn(str(self.artifacts_dir / "SHA256SUMS.operator-02.asc"), output)
        self.assertIn(f"keys_json_sha256={self.policy_sha256()}", result.stdout)

    def test_extra_unmanifested_file_fails(self) -> None:
        self.prepare_valid_staging()
        self.write_artifact(f"qbit-{self.version}-extra-linux-gnu.tar.gz")

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("not covered by SHA256SUMS", result.stderr)

    def test_missing_manifested_file_fails(self) -> None:
        artifact_name = self.prepare_valid_staging()
        (self.artifacts_dir / artifact_name).unlink()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing files listed", result.stderr)

    def test_tampered_artifact_hash_fails(self) -> None:
        artifact_name = self.prepare_valid_staging()
        (self.artifacts_dir / artifact_name).write_bytes(b"tampered\n")

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("SHA256 mismatch", result.stderr)

    def test_invalid_signature_fails(self) -> None:
        self.prepare_valid_staging()
        (self.artifacts_dir / "SHA256SUMS.operator-01.asc").write_text(
            "not a signature\n", encoding="utf8"
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("does not verify", result.stderr)

    def test_combined_release_signature_allowed_after_combine(self) -> None:
        self.prepare_valid_staging()

        result = self.run_validator()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_combined_release_signature_fails(self) -> None:
        self.prepare_valid_staging()
        (self.artifacts_dir / "SHA256SUMS.asc").unlink()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing files listed", result.stderr)
        self.assertIn("SHA256SUMS.asc", result.stderr)

    def test_invalid_combined_release_signature_fails(self) -> None:
        self.prepare_valid_staging()
        (self.artifacts_dir / "SHA256SUMS.asc").write_text(
            "not a combined signature\n", encoding="utf8"
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("SHA256SUMS.asc does not verify", result.stderr)

    def test_combined_release_signature_must_match_individual_signatures(self) -> None:
        self.prepare_valid_staging()
        self.write_combined_signature(["operator-01"])

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "SHA256SUMS.asc valid signer set does not match individual release signatures",
            result.stderr,
        )
        self.assertIn("missing operator-02", result.stderr)

    def test_combined_release_signature_rejects_extra_active_signer(self) -> None:
        self.prepare_valid_staging()
        self.sign_manifest([self.signers[2]])
        extra_signature = (self.artifacts_dir / "SHA256SUMS.operator-03.asc").read_bytes()
        (self.artifacts_dir / "SHA256SUMS.operator-03.asc").unlink()
        combined = b"".join(
            [
                (self.artifacts_dir / "SHA256SUMS.operator-01.asc").read_bytes(),
                (self.artifacts_dir / "SHA256SUMS.operator-02.asc").read_bytes(),
                extra_signature,
            ]
        )
        (self.artifacts_dir / "SHA256SUMS.asc").write_bytes(combined)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "SHA256SUMS.asc valid signer set does not match individual release signatures",
            result.stderr,
        )
        self.assertIn("extra operator-03", result.stderr)

    def test_signers_sharing_a_primary_key_count_once(self) -> None:
        shared = self.generate_shared_primary_signers("release-shared", ["shared-01", "shared-02"])
        for signer in shared:
            signer["public_key_file"] = f"public-keys/{signer['alias']}-release.asc"
        signers = [*shared, self.signers[2]]
        self.export_public_keys(shared)
        self.write_policy(signers, quorum=3, set_size=3)
        self.prepare_valid_staging(signers=signers)

        result = self.run_validator()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Release signature quorum not met", result.stderr)
        self.assertIn("by distinct primary keys", result.stderr)

        # Two distinct primary keys still meet a quorum of two.
        self.write_policy(signers, quorum=2, set_size=3)
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signatures_by_revoked_or_expired_keys_do_not_count(self) -> None:
        revoked = self.generate_signer(20, "operator-20")
        expired = self.generate_signer(21, "operator-21", faked_time="20200101T000000", expire="1d")
        for signer in (revoked, expired):
            with self.subTest(alias=signer["alias"]):
                for name in list(self.artifacts_dir.iterdir()):
                    name.unlink()
                signers = [self.signers[0], signer]
                self.write_policy(signers, quorum=2, set_size=2)
                self.prepare_valid_staging(signers=signers)
                if signer is revoked:
                    revocation = self.secret_home / "openpgp-revocs.d" / f"{signer['fingerprint']}.rev"
                    certificate = self.root / "revocation.asc"
                    certificate.write_text(revocation.read_text(encoding="utf8").replace(":-----BEGIN", "-----BEGIN"), encoding="utf8")
                    self.gpg(["--batch", "--import", str(certificate)], home=self.secret_home)
                self.export_public_keys([signer])

                result = self.run_validator()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("GPG verification produced no valid signature", result.stderr)

    def test_release_signature_under_quorum_fails(self) -> None:
        self.prepare_valid_staging(signers=self.signers[:1])

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("Release signature quorum not met", result.stderr)

    def test_boolean_release_signature_quorum_fails_closed(self) -> None:
        data = json.loads(self.policy.read_text(encoding="utf8"))
        data["release_lines"]["testnet"]["release_signature_quorum"] = True
        self.policy.write_text(json.dumps(data), encoding="utf8")

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("release_signature_quorum: must be an integer", result.stderr)

    def test_operator_policy_rejects_legacy_signing_subkey_fingerprint(self) -> None:
        data = json.loads(self.policy.read_text(encoding="utf8"))
        data["signers"][0]["signing_subkey_fingerprint"] = data["signers"][0].pop(
            "signing_fingerprint"
        )
        self.policy.write_text(json.dumps(data), encoding="utf8")
        self.prepare_valid_staging()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported field(s): signing_subkey_fingerprint", result.stderr)

    def test_external_policy_alias_is_accepted(self) -> None:
        external = dict(
            self.signers[3],
            capabilities=["release-signing", "builder-attestation"],
            artifact_sets=["core", "photon"],
            key_origin="external-gpg",
        )
        self.write_policy([self.signers[0], self.signers[1], external], quorum=2, set_size=3)
        self.prepare_valid_staging(signers=[self.signers[0], external])

        result = self.run_validator()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("counted aliases=external-01,operator-01", result.stdout)

    def test_extra_active_release_signer_fails_closed(self) -> None:
        self.write_policy(self.signers[:3], quorum=2, set_size=2)
        self.prepare_valid_staging(signers=self.signers[:2])

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("active signer count must be exactly 2, got 3", result.stderr)

    def test_wrong_signer_fails(self) -> None:
        artifact_name = f"qbit-{self.version}-x86_64-linux-gnu.tar.gz"
        self.write_artifact(artifact_name)
        self.write_sha256sums([artifact_name])
        self.sign_manifest(
            [self.signers[0], self.signers[2]],
            output_aliases=["operator-01", "operator-02"],
        )
        self.write_combined_signature(["operator-01", "operator-02"])

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("was signed by unexpected fingerprint", result.stderr)

    def test_unexpected_signer_alias_fails(self) -> None:
        self.prepare_valid_staging()
        self.sign_manifest([self.signers[3]])

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("release signature for non-active release signer", result.stderr)

    def test_revoked_signer_does_not_count(self) -> None:
        revoked = dict(
            self.signers[4],
            status="revoked",
            release_lines=[],
            capabilities=[],
            artifact_sets=[],
        )
        self.write_policy([self.signers[0], self.signers[1], revoked], quorum=2, set_size=2)
        self.prepare_valid_staging()
        self.sign_manifest([revoked])

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("release signature for non-active release signer", result.stderr)

    def test_wrong_public_certificate_fails(self) -> None:
        wrong_cert = (self.keys_dir / self.signers[1]["public_key_file"]).read_text(encoding="utf8")
        (self.keys_dir / self.signers[0]["public_key_file"]).write_text(wrong_cert, encoding="utf8")
        self.prepare_valid_staging()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("Active release fingerprints are not present", result.stderr)

    def test_primary_public_certificate_file_fails(self) -> None:
        (self.keys_dir / "qbit-operator-primary-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.asc").write_text(
            "legacy shared public cert\n",
            encoding="utf8",
        )
        self.prepare_valid_staging()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("primary public certificate files are not allowed", result.stderr)

    def test_photon_requirement_fails_when_photon_missing(self) -> None:
        self.prepare_valid_staging()

        result = self.run_validator("--require-photon-artifact")

        self.assertEqual(result.returncode, 1)
        self.assertIn("PHOTON artifact is required", result.stderr)

    def test_photon_requirement_succeeds_when_present(self) -> None:
        core = f"qbit-{self.version}-x86_64-linux-gnu.tar.gz"
        photon = f"qbit-photon-{self.version}-x86_64-linux-gnu.tar.gz"
        self.write_artifact(core)
        self.write_artifact(photon)
        self.write_sha256sums([core, photon])
        self.sign_manifest(self.signers[:2])
        self.write_combined_signature(["operator-01", "operator-02"])

        result = self.run_validator("--require-photon-artifact")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsigned_platform_artifact_requires_waiver(self) -> None:
        self.prepare_valid_staging(
            name=f"qbit-{self.version}-x86_64-apple-darwin-unsigned.zip"
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("Unsigned platform artifact requires an explicit waiver", result.stderr)

        waived = self.run_validator("--allow-unsigned-platform-artifacts")
        self.assertEqual(waived.returncode, 0, waived.stderr)

    def test_darwin_debug_archives_need_no_waiver(self) -> None:
        # v1.0.1 adds macOS debug tarballs; staging without them, as for
        # v1.0.0, is covered by the other tests.
        names = [
            f"qbit-{self.version}-x86_64-linux-gnu.tar.gz",
            f"qbit-{self.version}-x86_64-linux-gnu-debug.tar.gz",
            f"qbit-{self.version}-x86_64-apple-darwin-debug.tar.gz",
            f"qbit-{self.version}-arm64-apple-darwin-debug.tar.gz",
        ]
        for name in names:
            self.write_artifact(name)
        self.write_sha256sums(names)
        self.sign_manifest(self.signers[:2])
        self.write_combined_signature(["operator-01", "operator-02"])
        github_output = self.root / "github-output.txt"

        result = self.run_validator("--github-output", str(github_output))

        self.assertEqual(result.returncode, 0, result.stderr)
        output = github_output.read_text(encoding="utf8")
        self.assertIn("core_artifact_count=4", output)
        for name in names:
            self.assertIn(str(self.artifacts_dir / name), output)

    def test_codesigning_payload_fails(self) -> None:
        self.prepare_valid_staging(
            name=f"qbit-{self.version}-x86_64-apple-darwin-codesigning.tar.gz"
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("Codesigning payloads are not public release artifacts", result.stderr)

    def test_release_tag_signature_can_be_verified_with_active_release_key(self) -> None:
        self.prepare_valid_staging()
        repo = self.create_signed_tag_repo(self.signers[0])

        result = self.run_validator("--verify-tag-signature", cwd=repo)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_tag_signature_is_read_from_the_tag_ref(self) -> None:
        # Branches named like the tag or like its ref make those names ambiguous
        # to git, and git looks a bare name up as refs/<name> before refs/tags/<name>.
        self.prepare_valid_staging()
        repo = self.create_signed_tag_repo(self.signers[0])
        for branch in (self.tag, f"refs/tags/{self.tag}"):
            subprocess.run([GIT, "branch", branch], cwd=repo, check=True, capture_output=True)
        subprocess.run([GIT, "update-ref", f"refs/{self.tag}", "HEAD"], cwd=repo, check=True, capture_output=True)

        result = self.run_validator("--verify-tag-signature", cwd=repo)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_tag_signature_from_non_policy_key_fails(self) -> None:
        self.prepare_valid_staging()
        repo = self.create_signed_tag_repo(self.signers[3])

        result = self.run_validator("--verify-tag-signature", cwd=repo)

        self.assertEqual(result.returncode, 1)
        self.assertIn("not signed by an active qbit release key", result.stderr)


    def stage_forged_signatures(self) -> dict[str, str]:
        """operator-04 signs SHA256SUMS as itself and as operator-02, whose good signature its user ID poses as."""

        victim = self.signers[1]
        self.export_public_keys([self.forger])
        self.write_policy([self.signers[0], victim, self.forger], quorum=2, set_size=3)
        name = f"qbit-{self.version}-x86_64-linux-gnu.tar.gz"
        self.write_artifact(name)
        self.write_sha256sums([name])
        self.sign_manifest([self.forger, self.forger], output_aliases=["operator-02", "operator-04"])
        self.write_combined_signature(["operator-02", "operator-04"])
        status = subprocess.run(
            [GPG, "--homedir", str(self.secret_home), "--batch", "--trust-model", "always", "--status-fd", "1",
             "--verify", str(self.artifacts_dir / "SHA256SUMS.operator-02.asc"), str(self.artifacts_dir / "SHA256SUMS")],
            check=True, capture_output=True,
        ).stdout
        # A reader splitting at U+2028 would see operator-02's good signature.
        self.assertIn(f"[GNUPG:] GOODSIG {victim['fingerprint'][-16:]} victim", status.decode().splitlines())
        return victim

    def test_a_signer_whose_user_id_poses_as_another_signer_is_refused(self) -> None:
        self.stage_forged_signatures()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("line separator other than a line feed (U+2028)", result.stderr)

    def test_signature_checks_refuse_status_lines_a_user_id_adds(self) -> None:
        victim = self.stage_forged_signatures()
        home = self.root / "gnupg"
        home.mkdir(mode=0o700)
        for signer in (victim, self.forger):
            self.gpg(["--batch", "--import", str(self.keys_dir / signer["public_key_file"])], home=home)
        policy = validate_release_artifacts.load_release_policy(self.policy, self.keys_dir, "testnet")
        error = validate_release_artifacts.ReleaseValidationError

        with self.assertRaisesRegex(error, re.escape("SHA256SUMS.operator-02.asc: gpg status output line ") + r"\d+ holds a line separator other than a line feed \(U\+2028\)"):
            validate_release_artifacts.verify_manifest_signature_file(
                GPG,
                home,
                self.artifacts_dir / "SHA256SUMS.operator-02.asc",
                self.artifacts_dir / "SHA256SUMS",
                next(signer for signer in policy.release_signers if signer.alias == "operator-02"),
            )
        repo = self.create_signed_tag_repo(self.forger)
        previous = os.getcwd()
        os.chdir(repo)
        try:
            pattern = re.escape(f"Release tag {self.tag}: git verify-tag --raw output line ") + r"\d+ holds a line separator other than a line feed \(U\+2028\)"
            with self.assertRaisesRegex(error, pattern):
                validate_release_artifacts.verify_tag_signature(GPG, home, self.tag, policy)
        finally:
            os.chdir(previous)


class ReleasePublisherBoundaryTest(unittest.TestCase):
    def test_github_and_source_binding_checks_stay_in_publisher(self) -> None:
        publisher = PUBLISH_LOCAL.read_text(encoding="utf8")

        self.assertIn(".verification.verified", publisher)
        self.assertIn("not a GitHub-verified signed tag", publisher)
        self.assertIn('"$remote_target_type" = commit', publisher)
        self.assertIn('"$remote_verification_reason" = valid', publisher)
        self.assertIn("verify_remote_tag_pin pre-publication", publisher)
        self.assertIn("verify_remote_tag_pin post-publication", publisher)
        self.assertIn("merge-base --is-ancestor", publisher)
        self.assertIn("ci/release/validate_release_artifacts.py", publisher)
        self.assertIn("ci/release/verify_mainnet_release_posture.py", publisher)
        self.assertIn("ci/release/verify_testnet_release_posture.py", publisher)
        self.assertIn('--source-root "$TRUSTED_ROOT"', publisher)
        self.assertIn('--expected-tag-target "$TAG_TARGET"', publisher)
        self.assertIn("builder_attestation_source_sha256", publisher)
        self.assertIn("Release $TAG already exists and is published", publisher)

        validator_source = VALIDATOR.read_text(encoding="utf8")
        self.assertNotIn("github.rest", validator_source)
        self.assertNotIn("gh api", validator_source)
        self.assertNotIn("GITHUB_TOKEN", validator_source)

if __name__ == "__main__":
    unittest.main()
