#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for validate_builder_attestations.py."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDER_VALIDATOR = REPO_ROOT / "ci" / "release" / "validate_builder_attestations.py"
GPG = shutil.which("gpg")
GIT = shutil.which("git")


@unittest.skipUnless(GPG and GIT, "gpg and git are required for builder attestation tests")
class ValidateBuilderAttestationsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_tmp = tempfile.TemporaryDirectory()
        cls.tmp_path = Path(cls.class_tmp.name)
        cls.secret_home = cls.tmp_path / "secret-gnupg"
        cls.secret_home.mkdir(mode=0o700)
        cls.builders = [cls.generate_builder(index) for index in range(1, 5)]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_tmp.cleanup()

    @classmethod
    def generate_builder(cls, index: int) -> dict[str, str]:
        batch = cls.tmp_path / f"builder-{index}.batch"
        batch.write_text(
            "\n".join(
                [
                    "Key-Type: eddsa",
                    "Key-Curve: ed25519",
                    "Key-Usage: sign",
                    f"Name-Real: qbit builder {index}",
                    f"Name-Email: builder-{index}@example.invalid",
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
                f"builder-{index}@example.invalid",
            ],
            home=cls.secret_home,
        )
        fingerprint = next(
            line.split(":")[9]
            for line in list_result.stdout.splitlines()
            if line.startswith("fpr:")
        )
        alias = f"operator-{index:02d}"
        return {
            "alias": alias,
            "fingerprint": fingerprint,
        }

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

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifacts_dir = self.root / "artifacts"
        self.artifacts_dir.mkdir()
        self.guix_sigs_repo = self.root / "qbit-guix.sigs"
        self.guix_sigs_repo.mkdir()
        self.keys_dir = self.root / "operator-keys"
        self.keys_dir.mkdir()
        self.policy = self.keys_dir / "keys.json"
        self.mirror_keys_dir = self.guix_sigs_repo / "operator-keys"
        self.mirror_keys_dir.mkdir()
        self.mirror_policy = self.mirror_keys_dir / "keys.json"
        self.tag = "v1.0.0-testnet1"
        self.version = self.tag[1:]
        self.source_root = self.root / "source"
        self.source_root.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "qbit release fixture")
        self.git("config", "user.email", "release-fixture@example.invalid")
        (self.source_root / "README.md").write_text("qbit release fixture\n", encoding="utf8")
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "initial release source")
        self.git("tag", "-a", self.tag, "-m", "release fixture")
        self.tag_target = self.git("rev-parse", f"{self.tag}^{{commit}}").stdout.strip()
        self.source_archive = f"qbit-{self.version}.tar.gz"
        self.source_sha256 = self.archive_sha256(self.tag_target, self.source_archive)
        self.core_artifact = f"qbit-{self.version}-x86_64-linux-gnu.tar.gz"
        self.photon_artifact = f"qbit-photon-{self.version}-x86_64-linux-gnu.tar.gz"
        self.write_operator_policy(self.builders[:3])
        self.write_release_sha256sums([self.core_artifact])
        self.write_attestations(self.builders[:2], "core", [self.core_artifact])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                GIT,
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                *args,
            ],
            cwd=self.source_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"git failed: {' '.join(args)}\nstdout={result.stdout}\nstderr={result.stderr}"
            )
        return result

    def archive_sha256(self, target: str, name: str) -> str:
        archive = self.root / f"{hashlib.sha256(target.encode()).hexdigest()}-{name}"
        self.git(
            "archive",
            f"--prefix=qbit-{self.version}/",
            f"--output={archive}",
            target,
        )
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.unlink()
        return digest

    def public_key_file(self, alias: str) -> str:
        return f"public-keys/{alias}-release.asc"

    def signer_entry(
        self,
        signer: dict[str, str],
        *,
        key_origin: str = "qbit-generated",
        status: str = "active",
        release_lines: list[str] | None = None,
        capabilities: list[str] | None = None,
        artifact_sets: list[str] | None = None,
    ) -> dict[str, object]:
        alias = signer["alias"]
        return {
            "alias": alias,
            "status": status,
            "key_origin": key_origin,
            "public_key_file": self.public_key_file(alias),
            "signing_fingerprint": signer["fingerprint"],
            "release_lines": ["testnet"] if release_lines is None else release_lines,
            "capabilities": (
                ["release-signing", "builder-attestation"]
                if capabilities is None
                else capabilities
            ),
            "artifact_sets": ["core", "photon"] if artifact_sets is None else artifact_sets,
            "created": "2026-06-05",
            "first_release": self.tag,
        }

    def write_json(self, path: Path, data: dict[str, object]) -> None:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf8")

    def reset_public_key_dir(self, keys_dir: Path) -> None:
        shutil.rmtree(keys_dir / "public-keys", ignore_errors=True)
        (keys_dir / "public-keys").mkdir()

    def export_public_keys(self, signers: list[dict[str, str]], keys_dir: Path) -> None:
        for signer in signers:
            result = self.gpg(
                ["--batch", "--armor", "--export", signer["fingerprint"]],
                home=self.secret_home,
            )
            public_key_path = keys_dir / self.public_key_file(signer["alias"])
            public_key_path.parent.mkdir(parents=True, exist_ok=True)
            public_key_path.write_text(result.stdout, encoding="utf8")

    def write_operator_policy(
        self,
        signers: list[dict[str, str]],
        *,
        mirror: bool = True,
        testnet_builder_quorum: int = 2,
        active_signer_set_size: int | None = None,
        policy_sequence: int = 1,
        previous_policy_sha256: str | None = None,
        signer_overrides: dict[str, dict[str, object]] | None = None,
    ) -> dict[str, object]:
        signer_overrides = signer_overrides or {}
        entries: list[dict[str, object]] = []
        for signer in signers:
            entry = self.signer_entry(signer)
            entry.update(signer_overrides.get(signer["alias"], {}))
            entries.append(entry)

        set_size = active_signer_set_size if active_signer_set_size is not None else len(signers)
        data: dict[str, object] = {
            "schema_version": 2,
            "policy_id": f"qbit-release-keys-testnet-{policy_sequence:06d}",
            "policy_sequence": policy_sequence,
            "previous_policy_sha256": (
                None if policy_sequence == 1 else previous_policy_sha256 or "0" * 64
            ),
            "effective_from_tag": self.tag,
            "release_lines": {
                "testnet": {
                    "active_signer_set_size": set_size,
                    "release_signature_quorum": min(2, set_size),
                    "builder_attestation_quorum": testnet_builder_quorum,
                    "policy_change_quorum": min(2, set_size),
                }
            },
            "signers": entries,
        }
        self.write_json(self.policy, data)
        self.reset_public_key_dir(self.keys_dir)
        self.export_public_keys(signers, self.keys_dir)
        if mirror:
            self.write_json(self.mirror_policy, data)
            self.reset_public_key_dir(self.mirror_keys_dir)
            self.export_public_keys(signers, self.mirror_keys_dir)
        return data

    def policy_sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_approval_files(
        self,
        policy: dict[str, object],
        *,
        approvers: list[str] | None = None,
    ) -> None:
        approvers = approvers or ["operator-01", "operator-02"]
        for keys_dir in (self.keys_dir, self.mirror_keys_dir):
            approval_dir = keys_dir / "approvals" / str(policy["policy_id"])
            approval_dir.mkdir(parents=True)
            (approval_dir / "approval-note.md").write_text(
                "Policy transition approval.\n",
                encoding="utf8",
            )
            (approval_dir / "policy.SHA256").write_text(
                f"{self.policy_sha256(keys_dir / 'keys.json')}  keys.json\n",
                encoding="utf8",
            )
            for approver in approvers:
                (approval_dir / f"{approver}.asc").write_text(
                    "detached signature placeholder\n",
                    encoding="utf8",
                )

    def write_release_sha256sums(self, names: list[str]) -> None:
        lines = []
        for name in names:
            (self.artifacts_dir / name).write_bytes(f"{name}\n".encode("utf8"))
            digest = hashlib.sha256((self.artifacts_dir / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (self.artifacts_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf8")

    def manifest_line(self, name: str) -> str:
        digest = hashlib.sha256((self.artifacts_dir / name).read_bytes()).hexdigest()
        return f"{digest}  {name}\n"

    def write_attestations(
        self,
        builders: list[dict[str, str]],
        artifact: str,
        names: list[str],
        *,
        tamper: bool = False,
        omit_source: bool = False,
        source_name: str | None = None,
        source_digest: str | None = None,
        manifest_type: str = "noncodesigned",
    ) -> None:
        prefix = "" if artifact == "core" else f"{artifact}-"
        manifest_name = f"{prefix}{manifest_type}.SHA256SUMS"
        for builder in builders:
            builder_dir = self.guix_sigs_repo / self.version / builder["alias"]
            builder_dir.mkdir(parents=True, exist_ok=True)
            manifest = builder_dir / manifest_name
            lines = [self.manifest_line(name) for name in names]
            if tamper:
                lines[0] = "0" * 64 + f"  {names[0]}\n"
            if not omit_source:
                lines.append(
                    f"{source_digest or self.source_sha256}  "
                    f"{source_name or self.source_archive}\n"
                )
            manifest.write_text("".join(lines), encoding="utf8")
            self.gpg(
                [
                    "--batch",
                    "--yes",
                    "--armor",
                    "--detach-sign",
                    "--local-user",
                    builder["fingerprint"],
                    "--output",
                    str(manifest) + ".asc",
                    str(manifest),
                ],
                home=self.secret_home,
            )

    def attestation_signature(
        self,
        builder: dict[str, str],
        artifact: str,
        manifest_type: str = "noncodesigned",
    ) -> Path:
        prefix = "" if artifact == "core" else f"{artifact}-"
        manifest_name = f"{prefix}{manifest_type}.SHA256SUMS"
        manifest = self.guix_sigs_repo / self.version / builder["alias"] / manifest_name
        return Path(f"{manifest}.asc")

    def run_builder_validator(self, *extra_args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(BUILDER_VALIDATOR),
                "--artifacts-dir",
                str(self.artifacts_dir),
                "--tag",
                self.tag,
                "--source-root",
                str(self.source_root),
                "--expected-tag-target",
                self.tag_target,
                "--release-line",
                "testnet",
                "--guix-sigs-repo",
                str(self.guix_sigs_repo),
                "--operator-key-policy",
                str(self.policy),
                "--operator-keys-dir",
                str(self.keys_dir),
                "--guix-operator-key-policy",
                str(self.mirror_policy),
                "--guix-operator-keys-dir",
                str(self.mirror_keys_dir),
                "--gpg",
                GPG,
                "--git",
                GIT,
                *extra_args,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_valid_core_attestation_quorum_succeeds(self) -> None:
        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("core:2/2", result.stdout)
        self.assertIn(
            f"source={self.source_archive}:{self.source_sha256}",
            result.stdout,
        )
        self.assertIn(f"tag_target={self.tag_target}", result.stdout)

    def test_source_archive_evidence_is_written_to_github_output(self) -> None:
        github_output = self.root / "github-output.txt"

        result = self.run_builder_validator("--github-output", str(github_output))

        self.assertEqual(result.returncode, 0, result.stderr)
        output = github_output.read_text(encoding="utf8")
        self.assertIn(f"builder_attestation_source_archive={self.source_archive}\n", output)
        self.assertIn(f"builder_attestation_source_sha256={self.source_sha256}\n", output)
        self.assertIn(f"builder_attestation_tag_target={self.tag_target}\n", output)

    def test_missing_source_archive_fails_quorum(self) -> None:
        self.write_attestations(
            [self.builders[1]],
            "core",
            [self.core_artifact],
            omit_source=True,
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("core builder attestation quorum not met: got 1, need 2", result.stderr)
        self.assertIn(
            f"operator-02: manifest is missing canonical source archive {self.source_archive}",
            result.stderr,
        )

    def test_renamed_source_archive_fails_quorum(self) -> None:
        self.write_attestations(
            self.builders[:2],
            "core",
            [self.core_artifact],
            source_name=f"renamed-{self.source_archive}",
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"missing canonical source archive {self.source_archive}", result.stderr)

    def test_wrong_source_archive_digest_fails_quorum(self) -> None:
        self.write_attestations(
            self.builders[:2],
            "core",
            [self.core_artifact],
            source_digest="0" * 64,
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            f"expected {self.source_sha256} from signed tag target",
            result.stderr,
        )

    def test_source_archive_from_different_commit_fails_quorum(self) -> None:
        (self.source_root / "README.md").write_text(
            "different release source\n",
            encoding="utf8",
        )
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "different release source")
        other_target = self.git("rev-parse", "HEAD").stdout.strip()
        other_source_sha256 = self.archive_sha256(other_target, self.source_archive)
        self.write_attestations(
            self.builders[:2],
            "core",
            [self.core_artifact],
            source_digest=other_source_sha256,
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            f"expected {self.source_sha256} from signed tag target",
            result.stderr,
        )

    def test_invalid_source_manifest_does_not_block_met_quorum(self) -> None:
        self.write_attestations(
            self.builders[2:3],
            "core",
            [self.core_artifact],
            omit_source=True,
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("core:2/2", result.stdout)

    def test_all_manifest_cannot_bypass_source_binding(self) -> None:
        self.write_attestations(
            self.builders[:2],
            "core",
            [self.core_artifact],
            omit_source=True,
            manifest_type="all",
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"missing canonical source archive {self.source_archive}", result.stderr)

    def test_expected_tag_target_must_match_local_annotated_tag(self) -> None:
        (self.source_root / "README.md").write_text("new target\n", encoding="utf8")
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "new target")
        other_target = self.git("rev-parse", "HEAD").stdout.strip()

        result = self.run_builder_validator("--expected-tag-target", other_target)

        self.assertEqual(result.returncode, 1)
        self.assertIn("not verified target", result.stderr)

    def test_lightweight_release_tag_is_rejected(self) -> None:
        self.git("tag", "-d", self.tag)
        self.git("tag", self.tag, self.tag_target)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("must be an annotated tag object", result.stderr)

    def test_release_tag_must_directly_target_commit(self) -> None:
        inner_tag = "v1.0.0-testnet1-inner"
        self.git("tag", "-a", inner_tag, self.tag_target, "-m", "inner release tag")
        self.git("tag", "-d", self.tag)
        self.git("tag", "-a", self.tag, inner_tag, "-m", "outer release tag")

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("must directly target a commit", result.stderr)

    def test_missing_release_tag_is_rejected(self) -> None:
        self.git("tag", "-d", self.tag)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn(f"Failed to resolve annotated release tag {self.tag}", result.stderr)

    def test_invalid_expected_tag_target_is_rejected(self) -> None:
        result = self.run_builder_validator("--expected-tag-target", "abcd")

        self.assertEqual(result.returncode, 1)
        self.assertIn("must be a full 40-character commit SHA", result.stderr)

    def test_missing_source_root_is_rejected(self) -> None:
        result = self.run_builder_validator(
            "--source-root",
            str(self.root / "missing-source"),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Source root is not a directory", result.stderr)

    def test_under_quorum_fails(self) -> None:
        shutil.rmtree(self.guix_sigs_repo / self.version / "operator-02")

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("quorum not met", result.stderr)

    def test_release_policy_quorum_is_enforced(self) -> None:
        self.write_operator_policy(self.builders[:3], testnet_builder_quorum=3)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("need 3", result.stderr)

    def test_malformed_release_policy_fails_closed(self) -> None:
        self.policy.write_text("{not-json}\n", encoding="utf8")

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid JSON", result.stderr)

    def test_missing_release_line_fails_closed(self) -> None:
        data = json.loads(self.policy.read_text(encoding="utf8"))
        data["release_lines"]["mainnet"] = data["release_lines"].pop("testnet")
        for signer in data["signers"]:
            signer["release_lines"] = ["mainnet"]
        self.write_json(self.policy, data)
        self.write_json(self.mirror_policy, data)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("has no release line 'testnet'", result.stderr)

    def test_missing_builder_quorum_fails_closed(self) -> None:
        data = json.loads(self.policy.read_text(encoding="utf8"))
        del data["release_lines"]["testnet"]["builder_attestation_quorum"]
        self.write_json(self.policy, data)
        self.write_json(self.mirror_policy, data)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("builder_attestation_quorum", result.stderr)

    def test_mirror_policy_hash_mismatch_fails(self) -> None:
        data = json.loads(self.mirror_policy.read_text(encoding="utf8"))
        data["signers"][0]["notes"] = "fixture note"
        self.write_json(self.mirror_policy, data)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror file hash mismatch: keys.json", result.stderr)

    def test_mirror_missing_signer_public_cert_fails(self) -> None:
        (self.mirror_keys_dir / self.public_key_file("operator-01")).unlink()

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing signer public certificate", result.stderr)

    def test_mirror_public_cert_hash_mismatch_fails(self) -> None:
        (self.mirror_keys_dir / self.public_key_file("operator-01")).write_text(
            "tampered public cert\n",
            encoding="utf8",
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror file hash mismatch: public-keys/operator-01-release.asc", result.stderr)

    def test_mirror_extra_readme_and_hidden_files_fail(self) -> None:
        (self.mirror_keys_dir / "README.md").write_text("human docs\n", encoding="utf8")
        (self.mirror_keys_dir / ".DS_Store").write_text("hidden file\n", encoding="utf8")

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror file set does not match", result.stderr)
        self.assertIn(".DS_Store", result.stderr)
        self.assertIn("README.md", result.stderr)

    def test_mirror_symlinked_keys_json_is_rejected(self) -> None:
        # A symlinked mirror keys.json pointing at the trusted canonical file
        # would resolve to identical bytes; it must still be rejected because
        # the public mirror repo does not actually contain those bytes.
        self.mirror_policy.unlink()
        self.mirror_policy.symlink_to(self.policy)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("--guix-operator-key-policy must not be a symlink", result.stderr)

    def test_mirror_symlinked_public_cert_is_rejected(self) -> None:
        relative = self.public_key_file("operator-01")
        mirror_cert = self.mirror_keys_dir / relative
        canonical_cert = self.keys_dir / relative
        mirror_cert.unlink()
        mirror_cert.symlink_to(canonical_cert)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror file set does not match", result.stderr)
        self.assertIn(f"missing={relative}", result.stderr)

    def test_mirror_symlinked_public_keys_dir_is_rejected(self) -> None:
        # Symlinking the whole public-keys directory at the canonical tree must
        # not let the mirror borrow the canonical certificates.
        public_keys = self.mirror_keys_dir / "public-keys"
        shutil.rmtree(public_keys)
        public_keys.symlink_to(self.keys_dir / "public-keys", target_is_directory=True)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror file set does not match", result.stderr)
        self.assertIn("missing=", result.stderr)

    def test_mirror_symlinked_operator_keys_root_is_rejected(self) -> None:
        # The mirror root itself must contain the public policy bytes; otherwise a
        # local symlink can make validation pass without qbit-guix.sigs carrying
        # the mirrored operator-keys tree.
        shutil.rmtree(self.mirror_keys_dir)
        self.mirror_keys_dir.symlink_to(self.keys_dir, target_is_directory=True)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("--guix-operator-keys-dir must not be a symlink", result.stderr)

    def test_mirror_extra_primary_certificate_fails(self) -> None:
        (self.mirror_keys_dir / "qbit-operator-primary-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.asc").write_text(
            "legacy primary certificate\n",
            encoding="utf8",
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("primary public certificate files are not allowed", result.stderr)

    def test_mirror_approval_file_mismatch_fails(self) -> None:
        policy = self.write_operator_policy(
            self.builders[:3],
            policy_sequence=2,
            previous_policy_sha256="0" * 64,
        )
        self.write_approval_files(policy)
        mirror_approval = (
            self.mirror_keys_dir
            / "approvals"
            / str(policy["policy_id"])
            / "policy.SHA256"
        )
        mirror_approval.write_text("1" * 64 + "  keys.json\n", encoding="utf8")

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("operator key mirror file hash mismatch", result.stderr)
        self.assertIn("approvals/qbit-release-keys-testnet-000002/policy.SHA256", result.stderr)

    def test_operator_policy_requires_signing_fingerprint(self) -> None:
        data = json.loads(self.policy.read_text(encoding="utf8"))
        data["signers"][0]["fingerprint"] = data["signers"][0].pop(
            "signing_fingerprint"
        )
        self.write_json(self.policy, data)
        self.write_json(self.mirror_policy, data)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported field(s): fingerprint", result.stderr)

    def test_policy_signing_fingerprint_controls_attestation_trust(self) -> None:
        data = json.loads(self.policy.read_text(encoding="utf8"))
        data["signers"][1]["signing_fingerprint"] = "A" * 40
        self.write_json(self.policy, data)
        self.write_json(self.mirror_policy, data)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("not present in imported key material", result.stderr)

    def test_legacy_builder_alias_directory_does_not_count(self) -> None:
        (self.guix_sigs_repo / self.version / "operator-02").rename(
            self.guix_sigs_repo / self.version / "builder-02"
        )

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("core builder attestation quorum not met: got 1, need 2", result.stderr)

    def test_tampered_manifest_hash_fails_quorum(self) -> None:
        self.write_attestations(self.builders[:2], "core", [self.core_artifact], tamper=True)

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("quorum not met", result.stderr)

    def test_invalid_extra_builder_signature_does_not_block_met_quorum(self) -> None:
        self.write_attestations(self.builders[2:3], "core", [self.core_artifact])
        self.attestation_signature(self.builders[2], "core").unlink()

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("core:2/2", result.stdout)

    def test_invalid_builder_signature_does_not_count_for_quorum(self) -> None:
        shutil.rmtree(self.guix_sigs_repo / self.version / "operator-02")
        self.write_attestations(self.builders[2:3], "core", [self.core_artifact])
        self.attestation_signature(self.builders[2], "core").unlink()

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("core builder attestation quorum not met: got 1, need 2", result.stderr)
        self.assertIn("rejected=operator-03", result.stderr)

    def test_core_and_photon_quorum_succeeds(self) -> None:
        self.write_release_sha256sums([self.core_artifact, self.photon_artifact])
        self.write_attestations(self.builders[:2], "photon", [self.photon_artifact])

        result = self.run_builder_validator("--artifact", "core", "--artifact", "photon")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("core:2/2", result.stdout)
        self.assertIn("photon:2/2", result.stdout)

    def test_photon_manifest_without_source_archive_fails_photon_quorum(self) -> None:
        self.write_release_sha256sums([self.core_artifact, self.photon_artifact])
        self.write_attestations(self.builders[:2], "photon", [self.photon_artifact])
        self.write_attestations(
            [self.builders[1]],
            "photon",
            [self.photon_artifact],
            omit_source=True,
        )

        result = self.run_builder_validator("--artifact", "core", "--artifact", "photon")

        self.assertEqual(result.returncode, 1)
        self.assertIn("photon builder attestation quorum not met: got 1, need 2", result.stderr)
        self.assertIn(f"missing canonical source archive {self.source_archive}", result.stderr)

    def test_staged_photon_artifact_requires_photon_attestation_by_default(self) -> None:
        self.write_release_sha256sums([self.core_artifact, self.photon_artifact])

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("photon builder attestation quorum not met", result.stderr)

    def test_staged_photon_artifact_with_photon_attestations_succeeds_by_default(self) -> None:
        self.write_release_sha256sums([self.core_artifact, self.photon_artifact])
        self.write_attestations(self.builders[:2], "photon", [self.photon_artifact])

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("core:2/2", result.stdout)
        self.assertIn("photon:2/2", result.stdout)

    def test_external_builder_capable_signer_counts_for_quorum(self) -> None:
        external = {**self.builders[2], "alias": "external-01"}
        self.write_operator_policy(
            [self.builders[0], self.builders[1], external],
            signer_overrides={"external-01": {"key_origin": "external-gpg"}},
        )
        shutil.rmtree(self.guix_sigs_repo / self.version / "operator-02")
        self.write_attestations([external], "core", [self.core_artifact])

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("core:2/2", result.stdout)

    def test_external_release_only_signer_is_rejected_by_policy_parity(self) -> None:
        external = {**self.builders[2], "alias": "external-01"}
        self.write_operator_policy(
            [self.builders[0], self.builders[1], external],
            signer_overrides={
                "external-01": {
                    "key_origin": "external-gpg",
                    "capabilities": ["release-signing"],
                    "artifact_sets": [],
                }
            },
        )
        shutil.rmtree(self.guix_sigs_repo / self.version / "operator-02")
        self.write_attestations([external], "core", [self.core_artifact])

        result = self.run_builder_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("active release-signing and builder-attestation signer sets must match", result.stderr)

    def test_signer_without_artifact_set_does_not_count_for_that_artifact(self) -> None:
        self.write_operator_policy(
            self.builders[:3],
            signer_overrides={"operator-02": {"artifact_sets": ["core"]}},
        )
        self.write_release_sha256sums([self.core_artifact, self.photon_artifact])
        self.write_attestations(self.builders[:2], "photon", [self.photon_artifact])

        result = self.run_builder_validator("--artifact", "photon")

        self.assertEqual(result.returncode, 1)
        self.assertIn("photon builder attestation quorum not met: got 1, need 2", result.stderr)


if __name__ == "__main__":
    unittest.main()
