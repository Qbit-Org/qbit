#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for verify_testnet_release_posture.py."""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify_testnet_release_posture.py")

VALID_EVIDENCE = """\
testnet_only_mainnet_guard=enabled
no_flag_startup=mainnet_rejected
chain_main_startup=mainnet_rejected
testnet4_startup=testnet4_selected
mainnet_dns_seeds=none
mainnet_fixed_seeds=none
mainnet_archive_endpoints=none
"""

VALID_CHAINPARAMS_CPP = """\
class CMainParams : public CChainParams {
public:
    CMainParams() {
        vSeeds.clear();
        vFixedSeeds.clear();
    }
};

class CTestNetParams : public CChainParams {
};
"""

VALID_CHAINPARAMSSEEDS_H = """\
#include <array>
#include <cstdint>
static constexpr std::array<uint8_t, 0> chainparams_seed_main{{
}};
"""


class VerifyTestnetReleasePostureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "src" / "kernel").mkdir(parents=True)
        self.evidence = self.root / "posture.env"
        self.evidence.write_text(VALID_EVIDENCE, encoding="utf8")
        (self.root / "src" / "kernel" / "chainparams.cpp").write_text(
            VALID_CHAINPARAMS_CPP, encoding="utf8"
        )
        (self.root / "src" / "chainparamsseeds.h").write_text(
            VALID_CHAINPARAMSSEEDS_H, encoding="utf8"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_verifier(self, *extra_args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--evidence",
                str(self.evidence),
                "--source-root",
                str(self.root),
                *extra_args,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def commit_source_tree(self, tag: str) -> str:
        self.git("init")
        self.git("config", "user.name", "qbit tests")
        self.git("config", "user.email", "qbit-tests@example.com")
        self.git("add", "src/kernel/chainparams.cpp", "src/chainparamsseeds.h")
        self.git("commit", "-m", "source")
        self.git("tag", tag)
        return self.git("rev-parse", f"{tag}^{{commit}}").stdout.strip()

    def write_evidence(self, *, release_tag: str, source_commit: str) -> None:
        self.evidence.write_text(
            VALID_EVIDENCE
            + f"release_tag={release_tag}\n"
            + f"source_commit={source_commit}\n",
            encoding="utf8",
        )

    def write_staged_qbitd_evidence(
        self,
        *,
        smoke_bytes: bytes = b"smoked qbitd",
        artifact_bytes: bytes | None = None,
        extra_artifacts: dict[str, bytes] | None = None,
        extra_non_qbitd_artifacts: dict[str, bytes] | None = None,
        duplicate_primary_qbitd_bytes: bytes | None = None,
        primary_qbitd_member_name: str = "qbit-0.1.0/bin/qbitd",
        omit_qbitd_artifacts: set[str] | None = None,
    ) -> Path:
        artifact_bytes = smoke_bytes if artifact_bytes is None else artifact_bytes
        extra_artifacts = extra_artifacts or {}
        extra_non_qbitd_artifacts = extra_non_qbitd_artifacts or {}
        omit_qbitd_artifacts = omit_qbitd_artifacts or set()

        smoke_dir = self.root / "smoke"
        smoke_dir.mkdir()
        qbitd_path = smoke_dir / "qbitd"
        qbitd_path.write_bytes(smoke_bytes)
        qbitd_sha256 = hashlib.sha256(smoke_bytes).hexdigest()

        artifacts_dir = self.root / "staging"
        artifacts_dir.mkdir()
        artifact_name = "qbit-0.1.0-x86_64-linux-gnu.tar.gz"
        artifact_payloads = {artifact_name: artifact_bytes, **extra_artifacts}
        artifact_sha256s: dict[str, str] = {}
        qbitd_sha256s: dict[str, str] = {}

        def write_archive_member(
            artifact_path: Path, member_name: str, payload: bytes, mode: int
        ) -> None:
            if artifact_path.name.endswith(".zip"):
                with zipfile.ZipFile(artifact_path, "w") as archive:
                    info = zipfile.ZipInfo(member_name)
                    info.external_attr = mode << 16
                    archive.writestr(info, payload)
                return
            with tarfile.open(artifact_path, "w:gz") as archive:
                member = tarfile.TarInfo(member_name)
                member.mode = mode
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

        for name, payload in artifact_payloads.items():
            artifact_path = artifacts_dir / name
            if name == artifact_name and duplicate_primary_qbitd_bytes is not None:
                with tarfile.open(artifact_path, "w:gz") as archive:
                    member = tarfile.TarInfo(primary_qbitd_member_name)
                    member.mode = 0o755
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                    duplicate = tarfile.TarInfo("qbit-0.1.0/bin/qbitd")
                    duplicate.mode = 0o755
                    duplicate.size = len(duplicate_primary_qbitd_bytes)
                    archive.addfile(duplicate, io.BytesIO(duplicate_primary_qbitd_bytes))
            else:
                write_archive_member(artifact_path, primary_qbitd_member_name, payload, 0o755)
            artifact_sha256s[name] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            qbitd_sha256s[name] = hashlib.sha256(payload).hexdigest()

        for name, payload in extra_non_qbitd_artifacts.items():
            artifact_path = artifacts_dir / name
            write_archive_member(
                artifact_path,
                "qbit-0.1.0/codesigning-payload.txt",
                payload,
                0o644,
            )
            artifact_sha256s[name] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

        (artifacts_dir / "SHA256SUMS").write_text(
            "".join(
                f"{digest}  {name}\n" for name, digest in sorted(artifact_sha256s.items())
            ),
            encoding="utf8",
        )
        qbitd_artifacts = ",".join(
            f"{name}:{qbitd_sha256s[name]}"
            for name in sorted(qbitd_sha256s)
            if name not in omit_qbitd_artifacts
        )
        self.evidence.write_text(
            VALID_EVIDENCE
            + f"qbitd_path={qbitd_path}\n"
            + f"qbitd_sha256={qbitd_sha256}\n"
            + f"qbitd_artifact={artifact_name}\n"
            + f"qbitd_artifact_sha256={artifact_sha256s[artifact_name]}\n"
            + f"qbitd_artifacts={qbitd_artifacts}\n",
            encoding="utf8",
        )
        return artifacts_dir

    def write_staged_qbitd_evidence_with_wrong_claim(self) -> Path:
        smoke_bytes = b"smoked qbitd"
        second_name = "qbit-0.1.0-aarch64-linux-gnu.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            smoke_bytes=smoke_bytes,
            extra_artifacts={second_name: b"second platform qbitd"},
        )
        smoke_sha256 = hashlib.sha256(smoke_bytes).hexdigest()
        self.evidence.write_text(
            "\n".join(
                f"qbitd_artifacts=qbit-0.1.0-x86_64-linux-gnu.tar.gz:{smoke_sha256},"
                f"{second_name}:{smoke_sha256}"
                if line.startswith("qbitd_artifacts=")
                else line
                for line in self.evidence.read_text(encoding="utf8").splitlines()
            )
            + "\n",
            encoding="utf8",
        )
        return artifacts_dir

    def drop_evidence_keys(self, keys: set[str]) -> None:
        self.evidence.write_text(
            "\n".join(
                line
                for line in self.evidence.read_text(encoding="utf8").splitlines()
                if line.split("=", 1)[0] not in keys
            )
            + "\n",
            encoding="utf8",
        )

    def test_valid_posture_succeeds(self) -> None:
        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_guard_evidence_fails(self) -> None:
        self.evidence.write_text(
            VALID_EVIDENCE.replace("testnet_only_mainnet_guard=enabled\n", ""),
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("testnet_only_mainnet_guard", result.stderr)

    def test_wrong_guard_evidence_value_fails(self) -> None:
        self.evidence.write_text(
            VALID_EVIDENCE.replace(
                "testnet_only_mainnet_guard=enabled",
                "testnet_only_mainnet_guard=disabled",
            ),
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("expected 'enabled'", result.stderr)

    def test_mainnet_dns_seed_fails(self) -> None:
        (self.root / "src" / "kernel" / "chainparams.cpp").write_text(
            VALID_CHAINPARAMS_CPP.replace(
                "vSeeds.clear();",
                'vSeeds.clear();\n        vSeeds.emplace_back("seed-main.qbit.org");',
            ),
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("mainnet DNS seed hostname", result.stderr)

    def test_mainnet_fixed_seed_blob_fails(self) -> None:
        (self.root / "src" / "chainparamsseeds.h").write_text(
            VALID_CHAINPARAMSSEEDS_H.replace(
                "std::array<uint8_t, 0>", "std::array<uint8_t, 16>"
            ),
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("zero-length array", result.stderr)

    def test_commented_zero_length_seed_array_does_not_satisfy_requirement(self) -> None:
        (self.root / "src" / "chainparamsseeds.h").write_text(
            """\
#include <array>
#include <cstdint>
// static constexpr std::array<uint8_t, 0> chainparams_seed_main{{
// }};
static constexpr std::array<uint8_t, 16> chainparams_seed_main{{
    0x01,
}};
""",
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("zero-length array", result.stderr)

    def test_commented_seed_clears_do_not_satisfy_requirement(self) -> None:
        (self.root / "src" / "kernel" / "chainparams.cpp").write_text(
            VALID_CHAINPARAMS_CPP.replace(
                "        vSeeds.clear();\n        vFixedSeeds.clear();",
                "        // vSeeds.clear();\n        // vFixedSeeds.clear();",
            ),
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("explicitly clear mainnet DNS seeds", result.stderr)

    def test_commented_testnet_marker_does_not_truncate_mainnet_scan(self) -> None:
        (self.root / "src" / "kernel" / "chainparams.cpp").write_text(
            """\
class CMainParams : public CChainParams {
public:
    CMainParams() {
        vSeeds.clear();
        vFixedSeeds.clear();
        // class CTestNetParams starts later.
        vSeeds.emplace_back("seed-main.qbit.org");
    }
};

class CTestNetParams : public CChainParams {
};
""",
            encoding="utf8",
        )

        result = self.run_verifier()

        self.assertEqual(result.returncode, 1)
        self.assertIn("mainnet DNS seed hostname", result.stderr)

    def test_release_tag_reads_tagged_sources(self) -> None:
        tag = "v0.1.0-testnet4-rc1"
        source_commit = self.commit_source_tree(tag)
        self.write_evidence(release_tag=tag, source_commit=source_commit)
        (self.root / "src" / "kernel" / "chainparams.cpp").write_text(
            VALID_CHAINPARAMS_CPP.replace(
                "vSeeds.clear();",
                'vSeeds.clear();\n        vSeeds.emplace_back("seed-main.qbit.org");',
            ),
            encoding="utf8",
        )

        result = self.run_verifier("--release-tag", tag)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_tag_mismatch_fails(self) -> None:
        tag = "v0.1.0-testnet4-rc1"
        source_commit = self.commit_source_tree(tag)
        self.write_evidence(release_tag="v0.1.0-testnet4-rc0", source_commit=source_commit)

        result = self.run_verifier("--release-tag", tag)

        self.assertEqual(result.returncode, 1)
        self.assertIn("release_tag", result.stderr)

    def test_source_commit_mismatch_fails(self) -> None:
        tag = "v0.1.0-testnet4-rc1"
        source_commit = self.commit_source_tree(tag)
        self.write_evidence(release_tag=tag, source_commit="0" * len(source_commit))

        result = self.run_verifier("--release-tag", tag)

        self.assertEqual(result.returncode, 1)
        self.assertIn("source_commit", result.stderr)

    def test_artifacts_dir_requires_qbitd_metadata(self) -> None:
        artifacts_dir = self.root / "staging"
        artifacts_dir.mkdir()

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("qbitd_artifacts", result.stderr)

    def test_artifacts_dir_validates_qbitd_path_and_staged_artifact(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence()

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_accepts_qbitd_artifacts_without_local_smoke_linkage(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence()
        self.drop_evidence_keys(
            {"qbitd_path", "qbitd_sha256", "qbitd_artifact", "qbitd_artifact_sha256"}
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_accepts_missing_runner_qbitd_path(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence()
        self.evidence.write_text(
            "\n".join(
                "qbitd_path=/coordinator-only/smoke/bin/qbitd"
                if line.startswith("qbitd_path=")
                else line
                for line in self.evidence.read_text(encoding="utf8").splitlines()
            )
            + "\n",
            encoding="utf8",
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_rejects_binary_not_in_staged_artifact(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence(
            smoke_bytes=b"smoked qbitd", artifact_bytes=b"different staged qbitd"
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match any bin/qbitd", result.stderr)

    def test_artifacts_dir_rejects_duplicate_qbitd_members(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence(
            duplicate_primary_qbitd_bytes=b"stale qbitd"
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("multiple bin/qbitd entries", result.stderr)

    def test_artifacts_dir_rejects_traversal_qbitd_member(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence(
            primary_qbitd_member_name="qbit-0.1.0/../bin/qbitd"
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsafe archive member path", result.stderr)

    def test_artifacts_dir_requires_every_core_qbitd_artifact(self) -> None:
        second_name = "qbit-0.1.0-aarch64-linux-gnu.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_artifacts={second_name: b"second platform qbitd"},
            omit_qbitd_artifacts={second_name},
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn(second_name, result.stderr)

    def test_artifacts_dir_rejects_unlinked_core_qbitd_binary(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence_with_wrong_claim()

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match any bin/qbitd", result.stderr)

    def test_artifacts_dir_ignores_installer_core_artifacts(self) -> None:
        installer_names = {
            "qbit-0.1.0-osx.dmg",
            "qbit-0.1.0-win64-setup.exe",
        }
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_artifacts={name: b"installer payload" for name in installer_names},
            omit_qbitd_artifacts=installer_names,
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_ignores_debug_core_artifacts(self) -> None:
        debug_name = "qbit-0.1.0-x86_64-linux-gnu-debug.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_non_qbitd_artifacts={debug_name: b"debug symbols"},
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_honors_unsigned_platform_waiver(self) -> None:
        unsigned_name = "qbit-0.1.0-x86_64-apple-darwin-unsigned.zip"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_non_qbitd_artifacts={unsigned_name: b"unsigned gui payload"},
        )

        result = self.run_verifier(
            "--artifacts-dir",
            str(artifacts_dir),
            "--allow-unsigned-platform-artifacts",
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_keeps_unsigned_qbitd_artifact_under_waiver(self) -> None:
        unsigned_name = "qbit-0.1.0-x86_64-apple-darwin-unsigned.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_artifacts={unsigned_name: b"unsigned platform qbitd"},
            omit_qbitd_artifacts={unsigned_name},
        )

        result = self.run_verifier(
            "--artifacts-dir",
            str(artifacts_dir),
            "--allow-unsigned-platform-artifacts",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(unsigned_name, result.stderr)

    def test_artifacts_dir_honors_codesigning_waiver(self) -> None:
        codesigning_name = "qbit-0.1.0-x86_64-apple-darwin-codesigning.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_non_qbitd_artifacts={codesigning_name: b"codesigning payload"},
        )

        result = self.run_verifier(
            "--artifacts-dir",
            str(artifacts_dir),
            "--allow-codesigning-artifacts",
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_artifacts_dir_keeps_codesigning_qbitd_artifact_under_waiver(self) -> None:
        codesigning_name = "qbit-0.1.0-x86_64-apple-darwin-codesigning.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_artifacts={codesigning_name: b"codesigning qbitd"},
            omit_qbitd_artifacts={codesigning_name},
        )

        result = self.run_verifier(
            "--artifacts-dir",
            str(artifacts_dir),
            "--allow-codesigning-artifacts",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(codesigning_name, result.stderr)

    def test_artifacts_dir_rejects_codesigning_artifact_without_waiver(self) -> None:
        codesigning_name = "qbit-0.1.0-x86_64-apple-darwin-codesigning.tar.gz"
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_non_qbitd_artifacts={codesigning_name: b"codesigning payload"},
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn(codesigning_name, result.stderr)

    def test_artifacts_dir_rejects_unsupported_core_artifact(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence(
            extra_artifacts={"qbit-0.1.0-linux.tar.zst": b"unsupported payload"},
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported staged core artifact", result.stderr)

    def test_artifacts_dir_rejects_stale_artifact_hash(self) -> None:
        artifacts_dir = self.write_staged_qbitd_evidence()
        self.evidence.write_text(
            "\n".join(
                "qbitd_artifact_sha256=" + "0" * 64
                if line.startswith("qbitd_artifact_sha256=")
                else line
                for line in self.evidence.read_text(encoding="utf8").splitlines()
            )
            + "\n",
            encoding="utf8",
        )

        result = self.run_verifier("--artifacts-dir", str(artifacts_dir))

        self.assertEqual(result.returncode, 1)
        self.assertIn("SHA256SUMS lists", result.stderr)


if __name__ == "__main__":
    unittest.main()
