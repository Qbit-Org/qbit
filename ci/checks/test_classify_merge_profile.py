#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for classify_merge_profile.py."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import classify_merge_profile


TRUSTED_RELEASE_REF_PATHS = [
    "contrib/release-process/publish-local-release.sh",
    "ci/release/test_validate_release_artifacts.py",
    "contrib/keys/operator-keys/KEYS.md",
    "contrib/guix/repo-templates/qbit-guix.sigs/operator-keys/keys.json",
    "doc/release-trust-0.1.1-testnet4.md",
]

RPC_DOCS_PATHS = [
    "doc/rpc/site_builder.py",
    "doc/rpc/fixtures/rpc-docs-v1.sample.json",
    "test/rpc_docs/test_site_builder.py",
    "cmake/script/normalize_rpc_docs_site_paths.py",
]

PUBLIC_DOCS_PATHS = [
    "README.md",
    "doc/README.md",
    "doc/user/public-testnet.md",
    "doc/integration/exchange-integrator-quickstart.md",
    "doc/integration/p2mr-v1-support-matrix.json",
    "doc/integration/p2mr-v1-support-matrix.md",
    "doc/reference/ctv.md",
    "doc/policy/packages.md",
    "doc/deployment/init.md",
    "doc/design/p2mr-datapqchash.md",
    "doc/performance/rpc-benchmarking.md",
    "doc/release-notes-0.1.1-testnet4.md",
]

GITHUB_METADATA_PATHS = [
    ".github/rulesets/main.json",
    ".github/repository-settings/merge-methods.json",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "doc/development/public-branch-and-rulesets.md",
    "ci/README.md",
]


class ClassifyMergeProfileTest(unittest.TestCase):
    def classify(self, paths: list[str]) -> classify_merge_profile.Classification:
        return classify_merge_profile.classify_paths(paths)

    def test_trusted_release_ref_paths_are_release_policy_only(self) -> None:
        classification = self.classify(TRUSTED_RELEASE_REF_PATHS)

        self.assertEqual(classification.profile, classify_merge_profile.RELEASE_POLICY_PROFILE)
        self.assertTrue(classification.release_policy_only)
        self.assertEqual(classification.outside_paths, ())

    def test_release_policy_allowlist_covers_release_paths(self) -> None:
        classification = self.classify(
            [
                "contrib/release-process/publish-local-release.sh",
                "ci/release/validate_key_metadata.py",
                "contrib/keys/operator-keys/public-keys/operator-01-release.asc",
                "doc/release-trust-v0.1.0-testnet4.md",
            ]
        )

        self.assertEqual(classification.profile, classify_merge_profile.RELEASE_POLICY_PROFILE)

    def test_guix_operator_key_mirror_is_release_policy(self) -> None:
        path = (
            "contrib/guix/repo-templates/qbit-guix.sigs/operator-keys/"
            "approvals/qbit-release-keys-mainnet-000002/operator-02.asc"
        )
        classification = self.classify([path])
        outputs = classify_merge_profile.github_outputs(classification)

        self.assertEqual(classification.profile, classify_merge_profile.RELEASE_POLICY_PROFILE)
        self.assertTrue(classification.release_policy_only)
        self.assertEqual(outputs["touched_operator_keys"], "true")

    def test_p2mr_release_validator_paths_use_release_policy_profile(self) -> None:
        for path in (
            "ci/release/verify_p2mr_v1_conformance.py",
            "ci/release/test_verify_p2mr_v1_conformance.py",
        ):
            with self.subTest(path=path):
                classification = self.classify([path])
                outputs = classify_merge_profile.github_outputs(classification)

                self.assertEqual(
                    classification.profile,
                    classify_merge_profile.RELEASE_POLICY_PROFILE,
                )
                self.assertTrue(classification.release_policy_only)
                self.assertEqual(outputs["release_policy_only"], "true")
                self.assertEqual(outputs["source_validation_required"], "false")
                self.assertEqual(outputs["touched_release_validators"], "true")

    def test_retired_release_workflow_requires_source_validation(self) -> None:
        path = ".github/workflows/release-publish.yml"
        classification = self.classify([path])
        outputs = classify_merge_profile.github_outputs(classification)

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(classification.outside_paths, (path,))
        self.assertEqual(outputs["touched_release_publish"], "false")

    def test_rpc_docs_paths_are_rpc_docs_only(self) -> None:
        classification = self.classify(RPC_DOCS_PATHS)

        self.assertEqual(classification.profile, classify_merge_profile.RPC_DOCS_PROFILE)
        self.assertTrue(classification.rpc_docs_only)
        self.assertEqual(classification.outside_paths, ())

    def test_public_docs_paths_are_public_docs_only(self) -> None:
        classification = self.classify(PUBLIC_DOCS_PATHS)

        self.assertEqual(classification.profile, classify_merge_profile.PUBLIC_DOCS_PROFILE)
        self.assertTrue(classification.public_docs_only)
        self.assertEqual(classification.outside_paths, ())

    def test_github_metadata_paths_are_github_metadata_only(self) -> None:
        classification = self.classify(GITHUB_METADATA_PATHS)

        self.assertEqual(
            classification.profile,
            classify_merge_profile.GITHUB_METADATA_PROFILE,
        )
        self.assertTrue(classification.github_metadata_only)
        self.assertEqual(classification.outside_paths, ())

    def test_source_path_requires_source_validation(self) -> None:
        classification = self.classify(["src/kernel/chainparams.cpp"])

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(classification.outside_paths, ("src/kernel/chainparams.cpp",))

    def test_mixed_release_and_source_paths_require_source_validation(self) -> None:
        classification = self.classify(
            [
                "ci/release/test_validate_release_artifacts.py",
                "test/functional/wallet_p2mr.py",
            ]
        )

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(classification.outside_paths, ("test/functional/wallet_p2mr.py",))

    def test_mixed_lightweight_profiles_require_source_validation(self) -> None:
        classification = self.classify(
            [
                "ci/release/test_validate_release_artifacts.py",
                "doc/rpc/site_builder.py",
                "doc/user/public-testnet.md",
                ".github/rulesets/main.json",
            ]
        )

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)

    def test_workflow_metadata_requires_source_validation(self) -> None:
        classification = self.classify([".github/workflows/required-merge-gate.yml"])

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(
            classification.outside_paths,
            (".github/workflows/required-merge-gate.yml",),
        )

    def test_github_actions_require_source_validation(self) -> None:
        classification = self.classify([".github/actions/configure-docker/action.yml"])

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(
            classification.outside_paths,
            (".github/actions/configure-docker/action.yml",),
        )

    def test_empty_change_set_fails_closed_to_source_validation(self) -> None:
        classification = self.classify([])

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)

    def test_release_docs_outside_trust_note_pattern_require_source_validation(self) -> None:
        classification = self.classify(["doc/release/process.md"])

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(classification.outside_paths, ("doc/release/process.md",))

    def test_invalid_path_requires_source_validation(self) -> None:
        classification = self.classify(["../src/kernel/chainparams.cpp"])

        self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        self.assertEqual(classification.invalid_paths, ("../src/kernel/chainparams.cpp",))

    def test_github_outputs_report_touched_release_policy_areas(self) -> None:
        outputs = classify_merge_profile.github_outputs(
            self.classify(TRUSTED_RELEASE_REF_PATHS)
        )

        self.assertEqual(outputs["profile"], "release-policy")
        self.assertEqual(outputs["release_policy_only"], "true")
        self.assertEqual(outputs["source_validation_required"], "false")
        self.assertEqual(outputs["touched_operator_keys"], "true")
        self.assertEqual(outputs["touched_release_publish"], "true")
        self.assertEqual(outputs["touched_release_validators"], "true")
        self.assertEqual(outputs["touched_release_trust_docs"], "true")

    def test_github_outputs_report_rpc_docs_profile(self) -> None:
        outputs = classify_merge_profile.github_outputs(self.classify(RPC_DOCS_PATHS))

        self.assertEqual(outputs["profile"], "rpc-docs")
        self.assertEqual(outputs["rpc_docs_only"], "true")
        self.assertEqual(outputs["source_validation_required"], "false")
        self.assertEqual(outputs["touched_rpc_docs"], "true")

    def test_github_outputs_report_public_docs_profile(self) -> None:
        outputs = classify_merge_profile.github_outputs(self.classify(PUBLIC_DOCS_PATHS))

        self.assertEqual(outputs["profile"], "public-docs")
        self.assertEqual(outputs["public_docs_only"], "true")
        self.assertEqual(outputs["source_validation_required"], "false")
        self.assertEqual(outputs["touched_public_docs"], "true")

    def test_github_outputs_report_github_metadata_profile(self) -> None:
        outputs = classify_merge_profile.github_outputs(
            self.classify(GITHUB_METADATA_PATHS)
        )

        self.assertEqual(outputs["profile"], "github-metadata")
        self.assertEqual(outputs["github_metadata_only"], "true")
        self.assertEqual(outputs["source_validation_required"], "false")
        self.assertEqual(outputs["touched_github_metadata"], "true")

    def test_pq_aarch64_job_required_for_mlkem_and_transport_paths(self) -> None:
        required = [
            "src/mlkem-native/mlkem/src/kem.c",
            "src/crypto/mlkem.cpp",
            "src/crypto/mlkem_config.h",
            "cmake/mlkem-native.cmake",
            "src/bip324.cpp",
            "src/bip324.h",
            "src/bip324_pq.cpp",
            "src/bip324_pq.h",
            "src/net.h",
            "src/net.cpp",
            "src/compat/cpuid.h",
            "src/compat/cpu_features.h",
            "src/compat/cpu_features.cpp",
            ".github/workflows/ci-pq.yml",
            "ci/test/00_setup_env_native_aarch64_pq.sh",
            "ci/test/00_setup_env_s390x_unit.sh",
            "ci/test/00_setup_env_mac_native_pq.sh",
            "src/test/mlkem_tests.cpp",
            "src/test/bip324_tests.cpp",
            "src/test/net_tests.cpp",
            "src/test/data/pq_transport_vectors.json",
            "src/test/data/mlkem1024_vectors.json",
            # Build wiring.
            "CMakeLists.txt",
            "src/CMakeLists.txt",
            "src/util/CMakeLists.txt",
            "src/test/CMakeLists.txt",
            "src/test/fuzz/CMakeLists.txt",
            "src/bench/CMakeLists.txt",
            "cmake/bitcoin-build-config.h.in",
            # Gate and CI wiring, and its tests.
            ".github/workflows/ci.yml",
            ".github/workflows/core-checks.yml",
            ".github/workflows/required-merge-gate.yml",
            "ci/checks/classify_merge_profile.py",
            "ci/checks/ctest_evidence.py",
            "ci/checks/test_ci_pq_contract.py",
            "ci/checks/test_classify_merge_profile.py",
            "ci/checks/test_mlkem_build_policy.py",
            "ci/checks/test_pq_merge_gate_contract.py",
            "ci/test/03_test_script.sh",
        ]
        for path in required:
            with self.subTest(path=path):
                classification = self.classify([path])
                self.assertTrue(classification.pq_aarch64_required)
                self.assertEqual(classify_merge_profile.github_outputs(classification)["pq_aarch64_required"], "true")
                self.assertEqual(classification.profile, classify_merge_profile.SOURCE_PROFILE)
        # One matching path among others is enough.
        self.assertTrue(self.classify(["doc/user/README.md", "src/bip324.cpp"]).pq_aarch64_required)

    def test_pq_aarch64_job_not_required_elsewhere(self) -> None:
        for paths in (
            ["src/wallet/wallet.cpp"],
            ["src/netbase.cpp", "src/net_processing.cpp", "src/compat/compat.h"],
            ["src/test/net_peer_eviction_tests.cpp"],
            ["ci/test/00_setup_env_native_asan.sh", ".github/workflows/rpc-perf-manual.yml"],
            # Wiring shared by every CI job, and ML-KEM tooling the aarch64 job never runs.
            ["ci/test/01_base_install.sh", "ci/test/02_run_container.py", ".github/actions/configure-docker/action.yml"],
            ["src/crypto/CMakeLists.txt", "src/test/cpu_features_tests.cpp"],
            ["test/lint/mlkem-native-check.sh", "contrib/devtools/mlkem-native.pin", "contrib/devtools/update-mlkem-native.sh"],
            ["doc/user/README.md"],
            RPC_DOCS_PATHS,
            PUBLIC_DOCS_PATHS,
        ):
            with self.subTest(paths=paths):
                classification = self.classify(paths)
                self.assertFalse(classification.pq_aarch64_required)
                self.assertEqual(classify_merge_profile.github_outputs(classification)["pq_aarch64_required"], "false")

    def test_pq_aarch64_job_required_for_unreadable_paths(self) -> None:
        self.assertTrue(self.classify(["../src/bip324.cpp"]).pq_aarch64_required)
        self.assertTrue(self.classify(["/abs/path"]).pq_aarch64_required)

    def test_require_release_policy_only_cli_rejects_outside_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changed_files = Path(tmpdir) / "changed-files.txt"
            changed_files.write_text(
                "ci/release/test_validate_release_artifacts.py\nsrc/init.cpp\n",
                encoding="utf8",
            )

            result = classify_merge_profile.main(
                [
                    "--changed-files",
                    str(changed_files),
                    "--require-release-policy-only",
                ]
            )

        self.assertEqual(result, 1)

    def test_require_profile_accepts_rpc_docs_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changed_files = Path(tmpdir) / "changed-files.txt"
            changed_files.write_text("\n".join(RPC_DOCS_PATHS) + "\n", encoding="utf8")

            result = classify_merge_profile.main(
                [
                    "--changed-files",
                    str(changed_files),
                    "--require-profile",
                    classify_merge_profile.RPC_DOCS_PROFILE,
                ]
            )

        self.assertEqual(result, 0)

    def test_require_profile_accepts_public_docs_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changed_files = Path(tmpdir) / "changed-files.txt"
            changed_files.write_text("\n".join(PUBLIC_DOCS_PATHS) + "\n", encoding="utf8")

            result = classify_merge_profile.main(
                [
                    "--changed-files",
                    str(changed_files),
                    "--require-profile",
                    classify_merge_profile.PUBLIC_DOCS_PROFILE,
                ]
            )

        self.assertEqual(result, 0)

    def test_require_profile_accepts_github_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changed_files = Path(tmpdir) / "changed-files.txt"
            changed_files.write_text(
                "\n".join(GITHUB_METADATA_PATHS) + "\n",
                encoding="utf8",
            )

            result = classify_merge_profile.main(
                [
                    "--changed-files",
                    str(changed_files),
                    "--require-profile",
                    classify_merge_profile.GITHUB_METADATA_PROFILE,
                ]
            )

        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
