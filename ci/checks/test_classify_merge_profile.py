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
    ".github/workflows/release-publish.yml",
    "ci/release/test_validate_release_artifacts.py",
    "contrib/keys/operator-keys/KEYS.md",
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
                ".github/workflows/release-publish.yml",
                "ci/release/validate_key_metadata.py",
                "contrib/keys/operator-keys/public-keys/operator-01-release.asc",
                "doc/release-trust-v0.1.0-testnet4.md",
            ]
        )

        self.assertEqual(classification.profile, classify_merge_profile.RELEASE_POLICY_PROFILE)

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
