#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for verify_p2mr_v1_conformance.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("verify_p2mr_v1_conformance.py")
MODULE_SPEC = importlib.util.spec_from_file_location("p2mr_release_validator", SCRIPT)
assert MODULE_SPEC and MODULE_SPEC.loader
VALIDATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VALIDATOR)

REFERENCE_COMMIT = "988756471aeecdf4463c04be49da2b7b89a98c21"
ANCESTRY_COMMIT = "6740c533e8dce4e912f17ee85a6f627644e1b783"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VerifyP2MRV1ConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "qbit release fixture")
        self.git("config", "user.email", "release-fixture@example.invalid")

        spec = self.source / "doc" / "consensus" / "p2mr-v1.md"
        spec.parent.mkdir(parents=True)
        spec.write_text("# qbit P2MR v1\n\nNormative fixture.\n", encoding="utf8")
        self.git("add", "doc/consensus/p2mr-v1.md")
        self.git("commit", "--quiet", "-m", "specification")
        self.specification_commit = self.git("rev-parse", "HEAD").stdout.strip()

        data_dir = self.source / "src" / "test" / "data"
        data_dir.mkdir(parents=True)
        self.cross_corpus = data_dir / "p2mr_cross_profile_vectors.json"
        self.write_json(
            self.cross_corpus,
            {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "comparison_profile": {},
                "vectors": [],
            },
        )
        self.corpus = data_dir / "p2mr_pqc_witness_vectors.json"
        self.write_json(
            self.corpus,
            {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "vectors": [
                    {
                        "id": "accept-case",
                        "expected": {
                            "accepted": True,
                            "stage": "script",
                            "error": "OK",
                        },
                    },
                    {
                        "id": "reject-case",
                        "expected": {
                            "accepted": False,
                            "stage": "commitment",
                            "error": "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
                        },
                    },
                ],
            },
        )
        self.boundary_corpus = data_dir / "p2mr_script_boundary_vectors.json"
        self.write_json(
            self.boundary_corpus,
            {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "limits": {},
                "cases": [],
            },
        )
        self.commitment_corpus = data_dir / "p2mr_vectors.json"
        self.write_json(
            self.commitment_corpus,
            {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "generator": {},
                "valid": [],
                "invalid": [],
            },
        )
        self.manifest = data_dir / "p2mr_v1_manifest.json"
        self.write_json(
            self.manifest,
            {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "specification": "doc/consensus/p2mr-v1.md",
                "reference_implementation": {
                    "repository": "Qbit-Org/qbit",
                    "commit": REFERENCE_COMMIT,
                },
                "ancestry": {
                    "name": "BIP-360",
                    "version": "0.12.0",
                    "commit": ANCESTRY_COMMIT,
                    "normative": False,
                },
                "case_count": 2,
                "case_counts": {
                    "commitment_valid": 0,
                    "commitment_invalid": 0,
                    "witness": 2,
                    "cross_profile": 0,
                    "script_boundary": 0,
                },
                "files": [
                    {
                        "path": "src/test/data/p2mr_cross_profile_vectors.json",
                        "purpose": "qbit and pinned-profile boundary vectors",
                        "case_count": 0,
                        "sha256": sha256(self.cross_corpus),
                    },
                    {
                        "path": "src/test/data/p2mr_pqc_witness_vectors.json",
                        "purpose": "PQC sighash and witness vectors",
                        "case_count": 2,
                        "sha256": sha256(self.corpus),
                    },
                    {
                        "path": "src/test/data/p2mr_script_boundary_vectors.json",
                        "purpose": "script, control, leaf, opcode, and resource boundary vectors",
                        "case_count": 0,
                        "sha256": sha256(self.boundary_corpus),
                    },
                    {
                        "path": "src/test/data/p2mr_vectors.json",
                        "purpose": "commitment, control block, root, and address vectors",
                        "case_count": 0,
                        "sha256": sha256(self.commitment_corpus),
                    },
                ],
            },
        )
        self.git("add", "src/test/data")
        self.git("commit", "--quiet", "-m", "release source")
        self.release_commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.tag = "v1.0.0-testnet-fixture"
        self.git("tag", "-a", self.tag, "-m", "release fixture")
        self.manifest_sha256 = sha256(self.manifest)

        self.report = self.root / "p2mr-v1-conformance-report.json"
        self.write_json(
            self.report,
            {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "manifest_sha256": self.manifest_sha256,
                "oracle": {
                    "name": "p2mr-v1-oracle",
                    "version": "1",
                    "commit": self.release_commit,
                },
                "reference_implementation_commit": REFERENCE_COMMIT,
                "manifest_case_counts": {
                    "commitment_valid": 0,
                    "commitment_invalid": 0,
                    "witness": 2,
                    "cross_profile": 0,
                    "script_boundary": 0,
                },
                "case_counts": {
                    "total": 2,
                    "accepted": 1,
                    "rejected": 1,
                    "cross_profile": 0,
                },
                "result": "pass",
                "cases": [
                    {
                        "id": "accept-case",
                        "category": "witness",
                        "result": "pass",
                        "observed_accept": True,
                        "observed_stage": "script",
                        "observed_error": "OK",
                    },
                    {
                        "id": "reject-case",
                        "category": "witness",
                        "result": "pass",
                        "observed_accept": False,
                        "observed_stage": "commitment",
                        "observed_error": "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
                    },
                ],
            },
        )
        self.matrix = self.root / "p2mr-v1-support-matrix.json"
        self.write_json(self.matrix, self.valid_matrix())
        self.evidence = self.root / "p2mr-v1-conformance-evidence.json"
        self.write_json(self.evidence, self.valid_evidence())

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "git",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-C",
                str(self.source),
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def write_json(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf8")

    @staticmethod
    def read_json(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf8"))

    def component(
        self,
        component_id: str,
        category: str,
        *,
        supported: bool = True,
    ) -> dict[str, Any]:
        return {
            "id": component_id,
            "component": component_id.replace("-", " "),
            "category": category,
            "owner": "Qbit-Org/qbit",
            "version": self.release_commit if supported else None,
            "profile": "qbit-p2mr-v1",
            "corpus_manifest_sha256": self.manifest_sha256,
            "test_environment": "release fixture",
            "result": "pass" if supported else "not-applicable",
            "release_surface": "supported" if supported else "not-claimed",
            "evidence": "https://example.invalid/qbit-ci/1" if supported else None,
            "limitations": "Fixture evidence only.",
            "reviewed_at": "2026-07-11" if supported else None,
        }

    def valid_matrix(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile": "qbit-p2mr-v1",
            "profile_version": 1,
            "status": "release",
            "release_source_commit": self.release_commit,
            "corpus_manifest_sha256": self.manifest_sha256,
            "components": [
                self.component("qbit-consensus-validation", "reference-implementation"),
                self.component("qbit-descriptor-wallet", "wallet"),
                self.component("qbit-watch-only-pubkeydb", "wallet"),
                self.component("qbit-raw-transaction-signing", "signer"),
                self.component("qbit-psbt-flow", "psbt-tool"),
                self.component("qbit-qt-wallet-surfaces", "wallet"),
                self.component("qbit-mining-payout-validation", "miner-pool"),
                self.component("python-corpus-generator", "corpus-generator"),
                self.component("rust-corpus-generator", "corpus-generator"),
                self.component("p2mr-v1-oracle", "alternative-validator"),
                self.component(
                    "no-external-exchange-claimed", "exchange", supported=False
                ),
                self.component(
                    "no-external-explorer-claimed", "explorer", supported=False
                ),
            ],
        }

    def valid_evidence(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile": "qbit-p2mr-v1",
            "profile_version": 1,
            "specification_commit": self.specification_commit,
            "corpus_manifest_sha256": self.manifest_sha256,
            "release_tag": self.tag,
            "release_source_commit": self.release_commit,
            "consensus_review": {
                "source_commit": self.release_commit,
                "evidence": "https://example.invalid/qbit-review/1",
            },
            "oracle": {
                "name": "p2mr-v1-oracle",
                "version": "1",
                "source_commit": self.release_commit,
                "report_sha256": sha256(self.report),
                "result": "pass",
                "case_count": 2,
            },
            "qbit": {
                "test_binary_commit": self.release_commit,
                "result": "pass",
                "case_count": 2,
                "evidence": "https://example.invalid/qbit-ci/1",
            },
            "integration_matrix": {
                "release_source_commit": self.release_commit,
                "sha256": sha256(self.matrix),
                "blocking_failures": 0,
                "unresolved_claimed_support": 0,
            },
        }

    def refresh_evidence_hashes(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["oracle"]["report_sha256"] = sha256(self.report)
        evidence["integration_matrix"]["sha256"] = sha256(self.matrix)
        self.write_json(self.evidence, evidence)

    def retag_changed_release_source(self) -> None:
        """Commit a deliberately changed source fixture and rebind external files."""

        self.git("tag", "-d", self.tag)
        self.git("add", "src/test/data", "doc/consensus/p2mr-v1.md")
        self.git("commit", "--quiet", "-m", "changed release source")
        self.release_commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("tag", "-a", self.tag, "-m", "changed release fixture")
        self.manifest_sha256 = sha256(self.manifest)

        report = self.read_json(self.report)
        report["manifest_sha256"] = self.manifest_sha256
        report["oracle"]["commit"] = self.release_commit
        self.write_json(self.report, report)

        matrix = self.read_json(self.matrix)
        matrix["release_source_commit"] = self.release_commit
        matrix["corpus_manifest_sha256"] = self.manifest_sha256
        for component in matrix["components"]:
            component["corpus_manifest_sha256"] = self.manifest_sha256
            if component["release_surface"] == "supported":
                component["version"] = self.release_commit
        self.write_json(self.matrix, matrix)
        self.write_json(self.evidence, self.valid_evidence())

    def run_validator(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--evidence",
                str(self.evidence),
                "--source-root",
                str(self.source),
                "--release-tag",
                self.tag,
                "--oracle-report",
                str(self.report),
                "--integration-matrix",
                str(self.matrix),
                *extra,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_valid_evidence_succeeds_deterministically(self) -> None:
        first = self.run_validator()
        second = self.run_validator()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertIn(self.release_commit, first.stdout)
        self.assertIn(self.manifest_sha256, first.stdout)
        self.assertNotIn(str(self.root), first.stdout)

    def test_writes_release_summary_outputs(self) -> None:
        output = self.root / "github-output"
        result = self.run_validator("--github-output", str(output))

        self.assertEqual(result.returncode, 0, result.stderr)
        values = output.read_text(encoding="utf8")
        self.assertIn(f"release_source_commit={self.release_commit}", values)
        self.assertIn(f"manifest_sha256={self.manifest_sha256}", values)
        self.assertIn("case_count=2", values)

    def test_unknown_evidence_key_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["unexpected"] = True
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown=unexpected", result.stderr)

    def test_missing_evidence_key_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        del evidence["qbit"]
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing=qbit", result.stderr)

    def test_malformed_sha256_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["corpus_manifest_sha256"] = "not-a-sha256"
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("64 lowercase hex", result.stderr)

    def test_duplicate_json_key_fails(self) -> None:
        raw = self.evidence.read_text(encoding="utf8")
        self.evidence.write_text(
            raw.replace(
                '"schema_version": 1,',
                '"schema_version": 1,\n  "schema_version": 1,',
                1,
            ),
            encoding="utf8",
        )

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate JSON key", result.stderr)

    def test_uppercase_sha_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["release_source_commit"] = self.release_commit.upper()
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("lowercase", result.stderr)

    def test_wrong_evidence_profile_or_version_fails(self) -> None:
        for key, value in (("profile", "BIP-360"), ("profile_version", 2)):
            with self.subTest(key=key):
                evidence = self.valid_evidence()
                evidence[key] = value
                self.write_json(self.evidence, evidence)

                result = self.run_validator()

                self.assertEqual(result.returncode, 1)
                self.assertIn(key, result.stderr)

    def test_release_tag_mismatch_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["release_tag"] = "v1.0.0-other"
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("release_tag", result.stderr)

    def test_consensus_review_of_ancestor_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["consensus_review"]["source_commit"] = self.specification_commit
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("exact tag target", result.stderr)

    def test_oracle_result_failure_fails(self) -> None:
        report = self.read_json(self.report)
        report["result"] = "fail"
        self.write_json(self.report, report)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("report result", result.stderr)

    def test_oracle_commit_mismatch_fails(self) -> None:
        report = self.read_json(self.report)
        report["oracle"]["commit"] = self.specification_commit
        self.write_json(self.report, report)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("commit must equal", result.stderr)

    def test_oracle_report_from_another_profile_fails(self) -> None:
        report = self.read_json(self.report)
        report["profile"] = "BIP-360"
        self.write_json(self.report, report)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("oracle report.profile", result.stderr)

    def test_oracle_case_count_mismatch_fails(self) -> None:
        report = self.read_json(self.report)
        report["case_counts"]["total"] = 3
        self.write_json(self.report, report)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("manifest.case_count", result.stderr)

    def test_duplicate_or_unsorted_oracle_ids_fail(self) -> None:
        report = self.read_json(self.report)
        report["cases"][1] = report["cases"][0].copy()
        self.write_json(self.report, report)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("unique and sorted", result.stderr)

    def test_oracle_case_must_match_tagged_corpus_expectation(self) -> None:
        report = self.read_json(self.report)
        report["cases"][0]["observed_stage"] = "different-stage"
        self.write_json(self.report, report)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("tagged corpus expectation", result.stderr)

    def test_qbit_commit_mismatch_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["qbit"]["test_binary_commit"] = self.specification_commit
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("qbit test binary commit", result.stderr)

    def test_matrix_digest_mismatch_fails(self) -> None:
        matrix = self.read_json(self.matrix)
        matrix["components"][0]["limitations"] = "Changed after evidence was produced."
        self.write_json(self.matrix, matrix)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("matrix digest mismatch", result.stderr)

    def test_missing_matrix_category_fails(self) -> None:
        matrix = self.read_json(self.matrix)
        matrix["components"] = [
            row for row in matrix["components"] if row["category"] != "explorer"
        ]
        self.write_json(self.matrix, matrix)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing required categories", result.stderr)

    def test_duplicate_matrix_component_fails(self) -> None:
        matrix = self.read_json(self.matrix)
        matrix["components"].append(dict(matrix["components"][0]))
        self.write_json(self.matrix, matrix)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate integration component", result.stderr)

    def test_supported_not_tested_component_fails(self) -> None:
        matrix = self.read_json(self.matrix)
        matrix["components"][0]["result"] = "not-tested"
        self.write_json(self.matrix, matrix)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("supported component failure", result.stderr)

    def test_supported_partial_or_failed_component_fails(self) -> None:
        for failure in ("partial", "fail"):
            with self.subTest(result=failure):
                matrix = self.valid_matrix()
                matrix["components"][0]["result"] = failure
                self.write_json(self.matrix, matrix)
                self.refresh_evidence_hashes()

                result = self.run_validator()

                self.assertEqual(result.returncode, 1)
                self.assertIn("supported component failure", result.stderr)

    def test_not_claimed_partial_component_fails(self) -> None:
        matrix = self.read_json(self.matrix)
        matrix["components"][-1]["result"] = "partial"
        self.write_json(self.matrix, matrix)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("must use result not-applicable", result.stderr)

    def test_required_in_tree_component_cannot_be_not_claimed(self) -> None:
        matrix = self.read_json(self.matrix)
        component = matrix["components"][0]
        component["release_surface"] = "not-claimed"
        component["result"] = "not-applicable"
        component["version"] = None
        component["evidence"] = None
        component["reviewed_at"] = None
        self.write_json(self.matrix, matrix)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("required in-tree components must be supported", result.stderr)

    def test_required_in_tree_component_version_must_match_release(self) -> None:
        matrix = self.read_json(self.matrix)
        matrix["components"][0]["version"] = self.specification_commit
        self.write_json(self.matrix, matrix)
        self.refresh_evidence_hashes()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("version must equal the release tag target", result.stderr)

    def test_non_https_review_evidence_fails(self) -> None:
        evidence = self.read_json(self.evidence)
        evidence["consensus_review"]["evidence"] = "/private/review.txt"
        self.write_json(self.evidence, evidence)

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("stable HTTPS", result.stderr)

    def test_tagged_manifest_listed_corpus_digest_mismatch_fails(self) -> None:
        manifest = self.read_json(self.manifest)
        manifest["files"][0]["sha256"] = "0" * 64
        self.write_json(self.manifest, manifest)
        self.retag_changed_release_source()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("manifest digest mismatch", result.stderr)

    def test_tagged_manifest_path_traversal_fails(self) -> None:
        manifest = self.read_json(self.manifest)
        manifest["files"][0]["path"] = "src/test/data/../p2mr_fixture_vectors.json"
        self.write_json(self.manifest, manifest)
        self.retag_changed_release_source()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsafe manifest file path", result.stderr)

    def test_tagged_manifest_absolute_path_fails(self) -> None:
        manifest = self.read_json(self.manifest)
        manifest["files"][0]["path"] = "/tmp/p2mr_fixture_vectors.json"
        self.write_json(self.manifest, manifest)
        self.retag_changed_release_source()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsafe manifest file path", result.stderr)

    def test_specification_changed_after_review_commit_fails(self) -> None:
        spec = self.source / "doc" / "consensus" / "p2mr-v1.md"
        spec.write_text("# qbit P2MR v1\n\nChanged after review.\n", encoding="utf8")
        self.retag_changed_release_source()

        result = self.run_validator()

        self.assertEqual(result.returncode, 1)
        self.assertIn("specification changed", result.stderr)


class CheckedInP2MRIntegrationMatrixTest(unittest.TestCase):
    def test_draft_matrix_is_valid_and_markdown_is_current(self) -> None:
        repo_root = SCRIPT.parents[2]
        matrix_path = repo_root / "doc" / "integration" / "p2mr-v1-support-matrix.json"
        markdown_path = repo_root / "doc" / "integration" / "p2mr-v1-support-matrix.md"
        manifest_path = repo_root / "src" / "test" / "data" / "p2mr_v1_manifest.json"
        matrix = json.loads(matrix_path.read_text(encoding="utf8"))
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

        VALIDATOR.validate_integration_matrix(
            matrix,
            release_commit=None,
            manifest_sha256=manifest_sha256,
            require_release=False,
        )
        self.assertEqual(
            markdown_path.read_text(encoding="utf8"),
            VALIDATOR.render_integration_matrix_markdown(matrix),
        )


if __name__ == "__main__":
    unittest.main()
