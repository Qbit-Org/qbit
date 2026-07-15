#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for verify_mainnet_ci_posture.py and its Core Checks integration."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("verify_mainnet_ci_posture.py")
VALIDATOR = Path(__file__).with_name("verify_mainnet_release_posture.py")
POLICY = Path(__file__).with_name("mainnet_ci_posture.json")
CORE_CHECKS = REPO_ROOT / ".github" / "workflows" / "core-checks.yml"
REQUIRED_MERGE_GATE = REPO_ROOT / ".github" / "workflows" / "required-merge-gate.yml"


def failure(failure_id: str) -> dict[str, str]:
    return {
        "id": failure_id,
        "name": failure_id.replace("_", " "),
        "message": f"{failure_id} failed",
    }


class VerifyMainnetCIPostureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_json(self, name: str, value: Any) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value) + "\n", encoding="utf8")
        return path

    def policy(self, phase: str, expected: list[str]) -> Path:
        return self.write_json(
            "policy.json",
            {"schema": 1, "phase": phase, "expected_failure_ids": expected},
        )

    def result(self, ready: bool, failure_ids: list[str]) -> Path:
        return self.write_json(
            "result.json",
            {
                "schema": 1,
                "ready": ready,
                "source": "candidate commit",
                "failures": [failure(item) for item in failure_ids],
            },
        )

    def run_checker(
        self,
        policy: Path,
        result: Path,
        validator_exit_code: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--policy",
                str(policy),
                "--result-json",
                str(result),
                "--validator-exit-code",
                str(validator_exit_code),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_staging_accepts_exact_declared_publish_blockers(self) -> None:
        result = self.run_checker(
            self.policy("staging", ["auxpow_chain_id", "genesis_asert"]),
            self.result(False, ["auxpow_chain_id", "genesis_asert"]),
            1,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("publication remains blocked", result.stdout)

    def test_staging_rejects_unexpected_failure(self) -> None:
        result = self.run_checker(
            self.policy("staging", ["auxpow_chain_id", "genesis_asert"]),
            self.result(False, ["auxpow_chain_id", "bootstrap", "genesis_asert"]),
            1,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("unexpected: bootstrap", result.stderr)

    def test_staging_rejects_missing_declared_failure(self) -> None:
        result = self.run_checker(
            self.policy("staging", ["auxpow_chain_id", "genesis_asert"]),
            self.result(False, ["genesis_asert"]),
            1,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing expected: auxpow_chain_id", result.stderr)

    def test_staging_rejects_publication_ready_source(self) -> None:
        result = self.run_checker(
            self.policy("staging", ["auxpow_chain_id", "genesis_asert"]),
            self.result(True, []),
            0,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("policy remains staging", result.stderr)

    def test_final_accepts_publication_ready_source(self) -> None:
        result = self.run_checker(
            self.policy("final", []),
            self.result(True, []),
            0,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("publication-ready", result.stdout)

    def test_final_rejects_validator_failure(self) -> None:
        result = self.run_checker(
            self.policy("final", []),
            self.result(False, ["genesis_asert"]),
            1,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("requires publication-ready source", result.stderr)

    def test_exit_code_must_match_result(self) -> None:
        result = self.run_checker(
            self.policy("final", []),
            self.result(True, []),
            1,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("exit code disagrees", result.stderr)

    def test_checked_in_final_policy_matches_publication_ready_source(self) -> None:
        result_path = self.root / "checked-in-result.json"
        validator = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--source-root",
                str(REPO_ROOT),
                "--result-json",
                str(result_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(validator.returncode, 0, validator.stderr)

        result = self.run_checker(POLICY, result_path, validator.returncode)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workflows_enforce_phase_aware_gate_for_release_policy(self) -> None:
        core_checks = CORE_CHECKS.read_text(encoding="utf8")
        required_gate = REQUIRED_MERGE_GATE.read_text(encoding="utf8")

        release_target_start = core_checks.index("      - name: Classify release target")
        release_target_end = core_checks.index("  build-smoke:", release_target_start)
        release_target = core_checks[release_target_start:release_target_end]
        self.assertIn(
            "VALIDATION_PROFILE: ${{ steps.classify.outputs.profile }}",
            release_target,
        )
        self.assertIn('"${VALIDATION_PROFILE}" == "release-policy"', release_target)

        job_start = core_checks.index("  mainnet-publish-gate:")
        job_end = core_checks.index("  core-checks-gate:", job_start)
        job = core_checks[job_start:job_end]
        self.assertIn(
            "if: ${{ needs.classify-changes.outputs.mainnet_publish_gate_required == 'true' }}",
            job,
        )
        self.assertNotIn("source_validation_required", job)
        self.assertIn("ci/release/verify_mainnet_release_posture.py", job)
        self.assertIn("ci/release/verify_mainnet_ci_posture.py", job)

        mainnet_check = core_checks.index(
            'check_result "mainnet publication posture"'
        )
        source_early_exit = core_checks.index(
            'if [[ "${SOURCE_VALIDATION_REQUIRED}" != "true" ]]'
        )
        self.assertLess(mainnet_check, source_early_exit)

        release_policy_case = required_gate.split("release-policy)", 1)[1].split(
            ";;", 1
        )[0]
        self.assertIn('wait_for_checks "Core Checks Gate"', release_policy_case)


if __name__ == "__main__":
    unittest.main()
