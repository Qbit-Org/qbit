#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Enforce the checked-in merge posture around the real mainnet publish gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = 1
VALID_FAILURE_IDS = {
    "auxpow_chain_id",
    "bootstrap",
    "default_mainnet",
    "genesis_asert",
    "source_read",
}


class MainnetCIPostureError(RuntimeError):
    """Raised when the validator result does not match checked-in CI posture."""


def load_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf8"))
    except FileNotFoundError as exc:
        raise MainnetCIPostureError(f"Missing {description}: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise MainnetCIPostureError(f"Invalid {description} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MainnetCIPostureError(f"{description} must be a JSON object: {path}")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], description: str) -> None:
    actual = set(value)
    if actual != expected:
        raise MainnetCIPostureError(
            f"{description} keys must be {sorted(expected)}, got {sorted(actual)}"
        )


def load_policy(path: Path) -> tuple[str, set[str]]:
    policy = load_object(path, "mainnet CI posture policy")
    require_exact_keys(
        policy,
        {"schema", "phase", "expected_failure_ids"},
        "mainnet CI posture policy",
    )
    if policy["schema"] != SCHEMA:
        raise MainnetCIPostureError(
            f"Unsupported mainnet CI posture policy schema: {policy['schema']!r}"
        )
    phase = policy["phase"]
    if phase not in {"staging", "final"}:
        raise MainnetCIPostureError(f"Unsupported mainnet CI phase: {phase!r}")
    expected = policy["expected_failure_ids"]
    if (
        not isinstance(expected, list)
        or any(not isinstance(item, str) for item in expected)
        or len(expected) != len(set(expected))
    ):
        raise MainnetCIPostureError(
            "expected_failure_ids must be a list of unique strings"
        )
    unknown = set(expected) - (VALID_FAILURE_IDS - {"source_read"})
    if unknown:
        raise MainnetCIPostureError(
            "Unknown expected mainnet failure id(s): " + ", ".join(sorted(unknown))
        )
    if phase == "staging" and not expected:
        raise MainnetCIPostureError("Staging phase must declare expected failure ids")
    if phase == "final" and expected:
        raise MainnetCIPostureError("Final phase must not declare expected failures")
    return phase, set(expected)


def load_result(path: Path) -> tuple[bool, set[str]]:
    result = load_object(path, "mainnet validator result")
    require_exact_keys(
        result,
        {"schema", "ready", "source", "failures"},
        "mainnet validator result",
    )
    if result["schema"] != SCHEMA:
        raise MainnetCIPostureError(
            f"Unsupported mainnet validator result schema: {result['schema']!r}"
        )
    ready = result["ready"]
    if not isinstance(ready, bool):
        raise MainnetCIPostureError("mainnet validator result ready must be boolean")
    if not isinstance(result["source"], str) or not result["source"]:
        raise MainnetCIPostureError("mainnet validator result source must be nonempty")
    failures = result["failures"]
    if not isinstance(failures, list):
        raise MainnetCIPostureError("mainnet validator failures must be a list")
    failure_ids: list[str] = []
    for index, failure in enumerate(failures):
        if not isinstance(failure, dict):
            raise MainnetCIPostureError(f"mainnet validator failure {index} must be an object")
        require_exact_keys(
            failure,
            {"id", "name", "message"},
            f"mainnet validator failure {index}",
        )
        if any(not isinstance(failure[key], str) or not failure[key] for key in failure):
            raise MainnetCIPostureError(
                f"mainnet validator failure {index} fields must be nonempty strings"
            )
        failure_ids.append(failure["id"])
    if len(failure_ids) != len(set(failure_ids)):
        raise MainnetCIPostureError("mainnet validator failure ids must be unique")
    unknown = set(failure_ids) - VALID_FAILURE_IDS
    if unknown:
        raise MainnetCIPostureError(
            "Unknown mainnet validator failure id(s): " + ", ".join(sorted(unknown))
        )
    if ready == bool(failures):
        raise MainnetCIPostureError(
            "mainnet validator ready value is inconsistent with its failures"
        )
    return ready, set(failure_ids)


def validate(
    policy_path: Path,
    result_path: Path,
    validator_exit_code: int,
) -> str:
    phase, expected_failures = load_policy(policy_path)
    ready, actual_failures = load_result(result_path)
    if validator_exit_code not in {0, 1}:
        raise MainnetCIPostureError(
            f"Mainnet validator returned unexpected exit code {validator_exit_code}"
        )
    if ready != (validator_exit_code == 0):
        raise MainnetCIPostureError(
            "Mainnet validator exit code disagrees with its machine-readable result"
        )
    if phase == "final":
        if not ready:
            raise MainnetCIPostureError(
                "Final mainnet CI phase requires publication-ready source; got failure id(s): "
                + ", ".join(sorted(actual_failures))
            )
        return "Validated publication-ready mainnet CI posture"
    if ready:
        raise MainnetCIPostureError(
            "Mainnet source is publication-ready while CI policy remains staging; "
            "change the checked-in policy to final"
        )
    if actual_failures != expected_failures:
        missing = expected_failures - actual_failures
        unexpected = actual_failures - expected_failures
        details = []
        if missing:
            details.append("missing expected: " + ", ".join(sorted(missing)))
        if unexpected:
            details.append("unexpected: " + ", ".join(sorted(unexpected)))
        raise MainnetCIPostureError(
            "Mainnet staging failures do not exactly match policy (" + "; ".join(details) + ")"
        )
    return (
        "Validated merge-safe mainnet staging posture; publication remains blocked by: "
        + ", ".join(sorted(actual_failures))
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--result-json", required=True, type=Path)
    parser.add_argument("--validator-exit-code", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        message = validate(args.policy, args.result_json, args.validator_exit_code)
    except MainnetCIPostureError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
