# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Assert that the shared-fuzz-required harnesses are compiled into the main fuzz binary."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


def parse_required_features(value: object, target_id: str, harness_name: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise SystemExit(
            "Invalid required_features for smoke harness "
            f"{harness_name} in target {target_id}"
        )
    return {item for item in value}


def smoke_harnesses_for_target(target: dict[str, object], enabled_features: set[str]) -> set[str]:
    target_id = str(target.get("target_id", "<unknown>"))
    raw_harnesses = target.get("smoke_harnesses", target.get("harnesses", []))
    if not isinstance(raw_harnesses, list):
        raise SystemExit(f"Invalid smoke harness list for target {target_id}")

    harnesses: set[str] = set()
    for raw_harness in raw_harnesses:
        if isinstance(raw_harness, str):
            if not raw_harness:
                raise SystemExit(f"Invalid smoke harness entry for target {target_id}")
            harnesses.add(raw_harness)
            continue

        if not isinstance(raw_harness, dict):
            raise SystemExit(f"Invalid smoke harness entry for target {target_id}")

        harness_name = str(raw_harness.get("name", "")).strip()
        if not harness_name:
            raise SystemExit(f"Invalid smoke harness entry for target {target_id}")

        required_features = parse_required_features(
            raw_harness.get("required_features"),
            target_id,
            harness_name,
        )
        if required_features.issubset(enabled_features):
            harnesses.add(harness_name)

    return harnesses


def list_fuzz_targets(fuzz_binary: Path) -> set[str]:
    env = os.environ.copy()
    env["PRINT_ALL_FUZZ_TARGETS_AND_ABORT"] = "1"
    completed = subprocess.run(
        [str(fuzz_binary)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"Failed to enumerate fuzz targets from {fuzz_binary}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping-file", required=True, type=Path)
    parser.add_argument("--fuzz-binary", required=True, type=Path)
    parser.add_argument("--enabled-feature", dest="enabled_features", action="append", default=[])
    args = parser.parse_args()

    mapping = json.loads(args.mapping_file.read_text(encoding="utf-8"))
    enabled_features = {feature for feature in args.enabled_features if feature}
    required_harnesses: set[str] = set()
    for target in mapping.get("targets", []):
        if target.get("binary") != "fuzz" or not target.get("smoke_check", False):
            continue
        required_harnesses.update(smoke_harnesses_for_target(target, enabled_features))

    if not required_harnesses:
        raise SystemExit("No required fuzz harnesses were declared for the main fuzz binary.")

    compiled_targets = list_fuzz_targets(args.fuzz_binary)
    missing = sorted(required_harnesses - compiled_targets)
    if missing:
        raise SystemExit(
            "Missing required fuzz harnesses from main fuzz binary: "
            + ", ".join(missing)
        )

    print("required fuzz harnesses present: " + ", ".join(sorted(required_harnesses)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
