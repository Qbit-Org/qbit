#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Merge independently generated Python and Rust P2MR witness vectors."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PROFILE = "qbit-p2mr-v1"
SCHEMA_VERSION = 1
PROFILE_VERSION = 1
GENERATOR_VERSION = 1
CANONICAL_IDS = (
    "single_key_default_sighash",
    "single_key_sighash_none",
    "single_key_sighash_single_matching_output",
    "single_key_sighash_all_anyonecanpay",
    "single_key_sighash_none_anyonecanpay",
    "single_key_sighash_single_anyonecanpay",
    "single_key_default_sighash_annex_present",
    "single_key_sighash_single_missing_first",
    "single_key_sighash_single_missing_beyond",
    "single_key_sighash_single_anyonecanpay_missing_first",
    "single_key_sighash_single_anyonecanpay_missing_beyond",
    "single_key_leading_codesep",
    "branch_codesep_true",
    "branch_codesep_false",
)
PYTHON_IDS = frozenset(CANONICAL_IDS[:11])
RUST_IDS = frozenset(CANONICAL_IDS[11:])


def load_generated(path: Path, owner: str, expected_ids: frozenset[str]) -> dict[str, dict[str, Any]]:
    corpus = json.loads(path.read_text(encoding="utf8"))
    if not isinstance(corpus, dict) or set(corpus) != {
        "schema_version",
        "profile",
        "profile_version",
        "vectors",
    }:
        raise ValueError(f"{path} has an invalid corpus wrapper")
    if (
        corpus["schema_version"] != SCHEMA_VERSION
        or corpus["profile"] != PROFILE
        or corpus["profile_version"] != PROFILE_VERSION
        or not isinstance(corpus["vectors"], list)
    ):
        raise ValueError(f"{path} has an unsupported schema or profile")

    by_id: dict[str, dict[str, Any]] = {}
    for vector in corpus["vectors"]:
        if not isinstance(vector, dict):
            raise ValueError(f"{path} contains a non-object vector")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or vector.get("name") != vector_id:
            raise ValueError(f"{path} contains a vector without a stable id/name")
        if vector_id in by_id:
            raise ValueError(f"{path} contains duplicate vector {vector_id}")
        if vector.get("generator") != {"id": owner, "version": GENERATOR_VERSION}:
            raise ValueError(f"{path} vector {vector_id} has incorrect ownership")
        by_id[vector_id] = vector
    if set(by_id) != expected_ids:
        raise ValueError(
            f"{path} generated ids differ: missing={sorted(expected_ids - set(by_id))}, "
            f"unknown={sorted(set(by_id) - expected_ids)}"
        )
    return by_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True, dest="python_path")
    parser.add_argument("--rust", type=Path, required=True, dest="rust_path")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    vectors = load_generated(args.python_path, "standalone-python", PYTHON_IDS)
    rust_vectors = load_generated(args.rust_path, "standalone-rust", RUST_IDS)
    overlap = set(vectors) & set(rust_vectors)
    if overlap:
        raise ValueError(f"generator ownership overlaps: {sorted(overlap)}")
    vectors.update(rust_vectors)
    corpus = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "vectors": [vectors[vector_id] for vector_id in CANONICAL_IDS],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
