#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Update or check exact-byte digests and case counts in the P2MR v1 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PROFILE = "qbit-p2mr-v1"
SCHEMA_VERSION = 1
PROFILE_VERSION = 1
SPECIFICATION = "doc/consensus/p2mr-v1.md"
REFERENCE_REPOSITORY = "Qbit-Org/qbit"
REFERENCE_COMMIT = "988756471aeecdf4463c04be49da2b7b89a98c21"
ANCESTRY_NAME = "BIP-360"
ANCESTRY_VERSION = "0.12.0"
ANCESTRY_COMMIT = "6740c533e8dce4e912f17ee85a6f627644e1b783"
MANIFEST_FIELDS = {
    "schema_version",
    "profile",
    "profile_version",
    "specification",
    "reference_implementation",
    "ancestry",
    "case_count",
    "case_counts",
    "files",
}
FILE_FIELDS = {"path", "purpose", "case_count", "sha256"}
REFERENCE_FIELDS = {"repository", "commit"}
ANCESTRY_FIELDS = {"name", "version", "commit", "normative"}
CASE_COUNT_FIELDS = {"commitment_valid", "commitment_invalid", "witness", "cross_profile", "script_boundary"}
FILE_PURPOSES = {
    "src/test/data/p2mr_cross_profile_vectors.json": "qbit and pinned-profile boundary vectors",
    "src/test/data/p2mr_pqc_witness_vectors.json": "PQC sighash and witness vectors",
    "src/test/data/p2mr_script_boundary_vectors.json": "script, control, leaf, opcode, and resource boundary vectors",
    "src/test/data/p2mr_vectors.json": "commitment, control block, root, and address vectors",
}
CORPUS_FILES = tuple(FILE_PURPOSES)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def case_counts(repo_root: Path) -> tuple[dict[str, int], dict[str, int]]:
    commitments = read_json(repo_root / "src/test/data/p2mr_vectors.json")
    witnesses = read_json(repo_root / "src/test/data/p2mr_pqc_witness_vectors.json")
    cross_profile = read_json(repo_root / "src/test/data/p2mr_cross_profile_vectors.json")
    script_boundary = read_json(repo_root / "src/test/data/p2mr_script_boundary_vectors.json")
    for path, corpus in (
        ("p2mr_vectors.json", commitments),
        ("p2mr_pqc_witness_vectors.json", witnesses),
        ("p2mr_cross_profile_vectors.json", cross_profile),
        ("p2mr_script_boundary_vectors.json", script_boundary),
    ):
        if corpus.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"{path} has an unsupported schema_version")
        if corpus.get("profile") != PROFILE or corpus.get("profile_version") != PROFILE_VERSION:
            raise ValueError(f"{path} has an unsupported profile")

    valid = commitments.get("valid")
    invalid = commitments.get("invalid")
    witness_vectors = witnesses.get("vectors")
    cross_vectors = cross_profile.get("vectors")
    boundary_vectors = script_boundary.get("cases")
    if not all(isinstance(value, list) for value in (valid, invalid, witness_vectors, cross_vectors, boundary_vectors)):
        raise ValueError("a corpus vector collection is not an array")
    assert isinstance(valid, list)
    assert isinstance(invalid, list)
    assert isinstance(witness_vectors, list)
    assert isinstance(cross_vectors, list)
    assert isinstance(boundary_vectors, list)

    counts = {
        "commitment_valid": len(valid),
        "commitment_invalid": len(invalid),
        "witness": len(witness_vectors),
        "cross_profile": len(cross_vectors),
        "script_boundary": len(boundary_vectors),
    }
    per_file = {
        "src/test/data/p2mr_cross_profile_vectors.json": counts["cross_profile"],
        "src/test/data/p2mr_pqc_witness_vectors.json": counts["witness"],
        "src/test/data/p2mr_script_boundary_vectors.json": counts["script_boundary"],
        "src/test/data/p2mr_vectors.json": counts["commitment_valid"] + counts["commitment_invalid"],
    }
    return counts, per_file


def updated_manifest(repo_root: Path, manifest_path: Path) -> str:
    manifest = read_json(manifest_path)
    if set(manifest) != MANIFEST_FIELDS:
        raise ValueError("manifest has unknown or missing top-level fields")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("manifest has an unsupported schema_version")
    if manifest.get("profile") != PROFILE or manifest.get("profile_version") != PROFILE_VERSION:
        raise ValueError("manifest has an unsupported profile")
    if manifest.get("specification") != SPECIFICATION:
        raise ValueError("manifest has an unexpected specification path")

    reference = manifest.get("reference_implementation")
    if not isinstance(reference, dict) or set(reference) != REFERENCE_FIELDS:
        raise ValueError("manifest reference_implementation has unknown or missing fields")
    if reference.get("repository") != REFERENCE_REPOSITORY or reference.get("commit") != REFERENCE_COMMIT:
        raise ValueError("manifest has an unexpected reference implementation")

    ancestry = manifest.get("ancestry")
    if not isinstance(ancestry, dict) or set(ancestry) != ANCESTRY_FIELDS:
        raise ValueError("manifest ancestry has unknown or missing fields")
    if (
        ancestry.get("name") != ANCESTRY_NAME
        or ancestry.get("version") != ANCESTRY_VERSION
        or ancestry.get("commit") != ANCESTRY_COMMIT
        or ancestry.get("normative") is not False
    ):
        raise ValueError("manifest has unexpected ancestry metadata")

    manifest_counts = manifest.get("case_counts")
    if not isinstance(manifest_counts, dict) or set(manifest_counts) != CASE_COUNT_FIELDS:
        raise ValueError("manifest case_counts has unknown or missing fields")
    if not isinstance(manifest.get("case_count"), int):
        raise ValueError("manifest case_count must be an integer")

    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != len(CORPUS_FILES):
        raise ValueError("manifest has the wrong number of corpus files")
    paths = [entry.get("path") for entry in files if isinstance(entry, dict)]
    if paths != list(CORPUS_FILES):
        raise ValueError("manifest files must contain the canonical sorted paths")
    if any(set(entry) != FILE_FIELDS for entry in files):
        raise ValueError("manifest file entry has unknown or missing fields")
    for entry in files:
        path = entry["path"]
        if entry.get("purpose") != FILE_PURPOSES[path]:
            raise ValueError(f"manifest file {path} has an unexpected purpose")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"manifest file {path} has an invalid sha256")
        if not isinstance(entry.get("case_count"), int):
            raise ValueError(f"manifest file {path} has an invalid case_count")

    counts, per_file = case_counts(repo_root)
    manifest["case_count"] = sum(counts.values())
    manifest["case_counts"] = counts
    for entry in files:
        relative_path = entry["path"]
        data = (repo_root / relative_path).read_bytes()
        entry["case_count"] = per_file[relative_path]
        entry["sha256"] = hashlib.sha256(data).hexdigest()
    return json.dumps(manifest, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the manifest is not current")
    parser.add_argument(
        "--source-root",
        type=Path,
        help="source tree containing corpus files (default: repository root)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="manifest path (default: src/test/data/p2mr_v1_manifest.json)",
    )
    parser.add_argument("--output", type=Path, help="write an updated manifest to a separate path")
    args = parser.parse_args()

    if args.check and args.output:
        parser.error("--check and --output cannot be used together")
    repo_root = (args.source_root or Path(__file__).resolve().parents[2]).resolve()
    manifest_path = args.manifest or Path("src/test/data/p2mr_v1_manifest.json")
    if not manifest_path.is_absolute():
        manifest_path = repo_root / manifest_path
    expected = updated_manifest(repo_root, manifest_path)
    current = manifest_path.read_text(encoding="utf8")
    if args.check:
        if current != expected:
            print(f"{manifest_path} is stale")
            return 1
        return 0
    output_path = args.output or manifest_path
    output_path.write_text(expected, encoding="utf8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
