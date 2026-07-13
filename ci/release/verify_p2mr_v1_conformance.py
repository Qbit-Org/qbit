#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate qbit P2MR v1 evidence for an exact signed release tag target."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = "src/test/data/p2mr_v1_manifest.json"
SPECIFICATION_PATH = "doc/consensus/p2mr-v1.md"
PROFILE = "qbit-p2mr-v1"
PROFILE_VERSION = 1
REFERENCE_IMPLEMENTATION_COMMIT = "988756471aeecdf4463c04be49da2b7b89a98c21"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HTTPS_RE = re.compile(r"^https://[^\s]+$")

EVIDENCE_KEYS = {
    "schema_version",
    "profile",
    "profile_version",
    "specification_commit",
    "corpus_manifest_sha256",
    "release_tag",
    "release_source_commit",
    "consensus_review",
    "oracle",
    "qbit",
    "integration_matrix",
}
CONSENSUS_REVIEW_KEYS = {"source_commit", "evidence"}
ORACLE_EVIDENCE_KEYS = {
    "name",
    "version",
    "source_commit",
    "report_sha256",
    "result",
    "case_count",
}
QBIT_EVIDENCE_KEYS = {
    "test_binary_commit",
    "result",
    "case_count",
    "evidence",
}
MATRIX_EVIDENCE_KEYS = {
    "release_source_commit",
    "sha256",
    "blocking_failures",
    "unresolved_claimed_support",
}

MANIFEST_KEYS = {
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
REFERENCE_KEYS = {"repository", "commit"}
ANCESTRY_KEYS = {"name", "version", "commit", "normative"}
MANIFEST_FILE_KEYS = {"path", "purpose", "case_count", "sha256"}
EXPECTED_CASE_COUNT_KEYS = {
    "commitment_valid",
    "commitment_invalid",
    "witness",
    "cross_profile",
    "script_boundary",
}
EXPECTED_CORPUS_FILES = {
    "src/test/data/p2mr_cross_profile_vectors.json": "qbit and pinned-profile boundary vectors",
    "src/test/data/p2mr_pqc_witness_vectors.json": "PQC sighash and witness vectors",
    "src/test/data/p2mr_script_boundary_vectors.json": "script, control, leaf, opcode, and resource boundary vectors",
    "src/test/data/p2mr_vectors.json": "commitment, control block, root, and address vectors",
}

REPORT_KEYS = {
    "schema_version",
    "profile",
    "profile_version",
    "manifest_sha256",
    "oracle",
    "reference_implementation_commit",
    "manifest_case_counts",
    "case_counts",
    "result",
    "cases",
}
REPORT_ORACLE_KEYS = {"name", "version", "commit"}
REPORT_COUNT_KEYS = {"total", "accepted", "rejected", "cross_profile"}
REPORT_CASE_KEYS = {
    "id",
    "category",
    "result",
    "observed_accept",
    "observed_stage",
    "observed_error",
}

MATRIX_KEYS = {
    "schema_version",
    "profile",
    "profile_version",
    "status",
    "release_source_commit",
    "corpus_manifest_sha256",
    "components",
}
MATRIX_COMPONENT_KEYS = {
    "id",
    "component",
    "category",
    "owner",
    "version",
    "profile",
    "corpus_manifest_sha256",
    "test_environment",
    "result",
    "release_surface",
    "evidence",
    "limitations",
    "reviewed_at",
}
REQUIRED_CATEGORIES = {
    "wallet",
    "exchange",
    "explorer",
    "miner-pool",
    "signer",
    "psbt-tool",
    "alternative-validator",
}
ALLOWED_CATEGORIES = REQUIRED_CATEGORIES | {
    "reference-implementation",
    "corpus-generator",
}
REQUIRED_COMPONENT_IDS = {
    "qbit-consensus-validation",
    "qbit-descriptor-wallet",
    "qbit-watch-only-pubkeydb",
    "qbit-raw-transaction-signing",
    "qbit-psbt-flow",
    "qbit-qt-wallet-surfaces",
    "qbit-mining-payout-validation",
    "python-corpus-generator",
    "rust-corpus-generator",
    "p2mr-v1-oracle",
}
ALLOWED_RESULTS = {"pass", "fail", "partial", "not-tested", "not-applicable"}
ALLOWED_RELEASE_SURFACES = {"supported", "not-claimed"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")
DATE_RE = re.compile(r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$")


class P2MRConformanceError(Exception):
    """Raised when P2MR release evidence does not fail-closed validate."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise P2MRConformanceError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf8")
    except UnicodeDecodeError as exc:
        raise P2MRConformanceError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise P2MRConformanceError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise P2MRConformanceError(f"{label} must contain a JSON object")
    return value


def load_json_file(path: Path, *, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise P2MRConformanceError(f"missing {label}: {path}") from exc
    return raw, load_json_bytes(raw, label=label)


def require_exact_keys(
    value: object, expected: set[str], *, path: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P2MRConformanceError(f"{path} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if unknown:
            detail.append("unknown=" + ",".join(unknown))
        raise P2MRConformanceError(f"{path} has invalid fields: {'; '.join(detail)}")
    return value


def require_string(value: object, *, path: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise P2MRConformanceError(f"{path} must be a non-empty string")
    return value


def require_nonnegative_int(value: object, *, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise P2MRConformanceError(f"{path} must be a nonnegative integer")
    return value


def require_sha(value: object, *, path: str) -> str:
    sha = require_string(value, path=path)
    if not SHA_RE.fullmatch(sha):
        raise P2MRConformanceError(f"{path} must be 40 lowercase hex characters")
    return sha


def require_sha256(value: object, *, path: str) -> str:
    digest = require_string(value, path=path)
    if not SHA256_RE.fullmatch(digest):
        raise P2MRConformanceError(f"{path} must be 64 lowercase hex characters")
    return digest


def require_https(value: object, *, path: str) -> str:
    url = require_string(value, path=path)
    if not HTTPS_RE.fullmatch(url):
        raise P2MRConformanceError(f"{path} must be a stable HTTPS reference")
    return url


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_run(source_root: Path, args: list[str], *, binary: bool = False) -> bytes | str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *args],
            check=True,
            capture_output=True,
            text=not binary,
        )
    except FileNotFoundError as exc:
        raise P2MRConformanceError(
            "git is required for release source validation"
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace") if binary else exc.stderr
        stdout = exc.stdout.decode(errors="replace") if binary else exc.stdout
        detail = (stderr or stdout).strip()
        message = f"git {' '.join(args)} failed"
        if detail:
            message += f": {detail}"
        raise P2MRConformanceError(message) from exc
    return result.stdout


def resolve_release_commit(source_root: Path, release_tag: str) -> str:
    if (
        not release_tag
        or release_tag.startswith("-")
        or any(char.isspace() for char in release_tag)
    ):
        raise P2MRConformanceError(f"invalid release tag: {release_tag!r}")
    tag_ref = f"refs/tags/{release_tag}"
    object_type = str(git_run(source_root, ["cat-file", "-t", tag_ref])).strip()
    if object_type != "tag":
        raise P2MRConformanceError(f"release tag {release_tag!r} must be annotated")
    commit = str(
        git_run(source_root, ["rev-parse", "--verify", f"{tag_ref}^{{commit}}"])
    ).strip()
    return require_sha(commit, path="release tag target")


def validate_repo_path(path: object, *, expected_prefix: str) -> str:
    value = require_string(path, path="manifest file path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or str(pure) != value or ".." in pure.parts:
        raise P2MRConformanceError(f"unsafe manifest file path: {value!r}")
    if not value.startswith(expected_prefix):
        raise P2MRConformanceError(
            f"manifest file path must start with {expected_prefix!r}: {value!r}"
        )
    return value


def read_tagged_blob(source_root: Path, commit: str, path: str) -> bytes:
    tree_output = str(git_run(source_root, ["ls-tree", commit, "--", path])).strip()
    if not tree_output:
        raise P2MRConformanceError(f"tagged source is missing {path}")
    if "\t" not in tree_output:
        raise P2MRConformanceError(f"cannot inspect tagged source entry {path}")
    metadata, listed_path = tree_output.split("\t", 1)
    fields = metadata.split()
    if (
        listed_path != path
        or len(fields) != 3
        or fields[0] != "100644"
        or fields[1] != "blob"
    ):
        raise P2MRConformanceError(
            f"tagged source entry must be a regular file: {path}"
        )
    return bytes(git_run(source_root, ["show", f"{commit}:{path}"], binary=True))


def validate_profile(value: dict[str, Any], *, path: str) -> None:
    if value.get("schema_version") != 1:
        raise P2MRConformanceError(f"{path}.schema_version must be 1")
    if value.get("profile") != PROFILE:
        raise P2MRConformanceError(f"{path}.profile must be {PROFILE!r}")
    if value.get("profile_version") != PROFILE_VERSION:
        raise P2MRConformanceError(f"{path}.profile_version must be 1")


def validate_manifest(
    source_root: Path, release_commit: str
) -> tuple[dict[str, Any], str, bytes]:
    raw = read_tagged_blob(source_root, release_commit, MANIFEST_PATH)
    manifest = require_exact_keys(
        load_json_bytes(raw, label=MANIFEST_PATH), MANIFEST_KEYS, path="manifest"
    )
    validate_profile(manifest, path="manifest")
    if manifest["specification"] != SPECIFICATION_PATH:
        raise P2MRConformanceError(
            f"manifest.specification must be {SPECIFICATION_PATH!r}"
        )

    reference = require_exact_keys(
        manifest["reference_implementation"],
        REFERENCE_KEYS,
        path="manifest.reference_implementation",
    )
    if reference["repository"] != "Qbit-Org/qbit":
        raise P2MRConformanceError(
            "manifest reference repository must be Qbit-Org/qbit"
        )
    if (
        require_sha(
            reference["commit"], path="manifest.reference_implementation.commit"
        )
        != REFERENCE_IMPLEMENTATION_COMMIT
    ):
        raise P2MRConformanceError("manifest reference implementation commit mismatch")

    ancestry = require_exact_keys(
        manifest["ancestry"], ANCESTRY_KEYS, path="manifest.ancestry"
    )
    expected_ancestry = {
        "name": "BIP-360",
        "version": "0.12.0",
        "commit": "6740c533e8dce4e912f17ee85a6f627644e1b783",
        "normative": False,
    }
    if ancestry != expected_ancestry:
        raise P2MRConformanceError(
            "manifest ancestry does not match pinned BIP-360 v0.12.0"
        )

    case_count = require_nonnegative_int(
        manifest["case_count"], path="manifest.case_count"
    )
    if case_count == 0:
        raise P2MRConformanceError("manifest.case_count must be positive")
    case_counts = manifest["case_counts"]
    if not isinstance(case_counts, dict) or set(case_counts) != EXPECTED_CASE_COUNT_KEYS:
        raise P2MRConformanceError(
            "manifest.case_counts has unknown or missing fields"
        )
    category_total = sum(
        require_nonnegative_int(count, path=f"manifest.case_counts.{category}")
        for category, count in case_counts.items()
    )
    if category_total != case_count:
        raise P2MRConformanceError(
            "manifest.case_counts do not sum to manifest.case_count"
        )

    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise P2MRConformanceError("manifest.files must be a non-empty array")
    if len(files) != len(EXPECTED_CORPUS_FILES):
        raise P2MRConformanceError("manifest has the wrong number of corpus files")
    seen_paths: set[str] = set()
    file_total = 0
    ordered_paths: list[str] = []
    for index, raw_entry in enumerate(files):
        entry = require_exact_keys(
            raw_entry, MANIFEST_FILE_KEYS, path=f"manifest.files[{index}]"
        )
        path = validate_repo_path(entry["path"], expected_prefix="src/test/data/")
        if path == MANIFEST_PATH:
            raise P2MRConformanceError("manifest must not list itself")
        if path in seen_paths:
            raise P2MRConformanceError(f"duplicate manifest file path: {path}")
        seen_paths.add(path)
        ordered_paths.append(path)
        require_string(entry["purpose"], path=f"manifest.files[{index}].purpose")
        if path not in EXPECTED_CORPUS_FILES:
            raise P2MRConformanceError(f"unexpected manifest corpus path: {path}")
        if entry["purpose"] != EXPECTED_CORPUS_FILES[path]:
            raise P2MRConformanceError(f"unexpected manifest purpose for {path}")
        file_total += require_nonnegative_int(
            entry["case_count"], path=f"manifest.files[{index}].case_count"
        )
        expected_digest = require_sha256(
            entry["sha256"], path=f"manifest.files[{index}].sha256"
        )
        actual_digest = sha256_bytes(
            read_tagged_blob(source_root, release_commit, path)
        )
        if actual_digest != expected_digest:
            raise P2MRConformanceError(
                f"manifest digest mismatch for {path}: expected {expected_digest}, got {actual_digest}"
            )
    if ordered_paths != sorted(ordered_paths):
        raise P2MRConformanceError("manifest.files must be sorted by path")
    if set(ordered_paths) != set(EXPECTED_CORPUS_FILES):
        raise P2MRConformanceError(
            "manifest does not contain the exact P2MR v1 corpus files"
        )
    if file_total != case_count:
        raise P2MRConformanceError(
            "manifest file counts do not sum to manifest.case_count"
        )
    return manifest, sha256_bytes(raw), raw


def expected_corpus_cases(
    source_root: Path, release_commit: str, manifest: dict[str, Any]
) -> dict[str, tuple[str, bool, str, str]]:
    """Return the exact report projection declared by the tagged corpus."""

    projected: dict[str, tuple[str, bool, str, str]] = {}

    def add_case(raw_case: object, *, category: str, expected_key: str) -> None:
        if not isinstance(raw_case, dict):
            raise P2MRConformanceError("corpus case must be an object")
        case_id = require_string(raw_case.get("id"), path="corpus case.id")
        if case_id in projected:
            raise P2MRConformanceError(f"duplicate corpus case id: {case_id}")
        expected_value = raw_case.get(expected_key)
        if expected_key == "expected" and category == "cross_profile":
            if not isinstance(expected_value, dict):
                raise P2MRConformanceError(
                    f"corpus case {case_id}.expected must be an object"
                )
            expected_value = expected_value.get("qbit_p2mr_v1")
        expected = require_exact_keys(
            expected_value,
            {"accepted", "stage", "error"},
            path=f"corpus case {case_id} expectation",
        )
        if not isinstance(expected["accepted"], bool):
            raise P2MRConformanceError(
                f"corpus case {case_id} accepted must be boolean"
            )
        projected[case_id] = (
            category,
            expected["accepted"],
            require_string(expected["stage"], path=f"corpus case {case_id}.stage"),
            require_string(expected["error"], path=f"corpus case {case_id}.error"),
        )

    for entry in manifest["files"]:
        path = entry["path"]
        corpus = load_json_bytes(
            read_tagged_blob(source_root, release_commit, path), label=path
        )
        validate_profile(corpus, path=path)
        before = len(projected)
        if path == "src/test/data/p2mr_vectors.json":
            for collection in ("valid", "invalid"):
                cases = corpus.get(collection)
                if not isinstance(cases, list):
                    raise P2MRConformanceError(f"{path}.{collection} must be an array")
                for case in cases:
                    add_case(case, category="commitment", expected_key="expected")
        elif path == "src/test/data/p2mr_pqc_witness_vectors.json":
            cases = corpus.get("vectors")
            if not isinstance(cases, list):
                raise P2MRConformanceError(f"{path}.vectors must be an array")
            for case in cases:
                add_case(case, category="witness", expected_key="expected")
        elif path == "src/test/data/p2mr_cross_profile_vectors.json":
            cases = corpus.get("vectors")
            if not isinstance(cases, list):
                raise P2MRConformanceError(f"{path}.vectors must be an array")
            for case in cases:
                add_case(case, category="cross_profile", expected_key="expected")
        elif path == "src/test/data/p2mr_script_boundary_vectors.json":
            cases = corpus.get("cases")
            if not isinstance(cases, list):
                raise P2MRConformanceError(f"{path}.cases must be an array")
            for case in cases:
                add_case(case, category="script_boundary", expected_key="consensus")
        else:  # Exact manifest validation should make this unreachable.
            raise P2MRConformanceError(f"unsupported corpus path: {path}")
        if len(projected) - before != entry["case_count"]:
            raise P2MRConformanceError(f"corpus case count mismatch for {path}")
    if len(projected) != manifest["case_count"]:
        raise P2MRConformanceError("projected corpus cases do not equal manifest.case_count")
    return projected


def validate_specification_commit(
    source_root: Path, specification_commit: str, release_commit: str
) -> None:
    resolved = str(
        git_run(
            source_root, ["rev-parse", "--verify", f"{specification_commit}^{{commit}}"]
        )
    ).strip()
    if resolved != specification_commit:
        raise P2MRConformanceError("specification_commit did not resolve exactly")
    try:
        git_run(
            source_root,
            ["merge-base", "--is-ancestor", specification_commit, release_commit],
        )
    except P2MRConformanceError as exc:
        raise P2MRConformanceError(
            "specification_commit must be an ancestor of the release tag target"
        ) from exc
    reviewed = read_tagged_blob(source_root, specification_commit, SPECIFICATION_PATH)
    released = read_tagged_blob(source_root, release_commit, SPECIFICATION_PATH)
    if reviewed != released:
        raise P2MRConformanceError(
            "normative specification changed after specification_commit without updated review evidence"
        )


def validate_oracle_report(
    report: dict[str, Any],
    *,
    release_commit: str,
    manifest: dict[str, Any],
    manifest_sha256: str,
    expected_cases: dict[str, tuple[str, bool, str, str]],
) -> int:
    require_exact_keys(report, REPORT_KEYS, path="oracle report")
    validate_profile(report, path="oracle report")
    if report["manifest_sha256"] != manifest_sha256:
        raise P2MRConformanceError("oracle report manifest digest mismatch")
    if (
        report["reference_implementation_commit"]
        != manifest["reference_implementation"]["commit"]
    ):
        raise P2MRConformanceError(
            "oracle report reference implementation commit mismatch"
        )
    if report["manifest_case_counts"] != manifest["case_counts"]:
        raise P2MRConformanceError("oracle report manifest case counts mismatch")
    if report["result"] != "pass":
        raise P2MRConformanceError("oracle report result must be pass")

    identity = require_exact_keys(
        report["oracle"], REPORT_ORACLE_KEYS, path="oracle report.oracle"
    )
    if identity["name"] != "p2mr-v1-oracle" or identity["version"] != "1":
        raise P2MRConformanceError("oracle report identity mismatch")
    if (
        require_sha(identity["commit"], path="oracle report.oracle.commit")
        != release_commit
    ):
        raise P2MRConformanceError(
            "oracle report commit must equal the release tag target"
        )

    counts = require_exact_keys(
        report["case_counts"], REPORT_COUNT_KEYS, path="oracle report.case_counts"
    )
    normalized_counts = {
        key: require_nonnegative_int(value, path=f"oracle report.case_counts.{key}")
        for key, value in counts.items()
    }
    total = normalized_counts["total"]
    if total != manifest["case_count"]:
        raise P2MRConformanceError(
            "oracle report total does not equal manifest.case_count"
        )
    if normalized_counts["accepted"] + normalized_counts["rejected"] != total:
        raise P2MRConformanceError(
            "oracle accepted/rejected counts do not sum to total"
        )

    cases = report["cases"]
    if not isinstance(cases, list) or len(cases) != total:
        raise P2MRConformanceError("oracle report cases do not match total")
    ids: list[str] = []
    accepted = 0
    cross_profile = 0
    for index, raw_case in enumerate(cases):
        case = require_exact_keys(
            raw_case, REPORT_CASE_KEYS, path=f"oracle report.cases[{index}]"
        )
        case_id = require_string(case["id"], path=f"oracle report.cases[{index}].id")
        ids.append(case_id)
        category = require_string(
            case["category"], path=f"oracle report.cases[{index}].category"
        )
        if case["result"] != "pass":
            raise P2MRConformanceError(f"oracle case {case_id} did not pass")
        if not isinstance(case["observed_accept"], bool):
            raise P2MRConformanceError(
                f"oracle case {case_id} observed_accept must be boolean"
            )
        accepted += int(case["observed_accept"])
        cross_profile += int(category == "cross_profile")
        require_string(
            case["observed_stage"],
            path=f"oracle case {case_id}.observed_stage",
            allow_empty=True,
        )
        require_string(
            case["observed_error"],
            path=f"oracle case {case_id}.observed_error",
            allow_empty=True,
        )
        expected = expected_cases.get(case_id)
        observed = (
            category,
            case["observed_accept"],
            case["observed_stage"],
            case["observed_error"],
        )
        if expected is None or observed != expected:
            raise P2MRConformanceError(
                f"oracle case {case_id} does not match the tagged corpus expectation"
            )
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise P2MRConformanceError("oracle report case IDs must be unique and sorted")
    if accepted != normalized_counts["accepted"]:
        raise P2MRConformanceError("oracle accepted count does not match case rows")
    if total - accepted != normalized_counts["rejected"]:
        raise P2MRConformanceError("oracle rejected count does not match case rows")
    if cross_profile != normalized_counts["cross_profile"]:
        raise P2MRConformanceError(
            "oracle cross-profile count does not match case rows"
        )
    return total


def _optional_string(value: object, *, path: str) -> str | None:
    if value is None:
        return None
    return require_string(value, path=path)


def validate_integration_matrix(
    matrix: dict[str, Any],
    *,
    release_commit: str | None,
    manifest_sha256: str,
    require_release: bool,
) -> tuple[int, int]:
    require_exact_keys(matrix, MATRIX_KEYS, path="integration matrix")
    validate_profile(matrix, path="integration matrix")
    expected_status = "release" if require_release else "draft"
    if matrix["status"] != expected_status:
        raise P2MRConformanceError(
            f"integration matrix status must be {expected_status!r}"
        )
    if matrix["corpus_manifest_sha256"] != manifest_sha256:
        raise P2MRConformanceError("integration matrix corpus manifest digest mismatch")
    if require_release:
        if (
            require_sha(
                matrix["release_source_commit"],
                path="integration matrix.release_source_commit",
            )
            != release_commit
        ):
            raise P2MRConformanceError(
                "integration matrix release commit must equal the tag target"
            )
    elif matrix["release_source_commit"] is not None:
        raise P2MRConformanceError(
            "draft integration matrix release_source_commit must be null"
        )

    components = matrix["components"]
    if not isinstance(components, list) or not components:
        raise P2MRConformanceError(
            "integration matrix components must be a non-empty array"
        )
    seen_ids: set[str] = set()
    component_surfaces: dict[str, str] = {}
    categories: set[str] = set()
    blocking_failures = 0
    unresolved = 0
    for index, raw_component in enumerate(components):
        component = require_exact_keys(
            raw_component,
            MATRIX_COMPONENT_KEYS,
            path=f"integration matrix.components[{index}]",
        )
        component_id = require_string(
            component["id"], path=f"matrix component {index}.id"
        )
        if not ID_RE.fullmatch(component_id):
            raise P2MRConformanceError(
                f"invalid integration component id: {component_id!r}"
            )
        if component_id in seen_ids:
            raise P2MRConformanceError(
                f"duplicate integration component id: {component_id}"
            )
        seen_ids.add(component_id)
        require_string(
            component["component"], path=f"matrix component {component_id}.component"
        )
        category = require_string(
            component["category"], path=f"matrix component {component_id}.category"
        )
        if category not in ALLOWED_CATEGORIES:
            raise P2MRConformanceError(f"unsupported integration category: {category}")
        categories.add(category)
        require_string(
            component["owner"], path=f"matrix component {component_id}.owner"
        )
        result = require_string(
            component["result"], path=f"matrix component {component_id}.result"
        )
        if result not in ALLOWED_RESULTS:
            raise P2MRConformanceError(f"unsupported integration result: {result}")
        surface = require_string(
            component["release_surface"],
            path=f"matrix component {component_id}.release_surface",
        )
        if surface not in ALLOWED_RELEASE_SURFACES:
            raise P2MRConformanceError(f"unsupported release surface: {surface}")
        component_surfaces[component_id] = surface
        require_string(
            component["profile"], path=f"matrix component {component_id}.profile"
        )
        if component["profile"] != PROFILE:
            raise P2MRConformanceError(
                f"matrix component {component_id} profile mismatch"
            )
        if component["corpus_manifest_sha256"] != manifest_sha256:
            raise P2MRConformanceError(
                f"matrix component {component_id} corpus digest mismatch"
            )
        require_string(
            component["test_environment"],
            path=f"matrix component {component_id}.test_environment",
        )
        require_string(
            component["limitations"],
            path=f"matrix component {component_id}.limitations",
        )

        version = _optional_string(
            component["version"], path=f"matrix component {component_id}.version"
        )
        evidence = _optional_string(
            component["evidence"], path=f"matrix component {component_id}.evidence"
        )
        reviewed_at = _optional_string(
            component["reviewed_at"],
            path=f"matrix component {component_id}.reviewed_at",
        )
        if (
            require_release
            and component_id in REQUIRED_COMPONENT_IDS
            and surface == "supported"
            and version != release_commit
        ):
            raise P2MRConformanceError(
                f"required in-tree component {component_id} version must equal the release tag target"
            )
        if evidence is not None:
            require_https(evidence, path=f"matrix component {component_id}.evidence")
        if reviewed_at is not None and not DATE_RE.fullmatch(reviewed_at):
            raise P2MRConformanceError(
                f"matrix component {component_id}.reviewed_at must be YYYY-MM-DD"
            )

        if require_release and surface == "supported":
            if result != "pass":
                blocking_failures += 1
            if version is None or evidence is None or reviewed_at is None:
                unresolved += 1
        if require_release and surface == "not-claimed" and result != "not-applicable":
            raise P2MRConformanceError(
                f"not-claimed component {component_id} must use result not-applicable"
            )

    missing_categories = sorted(REQUIRED_CATEGORIES - categories)
    if missing_categories:
        raise P2MRConformanceError(
            "integration matrix is missing required categories: "
            + ", ".join(missing_categories)
        )
    missing_components = sorted(REQUIRED_COMPONENT_IDS - seen_ids)
    if missing_components:
        raise P2MRConformanceError(
            "integration matrix is missing required in-tree components: "
            + ", ".join(missing_components)
        )
    if require_release:
        unsupported_required = sorted(
            component_id
            for component_id in REQUIRED_COMPONENT_IDS
            if component_surfaces[component_id] != "supported"
        )
        if unsupported_required:
            raise P2MRConformanceError(
                "required in-tree components must be supported: "
                + ", ".join(unsupported_required)
            )
    if require_release and blocking_failures:
        raise P2MRConformanceError(
            f"integration matrix has {blocking_failures} supported component failure(s)"
        )
    if require_release and unresolved:
        raise P2MRConformanceError(
            f"integration matrix has {unresolved} unresolved supported component(s)"
        )
    return blocking_failures, unresolved


def render_integration_matrix_markdown(matrix: dict[str, Any]) -> str:
    """Render the public human view from the authoritative JSON inventory."""

    def cell(value: object) -> str:
        if value is None:
            return "—"
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = [
        "# qbit P2MR v1 Integration Support Matrix",
        "",
        "> This file is generated from `p2mr-v1-support-matrix.json`. The checked-in",
        "> inventory is a draft planning artifact, not final release evidence. Mainnet",
        "> publication requires a separate finalized snapshot for the exact signed tag target.",
        "",
        f"- Profile: `{cell(matrix.get('profile'))}`",
        f"- Profile version: `{cell(matrix.get('profile_version'))}`",
        f"- Status: `{cell(matrix.get('status'))}`",
        f"- Corpus manifest SHA256: `{cell(matrix.get('corpus_manifest_sha256'))}`",
        "",
        "| Component | Category | Owner/contact | Version | Profile | Result | Release surface | Evidence | Limitations | Reviewed at |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    components = matrix.get("components", [])
    if isinstance(components, list):
        for component in components:
            if not isinstance(component, dict):
                continue
            evidence = component.get("evidence")
            evidence_cell = f"[public evidence]({evidence})" if evidence else "—"
            lines.append(
                "| "
                + " | ".join(
                    cell(value)
                    for value in (
                        component.get("component"),
                        component.get("category"),
                        component.get("owner"),
                        component.get("version"),
                        component.get("profile"),
                        component.get("result"),
                        component.get("release_surface"),
                        evidence_cell,
                        component.get("limitations"),
                        component.get("reviewed_at"),
                    )
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "`not-claimed` means qbit makes no mainnet support claim for that row. It is",
            "not a passing test result. A finalized release snapshot must mark every claimed",
            "surface `supported` and `pass`, with stable public evidence. Required in-tree",
            "rows must set `version` to the exact release source commit; external rows use the",
            "exact version of the component that was tested.",
            "",
        ]
    )
    return "\n".join(lines)


def validate_evidence(
    evidence: dict[str, Any],
    *,
    release_tag: str,
    release_commit: str,
    specification_commit: str,
    manifest_sha256: str,
    report_sha256: str,
    matrix_sha256: str,
    case_count: int,
) -> None:
    require_exact_keys(evidence, EVIDENCE_KEYS, path="evidence")
    validate_profile(evidence, path="evidence")
    if evidence["release_tag"] != release_tag:
        raise P2MRConformanceError("evidence release_tag does not match --release-tag")
    if (
        require_sha(
            evidence["release_source_commit"], path="evidence.release_source_commit"
        )
        != release_commit
    ):
        raise P2MRConformanceError(
            "evidence release source commit must equal tag target"
        )
    if (
        require_sha(
            evidence["specification_commit"], path="evidence.specification_commit"
        )
        != specification_commit
    ):
        raise P2MRConformanceError("internal specification commit mismatch")
    if (
        require_sha256(
            evidence["corpus_manifest_sha256"], path="evidence.corpus_manifest_sha256"
        )
        != manifest_sha256
    ):
        raise P2MRConformanceError("evidence corpus manifest digest mismatch")

    review = require_exact_keys(
        evidence["consensus_review"],
        CONSENSUS_REVIEW_KEYS,
        path="evidence.consensus_review",
    )
    if (
        require_sha(
            review["source_commit"], path="evidence.consensus_review.source_commit"
        )
        != release_commit
    ):
        raise P2MRConformanceError("consensus review must cover the exact tag target")
    require_https(review["evidence"], path="evidence.consensus_review.evidence")

    oracle = require_exact_keys(
        evidence["oracle"], ORACLE_EVIDENCE_KEYS, path="evidence.oracle"
    )
    if oracle["name"] != "p2mr-v1-oracle" or oracle["version"] != "1":
        raise P2MRConformanceError("evidence oracle identity mismatch")
    if (
        require_sha(oracle["source_commit"], path="evidence.oracle.source_commit")
        != release_commit
    ):
        raise P2MRConformanceError("evidence oracle commit must equal tag target")
    if (
        require_sha256(oracle["report_sha256"], path="evidence.oracle.report_sha256")
        != report_sha256
    ):
        raise P2MRConformanceError("evidence oracle report digest mismatch")
    if oracle["result"] != "pass":
        raise P2MRConformanceError("evidence oracle result must be pass")
    if (
        require_nonnegative_int(oracle["case_count"], path="evidence.oracle.case_count")
        != case_count
    ):
        raise P2MRConformanceError("evidence oracle case count mismatch")

    qbit = require_exact_keys(
        evidence["qbit"], QBIT_EVIDENCE_KEYS, path="evidence.qbit"
    )
    if (
        require_sha(qbit["test_binary_commit"], path="evidence.qbit.test_binary_commit")
        != release_commit
    ):
        raise P2MRConformanceError("qbit test binary commit must equal tag target")
    if qbit["result"] != "pass":
        raise P2MRConformanceError("qbit conformance result must be pass")
    if (
        require_nonnegative_int(qbit["case_count"], path="evidence.qbit.case_count")
        != case_count
    ):
        raise P2MRConformanceError("qbit case count mismatch")
    require_https(qbit["evidence"], path="evidence.qbit.evidence")

    matrix = require_exact_keys(
        evidence["integration_matrix"],
        MATRIX_EVIDENCE_KEYS,
        path="evidence.integration_matrix",
    )
    if (
        require_sha(
            matrix["release_source_commit"],
            path="evidence.integration_matrix.release_source_commit",
        )
        != release_commit
    ):
        raise P2MRConformanceError(
            "evidence integration matrix commit must equal tag target"
        )
    if (
        require_sha256(matrix["sha256"], path="evidence.integration_matrix.sha256")
        != matrix_sha256
    ):
        raise P2MRConformanceError("evidence integration matrix digest mismatch")
    if (
        require_nonnegative_int(
            matrix["blocking_failures"],
            path="evidence.integration_matrix.blocking_failures",
        )
        != 0
    ):
        raise P2MRConformanceError(
            "evidence integration matrix blocking_failures must be zero"
        )
    if (
        require_nonnegative_int(
            matrix["unresolved_claimed_support"],
            path="evidence.integration_matrix.unresolved_claimed_support",
        )
        != 0
    ):
        raise P2MRConformanceError(
            "evidence integration matrix unresolved_claimed_support must be zero"
        )


def append_github_output(path: Path, values: dict[str, str | int]) -> None:
    with path.open("a", encoding="utf8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--source-root", default=REPO_ROOT, type=Path)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--oracle-report", required=True, type=Path)
    parser.add_argument("--integration-matrix", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        source_root = args.source_root.resolve()
        release_commit = resolve_release_commit(source_root, args.release_tag)
        evidence_raw, evidence = load_json_file(
            args.evidence.resolve(), label="P2MR evidence"
        )
        del evidence_raw  # Evidence is an envelope; the bound inputs are hashed below.
        report_raw, report = load_json_file(
            args.oracle_report.resolve(), label="oracle report"
        )
        matrix_raw, matrix = load_json_file(
            args.integration_matrix.resolve(), label="integration matrix"
        )

        manifest, manifest_sha256, _manifest_raw = validate_manifest(
            source_root, release_commit
        )
        expected_cases = expected_corpus_cases(source_root, release_commit, manifest)
        specification_commit = require_sha(
            evidence.get("specification_commit"), path="evidence.specification_commit"
        )
        validate_specification_commit(source_root, specification_commit, release_commit)
        case_count = validate_oracle_report(
            report,
            release_commit=release_commit,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            expected_cases=expected_cases,
        )
        matrix_sha256 = sha256_bytes(matrix_raw)
        validate_integration_matrix(
            matrix,
            release_commit=release_commit,
            manifest_sha256=manifest_sha256,
            require_release=True,
        )
        report_sha256 = sha256_bytes(report_raw)
        validate_evidence(
            evidence,
            release_tag=args.release_tag,
            release_commit=release_commit,
            specification_commit=specification_commit,
            manifest_sha256=manifest_sha256,
            report_sha256=report_sha256,
            matrix_sha256=matrix_sha256,
            case_count=case_count,
        )
        outputs: dict[str, str | int] = {
            "release_source_commit": release_commit,
            "profile": PROFILE,
            "profile_version": PROFILE_VERSION,
            "manifest_sha256": manifest_sha256,
            "case_count": case_count,
            "oracle_report_sha256": report_sha256,
            "integration_matrix_sha256": matrix_sha256,
        }
        if args.github_output:
            append_github_output(args.github_output.resolve(), outputs)
        print(
            "Validated qbit P2MR v1 conformance: "
            f"release={release_commit} profile={PROFILE} manifest_sha256={manifest_sha256} "
            f"cases={case_count} matrix_sha256={matrix_sha256}"
        )
        return 0
    except P2MRConformanceError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
