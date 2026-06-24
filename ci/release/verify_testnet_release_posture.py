#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate testnet-only release posture evidence before publication."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKSUMS_FILE = "SHA256SUMS"
SHA256_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
SHA256SUMS_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64}) ([ *])(.+)$")
QBITD_ARTIFACT_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".tar.xz",
    ".txz",
    ".tar.bz2",
    ".tbz2",
    ".zip",
)
CORE_INSTALLER_SUFFIXES = (".dmg", ".exe")
UNSIGNED_PLATFORM_ARTIFACT_RE = re.compile(r"(^|-)unsigned(?=[.-])")
CODESIGNING_ARTIFACT_RE = re.compile(r"(^|-)codesigning(?=[.-])")
DEBUG_ARTIFACT_RE = re.compile(r"(^|-)debug(?=[.-])")

REQUIRED_EVIDENCE = {
    "testnet_only_mainnet_guard": "enabled",
    "no_flag_startup": "mainnet_rejected",
    "chain_main_startup": "mainnet_rejected",
    "testnet4_startup": "testnet4_selected",
    "mainnet_dns_seeds": "none",
    "mainnet_fixed_seeds": "none",
    "mainnet_archive_endpoints": "none",
}

OPTIONAL_EVIDENCE_KEYS = {
    "checked_at_utc",
    "qbitd_artifact",
    "qbitd_artifact_sha256",
    "qbitd_artifacts",
    "operator",
    "qbitd_path",
    "qbitd_sha256",
    "qbitd_version",
    "release_tag",
    "smoke_datadir",
    "source_commit",
    "testnet4_chain",
}

STAGED_QBITD_EVIDENCE = {
    "qbitd_artifacts",
}

STAGED_QBITD_LOCAL_LINKAGE_EVIDENCE = {
    "qbitd_artifact",
    "qbitd_artifact_sha256",
    "qbitd_sha256",
}


class TestnetPostureError(Exception):
    """Raised when release posture validation fails."""


def parse_evidence(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf8").splitlines()
    except FileNotFoundError as exc:
        raise TestnetPostureError(f"Missing testnet release posture evidence file: {path}") from exc

    values: dict[str, str] = {}
    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise TestnetPostureError(f"{path}:{line_no}: expected key=value")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key:
            raise TestnetPostureError(f"{path}:{line_no}: empty evidence key")
        if key in values:
            raise TestnetPostureError(f"{path}:{line_no}: duplicate evidence key {key!r}")
        values[key] = value

    allowed = set(REQUIRED_EVIDENCE) | OPTIONAL_EVIDENCE_KEYS
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise TestnetPostureError(
            "Unknown testnet release posture evidence key(s): " + ", ".join(unknown)
        )

    return values


def validate_evidence(values: dict[str, str]) -> None:
    missing = sorted(set(REQUIRED_EVIDENCE) - set(values))
    if missing:
        raise TestnetPostureError(
            "Missing required testnet release posture evidence key(s): " + ", ".join(missing)
        )

    mismatches = []
    for key, expected in REQUIRED_EVIDENCE.items():
        actual = values[key]
        if actual != expected:
            mismatches.append(f"{key}={actual!r}, expected {expected!r}")
    if mismatches:
        raise TestnetPostureError(
            "Testnet release posture evidence did not match required values: "
            + "; ".join(mismatches)
        )


def git_stdout(source_root: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise TestnetPostureError("git is required for tagged source posture checks") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        message = f"git {' '.join(args)} failed"
        if detail:
            message += f": {detail}"
        raise TestnetPostureError(message) from exc
    return result.stdout


def resolve_release_commit(source_root: Path, release_tag: str) -> str:
    if release_tag.startswith("-"):
        raise TestnetPostureError(f"Invalid release tag: {release_tag!r}")
    return git_stdout(
        source_root,
        ["rev-parse", "--verify", f"{release_tag}^{{commit}}"],
    ).strip()


def validate_release_metadata(
    values: dict[str, str], *, release_tag: str | None, source_commit: str | None
) -> None:
    if release_tag is None:
        return

    required = {"release_tag", "source_commit"}
    missing = sorted(required - set(values))
    if missing:
        raise TestnetPostureError(
            "Missing required testnet release posture evidence metadata key(s): "
            + ", ".join(missing)
        )

    if values["release_tag"] != release_tag:
        raise TestnetPostureError(
            f"Testnet release posture evidence release_tag={values['release_tag']!r}, "
            f"expected {release_tag!r}"
        )
    if values["source_commit"] != source_commit:
        raise TestnetPostureError(
            f"Testnet release posture evidence source_commit={values['source_commit']!r}, "
            f"expected public tag target {source_commit!r}"
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(file) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: file.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def require_sha256_value(values: dict[str, str], key: str) -> str:
    digest = values[key].lower()
    if not SHA256_RE.fullmatch(digest):
        raise TestnetPostureError(f"{key} must be a 64-character SHA256 digest")
    return digest


def parse_sha256sums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf8").splitlines()
    except FileNotFoundError as exc:
        raise TestnetPostureError(f"Missing staged release manifest: {path}") from exc

    entries: dict[str, str] = {}
    for line_no, line in enumerate(lines, start=1):
        match = SHA256SUMS_LINE_RE.fullmatch(line)
        if not match:
            raise TestnetPostureError(f"{CHECKSUMS_FILE}:{line_no}: malformed checksum line")
        digest, _mode, name = match.groups()
        if "/" in name or "\\" in name:
            raise TestnetPostureError(
                f"{CHECKSUMS_FILE}:{line_no}: artifact path must be a basename"
            )
        if name in entries:
            raise TestnetPostureError(f"{CHECKSUMS_FILE}:{line_no}: duplicate artifact {name!r}")
        entries[name] = digest.lower()
    return entries


def archive_member_parts(name: str) -> list[str]:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        raise TestnetPostureError(f"qbitd_artifact contains unsafe archive member path: {name}")
    parts = [part for part in normalized.split("/") if part and part != "."]
    if any(part == ".." for part in parts):
        raise TestnetPostureError(f"qbitd_artifact contains unsafe archive member path: {name}")
    return parts


def qbitd_member_name(name: str) -> bool:
    parts = archive_member_parts(name)
    return len(parts) >= 2 and parts[-2] == "bin" and parts[-1] in {"qbitd", "qbitd.exe"}


def tar_qbitd_digests(path: Path) -> list[str]:
    digests: list[str] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile() or not qbitd_member_name(member.name):
                    continue
                fileobj = archive.extractfile(member)
                if fileobj is None:
                    continue
                with fileobj:
                    digests.append(sha256_stream(fileobj))
    except (tarfile.TarError, OSError) as exc:
        raise TestnetPostureError(f"Failed to inspect staged qbitd artifact {path}: {exc}") from exc
    return digests


def zip_qbitd_digests(path: Path) -> list[str]:
    digests: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not qbitd_member_name(info.filename):
                    continue
                with archive.open(info) as file:
                    digests.append(sha256_stream(file))
    except (zipfile.BadZipFile, OSError) as exc:
        raise TestnetPostureError(f"Failed to inspect staged qbitd artifact {path}: {exc}") from exc
    return digests


def qbitd_digests_from_artifact(path: Path) -> list[str]:
    name = path.name
    if name.endswith((".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2")):
        return tar_qbitd_digests(path)
    if name.endswith(".zip"):
        return zip_qbitd_digests(path)
    raise TestnetPostureError(
        "qbitd_artifact must be a staged tar or zip archive containing bin/qbitd"
    )


def single_qbitd_digest_from_artifact(path: Path, artifact_name: str) -> str:
    member_digests = qbitd_digests_from_artifact(path)
    if not member_digests:
        raise TestnetPostureError(f"qbitd_artifact contains no bin/qbitd entry: {artifact_name}")
    if len(member_digests) > 1:
        raise TestnetPostureError(
            f"qbitd_artifact contains multiple bin/qbitd entries: {artifact_name}"
        )
    return member_digests[0]


def is_core_artifact(name: str, release_tag: str | None) -> bool:
    if release_tag:
        if not release_tag.startswith("v") or len(release_tag) == 1:
            raise TestnetPostureError(f"Release tag must start with v: {release_tag!r}")
        return name.startswith(f"qbit-{release_tag[1:]}-")
    return name.startswith("qbit-") and not name.startswith("qbit-photon-")


def is_inspectable_qbitd_artifact(name: str) -> bool:
    return name.endswith(QBITD_ARTIFACT_SUFFIXES)


def has_inspectable_qbitd_member(artifacts_dir: Path, artifact_name: str) -> bool:
    artifact_path = artifacts_dir / artifact_name
    if not artifact_path.is_file():
        raise TestnetPostureError(f"Missing staged qbitd artifact: {artifact_path}")
    return bool(qbitd_digests_from_artifact(artifact_path))


def parse_qbitd_artifacts(value: str) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for raw_entry in re.split(r"[\s,]+", value.strip()):
        if not raw_entry:
            continue
        try:
            name, digest = raw_entry.rsplit(":", 1)
        except ValueError as exc:
            raise TestnetPostureError(
                "qbitd_artifacts entries must use artifact-name:bin-qbitd-sha256"
            ) from exc
        if Path(name).name != name or name in {"", ".", ".."}:
            raise TestnetPostureError("qbitd_artifacts entries must use artifact basenames")
        if name in artifacts:
            raise TestnetPostureError(f"Duplicate qbitd_artifacts entry: {name}")
        artifacts[name] = digest.lower()
        if not SHA256_RE.fullmatch(artifacts[name]):
            raise TestnetPostureError(f"qbitd_artifacts entry for {name} has invalid SHA256")
    if not artifacts:
        raise TestnetPostureError("qbitd_artifacts must list at least one core artifact")
    return artifacts


def validate_core_qbitd_artifact_set(
    *,
    artifacts_dir: Path,
    manifest_entries: dict[str, str],
    release_tag: str | None,
    qbitd_artifacts: dict[str, str],
    allow_unsigned_platform_artifacts: bool,
    allow_codesigning_artifacts: bool,
) -> None:
    core_artifacts = set()
    for name in manifest_entries:
        if not is_core_artifact(name, release_tag) or DEBUG_ARTIFACT_RE.search(name):
            continue
        if allow_codesigning_artifacts and CODESIGNING_ARTIFACT_RE.search(name):
            if not is_inspectable_qbitd_artifact(name):
                continue
            if not has_inspectable_qbitd_member(artifacts_dir, name):
                continue
        if allow_unsigned_platform_artifacts and UNSIGNED_PLATFORM_ARTIFACT_RE.search(name):
            if not is_inspectable_qbitd_artifact(name):
                continue
            if not has_inspectable_qbitd_member(artifacts_dir, name):
                continue
        core_artifacts.add(name)

    inspectable_core_artifacts = {
        name for name in core_artifacts if is_inspectable_qbitd_artifact(name)
    }
    unsupported = sorted(
        name
        for name in core_artifacts
        if not name.endswith(QBITD_ARTIFACT_SUFFIXES + CORE_INSTALLER_SUFFIXES)
    )
    if unsupported:
        raise TestnetPostureError(
            "Cannot validate qbitd posture for unsupported staged core artifact(s): "
            + ", ".join(unsupported)
        )

    expected = set(inspectable_core_artifacts)
    if not expected:
        raise TestnetPostureError("Staging manifest has no core qbitd artifacts")

    missing = sorted(expected - set(qbitd_artifacts))
    if missing:
        raise TestnetPostureError(
            "qbitd_artifacts is missing staged core qbitd artifact(s): "
            + ", ".join(missing)
        )

    extra = sorted(set(qbitd_artifacts) - expected)
    if extra:
        raise TestnetPostureError(
            "qbitd_artifacts lists non-staged or non-core qbitd artifact(s): "
            + ", ".join(extra)
        )

    for artifact_name in sorted(expected):
        artifact_path = artifacts_dir / artifact_name
        if not artifact_path.is_file():
            raise TestnetPostureError(f"Missing staged qbitd artifact: {artifact_path}")
        actual_artifact_sha256 = sha256_file(artifact_path)
        if actual_artifact_sha256 != manifest_entries[artifact_name]:
            raise TestnetPostureError(
                f"SHA256 mismatch for {artifact_name}: expected "
                f"{manifest_entries[artifact_name]}, got {actual_artifact_sha256}"
            )

        member_digest = single_qbitd_digest_from_artifact(artifact_path, artifact_name)
        if qbitd_artifacts[artifact_name] != member_digest:
            raise TestnetPostureError(
                f"qbitd_artifacts digest for {artifact_name} does not match any "
                "bin/qbitd entry in that artifact"
            )


def validate_staged_qbitd_metadata(
    values: dict[str, str],
    artifacts_dir: Path | None,
    release_tag: str | None,
    allow_unsigned_platform_artifacts: bool,
    allow_codesigning_artifacts: bool,
) -> None:
    if artifacts_dir is None:
        return

    missing = sorted(STAGED_QBITD_EVIDENCE - set(values))
    if missing:
        raise TestnetPostureError(
            "Missing required staged qbitd evidence key(s): " + ", ".join(missing)
        )

    artifacts_dir = artifacts_dir.resolve()
    if not artifacts_dir.is_dir():
        raise TestnetPostureError(f"Artifacts directory does not exist: {artifacts_dir}")

    manifest_entries = parse_sha256sums(artifacts_dir / CHECKSUMS_FILE)
    qbitd_artifacts = parse_qbitd_artifacts(values["qbitd_artifacts"])
    validate_core_qbitd_artifact_set(
        artifacts_dir=artifacts_dir,
        manifest_entries=manifest_entries,
        release_tag=release_tag,
        qbitd_artifacts=qbitd_artifacts,
        allow_unsigned_platform_artifacts=allow_unsigned_platform_artifacts,
        allow_codesigning_artifacts=allow_codesigning_artifacts,
    )

    local_linkage_keys = STAGED_QBITD_LOCAL_LINKAGE_EVIDENCE & set(values)
    if not local_linkage_keys:
        return

    missing_local = sorted(STAGED_QBITD_LOCAL_LINKAGE_EVIDENCE - set(values))
    if missing_local:
        raise TestnetPostureError(
            "Missing local staged qbitd evidence key(s): " + ", ".join(missing_local)
        )

    qbitd_sha256 = require_sha256_value(values, "qbitd_sha256")

    if "qbitd_path" in values:
        qbitd_path = Path(values["qbitd_path"])
        if not qbitd_path.is_absolute():
            raise TestnetPostureError("qbitd_path must be an absolute path to the smoked binary")
        if qbitd_path.exists():
            qbitd_path = qbitd_path.resolve(strict=True)
            if not qbitd_path.is_file():
                raise TestnetPostureError(f"qbitd_path is not a regular file: {qbitd_path}")
            actual_qbitd_sha256 = sha256_file(qbitd_path)
            if actual_qbitd_sha256 != qbitd_sha256:
                raise TestnetPostureError(
                    f"qbitd_sha256={qbitd_sha256!r}, actual smoked binary SHA256 "
                    f"is {actual_qbitd_sha256!r}"
                )

    artifact_name = values["qbitd_artifact"]
    if Path(artifact_name).name != artifact_name or artifact_name in {"", ".", ".."}:
        raise TestnetPostureError("qbitd_artifact must be a basename from the staging directory")

    manifest_sha256 = manifest_entries.get(artifact_name)
    if manifest_sha256 is None:
        raise TestnetPostureError(f"qbitd_artifact is not listed in {CHECKSUMS_FILE}: {artifact_name}")

    artifact_sha256 = require_sha256_value(values, "qbitd_artifact_sha256")
    if manifest_sha256 != artifact_sha256:
        raise TestnetPostureError(
            f"qbitd_artifact_sha256={artifact_sha256!r}, {CHECKSUMS_FILE} lists "
            f"{manifest_sha256!r} for {artifact_name}"
        )

    artifact_path = artifacts_dir / artifact_name
    if not artifact_path.is_file():
        raise TestnetPostureError(f"Missing staged qbitd artifact: {artifact_path}")
    actual_artifact_sha256 = sha256_file(artifact_path)
    if actual_artifact_sha256 != artifact_sha256:
        raise TestnetPostureError(
            f"qbitd_artifact_sha256={artifact_sha256!r}, actual staged artifact "
            f"SHA256 is {actual_artifact_sha256!r}"
        )

    member_digest = single_qbitd_digest_from_artifact(artifact_path, artifact_name)
    if qbitd_sha256 != member_digest:
        raise TestnetPostureError(
            "qbitd_sha256 does not match any bin/qbitd entry in qbitd_artifact"
        )
    if qbitd_artifacts.get(artifact_name) != qbitd_sha256:
        raise TestnetPostureError(
            "qbitd_artifact/qbitd_sha256 must match the corresponding qbitd_artifacts entry"
        )


def read_source_file(source_root: Path, relative_path: str) -> str:
    path = source_root / relative_path
    try:
        return path.read_text(encoding="utf8")
    except FileNotFoundError as exc:
        raise TestnetPostureError(f"Missing source file for posture check: {path}") from exc


def read_tagged_source_file(source_root: Path, source_commit: str, relative_path: str) -> str:
    return git_stdout(source_root, ["show", f"{source_commit}:{relative_path}"])


def mainnet_chainparams_body(chainparams_cpp: str) -> str:
    start = chainparams_cpp.find("class CMainParams")
    if start == -1:
        raise TestnetPostureError("Could not find CMainParams in src/kernel/chainparams.cpp")
    end = chainparams_cpp.find("class CTestNetParams", start)
    if end == -1:
        raise TestnetPostureError(
            "Could not find CTestNetParams after CMainParams in src/kernel/chainparams.cpp"
        )
    return chainparams_cpp[start:end]


def strip_cpp_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    state = "code"
    while i < len(text):
        char = text[i]
        next_char = text[i + 1] if i + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                state = "line_comment"
                i += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
                i += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            result.append(char)
            i += 1
            continue

        if state == "line_comment":
            if char == "\n":
                result.append(char)
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if char == "\n":
                result.append(char)
            if char == "*" and next_char == "/":
                state = "code"
                i += 2
                continue
            i += 1
            continue

        result.append(char)
        if char == "\\":
            if next_char:
                result.append(next_char)
                i += 2
            else:
                i += 1
            continue
        if state == "string" and char == '"':
            state = "code"
        elif state == "char" and char == "'":
            state = "code"
        i += 1

    return "".join(result)


def release_sources(source_root: Path, release_tag: str | None) -> tuple[str, str, str | None]:
    if release_tag is None:
        return (
            read_source_file(source_root, "src/kernel/chainparams.cpp"),
            read_source_file(source_root, "src/chainparamsseeds.h"),
            None,
        )

    source_commit = resolve_release_commit(source_root, release_tag)
    return (
        read_tagged_source_file(source_root, source_commit, "src/kernel/chainparams.cpp"),
        read_tagged_source_file(source_root, source_commit, "src/chainparamsseeds.h"),
        source_commit,
    )


def validate_mainnet_seed_sources(source_root: Path, release_tag: str | None) -> str | None:
    chainparams_cpp, chainparamsseeds_h, source_commit = release_sources(source_root, release_tag)
    chainparams_code = strip_cpp_comments(chainparams_cpp)
    mainnet_code = mainnet_chainparams_body(chainparams_code)
    chainparamsseeds_code = strip_cpp_comments(chainparamsseeds_h)

    if not re.search(r"\bvSeeds\s*\.\s*clear\s*\(\s*\)\s*;", mainnet_code):
        raise TestnetPostureError("CMainParams must explicitly clear mainnet DNS seeds")
    if not re.search(r"\bvFixedSeeds\s*\.\s*clear\s*\(\s*\)\s*;", mainnet_code):
        raise TestnetPostureError("CMainParams must explicitly clear mainnet fixed seeds")

    forbidden_seed_patterns = {
        r"\bvSeeds\s*\.\s*emplace_back\b": "mainnet DNS seed hostname",
        r"\bvSeeds\s*\.\s*push_back\b": "mainnet DNS seed hostname",
        r"\bchainparams_seed_main\s*\.\s*begin\s*\(": "mainnet fixed seed blob",
    }
    for pattern, description in forbidden_seed_patterns.items():
        if re.search(pattern, mainnet_code):
            raise TestnetPostureError(f"CMainParams publishes a {description}: {pattern}")

    if re.search(r"\bvSeeds\s*=", mainnet_code):
        raise TestnetPostureError("CMainParams assigns mainnet DNS seeds")
    if re.search(r"\bvFixedSeeds\s*=", mainnet_code):
        raise TestnetPostureError("CMainParams assigns mainnet fixed seeds")
    if ".qbit.org" in mainnet_code:
        raise TestnetPostureError("CMainParams contains qbit.org hostnames")
    if "connectarchive" in mainnet_code.lower():
        raise TestnetPostureError("CMainParams contains archive endpoint configuration")

    if not re.search(
        r"static\s+constexpr\s+std::array\s*<\s*uint8_t\s*,\s*0\s*>\s+chainparams_seed_main\b",
        chainparamsseeds_code,
    ):
        raise TestnetPostureError("chainparams_seed_main must remain a zero-length array")
    return source_commit


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--source-root", default=REPO_ROOT, type=Path)
    parser.add_argument(
        "--release-tag",
        help="release tag whose peeled public target commit must match evidence and source checks",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        help=(
            "flat staged release artifact directory whose SHA256SUMS and qbitd "
            "artifact must match evidence"
        ),
    )
    parser.add_argument(
        "--allow-unsigned-platform-artifacts",
        action="store_true",
        help="ignore waived unsigned platform artifacts in staged qbitd posture coverage",
    )
    parser.add_argument(
        "--allow-codesigning-artifacts",
        action="store_true",
        help="ignore waived codesigning artifacts in staged qbitd posture coverage",
    )
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        values = parse_evidence(args.evidence.resolve())
        validate_evidence(values)
        source_commit = validate_mainnet_seed_sources(
            args.source_root.resolve(), args.release_tag
        )
        validate_release_metadata(
            values, release_tag=args.release_tag, source_commit=source_commit
        )
        validate_staged_qbitd_metadata(
            values,
            artifacts_dir=args.artifacts_dir.resolve() if args.artifacts_dir else None,
            release_tag=args.release_tag,
            allow_unsigned_platform_artifacts=args.allow_unsigned_platform_artifacts,
            allow_codesigning_artifacts=args.allow_codesigning_artifacts,
        )
        if args.artifacts_dir:
            print(
                "Validated testnet release posture evidence, staged qbitd linkage, "
                "and empty mainnet seed sources"
            )
        else:
            print(
                "Validated testnet release posture evidence and empty mainnet seed sources"
            )
        return 0
    except TestnetPostureError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
