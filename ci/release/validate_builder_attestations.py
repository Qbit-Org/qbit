#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate qbit Guix builder attestation quorum for release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from validate_key_metadata import MetadataError, validate_operator_policy


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OPERATOR_KEYS_DIR = REPO_ROOT / "contrib" / "keys" / "operator-keys"
DEFAULT_OPERATOR_POLICY = DEFAULT_OPERATOR_KEYS_DIR / "keys.json"
CHECKSUMS_FILE = "SHA256SUMS"
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
APPROVAL_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")
SHA256SUMS_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64}) [ *](.+)$")
ALLOWED_ARTIFACT_SETS = {"core", "photon"}


class BuilderValidationError(Exception):
    """Raised when builder attestation validation fails."""


@dataclass(frozen=True)
class BuilderOperator:
    alias: str
    fingerprint: str
    public_key_file: str
    artifact_sets: frozenset[str]


@dataclass(frozen=True)
class BuilderPolicy:
    policy_id: str
    policy_sequence: int
    release_line: str
    builder_attestation_quorum: int
    active_signer_set_size: int
    signer_public_key_files: frozenset[str]
    active_builders: dict[str, BuilderOperator]


def normalize_fingerprint(value: str) -> str:
    fingerprint = re.sub(r"\s+", "", value).upper()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise BuilderValidationError(f"Invalid OpenPGP fingerprint in operator policy: {value!r}")
    return fingerprint


def signer_artifact_sets(raw_signer: dict[str, Any], *, alias: str) -> frozenset[str]:
    normalized = frozenset(str(artifact_set) for artifact_set in raw_signer["artifact_sets"])
    unsupported = sorted(normalized - ALLOWED_ARTIFACT_SETS)
    if unsupported:
        raise BuilderValidationError(
            f"Active builder signer {alias} has unsupported artifact_sets: "
            + ", ".join(unsupported)
        )
    return normalized


def positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise BuilderValidationError(f"{field} must be a positive integer")
    return value


def load_policy_projection(
    policy_path: Path,
    keys_dir: Path,
    *,
    require_files: bool,
) -> dict[str, Any]:
    try:
        return validate_operator_policy(
            policy_path,
            keys_dir,
            require_files,
            validate_transition=False,
        )
    except MetadataError as exc:
        raise BuilderValidationError(str(exc)) from exc


def load_builder_policy(policy_path: Path, keys_dir: Path, release_line: str) -> BuilderPolicy:
    projection = load_policy_projection(policy_path, keys_dir, require_files=True)
    release_lines = projection["release_lines"]
    line_policy = release_lines.get(release_line)
    if not isinstance(line_policy, dict):
        raise BuilderValidationError(
            f"Operator policy {policy_path} has no release line {release_line!r}"
        )
    active_signer_set_size = positive_integer(
        line_policy.get("active_signer_set_size"),
        f"{policy_path}.{release_line}.active_signer_set_size",
    )
    quorum = positive_integer(
        line_policy.get("builder_attestation_quorum"),
        f"{policy_path}.{release_line}.builder_attestation_quorum",
    )

    builders: dict[str, BuilderOperator] = {}
    builder_fingerprints: set[str] = set()
    signer_public_key_files: set[str] = set()
    for signer in projection["signers"]:
        signer_public_key_files.add(str(signer["public_key_file"]))
        if signer["status"] != "active":
            continue
        if release_line not in signer["release_lines"]:
            continue
        if "builder-attestation" not in signer["capabilities"]:
            continue
        alias = str(signer["alias"])
        fingerprint = normalize_fingerprint(str(signer["signing_fingerprint"]))
        if fingerprint in builder_fingerprints:
            raise BuilderValidationError(
                f"Duplicate active builder signer fingerprint: {fingerprint}"
            )
        builders[alias] = BuilderOperator(
            alias=alias,
            fingerprint=fingerprint,
            public_key_file=str(signer["public_key_file"]),
            artifact_sets=signer_artifact_sets(signer, alias=alias),
        )
        builder_fingerprints.add(fingerprint)

    if not builders:
        raise BuilderValidationError(
            f"{release_line} has no active builder-attestation signers"
        )

    return BuilderPolicy(
        policy_id=str(projection["policy_id"]),
        policy_sequence=int(projection["policy_sequence"]),
        release_line=release_line,
        builder_attestation_quorum=quorum,
        active_signer_set_size=active_signer_set_size,
        signer_public_key_files=frozenset(signer_public_key_files),
        active_builders=dict(sorted(builders.items())),
    )


def sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError as exc:
        raise BuilderValidationError(f"Required operator key file not found: {path}") from exc


def path_traverses_symlink(root: Path, relative: Path) -> bool:
    """Return True if any component of ``relative`` under ``root`` is a symlink.

    ``Path.is_file()`` and ``read_bytes()`` both follow symlinks, so a symlinked
    mirror entry (leaf file or an intermediate directory) could point at the
    trusted canonical ``keys.json``/``public-keys`` files and pass the
    byte/hash comparison even though the mirror repo never contains those bytes.
    Detect symlinks anywhere along the path so they are excluded before hashing.
    """
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def reject_symlinked_input(path: Path, *, label: str) -> None:
    if path.is_symlink():
        raise BuilderValidationError(f"{label} must not be a symlink: {path}")


def relative_files(root: Path) -> set[str]:
    try:
        entries = list(root.rglob("*"))
    except FileNotFoundError as exc:
        raise BuilderValidationError(f"Operator keys directory not found: {root}") from exc
    files: set[str] = set()
    for entry in entries:
        relative = entry.relative_to(root)
        # Reject any path that traverses a symlink before hashing: a symlinked
        # mirror entry must surface as missing/extra rather than being resolved
        # to the canonical bytes it points at.
        if path_traverses_symlink(root, relative):
            continue
        if not entry.is_file():
            continue
        files.add(str(relative))
    return files


def approval_files_for_policy(keys_dir: Path, policy: BuilderPolicy) -> set[str]:
    if policy.policy_sequence == 1:
        return set()
    approval_dir = keys_dir / "approvals" / policy.policy_id
    if not approval_dir.is_dir():
        raise BuilderValidationError(f"missing policy approval directory: {approval_dir}")
    required = {
        f"approvals/{policy.policy_id}/policy.SHA256",
        f"approvals/{policy.policy_id}/approval-note.md",
    }
    for relative in required:
        if not (keys_dir / relative).is_file():
            raise BuilderValidationError(f"missing policy approval file: {keys_dir / relative}")
    signatures: set[str] = set()
    for signature in sorted(approval_dir.glob("*.asc")):
        alias = signature.stem
        if not APPROVAL_ALIAS_RE.fullmatch(alias):
            raise BuilderValidationError(f"{signature}: invalid approval signature filename")
        signatures.add(str(signature.relative_to(keys_dir)))
    if not signatures:
        raise BuilderValidationError(f"{approval_dir}: missing detached approval signatures")
    return required | signatures


def expected_operator_key_files(keys_dir: Path, policy: BuilderPolicy) -> set[str]:
    return {
        "keys.json",
        *sorted(policy.signer_public_key_files),
        *sorted(approval_files_for_policy(keys_dir, policy)),
    }


def compare_required_file_hashes(
    canonical_keys_dir: Path,
    mirror_keys_dir: Path,
    required_files: set[str],
) -> None:
    mismatches: list[str] = []
    for relative in sorted(required_files):
        canonical_file = canonical_keys_dir / relative
        mirror_file = mirror_keys_dir / relative
        canonical_hash = sha256_file(canonical_file)
        mirror_hash = sha256_file(mirror_file)
        if canonical_hash != mirror_hash:
            mismatches.append(relative)
    if mismatches:
        raise BuilderValidationError(
            "operator key mirror file hash mismatch: " + ", ".join(mismatches)
        )


def active_builder_projection(policy: BuilderPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "active_signer_set_size": policy.active_signer_set_size,
        "builder_attestation_quorum": policy.builder_attestation_quorum,
        "active_builders": {
            alias: {
                "fingerprint": builder.fingerprint,
                "public_key_file": builder.public_key_file,
                "artifact_sets": ",".join(sorted(builder.artifact_sets)),
            }
            for alias, builder in sorted(policy.active_builders.items())
        },
    }


def validate_builder_mirror(
    canonical: BuilderPolicy,
    canonical_keys_dir: Path,
    mirror_path: Path | None,
    mirror_keys_dir: Path | None,
    release_line: str,
) -> None:
    if mirror_path is None:
        return
    resolved_mirror_keys_dir = mirror_keys_dir or mirror_path.parent
    mirror = load_builder_policy(mirror_path, resolved_mirror_keys_dir, release_line)
    if active_builder_projection(canonical) != active_builder_projection(mirror):
        raise BuilderValidationError(
            "builder operator metadata mirror does not match canonical operator metadata"
        )
    required_files = expected_operator_key_files(canonical_keys_dir, canonical)
    mirror_files = relative_files(resolved_mirror_keys_dir)
    extra_files = sorted(mirror_files - required_files)
    missing_files = sorted(required_files - mirror_files)
    if extra_files or missing_files:
        message = "operator key mirror file set does not match canonical metadata"
        if missing_files:
            message += "; missing=" + ", ".join(missing_files)
        if extra_files:
            message += "; extra=" + ", ".join(extra_files)
        raise BuilderValidationError(message)
    compare_required_file_hashes(canonical_keys_dir, resolved_mirror_keys_dir, required_files)


def parse_sha256sums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf8").splitlines()
    except FileNotFoundError as exc:
        raise BuilderValidationError(f"SHA256SUMS not found: {path}") from exc
    entries: dict[str, str] = {}
    for line_no, line in enumerate(lines, start=1):
        match = SHA256SUMS_LINE_RE.fullmatch(line)
        if not match:
            raise BuilderValidationError(f"{path}:{line_no}: malformed checksum line")
        digest, name = match.groups()
        if "/" in name or "\\" in name:
            name = Path(name).name
        if name in entries:
            raise BuilderValidationError(f"{path}:{line_no}: duplicate entry {name}")
        entries[name] = digest.lower()
    return entries


def expected_release_entries(artifacts_dir: Path, tag: str, artifact: str) -> dict[str, str]:
    version = tag.removeprefix("v")
    all_entries = parse_sha256sums(artifacts_dir / CHECKSUMS_FILE)
    if artifact == "core":
        prefix = f"qbit-{version}-"
    elif artifact == "photon":
        prefix = f"qbit-photon-{version}-"
    else:
        raise BuilderValidationError(f"Unsupported artifact set: {artifact}")
    entries = {
        name: digest
        for name, digest in all_entries.items()
        if name.startswith(prefix)
    }
    if not entries:
        raise BuilderValidationError(f"No {artifact} release artifacts found in SHA256SUMS")
    return entries


def detected_artifacts(artifacts_dir: Path, tag: str) -> list[str]:
    version = tag.removeprefix("v")
    all_entries = parse_sha256sums(artifacts_dir / CHECKSUMS_FILE)
    artifacts: list[str] = []
    if any(name.startswith(f"qbit-{version}-") for name in all_entries):
        artifacts.append("core")
    if any(name.startswith(f"qbit-photon-{version}-") for name in all_entries):
        artifacts.append("photon")
    if not artifacts:
        raise BuilderValidationError("No supported release artifacts found in SHA256SUMS")
    return artifacts


def manifest_names(artifact: str) -> tuple[str, str]:
    prefix = "" if artifact == "core" else f"{artifact}-"
    return (f"{prefix}all.SHA256SUMS", f"{prefix}noncodesigned.SHA256SUMS")


def import_operator_keys(
    gpg: str,
    gnupg_home: Path,
    keys_dir: Path,
    policy: BuilderPolicy,
) -> None:
    key_files = sorted({builder.public_key_file for builder in policy.active_builders.values()})
    for public_key_file in key_files:
        key_file = keys_dir / public_key_file
        if not key_file.is_file():
            raise BuilderValidationError(f"Missing signer public certificate: {key_file}")
        result = run_command([gpg, "--batch", "--homedir", str(gnupg_home), "--import", str(key_file)])
        if result.returncode != 0:
            raise BuilderValidationError(
                f"Failed to import signer public certificate {key_file}:\n{result.stderr}"
            )

    result = run_command(
        [gpg, "--batch", "--homedir", str(gnupg_home), "--with-colons", "--fingerprint", "--list-keys"]
    )
    if result.returncode != 0:
        raise BuilderValidationError(f"Failed to list imported builder keys:\n{result.stderr}")

    imported: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields and fields[0] == "fpr" and len(fields) > 9:
            imported.add(normalize_fingerprint(fields[9]))

    expected = {builder.fingerprint for builder in policy.active_builders.values()}
    missing = sorted(expected - imported)
    if missing:
        raise BuilderValidationError(
            "Active builder fingerprints are not present in imported key material: "
            + ", ".join(missing)
        )


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=cwd,
        env=env,
        text=True,
    )


def status_fingerprints(status_output: str) -> list[str]:
    fingerprints: list[str] = []
    for line in status_output.splitlines():
        if not line.startswith("[GNUPG:] VALIDSIG "):
            continue
        fields = line.split()
        if len(fields) >= 3:
            fingerprints.append(normalize_fingerprint(fields[2]))
    return fingerprints


def verify_manifest_signature(
    gpg: str,
    gnupg_home: Path,
    manifest: Path,
    expected_fingerprint: str,
) -> None:
    signature = Path(f"{manifest}.asc")
    if not signature.is_file():
        raise BuilderValidationError(f"Missing builder attestation signature: {signature}")
    result = run_command(
        [
            gpg,
            "--batch",
            "--no-tty",
            "--homedir",
            str(gnupg_home),
            "--trust-model",
            "always",
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(manifest),
        ]
    )
    if result.returncode != 0:
        raise BuilderValidationError(f"Builder attestation signature failed: {signature}\n{result.stderr}")
    valid_fingerprints = set(status_fingerprints(result.stdout))
    unexpected = sorted(valid_fingerprints - {expected_fingerprint})
    if unexpected:
        raise BuilderValidationError(
            f"Builder attestation {signature} was signed by unexpected fingerprint(s): "
            + ", ".join(unexpected)
        )
    if expected_fingerprint not in valid_fingerprints:
        raise BuilderValidationError(
            f"Builder attestation {signature} was not signed by expected fingerprint {expected_fingerprint}"
        )


def find_builder_manifest(builder_dir: Path, artifact: str) -> Path | None:
    for name in manifest_names(artifact):
        candidate = builder_dir / name
        if candidate.is_file():
            return candidate
    return None


def manifest_covers_release_entries(manifest: Path, expected_entries: dict[str, str]) -> bool:
    manifest_entries = parse_sha256sums(manifest)
    for name, digest in expected_entries.items():
        if manifest_entries.get(name) != digest:
            return False
    return True


def one_line_error(error: Exception) -> str:
    return " ".join(str(error).split())


def validate_artifact_attestations(
    *,
    gpg: str,
    gnupg_home: Path,
    guix_sigs_repo: Path,
    version: str,
    artifact: str,
    release_entries: dict[str, str],
    builders: dict[str, BuilderOperator],
    quorum: int,
) -> list[str]:
    counted: list[str] = []
    rejected: list[str] = []
    version_dir = guix_sigs_repo / version
    if not version_dir.is_dir():
        raise BuilderValidationError(f"Guix signatures version directory not found: {version_dir}")

    for alias, builder in sorted(builders.items()):
        if artifact not in builder.artifact_sets:
            continue
        builder_dir = version_dir / alias
        if not builder_dir.is_dir():
            continue
        manifest = find_builder_manifest(builder_dir, artifact)
        if manifest is None:
            continue
        try:
            verify_manifest_signature(gpg, gnupg_home, manifest, builder.fingerprint)
            if not manifest_covers_release_entries(manifest, release_entries):
                rejected.append(f"{alias}: manifest does not cover staged {artifact} artifacts")
                continue
            counted.append(alias)
        except BuilderValidationError as exc:
            rejected.append(f"{alias}: {one_line_error(exc)}")
            continue

    if len(counted) < quorum:
        message = (
            f"{artifact} builder attestation quorum not met: "
            f"got {len(counted)}, need {quorum}; counted={', '.join(counted) or 'none'}"
        )
        if rejected:
            message += f"; rejected={'; '.join(rejected)}"
        raise BuilderValidationError(message)
    return counted


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-line", required=True, choices=("testnet", "mainnet"))
    parser.add_argument("--guix-sigs-repo", required=True, type=Path)
    parser.add_argument("--operator-key-policy", default=DEFAULT_OPERATOR_POLICY, type=Path)
    parser.add_argument("--operator-keys-dir", default=DEFAULT_OPERATOR_KEYS_DIR, type=Path)
    parser.add_argument("--guix-operator-key-policy", type=Path)
    parser.add_argument("--guix-operator-keys-dir", type=Path)
    parser.add_argument("--gpg", default=shutil.which("gpg") or "gpg")
    parser.add_argument("--artifact", choices=("core", "photon"), action="append")
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        reject_symlinked_input(args.operator_key_policy, label="--operator-key-policy")
        reject_symlinked_input(args.operator_keys_dir, label="--operator-keys-dir")
        guix_operator_keys_dir_arg = args.guix_operator_keys_dir
        if args.guix_operator_key_policy:
            if guix_operator_keys_dir_arg is None:
                guix_operator_keys_dir_arg = args.guix_operator_key_policy.parent
            reject_symlinked_input(args.guix_operator_key_policy, label="--guix-operator-key-policy")
            reject_symlinked_input(guix_operator_keys_dir_arg, label="--guix-operator-keys-dir")
        artifacts_dir = args.artifacts_dir.resolve()
        guix_sigs_repo = args.guix_sigs_repo.resolve()
        operator_keys_dir = args.operator_keys_dir.resolve()
        policy = load_builder_policy(
            args.operator_key_policy.resolve(),
            operator_keys_dir,
            args.release_line,
        )
        builders = policy.active_builders
        validate_builder_mirror(
            policy,
            operator_keys_dir,
            args.guix_operator_key_policy.resolve() if args.guix_operator_key_policy else None,
            guix_operator_keys_dir_arg.resolve() if guix_operator_keys_dir_arg else None,
            args.release_line,
        )
        quorum = policy.builder_attestation_quorum
        version = args.tag.removeprefix("v")
        artifacts = args.artifact or detected_artifacts(artifacts_dir, args.tag)

        with tempfile.TemporaryDirectory(prefix="qbit-operator-gnupg-") as gnupg_home:
            gnupg_home_path = Path(gnupg_home)
            os.chmod(gnupg_home_path, 0o700)
            import_operator_keys(args.gpg, gnupg_home_path, operator_keys_dir, policy)
            counts: dict[str, list[str]] = {}
            for artifact in artifacts:
                counted = validate_artifact_attestations(
                    gpg=args.gpg,
                    gnupg_home=gnupg_home_path,
                    guix_sigs_repo=guix_sigs_repo,
                    version=version,
                    artifact=artifact,
                    release_entries=expected_release_entries(artifacts_dir, args.tag, artifact),
                    builders=builders,
                    quorum=quorum,
                )
                counts[artifact] = counted

        if args.github_output:
            with args.github_output.open("a", encoding="utf8") as output:
                output.write(f"builder_attestation_quorum={quorum}\n")
                for artifact, counted in sorted(counts.items()):
                    output.write(f"builder_attestation_{artifact}_count={len(counted)}\n")
                    output.write(f"builder_attestation_{artifact}_aliases={','.join(counted)}\n")

        summary = ", ".join(f"{artifact}:{len(counted)}/{quorum}" for artifact, counted in sorted(counts.items()))
        print(f"Validated builder attestations: {summary}")
        return 0
    except BuilderValidationError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
