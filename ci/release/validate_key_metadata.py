#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate qbit release signer key metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OPERATOR_POLICY = REPO_ROOT / "contrib" / "keys" / "operator-keys" / "keys.json"
DEFAULT_OPERATOR_KEYS_DIR = REPO_ROOT / "contrib" / "keys" / "operator-keys"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POLICY_SHA256_RE = re.compile(r"^[0-9a-f]{64}  keys\.json\n$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
POLICY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")
SIGNER_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")
EFFECTIVE_TAG_RE = re.compile(r"^v[0-9][A-Za-z0-9._-]*$")

VALID_STATUSES = {"active", "rotated", "revoked", "lost"}
VALID_KEY_ORIGINS = {"qbit-generated", "external-gpg", "external-yubikey"}
VALID_RELEASE_LINES = {"testnet", "mainnet"}
VALID_CAPABILITIES = {"release-signing", "builder-attestation"}
VALID_ARTIFACT_SETS = {"core", "photon"}

TOP_LEVEL_KEYS = {
    "schema_version",
    "policy_id",
    "policy_sequence",
    "previous_policy_sha256",
    "effective_from_tag",
    "release_lines",
    "signers",
}
RELEASE_LINE_KEYS = {
    "active_signer_set_size",
    "release_signature_quorum",
    "builder_attestation_quorum",
    "policy_change_quorum",
}
SIGNER_REQUIRED_KEYS = {
    "alias",
    "status",
    "key_origin",
    "public_key_file",
    "signing_fingerprint",
    "release_lines",
    "capabilities",
    "artifact_sets",
}
SIGNER_OPTIONAL_KEYS = {
    "created",
    "first_release",
    "replacement_signing_fingerprint",
    "revocation_date",
    "notes",
}
SIGNER_KEYS = SIGNER_REQUIRED_KEYS | SIGNER_OPTIONAL_KEYS

PUBLIC_FORBIDDEN_TERM_RE = re.compile(
    r"(^|[^A-Za-z])(primary|root|certification|certify|certifies|certified)([^A-Za-z]|$)",
    re.IGNORECASE,
)

class MetadataError(Exception):
    """Raised when key metadata is invalid."""


def sha256_file(path: Path) -> str:
    """Return the exact-byte SHA256 for a checked-in policy file."""

    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError as exc:
        raise MetadataError(f"metadata file not found: {path}") from exc


def load_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise MetadataError(f"metadata file not found: {path}") from exc
    try:
        data = json.loads(raw.decode("utf8"))
    except UnicodeDecodeError as exc:
        raise MetadataError(f"metadata file is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MetadataError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MetadataError(f"metadata file must contain a JSON object: {path}")
    return data


def require_allowed_keys(entry: dict[str, Any], allowed: set[str], *, path: str) -> None:
    extra = sorted(set(entry) - allowed)
    if extra:
        raise MetadataError(f"{path}: unsupported field(s): {', '.join(extra)}")


def ensure_no_public_forbidden_terms(value: object, *, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}"
            if PUBLIC_FORBIDDEN_TERM_RE.search(str(key)):
                raise MetadataError(f"{key_path}: public release key metadata must not use primary/root/certification terms")
            ensure_no_public_forbidden_terms(item, path=key_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            ensure_no_public_forbidden_terms(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and not path.endswith(".public_key_file") and PUBLIC_FORBIDDEN_TERM_RE.search(value):
        raise MetadataError(f"{path}: public release key metadata must not use primary/root/certification terms")


def require_string(entry: dict[str, Any], key: str, *, path: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MetadataError(f"{path}.{key}: expected non-empty string")
    return value.strip()


def require_string_list(
    entry: dict[str, Any],
    key: str,
    *,
    path: str,
    allowed_values: set[str] | None = None,
    allow_empty: bool = False,
) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list):
        raise MetadataError(f"{path}.{key}: expected list")
    if not values and not allow_empty:
        raise MetadataError(f"{path}.{key}: expected non-empty list")

    normalized: list[str] = []
    seen: set[str] = set()
    for item_index, value in enumerate(values):
        item_path = f"{path}.{key}[{item_index}]"
        if not isinstance(value, str) or not value.strip():
            raise MetadataError(f"{item_path}: expected non-empty string")
        item = value.strip()
        if allowed_values is not None and item not in allowed_values:
            raise MetadataError(f"{item_path}: unsupported value {item!r}")
        if item in seen:
            raise MetadataError(f"{item_path}: duplicate value {item!r}")
        seen.add(item)
        normalized.append(item)
    return normalized


def require_positive_int(policy: dict[str, Any], key: str, *, path: str) -> int:
    value = policy.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise MetadataError(f"{path}.{key}: must be an integer")
    if value < 1:
        raise MetadataError(f"{path}.{key}: must be positive")
    return value


def normalize_fingerprint(raw: object, *, path: str) -> str:
    fingerprint = re.sub(r"\s+", "", str(raw)).upper()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise MetadataError(f"{path}: invalid fingerprint {raw!r}")
    return fingerprint


def validate_policy_identity(path: Path, data: dict[str, Any]) -> tuple[str, int, str | None, str]:
    if data.get("schema_version") != 2:
        raise MetadataError(f"{path}: schema_version must be 2")

    policy_id = require_string(data, "policy_id", path=str(path))
    if not POLICY_ID_RE.fullmatch(policy_id):
        raise MetadataError(f"{path}.policy_id: invalid policy id {policy_id!r}")

    policy_sequence = require_positive_int(data, "policy_sequence", path=str(path))
    previous_policy_sha256 = data.get("previous_policy_sha256")
    if policy_sequence == 1:
        if previous_policy_sha256 is not None:
            raise MetadataError(f"{path}.previous_policy_sha256: bootstrap policy must use null")
    else:
        if not isinstance(previous_policy_sha256, str) or not SHA256_RE.fullmatch(previous_policy_sha256):
            raise MetadataError(
                f"{path}.previous_policy_sha256: non-bootstrap policy requires a lowercase SHA256"
            )

    effective_from_tag = require_string(data, "effective_from_tag", path=str(path))
    if not EFFECTIVE_TAG_RE.fullmatch(effective_from_tag):
        raise MetadataError(f"{path}.effective_from_tag: invalid tag {effective_from_tag!r}")

    return policy_id, policy_sequence, previous_policy_sha256, effective_from_tag


def validate_release_lines(path: Path, data: dict[str, Any]) -> dict[str, dict[str, int]]:
    release_lines = data.get("release_lines")
    if not isinstance(release_lines, dict) or not release_lines:
        raise MetadataError(f"{path}: release_lines must be a non-empty object")

    normalized: dict[str, dict[str, int]] = {}
    for release_line, policy in release_lines.items():
        if release_line not in VALID_RELEASE_LINES:
            raise MetadataError(f"{path}: unsupported release line {release_line!r}")
        if not isinstance(policy, dict):
            raise MetadataError(f"{path}.{release_line}: policy must be an object")
        require_allowed_keys(policy, RELEASE_LINE_KEYS, path=f"{path}.{release_line}")

        active_signer_set_size = require_positive_int(
            policy,
            "active_signer_set_size",
            path=f"{path}.{release_line}",
        )
        release_quorum = require_positive_int(
            policy,
            "release_signature_quorum",
            path=f"{path}.{release_line}",
        )
        builder_quorum = require_positive_int(
            policy,
            "builder_attestation_quorum",
            path=f"{path}.{release_line}",
        )
        policy_change_quorum = require_positive_int(
            policy,
            "policy_change_quorum",
            path=f"{path}.{release_line}",
        )
        if release_quorum > active_signer_set_size:
            raise MetadataError(f"{path}.{release_line}: release quorum exceeds active signer set size")
        if builder_quorum > active_signer_set_size:
            raise MetadataError(f"{path}.{release_line}: builder quorum exceeds active signer set size")
        if policy_change_quorum > active_signer_set_size:
            raise MetadataError(f"{path}.{release_line}: policy change quorum exceeds active signer set size")
        normalized[release_line] = {
            "active_signer_set_size": active_signer_set_size,
            "release_signature_quorum": release_quorum,
            "builder_attestation_quorum": builder_quorum,
            "policy_change_quorum": policy_change_quorum,
        }
    return normalized


def validate_status(entry: dict[str, Any], *, path: str) -> str:
    status = require_string(entry, "status", path=path)
    if status not in VALID_STATUSES:
        raise MetadataError(f"{path}.status: expected one of {sorted(VALID_STATUSES)}, got {status!r}")
    return status


def validate_key_origin(entry: dict[str, Any], *, path: str) -> str:
    key_origin = require_string(entry, "key_origin", path=path)
    if key_origin not in VALID_KEY_ORIGINS:
        raise MetadataError(f"{path}.key_origin: expected one of {sorted(VALID_KEY_ORIGINS)}, got {key_origin!r}")
    return key_origin


def validate_public_key_file(entry: dict[str, Any], *, path: str) -> str:
    public_key_file = require_string(entry, "public_key_file", path=path)
    public_key_path = Path(public_key_file)
    if public_key_path.is_absolute() or ".." in public_key_path.parts:
        raise MetadataError(f"{path}.public_key_file: expected a relative file under public-keys/")
    if len(public_key_path.parts) != 2 or public_key_path.parts[0] != "public-keys":
        raise MetadataError(f"{path}.public_key_file: expected a file under public-keys/")
    if public_key_path.suffix != ".asc":
        raise MetadataError(f"{path}.public_key_file: expected an armored .asc file")
    if public_key_path.name.startswith("qbit-operator-primary-"):
        raise MetadataError(f"{path}.public_key_file: primary public certificate files are not allowed")
    if PUBLIC_FORBIDDEN_TERM_RE.search(public_key_path.name):
        raise MetadataError(
            f"{path}.public_key_file: primary/root/certification terms are not allowed in public key filenames"
        )
    return public_key_file


def reject_legacy_public_key_files(keys_dir: Path, *, path: Path) -> None:
    legacy_files = sorted(str(file.relative_to(keys_dir)) for file in keys_dir.rglob("qbit-operator-primary-*.asc"))
    if legacy_files:
        raise MetadataError(f"{path}: primary public certificate files are not allowed: {', '.join(legacy_files)}")


def reject_symlinked_input(path: Path, *, label: str) -> None:
    if path.is_symlink():
        raise MetadataError(f"{label} must not be a symlink: {path}")


def validate_signers(
    path: Path,
    keys_dir: Path,
    data: dict[str, Any],
    release_lines: dict[str, dict[str, int]],
    require_files: bool,
) -> list[dict[str, Any]]:
    signers = data.get("signers")
    if not isinstance(signers, list):
        raise MetadataError(f"{path}: signers must be a list")
    if not signers:
        raise MetadataError(f"{path}: signers must be non-empty")

    seen_aliases: set[str] = set()
    seen_fingerprints: set[str] = set()
    active_by_line: dict[str, set[str]] = {release_line: set() for release_line in release_lines}
    release_capable_by_line: dict[str, set[str]] = {release_line: set() for release_line in release_lines}
    builder_capable_by_line: dict[str, set[str]] = {release_line: set() for release_line in release_lines}
    builder_capable_by_artifact: dict[str, dict[str, set[str]]] = {
        release_line: {artifact_set: set() for artifact_set in VALID_ARTIFACT_SETS}
        for release_line in release_lines
    }
    normalized_signers: list[dict[str, Any]] = []

    for index, signer in enumerate(signers):
        item_path = f"{path}.signers[{index}]"
        if not isinstance(signer, dict):
            raise MetadataError(f"{item_path}: entry must be an object")
        require_allowed_keys(signer, SIGNER_KEYS, path=item_path)

        alias = require_string(signer, "alias", path=item_path)
        if not SIGNER_ALIAS_RE.fullmatch(alias):
            raise MetadataError(
                f"{item_path}.alias: must be 3-32 lowercase alphanumeric or hyphen characters"
            )
        if alias in seen_aliases:
            raise MetadataError(f"{item_path}.alias: duplicate alias {alias}")
        seen_aliases.add(alias)

        status = validate_status(signer, path=item_path)
        key_origin = validate_key_origin(signer, path=item_path)
        public_key_file = validate_public_key_file(signer, path=item_path)
        signing_fingerprint = normalize_fingerprint(
            signer.get("signing_fingerprint"),
            path=f"{item_path}.signing_fingerprint",
        )
        if signing_fingerprint in seen_fingerprints:
            raise MetadataError(f"{item_path}.signing_fingerprint: duplicate signing fingerprint {signing_fingerprint}")
        seen_fingerprints.add(signing_fingerprint)

        signer_release_lines = require_string_list(
            signer,
            "release_lines",
            path=item_path,
            allowed_values=set(release_lines),
            allow_empty=status != "active",
        )
        capabilities = set(
            require_string_list(
                signer,
                "capabilities",
                path=item_path,
                allowed_values=VALID_CAPABILITIES,
                allow_empty=status != "active",
            )
        )
        artifact_sets = require_string_list(
            signer,
            "artifact_sets",
            path=item_path,
            allowed_values=VALID_ARTIFACT_SETS,
            allow_empty=status != "active" or "builder-attestation" not in capabilities,
        )
        if status == "active" and "builder-attestation" in capabilities and not artifact_sets:
            raise MetadataError(f"{item_path}.artifact_sets: expected non-empty list")

        if "replacement_signing_fingerprint" in signer and signer["replacement_signing_fingerprint"]:
            normalize_fingerprint(
                signer["replacement_signing_fingerprint"],
                path=f"{item_path}.replacement_signing_fingerprint",
            )
        if require_files and not (keys_dir / public_key_file).is_file():
            raise MetadataError(f"{path}: missing signer public certificate {keys_dir / public_key_file}")

        if status == "active":
            for release_line in signer_release_lines:
                active_by_line[release_line].add(alias)
                if "release-signing" in capabilities:
                    release_capable_by_line[release_line].add(alias)
                if "builder-attestation" in capabilities:
                    builder_capable_by_line[release_line].add(alias)
                    for artifact_set in artifact_sets:
                        builder_capable_by_artifact[release_line][artifact_set].add(alias)

        normalized_signers.append(
            {
                "alias": alias,
                "status": status,
                "key_origin": key_origin,
                "public_key_file": public_key_file,
                "signing_fingerprint": signing_fingerprint,
                "release_lines": sorted(signer_release_lines),
                "capabilities": sorted(capabilities),
                "artifact_sets": sorted(artifact_sets),
            }
        )

    for release_line, policy in release_lines.items():
        active_count = len(active_by_line[release_line])
        required_active = policy["active_signer_set_size"]
        if active_count != required_active:
            raise MetadataError(
                f"{path}.{release_line}: active signer count must be exactly {required_active}, got {active_count}"
            )
        if len(release_capable_by_line[release_line]) < policy["release_signature_quorum"]:
            raise MetadataError(f"{path}.{release_line}: release-signing quorum is not satisfiable")
        if len(builder_capable_by_line[release_line]) < policy["builder_attestation_quorum"]:
            raise MetadataError(f"{path}.{release_line}: builder-attestation quorum is not satisfiable")
        for artifact_set in sorted(VALID_ARTIFACT_SETS):
            if (
                len(builder_capable_by_artifact[release_line][artifact_set])
                < policy["builder_attestation_quorum"]
            ):
                raise MetadataError(
                    f"{path}.{release_line}: builder-attestation quorum is not satisfiable "
                    f"for artifact set {artifact_set}"
                )
        if release_capable_by_line[release_line] != builder_capable_by_line[release_line]:
            raise MetadataError(
                f"{path}.{release_line}: active release-signing and builder-attestation signer sets must match"
            )

    return sorted(normalized_signers, key=lambda item: item["alias"])


def active_signer_aliases(projection: dict[str, Any]) -> set[str]:
    return {signer["alias"] for signer in projection["signers"] if signer["status"] == "active"}


def active_aliases_for_line(projection: dict[str, Any], release_line: str) -> set[str]:
    return {
        signer["alias"]
        for signer in projection["signers"]
        if signer["status"] == "active" and release_line in signer["release_lines"]
    }


def line_transition_state(projection: dict[str, Any], release_line: str) -> tuple[Any, ...]:
    """Return a comparable view of one release line's policy and active signers.

    Two policies share the same state for a release line only when its quorum
    settings and the full identity of every active signer scoped to that line
    are identical. Any difference means that line is being changed and must be
    re-approved by that line's previous active signer set.
    """

    policy = projection["release_lines"][release_line]
    signers = sorted(
        (
            signer["alias"],
            signer["signing_fingerprint"],
            signer["key_origin"],
            signer["public_key_file"],
            tuple(signer["capabilities"]),
            tuple(signer["artifact_sets"]),
        )
        for signer in projection["signers"]
        if signer["status"] == "active" and release_line in signer["release_lines"]
    )
    return (
        policy["active_signer_set_size"],
        policy["release_signature_quorum"],
        policy["builder_attestation_quorum"],
        policy["policy_change_quorum"],
        tuple(signers),
    )


def required_policy_change_quorum(projection: dict[str, Any]) -> int:
    return max(policy["policy_change_quorum"] for policy in projection["release_lines"].values())


def approval_dir_for(keys_dir: Path, policy_id: str) -> Path:
    return keys_dir / "approvals" / policy_id


def validate_policy_sha256_file(path: Path, expected_policy_sha256: str) -> None:
    try:
        content = path.read_text(encoding="utf8")
    except FileNotFoundError as exc:
        raise MetadataError(f"missing policy approval hash file: {path}") from exc
    if not POLICY_SHA256_RE.fullmatch(content):
        raise MetadataError(f"{path}: expected '<64-hex>  keys.json\\n'")
    approved_hash = content[:64]
    if approved_hash != expected_policy_sha256:
        raise MetadataError(f"{path}: policy hash does not match checked-in keys.json")


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def status_fingerprints(status_output: str) -> list[str]:
    fingerprints: list[str] = []
    for line in status_output.splitlines():
        if not line.startswith("[GNUPG:] VALIDSIG "):
            continue
        fields = line.split()
        if len(fields) >= 3:
            fingerprints.append(normalize_fingerprint(fields[2], path="gpg status"))
    return fingerprints


def import_previous_signer_key(
    gpg: str,
    gnupg_home: Path,
    previous_keys_dir: Path,
    signer: dict[str, Any],
) -> None:
    key_file = previous_keys_dir / signer["public_key_file"]
    if not key_file.is_file():
        raise MetadataError(f"missing previous signer public certificate: {key_file}")
    result = run_command([gpg, "--batch", "--homedir", str(gnupg_home), "--import", str(key_file)])
    if result.returncode != 0:
        raise MetadataError(f"failed to import previous signer public certificate {key_file}:\n{result.stderr}")


def verify_approval_signature(
    gpg: str,
    gnupg_home: Path,
    approval_file: Path,
    signed_policy_sha256: Path,
    *,
    alias: str,
    expected_fingerprint: str,
) -> None:
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
            str(approval_file),
            str(signed_policy_sha256),
        ]
    )
    if result.returncode != 0:
        raise MetadataError(
            f"{approval_file}: approval signature does not verify against policy.SHA256:\n"
            f"{result.stdout}{result.stderr}"
        )
    valid_fingerprints = set(status_fingerprints(result.stdout))
    if not valid_fingerprints:
        raise MetadataError(f"{approval_file}: approval signature produced no valid signer fingerprint")
    unexpected = sorted(valid_fingerprints - {expected_fingerprint})
    if unexpected:
        raise MetadataError(
            f"{approval_file}: approval signature for {alias} was signed by unexpected fingerprint(s): "
            + ", ".join(unexpected)
        )
    if expected_fingerprint not in valid_fingerprints:
        raise MetadataError(
            f"{approval_file}: approval signature was not signed by expected previous signer "
            f"{alias} ({expected_fingerprint})"
        )


def validate_policy_transition(
    projection: dict[str, Any],
    previous_policy_path: Path | None,
    approval_dir: Path,
    gpg: str,
) -> None:
    policy_sequence = projection["policy_sequence"]
    if policy_sequence == 1:
        return

    previous_projection = validate_operator_policy(
        previous_policy_path.resolve(),
        previous_policy_path.resolve().parent,
        require_files=False,
        previous_policy_path=None,
        approval_dir=None,
        validate_transition=False,
    )
    if projection["previous_policy_sha256"] != previous_projection["policy_sha256"]:
        raise MetadataError("previous_policy_sha256 does not match previous policy exact-byte SHA256")
    if policy_sequence != previous_projection["policy_sequence"] + 1:
        raise MetadataError("policy_sequence must advance by exactly one")
    if not approval_dir.is_dir():
        raise MetadataError(f"missing policy approval directory: {approval_dir}")

    note = approval_dir / "approval-note.md"
    if not note.is_file():
        raise MetadataError(f"missing policy approval note: {note}")
    validate_policy_sha256_file(approval_dir / "policy.SHA256", projection["policy_sha256"])

    previous_active_aliases = active_signer_aliases(previous_projection)
    current_active_aliases = active_signer_aliases(projection)
    previous_signers_by_alias = {
        signer["alias"]: signer for signer in previous_projection["signers"] if signer["status"] == "active"
    }
    approval_files = sorted(approval_dir.glob("*.asc"))
    approvers: set[str] = set()
    approval_aliases: list[tuple[Path, str]] = []
    for approval_file in approval_files:
        alias = approval_file.stem
        if alias in current_active_aliases and alias not in previous_active_aliases:
            raise MetadataError(f"{approval_file}: newly added signer cannot approve its own addition")
        if alias not in previous_active_aliases:
            raise MetadataError(f"{approval_file}: approval signer is not active in previous policy")
        if alias in approvers:
            raise MetadataError(f"{approval_file}: duplicate approval from {alias}")
        if not approval_file.read_text(encoding="utf8").strip():
            raise MetadataError(f"{approval_file}: approval signature must be non-empty")
        approvers.add(alias)
        approval_aliases.append((approval_file, alias))

    gpg_path = shutil.which(gpg) if Path(gpg).name == gpg else gpg
    if not gpg_path:
        raise MetadataError(f"gpg executable not found: {gpg}")
    with tempfile.TemporaryDirectory(prefix="qpa-gpg-") as gnupg_home:
        gnupg_home_path = Path(gnupg_home)
        gnupg_home_path.chmod(0o700)
        for signer in previous_signers_by_alias.values():
            import_previous_signer_key(gpg_path, gnupg_home_path, previous_policy_path.resolve().parent, signer)
        for approval_file, alias in approval_aliases:
            signer = previous_signers_by_alias[alias]
            verify_approval_signature(
                gpg_path,
                gnupg_home_path,
                approval_file,
                approval_dir / "policy.SHA256",
                alias=alias,
                expected_fingerprint=signer["signing_fingerprint"],
            )

    # Scope policy-change approvals to the release line(s) actually being changed.
    # Each changed line must be approved by that line's previous active signer set at
    # that line's previous policy_change_quorum; approvers active only in other release
    # lines do not count toward it. This prevents, for example, testnet-only signers
    # from satisfying a mainnet policy-change quorum.
    previous_lines = set(previous_projection["release_lines"])
    current_lines = set(projection["release_lines"])
    changed_lines: list[str] = []
    for release_line in sorted(previous_lines | current_lines):
        previous_state = (
            line_transition_state(previous_projection, release_line)
            if release_line in previous_lines
            else None
        )
        current_state = (
            line_transition_state(projection, release_line) if release_line in current_lines else None
        )
        if previous_state == current_state:
            continue
        changed_lines.append(release_line)
        if release_line in previous_lines:
            eligible = active_aliases_for_line(previous_projection, release_line)
            required = previous_projection["release_lines"][release_line]["policy_change_quorum"]
        else:
            # A brand-new release line has no previous line-scoped signers, so require
            # approval from the established previous active signer set. The threshold must
            # come from the PREVIOUS policy (the strongest previous policy-change quorum),
            # not the new line's self-declared quorum -- otherwise a transition could add a
            # line with policy_change_quorum: 1 and self-authorize under a single approval.
            eligible = active_signer_aliases(previous_projection)
            required = required_policy_change_quorum(previous_projection)
        line_approvers = approvers & eligible
        if len(line_approvers) < required:
            raise MetadataError(
                f"release line {release_line!r}: need {required} approval(s) from the previous "
                f"active signer set for that line, got {len(line_approvers)}"
            )

    if not changed_lines:
        # No release-line state changed (e.g. an administrative re-pin that only advances
        # the sequence or effective tag). Keep a baseline requiring the strongest previous
        # line quorum so such transitions still need prior-quorum approval.
        required_quorum = required_policy_change_quorum(previous_projection)
        if len(approvers) < required_quorum:
            raise MetadataError(f"missing approvals: need {required_quorum}, got {len(approvers)}")


def validate_operator_policy(
    path: Path,
    keys_dir: Path,
    require_files: bool,
    *,
    previous_policy_path: Path | None = None,
    approval_dir: Path | None = None,
    gpg: str = shutil.which("gpg") or "gpg",
    validate_transition: bool = True,
) -> dict[str, Any]:
    data = load_json(path)
    policy_sha256 = sha256_file(path)
    ensure_no_public_forbidden_terms(data, path=str(path))
    require_allowed_keys(data, TOP_LEVEL_KEYS, path=str(path))

    policy_id, policy_sequence, previous_policy_sha256, effective_from_tag = validate_policy_identity(path, data)
    release_lines = validate_release_lines(path, data)
    if require_files:
        reject_legacy_public_key_files(keys_dir, path=path)
    signers = validate_signers(path, keys_dir, data, release_lines, require_files)

    projection = {
        "schema_version": 2,
        "policy_id": policy_id,
        "policy_sequence": policy_sequence,
        "previous_policy_sha256": previous_policy_sha256,
        "effective_from_tag": effective_from_tag,
        "policy_sha256": policy_sha256,
        "release_lines": release_lines,
        "signers": signers,
    }
    ensure_no_public_forbidden_terms(projection, path=f"{path}.normalized")

    # Fail closed for non-bootstrap policy updates. Routine release-time mirror
    # checks that do not have previous-policy material must opt into shape-only
    # validation with --skip-policy-transition-validation.
    if validate_transition:
        if previous_policy_path is None:
            if policy_sequence > 1:
                raise MetadataError(
                    "policy_sequence > 1 requires --previous-operator-policy "
                    "or explicit --skip-policy-transition-validation"
                )
        else:
            validate_policy_transition(
                projection,
                previous_policy_path,
                approval_dir or approval_dir_for(keys_dir, policy_id),
                gpg,
            )
    return projection


def compare_operator_mirror(canonical: dict[str, Any], mirror: dict[str, Any]) -> None:
    if canonical != mirror:
        raise MetadataError(
            "operator key mirror mismatch: policy hash, active aliases, signing fingerprints, "
            "capabilities, artifact sets, public key files, and release-line policy must match canonical metadata"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-policy", default=DEFAULT_OPERATOR_POLICY, type=Path)
    parser.add_argument("--operator-keys-dir", default=DEFAULT_OPERATOR_KEYS_DIR, type=Path)
    parser.add_argument("--operator-policy-mirror", type=Path)
    parser.add_argument("--operator-keys-dir-mirror", type=Path)
    parser.add_argument("--previous-operator-policy", type=Path)
    parser.add_argument("--previous-operator-policy-mirror", type=Path)
    parser.add_argument("--approval-dir", type=Path)
    parser.add_argument("--approval-dir-mirror", type=Path)
    parser.add_argument("--gpg", default=shutil.which("gpg") or "gpg")
    parser.add_argument("--require-public-key-files", action="store_true")
    parser.add_argument(
        "--skip-policy-transition-validation",
        action="store_true",
        help=(
            "Validate the committed policy and mirror shape without requiring previous-policy "
            "approval material. Intended for release-time mirror checks; policy rotation PRs "
            "must omit this flag and provide --previous-operator-policy."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        reject_symlinked_input(args.operator_policy, label="--operator-policy")
        reject_symlinked_input(args.operator_keys_dir, label="--operator-keys-dir")
        canonical_policy = args.operator_policy.resolve()
        canonical_keys_dir = args.operator_keys_dir.resolve()
        canonical_projection = validate_operator_policy(
            canonical_policy,
            canonical_keys_dir,
            args.require_public_key_files,
            previous_policy_path=args.previous_operator_policy.resolve() if args.previous_operator_policy else None,
            approval_dir=args.approval_dir.resolve() if args.approval_dir else None,
            gpg=args.gpg,
            validate_transition=not args.skip_policy_transition_validation,
        )
        if args.operator_policy_mirror:
            mirror_keys_dir_arg = args.operator_keys_dir_mirror or args.operator_policy_mirror.parent
            reject_symlinked_input(args.operator_policy_mirror, label="--operator-policy-mirror")
            reject_symlinked_input(mirror_keys_dir_arg, label="--operator-keys-dir-mirror")
            mirror_policy = args.operator_policy_mirror.resolve()
            mirror_keys_dir = mirror_keys_dir_arg.resolve()
            mirror_projection = validate_operator_policy(
                mirror_policy,
                mirror_keys_dir,
                args.require_public_key_files,
                previous_policy_path=(
                    args.previous_operator_policy_mirror.resolve()
                    if args.previous_operator_policy_mirror
                    else args.previous_operator_policy.resolve()
                    if args.previous_operator_policy
                    else None
                ),
                approval_dir=(
                    args.approval_dir_mirror.resolve()
                    if args.approval_dir_mirror
                    else args.approval_dir.resolve()
                    if args.approval_dir
                    else None
                ),
                gpg=args.gpg,
                validate_transition=not args.skip_policy_transition_validation,
            )
            compare_operator_mirror(canonical_projection, mirror_projection)
        print("Key metadata validated")
        print(f"policy_sha256={canonical_projection['policy_sha256']}")
        return 0
    except MetadataError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
