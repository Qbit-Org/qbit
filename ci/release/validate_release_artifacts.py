#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate a staged qbit signed-release artifact directory."""

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

import validate_key_metadata as key_metadata


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KEYS_DIR = REPO_ROOT / "contrib" / "keys" / "operator-keys"
DEFAULT_KEYS_POLICY = DEFAULT_KEYS_DIR / "keys.json"
CHECKSUMS_FILE = "SHA256SUMS"
ALLOWED_ARTIFACT_SUFFIXES = (".tar.gz", ".tar.xz", ".zip", ".dmg", ".exe")
SHA256SUMS_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64}) ([ *])(.+)$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
RELEASE_SIGNATURE_RE = re.compile(r"^SHA256SUMS\.([a-z0-9][a-z0-9-]{2,31})\.asc$")


class ReleaseValidationError(Exception):
    """Raised when release validation fails."""


@dataclass(frozen=True)
class ArtifactEntry:
    name: str
    digest: str


@dataclass(frozen=True)
class ReleaseSigner:
    alias: str
    fingerprint: str
    public_key_file: str
    capabilities: tuple[str, ...]
    release_lines: tuple[str, ...]


@dataclass(frozen=True)
class ReleasePolicy:
    release_line: str
    policy_sha256: str
    signature_quorum: int
    active_signer_set_size: int
    release_signers: tuple[ReleaseSigner, ...]

    @property
    def active_fingerprints(self) -> set[str]:
        return {signer.fingerprint for signer in self.release_signers}

    @property
    def active_aliases(self) -> set[str]:
        return {signer.alias for signer in self.release_signers}

    @property
    def signers_by_alias(self) -> dict[str, ReleaseSigner]:
        return {signer.alias: signer for signer in self.release_signers}


def normalize_fingerprint(value: str) -> str:
    fingerprint = re.sub(r"\s+", "", value).upper()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise ReleaseValidationError(
            f"Invalid OpenPGP fingerprint in release key policy: {value!r}"
        )
    return fingerprint


def load_release_policy(policy_path: Path, keys_dir: Path, release_line: str) -> ReleasePolicy:
    try:
        projection = key_metadata.validate_operator_policy(
            policy_path,
            keys_dir,
            require_files=True,
            validate_transition=False,
        )
    except key_metadata.MetadataError as exc:
        raise ReleaseValidationError(str(exc)) from exc

    release_lines = projection["release_lines"]
    if release_line not in release_lines:
        raise ReleaseValidationError(f"Release key policy has no release line {release_line!r}")

    line_policy = release_lines[release_line]
    signature_quorum = int(line_policy["release_signature_quorum"])
    active_signer_set_size = int(line_policy["active_signer_set_size"])

    release_signers: dict[str, ReleaseSigner] = {}
    for signer in projection["signers"]:
        if signer["status"] != "active":
            continue
        release_lines_for_signer = tuple(str(line) for line in signer["release_lines"])
        capabilities = tuple(str(capability) for capability in signer["capabilities"])
        if release_line not in release_lines_for_signer or "release-signing" not in capabilities:
            continue

        alias = str(signer["alias"])
        release_signers[alias] = ReleaseSigner(
            alias=alias,
            fingerprint=normalize_fingerprint(str(signer["signing_fingerprint"])),
            public_key_file=str(signer["public_key_file"]),
            capabilities=capabilities,
            release_lines=release_lines_for_signer,
        )

    if len(release_signers) < signature_quorum:
        raise ReleaseValidationError(
            f"{release_line} release-signing quorum is not satisfiable: "
            f"need {signature_quorum}, got {len(release_signers)} active release signer(s)"
        )

    return ReleasePolicy(
        release_line=release_line,
        policy_sha256=str(projection["policy_sha256"]),
        signature_quorum=signature_quorum,
        active_signer_set_size=active_signer_set_size,
        release_signers=tuple(signer for _alias, signer in sorted(release_signers.items())),
    )


def parse_sha256sums(path: Path) -> dict[str, ArtifactEntry]:
    entries: dict[str, ArtifactEntry] = {}
    try:
        lines = path.read_text(encoding="utf8").splitlines()
    except FileNotFoundError as exc:
        raise ReleaseValidationError(f"Missing required release file: {path}") from exc

    if not lines:
        raise ReleaseValidationError("SHA256SUMS is empty")

    for line_no, line in enumerate(lines, start=1):
        if not line:
            raise ReleaseValidationError(f"SHA256SUMS:{line_no}: blank lines are not allowed")
        if line.startswith("\\"):
            raise ReleaseValidationError(
                f"SHA256SUMS:{line_no}: escaped filenames are not allowed in release manifests"
            )

        match = SHA256SUMS_LINE_RE.fullmatch(line)
        if not match:
            raise ReleaseValidationError(f"SHA256SUMS:{line_no}: malformed checksum line")

        digest, _mode, name = match.groups()
        if name == CHECKSUMS_FILE or RELEASE_SIGNATURE_RE.fullmatch(name) or name == "SHA256SUMS.asc":
            raise ReleaseValidationError(f"SHA256SUMS:{line_no}: manifest files must not be listed")
        if "/" in name or "\\" in name:
            raise ReleaseValidationError(f"SHA256SUMS:{line_no}: artifact path must be a basename")
        if name in {"", ".", ".."} or name.startswith("."):
            raise ReleaseValidationError(f"SHA256SUMS:{line_no}: invalid artifact name {name!r}")
        if name in entries:
            raise ReleaseValidationError(f"SHA256SUMS:{line_no}: duplicate artifact entry {name!r}")

        entries[name] = ArtifactEntry(name=name, digest=digest.lower())

    return entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def staged_file_names(artifacts_dir: Path) -> set[str]:
    if not artifacts_dir.is_dir():
        raise ReleaseValidationError(f"Artifacts directory does not exist: {artifacts_dir}")

    names: set[str] = set()
    non_files: list[str] = []
    for child in artifacts_dir.iterdir():
        if child.is_file():
            names.add(child.name)
        else:
            non_files.append(child.name)

    if non_files:
        raise ReleaseValidationError(
            "Artifacts directory must be flat and contain files only; found non-file entries: "
            + ", ".join(sorted(non_files))
        )
    return names


def release_signature_paths(
    artifacts_dir: Path,
    staged: set[str],
    policy: ReleasePolicy,
) -> dict[str, Path]:
    signatures: dict[str, Path] = {}
    for name in sorted(staged):
        match = RELEASE_SIGNATURE_RE.fullmatch(name)
        if not match:
            continue
        alias = match.group(1)
        if alias not in policy.active_aliases:
            raise ReleaseValidationError(
                f"Artifacts directory contains release signature for non-active release signer: {name}"
            )
        signatures[alias] = artifacts_dir / name
    return signatures


def validate_manifest_coverage(
    artifacts_dir: Path, entries: dict[str, ArtifactEntry], policy: ReleasePolicy
) -> list[Path]:
    required = {CHECKSUMS_FILE, "SHA256SUMS.asc"}
    staged = staged_file_names(artifacts_dir)
    signatures = release_signature_paths(artifacts_dir, staged, policy)
    expected = set(entries) | required | {path.name for path in signatures.values()}
    missing = sorted(expected - staged)
    extra = sorted(staged - expected)
    if missing:
        raise ReleaseValidationError(
            "Artifacts directory is missing files listed or required by the release manifest: "
            + ", ".join(missing)
        )
    if extra:
        raise ReleaseValidationError(
            "Artifacts directory contains files not covered by SHA256SUMS: " + ", ".join(extra)
        )

    for entry in entries.values():
        artifact_path = artifacts_dir / entry.name
        actual_digest = sha256_file(artifact_path)
        if actual_digest != entry.digest:
            raise ReleaseValidationError(
                f"SHA256 mismatch for {entry.name}: expected {entry.digest}, got {actual_digest}"
            )

    return [artifacts_dir / name for name in sorted(expected)]


def validate_artifact_names(
    entries: dict[str, ArtifactEntry],
    tag: str,
    release_line: str,
    require_core_artifact: bool,
    require_photon_artifact: bool,
    allow_unsigned_platform_artifacts: bool,
    allow_codesigning_artifacts: bool,
) -> tuple[int, int]:
    if not tag.startswith("v") or len(tag) == 1:
        raise ReleaseValidationError(f"Release tag must start with v: {tag!r}")
    version = tag[1:]

    if release_line == "testnet" and "testnet" not in version:
        raise ReleaseValidationError("testnet release line requires a testnet tag/version")
    if release_line == "mainnet" and "testnet" in version:
        raise ReleaseValidationError("mainnet release line must not use a testnet tag/version")

    core_count = 0
    photon_count = 0
    for name in entries:
        if not name.endswith(ALLOWED_ARTIFACT_SUFFIXES):
            raise ReleaseValidationError(f"Unsupported release artifact suffix: {name}")
        if not allow_unsigned_platform_artifacts and re.search(r"(^|-)unsigned(?=[.-])", name):
            raise ReleaseValidationError(
                f"Unsigned platform artifact requires an explicit waiver: {name}"
            )
        if not allow_codesigning_artifacts and re.search(r"(^|-)codesigning(?=[.-])", name):
            raise ReleaseValidationError(
                f"Codesigning payloads are not public release artifacts: {name}"
            )

        if name.startswith(f"qbit-{version}-"):
            core_count += 1
        elif name.startswith(f"qbit-photon-{version}-"):
            photon_count += 1
        else:
            raise ReleaseValidationError(
                f"Artifact name does not match release tag {tag}: {name}"
            )

    if require_core_artifact and core_count == 0:
        raise ReleaseValidationError("At least one core qbit release artifact is required")
    if require_photon_artifact and photon_count == 0:
        raise ReleaseValidationError("PHOTON artifact is required for this release profile")
    return core_count, photon_count


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


def import_release_keys(
    gpg: str, gnupg_home: Path, keys_dir: Path, policy: ReleasePolicy
) -> None:
    for signer in policy.release_signers:
        key_file = keys_dir / signer.public_key_file
        if not key_file.is_file():
            raise ReleaseValidationError(
                f"Missing public certificate for release signer {signer.alias}: {key_file}"
            )

        result = run_command([gpg, "--batch", "--homedir", str(gnupg_home), "--import", str(key_file)])
        if result.returncode != 0:
            raise ReleaseValidationError(
                f"Failed to import public certificate for release signer {signer.alias} "
                f"from {key_file}:\n{result.stderr}"
            )

    result = run_command(
        [gpg, "--batch", "--homedir", str(gnupg_home), "--with-colons", "--fingerprint", "--list-keys"]
    )
    if result.returncode != 0:
        raise ReleaseValidationError(f"Failed to list imported release keys:\n{result.stderr}")

    imported: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields and fields[0] == "fpr" and len(fields) > 9:
            imported.add(normalize_fingerprint(fields[9]))

    missing_fingerprints = sorted(policy.active_fingerprints - imported)
    if missing_fingerprints:
        raise ReleaseValidationError(
            "Active release fingerprints are not present in imported key material: "
            + ", ".join(missing_fingerprints)
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


def verify_detached_signature_file(
    gpg: str,
    gnupg_home: Path,
    signature: Path,
    checksums: Path,
) -> set[str]:
    if not signature.is_file():
        raise ReleaseValidationError(f"Missing required release file: {signature}")

    command = [
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
        str(checksums),
    ]
    result = run_command(command)
    if result.returncode != 0:
        raise ReleaseValidationError(
            f"{signature.name} does not verify against SHA256SUMS:\n{result.stdout}{result.stderr}"
        )

    valid_fingerprints = set(status_fingerprints(result.stdout))
    if not valid_fingerprints:
        raise ReleaseValidationError(f"GPG verification produced no valid signature for {signature.name}")
    return valid_fingerprints


def verify_manifest_signature_file(
    gpg: str,
    gnupg_home: Path,
    signature: Path,
    checksums: Path,
    signer: ReleaseSigner,
) -> None:
    valid_fingerprints = verify_detached_signature_file(gpg, gnupg_home, signature, checksums)

    expected = {signer.fingerprint}
    unexpected = sorted(valid_fingerprints - expected)
    if unexpected:
        raise ReleaseValidationError(
            f"{signature.name} was signed by unexpected fingerprint(s): "
            + ", ".join(unexpected)
        )
    if signer.fingerprint not in valid_fingerprints:
        raise ReleaseValidationError(
            f"{signature.name} was not signed by expected fingerprint {signer.fingerprint}"
        )


def verify_combined_manifest_signature_file(
    gpg: str,
    gnupg_home: Path,
    signature: Path,
    checksums: Path,
    policy: ReleasePolicy,
    expected_aliases: set[str],
) -> None:
    valid_fingerprints = verify_detached_signature_file(gpg, gnupg_home, signature, checksums)

    aliases_by_fingerprint = {
        signer.fingerprint: signer.alias for signer in policy.release_signers
    }
    unexpected = sorted(valid_fingerprints - set(aliases_by_fingerprint))
    if unexpected:
        raise ReleaseValidationError(
            f"{signature.name} was signed by unexpected fingerprint(s): "
            + ", ".join(unexpected)
        )

    actual_aliases = {aliases_by_fingerprint[fingerprint] for fingerprint in valid_fingerprints}
    if actual_aliases != expected_aliases:
        missing = sorted(expected_aliases - actual_aliases)
        extra = sorted(actual_aliases - expected_aliases)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        raise ReleaseValidationError(
            f"{signature.name} valid signer set does not match individual release signatures: "
            + "; ".join(details)
        )


def verify_manifest_signatures(
    gpg: str,
    gnupg_home: Path,
    artifacts_dir: Path,
    policy: ReleasePolicy,
) -> tuple[str, ...]:
    checksums = artifacts_dir / CHECKSUMS_FILE
    staged = staged_file_names(artifacts_dir)
    signatures = release_signature_paths(artifacts_dir, staged, policy)
    counted: list[str] = []
    for alias, signature in sorted(signatures.items()):
        signer = policy.signers_by_alias[alias]
        verify_manifest_signature_file(gpg, gnupg_home, signature, checksums, signer)
        counted.append(alias)

    if len(counted) < policy.signature_quorum:
        raise ReleaseValidationError(
            f"Release signature quorum not met for {policy.release_line}: "
            f"got {len(counted)} valid active release signer signature(s), "
            f"need {policy.signature_quorum}; counted={', '.join(counted) or 'none'}"
        )

    verify_combined_manifest_signature_file(
        gpg,
        gnupg_home,
        artifacts_dir / "SHA256SUMS.asc",
        checksums,
        policy,
        set(counted),
    )
    return tuple(counted)


def verify_tag_signature(
    gpg: str, gnupg_home: Path, tag: str, policy: ReleasePolicy
) -> None:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupg_home)
    result = run_command(
        ["git", "-c", f"gpg.program={gpg}", "verify-tag", "--raw", tag],
        env=env,
    )
    if result.returncode != 0:
        raise ReleaseValidationError(
            f"Release tag {tag} was not signed by an active qbit release key:\n"
            f"{result.stdout}{result.stderr}"
        )
    valid_fingerprints = status_fingerprints(result.stdout + result.stderr)
    counted = sorted(set(valid_fingerprints) & policy.active_fingerprints)
    if not counted:
        raise ReleaseValidationError(
            f"Release tag {tag} signature did not come from an active qbit release key"
        )


def write_github_outputs(
    output_path: Path,
    *,
    artifacts_dir: Path,
    upload_files: list[Path],
    artifact_count: int,
    core_artifact_count: int,
    photon_artifact_count: int,
    release_signer_count: int,
    release_signature_count: int,
    release_signature_quorum: int,
    release_signature_aliases: tuple[str, ...],
    keys_json_sha256: str,
) -> None:
    delimiter = "release_files_" + hashlib.sha256(
        "\n".join(str(path) for path in upload_files).encode("utf8")
    ).hexdigest()
    with output_path.open("a", encoding="utf8") as output:
        output.write(f"dir={artifacts_dir}\n")
        output.write(f"file_count={len(upload_files)}\n")
        output.write(f"artifact_count={artifact_count}\n")
        output.write(f"core_artifact_count={core_artifact_count}\n")
        output.write(f"photon_artifact_count={photon_artifact_count}\n")
        output.write(f"release_signer_count={release_signer_count}\n")
        output.write(f"release_signature_count={release_signature_count}\n")
        output.write(f"release_signature_quorum={release_signature_quorum}\n")
        output.write(f"release_signature_aliases={','.join(release_signature_aliases)}\n")
        output.write(f"keys_json_sha256={keys_json_sha256}\n")
        output.write(f"policy_sha256={keys_json_sha256}\n")
        output.write(f"files<<{delimiter}\n")
        for path in upload_files:
            output.write(f"{path}\n")
        output.write(f"{delimiter}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-line", required=True, choices=("testnet", "mainnet"))
    parser.add_argument("--operator-key-policy", default=DEFAULT_KEYS_POLICY, type=Path)
    parser.add_argument("--operator-keys-dir", default=DEFAULT_KEYS_DIR, type=Path)
    parser.add_argument("--gpg", default=shutil.which("gpg") or "gpg")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--require-core-artifact", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--require-photon-artifact", action="store_true")
    parser.add_argument("--allow-unsigned-platform-artifacts", action="store_true")
    parser.add_argument("--allow-codesigning-artifacts", action="store_true")
    parser.add_argument("--verify-tag-signature", action="store_true")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        artifacts_dir = args.artifacts_dir.resolve()
        keys_dir = args.operator_keys_dir.resolve()
        policy_path = args.operator_key_policy.resolve()

        policy = load_release_policy(policy_path, keys_dir, args.release_line)
        entries = parse_sha256sums(artifacts_dir / CHECKSUMS_FILE)
        upload_files = validate_manifest_coverage(artifacts_dir, entries, policy)
        core_count, photon_count = validate_artifact_names(
            entries,
            args.tag,
            args.release_line,
            args.require_core_artifact,
            args.require_photon_artifact,
            args.allow_unsigned_platform_artifacts,
            args.allow_codesigning_artifacts,
        )

        with tempfile.TemporaryDirectory(prefix="qbit-release-gnupg-") as gnupg_home:
            gnupg_home_path = Path(gnupg_home)
            gnupg_home_path.chmod(0o700)
            import_release_keys(args.gpg, gnupg_home_path, keys_dir, policy)
            counted_aliases = verify_manifest_signatures(
                args.gpg, gnupg_home_path, artifacts_dir, policy
            )
            if args.verify_tag_signature:
                verify_tag_signature(args.gpg, gnupg_home_path, args.tag, policy)
        signature_count = len(counted_aliases)

        if args.github_output:
            write_github_outputs(
                args.github_output,
                artifacts_dir=artifacts_dir,
                upload_files=upload_files,
                artifact_count=len(entries),
                core_artifact_count=core_count,
                photon_artifact_count=photon_count,
                release_signer_count=len(policy.release_signers),
                release_signature_count=signature_count,
                release_signature_quorum=policy.signature_quorum,
                release_signature_aliases=counted_aliases,
                keys_json_sha256=policy.policy_sha256,
            )

        print(
            "Validated signed release staging directory: "
            f"{len(entries)} artifact(s), {signature_count}/"
            f"{policy.signature_quorum} release signatures, "
            f"{len(policy.release_signers)} active release signer(s), "
            f"counted aliases={','.join(counted_aliases)}, "
            f"keys_json_sha256={policy.policy_sha256}"
        )
        for path in upload_files:
            print(path)
        return 0
    except ReleaseValidationError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
