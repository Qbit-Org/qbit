#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Combine per-operator SHA256SUMS signatures into SHA256SUMS.asc.

Every SHA256SUMS.<alias>.asc in the directory must verify against SHA256SUMS
with the signing fingerprint that keys.json of the trusted qbit checkout gives
an active release signer of the release line, the signers must be distinct and
their number must reach the release-signature quorum. SHA256SUMS.asc is then the
byte concatenation of those files in alias order, which is how the v1.0.0
release was assembled. The combined file is verified before it is moved into
place; an existing SHA256SUMS.asc is kept only if it is byte-identical.

The tool does not hash release artifacts. sign-sha256sums.py checks them before
each signature and publish-local-release.sh checks them again before upload.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Keep the trusted checkout byte-for-byte clean between tool runs.
sys.dont_write_bytecode = True

import release_staging_common as common  # noqa: E402


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_common_arguments(parser)
    parser.add_argument(
        "--stage-dir",
        required=True,
        type=Path,
        help="Directory holding SHA256SUMS and the per-operator SHA256SUMS.<alias>.asc files.",
    )
    parser.add_argument(
        "--expected-sha256sums-sha256",
        help="Refuse to combine unless SHA256SUMS has this SHA-256 digest.",
    )
    return parser.parse_args(argv)


def signature_inputs(validators: common.Validators, stage_dir: Path, policy: object) -> dict[str, Path]:
    """Return the per-operator signatures, refusing unknown SHA256SUMS* names."""

    vra = validators.release_artifacts
    names = {child.name for child in stage_dir.iterdir()}
    unexpected = sorted(
        name
        for name in names
        if name.startswith(common.CHECKSUMS_FILE)
        and name not in {common.CHECKSUMS_FILE, common.COMBINED_SIGNATURE_FILE}
        and not vra.RELEASE_SIGNATURE_RE.fullmatch(name)
    )
    if unexpected:
        raise common.ReleaseToolError(
            "Unexpected SHA256SUMS files in the stage directory: " + ", ".join(unexpected)
        )
    try:
        return vra.release_signature_paths(stage_dir, names, policy)
    except validators.errors as exc:
        raise common.ReleaseToolError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        expected_digest = common.normalize_expected_sha256(args.expected_sha256sums_sha256)
        checkout = common.resolve_trusted_checkout(Path(__file__), args.trusted_release_ref, git=args.git)
        validators = common.load_validators(checkout.root)
        vra = validators.release_artifacts
        try:
            policy = vra.load_release_policy(checkout.policy_path, checkout.keys_dir, args.release_line)
        except validators.errors as exc:
            raise common.ReleaseToolError(str(exc)) from exc

        stage_dir = common.require_directory(args.stage_dir, label="--stage-dir")
        manifest = stage_dir / common.CHECKSUMS_FILE
        sha256sums = common.read_regular_file(manifest, label="SHA256SUMS")
        try:
            vra.parse_sha256sums(manifest)
        except validators.errors as exc:
            raise common.ReleaseToolError(str(exc)) from exc
        sha256sums_sha256 = common.sha256_bytes(sha256sums)
        if expected_digest is not None and sha256sums_sha256 != expected_digest:
            raise common.ReleaseToolError(
                f"SHA256SUMS SHA-256 mismatch: expected {expected_digest}, got {sha256sums_sha256}"
            )

        signatures = signature_inputs(validators, stage_dir, policy)
        if len(signatures) < policy.signature_quorum:
            raise common.ReleaseToolError(
                f"Release signature quorum not met for {args.release_line}: found {len(signatures)} "
                f"per-operator signature file(s), need {policy.signature_quorum}"
            )
        combined_path = stage_dir / common.COMBINED_SIGNATURE_FILE

        with common.temporary_gnupg_home("qbit-combine-gnupg-") as gnupg_home:
            try:
                vra.import_release_keys(args.gpg, gnupg_home, checkout.keys_dir, policy)
            except validators.errors as exc:
                raise common.ReleaseToolError(str(exc)) from exc

            parts: list[bytes] = []
            fingerprints: dict[str, str] = {}
            for alias, signature in sorted(signatures.items()):
                signer = policy.signers_by_alias[alias]
                data = common.read_regular_file(signature, label="Per-operator signature")
                common.require_single_armored_signature(signature, data)
                try:
                    vra.verify_manifest_signature_file(args.gpg, gnupg_home, signature, manifest, signer)
                except validators.errors as exc:
                    raise common.ReleaseToolError(str(exc)) from exc
                if signer.fingerprint in fingerprints:
                    raise common.ReleaseToolError(
                        f"{signature.name} and SHA256SUMS.{fingerprints[signer.fingerprint]}.asc have the same signer"
                    )
                fingerprints[signer.fingerprint] = alias
                parts.append(data)
            counted = sorted(signatures)
            combined = b"".join(parts)

            def verify_combined(path: Path, checksums: Path) -> None:
                try:
                    vra.verify_combined_manifest_signature_file(
                        args.gpg, gnupg_home, path, checksums, policy, set(counted)
                    )
                except validators.errors as exc:
                    raise common.ReleaseToolError(str(exc)) from exc

            if combined_path.exists() or combined_path.is_symlink():
                existing = common.read_regular_file(combined_path, label="Existing SHA256SUMS.asc")
                if existing != combined:
                    raise common.ReleaseToolError(
                        f"{combined_path} already exists and differs from the concatenation of "
                        f"{', '.join(counted)}; refusing to overwrite it"
                    )
                verify_combined(combined_path, manifest)
                status = "unchanged"
            else:
                with common.scratch_dir_beside(stage_dir) as scratch:
                    candidate_manifest = scratch / common.CHECKSUMS_FILE
                    candidate_manifest.write_bytes(sha256sums)
                    candidate = scratch / common.COMBINED_SIGNATURE_FILE
                    candidate.write_bytes(combined)
                    verify_combined(candidate, candidate_manifest)
                    if common.read_regular_file(manifest, label="SHA256SUMS") != sha256sums:
                        raise common.ReleaseToolError("SHA256SUMS changed while signatures were combined")
                    common.publish_file_no_clobber(candidate, combined_path)
                status = "created"

        common.emit("status", status)
        common.emit("release_line", args.release_line)
        common.emit("trusted_release_ref", checkout.ref)
        common.emit("policy_sha256", policy.policy_sha256)
        common.emit("sha256sums_sha256", sha256sums_sha256)
        common.emit("release_signature_quorum", policy.signature_quorum)
        common.emit("release_signature_count", len(counted))
        common.emit("release_signature_aliases", ",".join(counted))
        common.emit("combined_path", combined_path)
        common.emit("combined_sha256", common.sha256_bytes(combined))
        return 0
    except common.ReleaseToolError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
