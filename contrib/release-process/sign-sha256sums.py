#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Sign a staged release SHA256SUMS once, as one release operator.

The signer alias is resolved to its signing fingerprint through keys.json of
the trusted qbit checkout this tool runs from. The tool checks SHA256SUMS
against the staged files, makes an ASCII-armored detached signature with the
operator's existing GnuPG setup (smartcard or keyring; it never exports or
reads private key material), verifies the signature against the trusted public
certificate, and only then writes SHA256SUMS.<alias>.asc. An existing valid
signature by the same signer is kept, so re-running is safe.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Keep the trusted checkout byte-for-byte clean between tool runs.
sys.dont_write_bytecode = True

import release_staging_common as common  # noqa: E402


def confirm(summary: list[tuple[str, object]]) -> None:
    if not sys.stdin.isatty():
        raise common.ReleaseToolError("Signing requires --yes when stdin is not interactive")
    sys.stderr.write("Release SHA256SUMS signing\n--------------------------\n")
    for label, value in summary:
        sys.stderr.write(f"{label + ':':<17}{value}\n")
    sys.stderr.write("Sign SHA256SUMS? [y/N] ")
    sys.stderr.flush()
    reply = sys.stdin.readline().strip()
    if reply not in {"y", "Y", "yes", "YES"}:
        raise common.ReleaseToolError("Operator declined to sign")


def require_secret_key(gpg: str, fingerprint: str) -> None:
    result = common.run_command([gpg, "--batch", "--with-colons", "--list-secret-keys", fingerprint])
    if result.returncode != 0:
        raise common.ReleaseToolError(
            f"GnuPG has no usable secret key for {fingerprint}; connect the operator smartcard or keyring"
        )


def detach_sign(gpg: str, fingerprint: str, manifest: Path, signature: Path) -> None:
    # The trailing "!" makes GnuPG use exactly this (sub)key rather than the
    # newest signing subkey of the same certificate.
    result = common.run_command(
        [
            gpg,
            "--batch",
            "--armor",
            "--detach-sign",
            "--digest-algo",
            "SHA256",
            "--local-user",
            f"{fingerprint}!",
            "--output",
            str(signature),
            str(manifest),
        ]
    )
    if result.returncode != 0:
        raise common.ReleaseToolError(f"gpg failed to sign SHA256SUMS:\n{result.stderr.strip()}")


def verify_signature(
    validators: common.Validators,
    gpg: str,
    gnupg_home: Path,
    signature: Path,
    manifest: Path,
    signer: Any,
) -> None:
    data = common.read_regular_file(signature, label="Release signature")
    common.require_single_armored_signature(signature, data)
    try:
        validators.release_artifacts.verify_manifest_signature_file(gpg, gnupg_home, signature, manifest, signer)
    except validators.errors as exc:
        raise common.ReleaseToolError(str(exc)) from exc


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_common_arguments(parser)
    parser.add_argument("--stage-dir", required=True, type=Path, help="Stage directory holding SHA256SUMS.")
    parser.add_argument("--alias", required=True, help="Release signer alias from keys.json, for example operator-02.")
    parser.add_argument(
        "--expected-sha256sums-sha256",
        help="Refuse to sign unless SHA256SUMS has this SHA-256 digest.",
    )
    parser.add_argument(
        "--expected-fingerprint",
        help="Cross-check: refuse to sign unless keys.json resolves the alias to this fingerprint.",
    )
    parser.add_argument("--yes", action="store_true", help="Sign without an interactive confirmation.")
    return parser.parse_args(argv)


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
        signer = policy.signers_by_alias.get(args.alias)
        if signer is None:
            raise common.ReleaseToolError(
                f"{args.alias!r} is not an active release-signing signer for {args.release_line} in "
                f"{checkout.policy_path}; active: {', '.join(sorted(policy.active_aliases))}"
            )
        if args.expected_fingerprint is not None:
            try:
                expected_fingerprint = vra.normalize_fingerprint(args.expected_fingerprint)
            except vra.ReleaseValidationError as exc:
                raise common.ReleaseToolError(f"--expected-fingerprint: {exc}") from exc
            if expected_fingerprint != signer.fingerprint:
                raise common.ReleaseToolError(
                    f"keys.json resolves {args.alias} to {signer.fingerprint}, not --expected-fingerprint "
                    f"{expected_fingerprint}"
                )

        stage_dir = common.require_directory(args.stage_dir, label="--stage-dir")
        manifest = stage_dir / common.CHECKSUMS_FILE
        common.verify_staged_files(validators, stage_dir, policy)
        sha256sums = common.read_regular_file(manifest, label="SHA256SUMS")
        sha256sums_sha256 = common.sha256_bytes(sha256sums)
        if expected_digest is not None and sha256sums_sha256 != expected_digest:
            raise common.ReleaseToolError(
                f"SHA256SUMS SHA-256 mismatch: expected {expected_digest}, got {sha256sums_sha256}"
            )
        signature_path = stage_dir / f"{common.CHECKSUMS_FILE}.{signer.alias}.asc"

        with common.temporary_gnupg_home("qbit-sign-verify-gnupg-") as verify_home:
            try:
                vra.import_release_keys(args.gpg, verify_home, checkout.keys_dir, policy)
            except validators.errors as exc:
                raise common.ReleaseToolError(str(exc)) from exc

            if signature_path.exists() or signature_path.is_symlink():
                try:
                    verify_signature(validators, args.gpg, verify_home, signature_path, manifest, signer)
                except common.ReleaseToolError as exc:
                    raise common.ReleaseToolError(
                        f"{signature_path} already exists and does not verify ({exc}); refusing to overwrite it"
                    ) from exc
                status = "unchanged"
            else:
                require_secret_key(args.gpg, signer.fingerprint)
                if not args.yes:
                    confirm(
                        [
                            ("Stage dir", stage_dir),
                            ("Signer alias", signer.alias),
                            ("Signer FPR", signer.fingerprint),
                            ("Release line", args.release_line),
                            ("SHA256SUMS hash", sha256sums_sha256),
                            ("Signature path", signature_path),
                        ]
                    )
                with common.scratch_dir_beside(stage_dir) as scratch:
                    signed_manifest = scratch / common.CHECKSUMS_FILE
                    signed_manifest.write_bytes(sha256sums)
                    candidate = scratch / signature_path.name
                    detach_sign(args.gpg, signer.fingerprint, signed_manifest, candidate)
                    verify_signature(validators, args.gpg, verify_home, candidate, signed_manifest, signer)
                    if common.read_regular_file(manifest, label="SHA256SUMS") != sha256sums:
                        raise common.ReleaseToolError("SHA256SUMS changed while it was being signed")
                    common.publish_file_no_clobber(candidate, signature_path)
                status = "created"

        common.emit("status", status)
        common.emit("signer_alias", signer.alias)
        common.emit("signer_fpr", signer.fingerprint)
        common.emit("release_line", args.release_line)
        common.emit("trusted_release_ref", checkout.ref)
        common.emit("policy_sha256", policy.policy_sha256)
        common.emit("sha256sums_sha256", sha256sums_sha256)
        common.emit("signature_path", signature_path)
        common.emit("signature_sha256", common.sha256_bytes(signature_path.read_bytes()))
        return 0
    except common.ReleaseToolError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
