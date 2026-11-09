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

import os
import sys

# Run isolated (python3 -I -S -B): no PYTHONPATH, user or site packages, startup
# hooks or bytecode. The tools need only the standard library. Started any
# other way, the tool runs itself again isolated before importing anything
# else; hooks the first interpreter already ran cannot be undone, which is why
# the documented invocation passes the flags itself.
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    if not sys.executable:
        sys.exit("ERR: cannot find the Python interpreter; run python3 -I -S -B " + __file__)
    os.execv(sys.executable, [sys.executable, "-I", "-S", "-B", os.path.realpath(__file__), *sys.argv[1:]])

# Never look modules up by name in this directory, so a stray sourceless .pyc
# beside the tools cannot shadow a module, and never read or write __pycache__
# in the trusted checkout.
_TOOL_DIR = os.path.dirname(os.path.realpath(__file__))
if sys.path and os.path.realpath(sys.path[0] or os.curdir) == _TOOL_DIR:
    del sys.path[0]
sys.dont_write_bytecode = True

import atexit  # noqa: E402
import importlib.util  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402

sys.pycache_prefix = tempfile.mkdtemp(prefix="qbit-release-tools-pycache-")
atexit.register(shutil.rmtree, sys.pycache_prefix, True)


def _load_common():  # type: ignore[no-untyped-def]
    path = os.path.join(_TOOL_DIR, "release_staging_common.py")
    spec = importlib.util.spec_from_file_location("release_staging_common", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


common = _load_common()

import argparse  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402


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


def gpg_environment() -> dict[str, str]:
    """The operator's environment, with GPG_TTY set if a terminal is at hand.

    Curses and tty pinentries ask for the smartcard PIN on the terminal that
    GPG_TTY names; GUI pinentries such as pinentry-mac do not need it.
    """

    env = dict(os.environ)
    if not env.get("GPG_TTY") and sys.stdin.isatty():
        env["GPG_TTY"] = os.ttyname(sys.stdin.fileno())
    return env


def detach_sign(gpg: str, fingerprint: str, manifest: Path, signature: Path) -> None:
    # The trailing "!" makes GnuPG use exactly this (sub)key rather than the
    # newest signing subkey of the same certificate. The manifest is a private
    # copy of the verified bytes; stdin stays the operator's terminal.
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
        ],
        env=gpg_environment(),
    )
    if result.returncode != 0:
        raise common.ReleaseToolError(f"gpg failed to sign SHA256SUMS:\n{result.stderr.strip()}")


def require_digest(path: Path, expected: str, moment: str) -> None:
    if common.sha256_bytes(path.read_bytes()) != expected:
        raise common.ReleaseToolError(f"The private copy of SHA256SUMS changed {moment}; nothing was written")


def verify_signature(
    validators: common.Validators,
    gpg: str,
    gnupg_home: Path,
    signature: Path,
    manifest: Path,
    signer: Any,
) -> None:
    common.read_regular_file(signature, label="Release signature")
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
    return common.run_main(lambda: sign(parse_args(argv)))


def sign(args: argparse.Namespace) -> int:
    expected_digest = common.normalize_expected_sha256(args.expected_sha256sums_sha256)
    common.note_non_default_gpg(args.gpg)
    with common.open_trusted_release(Path(__file__), args.trusted_release_ref, git=common.GIT) as trusted:
        validators = trusted.validators
        vra = validators.release_artifacts
        try:
            policy = vra.load_release_policy(trusted.policy_path, trusted.keys_dir, args.release_line)
        except validators.errors as exc:
            raise common.ReleaseToolError(str(exc)) from exc
        signer = policy.signers_by_alias.get(args.alias)
        if signer is None:
            raise common.ReleaseToolError(
                f"{args.alias!r} is not an active release-signing signer for {args.release_line} in "
                f"keys.json at {trusted.ref}; active: {', '.join(sorted(policy.active_aliases))}"
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
        signature_path = stage_dir / f"{common.CHECKSUMS_FILE}.{signer.alias}.asc"
        common.note_stale_scratch(stage_dir)
        # Read SHA256SUMS once: these bytes are checked against the staged
        # files, compared with the expected digest, signed and verified.
        sha256sums = common.read_regular_file(manifest, label="SHA256SUMS")
        sha256sums_sha256 = common.sha256_bytes(sha256sums)
        if expected_digest is not None and sha256sums_sha256 != expected_digest:
            raise common.ReleaseToolError(
                f"SHA256SUMS SHA-256 mismatch: expected {expected_digest}, got {sha256sums_sha256}"
            )

        with common.temporary_gnupg_home("qbit-sign-verify-gnupg-") as verify_home, common.scratch_dir_beside(
            stage_dir
        ) as scratch:
            # The scratch directory is a private 0700 directory and the copy is
            # 0600, so only this user can change the bytes that get signed.
            verified_manifest = scratch / common.CHECKSUMS_FILE
            fd = os.open(verified_manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(sha256sums)
            common.verify_staged_files(validators, stage_dir, policy, manifest=verified_manifest)
            try:
                vra.import_release_keys(args.gpg, verify_home, trusted.keys_dir, policy)
            except validators.errors as exc:
                raise common.ReleaseToolError(str(exc)) from exc

            if signature_path.exists() or signature_path.is_symlink():
                try:
                    verify_signature(validators, args.gpg, verify_home, signature_path, verified_manifest, signer)
                except common.ReleaseToolError as exc:
                    raise common.ReleaseToolError(
                        f"{signature_path} already exists and the publisher's check rejects it ({exc}); "
                        "refusing to overwrite it"
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
                candidate = scratch / signature_path.name
                require_digest(verified_manifest, sha256sums_sha256, "before signing")
                detach_sign(args.gpg, signer.fingerprint, verified_manifest, candidate)
                require_digest(verified_manifest, sha256sums_sha256, "while it was being signed")
                verify_signature(validators, args.gpg, verify_home, candidate, verified_manifest, signer)
                if common.read_regular_file(manifest, label="SHA256SUMS") != sha256sums:
                    raise common.ReleaseToolError("SHA256SUMS changed while it was being signed")
                common.publish_file_no_clobber(candidate, signature_path)
                status = "created"

        common.emit("status", status)
        common.emit("signer_alias", signer.alias)
        common.emit("signer_fpr", signer.fingerprint)
        common.emit("release_line", args.release_line)
        common.emit("trusted_release_ref", trusted.ref)
        common.emit("policy_sha256", policy.policy_sha256)
        common.emit("sha256sums_sha256", sha256sums_sha256)
        common.emit("signature_path", signature_path)
        common.emit("signature_sha256", common.sha256_bytes(signature_path.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
