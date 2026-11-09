#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Combine per-operator SHA256SUMS signatures into SHA256SUMS.asc.

SHA256SUMS.asc is the byte concatenation of every SHA256SUMS.<alias>.asc in the
directory, in alias order, which is how the v1.0.0 release was assembled. The
tool does not count signers itself: it checks each file and then the assembled
set with the publisher's own functions in ci/release/validate_release_artifacts.py
(verify_manifest_signature_file and verify_manifest_signatures, using keys.json
at the trusted ref), so the combined file passes exactly when the publisher's
release-signature check would. Only then is it moved into place; an existing
SHA256SUMS.asc is kept only if it is byte-identical.

The tool does not hash release artifacts. sign-sha256sums.py checks them before
each signature and publish-local-release.sh checks them again before upload.
"""

from __future__ import annotations

import os
import sys

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
    return common.run_main(lambda: combine(parse_args(argv)))


def combine(args: argparse.Namespace) -> int:
    expected_digest = common.normalize_expected_sha256(args.expected_sha256sums_sha256)
    with common.open_trusted_release(Path(__file__), args.trusted_release_ref, git=args.git) as trusted:
        validators = trusted.validators
        vra = validators.release_artifacts
        try:
            policy = vra.load_release_policy(trusted.policy_path, trusted.keys_dir, args.release_line)
        except validators.errors as exc:
            raise common.ReleaseToolError(str(exc)) from exc

        stage_dir = common.require_directory(args.stage_dir, label="--stage-dir")
        manifest = stage_dir / common.CHECKSUMS_FILE
        combined_path = stage_dir / common.COMBINED_SIGNATURE_FILE
        common.note_stale_scratch(stage_dir)
        common.note_stale_scratch(combined_path)
        sha256sums = common.read_regular_file(manifest, label="SHA256SUMS")
        sha256sums_sha256 = common.sha256_bytes(sha256sums)
        if expected_digest is not None and sha256sums_sha256 != expected_digest:
            raise common.ReleaseToolError(
                f"SHA256SUMS SHA-256 mismatch: expected {expected_digest}, got {sha256sums_sha256}"
            )
        parts: dict[str, bytes] = {}
        for alias, signature in sorted(signature_inputs(validators, stage_dir, policy).items()):
            data = common.read_regular_file(signature, label="Per-operator signature")
            common.require_single_armored_signature(signature, data)
            parts[alias] = data
        combined = b"".join(parts[alias] for alias in sorted(parts))

        with common.temporary_gnupg_home("qbit-combine-gnupg-") as gnupg_home, common.scratch_dir_beside(
            stage_dir
        ) as scratch:
            # Assemble exactly the bytes read above and let the publisher's
            # functions decide: each file, then quorum and the combined file.
            candidate_manifest = scratch / common.CHECKSUMS_FILE
            candidate_manifest.write_bytes(sha256sums)
            try:
                vra.parse_sha256sums(candidate_manifest)
                vra.import_release_keys(args.gpg, gnupg_home, trusted.keys_dir, policy)
                for alias, data in parts.items():
                    copy = scratch / f"{common.CHECKSUMS_FILE}.{alias}.asc"
                    copy.write_bytes(data)
                    vra.verify_manifest_signature_file(
                        args.gpg, gnupg_home, copy, candidate_manifest, policy.signers_by_alias[alias]
                    )
                candidate = scratch / common.COMBINED_SIGNATURE_FILE
                candidate.write_bytes(combined)
                counted = vra.verify_manifest_signatures(args.gpg, gnupg_home, scratch, policy)
            except validators.errors as exc:
                raise common.ReleaseToolError(str(exc)) from exc

            if combined_path.exists() or combined_path.is_symlink():
                existing = common.read_regular_file(combined_path, label="Existing SHA256SUMS.asc")
                if existing != combined:
                    raise common.ReleaseToolError(
                        f"{combined_path} already exists and differs from the concatenation of "
                        f"{', '.join(sorted(parts))}; refusing to overwrite it"
                    )
                status = "unchanged"
            else:
                if common.read_regular_file(manifest, label="SHA256SUMS") != sha256sums or any(
                    common.read_regular_file(stage_dir / f"{common.CHECKSUMS_FILE}.{alias}.asc", label="Signature")
                    != data
                    for alias, data in parts.items()
                ):
                    raise common.ReleaseToolError("SHA256SUMS or a signature changed while signatures were combined")
                common.publish_file_no_clobber(candidate, combined_path)
                status = "created"

        common.emit("status", status)
        common.emit("release_line", args.release_line)
        common.emit("trusted_release_ref", trusted.ref)
        common.emit("policy_sha256", policy.policy_sha256)
        common.emit("sha256sums_sha256", sha256sums_sha256)
        common.emit("release_signature_quorum", policy.signature_quorum)
        common.emit("release_signature_count", len(counted))
        common.emit("release_signature_aliases", ",".join(counted))
        common.emit("combined_path", combined_path)
        common.emit("combined_sha256", common.sha256_bytes(combined))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
