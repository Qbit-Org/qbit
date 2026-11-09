#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Stage release artifacts and SHA256SUMS from the counted builder attestations.

The upload set is derived from qbit-guix.sigs: for each artifact set, the
builder manifests that verify against the trusted release key policy propose a
set of public release artifacts (filtered with the publisher's naming rules),
and the staged set is the largest proposal that reaches the builder-attestation
quorum (conflicting proposals that both reach it are refused). The tool
then copies those artifacts out of the builder output directories, verifies
every copy, writes SHA256SUMS, re-validates the result with the publisher's
validators and only then moves the stage directory into place.

With --sha256sums-output the tool only derives SHA256SUMS from the
attestations, which reproduces a release manifest without its artifacts.
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
import re  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402


TAG_RE = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]*$")
ARTIFACT_SETS = ("core", "photon")


@dataclass(frozen=True)
class NamingRules:
    tag: str
    release_line: str
    allow_unsigned_platform_artifacts: bool
    allow_codesigning_artifacts: bool


@dataclass(frozen=True)
class SelectedArtifactSet:
    artifact: str
    entries: dict[str, str]
    counted: list[str]
    not_counted: list[str]


def artifact_prefix(version: str, artifact: str) -> str:
    """Name prefix of an artifact set, as in validate_builder_attestations.expected_release_entries."""

    if artifact == "core":
        return f"qbit-{version}-"
    if artifact == "photon":
        return f"qbit-photon-{version}-"
    raise common.ReleaseToolError(f"Unsupported artifact set: {artifact}")


def check_release_naming(validators: common.Validators, rules: NamingRules) -> None:
    vra = validators.release_artifacts
    try:
        vra.validate_artifact_names(
            {},
            rules.tag,
            rules.release_line,
            False,
            False,
            rules.allow_unsigned_platform_artifacts,
            rules.allow_codesigning_artifacts,
        )
    except vra.ReleaseValidationError as exc:
        raise common.ReleaseToolError(str(exc)) from exc


def upload_exclusion(validators: common.Validators, name: str, rules: NamingRules) -> str | None:
    """Return why the publisher would refuse ``name`` as a release asset, or None."""

    vra = validators.release_artifacts
    try:
        vra.validate_artifact_names(
            {name: vra.ArtifactEntry(name=name, digest="0" * 64)},
            rules.tag,
            rules.release_line,
            False,
            False,
            rules.allow_unsigned_platform_artifacts,
            rules.allow_codesigning_artifacts,
        )
    except vra.ReleaseValidationError as exc:
        return str(exc)
    return None


def derive_upload_entries(
    validators: common.Validators,
    manifest_entries: dict[str, str],
    *,
    artifact: str,
    rules: NamingRules,
) -> tuple[dict[str, str], dict[str, str]]:
    """Split one attested manifest into its public upload entries and exclusions.

    Entries outside the artifact set's name prefix belong to another set and are
    neither selected nor reported.
    """

    version = validators.builder_attestations.release_version(rules.tag)
    prefix = artifact_prefix(version, artifact)
    selected: dict[str, str] = {}
    excluded: dict[str, str] = {}
    for name, digest in sorted(manifest_entries.items()):
        reason = upload_exclusion(validators, name, rules)
        if reason is not None:
            excluded[name] = reason
        elif name.startswith(prefix):
            selected[name] = digest.lower()
    return selected, excluded


def render_sha256sums(entries: dict[str, str]) -> bytes:
    """Render SHA256SUMS exactly as the v1.0.0 release did: sorted, two spaces, LF."""

    lines = [f"{entries[name]}  {name}\n" for name in sorted(entries)]
    return "".join(lines).encode("utf8")


def builders_for(policy: Any, artifact: str) -> dict[str, Any]:
    return {
        alias: builder
        for alias, builder in sorted(policy.active_builders.items())
        if artifact in builder.artifact_sets
    }


def detect_artifact_sets(validators: common.Validators, version_dir: Path, policy: Any) -> list[str]:
    vba = validators.builder_attestations
    artifacts = ["core"]
    for alias in builders_for(policy, "photon"):
        builder_dir = version_dir / alias
        if builder_dir.is_dir() and vba.find_builder_manifest(builder_dir, "photon") is not None:
            artifacts.append("photon")
            break
    return artifacts


def select_artifact_set(
    validators: common.Validators,
    *,
    gpg: str,
    gnupg_home: Path,
    guix_sigs_dir: Path,
    version: str,
    artifact: str,
    policy: Any,
    source_archive: Any,
    rules: NamingRules,
    exclusions: dict[str, str],
) -> SelectedArtifactSet:
    """Pick the one upload set that reaches the builder-attestation quorum."""

    vba = validators.builder_attestations
    version_dir = guix_sigs_dir / version
    proposals: dict[tuple[tuple[str, str], ...], list[str]] = {}
    verified: list[str] = []
    rejected: list[str] = []
    for alias, builder in builders_for(policy, artifact).items():
        builder_dir = version_dir / alias
        if not builder_dir.is_dir():
            continue
        manifest = vba.find_builder_manifest(builder_dir, artifact)
        if manifest is None:
            continue
        try:
            vba.verify_manifest_signature(gpg, gnupg_home, manifest, builder.fingerprint)
            manifest_entries = vba.parse_sha256sums(manifest)
        except vba.BuilderValidationError as exc:
            rejected.append(f"{alias}: {common.one_line(exc)}")
            continue
        verified.append(alias)
        selected, excluded = derive_upload_entries(
            validators, manifest_entries, artifact=artifact, rules=rules
        )
        for name, reason in excluded.items():
            exclusions.setdefault(name, reason)
        proposals.setdefault(tuple(sorted(selected.items())), []).append(alias)

    viable: list[tuple[dict[str, str], list[str]]] = []
    failures: list[str] = []
    for proposal, proposers in sorted(proposals.items()):
        entries = dict(proposal)
        if not entries:
            failures.append(f"{','.join(proposers)}: no public {artifact} release artifacts")
            continue
        try:
            counted = vba.validate_artifact_attestations(
                gpg=gpg,
                gnupg_home=gnupg_home,
                guix_sigs_repo=guix_sigs_dir,
                version=version,
                artifact=artifact,
                release_entries=entries,
                source_archive=source_archive,
                builders=policy.active_builders,
                quorum=policy.builder_attestation_quorum,
            )
        except vba.BuilderValidationError as exc:
            failures.append(f"set proposed by {','.join(proposers)}: {common.one_line(exc)}")
            continue
        viable.append((entries, counted))

    if not viable:
        details = failures + [f"rejected {item}" for item in rejected]
        raise common.ReleaseToolError(
            f"No {artifact} upload set reaches the builder-attestation quorum of "
            f"{policy.builder_attestation_quorum} in {version_dir}"
            + (": " + "; ".join(details) if details else "; no builder attestations found")
        )
    # Sets that reach quorum and nest (a builder skipped a platform) resolve to
    # the largest one, which is itself quorum-attested. Sets that conflict do not.
    maximal = [
        candidate
        for candidate in viable
        if all(other[0].items() <= candidate[0].items() for other in viable)
    ]
    if len(maximal) != 1:
        raise common.ReleaseToolError(
            f"Ambiguous {artifact} upload set: {len(viable)} conflicting attested sets each reach the "
            "builder-attestation quorum; resolve the disagreement in qbit-guix.sigs before staging"
        )
    entries, counted = maximal[0]
    for item in rejected:
        common.note(f"{artifact} attestation not counted: {item}")
    not_counted = sorted(set(verified) - set(counted))
    for alias in not_counted:
        common.note(f"{artifact} attestation from {alias} verifies but does not cover the staged set")
    return SelectedArtifactSet(artifact=artifact, entries=entries, counted=counted, not_counted=not_counted)


def locate_builder_outputs(
    validators: common.Validators,
    output_dirs: list[Path],
    entries: dict[str, str],
    *,
    prefixes: tuple[str, ...],
    rules: NamingRules,
) -> dict[str, Path]:
    """Find each staged artifact exactly once and refuse unattested release artifacts."""

    found: dict[str, Path] = {}
    unattested: list[str] = []
    duplicates: list[str] = []
    for output_dir in output_dirs:
        for dirpath, dirnames, filenames in os.walk(output_dir):
            dirnames.sort()
            for filename in sorted(filenames):
                path = Path(dirpath) / filename
                if filename in entries:
                    if path.is_symlink() or not path.is_file():
                        raise common.ReleaseToolError(f"Builder output must be a regular file: {path}")
                    if filename in found:
                        duplicates.append(f"{found[filename]} and {path}")
                        continue
                    found[filename] = path
                elif filename.startswith(prefixes) and upload_exclusion(validators, filename, rules) is None:
                    unattested.append(str(path))
    if duplicates:
        raise common.ReleaseToolError("Duplicate release artifact in builder outputs: " + "; ".join(duplicates))
    if unattested:
        raise common.ReleaseToolError(
            "Builder outputs contain release artifacts that the counted attestations do not cover: "
            + ", ".join(sorted(unattested))
        )
    missing = sorted(set(entries) - set(found))
    if missing:
        raise common.ReleaseToolError("Builder outputs are missing attested artifacts: " + ", ".join(missing))
    return found


def verify_new_stage(
    validators: common.Validators,
    stage_dir: Path,
    entries: dict[str, str],
    *,
    gpg: str,
    gnupg_home: Path,
    guix_sigs_dir: Path,
    version: str,
    selections: list[SelectedArtifactSet],
    policy: Any,
    source_archive: Any,
    rules: NamingRules,
) -> None:
    """Re-check an assembled stage directory the way the publisher will."""

    vra = validators.release_artifacts
    vba = validators.builder_attestations
    try:
        staged = vra.staged_file_names(stage_dir)
        parsed = vra.parse_sha256sums(stage_dir / common.CHECKSUMS_FILE)
        if staged != set(entries) | {common.CHECKSUMS_FILE}:
            raise common.ReleaseToolError("Assembled stage directory does not match the derived upload set")
        if {name: entry.digest for name, entry in parsed.items()} != entries:
            raise common.ReleaseToolError("Written SHA256SUMS does not match the derived upload set")
        vra.validate_artifact_names(
            parsed,
            rules.tag,
            rules.release_line,
            True,
            any(selection.artifact == "photon" for selection in selections),
            rules.allow_unsigned_platform_artifacts,
            rules.allow_codesigning_artifacts,
        )
        for selection in selections:
            vba.validate_artifact_attestations(
                gpg=gpg,
                gnupg_home=gnupg_home,
                guix_sigs_repo=guix_sigs_dir,
                version=version,
                artifact=selection.artifact,
                release_entries=vba.expected_release_entries(stage_dir, rules.tag, selection.artifact),
                source_archive=source_archive,
                builders=policy.active_builders,
                quorum=policy.builder_attestation_quorum,
            )
    except validators.errors as exc:
        raise common.ReleaseToolError(f"Assembled stage directory failed validation: {exc}") from exc


def check_existing_stage(
    validators: common.Validators,
    stage_dir: Path,
    sha256sums: bytes,
    release_policy: Any,
) -> None:
    existing = common.read_regular_file(stage_dir / common.CHECKSUMS_FILE, label="Existing SHA256SUMS")
    if existing != sha256sums:
        raise common.ReleaseToolError(
            f"Stage directory {stage_dir} already exists with a different SHA256SUMS; refusing to overwrite it. "
            "Move it aside to stage again."
        )
    try:
        common.verify_staged_files(validators, stage_dir, release_policy)
    except common.ReleaseToolError as exc:
        raise common.ReleaseToolError(
            f"Stage directory {stage_dir} already exists and differs from the derived stage: {exc}; "
            "refusing to overwrite it"
        ) from exc


def write_sha256sums_only(destination: Path, sha256sums: bytes) -> str:
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise common.ReleaseToolError(f"--sha256sums-output must be a regular file path: {destination}")
    if destination.exists():
        if destination.read_bytes() != sha256sums:
            raise common.ReleaseToolError(f"{destination} already exists with different content; refusing to overwrite it")
        return "unchanged"
    with common.scratch_dir_beside(destination) as scratch:
        candidate = scratch / common.CHECKSUMS_FILE
        candidate.write_bytes(sha256sums)
        common.publish_file_no_clobber(candidate, destination)
    return "created"


def assemble_stage(
    validators: common.Validators,
    stage_dir: Path,
    entries: dict[str, str],
    sources: dict[str, Path],
    sha256sums: bytes,
    **verify_args: Any,
) -> None:
    vra = validators.release_artifacts
    with common.scratch_dir_beside(stage_dir) as scratch:
        for name in sorted(entries):
            destination = scratch / name
            shutil.copyfile(sources[name], destination)
            actual = vra.sha256_file(destination)
            if actual != entries[name]:
                raise common.ReleaseToolError(
                    f"Staged copy of {name} does not match the attested digest: expected {entries[name]}, "
                    f"got {actual} (source {sources[name]})"
                )
        with (scratch / common.CHECKSUMS_FILE).open("xb") as output:
            output.write(sha256sums)
        verify_new_stage(validators, scratch, entries, **verify_args)
        # mkdtemp creates the scratch 0700; the stage gets the mode a plain
        # mkdir would give it, so a separate publishing account can read it.
        os.chmod(scratch, 0o777 & ~common.current_umask())
        try:
            os.rename(scratch, stage_dir)
        except OSError as exc:
            raise common.ReleaseToolError(f"Cannot move the verified stage into {stage_dir}: {exc}") from exc


def reject_overlap(stage_dir: Path, protected: list[tuple[str, Path]]) -> None:
    for label, path in protected:
        if stage_dir == path or stage_dir.is_relative_to(path) or path.is_relative_to(stage_dir):
            raise common.ReleaseToolError(f"--stage-dir must not overlap the {label}: {path}")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_common_arguments(parser)
    parser.add_argument("--tag", required=True, help="Signed annotated release tag, for example v1.0.1.")
    parser.add_argument("--guix-sigs-dir", required=True, type=Path, help="qbit-guix.sigs checkout.")
    parser.add_argument(
        "--artifact",
        choices=ARTIFACT_SETS,
        action="append",
        help="Artifact set to stage; repeat for both. Default: core, plus photon when attested.",
    )
    parser.add_argument("--allow-unsigned-platform-artifacts", action="store_true")
    parser.add_argument("--allow-codesigning-artifacts", action="store_true")
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--stage-dir", type=Path, help="New stage directory to create.")
    output.add_argument(
        "--sha256sums-output",
        type=Path,
        help="Only derive SHA256SUMS from the attestations and write it to this file.",
    )
    parser.add_argument(
        "--builder-output-dir",
        type=Path,
        action="append",
        default=[],
        help="Guix output directory to copy artifacts from; repeat for core and PHOTON outputs.",
    )
    args = parser.parse_args(argv)
    if args.stage_dir is not None and not args.builder_output_dir:
        parser.error("--stage-dir requires at least one --builder-output-dir")
    if args.sha256sums_output is not None and args.builder_output_dir:
        parser.error("--builder-output-dir is only used with --stage-dir")
    return args


def main(argv: list[str] | None = None) -> int:
    return common.run_main(lambda: stage(parse_args(argv)))


def stage(args: argparse.Namespace) -> int:
    if not TAG_RE.fullmatch(args.tag):
        raise common.ReleaseToolError(f"--tag must be a safe v-prefixed release tag: {args.tag!r}")
    with common.open_trusted_release(Path(__file__), args.trusted_release_ref, git=args.git) as checkout:
        validators = checkout.validators
        vra = validators.release_artifacts
        vba = validators.builder_attestations
        rules = NamingRules(
            tag=args.tag,
            release_line=args.release_line,
            allow_unsigned_platform_artifacts=args.allow_unsigned_platform_artifacts,
            allow_codesigning_artifacts=args.allow_codesigning_artifacts,
        )
        check_release_naming(validators, rules)
        version = vba.release_version(args.tag)
        guix_sigs_dir = common.require_directory(args.guix_sigs_dir, label="--guix-sigs-dir")
        version_dir = guix_sigs_dir / version
        if not version_dir.is_dir():
            raise common.ReleaseToolError(f"qbit-guix.sigs has no attestations for {version}: {version_dir}")

        try:
            builder_policy = vba.load_builder_policy(checkout.policy_path, checkout.keys_dir, args.release_line)
            release_policy = vra.load_release_policy(checkout.policy_path, checkout.keys_dir, args.release_line)
        except validators.errors as exc:
            raise common.ReleaseToolError(str(exc)) from exc

        tag_target = common.git_output(
            args.git,
            checkout.root,
            ["rev-parse", "--verify", f"refs/tags/{args.tag}^{{commit}}"],
            action=f"resolve release tag {args.tag} in the trusted qbit checkout",
        ).strip()
        ancestor = common.run_command(
            [args.git, "-C", str(checkout.root), "merge-base", "--is-ancestor", tag_target, checkout.ref]
        )
        if ancestor.returncode != 0:
            raise common.ReleaseToolError(
                f"Release tag {args.tag} target {tag_target} is not an ancestor of the trusted release ref {checkout.ref}"
            )
        try:
            source_archive = vba.reconstruct_canonical_source_archive(
                git=args.git,
                source_root=checkout.root,
                tag=args.tag,
                expected_tag_target=tag_target,
            )
        except vba.BuilderValidationError as exc:
            raise common.ReleaseToolError(str(exc)) from exc

        stage_dir = None
        output_dirs: list[Path] = []
        if args.stage_dir is not None:
            output_dirs = [
                common.require_directory(path, label="--builder-output-dir") for path in args.builder_output_dir
            ]
            stage_dir = Path(os.path.abspath(args.stage_dir))
            if stage_dir.is_symlink() or (stage_dir.exists() and not stage_dir.is_dir()):
                raise common.ReleaseToolError(f"--stage-dir must be a directory path: {stage_dir}")
            stage_dir = stage_dir.parent.resolve() / stage_dir.name
            reject_overlap(
                stage_dir,
                [("builder output directory", path) for path in output_dirs]
                + [("qbit-guix.sigs checkout", guix_sigs_dir), ("trusted qbit checkout", checkout.root)],
            )

        common.note_stale_scratch(stage_dir if stage_dir is not None else Path(os.path.abspath(args.sha256sums_output)))
        exclusions: dict[str, str] = {}
        with common.temporary_gnupg_home("qbit-stage-gnupg-") as gnupg_home:
            try:
                vba.import_operator_keys(args.gpg, gnupg_home, checkout.keys_dir, builder_policy)
            except vba.BuilderValidationError as exc:
                raise common.ReleaseToolError(str(exc)) from exc
            artifacts = sorted(set(args.artifact or detect_artifact_sets(validators, version_dir, builder_policy)))
            if "core" not in artifacts:
                raise common.ReleaseToolError("The core artifact set is required in every release")
            selections = [
                select_artifact_set(
                    validators,
                    gpg=args.gpg,
                    gnupg_home=gnupg_home,
                    guix_sigs_dir=guix_sigs_dir,
                    version=version,
                    artifact=artifact,
                    policy=builder_policy,
                    source_archive=source_archive,
                    rules=rules,
                    exclusions=exclusions,
                )
                for artifact in artifacts
            ]
            entries: dict[str, str] = {}
            for selection in selections:
                entries.update(selection.entries)
            for name in sorted(set(exclusions) - set(entries)):
                common.note(f"not staged: {name}: {exclusions[name]}")
            sha256sums = render_sha256sums(entries)

            if stage_dir is None:
                status = write_sha256sums_only(args.sha256sums_output, sha256sums)
                sha256sums_path = Path(os.path.abspath(args.sha256sums_output))
            else:
                sha256sums_path = stage_dir / common.CHECKSUMS_FILE
                if stage_dir.is_dir() and any(stage_dir.iterdir()):
                    check_existing_stage(validators, stage_dir, sha256sums, release_policy)
                    status = "unchanged"
                else:
                    prefixes = tuple(artifact_prefix(version, artifact) for artifact in artifacts)
                    sources = locate_builder_outputs(validators, output_dirs, entries, prefixes=prefixes, rules=rules)
                    assemble_stage(
                        validators,
                        stage_dir,
                        entries,
                        sources,
                        sha256sums,
                        gpg=args.gpg,
                        gnupg_home=gnupg_home,
                        guix_sigs_dir=guix_sigs_dir,
                        version=version,
                        selections=selections,
                        policy=builder_policy,
                        source_archive=source_archive,
                        rules=rules,
                    )
                    status = "created"

        common.emit("status", status)
        common.emit("tag", args.tag)
        common.emit("release_line", args.release_line)
        common.emit("trusted_release_ref", checkout.ref)
        common.emit("policy_sha256", release_policy.policy_sha256)
        common.emit("source_archive", source_archive.name)
        common.emit("source_sha256", source_archive.sha256)
        common.emit("builder_attestation_quorum", builder_policy.builder_attestation_quorum)
        for selection in selections:
            common.emit(f"counted_{selection.artifact}", ",".join(selection.counted))
        if stage_dir is not None:
            common.emit("stage_dir", stage_dir)
        common.emit("artifact_count", len(entries))
        for name in sorted(entries):
            common.emit("artifact", name)
        common.emit("sha256sums_path", sha256sums_path)
        common.emit("sha256sums_sha256", common.sha256_bytes(sha256sums))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
