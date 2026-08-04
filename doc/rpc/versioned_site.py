# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Discover qbit RPC doc versions and assemble a complete Pages site."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Callable

import site_builder


SCHEMA_VERSION = "1"
TAG_PATTERN = re.compile(
    r"^v(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<suffix>[0-9A-Za-z][0-9A-Za-z.-]*))?$"
)
RC_SUFFIX_PATTERN = re.compile(r"(?:^|[.-])rc[0-9]+$", re.IGNORECASE)


class VersionedSiteError(Exception):
    """Raised when version discovery or site assembly fails."""


def parse_release_tag(tag: str) -> re.Match[str] | None:
    """Return a release-tag match, excluding release candidates."""
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        return None
    suffix = match.group("suffix")
    if suffix and RC_SUFFIX_PATTERN.search(suffix):
        return None
    return match


def version_sort_key(tag: str) -> tuple[Any, ...]:
    """Return a deterministic key for qbit release ordering."""
    match = parse_release_tag(tag)
    if match is None:
        raise VersionedSiteError(f"unsupported qbit release tag: {tag}")

    suffix = match.group("suffix")
    suffix_key: tuple[tuple[int, Any], ...] = ()
    if suffix:
        suffix_key = tuple(
            (0, int(part)) if part.isdigit() else (1, part.lower())
            for part in re.split(r"[.-]", suffix)
        )
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        suffix is None,
        suffix_key,
    )


def git_output(arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def resolve_annotated_tag(tag: str) -> str:
    ref = f"refs/tags/{tag}"
    try:
        object_type = git_output(["cat-file", "-t", ref])
    except subprocess.CalledProcessError as exc:
        raise VersionedSiteError(f"release tag does not exist: {tag}") from exc
    if object_type != "tag":
        raise VersionedSiteError(f"release tag is not annotated: {tag}")
    return git_output(["rev-parse", f"{ref}^{{commit}}"])


def resolve_commit(ref: str) -> str:
    candidates = (
        ref,
        f"refs/heads/{ref}",
        f"refs/remotes/origin/{ref}",
        f"refs/tags/{ref}",
    )
    for candidate in candidates:
        try:
            return git_output(["rev-parse", "--verify", f"{candidate}^{{commit}}"])
        except subprocess.CalledProcessError:
            continue
    raise VersionedSiteError(f"unable to resolve development ref: {ref}")


def load_github_releases(repository: str) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            [
                "gh",
                "api",
                "--paginate",
                "--slurp",
                "-H",
                "Accept: application/vnd.github+json",
                f"repos/{repository}/releases?per_page=100",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise VersionedSiteError("unable to query GitHub releases") from exc

    payload = json.loads(result.stdout)
    if payload and all(isinstance(page, list) for page in payload):
        return [release for page in payload for release in page]
    if isinstance(payload, list):
        return payload
    raise VersionedSiteError("GitHub releases response must be an array")


def select_release_entries(
    releases: list[dict[str, Any]],
    tag_resolver: Callable[[str], str] = resolve_annotated_tag,
) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen_tags: set[str] = set()

    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str) or parse_release_tag(tag) is None:
            continue
        if tag in seen_tags:
            raise VersionedSiteError(f"duplicate published release tag: {tag}")
        seen_tags.add(tag)
        source_sha = tag_resolver(tag)
        entries.append(
            {
                "id": tag,
                "label": f"qbit {tag}",
                "kind": "release",
                "path": tag,
                "source_ref": f"refs/tags/{tag}",
                "source_sha": source_sha,
                "source_checkout_ref": source_sha,
            }
        )

    entries.sort(key=lambda entry: version_sort_key(entry["id"]), reverse=True)
    if not entries:
        raise VersionedSiteError("no published qbit releases were discovered")
    return entries


def build_plan(
    releases: list[dict[str, Any]],
    development_ref: str,
    publisher_sha: str,
    development_checkout_ref: str = "",
    tag_resolver: Callable[[str], str] = resolve_annotated_tag,
    development_resolver: Callable[[str], str] = resolve_commit,
) -> dict[str, Any]:
    release_entries = select_release_entries(releases, tag_resolver)
    development_sha = development_resolver(development_ref)
    development = {
        "id": "main",
        "label": f"{development_ref} (development @ {development_sha[:8]})",
        "kind": "development",
        "path": "main",
        "source_ref": development_ref,
        "source_sha": development_sha,
        "source_checkout_ref": development_checkout_ref or development_sha,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "publisher_sha": publisher_sha,
        "latest": release_entries[0]["id"],
        "development": development,
        "releases": release_entries,
        "builds": [*release_entries, development],
    }


def write_json(path: str | Path, value: dict[str, Any]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return output


def write_github_outputs(path: str | Path, plan: dict[str, Any]) -> None:
    matrix = json.dumps({"include": plan["builds"]}, separators=(",", ":"))
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(f"matrix={matrix}\n")
        handle.write(f"latest={plan['latest']}\n")
        handle.write(f"publisher_sha={plan['publisher_sha']}\n")
        handle.write(f"development_sha={plan['development']['source_sha']}\n")


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise VersionedSiteError(f"JSON object expected in {path}")
    return value


def _assert_regular_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise VersionedSiteError(f"artifact contains a symbolic link: {path}")


def _artifact_dir(artifacts_root: Path, entry: dict[str, str]) -> Path:
    return artifacts_root / f"rpc-docs-version-{entry['id']}"


def _validate_version_artifact(
    artifacts_root: Path, entry: dict[str, str]
) -> tuple[Path, dict[str, Any]]:
    artifact = _artifact_dir(artifacts_root, entry)
    site_dir = artifact / "site"
    data_dir = artifact / "data"
    required = (
        site_dir / "index.html",
        site_dir / "search" / "search_index.json",
        site_dir / "assets" / "rpcdocs-version.json",
        data_dir / "rpc-docs.json",
        data_dir / "rpc-docs-build-meta.json",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise VersionedSiteError(
            f"version artifact {entry['id']} is incomplete: {', '.join(missing)}"
        )

    _assert_regular_tree(artifact)
    manifest = _load_json(data_dir / "rpc-docs.json")
    build_meta = _load_json(data_dir / "rpc-docs-build-meta.json")
    if manifest.get("project") != "qbit":
        raise VersionedSiteError(f"artifact {entry['id']} is not a qbit manifest")
    if build_meta.get("project") != "qbit":
        raise VersionedSiteError(f"artifact {entry['id']} is not qbit build metadata")
    if entry["kind"] == "release":
        for document_name, document in (
            ("manifest", manifest),
            ("build metadata", build_meta),
        ):
            project_version = document.get("project_version")
            if not _release_version_matches_tag(project_version, entry["id"]):
                raise VersionedSiteError(
                    f"artifact {entry['id']} {document_name} reports "
                    f"project_version {project_version!r}"
                )

    context = _load_json(site_dir / "assets" / "rpcdocs-version.json")
    current = context.get("current", {})
    if current.get("id") != entry["id"] or current.get("path") != entry["path"]:
        raise VersionedSiteError(f"artifact {entry['id']} has mismatched context")
    return site_dir, manifest


def _release_version_matches_tag(project_version: Any, tag: str) -> bool:
    if not isinstance(project_version, str):
        return False
    if project_version == tag:
        return True
    return tag.startswith("v") and project_version == tag[1:]


def _html_pages(site_dir: Path) -> list[str]:
    return sorted(
        path.relative_to(site_dir).as_posix()
        for path in site_dir.rglob("*.html")
        if path.is_file()
    )


def _published_entry(entry: dict[str, str], site_dir: Path) -> dict[str, Any]:
    return {
        "id": entry["id"],
        "label": entry["label"],
        "url": f"{entry['path']}/",
        "source_ref": entry["source_ref"],
        "source_sha": entry["source_sha"],
        "pages": _html_pages(site_dir),
    }


def assemble_site(plan_path: str | Path, artifacts_root: str | Path, out: str | Path) -> Path:
    plan = _load_json(Path(plan_path))
    if plan.get("schema_version") != SCHEMA_VERSION:
        raise VersionedSiteError("unsupported version build-plan schema")

    output_dir = Path(out)
    if output_dir.exists():
        if output_dir.resolve() == Path(output_dir.anchor):
            raise VersionedSiteError("refusing to replace a filesystem root")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    artifact_root = Path(artifacts_root)
    expected_artifacts = {
        f"rpc-docs-version-{entry['id']}" for entry in plan["builds"]
    }
    actual_artifacts = {path.name for path in artifact_root.iterdir() if path.is_dir()}
    if actual_artifacts != expected_artifacts:
        missing = sorted(expected_artifacts - actual_artifacts)
        unexpected = sorted(actual_artifacts - expected_artifacts)
        raise VersionedSiteError(
            "version artifact set does not match the build plan: "
            f"missing={missing}, unexpected={unexpected}"
        )

    published_by_id: dict[str, dict[str, Any]] = {}
    for entry in plan["builds"]:
        publication = site_builder.validate_publication(
            entry["id"], entry["label"], entry["kind"], entry["path"]
        )
        site_dir, _manifest = _validate_version_artifact(artifact_root, entry)
        destination = output_dir / publication["path"]
        shutil.copytree(site_dir, destination)
        published_by_id[entry["id"]] = _published_entry(entry, site_dir)

    latest = plan["latest"]
    if latest not in published_by_id:
        raise VersionedSiteError(f"latest release was not built: {latest}")

    latest_dir = output_dir / latest
    shutil.copytree(latest_dir, output_dir, dirs_exist_ok=True)
    try:
        latest_entry = next(
            entry for entry in plan["releases"] if entry["id"] == latest
        )
    except StopIteration as exc:
        raise VersionedSiteError(
            f"latest release is absent from the release plan: {latest}"
        ) from exc
    root_publication = site_builder.validate_publication(
        latest_entry["id"], latest_entry["label"], "release", ""
    )
    site_builder.write_publication_context(output_dir / "assets", root_publication)

    versions = {
        "schema_version": SCHEMA_VERSION,
        "latest": latest,
        "development": published_by_id[plan["development"]["id"]],
        "versions": [published_by_id[entry["id"]] for entry in plan["releases"]],
    }
    write_json(output_dir / "versions.json", versions)
    output_dir.joinpath(".nojekyll").write_text("", encoding="utf-8")
    return output_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover")
    discover.add_argument("--repository", required=True)
    discover.add_argument("--development-ref", required=True)
    discover.add_argument("--development-checkout-ref", default="")
    discover.add_argument("--publisher-sha", required=True)
    discover.add_argument("--output", required=True)
    discover.add_argument("--github-output")
    discover.add_argument("--releases-file")

    assemble = subparsers.add_parser("assemble")
    assemble.add_argument("--plan", required=True)
    assemble.add_argument("--artifacts-root", required=True)
    assemble.add_argument("--out", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "discover":
        releases = (
            json.loads(Path(args.releases_file).read_text(encoding="utf-8"))
            if args.releases_file
            else load_github_releases(args.repository)
        )
        plan = build_plan(
            releases,
            development_ref=args.development_ref,
            development_checkout_ref=args.development_checkout_ref,
            publisher_sha=args.publisher_sha,
        )
        write_json(args.output, plan)
        if args.github_output:
            write_github_outputs(args.github_output, plan)
        return 0

    assemble_site(args.plan, args.artifacts_root, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
