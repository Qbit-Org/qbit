#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Classify pull request changes for the required merge gate."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath


RELEASE_POLICY_PROFILE = "release-policy"
RPC_DOCS_PROFILE = "rpc-docs"
PUBLIC_DOCS_PROFILE = "public-docs"
GITHUB_METADATA_PROFILE = "github-metadata"
SOURCE_PROFILE = "source"

RELEASE_TRUST_DOC_RE = re.compile(r"^doc/release-trust-[^/]+[.]md$")
PUBLIC_RELEASE_NOTES_RE = re.compile(r"^doc/release-notes-[^/]+[.]md$")

PUBLIC_DOCS_ROOT_FILES = frozenset(
    {
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "doc/README.md",
    }
)
PUBLIC_DOCS_PREFIXES = (
    "doc/deployment/",
    "doc/design/",
    "doc/integration/",
    "doc/performance/",
    "doc/policy/",
    "doc/reference/",
    "doc/user/",
)
GITHUB_METADATA_FILES = frozenset(
    {
        ".github/PULL_REQUEST_TEMPLATE.md",
        "ci/README.md",
        "doc/development/public-branch-and-rulesets.md",
    }
)
GITHUB_METADATA_PREFIXES = (
    ".github/ISSUE_TEMPLATE/",
    ".github/repository-settings/",
    ".github/rulesets/",
)


@dataclass(frozen=True)
class Classification:
    paths: tuple[str, ...]
    invalid_paths: tuple[str, ...]
    release_policy_paths: tuple[str, ...]
    rpc_docs_paths: tuple[str, ...]
    public_docs_paths: tuple[str, ...]
    github_metadata_paths: tuple[str, ...]
    outside_paths: tuple[str, ...]

    @property
    def lightweight_profile_paths(self) -> dict[str, tuple[str, ...]]:
        return {
            RELEASE_POLICY_PROFILE: self.release_policy_paths,
            RPC_DOCS_PROFILE: self.rpc_docs_paths,
            PUBLIC_DOCS_PROFILE: self.public_docs_paths,
            GITHUB_METADATA_PROFILE: self.github_metadata_paths,
        }

    @property
    def profile(self) -> str:
        if not self.paths or self.invalid_paths or self.outside_paths:
            return SOURCE_PROFILE
        active_profiles = [
            profile
            for profile, profile_paths in self.lightweight_profile_paths.items()
            if profile_paths
        ]
        if len(active_profiles) == 1:
            return active_profiles[0]
        return SOURCE_PROFILE

    @property
    def release_policy_only(self) -> bool:
        return self.profile == RELEASE_POLICY_PROFILE

    @property
    def rpc_docs_only(self) -> bool:
        return self.profile == RPC_DOCS_PROFILE

    @property
    def public_docs_only(self) -> bool:
        return self.profile == PUBLIC_DOCS_PROFILE

    @property
    def github_metadata_only(self) -> bool:
        return self.profile == GITHUB_METADATA_PROFILE


def normalize_path(path: str) -> str | None:
    path = path.strip()
    if not path or "\0" in path or path.startswith("/"):
        return None

    parts = PurePosixPath(path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None

    return "/".join(parts)


def is_release_policy_path(path: str) -> bool:
    return (
        path == ".github/workflows/release-publish.yml"
        or path.startswith("ci/release/")
        or path.startswith("contrib/keys/operator-keys/")
        or RELEASE_TRUST_DOC_RE.fullmatch(path) is not None
    )


def is_rpc_docs_path(path: str) -> bool:
    return (
        path.startswith("doc/rpc/")
        or path.startswith("test/rpc_docs/")
        or path == "cmake/script/normalize_rpc_docs_site_paths.py"
    )


def is_public_docs_path(path: str) -> bool:
    return (
        path in PUBLIC_DOCS_ROOT_FILES
        or path.startswith(PUBLIC_DOCS_PREFIXES)
        or PUBLIC_RELEASE_NOTES_RE.fullmatch(path) is not None
    )


def is_github_metadata_path(path: str) -> bool:
    return path in GITHUB_METADATA_FILES or path.startswith(GITHUB_METADATA_PREFIXES)


def classify_paths(paths: list[str] | tuple[str, ...]) -> Classification:
    normalized: list[str] = []
    invalid: list[str] = []
    release_policy: list[str] = []
    rpc_docs: list[str] = []
    public_docs: list[str] = []
    github_metadata: list[str] = []
    outside: list[str] = []

    for raw_path in paths:
        path = normalize_path(raw_path)
        if path is None:
            invalid.append(raw_path)
            continue

        normalized.append(path)
        if is_release_policy_path(path):
            release_policy.append(path)
        elif is_rpc_docs_path(path):
            rpc_docs.append(path)
        elif is_public_docs_path(path):
            public_docs.append(path)
        elif is_github_metadata_path(path):
            github_metadata.append(path)
        else:
            outside.append(path)

    return Classification(
        paths=tuple(normalized),
        invalid_paths=tuple(invalid),
        release_policy_paths=tuple(release_policy),
        rpc_docs_paths=tuple(rpc_docs),
        public_docs_paths=tuple(public_docs),
        github_metadata_paths=tuple(github_metadata),
        outside_paths=tuple(outside),
    )


def load_changed_files(path: str) -> list[str]:
    with open(path, encoding="utf8") as file:
        return file.read().splitlines()


def bool_output(value: bool) -> str:
    return "true" if value else "false"


def github_outputs(classification: Classification) -> dict[str, str]:
    paths = classification.paths
    return {
        "profile": classification.profile,
        "release_policy_only": bool_output(classification.release_policy_only),
        "rpc_docs_only": bool_output(classification.rpc_docs_only),
        "public_docs_only": bool_output(classification.public_docs_only),
        "github_metadata_only": bool_output(classification.github_metadata_only),
        "source_validation_required": bool_output(classification.profile == SOURCE_PROFILE),
        "changed_count": str(len(paths)),
        "touched_operator_keys": bool_output(
            any(path.startswith("contrib/keys/operator-keys/") for path in paths)
        ),
        "touched_release_publish": bool_output(
            ".github/workflows/release-publish.yml" in paths
        ),
        "touched_release_validators": bool_output(
            any(path.startswith("ci/release/") for path in paths)
        ),
        "touched_release_trust_docs": bool_output(
            any(RELEASE_TRUST_DOC_RE.fullmatch(path) for path in paths)
        ),
        "touched_rpc_docs": bool_output(bool(classification.rpc_docs_paths)),
        "touched_public_docs": bool_output(bool(classification.public_docs_paths)),
        "touched_github_metadata": bool_output(bool(classification.github_metadata_paths)),
    }


def write_github_output(path: str, values: dict[str, str]) -> None:
    with open(path, "a", encoding="utf8") as file:
        for key, value in values.items():
            file.write(f"{key}={value}\n")


def describe_classification(classification: Classification) -> str:
    lines = [
        f"validation_profile={classification.profile}",
        f"changed_count={len(classification.paths)}",
    ]

    if classification.release_policy_paths:
        lines.append("release_policy_paths:")
        lines.extend(f"  {path}" for path in classification.release_policy_paths)
    if classification.rpc_docs_paths:
        lines.append("rpc_docs_paths:")
        lines.extend(f"  {path}" for path in classification.rpc_docs_paths)
    if classification.public_docs_paths:
        lines.append("public_docs_paths:")
        lines.extend(f"  {path}" for path in classification.public_docs_paths)
    if classification.github_metadata_paths:
        lines.append("github_metadata_paths:")
        lines.extend(f"  {path}" for path in classification.github_metadata_paths)
    if classification.outside_paths:
        lines.append("full_validation_paths:")
        lines.extend(f"  {path}" for path in classification.outside_paths)
    if classification.invalid_paths:
        lines.append("invalid_paths:")
        lines.extend(f"  {path}" for path in classification.invalid_paths)

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-files",
        required=True,
        help="newline-delimited file list from git diff --name-only",
    )
    parser.add_argument(
        "--github-output",
        help="append classifier outputs to the GitHub Actions output file",
    )
    parser.add_argument(
        "--require-profile",
        choices=[
            RELEASE_POLICY_PROFILE,
            RPC_DOCS_PROFILE,
            PUBLIC_DOCS_PROFILE,
            GITHUB_METADATA_PROFILE,
            SOURCE_PROFILE,
        ],
        help="fail unless the changed files classify into this validation profile",
    )
    parser.add_argument(
        "--require-release-policy-only",
        action="store_true",
        help="fail if any changed path is outside the release-policy allowlist",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    classification = classify_paths(load_changed_files(args.changed_files))

    print(describe_classification(classification))

    if args.github_output:
        write_github_output(args.github_output, github_outputs(classification))

    required_profile = args.require_profile
    if args.require_release_policy_only:
        required_profile = RELEASE_POLICY_PROFILE

    if required_profile is not None and classification.profile != required_profile:
        print(
            f"{required_profile} validation requires every changed path to be in "
            f"the {required_profile} allowlist",
            file=sys.stderr,
        )
        for path in classification.invalid_paths + classification.outside_paths:
            print(f"outside allowlist: {path}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
