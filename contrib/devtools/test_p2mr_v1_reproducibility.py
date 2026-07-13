#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test exact-byte P2MR v1 reproduction, mutation resistance, and LF checkout policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


CORPUS_FILES = (
    "p2mr_cross_profile_vectors.json",
    "p2mr_pqc_witness_vectors.json",
    "p2mr_script_boundary_vectors.json",
    "p2mr_vectors.json",
)
MANIFEST_FILE = "p2mr_v1_manifest.json"
GENERATED_FILES = (*CORPUS_FILES, MANIFEST_FILE)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level value must be an object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf8")


def differing_files(expected: Path, candidate: Path) -> set[str]:
    return {
        filename
        for filename in GENERATED_FILES
        if (expected / filename).read_bytes() != (candidate / filename).read_bytes()
    }


def mutate_first_case(path: Path) -> None:
    corpus = read_json(path)
    if path.name == "p2mr_vectors.json":
        cases = corpus.get("valid")
    elif path.name == "p2mr_script_boundary_vectors.json":
        cases = corpus.get("cases")
    else:
        cases = corpus.get("vectors")
    if not isinstance(cases, list) or not cases or not isinstance(cases[0], dict):
        raise ValueError(f"{path}: missing first corpus case")
    case_id = cases[0].get("id")
    if not isinstance(case_id, str):
        raise ValueError(f"{path}: first corpus case has no string id")
    cases[0]["id"] = f"{case_id}-mutation-probe"
    write_json(path, corpus)


def manifest_digest(manifest: dict[str, Any], filename: str) -> str:
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError("manifest files must be an array")
    path = f"src/test/data/{filename}"
    for entry in entries:
        if isinstance(entry, dict) and entry.get("path") == path:
            digest = entry.get("sha256")
            if isinstance(digest, str):
                return digest
    raise ValueError(f"manifest has no digest for {path}")


def test_mutation_resistance(repo_root: Path, generated_data: Path) -> None:
    checked_data = repo_root / "src/test/data"
    updater = repo_root / "contrib/devtools/update-p2mr-v1-manifest.py"
    with tempfile.TemporaryDirectory(prefix="p2mr-v1-mutations-") as tmp:
        mutation_root = Path(tmp)
        for filename in CORPUS_FILES:
            candidate_root = mutation_root / filename.removesuffix(".json")
            candidate_data = candidate_root / "src/test/data"
            candidate_data.mkdir(parents=True)
            for copied in GENERATED_FILES:
                shutil.copy2(checked_data / copied, candidate_data / copied)

            mutated_path = candidate_data / filename
            mutate_first_case(mutated_path)
            subprocess.run(
                [
                    updater,
                    "--source-root",
                    candidate_root,
                    "--manifest",
                    "src/test/data/p2mr_v1_manifest.json",
                ],
                check=True,
            )

            candidate_manifest = read_json(candidate_data / MANIFEST_FILE)
            actual_digest = hashlib.sha256(mutated_path.read_bytes()).hexdigest()
            if manifest_digest(candidate_manifest, filename) != actual_digest:
                raise AssertionError(f"manifest did not bless mutation of {filename}")

            differences = differing_files(generated_data, candidate_data)
            expected_differences = {filename, MANIFEST_FILE}
            if differences != expected_differences:
                raise AssertionError(
                    f"mutation of {filename} changed {sorted(differences)}, "
                    f"expected {sorted(expected_differences)}"
                )


def git_env() -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def test_lf_checkout(repo_root: Path) -> None:
    corpus_paths = sorted((repo_root / "src/test/data").glob("p2mr*.json"))
    if not corpus_paths:
        raise AssertionError("no P2MR JSON files found for LF checkout test")
    relative_paths = [path.relative_to(repo_root) for path in corpus_paths]
    env = git_env()
    with tempfile.TemporaryDirectory(prefix="p2mr-v1-lf-") as tmp:
        fixture = Path(tmp) / "fixture"
        checkout = Path(tmp) / "checkout"
        fixture.mkdir()
        shutil.copy2(repo_root / ".gitattributes", fixture / ".gitattributes")
        for source, relative in zip(corpus_paths, relative_paths, strict=True):
            destination = fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        subprocess.run(["git", "init", "--quiet", fixture], check=True, env=env)
        subprocess.run(
            ["git", "-C", fixture, "add", ".gitattributes", *relative_paths],
            check=True,
            env=env,
        )
        subprocess.run(
            [
                "git",
                "-C",
                fixture,
                "-c",
                "user.name=P2MR fixture",
                "-c",
                "user.email=p2mr-fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "p2mr LF fixture",
            ],
            check=True,
            env=env,
        )
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                "-c",
                "core.autocrlf=true",
                fixture,
                checkout,
            ],
            check=True,
            env=env,
        )

        attributes = subprocess.run(
            ["git", "-C", checkout, "check-attr", "text", "eol", "--", *relative_paths],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        ).stdout
        for relative in relative_paths:
            expected = {
                f"{relative}: text: set",
                f"{relative}: eol: lf",
            }
            if not expected.issubset(set(attributes.splitlines())):
                raise AssertionError(f"{relative}: missing text/eol=lf attributes")
            checked_out = (checkout / relative).read_bytes()
            if b"\r" in checked_out:
                raise AssertionError(f"{relative}: CR byte present after autocrlf checkout")
            if checked_out != (repo_root / relative).read_bytes():
                raise AssertionError(f"{relative}: bytes changed after autocrlf checkout")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--generated-data", required=True, type=Path)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    generated_data = args.generated_data.resolve()
    checked_data = repo_root / "src/test/data"

    differences = differing_files(generated_data, checked_data)
    if differences:
        for filename in sorted(differences):
            print(
                f"P2MR v1 corpus is not reproducible: src/test/data/{filename}",
                file=sys.stderr,
            )
        return 1

    test_mutation_resistance(repo_root, generated_data)
    test_lf_checkout(repo_root)
    print("P2MR v1 generated corpus, mutation resistance, and LF checkout are reproducible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
