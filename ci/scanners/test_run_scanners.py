#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for scanner evidence helpers."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCANNERS_PATH = REPO_ROOT / "ci/scanners/run-scanners.py"


def load_run_scanners():
    spec = importlib.util.spec_from_file_location("run_scanners", RUN_SCANNERS_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run_scanners = load_run_scanners()


class RunScannersTest(unittest.TestCase):
    def test_ls_remote_ref_oid_accepts_exact_peeled_tag_ref(self) -> None:
        stdout = "ac72d1\trefs/tags/v0.3.0^{}\n456aaf\trefs/tags/v0.3.0\n"

        self.assertEqual(
            run_scanners.ls_remote_ref_oid(stdout, "refs/tags/v0.3.0^{}"),
            "ac72d1",
        )

    def test_ls_remote_ref_oid_accepts_base_ref_for_peeled_query(self) -> None:
        stdout = "ac72d1\trefs/tags/v0.3.0\n"

        self.assertEqual(
            run_scanners.ls_remote_ref_oid(stdout, "refs/tags/v0.3.0^{}"),
            "ac72d1",
        )

    def test_ls_remote_ref_oid_does_not_accept_peeled_ref_for_base_query(self) -> None:
        stdout = "ac72d1\trefs/tags/v0.3.0^{}\n"

        self.assertEqual(
            run_scanners.ls_remote_ref_oid(stdout, "refs/tags/v0.3.0"),
            "",
        )

    def test_git_peel_commit_resolves_annotated_tag_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, check=True)
            subprocess.run(["git", "config", "tag.gpgSign", "false"], cwd=repo, check=True)
            (repo / "file.txt").write_text("content\n", encoding="utf8")
            subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True)
            subprocess.run(["git", "tag", "-a", "v1", "-m", "release"], cwd=repo, check=True)

            tag_object = subprocess.check_output(
                ["git", "rev-parse", "v1"],
                cwd=repo,
                text=True,
                encoding="utf8",
            ).strip()
            commit = subprocess.check_output(
                ["git", "rev-parse", "v1^{}"],
                cwd=repo,
                text=True,
                encoding="utf8",
            ).strip()

            self.assertNotEqual(tag_object, commit)
            self.assertEqual(run_scanners.git_peel_commit(repo, tag_object), commit)


if __name__ == "__main__":
    unittest.main()
