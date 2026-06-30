#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for scanner evidence helpers."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_libbitcoinpqc_verify_env_uses_read_token(self) -> None:
        with patch.dict(
            os.environ,
            {"LIBBITCOINPQC_READ_TOKEN": "test-token"},
            clear=False,
        ):
            env = run_scanners.libbitcoinpqc_verify_env()

        self.assertIsNotNone(env)
        assert env is not None
        auth_headers = [
            value
            for key, value in env.items()
            if key.startswith("GIT_CONFIG_VALUE_")
        ]
        self.assertTrue(
            any(value.startswith("AUTHORIZATION: basic ") for value in auth_headers)
        )
        self.assertEqual(run_scanners.LIBBITCOINPQC_PATH, env["LIBBITCOINPQC_PATH"])
        self.assertEqual(
            run_scanners.LIBBITCOINPQC_UPSTREAM_REPO,
            env["LIBBITCOINPQC_REMOTE_URL"],
        )
        self.assertEqual(
            run_scanners.LIBBITCOINPQC_UPSTREAM_TAG,
            env["LIBBITCOINPQC_REMOTE_REF"],
        )

    def test_libbitcoinpqc_verify_env_pins_shell_inputs_without_auth(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LIBBITCOINPQC_READ_TOKEN": "",
                "UPSTREAM_GITHUB_TOKEN": "",
            },
            clear=False,
        ):
            env = run_scanners.libbitcoinpqc_verify_env()

        self.assertEqual(run_scanners.LIBBITCOINPQC_PATH, env["LIBBITCOINPQC_PATH"])
        self.assertEqual(
            run_scanners.LIBBITCOINPQC_UPSTREAM_REPO,
            env["LIBBITCOINPQC_REMOTE_URL"],
        )
        self.assertEqual(
            run_scanners.LIBBITCOINPQC_UPSTREAM_TAG,
            env["LIBBITCOINPQC_REMOTE_REF"],
        )

    def test_libbitcoinpqc_provenance_passes_auth_to_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir)
            verify_script = source / run_scanners.LIBBITCOINPQC_VERIFY_COMMAND[0]
            verify_script.parent.mkdir(parents=True)
            verify_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf8")
            verifier_envs = []

            def fake_run_text_command(command, cwd, env=None):
                verifier_envs.append(env)
                return 0, "", ""

            with (
                patch.dict(
                    os.environ,
                    {"LIBBITCOINPQC_READ_TOKEN": "test-token"},
                    clear=False,
                ),
                patch.object(
                    run_scanners,
                    "git_ls_remote_ref",
                    return_value=("tag-object", 0),
                ),
                patch.object(
                    run_scanners,
                    "latest_git_subtree_metadata",
                    return_value={
                        "git_subtree_split": "commit",
                        "qbit_import_commit": "import",
                    },
                ),
                patch.object(
                    run_scanners,
                    "fetch_libbitcoinpqc_provenance_objects",
                    return_value=([], []),
                ),
                patch.object(run_scanners, "git_peel_commit", return_value="commit"),
                patch.object(run_scanners, "git_tree_for_path", return_value="tree"),
                patch.object(run_scanners, "git_commit_tree", return_value="tree"),
                patch.object(
                    run_scanners,
                    "run_text_command",
                    side_effect=fake_run_text_command,
                ),
            ):
                provenance, gaps = run_scanners.libbitcoinpqc_provenance(source)

        self.assertEqual([], gaps)
        self.assertEqual(0, provenance["verification_exit_code"])
        self.assertEqual(1, len(verifier_envs))
        verifier_env = verifier_envs[0]
        self.assertIsNotNone(verifier_env)
        assert verifier_env is not None
        auth_headers = [
            value
            for key, value in verifier_env.items()
            if key.startswith("GIT_CONFIG_VALUE_")
        ]
        self.assertTrue(
            any(value.startswith("AUTHORIZATION: basic ") for value in auth_headers)
        )
        self.assertEqual(
            run_scanners.LIBBITCOINPQC_UPSTREAM_TAG,
            verifier_env["LIBBITCOINPQC_REMOTE_REF"],
        )

    def test_libbitcoinpqc_provenance_flags_import_tree_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir)
            verify_script = source / run_scanners.LIBBITCOINPQC_VERIFY_COMMAND[0]
            verify_script.parent.mkdir(parents=True)
            verify_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf8")

            def fake_git_tree_for_path(source, relpath, commit="HEAD"):
                return "current-tree" if commit == "HEAD" else "import-tree"

            with (
                patch.object(
                    run_scanners,
                    "git_ls_remote_ref",
                    return_value=("tag-object", 0),
                ),
                patch.object(
                    run_scanners,
                    "latest_git_subtree_metadata",
                    return_value={
                        "git_subtree_split": "commit",
                        "qbit_import_commit": "import",
                    },
                ),
                patch.object(
                    run_scanners,
                    "fetch_libbitcoinpqc_provenance_objects",
                    return_value=([], []),
                ),
                patch.object(run_scanners, "git_peel_commit", return_value="commit"),
                patch.object(
                    run_scanners,
                    "git_tree_for_path",
                    side_effect=fake_git_tree_for_path,
                ),
                patch.object(
                    run_scanners,
                    "git_commit_tree",
                    return_value="current-tree",
                ),
                patch.object(
                    run_scanners,
                    "run_text_command",
                    return_value=(0, "", ""),
                ),
            ):
                provenance, gaps = run_scanners.libbitcoinpqc_provenance(source)

        self.assertEqual("current-tree", provenance["qbit_subtree_tree"])
        self.assertEqual("import-tree", provenance["qbit_import_tree"])
        self.assertEqual("current-tree", provenance["upstream_tag_tree"])
        self.assertIn(
            "libbitcoinpqc subtree tree does not match the recorded qbit import commit tree.",
            gaps,
        )


if __name__ == "__main__":
    unittest.main()
