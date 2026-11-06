#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for scanner evidence helpers."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import string
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
    def test_infra_and_secrets_fails_only_on_an_incomplete_secret_history_scan(self) -> None:
        def summary(tool: str, status: str, gaps: list[str] = [], **details: object) -> dict[str, object]:
            return {
                "tool": tool, "status": status, "high_or_critical_untriaged_count": 0,
                "coverage_gaps": gaps, "details": details,
            }

        complete = summary("gitleaks", "completed", history_scan_complete=True)
        # Informational gaps from other scanners do not fail the policy.
        informational = [
            summary("zizmor", "skipped", ["zizmor is too old for qbit workflow syntax"]),
            summary("clang_static_analyzer", "skipped", ["Build-backed scanner skipped by --skip-build-scanners."]),
        ]
        self.assertFalse(run_scanners.should_fail("infra-and-secrets", [complete, *informational]))
        incomplete = {
            "skipped": summary("gitleaks", "skipped", ["skipped"]),
            "failed": summary("gitleaks", "failed", ["Scanner command exited non-zero"]),
            "missing_tool": summary("gitleaks", "missing_tool", ["Required executable is not on PATH: gitleaks"]),
            "no status": summary("gitleaks", ""),
            "old-Git fallback": summary(
                "gitleaks", "completed", ["merge-only content was not scanned"], history_scan_complete=False
            ),
            "completeness not recorded": summary("gitleaks", "completed"),
        }
        for name, gitleaks in incomplete.items():
            with self.subTest(gitleaks=name):
                self.assertTrue(run_scanners.should_fail("infra-and-secrets", [gitleaks, *informational]))
        self.assertFalse(
            run_scanners.should_fail("infra-only", [incomplete["skipped"], incomplete["old-Git fallback"]])
        )

    def test_zizmor_version_gate_rejects_old_python38_compatible_release(self) -> None:
        self.assertFalse(run_scanners.zizmor_version_supported("zizmor 1.2.0"))

    def test_zizmor_version_gate_accepts_anchor_compatible_release(self) -> None:
        self.assertTrue(run_scanners.zizmor_version_supported("zizmor 1.24.1"))

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
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
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

    def test_cargo_audit_fetches_one_advisory_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            raw_dir = Path(tmp) / "raw"
            for relpath in ("a/Cargo.lock", "b/Cargo.lock"):
                (source / relpath).parent.mkdir(parents=True)
                (source / relpath).write_text("", encoding="utf-8")
            commands, _ = run_scanners.external_commands("cargo_audit", source, raw_dir, object())
        db_args = ["--db", str(raw_dir / "advisory-db")]
        self.assertEqual(len(commands), 2)
        self.assertNotIn("--no-fetch", commands[0])
        self.assertIn("--no-fetch", commands[1])
        for command in commands:
            self.assertEqual(command[command.index("--db"):command.index("--db") + 2], db_args)

    def test_cargo_audit_retries_failed_advisory_fetch(self) -> None:
        attempts = []

        partial_db_seen_on_retry = []

        def fake_run_command(command, raw_dir, index, cwd):
            attempts.append(index)
            raw_dir.mkdir(parents=True, exist_ok=True)
            advisory_db = run_scanners.cargo_audit_advisory_db(raw_dir)
            if attempts.count(0) == 2:
                partial_db_seen_on_retry.append(advisory_db.exists())
            report = {"database": {}, "vulnerabilities": {"list": []}}
            failed_fetch = index == 0 and attempts.count(0) == 1
            if failed_fetch:
                # A failed fetch can leave a partial clone behind.
                advisory_db.mkdir(parents=True, exist_ok=True)
                (advisory_db / "partial").write_text("", encoding="utf-8")
            (raw_dir / f"command-{index}.stdout.txt").write_text(
                "" if failed_fetch else run_scanners.json.dumps(report), encoding="utf-8"
            )
            (raw_dir / f"command-{index}.stderr.txt").write_text(
                "fetch failed\n" if failed_fetch else "", encoding="utf-8"
            )
            return 1 if failed_fetch else 0

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            (source / "a").mkdir(parents=True)
            (source / "a" / "Cargo.lock").write_text("", encoding="utf-8")
            args = run_scanners.argparse.Namespace(
                source=source, skip_build_scanners=False, mode="manual_dry_run",
                source_commit="", freeze_commit="", scanner=["cargo_audit"],
            )
            with patch.object(run_scanners, "run_command", side_effect=fake_run_command), \
                    patch.object(run_scanners.shutil, "which", return_value="/usr/bin/cargo"), \
                    patch.object(run_scanners, "tool_version", return_value="cargo 1.0.0"), \
                    patch.object(run_scanners.time, "sleep"):
                summary = run_scanners.run_scanner("cargo_audit", args, Path(tmp) / "out")
            first_attempt_stderr = next(Path(tmp, "out").rglob("attempt-1.command-0.stderr.txt"))
            self.assertEqual(first_attempt_stderr.read_text(encoding="utf-8"), "fetch failed\n")
        self.assertEqual(attempts, [0, 0])
        self.assertEqual(partial_db_seen_on_retry, [False])
        self.assertEqual(summary["status"], "completed")

    def test_cargo_audit_falls_back_to_own_fetch_after_failed_retries(self) -> None:
        commands_run = []
        # A failed attempt that still printed vulnerabilities must not be counted.
        stray = {"vulnerabilities": {"list": [{"advisory": {"id": "RUSTSEC-0000-0000"}, "package": {}}]}}

        def fake_run_command(command, raw_dir, index, cwd):
            commands_run.append((index, list(command)))
            raw_dir.mkdir(parents=True, exist_ok=True)
            report = {"database": {}, "vulnerabilities": {"list": stray["vulnerabilities"]["list"]}}
            output = stray if index == 0 else report
            (raw_dir / f"command-{index}.stdout.txt").write_text(run_scanners.json.dumps(output), encoding="utf-8")
            (raw_dir / f"command-{index}.stderr.txt").write_text("", encoding="utf-8")
            return 1 if index == 0 else 0

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            for relpath in ("a/Cargo.lock", "b/Cargo.lock"):
                (source / relpath).parent.mkdir(parents=True)
                (source / relpath).write_text("", encoding="utf-8")
            args = run_scanners.argparse.Namespace(
                source=source, skip_build_scanners=False, mode="manual_dry_run",
                source_commit="", freeze_commit="", scanner=["cargo_audit"],
            )
            with patch.object(run_scanners, "run_command", side_effect=fake_run_command), \
                    patch.object(run_scanners.shutil, "which", return_value="/usr/bin/cargo"), \
                    patch.object(run_scanners, "tool_version", return_value="cargo 1.0.0"), \
                    patch.object(run_scanners.time, "sleep"):
                summary = run_scanners.run_scanner("cargo_audit", args, Path(tmp) / "out")
            raw_dir = next(Path(tmp, "out").rglob("attempt-1.command-0.stdout.txt")).parent
            counts = run_scanners.summarize_cargo_audit_outputs(raw_dir)
        indexes = [index for index, _ in commands_run]
        self.assertEqual(indexes, [0] * run_scanners.CARGO_AUDIT_FETCH_ATTEMPTS + [1])
        self.assertNotIn("--no-fetch", commands_run[-1][1])
        # Only the second lockfile's real report counts; output without a
        # report, from the kept attempts or the last one, does not.
        self.assertEqual(sum(counts.values()), 1)
        self.assertEqual(summary["details"]["command_exit_codes"], [1, 0])
        # The first lockfile was never audited: a failure with a gap, not a masked success.
        self.assertEqual(summary["status"], "failed")
        self.assertTrue(any("advisory database" in gap for gap in summary["coverage_gaps"]))
        # The summary records the command that actually ran for the second lockfile.
        self.assertNotIn("--no-fetch", summary["command"].split(" && ")[1])

    def test_clang_static_analyzer_keeps_issues_in_different_files_apart(self) -> None:
        def findings_for(root: Path) -> list[str]:
            source = root / "checkout"
            raw_dir = root / "out" / "raw"
            run_dir = raw_dir / "scan-build" / "run"
            run_dir.mkdir(parents=True)
            for name in ("a.cpp", "b.cpp"):
                diagnostic = {
                    "check_name": "core.NullDereference",
                    "issue_hash_content_of_line_in_context": "same",
                    "location": {"file": 0, "line": 7},
                }
                plist = {"files": [str(source / "src" / name)], "diagnostics": [diagnostic]}
                (run_dir / f"report-{name}.plist").write_bytes(run_scanners.plistlib.dumps(plist))
            for line in (3, 9):
                diagnostic = {"check_name": "core.CallAndMessage", "location": {"file": 0, "line": line}}
                plist = {"files": [str(source / "src" / "c.cpp")], "diagnostics": [diagnostic]}
                (run_dir / f"report-c-{line}.plist").write_bytes(run_scanners.plistlib.dumps(plist))
            # A generated header in the out-of-tree build directory.
            diagnostic = {"check_name": "core.uninitialized.Assign", "location": {"file": 0, "line": 1}}
            plist = {"files": [str(raw_dir / "build" / "gen.h")], "diagnostics": [diagnostic]}
            (run_dir / "report-gen.plist").write_bytes(run_scanners.plistlib.dumps(plist))
            findings = run_scanners.parse_findings("clang_static_analyzer", run_dir, raw_dir, source)
            return sorted(finding["finding_id"] for finding in findings)

        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            first = findings_for(Path(tmp_a))
            second = findings_for(Path(tmp_b))
        self.assertEqual(len(first), 5)
        self.assertEqual(len(set(first)), 5)
        # Identities use paths relative to the source, so they match across checkouts.
        self.assertEqual(first, second)

    def test_clang_static_analyzer_configures_under_scan_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = Path(tmp) / "raw"
            commands, report = run_scanners.external_commands("clang_static_analyzer", Path(tmp), raw_dir, object())
        configure, build = commands
        for command in commands:
            self.assertEqual(command[:3], ["scan-build", "--use-cc=clang", "--use-c++=clang++"])
        self.assertIn("-DWITH_CCACHE=OFF", configure)
        self.assertNotEqual(configure[configure.index("-o") + 1], str(report))
        self.assertEqual(build[build.index("-o") + 1], str(report))
        self.assertIn("-plist-html", build)

    def test_clang_static_analyzer_counts_diagnostics_not_plists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = Path(tmp) / "raw"
            run_dir = raw_dir / "scan-build" / "run"
            run_dir.mkdir(parents=True)
            diagnostic = {"check_name": "core.NullDereference", "issue_hash_content_of_line_in_context": "abc"}
            (run_dir / "report-empty.plist").write_bytes(run_scanners.plistlib.dumps({"diagnostics": []}))
            (run_dir / "report-bug.plist").write_bytes(run_scanners.plistlib.dumps({"diagnostics": [diagnostic]}))
            (run_dir / "report-bad.plist").write_text("not a plist", encoding="utf-8")
            # Cut short mid-write: plistlib raises the XML parser's own error.
            (run_dir / "report-truncated.plist").write_bytes(
                b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>diagnostics</key>'
            )
            # The same header issue reported again from another translation unit.
            (run_dir / "report-bug-again.plist").write_bytes(
                run_scanners.plistlib.dumps({"diagnostics": [diagnostic]})
            )
            other = dict(diagnostic, check_name="core.DivideZero")
            (run_dir / "report-other.plist").write_bytes(run_scanners.plistlib.dumps({"diagnostics": [other]}))
            counts = run_scanners.parse_counts("clang_static_analyzer", run_dir, raw_dir)
            findings = run_scanners.parse_findings("clang_static_analyzer", run_dir, raw_dir)
        self.assertEqual(counts["unknown"], 2)
        self.assertEqual(len(findings), 2)



class LatestGitSubtreeMetadataTest(unittest.TestCase):
    """The scanner reads the subtree split the way the subtree lint does."""

    QUOTED = f"git-subtree-dir: src/libbitcoinpqc\ngit-subtree-split: {'0' * 40}"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        self.git("init", "-q", "-b", "main")
        (self.repo / "README").write_text("qbit\n", encoding="utf8")
        (self.repo / "src" / "libbitcoinpqc").mkdir(parents=True)
        (self.repo / "src" / "libbitcoinpqc" / "lib.c").write_text("int x;\n", encoding="utf8")
        self.git("add", "-A")
        self.split = "1" * 40
        self.git(
            "commit", "-q", "-m", "Squashed 'src/libbitcoinpqc/' content",
            "-m", f"git-subtree-dir: src/libbitcoinpqc\ngit-subtree-split: {self.split}",
        )
        self.import_commit = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def git(self, *args: str) -> str:
        result = subprocess.run(
            [
                "git", "-c", "user.name=scanner test", "-c", "user.email=scanner@example.invalid",
                "-c", "commit.gpgsign=false", "-C", str(self.repo), *args,
            ],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def metadata(self) -> dict:
        return run_scanners.latest_git_subtree_metadata(self.repo, "src/libbitcoinpqc")

    def commit_at(self, date: str, *args: str) -> None:
        env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        subprocess.run(
            [
                "git", "-c", "user.name=scanner test", "-c", "user.email=scanner@example.invalid",
                "-c", "commit.gpgsign=false", "-C", str(self.repo), *args,
            ],
            check=True, capture_output=True, text=True, env=env,
        )

    def test_a_skewed_committer_date_does_not_pick_an_older_import(self) -> None:
        # The older import is dated in the future. Walked by date from the
        # merge, it would come before its own descendant.
        older, newer = "2" * 40, "3" * 40
        self.commit_at(
            "2035-01-01T00:00:00Z", "commit", "-q", "--allow-empty", "-m", "Squashed older",
            "-m", f"git-subtree-dir: src/libbitcoinpqc\ngit-subtree-split: {older}",
        )
        self.git("checkout", "-q", "-b", "import")
        self.commit_at(
            "2026-01-01T00:00:00Z", "commit", "-q", "--allow-empty", "-m", "Squashed newer",
            "-m", f"git-subtree-dir: src/libbitcoinpqc\ngit-subtree-split: {newer}",
        )
        self.git("checkout", "-q", "main")
        self.commit_at("2026-01-02T00:00:00Z", "commit", "-q", "--allow-empty", "-m", "main moved on")
        self.commit_at("2026-01-03T00:00:00Z", "merge", "-q", "--no-ff", "-m", "Merge pull request #2", "import")
        self.assertEqual(self.metadata()["git_subtree_split"], newer)

    def test_ignores_a_merge_commit_that_quotes_the_trailer(self) -> None:
        self.git("checkout", "-q", "-b", "topic")
        (self.repo / "notes.txt").write_text("notes\n", encoding="utf8")
        self.git("add", "notes.txt")
        self.git("commit", "-q", "-m", "notes")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "-m", "Merge pull request #1", "-m", self.QUOTED, "topic")
        self.assertEqual(self.metadata()["qbit_import_commit"], self.import_commit)
        self.assertEqual(self.metadata()["git_subtree_split"], self.split)

    def test_finds_an_import_commit_that_only_moves_the_split(self) -> None:
        moved = "2" * 40
        self.git(
            "commit", "-q", "--allow-empty", "-m", "Squashed 'src/libbitcoinpqc/' changes",
            "-m", f"git-subtree-dir: src/libbitcoinpqc\ngit-subtree-split: {moved}",
        )
        self.assertEqual(self.metadata()["git_subtree_split"], moved)

    def test_a_non_merge_commit_that_quotes_the_trailer_is_reported(self) -> None:
        # Its split matches no release, so the subtree check fails closed.
        (self.repo / "README").write_text("docs\n", encoding="utf8")
        self.git("add", "README")
        self.git("commit", "-q", "-m", "doc: describe the import", "-m", self.QUOTED)
        self.assertEqual(self.metadata()["git_subtree_split"], "0" * 40)



class HistoryLogOptsTest(unittest.TestCase):
    """The history secret scan sees merge-only changes once, without duplicates."""

    PR_TOKEN = "PR_COMMIT_TOKEN"
    EVIL_TOKEN = "ONLY_IN_MERGE_TOKEN"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        self.git("init", "-q", "-b", "main")
        self.commit_file("a.txt", "base", "base")
        self.base = self.git("rev-parse", "HEAD")
        # A pull request commit with a token, merged by a clean merge commit.
        self.git("checkout", "-q", "-b", "pr")
        self.commit_file("pr.txt", self.PR_TOKEN, "pull request commit")
        self.pr_commit = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "main")
        self.commit_file("m.txt", "main moves", "main moves")
        self.git("merge", "-q", "--no-ff", "-m", "Merge pull request #1", "pr")
        self.pr_merge = self.git("rev-parse", "HEAD")
        # An evil merge: a token that exists only in the merge commit.
        self.git("checkout", "-q", "-b", "topic")
        self.commit_file("b.txt", "topic", "topic")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "--no-commit", "topic")
        (self.repo / "c.txt").write_text(f"{self.EVIL_TOKEN}\n", encoding="utf8")
        self.git("add", "c.txt")
        self.git("commit", "-q", "-m", "Merge pull request #2")
        self.evil_merge = self.git("rev-parse", "HEAD")
        # A clean upstream-style merge with no token.
        self.git("checkout", "-q", "-b", "upstream")
        self.commit_file("u.txt", "upstream", "upstream")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "-m", "Merge upstream", "upstream")
        self.clean_merge = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def git(self, *args: str) -> str:
        result = subprocess.run(
            [
                "git", "-c", "user.name=scanner test", "-c", "user.email=scanner@example.invalid",
                "-c", "commit.gpgsign=false", "-C", str(self.repo), *args,
            ],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def commit_file(self, path: str, content: str, message: str) -> None:
        (self.repo / path).write_text(f"{content}\n", encoding="utf8")
        self.git("add", path)
        self.git("commit", "-q", "-m", message)

    def added_lines_by_commit(self, log_opts: str) -> dict[str, str]:
        """Run the git log that gitleaks runs and map each commit to its added lines."""
        output = self.git("log", "-p", "-U0", "--format=@@COMMIT %H", *log_opts.split())
        added: dict[str, str] = {}
        commit = ""
        for line in output.splitlines():
            if line.startswith("@@COMMIT "):
                commit = line.split()[1]
                added[commit] = ""
            elif line.startswith("+") and not line.startswith("+++"):
                added[commit] += line[1:] + "\n"
        return added

    def commits_reporting(self, token: str, log_opts: str) -> list[str]:
        return [c for c, lines in self.added_lines_by_commit(log_opts).items() if token in lines]

    def args(self, base_ref: str) -> object:
        return type("Args", (), {"history_diff_base_ref": base_ref, "source_commit": self.clean_merge})()

    def full_history_opts(self) -> str:
        return run_scanners.history_log_opts(self.repo, self.args(""))

    def test_full_history_log_opts(self) -> None:
        self.assertEqual(
            self.full_history_opts(), "--full-history --all --diff-filter=tuxdb --remerge-diff"
        )

    def test_ranged_log_opts(self) -> None:
        self.assertEqual(
            run_scanners.history_log_opts(self.repo, self.args(self.base)),
            f"--diff-filter=tuxdb --remerge-diff {self.base}..{self.clean_merge}",
        )

    def test_log_opts_without_remerge_diff_keep_the_rest(self) -> None:
        self.assertEqual(
            run_scanners.history_log_opts(self.repo, self.args(""), remerge_diff=False),
            "--full-history --all --diff-filter=tuxdb",
        )
        self.assertEqual(
            run_scanners.history_log_opts(self.repo, self.args(self.base), remerge_diff=False),
            f"--diff-filter=tuxdb {self.base}..{self.clean_merge}",
        )

    def test_pull_request_secret_is_reported_once_on_its_own_commit(self) -> None:
        self.assertEqual(self.commits_reporting(self.PR_TOKEN, self.full_history_opts()), [self.pr_commit])

    def test_evil_merge_secret_is_reported_on_the_merge(self) -> None:
        self.assertEqual(self.commits_reporting(self.EVIL_TOKEN, self.full_history_opts()), [self.evil_merge])

    def test_clean_merges_add_no_lines(self) -> None:
        # A merge with an empty remerge diff adds no lines; with --diff-filter,
        # git log does not list it at all.
        added = self.added_lines_by_commit(self.full_history_opts())
        self.assertEqual(added.get(self.clean_merge, ""), "")
        self.assertEqual(added.get(self.pr_merge, ""), "")

    def test_ranged_scan_covers_every_parent(self) -> None:
        log_opts = run_scanners.history_log_opts(self.repo, self.args(self.base))
        self.assertEqual(self.commits_reporting(self.PR_TOKEN, log_opts), [self.pr_commit])
        self.assertEqual(self.commits_reporting(self.EVIL_TOKEN, log_opts), [self.evil_merge])

    def test_plain_git_log_misses_the_evil_merge(self) -> None:
        self.assertEqual(self.commits_reporting(self.EVIL_TOKEN, "--full-history --all"), [])

    def test_gitleaks_command_always_passes_log_opts(self) -> None:
        raw_dir = self.repo / "raw"
        commands, _report = run_scanners.external_commands("gitleaks", self.repo, raw_dir, self.args(""))
        command = commands[0]
        self.assertEqual(
            command[command.index("--log-opts") + 1],
            "--full-history --all --diff-filter=tuxdb --remerge-diff",
        )

    def with_git_version(self, output: str, exit_code: int = 0):
        real = run_scanners.git_command

        def fake(source, *args):
            if args == ("version",):
                return exit_code, output, ""
            return real(source, *args)

        return patch.object(run_scanners, "git_command", fake)

    def test_old_or_unknown_git_is_a_coverage_gap(self) -> None:
        for output, code in (
            ("git version 2.35.1\n", 0),
            ("git version 1.9.5\n", 0),
            ("not git\n", 0),
            ("", 127),
        ):
            with self.subTest(output=output, code=code), self.with_git_version(output, code):
                gap = run_scanners.remerge_diff_git_gap(self.repo)
                self.assertIn("without --remerge-diff, which needs Git 2.36 or later", gap)
                self.assertIn("content changed only in merge commits was not scanned", gap)
                self.assertIn(output.strip() or "git version exited 127", gap)

    def test_git_2_36_is_enough(self) -> None:
        with self.with_git_version("git version 2.36.0\n"):
            self.assertEqual(run_scanners.remerge_diff_git_gap(self.repo), "")

    def run_fake_gitleaks(self, git_version: str, source: Path | None = None) -> tuple[dict, list[str]]:
        bin_dir = self.repo / "fake-bin"
        bin_dir.mkdir()
        fake = bin_dir / "gitleaks"
        argv_log = self.repo / "gitleaks-argv"
        fake.write_text(
            "#!/bin/sh\n"
            '[ "$1" = detect ] || { echo 8.30.1; exit 0; }\n'
            f'printf "%s\\n" "$@" > "{argv_log}"\n'
            'while [ $# -gt 0 ]; do [ "$1" = --report-path ] && echo "[]" > "$2"; shift; done\n',
            encoding="utf8",
        )
        fake.chmod(0o755)
        args = argparse.Namespace(
            mode="nightly", source=source or self.repo, source_commit=self.clean_merge,
            freeze_commit=self.clean_merge, history_diff_base_ref="", skip_build_scanners=False,
        )
        output_root = self.repo / "evidence"
        output_root.mkdir()
        path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        with self.with_git_version(git_version), patch.dict(os.environ, {"PATH": path}):
            summary = run_scanners.run_scanner("gitleaks", args, output_root)
        return summary, argv_log.read_text(encoding="utf8").splitlines()

    def shallow_clone(self, depth: int) -> Path:
        parent = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, parent, True)
        clone = parent / "clone"
        subprocess.run(
            ["git", "clone", "-q", f"--depth={depth}", "--branch", "main", f"file://{self.repo}", str(clone)],
            check=True, capture_output=True,
        )
        shallow = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "--is-shallow-repository"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(shallow, "true")
        return clone

    def test_a_shallow_checkout_is_an_incomplete_history_scan(self) -> None:
        clone = self.shallow_clone(depth=2)
        summary, _argv = self.run_fake_gitleaks("git version 2.50.1\n", source=clone)
        self.assertIs(summary["details"]["history_scan_complete"], False)
        self.assertTrue(any("the source checkout is shallow at" in gap for gap in summary["coverage_gaps"]))
        self.assertTrue(run_scanners.should_fail("infra-and-secrets", [summary]))
        # A ranged scan whose range crosses the shallow boundary is cut too.
        gap = run_scanners.shallow_history_gap(clone, [f"{self.evil_merge}..{self.clean_merge}"])
        self.assertIn("could not walk all of it", gap)

    def test_a_shallow_boundary_outside_the_scanned_history_does_not_count(self) -> None:
        # As when the libbitcoinpqc subtree check fetches an upstream tag with
        # --depth=1: the checkout is shallow, but no scanned ref reaches it.
        other = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other, True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(other)], check=True)
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
             "-C", str(other), "commit", "-q", "--allow-empty", "-m", "upstream"],
            check=True,
        )
        self.git("fetch", "-q", "--depth=1", f"file://{other}", "main")
        self.assertEqual(self.git("rev-parse", "--is-shallow-repository"), "true")
        summary, _argv = self.run_fake_gitleaks("git version 2.50.1\n")
        self.assertEqual(summary["coverage_gaps"], [])
        self.assertIs(summary["details"]["history_scan_complete"], True)
        self.assertEqual(run_scanners.shallow_history_gap(self.repo, [f"{self.base}..{self.clean_merge}"]), "")

    def test_an_octopus_merge_is_named_as_a_coverage_gap(self) -> None:
        token = "ONLY_IN_OCTOPUS_TOKEN"
        for branch in ("o1", "o2"):
            self.git("checkout", "-q", "-b", branch, self.clean_merge)
            self.commit_file(f"{branch}.txt", branch, branch)
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "--no-commit", "o1", "o2")
        (self.repo / "octopus.txt").write_text(f"{token}\n", encoding="utf8")
        self.git("add", "octopus.txt")
        self.git("commit", "-q", "-m", "Merge o1 and o2")
        octopus = self.git("rev-parse", "HEAD")
        self.assertEqual(len(self.git("log", "-1", "--format=%P", octopus).split()), 3)
        # --remerge-diff shows nothing for it, so the secret is not scanned.
        self.assertEqual(self.commits_reporting(token, self.full_history_opts()), [])
        summary, _argv = self.run_fake_gitleaks("git version 2.50.1\n")
        self.assertIs(summary["details"]["history_scan_complete"], False)
        self.assertTrue(any(octopus[:12] in gap and "octopus merge" in gap for gap in summary["coverage_gaps"]))
        self.assertTrue(run_scanners.should_fail("infra-and-secrets", [summary]))

    def test_current_git_scans_merges_and_passes_the_policy(self) -> None:
        summary, argv = self.run_fake_gitleaks("git version 2.50.1\n")
        self.assertEqual(argv[argv.index("--log-opts") + 1], "--full-history --all --diff-filter=tuxdb --remerge-diff")
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["coverage_gaps"], [])
        self.assertIs(summary["details"]["history_scan_complete"], True)
        self.assertFalse(run_scanners.should_fail("infra-and-secrets", [summary]))

    def test_old_git_scans_without_remerge_diff_and_records_the_gap(self) -> None:
        summary, argv = self.run_fake_gitleaks("git version 2.35.1\n")
        self.assertEqual(argv[argv.index("--log-opts") + 1], "--full-history --all --diff-filter=tuxdb")
        self.assertEqual(summary["status"], "completed")
        self.assertIs(summary["details"]["history_scan_complete"], False)
        self.assertEqual(len(summary["coverage_gaps"]), 1)
        self.assertIn("merge commits was not scanned", summary["coverage_gaps"][0])
        self.assertIn("git version 2.35.1", summary["coverage_gaps"][0])
        self.assertTrue(run_scanners.should_fail("infra-and-secrets", [summary]))
        self.assertFalse(run_scanners.should_fail("infra-only", [summary]))



@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is not on PATH")
class GitleaksRemergeIntegrationTest(unittest.TestCase):
    """Run the real gitleaks with the scanner's own command on conflicted merges."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.write("a.txt", "base")
        self.write("conf.txt", "shared = 1")
        self.write("del.txt", "keep")
        self.commit("base")
        self.base = self.git("rev-parse", "HEAD")
        # A pull request commit with a secret, merged cleanly.
        self.git("checkout", "-q", "-b", "pr")
        self.write("pr.txt", f'token = "{self.token()}"')
        self.commit("pull request commit with a secret")
        self.pr_commit = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "-m", "Merge pull request #1", "pr")
        # A conflicted merge whose resolution adds a secret (remerge CONFLICT
        # header plus a hunk).
        self.git("checkout", "-q", "-b", "topic")
        self.write("conf.txt", "shared = topic")
        self.commit("topic edits conf")
        self.git("checkout", "-q", "main")
        self.write("conf.txt", "shared = main")
        self.commit("main edits conf")
        self.git("merge", "-q", "--no-ff", "topic", check=False)
        self.write("conf.txt", f'shared = resolved\ntoken = "{self.token()}"')
        self.commit("Merge pull request #2 (conflict resolved with a secret)")
        self.evil_merge = self.git("rev-parse", "HEAD")
        # A modify/delete conflict resolved by keeping the modified file: its
        # remerge diff has a CONFLICT header and no hunks.
        self.git("checkout", "-q", "-b", "remove")
        self.git("rm", "-q", "del.txt")
        self.commit("topic deletes del.txt")
        self.git("checkout", "-q", "main")
        self.write("del.txt", "keep, edited")
        self.commit("main edits del.txt")
        self.git("merge", "-q", "--no-ff", "remove", check=False)
        self.git("add", "del.txt")
        self.commit("Merge pull request #3 (modify/delete conflict)")
        self.modify_delete_merge = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def git(self, *args: str, check: bool = True) -> str:
        result = subprocess.run(
            [
                "git", "-c", "user.name=scanner test", "-c", "user.email=scanner@example.invalid",
                "-c", "commit.gpgsign=false", "-C", str(self.repo), *args,
            ],
            check=check, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def write(self, path: str, content: str) -> None:
        (self.repo / path).write_text(f"{content}\n", encoding="utf8")

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    @staticmethod
    def token() -> str:
        alphabet = string.ascii_letters + string.digits
        return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))

    def test_merge_only_secret_found_and_pull_request_secret_reported_once(self) -> None:
        remerge = self.git("log", "-1", "-p", "--remerge-diff", self.evil_merge)
        self.assertIn("remerge CONFLICT (content)", remerge)
        no_hunks = self.git("log", "-1", "-p", "--remerge-diff", self.modify_delete_merge)
        self.assertIn("remerge CONFLICT (modify/delete)", no_hunks)
        self.assertNotIn("\n@@", no_hunks)

        args = argparse.Namespace(history_diff_base_ref="", source_commit=self.modify_delete_merge)
        raw_dir = Path(self.temp_dir.name) / "raw"
        raw_dir.mkdir()
        commands, report = run_scanners.external_commands("gitleaks", self.repo, raw_dir, args)
        result = subprocess.run(commands[0], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        findings = json.loads(Path(report).read_text(encoding="utf8"))
        by_commit = sorted((finding["Commit"], finding["File"]) for finding in findings)
        self.assertEqual(
            [commit for commit, _ in by_commit], sorted([self.pr_commit, self.evil_merge])
        )
        files = dict(by_commit)
        self.assertEqual(files[self.pr_commit], "pr.txt")
        # gitleaks 8.30.1 records a finding inside a conflicted file of a
        # remerge diff as b/<path>: the "remerge CONFLICT" line between the
        # diff and index headers changes how it parses the name.
        self.assertIn(files[self.evil_merge], ("conf.txt", "b/conf.txt"))


if __name__ == "__main__":
    unittest.main()
