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


if __name__ == "__main__":
    unittest.main()
