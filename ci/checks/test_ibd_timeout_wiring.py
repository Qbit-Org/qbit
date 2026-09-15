#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests that the IBD perf workflow forwards its timeout inputs to the harness.

The workflow's ``Run IBD lanes`` step sources ``ci/ibd-perf-lanes.sh``. These
tests execute that helper with bash, capture every harness argv through a
controlled ``python3`` shim, and feed each captured argv to the real harness
parser and ``validate_options``. No numeric rule is asserted here beyond what
the harness itself enforces.

When ``QBIT_IBD_PERF_CONFIGFILE`` points at a built tree's ``test/config.ini``
the tests additionally run tiny real lanes and the real preflight and check the
harness-written report fields. Without it those cases are reported as skipped.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "ci" / "ibd-perf-lanes.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ibd-perf-manual.yml"
CORE_CHECKS = REPO_ROOT / ".github" / "workflows" / "core-checks.yml"
FUNCTIONAL_DIR = REPO_ROOT / "test" / "functional"
SUMMARIZER = REPO_ROOT / "contrib" / "devtools" / "summarize_ibd_perf.py"
REAL_CONFIGFILE = os.environ.get("QBIT_IBD_PERF_CONFIGFILE") or None

REPLAY_SCRIPT = "test/functional/feature_ibd_perf_replay.py"
NETWORK_SCRIPT = "test/functional/feature_ibd_perf_network.py"

# env var -> (harness flag, parsed attribute / report field, harness default, owning lane)
TIMEOUTS: dict[str, tuple[str, str, int, str]] = {
    "REPLAY_TIMEOUT": ("--replay-timeout", "replay_timeout", 3600, "replay"),
    "NETWORK_HEADERS_TIMEOUT": ("--network-headers-timeout", "network_headers_timeout", 600, "network"),
    "NETWORK_TIP_TIMEOUT": ("--network-tip-timeout", "network_tip_timeout", 1800, "network"),
    "NETWORK_IBD_EXIT_TIMEOUT": ("--network-ibd-exit-timeout", "network_ibd_exit_timeout", 600, "network"),
}
NONDEFAULT = {
    "REPLAY_TIMEOUT": "1234",
    "NETWORK_HEADERS_TIMEOUT": "77",
    "NETWORK_TIP_TIMEOUT": "88",
    "NETWORK_IBD_EXIT_TIMEOUT": "99",
}
BELOW_ONE = ["0", "-5"]
MALFORMED = ["abc", "12x", "1e3", "0x10"]
# Python int() strips surrounding whitespace, so the harness accepts this one.
WHITESPACE_ACCEPTED = {" 12": 12}
WORKFLOW_SEQUENCE = "preflight_ibd_timeouts; run_ibd_lanes"

RECORD_SEPARATOR = "\x1e"

# Records "$@" NUL-separated plus a record separator, counts calls, and exits
# nonzero only on the requested call so exit propagation can be observed.
SHIM = """#!/bin/sh
count_file="$ARGV_CAPTURE.count"
n=$(cat "$count_file" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$count_file"
printf '%s\\0' "$@" >> "$ARGV_CAPTURE"
printf '\\036' >> "$ARGV_CAPTURE"
if [ -n "${SHIM_EXIT_ON_CALL:-}" ] && [ "$n" -eq "$SHIM_EXIT_ON_CALL" ]; then
  exit "$SHIM_EXIT"
fi
exit 0
"""


@dataclass
class HelperRun:
    returncode: int
    stdout: str
    stderr: str
    argvs: list[list[str]]
    artifact_root: Path
    env: dict[str, str]


@dataclass
class ParseResult:
    exit_code: int
    message: str = ""
    options: Any = None
    warnings: list[str] = field(default_factory=list)


def lane_of(argv: list[str]) -> str:
    """Captured argv holds the harness arguments, i.e. everything after the interpreter."""
    if argv[0] == REPLAY_SCRIPT:
        return "replay"
    if argv[0] == NETWORK_SCRIPT:
        return "network"
    raise AssertionError(f"unexpected harness script in argv: {argv}")


def is_preflight(argv: list[str]) -> bool:
    return "--test_methods" in argv


def write_scratch_config(build_dir: Path) -> Path:
    """A config.ini the parser accepts; BUILDDIR holds no binaries on purpose."""
    config = build_dir / "test" / "config.ini"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "[environment]\n"
        f"SRCDIR={REPO_ROOT}\n"
        f"BUILDDIR={build_dir}\n"
        "EXEEXT=\n"
        f"RPCAUTH={REPO_ROOT / 'share' / 'rpcauth' / 'rpcauth.py'}\n"
        "\n[components]\n",
        encoding="utf-8",
    )
    return config


class IBDTimeoutWiringTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="ibd-timeout-wiring-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.shim_dir = self.tmp / "shim"
        self.shim_dir.mkdir()
        shim = self.shim_dir / "python3"
        shim.write_text(SHIM, encoding="utf-8")
        shim.chmod(0o755)
        self.real_python_dir = self.tmp / "real-python"
        self.real_python_dir.mkdir()
        (self.real_python_dir / "python3").symlink_to(sys.executable)
        if REAL_CONFIGFILE:
            self.configfile = Path(REAL_CONFIGFILE).resolve()
            self.build_dir = self.configfile.parent.parent
        else:
            self.build_dir = self.tmp / "scratch-build"
            self.configfile = write_scratch_config(self.build_dir)
        self.assertEqual(self.configfile, self.build_dir / "test" / "config.ini")
        if str(FUNCTIONAL_DIR) not in sys.path:
            sys.path.insert(0, str(FUNCTIONAL_DIR))
        self.run_counter = 0

    # -- executing the actual helper -------------------------------------------------

    def base_env(self, artifact_root: Path, real_python: bool) -> dict[str, str]:
        # A fixed, closed environment: the workflow job env is the only source
        # of these variables and nothing from the host may leak into the run.
        path_dir = self.real_python_dir if real_python else self.shim_dir
        env = {
            "PATH": f"{path_dir}:/usr/bin:/bin",
            "PERF_BUILD_DIR": str(self.build_dir),
            "PERF_ARTIFACT_ROOT": str(artifact_root),
            "BLOCKS": "1",
            "TAIL_BLOCKS": "0",
            "RUNS_PER_LANE": "1",
            "TXS_PER_BLOCK": "1",
            "P2MR_SPENDS_PER_BLOCK": "1",
            "TRACE_THRESHOLD_MS": "25",
            "FASTPRUNE": "false",
            "ENABLE_TRACING": "false",
            "ENABLE_REPLAY_LANES": "true",
            "ENABLE_NETWORK_IBD": "true",
        }
        for name in TIMEOUTS:
            env[name] = ""
        if real_python:
            # The real harness writes node data below a tmpdir and the
            # interpreter may need HOME; nothing else is passed through.
            for name in ("HOME", "TMPDIR"):
                value = os.environ.get(name)
                if value:
                    env[name] = value
        return env

    def run_helper(
        self,
        commands: str,
        overrides: dict[str, str],
        *,
        real_python: bool = False,
        shim_exit: int | None = None,
        shim_exit_on_call: int | None = None,
        timeout: int = 1800,
    ) -> HelperRun:
        self.run_counter += 1
        artifact_root = self.tmp / f"artifacts-{self.run_counter}"
        for sub in ("bench", "replay", "network", "summary"):
            (artifact_root / sub).mkdir(parents=True)
        capture = self.tmp / f"argv-{self.run_counter}"
        env = self.base_env(artifact_root, real_python)
        env.update(overrides)
        env["ARGV_CAPTURE"] = str(capture)
        if shim_exit is not None:
            env["SHIM_EXIT"] = str(shim_exit)
            env["SHIM_EXIT_ON_CALL"] = str(shim_exit_on_call or 1)
        proc = subprocess.run(
            ["bash", "-c", f"set -euo pipefail; source {HELPER.relative_to(REPO_ROOT)}; {commands}"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        argvs: list[list[str]] = []
        if capture.exists():
            for record in capture.read_text(encoding="utf-8").split(RECORD_SEPARATOR):
                if record:
                    argvs.append(record.split("\0")[:-1])
        return HelperRun(proc.returncode, proc.stdout, proc.stderr, argvs, artifact_root, env)

    # -- feeding captured argv to the real parser ----------------------------------------

    def parse_with_harness(self, argv: list[str]) -> ParseResult:
        """Instantiate the real harness class on the captured argv and run validate_options.

        This is the campaign's own code path (``__init__`` -> ``parse_args``,
        then ``validate_options``) minus ``setup()``; no node is started.
        """
        script = REPO_ROOT / argv[0]
        module = importlib.import_module(script.stem)
        cls = {
            "replay": getattr(module, "IBDPerfReplayTest", None),
            "network": getattr(module, "IBDPerfNetworkTest", None),
        }[lane_of(argv)]
        self.assertIsNotNone(cls)
        saved_argv = sys.argv
        sys.argv = [str(script), *argv[1:]]
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                instance = cls(str(script))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            return ParseResult(code, stderr.getvalue())
        finally:
            sys.argv = saved_argv
        try:
            instance.validate_options()
        except AssertionError as exc:
            return ParseResult(1, str(exc), instance.options)
        return ParseResult(0, "", instance.options)

    def assert_parsed(self, argv: list[str], expected: dict[str, int]) -> None:
        result = self.parse_with_harness(argv)
        self.assertEqual(result.exit_code, 0, f"{argv}\n{result.message}")
        for attribute, value in expected.items():
            self.assertEqual(getattr(result.options, attribute), value, f"{attribute} in {argv}")

    # -- helpers over captured argv ---------------------------------------------------------

    @staticmethod
    def timeout_tokens(argv: list[str]) -> list[str]:
        return [token for token in argv if token.startswith("--") and "-timeout" in token.partition("=")[0]]

    def lane_argvs(self, run: HelperRun, lane: str) -> list[list[str]]:
        return [argv for argv in run.argvs if lane_of(argv) == lane and not is_preflight(argv)]

    def preflight_argvs(self, run: HelperRun, lane: str) -> list[list[str]]:
        return [argv for argv in run.argvs if lane_of(argv) == lane and is_preflight(argv)]

    @staticmethod
    def host_env(run: HelperRun) -> dict[str, str]:
        text = (run.artifact_root / "summary" / "host.env").read_text(encoding="utf-8")
        values: dict[str, str] = {}
        for line in text.splitlines():
            key, _, value = line.partition("=")
            values[key] = value
        return values

    def all_set(self) -> dict[str, str]:
        return dict(NONDEFAULT)

    # ================================================================================
    # Named acceptance tests
    # ================================================================================

    def test_actual_commands_forward_each_timeout(self) -> None:
        run = self.run_helper(WORKFLOW_SEQUENCE, self.all_set())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(all(argv[0] in (REPLAY_SCRIPT, NETWORK_SCRIPT) for argv in run.argvs), run.argvs)

        replay_lanes = self.lane_argvs(run, "replay")
        network_lanes = self.lane_argvs(run, "network")
        self.assertEqual(len(replay_lanes), 6, run.argvs)
        self.assertEqual(len(network_lanes), 1, run.argvs)
        self.assertEqual(len(self.preflight_argvs(run, "replay")), 1)
        self.assertEqual(len(self.preflight_argvs(run, "network")), 1)
        self.assertEqual(len(run.argvs), 9)

        for argv in replay_lanes + self.preflight_argvs(run, "replay"):
            self.assertEqual(self.timeout_tokens(argv), ["--replay-timeout=1234"], argv)
            self.assert_parsed(argv, {"replay_timeout": 1234})
        for argv in network_lanes + self.preflight_argvs(run, "network"):
            self.assertEqual(
                self.timeout_tokens(argv),
                ["--network-headers-timeout=77", "--network-tip-timeout=88", "--network-ibd-exit-timeout=99"],
                argv,
            )
            self.assert_parsed(
                argv,
                {"network_headers_timeout": 77, "network_tip_timeout": 88, "network_ibd_exit_timeout": 99},
            )
        for argv in run.argvs:
            # Every value is one --flag=value token, never a separate word.
            for token in self.timeout_tokens(argv):
                self.assertIn("=", token)
                self.assertNotIn(" ", token)

        # Each input is forwarded independently: setting only one variable
        # must add exactly that flag and nothing else.
        for name, (flag, attribute, _default, lane) in TIMEOUTS.items():
            single = self.run_helper(WORKFLOW_SEQUENCE, {name: NONDEFAULT[name]})
            self.assertEqual(single.returncode, 0, single.stderr)
            for argv in single.argvs:
                if lane_of(argv) == lane:
                    self.assertEqual(self.timeout_tokens(argv), [f"{flag}={NONDEFAULT[name]}"], argv)
                    self.assert_parsed(argv, {attribute: int(NONDEFAULT[name])})
                else:
                    self.assertEqual(self.timeout_tokens(argv), [], argv)
            other_lane = "network" if lane == "replay" else "replay"
            self.assertEqual(self.preflight_argvs(single, other_lane), [], single.argvs)

    def test_blank_and_invalid_values_propagate(self) -> None:
        # Blank omits the flag and the harness defaults remain.
        blank = self.run_helper(WORKFLOW_SEQUENCE, {})
        self.assertEqual(blank.returncode, 0, blank.stderr)
        self.assertEqual(len(blank.argvs), 7, "a blank request must not trigger a preflight")
        for argv in blank.argvs:
            self.assertEqual(self.timeout_tokens(argv), [], argv)
            defaults = {
                attribute: default
                for _flag, attribute, default, lane in TIMEOUTS.values()
                if lane == lane_of(argv)
            }
            self.assert_parsed(argv, defaults)

        # A nonempty value is never dropped or rewritten by the shell: it reaches
        # the harness verbatim as one token and the harness decides.
        for name, (flag, attribute, _default, lane) in TIMEOUTS.items():
            for value in BELOW_ONE + MALFORMED + list(WHITESPACE_ACCEPTED):
                run = self.run_helper(WORKFLOW_SEQUENCE, {name: value})
                self.assertEqual(run.returncode, 0, run.stderr)
                argvs = [argv for argv in run.argvs if lane_of(argv) == lane]
                self.assertTrue(argvs)
                for argv in argvs:
                    self.assertEqual(self.timeout_tokens(argv), [f"{flag}={value}"], argv)
                    result = self.parse_with_harness(argv)
                    if value in WHITESPACE_ACCEPTED:
                        self.assertEqual(result.exit_code, 0, (value, argv, result.message))
                        self.assertEqual(getattr(result.options, attribute), WHITESPACE_ACCEPTED[value])
                    elif value in BELOW_ONE:
                        self.assertEqual(result.exit_code, 1, (value, argv))
                        self.assertEqual(result.message, f"{flag} must be at least 1")
                    else:
                        self.assertEqual(result.exit_code, 2, (value, argv))
                        self.assertIn(f"argument {flag}: invalid int value", result.message)
            # An empty value handed to the parser fails, which is why the helper
            # must omit the flag for a blank request rather than forward it.
            base = next(argv for argv in blank.argvs if lane_of(argv) == lane)
            empty = self.parse_with_harness([*base, f"{flag}="])
            self.assertEqual(empty.exit_code, 2, (flag, empty.message))
            self.assertIn(f"argument {flag}: invalid int value: ''", empty.message)

        # A harness exit status stops the sequence unchanged, before later lanes.
        failing = self.run_helper(WORKFLOW_SEQUENCE, self.all_set(), shim_exit=3, shim_exit_on_call=2)
        self.assertEqual(failing.returncode, 3, failing.stderr)
        self.assertEqual(len(failing.argvs), 2)
        lanes_only = self.run_helper("run_ibd_lanes", self.all_set(), shim_exit=3, shim_exit_on_call=2)
        self.assertEqual(lanes_only.returncode, 3, lanes_only.stderr)
        self.assertEqual(len(lanes_only.argvs), 2)

        # The real interpreter and the real argparse: a malformed value fails the
        # preflight with exit 2 before any lane, even when its lane is disabled.
        # argparse rejects the value before setup(), so this needs no build.
        for name, (flag, _attribute, _default, lane) in TIMEOUTS.items():
            disabled = "ENABLE_REPLAY_LANES" if lane == "replay" else "ENABLE_NETWORK_IBD"
            run = self.run_helper(
                WORKFLOW_SEQUENCE,
                {name: "abc", disabled: "false"},
                real_python=True,
            )
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertIn(f"argument {flag}: invalid int value: 'abc'", run.stderr)
            self.assertIn("preflight", run.stdout)
            self.assertNotIn("=== replay ", run.stdout)
            self.assertNotIn("=== network ", run.stdout)
            self.assertFalse(list((run.artifact_root / "replay").iterdir()))
            self.assertFalse(list((run.artifact_root / "network").iterdir()))

    def test_requested_and_effective_evidence_are_distinct(self) -> None:
        evidence = f"{WORKFLOW_SEQUENCE}; write_ibd_timeout_evidence > \"$PERF_ARTIFACT_ROOT/summary/host.env\""

        # Replay lane disabled but a replay timeout requested.
        run = self.run_helper(evidence, {"ENABLE_REPLAY_LANES": "false", "REPLAY_TIMEOUT": "1234"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.lane_argvs(run, "replay"), [])
        self.assertEqual(len(self.preflight_argvs(run, "replay")), 1, "a request is still validated")
        network = self.lane_argvs(run, "network")
        self.assertEqual(len(network), 1)
        self.assertEqual(self.timeout_tokens(network[0]), [])
        host_env = self.host_env(run)
        self.assertEqual(host_env["replay_timeout"], "1234")
        self.assertEqual(host_env["replay_timeout_forwarded"], "false")
        self.assertEqual(host_env["replay_timeout_forwarded_reason"], "lane-disabled")
        for key in ("network_headers_timeout", "network_tip_timeout", "network_ibd_exit_timeout"):
            self.assertEqual(host_env[key], "")
            self.assertEqual(host_env[f"{key}_forwarded"], "false")
            self.assertEqual(host_env[f"{key}_forwarded_reason"], "blank")
        self.assertNotIn("effective", "\n".join(host_env))
        self.assertFalse(list((run.artifact_root / "replay").iterdir()), "no lane ran, so no report")
        self.assertFalse(list((run.artifact_root / "network").iterdir()))

        # The summarizer exposes the request and its marker, with no lane summary
        # that could be read as an applied setting.
        proc = subprocess.run(
            [sys.executable, str(SUMMARIZER), str(run.artifact_root)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(
            (run.artifact_root / "summary" / "ibd-baseline-summary.json").read_text(encoding="utf-8")
        )
        metadata_env = summary["metadata"]["host_env"]
        self.assertEqual(metadata_env["replay_timeout"], "1234")
        self.assertEqual(metadata_env["replay_timeout_forwarded"], "false")
        self.assertEqual(metadata_env["replay_timeout_forwarded_reason"], "lane-disabled")
        self.assertEqual(summary["replay"], [])
        self.assertEqual(summary["network"], [])

        # The markers mirror what the command builder actually appended.
        for overrides, expected_forwarded in (
            (self.all_set(), True),
            ({}, False),
            ({**self.all_set(), "ENABLE_NETWORK_IBD": "false"}, None),
        ):
            run = self.run_helper(evidence, overrides)
            self.assertEqual(run.returncode, 0, run.stderr)
            host_env = self.host_env(run)
            for name, (flag, key, _default, lane) in TIMEOUTS.items():
                lanes = self.lane_argvs(run, lane)
                forwarded = bool(lanes) and all(
                    any(token.startswith(f"{flag}=") for token in argv) for argv in lanes
                )
                self.assertEqual(host_env[key], overrides.get(name, ""))
                self.assertEqual(host_env[f"{key}_forwarded"], "true" if forwarded else "false", (overrides, key))
                if expected_forwarded is not None:
                    self.assertEqual(forwarded, expected_forwarded, (overrides, key))
                reason = host_env[f"{key}_forwarded_reason"]
                if not overrides.get(name, ""):
                    self.assertEqual(reason, "blank")
                elif not lanes:
                    self.assertEqual(reason, "lane-disabled")
                else:
                    self.assertEqual(reason, "forwarded")

    # ================================================================================
    # Workflow wiring
    # ================================================================================

    def test_workflow_sources_helper_and_calls_entry_points(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        sourced = [line.strip() for line in text.splitlines() if line.strip().startswith("source ")]
        self.assertTrue(sourced, "the workflow must source the helper")
        self.assertEqual(set(sourced), {"source ci/ibd-perf-lanes.sh"})
        self.assertNotIn("feature_ibd_perf_replay.py", text, "the workflow must not carry a second command builder")
        self.assertNotIn("feature_ibd_perf_network.py", text)
        self.assertNotIn("cmd+=", text)

        marker = "      - name: Run IBD lanes\n        run: |\n"
        start = text.index(marker) + len(marker)
        end = text.index("      - name:", start)
        body = [line.strip() for line in text[start:end].splitlines() if line.strip()]
        self.assertEqual(
            body,
            [
                "set -euo pipefail",
                "ulimit -n 10240",
                "source ci/ibd-perf-lanes.sh",
                "preflight_ibd_timeouts",
                "run_ibd_lanes",
            ],
        )

        metadata_marker = "      - name: Capture host metadata\n"
        metadata_start = text.index(metadata_marker)
        metadata_end = text.index("      - name:", metadata_start + len(metadata_marker))
        metadata = text[metadata_start:metadata_end]
        metadata_lines = [line.strip() for line in metadata.splitlines()]
        # The evidence writer must run inside the command group whose output is
        # redirected into host.env, after the helper is sourced, and nowhere
        # else in the step; otherwise the markers never reach host.env.
        group_end = '} > "$PERF_ARTIFACT_ROOT/summary/host.env"'
        self.assertIn(group_end, metadata_lines)
        host_env_group = metadata_lines[: metadata_lines.index(group_end)]
        self.assertIn("source ci/ibd-perf-lanes.sh", host_env_group)
        self.assertIn("write_ibd_timeout_evidence", host_env_group)
        self.assertLess(
            host_env_group.index("source ci/ibd-perf-lanes.sh"),
            host_env_group.index("write_ibd_timeout_evidence"),
        )
        self.assertEqual(metadata_lines.count("write_ibd_timeout_evidence"), 1)
        # The helper is the only writer of any timeout-named host.env line: the
        # workflow may not echo a requested, effective or otherwise-labelled
        # timeout key of its own.
        for line in metadata_lines:
            if line.startswith("echo "):
                self.assertNotIn("timeout", line.lower(), f"timeout evidence must come from the helper only: {line}")

        self.assertIn(
            'QBIT_IBD_PERF_CONFIGFILE="$PERF_BUILD_DIR/test/config.ini" \\\n'
            "            python3 ci/checks/test_ibd_timeout_wiring.py -v\n",
            text,
        )
        self.assertIn("run: python3 ci/checks/test_ibd_timeout_wiring.py\n", CORE_CHECKS.read_text(encoding="utf-8"))

    # ================================================================================
    # Gated on a real build: effective values come only from harness reports
    # ================================================================================

    def require_build(self) -> None:
        if not REAL_CONFIGFILE:
            self.skipTest("QBIT_IBD_PERF_CONFIGFILE is unset; no build to run a real lane against")

    def run_real_lane(self, argv: list[str], tmpdir: Path) -> dict[str, Any]:
        """Run one captured lane argv for real and return the harness-written report."""
        report_file = next(token for token in argv if token.startswith("--report-file="))[len("--report-file="):]
        proc = subprocess.run(
            [sys.executable, *argv, f"--tmpdir={tmpdir}"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=1800,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"{argv}\n{proc.stdout}\n{proc.stderr}")
        report = json.loads(Path(report_file).read_text(encoding="utf-8"))
        print(f"real lane report: {report_file}")
        return report

    def test_real_lanes_report_effective_timeouts(self) -> None:
        self.require_build()
        from test_framework.ibd_perf import validate_network_report_schema, validate_replay_report_schema

        def pick(run: HelperRun) -> tuple[list[str], list[str]]:
            replay = next(
                argv for argv in self.lane_argvs(run, "replay") if "--history-mode=archive" in argv and "--reindex-mode=chainstate" in argv
            )
            network = self.lane_argvs(run, "network")[0]
            return replay, network

        nondefault = self.run_helper(WORKFLOW_SEQUENCE, self.all_set())
        self.assertEqual(nondefault.returncode, 0, nondefault.stderr)
        replay_argv, network_argv = pick(nondefault)
        replay_report = self.run_real_lane(replay_argv, self.tmp / "lane-replay-nondefault")
        validate_replay_report_schema(replay_report)
        self.assertEqual(replay_report["replay_timeout"], 1234)
        network_report = self.run_real_lane(network_argv, self.tmp / "lane-network-nondefault")
        validate_network_report_schema(network_report)
        self.assertEqual(network_report["network_headers_timeout"], 77)
        self.assertEqual(network_report["network_tip_timeout"], 88)
        self.assertEqual(network_report["network_ibd_exit_timeout"], 99)

        omitted = self.run_helper(WORKFLOW_SEQUENCE, {})
        self.assertEqual(omitted.returncode, 0, omitted.stderr)
        replay_argv, network_argv = pick(omitted)
        self.assertEqual(self.timeout_tokens(replay_argv), [])
        self.assertEqual(self.timeout_tokens(network_argv), [])
        replay_report = self.run_real_lane(replay_argv, self.tmp / "lane-replay-omitted")
        validate_replay_report_schema(replay_report)
        self.assertEqual(replay_report["replay_timeout"], 3600)
        network_report = self.run_real_lane(network_argv, self.tmp / "lane-network-omitted")
        validate_network_report_schema(network_report)
        self.assertEqual(network_report["network_headers_timeout"], 600)
        self.assertEqual(network_report["network_tip_timeout"], 1800)
        self.assertEqual(network_report["network_ibd_exit_timeout"], 600)

    def test_real_preflight_uses_harness_validation(self) -> None:
        self.require_build()
        preflight = "preflight_ibd_timeouts"

        valid = self.run_helper(preflight, self.all_set(), real_python=True)
        self.assertEqual(valid.returncode, 0, f"{valid.stdout}\n{valid.stderr}")
        self.assertIn("Method 'validate_options' executed successfully", valid.stdout)
        self.assertFalse(list((valid.artifact_root / "replay").iterdir()), "the preflight writes no report")
        self.assertFalse(list((valid.artifact_root / "network").iterdir()))
        self.assertFalse(list((valid.artifact_root / "summary").iterdir()))

        for name, (flag, _attribute, _default, lane) in TIMEOUTS.items():
            for value in BELOW_ONE:
                disabled = "ENABLE_REPLAY_LANES" if lane == "replay" else "ENABLE_NETWORK_IBD"
                run = self.run_helper(preflight, {name: value, disabled: "false"}, real_python=True)
                self.assertEqual(run.returncode, 1, f"{name}={value}\n{run.stdout}\n{run.stderr}")
                self.assertIn(f"{flag} must be at least 1", run.stdout)
                self.assertFalse(list((run.artifact_root / "replay").iterdir()))
                self.assertFalse(list((run.artifact_root / "network").iterdir()))


if __name__ == "__main__":
    unittest.main()
