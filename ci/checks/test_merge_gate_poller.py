#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract tests: how the Required Merge Gate waits for other checks.

The gate's ``wait_for_checks`` loop is the last thing standing between a
merge and the checks it depends on, so infrastructure noise must not be able
to turn it red, and nothing may turn it green while a required check failed,
is absent, or cannot be read.

These tests execute the gate step's **real** ``run:`` script, lifted out of
``.github/workflows/required-merge-gate.yml``, against a stubbed ``gh`` whose
responses and exit codes each test scripts.  The polling logic therefore has
exactly one definition: this file asserts against it and never restates it.
The loop's waiting tunables are read from the same script and overridden per
test, so the production defaults stay the values CI actually uses while the
suite still runs in seconds.

The stub also answers the workflow-run lookups the gate makes to tell which
event produced a failed check (its own run, and the run that owns each failed
check's check suite), so those are exercised by the same real script.

Not provable here: whether the hosted ``Required Merge Gate`` check is
attached to a branch ruleset, and whether the real API agrees with the shapes
modelled below.  The workflow-run shapes and their re-run semantics (a re-run
keeps the run's ``check_suite_id`` and ``created_at`` and moves only
``run_attempt`` and ``run_started_at``) were read from GitHub's REST API
description and checked against this repository's PR #229 on 2026-10-06.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

# The workflow loader, the repository root and the "run this block the way
# GitHub's bash shell does" helper already exist for the classifier contract.
# Reuse them rather than growing a second, divergent copy.
from test_classifier_ci_contract import (  # noqa: E402  sibling module, path-dependent
    GATE_JOB,
    REPO_ROOT,
    WORKFLOW,
    load_workflow,
    run_bash_step,
)

# GitHub-hosted jobs are cancelled at this many minutes, so the wait budget
# cannot be raised to meet a slow validation; it has to fit underneath.
GITHUB_HOSTED_TIMEOUT_MINUTES = 360

# Headroom the gate needs after the deadline to report which checks were still
# pending: one in-flight query per check plus the runner's own bookkeeping.
MIN_TIMEOUT_HEADROOM_SECONDS = 900

# ``NAME="${NAME:-<digits>}"`` — the tunables the loop reads and this suite
# overrides.  A rename must fail the discovery test rather than silently leave
# the overrides inert and the suite running at production speed.
TUNABLE = re.compile(
    r'^\s*(?P<name>GATE_[A-Z_]+)="\$\{(?P=name):-(?P<default>\d+)\}"\s*$',
    re.MULTILINE,
)
OVERRIDDEN_TUNABLES = frozenset(
    {
        "GATE_WAIT_TIMEOUT_SECONDS",
        "GATE_POLL_INTERVAL_SECONDS",
        "GATE_QUERY_MAX_ATTEMPTS",
        "GATE_QUERY_BACKOFF_SECONDS",
        "GATE_QUERY_BACKOFF_CAP_SECONDS",
        "GATE_QUERY_TIMEOUT_SECONDS",
    }
)

# The profiles and the check names each one waits for. Changing which checks a
# profile requires is out of scope for the waiting behaviour, so it is pinned.
PROFILE_CHECKS = {
    "release-policy": ["Core Checks Gate"],
    "rpc-docs": ["rpc-docs"],
    "public-docs": ["public-docs-lint"],
    "source": ["Core Checks Gate", "Full Validation Gate"],
}

ERROR_CHECK_FAILED = "::error title=Required Merge Gate failed::"
ERROR_UNREADABLE = "::error title=Required Merge Gate could not read check runs::"
ERROR_UNCORRELATED = "::error title=Required Merge Gate could not correlate check runs::"
ERROR_TIMED_OUT = "::error title=Required Merge Gate timed out::"
WARNING_RETRYING = "::warning title=Required Merge Gate retrying::"

# The documented allowance between the workflow runs one event creates.
EVENT_SKEW = re.compile(r"^\s*EVENT_SKEW_SECONDS=(?P<seconds>\d+)\s*$", re.MULTILINE)
DOCUMENTED_EVENT_SKEW_SECONDS = 60

# -- the events a commit has seen -------------------------------------------
#
# Every workflow run an event starts is created at that event, and a re-run
# keeps the run's created_at.  The gate's own run (RUN_ID) was created by
# THIS_EVENT unless a test says otherwise.  Check suites, one per workflow run,
# are numbered by event: 1xx earlier, 2xx this one, 3xx a later one.
GATE_RUN_ID = 12345
EARLIER_EVENT = "2026-10-05T20:17:51Z"
THIS_EVENT = "2026-10-06T14:12:00Z"
LATER_EVENT = "2026-10-06T14:40:00Z"
CORE_EARLIER, FULL_EARLIER = 101, 102
CORE_THIS, FULL_THIS, RPC_DOCS_THIS = 201, 202, 203
CORE_LATER = 301
SUITE_CREATED_AT = {
    CORE_EARLIER: EARLIER_EVENT,
    FULL_EARLIER: EARLIER_EVENT,
    CORE_THIS: THIS_EVENT,
    FULL_THIS: THIS_EVENT,
    RPC_DOCS_THIS: THIS_EVENT,
    CORE_LATER: LATER_EVENT,
}

GATE_RUN_PATH = re.escape(f"/actions/runs/{GATE_RUN_ID}") + "$"


def suite_lookup(suite: int) -> str:
    """The route for the lookup of the workflow run that owns ``suite``."""
    return re.escape(f"/actions/runs?check_suite_id={suite}&exclude_pull_requests=true&per_page=100") + "$"


def check_run(
    name: str, status: str, conclusion: str | None = None, *, suite: int | None = None, **stamps: str
) -> dict:
    run = {"name": name, "status": status, "conclusion": conclusion}
    if suite is not None:
        run["check_suite"] = {"id": suite}
    run.update(stamps)
    return run


def workflow_run(run_id: int, suite: int, created_at: str, **fields) -> dict:
    run = {
        "id": run_id,
        "check_suite_id": suite,
        "created_at": created_at,
        "run_started_at": created_at,
        "run_attempt": 1,
    }
    run.update(fields)
    return run


def workflow_runs(*runs: dict) -> str:
    return json.dumps({"total_count": len(runs), "workflow_runs": list(runs)})


def event_routes(
    gate_run: dict | None = None, suites: dict[int, str] | None = None
) -> dict[str, tuple]:
    """Answers for the gate's own run and for the run behind each check suite."""
    routes: dict[str, tuple] = {
        GATE_RUN_PATH: ok(json.dumps(gate_run or workflow_run(GATE_RUN_ID, 999, THIS_EVENT))),
    }
    for suite, created_at in (SUITE_CREATED_AT if suites is None else suites).items():
        routes[suite_lookup(suite)] = ok(workflow_runs(workflow_run(50_000 + suite, suite, created_at)))
    return routes


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def page(*runs: dict) -> dict:
    return {"total_count": len(runs), "check_runs": list(runs)}


def body(*pages: dict) -> str:
    """Concatenated page objects, the way ``gh api --paginate`` emits them."""
    return "".join(json.dumps(item) for item in pages)


def ok(payload: str) -> tuple[int, str]:
    return (0, payload)


class FakeGh:
    """A ``gh`` on PATH that scripts its answers.

    Check-runs queries are answered in order from ``responses``; once those are
    exhausted, ``default`` answers every further one.  ``routes`` answers any
    other call whose arguments match its regular expression, with one reply or
    a list of replies whose last one repeats.  A call nothing answers fails as
    an unscripted call, which ``run_gate`` refuses.  Each reply is
    ``(exit_code, stdout)``, optionally with a third element written to stderr
    the way ``gh`` reports an HTTP error.  ``delay`` makes every call take that
    many seconds, so a test can show the wait deadline counts time spent in the
    API and not only in ``sleep``.
    """

    STUB = """#!/usr/bin/env python3
import json, re, sys, time
from pathlib import Path

state = Path(__file__).resolve().parent
config = json.loads((state / "config.json").read_text(encoding="utf8"))
args = " ".join(sys.argv[1:])
with open(state / "calls", "a", encoding="utf8") as log:
    log.write(args + "\\n")
counts_path = state / "counts.json"
counts = json.loads(counts_path.read_text(encoding="utf8")) if counts_path.exists() else {}
key, replies, fallback = None, [], None
for index, (pattern, route_replies) in enumerate(config["routes"]):
    if re.search(pattern, args):
        key, replies, fallback = f"route-{index}", route_replies, route_replies[-1]
        break
if key is None and "/check-runs" in args:
    key, replies, fallback = "check-runs", config["responses"], config["default"]
served = counts.get(key, 0) if key else 0
reply = replies[served] if served < len(replies) else fallback
if reply is None:
    sys.stderr.write(f"fake gh: unscripted call: {args}\\n")
    sys.exit(97)
counts[key] = served + 1
counts_path.write_text(json.dumps(counts), encoding="utf8")
time.sleep(config["delay"])
sys.stdout.write(reply[1])
sys.stderr.write(reply[2] if len(reply) > 2 and reply[2] else "")
sys.exit(reply[0])
"""

    def __init__(
        self,
        directory: Path,
        *,
        responses: list[tuple] | None = None,
        default: tuple | None = None,
        routes: dict[str, tuple | list[tuple]] | None = None,
        delay: int = 0,
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.calls_path = directory / "calls"
        config = {
            "responses": list(responses or []),
            "default": default,
            "routes": [
                [pattern, list(reply) if isinstance(reply, list) else [reply]]
                for pattern, reply in (routes or {}).items()
            ],
            "delay": delay,
        }
        (directory / "config.json").write_text(json.dumps(config), encoding="utf8")
        script = directory / "gh"
        script.write_text(self.STUB, encoding="utf8")
        script.chmod(0o755)

    @property
    def calls(self) -> list[str]:
        if not self.calls_path.exists():
            return []
        return self.calls_path.read_text(encoding="utf8").splitlines()

    def calls_matching(self, pattern: str) -> list[str]:
        return [call for call in self.calls if re.search(pattern, call)]

    @property
    def check_run_calls(self) -> list[str]:
        return [call for call in self.calls if "/check-runs" in call]

    @property
    def workflow_run_calls(self) -> list[str]:
        return [call for call in self.calls if "/actions/runs" in call]


def load_yaml(path: Path) -> dict:
    import yaml
    from test_classifier_ci_contract import WorkflowLoader  # noqa: E402  keeps "on" a string key
    return yaml.load(path.read_text(encoding="utf8"), Loader=WorkflowLoader)


class MergeGatePollerTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.workflow = load_workflow()
        self.job = self.workflow["jobs"][GATE_JOB]
        matches = [
            step
            for step in self.job["steps"]
            if "wait_for_checks" in str(step.get("run", ""))
        ]
        self.assertEqual(len(matches), 1, "expected exactly one gate step that waits for checks")
        self.step = matches[0]
        self.script = self.step["run"]
        self.assertNotIn("continue-on-error", self.step, "the gate step must not swallow failures")
        self.assertNotIn("shell", self.step, "the gate step must use the workflow default bash shell")
        self.assertIn("set -euo pipefail", self.script)
        self.defaults = {
            match.group("name"): int(match.group("default"))
            for match in TUNABLE.finditer(self.script)
        }
        skews = EVENT_SKEW.findall(self.script)
        self.assertEqual(len(skews), 1, "expected the gate to declare EVENT_SKEW_SECONDS once")
        self.event_skew = int(skews[0])

    # -- helpers -----------------------------------------------------------

    def gate_env(self, fake: FakeGh, profile: str, **overrides: str) -> dict[str, str]:
        """Environment for one gate run, with the stub ahead of the real ``gh``.

        Every key the step declares is set explicitly, so a value this suite
        forgot cannot silently inherit from the developer's shell.  That the
        step's ``env`` really binds those keys to ``needs`` contexts is the
        classifier contract's assertion, not this one's.
        """
        env = {
            "CLASSIFY_CHANGES_RESULT": "success",
            "OPERATOR_KEY_POLICY_VALIDATION_RESULT": "skipped",
            "TOUCHED_OPERATOR_KEYS": "false",
            "VALIDATION_PROFILE": profile,
            "RELEASE_POLICY_VALIDATION_RESULT": "success",
            "RPC_DOCS_VALIDATION_RESULT": "success",
            "PUBLIC_DOCS_VALIDATION_RESULT": "success",
            "GITHUB_METADATA_VALIDATION_RESULT": "success",
            "SOURCE_VALIDATION_REQUIRED": "true",
            "GH_TOKEN": "fake-token",
            "REPOSITORY": "example/repo",
            "SHA": "0" * 40,
            "RUN_ID": str(GATE_RUN_ID),
        }
        declared = set(self.step["env"])
        self.assertFalse(
            declared - set(env),
            f"gate step reads inputs this suite does not model: {sorted(declared - set(env))}",
        )
        # Fast tunables: the loop runs its real logic, just not for hours.
        env.update(
            {
                "GATE_WAIT_TIMEOUT_SECONDS": "30",
                "GATE_POLL_INTERVAL_SECONDS": "1",
                "GATE_QUERY_MAX_ATTEMPTS": "3",
                "GATE_QUERY_BACKOFF_SECONDS": "1",
                "GATE_QUERY_BACKOFF_CAP_SECONDS": "1",
                "GATE_QUERY_TIMEOUT_SECONDS": "10",
            }
        )
        env.update(overrides)
        env["PATH"] = f"{fake.directory}{os.pathsep}{os.environ.get('PATH', '')}"
        env["HOME"] = os.environ.get("HOME", "")
        return env

    def run_gate(self, fake: FakeGh, profile: str = "source", **overrides: str):
        completed = run_bash_step(
            self.script, cwd=REPO_ROOT, env=self.gate_env(fake, profile, **overrides)
        )
        self.assertNotIn("fake gh: unscripted call", completed.stderr + completed.stdout)
        return completed

    def assertGateFailed(self, completed, expected: str, *, forbidden: tuple[str, ...] = ()) -> None:
        output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, f"gate reported success\n{output}")
        self.assertIn(expected, output)
        for other in forbidden:
            self.assertNotIn(other, output)

    # -- the budget --------------------------------------------------------

    def test_tunables_are_declared_with_defaults_the_suite_can_override(self) -> None:
        self.assertEqual(
            OVERRIDDEN_TUNABLES,
            set(self.defaults),
            "the loop's waiting tunables changed; the overrides below are inert until this matches",
        )

    def test_wait_budget_fits_under_the_job_timeout(self) -> None:
        cap_minutes = self.job["timeout-minutes"]
        self.assertLessEqual(
            cap_minutes,
            GITHUB_HOSTED_TIMEOUT_MINUTES,
            "a GitHub-hosted job cannot be given a larger timeout",
        )
        budget = self.defaults["GATE_WAIT_TIMEOUT_SECONDS"]
        self.assertLessEqual(
            budget + MIN_TIMEOUT_HEADROOM_SECONDS,
            cap_minutes * 60,
            "the loop would be cancelled by the runner before it could report pending checks",
        )

    def test_profiles_wait_for_the_same_checks_as_before(self) -> None:
        for profile, checks in PROFILE_CHECKS.items():
            with self.subTest(profile=profile):
                quoted = " ".join(f'"{name}"' for name in checks)
                self.assertIn(f"wait_for_checks {quoted}\n", self.script)

    # -- success and failure verdicts --------------------------------------

    def test_completed_success_on_every_required_check_passes(self) -> None:
        with self.subTest("source"):
            fake = FakeGh(
                self.tmp("all-green"),
                default=ok(
                    body(
                        page(
                            check_run("Core Checks Gate", "completed", "success", started_at="1"),
                            check_run("Full Validation Gate", "completed", "success", started_at="1"),
                        )
                    )
                ),
            )
            completed = self.run_gate(fake)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("Core Checks Gate: status=completed conclusion=success", completed.stdout)
            self.assertIn("Full Validation Gate: status=completed conclusion=success", completed.stdout)

    def test_failed_conclusion_fails_as_a_failed_check_not_as_pending(self) -> None:
        for conclusion in ("failure", "timed_out", "action_required", "neutral", "skipped", "stale"):
            with self.subTest(conclusion=conclusion):
                fake = FakeGh(
                    self.tmp(f"concluded-{conclusion}"),
                    default=ok(
                        body(
                            page(
                                check_run("Core Checks Gate", "completed", conclusion, suite=CORE_THIS, started_at="1"),
                                check_run("Full Validation Gate", "completed", "success", suite=FULL_THIS, started_at="1"),
                            )
                        )
                    ),
                    routes=event_routes(),
                )
                completed = self.run_gate(fake)
                self.assertGateFailed(
                    completed,
                    f"{ERROR_CHECK_FAILED}Core Checks Gate concluded {conclusion}.",
                    forbidden=(ERROR_TIMED_OUT, ERROR_UNREADABLE, ERROR_UNCORRELATED),
                )
                # A verdict is reached on the first poll, not after a wait.
                self.assertEqual(len(fake.check_run_calls), 1, fake.calls)

    def test_a_check_still_running_is_pending_and_the_timeout_names_it(self) -> None:
        fake = FakeGh(
            self.tmp("still-running"),
            default=ok(
                body(
                    page(
                        check_run("Core Checks Gate", "completed", "success", started_at="1"),
                        check_run("Full Validation Gate", "in_progress", None, started_at="1"),
                    )
                )
            ),
        )
        completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="3")
        self.assertGateFailed(
            completed,
            f"{ERROR_TIMED_OUT}Required checks did not complete within 3s "
            "and are still pending: Full Validation Gate",
            forbidden=(ERROR_UNREADABLE, ERROR_CHECK_FAILED),
        )
        self.assertIn("Full Validation Gate: status=in_progress conclusion=pending", completed.stdout)

    def test_absent_check_is_pending_and_distinguished_from_an_unreadable_query(self) -> None:
        fake = FakeGh(self.tmp("absent"), default=ok(body(page())))
        completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="3")
        self.assertIn("Core Checks Gate: query succeeded, no such check run", completed.stdout)
        self.assertGateFailed(
            completed,
            "still pending: Core Checks Gate Full Validation Gate",
            forbidden=(ERROR_UNREADABLE, ERROR_CHECK_FAILED, WARNING_RETRYING),
        )

    # -- transient and persistent query failure ----------------------------

    def test_transient_query_failure_is_retried_and_does_not_fail_the_gate(self) -> None:
        green = body(
            page(
                check_run("Core Checks Gate", "completed", "success", started_at="1"),
                check_run("Full Validation Gate", "completed", "success", started_at="1"),
            )
        )
        fake = FakeGh(
            self.tmp("transient"),
            responses=[(1, ""), (0, "")],  # API error, then a truncated body
            default=ok(green),
        )
        completed = self.run_gate(fake)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn(f"{WARNING_RETRYING}Core Checks Gate: check-runs query failed (exit 1)", completed.stdout)
        self.assertIn("check-runs response could not be read (jq exit", completed.stdout)
        self.assertIn("(attempt 2/3)", completed.stdout)
        self.assertEqual(len(fake.calls), 4, fake.calls)

    def test_persistent_query_failure_fails_closed_with_a_distinct_error(self) -> None:
        fake = FakeGh(self.tmp("persistent"), default=(1, ""))
        completed = self.run_gate(fake)
        self.assertGateFailed(
            completed,
            f"{ERROR_UNREADABLE}Check runs for Core Checks Gate on {'0' * 40} could not be read "
            "after 3 attempts; failing closed with no verdict for: "
            "Core Checks Gate Full Validation Gate",
            forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT),
        )
        # Bounded: the gate stops at GATE_QUERY_MAX_ATTEMPTS, it does not retry forever.
        self.assertEqual(len(fake.calls), 3, fake.calls)

    def test_a_permission_error_is_bounded_like_any_other_query_failure(self) -> None:
        # A 4xx will not start succeeding on retry, and the loop has no way to
        # tell it apart from a 5xx blip.  What matters is that the retries are
        # bounded either way, that the reason reaches the log instead of being
        # swallowed, and that the gate fails closed rather than spending its
        # whole budget on a query that can never be read.
        response = (1, "", "gh: Resource not accessible by integration (HTTP 403)\n")
        fake = FakeGh(self.tmp("forbidden"), default=response)
        completed = self.run_gate(fake, GATE_QUERY_MAX_ATTEMPTS="2")
        self.assertGateFailed(
            completed,
            ERROR_UNREADABLE,
            forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT),
        )
        self.assertIn("HTTP 403", completed.stdout)
        self.assertEqual(len(fake.calls), 2, fake.calls)

    def test_unreadable_bodies_are_never_success_and_never_pending(self) -> None:
        cases = {
            "empty body": "",
            "whitespace": "\n\n",
            "not json": "unexpected end of JSON input",
            "truncated json": '{"check_runs": [',
            "html error page": "<html><body>502 Bad Gateway</body></html>",
            "null body": "null",
            "check_runs not an array": '{"check_runs": "nope"}',
            "check_runs missing": '{"message": "Not Found"}',
            "array instead of object": "[]",
        }
        for index, (label, payload) in enumerate(cases.items()):
            with self.subTest(case=label):
                fake = FakeGh(self.tmp(f"malformed-{index}"), default=ok(payload))
                completed = self.run_gate(
                    fake, GATE_WAIT_TIMEOUT_SECONDS="3", GATE_QUERY_MAX_ATTEMPTS="2"
                )
                self.assertGateFailed(
                    completed,
                    ERROR_UNREADABLE,
                    forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT),
                )
                self.assertEqual(len(fake.calls), 2, fake.calls)

    def test_malformed_check_run_status_is_not_trusted(self) -> None:
        fake = FakeGh(
            self.tmp("no-status"),
            default=ok(body(page(check_run("Core Checks Gate", "", "success", started_at="1")))),
        )
        completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="3")
        self.assertGateFailed(completed, ERROR_UNREADABLE, forbidden=(ERROR_CHECK_FAILED,))
        self.assertIn("check-runs response was malformed", completed.stdout)

    def test_non_numeric_tunable_fails_closed_before_polling(self) -> None:
        fake = FakeGh(self.tmp("bad-tunable"), default=ok(body(page())))
        completed = self.run_gate(fake, GATE_POLL_INTERVAL_SECONDS="0")
        self.assertGateFailed(
            completed,
            "GATE_POLL_INTERVAL_SECONDS must be a positive integer",
        )
        self.assertEqual(fake.calls, [], "gate polled with an invalid waiting budget")

    # -- selection ---------------------------------------------------------

    def test_the_newest_check_run_wins_when_a_check_was_rerun(self) -> None:
        older_failed = check_run("rpc-docs", "completed", "failure", started_at="2026-09-17T00:00:00Z")
        newer_green = check_run("rpc-docs", "completed", "success", started_at="2026-09-18T00:00:00Z")

        for label, runs in {
            "newest last": [older_failed, newer_green],
            "newest first": [newer_green, older_failed],
        }.items():
            with self.subTest(order=label):
                fake = FakeGh(self.tmp(f"rerun-green-{label}"), default=ok(body(page(*runs))))
                completed = self.run_gate(fake, profile="rpc-docs")
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("rpc-docs: status=completed conclusion=success", completed.stdout)

        # ... and the reverse: a green first attempt must not mask a red re-run.
        older_green = check_run("rpc-docs", "completed", "success", started_at="2026-09-17T00:00:00Z")
        newer_failed = check_run(
            "rpc-docs", "completed", "failure", suite=RPC_DOCS_THIS, started_at="2026-09-18T00:00:00Z"
        )
        fake = FakeGh(
            self.tmp("rerun-red"), default=ok(body(page(older_green, newer_failed))), routes=event_routes()
        )
        self.assertGateFailed(
            self.run_gate(fake, profile="rpc-docs"),
            f"{ERROR_CHECK_FAILED}rpc-docs concluded failure.",
        )

    # -- which event a failed check belongs to -------------------------------
    #
    # A reopen, a label or a re-run starts this gate within seconds, while the
    # workflows it waits for create their gate checks only at their last job.
    # Until then the newest check of a name can be an earlier event's, whose
    # failure says nothing about the run under way.

    def failed_core(self, suite: int, **stamps: str) -> dict:
        stamps.setdefault("started_at", "2026-10-06T14:20:00Z")
        stamps.setdefault("completed_at", "2026-10-06T14:26:19Z")
        return check_run("Core Checks Gate", "completed", "failure", suite=suite, **stamps)

    def green_validation(self) -> dict:
        return check_run(
            "Full Validation Gate", "completed", "success", suite=FULL_THIS,
            started_at="2026-10-06T14:30:00Z", completed_at="2026-10-06T14:31:00Z",
        )

    def test_a_failure_from_this_event_fails_at_once(self) -> None:
        # Core Checks, Full Validation and this gate are separate workflows the
        # same event starts, so a free runner can let Core Checks fail before
        # this gate's step, or even its run, has started.
        for conclusion in ("failure", "timed_out"):
            with self.subTest(conclusion=conclusion):
                fake = FakeGh(
                    self.tmp(f"this-event-{conclusion}"),
                    default=ok(body(page(
                        check_run(
                            "Core Checks Gate", "completed", conclusion, suite=CORE_THIS,
                            started_at="2026-10-06T14:12:01Z", completed_at="2026-10-06T14:12:02Z",
                        ),
                        check_run("Full Validation Gate", "in_progress", None, suite=FULL_THIS, started_at="2026-10-06T14:12:01Z"),
                    ))),
                    routes=event_routes(),
                )
                completed = self.run_gate(fake)
                self.assertGateFailed(
                    completed,
                    f"{ERROR_CHECK_FAILED}Core Checks Gate concluded {conclusion}.",
                    forbidden=(ERROR_TIMED_OUT, ERROR_UNREADABLE, ERROR_UNCORRELATED),
                )
                self.assertEqual(len(fake.check_run_calls), 1, fake.calls)
                self.assertIn(f"This gate's workflow run was created at {THIS_EVENT}", completed.stdout)
                # The workflow run, not one of its attempts: an attempt has its own created_at.
                self.assertEqual(len(fake.calls_matching(GATE_RUN_PATH)), 1, fake.calls)
                self.assertEqual(len(fake.calls_matching(suite_lookup(CORE_THIS))), 1, fake.calls)

    def test_an_earlier_events_failure_is_waited_on_and_the_timeout_names_it(self) -> None:
        # It ended after this gate's event, as a failure that outlives a newer
        # push or label can: when a check ended says nothing about its event.
        for conclusion in ("failure", "timed_out", "action_required"):
            with self.subTest(conclusion=conclusion):
                fake = FakeGh(
                    self.tmp(f"earlier-{conclusion}"),
                    default=ok(body(page(
                        check_run(
                            "Core Checks Gate", "completed", conclusion, suite=CORE_EARLIER,
                            started_at=EARLIER_EVENT, completed_at=LATER_EVENT,
                        ),
                        self.green_validation(),
                    ))),
                    routes=event_routes(),
                )
                completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="3")
                self.assertGateFailed(
                    completed,
                    f"{ERROR_TIMED_OUT}Required checks did not complete within 3s and are still pending: "
                    f"Core Checks Gate (last {conclusion} from an earlier event)",
                    forbidden=(ERROR_CHECK_FAILED, ERROR_UNREADABLE, ERROR_UNCORRELATED),
                )
                self.assertIn(
                    f"Core Checks Gate: concluded {conclusion} in a workflow run created at {EARLIER_EVENT}, "
                    f"by an earlier event than this gate's ({THIS_EVENT}); waiting for a newer run",
                    completed.stdout,
                )
                self.assertGreater(len(fake.check_run_calls), 2, "an earlier event's failure must be polled again")
                # Dated once: the workflow run behind a check suite cannot change.
                self.assertEqual(len(fake.calls_matching(suite_lookup(CORE_EARLIER))), 1, fake.calls)
                self.assertEqual(len(fake.calls_matching(GATE_RUN_PATH)), 1, fake.calls)

    def test_the_newer_run_replaces_an_earlier_events_failure(self) -> None:
        stale = self.failed_core(CORE_EARLIER, started_at=EARLIER_EVENT, completed_at=EARLIER_EVENT)
        fresh_running = check_run("Core Checks Gate", "in_progress", None, suite=CORE_THIS, started_at="2026-10-06T14:30:00Z")
        fresh_green = check_run(
            "Core Checks Gate", "completed", "success", suite=CORE_THIS,
            started_at="2026-10-06T14:30:00Z", completed_at="2026-10-06T14:44:00Z",
        )
        validation = self.green_validation()
        fake = FakeGh(
            self.tmp("earlier-then-green"),
            responses=[
                ok(body(page(stale, validation))),
                ok(body(page(stale, validation))),
                ok(body(page(stale, fresh_running, validation))),
                ok(body(page(stale, fresh_running, validation))),
            ],
            default=ok(body(page(stale, fresh_green, validation))),
            routes=event_routes(),
        )
        completed = self.run_gate(fake)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("waiting for a newer run", completed.stdout)
        self.assertIn("Core Checks Gate: status=in_progress conclusion=pending", completed.stdout)
        self.assertIn("Core Checks Gate: status=completed conclusion=success", completed.stdout)

    def test_a_rerun_of_only_this_gate_fails_at_once_on_this_events_failure(self) -> None:
        # Re-running this gate alone starts no Core Checks or Full Validation,
        # so no newer run is coming.  The re-run keeps its workflow run and that
        # run's created_at, and moves only run_attempt and run_started_at, so a
        # failure that ended hours before the re-run is still this event's.
        rerun = workflow_run(GATE_RUN_ID, 999, THIS_EVENT, run_attempt=4, run_started_at="2026-10-06T18:02:04Z")
        fake = FakeGh(
            self.tmp("gate-only-rerun"),
            default=ok(body(page(self.failed_core(CORE_THIS), self.green_validation()))),
            routes=event_routes(gate_run=rerun),
        )
        completed = self.run_gate(fake)
        self.assertGateFailed(
            completed,
            f"{ERROR_CHECK_FAILED}Core Checks Gate concluded failure.",
            forbidden=(ERROR_TIMED_OUT, ERROR_UNCORRELATED),
        )
        self.assertEqual(len(fake.check_run_calls), 1, fake.calls)

    def test_a_rerun_of_an_earlier_events_workflow_is_still_that_events(self) -> None:
        # Re-running an earlier event's Core Checks keeps its workflow run's
        # created_at, so its failure, however recent, is still waited on: the
        # check this event started will be newer.
        rerun = workflow_run(
            50_101, CORE_EARLIER, EARLIER_EVENT, run_attempt=2, run_started_at="2026-10-06T15:31:19Z"
        )
        routes = event_routes()
        routes[suite_lookup(CORE_EARLIER)] = ok(workflow_runs(rerun))
        fake = FakeGh(
            self.tmp("earlier-workflow-rerun"),
            default=ok(body(page(
                self.failed_core(CORE_EARLIER, started_at="2026-10-06T15:31:30Z", completed_at="2026-10-06T15:45:16Z"),
                self.green_validation(),
            ))),
            routes=routes,
        )
        completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="2")
        self.assertGateFailed(
            completed,
            f"{ERROR_TIMED_OUT}Required checks did not complete within 2s and are still pending: "
            "Core Checks Gate (last failure from an earlier event)",
            forbidden=(ERROR_CHECK_FAILED, ERROR_UNCORRELATED),
        )

    def test_a_label_event_fails_at_once_on_its_own_core_checks_failure(self) -> None:
        # A label on a commit whose Core Checks had passed starts this gate,
        # Core Checks and Full Validation again.  This event's Core Checks
        # failed before this gate first polled: it is the newest Core Checks
        # Gate and the verdict, while Full Validation is still running.
        earlier_green = check_run(
            "Core Checks Gate", "completed", "success", suite=CORE_EARLIER,
            started_at=EARLIER_EVENT, completed_at=EARLIER_EVENT,
        )
        this_failed = self.failed_core(CORE_THIS, started_at="2026-10-06T14:12:40Z", completed_at="2026-10-06T14:13:10Z")
        validation_running = check_run("Full Validation Gate", "in_progress", None, suite=FULL_THIS, started_at="2026-10-06T14:12:05Z")
        fake = FakeGh(
            self.tmp("label-this-event"),
            default=ok(body(page(earlier_green, this_failed, validation_running))),
            routes=event_routes(),
        )
        completed = self.run_gate(fake)
        self.assertGateFailed(
            completed,
            f"{ERROR_CHECK_FAILED}Core Checks Gate concluded failure.",
            forbidden=(ERROR_TIMED_OUT, ERROR_UNCORRELATED),
        )
        self.assertEqual(len(fake.check_run_calls), 1, fake.calls)

    def test_a_later_events_failure_is_current(self) -> None:
        # Nothing this gate could wait for is newer than a later event's run.
        fake = FakeGh(
            self.tmp("later-event"),
            default=ok(body(page(self.failed_core(CORE_LATER, started_at=LATER_EVENT), self.green_validation()))),
            routes=event_routes(),
        )
        completed = self.run_gate(fake)
        self.assertGateFailed(
            completed,
            f"{ERROR_CHECK_FAILED}Core Checks Gate concluded failure.",
            forbidden=(ERROR_TIMED_OUT, ERROR_UNCORRELATED),
        )
        self.assertEqual(len(fake.check_run_calls), 1, fake.calls)

    def test_the_event_skew_allowance_is_a_documented_constant(self) -> None:
        self.assertEqual(self.event_skew, DOCUMENTED_EVENT_SKEW_SECONDS)
        self.assertNotIn("EVENT_SKEW_SECONDS:-", self.script, "the allowance must not be overridable")

    def test_the_event_skew_boundary(self) -> None:
        # Workflow runs one event starts are created within the allowance of
        # each other; a run created further before this gate's is an earlier
        # event's.  The documented value, not the script's, sets the boundary.
        gate = parse_iso(THIS_EVENT)
        skew = timedelta(seconds=DOCUMENTED_EVENT_SKEW_SECONDS)
        one = timedelta(seconds=1)
        cases = {
            "the same second": (gate, "current"),
            "the allowance before": (gate - skew, "current"),
            "one second more": (gate - skew - one, "earlier"),
            "after this gate's run": (gate + skew + one, "current"),
        }
        for label, (created, expected) in cases.items():
            with self.subTest(case=label, created=iso(created)):
                fake = FakeGh(
                    self.tmp(f"skew-{label}"),
                    default=ok(body(page(self.failed_core(777), self.green_validation()))),
                    routes=event_routes(suites={777: iso(created)}),
                )
                completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="2")
                if expected == "current":
                    self.assertGateFailed(
                        completed,
                        f"{ERROR_CHECK_FAILED}Core Checks Gate concluded failure.",
                        forbidden=(ERROR_TIMED_OUT, ERROR_UNCORRELATED),
                    )
                    self.assertEqual(len(fake.check_run_calls), 1, fake.calls)
                else:
                    self.assertGateFailed(
                        completed,
                        f"{ERROR_TIMED_OUT}Required checks did not complete within 2s and are still pending: "
                        "Core Checks Gate (last failure from an earlier event)",
                        forbidden=(ERROR_CHECK_FAILED, ERROR_UNCORRELATED),
                    )

    def test_a_success_from_an_earlier_event_still_counts(self) -> None:
        # A success on this commit is a verdict whichever event produced it,
        # so it is never dated: no workflow run is read for it.
        fake = FakeGh(
            self.tmp("earlier-success"),
            default=ok(body(page(
                check_run(
                    "Core Checks Gate", "completed", "success", suite=CORE_EARLIER,
                    started_at=EARLIER_EVENT, completed_at=EARLIER_EVENT,
                ),
                self.green_validation(),
            ))),
        )
        completed = self.run_gate(fake)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(fake.workflow_run_calls, [])

    def test_a_cancelled_check_is_never_a_verdict(self) -> None:
        # A newer push, reopen or label cancels the running Full Validation,
        # and that cancellation can complete after this gate run started.
        # Whichever event's it is, it is waited on and never dated.
        core = check_run(
            "Core Checks Gate", "completed", "success", suite=CORE_THIS,
            started_at="2026-10-06T14:12:05Z", completed_at="2026-10-06T14:26:00Z",
        )
        for label, suite in {"earlier": FULL_EARLIER, "this": FULL_THIS}.items():
            with self.subTest(event=label):
                cancelled = check_run(
                    "Full Validation Gate", "completed", "cancelled", suite=suite,
                    started_at=EARLIER_EVENT, completed_at=LATER_EVENT,
                )
                fake = FakeGh(self.tmp(f"cancelled-{label}"), default=ok(body(page(core, cancelled))))
                completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="3")
                self.assertGateFailed(
                    completed,
                    f"{ERROR_TIMED_OUT}Required checks did not complete within 3s and are still pending: "
                    "Full Validation Gate (cancelled)",
                    forbidden=(ERROR_CHECK_FAILED, ERROR_UNREADABLE, ERROR_UNCORRELATED),
                )
                self.assertEqual(fake.workflow_run_calls, [])

        cancelled = check_run(
            "Full Validation Gate", "completed", "cancelled", suite=FULL_THIS,
            started_at="2026-10-06T14:12:05Z", completed_at="2026-10-06T14:13:00Z",
        )
        newer_green = check_run(
            "Full Validation Gate", "completed", "success", suite=FULL_THIS,
            started_at="2026-10-06T14:20:00Z", completed_at="2026-10-06T15:00:00Z",
        )
        fake = FakeGh(
            self.tmp("cancelled-then-green"),
            responses=[ok(body(page(core, cancelled))), ok(body(page(core, cancelled)))],
            default=ok(body(page(core, cancelled, newer_green))),
        )
        completed = self.run_gate(fake)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_a_failure_that_cannot_be_dated_fails_closed_with_a_distinct_error(self) -> None:
        # Not knowing a failure's event is never success, never a wait for a
        # run that may not come, and never reported as the check's own verdict.
        gate_run = ok(json.dumps(workflow_run(GATE_RUN_ID, 999, THIS_EVENT)))
        core_run = workflow_run(60_201, CORE_THIS, THIS_EVENT)
        server_error = (1, "", "gh: Server Error (HTTP 502)\n")
        forbidden = (1, "", "gh: Resource not accessible by integration (HTTP 403)\n")
        failed = self.failed_core(CORE_THIS)
        suite_route = suite_lookup(CORE_THIS)
        # case: (routes, check run, env overrides, the route read until it gave up)
        cases = {
            "the check's run cannot be read": ({GATE_RUN_PATH: gate_run, suite_route: server_error}, failed, {}, suite_route),
            "the token cannot read workflow runs": ({GATE_RUN_PATH: gate_run, suite_route: forbidden}, failed, {}, suite_route),
            "no run owns the check suite": ({GATE_RUN_PATH: gate_run, suite_route: ok(workflow_runs())}, failed, {}, suite_route),
            "only another suite's run": (
                {GATE_RUN_PATH: gate_run, suite_route: ok(workflow_runs(workflow_run(1, 555, THIS_EVENT)))},
                failed, {}, suite_route,
            ),
            "two runs claim the check suite": (
                {GATE_RUN_PATH: gate_run, suite_route: ok(workflow_runs(core_run, workflow_run(2, CORE_THIS, EARLIER_EVENT)))},
                failed, {}, suite_route,
            ),
            "the check's run has no created_at": (
                {GATE_RUN_PATH: gate_run, suite_route: ok(workflow_runs(workflow_run(1, CORE_THIS, None)))},
                failed, {}, suite_route,
            ),
            "the check's run has fractional seconds": (
                {GATE_RUN_PATH: gate_run, suite_route: ok(workflow_runs(workflow_run(1, CORE_THIS, "2026-10-06T14:12:00.5Z")))},
                failed, {}, suite_route,
            ),
            "the response is not json": ({GATE_RUN_PATH: gate_run, suite_route: ok("<html>502</html>")}, failed, {}, suite_route),
            "this gate's run cannot be read": ({GATE_RUN_PATH: server_error}, failed, {}, GATE_RUN_PATH),
            "this gate's run is another run": (
                {GATE_RUN_PATH: ok(json.dumps(workflow_run(GATE_RUN_ID + 1, 999, THIS_EVENT)))}, failed, {}, GATE_RUN_PATH,
            ),
            "this gate's run has no created_at": (
                {GATE_RUN_PATH: ok(json.dumps(workflow_run(GATE_RUN_ID, 999, "")))}, failed, {}, GATE_RUN_PATH,
            ),
            "this gate's run id is missing": ({}, failed, {"RUN_ID": ""}, None),
            "the check run names no check suite": (
                {GATE_RUN_PATH: gate_run},
                check_run("Core Checks Gate", "completed", "failure", started_at="2026-10-06T14:20:00Z"),
                {}, None,
            ),
        }
        for index, (label, (routes, core, env, gave_up)) in enumerate(cases.items()):
            with self.subTest(case=label):
                fake = FakeGh(
                    self.tmp(f"undatable-{index}"),
                    default=ok(body(page(core, self.green_validation()))),
                    routes=routes,
                )
                completed = self.run_gate(fake, GATE_QUERY_MAX_ATTEMPTS="2", **env)
                self.assertGateFailed(
                    completed,
                    f"{ERROR_UNCORRELATED}Core Checks Gate on {'0' * 40} concluded failure, but the workflow "
                    "runs that tell whether it belongs to this event could not be read; failing closed with "
                    "no verdict for: Core Checks Gate Full Validation Gate",
                    forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT, ERROR_UNREADABLE),
                )
                self.assertEqual(len(fake.check_run_calls), 1, fake.calls)
                if gave_up is not None:
                    # Bounded by the same retries as the check-runs query.
                    self.assertEqual(len(fake.calls_matching(gave_up)), 2, fake.calls)
                    self.assertIn(f"{WARNING_RETRYING}Core Checks Gate: workflow-run ", completed.stdout)

    def test_a_transient_lookup_failure_is_retried(self) -> None:
        routes = event_routes()
        routes[suite_lookup(CORE_THIS)] = [
            (1, "", "gh: Server Error (HTTP 502)\n"),
            ok(workflow_runs(workflow_run(60_201, CORE_THIS, THIS_EVENT))),
        ]
        fake = FakeGh(
            self.tmp("lookup-transient"),
            default=ok(body(page(self.failed_core(CORE_THIS), self.green_validation()))),
            routes=routes,
        )
        completed = self.run_gate(fake)
        self.assertGateFailed(
            completed,
            f"{ERROR_CHECK_FAILED}Core Checks Gate concluded failure.",
            forbidden=(ERROR_UNCORRELATED, ERROR_TIMED_OUT),
        )
        self.assertIn(f"{WARNING_RETRYING}Core Checks Gate: workflow-run query failed (exit 1)", completed.stdout)
        self.assertEqual(len(fake.calls_matching(suite_lookup(CORE_THIS))), 2, fake.calls)

    def test_every_gate_event_can_start_the_checks_it_waits_for(self) -> None:
        # The gate waits for this event's run instead of trusting an earlier
        # event's failure, so each event that starts the gate must also start
        # the gated workflows.
        gate_types = set(self.workflow["on"]["pull_request"]["types"])
        for name in ("core-checks.yml", "ci.yml"):
            other = load_yaml(REPO_ROOT / ".github" / "workflows" / name)
            types = set(other["on"]["pull_request"].get("types", ["opened", "synchronize", "reopened"]))
            self.assertEqual(gate_types - types, set(), f"{name} misses events that start the Required Merge Gate")

    def test_the_workflow_token_can_read_workflow_runs(self) -> None:
        # Getting or listing workflow runs needs Actions: read; without it every
        # failure would fail closed as undatable.
        permissions = self.workflow["permissions"]
        self.assertEqual(permissions.get("actions"), "read", permissions)
        self.assertEqual(permissions.get("checks"), "read", permissions)

    def test_a_queued_rerun_falls_back_to_created_at_and_is_pending(self) -> None:
        # A re-run that has not started yet has no started_at at all; ordering
        # by created_at keeps it, so an old green run cannot pass the gate.
        old_green = check_run(
            "rpc-docs", "completed", "success",
            started_at="2026-09-17T00:00:00Z", created_at="2026-09-17T00:00:00Z",
        )
        queued_rerun = check_run("rpc-docs", "queued", None, created_at="2026-09-18T00:00:00Z")
        fake = FakeGh(self.tmp("queued-rerun"), default=ok(body(page(old_green, queued_rerun))))
        completed = self.run_gate(fake, profile="rpc-docs", GATE_WAIT_TIMEOUT_SECONDS="3")
        self.assertIn("rpc-docs: status=queued conclusion=pending", completed.stdout)
        self.assertGateFailed(
            completed,
            f"{ERROR_TIMED_OUT}Required checks did not complete within 3s and are still pending: rpc-docs",
        )

    def test_a_check_beyond_the_first_page_is_still_read(self) -> None:
        # per_page=100 alone would hide the 101st check run; --paginate is what
        # keeps a required check on a later page from looking absent.
        filler = [check_run(f"other-{index}", "completed", "success", started_at="1") for index in range(100)]
        fake = FakeGh(
            self.tmp("paginated"),
            default=ok(
                body(
                    page(*filler),
                    page(check_run("rpc-docs", "completed", "success", started_at="2")),
                )
            ),
        )
        completed = self.run_gate(fake, profile="rpc-docs")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("rpc-docs: status=completed conclusion=success", completed.stdout)
        self.assertTrue(all("--paginate" in call for call in fake.calls), fake.calls)

    # -- the deadline ------------------------------------------------------

    def test_the_deadline_counts_time_spent_in_api_calls(self) -> None:
        # Two checks, one second per call, a one second poll interval and a
        # four second budget.  A deadline that counted only the sleeps would
        # run four poll cycles and therefore make eight calls, whatever the
        # machine is doing; a wall-clock deadline is spent by the calls
        # themselves and stops sooner.  Load can only make it stop sooner
        # still, so the bound below cannot flake upwards.
        fake = FakeGh(self.tmp("slow-api"), default=ok(body(page())), delay=1)
        started = time.monotonic()
        completed = self.run_gate(
            fake, GATE_WAIT_TIMEOUT_SECONDS="4", GATE_POLL_INTERVAL_SECONDS="1"
        )
        elapsed = time.monotonic() - started
        self.assertGateFailed(completed, ERROR_TIMED_OUT)
        self.assertLess(
            len(fake.calls),
            8,
            f"the wait budget ignored the time spent in the API: {len(fake.calls)} calls "
            f"in {elapsed:.1f}s",
        )

    # -- scaffolding -------------------------------------------------------

    def tmp(self, name: str) -> Path:
        return Path(self._tmpdir.name) / name


def setUpModule() -> None:
    if not WORKFLOW.exists():  # pragma: no cover - misconfigured checkout
        raise AssertionError(f"{WORKFLOW} not found")


if __name__ == "__main__":
    unittest.main()
