#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Contract tests: how the Required Merge Gate waits for other checks.

The gate's ``wait_for_checks`` loop is the last thing standing between a
merge and the checks it depends on, so infrastructure noise must not be able
to turn it red, and nothing may turn it green while a required check failed,
is absent, or cannot be read.  A check only counts when it comes from a
workflow run of the event the gate is running for: another event's run on the
same commit, such as a docs-only push, or an earlier run of the same pull
request, such as one from while it was a draft, is not this event's result.

These tests execute the gate step's **real** ``run:`` script, lifted out of
``.github/workflows/required-merge-gate.yml``, against a stubbed ``gh`` whose
responses and exit codes each test scripts.  The polling logic therefore has
exactly one definition: this file asserts against it and never restates it.
The loop's waiting tunables are read from the same script and overridden per
test, so the production defaults stay the values CI actually uses while the
suite still runs in seconds.

Not provable here: whether the hosted ``Required Merge Gate`` check is
attached to a branch ruleset, and whether the real API agrees with the shapes
modelled below.  The workflow-run fields modelled are the ones GitHub returned
for the runs of #268 and #297.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

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
    WorkflowLoader,
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
SKEW = re.compile(r"^\s*SIBLING_RUN_SKEW_SECONDS=(?P<seconds>\d+)\s*$", re.MULTILINE)

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
ERROR_TIMED_OUT = "::error title=Required Merge Gate timed out::"
WARNING_RETRYING = "::warning title=Required Merge Gate retrying::"

GATE_WORKFLOW = ".github/workflows/required-merge-gate.yml"
FULL_VALIDATION = ".github/workflows/ci.yml"
CORE_CHECKS = ".github/workflows/core-checks.yml"
GITHUB_DEFAULT_PULL_REQUEST_TYPES = ("opened", "synchronize", "reopened")

# The event every test runs for unless it says otherwise: a push to pull
# request #7.  On #297 GitHub created Full Validation and Core Checks a second
# before the gate run of the same event, so the modelled runs are too.
SHA = "0" * 40
PR = 7
RUN_ID = 4000
GATE_SUITE = 10
FULL_VALIDATION_SUITE = 20
CORE_CHECKS_SUITE = 30
GATE_CREATED = datetime(2026, 11, 4, 15, 32, 35, tzinfo=timezone.utc)
SIBLINGS_CREATED = GATE_CREATED - timedelta(seconds=1)

RUNS_ROUTE = r"/actions/runs\?"
CHECK_RUNS_ROUTE = r"/check-runs\?"
# Every suite's check runs on the commit at once: the listing the gate read
# before it bound its waits to this event's runs, and must no longer read.
COMMIT_CHECK_RUNS_ROUTE = r"/commits/[0-9a-f]+/check-runs\?"


def check_run(name: str, status: str, conclusion: str | None = None, **stamps: str) -> dict:
    run = {"name": name, "status": status, "conclusion": conclusion}
    run.update(stamps)
    return run


def page(*runs: dict) -> dict:
    return {"total_count": len(runs), "check_runs": list(runs)}


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def workflow_run(
    run_id: int,
    path: str,
    suite: int,
    *,
    created: datetime = SIBLINGS_CREATED,
    event: str = "pull_request",
    head_branch: str = "topic",
    repository_id: int = 1,
    pull_requests: tuple[int, ...] = (PR,),
) -> dict:
    """A workflow run as ``/actions/runs`` lists it, cut to the fields read."""
    return {
        "id": run_id,
        "path": path,
        "event": event,
        "head_sha": SHA,
        "head_branch": head_branch,
        "head_repository": {"id": repository_id},
        "pull_requests": [{"number": number} for number in pull_requests],
        "created_at": stamp(created),
        "check_suite_id": suite,
    }


def this_events_runs(**fields) -> list[dict]:
    """The gate's own run and the Full Validation and Core Checks runs of its event."""
    return [
        workflow_run(RUN_ID, GATE_WORKFLOW, GATE_SUITE, **{"created": GATE_CREATED, **fields}),
        workflow_run(RUN_ID + 1, FULL_VALIDATION, FULL_VALIDATION_SUITE, **fields),
        workflow_run(RUN_ID + 2, CORE_CHECKS, CORE_CHECKS_SUITE, **fields),
    ]


def runs_page(*runs: dict) -> dict:
    return {"total_count": len(runs), "workflow_runs": list(runs)}


def body(*pages: dict) -> str:
    """Concatenated page objects, the way ``gh api --paginate`` emits them."""
    return "".join(json.dumps(item) for item in pages)


def ok(payload: str) -> tuple[int, str]:
    return (0, payload)


def github(runs: list[dict], suites: dict[int, list[dict]]) -> list[tuple]:
    """Routes answering the gate the way GitHub would for one head commit.

    ``runs`` are every workflow run on the commit, of every event.  The
    listing ignores its query's filters, so it is the gate's own selection that
    keeps another event's runs out.  ``suites`` maps each check suite to its
    check runs; the commit-wide listing serves all of them together.
    """
    routes = [(RUNS_ROUTE, [], ok(body(runs_page(*runs))))]
    for suite, check_runs in suites.items():
        routes.append((rf"/check-suites/{suite}/check-runs\?", [], ok(body(page(*check_runs)))))
    every_suite = [run for check_runs in suites.values() for run in check_runs]
    routes.append((COMMIT_CHECK_RUNS_ROUTE, [], ok(body(page(*every_suite)))))
    return routes


class FakeGh:
    """A ``gh`` on PATH that scripts one response per call, per endpoint.

    Each route is ``(pattern, responses, default)``: the first route whose
    regular expression occurs in a call's arguments answers it, from its own
    ``responses`` in order and then from its ``default``.  Each reply is
    ``(exit_code, stdout)``, optionally with a third element written to stderr
    the way ``gh`` reports an HTTP error.  ``delay`` makes every call take
    that many seconds, so a test can show the wait deadline counts time spent
    in the API and not only in ``sleep``.

    Without ``routes``, ``responses`` and ``default`` script the check-run
    listings, and ``runs`` answers the workflow-run listing.  By default that
    lists this event's own runs, so a test about check runs need not restate
    which runs they belong to.
    """

    def __init__(
        self,
        directory: Path,
        *,
        responses: list[tuple] | None = None,
        default: tuple | None = None,
        runs: tuple | None = None,
        routes: list[tuple] | None = None,
        delay: int = 0,
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.calls_path = directory / "calls"
        if routes is None:
            if runs is None:
                runs = ok(body(runs_page(*this_events_runs())))
            routes = [(RUNS_ROUTE, [], runs), (CHECK_RUNS_ROUTE, responses or [], default)]
        script = [
            "#!/usr/bin/env bash",
            f'printf "%s\\n" "$*" >> {shlex.quote(str(self.calls_path))}',
            'route=""',
        ]
        for index, (pattern, replies, fallback) in enumerate(routes):
            route = directory / f"route-{index}"
            route.mkdir()
            for number, reply in enumerate(replies, start=1):
                self._write_reply(route, str(number), reply)
            if fallback is not None:
                self._write_reply(route, "default", fallback)
            keyword = "if" if index == 0 else "elif"
            script += [
                f'{keyword} grep -Eq -- {shlex.quote(pattern)} <<< "$*"; then',
                f"  route={shlex.quote(str(route))}",
            ]
        script += [
            "fi",
            'reply=""',
            'if [[ -n "${route}" ]]; then',
            '  printf "%s\\n" "$*" >> "${route}/calls"',
            '  reply="${route}/$(wc -l < "${route}/calls")"',
            '  [[ -f "${reply}" ]] || reply="${route}/default"',
            "fi",
            'if [[ ! -f "${reply}" ]]; then',
            '  echo "fake gh: unscripted call: $*" >&2',
            "  exit 97",
            "fi",
            f"sleep {delay}" if delay else "",
            'code="$(head -n 1 "${reply}")"',
            '[[ -f "${reply}.err" ]] && cat "${reply}.err" >&2',
            'tail -n +2 "${reply}"',
            'exit "${code}"',
            "",
        ]
        gh = directory / "gh"
        gh.write_text("\n".join(script), encoding="utf8")
        gh.chmod(0o755)

    @staticmethod
    def _write_reply(route: Path, name: str, reply: tuple) -> None:
        code, payload = reply[0], reply[1]
        (route / name).write_text(f"{code}\n{payload}", encoding="utf8")
        if len(reply) > 2 and reply[2]:
            (route / f"{name}.err").write_text(reply[2], encoding="utf8")

    @property
    def calls(self) -> list[str]:
        if not self.calls_path.exists():
            return []
        return self.calls_path.read_text(encoding="utf8").splitlines()

    def calls_to(self, pattern: str) -> list[str]:
        return [call for call in self.calls if re.search(pattern, call)]

    @property
    def check_run_calls(self) -> list[str]:
        return self.calls_to(CHECK_RUNS_ROUTE)

    @property
    def run_calls(self) -> list[str]:
        return self.calls_to(RUNS_ROUTE)


def load_workflow_file(relative: str) -> dict:
    return yaml.load((REPO_ROOT / relative).read_text(encoding="utf8"), Loader=WorkflowLoader)


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
            "SHA": SHA,
            "EVENT_NAME": "pull_request",
            "EVENT_ACTION": "synchronize",
            "PR_NUMBER": str(PR),
            "PR_DRAFT": "false",
            "RUN_ID": str(RUN_ID),
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

    def assertGatePassed(self, completed) -> None:
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def run_pending(self, fake: FakeGh, profile: str = "source", **overrides: str):
        """Run the gate on a one-second budget, for a scenario that must stay pending."""
        return self.run_gate(fake, profile, GATE_WAIT_TIMEOUT_SECONDS="1", **overrides)

    def assertStillPending(self, completed, *checks: str) -> None:
        """The verdict of ``run_pending``: a timeout naming exactly ``checks``."""
        self.assertGateFailed(
            completed,
            f"{ERROR_TIMED_OUT}Required checks did not complete within 1s "
            f"and are still pending: {' '.join(checks)}\n",
            forbidden=(ERROR_CHECK_FAILED, ERROR_UNREADABLE),
        )

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
            self.assertGatePassed(completed)
            self.assertIn("Core Checks Gate: status=completed conclusion=success", completed.stdout)
            self.assertIn("Full Validation Gate: status=completed conclusion=success", completed.stdout)

    def test_failed_conclusion_fails_as_a_failed_check_not_as_pending(self) -> None:
        for conclusion in ("failure", "cancelled", "timed_out", "action_required", "neutral", "skipped"):
            with self.subTest(conclusion=conclusion):
                fake = FakeGh(
                    self.tmp(f"concluded-{conclusion}"),
                    default=ok(
                        body(
                            page(
                                check_run("Core Checks Gate", "completed", conclusion, started_at="1"),
                                check_run("Full Validation Gate", "completed", "success", started_at="1"),
                            )
                        )
                    ),
                )
                completed = self.run_gate(fake)
                self.assertGateFailed(
                    completed,
                    f"{ERROR_CHECK_FAILED}Core Checks Gate concluded {conclusion}.",
                    forbidden=(ERROR_TIMED_OUT, ERROR_UNREADABLE),
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
        self.assertGatePassed(completed)
        self.assertIn(f"{WARNING_RETRYING}Core Checks Gate: check-runs query failed (exit 1)", completed.stdout)
        self.assertIn("check-runs response could not be read (jq exit", completed.stdout)
        self.assertIn("(attempt 2/3)", completed.stdout)
        self.assertEqual(len(fake.check_run_calls), 4, fake.calls)

    def test_persistent_query_failure_fails_closed_with_a_distinct_error(self) -> None:
        fake = FakeGh(self.tmp("persistent"), default=(1, ""))
        completed = self.run_gate(fake)
        self.assertGateFailed(
            completed,
            f"{ERROR_UNREADABLE}Check runs for Core Checks Gate on {SHA} could not be read "
            "after 3 attempts; failing closed with no verdict for: "
            "Core Checks Gate Full Validation Gate",
            forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT),
        )
        # Bounded: the gate stops at GATE_QUERY_MAX_ATTEMPTS, it does not retry forever.
        self.assertEqual(len(fake.check_run_calls), 3, fake.calls)

    def test_a_permission_error_is_bounded_like_any_other_query_failure(self) -> None:
        # A 4xx will not start succeeding on retry, and the loop has no way to
        # tell it apart from a 5xx blip.  What matters is that the retries are
        # bounded either way, that the reason reaches the log instead of being
        # swallowed, and that the gate fails closed rather than spending its
        # whole budget on a query that can never be read.
        response = (1, "", "gh: Resource not accessible by integration (HTTP 403)\n")
        for label, fake, route in (
            ("check runs", FakeGh(self.tmp("forbidden-checks"), default=response), CHECK_RUNS_ROUTE),
            ("workflow runs", FakeGh(self.tmp("forbidden-runs"), runs=response), RUNS_ROUTE),
        ):
            with self.subTest(listing=label):
                completed = self.run_gate(fake, GATE_QUERY_MAX_ATTEMPTS="2")
                self.assertGateFailed(
                    completed,
                    ERROR_UNREADABLE,
                    forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT),
                )
                self.assertIn("HTTP 403", completed.stdout)
                self.assertEqual(len(fake.calls_to(route)), 2, fake.calls)

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
                self.assertEqual(len(fake.check_run_calls), 2, fake.calls)

    def test_malformed_check_run_status_is_not_trusted(self) -> None:
        fake = FakeGh(
            self.tmp("no-status"),
            default=ok(body(page(check_run("Core Checks Gate", "", "success", started_at="1")))),
        )
        completed = self.run_gate(fake, GATE_WAIT_TIMEOUT_SECONDS="3")
        self.assertGateFailed(completed, ERROR_UNREADABLE, forbidden=(ERROR_CHECK_FAILED,))
        self.assertIn("check-runs response was malformed", completed.stdout)

    def test_unreadable_workflow_runs_are_never_success_and_never_pending(self) -> None:
        own, full_validation, core_checks = this_events_runs()
        cases = {
            "workflow_runs missing": body({"message": "Not Found"}),
            "this gate run not listed": body(runs_page(full_validation, core_checks)),
            "no check suite": body(runs_page(own, {**full_validation, "check_suite_id": None}, core_checks)),
            "unparsable creation time": body(runs_page(own, {**full_validation, "created_at": "yesterday"}, core_checks)),
        }
        for index, (label, payload) in enumerate(cases.items()):
            with self.subTest(case=label):
                fake = FakeGh(self.tmp(f"malformed-runs-{index}"), runs=ok(payload))
                completed = self.run_gate(fake, GATE_QUERY_MAX_ATTEMPTS="2")
                self.assertGateFailed(
                    completed,
                    f"{ERROR_UNREADABLE}Workflow runs for this pull_request event on {SHA} could not "
                    "be read after 2 attempts; failing closed with no verdict for: "
                    "Core Checks Gate Full Validation Gate",
                    forbidden=(ERROR_CHECK_FAILED, ERROR_TIMED_OUT),
                )
                self.assertIn(f"{WARNING_RETRYING}workflow runs: workflow-runs ", completed.stdout)
                self.assertEqual(len(fake.run_calls), 2, fake.calls)
                self.assertEqual(fake.check_run_calls, [], "gate read check runs it could not attribute")

    def test_non_numeric_tunable_fails_closed_before_polling(self) -> None:
        fake = FakeGh(self.tmp("bad-tunable"), default=ok(body(page())))
        completed = self.run_gate(fake, GATE_POLL_INTERVAL_SECONDS="0")
        self.assertGateFailed(
            completed,
            "GATE_POLL_INTERVAL_SECONDS must be a positive integer",
        )
        self.assertEqual(fake.calls, [], "gate polled with an invalid waiting budget")

    def test_an_unreadable_event_context_fails_closed_before_polling(self) -> None:
        cases = {
            "unsupported event": {"EVENT_NAME": "workflow_dispatch"},
            "no pull request number": {"PR_NUMBER": ""},
            "no event action": {"EVENT_ACTION": ""},
            "no run ID": {"RUN_ID": ""},
            "malformed head SHA": {"SHA": "HEAD"},
        }
        for index, (label, overrides) in enumerate(cases.items()):
            with self.subTest(case=label):
                fake = FakeGh(self.tmp(f"bad-context-{index}"), default=ok(body(page())))
                completed = self.run_gate(fake, **overrides)
                self.assertGateFailed(completed, ERROR_CHECK_FAILED, forbidden=(ERROR_TIMED_OUT,))
                self.assertEqual(fake.calls, [], "gate polled without knowing which runs are its event's")

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
                self.assertGatePassed(completed)
                self.assertIn("rpc-docs: status=completed conclusion=success", completed.stdout)

        # ... and the reverse: a green first attempt must not mask a red re-run.
        older_green = check_run("rpc-docs", "completed", "success", started_at="2026-09-17T00:00:00Z")
        newer_failed = check_run("rpc-docs", "completed", "failure", started_at="2026-09-18T00:00:00Z")
        fake = FakeGh(self.tmp("rerun-red"), default=ok(body(page(older_green, newer_failed))))
        self.assertGateFailed(
            self.run_gate(fake, profile="rpc-docs"),
            f"{ERROR_CHECK_FAILED}rpc-docs concluded failure.",
        )

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
        self.assertGatePassed(completed)
        self.assertIn("rpc-docs: status=completed conclusion=success", completed.stdout)
        self.assertTrue(all("--paginate" in call for call in fake.calls), fake.calls)

    # -- binding the waits to this event's runs ----------------------------

    def test_the_gate_reads_runs_of_this_commit_and_event_only(self) -> None:
        fake = FakeGh(
            self.tmp("query"),
            default=ok(body(page(check_run("Core Checks Gate", "completed", "success", started_at="1")))),
        )
        completed = self.run_gate(fake, profile="release-policy")
        self.assertGatePassed(completed)
        self.assertEqual(len(fake.run_calls), 1, fake.calls)
        self.assertIn(f"/repos/example/repo/actions/runs?head_sha={SHA}&event=pull_request&", fake.run_calls[0])
        self.assertEqual(
            fake.check_run_calls,
            [
                "api -H Accept: application/vnd.github+json --paginate "
                f"/repos/example/repo/check-suites/{CORE_CHECKS_SUITE}/check-runs?per_page=100"
            ],
        )
        # The log names the run each wait is bound to.
        self.assertIn(
            f"{CORE_CHECKS}: reading run {RUN_ID + 2} (check suite {CORE_CHECKS_SUITE}, "
            f"created {stamp(SIBLINGS_CREATED)}) for this pull_request event",
            completed.stdout,
        )

    def test_an_earlier_events_skipped_check_does_not_fail_this_event(self) -> None:
        # #268, replayed: marked ready for review 50 minutes after its last
        # push.  The draft-era Full Validation run skipped its gate job, and
        # the new run's gate job did not exist yet when the gate first polled.
        # Core Checks does not run for ready_for_review, so its draft-era run
        # is still the result for this head.
        # The draft-era runs were stamped a second apart, Full Validation's
        # after its gate run's.
        draft_era = GATE_CREATED - timedelta(minutes=50)
        runs = [
            workflow_run(3000, GATE_WORKFLOW, 11, created=draft_era),
            workflow_run(3001, FULL_VALIDATION, 21, created=draft_era + timedelta(seconds=1)),
            workflow_run(3002, CORE_CHECKS, CORE_CHECKS_SUITE, created=draft_era),
            workflow_run(RUN_ID, GATE_WORKFLOW, GATE_SUITE, created=GATE_CREATED),
            workflow_run(RUN_ID + 1, FULL_VALIDATION, FULL_VALIDATION_SUITE),
        ]
        suites = {
            21: [check_run("Full Validation Gate", "completed", "skipped", started_at="2026-11-04T14:43:00Z")],
            CORE_CHECKS_SUITE: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T14:55:00Z")],
            FULL_VALIDATION_SUITE: [],
        }
        fake = FakeGh(self.tmp("ready-for-review"), routes=github(runs, suites))
        completed = self.run_pending(fake, EVENT_ACTION="ready_for_review")
        self.assertNotIn("concluded skipped", completed.stdout)
        self.assertIn("Core Checks Gate: status=completed conclusion=success", completed.stdout)
        self.assertStillPending(completed, "Full Validation Gate")
        self.assertEqual(fake.calls_to(COMMIT_CHECK_RUNS_ROUTE), [])

        # Once this event's Full Validation Gate passes, so does the gate.
        suites[FULL_VALIDATION_SUITE] = [
            check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T21:00:00Z")
        ]
        fake = FakeGh(self.tmp("ready-for-review-green"), routes=github(runs, suites))
        self.assertGatePassed(self.run_gate(fake, EVENT_ACTION="ready_for_review"))

    def test_another_events_successes_do_not_pass_the_gate(self) -> None:
        # The 1.x.x -> main integration pattern: the pull request's head is a
        # branch head whose push runs passed as docs-only.  GitHub ties those
        # push runs to the open pull request from that branch, so only the
        # event tells them apart from the pull request's own runs, whose gate
        # jobs have not been created yet.
        push = {"event": "push", "head_branch": "1.x.x"}
        runs = [
            workflow_run(3001, FULL_VALIDATION, 21, created=GATE_CREATED - timedelta(minutes=10), **push),
            workflow_run(3002, CORE_CHECKS, 31, created=GATE_CREATED - timedelta(minutes=10), **push),
            *this_events_runs(head_branch="1.x.x"),
        ]
        suites = {
            21: [
                check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T15:25:00Z"),
                check_run("public-docs-lint", "completed", "success", started_at="2026-11-04T15:23:00Z"),
            ],
            31: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T15:24:00Z")],
            FULL_VALIDATION_SUITE: [check_run("lint", "in_progress", None, started_at="2026-11-04T15:33:00Z")],
            CORE_CHECKS_SUITE: [check_run("build smoke", "in_progress", None, started_at="2026-11-04T15:33:00Z")],
        }
        fake = FakeGh(self.tmp("push-context"), routes=github(runs, suites))
        completed = self.run_pending(fake, EVENT_ACTION="opened")
        self.assertStillPending(completed, "Core Checks Gate", "Full Validation Gate")
        self.assertEqual(fake.calls_to(COMMIT_CHECK_RUNS_ROUTE), [])

    def test_runs_for_another_branch_repository_or_pull_request_are_not_read(self) -> None:
        green = {
            21: [check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
            31: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
        }
        own = workflow_run(RUN_ID, GATE_WORKFLOW, GATE_SUITE, created=GATE_CREATED)
        cases = {
            "another branch": {"head_branch": "other"},
            "another repository": {"repository_id": 2},
            "another pull request": {"pull_requests": (PR + 1,)},
        }
        for label, fields in cases.items():
            with self.subTest(case=label):
                runs = [
                    own,
                    workflow_run(3001, FULL_VALIDATION, 21, **fields),
                    workflow_run(3002, CORE_CHECKS, 31, **fields),
                ]
                fake = FakeGh(self.tmp(f"other-{label}"), routes=github(runs, green))
                completed = self.run_pending(fake)
                self.assertStillPending(completed, "Core Checks Gate", "Full Validation Gate")

        # The same holds for a push: another branch pushed at this commit has
        # its own runs, and they are not this push's.
        push = {"event": "push", "pull_requests": ()}
        runs = [
            workflow_run(RUN_ID, GATE_WORKFLOW, GATE_SUITE, created=GATE_CREATED, head_branch="main", **push),
            workflow_run(3001, FULL_VALIDATION, 21, head_branch="1.x.x", **push),
            workflow_run(3002, CORE_CHECKS, 31, head_branch="1.x.x", **push),
        ]
        fake = FakeGh(self.tmp("other-push-branch"), routes=github(runs, green))
        completed = self.run_pending(fake, EVENT_NAME="push", EVENT_ACTION="", PR_NUMBER="", PR_DRAFT="")
        self.assertStillPending(completed, "Core Checks Gate", "Full Validation Gate")

    def test_a_fork_head_is_bound_by_its_branch_and_repository(self) -> None:
        # GitHub ties no workflow run to a pull request whose head is in a
        # fork, this gate's own run included.
        runs = this_events_runs(repository_id=2, pull_requests=())
        suites = {
            FULL_VALIDATION_SUITE: [check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
            CORE_CHECKS_SUITE: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
        }
        fake = FakeGh(self.tmp("fork"), routes=github(runs, suites))
        self.assertGatePassed(self.run_gate(fake))

    def test_a_rerun_is_read_from_its_own_check_suite(self) -> None:
        # A re-run keeps its workflow run and check suite.  The newest check
        # run in this event's suite decides, even when another suite on the
        # commit has a check run that started later still.
        stale = GATE_CREATED - timedelta(hours=1)
        runs = [
            workflow_run(3001, FULL_VALIDATION, 21, created=stale),
            workflow_run(3002, CORE_CHECKS, 31, created=stale),
            *this_events_runs(),
        ]
        later_elsewhere = {
            21: [check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T23:00:00Z")],
            31: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T23:00:00Z")],
            CORE_CHECKS_SUITE: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
        }
        attempts = {
            "red, then green": (("failure", "success"), True),
            "green, then red": (("success", "failure"), False),
        }
        for label, ((first, second), passes) in attempts.items():
            with self.subTest(attempts=label):
                suites = {
                    **later_elsewhere,
                    FULL_VALIDATION_SUITE: [
                        check_run("Full Validation Gate", "completed", second, started_at="2026-11-04T21:00:00Z"),
                        check_run("Full Validation Gate", "completed", first, started_at="2026-11-04T18:00:00Z"),
                    ],
                }
                fake = FakeGh(self.tmp(f"rerun-{label}"), routes=github(runs, suites))
                completed = self.run_gate(fake)
                if passes:
                    self.assertGatePassed(completed)
                else:
                    self.assertGateFailed(completed, f"{ERROR_CHECK_FAILED}Full Validation Gate concluded failure.")

    def test_runs_created_before_the_gate_run_can_still_be_its_events(self) -> None:
        # GitHub creates one event's runs a second or so apart, in either
        # order, so "created at or after the gate run" would leave the gate
        # waiting for runs it already has.  A run of this event is one created
        # close enough to this gate run, or long enough after the previous
        # gate run on the head that it cannot be the previous event's.
        match = SKEW.search(self.script)
        self.assertIsNotNone(match, "SIBLING_RUN_SKEW_SECONDS is not declared")
        skew = int(match.group("seconds"))
        self.assertLessEqual(skew, 300, "a wide window lets an earlier event's runs stand in for this one's")
        green = {
            FULL_VALIDATION_SUITE: [check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
            CORE_CHECKS_SUITE: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T16:00:00Z")],
            21: [check_run("Full Validation Gate", "completed", "failure", started_at="2026-11-04T14:40:00Z")],
            31: [check_run("Core Checks Gate", "completed", "failure", started_at="2026-11-04T14:40:00Z")],
        }
        an_hour_ago = GATE_CREATED - timedelta(hours=1)
        earlier_event = [
            workflow_run(2000, GATE_WORKFLOW, 11, created=an_hour_ago),
            workflow_run(2001, FULL_VALIDATION, 21, created=an_hour_ago),
            workflow_run(2002, CORE_CHECKS, 31, created=an_hour_ago),
        ]
        cases = {
            # (earlier runs on the head, offset of this event's other runs
            # from its gate run in seconds, whether they are bound)
            "first event on the head, runs at the window's edge": ([], -skew, True),
            "first event on the head, runs past the window's edge": ([], -skew - 1, False),
            "runs created long after the previous event": (earlier_event, -10 * skew, True),
            "runs created just after the previous event": (
                earlier_event,
                -3600 + skew - 1,
                False,
            ),
            "previous event close by, runs at the window's edge": (
                [workflow_run(2000, GATE_WORKFLOW, 11, created=GATE_CREATED - timedelta(seconds=skew // 2))],
                -skew,
                True,
            ),
            "previous event close by, runs past the window's edge": (
                [workflow_run(2000, GATE_WORKFLOW, 11, created=GATE_CREATED - timedelta(seconds=skew // 2))],
                -skew - 1,
                False,
            ),
        }
        for label, (previous, offset, bound) in cases.items():
            with self.subTest(case=label):
                runs = [*previous, *this_events_runs(created=GATE_CREATED + timedelta(seconds=offset))]
                runs[len(previous)]["created_at"] = stamp(GATE_CREATED)
                fake = FakeGh(self.tmp(f"window-{offset}-{len(previous)}"), routes=github(runs, green))
                if bound:
                    self.assertGatePassed(self.run_gate(fake))
                else:
                    self.assertStillPending(self.run_pending(fake), "Core Checks Gate", "Full Validation Gate")

    def test_runs_listed_late_are_read_on_a_later_poll(self) -> None:
        # Every poll lists the runs again, so a run GitHub lists late is read,
        # and so is a newer run of this event than the one read before.
        own, *_ = this_events_runs()
        green = body(
            page(
                check_run("Core Checks Gate", "completed", "success", started_at="1"),
                check_run("Full Validation Gate", "completed", "success", started_at="1"),
            )
        )
        fake = FakeGh(
            self.tmp("listed-late"),
            routes=[
                (RUNS_ROUTE, [ok(body(runs_page(own)))], ok(body(runs_page(*this_events_runs())))),
                (CHECK_RUNS_ROUTE, [], ok(green)),
            ],
        )
        completed = self.run_gate(fake)
        self.assertIn(f"Core Checks Gate: query succeeded, no {CORE_CHECKS} run for this pull_request event", completed.stdout)
        self.assertGatePassed(completed)
        self.assertEqual(len(fake.run_calls), 2, fake.calls)
        self.assertEqual(len(fake.check_run_calls), 2, fake.calls)

    def test_a_workflow_this_event_did_not_start_is_read_from_its_newest_run(self) -> None:
        # Which events start each workflow is read from the workflow files, so
        # a trigger change that the gate does not know about fails here.  The
        # only runs of either workflow are an earlier event's, an hour old: a
        # workflow this event started has to be read from this event's run,
        # and is pending until it exists.
        gate_triggers = self.workflow["on"]
        workflows = {path: load_workflow_file(path)["on"] for path in (FULL_VALIDATION, CORE_CHECKS)}
        check_of = {FULL_VALIDATION: "Full Validation Gate", CORE_CHECKS: "Core Checks Gate"}

        def starts(triggers: dict, event: str, action: str) -> bool:
            if event not in triggers:
                return False
            if event != "pull_request":
                return True
            types = (triggers[event] or {}).get("types", GITHUB_DEFAULT_PULL_REQUEST_TYPES)
            return action in types

        for path, triggers in workflows.items():
            for event in ("pull_request", "push", "merge_group"):
                with self.subTest(workflow=path, event=event, branches=True):
                    # A branch the gate runs for but the workflow does not
                    # would leave the gate waiting for a run that never comes.
                    self.assertLessEqual(
                        set(gate_triggers[event]["branches"]),
                        set(triggers[event]["branches"]),
                    )

        events = [("pull_request", action) for action in gate_triggers["pull_request"]["types"]]
        events += [("push", ""), ("merge_group", "checks_requested")]
        stale = GATE_CREATED - timedelta(hours=1)
        for event, action in events:
            with self.subTest(event=event, action=action):
                fields = {"event": event} if event == "pull_request" else {"event": event, "pull_requests": ()}
                runs = [
                    workflow_run(3000, GATE_WORKFLOW, 11, created=stale, **fields),
                    workflow_run(3001, FULL_VALIDATION, 21, created=stale, **fields),
                    workflow_run(3002, CORE_CHECKS, 31, created=stale, **fields),
                    workflow_run(RUN_ID, GATE_WORKFLOW, GATE_SUITE, created=GATE_CREATED, **fields),
                ]
                suites = {
                    21: [check_run("Full Validation Gate", "completed", "success", started_at="2026-11-04T15:00:00Z")],
                    31: [check_run("Core Checks Gate", "completed", "success", started_at="2026-11-04T15:00:00Z")],
                }
                context = {"EVENT_NAME": event, "EVENT_ACTION": action}
                if event != "pull_request":
                    context.update(PR_NUMBER="", PR_DRAFT="")
                fake = FakeGh(self.tmp(f"started-{event}-{action}"), routes=github(runs, suites))
                completed = self.run_pending(fake, **context)
                pending = [check_of[path] for path in (CORE_CHECKS, FULL_VALIDATION) if starts(workflows[path], event, action)]
                self.assertTrue(pending, "Full Validation runs for every event the gate runs for")
                self.assertStillPending(completed, *pending)
                for path in (CORE_CHECKS, FULL_VALIDATION):
                    if check_of[path] not in pending:
                        self.assertIn(f"{check_of[path]}: status=completed conclusion=success", completed.stdout)

    def test_each_check_is_read_from_the_workflow_that_reports_it(self) -> None:
        suite_workflow = {FULL_VALIDATION_SUITE: FULL_VALIDATION, CORE_CHECKS_SUITE: CORE_CHECKS}
        reported = {
            suite: [
                check_run(job["name"], "completed", "success", started_at="2026-11-04T16:00:00Z")
                for job in load_workflow_file(path)["jobs"].values()
                if "name" in job
            ]
            for suite, path in suite_workflow.items()
        }
        for profile, checks in PROFILE_CHECKS.items():
            with self.subTest(profile=profile):
                fake = FakeGh(self.tmp(f"reported-{profile}"), routes=github(this_events_runs(), reported))
                self.assertGatePassed(self.run_gate(fake, profile=profile))
                suites = [int(suite) for suite in re.findall(r"/check-suites/(\d+)/check-runs\?", "\n".join(fake.calls))]
                self.assertEqual(len(suites), len(checks), fake.calls)
                for check, suite in zip(checks, suites):
                    jobs = load_workflow_file(suite_workflow[suite])["jobs"].values()
                    self.assertIn(check, [job.get("name") for job in jobs], f"{check} read from {suite_workflow[suite]}")

    # -- drafts ------------------------------------------------------------

    def test_a_draft_fails_the_gate_before_anything_is_read(self) -> None:
        for profile in ("github-metadata", "source"):
            with self.subTest(profile=profile):
                fake = FakeGh(self.tmp(f"draft-{profile}"), default=ok(body(page())))
                completed = self.run_gate(fake, profile=profile, PR_DRAFT="true")
                self.assertGateFailed(
                    completed,
                    f"{ERROR_CHECK_FAILED}Pull request #{PR} is a draft: draft pull requests are not mergeable.",
                )
                self.assertEqual(fake.calls, [])

        fake = FakeGh(self.tmp("draft-unknown"), default=ok(body(page())))
        completed = self.run_gate(fake, profile="github-metadata", PR_DRAFT="")
        self.assertGateFailed(completed, f"{ERROR_CHECK_FAILED}Pull request draft state '' could not be read.")

        # Only a pull request can be a draft.
        fake = FakeGh(self.tmp("draft-push"), default=ok(body(page())))
        completed = self.run_gate(
            fake, profile="github-metadata", EVENT_NAME="push", EVENT_ACTION="", PR_NUMBER="", PR_DRAFT=""
        )
        self.assertGatePassed(completed)

    def test_the_gate_job_runs_for_drafts_and_again_when_ready(self) -> None:
        # A job skipped by its condition reports a skipped check, and branch
        # protection treats a skipped required check as passing.  The gate
        # must run, and fail, for a draft; marking it ready runs it afresh.
        self.assertEqual(self.job.get("if"), "${{ always() }}")
        self.assertIn("ready_for_review", self.workflow["on"]["pull_request"]["types"])
        self.assertEqual(self.step["env"]["PR_DRAFT"], "${{ github.event.pull_request.draft }}")

    def test_the_gate_token_can_read_the_runs_it_binds_to(self) -> None:
        # Job permissions replace the workflow's, and only the gate job, which
        # runs no code from the change, may read other workflows' runs.
        self.assertEqual(self.job.get("permissions"), {"actions": "read", "checks": "read"})
        for name, job in self.workflow["jobs"].items():
            if name != GATE_JOB:
                self.assertNotIn("permissions", job, name)
        self.assertNotIn("actions", self.workflow["permissions"])
        self.assertNotIn("write", self.workflow["permissions"].values())

    # -- the deadline ------------------------------------------------------

    def test_the_deadline_counts_time_spent_in_api_calls(self) -> None:
        # Two checks, one second per call, a one second poll interval and a
        # four second budget.  Each poll lists the runs and reads both checks.
        # A deadline that counted only the sleeps would run four polls and
        # therefore read the checks eight times, whatever
        # the machine is doing; a wall-clock deadline is spent by the calls
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
            len(fake.check_run_calls),
            8,
            f"the wait budget ignored the time spent in the API: {len(fake.check_run_calls)} "
            f"check reads in {elapsed:.1f}s",
        )

    # -- scaffolding -------------------------------------------------------

    def tmp(self, name: str) -> Path:
        return Path(self._tmpdir.name) / name


def setUpModule() -> None:
    if not WORKFLOW.exists():  # pragma: no cover - misconfigured checkout
        raise AssertionError(f"{WORKFLOW} not found")


if __name__ == "__main__":
    unittest.main()
