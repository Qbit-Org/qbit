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

Not provable here: whether the hosted ``Required Merge Gate`` check is
attached to a branch ruleset, and whether the real API agrees with the shapes
modelled below.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import unittest
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
ERROR_TIMED_OUT = "::error title=Required Merge Gate timed out::"
WARNING_RETRYING = "::warning title=Required Merge Gate retrying::"


def check_run(name: str, status: str, conclusion: str | None = None, **stamps: str) -> dict:
    run = {"name": name, "status": status, "conclusion": conclusion}
    run.update(stamps)
    return run


def page(*runs: dict) -> dict:
    return {"total_count": len(runs), "check_runs": list(runs)}


def body(*pages: dict) -> str:
    """Concatenated page objects, the way ``gh api --paginate`` emits them."""
    return "".join(json.dumps(item) for item in pages)


def ok(payload: str) -> tuple[int, str]:
    return (0, payload)


class FakeGh:
    """A ``gh`` on PATH that scripts one response per call.

    ``responses`` is consumed in order; once exhausted, ``default`` answers
    every further call.  Each entry is ``(exit_code, stdout)``, optionally with
    a third element written to stderr the way ``gh`` reports an HTTP error.
    ``delay`` makes every call take that many seconds, so a test can show the
    wait deadline counts time spent in the API and not only in ``sleep``.
    """

    def __init__(
        self,
        directory: Path,
        *,
        responses: list[tuple] | None = None,
        default: tuple | None = None,
        delay: int = 0,
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.calls_path = directory / "calls"
        replies = directory / "replies"
        replies.mkdir()
        for name, reply in [(str(i), r) for i, r in enumerate(responses or [], start=1)]:
            self._write_reply(replies, name, reply)
        if default is not None:
            self._write_reply(replies, "default", default)
        script = directory / "gh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            f'printf "%s\\n" "$*" >> {self.calls_path!s}\n'
            f'call="$(wc -l < {self.calls_path!s})"\n'
            f'reply="{replies!s}/${{call}}"\n'
            f'[[ -f "${{reply}}" ]] || reply="{replies!s}/default"\n'
            'if [[ ! -f "${reply}" ]]; then\n'
            '  echo "fake gh: unscripted call: $*" >&2\n'
            "  exit 97\n"
            "fi\n"
            f"{f'sleep {delay}' if delay else ''}\n"
            'code="$(head -n 1 "${reply}")"\n'
            '[[ -f "${reply}.err" ]] && cat "${reply}.err" >&2\n'
            'tail -n +2 "${reply}"\n'
            'exit "${code}"\n',
            encoding="utf8",
        )
        script.chmod(0o755)

    @staticmethod
    def _write_reply(replies: Path, name: str, reply: tuple) -> None:
        code, payload = reply[0], reply[1]
        (replies / name).write_text(f"{code}\n{payload}", encoding="utf8")
        if len(reply) > 2 and reply[2]:
            (replies / f"{name}.err").write_text(reply[2], encoding="utf8")

    @property
    def calls(self) -> list[str]:
        if not self.calls_path.exists():
            return []
        return self.calls_path.read_text(encoding="utf8").splitlines()


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
            "SHA": "0" * 40,
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
                self.assertEqual(len(fake.calls), 1, fake.calls)

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
