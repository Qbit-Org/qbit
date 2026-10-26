#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Prove that a CI job's expected unit-test suites really ran and passed.

ctest exits 0 when a suite is skipped: a Boost suite that was compiled out, or
filtered away, prints "no test cases matching filter", which the suite's
SKIP_REGULAR_EXPRESSION turns into a skip. A selection regex can also drift and
quietly select fewer suites. ci/test/03_test_script.sh therefore runs this
check after ctest whenever CTEST_EXPECTED_SUITES is set:

* the tests ctest selected (``ctest --show-only=json-v1`` with the same
  arguments as the run) must be exactly the expected suites;
* every expected suite must appear once in ctest's JUnit file with status
  ``run`` and no failure; skipped (``notrun``), disabled, failed and missing
  suites fail the check.

It writes a Markdown table of the results, which the workflow adds to the job
summary, and exits non-zero on any violation.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PASSED = "passed"


def parse_expected(text: str) -> list[str]:
    names = text.split()
    if not names:
        raise ValueError("no expected suites given")
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"expected suites listed more than once: {', '.join(duplicates)}")
    return names


def selected_tests(listing: str) -> list[str]:
    """Test names from ``ctest --show-only=json-v1`` output."""
    return [test["name"] for test in json.loads(listing).get("tests", [])]


def junit_outcomes(junit: str) -> dict[str, tuple[str, str]]:
    """Map each test case in a ctest JUnit file to (outcome, time in seconds)."""
    root = ET.fromstring(junit)
    outcomes: dict[str, tuple[str, str]] = {}
    for case in root.iter("testcase"):
        name = case.get("name", "")
        status = case.get("status", "")
        if case.find("failure") is not None or case.find("error") is not None or status == "fail":
            outcome = "failed"
        elif case.find("skipped") is not None or status == "notrun":
            outcome = "skipped"
        elif status == "disabled":
            outcome = "disabled"
        elif status == "run":
            outcome = PASSED
        else:
            outcome = f"unknown status {status!r}"
        if name in outcomes:
            outcome = "reported more than once"
        outcomes[name] = (outcome, case.get("time", ""))
    return outcomes


def check(expected: list[str], selected: list[str], outcomes: dict[str, tuple[str, str]]) -> list[str]:
    errors = []
    missing = [name for name in expected if name not in selected]
    unexpected = [name for name in selected if name not in expected]
    if missing:
        errors.append(f"ctest did not select expected suite(s): {', '.join(missing)}")
    if unexpected:
        errors.append(f"ctest selected suite(s) that are not expected: {', '.join(unexpected)}")
    for name in expected:
        outcome = outcomes.get(name, ("missing from the JUnit results", ""))[0]
        if outcome != PASSED:
            errors.append(f"{name}: {outcome}")
    return errors


def summary(expected: list[str], outcomes: dict[str, tuple[str, str]], errors: list[str]) -> str:
    lines = ["| suite | result | time (s) |", "| --- | --- | --- |"]
    for name in expected:
        outcome, seconds = outcomes.get(name, ("missing", ""))
        lines.append(f"| {name} | {outcome} | {seconds} |")
    lines.append("")
    if errors:
        lines.append("Unit-test evidence check failed:")
        lines.extend(f"- {error}" for error in errors)
    else:
        lines.append(f"All {len(expected)} expected suites were selected, executed and passed; none was skipped.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expected", required=True, help="space-separated suite names (CTEST_EXPECTED_SUITES)")
    parser.add_argument("--listing", required=True, type=Path, help="ctest --show-only=json-v1 output")
    parser.add_argument("--junit", required=True, type=Path, help="ctest --output-junit file")
    parser.add_argument("--summary", type=Path, help="write a Markdown summary here")
    args = parser.parse_args(argv)

    try:
        expected = parse_expected(args.expected)
    except ValueError as e:
        print(f"Error: CTEST_EXPECTED_SUITES: {e}", file=sys.stderr)
        return 1
    errors: list[str] = []
    try:
        selected = selected_tests(args.listing.read_text(encoding="utf8"))
    except (OSError, ValueError, KeyError, TypeError) as e:
        selected = []
        errors.append(f"unreadable ctest test listing {args.listing}: {e}")
    try:
        outcomes = junit_outcomes(args.junit.read_text(encoding="utf8"))
    except (OSError, ET.ParseError) as e:
        outcomes = {}
        errors.append(f"unreadable JUnit results {args.junit}: {e}")
    errors.extend(check(expected, selected, outcomes))

    text = summary(expected, outcomes, errors)
    if args.summary is not None:
        args.summary.write_text(text, encoding="utf8")
    print(text, end="")
    for error in errors:
        print(f"Error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
