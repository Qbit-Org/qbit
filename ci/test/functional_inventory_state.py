#!/usr/bin/env python3
#
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Prepare and update state for non-failfast functional failure inventory runs."""

from __future__ import annotations

import argparse
import csv
import pathlib
import re
from typing import Iterable

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
FAILED_LINE_RE = re.compile(r"\b\d+/\d+\s+-\s+(.+?)\s+failed,\s+Duration:")


def normalize_test_name(name: str) -> str:
    return " ".join(name.strip().split())


def read_test_list(path: pathlib.Path) -> set[str]:
    tests: set[str] = set()
    if not path.exists():
        return tests
    for raw_line in path.read_text(encoding="utf8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tests.add(normalize_test_name(line))
    return tests


def write_test_list(path: pathlib.Path, tests: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf8") as file:
        for test in sorted(set(tests)):
            file.write(f"{test}\n")


def write_csv_list(path: pathlib.Path, tests: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(",".join(sorted(set(tests))), encoding="utf8")


def select_for_retest(tests: set[str], count: int) -> set[str]:
    if count <= 0:
        return set()
    return set(sorted(tests)[:count])


def parse_results_csv(path: pathlib.Path, slow_threshold_seconds: int) -> tuple[set[str], set[str], set[str], bool]:
    if not path.exists():
        return set(), set(), set(), False

    failed: set[str] = set()
    passed: set[str] = set()
    slow_passed: set[str] = set()

    with path.open(encoding="utf8", newline="") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames is None or "test" not in reader.fieldnames or "status" not in reader.fieldnames:
            raise RuntimeError(f"Unexpected CSV format in {path}")
        for row in reader:
            test = normalize_test_name(row.get("test", ""))
            if not test or test == "ALL":
                continue
            status = row.get("status", "").strip()
            try:
                duration = float(row.get("duration(seconds)", "0").strip() or "0")
            except ValueError:
                duration = 0.0
            if status == "Failed":
                failed.add(test)
            elif status == "Passed":
                passed.add(test)
                if duration >= slow_threshold_seconds:
                    slow_passed.add(test)

    return failed, passed, slow_passed, True


def parse_failed_from_ci_log(path: pathlib.Path) -> set[str]:
    failed: set[str] = set()
    if not path.exists():
        return failed
    with path.open(encoding="utf8", errors="ignore") as file:
        for line in file:
            clean = ANSI_ESCAPE_RE.sub("", line)
            match = FAILED_LINE_RE.search(clean)
            if match:
                failed.add(normalize_test_name(match.group(1)))
    return failed


def render_list(title: str, values: set[str], limit: int = 200) -> list[str]:
    lines = [f"### {title}", ""]
    if not values:
        lines.append("- (none)")
        lines.append("")
        return lines
    for item in sorted(values)[:limit]:
        lines.append(f"- `{item}`")
    if len(values) > limit:
        lines.append(f"- ... ({len(values) - limit} more)")
    lines.append("")
    return lines


def prepare(args: argparse.Namespace) -> None:
    state_dir = pathlib.Path(args.state_dir)
    static_known_good_path = pathlib.Path(args.static_known_good_file)
    exclude_list_out = pathlib.Path(args.exclude_list_out)
    exclude_csv_out = pathlib.Path(args.exclude_csv_out)
    summary_out = pathlib.Path(args.summary_out)

    quarantine = read_test_list(state_dir / "quarantine.txt")
    known_good_slow = read_test_list(state_dir / "known_good_slow.txt")
    static_known_good = read_test_list(static_known_good_path)

    retest_quarantine = select_for_retest(quarantine, args.retest_quarantine)
    retest_known_good = select_for_retest(known_good_slow, args.retest_known_good)
    include_tests_file = getattr(args, "include_tests_file", None)
    include_tests = read_test_list(pathlib.Path(include_tests_file)) if include_tests_file else set()
    force_run = retest_quarantine | retest_known_good | include_tests

    excluded = (quarantine - retest_quarantine) | (known_good_slow - retest_known_good) | static_known_good

    # Apply max-tests limit if requested.
    deferred: set[str] = set()
    max_tests = getattr(args, "max_tests", 0) or 0
    available_tests_file = getattr(args, "available_tests_file", None)
    if max_tests > 0 and available_tests_file:
        all_available = read_test_list(pathlib.Path(available_tests_file))
        force_run_base = {t.split()[0] for t in force_run if t}
        force_run_base &= all_available

        # Ensure forced tests are not excluded by previous state/static lists.
        excluded = {e for e in excluded if e.split()[0] not in force_run_base}

        # A base name is fully excluded only when it appears without arguments
        # (bare name in --exclude removes all variants).
        fully_excluded_base = {e.split()[0] for e in excluded if " " not in e}
        remaining = sorted(all_available - fully_excluded_base)

        if len(remaining) > max_tests:
            cursor_path = state_dir / "max_tests_cursor.txt"
            cursor = 0
            if cursor_path.exists():
                try:
                    cursor = int(cursor_path.read_text(encoding="utf8").strip())
                except (ValueError, OSError):
                    cursor = 0
            dynamic_pool = sorted(set(remaining) - force_run_base)
            dynamic_slots = max(max_tests - len(force_run_base), 0)
            selected = set(force_run_base)
            if dynamic_slots > 0 and dynamic_pool:
                cursor = cursor % len(dynamic_pool)
                selected |= set(dynamic_pool[i % len(dynamic_pool)] for i in range(cursor, cursor + dynamic_slots))
                next_cursor = (cursor + dynamic_slots) % len(dynamic_pool)
            else:
                next_cursor = 0
            deferred = set(remaining) - selected
            excluded = excluded | deferred

            cursor_path.parent.mkdir(parents=True, exist_ok=True)
            cursor_path.write_text(str(next_cursor), encoding="utf8")

        write_test_list(state_dir / "deferred.txt", deferred)

    write_test_list(exclude_list_out, excluded)
    write_csv_list(exclude_csv_out, excluded)
    write_test_list(state_dir / "retest_quarantine.txt", retest_quarantine)
    write_test_list(state_dir / "retest_known_good.txt", retest_known_good)

    summary_lines = [
        "## Functional Inventory Prepare",
        "",
        f"- Excluded tests: {len(excluded)}",
        f"- Existing quarantine tests: {len(quarantine)}",
        f"- Existing dynamic known-good tests: {len(known_good_slow)}",
        f"- Static known-good tests: {len(static_known_good)}",
        f"- Retesting quarantined tests this run: {len(retest_quarantine)}",
        f"- Retesting dynamic known-good tests this run: {len(retest_known_good)}",
        f"- Force-included tests this run: {len(force_run)}",
        "",
    ]
    if max_tests > 0 and available_tests_file:
        summary_lines.extend([
            f"- Max tests per run: {max_tests}",
            f"- Tests eligible to run: {len(remaining)}",
            f"- Tests deferred to future runs: {len(deferred)}",
            "",
        ])
        summary_lines.extend(render_list("Deferred Tests", deferred, limit=50))
    summary_lines.extend(render_list("Force Included", force_run, limit=50))
    summary_lines.extend(render_list("Retest Quarantine", retest_quarantine, limit=50))
    summary_lines.extend(render_list("Retest Known Good", retest_known_good, limit=50))

    summary_out.parent.mkdir(parents=True, exist_ok=True)
    summary_out.write_text("\n".join(summary_lines), encoding="utf8")


def update(args: argparse.Namespace) -> None:
    state_dir = pathlib.Path(args.state_dir)
    static_known_good_path = pathlib.Path(args.static_known_good_file)
    results_file = pathlib.Path(args.results_file)
    ci_log_file = pathlib.Path(args.ci_log_file)
    summary_out = pathlib.Path(args.summary_out)
    new_failures_out = pathlib.Path(args.new_failures_out)
    all_failures_out = pathlib.Path(args.all_failures_out)
    exclude_list_out = pathlib.Path(args.exclude_list_out)
    exclude_csv_out = pathlib.Path(args.exclude_csv_out)

    quarantine_old = read_test_list(state_dir / "quarantine.txt")
    known_good_old = read_test_list(state_dir / "known_good_slow.txt")
    static_known_good = read_test_list(static_known_good_path)

    failed, passed, slow_passed, had_results = parse_results_csv(
        results_file, slow_threshold_seconds=args.slow_threshold_seconds
    )
    if not had_results:
        failed = parse_failed_from_ci_log(ci_log_file)

    quarantine_new = (quarantine_old - passed) | failed
    known_good_new = known_good_old - failed
    if had_results:
        known_good_new |= slow_passed

    write_test_list(state_dir / "quarantine.txt", quarantine_new)
    write_test_list(state_dir / "known_good_slow.txt", known_good_new)

    excluded = quarantine_new | known_good_new | static_known_good
    write_test_list(exclude_list_out, excluded)
    write_csv_list(exclude_csv_out, excluded)

    failed_previously_excluded = quarantine_old | known_good_old | static_known_good
    new_failures = failed - failed_previously_excluded
    newly_quarantined = quarantine_new - quarantine_old
    resolved_quarantine = quarantine_old - quarantine_new
    newly_known_good = known_good_new - known_good_old
    removed_known_good = known_good_old - known_good_new

    write_test_list(new_failures_out, new_failures)
    write_test_list(all_failures_out, failed)

    summary_lines = [
        "## Functional Inventory Update",
        "",
        f"- Results CSV available: {'yes' if had_results else 'no'}",
        f"- Failed tests this run: {len(failed)}",
        f"- New failures (not previously excluded): {len(new_failures)}",
        f"- Quarantine size: {len(quarantine_old)} -> {len(quarantine_new)}",
        f"- Dynamic known-good size: {len(known_good_old)} -> {len(known_good_new)}",
        "",
    ]
    summary_lines.extend(render_list("New Failures", new_failures))
    summary_lines.extend(render_list("All Failures This Run", failed))
    summary_lines.extend(render_list("Newly Quarantined", newly_quarantined))
    summary_lines.extend(render_list("Resolved Quarantine Entries", resolved_quarantine))
    summary_lines.extend(render_list("New Dynamic Known Good", newly_known_good))
    summary_lines.extend(render_list("Removed Dynamic Known Good", removed_known_good))

    summary_out.parent.mkdir(parents=True, exist_ok=True)
    summary_out.write_text("\n".join(summary_lines), encoding="utf8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare", help="prepare exclusion state for a run")
    prepare_parser.add_argument("--state-dir", required=True)
    prepare_parser.add_argument("--static-known-good-file", required=True)
    prepare_parser.add_argument("--exclude-list-out", required=True)
    prepare_parser.add_argument("--exclude-csv-out", required=True)
    prepare_parser.add_argument("--summary-out", required=True)
    prepare_parser.add_argument("--retest-quarantine", type=int, default=0)
    prepare_parser.add_argument("--retest-known-good", type=int, default=0)
    prepare_parser.add_argument("--max-tests", type=int, default=0,
                                help="max base test scripts to run per invocation (0 = unlimited)")
    prepare_parser.add_argument("--available-tests-file", default=None,
                                help="file listing all available base test names, one per line")
    prepare_parser.add_argument("--include-tests-file", default=None,
                                help="file listing tests to force-run (base names or full test args), one per line")
    prepare_parser.set_defaults(func=prepare)

    update_parser = subparsers.add_parser("update", help="update exclusion state after a run")
    update_parser.add_argument("--state-dir", required=True)
    update_parser.add_argument("--static-known-good-file", required=True)
    update_parser.add_argument("--results-file", required=True)
    update_parser.add_argument("--ci-log-file", required=True)
    update_parser.add_argument("--summary-out", required=True)
    update_parser.add_argument("--new-failures-out", required=True)
    update_parser.add_argument("--all-failures-out", required=True)
    update_parser.add_argument("--exclude-list-out", required=True)
    update_parser.add_argument("--exclude-csv-out", required=True)
    update_parser.add_argument("--slow-threshold-seconds", type=int, default=300)
    update_parser.set_defaults(func=update)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
