#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Turn PQ canary samples into the R5 canary figures (#184).

Each figure is printed with its sample count, its coverage and pass, fail or
unknown:

1. the pool node's pinned link to the archive node is manual and hybrid in at
   least 99% of samples, excluding restarts;
2. no malformed_record, first_packet_failed or fallback entry between
   known-good endpoints, on every monitored canary node;
3. closed_after_switch entries between known-good endpoints, listed for triage
   (not part of the canary verdict);
4. the canary archive node's connections_in stays within +-20% of the control
   node's, relative to their baseline ratio, per UTC day, excluding the 48 hours
   after a restart of either node.

Evidence rules:
- A jump in a node's boot time (time - uptime) is a restart. The samples from
  the last sample before it to the end of the grace period after it are a gap,
  not a failure.
- Coverage is the share of the expected 5-minute samples that are present and
  usable. A figure, node or day below --min-coverage (default 90%) is unknown,
  not judged.
- Failure rings are read by their per-ring sequence. A ring that wrapped is
  still complete when the entries read continue from the last sequence already
  processed; entries are lost only when the oldest entry read is past that point
  (a wrap between samples that hid unread entries), and across a changed
  instance_id. A lost stretch makes that interval unknown for that ring.
- Missing evidence is unknown, never clean: the pinned link passes only if it
  would pass with every unknown sample counted against it.
- The report names known-good peers by their label, never by address; peer
  addresses stay in failures.jsonl and the known-good list on the node.

Exit status: 0 when the verdict (figures 1, 2 and 4) is pass, 1 when any of
them fails, 3 when none fails but one is unknown, 2 for bad arguments or input.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_canary  # noqa: E402

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"
PINNED_THRESHOLD = 0.99
CONNECTIONS_TOLERANCE = 0.20
CONNECTIONS_RESTART_EXCLUSION = 48 * 3600
DEFAULT_MIN_COVERAGE = 0.90
RESTART_TOLERANCE = 120  # seconds of boot-time jitter that is not a restart
MONITORED_OUTCOMES = {"malformed_record", "first_packet_failed", "fallback"}
TRIAGE_OUTCOMES = {"closed_after_switch"}
RINGS = ("inbound", "outbound")
LABEL = re.compile(r"^[A-Za-z0-9._-]+$")
REMEDY = ("an automatic connection held the pinned address in {count} sample(s), so the -addnode thread "
          "(GetAddedNodeInfo) skipped it. Remedy: run `qbit-cli disconnectnode <pinned address>` once; "
          "the -addnode thread reconnects it as manual within about 60 s.")


def parse_time(text: str) -> int:
    """Epoch seconds from Unix seconds or an ISO 8601 time such as 2026-10-20T00:00:00Z (UTC unless it says otherwise)."""
    text = text.strip()
    if text.isdigit():
        return int(text)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"expected Unix seconds or an ISO 8601 time such as 2026-11-02T00:00:00Z, got {text!r}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def utc(epoch: int | float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_int(value: str | None) -> int | None:
    try:
        return None if value is None else int(value)
    except ValueError:
        return None


def percent(share: float | None) -> str:
    return "n/a" if share is None else f"{100 * share:.1f}%"


def expected_samples(begin: int, end: int, interval: int, phase: int | None = None) -> int:
    """Samples expected in [begin, end] at phase + k * interval (phase defaults to begin)."""
    phase = begin if phase is None else phase
    first = phase + -(-(begin - phase) // interval) * interval
    return 0 if end < first else (end - first) // interval + 1


@dataclass
class Figure:
    name: str
    result: str
    samples: int
    coverage: float | None
    summary: str = ""
    details: list[str] = field(default_factory=list)


@dataclass
class Window:
    start: int
    end: int

    def contains(self, time: int) -> bool:
        return self.start <= time <= self.end

    def overlaps(self, begin: int, finish: int) -> bool:
        return begin <= self.end and finish >= self.start


# ---------------------------------------------------------------------------
# Restarts
# ---------------------------------------------------------------------------


@dataclass
class Restart:
    last_seen: int  # time of the last sample of the previous run
    boot: int       # boot time of the new run


def restarts(rows: list[dict[str, str | None]]) -> list[Restart]:
    """Restarts seen as a jump in boot time (time - uptime) or a new instance_id."""
    found = []
    previous: tuple[int, int, str | None] | None = None
    for row in rows:
        time, uptime = as_int(row["time"]), as_int(row["uptime"])
        if time is None or uptime is None:
            continue
        boot, instance = time - uptime, row["instance_id"]
        if previous is not None:
            last_time, last_boot, last_instance = previous
            new_instance = instance is not None and last_instance is not None and instance != last_instance
            if boot > last_boot + RESTART_TOLERANCE or new_instance:
                found.append(Restart(last_seen=last_time, boot=boot))
        previous = (time, boot, instance)
    return found


def merged_gaps(node_restarts: Iterable[Restart], grace: int) -> list[tuple[int, int]]:
    """Restart gaps as merged (start, end] intervals."""
    merged: list[tuple[int, int]] = []
    for low, high in sorted((restart.last_seen, restart.boot + grace) for restart in node_restarts):
        if merged and low <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged


def missing_samples(after: int, before: int, interval: int, gaps: list[tuple[int, int]]) -> tuple[int, int]:
    """(unknown, excluded) counts of the samples expected strictly between two sample times."""
    count = int((before - after) / interval + 0.5) - 1
    if count <= 0:
        return 0, 0
    excluded = 0
    for low, high in gaps:
        # Expected times after + i * interval, 1 <= i <= count, inside (low, high].
        first = max(1, (low - after) // interval + 1)
        last = min(count, (high - after) // interval)
        excluded += max(0, last - first + 1)
    return count - excluded, excluded


# ---------------------------------------------------------------------------
# Figure 1: the pinned link
# ---------------------------------------------------------------------------


def evaluate_pinned(pool: list[dict[str, str | None]] | None, archive: list[dict[str, str | None]] | None,
                    window: Window, interval: int, grace: int, min_coverage: float) -> Figure:
    name = "pinned link manual and hybrid in >= 99% of samples, excluding restarts"
    if not pool:
        return Figure(name, UNKNOWN, 0, None, "no pool node samples")
    gaps = merged_gaps(restarts(pool) + (restarts(archive) if archive else []), grace)
    good = bad = unknown = excluded = automatic = 0
    rows = sorted(((int(row["time"]), row) for row in pool if row["time"] is not None and window.contains(int(row["time"]))),
                  key=lambda item: item[0])
    previous = window.start - interval
    for time, row in rows + [(window.end + interval, None)]:
        missing, skipped = missing_samples(previous, time, interval, gaps)
        unknown += missing
        excluded += skipped
        previous = time
        if row is None:
            break
        uptime = as_int(row["uptime"])
        if any(low < time <= high for low, high in gaps) or (uptime is not None and uptime < grace):
            excluded += 1
        elif row["sample_ok"] != "1" or row["pinned_present"] is None:
            unknown += 1
        elif row["pinned_present"] == "1" and row["pinned_connection_type"] == "manual" and row["pinned_transport_pq"] == "1":
            good += 1
        else:
            bad += 1
            if row["pinned_present"] == "1" and row["pinned_connection_type"] not in (None, "manual"):
                automatic += 1
    total = good + bad + unknown
    if total == 0:
        return Figure(name, UNKNOWN, 0, None, f"no samples outside restarts (excluded={excluded})")
    coverage = (good + bad) / total
    if coverage < min_coverage:
        result = UNKNOWN
    elif good / total >= PINNED_THRESHOLD:
        result = PASS
    elif (good + unknown) / total < PINNED_THRESHOLD:
        result = FAIL
    else:
        result = UNKNOWN
    figure = Figure(name, result, total, coverage,
                    f"hybrid={good} not_hybrid={bad} unknown={unknown} excluded={excluded} ({100 * good / total:.2f}% hybrid)")
    if automatic:
        figure.details.append(REMEDY.format(count=automatic))
    return figure


# ---------------------------------------------------------------------------
# Figures 2 and 3: failure entries between known-good endpoints
# ---------------------------------------------------------------------------


def endpoint_key(address: str, port: Any) -> str:
    address = address.strip().lower()
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


class KnownGood:
    """Known-good endpoints, each with a label that the report prints instead of the address.

    An entry is address:port, or an address alone to match any port: inbound
    failures carry the peer's source port, which changes per connection.
    """

    def __init__(self, endpoints: dict[str, str], addresses: dict[str, str]) -> None:
        self.endpoints = endpoints  # address:port -> label
        self.addresses = addresses  # address -> label

    def __bool__(self) -> bool:
        return bool(self.endpoints or self.addresses)

    def label(self, endpoint: Any) -> str | None:
        """The label of a known-good endpoint, else None."""
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("address"), str):
            return None
        key = endpoint_key(endpoint["address"], endpoint.get("port"))
        return self.endpoints.get(key) or self.addresses.get(endpoint["address"].strip().lower())


def read_known_good(path: Path) -> KnownGood:
    """One endpoint per line, then an optional label: address:port, [ipv6]:port, an address or [ipv6].

    # starts a comment. Unlabeled entries are known-good-1, known-good-2, ... in file
    order. Errors name the line, never its address.
    """
    endpoints: dict[str, str] = {}
    addresses: dict[str, str] = {}
    count = 0
    for number, raw in enumerate(path.read_text(encoding="utf8").splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) > 2:
            raise ValueError(f"{path}:{number}: expected an endpoint and at most one label")
        line = fields[0].lower()
        if line.startswith("["):
            address, close, rest = line[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else None
            if not close or (rest and port is None):
                raise ValueError(f"{path}:{number}: expected [ipv6] or [ipv6]:port")
        elif line.count(":") == 1:
            address, _, port = line.partition(":")
        elif ":" in line:
            raise ValueError(f"{path}:{number}: write an IPv6 endpoint as [address] or [address]:port")
        else:
            address, port = line, None
        if not address or (port is not None and not (port.isdigit() and 0 < int(port) < 65536)):
            raise ValueError(f"{path}:{number}: expected address or address:port with a port from 1 to 65535")
        count += 1
        label = fields[1] if len(fields) == 2 else f"known-good-{count}"
        if not LABEL.match(label):
            raise ValueError(f"{path}:{number}: a label is letters, digits, '.', '_' or '-'")
        target = addresses if port is None else endpoints
        key = address if port is None else endpoint_key(address, int(port))
        if key in target:
            raise ValueError(f"{path}:{number}: endpoint listed twice")
        target[key] = label
    return KnownGood(endpoints, addresses)


def ring_of(record: dict[str, Any], direction: str) -> dict[str, Any] | None:
    """A structurally valid ring: integer counters and entries with consecutive sequences ending at last_sequence."""
    ring = (record.get("recent_failures") or {}).get(direction)
    if not isinstance(ring, dict) or not isinstance(ring.get("entries"), list):
        return None
    last, dropped = ring.get("last_sequence"), ring.get("dropped")
    if not isinstance(last, int) or not isinstance(dropped, int) or last < 0 or dropped < 0:
        return None
    sequences: list[Any] = [entry.get("sequence") if isinstance(entry, dict) else None for entry in ring["entries"]]
    if any(not isinstance(sequence, int) for sequence in sequences):
        return None
    if any(after != before + 1 for before, after in zip(sequences, sequences[1:])):
        return None
    if sequences and sequences[-1] != last:
        return None
    return ring


@dataclass
class RingState:
    instance: Any
    last_sequence: int
    dropped: int
    time: int


def unknown_intervals(records: list[dict[str, Any]], end: int, interval: int) -> list[tuple[str, str, int, int, str]]:
    """(host, ring, begin, end, reason) for every stretch whose failure entries may be incomplete."""
    found = []
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_host[str(record.get("host"))].append(record)
    for host, host_records in by_host.items():
        host_records.sort(key=lambda record: record.get("time", 0))
        state: dict[str, RingState] = {}
        for record in host_records:
            time = record.get("time", 0)
            instance = record.get("instance_id")
            since = record.get("since") if isinstance(record.get("since"), int) else time
            for direction in RINGS:
                ring = ring_of(record, direction)
                before = state.get(direction)
                if ring is None:
                    found.append((host, direction, before.time if before else time, time, "malformed ring"))
                    continue
                entries = ring["entries"]
                oldest_sequence = entries[0]["sequence"] if entries else ring["last_sequence"] + 1
                oldest_time = entries[0].get("time", time) if entries else time
                if before is None or before.instance != instance:
                    if before is not None:
                        found.append((host, direction, before.time, max(before.time, since),
                                      "instance_id changed; the previous run's later entries are lost"))
                    if ring["last_sequence"] > 0 and oldest_sequence > 1:
                        found.append((host, direction, since, max(since, oldest_time),
                                      f"sequences 1..{oldest_sequence - 1} were dropped before the first sample"))
                elif ring["last_sequence"] < before.last_sequence or ring["dropped"] < before.dropped:
                    found.append((host, direction, before.time, time, "last_sequence or dropped went backwards"))
                elif ring["last_sequence"] == before.last_sequence:
                    if ring["dropped"] != before.dropped:
                        found.append((host, direction, before.time, time, "dropped changed without new entries"))
                elif oldest_sequence > before.last_sequence + 1:
                    # The ring wrapped past entries never read: they lie between the
                    # previous sample and the oldest entry still held.
                    found.append((host, direction, before.time, max(before.time, oldest_time),
                                  f"sequences {before.last_sequence + 1}..{oldest_sequence - 1} were lost when the ring wrapped"))
                state[direction] = RingState(instance, ring["last_sequence"], ring["dropped"], time)
        if host_records and host_records[-1].get("time", 0) < end - 2 * interval:
            for direction in RINGS:
                found.append((host, direction, host_records[-1]["time"], end, "no samples since"))
    return found


def describe(host: str, entry: dict[str, Any], label: str) -> str:
    return (f"{utc(entry.get('time', 0))} {host} {entry.get('direction')} {entry.get('outcome')}/{entry.get('reason')} "
            f"conn_type={entry.get('connection_type')} peer_id={entry.get('peer_id')} known_good={label}")


def evaluate_failures(records: list[dict[str, Any]] | None, known_good: KnownGood | None, monitored: list[str],
                      window: Window, interval: int, min_coverage: float) -> tuple[Figure, Figure]:
    monitored_name = "no malformed_record, first_packet_failed or fallback entry between known-good endpoints"
    triage_name = "closed_after_switch entries between known-good endpoints (triage, not in the verdict)"

    def both_unknown(reason: str) -> tuple[Figure, Figure]:
        return Figure(monitored_name, UNKNOWN, 0, None, reason), Figure(triage_name, UNKNOWN, 0, None, reason)

    if records is None:
        return both_unknown("no failures files")
    if not known_good:
        return both_unknown("no known-good endpoint list")
    if not monitored:
        return both_unknown("no monitored canary nodes named (--monitored, or the hosts of --pool and --archive)")

    # Every monitored node must have its own evidence: one node's file cannot pass the figure.
    expected = expected_samples(window.start, window.end, interval)
    slots: dict[str, set[int]] = defaultdict(set)
    for record in records:
        if window.contains(record.get("time", 0)):
            slots[str(record.get("host"))].add(int((record["time"] - window.start) / interval + 0.5))
    coverage = {host: min(1.0, len(slots[host]) / expected) if expected else 0.0 for host in monitored}
    low = [host for host in monitored if coverage[host] < min_coverage]

    seen: set[tuple[Any, ...]] = set()
    found_monitored: list[str] = []
    found_triage: list[str] = []
    for record in records:
        host = str(record.get("host"))
        for direction in RINGS:
            ring = ring_of(record, direction)
            for entry in (ring or {}).get("entries", []):
                key: tuple[Any, ...] = (host, record.get("instance_id"), direction, entry.get("sequence"))
                if key in seen or not window.contains(entry.get("time", 0)):
                    continue
                seen.add(key)
                label = known_good.label(entry.get("endpoint"))
                if label is None:
                    continue
                if entry.get("outcome") in MONITORED_OUTCOMES:
                    found_monitored.append(describe(host, entry, label))
                elif entry.get("outcome") in TRIAGE_OUTCOMES:
                    found_triage.append(describe(host, entry, label))
        if not window.contains(record.get("time", 0)):
            continue
        for item in record.get("fallback_set") or []:
            if not isinstance(item, dict):
                continue
            label = known_good.label(item.get("endpoint"))
            key = (host, "fallback_set", label, item.get("entered"))
            if label is not None and key not in seen:
                seen.add(key)
                found_monitored.append(f"{utc(item.get('entered', 0))} {host} fallback_set cause={item.get('cause')}/{item.get('reason')} "
                                       f"streak={item.get('streak')} expires={utc(item.get('expires', 0))} known_good={label}")

    gaps = [gap for gap in unknown_intervals(records, window.end, interval) if window.overlaps(gap[2], gap[3])]
    notes = [f"unknown {host} {ring} {utc(max(begin, window.start))}..{utc(min(finish, window.end))}: {reason}"
             for host, ring, begin, finish, reason in gaps]
    notes += [f"unknown {host}: coverage {percent(coverage[host])} is below {percent(min_coverage)}" for host in low]
    samples = sum(len(slots[host]) for host in monitored)
    per_host = ",".join(f"{host}:{percent(coverage[host])}" for host in monitored)

    def figure(name: str, found: list[str]) -> Figure:
        result = FAIL if found else (UNKNOWN if gaps or low else PASS)
        return Figure(name, result, samples, min(coverage.values()),
                      f"entries={len(found)} unknown_intervals={len(gaps)} nodes={per_host}", found + notes)

    return figure(monitored_name, found_monitored), figure(triage_name, found_triage)


# ---------------------------------------------------------------------------
# Figure 4: inbound connections against the control
# ---------------------------------------------------------------------------


def evaluate_connections(archive: list[dict[str, str | None]] | None, control: list[dict[str, str | None]] | None,
                         canary_start: int, window: Window, interval: int, baseline_ratio: float | None,
                         min_coverage: float) -> Figure:
    """Daily archive/control connections_in ratios, relative to the baseline ratio.

    Samples are paired by sampling slot. A day is judged only when its valid
    pairs cover at least min_coverage of the samples expected outside restart
    exclusions; otherwise the day is unknown.
    """
    name = "archive connections_in within +-20% of control, relative to the baseline ratio, excluding 48 h after restarts"
    if not archive or not control:
        return Figure(name, UNKNOWN, 0, None, "needs both archive and control samples")

    def by_slot(rows: list[dict[str, str | None]]) -> dict[int, dict[str, str | None]]:
        return {int(int(row["time"]) / interval + 0.5): row for row in rows if row["time"] is not None}

    archive_slots, control_slots = by_slot(archive), by_slot(control)
    baseline = [0, 0, 0]  # archive sum, control sum, pairs
    days: dict[str, dict[str, int]] = defaultdict(lambda: {"archive": 0, "control": 0, "pairs": 0, "excluded": 0})
    for slot in sorted(set(archive_slots) | set(control_slots)):
        pair = (archive_slots.get(slot), control_slots.get(slot))
        time = min(int(row["time"]) for row in pair if row is not None)  # type: ignore[arg-type]
        uptimes = [as_int(row["uptime"]) if row else None for row in pair]
        counts = [as_int(row["connections_in"]) if row else None for row in pair]
        restarted = any(uptime is not None and uptime < CONNECTIONS_RESTART_EXCLUSION for uptime in uptimes)
        valid = not restarted and None not in uptimes and None not in counts
        if time < canary_start:
            if valid:
                baseline[0] += counts[0]  # type: ignore[operator]
                baseline[1] += counts[1]  # type: ignore[operator]
                baseline[2] += 1
            continue
        if not window.contains(time):
            continue
        day = days[utc(time)[:10]]
        if restarted:
            day["excluded"] += 1
        elif valid:
            day["archive"] += counts[0]  # type: ignore[operator]
            day["control"] += counts[1]  # type: ignore[operator]
            day["pairs"] += 1

    if baseline_ratio is None:
        # Every day is compared against this ratio, so a zero on either side is
        # no evidence: the ratio is undefined, or every day divides by zero.
        if baseline[2] == 0:
            return Figure(name, UNKNOWN, 0, None, "no baseline: no valid paired samples before the canary start")
        for node, total in (("archive", baseline[0]), ("control", baseline[1])):
            if total == 0:
                return Figure(name, UNKNOWN, 0, None,
                              f"no baseline: {node} connections_in summed to 0 over {baseline[2]} valid pre-canary pairs")
        baseline_ratio = baseline[0] / baseline[1]
        baseline_text = f"baseline_ratio={baseline_ratio:.3f} baseline_pairs={baseline[2]}"
    else:
        baseline_text = f"baseline_ratio={baseline_ratio:.3f} (given)"
    details = []
    results = []
    pairs = judged_expected = 0
    day_start = datetime.fromtimestamp(window.start, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    while int(day_start.timestamp()) <= window.end:
        label = day_start.date().isoformat()
        begin = max(window.start, int(day_start.timestamp()))
        finish = min(window.end, int((day_start + timedelta(days=1)).timestamp()) - 1)
        day_start += timedelta(days=1)
        day = days.get(label) or {"archive": 0, "control": 0, "pairs": 0, "excluded": 0}
        expected = expected_samples(begin, finish, interval, phase=window.start) - day["excluded"]
        if expected <= 0:
            details.append(f"{label} excluded: excluded={day['excluded']}")
            continue
        pairs += day["pairs"]
        judged_expected += expected
        coverage = min(1.0, day["pairs"] / expected)
        counts_text = f"pairs={day['pairs']} expected={expected} excluded={day['excluded']} coverage={percent(coverage)}"
        if coverage < min_coverage or day["control"] == 0:
            details.append(f"{label} unknown: {counts_text}")
            results.append(UNKNOWN)
            continue
        relative = (day["archive"] / day["control"]) / baseline_ratio
        state = PASS if abs(relative - 1) <= CONNECTIONS_TOLERANCE else FAIL
        results.append(state)
        details.append(f"{label} {state}: relative={relative:.3f} {counts_text}")
    if FAIL in results:
        result = FAIL
    elif UNKNOWN in results or PASS not in results:
        result = UNKNOWN
    else:
        result = PASS
    overall = min(1.0, pairs / judged_expected) if judged_expected else None
    return Figure(name, result, pairs, overall, f"{baseline_text} days={len(results)}", details)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def verdict(figures: list[Figure]) -> str:
    results = [figure.result for figure in figures]
    if FAIL in results:
        return FAIL
    return UNKNOWN if UNKNOWN in results else PASS


def time_arg(text: str) -> int:
    try:
        return parse_time(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def positive_int(text: str) -> int:
    if not text.isdigit() or int(text) == 0:
        raise argparse.ArgumentTypeError(f"expected a positive whole number of seconds, got {text!r}")
    return int(text)


def non_negative_int(text: str) -> int:
    if not text.isdigit():
        raise argparse.ArgumentTypeError(f"expected a whole number of seconds, got {text!r}")
    return int(text)


def share_arg(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = -1.0
    if not 0 < value <= 1:
        raise argparse.ArgumentTypeError(f"expected a share greater than 0 and at most 1, such as 0.9, got {text!r}")
    return value


def ratio_arg(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = -1.0
    if not 0 < value < float("inf"):
        raise argparse.ArgumentTypeError(f"expected a positive ratio, got {text!r}")
    return value


def file_arg(text: str) -> Path:
    path = Path(text)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"no such file: {text}")
    return path


def hosts_arg(text: str) -> list[str]:
    hosts = [host.strip() for host in text.split(",")]
    if not all(LABEL.match(host) for host in hosts) or len(set(hosts)) != len(hosts):
        raise argparse.ArgumentTypeError(f"expected distinct comma-separated host labels, got {text!r}")
    return hosts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--canary-start", required=True, type=time_arg,
                        help="start of the canary window (Unix seconds or ISO 8601); earlier samples are the baseline")
    parser.add_argument("--end", type=time_arg, help="end of the window (default: the latest sample)")
    parser.add_argument("--pool", type=file_arg, help="the pool node's samples.csv")
    parser.add_argument("--archive", type=file_arg, help="the canary archive node's samples.csv")
    parser.add_argument("--control", type=file_arg, help="the control archive node's samples.csv")
    parser.add_argument("--failures", type=file_arg, action="append", default=[],
                        help="a canary node's failures.jsonl (repeatable; every monitored node needs one)")
    parser.add_argument("--known-good", type=file_arg, help="known-good endpoints with labels, required with --failures")
    parser.add_argument("--monitored", type=hosts_arg,
                        help="host labels whose failures must all be present (default: the hosts of --pool and --archive)")
    parser.add_argument("--baseline-ratio", type=ratio_arg,
                        help="archive/control connections_in ratio to use instead of the samples before --canary-start")
    parser.add_argument("--min-coverage", type=share_arg, default=DEFAULT_MIN_COVERAGE,
                        help="share of expected samples a figure, node or day needs to be judged (default: 0.9)")
    parser.add_argument("--interval", type=positive_int, default=300, help="sampling interval in seconds (default: 300)")
    parser.add_argument("--restart-grace", type=non_negative_int, default=600,
                        help="seconds after a restart excluded from the pinned-link figure (default: 600)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.pool or args.archive or args.control or args.failures):
        parser.error("give at least one of --pool, --archive, --control or --failures")
    if args.failures and not args.known_good:
        parser.error("--failures needs --known-good")
    if args.known_good and not args.failures:
        parser.error("--known-good is only used with --failures")
    if args.monitored and not args.failures:
        parser.error("--monitored is only used with --failures")
    if args.end is not None and args.end < args.canary_start:
        parser.error("--end is before --canary-start")

    try:
        pool = pq_canary.read_rows(args.pool) if args.pool else None
        archive = pq_canary.read_rows(args.archive) if args.archive else None
        control = pq_canary.read_rows(args.control) if args.control else None
        records = [record for path in args.failures for record in pq_canary.read_failures(path)] if args.failures else None
        known_good = read_known_good(args.known_good) if args.known_good else None
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    for record in records or []:
        if not isinstance(record, dict) or not isinstance(record.get("time"), int) or not isinstance(record.get("host"), str):
            print("Error: a failures.jsonl line lacks an integer time or a host label", file=sys.stderr)
            return 2

    monitored = args.monitored
    if monitored is None:
        monitored = sorted({row["host"] for rows in (pool, archive) if rows for row in rows if row["host"]})

    start = args.canary_start
    latest = [int(row["time"]) for rows in (pool, archive, control) if rows for row in rows if row["time"] is not None]
    latest += [record["time"] for record in records or []]
    end = args.end if args.end is not None else max(latest, default=start)
    window = Window(start, end)

    pinned = evaluate_pinned(pool, archive, window, args.interval, args.restart_grace, args.min_coverage)
    failures, triage = evaluate_failures(records, known_good, monitored, window, args.interval, args.min_coverage)
    connections = evaluate_connections(archive, control, start, window, args.interval, args.baseline_ratio, args.min_coverage)

    print(f"PQ canary evaluation: {utc(start)} to {utc(end)}, minimum coverage {percent(args.min_coverage)}")
    for label, rows in (("pool", pool), ("archive", archive), ("control", control)):
        if rows is None:
            print(f"restarts: {label} no samples")
            continue
        node_restarts = [restart for restart in restarts(rows) if window.overlaps(restart.last_seen, restart.boot)]
        print(f"restarts: {label} {len(node_restarts)}" + "".join(f" {utc(restart.boot)}" for restart in node_restarts))
    print()
    for figure in (pinned, failures, triage, connections):
        print(f"{figure.result:<8} {figure.name}: samples={figure.samples} coverage={percent(figure.coverage)} {figure.summary}".rstrip())
        for detail in figure.details:
            print(f"         {detail}")
    final = verdict([pinned, failures, connections])
    print()
    print(f"canary verdict (figures 1, 2 and 4): {final}")
    return {PASS: 0, FAIL: 1, UNKNOWN: 3}[final]


if __name__ == "__main__":
    sys.exit(main())
