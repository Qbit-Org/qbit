#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Sample format shared by pq-canary-sample.sh and pq-canary-eval.py.

One sample is one CSV row (COLUMNS) plus, when getpqtransportinfo answered, one
JSON line with the raw recent_failures and fallback_set. The rules that keep the
evidence honest:

* a field that is missing, or whose RPC failed, is written as NA, never 0;
  v1.0.0 has neither getnetworkinfo.connections_pq nor getpqtransportinfo;
* a real 0 stays 0;
* sample_ok is 1 only when uptime, getnetworkinfo and, on the pool node,
  getpeerinfo all answered.

The RPC fields follow the getpqtransportinfo contract in #184.

Run as ``pq_canary.py sample ...`` by pq-canary-sample.sh, which gathers the RPC
results into files; see that script for the arguments.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Iterator

NA = "NA"

DIRECTION_COUNTS = ["switched", "legacy_peer", "malformed_record", "first_packet_failed", "abandoned", "internal_error"]
INBOUND_COUNTS = DIRECTION_COUNTS + ["shed"]
OUTBOUND_COUNTS = DIRECTION_COUNTS + ["closed_after_switch", "fallback"]

COLUMNS = (
    ["time", "utc", "host", "uptime", "version", "sample_ok",
     "pq_enabled", "instance_id", "arith_backend", "keccak_backend", "since"]
    + [f"in_{name}" for name in INBOUND_COUNTS]
    + [f"out_{name}" for name in OUTBOUND_COUNTS]
    + ["load_shedding_active",
       "in_ring_last_sequence", "in_ring_dropped", "out_ring_last_sequence", "out_ring_dropped",
       "connections_in", "connections_pq",
       "pinned_present", "pinned_connection_type", "pinned_transport_pq", "pinned_transport_pq_status"]
)


def field(value: Any) -> str:
    """CSV text for a JSON value: NA when absent, 1/0 for booleans, else the value."""
    if value is None:
        return NA
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, str)):
        return str(value)
    return NA


def lookup(document: Any, *path: str) -> Any:
    """document[path[0]][path[1]]..., or None if any step is missing or not an object."""
    for key in path:
        if not isinstance(document, dict) or key not in document:
            return None
        document = document[key]
    return document


def build_row(*, time: int, utc: str, host: str, uptime: Any, netinfo: Any, pqinfo: Any,
              peers: Any, pinned: str | None) -> dict[str, str]:
    """One CSV row. uptime, netinfo, pqinfo and peers are the parsed RPC results, or None
    when the call failed; peers and pinned are None on nodes that do not pin a peer."""
    row = {name: NA for name in COLUMNS}
    row.update(time=str(time), utc=utc, host=host)
    if isinstance(uptime, int) and not isinstance(uptime, bool):
        row["uptime"] = str(uptime)
    row["version"] = field(lookup(netinfo, "version"))
    row["connections_in"] = field(lookup(netinfo, "connections_in"))
    row["connections_pq"] = field(lookup(netinfo, "connections_pq"))

    row["pq_enabled"] = field(lookup(pqinfo, "enabled"))
    for name in ("instance_id", "arith_backend", "keccak_backend", "since"):
        row[name] = field(lookup(pqinfo, name))
    for name in INBOUND_COUNTS:
        row[f"in_{name}"] = field(lookup(pqinfo, "handshakes", "inbound", name))
    for name in OUTBOUND_COUNTS:
        row[f"out_{name}"] = field(lookup(pqinfo, "handshakes", "outbound", name))
    row["load_shedding_active"] = field(lookup(pqinfo, "load_shedding", "active"))
    for prefix, direction in (("in", "inbound"), ("out", "outbound")):
        row[f"{prefix}_ring_last_sequence"] = field(lookup(pqinfo, "recent_failures", direction, "last_sequence"))
        row[f"{prefix}_ring_dropped"] = field(lookup(pqinfo, "recent_failures", direction, "dropped"))

    pool_node = pinned is not None
    peers_ok = isinstance(peers, list)
    if pool_node and peers_ok:
        matches = [peer for peer in peers if isinstance(peer, dict) and peer.get("addr") == pinned]
        # Prefer the manual connection if the address is connected more than once.
        matches.sort(key=lambda peer: peer.get("connection_type") != "manual")
        row["pinned_present"] = "1" if matches else "0"
        if matches:
            peer = matches[0]
            row["pinned_connection_type"] = field(peer.get("connection_type"))
            row["pinned_transport_pq"] = field(peer.get("transport_pq"))
            row["pinned_transport_pq_status"] = field(peer.get("transport_pq_status"))

    answered = row["uptime"] != NA and isinstance(netinfo, dict) and (peers_ok or not pool_node)
    row["sample_ok"] = "1" if answered else "0"
    return row


def build_failures_record(*, time: int, host: str, pqinfo: Any) -> dict[str, Any] | None:
    """The JSON line kept for the evaluator, or None when getpqtransportinfo did not answer."""
    if not isinstance(pqinfo, dict):
        return None
    return {
        "time": time,
        "host": host,
        "instance_id": pqinfo.get("instance_id"),
        "since": pqinfo.get("since"),
        "recent_failures": pqinfo.get("recent_failures"),
        "fallback_set": pqinfo.get("fallback_set"),
    }


def append_row(path: Path, row: dict[str, str]) -> None:
    """Append a row, writing the header first when the file is new or empty."""
    new = not path.exists() or path.stat().st_size == 0
    if not new:
        with path.open(encoding="utf8", newline="") as existing:
            header = next(csv.reader(existing), None)
        if header != COLUMNS:
            raise ValueError(f"{path} has a different header; move it aside and start a new file")
    with path.open("a", encoding="utf8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
        if new:
            writer.writeheader()
        writer.writerow(row)


def read_rows(path: Path) -> list[dict[str, str | None]]:
    """Rows of a samples file, with NA turned into None."""
    with path.open(encoding="utf8", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != COLUMNS:
            raise ValueError(f"{path}: unexpected header {reader.fieldnames}")
        return [{key: (None if value == NA else value) for key, value in row.items()} for row in reader]


def read_failures(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf8") as source:
        for number, line in enumerate(source, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{path}:{number}: {e}") from e


def load_rpc_result(path: Path) -> Any:
    """A parsed RPC result, or None when the call failed (marker file) or printed nothing parsable."""
    if not path.exists() or path.with_name(path.name + ".failed").exists():
        return None
    text = path.read_text(encoding="utf8").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def sample_main(args: argparse.Namespace) -> int:
    rpc = Path(args.rpc_dir)
    uptime = load_rpc_result(rpc / "uptime")
    netinfo = load_rpc_result(rpc / "getnetworkinfo")
    pqinfo = load_rpc_result(rpc / "getpqtransportinfo")
    peers = load_rpc_result(rpc / "getpeerinfo") if args.pinned else None
    row = build_row(time=args.time, utc=args.utc, host=args.host, uptime=uptime, netinfo=netinfo,
                    pqinfo=pqinfo, peers=peers, pinned=args.pinned)
    out = Path(args.out)
    append_row(out / "samples.csv", row)
    record = build_failures_record(time=args.time, host=args.host, pqinfo=pqinfo)
    if record is not None:
        with (out / "failures.jsonl").open("a", encoding="utf8") as failures:
            failures.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if row["sample_ok"] == "1" else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PQ canary sample formatting (used by pq-canary-sample.sh).")
    commands = parser.add_subparsers(dest="command", required=True)
    sample = commands.add_parser("sample", help="append one sample from RPC results gathered in --rpc-dir")
    sample.add_argument("--rpc-dir", required=True)
    sample.add_argument("--out", required=True)
    sample.add_argument("--host", required=True)
    sample.add_argument("--time", required=True, type=int)
    sample.add_argument("--utc", required=True)
    sample.add_argument("--pinned")
    args = parser.parse_args(argv)
    return sample_main(args)


if __name__ == "__main__":
    sys.exit(main())
