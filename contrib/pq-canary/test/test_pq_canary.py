#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for the PQ canary sampler and evaluator (contrib/pq-canary).

The RPC fixtures in fixtures/ follow the getpqtransportinfo contract in #184.
Standard library only, so the Required Merge Gate can run it as is.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
FIXTURES = HERE / "fixtures"
SAMPLER = TOOL_DIR / "pq-canary-sample.sh"
EVALUATOR = TOOL_DIR / "pq-canary-eval.py"

sys.path.insert(0, str(TOOL_DIR))
import pq_canary  # noqa: E402

_spec = importlib.util.spec_from_file_location("pq_canary_eval", EVALUATOR)
assert _spec is not None and _spec.loader is not None
pq_eval = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pq_eval  # dataclasses look their module up while it loads
_spec.loader.exec_module(pq_eval)

NA = pq_canary.NA
PINNED = "203.0.113.5:8333"
POOL_ADDRESS = "198.51.100.7"
T0 = 1_760_000_000  # canary start
INTERVAL = 300
DAY = 86_400
LONG_UPTIME = 30 * DAY


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf8"))


def parsed(row: dict[str, str]) -> dict[str, str | None]:
    """A row as read_rows returns it: NA becomes None."""
    return {key: (None if value == NA else value) for key, value in row.items()}


class Node:
    """A simulated node producing samples the way pq-canary-sample.sh records them."""

    def __init__(self, host: str, *, boot: int, pinned: str | None = None, v1_0_0: bool = False) -> None:
        self.host = host
        self.boot = boot
        self.pinned = pinned
        self.v1_0_0 = v1_0_0
        self.instance = 0

    def restart(self, boot: int) -> None:
        self.boot = boot
        self.instance += 1

    def pqinfo(self, time: int) -> dict[str, Any] | None:
        """getpqtransportinfo at time: the rings hold the fixture's failures recorded by then."""
        if self.v1_0_0:
            return None
        info = fixture("getpqtransportinfo.json")
        # Random per process start on a real node; distinct per node and run here.
        info["instance_id"] = hashlib.sha256(f"{self.host}/{self.instance}".encode()).hexdigest()
        info["since"] = self.boot
        for failures in info["recent_failures"].values():
            failures["entries"] = [item for item in failures["entries"] if item["time"] <= time]
            failures["last_sequence"] = failures["entries"][-1]["sequence"] if failures["entries"] else 0
        return info

    def sample(self, time: int, *, down: bool = False, connections_in: int | None = 30,
               pinned_peer: dict[str, Any] | None | str = "manual-hybrid") -> dict[str, str | None]:
        netinfo = None if down else fixture("getnetworkinfo-v1.0.0.json" if self.v1_0_0 else "getnetworkinfo.json")
        if netinfo is not None:
            if connections_in is None:
                del netinfo["connections_in"]
            else:
                netinfo["connections_in"] = connections_in
        peers = None
        if self.pinned and not down:
            peers = [peer for peer in fixture("getpeerinfo.json") if peer["addr"] != PINNED]
            if pinned_peer == "manual-hybrid":
                peers.append({"addr": self.pinned, "connection_type": "manual", "transport_pq": True, "transport_pq_status": "hybrid"})
            elif isinstance(pinned_peer, dict):
                peers.append(dict(pinned_peer, addr=self.pinned))
        row = pq_canary.build_row(
            time=time, utc=pq_eval.utc(time), host=self.host,
            uptime=None if down else time - self.boot,
            netinfo=netinfo, pqinfo=None if down else self.pqinfo(time), peers=peers, pinned=self.pinned)
        return parsed(row)


def window(count: int) -> Any:
    return pq_eval.Window(T0, T0 + (count - 1) * INTERVAL)


def entry(sequence: int, time: int, address: str, port: int, outcome: str, *, direction: str = "outbound",
          reason: str = "tag", connection_type: str = "manual") -> dict[str, Any]:
    network = "ipv6" if ":" in address else "ipv4"
    return {"sequence": sequence, "time": time, "direction": direction, "connection_type": connection_type,
            "peer_id": sequence, "outcome": outcome, "reason": reason,
            "endpoint": {"kind": "address", "network": network, "address": address, "port": port}}


def ring(last_sequence: Any, dropped: Any, entries: list[Any]) -> dict[str, Any]:
    return {"last_sequence": last_sequence, "dropped": dropped, "entries": entries}


def record(time: int, *, inbound: Any, outbound: Any, host: str = "archive",
           instance: Any = "a" * 64, since: Any = T0 - DAY, fallback_set: list[Any] | None = None) -> dict[str, Any]:
    return {"time": time, "host": host, "instance_id": instance, "since": since,
            "recent_failures": {"inbound": inbound, "outbound": outbound}, "fallback_set": fallback_set or []}


def known_good() -> Any:
    return pq_eval.read_known_good(FIXTURES / "known-good.txt")


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------


class SampleRowTest(unittest.TestCase):
    def test_full_schema_fills_every_column(self) -> None:
        row = pq_canary.build_row(time=T0, utc="2025-10-09T08:53:20Z", host="pool", uptime=1234,
                                  netinfo=fixture("getnetworkinfo.json"), pqinfo=fixture("getpqtransportinfo.json"),
                                  peers=fixture("getpeerinfo.json"), pinned=PINNED)
        self.assertEqual(list(row), pq_canary.COLUMNS)
        self.assertNotIn(NA, row.values())
        self.assertEqual(row["sample_ok"], "1")
        self.assertEqual((row["pq_enabled"], row["load_shedding_active"]), ("1", "0"))
        self.assertEqual((row["in_switched"], row["out_closed_after_switch"], row["out_fallback"]), ("120", "1", "0"))
        self.assertEqual((row["in_ring_last_sequence"], row["out_ring_last_sequence"], row["out_ring_dropped"]), ("1", "2", "0"))
        self.assertEqual((row["connections_in"], row["connections_pq"]), ("30", "12"))
        self.assertEqual((row["pinned_present"], row["pinned_connection_type"], row["pinned_transport_pq"],
                          row["pinned_transport_pq_status"]), ("1", "manual", "1", "hybrid"))
        # A real zero is a measurement, not a missing value.
        self.assertEqual(row["in_internal_error"], "0")
        self.assertNotIn(PINNED, ",".join(row.values()), "addresses stay out of the CSV")

    def test_v1_0_0_writes_na_and_a_complete_sample(self) -> None:
        row = Node("control", boot=T0 - DAY, v1_0_0=True).sample(T0)
        self.assertEqual(row["sample_ok"], "1")
        self.assertEqual(row["version"], "10000")
        self.assertEqual(row["connections_in"], "30")
        new_fields = [name for name in pq_canary.COLUMNS if name not in
                      ("time", "utc", "host", "uptime", "version", "sample_ok", "connections_in")]
        self.assertEqual({name: row[name] for name in new_fields}, {name: None for name in new_fields})

    def test_failed_or_missing_values_are_na_never_zero(self) -> None:
        down = Node("pool", boot=T0 - DAY, pinned=PINNED).sample(T0, down=True)
        self.assertEqual(down["sample_ok"], "0")
        self.assertIsNone(down["uptime"])
        self.assertIsNone(down["connections_in"])
        self.assertIsNone(down["pinned_present"])

        info = fixture("getpqtransportinfo.json")
        del info["handshakes"]["inbound"]["shed"]
        info["recent_failures"]["outbound"] = "not a ring"
        row = pq_canary.build_row(time=T0, utc="x", host="archive", uptime=10, netinfo={"version": 10100},
                                  pqinfo=info, peers=None, pinned=None)
        self.assertEqual(row["in_shed"], NA)
        self.assertEqual(row["out_ring_last_sequence"], NA)
        self.assertEqual(row["connections_in"], NA)
        self.assertEqual(row["in_switched"], "120")
        self.assertEqual(row["sample_ok"], "1", "getpeerinfo is only part of the pool node's sample")

        # The pool node needs getpeerinfo; a pinned peer that is not connected is a 0, not NA.
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        absent = pool.sample(T0, pinned_peer=None)
        self.assertEqual((absent["sample_ok"], absent["pinned_present"], absent["pinned_connection_type"]), ("1", "0", None))
        row = pq_canary.build_row(time=T0, utc="x", host="pool", uptime=10, netinfo={}, pqinfo=None, peers=None, pinned=PINNED)
        self.assertEqual((row["sample_ok"], row["pinned_present"]), ("0", NA))

    def test_values_of_the_wrong_type_are_na(self) -> None:
        info = fixture("getpqtransportinfo.json")
        info.update(enabled="yes", instance_id=info["instance_id"].upper(), arith_backend=3, since=-5)
        info["handshakes"]["inbound"]["switched"] = True
        info["handshakes"]["outbound"]["fallback"] = -1
        info["handshakes"]["outbound"]["switched"] = "40"
        info["load_shedding"]["active"] = 1
        info["recent_failures"]["inbound"]["last_sequence"] = 1.0
        netinfo = dict(fixture("getnetworkinfo.json"), version="10100", connections_in=True, connections_pq=-2)
        peers = [{"addr": PINNED, "connection_type": 5, "transport_pq": "true", "transport_pq_status": ["hybrid"]}]
        wrong = ["uptime", "version", "connections_in", "connections_pq", "pq_enabled", "instance_id", "arith_backend", "since",
                 "in_switched", "out_fallback", "out_switched", "load_shedding_active", "in_ring_last_sequence",
                 "pinned_connection_type", "pinned_transport_pq", "pinned_transport_pq_status"]
        for uptime in (-1, True, 12.5, "4300"):
            with self.subTest(uptime=uptime):
                row = pq_canary.build_row(time=T0, utc="x", host="pool", uptime=uptime, netinfo=netinfo, pqinfo=info,
                                          peers=peers, pinned=PINNED)
                self.assertEqual({name: row[name] for name in wrong}, dict.fromkeys(wrong, NA))
                # The values of the right type are kept.
                self.assertEqual((row["keccak_backend"], row["in_legacy_peer"], row["out_ring_dropped"], row["pinned_present"]),
                                 ("x86_64-avx2", "30", "0", "1"))
                self.assertEqual(row["sample_ok"], "0", "a sample without a valid uptime is incomplete")

    def test_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.csv"
            row = pq_canary.build_row(time=T0, utc="x", host="pool", uptime=1, netinfo={}, pqinfo=None, peers=None, pinned=None)
            pq_canary.append_row(path, row)
            pq_canary.append_row(path, row)
            lines = path.read_text(encoding="utf8").splitlines()
            self.assertEqual(lines[0], ",".join(pq_canary.COLUMNS))
            self.assertEqual(len(lines), 3)
            self.assertEqual(len(pq_canary.read_rows(path)), 2)
            path.write_text("time,host\n1,pool\n", encoding="utf8")
            with self.assertRaises(ValueError):
                pq_canary.append_row(path, row)

    def test_rows_with_the_wrong_number_of_fields_are_not_samples(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.csv"
            for index in range(3):
                pq_canary.append_row(path, {key: NA if value is None else value for key, value in pool.sample(T0 + index * INTERVAL).items()})
            header, first, second, third = path.read_text(encoding="utf8").splitlines()
            # A crash cut the second row short and the next sample continued its line;
            # a later crash left a short last line.
            path.write_text("\n".join([header, first, second[:len(second) // 2] + third, first[:40]]) + "\n", encoding="utf8")
            rows = pq_canary.read_rows(path)
        self.assertEqual([row["time"] for row in rows], [str(T0)])


@unittest.skipIf(shutil.which("bash") is None, "needs bash")
class SamplerScriptTest(unittest.TestCase):
    """pq-canary-sample.sh end to end, with a fake qbit-cli serving the fixtures."""

    FAKE_CLI = (
        "import json, os, sys\n"
        "method = sys.argv[-1]\n"
        "path = os.path.join(os.environ['FAKE_RPC'], method)\n"
        "if not os.path.exists(path):\n"
        "    print('error code: -32601\\nerror message:\\nMethod not found', file=sys.stderr)\n"
        "    sys.exit(89)\n"
        "print(open(path, encoding='utf8').read())\n"
        "sys.exit(int(os.environ.get('FAKE_EXIT_' + method, '0')))\n"
    )

    def run_sampler(self, root: Path, served: dict[str, Any], *args: str, exits: dict[str, int] | None = None) -> subprocess.CompletedProcess[str]:
        rpc = root / "rpc"
        shutil.rmtree(rpc, ignore_errors=True)
        rpc.mkdir()
        for method, result in served.items():
            (rpc / method).write_text(json.dumps(result), encoding="utf8")
        cli = root / "fake_cli.py"
        cli.write_text(self.FAKE_CLI, encoding="utf8")
        env = dict(os.environ, FAKE_RPC=str(rpc), **{f"FAKE_EXIT_{method}": str(code) for method, code in (exits or {}).items()})
        return subprocess.run(["bash", str(SAMPLER), *args, "--", sys.executable, str(cli), "-datadir=/nonexistent"],
                              env=env, text=True, capture_output=True)

    def test_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            v1_0_0 = {"uptime": 4000, "getnetworkinfo": fixture("getnetworkinfo-v1.0.0.json")}
            result = self.run_sampler(root, v1_0_0, "--host", "control", "--out", str(out))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((out / "failures.jsonl").exists())

            full = {"uptime": 4300, "getnetworkinfo": fixture("getnetworkinfo.json"),
                    "getpqtransportinfo": fixture("getpqtransportinfo.json"), "getpeerinfo": fixture("getpeerinfo.json")}
            result = self.run_sampler(root, full, "--host", "control", "--out", str(out))
            self.assertEqual(result.returncode, 0, result.stderr)

            result = self.run_sampler(root, {}, "--host", "control", "--out", str(out))
            self.assertEqual(result.returncode, 2, "an unreachable node is an incomplete sample")

            # A call that fails is NA even if it printed something that parses.
            result = self.run_sampler(root, full, "--host", "control", "--out", str(out), exits={"uptime": 1})
            self.assertEqual(result.returncode, 2)

            rows = pq_canary.read_rows(out / "samples.csv")
            self.assertEqual([row["sample_ok"] for row in rows], ["1", "1", "0", "0"])
            self.assertEqual([row["connections_pq"] for row in rows], [None, "12", None, "12"])
            self.assertEqual([row["instance_id"] is None for row in rows], [True, False, True, False])
            self.assertEqual([row["uptime"] for row in rows], ["4000", "4300", None, None])
            records = list(pq_canary.read_failures(out / "failures.jsonl"))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["recent_failures"], fixture("getpqtransportinfo.json")["recent_failures"])
            self.assertEqual(records[0]["host"], "control")

            result = self.run_sampler(root, full, "--host", "pool", "--out", str(root / "pool"), "--pinned", PINNED)
            self.assertEqual(result.returncode, 0, result.stderr)
            for pinned in ("[2001:db8::5]:8333", "example.b32.i2p:0"):
                result = self.run_sampler(root, full, "--host", "pool", "--out", str(root / "other"), "--pinned", pinned)
                self.assertEqual(result.returncode, 0, result.stderr)
            (row,) = pq_canary.read_rows(root / "pool" / "samples.csv")
            self.assertEqual((row["pinned_present"], row["pinned_connection_type"], row["pinned_transport_pq"]), ("1", "manual", "1"))

    def test_usage_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_pinned = [("--host", "pool", "--out", tmp, "--pinned", value)
                          for value in ("pool-node", "203.0.113.5", "[2001:db8::5", "203.0.113.5:99999", "a b:8333", ":8333")]
            for args in ((), ("--host", "pool"), ("--host", "bad label", "--out", tmp), ("--host", "NA", "--out", tmp),
                         ("--host", "pool", "--out", tmp, "--bogus"),
                         *bad_pinned):
                result = subprocess.run(["bash", str(SAMPLER), *args, "--", "true"], text=True, capture_output=True)
                self.assertEqual(result.returncode, 1, args)
            self.assertFalse((root / "samples.csv").exists())


# ---------------------------------------------------------------------------
# Figure 1: the pinned link
# ---------------------------------------------------------------------------


class PinnedLinkTest(unittest.TestCase):
    def evaluate(self, pool_rows: list[dict[str, str | None]], count: int, archive_rows: Any = None,
                 min_coverage: float = 0.9) -> Any:
        return pq_eval.evaluate_pinned(pool_rows, archive_rows, window(count), INTERVAL, 600, min_coverage)

    def test_pass(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        figure = self.evaluate([pool.sample(T0 + i * INTERVAL) for i in range(200)], 200)
        self.assertEqual((figure.result, figure.samples), ("pass", 200))

    def test_restart_is_a_gap(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = []
        for i in range(100):
            time = T0 + i * INTERVAL
            if i in (40, 41):
                rows.append(pool.sample(time, down=True))  # the node is restarting
                continue
            if i == 42:
                pool.restart(time - 30)
            rows.append(pool.sample(time))
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "pass", figure.summary)
        self.assertIn("excluded=4", figure.summary)  # two down, then uptime 30 s and 330 s < 600 s grace
        self.assertEqual(figure.samples, 96)
        self.assertEqual(len(pq_eval.restarts(rows)), 1)

    def test_archive_restart_is_a_gap_for_the_pool(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        archive = Node("archive", boot=T0 - DAY)
        pool_rows, archive_rows = [], []
        for i in range(50):
            time = T0 + i * INTERVAL
            if i == 25:
                archive.restart(time - 60)
            pool_rows.append(pool.sample(time, pinned_peer=None if i == 25 else "manual-hybrid"))
            archive_rows.append(archive.sample(time))
        # Without the archive node's samples the dropped link is a real miss: 49 of 50 is below 99%.
        self.assertEqual(self.evaluate(pool_rows, 50).result, "fail")
        self.assertEqual(self.evaluate(pool_rows, 50, archive_rows).result, "pass")

    def test_rpc_outage_is_unknown(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL, down=i in (10, 11)) for i in range(100)]
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "unknown", figure.summary)
        self.assertIn("unknown=2", figure.summary)
        # Missing rows, such as a stopped cron, are unknown too.
        figure = self.evaluate([row for index, row in enumerate(rows) if index not in (10, 11)], 100)
        self.assertEqual(figure.result, "unknown", figure.summary)
        self.assertIn("unknown=2", figure.summary)

    def test_missing_rows_are_counted_not_listed(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL) for i in range(100)]
        # A window starting long before the sampler did is mostly unknown, and cheap to evaluate.
        early = pq_eval.evaluate_pinned(rows, None, pq_eval.Window(0, T0 + 99 * INTERVAL), INTERVAL, 600, 0.9)
        self.assertEqual(early.result, "unknown")
        self.assertIn(f"unknown={int(T0 / INTERVAL + 0.5)}", early.summary)  # samples at 0, 300, ... before T0
        # Rows missing because the whole machine was down for a restart are part of the gap.
        pool.restart(T0 + 50 * INTERVAL - 30)
        rows = rows[:40] + [pool.sample(T0 + i * INTERVAL) for i in range(50, 100)]
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "pass", figure.summary)
        self.assertIn("unknown=0 excluded=12", figure.summary)

    def test_automatic_connection_fails_with_remedy(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        automatic = {"connection_type": "outbound-full-relay", "transport_pq": True, "transport_pq_status": "hybrid"}
        rows = [pool.sample(T0 + i * INTERVAL, pinned_peer=automatic if i < 5 else "manual-hybrid") for i in range(100)]
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "fail")
        self.assertIn("disconnectnode", " ".join(figure.details))

    def test_no_samples_is_unknown(self) -> None:
        self.assertEqual(self.evaluate([], 10).result, "unknown")
        # Two rows for one expected sample (for example a manual run beside cron) are one sample.
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        self.assertEqual(self.evaluate([pool.sample(T0), pool.sample(T0)], 1).samples, 1)
        self.assertEqual(pq_eval.evaluate_pinned(None, None, window(10), INTERVAL, 600, 0.9).result, "unknown")

    def test_malformed_numbers_are_missing(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL, pinned_peer=None if i in (40, 41) else "manual-hybrid") for i in range(100)]
        # The link was down in two samples: 98 of 100 fails.
        self.assertEqual(self.evaluate(rows, 100).result, "fail")
        for label, uptime in (("negative", "-30"), ("decimal", "30.0"), ("spaced", " 30"), ("non-ASCII digits", "\u0663\u0660"),
                              ("underscored", "3_0")):
            with self.subTest(uptime=label):
                # Not an uptime, so not a restart: the two samples are judged, not excluded.
                figure = self.evaluate([dict(row, uptime=uptime) if index in (40, 41) else row for index, row in enumerate(rows)], 100)
                self.assertEqual(figure.result, "fail", figure.summary)
                self.assertIn("unknown=0 excluded=0", figure.summary)
        good = [pool.sample(T0 + i * INTERVAL) for i in range(100)]
        for label, time in (("text", "soon"), ("decimal", f"{T0 + 40 * INTERVAL}.0"), ("negative", "-1"),
                            ("beyond year 9999", str(10**14))):
            with self.subTest(time=label):
                # A row without a time is a missing sample: unknown.
                figure = self.evaluate([dict(row, time=time) if index == 40 else row for index, row in enumerate(good)], 100)
                self.assertIn("hybrid=99 not_hybrid=0 unknown=1", figure.summary)

    def test_malformed_pinned_peer_is_unknown(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL) for i in range(100)]
        malformed = {
            "pinned_present not 0 or 1": {"pinned_present": "yes"},
            "no connection type": {"pinned_connection_type": None},
            "malformed connection type": {"pinned_connection_type": "Manual connection"},
            "transport_pq not 0 or 1": {"pinned_transport_pq": "true"},
            "no transport_pq": {"pinned_transport_pq": None},
            "no status": {"pinned_transport_pq_status": None},
            "unknown status": {"pinned_transport_pq_status": "quantum"},
            "unknown status, not hybrid": {"pinned_transport_pq": "0", "pinned_transport_pq_status": "quantum"},
            "no status, not hybrid": {"pinned_transport_pq": "0", "pinned_transport_pq_status": None},
            "hybrid without transport_pq": {"pinned_transport_pq": "0"},
            "transport_pq without hybrid": {"pinned_transport_pq_status": "pending"},
        }
        for label, change in malformed.items():
            with self.subTest(label):
                # Neither hybrid nor a miss: two unknown samples in 100 cannot be judged against 99%.
                figure = self.evaluate([dict(row, **change) if index in (10, 11) else row for index, row in enumerate(rows)], 100)
                self.assertEqual(figure.result, "unknown", figure.summary)
                self.assertIn("hybrid=98 not_hybrid=0 unknown=2", figure.summary)
        # Well-formed values that are not a manual hybrid link are misses.
        misses = {
            "not connected": {"pinned_present": "0", "pinned_connection_type": None, "pinned_transport_pq": None,
                              "pinned_transport_pq_status": None},
            "not hybrid": {"pinned_transport_pq": "0", "pinned_transport_pq_status": "fallback"},
            "automatic": {"pinned_connection_type": "outbound-full-relay"},
        }
        for label, change in misses.items():
            with self.subTest(label):
                figure = self.evaluate([dict(row, **change) if index in (10, 11) else row for index, row in enumerate(rows)], 100)
                self.assertEqual(figure.result, "fail", figure.summary)
                self.assertIn("hybrid=98 not_hybrid=2 unknown=0", figure.summary)

    def test_uptime_that_contradicts_the_instance_is_unknown(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL, pinned_peer=None if i in (40, 41) else "manual-hybrid") for i in range(100)]
        # The node reports a fresh boot in the two samples where the link was down,
        # but its instance_id did not change: that is no restart, so they are judged.
        rows[40]["uptime"], rows[41]["uptime"] = "30", "330"
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "fail", figure.summary)
        self.assertIn("excluded=0", figure.summary)
        self.assertEqual(pq_eval.restarts(rows), [])
        self.assertEqual([row["uptime"] for _, row in pq_eval.sample_rows(rows)[39:43]], [rows[39]["uptime"], None, None, rows[42]["uptime"]])

        # A restart between the sampler's uptime and getpqtransportinfo calls pairs the
        # old uptime with the new instance_id once: only that uptime is unknown.
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = []
        for i in range(100):
            time = T0 + i * INTERVAL
            if i == 50:
                old_uptime = str(time - pool.boot)
                pool.restart(time - 30)
            rows.append(pool.sample(time))
        rows[50]["uptime"] = old_uptime
        self.assertEqual([index for index, (_, row) in enumerate(pq_eval.sample_rows(rows)) if row["uptime"] is None], [50])
        self.assertEqual([restart.last_seen for restart in pq_eval.restarts(rows)], [T0 + 49 * INTERVAL])
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "pass", figure.summary)
        self.assertIn("excluded=2", figure.summary)  # 30 s and 330 s after the restart

    def test_low_coverage_is_unknown_not_judged(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        automatic = {"connection_type": "outbound-full-relay", "transport_pq": True, "transport_pq_status": "hybrid"}
        # 15 of 100 samples missing and 5 bad: with the gaps it cannot be judged.
        rows = [pool.sample(T0 + i * INTERVAL, pinned_peer=automatic if i < 5 else "manual-hybrid") for i in range(100) if i % 7 or i > 98]
        self.assertEqual(len(rows), 85)
        figure = self.evaluate(rows, 100)
        self.assertEqual(figure.result, "unknown", figure.summary)
        self.assertAlmostEqual(figure.coverage, 0.85)
        self.assertEqual(self.evaluate(rows, 100, min_coverage=0.8).result, "fail")

    def test_each_expected_sample_counts_once(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        # 95 of 100 expected samples cannot show 99%, however often each one is recorded.
        rows = [pool.sample(T0 + i * INTERVAL) for i in range(100) if i % 20]
        self.assertEqual(len(rows), 95)
        cases = {
            "once": rows,
            "each row six times": [row for row in rows for _ in range(6)],
            "files that overlap": rows + rows[10:] + rows[40:],
            "six sampler runs per expected sample":
                [pool.sample(T0 + i * INTERVAL + offset) for i in range(100) if i % 20 for offset in range(-100, 101, 40)],
        }
        for label, case in cases.items():
            with self.subTest(label):
                figure = self.evaluate(case, 100)
                self.assertEqual((figure.result, figure.samples), ("unknown", 100), figure.summary)
                self.assertIn("hybrid=95 not_hybrid=0 unknown=5 excluded=0", figure.summary)
                self.assertAlmostEqual(figure.coverage, 0.95)

    def test_several_samples_for_one_expected_sample_count_as_the_least_favorable(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL) for i in range(100)]

        def with_extra(extra: Any, before: bool) -> list[Any]:
            """rows with an extra sample a minute before or after expected samples 10 and 11."""
            offset = -60 if before else 60
            return rows + [extra(T0 + i * INTERVAL + offset) for i in (10, 11)]
        cases = {
            "not connected": (lambda time: pool.sample(time, pinned_peer=None), "fail", "hybrid=98 not_hybrid=2 unknown=0"),
            "unanswered": (lambda time: pool.sample(time, down=True), "unknown", "hybrid=98 not_hybrid=0 unknown=2"),
            "hybrid": (pool.sample, "pass", "hybrid=100 not_hybrid=0 unknown=0"),
        }
        for label, (extra, result, summary) in cases.items():
            for before in (True, False):
                with self.subTest(label, before=before):
                    figure = self.evaluate(with_extra(extra, before), 100)
                    self.assertEqual((figure.result, figure.samples), (result, 100), figure.summary)
                    self.assertIn(summary, figure.summary)
        # Not connected in one sample and unanswered in the other is a miss.
        unanswered = [dict(row, sample_ok="0") if index in (10, 11) else row for index, row in enumerate(rows)]
        figure = self.evaluate(unanswered + [pool.sample(T0 + i * INTERVAL + 60, pinned_peer=None) for i in (10, 11)], 100)
        self.assertIn("hybrid=98 not_hybrid=2 unknown=0", figure.summary)

        # In a restart gap (the archive node restarts after expected sample 49), a sample
        # excludes its expected sample from the figure, unless another one is a miss.
        archive = Node("archive", boot=T0 - DAY)
        archive_rows = [archive.sample(T0 + i * INTERVAL) for i in range(50)]
        archive.restart(T0 + 50 * INTERVAL - 60)
        archive_rows += [archive.sample(T0 + i * INTERVAL) for i in range(50, 100)]
        figure = self.evaluate(rows, 100, archive_rows)
        self.assertIn("hybrid=98 not_hybrid=0 unknown=0 excluded=2", figure.summary)
        in_gap = pool.sample(T0 + 49 * INTERVAL + 60)
        figure = self.evaluate(rows + [in_gap], 100, archive_rows)
        self.assertIn("hybrid=97 not_hybrid=0 unknown=0 excluded=3", figure.summary)
        missed = [dict(row, pinned_present="0") if index == 49 else row for index, row in enumerate(rows)]
        figure = self.evaluate(missed + [in_gap], 100, archive_rows)
        self.assertIn("hybrid=97 not_hybrid=1 unknown=0 excluded=2", figure.summary)

    def test_repeated_rows_do_not_outvote_the_boot_time(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        rows = [pool.sample(T0 + i * INTERVAL, pinned_peer=None if i in (40, 41) else "manual-hybrid") for i in range(100)]
        # A fresh boot in the two misses, without a new instance_id, is no restart: they are judged.
        rows[40]["uptime"], rows[41]["uptime"] = "30", "330"
        for copies in (1, 100):
            with self.subTest(copies=copies):
                figure = self.evaluate(rows + [dict(rows[index]) for index in (40, 41) for _ in range(copies - 1)], 100)
                self.assertEqual(figure.result, "fail", figure.summary)
                self.assertIn("hybrid=98 not_hybrid=2 unknown=0 excluded=0", figure.summary)


# ---------------------------------------------------------------------------
# Figures 2 and 3: failure entries
# ---------------------------------------------------------------------------


class FailureEntriesTest(unittest.TestCase):
    ADDRESSES = ("203.0.113.5", "198.51.100.7", "2001:db8::5", "192.0.2.")

    def evaluate(self, records: list[dict[str, Any]], *, good: Any = None, monitored: list[str] | None = None,
                 min_coverage: float = 0.9, end: int | None = None) -> tuple[Any, Any]:
        win = pq_eval.Window(T0, max(record["time"] for record in records) if end is None else end)
        hosts = sorted({record["host"] for record in records}) if monitored is None else monitored
        return pq_eval.evaluate_failures(records, known_good() if good is None else good, hosts, win, INTERVAL, min_coverage)

    def assert_no_addresses(self, *figures: Any) -> None:
        text = " ".join(" ".join([figure.summary] + figure.details) for figure in figures)
        for address in self.ADDRESSES:
            self.assertNotIn(address, text)

    def test_monitored_outbound_failure_survives_an_inbound_flood(self) -> None:
        first = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        flood = [entry(seq, T0 + 100, "192.0.2.200", 40000 + seq, "malformed_record", direction="inbound",
                       reason="ek_length", connection_type="inbound") for seq in range(45, 301)]
        monitored = entry(1, T0 + 50, "203.0.113.5", 8333, "first_packet_failed")
        second = record(T0 + INTERVAL, inbound=ring(300, 44, flood), outbound=ring(1, 0, [monitored]))
        figure, triage = self.evaluate([first, second])
        self.assertEqual(figure.result, "fail")
        self.assertIn("entries=1", figure.summary)
        self.assertTrue(any("first_packet_failed/tag" in line and "known_good=archive" in line for line in figure.details))
        # 300 inbound failures between two samples overflow the ring: those lost entries are unknown.
        self.assertTrue(any("unknown archive inbound" in line and "sequences 1..44 were lost" in line for line in figure.details))
        self.assertEqual(triage.result, "unknown")
        self.assert_no_addresses(figure, triage)

    def test_wrapped_ring_without_loss_stays_judged(self) -> None:
        def unrelated(first: int, last: int) -> list[dict[str, Any]]:
            return [entry(seq, T0 + seq, "192.0.2.9", 9000 + seq, "malformed_record", direction="inbound") for seq in range(first, last + 1)]
        # The ring holds 256 entries and has wrapped twice, but every sample reaches back past the previous one.
        records = [record(T0, inbound=ring(256, 0, unrelated(1, 256)), outbound=ring(0, 0, [])),
                   record(T0 + INTERVAL, inbound=ring(300, 44, unrelated(45, 300)), outbound=ring(0, 0, [])),
                   record(T0 + 2 * INTERVAL, inbound=ring(556, 300, unrelated(301, 556)), outbound=ring(0, 0, []))]
        figure, triage = self.evaluate(records)
        self.assertEqual((figure.result, triage.result), ("pass", "pass"), figure.details)
        self.assertIn("unknown_intervals=0", figure.summary)
        # It is judged, so a known-good failure inside the wrapped stretch fails it.
        records[2]["recent_failures"]["inbound"]["entries"][-1] = entry(
            556, T0 + 556, "198.51.100.7", 50000, "first_packet_failed", direction="inbound")
        figure, _ = self.evaluate(records)
        self.assertEqual(figure.result, "fail")
        self.assertIn("known_good=pool", figure.details[0])

    def test_wrap_that_loses_entries_is_unknown(self) -> None:
        unrelated = [entry(seq, T0 + seq, "192.0.2.9", 9000 + seq, "malformed_record", direction="inbound") for seq in range(1, 301)]
        first = record(T0, inbound=ring(10, 0, unrelated[:10]), outbound=ring(0, 0, []))
        wrapped = record(T0 + INTERVAL, inbound=ring(300, 44, unrelated[44:]), outbound=ring(0, 0, []))
        figure, _ = self.evaluate([first, wrapped])
        self.assertEqual(figure.result, "unknown")
        self.assertIn("sequences 11..44 were lost when the ring wrapped", " ".join(figure.details))
        # Read again with nothing new, the ring is complete.
        self.assertEqual(self.evaluate([first, record(T0 + INTERVAL, inbound=ring(10, 0, unrelated[:10]),
                                                      outbound=ring(0, 0, []))])[0].result, "pass")

    def test_inconsistent_rings_are_unknown(self) -> None:
        entries = [entry(seq, T0 + seq, "192.0.2.9", 9000 + seq, "malformed_record", direction="inbound") for seq in range(1, 11)]
        first = record(T0, inbound=ring(10, 0, entries), outbound=ring(0, 0, []))
        cases = {
            "dropped changed without new entries": ring(10, 3, entries[3:]),
            "went backwards": ring(5, 0, entries[:5]),
            "malformed ring": ring(10, 0, entries[:4] + entries[5:]),
        }
        for reason, inbound in cases.items():
            with self.subTest(reason):
                figure, _ = self.evaluate([first, record(T0 + INTERVAL, inbound=inbound, outbound=ring(0, 0, []))])
                self.assertEqual(figure.result, "unknown")
                self.assertIn(reason, " ".join(figure.details))

    def test_unrelated_noise_does_not_fail(self) -> None:
        noise = [entry(seq, T0 + seq, "192.0.2.9", 8333, outcome) for seq, outcome in
                 enumerate(["malformed_record", "first_packet_failed", "fallback", "closed_after_switch"], 1)]
        records = [record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, [])),
                   record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(4, 0, noise)),
                   record(T0 + 2 * INTERVAL, inbound=ring(0, 0, []), outbound=ring(4, 0, noise))]
        figure, triage = self.evaluate(records)
        self.assertEqual((figure.result, figure.samples), ("pass", 3))
        self.assertEqual(triage.result, "pass")
        self.assertAlmostEqual(figure.coverage, 1.0)

    def test_malformed_endpoint_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))

        def evaluate(outcome: str, endpoint: Any) -> tuple[Any, Any]:
            failure = entry(1, T0 + 5, "192.0.2.9", 8333, outcome)
            if endpoint is ...:
                del failure["endpoint"]
            else:
                failure["endpoint"] = endpoint
            return self.evaluate([start, record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [failure]))])

        good = {"kind": "address", "network": "ipv4", "address": "192.0.2.9", "port": 8333}
        malformed = {
            "absent": ..., "null": None, "not an object": "192.0.2.9:8333",
            "no address": {key: value for key, value in good.items() if key != "address"},
            "address not a string": dict(good, address=3221225993), "empty address": dict(good, address=""),
            "address with a port": dict(good, address="192.0.2.9:8333"), "ipv6 address as ipv4": dict(good, address="2001:db8::9"),
            "no port": {key: value for key, value in good.items() if key != "port"}, "port as text": dict(good, port="8333"),
            "port true": dict(good, port=True), "port out of range": dict(good, port=65536), "negative port": dict(good, port=-1),
            "unknown kind": dict(good, kind="service"), "kind a list": dict(good, kind=["address"]),
            "unknown network": dict(good, network="tor"),
            "kind and network disagree": dict(good, kind="name_proxy"),
        }
        for outcome in ("malformed_record", "first_packet_failed", "fallback", "closed_after_switch"):
            monitored = outcome != "closed_after_switch"
            for label, endpoint in malformed.items():
                with self.subTest(outcome=outcome, endpoint=label):
                    figure, triage = evaluate(outcome, endpoint)
                    judged, other = (figure, triage) if monitored else (triage, figure)
                    self.assertEqual((judged.result, other.result), ("unknown", "pass"), judged.details)
                    self.assertIn(f"{outcome} entry 1 has a missing or malformed endpoint", " ".join(judged.details))
                    self.assert_no_addresses(figure, triage)
        # Valid endpoints of unrelated peers, on every network, are judged clean.
        valid = [good, dict(good, network="ipv6", address="2001:db8::9"), dict(good, network="cjdns", address="fc00::9"),
                 dict(good, network="onion", address="example.onion"), dict(good, network="i2p", address="example.b32.i2p", port=0),
                 {"kind": "name_proxy", "network": "name_proxy", "address": "seed.example.org", "port": 8333}]
        for endpoint in valid:
            with self.subTest(valid=endpoint["network"]):
                self.assertEqual(tuple(figure.result for figure in evaluate("fallback", endpoint)), ("pass", "pass"))
        # Outcomes outside both figures do not need an endpoint.
        self.assertEqual(evaluate("legacy_peer", None)[0].result, "pass")
        # A malformed endpoint that still names a known-good peer is that peer's failure.
        figure, _ = evaluate("fallback", {"address": "203.0.113.5", "port": 8333})
        self.assertEqual(figure.result, "fail")
        self.assertIn("known_good=archive", figure.details[0])

    def test_malformed_rings_are_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        failure = entry(1, T0 + 5, "192.0.2.9", 8333, "malformed_record", direction="inbound")
        cases: dict[str, Any] = {
            "recent_failures absent": ..., "recent_failures null": None, "recent_failures a list": [failure],
            "recent_failures text": "inbound",
            "last_sequence true": ring(True, 0, [failure]), "dropped true": ring(1, True, [failure]),
            "negative dropped": ring(1, -1, [failure]), "sequence true": ring(1, 0, [dict(failure, sequence=True)]),
            "sequence 0": ring(0, 0, [dict(failure, sequence=0)]), "entry not an object": ring(1, 0, ["entry"]),
        }
        for label, value in cases.items():
            with self.subTest(label):
                later = record(T0 + INTERVAL, inbound=value, outbound=ring(0, 0, []))
                if label.startswith("recent_failures"):
                    if value is ...:
                        del later["recent_failures"]
                    else:
                        later["recent_failures"] = value
                figure, triage = self.evaluate([start, later])
                self.assertEqual((figure.result, triage.result), ("unknown", "unknown"))
                self.assertIn("malformed ring", " ".join(figure.details))

    def test_malformed_outcome_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))

        def evaluate(outcome: Any) -> tuple[Any, Any]:
            failure = entry(1, T0 + 5, "192.0.2.9", 8333, "fallback")
            if outcome is ...:
                del failure["outcome"]
            else:
                failure["outcome"] = outcome
            return self.evaluate([start, record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [failure]))])

        # A malformed outcome may be a monitored or a triage one: both figures are unknown.
        for label, outcome in (("absent", ...), ("null", None), ("unknown word", "timeout"), ("capitalized", "Fallback"),
                               ("number", 3), ("object", {"outcome": "fallback"})):
            with self.subTest(label):
                figures = evaluate(outcome)
                self.assertEqual(tuple(figure.result for figure in figures), ("unknown", "unknown"))
                for figure in figures:
                    self.assertIn("entry 1 has a missing or malformed outcome", " ".join(figure.details))
        # The other outcomes in the vocabulary count towards neither figure.
        for outcome in ("legacy_peer", "abandoned", "internal_error"):
            with self.subTest(outcome):
                self.assertEqual(tuple(figure.result for figure in evaluate(outcome)), ("pass", "pass"))

    def test_implausible_entry_time_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))

        def evaluate(time: Any) -> Any:
            # A known-good failure: with its time it fails the figure, or is outside the window.
            failure = entry(1, T0 + 5, "203.0.113.5", 8333, "first_packet_failed")
            if time is ...:
                del failure["time"]
            else:
                failure["time"] = time
            later = record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [failure]))
            return self.evaluate([start, later], end=T0 + 2 * INTERVAL)[0]

        implausible = {"absent": ..., "null": None, "text": str(T0 + 5), "true": True, "negative": -1,
                       "beyond year 9999": 10**12, "milliseconds": (T0 + 5) * 1000,
                       "after the sample that read it": T0 + INTERVAL + 301, "before its process started": T0 - DAY - 301}
        for label, time in implausible.items():
            with self.subTest(label):
                figure = evaluate(time)
                self.assertEqual(figure.result, "unknown", figure.details)
                self.assertIn("entry 1 has a missing or implausible time", " ".join(figure.details))
                self.assert_no_addresses(figure)
        # Within the clock slack it is judged by its time: in the window, or before it.
        self.assertEqual(evaluate(T0 + INTERVAL + 300).result, "fail")
        # First read long before the window, it was recorded before the window, whatever its time says.
        held = ring(1, 0, [dict(entry(1, 0, "203.0.113.5", 8333, "fallback"), time="x")])
        early, later = (record(time, inbound=ring(0, 0, []), outbound=held) for time in (T0 - DAY + 600, T0))
        self.assertEqual(self.evaluate([early, later])[0].result, "pass")
        figure = evaluate(T0 - DAY - 300)
        self.assertEqual(figure.result, "unknown")  # only the coverage: 2 of 3 samples
        self.assertIn("entries=0 unknown_intervals=0", figure.summary)

    def test_malformed_fallback_set_entry_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        unrelated = {"endpoint": {"kind": "address", "network": "ipv4", "address": "192.0.2.9", "port": 8333},
                     "cause": "first_packet_failed", "reason": "tag", "streak": 3, "entered": T0 + 5, "expires": T0 + 3605,
                     "window_seconds": 3600}
        malformed = {"not an object": "192.0.2.9:8333", "null": None, "a list": [unrelated],
                     "no endpoint": {key: value for key, value in unrelated.items() if key != "endpoint"},
                     "malformed endpoint": dict(unrelated, endpoint={"address": "192.0.2.9"})}
        for label, item in malformed.items():
            with self.subTest(label):
                # Held over three samples, it is one unknown entry.
                records = [start] + [record(T0 + i * INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []), fallback_set=[item])
                                     for i in (1, 2, 3)]
                figure, triage = self.evaluate(records)
                self.assertEqual((figure.result, triage.result), ("unknown", "pass"))
                self.assertEqual(sum("fallback_set" in detail and "without a well-formed endpoint" in detail
                                     for detail in figure.details), 1, figure.details)
                self.assert_no_addresses(figure, triage)
        figure, _ = self.evaluate([start, record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []), fallback_set=[unrelated])])
        self.assertEqual(figure.result, "pass")

    def test_malformed_since_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        cases = {"absent": ..., "null": None, "text": str(T0 - DAY), "true": True, "negative": -1, "beyond year 9999": 10**12,
                 "after the sample": T0 + INTERVAL + 301}
        reasons = dict.fromkeys(cases, "since missing, malformed or after the sample")
        cases["changed within one instance_id"] = T0 - DAY + 1
        reasons["changed within one instance_id"] = "since changed within one instance_id"
        for label, since in cases.items():
            with self.subTest(label):
                later = record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []), since=since)
                if since is ...:
                    del later["since"]
                after = record(T0 + 2 * INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
                figure, _ = self.evaluate([start, later, after])
                self.assertEqual(figure.result, "unknown")
                self.assertIn(reasons[label], " ".join(figure.details))
        # A process that started while the sampler ran is not after the sample.
        self.assertEqual(self.evaluate([record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []), since=T0 + 300)])[0].result, "pass")

    def test_report_prints_only_well_formed_values(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        # Known-good failures whose other fields are malformed: still failures, and an
        # address in a malformed field never reaches the report.
        failure = dict(entry(1, T0 + 5, "203.0.113.5", 8333, "first_packet_failed"),
                       reason="203.0.113.9", connection_type="2001:db8::7", peer_id="198.51.100.20")
        held = {"endpoint": {"kind": "address", "network": "ipv6", "address": "2001:db8::5", "port": 8333}, "cause": ["tag"],
                "reason": "198.51.100.20", "streak": True, "entered": {"time": T0}, "expires": 10**30}
        later = record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [failure]), fallback_set=[held, held])
        figure, triage = self.evaluate([start, later])
        self.assertEqual(figure.result, "fail")
        self.assertIn("entries=2", figure.summary)
        self.assertIn("first_packet_failed/malformed conn_type=malformed peer_id=malformed known_good=archive", figure.details[0])
        self.assertEqual(figure.details[1], "malformed archive fallback_set cause=malformed/malformed streak=malformed "
                                            "expires=malformed known_good=known-good-3")
        text = " ".join(figure.details + triage.details)
        for address in ("203.0.113.9", "2001:db8::7", "198.51.100.20"):
            self.assertNotIn(address, text)
        self.assert_no_addresses(figure, triage)

    def test_restart_is_an_unknown_interval(self) -> None:
        first = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        restarted = record(T0 + 2 * INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []),
                           instance="b" * 64, since=T0 + INTERVAL)
        figure, _ = self.evaluate([first, restarted], min_coverage=0.5)
        self.assertEqual(figure.result, "unknown")
        self.assertIn("instance_id changed", " ".join(figure.details))
        # A fresh process whose rings are complete since startup is clean.
        fresh = record(T0, inbound=ring(0, 0, []), outbound=ring(1, 0, [entry(1, T0 - 5, "192.0.2.1", 1, "fallback")]),
                       since=T0 - 10)
        self.assertEqual(self.evaluate([fresh])[0].result, "pass")
        incomplete = record(T0, inbound=ring(0, 0, []), outbound=ring(300, 44, []), since=T0 - 10)
        figure, _ = self.evaluate([incomplete])
        self.assertEqual(figure.result, "unknown")
        self.assertIn("sequences 1..300 were dropped before the first sample", " ".join(figure.details))

    def test_known_good_failures(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        cases: dict[str, tuple[dict[str, Any], dict[str, Any], list[Any], str]] = {
            "inbound from the pool node, any source port":
                (ring(1, 0, [entry(1, T0 + 5, POOL_ADDRESS, 50123, "malformed_record", direction="inbound")]), ring(0, 0, []), [], "pool"),
            "fallback entry":
                (ring(0, 0, []), ring(1, 0, [entry(1, T0 + 5, "203.0.113.5", 8333, "fallback", reason="first_packet_failed")]), [], "archive"),
            "fallback_set":
                (ring(0, 0, []), ring(0, 0, []), [{"endpoint": {"kind": "address", "network": "ipv6", "address": "2001:db8::5", "port": 8333},
                                                     "cause": "closed_after_switch", "reason": "eof", "streak": 3,
                                                     "entered": T0 + 5, "expires": T0 + 3605, "window_seconds": 3600}], "known-good-3"),
        }
        for label, (inbound, outbound, fallback_set, name) in cases.items():
            with self.subTest(label):
                figure, triage = self.evaluate([start, record(T0 + INTERVAL, inbound=inbound, outbound=outbound, fallback_set=fallback_set)])
                self.assertEqual(figure.result, "fail")
                self.assertIn("entries=1", figure.summary)
                self.assertIn(f"known_good={name}", figure.details[0])
                self.assert_no_addresses(figure, triage)

    def test_missing_instance_id_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        for label, value in (("null", None), ("short", "abc"), ("number", 7), ("list", ["a" * 64])):
            with self.subTest(label):
                broken = record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [entry(1, T0 + 5, "192.0.2.9", 1, "fallback")]),
                                instance=value)
                after = record(T0 + 2 * INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
                figure, _ = self.evaluate([start, broken, after])
                self.assertEqual(figure.result, "unknown")
                self.assertTrue(any("instance_id missing or malformed" in detail for detail in figure.details))

    def test_missing_fallback_set_is_unknown(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        for label, value in (("null", None), ("not a list", {"endpoint": "x"}), ("absent", ...)):
            with self.subTest(label):
                later = record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
                if value is ...:
                    del later["fallback_set"]
                else:
                    later["fallback_set"] = value
                figure, _ = self.evaluate([start, later])
                self.assertEqual(figure.result, "unknown")
                self.assertTrue(any("fallback_set missing or malformed" in detail for detail in figure.details))

    def test_closed_after_switch_is_listed_for_triage(self) -> None:
        closed = entry(1, T0 + 5, "2001:db8::5", 8333, "closed_after_switch", reason="eof", connection_type="block-relay-only")
        records = [record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, [])),
                   record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [closed]))]
        figure, triage = self.evaluate(records)
        self.assertEqual(figure.result, "pass")
        self.assertEqual(triage.result, "fail")
        self.assertIn("known_good=known-good-3", triage.details[0])
        self.assert_no_addresses(figure, triage)

    def test_every_monitored_node_needs_evidence(self) -> None:
        archive = [record(T0 + i * INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, [])) for i in range(3)]
        figure, _ = self.evaluate(archive, monitored=["archive", "pool"])
        self.assertEqual(figure.result, "unknown")
        self.assertIn("unknown pool: coverage 0.0% is below 90.0%", figure.details)
        self.assertIn("nodes=archive:100.0%,pool:0.0%", figure.summary)
        pool = [dict(item, host="pool") for item in archive]
        self.assertEqual(self.evaluate(archive + pool, monitored=["archive", "pool"])[0].result, "pass")

    def test_low_coverage_is_unknown(self) -> None:
        # Records for half of the expected samples; the rings say nothing was lost.
        records = [record(T0 + i * INTERVAL, inbound=ring(0, 0, []), outbound=ring(0, 0, [])) for i in range(0, 10, 2)]
        figure, _ = self.evaluate(records, end=T0 + 9 * INTERVAL)
        self.assertEqual(figure.result, "unknown")
        self.assertAlmostEqual(figure.coverage, 0.5)
        self.assertEqual(self.evaluate(records, end=T0 + 9 * INTERVAL, min_coverage=0.5)[0].result, "pass")
        # Repeated records, files given twice and extra sampler runs add no coverage.
        for label, case in (("repeated", records * 3),
                            ("extra runs", records + [dict(item, time=item["time"] + offset) for item in records for offset in (-100, 100)])):
            with self.subTest(label):
                figure, _ = self.evaluate(case, end=T0 + 9 * INTERVAL)
                self.assertEqual((figure.result, figure.samples), ("unknown", 5))
                self.assertAlmostEqual(figure.coverage, 0.5)

    def test_coverage_counts_only_expected_samples_in_the_window(self) -> None:
        # Records for expected samples 0 to 8, and one 160 s after sample 9: nearest to
        # sample 10, which is after the window, so sample 9 is missing.
        def empty(time: int) -> dict[str, Any]:
            return record(time, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        records = [empty(T0 + i * INTERVAL) for i in range(9)] + [empty(T0 + 9 * INTERVAL + 160)]
        figure, _ = self.evaluate(records, min_coverage=0.95)
        self.assertEqual((figure.result, figure.samples), ("unknown", 9))
        self.assertAlmostEqual(figure.coverage, 0.9)
        # Likewise a record 100 s before the window starts is nearest to sample 0, but not in the window.
        records = [empty(T0 - 100)] + [empty(T0 + i * INTERVAL) for i in range(1, 10)]
        figure, _ = self.evaluate(records, min_coverage=0.95)
        self.assertEqual((figure.result, figure.samples), ("unknown", 9))

    def test_repeated_records_count_each_entry_once(self) -> None:
        start = record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))
        failed = record(T0 + INTERVAL, inbound=ring(0, 0, []), outbound=ring(1, 0, [entry(1, T0 + 5, "203.0.113.5", 8333, "first_packet_failed")]))
        once = self.evaluate([start, failed])
        twice = self.evaluate([start, failed, start, failed])
        self.assertEqual([(figure.result, figure.samples, figure.summary, figure.details) for figure in twice],
                         [(figure.result, figure.samples, figure.summary, figure.details) for figure in once])
        self.assertIn("entries=1", twice[0].summary)

    def test_missing_evidence_is_unknown(self) -> None:
        records = [record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, []))]
        win = pq_eval.Window(T0, T0)
        self.assertEqual(pq_eval.evaluate_failures(None, known_good(), ["archive"], win, INTERVAL, 0.9)[0].result, "unknown")
        empty = pq_eval.KnownGood({}, {})
        self.assertEqual(pq_eval.evaluate_failures(records, empty, ["archive"], win, INTERVAL, 0.9)[0].result, "unknown")
        self.assertEqual(pq_eval.evaluate_failures(records, known_good(), [], win, INTERVAL, 0.9)[0].result, "unknown")
        self.assertEqual(pq_eval.evaluate_failures([], known_good(), ["archive"], win, INTERVAL, 0.9)[0].result, "unknown")
        # A node that stopped reporting leaves the rest of the window unknown.
        figure, _ = self.evaluate(records, end=T0 + 10 * INTERVAL, min_coverage=0.05)
        self.assertEqual(figure.result, "unknown")
        self.assertIn("no samples since", " ".join(figure.details))
        broken = record(T0, inbound=ring(0, 0, []), outbound={"entries": []})
        self.assertEqual(self.evaluate([broken])[0].result, "unknown")

    def test_known_good_file(self) -> None:
        good = known_good()
        self.assertEqual(good.endpoints, {"203.0.113.5:8333": "archive", "[2001:db8::5]:8333": "known-good-3"})
        self.assertEqual(good.addresses, {POOL_ADDRESS: "pool"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "known-good.txt"
            bad = ["2001:db8::1:8333", "198.51.100.1:port", "[2001:db8::1", ":8333", "198.51.100.1:0", "198.51.100.1:70000",
                   "198.51.100.1 two labels", "198.51.100.1 bad/label", "198.51.100.1\n198.51.100.1"]
            for line in bad:
                path.write_text(line.replace("\\n", "\n") + "\n", encoding="utf8")
                with self.subTest(line), self.assertRaises(ValueError) as raised:
                    pq_eval.read_known_good(path)
                self.assertNotIn("198.51.100.1", str(raised.exception).replace(str(path), ""))
                self.assertNotIn("2001:db8", str(raised.exception))
            path.write_text("[2001:db8::1]\nExample.org:8333 seed  # comment\n", encoding="utf8")
            good = pq_eval.read_known_good(path)
            self.assertEqual((good.endpoints, good.addresses), ({"example.org:8333": "seed"}, {"2001:db8::1": "known-good-1"}))


# ---------------------------------------------------------------------------
# Figure 4: connections_in against the control
# ---------------------------------------------------------------------------


class ConnectionsTest(unittest.TestCase):
    BASELINE_DAYS = 3
    CANARY_DAYS = 4

    def series(self, archive_in: Any, control_in: Any, *, archive_restart: int | None = None,
               control_down: range | None = None) -> tuple[list[Any], list[Any], Any]:
        archive = Node("archive", boot=T0 - 60 * DAY)
        control = Node("control", boot=T0 - 60 * DAY, v1_0_0=True)
        archive_rows, control_rows = [], []
        per_day = DAY // INTERVAL
        for index in range(-self.BASELINE_DAYS * per_day, self.CANARY_DAYS * per_day):
            time = T0 + index * INTERVAL
            if archive_restart is not None and index == archive_restart:
                archive.restart(time - 60)
            archive_rows.append(archive.sample(time, connections_in=archive_in(index)))
            down = control_down is not None and index in control_down
            control_rows.append(control.sample(time, connections_in=control_in(index), down=down))
        end = T0 + (self.CANARY_DAYS * per_day - 1) * INTERVAL
        return archive_rows, control_rows, pq_eval.Window(T0, end)

    def evaluate(self, archive_rows: Any, control_rows: Any, win: Any, baseline_ratio: float | None = None,
                 min_coverage: float = 0.9) -> Any:
        return pq_eval.evaluate_connections(archive_rows, control_rows, T0, win, INTERVAL, baseline_ratio, min_coverage)

    def test_within_tolerance(self) -> None:
        # The archive runs at 1.2 times the control in the baseline; 1.3 times is within 20% of that.
        figure = self.evaluate(*self.series(lambda i: 36 if i < 0 else 39, lambda i: 30))
        self.assertEqual(figure.result, "pass", figure.details)
        self.assertIn("baseline_ratio=1.200", figure.summary)
        self.assertEqual(figure.samples, self.CANARY_DAYS * DAY // INTERVAL)

    def test_outside_tolerance(self) -> None:
        figure = self.evaluate(*self.series(lambda i: 36 if i < 288 else 25, lambda i: 30))
        self.assertEqual(figure.result, "fail")
        self.assertTrue(any(" fail: relative=0.694" in line for line in figure.details))

    def test_48_hours_after_a_restart_are_excluded(self) -> None:
        # Inbound connections recover slowly after the restart at the canary start.
        archive_rows, control_rows, win = self.series(
            lambda i: 36 if i < 0 or i >= 2 * 288 else 5, lambda i: 30, archive_restart=0)
        figure = self.evaluate(archive_rows, control_rows, win)
        self.assertEqual(figure.result, "pass", figure.details)
        self.assertEqual(sum(" excluded:" in line for line in figure.details), 2)

    def test_missing_measurements_are_unknown(self) -> None:
        archive_rows, control_rows, win = self.series(lambda i: 36, lambda i: 30, control_down=range(288, 2 * 288))
        figure = self.evaluate(archive_rows, control_rows, win)
        self.assertEqual(figure.result, "unknown", figure.details)
        archive_rows, control_rows, win = self.series(lambda i: 36, lambda i: None if 0 <= i < 288 else 30)
        self.assertEqual(self.evaluate(archive_rows, control_rows, win).result, "unknown")
        # Without a baseline there is nothing to compare against, unless one is given.
        archive_rows, control_rows, win = self.series(lambda i: 36, lambda i: 30)
        canary_only = ([row for row in archive_rows if int(row["time"]) >= T0], [row for row in control_rows if int(row["time"]) >= T0])
        self.assertEqual(self.evaluate(*canary_only, win).result, "unknown")
        self.assertEqual(self.evaluate(*canary_only, win, baseline_ratio=1.2).result, "pass")
        self.assertEqual(pq_eval.evaluate_connections(archive_rows, None, T0, win, INTERVAL, None, 0.9).result, "unknown")

    def test_zero_baseline_is_unknown(self) -> None:
        # Valid pre-canary pairs whose connections_in sum to 0 on one side give no usable ratio.
        pairs = self.BASELINE_DAYS * DAY // INTERVAL
        cases = {
            "archive": (lambda i: 0 if i < 0 else 36, lambda i: 30),
            "control": (lambda i: 36, lambda i: 0 if i < 0 else 30),
        }
        for node, (archive_in, control_in) in cases.items():
            with self.subTest(node=node):
                archive_rows, control_rows, win = self.series(archive_in, control_in)
                figure = self.evaluate(archive_rows, control_rows, win)
                self.assertEqual(figure.result, "unknown")
                self.assertEqual(figure.summary, f"no baseline: {node} connections_in summed to 0 over {pairs} valid pre-canary pairs")
                self.assertEqual((figure.samples, figure.coverage), (0, None))
                # A given ratio still judges the canary days.
                self.assertEqual(self.evaluate(archive_rows, control_rows, win, baseline_ratio=1.2).result, "pass")

    def test_malformed_numbers_are_missing(self) -> None:
        # Day 0 holds the baseline ratio; the archive then loses a third of its connections.
        archive_rows, control_rows, win = self.series(lambda i: 36 if i < 288 else 24, lambda i: 30)
        self.assertEqual(self.evaluate(archive_rows, control_rows, win).result, "fail")
        later = T0 + DAY
        for label, uptime in (("negative", "-1"), ("non-ASCII digits", "\u0661")):
            with self.subTest(uptime=label):
                # Not an uptime, so not a restart: the later days are unknown, not excluded.
                broken = [dict(row, uptime=uptime) if int(row["time"]) >= later else row for row in archive_rows]
                figure = self.evaluate(broken, control_rows, win)
                self.assertEqual(figure.result, "unknown", figure.details)
                self.assertFalse(any(" excluded:" in line for line in figure.details), figure.details)
        for label, count in (("negative", "-30"), ("decimal", "30.5")):
            with self.subTest(connections_in=label):
                broken = [dict(row, connections_in=count) if int(row["time"]) >= later else row for row in control_rows]
                self.assertEqual(self.evaluate(archive_rows, broken, win).result, "unknown")

    def test_unanswered_samples_are_not_pairs(self) -> None:
        archive_rows, control_rows, win = self.series(lambda i: 36, lambda i: 30)
        # sample_ok=0 says a call failed: its values are not a measurement, even when present.
        control_rows = [dict(row, sample_ok="0") if T0 + DAY <= int(row["time"]) < T0 + 2 * DAY else row for row in control_rows]
        figure = self.evaluate(archive_rows, control_rows, win)
        self.assertEqual(figure.result, "unknown", figure.details)
        self.assertEqual(figure.samples, (self.CANARY_DAYS - 1) * DAY // INTERVAL)

    def test_days_need_coverage(self) -> None:
        # 30 of a full day's 288 samples missing on the control: 89.6% coverage.
        archive_rows, control_rows, win = self.series(lambda i: 36, lambda i: 30)
        gap = {T0 + index * INTERVAL for index in range(400, 430)}
        control_rows = [row for row in control_rows if int(row["time"]) not in gap]
        figure = self.evaluate(archive_rows, control_rows, win)
        self.assertEqual(figure.result, "unknown")
        self.assertTrue(any(line.startswith("2025-10-10 unknown:") and "coverage=89.6%" in line for line in figure.details), figure.details)
        self.assertEqual(self.evaluate(archive_rows, control_rows, win, min_coverage=0.85).result, "pass")
        # Recording the other samples twice does not fill the gap.
        twice = control_rows + [dict(row, time=str(int(row["time"]) + 60)) for row in control_rows]
        figure = self.evaluate(archive_rows * 2, twice, win)
        self.assertEqual(figure.result, "unknown")
        self.assertTrue(any(line.startswith("2025-10-10 unknown:") and "coverage=89.6%" in line for line in figure.details), figure.details)

    def test_several_samples_for_one_expected_sample_count_as_the_least_favorable(self) -> None:
        archive_rows, control_rows, win = self.series(lambda i: 36, lambda i: 30)
        full = self.CANARY_DAYS * DAY // INTERVAL
        self.assertEqual(self.evaluate(archive_rows, control_rows, win).samples, full)

        def shifted(rows: list[Any], indexes: range, offset: int, **changes: str) -> list[Any]:
            """Copies of the canary samples at indexes, offset seconds later, with changes."""
            return [dict(rows[self.BASELINE_DAYS * 288 + index], time=str(T0 + index * INTERVAL + offset), **changes) for index in indexes]
        cases = {
            # An unanswered sample a minute before some expected samples and after others.
            "unanswered": shifted(control_rows, range(300, 310), -60, sample_ok="0") + shifted(control_rows, range(400, 410), 60, sample_ok="0"),
            # A second measurement that disagrees with the first.
            "disagreeing": shifted(control_rows, range(300, 310), -60, connections_in="31") + shifted(control_rows, range(400, 410), 60, connections_in="29"),
        }
        for label, extra in cases.items():
            with self.subTest(label):
                figure = self.evaluate(archive_rows, control_rows + extra, win)
                self.assertEqual(figure.samples, full - 20, figure.details)
        # A measurement that agrees is the same measurement.
        figure = self.evaluate(archive_rows, control_rows + shifted(control_rows, range(300, 310), -60), win)
        self.assertEqual((figure.result, figure.samples), ("pass", full))

        # A sample of the node 30 s after a restart excludes its expected sample,
        # unless another sample for it is unusable.
        restarted = Node("archive", boot=T0 + 300 * INTERVAL + 30)
        restarted.instance = 1
        after_restart = restarted.sample(T0 + 300 * INTERVAL + 60)
        figure = self.evaluate(archive_rows + [after_restart], control_rows, win)
        self.assertEqual(figure.samples, full - 1)
        self.assertTrue(any(" excluded=1 " in line for line in figure.details), figure.details)
        unanswered = [dict(row, sample_ok="0") if int(row["time"]) == T0 + 300 * INTERVAL else row for row in archive_rows]
        figure = self.evaluate(unanswered + [after_restart], control_rows, win)
        self.assertEqual(figure.samples, full - 1)
        self.assertFalse(any(" excluded=1 " in line for line in figure.details), figure.details)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


class EvaluatorCommandTest(unittest.TestCase):
    # Every address in the fixtures; none may reach the report.
    ADDRESSES = ("203.0.113.5", "203.0.113.9", "198.51.100.7", "198.51.100.20", "198.51.100.77", "2001:db8")

    @staticmethod
    def run_evaluator(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(EVALUATOR), *args], text=True, capture_output=True)

    def write_samples(self, root: Path) -> None:
        nodes = {"pool": Node("pool", boot=T0 - 3 * DAY, pinned=PINNED), "archive": Node("archive", boot=T0 - 3 * DAY),
                 "control": Node("control", boot=T0 - 10 * DAY, v1_0_0=True)}
        for index in range(-2 * 288, 3 * 288):
            time = T0 + index * INTERVAL
            for name, node in nodes.items():
                row = node.sample(time)
                pq_canary.append_row(root / f"{name}.csv", {key: NA if value is None else value for key, value in row.items()})
                failures = pq_canary.build_failures_record(time=time, host=name, pqinfo=node.pqinfo(time))
                if failures is not None and name != "control":
                    with (root / f"{name}.jsonl").open("a", encoding="utf8") as out:
                        out.write(json.dumps(failures) + "\n")

    def test_prints_every_figure_without_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_samples(root)
            inputs = ["--canary-start", pq_eval.utc(T0), "--pool", str(root / "pool.csv"), "--archive", str(root / "archive.csv"),
                      "--control", str(root / "control.csv"), "--known-good", str(FIXTURES / "known-good.txt"), "--baseline-ratio", "1.0"]
            result = self.run_evaluator(*inputs, "--failures", str(root / "pool.jsonl"), "--failures", str(root / "archive.jsonl"))
            # The pool and archive nodes are monitored by default: one node's file is not enough.
            one_node = self.run_evaluator(*inputs, "--failures", str(root / "archive.jsonl"))
        lines = result.stdout.splitlines()
        figures = [line for line in lines if line.split(" ", 1)[0] in ("pass", "fail", "unknown")]
        self.assertEqual(len(figures), 4, result.stdout + result.stderr)
        for line in figures:
            self.assertIn("samples=", line)
            self.assertIn("coverage=", line)
        self.assertTrue(figures[0].startswith("pass ") and "pinned link" in figures[0], figures[0])
        self.assertTrue(figures[1].startswith("pass ") and "nodes=archive:100.0%,pool:100.0%" in figures[1], figures[1])
        # The fixture's closed_after_switch entry comes from a known-good IPv6 peer, reported by its label.
        self.assertTrue(figures[2].startswith("fail ") and "closed_after_switch" in figures[2], figures[2])
        self.assertIn("known_good=known-good-3", result.stdout)
        for address in self.ADDRESSES:
            self.assertNotIn(address, result.stdout + result.stderr)
        self.assertIn("canary verdict (figures 1, 2 and 4):", lines[-1])
        verdict = lines[-1].rsplit(" ", 1)[1]
        self.assertEqual(result.returncode, {"pass": 0, "fail": 1, "unknown": 3}[verdict])

        failures_line = next(line for line in one_node.stdout.splitlines() if "first_packet_failed or fallback" in line)
        self.assertTrue(failures_line.startswith("unknown "), failures_line)
        self.assertIn("unknown pool: coverage 0.0%", one_node.stdout)

    def test_sample_time_beyond_year_9999_is_not_a_sample(self) -> None:
        pool = Node("pool", boot=T0 - DAY, pinned=PINNED)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pool.csv"
            for index in range(3):
                row = pool.sample(T0 + index * INTERVAL)
                pq_canary.append_row(path, {key: NA if value is None else value for key, value in dict(row, time=str(10**14) if index == 2 else row["time"]).items()})
            result = self.run_evaluator("--canary-start", str(T0), "--pool", str(path))
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(f"PQ canary evaluation: {pq_eval.utc(T0)} to {pq_eval.utc(T0 + INTERVAL)}", result.stdout)

    def test_zero_baseline_is_reported_not_raised(self) -> None:
        archive, control = Node("archive", boot=T0 - 60 * DAY), Node("control", boot=T0 - 60 * DAY, v1_0_0=True)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(-288, 288):
                time = T0 + index * INTERVAL
                for name, row in (("archive", archive.sample(time, connections_in=0 if index < 0 else 36)), ("control", control.sample(time))):
                    pq_canary.append_row(root / f"{name}.csv", {key: NA if value is None else value for key, value in row.items()})
            result = self.run_evaluator("--canary-start", str(T0), "--archive", str(root / "archive.csv"), "--control", str(root / "control.csv"))
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        line = next(line for line in result.stdout.splitlines() if "connections_in within" in line)
        self.assertTrue(line.startswith("unknown "), line)
        self.assertIn("no baseline: archive connections_in summed to 0 over 288 valid pre-canary pairs", line)

    def test_argument_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_samples(root)
            pool, failures, good = str(root / "pool.csv"), str(root / "archive.jsonl"), str(FIXTURES / "known-good.txt")
            bad_csv = root / "bad.csv"
            bad_csv.write_text("not,a,sample\n", encoding="utf8")
            bad_good = root / "bad-known-good.txt"
            bad_good.write_text("203.0.113.5:99999\n", encoding="utf8")
            archive, control = str(root / "archive.csv"), str(root / "control.csv")

            def samples(name: str, *sources: str, **changes: str) -> str:
                """A samples file with the rows of sources, with changes applied to each row."""
                for source in sources:
                    for row in pq_canary.read_rows(Path(source)):
                        pq_canary.append_row(root / name, {key: NA if value is None else value for key, value in dict(row, **changes).items()})
                return str(root / name)
            start = ["--canary-start", str(T0)]
            cases = {
                "the following arguments are required: --canary-start": ["--pool", pool],
                "expected Unix seconds or an ISO 8601 time": ["--canary-start", "yesterday", "--pool", pool],
                "expected a time from 1970 to 9999, got '99999999999999'": start + ["--pool", pool, "--end", "99999999999999"],
                "give at least one of --pool": start,
                "unrecognized arguments: --bogus": start + ["--pool", pool, "--bogus"],
                "unrecognized arguments: --pool-csv": start + ["--pool-csv", pool],
                "unrecognized arguments: --canary-st": start + ["--canary-st", str(T0), "--pool", pool],
                "no such file": start + ["--pool", str(root / "missing.csv")],
                "expected a positive whole number": start + ["--pool", pool, "--interval", "0"],
                "expected a whole number of seconds": start + ["--pool", pool, "--restart-grace", "-1"],
                "expected a share greater than 0": start + ["--pool", pool, "--min-coverage", "1.5"],
                "expected a positive ratio": start + ["--pool", pool, "--baseline-ratio", "inf"],
                "expected a positive ratio, got '0'": start + ["--pool", pool, "--baseline-ratio", "0"],
                "--failures needs --known-good": start + ["--failures", failures],
                "--known-good is only used with --failures": start + ["--pool", pool, "--known-good", good],
                "--monitored is only used with --failures": start + ["--pool", pool, "--monitored", "pool"],
                "expected distinct comma-separated host labels": start + ["--failures", failures, "--known-good", good, "--monitored", "pool,pool"],
                "--end is before --canary-start": start + ["--pool", pool, "--end", str(T0 - 1)],
                "unexpected header": start + ["--pool", str(bad_csv)],
                # Each role is a different node: never compare a node with itself.
                "--archive and --control are the same file": start + ["--archive", archive, "--control", archive],
                "--archive and --control both have the host label archive":
                    start + ["--archive", archive, "--control", samples("relabeled.csv", control, host="archive")],
                "--archive mixes the host labels archive, control": start + ["--archive", samples("mixed.csv", archive, control)],
                "--pool has a row without a valid host label": start + ["--pool", samples("no-host.csv", pool, host=NA)],
                "--archive and --control report the same instance_id":
                    start + ["--archive", archive, "--control", samples("same-node.csv", archive, host="control")],
                "--pool and --archive both have the host label pool":
                    start + ["--pool", pool, "--archive", samples("pool-as-archive.csv", archive, host="pool")],
                "expected address or address:port with a port from 1 to 65535": start + ["--failures", failures, "--known-good", str(bad_good)],
            }
            for message, args in cases.items():
                with self.subTest(message):
                    result = self.run_evaluator(*args)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertNotIn("203.0.113.5", result.stderr)
            # A failures.jsonl line that cannot be placed in time or attributed to a node.
            for label, change in (("time true", {"time": True}), ("time text", {"time": str(T0)}), ("time negative", {"time": -1}),
                                  ("time beyond year 9999", {"time": 10**12}), ("host null", {"host": None}),
                                  ("host not a label", {"host": "archive node"}), ("host with a newline", {"host": "archive\n"})):
                with self.subTest(label):
                    bad_failures = root / "bad.jsonl"
                    line = dict(record(T0, inbound=ring(0, 0, []), outbound=ring(0, 0, [])), **change)
                    bad_failures.write_text(json.dumps(line) + "\n", encoding="utf8")
                    result = self.run_evaluator(*start, "--failures", str(bad_failures), "--known-good", good)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("a failures.jsonl line lacks a time in Unix seconds or a host label", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_time_parsing(self) -> None:
        self.assertEqual(pq_eval.parse_time("1760000000"), T0)
        self.assertEqual(pq_eval.parse_time(pq_eval.utc(T0)), T0)
        self.assertEqual(pq_eval.parse_time("2025-10-09T08:53:20+00:00"), T0)
        with self.assertRaises(ValueError):
            pq_eval.parse_time("2025-13-01")


if __name__ == "__main__":
    unittest.main()
