#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shared helpers for manual IBD performance harnesses."""

from __future__ import annotations

from contextlib import AbstractContextManager
from decimal import Decimal
from pathlib import Path
import logging
import os
import re
import signal
import subprocess
import threading
import time
from typing import Any


REPLAY_REPORT_VERSION = 6
NETWORK_REPORT_VERSION = 3
W1_REPLAY_FLOOR = "w1-replay-floor"
W2_REPLAY_MIXED = "w2-replay-mixed"
W2_P2MR_FUND_AMOUNT_SAT = 5_000_000
W2_P2MR_SPEND_AMOUNT = Decimal("0.02000000")
QBIT_TARGET_SPACING_SEC = 60


class WorkloadTimekeeper:
    """Keep mocktime aligned with long synthetic block histories."""

    def __init__(self, node, *, target_spacing: int = QBIT_TARGET_SPACING_SEC) -> None:
        self.node = node
        self.target_spacing = target_spacing
        self.mocktime: int | None = None
        self._next_block_time: int | None = None

    def sync_to_tip(self) -> int:
        tip_time = self.node.getblockheader(self.node.getbestblockhash())["time"]
        mocktime = tip_time + self.target_spacing
        self.mocktime = mocktime
        self._next_block_time = mocktime
        self.node.setmocktime(mocktime)
        return mocktime

    def generate(self, test, generator, blocks: int) -> list[str]:
        hashes = []
        for _ in range(blocks):
            if self._next_block_time is None:
                block_time = self.sync_to_tip()
            else:
                block_time = self._next_block_time
                self.node.setmocktime(block_time)
                self.mocktime = block_time
            hashes.extend(test.generate(generator, 1, sync_fun=test.no_op))
            self._next_block_time = block_time + self.target_spacing
        return hashes


def debug_log_tail(path: Path, *, max_lines: int = 80, max_bytes: int = 64_000) -> list[str]:
    """Return a bounded tail of debug.log without reading large logs into memory."""
    if not path.exists():
        return []
    try:
        with path.open("rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            size = log_file.tell()
            log_file.seek(max(0, size - max_bytes))
            data = log_file.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()[-max_lines:]


def rpc_chain_snapshot(node, *, expected_tip_height: int | None = None) -> dict[str, Any]:
    """Collect RPC progress fields that are useful when long IBD waits time out."""
    snapshot: dict[str, Any] = {
        "expected_tip_height": expected_tip_height,
    }
    try:
        chaininfo = node.getblockchaininfo()
    except Exception as exc:  # noqa: BLE001 - diagnostics should not mask the original timeout
        snapshot["getblockchaininfo_error"] = repr(exc)
        return snapshot

    for field in (
        "blocks",
        "headers",
        "bestblockhash",
        "initialblockdownload",
        "verificationprogress",
        "pruned",
        "pruneheight",
        "size_on_disk",
        "warnings",
    ):
        if field in chaininfo:
            snapshot[field] = chaininfo[field]

    try:
        snapshot["mempool_loaded"] = node.getmempoolinfo().get("loaded")
    except Exception as exc:  # noqa: BLE001 - mempool may be unavailable while replay is still starting
        snapshot["getmempoolinfo_error"] = repr(exc)
    return snapshot


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    try:
        entries = path.rglob("*") if path.is_dir() else (path,)
        for entry in entries:
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                continue
    except OSError:
        return total
    return total


def git_head(repo_root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            encoding="utf-8",
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def slugify(value: str) -> str:
    import re

    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-").lower()
    return slug or "report"


def replay_lane_name(history_mode: str, reindex_mode: str, lane_name: str | None = None) -> str:
    return lane_name or f"{history_mode}-{reindex_mode}"


def build_replay_workload_recipe(
    *,
    workload: str,
    txs_per_block: int,
    p2mr_spends_per_block: int,
) -> dict[str, Any]:
    effective_p2mr_spends = p2mr_spends_per_block if workload == W2_REPLAY_MIXED else 0
    recipe: dict[str, Any] = {
        "workload": workload,
        "proxy_txs_per_block": txs_per_block,
        "p2mr_spends_per_block": effective_p2mr_spends,
    }
    if workload == W2_REPLAY_MIXED:
        recipe["p2mr_fund_amount_sat"] = W2_P2MR_FUND_AMOUNT_SAT
        recipe["p2mr_target_output_btc"] = str(W2_P2MR_SPEND_AMOUNT)
    return recipe


def build_replay_workload_count_expectations(
    *,
    workload: str,
    blocks: int,
    txs_per_block: int,
    p2mr_spends_per_block: int,
) -> dict[str, int]:
    """Return the deterministic counts the replay/network builders should emit."""
    if blocks < 0:
        raise AssertionError("blocks must be non-negative")
    if txs_per_block < 0:
        raise AssertionError("txs_per_block must be non-negative")
    if p2mr_spends_per_block < 0:
        raise AssertionError("p2mr_spends_per_block must be non-negative")

    effective_p2mr_spends = p2mr_spends_per_block if workload == W2_REPLAY_MIXED else 0
    return {
        "seeded_p2mr_utxos": effective_p2mr_spends,
        "measured_proxy_txs_total": blocks * txs_per_block,
        "measured_p2mr_funding_txs_total": blocks * effective_p2mr_spends,
        "measured_p2mr_spend_txs_total": blocks * effective_p2mr_spends,
    }


def build_replay_workload_name(
    *,
    workload: str,
    blocks: int,
    txs_per_block: int,
    p2mr_spends_per_block: int,
    tail_blocks: int,
    workload_name: str | None = None,
) -> str:
    if workload_name:
        return workload_name

    tail_suffix = f"-tail{tail_blocks}" if tail_blocks else ""
    if workload == W2_REPLAY_MIXED:
        return (
            f"w2-replay-mixed-{blocks}blk-"
            f"{txs_per_block}proxy-"
            f"{p2mr_spends_per_block}p2mrpb{tail_suffix}"
        )
    return f"address-op-true-{blocks}blk-{txs_per_block}txpb{tail_suffix}"


def _require_key(report: dict[str, Any], key: str) -> Any:
    if key not in report:
        raise AssertionError(f"missing report field: {key}")
    return report[key]


def _require_type(value: Any, expected_type, field: str) -> None:
    if not isinstance(value, expected_type):
        raise AssertionError(f"unexpected type for {field}: {type(value).__name__}")


def _require_number(value: Any, field: str) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise AssertionError(f"unexpected numeric field type for {field}: {type(value).__name__}")


def _require_nullable_number(value: Any, field: str) -> None:
    if value is not None:
        _require_number(value, field)


def _require_non_negative_int(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AssertionError(f"expected non-negative int for {field}")


def _require_nullable_non_negative_int(value: Any, field: str) -> None:
    if value is not None:
        _require_non_negative_int(value, field)


def _validate_disk_usage_sampling(value: Any, field: str) -> None:
    _require_type(value, dict, field)
    _require_type(_require_key(value, "enabled"), bool, f"{field}.enabled")
    _require_number(_require_key(value, "interval_sec"), f"{field}.interval_sec")
    _require_non_negative_int(_require_key(value, "sample_count"), f"{field}.sample_count")
    _require_type(_require_key(value, "monitored_paths"), dict, f"{field}.monitored_paths")
    _require_type(_require_key(value, "peak_paths_bytes"), dict, f"{field}.peak_paths_bytes")
    for nested in value["monitored_paths"].values():
        _require_type(nested, str, f"{field}.monitored_paths[]")
    for nested in value["peak_paths_bytes"].values():
        _require_non_negative_int(nested, f"{field}.peak_paths_bytes[]")
    for nested_field in (
        "start_total_bytes",
        "end_total_bytes",
        "peak_total_bytes",
    ):
        _require_nullable_non_negative_int(_require_key(value, nested_field), f"{field}.{nested_field}")
    _require_nullable_number(_require_key(value, "peak_elapsed_sec"), f"{field}.peak_elapsed_sec")


def _validate_connectblock_trace_summary(value: Any, field: str) -> None:
    _require_type(value, dict, field)
    _require_type(_require_key(value, "captured"), bool, f"{field}.captured")
    _require_type(_require_key(value, "parseable"), bool, f"{field}.parseable")
    _require_type(_require_key(value, "bench_sample_count"), int, f"{field}.bench_sample_count")
    _require_non_negative_int(value["bench_sample_count"], f"{field}.bench_sample_count")
    for nested_field in (
        "sample_count",
        "bench_blocks_total",
        "bench_txs_total",
        "bench_inputs_total",
        "bench_sigops_total",
        "bench_max_height",
        "slow_block_sample_count",
        "slow_block_max_ms",
    ):
        _require_nullable_non_negative_int(_require_key(value, nested_field), f"{field}.{nested_field}")
    for nested_field in ("median_ms", "p95_ms", "max_ms"):
        _require_nullable_number(_require_key(value, nested_field), f"{field}.{nested_field}")
    for nested_field in ("path", "duration_summary_method", "parse_error"):
        if _require_key(value, nested_field) is not None:
            _require_type(value[nested_field], str, f"{field}.{nested_field}")


def _validate_utxo_flush_evidence(value: Any, field: str) -> None:
    _require_type(value, dict, field)
    _require_type(_require_key(value, "captured"), bool, f"{field}.captured")
    for nested_field in (
        "source",
        "log_path",
        "parse_error",
        "privileged_trace_path",
        "privileged_trace_status",
    ):
        if _require_key(value, nested_field) is not None:
            _require_type(value[nested_field], str, f"{field}.{nested_field}")
    for nested_field in (
        "log_start_offset",
        "log_end_offset",
        "utxo_cache_sample_count",
        "utxo_cache_peak_utxos",
        "flush_event_count",
    ):
        _require_nullable_non_negative_int(_require_key(value, nested_field), f"{field}.{nested_field}")
    _require_nullable_number(_require_key(value, "utxo_cache_peak_mib"), f"{field}.utxo_cache_peak_mib")
    _require_type(_require_key(value, "flush_events"), list, f"{field}.flush_events")
    for index, event in enumerate(value["flush_events"]):
        _require_type(event, dict, f"{field}.flush_events[{index}]")
        _require_nullable_non_negative_int(_require_key(event, "coins"), f"{field}.flush_events[{index}].coins")
        _require_nullable_number(_require_key(event, "cache_kib"), f"{field}.flush_events[{index}].cache_kib")
        _require_type(_require_key(event, "line"), str, f"{field}.flush_events[{index}].line")


def _validate_replay_workload_metadata(report: dict[str, Any]) -> None:
    expected_recipe = build_replay_workload_recipe(
        workload=report["workload"],
        txs_per_block=report["txs_per_block"],
        p2mr_spends_per_block=report["p2mr_spends_per_block"],
    )
    if report["workload_recipe"] != expected_recipe:
        raise AssertionError("workload recipe does not match workload inputs")

    expected_counts = build_replay_workload_count_expectations(
        workload=report["workload"],
        blocks=report["measured_blocks"],
        txs_per_block=report["txs_per_block"],
        p2mr_spends_per_block=report["p2mr_spends_per_block"],
    )
    for field, expected_value in expected_counts.items():
        if report[field] != expected_value:
            raise AssertionError(f"unexpected {field}: {report[field]} != {expected_value}")


def validate_replay_report_schema(report: dict[str, Any]) -> None:
    _require_type(_require_key(report, "report_version"), int, "report_version")
    if report["report_version"] != REPLAY_REPORT_VERSION:
        raise AssertionError(f"unexpected replay report version: {report['report_version']}")
    if _require_key(report, "report_kind") != "replay":
        raise AssertionError("unexpected replay report kind")
    if _require_key(report, "report_only") is not True:
        raise AssertionError("replay reports must stay report-only")

    for field in (
        "generated_at_utc",
        "chain",
        "lane_name",
        "workload_name",
        "workload",
        "reindex_mode",
        "history_mode",
        "history_script",
        "expected_tip_hash",
        "tmpdir",
        "builddir",
        "bitcoind_path",
        "bitcoin_cli_path",
        "pre_replay_localservices",
        "post_replay_localservices",
    ):
        _require_type(_require_key(report, field), str, field)

    for field in (
        "workload_recipe",
        "host",
    ):
        _require_type(_require_key(report, field), dict, field)

    for field in ("history_node_args", "node_args", "pre_replay_localservicesnames", "post_replay_localservicesnames"):
        _require_type(_require_key(report, field), list, field)

    for field in (
        "warmup_blocks",
        "measured_blocks",
        "tail_blocks",
        "measured_start_height",
        "measured_end_height",
        "txs_per_block",
        "p2mr_spends_per_block",
        "seeded_p2mr_utxos",
        "measured_proxy_txs_total",
        "measured_p2mr_funding_txs_total",
        "measured_p2mr_spend_txs_total",
        "expected_tip_height",
        "replay_timeout",
        "pre_replay_blocks_bytes",
        "pre_replay_chainstate_bytes",
        "post_replay_blocks_bytes",
        "post_replay_chainstate_bytes",
        "observed_total_bytes_before_replay",
        "observed_total_bytes_after_replay",
        "observed_total_bytes_max",
    ):
        _require_non_negative_int(_require_key(report, field), field)

    _validate_disk_usage_sampling(_require_key(report, "disk_usage_sampling"), "disk_usage_sampling")
    _validate_connectblock_trace_summary(
        _require_key(report, "connectblock_trace_summary"), "connectblock_trace_summary"
    )
    _validate_utxo_flush_evidence(_require_key(report, "utxo_flush_evidence"), "utxo_flush_evidence")

    for field in (
        "replay_rpc_connect_sec",
        "replay_completion_wait_sec",
        "elapsed_sec",
        "blocks_per_sec",
        "measured_blocks_per_total_replay_sec",
    ):
        _require_number(_require_key(report, field), field)

    for field in ("history_witness_pruned", "pre_replay_witness_pruned", "post_replay_witness_pruned"):
        _require_type(_require_key(report, field), bool, field)

    if report["host"].get("cpu_count") is not None and not isinstance(report["host"]["cpu_count"], int):
        raise AssertionError("unexpected host.cpu_count type")

    if report.get("git_commit") is not None:
        _require_type(report["git_commit"], str, "git_commit")
    if report.get("assumevalid_height") is not None:
        _require_non_negative_int(report["assumevalid_height"], "assumevalid_height")
    if report.get("assumevalid_hash") is not None:
        _require_type(report["assumevalid_hash"], str, "assumevalid_hash")
    if report.get("connectblock_trace_file") is not None:
        _require_type(report["connectblock_trace_file"], str, "connectblock_trace_file")

    _validate_replay_workload_metadata(report)


def validate_network_report_schema(report: dict[str, Any]) -> None:
    _require_type(_require_key(report, "report_version"), int, "report_version")
    if report["report_version"] != NETWORK_REPORT_VERSION:
        raise AssertionError(f"unexpected network report version: {report['report_version']}")
    if _require_key(report, "report_kind") != "network":
        raise AssertionError("unexpected network report kind")
    if _require_key(report, "report_only") is not True:
        raise AssertionError("network reports must stay report-only")

    for field in (
        "generated_at_utc",
        "chain",
        "lane_name",
        "workload_name",
        "workload",
        "history_script",
        "expected_tip_hash",
        "tmpdir",
        "builddir",
        "bitcoind_path",
        "bitcoin_cli_path",
    ):
        _require_type(_require_key(report, field), str, field)

    for field in (
        "workload_recipe",
        "host",
        "peer_at_headers_sync",
        "peer_at_tip_sync",
        "peer_at_ibd_exit",
    ):
        _require_type(_require_key(report, field), dict, field)

    for field in ("source_node_args", "ibd_node_args"):
        _require_type(_require_key(report, field), list, field)

    for field in (
        "warmup_blocks",
        "measured_blocks",
        "measured_start_height",
        "measured_end_height",
        "txs_per_block",
        "p2mr_spends_per_block",
        "seeded_p2mr_utxos",
        "measured_proxy_txs_total",
        "measured_p2mr_funding_txs_total",
        "measured_p2mr_spend_txs_total",
        "expected_tip_height",
        "network_headers_timeout",
        "network_tip_timeout",
        "network_ibd_exit_timeout",
        "headers_synced_height",
        "tip_synced_height",
        "source_blocks_bytes",
        "source_chainstate_bytes",
        "ibd_blocks_bytes",
        "ibd_chainstate_bytes",
        "observed_total_bytes_max",
    ):
        _require_non_negative_int(_require_key(report, field), field)

    _validate_disk_usage_sampling(_require_key(report, "disk_usage_sampling"), "disk_usage_sampling")
    _validate_connectblock_trace_summary(
        _require_key(report, "connectblock_trace_summary"), "connectblock_trace_summary"
    )
    _validate_utxo_flush_evidence(_require_key(report, "utxo_flush_evidence"), "utxo_flush_evidence")

    for field in (
        "connect_to_headers_sec",
        "connect_to_tip_sec",
        "connect_to_ibd_exit_sec",
        "headers_sync_sec",
        "tip_sync_sec",
        "ibd_exit_wait_sec",
        "blocks_per_sec",
    ):
        _require_number(_require_key(report, field), field)

    for field in ("initialblockdownload_before_connect", "initialblockdownload_after_sync"):
        _require_type(_require_key(report, field), bool, field)

    if report.get("git_commit") is not None:
        _require_type(report["git_commit"], str, "git_commit")
    if report.get("connectblock_trace_file") is not None:
        _require_type(report["connectblock_trace_file"], str, "connectblock_trace_file")

    _validate_replay_workload_metadata(report)


class DiskUsageSampler(AbstractContextManager):
    """Sample total bytes for selected paths during a measured sync window."""

    def __init__(
        self,
        *,
        paths: dict[str, Path],
        interval_sec: float = 0.25,
    ) -> None:
        self.paths = paths
        self.interval_sec = interval_sec
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._started_at: float | None = None
        self._sample_count = 0
        self._first_sample: dict[str, Any] | None = None
        self._last_sample: dict[str, Any] | None = None
        self._peak_sample: dict[str, Any] | None = None

    def __enter__(self):
        self._started_at = time.perf_counter()
        self._record_sample()
        self._thread = threading.Thread(target=self._sample_until_stopped, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, _exc_type, _exc, _exc_tb):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_sec * 4))
        self._record_sample()
        return False

    def _sample_until_stopped(self) -> None:
        while not self._stop_event.wait(self.interval_sec):
            self._record_sample()

    def _record_sample(self) -> None:
        assert self._started_at is not None
        paths_bytes = {label: directory_size(path) for label, path in self.paths.items()}
        sample = {
            "elapsed_sec": round(time.perf_counter() - self._started_at, 6),
            "total_bytes": sum(paths_bytes.values()),
            "paths_bytes": paths_bytes,
        }
        with self._lock:
            self._sample_count += 1
            if self._first_sample is None:
                self._first_sample = sample
            self._last_sample = sample
            if self._peak_sample is None or sample["total_bytes"] > self._peak_sample["total_bytes"]:
                self._peak_sample = sample

    def summary(self) -> dict[str, Any]:
        with self._lock:
            first = self._first_sample
            last = self._last_sample
            peak = self._peak_sample
            sample_count = self._sample_count

        return {
            "enabled": True,
            "interval_sec": self.interval_sec,
            "sample_count": sample_count,
            "monitored_paths": {label: str(path) for label, path in self.paths.items()},
            "start_total_bytes": first["total_bytes"] if first is not None else None,
            "end_total_bytes": last["total_bytes"] if last is not None else None,
            "peak_total_bytes": peak["total_bytes"] if peak is not None else None,
            "peak_elapsed_sec": peak["elapsed_sec"] if peak is not None else None,
            "peak_paths_bytes": peak["paths_bytes"] if peak is not None else {},
        }


_BENCH_LINE_RE = re.compile(
    r"BENCH\s+"
    r"(?P<blocks>\d+)\s+blk/s\s+"
    r"(?P<txs>\d+)\s+tx/s\s+"
    r"(?P<inputs>\d+)\s+inputs/s\s+"
    r"(?P<sigops>\d+)\s+sigops/s\s+"
    r"\(height\s+(?P<height>\d+)\)"
)
_HISTOGRAM_LINE_RE = re.compile(
    r"^\s*\[\s*(?P<low>[0-9.]+[KMGTP]?)\s*,\s*(?P<high>[0-9.]+[KMGTP]?)\)\s+"
    r"(?P<count>\d+)\s+\|"
)
_SLOW_BLOCK_LINE_RE = re.compile(r"^Block\s+\d+\s+\([0-9a-fA-F]{64}\).*?\btook\s+(?P<duration>\d+)\s+ms")


def _parse_histogram_number(value: str) -> int:
    multipliers = {
        "": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
    }
    suffix = value[-1].upper() if value[-1].isalpha() else ""
    number = value[:-1] if suffix else value
    return int(float(number) * multipliers[suffix])


def _histogram_percentile_ms(buckets: list[tuple[int, int, int]], percentile: float) -> float | None:
    sample_count = sum(count for _low, _high, count in buckets)
    if sample_count == 0:
        return None
    target = sample_count * percentile
    cumulative = 0
    for _low, high, count in sorted(buckets):
        cumulative += count
        if cumulative >= target:
            return float(high)
    return float(max(high for _low, high, _count in buckets))


def empty_connectblock_trace_summary(output_path: Path | None) -> dict[str, Any]:
    return {
        "path": str(output_path) if output_path is not None else None,
        "captured": False,
        "parseable": False,
        "sample_count": None,
        "median_ms": None,
        "p95_ms": None,
        "max_ms": None,
        "duration_summary_method": None,
        "bench_sample_count": 0,
        "bench_blocks_total": None,
        "bench_txs_total": None,
        "bench_inputs_total": None,
        "bench_sigops_total": None,
        "bench_max_height": None,
        "slow_block_sample_count": None,
        "slow_block_max_ms": None,
        "parse_error": None,
    }


def parse_connectblock_trace(output_path: Path | None) -> dict[str, Any]:
    summary = empty_connectblock_trace_summary(output_path)
    if output_path is None:
        return summary
    if not output_path.exists():
        summary["parse_error"] = "trace file not found"
        return summary

    summary["captured"] = True
    buckets: list[tuple[int, int, int]] = []
    slow_block_durations: list[int] = []
    bench_blocks = 0
    bench_txs = 0
    bench_inputs = 0
    bench_sigops = 0
    bench_max_height: int | None = None
    bench_sample_count = 0

    try:
        with output_path.open("r", encoding="utf-8", errors="replace") as trace_file:
            for line in trace_file:
                if match := _HISTOGRAM_LINE_RE.search(line):
                    count = int(match.group("count"))
                    if count > 0:
                        buckets.append(
                            (
                                _parse_histogram_number(match.group("low")),
                                _parse_histogram_number(match.group("high")),
                                count,
                            )
                        )
                    continue
                if match := _BENCH_LINE_RE.search(line):
                    bench_sample_count += 1
                    bench_blocks += int(match.group("blocks"))
                    bench_txs += int(match.group("txs"))
                    bench_inputs += int(match.group("inputs"))
                    bench_sigops += int(match.group("sigops"))
                    height = int(match.group("height"))
                    bench_max_height = height if bench_max_height is None else max(bench_max_height, height)
                    continue
                if match := _SLOW_BLOCK_LINE_RE.search(line):
                    slow_block_durations.append(int(match.group("duration")))
    except OSError as exc:
        summary["parse_error"] = str(exc)
        return summary

    sample_count = sum(count for _low, _high, count in buckets)
    if sample_count > 0:
        summary.update(
            {
                "parseable": True,
                "sample_count": sample_count,
                "median_ms": _histogram_percentile_ms(buckets, 0.50),
                "p95_ms": _histogram_percentile_ms(buckets, 0.95),
                "max_ms": float(max(high for _low, high, _count in buckets)),
                "duration_summary_method": "bpftrace_histogram_bucket_upper_bound_ms",
            }
        )
    else:
        summary["parse_error"] = "no duration histogram buckets found"

    summary.update(
        {
            "bench_sample_count": bench_sample_count,
            "bench_blocks_total": bench_blocks if bench_sample_count > 0 else None,
            "bench_txs_total": bench_txs if bench_sample_count > 0 else None,
            "bench_inputs_total": bench_inputs if bench_sample_count > 0 else None,
            "bench_sigops_total": bench_sigops if bench_sample_count > 0 else None,
            "bench_max_height": bench_max_height,
            "slow_block_sample_count": len(slow_block_durations),
            "slow_block_max_ms": max(slow_block_durations) if slow_block_durations else None,
        }
    )
    return summary


_UPDATE_TIP_CACHE_RE = re.compile(r"\bcache=(?P<mib>[0-9.]+)MiB\((?P<utxos>\d+)utxo\)")
_FLUSH_COINS_RE = re.compile(
    r"write coins cache to disk \((?P<coins>\d+) coins, (?P<kib>[0-9.]+)KiB\)"
)


def empty_utxo_flush_evidence(log_path: Path | None, start_offset: int | None) -> dict[str, Any]:
    return {
        "captured": False,
        "source": "debug.log",
        "log_path": str(log_path) if log_path is not None else None,
        "log_start_offset": start_offset,
        "log_end_offset": None,
        "utxo_cache_sample_count": None,
        "utxo_cache_peak_mib": None,
        "utxo_cache_peak_utxos": None,
        "flush_event_count": None,
        "flush_events": [],
        "privileged_trace_path": None,
        "privileged_trace_status": "not_captured",
        "parse_error": None,
    }


def collect_utxo_flush_evidence(log_path: Path | None, start_offset: int | None = None) -> dict[str, Any]:
    evidence = empty_utxo_flush_evidence(log_path, start_offset)
    if log_path is None:
        evidence["parse_error"] = "debug log path not available"
        return evidence
    if not log_path.exists():
        evidence["parse_error"] = "debug log not found"
        return evidence

    cache_sample_count = 0
    cache_peak_mib: float | None = None
    cache_peak_utxos: int | None = None
    flush_events: list[dict[str, Any]] = []

    try:
        with log_path.open("rb") as log_file:
            if start_offset is not None:
                log_file.seek(start_offset)
            for raw_line in log_file:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if match := _UPDATE_TIP_CACHE_RE.search(line):
                    cache_sample_count += 1
                    cache_mib = float(match.group("mib"))
                    cache_utxos = int(match.group("utxos"))
                    if cache_peak_mib is None or cache_mib > cache_peak_mib:
                        cache_peak_mib = cache_mib
                        cache_peak_utxos = cache_utxos
                    continue
                if match := _FLUSH_COINS_RE.search(line):
                    flush_events.append(
                        {
                            "coins": int(match.group("coins")),
                            "cache_kib": float(match.group("kib")),
                            "line": line,
                        }
                    )
            log_end_offset = log_file.tell()
    except OSError as exc:
        evidence["parse_error"] = str(exc)
        return evidence

    evidence.update(
        {
            "captured": True,
            "log_end_offset": log_end_offset,
            "utxo_cache_sample_count": cache_sample_count,
            "utxo_cache_peak_mib": cache_peak_mib,
            "utxo_cache_peak_utxos": cache_peak_utxos,
            "flush_event_count": len(flush_events),
            "flush_events": flush_events,
        }
    )
    return evidence


class ConnectBlockTrace(AbstractContextManager):
    """Optional bpftrace capture for ConnectBlock benchmark output."""

    def __init__(
        self,
        *,
        repo_root: Path,
        output_path: Path | None,
        threshold_ms: int,
    ) -> None:
        self.repo_root = repo_root
        self.output_path = output_path
        self.threshold_ms = threshold_ms
        self.process: subprocess.Popen | None = None
        self.handle = None

    def __enter__(self):
        if self.output_path is None:
            return self

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.output_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            [
                "sudo",
                "-n",
                "bpftrace",
                str(self.repo_root / "contrib/tracing/connectblock_benchmark.bt"),
                "0",
                "0",
                str(self.threshold_ms),
            ],
            cwd=self.repo_root,
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            text=True,
            env=dict(os.environ, LIBC_FATAL_STDERR_="1"),
        )
        time.sleep(1)
        if self.process.poll() is not None:
            if self.handle is not None:
                self.handle.close()
                self.handle = None
            raise AssertionError(
                f"connectblock trace exited early with status {self.process.returncode}; "
                f"see {self.output_path}"
            )
        return self

    def __exit__(self, _exc_type, exc, _exc_tb):
        try:
            if self.process is not None:
                self.process.send_signal(signal.SIGINT)
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=30)
                if self.process.returncode not in (0, -signal.SIGINT, 130):
                    message = (
                        f"connectblock trace exited with unexpected status {self.process.returncode}; "
                        f"see {self.output_path}"
                    )
                    if exc is not None:
                        logging.getLogger("TestFramework").warning(
                            "%s (preserving original exception)", message
                        )
                    else:
                        raise AssertionError(message)
        finally:
            if self.handle is not None:
                self.handle.close()
        return False

    def summary(self) -> dict[str, Any]:
        return parse_connectblock_trace(self.output_path)
