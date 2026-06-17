#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Summarize qbit IBD performance benchmark artifact bundles."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def to_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        return numeric if math.isfinite(numeric) else None
    if isinstance(value, str):
        try:
            numeric = float(value)
        except ValueError:
            return None
        return numeric if math.isfinite(numeric) else None
    return None


def to_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def clean_values(values: list[Any]) -> list[float]:
    cleaned = []
    for value in values:
        numeric = to_float(value)
        if numeric is not None:
            cleaned.append(numeric)
    return cleaned


def median(values: list[Any]) -> float | None:
    cleaned = clean_values(values)
    if not cleaned:
        return None
    return float(statistics.median(cleaned))


def percentile_95(values: list[Any]) -> float | None:
    cleaned = sorted(clean_values(values))
    if not cleaned:
        return None
    if len(cleaned) == 1:
        return cleaned[0]
    return cleaned[max(0, round(0.95 * (len(cleaned) - 1)))]


def maximum(values: list[Any]) -> float | None:
    cleaned = clean_values(values)
    if not cleaned:
        return None
    return max(cleaned)


def inverse_rate(value: float | None) -> float | None:
    if value is None or value <= 0:
        return None
    rate = 1.0 / value
    return rate if math.isfinite(rate) else None


def sum_ints(values: list[Any]) -> int | None:
    cleaned: list[int] = []
    for value in values:
        numeric = to_int(value)
        if numeric is not None:
            cleaned.append(numeric)
    if not cleaned:
        return None
    return sum(cleaned)


def format_float(value: float | None, digits: int = 6) -> str:
    if value is None:
        return "not captured"
    return f"{value:.{digits}f}"


def format_rate(value: float | None) -> str:
    if value is None:
        return "not captured"
    return f"{value:.3f}"


def format_bytes(value: float | int | None) -> str:
    if value is None:
        return "not captured"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{int(value)} B"


def format_ms(value: float | None) -> str:
    if value is None:
        return "not captured"
    return f"{value:.3f} ms"


def markdown_escape(value: Any) -> str:
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def parse_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def first_non_empty_line(path: Path) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            return line.strip()
    return None


def relative_to_root(path: str | Path, artifact_root: Path) -> str:
    candidate = Path(path)
    try:
        return str(candidate.relative_to(artifact_root))
    except ValueError:
        return str(path)


def load_bench_json_rows(bench_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(bench_dir.glob("*.json")):
        data = read_json(path)
        for result in data.get("results", []):
            if not isinstance(result, dict):
                continue
            name = result.get("name")
            if not isinstance(name, str) or not name:
                continue
            row = dict(result)
            row["name"] = name
            row["source_file"] = str(path)
            rows.append(row)
    return rows


def load_bench_csv_rows(bench_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(bench_dir.glob("*.csv")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            continue
        header = lines[0].lstrip("#").strip()
        reader = csv.DictReader([header, *lines[1:]], skipinitialspace=True)
        for result in reader:
            name = result.get("Benchmark")
            median_elapsed = result.get("median")
            if not name or median_elapsed is None:
                continue
            rows.append(
                {
                    "name": name,
                    "median(elapsed)": to_float(median_elapsed),
                    "source_file": str(path),
                }
            )
    return rows


def group_rows(rows: list[dict[str, Any]], key_fields: tuple[str, ...]) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key = tuple(row.get(field) for field in key_fields)
        grouped.setdefault(key, []).append(row)
    return grouped


def summarize_benchmarks(bench_dir: Path) -> list[dict[str, Any]]:
    json_rows = load_bench_json_rows(bench_dir)
    rows = json_rows if json_rows else load_bench_csv_rows(bench_dir)
    summaries: list[dict[str, Any]] = []
    for (name,), group in sorted(group_rows(rows, ("name",)).items()):
        elapsed = [row.get("median(elapsed)") for row in group]
        median_elapsed = median(elapsed)
        p95_elapsed = percentile_95(elapsed)
        summaries.append(
            {
                "benchmark": name,
                "runs": len(group),
                "median_elapsed_per_op_sec": median_elapsed,
                "p95_elapsed_per_op_sec": p95_elapsed,
                "approx_ops_per_sec": inverse_rate(median_elapsed),
                "source": "json" if json_rows else "csv",
            }
        )
    return summaries


def load_reports(report_dir: Path) -> list[dict[str, Any]]:
    reports = []
    for path in sorted(report_dir.glob("*.json")):
        report = read_json(path)
        if isinstance(report, dict):
            report["source_file"] = str(path)
            reports.append(report)
    return reports


def disk_peak_bytes(report: dict[str, Any]) -> int | None:
    sampling = report.get("disk_usage_sampling")
    if isinstance(sampling, dict):
        peak = to_int(sampling.get("peak_total_bytes"))
        if peak is not None:
            return peak
    return to_int(report.get("observed_total_bytes_max"))


def connectblock_rollup(reports: list[dict[str, Any]]) -> dict[str, Any]:
    summaries: list[dict[str, Any]] = []
    for report in reports:
        summary = report.get("connectblock_trace_summary")
        if isinstance(summary, dict):
            summaries.append(summary)
    parseable = [summary for summary in summaries if summary.get("parseable") is True]
    trace_paths = [
        summary.get("path")
        for summary in summaries
        if summary.get("path")
    ]
    return {
        "reports_with_summary": len(summaries),
        "parseable_reports": len(parseable),
        "sample_count_total": sum_ints([summary.get("sample_count") for summary in parseable]),
        "median_ms": median([summary.get("median_ms") for summary in parseable]),
        "p95_ms": percentile_95([summary.get("p95_ms") for summary in parseable]),
        "max_ms": maximum([summary.get("max_ms") for summary in parseable]),
        "trace_paths": sorted(set(trace_paths)),
    }


def utxo_flush_rollup(reports: list[dict[str, Any]]) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    for report in reports:
        item = report.get("utxo_flush_evidence")
        if isinstance(item, dict):
            evidence.append(item)
    captured = [item for item in evidence if item.get("captured") is True]
    return {
        "reports_with_evidence": len(evidence),
        "captured_reports": len(captured),
        "utxo_cache_peak_mib": maximum([item.get("utxo_cache_peak_mib") for item in captured]),
        "utxo_cache_peak_utxos": maximum([item.get("utxo_cache_peak_utxos") for item in captured]),
        "flush_event_count_total": sum_ints([item.get("flush_event_count") for item in captured]),
        "privileged_trace_statuses": sorted(
            set(
                item.get("privileged_trace_status")
                for item in evidence
                if item.get("privileged_trace_status")
            )
        ),
    }


def peer_inflight_count(peer: Any) -> int | None:
    if not isinstance(peer, dict):
        return None
    inflight = peer.get("inflight")
    if isinstance(inflight, list):
        return len(inflight)
    return None


def summarize_replay(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for key, group in sorted(group_rows(reports, ("workload", "history_mode", "reindex_mode")).items()):
        workload, history_mode, reindex_mode = key
        connectblock = connectblock_rollup(group)
        utxo_flush = utxo_flush_rollup(group)
        summaries.append(
            {
                "workload": workload,
                "history_mode": history_mode,
                "reindex_mode": reindex_mode,
                "runs": len(group),
                "measured_blocks": sorted(
                    set(value for value in (to_int(row.get("measured_blocks")) for row in group) if value is not None)
                ),
                "median_elapsed_sec": median([row.get("elapsed_sec") for row in group]),
                "p95_elapsed_sec": percentile_95([row.get("elapsed_sec") for row in group]),
                "median_blocks_per_sec": median([row.get("blocks_per_sec") for row in group]),
                "median_peak_disk_bytes": median([disk_peak_bytes(row) for row in group]),
                "max_peak_disk_bytes": maximum([disk_peak_bytes(row) for row in group]),
                "connectblock": connectblock,
                "utxo_flush": utxo_flush,
                "source_files": [row["source_file"] for row in group],
            }
        )
    return summaries


def summarize_network(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for key, group in sorted(group_rows(reports, ("lane_name", "workload")).items()):
        lane_name, workload = key
        connectblock = connectblock_rollup(group)
        utxo_flush = utxo_flush_rollup(group)
        inflight_counts = []
        for row in group:
            for field in ("peer_at_headers_sync", "peer_at_tip_sync", "peer_at_ibd_exit"):
                count = peer_inflight_count(row.get(field))
                if count is not None:
                    inflight_counts.append(count)
        summaries.append(
            {
                "lane_name": lane_name,
                "workload": workload,
                "runs": len(group),
                "measured_blocks": sorted(
                    set(value for value in (to_int(row.get("measured_blocks")) for row in group) if value is not None)
                ),
                "median_headers_sync_sec": median([row.get("connect_to_headers_sec") for row in group]),
                "median_tip_sync_sec": median([row.get("connect_to_tip_sec") for row in group]),
                "median_ibd_exit_sec": median([row.get("connect_to_ibd_exit_sec") for row in group]),
                "p95_ibd_exit_sec": percentile_95([row.get("connect_to_ibd_exit_sec") for row in group]),
                "median_blocks_per_sec": median([row.get("blocks_per_sec") for row in group]),
                "headers_synced_height_max": maximum([row.get("headers_synced_height") for row in group]),
                "tip_synced_height_max": maximum([row.get("tip_synced_height") for row in group]),
                "max_inflight_count": max(inflight_counts) if inflight_counts else None,
                "median_peak_disk_bytes": median([disk_peak_bytes(row) for row in group]),
                "max_peak_disk_bytes": maximum([disk_peak_bytes(row) for row in group]),
                "connectblock": connectblock,
                "utxo_flush": utxo_flush,
                "source_files": [row["source_file"] for row in group],
            }
        )
    return summaries


def summarize_artifact_counts(root: Path) -> dict[str, int]:
    return {
        "bench_json": len(list((root / "bench").glob("*.json"))),
        "bench_csv": len(list((root / "bench").glob("*.csv"))),
        "replay_json": len(list((root / "replay").glob("*.json"))),
        "network_json": len(list((root / "network").glob("*.json"))),
        "trace_files": len(list(root.rglob("*.trace.txt"))),
    }


def collect_trace_paths(root: Path, replay_reports: list[dict[str, Any]], network_reports: list[dict[str, Any]]) -> list[str]:
    paths = {relative_to_root(path, root) for path in root.rglob("*.trace.txt")}
    for report in [*replay_reports, *network_reports]:
        trace_path = report.get("connectblock_trace_file")
        if trace_path:
            paths.add(relative_to_root(trace_path, root))
        summary = report.get("connectblock_trace_summary")
        if isinstance(summary, dict) and summary.get("path"):
            paths.add(relative_to_root(summary["path"], root))
    return sorted(paths)


def collect_caveats(
    counts: dict[str, int],
    replay_reports: list[dict[str, Any]],
    network_reports: list[dict[str, Any]],
) -> list[str]:
    caveats = []
    reports = [*replay_reports, *network_reports]
    if counts["bench_json"] == 0:
        caveats.append("No bench JSON files found; hotspot table may be empty or CSV-derived.")
    if counts["bench_csv"] == 0:
        caveats.append("No bench CSV files found.")
    if counts["replay_json"] == 0:
        caveats.append("No replay JSON reports found.")
    if counts["network_json"] == 0:
        caveats.append("No network JSON reports found.")
    missing_disk = sum(1 for report in reports if "disk_usage_sampling" not in report)
    missing_trace_summary = sum(1 for report in reports if "connectblock_trace_summary" not in report)
    missing_utxo = sum(1 for report in reports if "utxo_flush_evidence" not in report)
    if missing_disk:
        caveats.append(f"{missing_disk} report(s) lack structured disk sampling fields.")
    if missing_trace_summary:
        caveats.append(f"{missing_trace_summary} report(s) lack structured ConnectBlock summary fields.")
    if missing_utxo:
        caveats.append(f"{missing_utxo} report(s) lack UTXO/flush evidence fields.")
    unparseable = 0
    for report in reports:
        summary = report.get("connectblock_trace_summary")
        if isinstance(summary, dict) and summary.get("captured") and not summary.get("parseable"):
            unparseable += 1
    if unparseable:
        caveats.append(f"{unparseable} captured ConnectBlock trace summary report(s) were not parseable.")
    return caveats


def build_bottleneck_ranking(
    benchmarks: list[dict[str, Any]],
    replay: list[dict[str, Any]],
    network: list[dict[str, Any]],
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    missing: list[str] = []

    replay_wall = [row for row in replay if row.get("median_elapsed_sec") is not None]
    if replay_wall:
        slowest = max(replay_wall, key=lambda row: row["median_elapsed_sec"])
        items.append(
            {
                "signal": "replay wall-clock",
                "evidence": (
                    f"{slowest['workload']} {slowest['history_mode']} {slowest['reindex_mode']} "
                    f"median elapsed {format_float(slowest['median_elapsed_sec'])} s"
                ),
                "basis": "median replay elapsed seconds",
            }
        )
    else:
        missing.append("Replay wall-clock timing is missing.")

    network_wall = [row for row in network if row.get("median_ibd_exit_sec") is not None]
    if network_wall:
        slowest = max(network_wall, key=lambda row: row["median_ibd_exit_sec"])
        items.append(
            {
                "signal": "network IBD wall-clock",
                "evidence": (
                    f"{slowest['lane_name']} {slowest['workload']} median IBD exit "
                    f"{format_float(slowest['median_ibd_exit_sec'])} s"
                ),
                "basis": "median connect-to-IBD-exit seconds",
            }
        )
    else:
        missing.append("Network IBD timing is missing.")

    connectblock_rows = [
        (row, row["connectblock"].get("p95_ms"))
        for row in [*replay, *network]
        if row.get("connectblock", {}).get("p95_ms") is not None
    ]
    if connectblock_rows:
        row, p95_ms = max(connectblock_rows, key=lambda item: item[1])
        label = row.get("lane_name") or " ".join(
            str(row.get(field)) for field in ("workload", "history_mode", "reindex_mode")
        )
        items.append(
            {
                "signal": "ConnectBlock distribution",
                "evidence": f"{label} p95 {format_ms(p95_ms)}",
                "basis": "parsed ConnectBlock trace p95 bucket upper bound",
            }
        )
    else:
        missing.append("Parseable ConnectBlock trace timing is missing.")

    benchmark_rows = [row for row in benchmarks if row.get("median_elapsed_per_op_sec") is not None]
    if benchmark_rows:
        slowest = max(benchmark_rows, key=lambda row: row["median_elapsed_per_op_sec"])
        items.append(
            {
                "signal": "hotspot microbenchmark",
                "evidence": (
                    f"{slowest['benchmark']} median/op "
                    f"{format_float(slowest['median_elapsed_per_op_sec'], digits=9)} s"
                ),
                "basis": "slowest median elapsed/op among hotspot benches",
            }
        )
    else:
        missing.append("Hotspot microbenchmark timing is missing.")

    utxo_rows = [
        (row, row["utxo_flush"])
        for row in [*replay, *network]
        if row.get("utxo_flush", {}).get("captured_reports", 0) > 0
    ]
    if utxo_rows:
        row, evidence = max(
            utxo_rows,
            key=lambda item: (
                item[1].get("flush_event_count_total") or 0,
                item[1].get("utxo_cache_peak_mib") or 0,
            ),
        )
        label = row.get("lane_name") or " ".join(
            str(row.get(field)) for field in ("workload", "history_mode", "reindex_mode")
        )
        items.append(
            {
                "signal": "UTXO/flush evidence",
                "evidence": (
                    f"{label} flush events {evidence.get('flush_event_count_total')}, "
                    f"peak cache {format_float(evidence.get('utxo_cache_peak_mib'))} MiB"
                ),
                "basis": "debug-log cache and flush metadata",
            }
        )
    else:
        missing.append("UTXO/flush evidence is missing.")

    disk_rows = [row for row in [*replay, *network] if row.get("max_peak_disk_bytes") is not None]
    if disk_rows:
        largest = max(disk_rows, key=lambda row: row["max_peak_disk_bytes"])
        label = largest.get("lane_name") or " ".join(
            str(largest.get(field)) for field in ("workload", "history_mode", "reindex_mode")
        )
        items.append(
            {
                "signal": "peak disk footprint",
                "evidence": f"{label} max peak disk {format_bytes(largest['max_peak_disk_bytes'])}",
                "basis": "disk usage sampling peak bytes",
            }
        )
    else:
        missing.append("Peak disk sampling evidence is missing.")

    for rank, item in enumerate(items, start=1):
        item["rank"] = rank
    return {
        "items": items,
        "missing_evidence": missing,
        "caveat": "Ranking is evidence triage, not causal proof; heterogeneous units are not normalized.",
    }


def metadata(root: Path, host_env: dict[str, str]) -> dict[str, Any]:
    host_txt = root / "summary" / "host.txt"
    inferred_run_id = None
    name = root.name
    if name.startswith("ibd-perf-"):
        inferred_run_id = name.removeprefix("ibd-perf-")
    return {
        "artifact_root": str(root),
        "git_commit": host_env.get("git_commit"),
        "timestamp_utc": host_env.get("timestamp_utc"),
        "github_repository": host_env.get("github_repository"),
        "github_workflow": host_env.get("github_workflow"),
        "github_run_id": host_env.get("github_run_id") or inferred_run_id,
        "github_run_number": host_env.get("github_run_number"),
        "github_run_attempt": host_env.get("github_run_attempt"),
        "github_ref": host_env.get("github_ref"),
        "github_ref_name": host_env.get("github_ref_name"),
        "runner_name": host_env.get("runner_name"),
        "runner_arch": host_env.get("runner_arch"),
        "kernel": host_env.get("kernel"),
        "host_summary": first_non_empty_line(host_txt),
        "host_env": host_env,
        "host_txt": str(host_txt) if host_txt.exists() else None,
    }


def measured_blocks_label(values: list[int]) -> str:
    if not values:
        return "not captured"
    if len(values) == 1:
        return str(values[0])
    return ",".join(str(value) for value in values)


def render_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    meta = summary["metadata"]
    lines.extend(
        [
            "# IBD baseline summary",
            "",
            "## Campaign metadata",
            "",
            f"- Artifact root: `{markdown_escape(meta['artifact_root'])}`",
            f"- Git commit: `{markdown_escape(meta.get('git_commit') or 'not captured')}`",
            f"- Timestamp UTC: `{markdown_escape(meta.get('timestamp_utc') or 'not captured')}`",
            f"- GitHub run: `{markdown_escape(meta.get('github_run_id') or 'not captured')}`",
            f"- GitHub ref: `{markdown_escape(meta.get('github_ref') or 'not captured')}`",
            f"- Runner: `{markdown_escape(meta.get('runner_name') or 'not captured')}` "
            f"({markdown_escape(meta.get('runner_arch') or 'arch not captured')})",
            f"- Kernel: `{markdown_escape(meta.get('kernel') or 'not captured')}`",
            f"- Host summary: `{markdown_escape(meta.get('host_summary') or 'not captured')}`",
            "",
            "## Hotspot microbenchmarks",
            "",
        ]
    )

    if summary["hotspot_microbenchmarks"]:
        lines.extend(
            [
                "| benchmark | runs | median elapsed/op (s) | p95 elapsed/op (s) | approx ops/s |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for row in summary["hotspot_microbenchmarks"]:
            lines.append(
                f"| {markdown_escape(row['benchmark'])} | {row['runs']} | "
                f"{format_float(row['median_elapsed_per_op_sec'], digits=9)} | "
                f"{format_float(row['p95_elapsed_per_op_sec'], digits=9)} | "
                f"{format_rate(row['approx_ops_per_sec'])} |"
            )
    else:
        lines.append("No hotspot microbenchmark results were captured.")

    lines.extend(["", "## Replay summary", ""])
    if summary["replay"]:
        lines.extend(
            [
                "| workload | history | reindex | runs | measured blocks | median elapsed | "
                "p95 elapsed | median blocks/s | peak disk | ConnectBlock p95 | UTXO/flush |",
                "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
            ]
        )
        for row in summary["replay"]:
            utxo = row["utxo_flush"]
            flush_label = (
                f"{utxo.get('flush_event_count_total')} flush, "
                f"{format_float(utxo.get('utxo_cache_peak_mib'))} MiB cache"
                if utxo.get("captured_reports")
                else "not captured"
            )
            lines.append(
                f"| {markdown_escape(row['workload'])} | {markdown_escape(row['history_mode'])} | "
                f"{markdown_escape(row['reindex_mode'])} | {row['runs']} | "
                f"{measured_blocks_label(row['measured_blocks'])} | "
                f"{format_float(row['median_elapsed_sec'])} | {format_float(row['p95_elapsed_sec'])} | "
                f"{format_float(row['median_blocks_per_sec'])} | "
                f"{format_bytes(row['max_peak_disk_bytes'])} | "
                f"{format_ms(row['connectblock'].get('p95_ms'))} | {flush_label} |"
            )
    else:
        lines.append("No replay reports were captured.")

    lines.extend(["", "## Network IBD summary", ""])
    if summary["network"]:
        lines.extend(
            [
                "| lane | workload | runs | measured blocks | headers sync | tip sync | IBD exit | "
                "median blocks/s | peak disk | max inflight | ConnectBlock p95 | UTXO/flush |",
                "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
            ]
        )
        for row in summary["network"]:
            utxo = row["utxo_flush"]
            flush_label = (
                f"{utxo.get('flush_event_count_total')} flush, "
                f"{format_float(utxo.get('utxo_cache_peak_mib'))} MiB cache"
                if utxo.get("captured_reports")
                else "not captured"
            )
            lines.append(
                f"| {markdown_escape(row['lane_name'])} | {markdown_escape(row['workload'])} | "
                f"{row['runs']} | {measured_blocks_label(row['measured_blocks'])} | "
                f"{format_float(row['median_headers_sync_sec'])} | "
                f"{format_float(row['median_tip_sync_sec'])} | "
                f"{format_float(row['median_ibd_exit_sec'])} | "
                f"{format_float(row['median_blocks_per_sec'])} | "
                f"{format_bytes(row['max_peak_disk_bytes'])} | "
                f"{row['max_inflight_count'] if row['max_inflight_count'] is not None else 'not captured'} | "
                f"{format_ms(row['connectblock'].get('p95_ms'))} | {flush_label} |"
            )
    else:
        lines.append("No network IBD reports were captured.")

    ranking = summary["bottleneck_ranking"]
    lines.extend(
        [
            "",
            "## Bottleneck ranking",
            "",
            ranking["caveat"],
            "",
        ]
    )
    if ranking["items"]:
        lines.extend(["| rank | signal | evidence | basis |", "|---:|---|---|---|"])
        for item in ranking["items"]:
            lines.append(
                f"| {item['rank']} | {markdown_escape(item['signal'])} | "
                f"{markdown_escape(item['evidence'])} | {markdown_escape(item['basis'])} |"
            )
    else:
        lines.append("No bottleneck evidence was captured.")
    if ranking["missing_evidence"]:
        lines.extend(["", "Missing evidence:"])
        for missing in ranking["missing_evidence"]:
            lines.append(f"- {missing}")

    lines.extend(["", "## Trace and artifact references", ""])
    counts = summary["artifact_counts"]
    lines.extend(
        [
            f"- Bench JSON files: {counts['bench_json']}",
            f"- Bench CSV files: {counts['bench_csv']}",
            f"- Replay JSON reports: {counts['replay_json']}",
            f"- Network JSON reports: {counts['network_json']}",
            f"- Trace files: {counts['trace_files']}",
        ]
    )
    if summary["trace_files"]:
        lines.extend(["", "Trace files:"])
        for path in summary["trace_files"]:
            lines.append(f"- `{markdown_escape(path)}`")
    if summary["caveats"]:
        lines.extend(["", "Caveats:"])
        for caveat in summary["caveats"]:
            lines.append(f"- {caveat}")
    return "\n".join(lines) + "\n"


def build_summary(root: Path) -> dict[str, Any]:
    root = root.resolve()
    host_env = parse_env(root / "summary" / "host.env")
    replay_reports = load_reports(root / "replay")
    network_reports = load_reports(root / "network")
    counts = summarize_artifact_counts(root)
    benchmarks = summarize_benchmarks(root / "bench")
    replay = summarize_replay(replay_reports)
    network = summarize_network(network_reports)
    return {
        "metadata": metadata(root, host_env),
        "artifact_counts": counts,
        "hotspot_microbenchmarks": benchmarks,
        "replay": replay,
        "network": network,
        "bottleneck_ranking": build_bottleneck_ranking(benchmarks, replay, network),
        "trace_files": collect_trace_paths(root, replay_reports, network_reports),
        "caveats": collect_caveats(counts, replay_reports, network_reports),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path, help="IBD perf artifact root directory")
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=None,
        help="Markdown output path (default: <artifact-root>/summary/ibd-baseline-summary.md)",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=None,
        help="JSON output path (default: <artifact-root>/summary/ibd-baseline-summary.json)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.artifact_root.resolve()
    if not root.is_dir():
        raise SystemExit(f"artifact root does not exist or is not a directory: {root}")

    summary_dir = root / "summary"
    summary_dir.mkdir(parents=True, exist_ok=True)
    markdown_output = args.markdown_output or summary_dir / "ibd-baseline-summary.md"
    json_output = args.json_output or summary_dir / "ibd-baseline-summary.json"

    summary = build_summary(root)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text(render_markdown(summary), encoding="utf-8")
    json_output.write_text(json.dumps(summary, allow_nan=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {markdown_output}")
    print(f"Wrote {json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
