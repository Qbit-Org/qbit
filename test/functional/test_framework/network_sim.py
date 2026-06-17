#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shared helpers for qbit network simulation functional tests."""

from __future__ import annotations

from decimal import Decimal
import re
import unittest
from typing import Any

from test_framework.ibd_perf import (
    _require_key,
    _require_number,
    _require_type,
)


NETWORK_SIM_REPORT_VERSION = 1
NETWORK_SIM_REPORT_KIND = "network-sim"
TESTNODE_SUBVER_RE = re.compile(r"\(testnode([0-9]+)\)")

QBIT_NETWORK_ASSUMPTIONS: dict[str, Any] = {
    "target_spacing_seconds": 60,
    "max_block_weight": 2_000_000,
    "witness_scale_factor": 1,
    "coinbase_maturity": 1_000,
    "default_mempool_mb": 300,
    "mainnet_default_port": 8355,
    "roles_under_test": ["archive", "fastprune", "bridge", "edge"],
    "report_policy": (
        "CI enforces deterministic convergence and accounting invariants; "
        "propagation timing remains report-only until variance is understood."
    ),
}

STEADY_TOPOLOGY: dict[str, Any] = {
    "name": "line-4",
    "description": "Four qbit nodes connected as miner -> bridge -> fastprune -> edge.",
    "connections": [[0, 1], [1, 2], [2, 3]],
    "partition_bridge": [1, 2],
    "nodes": [
        {"index": 0, "role": "miner", "args": []},
        {"index": 1, "role": "bridge", "args": []},
        {"index": 2, "role": "fastprune", "args": ["-fastprune"]},
        {"index": 3, "role": "edge", "args": []},
    ],
}


def json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    return value


def peer_testnode_index(peer: dict[str, Any]) -> int | None:
    subver = peer.get("subver")
    if not isinstance(subver, str):
        return None
    match = TESTNODE_SUBVER_RE.search(subver)
    return int(match.group(1)) if match else None


def snapshot_peer(peer: dict[str, Any]) -> dict[str, Any]:
    return json_safe({
        "id": peer.get("id"),
        "addr": peer.get("addr"),
        "subver": peer.get("subver"),
        "testnode_index": peer_testnode_index(peer),
        "connection_type": peer.get("connection_type"),
        "permissions": peer.get("permissions"),
        "servicesnames": peer.get("servicesnames"),
        "relaytxes": peer.get("relaytxes"),
        "synced_headers": peer.get("synced_headers"),
        "synced_blocks": peer.get("synced_blocks"),
        "inflight": peer.get("inflight"),
        "bytesrecv": peer.get("bytesrecv"),
        "bytessent": peer.get("bytessent"),
        "bytessent_per_msg": peer.get("bytessent_per_msg"),
        "bytesrecv_per_msg": peer.get("bytesrecv_per_msg"),
    })


def snapshot_node(node, *, role: str) -> dict[str, Any]:
    chaininfo = node.getblockchaininfo()
    networkinfo = node.getnetworkinfo()
    peerinfo = node.getpeerinfo()
    mempoolinfo = node.getmempoolinfo()
    tips = node.getchaintips()
    orphan_metrics = node.getorphanmetrics()

    return json_safe({
        "index": node.index,
        "role": role,
        "bestblockhash": chaininfo["bestblockhash"],
        "blocks": chaininfo["blocks"],
        "headers": chaininfo["headers"],
        "initialblockdownload": chaininfo["initialblockdownload"],
        "verificationprogress": chaininfo.get("verificationprogress"),
        "localservices": networkinfo["localservices"],
        "localservicesnames": networkinfo["localservicesnames"],
        "connections": networkinfo["connections"],
        "connections_in": networkinfo["connections_in"],
        "connections_out": networkinfo["connections_out"],
        "localrelay": networkinfo["localrelay"],
        "peer_count": len(peerinfo),
        "peers": [snapshot_peer(peer) for peer in peerinfo],
        "mempool": {
            "size": mempoolinfo["size"],
            "bytes": mempoolinfo["bytes"],
            "usage": mempoolinfo["usage"],
            "maxmempool": mempoolinfo["maxmempool"],
            "mempoolminfee": mempoolinfo["mempoolminfee"],
            "minrelaytxfee": mempoolinfo["minrelaytxfee"],
        },
        "chain_tips": tips,
        "non_active_tip_count": sum(1 for tip in tips if tip["status"] != "active"),
        "orphan_metrics": orphan_metrics,
    })


def make_red_flag(
    *,
    lane_name: str,
    flag_class: str,
    severity: str,
    detail: str,
    node_index: int | None = None,
    expected: Any = None,
    observed: Any = None,
) -> dict[str, Any]:
    flag: dict[str, Any] = {
        "lane_name": lane_name,
        "class": flag_class,
        "severity": severity,
        "detail": detail,
    }
    if node_index is not None:
        flag["node_index"] = node_index
    if expected is not None:
        flag["expected"] = json_safe(expected)
    if observed is not None:
        flag["observed"] = json_safe(observed)
    return flag


def classify_convergence(
    *,
    lane_name: str,
    snapshots: list[dict[str, Any]],
    expected_tip_hash: str | None = None,
    expected_tip_height: int | None = None,
) -> list[dict[str, Any]]:
    red_flags = []
    observed_hashes = {snapshot["bestblockhash"] for snapshot in snapshots}
    observed_heights = {snapshot["blocks"] for snapshot in snapshots}

    if len(observed_hashes) != 1:
        red_flags.append(make_red_flag(
            lane_name=lane_name,
            flag_class="non_convergence",
            severity="ci-fail",
            detail="Nodes ended the lane on different best block hashes.",
            expected=expected_tip_hash,
            observed=sorted(observed_hashes),
        ))
    elif expected_tip_hash is not None and next(iter(observed_hashes)) != expected_tip_hash:
        red_flags.append(make_red_flag(
            lane_name=lane_name,
            flag_class="unexpected_tip_hash",
            severity="ci-fail",
            detail="Nodes converged to a different tip than the scenario expected.",
            expected=expected_tip_hash,
            observed=next(iter(observed_hashes)),
        ))

    if len(observed_heights) != 1:
        red_flags.append(make_red_flag(
            lane_name=lane_name,
            flag_class="height_divergence",
            severity="ci-fail",
            detail="Nodes ended the lane at different block heights.",
            expected=expected_tip_height,
            observed=sorted(observed_heights),
        ))
    elif expected_tip_height is not None and next(iter(observed_heights)) != expected_tip_height:
        red_flags.append(make_red_flag(
            lane_name=lane_name,
            flag_class="unexpected_tip_height",
            severity="ci-fail",
            detail="Nodes converged to a different height than the scenario expected.",
            expected=expected_tip_height,
            observed=next(iter(observed_heights)),
        ))

    for snapshot in snapshots:
        orphan_metrics = snapshot["orphan_metrics"]
        if orphan_metrics["persistent_stale_tip_count"] != snapshot["non_active_tip_count"]:
            red_flags.append(make_red_flag(
                lane_name=lane_name,
                flag_class="stale_tip_count_mismatch",
                severity="ci-fail",
                detail="getorphanmetrics persistent stale tip count diverges from getchaintips.",
                node_index=snapshot["index"],
                expected=snapshot["non_active_tip_count"],
                observed=orphan_metrics["persistent_stale_tip_count"],
            ))

    return red_flags


def has_ci_failures(red_flags: list[dict[str, Any]]) -> bool:
    return any(flag.get("severity") == "ci-fail" for flag in red_flags)


def validate_network_sim_report_schema(report: dict[str, Any]) -> None:
    _require_type(_require_key(report, "report_version"), int, "report_version")
    if report["report_version"] != NETWORK_SIM_REPORT_VERSION:
        raise AssertionError(f"unexpected network simulation report version: {report['report_version']}")
    if _require_key(report, "report_kind") != NETWORK_SIM_REPORT_KIND:
        raise AssertionError("unexpected network simulation report kind")

    for field in (
        "generated_at_utc",
        "chain",
        "workload_name",
        "tmpdir",
        "builddir",
        "bitcoind_path",
        "bitcoin_cli_path",
    ):
        _require_type(_require_key(report, field), str, field)

    for field in ("ci_smoke", "ci_enforced"):
        _require_type(_require_key(report, field), bool, field)

    for field in ("seed", "node_count", "total_red_flags", "ci_failure_count"):
        _require_type(_require_key(report, field), int, field)

    for field in ("qbit_assumptions", "topology", "host", "summary"):
        _require_type(_require_key(report, field), dict, field)

    for field in ("node_args", "lane_results", "red_flags"):
        _require_type(_require_key(report, field), list, field)

    if report.get("git_commit") is not None:
        _require_type(report["git_commit"], str, "git_commit")

    for index, lane_result in enumerate(report["lane_results"]):
        _require_type(lane_result, dict, f"lane_results[{index}]")
        for field in ("lane_name", "topology_name"):
            _require_type(_require_key(lane_result, field), str, f"lane_results[{index}].{field}")
        for field in ("events", "initial_node_snapshots", "final_node_snapshots", "red_flags"):
            _require_type(_require_key(lane_result, field), list, f"lane_results[{index}].{field}")
        _require_type(_require_key(lane_result, "summary"), dict, f"lane_results[{index}].summary")
        _require_number(_require_key(lane_result, "elapsed_sec"), f"lane_results[{index}].elapsed_sec")


class TestFrameworkNetworkSim(unittest.TestCase):
    def test_json_safe_decimal(self):
        self.assertEqual(json_safe({"fee": Decimal("0.00000250")}), {"fee": "0.00000250"})

    def test_peer_testnode_index(self):
        self.assertEqual(peer_testnode_index({"subver": "/qbit:0.1.0-testnet1(testnode12)/"}), 12)
        self.assertIsNone(peer_testnode_index({"subver": "/qbit:0.1.0-testnet1/"}))
        self.assertIsNone(peer_testnode_index({"subver": None}))

    def test_validate_network_sim_report_schema(self):
        report = {
            "report_version": NETWORK_SIM_REPORT_VERSION,
            "report_kind": NETWORK_SIM_REPORT_KIND,
            "generated_at_utc": "2026-04-22T00:00:00+00:00",
            "git_commit": None,
            "chain": "regtest",
            "ci_smoke": True,
            "ci_enforced": True,
            "seed": 389,
            "workload_name": "unit",
            "node_count": 4,
            "qbit_assumptions": QBIT_NETWORK_ASSUMPTIONS,
            "topology": STEADY_TOPOLOGY,
            "node_args": [[], [], [], []],
            "lane_results": [{
                "lane_name": "topology-steady",
                "topology_name": "line-4",
                "elapsed_sec": 0.1,
                "events": [],
                "initial_node_snapshots": [],
                "final_node_snapshots": [],
                "red_flags": [],
                "summary": {},
            }],
            "red_flags": [],
            "total_red_flags": 0,
            "ci_failure_count": 0,
            "summary": {},
            "tmpdir": "/tmp/qbit-network-sim",
            "builddir": "/tmp/qbit-build",
            "bitcoind_path": "/tmp/qbitd",
            "bitcoin_cli_path": "/tmp/qbit-cli",
            "host": {},
        }
        validate_network_sim_report_schema(report)

    def test_classify_convergence_stale_tip_mismatch(self):
        snapshots = [{
            "index": 0,
            "bestblockhash": "00",
            "blocks": 1,
            "non_active_tip_count": 1,
            "orphan_metrics": {"persistent_stale_tip_count": 0},
        }]
        red_flags = classify_convergence(lane_name="unit", snapshots=snapshots)
        self.assertEqual(len(red_flags), 1)
        self.assertEqual(red_flags[0]["class"], "stale_tip_count_mismatch")
