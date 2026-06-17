#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pre-launch qbit network simulation harness.

This is a deterministic, correctness-oriented simulation around real qbit
regtest nodes. It emits structured reports and fails only on invariants that
should be stable in CI.
"""

from __future__ import annotations

from datetime import datetime, timezone
import copy
import json
import os
from pathlib import Path
import platform
import time

from test_framework.ibd_perf import (
    git_head,
    slugify,
)
from test_framework.network_sim import (
    NETWORK_SIM_REPORT_KIND,
    NETWORK_SIM_REPORT_VERSION,
    QBIT_NETWORK_ASSUMPTIONS,
    STEADY_TOPOLOGY,
    classify_convergence,
    has_ci_failures,
    json_safe,
    make_red_flag,
    peer_testnode_index,
    snapshot_node,
    validate_network_sim_report_schema,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet


LANE_ALL = "all"
LANE_TOPOLOGY_STEADY = "topology-steady"
LANE_PARTITION_REJOIN = "partition-rejoin"
SUPPORTED_LANES = (LANE_ALL, LANE_TOPOLOGY_STEADY, LANE_PARTITION_REJOIN)
PARTITION_LEFT_NODES = [0, 1]
PARTITION_RIGHT_NODES = [2, 3]


class NetworkSimulationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.rpc_timeout = 600
        base_args = ["-dnsseed=0", "-fixedseeds=0", "-persistmempool=0"]
        self.extra_args = [
            base_args + list(node_spec["args"])
            for node_spec in STEADY_TOPOLOGY["nodes"]
        ]

    def setup_network(self):
        self.setup_nodes()
        for node_a, node_b in STEADY_TOPOLOGY["connections"]:
            self.connect_nodes(node_a, node_b)
        self.sync_all()

    def add_options(self, parser):
        parser.add_argument(
            "--ci-smoke",
            dest="ci_smoke",
            default=False,
            action="store_true",
            help="Run the bounded PR-CI smoke profile.",
        )
        parser.add_argument(
            "--lane",
            dest="lane",
            choices=SUPPORTED_LANES,
            default=LANE_ALL,
            help="Network simulation lane to run (default: all).",
        )
        parser.add_argument(
            "--seed",
            dest="sim_seed",
            type=int,
            default=389,
            help="Deterministic simulation seed recorded in the report.",
        )
        parser.add_argument(
            "--rounds",
            dest="rounds",
            type=int,
            default=None,
            help="Steady-topology block rounds (default: 2 in CI smoke, otherwise 5).",
        )
        parser.add_argument(
            "--partition-left-blocks",
            dest="partition_left_blocks",
            type=int,
            default=1,
            help="Blocks mined by the losing partition before rejoin (default: 1).",
        )
        parser.add_argument(
            "--partition-right-blocks",
            dest="partition_right_blocks",
            type=int,
            default=2,
            help="Blocks mined by the winning partition before rejoin (default: 2).",
        )
        parser.add_argument(
            "--txs-per-round",
            dest="txs_per_round",
            type=int,
            default=0,
            help="Optional MiniWallet transactions relayed before each steady block (default: 0).",
        )
        parser.add_argument(
            "--workload-name",
            dest="workload_name",
            default=None,
            help="Optional workload label to store in the report.",
        )
        parser.add_argument(
            "--report-file",
            dest="report_file",
            default=None,
            help=(
                "Where to write the JSON report "
                "(default: <repo>/build/reports/feature-network-sim-<workload>.json)"
            ),
        )

    def role_for_node(self, node_index: int) -> str:
        for node_spec in STEADY_TOPOLOGY["nodes"]:
            if node_spec["index"] == node_index:
                return node_spec["role"]
        raise AssertionError(f"missing network simulation role for node {node_index}")

    def effective_rounds(self) -> int:
        if self.options.rounds is not None:
            return self.options.rounds
        return 2 if self.options.ci_smoke else 5

    def effective_lanes(self) -> list[str]:
        if self.options.lane == LANE_ALL:
            return [LANE_TOPOLOGY_STEADY, LANE_PARTITION_REJOIN]
        return [self.options.lane]

    def workload_name(self) -> str:
        if self.options.workload_name:
            return self.options.workload_name
        profile = "ci-smoke" if self.options.ci_smoke else "manual"
        lanes = "all" if self.options.lane == LANE_ALL else self.options.lane
        return f"{lanes}-{profile}-seed{self.options.sim_seed}"

    def default_report_path(self) -> Path:
        repo_root = Path(self.config["environment"]["SRCDIR"])
        report_dir = repo_root / "build" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / f"feature-network-sim-{slugify(self.workload_name())}.json"

    def write_report(self, report: dict) -> Path:
        report_path = self.default_report_path() if self.options.report_file is None else Path(self.options.report_file).expanduser()
        report_path.parent.mkdir(parents=True, exist_ok=True)

        safe_report = json_safe(report)
        validate_network_sim_report_schema(safe_report)
        report_path.write_text(json.dumps(safe_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.log.info(f"Wrote network simulation report to {report_path}")
        return report_path

    def validate_options(self):
        if self.options.sim_seed < 0:
            raise AssertionError("--seed must be non-negative")
        if self.effective_rounds() < 1:
            raise AssertionError("--rounds must be at least 1")
        if self.options.partition_left_blocks < 1:
            raise AssertionError("--partition-left-blocks must be at least 1")
        if self.options.partition_right_blocks <= self.options.partition_left_blocks:
            raise AssertionError("--partition-right-blocks must be greater than --partition-left-blocks")
        if self.options.txs_per_round < 0:
            raise AssertionError("--txs-per-round must be non-negative")

    def lane_event(self, *, lane_name: str, event_type: str, lane_start: float, **details) -> dict:
        return json_safe({
            "lane_name": lane_name,
            "event": event_type,
            "time_offset_sec": round(time.perf_counter() - lane_start, 6),
            **details,
        })

    def node_snapshots(self) -> list[dict]:
        return [
            snapshot_node(node, role=self.role_for_node(node.index))
            for node in self.nodes
        ]

    def expected_peer_indices(self) -> dict[int, set[int]]:
        expected: dict[int, set[int]] = {node_spec["index"]: set() for node_spec in STEADY_TOPOLOGY["nodes"]}
        for node_a, node_b in STEADY_TOPOLOGY["connections"]:
            expected[node_a].add(node_b)
            expected[node_b].add(node_a)
        return expected

    def classify_peer_connectivity(self, *, lane_name: str, snapshots: list[dict]) -> list[dict]:
        red_flags = []
        expected_indices = self.expected_peer_indices()
        for snapshot in snapshots:
            expected = expected_indices[snapshot["index"]]
            observed = {
                peer["testnode_index"]
                for peer in snapshot["peers"]
                if peer.get("testnode_index") is not None
            }
            missing = sorted(expected - observed)
            if missing:
                red_flags.append(make_red_flag(
                    lane_name=lane_name,
                    flag_class="missing_required_peer",
                    severity="ci-fail",
                    detail="A node ended the lane without one or more required topology peers.",
                    node_index=snapshot["index"],
                    expected=sorted(expected),
                    observed=sorted(observed),
                ))
        return red_flags

    def cross_partition_edges(self, *, left_nodes: list[int], right_nodes: list[int]) -> list[list[int]]:
        left_set = set(left_nodes)
        right_set = set(right_nodes)
        edges = set()
        for node_index in sorted(left_set | right_set):
            cross_side = right_set if node_index in left_set else left_set
            for peer in self.nodes[node_index].getpeerinfo():
                peer_index = peer_testnode_index(peer)
                if peer_index in cross_side:
                    edges.add(tuple(sorted((node_index, peer_index))))
        return [list(edge) for edge in sorted(edges)]

    def disconnect_cross_partition_edges(self, *, left_nodes: list[int], right_nodes: list[int]) -> list[list[int]]:
        disconnected_edges = self.cross_partition_edges(left_nodes=left_nodes, right_nodes=right_nodes)
        for node_a, node_b in disconnected_edges:
            self.disconnect_nodes(node_a, node_b)

        self.wait_until(
            lambda: not self.cross_partition_edges(left_nodes=left_nodes, right_nodes=right_nodes),
            timeout=5,
        )
        return disconnected_edges

    def prepare_tx_wallet(self) -> MiniWallet | None:
        if self.options.txs_per_round == 0:
            return None
        self.log.info("Mature cached coinbases for optional transaction relay workload")
        self.ensure_cached_coinbase_mature(self.nodes[0])
        self.sync_all()
        return MiniWallet(self.nodes[0])

    def run_topology_steady(self) -> dict:
        lane_name = LANE_TOPOLOGY_STEADY
        self.log.info("Run network simulation lane: topology-steady")
        lane_start = time.perf_counter()
        events = []
        wallet = self.prepare_tx_wallet()
        initial_snapshots = self.node_snapshots()
        start_height = self.nodes[0].getblockcount()
        submitted_txids = []

        for round_index in range(self.effective_rounds()):
            round_txids = []
            if wallet is not None:
                for _ in range(self.options.txs_per_round):
                    tx = wallet.send_self_transfer(from_node=self.nodes[0])
                    round_txids.append(tx["txid"])
                    submitted_txids.append(tx["txid"])
                self.sync_mempools(wait=0.1)

            block_hash = self.generate(self.nodes[0], 1)[0]
            events.append(self.lane_event(
                lane_name=lane_name,
                event_type="mine_round",
                lane_start=lane_start,
                round=round_index + 1,
                miner=0,
                block_hash=block_hash,
                block_height=self.nodes[0].getblockcount(),
                txids=round_txids,
            ))

        final_tip_hash = self.nodes[0].getbestblockhash()
        final_tip_height = self.nodes[0].getblockcount()
        final_snapshots = self.node_snapshots()

        red_flags = classify_convergence(
            lane_name=lane_name,
            snapshots=final_snapshots,
            expected_tip_hash=final_tip_hash,
            expected_tip_height=start_height + self.effective_rounds(),
        )
        red_flags.extend(self.classify_peer_connectivity(lane_name=lane_name, snapshots=final_snapshots))

        if submitted_txids:
            for snapshot in final_snapshots:
                if snapshot["mempool"]["size"] != 0:
                    red_flags.append(make_red_flag(
                        lane_name=lane_name,
                        flag_class="post_block_mempool_not_empty",
                        severity="ci-fail",
                        detail="Transactions submitted during steady relay remained in a mempool after mining.",
                        node_index=snapshot["index"],
                        expected=0,
                        observed=snapshot["mempool"]["size"],
                    ))

        return {
            "lane_name": lane_name,
            "topology_name": STEADY_TOPOLOGY["name"],
            "elapsed_sec": round(time.perf_counter() - lane_start, 6),
            "events": events,
            "initial_node_snapshots": initial_snapshots,
            "final_node_snapshots": final_snapshots,
            "red_flags": red_flags,
            "summary": {
                "start_height": start_height,
                "final_tip_height": final_tip_height,
                "final_tip_hash": final_tip_hash,
                "rounds": self.effective_rounds(),
                "submitted_txids": submitted_txids,
            },
        }

    def run_partition_rejoin(self) -> dict:
        lane_name = LANE_PARTITION_REJOIN
        self.log.info("Run network simulation lane: partition-rejoin")
        lane_start = time.perf_counter()
        events = []
        initial_snapshots = self.node_snapshots()
        pre_split_height = self.nodes[0].getblockcount()
        left_nodes = PARTITION_LEFT_NODES
        right_nodes = PARTITION_RIGHT_NODES
        losing_nodes = left_nodes

        disconnected_edges = self.disconnect_cross_partition_edges(left_nodes=left_nodes, right_nodes=right_nodes)
        self.sync_blocks([self.nodes[index] for index in left_nodes])
        self.sync_blocks([self.nodes[index] for index in right_nodes])
        events.append(self.lane_event(
            lane_name=lane_name,
            event_type="split",
            lane_start=lane_start,
            bridge=STEADY_TOPOLOGY["partition_bridge"],
            disconnected_edges=disconnected_edges,
            left_nodes=left_nodes,
            right_nodes=right_nodes,
            split_height=pre_split_height,
        ))

        pre_reorg_metrics = {
            index: self.nodes[index].getorphanmetrics()
            for index in losing_nodes
        }

        left_hashes = self.generate(
            self.nodes[0],
            self.options.partition_left_blocks,
            sync_fun=lambda: self.sync_blocks([self.nodes[index] for index in left_nodes]),
        )
        events.append(self.lane_event(
            lane_name=lane_name,
            event_type="mine_partition",
            lane_start=lane_start,
            side="left",
            miner=0,
            blocks=left_hashes,
            final_height=self.nodes[0].getblockcount(),
        ))

        right_hashes = self.generate(
            self.nodes[2],
            self.options.partition_right_blocks,
            sync_fun=lambda: self.sync_blocks([self.nodes[index] for index in right_nodes]),
        )
        winning_tip_hash = right_hashes[-1]
        winning_tip_height = self.nodes[2].getblockcount()
        events.append(self.lane_event(
            lane_name=lane_name,
            event_type="mine_partition",
            lane_start=lane_start,
            side="right",
            miner=2,
            blocks=right_hashes,
            final_height=winning_tip_height,
        ))

        pre_rejoin_snapshots = self.node_snapshots()
        self.connect_nodes(*STEADY_TOPOLOGY["partition_bridge"])
        self.sync_all()
        events.append(self.lane_event(
            lane_name=lane_name,
            event_type="rejoin",
            lane_start=lane_start,
            bridge=STEADY_TOPOLOGY["partition_bridge"],
            expected_winning_tip_hash=winning_tip_hash,
            expected_winning_tip_height=winning_tip_height,
        ))

        final_snapshots = self.node_snapshots()
        red_flags = classify_convergence(
            lane_name=lane_name,
            snapshots=final_snapshots,
            expected_tip_hash=winning_tip_hash,
            expected_tip_height=winning_tip_height,
        )
        red_flags.extend(self.classify_peer_connectivity(lane_name=lane_name, snapshots=final_snapshots))

        final_by_index = {snapshot["index"]: snapshot for snapshot in final_snapshots}
        for index in losing_nodes:
            metrics = final_by_index[index]["orphan_metrics"]
            stale_delta = metrics["lifetime_stale_blocks"] - pre_reorg_metrics[index]["lifetime_stale_blocks"]
            reorg_delta = metrics["lifetime_reorgs"] - pre_reorg_metrics[index]["lifetime_reorgs"]
            if stale_delta < self.options.partition_left_blocks:
                red_flags.append(make_red_flag(
                    lane_name=lane_name,
                    flag_class="stale_accounting_underreported",
                    severity="ci-fail",
                    detail="Losing partition did not account for all stale blocks after rejoin.",
                    node_index=index,
                    expected={">=": self.options.partition_left_blocks},
                    observed=stale_delta,
                ))
            if reorg_delta < 1:
                red_flags.append(make_red_flag(
                    lane_name=lane_name,
                    flag_class="reorg_accounting_missing",
                    severity="ci-fail",
                    detail="Losing partition did not report a reorg after adopting the winning chain.",
                    node_index=index,
                    expected={">=": 1},
                    observed=reorg_delta,
                ))
            if metrics["deepest_reorg"] < self.options.partition_left_blocks:
                red_flags.append(make_red_flag(
                    lane_name=lane_name,
                    flag_class="deepest_reorg_underreported",
                    severity="ci-fail",
                    detail="Losing partition deepest_reorg is shallower than the stale branch depth.",
                    node_index=index,
                    expected={">=": self.options.partition_left_blocks},
                    observed=metrics["deepest_reorg"],
                ))

        return {
            "lane_name": lane_name,
            "topology_name": STEADY_TOPOLOGY["name"],
            "elapsed_sec": round(time.perf_counter() - lane_start, 6),
            "events": events,
            "initial_node_snapshots": initial_snapshots,
            "pre_rejoin_node_snapshots": pre_rejoin_snapshots,
            "final_node_snapshots": final_snapshots,
            "red_flags": red_flags,
            "summary": {
                "pre_split_height": pre_split_height,
                "losing_partition_blocks": self.options.partition_left_blocks,
                "winning_partition_blocks": self.options.partition_right_blocks,
                "winning_tip_hash": winning_tip_hash,
                "winning_tip_height": winning_tip_height,
                "losing_nodes": losing_nodes,
            },
        }

    def run_lane(self, lane_name: str) -> dict:
        if lane_name == LANE_TOPOLOGY_STEADY:
            return self.run_topology_steady()
        if lane_name == LANE_PARTITION_REJOIN:
            return self.run_partition_rejoin()
        raise AssertionError(f"unsupported network simulation lane: {lane_name}")

    def run_test(self):
        self.validate_options()
        repo_root = Path(self.config["environment"]["SRCDIR"])

        lane_results = []
        red_flags = []
        for lane_name in self.effective_lanes():
            lane_result = self.run_lane(lane_name)
            lane_results.append(lane_result)
            red_flags.extend(lane_result["red_flags"])

        ci_failure_count = sum(1 for flag in red_flags if flag["severity"] == "ci-fail")
        report = {
            "report_version": NETWORK_SIM_REPORT_VERSION,
            "report_kind": NETWORK_SIM_REPORT_KIND,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": git_head(repo_root),
            "chain": self.chain,
            "ci_smoke": self.options.ci_smoke,
            "ci_enforced": True,
            "seed": self.options.sim_seed,
            "workload_name": self.workload_name(),
            "node_count": self.num_nodes,
            "qbit_assumptions": copy.deepcopy(QBIT_NETWORK_ASSUMPTIONS),
            "topology": copy.deepcopy(STEADY_TOPOLOGY),
            "node_args": self.extra_args,
            "lane_results": lane_results,
            "red_flags": red_flags,
            "total_red_flags": len(red_flags),
            "ci_failure_count": ci_failure_count,
            "summary": {
                "lanes": self.effective_lanes(),
                "rounds": self.effective_rounds(),
                "partition_left_blocks": self.options.partition_left_blocks,
                "partition_right_blocks": self.options.partition_right_blocks,
                "txs_per_round": self.options.txs_per_round,
            },
            "tmpdir": self.options.tmpdir,
            "builddir": self.config["environment"]["BUILDDIR"],
            "bitcoind_path": self.binary_paths.bitcoind,
            "bitcoin_cli_path": self.binary_paths.bitcoincli,
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "cpu_count": os.cpu_count(),
            },
        }

        self.write_report(report)
        if has_ci_failures(red_flags):
            raise AssertionError(
                "network simulation red flags:\n"
                + json.dumps(json_safe(red_flags), indent=2, sort_keys=True)
            )


if __name__ == "__main__":
    NetworkSimulationTest(__file__).main()
