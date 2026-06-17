#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Validate IBD perf workload determinism helpers and report schemas."""

from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.ibd_perf import (
    NETWORK_REPORT_VERSION,
    REPLAY_REPORT_VERSION,
    W1_REPLAY_FLOOR,
    W2_P2MR_FUND_AMOUNT_SAT,
    W2_P2MR_SPEND_AMOUNT,
    W2_REPLAY_MIXED,
    build_replay_workload_count_expectations,
    build_replay_workload_name,
    build_replay_workload_recipe,
    collect_utxo_flush_evidence,
    parse_connectblock_trace,
    validate_network_report_schema,
    validate_replay_report_schema,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


W1_DETERMINISM_CASE = {
    "workload": W1_REPLAY_FLOOR,
    "blocks": 4,
    "txs_per_block": 2,
    "p2mr_spends_per_block": 7,
    "tail_blocks": 1,
    "workload_name": None,
}

W2_DETERMINISM_CASE = {
    "workload": W2_REPLAY_MIXED,
    "blocks": 3,
    "txs_per_block": 2,
    "p2mr_spends_per_block": 3,
    "tail_blocks": 5,
    "workload_name": None,
}

GENERATED_HISTORY_FIELDS = (
    "workload",
    "workload_name",
    "workload_recipe",
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
)


class IBDPerfValidationTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument(
            "--run-history-determinism",
            dest="run_history_determinism",
            default=False,
            action="store_true",
            help=(
                "Also build tiny W1/W2 histories on two clean nodes and compare "
                "stable workload metadata. "
                "This remains report-only and is not run by the default functional suite."
            ),
        )

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2 if self.options.run_history_determinism else 0
        self.rpc_timeout = 600
        self.extra_args = [
            ["-maxconnections=0", "-dnsseed=0", "-fixedseeds=0"]
            for _ in range(self.num_nodes)
        ]

    def setup_network(self):
        if self.num_nodes:
            self.setup_nodes()

    def skip_test_if_missing_module(self):
        if self.options.run_history_determinism:
            self.skip_if_no_wallet()

    def workload_metadata(
        self,
        *,
        workload,
        blocks,
        txs_per_block,
        p2mr_spends_per_block,
        tail_blocks,
        workload_name,
    ):
        return {
            "name": build_replay_workload_name(
                workload=workload,
                blocks=blocks,
                txs_per_block=txs_per_block,
                p2mr_spends_per_block=p2mr_spends_per_block,
                tail_blocks=tail_blocks,
                workload_name=workload_name,
            ),
            "recipe": build_replay_workload_recipe(
                workload=workload,
                txs_per_block=txs_per_block,
                p2mr_spends_per_block=p2mr_spends_per_block,
            ),
            "counts": build_replay_workload_count_expectations(
                workload=workload,
                blocks=blocks,
                txs_per_block=txs_per_block,
                p2mr_spends_per_block=p2mr_spends_per_block,
            ),
        }

    def check_workload_metadata_determinism(self):
        self.log.info("Check W1/W2 replay workload metadata stays deterministic")
        for case in (W1_DETERMINISM_CASE, W2_DETERMINISM_CASE):
            first = self.workload_metadata(**case)
            second = self.workload_metadata(**case)
            assert_equal(first, second)

        w1 = self.workload_metadata(**W1_DETERMINISM_CASE)
        assert_equal(w1["recipe"]["p2mr_spends_per_block"], 0)
        assert_equal(w1["counts"]["seeded_p2mr_utxos"], 0)
        assert_equal(w1["counts"]["measured_p2mr_funding_txs_total"], 0)
        assert_equal(w1["counts"]["measured_p2mr_spend_txs_total"], 0)

        w2 = self.workload_metadata(**W2_DETERMINISM_CASE)
        assert_equal(w2["counts"]["seeded_p2mr_utxos"], 3)
        assert_equal(w2["counts"]["measured_proxy_txs_total"], 6)
        assert_equal(w2["counts"]["measured_p2mr_funding_txs_total"], 9)
        assert_equal(w2["counts"]["measured_p2mr_spend_txs_total"], 9)
        return w1, w2

    def find_wallet_utxo(self, wallet, txid: str, address: str) -> dict:
        for utxo in wallet.listunspent(minconf=1, addresses=[address]):
            if utxo["txid"] == txid:
                return {"txid": utxo["txid"], "vout": utxo["vout"]}
        raise AssertionError(f"could not find confirmed wallet utxo for {txid} paying {address}")

    def setup_tiny_w2_state(
        self,
        node,
        proxy_wallet: MiniWallet,
        p2mr_spends_per_block: int,
    ) -> dict:
        wallet_name = f"validation_p2mr_{node.index}_{node.getblockcount()}"
        node.createwallet(wallet_name)
        p2mr_wallet = node.get_wallet_rpc(wallet_name)
        try:
            p2mr_wallet.createwalletdescriptor("p2mr")
        except JSONRPCException as e:
            if "Descriptor already exists" not in e.error["message"]:
                raise

        receive_addr = p2mr_wallet.getnewaddress(address_type="p2mr")
        change_addr = p2mr_wallet.getrawchangeaddress(address_type="p2mr")
        receive_script = bytes.fromhex(p2mr_wallet.getaddressinfo(receive_addr)["scriptPubKey"])

        seeded_txids = []
        for _ in range(p2mr_spends_per_block):
            funding = proxy_wallet.send_to(
                from_node=node,
                scriptPubKey=receive_script,
                amount=W2_P2MR_FUND_AMOUNT_SAT,
            )
            seeded_txids.append(funding["txid"])
        self.generate(node, 1, sync_fun=self.no_op)

        return {
            "p2mr_wallet": p2mr_wallet,
            "receive_addr": receive_addr,
            "change_addr": change_addr,
            "receive_script": receive_script,
            "spend_queue": [
                self.find_wallet_utxo(p2mr_wallet, txid, receive_addr)
                for txid in seeded_txids
            ],
            "seeded_utxos": len(seeded_txids),
        }

    def generate_tiny_measured_block(
        self,
        node,
        proxy_wallet: MiniWallet,
        workload_state: dict | None,
        p2mr_spends_per_block: int,
    ) -> dict:
        proxy_wallet.send_self_transfer(from_node=node)

        p2mr_fund_txids = []
        p2mr_spend_txids = []
        if workload_state is not None:
            for _ in range(p2mr_spends_per_block):
                funding = proxy_wallet.send_to(
                    from_node=node,
                    scriptPubKey=workload_state["receive_script"],
                    amount=W2_P2MR_FUND_AMOUNT_SAT,
                )
                p2mr_fund_txids.append(funding["txid"])

                if not workload_state["spend_queue"]:
                    raise AssertionError("tiny W2 mixed workload ran out of confirmed P2MR UTXOs")

                spend_utxo = workload_state["spend_queue"].pop(0)
                spend = workload_state["p2mr_wallet"].send(
                    outputs=[{proxy_wallet.get_address(): W2_P2MR_SPEND_AMOUNT}],
                    fee_rate=200,
                    inputs=[{"txid": spend_utxo["txid"], "vout": spend_utxo["vout"]}],
                    add_inputs=False,
                    change_address=workload_state["change_addr"],
                    subtract_fee_from_outputs=[0],
                )
                p2mr_spend_txids.append(spend["txid"])

        self.generate(node, 1, sync_fun=self.no_op)

        if workload_state is not None:
            for txid in p2mr_fund_txids:
                workload_state["spend_queue"].append(
                    self.find_wallet_utxo(
                        workload_state["p2mr_wallet"],
                        txid,
                        workload_state["receive_addr"],
                    )
                )

        return {
            "proxy_txs": 1,
            "p2mr_funding_txs": len(p2mr_fund_txids),
            "p2mr_spend_txs": len(p2mr_spend_txids),
        }

    def build_tiny_history(
        self,
        node,
        *,
        workload: str,
        blocks: int,
        p2mr_spends_per_block: int,
    ) -> dict:
        proxy_wallet = MiniWallet(node, tag_name="ibd-perf-validation-proxy")
        warmup_blocks = max(0, COINBASE_MATURITY + 1 - node.getblockcount())
        if warmup_blocks:
            self.generate(proxy_wallet, warmup_blocks, sync_fun=self.no_op)

        workload_state = None
        if workload == W2_REPLAY_MIXED:
            workload_state = self.setup_tiny_w2_state(
                node,
                proxy_wallet,
                p2mr_spends_per_block,
            )

        measured_start_height = node.getblockcount() + 1
        measured_proxy_txs = 0
        measured_p2mr_funding_txs = 0
        measured_p2mr_spend_txs = 0
        for _ in range(blocks):
            block_stats = self.generate_tiny_measured_block(
                node,
                proxy_wallet,
                workload_state,
                p2mr_spends_per_block if workload == W2_REPLAY_MIXED else 0,
            )
            measured_proxy_txs += block_stats["proxy_txs"]
            measured_p2mr_funding_txs += block_stats["p2mr_funding_txs"]
            measured_p2mr_spend_txs += block_stats["p2mr_spend_txs"]

        effective_p2mr_spends = p2mr_spends_per_block if workload == W2_REPLAY_MIXED else 0
        seeded_p2mr_utxos = workload_state["seeded_utxos"] if workload_state is not None else 0
        return {
            "workload": workload,
            "workload_name": build_replay_workload_name(
                workload=workload,
                blocks=blocks,
                txs_per_block=1,
                p2mr_spends_per_block=effective_p2mr_spends,
                tail_blocks=0,
                workload_name=None,
            ),
            "workload_recipe": build_replay_workload_recipe(
                workload=workload,
                txs_per_block=1,
                p2mr_spends_per_block=p2mr_spends_per_block,
            ),
            "measured_blocks": blocks,
            "measured_start_height": measured_start_height,
            "measured_end_height": measured_start_height + blocks - 1,
            "txs_per_block": 1,
            "p2mr_spends_per_block": effective_p2mr_spends,
            "seeded_p2mr_utxos": seeded_p2mr_utxos,
            "measured_proxy_txs_total": measured_proxy_txs,
            "measured_p2mr_funding_txs_total": measured_p2mr_funding_txs,
            "measured_p2mr_spend_txs_total": measured_p2mr_spend_txs,
            "expected_tip_height": node.getblockcount(),
            "expected_tip_hash": node.getbestblockhash(),
        }

    def check_generated_history_determinism(self):
        self.log.info("Build tiny W1/W2 histories and compare stable metadata")
        for workload, blocks, p2mr_spends_per_block in (
            (W1_REPLAY_FLOOR, 2, 0),
            (W2_REPLAY_MIXED, 2, 1),
        ):
            first = self.build_tiny_history(
                self.nodes[0],
                workload=workload,
                blocks=blocks,
                p2mr_spends_per_block=p2mr_spends_per_block,
            )
            second = self.build_tiny_history(
                self.nodes[1],
                workload=workload,
                blocks=blocks,
                p2mr_spends_per_block=p2mr_spends_per_block,
            )
            assert_equal(
                {field: first[field] for field in GENERATED_HISTORY_FIELDS},
                {field: second[field] for field in GENERATED_HISTORY_FIELDS},
            )
            # The production harness does not fix node mining time or wallet key
            # entropy, so this smoke checks only the controlled construction
            # metadata. Tip hashes are recorded for operators but not asserted.
            if first["expected_tip_hash"] != second["expected_tip_hash"]:
                self.log.info(
                    "Tiny %s tip hashes differ; hash determinism is not asserted",
                    workload,
                )

    def run_test(self):
        w1, w2 = self.check_workload_metadata_determinism()

        if self.options.run_history_determinism:
            self.check_generated_history_determinism()

        self.log.info("Validate ConnectBlock trace parsing")
        trace_path = Path(self.options.tmpdir) / "connectblock.trace"
        block_hash = "0" * 64
        trace_path.write_text(
            "\n".join(
                [
                    "BENCH    1 blk/s      2 tx/s       3 inputs/s        4 sigops/s (height 5)",
                    f"Block 5 ({block_hash})     2 tx      3 ins      4 sigops  took    3 ms",
                    "Histogram of block connection times in milliseconds (ms).",
                    "@durations:",
                    "[0, 1)                1 |@|",
                    "[1, 2)                3 |@@@|",
                    "[2, 4)                1 |@|",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        trace_summary = parse_connectblock_trace(trace_path)
        assert trace_summary["captured"]
        assert trace_summary["parseable"]
        assert trace_summary["sample_count"] == 5
        assert trace_summary["median_ms"] == 2.0
        assert trace_summary["p95_ms"] == 4.0
        assert trace_summary["max_ms"] == 4.0
        assert trace_summary["bench_blocks_total"] == 1
        assert trace_summary["bench_txs_total"] == 2
        assert trace_summary["bench_inputs_total"] == 3
        assert trace_summary["bench_sigops_total"] == 4
        assert trace_summary["bench_max_height"] == 5
        assert trace_summary["slow_block_sample_count"] == 1
        assert trace_summary["slow_block_max_ms"] == 3

        self.log.info("Validate UTXO/flush debug-log evidence parsing")
        debug_log_path = Path(self.options.tmpdir) / "debug.log"
        debug_log_path.write_text(
            "\n".join(
                [
                    "UpdateTip: new best=00 height=1 cache=0.5MiB(3utxo)",
                    "write coins cache to disk (10 coins, 12.50KiB)",
                    "UpdateTip: new best=11 height=2 cache=1.5MiB(10utxo)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        flush_evidence = collect_utxo_flush_evidence(debug_log_path, 0)
        assert flush_evidence["captured"]
        assert flush_evidence["utxo_cache_sample_count"] == 2
        assert flush_evidence["utxo_cache_peak_mib"] == 1.5
        assert flush_evidence["utxo_cache_peak_utxos"] == 10
        assert flush_evidence["flush_event_count"] == 1

        self.log.info("Validate replay report schema")
        replay_report = {
            "report_version": REPLAY_REPORT_VERSION,
            "report_kind": "replay",
            "report_only": True,
            "generated_at_utc": "2026-03-27T00:00:00+00:00",
            "git_commit": "deadbeef",
            "chain": "regtest",
            "lane_name": "archive-chainstate",
            "workload_name": w2["name"],
            "workload": W2_REPLAY_MIXED,
            "reindex_mode": "chainstate",
            "history_mode": "archive",
            "history_script": "MiniWallet ADDRESS_OP_TRUE + wallet P2MR send",
            "workload_recipe": w2["recipe"],
            "history_node_args": [],
            "warmup_blocks": 1001,
            "measured_blocks": W2_DETERMINISM_CASE["blocks"],
            "tail_blocks": 5,
            "measured_start_height": 1003,
            "measured_end_height": 1005,
            "txs_per_block": W2_DETERMINISM_CASE["txs_per_block"],
            "p2mr_spends_per_block": W2_DETERMINISM_CASE["p2mr_spends_per_block"],
            "seeded_p2mr_utxos": w2["counts"]["seeded_p2mr_utxos"],
            "measured_proxy_txs_total": w2["counts"]["measured_proxy_txs_total"],
            "measured_p2mr_funding_txs_total": w2["counts"]["measured_p2mr_funding_txs_total"],
            "measured_p2mr_spend_txs_total": w2["counts"]["measured_p2mr_spend_txs_total"],
            "expected_tip_height": 1307,
            "expected_tip_hash": "00" * 32,
            "assumevalid_height": None,
            "assumevalid_hash": None,
            "history_witness_pruned": False,
            "pre_replay_witness_pruned": False,
            "replay_timeout": 3600,
            "replay_rpc_connect_sec": 0.5,
            "replay_completion_wait_sec": 12.0,
            "elapsed_sec": 12.5,
            "blocks_per_sec": 104.56,
            "measured_blocks_per_total_replay_sec": 24.0,
            "node_args": ["-reindex-chainstate", "-disablewallet"],
            "tmpdir": "/tmp/example",
            "builddir": "/tmp/build",
            "bitcoind_path": "/tmp/build/bin/qbitd",
            "bitcoin_cli_path": "/tmp/build/bin/qbit-cli",
            "host": {"platform": "Linux", "machine": "x86_64", "cpu_count": 16},
            "pre_replay_localservices": "00000001",
            "pre_replay_localservicesnames": ["NETWORK"],
            "post_replay_localservices": "00000001",
            "post_replay_localservicesnames": ["NETWORK"],
            "post_replay_witness_pruned": False,
            "pre_replay_blocks_bytes": 10,
            "pre_replay_chainstate_bytes": 20,
            "post_replay_blocks_bytes": 30,
            "post_replay_chainstate_bytes": 40,
            "observed_total_bytes_before_replay": 30,
            "observed_total_bytes_after_replay": 70,
            "observed_total_bytes_max": 70,
            "disk_usage_sampling": {
                "enabled": True,
                "interval_sec": 0.25,
                "sample_count": 3,
                "monitored_paths": {
                    "replay_blocks": "/tmp/example/node0/regtest/blocks",
                    "replay_chainstate": "/tmp/example/node0/regtest/chainstate",
                },
                "start_total_bytes": 30,
                "end_total_bytes": 70,
                "peak_total_bytes": 70,
                "peak_elapsed_sec": 1.0,
                "peak_paths_bytes": {
                    "replay_blocks": 30,
                    "replay_chainstate": 40,
                },
            },
            "connectblock_trace_file": None,
            "connectblock_trace_summary": {
                "path": None,
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
            },
            "utxo_flush_evidence": {
                "captured": True,
                "source": "debug.log",
                "log_path": "/tmp/example/node0/regtest/debug.log",
                "log_start_offset": 100,
                "log_end_offset": 200,
                "utxo_cache_sample_count": 2,
                "utxo_cache_peak_mib": 1.5,
                "utxo_cache_peak_utxos": 10,
                "flush_event_count": 0,
                "flush_events": [],
                "privileged_trace_path": None,
                "privileged_trace_status": "not_captured",
                "parse_error": None,
            },
        }
        validate_replay_report_schema(replay_report)

        w1_replay_report = replay_report.copy()
        w1_replay_report.update({
            "workload_name": w1["name"],
            "workload": W1_REPLAY_FLOOR,
            "history_script": "MiniWallet ADDRESS_OP_TRUE",
            "workload_recipe": w1["recipe"],
            "measured_blocks": W1_DETERMINISM_CASE["blocks"],
            "tail_blocks": W1_DETERMINISM_CASE["tail_blocks"],
            "measured_start_height": 1002,
            "measured_end_height": 1005,
            "txs_per_block": W1_DETERMINISM_CASE["txs_per_block"],
            "p2mr_spends_per_block": 0,
            "seeded_p2mr_utxos": w1["counts"]["seeded_p2mr_utxos"],
            "measured_proxy_txs_total": w1["counts"]["measured_proxy_txs_total"],
            "measured_p2mr_funding_txs_total": w1["counts"]["measured_p2mr_funding_txs_total"],
            "measured_p2mr_spend_txs_total": w1["counts"]["measured_p2mr_spend_txs_total"],
        })
        validate_replay_report_schema(w1_replay_report)

        self.log.info("Validate network report schema")
        network_report = {
            "report_version": NETWORK_REPORT_VERSION,
            "report_kind": "network",
            "report_only": True,
            "generated_at_utc": "2026-03-27T00:00:00+00:00",
            "git_commit": "deadbeef",
            "chain": "regtest",
            "lane_name": "w3-network-mixed",
            "workload_name": w2["name"],
            "workload": W2_REPLAY_MIXED,
            "history_script": "MiniWallet ADDRESS_OP_TRUE + wallet P2MR send",
            "workload_recipe": w2["recipe"],
            "source_node_args": [],
            "ibd_node_args": [],
            "warmup_blocks": 1001,
            "measured_blocks": W2_DETERMINISM_CASE["blocks"],
            "measured_start_height": 1003,
            "measured_end_height": 1005,
            "txs_per_block": W2_DETERMINISM_CASE["txs_per_block"],
            "p2mr_spends_per_block": W2_DETERMINISM_CASE["p2mr_spends_per_block"],
            "seeded_p2mr_utxos": w2["counts"]["seeded_p2mr_utxos"],
            "measured_proxy_txs_total": w2["counts"]["measured_proxy_txs_total"],
            "measured_p2mr_funding_txs_total": w2["counts"]["measured_p2mr_funding_txs_total"],
            "measured_p2mr_spend_txs_total": w2["counts"]["measured_p2mr_spend_txs_total"],
            "expected_tip_height": 1302,
            "expected_tip_hash": "11" * 32,
            "initialblockdownload_before_connect": True,
            "initialblockdownload_after_sync": False,
            "network_headers_timeout": 600,
            "network_tip_timeout": 1800,
            "network_ibd_exit_timeout": 600,
            "connect_to_headers_sec": 1.0,
            "connect_to_tip_sec": 2.0,
            "connect_to_ibd_exit_sec": 2.5,
            "headers_sync_sec": 1.0,
            "tip_sync_sec": 1.0,
            "ibd_exit_wait_sec": 0.5,
            "blocks_per_sec": 651.0,
            "headers_synced_height": 1302,
            "tip_synced_height": 1302,
            "peer_at_headers_sync": {"synced_headers": 1302},
            "peer_at_tip_sync": {"synced_headers": 1302, "inflight": []},
            "peer_at_ibd_exit": {"synced_headers": 1302, "inflight": []},
            "tmpdir": "/tmp/example",
            "builddir": "/tmp/build",
            "bitcoind_path": "/tmp/build/bin/qbitd",
            "bitcoin_cli_path": "/tmp/build/bin/qbit-cli",
            "host": {"platform": "Linux", "machine": "x86_64", "cpu_count": 16},
            "source_blocks_bytes": 10,
            "source_chainstate_bytes": 20,
            "ibd_blocks_bytes": 30,
            "ibd_chainstate_bytes": 40,
            "observed_total_bytes_max": 70,
            "disk_usage_sampling": {
                "enabled": True,
                "interval_sec": 0.25,
                "sample_count": 3,
                "monitored_paths": {
                    "source_blocks": "/tmp/example/node0/regtest/blocks",
                    "source_chainstate": "/tmp/example/node0/regtest/chainstate",
                    "ibd_blocks": "/tmp/example/node1/regtest/blocks",
                    "ibd_chainstate": "/tmp/example/node1/regtest/chainstate",
                },
                "start_total_bytes": 30,
                "end_total_bytes": 70,
                "peak_total_bytes": 70,
                "peak_elapsed_sec": 1.0,
                "peak_paths_bytes": {
                    "source_blocks": 10,
                    "source_chainstate": 20,
                    "ibd_blocks": 30,
                    "ibd_chainstate": 10,
                },
            },
            "connectblock_trace_file": None,
            "connectblock_trace_summary": {
                "path": None,
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
            },
            "utxo_flush_evidence": {
                "captured": True,
                "source": "debug.log",
                "log_path": "/tmp/example/node1/regtest/debug.log",
                "log_start_offset": 100,
                "log_end_offset": 200,
                "utxo_cache_sample_count": 2,
                "utxo_cache_peak_mib": 1.5,
                "utxo_cache_peak_utxos": 10,
                "flush_event_count": 1,
                "flush_events": [
                    {
                        "coins": 10,
                        "cache_kib": 12.5,
                        "line": "write coins cache to disk (10 coins, 12.50KiB)",
                    }
                ],
                "privileged_trace_path": None,
                "privileged_trace_status": "not_captured",
                "parse_error": None,
            },
        }
        validate_network_report_schema(network_report)


if __name__ == "__main__":
    IBDPerfValidationTest(__file__).main()
