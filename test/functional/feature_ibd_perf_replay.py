#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Report-only replay benchmark for default archive and explicit witness-pruned lanes.

This script is a manual performance harness. It is not part of the default
functional suite and does not assert performance thresholds. Instead, it builds
deterministic regtest history, restarts the node with `-reindex` or
`-reindex-chainstate`, and writes a JSON report with replay timing and storage
footprint. The history can be kept in the default archive lane or compacted
into an explicit witness-pruned lane before replay. Two history recipes are
supported today:
`W1-replay-floor` for a lower-bound witness-bearing proxy workload and
`W2-replay-mixed` for a mixed proxy + P2MR spend workload.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
import time
from datetime import datetime, timezone
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.ibd_perf import (
    ConnectBlockTrace,
    DiskUsageSampler,
    REPLAY_REPORT_VERSION,
    WorkloadTimekeeper,
    W2_P2MR_FUND_AMOUNT_SAT,
    W2_P2MR_SPEND_AMOUNT,
    build_replay_workload_name,
    build_replay_workload_recipe,
    collect_utxo_flush_evidence,
    debug_log_tail,
    directory_size,
    git_head,
    replay_lane_name,
    rpc_chain_snapshot,
    slugify,
    validate_replay_report_schema,
)
from test_framework.messages import NODE_WITNESS_PRUNED
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

class IBDPerfReplayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.rpc_timeout = 600
        self.extra_args = [self.history_node_args()]

    def skip_test_if_missing_module(self):
        if self.options.workload == "w2-replay-mixed":
            self.skip_if_no_wallet()

    def add_options(self, parser):
        parser.add_argument(
            "--blocks",
            dest="blocks",
            type=int,
            default=300,
            help="Number of measured history blocks to generate before replay (default: 300)",
        )
        parser.add_argument(
            "--workload",
            dest="workload",
            choices=["w1-replay-floor", "w2-replay-mixed"],
            default="w1-replay-floor",
            help=(
                "Measured history recipe. "
                "'w1-replay-floor' is the existing MiniWallet proxy floor; "
                "'w2-replay-mixed' adds deterministic P2MR spends to each measured block "
                "(default: w1-replay-floor)"
            ),
        )
        parser.add_argument(
            "--txs-per-block",
            dest="txs_per_block",
            type=int,
            default=1,
            help=(
                "Number of deterministic MiniWallet witness-bearing proxy self-transfers to mine per measured "
                "block (default: 1)"
            ),
        )
        parser.add_argument(
            "--p2mr-spends-per-block",
            dest="p2mr_spends_per_block",
            type=int,
            default=1,
            help=(
                "For --workload=w2-replay-mixed, number of confirmed P2MR wallet spends to include per measured "
                "block (default: 1)"
            ),
        )
        parser.add_argument(
            "--tail-blocks",
            dest="tail_blocks",
            type=int,
            default=0,
            help=(
                "Number of extra empty tail blocks to mine after the measured history before replay. "
                "Useful for witness-pruned smoke runs where the measured history alone would not fall "
                "outside the witness retention window (default: 0)"
            ),
        )
        parser.add_argument(
            "--history-mode",
            dest="history_mode",
            choices=["archive", "witness-pruned"],
            default="archive",
            help="History lane to build before replay: default archive or explicit witness-pruned (default: archive)",
        )
        parser.add_argument(
            "--reindex-mode",
            dest="reindex_mode",
            choices=["chainstate", "full"],
            default="chainstate",
            help="Replay mode: 'chainstate' uses -reindex-chainstate, 'full' uses -reindex (default: chainstate)",
        )
        parser.add_argument(
            "--fastprune",
            dest="fastprune",
            default=False,
            action="store_true",
            help="Use smaller block files for test/smoke runs. Not recommended for host baseline numbers.",
        )
        parser.add_argument(
            "--assumevalid-blocks-from-tip",
            dest="assumevalid_blocks_from_tip",
            type=int,
            default=5,
            help=(
                "For witness-pruned chainstate replay, derive -assumevalid from this many blocks below the "
                "current tip (default: 5)"
            ),
        )
        parser.add_argument(
            "--witness-prune-timeout",
            dest="witness_prune_timeout",
            type=int,
            default=300,
            help="Seconds to wait for witness compaction before replay in witness-pruned mode (default: 300)",
        )
        parser.add_argument(
            "--replay-timeout",
            dest="replay_timeout",
            type=int,
            default=3600,
            help=(
                "Seconds to wait for explicit reindex/replay completion after restarting the replay node "
                "(default: 3600)"
            ),
        )
        parser.add_argument(
            "--lane-name",
            dest="lane_name",
            default=None,
            help="Optional lane label to store in the report (default: derived from history mode + replay mode)",
        )
        parser.add_argument(
            "--workload-name",
            dest="workload_name",
            default=None,
            help="Optional workload label to store in the report (default: derived from block/tx settings)",
        )
        parser.add_argument(
            "--report-file",
            dest="report_file",
            default=None,
            help=(
                "Where to write the JSON report "
                "(default: <repo>/build/reports/feature-ibd-perf-replay-<lane>-<workload>.json)"
            ),
        )
        parser.add_argument(
            "--connectblock-trace-file",
            dest="connectblock_trace_file",
            default=None,
            help="Optional path for ConnectBlock bpftrace output captured during replay",
        )
        parser.add_argument(
            "--connectblock-threshold-ms",
            dest="connectblock_threshold_ms",
            type=int,
            default=25,
            help="Threshold passed to connectblock_benchmark.bt when tracing is enabled (default: 25)",
        )

    def base_node_args(self) -> list[str]:
        args = ["-maxconnections=0", "-dnsseed=0", "-fixedseeds=0"]
        if self.options.fastprune:
            args.append("-fastprune")
        return args

    def history_node_args(self) -> list[str]:
        args = self.base_node_args()
        if self.options.history_mode == "witness-pruned":
            args.append("-prunewitnesses=1")
        return args

    def lane_name(self) -> str:
        return replay_lane_name(self.options.history_mode, self.options.reindex_mode, self.options.lane_name)

    def effective_p2mr_spends_per_block(self) -> int:
        return self.options.p2mr_spends_per_block if self.options.workload == "w2-replay-mixed" else 0

    def history_script(self) -> str:
        if self.options.workload == "w2-replay-mixed":
            return "MiniWallet ADDRESS_OP_TRUE + wallet P2MR send"
        return "MiniWallet ADDRESS_OP_TRUE"

    def workload_recipe(self) -> dict:
        return build_replay_workload_recipe(
            workload=self.options.workload,
            txs_per_block=self.options.txs_per_block,
            p2mr_spends_per_block=self.effective_p2mr_spends_per_block(),
        )

    def workload_name(self) -> str:
        return build_replay_workload_name(
            workload=self.options.workload,
            blocks=self.options.blocks,
            txs_per_block=self.options.txs_per_block,
            p2mr_spends_per_block=self.effective_p2mr_spends_per_block(),
            tail_blocks=self.options.tail_blocks,
            workload_name=self.options.workload_name,
        )

    def connectblock_trace_path(self) -> Path | None:
        if self.options.connectblock_trace_file is None:
            return None
        return Path(self.options.connectblock_trace_file).expanduser()

    def default_report_path(self) -> Path:
        repo_root = Path(self.config["environment"]["SRCDIR"])
        report_dir = repo_root / "build" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        lane_slug = slugify(self.lane_name())
        workload_slug = slugify(self.workload_name())
        return report_dir / f"feature-ibd-perf-replay-{lane_slug}-{workload_slug}.json"

    def validate_options(self):
        if self.options.blocks < 1:
            raise AssertionError("--blocks must be at least 1")
        if self.options.txs_per_block < 0:
            raise AssertionError("--txs-per-block must be non-negative")
        if self.options.p2mr_spends_per_block < 0:
            raise AssertionError("--p2mr-spends-per-block must be non-negative")
        if self.options.tail_blocks < 0:
            raise AssertionError("--tail-blocks must be non-negative")
        if self.options.assumevalid_blocks_from_tip < 1:
            raise AssertionError("--assumevalid-blocks-from-tip must be at least 1")
        if self.options.workload == "w2-replay-mixed" and self.options.p2mr_spends_per_block < 1:
            raise AssertionError("--workload=w2-replay-mixed requires --p2mr-spends-per-block to be at least 1")
        if self.options.connectblock_threshold_ms < 0:
            raise AssertionError("--connectblock-threshold-ms must be non-negative")
        if self.options.replay_timeout < 1:
            raise AssertionError("--replay-timeout must be at least 1")

        if self.options.history_mode == "witness-pruned":
            if self.options.reindex_mode != "chainstate":
                raise AssertionError(
                    "--history-mode=witness-pruned only supports --reindex-mode=chainstate"
                )
            if self.options.blocks + self.options.tail_blocks < COINBASE_MATURITY + 2:
                raise AssertionError(
                    "--history-mode=witness-pruned requires --blocks + --tail-blocks to be at least "
                    f"{COINBASE_MATURITY + 2} so at least one measured witness-bearing block falls "
                    "strictly outside the witness retention window"
                )

    def wait_for_witness_pruned(self, node):
        self.wait_until(
            lambda: int(node.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED,
            timeout=self.options.witness_prune_timeout,
        )

    def find_wallet_utxo(self, wallet, txid: str, address: str) -> dict:
        for utxo in wallet.listunspent(minconf=1, addresses=[address]):
            if utxo["txid"] == txid:
                return {
                    "txid": utxo["txid"],
                    "vout": utxo["vout"],
                    "amount": Decimal(str(utxo["amount"])),
                }
        raise AssertionError(f"could not find confirmed wallet utxo for {txid} paying {address}")

    def setup_w2_mixed_state(self, node, proxy_wallet: MiniWallet, timekeeper: WorkloadTimekeeper) -> dict:
        self.log.info(
            f"Initialize W2 mixed workload with {self.effective_p2mr_spends_per_block()} seeded P2MR UTXO(s)"
        )
        wallet_name = "replay_p2mr_source"
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
        for _ in range(self.effective_p2mr_spends_per_block()):
            funding = proxy_wallet.send_to(
                from_node=node,
                scriptPubKey=receive_script,
                amount=W2_P2MR_FUND_AMOUNT_SAT,
            )
            seeded_txids.append(funding["txid"])
        timekeeper.generate(self, node, 1)

        return {
            "p2mr_wallet": p2mr_wallet,
            "receive_addr": receive_addr,
            "change_addr": change_addr,
            "receive_script": receive_script,
            "spend_queue": [self.find_wallet_utxo(p2mr_wallet, txid, receive_addr) for txid in seeded_txids],
            "seeded_utxos": len(seeded_txids),
        }

    def generate_measured_block(
        self,
        node,
        proxy_wallet: MiniWallet,
        workload_state: dict | None,
        timekeeper: WorkloadTimekeeper,
    ) -> dict:
        for _ in range(self.options.txs_per_block):
            proxy_wallet.send_self_transfer(from_node=node)

        p2mr_fund_txids = []
        p2mr_spend_txids = []
        if self.options.workload == "w2-replay-mixed":
            assert workload_state is not None
            for _ in range(self.effective_p2mr_spends_per_block()):
                funding = proxy_wallet.send_to(
                    from_node=node,
                    scriptPubKey=workload_state["receive_script"],
                    amount=W2_P2MR_FUND_AMOUNT_SAT,
                )
                p2mr_fund_txids.append(funding["txid"])

                if not workload_state["spend_queue"]:
                    raise AssertionError("W2 mixed workload ran out of confirmed P2MR UTXOs to spend")

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

        timekeeper.generate(self, node, 1)

        if self.options.workload == "w2-replay-mixed":
            assert workload_state is not None
            for txid in p2mr_fund_txids:
                workload_state["spend_queue"].append(
                    self.find_wallet_utxo(workload_state["p2mr_wallet"], txid, workload_state["receive_addr"])
                )

        return {
            "proxy_txs": self.options.txs_per_block,
            "p2mr_funding_txs": len(p2mr_fund_txids),
            "p2mr_spend_txs": len(p2mr_spend_txids),
        }

    def build_history(self, node):
        self.validate_options()

        proxy_wallet = MiniWallet(node)
        timekeeper = WorkloadTimekeeper(node)
        warmup_blocks = COINBASE_MATURITY + 1

        self.log.info(f"Mine {warmup_blocks} warmup blocks so history has mature spendable outputs")
        timekeeper.generate(self, proxy_wallet, warmup_blocks)

        workload_state = None
        if self.options.workload == "w2-replay-mixed":
            workload_state = self.setup_w2_mixed_state(node, proxy_wallet, timekeeper)

        measured_start_height = node.getblockcount() + 1
        if self.options.workload == "w2-replay-mixed":
            self.log.info(
                f"Build {self.options.blocks} measured W2 mixed blocks with {self.options.txs_per_block} proxy "
                f"self-transfer(s) and {self.effective_p2mr_spends_per_block()} P2MR spend(s) per block"
            )
        else:
            self.log.info(
                f"Build {self.options.blocks} measured history blocks with {self.options.txs_per_block} "
                "witness-bearing self-transfer(s) per block"
            )

        measured_proxy_txs = 0
        measured_p2mr_funding_txs = 0
        measured_p2mr_spend_txs = 0
        for height in range(self.options.blocks):
            block_stats = self.generate_measured_block(node, proxy_wallet, workload_state, timekeeper)
            measured_proxy_txs += block_stats["proxy_txs"]
            measured_p2mr_funding_txs += block_stats["p2mr_funding_txs"]
            measured_p2mr_spend_txs += block_stats["p2mr_spend_txs"]
            if (height + 1) % 100 == 0 or height + 1 == self.options.blocks:
                self.log.info(f"Generated {height + 1}/{self.options.blocks} measured replay blocks")

        if self.options.tail_blocks:
            self.log.info(
                f"Mine {self.options.tail_blocks} empty tail block(s) after the measured history"
            )
            for height in range(self.options.tail_blocks):
                timekeeper.generate(self, node, 1)
                if (height + 1) % 100 == 0 or height + 1 == self.options.tail_blocks:
                    self.log.info(f"Generated {height + 1}/{self.options.tail_blocks} tail block(s)")

        history_mocktime = timekeeper.sync_to_tip()

        pre_replay_services = node.getnetworkinfo()
        assumevalid_height = None
        assumevalid_hash = None
        history_witness_pruned = False

        if self.options.history_mode == "witness-pruned":
            self.log.info("Wait for witness compaction to complete before replay")
            self.wait_for_witness_pruned(node)
            pre_replay_services = node.getnetworkinfo()
            history_witness_pruned = bool(
                int(pre_replay_services["localservices"], 16) & NODE_WITNESS_PRUNED
            )

            expected_tip_height = node.getblockcount()
            assumevalid_height = expected_tip_height - self.options.assumevalid_blocks_from_tip
            assumevalid_hash = node.getblockhash(assumevalid_height)

        return {
            "warmup_blocks": warmup_blocks,
            "measured_start_height": measured_start_height,
            "measured_end_height": measured_start_height + self.options.blocks - 1,
            "tail_blocks": self.options.tail_blocks,
            "expected_tip_height": node.getblockcount(),
            "expected_tip_hash": node.getbestblockhash(),
            "history_mocktime": history_mocktime,
            "workload_state": {
                "seeded_p2mr_utxos": workload_state["seeded_utxos"] if workload_state is not None else 0,
            },
            "measured_proxy_txs_total": measured_proxy_txs,
            "measured_p2mr_funding_txs_total": measured_p2mr_funding_txs,
            "measured_p2mr_spend_txs_total": measured_p2mr_spend_txs,
            "pre_replay_services": pre_replay_services["localservices"],
            "pre_replay_service_names": pre_replay_services["localservicesnames"],
            "history_witness_pruned": history_witness_pruned,
            "assumevalid_height": assumevalid_height,
            "assumevalid_hash": assumevalid_hash,
        }

    def replay_args(self, assumevalid_hash: str | None, mocktime: int) -> list[str]:
        base_args = self.base_node_args()
        base_args.append(f"-mocktime={mocktime}")
        if self.options.history_mode == "witness-pruned":
            base_args.append("-prunewitnesses=1")
        if assumevalid_hash is not None:
            base_args.append(f"-assumevalid={assumevalid_hash}")

        base_args.append("-disablewallet")
        if self.options.reindex_mode == "chainstate":
            base_args.append("-reindex-chainstate")
        else:
            base_args.append("-reindex")
        return base_args

    def log_replay_timeout_diagnostics(self, node, *, expected_tip_height: int, expected_tip_hash: str) -> None:
        diagnostics = rpc_chain_snapshot(node, expected_tip_height=expected_tip_height)
        diagnostics["expected_tip_hash"] = expected_tip_hash
        self.log.error(
            "Replay timeout diagnostics: %s",
            json.dumps(diagnostics, indent=2, sort_keys=True),
        )

        tail = debug_log_tail(node.debug_log_path)
        if tail:
            self.log.error("Replay debug.log tail:\n%s", "\n".join(tail))

    def wait_for_replay_completion(
        self,
        node,
        *,
        expected_tip_height: int,
        expected_tip_hash: str,
        timeout: float,
    ) -> None:
        def replay_complete() -> bool:
            try:
                chaininfo = node.getblockchaininfo()
            except JSONRPCException as exc:
                if exc.error["code"] in (-28, -342):
                    return False
                raise
            return (
                chaininfo.get("blocks") == expected_tip_height
                and chaininfo.get("bestblockhash") == expected_tip_hash
            )

        try:
            self.wait_until(replay_complete, timeout=timeout)
        except AssertionError:
            self.log_replay_timeout_diagnostics(
                node,
                expected_tip_height=expected_tip_height,
                expected_tip_hash=expected_tip_hash,
            )
            raise

    def write_report(self, report: dict) -> Path:
        if self.options.report_file is None:
            report_path = self.default_report_path()
        else:
            report_path = Path(self.options.report_file).expanduser()
            report_path.parent.mkdir(parents=True, exist_ok=True)

        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.log.info(f"Wrote replay report to {report_path}")
        return report_path

    def run_test(self):
        node = self.nodes[0]
        repo_root = Path(self.config["environment"]["SRCDIR"])
        history = self.build_history(node)
        expected_tip_height = history["expected_tip_height"]

        pre_replay_blocks_bytes = directory_size(node.blocks_path)
        pre_replay_chainstate_bytes = directory_size(node.chain_path / "chainstate")

        self.log.info(
            f"Stop node and measure replay using {'-reindex-chainstate' if self.options.reindex_mode == 'chainstate' else '-reindex'}"
        )
        self.stop_node(0)
        replay_log_start_offset = node.debug_log_path.stat().st_size if node.debug_log_path.exists() else None

        replay_args = self.replay_args(history["assumevalid_hash"], history["history_mocktime"])
        with ConnectBlockTrace(
            repo_root=repo_root,
            output_path=self.connectblock_trace_path(),
            threshold_ms=self.options.connectblock_threshold_ms,
        ) as connectblock_trace, DiskUsageSampler(
            paths={
                "replay_blocks": node.blocks_path,
                "replay_chainstate": node.chain_path / "chainstate",
            },
        ) as disk_sampler:
            replay_start = time.perf_counter()
            old_rpc_timeout = node.rpc_timeout
            node.rpc_timeout = max(2, self.options.replay_timeout)
            try:
                node.start(extra_args=replay_args)
                node.wait_for_rpc_connection(wait_for_import=False)
            except Exception:
                self.log_replay_timeout_diagnostics(
                    node,
                    expected_tip_height=expected_tip_height,
                    expected_tip_hash=history["expected_tip_hash"],
                )
                raise
            finally:
                node.rpc_timeout = old_rpc_timeout
            replay_rpc_connected_sec = time.perf_counter() - replay_start
            replay_remaining_timeout = self.options.replay_timeout - replay_rpc_connected_sec
            if replay_remaining_timeout <= 0:
                self.log_replay_timeout_diagnostics(
                    node,
                    expected_tip_height=expected_tip_height,
                    expected_tip_hash=history["expected_tip_hash"],
                )
                raise AssertionError(
                    f"Replay RPC startup exceeded --replay-timeout={self.options.replay_timeout}s"
                )
            self.wait_for_replay_completion(
                node,
                expected_tip_height=expected_tip_height,
                expected_tip_hash=history["expected_tip_hash"],
                timeout=replay_remaining_timeout,
            )
            elapsed_sec = time.perf_counter() - replay_start
            replay_wait_after_rpc_sec = elapsed_sec - replay_rpc_connected_sec
        disk_usage_sampling = disk_sampler.summary()
        connectblock_trace_summary = connectblock_trace.summary()
        utxo_flush_evidence = collect_utxo_flush_evidence(node.debug_log_path, replay_log_start_offset)

        assert_equal(node.getblockcount(), expected_tip_height)

        post_replay_services = node.getnetworkinfo()
        if self.options.history_mode == "witness-pruned":
            assert int(post_replay_services["localservices"], 16) & NODE_WITNESS_PRUNED

        post_replay_blocks_bytes = directory_size(node.blocks_path)
        post_replay_chainstate_bytes = directory_size(node.chain_path / "chainstate")
        observed_total_bytes_before = pre_replay_blocks_bytes + pre_replay_chainstate_bytes
        observed_total_bytes_after = post_replay_blocks_bytes + post_replay_chainstate_bytes
        disk_usage_peak_total = disk_usage_sampling["peak_total_bytes"] or 0

        report = {
            "report_version": REPLAY_REPORT_VERSION,
            "report_kind": "replay",
            "report_only": True,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": git_head(repo_root),
            "chain": self.chain,
            "lane_name": self.lane_name(),
            "workload_name": self.workload_name(),
            "workload": self.options.workload,
            "reindex_mode": self.options.reindex_mode,
            "history_mode": self.options.history_mode,
            "history_script": self.history_script(),
            "workload_recipe": self.workload_recipe(),
            "history_node_args": self.history_node_args(),
            "warmup_blocks": history["warmup_blocks"],
            "measured_blocks": self.options.blocks,
            "tail_blocks": history["tail_blocks"],
            "measured_start_height": history["measured_start_height"],
            "measured_end_height": history["measured_end_height"],
            "txs_per_block": self.options.txs_per_block,
            "p2mr_spends_per_block": self.effective_p2mr_spends_per_block(),
            "seeded_p2mr_utxos": history["workload_state"]["seeded_p2mr_utxos"],
            "measured_proxy_txs_total": history["measured_proxy_txs_total"],
            "measured_p2mr_funding_txs_total": history["measured_p2mr_funding_txs_total"],
            "measured_p2mr_spend_txs_total": history["measured_p2mr_spend_txs_total"],
            "expected_tip_height": expected_tip_height,
            "expected_tip_hash": history["expected_tip_hash"],
            "history_mocktime": history["history_mocktime"],
            "assumevalid_height": history["assumevalid_height"],
            "assumevalid_hash": history["assumevalid_hash"],
            "history_witness_pruned": history["history_witness_pruned"],
            "pre_replay_witness_pruned": history["history_witness_pruned"],
            "replay_timeout": self.options.replay_timeout,
            "replay_rpc_connect_sec": round(replay_rpc_connected_sec, 6),
            "replay_completion_wait_sec": round(replay_wait_after_rpc_sec, 6),
            "elapsed_sec": round(elapsed_sec, 6),
            "blocks_per_sec": round(expected_tip_height / elapsed_sec, 6),
            "measured_blocks_per_total_replay_sec": round(self.options.blocks / elapsed_sec, 6),
            "node_args": replay_args,
            "tmpdir": self.options.tmpdir,
            "builddir": self.config["environment"]["BUILDDIR"],
            "bitcoind_path": self.binary_paths.bitcoind,
            "bitcoin_cli_path": self.binary_paths.bitcoincli,
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "cpu_count": os.cpu_count(),
            },
            "pre_replay_localservices": history["pre_replay_services"],
            "pre_replay_localservicesnames": history["pre_replay_service_names"],
            "post_replay_localservices": post_replay_services["localservices"],
            "post_replay_localservicesnames": post_replay_services["localservicesnames"],
            "post_replay_witness_pruned": bool(
                int(post_replay_services["localservices"], 16) & NODE_WITNESS_PRUNED
            ),
            "pre_replay_blocks_bytes": pre_replay_blocks_bytes,
            "pre_replay_chainstate_bytes": pre_replay_chainstate_bytes,
            "post_replay_blocks_bytes": post_replay_blocks_bytes,
            "post_replay_chainstate_bytes": post_replay_chainstate_bytes,
            "observed_total_bytes_before_replay": observed_total_bytes_before,
            "observed_total_bytes_after_replay": observed_total_bytes_after,
            "observed_total_bytes_max": max(
                observed_total_bytes_before,
                observed_total_bytes_after,
                disk_usage_peak_total,
            ),
            "disk_usage_sampling": disk_usage_sampling,
            "connectblock_trace_file": connectblock_trace_summary["path"],
            "connectblock_trace_summary": connectblock_trace_summary,
            "utxo_flush_evidence": utxo_flush_evidence,
        }
        validate_replay_report_schema(report)
        self.write_report(report)
        self.stop_node(0)


if __name__ == "__main__":
    IBDPerfReplayTest(__file__).main()
