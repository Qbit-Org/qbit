#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Report-only localhost network IBD benchmark for W3 mixed sync."""

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
    NETWORK_REPORT_VERSION,
    WorkloadTimekeeper,
    W2_P2MR_FUND_AMOUNT_SAT,
    W2_P2MR_SPEND_AMOUNT,
    build_replay_workload_name,
    build_replay_workload_recipe,
    collect_utxo_flush_evidence,
    debug_log_tail,
    directory_size,
    git_head,
    rpc_chain_snapshot,
    slugify,
    validate_network_report_schema,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class IBDPerfNetworkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.rpc_timeout = 600
        self.extra_args = [self.source_node_args(), self.ibd_node_args()]

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        if self.options.workload == "w2-replay-mixed":
            self.skip_if_no_wallet()

    def add_options(self, parser):
        parser.add_argument(
            "--blocks",
            dest="blocks",
            type=int,
            default=300,
            help="Number of measured history blocks to serve over localhost network IBD (default: 300)",
        )
        parser.add_argument(
            "--workload",
            dest="workload",
            choices=["w1-replay-floor", "w2-replay-mixed"],
            default="w2-replay-mixed",
            help="History recipe to serve over localhost IBD (default: w2-replay-mixed)",
        )
        parser.add_argument(
            "--txs-per-block",
            dest="txs_per_block",
            type=int,
            default=1,
            help="Number of deterministic MiniWallet witness-bearing proxy self-transfers per measured block",
        )
        parser.add_argument(
            "--p2mr-spends-per-block",
            dest="p2mr_spends_per_block",
            type=int,
            default=1,
            help="For W2, number of confirmed P2MR wallet spends to include per measured block",
        )
        parser.add_argument(
            "--fastprune",
            dest="fastprune",
            default=False,
            action="store_true",
            help="Use -fastprune for smaller block files during smoke runs",
        )
        parser.add_argument(
            "--lane-name",
            dest="lane_name",
            default=None,
            help="Optional lane label to store in the report (default: w3-network-mixed)",
        )
        parser.add_argument(
            "--workload-name",
            dest="workload_name",
            default=None,
            help="Optional workload label to store in the report",
        )
        parser.add_argument(
            "--report-file",
            dest="report_file",
            default=None,
            help=(
                "Where to write the JSON report "
                "(default: <repo>/build/reports/feature-ibd-perf-network-<lane>-<workload>.json)"
            ),
        )
        parser.add_argument(
            "--connectblock-trace-file",
            dest="connectblock_trace_file",
            default=None,
            help="Optional path for ConnectBlock bpftrace output captured during localhost IBD",
        )
        parser.add_argument(
            "--connectblock-threshold-ms",
            dest="connectblock_threshold_ms",
            type=int,
            default=25,
            help="Threshold passed to connectblock_benchmark.bt when tracing is enabled (default: 25)",
        )
        parser.add_argument(
            "--network-headers-timeout",
            dest="network_headers_timeout",
            type=int,
            default=600,
            help="Seconds to wait for localhost IBD headers sync after connecting peers (default: 600)",
        )
        parser.add_argument(
            "--network-tip-timeout",
            dest="network_tip_timeout",
            type=int,
            default=1800,
            help="Seconds to wait for the IBD node to reach the source tip after headers sync (default: 1800)",
        )
        parser.add_argument(
            "--network-ibd-exit-timeout",
            dest="network_ibd_exit_timeout",
            type=int,
            default=600,
            help="Seconds to wait for initialblockdownload=false after reaching the source tip (default: 600)",
        )

    def base_node_args(self) -> list[str]:
        args = ["-dnsseed=0", "-fixedseeds=0"]
        if self.options.fastprune:
            args.append("-fastprune")
        return args

    def source_node_args(self) -> list[str]:
        return self.base_node_args()

    def ibd_node_args(self) -> list[str]:
        return self.base_node_args()

    def lane_name(self) -> str:
        return self.options.lane_name or "w3-network-mixed"

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
            tail_blocks=0,
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
        return report_dir / f"feature-ibd-perf-network-{lane_slug}-{workload_slug}.json"

    def validate_options(self):
        if self.options.blocks < 1:
            raise AssertionError("--blocks must be at least 1")
        if self.options.txs_per_block < 0:
            raise AssertionError("--txs-per-block must be non-negative")
        if self.options.p2mr_spends_per_block < 0:
            raise AssertionError("--p2mr-spends-per-block must be non-negative")
        if self.options.workload == "w2-replay-mixed" and self.options.p2mr_spends_per_block < 1:
            raise AssertionError("--workload=w2-replay-mixed requires --p2mr-spends-per-block to be at least 1")
        if self.options.connectblock_threshold_ms < 0:
            raise AssertionError("--connectblock-threshold-ms must be non-negative")
        if self.options.network_headers_timeout < 1:
            raise AssertionError("--network-headers-timeout must be at least 1")
        if self.options.network_tip_timeout < 1:
            raise AssertionError("--network-tip-timeout must be at least 1")
        if self.options.network_ibd_exit_timeout < 1:
            raise AssertionError("--network-ibd-exit-timeout must be at least 1")

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
        wallet_name = "network_p2mr_source"
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
        self.log.info(
            f"Build {self.options.blocks} measured network IBD blocks for {self.options.workload}"
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
                self.log.info(f"Generated {height + 1}/{self.options.blocks} measured network blocks")

        history_mocktime = timekeeper.sync_to_tip()

        return {
            "warmup_blocks": warmup_blocks,
            "measured_start_height": measured_start_height,
            "measured_end_height": measured_start_height + self.options.blocks - 1,
            "expected_tip_height": node.getblockcount(),
            "expected_tip_hash": node.getbestblockhash(),
            "history_mocktime": history_mocktime,
            "workload_state": {
                "seeded_p2mr_utxos": workload_state["seeded_utxos"] if workload_state is not None else 0,
            },
            "measured_proxy_txs_total": measured_proxy_txs,
            "measured_p2mr_funding_txs_total": measured_p2mr_funding_txs,
            "measured_p2mr_spend_txs_total": measured_p2mr_spend_txs,
        }

    def find_sync_peer(self, node, peer_index: int):
        marker = f"testnode{peer_index}"
        for peer in node.getpeerinfo():
            if marker in peer.get("subver", ""):
                return peer
        return None

    @staticmethod
    def snapshot_peer(peer: dict | None) -> dict:
        if peer is None:
            return {}
        return {
            "id": peer.get("id"),
            "subver": peer.get("subver"),
            "servicesnames": peer.get("servicesnames"),
            "synced_headers": peer.get("synced_headers"),
            "presynced_headers": peer.get("presynced_headers"),
            "inflight": peer.get("inflight"),
            "bytesrecv": peer.get("bytesrecv"),
            "bytessent": peer.get("bytessent"),
        }

    def log_network_timeout_diagnostics(
        self,
        node,
        *,
        stage: str,
        expected_tip_height: int,
    ) -> None:
        diagnostics = rpc_chain_snapshot(node, expected_tip_height=expected_tip_height)
        try:
            peer = self.find_sync_peer(node, 0)
            peers = [self.snapshot_peer(peer_info) for peer_info in node.getpeerinfo()]
        except Exception as exc:  # noqa: BLE001 - preserve the original timeout failure
            peer = None
            peers = []
            diagnostics["peer_snapshot_error"] = repr(exc)
        diagnostics.update({
            "stage": stage,
            "current_height": diagnostics.get("blocks"),
            "sync_peer": self.snapshot_peer(peer),
            "peers": peers,
        })
        self.log.error(
            "Network IBD timeout diagnostics: %s",
            json.dumps(diagnostics, indent=2, sort_keys=True),
        )

        tail = debug_log_tail(node.debug_log_path)
        if tail:
            self.log.error("Network IBD debug.log tail:\n%s", "\n".join(tail))

    def wait_for_network_stage(
        self,
        *,
        stage: str,
        predicate,
        timeout: int,
        node,
        expected_tip_height: int,
    ) -> None:
        try:
            self.wait_until(predicate, timeout=timeout)
        except AssertionError:
            self.log_network_timeout_diagnostics(
                node,
                stage=stage,
                expected_tip_height=expected_tip_height,
            )
            raise

    def write_report(self, report: dict) -> Path:
        if self.options.report_file is None:
            report_path = self.default_report_path()
        else:
            report_path = Path(self.options.report_file).expanduser()
            report_path.parent.mkdir(parents=True, exist_ok=True)

        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.log.info(f"Wrote network IBD report to {report_path}")
        return report_path

    def run_test(self):
        source_node = self.nodes[0]
        ibd_node = self.nodes[1]
        repo_root = Path(self.config["environment"]["SRCDIR"])
        history = self.build_history(source_node)
        expected_tip_height = history["expected_tip_height"]
        ibd_node.setmocktime(history["history_mocktime"])

        source_blocks_bytes = directory_size(source_node.blocks_path)
        source_chainstate_bytes = directory_size(source_node.chain_path / "chainstate")

        initial_chaininfo = ibd_node.getblockchaininfo()
        assert initial_chaininfo["initialblockdownload"]
        ibd_log_start_offset = ibd_node.debug_log_path.stat().st_size if ibd_node.debug_log_path.exists() else None

        with ConnectBlockTrace(
            repo_root=repo_root,
            output_path=self.connectblock_trace_path(),
            threshold_ms=self.options.connectblock_threshold_ms,
        ) as connectblock_trace, DiskUsageSampler(
            paths={
                "source_blocks": source_node.blocks_path,
                "source_chainstate": source_node.chain_path / "chainstate",
                "ibd_blocks": ibd_node.blocks_path,
                "ibd_chainstate": ibd_node.chain_path / "chainstate",
            },
        ) as disk_sampler:
            connect_start = time.perf_counter()
            self.connect_nodes(1, 0)

            self.wait_for_network_stage(
                stage="headers sync",
                predicate=lambda: (
                    (peer := self.find_sync_peer(ibd_node, 0)) is not None
                    and (peer.get("synced_headers") or -1) >= expected_tip_height
                ),
                timeout=self.options.network_headers_timeout,
                node=ibd_node,
                expected_tip_height=expected_tip_height,
            )
            connect_to_headers_sec = time.perf_counter() - connect_start
            peer_at_headers_sync = self.snapshot_peer(self.find_sync_peer(ibd_node, 0))

            self.wait_for_network_stage(
                stage="block tip sync",
                predicate=lambda: ibd_node.getblockcount() == expected_tip_height,
                timeout=self.options.network_tip_timeout,
                node=ibd_node,
                expected_tip_height=expected_tip_height,
            )
            connect_to_tip_sec = time.perf_counter() - connect_start
            peer_at_tip_sync = self.snapshot_peer(self.find_sync_peer(ibd_node, 0))

            self.wait_for_network_stage(
                stage="IBD exit",
                predicate=lambda: not ibd_node.getblockchaininfo()["initialblockdownload"],
                timeout=self.options.network_ibd_exit_timeout,
                node=ibd_node,
                expected_tip_height=expected_tip_height,
            )
            connect_to_ibd_exit_sec = time.perf_counter() - connect_start
            peer_at_ibd_exit = self.snapshot_peer(self.find_sync_peer(ibd_node, 0))
            headers_sync_sec = connect_to_headers_sec
            tip_sync_sec = connect_to_tip_sec - connect_to_headers_sec
            ibd_exit_wait_sec = connect_to_ibd_exit_sec - connect_to_tip_sec
        disk_usage_sampling = disk_sampler.summary()
        connectblock_trace_summary = connectblock_trace.summary()
        utxo_flush_evidence = collect_utxo_flush_evidence(ibd_node.debug_log_path, ibd_log_start_offset)

        final_chaininfo = ibd_node.getblockchaininfo()
        assert_equal(ibd_node.getbestblockhash(), history["expected_tip_hash"])

        ibd_blocks_bytes = directory_size(ibd_node.blocks_path)
        ibd_chainstate_bytes = directory_size(ibd_node.chain_path / "chainstate")
        disk_usage_peak_total = disk_usage_sampling["peak_total_bytes"] or 0

        report = {
            "report_version": NETWORK_REPORT_VERSION,
            "report_kind": "network",
            "report_only": True,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": git_head(repo_root),
            "chain": self.chain,
            "lane_name": self.lane_name(),
            "workload_name": self.workload_name(),
            "workload": self.options.workload,
            "history_script": self.history_script(),
            "workload_recipe": self.workload_recipe(),
            "source_node_args": self.source_node_args(),
            "ibd_node_args": self.ibd_node_args(),
            "warmup_blocks": history["warmup_blocks"],
            "measured_blocks": self.options.blocks,
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
            "initialblockdownload_before_connect": initial_chaininfo["initialblockdownload"],
            "initialblockdownload_after_sync": final_chaininfo["initialblockdownload"],
            "network_headers_timeout": self.options.network_headers_timeout,
            "network_tip_timeout": self.options.network_tip_timeout,
            "network_ibd_exit_timeout": self.options.network_ibd_exit_timeout,
            "connect_to_headers_sec": round(connect_to_headers_sec, 6),
            "connect_to_tip_sec": round(connect_to_tip_sec, 6),
            "connect_to_ibd_exit_sec": round(connect_to_ibd_exit_sec, 6),
            "headers_sync_sec": round(headers_sync_sec, 6),
            "tip_sync_sec": round(tip_sync_sec, 6),
            "ibd_exit_wait_sec": round(ibd_exit_wait_sec, 6),
            "blocks_per_sec": round(expected_tip_height / connect_to_tip_sec, 6),
            "headers_synced_height": peer_at_headers_sync.get("synced_headers", 0) or 0,
            "tip_synced_height": ibd_node.getblockcount(),
            "peer_at_headers_sync": peer_at_headers_sync,
            "peer_at_tip_sync": peer_at_tip_sync,
            "peer_at_ibd_exit": peer_at_ibd_exit,
            "tmpdir": self.options.tmpdir,
            "builddir": self.config["environment"]["BUILDDIR"],
            "bitcoind_path": self.binary_paths.bitcoind,
            "bitcoin_cli_path": self.binary_paths.bitcoincli,
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "cpu_count": os.cpu_count(),
            },
            "source_blocks_bytes": source_blocks_bytes,
            "source_chainstate_bytes": source_chainstate_bytes,
            "ibd_blocks_bytes": ibd_blocks_bytes,
            "ibd_chainstate_bytes": ibd_chainstate_bytes,
            "observed_total_bytes_max": max(
                source_blocks_bytes + source_chainstate_bytes,
                ibd_blocks_bytes + ibd_chainstate_bytes,
                disk_usage_peak_total,
            ),
            "disk_usage_sampling": disk_usage_sampling,
            "connectblock_trace_file": connectblock_trace_summary["path"],
            "connectblock_trace_summary": connectblock_trace_summary,
            "utxo_flush_evidence": utxo_flush_evidence,
        }
        validate_network_report_schema(report)
        self.write_report(report)


if __name__ == "__main__":
    IBDPerfNetworkTest(__file__).main()
