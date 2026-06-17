#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deterministic qbit mempool simulation smoke and reporting harness."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import MAX_STANDARD_TX_WEIGHT
from test_framework.mempool_util import MIN_MAX_MEMPOOL_SIZE_MB
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MAX_BIP125_RBF_SEQUENCE,
    MAX_BLOCK_WEIGHT,
    WITNESS_SCALE_FACTOR,
)
from test_framework.script import (
    CScript,
    OP_2,
    OP_DROP,
    OP_TRUE,
    TaggedHash,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.wallet import MiniWallet


MEMPOOL_SIM_REPORT_VERSION = 1

QBIT_MEMPOOL_ASSUMPTIONS = {
    "target_spacing_seconds": 60,
    "max_block_weight": MAX_BLOCK_WEIGHT,
    "witness_scale_factor": WITNESS_SCALE_FACTOR,
    "default_max_mempool_mb": 300,
    "max_standard_tx_weight": MAX_STANDARD_TX_WEIGHT,
    "default_min_relay_fee_sat_per_kvb": 250,
    "default_incremental_relay_fee_sat_per_kvb": 250,
    "dust_relay_fee_sat_per_kvb": 750,
    "ancestor_count_limit": 25,
    "ancestor_size_limit_vbytes": 404_000,
    "descendant_count_limit": 25,
    "descendant_size_limit_vbytes": 404_000,
    "pqc_signature_size_bytes": 3_680,
}

P2MR_LEAF_VERSION = 0xC0
P2MR_PQC_PROXY_BYTES = 3_680
CI_SMOKE_STEADY_ROUNDS = 1
CI_SMOKE_SATURATION_TXS = 32
MANUAL_STEADY_ROUNDS = 3
MANUAL_SATURATION_TXS = 64


def p2mr_leaf_hash(script: CScript, leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    return TaggedHash("P2MRLeaf", bytes([leaf_version]) + ser_string(bytes(script)))


def p2mr_control_block(leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    # P2MR control blocks use the tapscript leaf-version mask and require bit 0.
    return bytes([leaf_version | 1])


def btc_per_kvb_to_sat_per_kvb(value) -> int:
    return int(Decimal(str(value)) * COIN)


def validate_mempool_sim_report_schema(report: dict) -> None:
    if report.get("report_version") != MEMPOOL_SIM_REPORT_VERSION:
        raise AssertionError(f"unexpected report version: {report.get('report_version')}")
    if report.get("report_kind") != "mempool_sim":
        raise AssertionError("unexpected report kind")
    if not isinstance(report.get("generated_at_utc"), str):
        raise AssertionError("missing generated_at_utc")
    if not isinstance(report.get("qbit_assumptions"), dict):
        raise AssertionError("missing qbit assumptions")
    if report.get("profile") not in {"ci-smoke", "manual-default"}:
        raise AssertionError("missing or unexpected profile")
    effective_options = report.get("effective_options")
    if not isinstance(effective_options, dict):
        raise AssertionError("missing effective_options")
    for option in ("steady_rounds", "saturation_txs"):
        if not isinstance(effective_options.get(option), int):
            raise AssertionError(f"missing effective option: {option}")
    if not isinstance(report.get("lanes"), list) or not report["lanes"]:
        raise AssertionError("missing simulation lanes")
    if not isinstance(report.get("red_flags"), list):
        raise AssertionError("missing red_flags list")

    required_lanes = {"steady-default", "constrained-saturation", "package-rbf-boundary"}
    observed_lanes = {lane.get("name") for lane in report["lanes"]}
    missing = required_lanes - observed_lanes
    if missing:
        raise AssertionError(f"missing required lanes: {sorted(missing)}")

    for lane in report["lanes"]:
        if lane.get("status") != "passed":
            raise AssertionError(f"lane did not pass: {lane.get('name')}")
        steps = lane.get("steps")
        if not isinstance(steps, list) or not steps:
            raise AssertionError(f"lane has no steps: {lane.get('name')}")
        for step in steps:
            for field in ("scenario", "expected", "actual"):
                if field not in step:
                    raise AssertionError(f"missing {field} in {lane.get('name')} step")


def json_safe(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


class MempoolSimulationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.rpc_timeout = 600
        self.extra_args = [["-persistmempool=0"]]

    def add_options(self, parser):
        parser.add_argument(
            "--ci-smoke",
            dest="ci_smoke",
            action="store_true",
            default=False,
            help="Run the bounded CI smoke profile. This is the default profile used by normal CI.",
        )
        parser.add_argument(
            "--steady-rounds",
            dest="steady_rounds",
            type=int,
            default=None,
            help="Number of steady-default rounds to run (default: 1 with --ci-smoke, otherwise 3)",
        )
        parser.add_argument(
            "--saturation-txs",
            dest="saturation_txs",
            type=int,
            default=None,
            help="Number of large transactions to attempt in constrained saturation (default: 32 with --ci-smoke, otherwise 64)",
        )
        parser.add_argument(
            "--report-file",
            dest="report_file",
            default=None,
            help="Where to write the JSON report (default: <repo>/build/reports/feature-mempool-sim-report.json)",
        )
        parser.add_argument(
            "--summary-file",
            dest="summary_file",
            default=None,
            help="Where to write the Markdown summary (default: <repo>/build/reports/feature-mempool-sim-summary.md)",
        )

    def default_report_path(self) -> Path:
        report_dir = Path(self.config["environment"]["SRCDIR"]) / "build" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / "feature-mempool-sim-report.json"

    def default_summary_path(self) -> Path:
        report_dir = Path(self.config["environment"]["SRCDIR"]) / "build" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / "feature-mempool-sim-summary.md"

    def start_lane(self, name: str, description: str) -> dict:
        lane = {
            "name": name,
            "description": description,
            "status": "running",
            "steps": [],
        }
        self.report["lanes"].append(lane)
        return lane

    def finish_lane(self, lane: dict) -> None:
        lane["status"] = "passed"

    def record_step(self, lane: dict, *, scenario: str, expected: str, actual: str, **details) -> None:
        step = {
            "scenario": scenario,
            "expected": expected,
            "actual": actual,
        }
        step.update(details)
        lane["steps"].append(step)

    def record_red_flag(self, lane: dict, scenario: str, message: str, *, ci_blocking: bool) -> None:
        self.report["red_flags"].append({
            "lane": lane["name"],
            "scenario": scenario,
            "message": message,
            "ci_blocking": ci_blocking,
        })

    def resolve_profile_options(self) -> None:
        self.profile = "ci-smoke" if self.options.ci_smoke else "manual-default"
        self.steady_rounds = self.options.steady_rounds
        self.saturation_txs = self.options.saturation_txs

        if self.steady_rounds is None:
            self.steady_rounds = CI_SMOKE_STEADY_ROUNDS if self.options.ci_smoke else MANUAL_STEADY_ROUNDS
        if self.saturation_txs is None:
            self.saturation_txs = CI_SMOKE_SATURATION_TXS if self.options.ci_smoke else MANUAL_SATURATION_TXS

        if self.steady_rounds < 1:
            raise AssertionError("--steady-rounds must be at least 1")
        if self.saturation_txs < 8:
            raise AssertionError("--saturation-txs must be at least 8")

    def snapshot_mempool(self, node) -> dict:
        info = node.getmempoolinfo()
        entries = node.getrawmempool(verbose=True)
        buckets = {
            "below_250_sat_kvb": {"count": 0, "vbytes": 0},
            "250_to_999_sat_kvb": {"count": 0, "vbytes": 0},
            "1000_to_4999_sat_kvb": {"count": 0, "vbytes": 0},
            "5000_plus_sat_kvb": {"count": 0, "vbytes": 0},
        }
        for entry in entries.values():
            vsize = int(entry["vsize"])
            fee_sat_per_kvb = int((Decimal(str(entry["fees"]["modified"])) * COIN * 1000) / vsize)
            if fee_sat_per_kvb < 250:
                bucket = "below_250_sat_kvb"
            elif fee_sat_per_kvb < 1000:
                bucket = "250_to_999_sat_kvb"
            elif fee_sat_per_kvb < 5000:
                bucket = "1000_to_4999_sat_kvb"
            else:
                bucket = "5000_plus_sat_kvb"
            buckets[bucket]["count"] += 1
            buckets[bucket]["vbytes"] += vsize

        return {
            "size": int(info["size"]),
            "bytes": int(info["bytes"]),
            "usage": int(info["usage"]),
            "maxmempool": int(info["maxmempool"]),
            "mempoolminfee_sat_per_kvb": btc_per_kvb_to_sat_per_kvb(info["mempoolminfee"]),
            "minrelaytxfee_sat_per_kvb": btc_per_kvb_to_sat_per_kvb(info["minrelaytxfee"]),
            "incrementalrelayfee_sat_per_kvb": btc_per_kvb_to_sat_per_kvb(info["incrementalrelayfee"]),
            "fee_histogram": buckets,
        }

    def tx_metadata(self, tx: CTransaction, *, fee_sat: int | None = None, package_id: str | None = None) -> dict:
        metadata = {
            "txid": tx.txid_hex,
            "wtxid": tx.wtxid_hex,
            "weight": tx.get_weight(),
            "vsize": tx.get_vsize(),
        }
        if fee_sat is not None:
            metadata["fee_sat"] = fee_sat
            metadata["feerate_sat_per_kvb"] = int(fee_sat * 1000 / tx.get_vsize())
        if package_id is not None:
            metadata["package_id"] = package_id
        return metadata

    def template_txids(self, node) -> list[str]:
        try:
            template = node.getblocktemplate({"rules": ["segwit"]})
        except JSONRPCException as e:
            self.report["warnings"].append(f"getblocktemplate unavailable: {e.error['message']}")
            return []
        return [entry["txid"] for entry in template["transactions"]]

    def advance_block_round(self, node, *, expected_txids: list[str] | None = None) -> str:
        self.mock_time += 60
        node.setmocktime(self.mock_time)
        block_hash = self.generate(node, 1, sync_fun=self.no_op)[0]
        if expected_txids:
            block_txids = node.getblock(block_hash)["tx"]
            for txid in expected_txids:
                assert txid in block_txids
        self.wallet.rescan_utxos()
        return block_hash

    def submit_allowed_tx(self, lane: dict, *, scenario: str, tx_hex: str, tx: CTransaction, fee_sat: int | None = None) -> str:
        node = self.nodes[0]
        before = self.snapshot_mempool(node)
        accept = node.testmempoolaccept([tx_hex])[0]
        if not accept["allowed"]:
            self.record_red_flag(lane, scenario, f"unexpected reject: {accept}", ci_blocking=True)
        assert_equal(accept["allowed"], True)
        txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
        after = self.snapshot_mempool(node)
        self.record_step(
            lane,
            scenario=scenario,
            expected="accepted into mempool",
            actual="accepted",
            tx=self.tx_metadata(tx, fee_sat=fee_sat),
            before=before,
            after=after,
        )
        return txid

    def create_p2mr_proxy_spend(self, *, amount: int = 250_000, fee: int = 3_000) -> tuple[CTransaction, dict]:
        leaf_script = CScript([OP_DROP, OP_TRUE])
        merkle_root = p2mr_leaf_hash(leaf_script)
        script_pub_key = CScript([OP_2, merkle_root])
        funding = self.wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=script_pub_key,
            amount=amount,
            fee=1_000,
        )
        self.advance_block_round(self.nodes[0], expected_txids=[funding["txid"]])

        utxo = {
            "txid": funding["txid"],
            "vout": funding["sent_vout"],
            "amount": amount,
        }
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(utxo["amount"] - fee, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            bytes([0x42]) * P2MR_PQC_PROXY_BYTES,
            bytes(leaf_script),
            p2mr_control_block(),
        ]
        return tx, {"funding_txid": funding["txid"], "fee_sat": fee}

    def run_steady_default(self) -> None:
        node = self.nodes[0]
        lane = self.start_lane(
            "steady-default",
            "Default-policy steady-state flow with min-relay boundaries, P2MR-sized witness data, and block inclusion.",
        )

        for round_index in range(self.steady_rounds):
            low_fee_utxo = self.wallet.get_utxo(confirmed_only=True, mark_as_spent=False)
            low_fee_tx = self.wallet.create_self_transfer(
                utxo_to_spend=low_fee_utxo,
                fee_rate=Decimal("0.00000100"),
            )
            before = self.snapshot_mempool(node)
            low_fee_res = node.testmempoolaccept([low_fee_tx["hex"]])[0]
            if low_fee_res["allowed"]:
                self.record_red_flag(lane, "below-minrelay-proxy", "below-minrelay transaction was accepted", ci_blocking=True)
            assert_equal(low_fee_res["allowed"], False)
            self.record_step(
                lane,
                scenario=f"below-minrelay-proxy-round-{round_index}",
                expected="rejected below min relay",
                actual=low_fee_res.get("reject-reason", "rejected"),
                tx=self.tx_metadata(low_fee_tx["tx"], fee_sat=int(low_fee_tx["fee"] * COIN)),
                before=before,
                after=self.snapshot_mempool(node),
            )

            normal_tx = self.wallet.create_self_transfer(
                confirmed_only=True,
                fee_rate=Decimal("0.00000300"),
            )
            normal_txid = self.submit_allowed_tx(
                lane,
                scenario=f"above-minrelay-proxy-round-{round_index}",
                tx_hex=normal_tx["hex"],
                tx=normal_tx["tx"],
                fee_sat=int(normal_tx["fee"] * COIN),
            )
            assert normal_txid in self.template_txids(node)
            block_hash = self.advance_block_round(node, expected_txids=[normal_txid])
            self.record_step(
                lane,
                scenario=f"block-inclusion-proxy-round-{round_index}",
                expected="accepted proxy tx mined in next 60-second round",
                actual="mined",
                block_hash=block_hash,
                txids=[normal_txid],
            )

        p2mr_tx, p2mr_info = self.create_p2mr_proxy_spend()
        p2mr_tx_hex = p2mr_tx.serialize().hex()
        p2mr_txid = self.submit_allowed_tx(
            lane,
            scenario="p2mr-pqc-sized-proxy-spend",
            tx_hex=p2mr_tx_hex,
            tx=p2mr_tx,
            fee_sat=p2mr_info["fee_sat"],
        )
        assert p2mr_txid in self.template_txids(node)
        block_hash = self.advance_block_round(node, expected_txids=[p2mr_txid])
        self.record_step(
            lane,
            scenario="p2mr-block-inclusion",
            expected="P2MR-sized witness spend mined in next 60-second round",
            actual="mined",
            block_hash=block_hash,
            txids=[p2mr_txid],
        )

        self.finish_lane(lane)

    def run_constrained_saturation(self) -> None:
        fanout_count = self.saturation_txs
        fanout = self.wallet.create_self_transfer_multi(
            confirmed_only=True,
            num_outputs=fanout_count,
        )
        fanout_txid = self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=fanout["hex"])
        self.advance_block_round(self.nodes[0], expected_txids=[fanout_txid])
        saturation_utxos = fanout["new_utxos"]

        self.restart_node(0, extra_args=["-persistmempool=0", f"-maxmempool={MIN_MAX_MEMPOOL_SIZE_MB}"])
        node = self.nodes[0]
        self.wallet.rescan_utxos()
        lane = self.start_lane(
            "constrained-saturation",
            "Small-mempool pressure lane that checks eviction and floating mempool minimum fee behavior.",
        )

        initial = self.snapshot_mempool(node)
        assert_equal(initial["size"], 0)
        assert_equal(initial["mempoolminfee_sat_per_kvb"], initial["minrelaytxfee_sat_per_kvb"])

        accepted_txids = []
        rejected = []
        submitted_vbytes = 0
        accepted_vbytes = 0
        for index, utxo in enumerate(saturation_utxos):
            feerate = Decimal("0.00001000") + Decimal(index) * Decimal("0.00000200")
            tx = self.wallet.create_self_transfer(
                utxo_to_spend=utxo,
                fee_rate=feerate,
                target_vsize=195_000,
            )
            tx_vbytes = tx["tx"].get_vsize()
            submitted_vbytes += tx_vbytes
            before = self.snapshot_mempool(node)
            try:
                txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=tx["hex"])
                accepted_txids.append(txid)
                accepted_vbytes += tx_vbytes
                actual = "accepted"
            except JSONRPCException as e:
                rejected.append({"txid": tx["txid"], "error": e.error["message"]})
                actual = e.error["message"]
            self.record_step(
                lane,
                scenario=f"saturation-large-tx-{index}",
                expected="accepted or policy-rejected according to current floating mempool fee",
                actual=actual,
                tx=self.tx_metadata(tx["tx"], fee_sat=int(tx["fee"] * COIN)),
                before=before,
                after=self.snapshot_mempool(node),
            )

        final = self.snapshot_mempool(node)
        eviction_expected = accepted_vbytes > initial["maxmempool"]
        eviction_observed = len(accepted_txids) > final["size"]
        if eviction_expected and not eviction_observed:
            self.record_red_flag(lane, "constrained-eviction", "small mempool did not evict any accepted large transactions", ci_blocking=True)
        if eviction_expected:
            assert_greater_than(len(accepted_txids), final["size"])
        assert_greater_than_or_equal(final["mempoolminfee_sat_per_kvb"], final["minrelaytxfee_sat_per_kvb"])
        self.record_step(
            lane,
            scenario="constrained-eviction-summary",
            expected="eviction when accepted vbytes exceed the constrained mempool cap; mempool minimum fee remains at or above min relay",
            actual="eviction observed" if eviction_observed else "eviction not expected for override",
            submitted=len(accepted_txids) + len(rejected),
            submitted_vbytes=submitted_vbytes,
            accepted=len(accepted_txids),
            accepted_vbytes=accepted_vbytes,
            eviction_expected=eviction_expected,
            eviction_observed=eviction_observed,
            rejected=rejected,
            final=final,
        )

        self.finish_lane(lane)

    def run_package_rbf_boundary(self) -> None:
        self.restart_node(0, extra_args=["-persistmempool=0"])
        node = self.nodes[0]
        self.wallet.rescan_utxos()
        lane = self.start_lane(
            "package-rbf-boundary",
            "Ancestor/package limit and RBF fee-delta boundary lane.",
        )

        assert_equal(node.getmempoolinfo()["size"], 0)
        chain = self.wallet.send_self_transfer_chain(
            from_node=node,
            chain_length=24,
            utxo_to_spend=self.wallet.get_utxo(confirmed_only=True),
        )
        package_parent = self.wallet.create_self_transfer(utxo_to_spend=chain[-1]["new_utxo"])
        package_child = self.wallet.create_self_transfer(utxo_to_spend=package_parent["new_utxo"])
        package_hex = [package_parent["hex"], package_child["hex"]]
        package_res = node.testmempoolaccept(package_hex)
        package_errors = [res.get("package-error", "") for res in package_res]
        if not all("package-mempool-limits" in error for error in package_errors):
            self.record_red_flag(lane, "ancestor-count-26-package", f"unexpected package result: {package_res}", ci_blocking=True)
        assert all("package-mempool-limits" in error for error in package_errors)
        self.record_step(
            lane,
            scenario="ancestor-count-26-package",
            expected="package rejected at 26 combined ancestors/descendants",
            actual="package-mempool-limits",
            package=[
                self.tx_metadata(package_parent["tx"], package_id="ancestor-count-26"),
                self.tx_metadata(package_child["tx"], package_id="ancestor-count-26"),
            ],
            result=package_res,
            snapshot=self.snapshot_mempool(node),
        )

        self.advance_block_round(node, expected_txids=[entry["txid"] for entry in chain])
        package_after_mine = node.testmempoolaccept(package_hex)
        if not all(res["allowed"] for res in package_after_mine):
            self.record_red_flag(lane, "ancestor-package-after-mining", f"package did not pass after clearing mempool: {package_after_mine}", ci_blocking=True)
        assert all(res["allowed"] for res in package_after_mine)
        self.record_step(
            lane,
            scenario="ancestor-package-after-mining",
            expected="same package accepted once in-mempool ancestors are mined",
            actual="accepted by testmempoolaccept",
            result=package_after_mine,
        )

        rbf_coin = self.wallet.get_utxo(confirmed_only=True)
        original = self.wallet.create_self_transfer(
            utxo_to_spend=rbf_coin,
            fee=Decimal("0.00001000"),
            sequence=MAX_BIP125_RBF_SEQUENCE - 2,
        )
        original_txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=original["hex"])
        replacement_low = self.wallet.create_self_transfer(
            utxo_to_spend=rbf_coin,
            fee=Decimal("0.00001000"),
            sequence=MAX_BIP125_RBF_SEQUENCE - 3,
        )
        low_res = node.testmempoolaccept([replacement_low["hex"]])[0]
        if low_res["allowed"]:
            self.record_red_flag(lane, "rbf-insufficient-delta", "replacement without incremental fee was accepted", ci_blocking=True)
        assert_equal(low_res["allowed"], False)
        self.record_step(
            lane,
            scenario="rbf-insufficient-delta",
            expected="same-fee replacement rejected",
            actual=low_res.get("reject-reason", "rejected"),
            original=self.tx_metadata(original["tx"], fee_sat=int(original["fee"] * COIN)),
            replacement=self.tx_metadata(replacement_low["tx"], fee_sat=int(replacement_low["fee"] * COIN)),
            result=low_res,
        )

        replacement_high = self.wallet.create_self_transfer(
            utxo_to_spend=rbf_coin,
            fee=Decimal("0.00005000"),
            sequence=MAX_BIP125_RBF_SEQUENCE - 4,
        )
        replacement_txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=replacement_high["hex"])
        mempool = node.getrawmempool()
        assert replacement_txid in mempool
        assert original_txid not in mempool
        self.record_step(
            lane,
            scenario="rbf-sufficient-delta",
            expected="higher-fee replacement accepted and original removed",
            actual="replacement accepted",
            original_txid=original_txid,
            replacement=self.tx_metadata(replacement_high["tx"], fee_sat=int(replacement_high["fee"] * COIN)),
            snapshot=self.snapshot_mempool(node),
        )

        self.finish_lane(lane)

    def write_reports(self) -> None:
        report = json_safe(self.report)
        validate_mempool_sim_report_schema(report)
        report_path = Path(self.options.report_file).expanduser() if self.options.report_file else self.default_report_path()
        summary_path = Path(self.options.summary_file).expanduser() if self.options.summary_file else self.default_summary_path()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        lines = [
            "# qbit mempool simulation",
            "",
            f"- generated_at_utc: `{report['generated_at_utc']}`",
            f"- ci_smoke: `{report['ci_smoke']}`",
            f"- profile: `{report['profile']}`",
            f"- steady_rounds: `{report['effective_options']['steady_rounds']}`",
            f"- saturation_txs: `{report['effective_options']['saturation_txs']}`",
            f"- red_flags: `{len(report['red_flags'])}`",
            "",
            "## Lanes",
            "",
        ]
        for lane in report["lanes"]:
            lines.append(f"- `{lane['name']}`: {lane['status']} ({len(lane['steps'])} steps)")
        lines.extend(["", "## qbit assumptions", ""])
        for key, value in report["qbit_assumptions"].items():
            lines.append(f"- `{key}`: `{value}`")
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.log.info("Wrote mempool simulation report to %s", report_path)
        self.log.info("Wrote mempool simulation summary to %s", summary_path)

    def run_test(self):
        self.resolve_profile_options()

        node = self.nodes[0]
        self.mock_time = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(self.mock_time)
        self.wallet = MiniWallet(node)
        self.wallet.ensure_spendable_utxos(min_spendable=25, mature_coinbase_count=25)
        self.wallet.rescan_utxos()

        self.report = {
            "report_version": MEMPOOL_SIM_REPORT_VERSION,
            "report_kind": "mempool_sim",
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "ci_smoke": bool(self.options.ci_smoke),
            "profile": self.profile,
            "effective_options": {
                "steady_rounds": self.steady_rounds,
                "saturation_txs": self.saturation_txs,
            },
            "qbit_assumptions": QBIT_MEMPOOL_ASSUMPTIONS,
            "lanes": [],
            "red_flags": [],
            "warnings": [],
        }

        self.run_steady_default()
        self.run_constrained_saturation()
        self.run_package_rbf_boundary()

        ci_blocking_red_flags = [flag for flag in self.report["red_flags"] if flag["ci_blocking"]]
        assert_equal(ci_blocking_red_flags, [])
        self.write_reports()


if __name__ == "__main__":
    MempoolSimulationTest(__file__).main()
