#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Report-only RPC benchmark harness for qbit and a Bitcoin Core v30.2 reference."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from http import HTTPStatus
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time
from typing import Any

from test_framework.auxpow import make_valid_auxpow_from_template
from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet, getnewdestination


QBIT_TARGET = "qbit"
REFERENCE_TARGET = "reference"
DEFAULT_REFERENCE_LABEL = "bitcoin-core-v30.2"
DEFAULT_MODES = ("cold", "warm")
WALLET_READY_MATURE_OUTPUTS = 32
ALLOWED_TARGETS = {QBIT_TARGET, REFERENCE_TARGET}
ALLOWED_COMPARISON_MODES = {"latency_only", "none", "qbit_baseline_only"}
ALLOWED_FIXTURE_RESET_MODES = {
    "none",
    "restart_node",
    "rebuild_fixture",
    "prepare_each_sample",
    "fresh_wallet_each_sample",
    "fresh_mempool_each_sample",
    "fresh_node_each_sample",
    "prepared_tx_each_sample",
    "temporary_file_each_sample",
}
COLD_FIXTURE_RESET_MODES = {
    "none",
    "restart_node",
    "rebuild_fixture",
    "prepare_each_sample",
}

LANE_POLICIES = {
    "shared_deterministic_read_only": (
        "Compare latency and success/error class only. Record response shape metadata, "
        "but do not require strict JSON equality."
    ),
    "shared_stateful_mutating": (
        "Use explicit fixture resets and compare latency/error classes only. Do not require "
        "strict JSON equality across targets."
    ),
    "shared_name_qbit_modified": (
        "Treat latency as comparable, but document qbit-specific semantics separately and do not "
        "require strict JSON equality."
    ),
    "qbit_only_public": (
        "Track qbit baselines independently. No upstream comparison is attempted."
    ),
}


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    description: str
    endpoint: str
    fixture: str
    lane: str
    call_builder: str
    target_support: tuple[str, ...]
    modes: dict[str, int]
    comparison_mode: str
    fixture_reset_mode: str
    params: tuple[Any, ...] = ()


@dataclass(frozen=True)
class FixturePlan:
    key: str
    fixture: str
    target: str
    node_count: int
    extra_args: tuple[str, ...]
    bin_dir: str | None = None


@dataclass
class FixtureContext:
    plan: FixturePlan
    node_indexes: tuple[int, ...]
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.plan.key


def parse_rpc_help(help_output: str) -> list[str]:
    commands = set()
    for line in help_output.splitlines():
        line = line.strip()
        if line and not line.startswith("="):
            commands.add(line.split()[0])
    return sorted(commands)


def percentile(samples: list[float], target: float) -> float:
    if not samples:
        raise AssertionError("percentile() requires at least one sample")
    if len(samples) == 1:
        return samples[0]
    ordered = sorted(samples)
    position = (len(ordered) - 1) * (target / 100.0)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def round_float(value: float) -> float:
    return round(value, 6)


def round_bytes(value: float) -> int:
    return int(round(value))


class RPCPerfTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument(
            "--manifest-file",
            dest="manifest_file",
            default=str(Path(__file__).resolve().parent / "data" / "rpc_perf_manifest.json"),
            help="Path to the RPC benchmark manifest (default: %(default)s)",
        )
        parser.add_argument(
            "--benchmark-filter",
            dest="benchmark_filter",
            default=None,
            help="Regular expression used to select benchmark ids (default: all)",
        )
        parser.add_argument(
            "--run-scale",
            dest="run_scale",
            type=float,
            default=1.0,
            help="Scale manifest run counts by this factor (default: %(default)s)",
        )
        parser.add_argument(
            "--reference-bin-dir",
            dest="reference_bin_dir",
            default=None,
            help="Directory containing Bitcoin Core v30.2 reference binaries (bitcoind, bitcoin-cli, ...)",
        )
        parser.add_argument(
            "--reference-srcdir",
            dest="reference_srcdir",
            default=None,
            help="Optional source tree for the reference target; used to capture branch/commit metadata",
        )
        parser.add_argument(
            "--reference-label",
            dest="reference_label",
            default=DEFAULT_REFERENCE_LABEL,
            help="Label to use for the reference target in reports (default: %(default)s)",
        )
        parser.add_argument(
            "--no-reference",
            dest="no_reference",
            default=False,
            action="store_true",
            help="Run qbit-only benchmarks even if --reference-bin-dir is supplied",
        )
        parser.add_argument(
            "--report-file",
            dest="report_file",
            default=None,
            help="Where to write the JSON report (default: <repo>/build/reports/feature-rpc-perf-report.json)",
        )
        parser.add_argument(
            "--summary-file",
            dest="summary_file",
            default=None,
            help="Where to write the Markdown summary (default: <repo>/build/reports/feature-rpc-perf-summary.md)",
        )
        parser.add_argument(
            "--inventory-file",
            dest="inventory_file",
            default=None,
            help="Optional path for a standalone JSON inventory dump",
        )
        parser.add_argument(
            "--coverage-file",
            dest="coverage_file",
            default=None,
            help="Optional path for a standalone JSON coverage report",
        )

    def set_test_params(self):
        self.setup_clean_chain = True
        self.supports_cli = False
        self.rpc_timeout = 600
        self.uses_wallet = None

        if self.options.run_scale <= 0:
            raise AssertionError("--run-scale must be positive")

        self.manifest_path = Path(self.options.manifest_file).expanduser().resolve()
        self.manifest = self.load_manifest(self.manifest_path)
        self.selected_benchmarks = self.select_benchmarks(self.manifest["benchmarks"])
        self.reference_enabled = bool(self.options.reference_bin_dir) and not self.options.no_reference
        self.active_targets = {QBIT_TARGET}
        if self.reference_enabled:
            self.active_targets.add(REFERENCE_TARGET)

        self.fixture_contexts = self.plan_fixture_contexts()
        self.fixture_by_key = {ctx.key: ctx for ctx in self.fixture_contexts}

        self.num_nodes = sum(len(ctx.node_indexes) for ctx in self.fixture_contexts)
        self.extra_args = [[] for _ in range(self.num_nodes)]
        self.extra_init = [{} for _ in range(self.num_nodes)]
        for context in self.fixture_contexts:
            for node_index in context.node_indexes:
                self.extra_args[node_index] = list(context.plan.extra_args)
                node_init = {}
                if context.plan.bin_dir is not None:
                    node_init["binaries"] = self.get_binaries(context.plan.bin_dir)
                if context.plan.target == REFERENCE_TARGET:
                    node_init["supports_p2mronly"] = False
                if node_init:
                    self.extra_init[node_index] = node_init

    def setup_network(self):
        self.setup_nodes()

    def load_manifest(self, manifest_path: Path) -> dict[str, Any]:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("manifest_version") != 1:
            raise AssertionError(f"Unsupported manifest version in {manifest_path}")

        fixtures = manifest.get("fixtures")
        benchmarks = manifest.get("benchmarks")
        if not isinstance(fixtures, dict) or not isinstance(benchmarks, list):
            raise AssertionError(f"Malformed manifest in {manifest_path}")

        benchmark_ids = set()
        parsed_benchmarks = []
        for raw_benchmark in benchmarks:
            benchmark_id = raw_benchmark["id"]
            if benchmark_id in benchmark_ids:
                raise AssertionError(f"Duplicate benchmark id {benchmark_id}")
            benchmark_ids.add(benchmark_id)

            lane = raw_benchmark["lane"]
            if lane not in LANE_POLICIES:
                raise AssertionError(f"Unsupported lane {lane} in benchmark {benchmark_id}")

            fixture = raw_benchmark["fixture"]
            if fixture not in fixtures:
                raise AssertionError(f"Unknown fixture {fixture} in benchmark {benchmark_id}")

            call_builder = raw_benchmark["call_builder"]
            if not hasattr(self, f"build_{call_builder}"):
                raise AssertionError(f"Unknown call builder {call_builder} in benchmark {benchmark_id}")

            target_support = tuple(raw_benchmark["target_support"])
            unknown_targets = sorted(set(target_support) - ALLOWED_TARGETS)
            if unknown_targets:
                raise AssertionError(f"Unsupported targets {unknown_targets} in benchmark {benchmark_id}")

            modes = dict(raw_benchmark["modes"])
            unknown_modes = sorted(set(modes) - set(DEFAULT_MODES))
            if unknown_modes:
                raise AssertionError(f"Unsupported modes {unknown_modes} in benchmark {benchmark_id}")
            for mode, run_count in modes.items():
                if not isinstance(run_count, int) or run_count < 0:
                    raise AssertionError(f"Invalid run count for {benchmark_id} mode {mode}: {run_count}")

            comparison_mode = raw_benchmark["comparison_mode"]
            if comparison_mode not in ALLOWED_COMPARISON_MODES:
                raise AssertionError(f"Unsupported comparison mode {comparison_mode} in benchmark {benchmark_id}")

            fixture_reset_mode = raw_benchmark["fixture_reset_mode"]
            if fixture_reset_mode not in ALLOWED_FIXTURE_RESET_MODES:
                raise AssertionError(f"Unsupported fixture reset mode {fixture_reset_mode} in benchmark {benchmark_id}")
            if modes.get("cold", 0) > 0 and fixture_reset_mode not in COLD_FIXTURE_RESET_MODES:
                raise AssertionError(
                    f"Fixture reset mode {fixture_reset_mode} cannot run cold samples in benchmark {benchmark_id}"
                )

            parsed_benchmarks.append(
                BenchmarkCase(
                    id=benchmark_id,
                    description=raw_benchmark["description"],
                    endpoint=raw_benchmark["endpoint"],
                    fixture=fixture,
                    lane=lane,
                    call_builder=call_builder,
                    target_support=target_support,
                    modes=modes,
                    comparison_mode=comparison_mode,
                    fixture_reset_mode=fixture_reset_mode,
                    params=tuple(raw_benchmark.get("params", ())),
                )
            )

        manifest["benchmarks"] = parsed_benchmarks
        return manifest

    def select_benchmarks(self, benchmarks: list[BenchmarkCase]) -> list[BenchmarkCase]:
        if self.options.benchmark_filter is None:
            selected = list(benchmarks)
        else:
            matcher = re.compile(self.options.benchmark_filter)
            selected = [benchmark for benchmark in benchmarks if matcher.search(benchmark.id)]
        if not selected:
            raise AssertionError("No benchmarks selected")
        return selected

    def plan_fixture_contexts(self) -> list[FixtureContext]:
        required_fixture_keys = set()
        for benchmark in self.selected_benchmarks:
            for target in benchmark.target_support:
                if target in self.active_targets:
                    required_fixture_keys.add((target, benchmark.fixture))

        fixture_order = [
            (QBIT_TARGET, "orphan_window"),
            (QBIT_TARGET, "shared_chain"),
            (QBIT_TARGET, "wallet_ready"),
            (QBIT_TARGET, "auxpow_ready"),
            (REFERENCE_TARGET, "shared_chain"),
            (REFERENCE_TARGET, "wallet_ready"),
        ]
        fixture_catalog = {
            (QBIT_TARGET, "orphan_window"): FixturePlan(
                key=f"{QBIT_TARGET}:orphan_window",
                fixture="orphan_window",
                target=QBIT_TARGET,
                node_count=4,
                extra_args=("-dnsseed=0", "-fixedseeds=0"),
            ),
            (QBIT_TARGET, "shared_chain"): FixturePlan(
                key=f"{QBIT_TARGET}:shared_chain",
                fixture="shared_chain",
                target=QBIT_TARGET,
                node_count=1,
                extra_args=("-maxconnections=0", "-dnsseed=0", "-fixedseeds=0"),
            ),
            (QBIT_TARGET, "auxpow_ready"): FixturePlan(
                key=f"{QBIT_TARGET}:auxpow_ready",
                fixture="auxpow_ready",
                target=QBIT_TARGET,
                node_count=1,
                extra_args=("-asert", "-maxconnections=0", "-dnsseed=0", "-fixedseeds=0"),
            ),
            (QBIT_TARGET, "wallet_ready"): FixturePlan(
                key=f"{QBIT_TARGET}:wallet_ready",
                fixture="wallet_ready",
                target=QBIT_TARGET,
                node_count=1,
                extra_args=("-maxconnections=0", "-dnsseed=0", "-fixedseeds=0", "-deprecatedrpc=settxfee"),
            ),
            (REFERENCE_TARGET, "shared_chain"): FixturePlan(
                key=f"{REFERENCE_TARGET}:shared_chain",
                fixture="shared_chain",
                target=REFERENCE_TARGET,
                node_count=1,
                # The qbit functional framework writes qbit.conf; pass it explicitly so
                # upstream bitcoind uses the same regtest/RPC settings instead of
                # falling back to bitcoin.conf defaults.
                extra_args=("-conf=qbit.conf", "-maxconnections=0", "-dnsseed=0", "-fixedseeds=0"),
                bin_dir=None if self.options.reference_bin_dir is None else str(Path(self.options.reference_bin_dir).expanduser().resolve()),
            ),
            (REFERENCE_TARGET, "wallet_ready"): FixturePlan(
                key=f"{REFERENCE_TARGET}:wallet_ready",
                fixture="wallet_ready",
                target=REFERENCE_TARGET,
                node_count=1,
                extra_args=("-conf=qbit.conf", "-maxconnections=0", "-dnsseed=0", "-fixedseeds=0", "-deprecatedrpc=settxfee"),
                bin_dir=None if self.options.reference_bin_dir is None else str(Path(self.options.reference_bin_dir).expanduser().resolve()),
            ),
        }

        next_index = 0
        contexts = []
        for fixture_key in fixture_order:
            if fixture_key not in required_fixture_keys:
                continue
            plan = fixture_catalog[fixture_key]
            node_indexes = tuple(range(next_index, next_index + plan.node_count))
            contexts.append(FixtureContext(plan=plan, node_indexes=node_indexes))
            next_index += plan.node_count

        if not contexts:
            raise AssertionError("No fixture contexts planned")
        return contexts

    def scaled_run_count(self, configured_runs: int) -> int:
        if configured_runs <= 0:
            return 0
        scaled = int(round(configured_runs * self.options.run_scale))
        return max(1, scaled)

    def default_report_path(self) -> Path:
        report_dir = Path(self.config["environment"]["SRCDIR"]) / "build" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / "feature-rpc-perf-report.json"

    def default_summary_path(self) -> Path:
        report_dir = Path(self.config["environment"]["SRCDIR"]) / "build" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / "feature-rpc-perf-summary.md"

    def node_group(self, context: FixtureContext) -> list[Any]:
        return [self.nodes[index] for index in context.node_indexes]

    def primary_node(self, context: FixtureContext) -> Any:
        return self.nodes[context.node_indexes[0]]

    def prepare_fixture_context(self, context: FixtureContext):
        self.log.info(f"Prepare fixture {context.plan.key}")
        getattr(self, f"prepare_{context.plan.fixture}")(context)

    def prepare_shared_chain(self, context: FixtureContext):
        node = self.primary_node(context)
        wallet = MiniWallet(node)
        wallet.generate(COINBASE_MATURITY + 2)
        for _ in range(3):
            wallet.send_self_transfer(from_node=node)
            wallet.generate(1)
        wallet.rescan_utxos()

        confirmed_tx = wallet.send_self_transfer(from_node=node)
        confirmed_block_hash = wallet.generate(1)[0]
        confirmed_txid = confirmed_tx["txid"]
        confirmed_verbose_tx = node.getrawtransaction(confirmed_txid, True, confirmed_block_hash)
        confirmed_utxo = wallet.get_utxo(txid=confirmed_txid, mark_as_spent=False)
        txout_proof = node.gettxoutproof([confirmed_txid], confirmed_block_hash)

        mempool_tx = wallet.send_self_transfer(from_node=node)
        mempool_verbose_tx = node.getrawtransaction(mempool_tx["txid"], True)
        mempool_spent_prevouts = [
            {
                "txid": mempool_verbose_tx["vin"][0]["txid"],
                "vout": mempool_verbose_tx["vin"][0]["vout"],
            }
        ]
        wallet.rescan_utxos()

        sample_height = node.getblockcount() - 1
        context.state.update(
            {
                "mini_wallet": wallet,
                "confirmed_txid": confirmed_txid,
                "confirmed_block_hash": confirmed_block_hash,
                "confirmed_tx_hex": confirmed_verbose_tx["hex"],
                "confirmed_utxo": confirmed_utxo,
                "txout_proof": txout_proof,
                "mempool_txid": mempool_tx["txid"],
                "mempool_tx_hex": mempool_tx["hex"],
                "mempool_spent_prevouts": mempool_spent_prevouts,
                "sample_height": sample_height,
                "sample_hash": node.getblockhash(sample_height),
                "tip_height": node.getblockcount(),
            }
        )

    def connect_fixture_chain(self, context: FixtureContext):
        indexes = context.node_indexes
        for left, right in zip(indexes[1:], indexes[:-1]):
            self.connect_nodes(left, right)

    def split_fixture_chain(self, context: FixtureContext):
        indexes = context.node_indexes
        self.disconnect_nodes(indexes[1], indexes[2])
        self.sync_all([self.nodes[indexes[0]], self.nodes[indexes[1]]])
        self.sync_all([self.nodes[indexes[2]], self.nodes[indexes[3]]])

    def join_fixture_chain(self, context: FixtureContext):
        indexes = context.node_indexes
        self.connect_nodes(indexes[1], indexes[2])
        self.sync_all(self.node_group(context))

    def prepare_orphan_window(self, context: FixtureContext):
        nodes = self.node_group(context)
        self.connect_fixture_chain(context)
        self.generate(nodes[0], 200, sync_fun=lambda: self.sync_all(nodes))
        self.split_fixture_chain(context)
        self.generate(nodes[0], 1, sync_fun=lambda: self.sync_all(nodes[:2]))
        self.generate(nodes[2], 2, sync_fun=lambda: self.sync_all(nodes[2:]))
        self.join_fixture_chain(context)

    def prepare_auxpow_ready(self, context: FixtureContext):
        node = self.primary_node(context)
        wallet = MiniWallet(node)
        wallet.generate(COINBASE_MATURITY + 1)
        _, _, payout_address = getnewdestination("bech32")
        context.state.update(
            {
                "payout_address": payout_address,
                "mock_time": node.getblockheader(node.getbestblockhash())["time"],
            }
        )

    def prepare_wallet_ready(self, context: FixtureContext):
        node = self.primary_node(context)
        wallet_name = f"rpc_perf_{context.plan.target}"
        node.createwallet(wallet_name=wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)
        mining_address = wallet.getnewaddress()
        node.generatetoaddress(COINBASE_MATURITY + WALLET_READY_MATURE_OUTPUTS, mining_address, called_by_framework=True)

        receive_label = "rpc-perf-receive"
        receive_address = wallet.getnewaddress(receive_label)
        receive_script_pubkey = wallet.getaddressinfo(receive_address)["scriptPubKey"]
        raw_tx = wallet.createrawtransaction([], [{receive_address: Decimal("0.10000000")}])
        funded_tx = wallet.fundrawtransaction(raw_tx)
        psbt = wallet.walletcreatefundedpsbt([], [{receive_address: Decimal("0.10000000")}])["psbt"]
        lock_utxo = wallet.listunspent()[0]
        lock_output = {"txid": lock_utxo["txid"], "vout": lock_utxo["vout"]}
        wallet.lockunspent(False, [lock_output])

        context.state.update(
            {
                "wallet_name": wallet_name,
                "wallet_rpc": wallet,
                "receive_label": receive_label,
                "receive_address": receive_address,
                "receive_script_pubkey": receive_script_pubkey,
                "raw_tx": raw_tx,
                "funded_tx": funded_tx["hex"],
                "psbt": psbt,
                "lockunspent_output": lock_output,
                "createwallet_counter": 0,
            }
        )

        if context.plan.target == QBIT_TARGET:
            for _ in range(12):
                wallet.getnewaddress()
            for _ in range(4):
                wallet.getrawchangeaddress()
            exported = wallet.exportpubkeydb()
            watch_name = "rpc_perf_pubkeydb_watch"
            node.createwallet(wallet_name=watch_name, blank=True, disable_private_keys=True)
            watch_wallet = node.get_wallet_rpc(watch_name)
            watch_wallet.importpubkeydb(exported["pubkeys"], False, 0)
            context.state.update(
                {
                    "exported_pubkeydb": exported["pubkeys"],
                    "watch_wallet_name": watch_name,
                    "watch_wallet_rpc": watch_wallet,
                    "importpubkeydb_counter": 0,
                }
            )
        self.wait_pqc_key_validation_ready(wallet)

    def reset_fixture_for_cold_sample(self, benchmark: BenchmarkCase, context: FixtureContext):
        if benchmark.fixture_reset_mode == "restart_node":
            for node_index in context.node_indexes:
                self.restart_node(node_index)
            if context.plan.fixture == "auxpow_ready":
                context.state["mock_time"] = self.primary_node(context).getblockheader(
                    self.primary_node(context).getbestblockhash()
                )["time"]
        elif benchmark.fixture_reset_mode == "rebuild_fixture":
            for node_index in context.node_indexes:
                self.restart_node(node_index)
            context.state.clear()
            self.prepare_fixture_context(context)
        elif benchmark.fixture_reset_mode == "none":
            return
        elif benchmark.fixture_reset_mode == "prepare_each_sample":
            return
        else:
            raise AssertionError(f"Unsupported fixture reset mode {benchmark.fixture_reset_mode}")

    def collect_inventory(self) -> dict[str, Any]:
        target_nodes: dict[str, Any] = {}
        for context in self.fixture_contexts:
            target_nodes.setdefault(context.plan.target, self.primary_node(context))

        qbit_commands = parse_rpc_help(target_nodes[QBIT_TARGET].help())
        reference_commands = []
        if REFERENCE_TARGET in target_nodes:
            reference_commands = parse_rpc_help(target_nodes[REFERENCE_TARGET].help())

        manifest_endpoints = sorted({benchmark.endpoint for benchmark in self.manifest["benchmarks"]})
        inventory = {
            "source": "help()",
            "manifest_endpoints": manifest_endpoints,
            "qbit_commands": qbit_commands,
            "unbenchmarked_qbit_commands": sorted(set(qbit_commands) - set(manifest_endpoints)),
        }
        if reference_commands:
            qbit_set = set(qbit_commands)
            reference_set = set(reference_commands)
            inventory.update(
                {
                    "reference_commands": reference_commands,
                    "shared_commands": sorted(qbit_set & reference_set),
                    "qbit_only_commands": sorted(qbit_set - reference_set),
                    "reference_only_commands": sorted(reference_set - qbit_set),
                    "shared_commands_missing_from_manifest": sorted((qbit_set & reference_set) - set(manifest_endpoints)),
                }
            )
        return inventory

    def build_coverage_report(self, inventory: dict[str, Any]) -> dict[str, Any]:
        qbit_commands = set(inventory["qbit_commands"])
        manifest_endpoints = set(inventory["manifest_endpoints"])
        benchmarked = sorted(qbit_commands & manifest_endpoints)
        planned = sorted(qbit_commands - manifest_endpoints)

        lane_by_endpoint: dict[str, set[str]] = {}
        for benchmark in self.manifest["benchmarks"]:
            lane_by_endpoint.setdefault(benchmark.endpoint, set()).add(benchmark.lane)

        command_rows = []
        for command in sorted(qbit_commands):
            lanes = sorted(lane_by_endpoint.get(command, []))
            if command in manifest_endpoints:
                status = "benchmarked"
                reason = "covered by rpc_perf_manifest.json"
            else:
                status = "planned"
                reason = "public RPC endpoint not benchmarked yet; tracked for a future coverage expansion"
            command_rows.append(
                {
                    "command": command,
                    "status": status,
                    "lanes": lanes,
                    "reason": reason,
                }
            )

        report = {
            "schema_version": 1,
            "source": inventory["source"],
            "total_qbit_commands": len(qbit_commands),
            "benchmarked_commands": benchmarked,
            "planned_commands": planned,
            "unclassified_commands": [],
            "lane_endpoint_counts": {
                lane: len(
                    {
                        benchmark.endpoint
                        for benchmark in self.manifest["benchmarks"]
                        if benchmark.lane == lane
                    }
                )
                for lane in sorted(LANE_POLICIES)
            },
            "commands": command_rows,
        }
        if "qbit_only_commands" in inventory:
            qbit_only = set(inventory["qbit_only_commands"])
            shared = set(inventory["shared_commands"])
            report.update(
                {
                    "qbit_only_commands": sorted(qbit_only),
                    "benchmarked_qbit_only_commands": sorted(qbit_only & manifest_endpoints),
                    "planned_qbit_only_commands": sorted(qbit_only - manifest_endpoints),
                    "shared_commands": sorted(shared),
                    "benchmarked_shared_commands": sorted(shared & manifest_endpoints),
                    "planned_shared_commands": sorted(shared - manifest_endpoints),
                }
            )
        return report

    def write_json_file(self, path_value: str | Path, payload: dict[str, Any]):
        path = Path(path_value).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.log.info(f"Wrote JSON artifact to {path}")
        return path

    def discover_source_dir(self, configured_path: str | None, bin_dir: str | None) -> str | None:
        if configured_path is not None:
            return str(Path(configured_path).expanduser().resolve())

        if bin_dir is None:
            return None

        candidate = Path(bin_dir).expanduser().resolve()
        for path in [candidate] + list(candidate.parents):
            if (path / ".git").exists():
                return str(path)
        return None

    def read_git_value(self, source_dir: str, args: list[str]) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", source_dir] + args,
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None
        value = result.stdout.strip()
        return value or None

    def read_binary_version(self, binary_path: str) -> str | None:
        try:
            result = subprocess.run(
                [binary_path, "-version"],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None
        first_line = result.stdout.splitlines()[0] if result.stdout else ""
        return first_line or None

    def build_target_metadata(self) -> list[dict[str, Any]]:
        metadata = []
        qbit_source_dir = self.config["environment"]["SRCDIR"]
        qbit_binary = self.primary_node(self.fixture_by_key[next(key for key in self.fixture_by_key if key.startswith(f"{QBIT_TARGET}:"))]).binaries.node_argv()[0]
        metadata.append(
            {
                "target": QBIT_TARGET,
                "label": self.read_git_value(qbit_source_dir, ["rev-parse", "--abbrev-ref", "HEAD"]) or "qbit",
                "source_dir": qbit_source_dir,
                "branch": self.read_git_value(qbit_source_dir, ["rev-parse", "--abbrev-ref", "HEAD"]),
                "commit": self.read_git_value(qbit_source_dir, ["rev-parse", "HEAD"]),
                "describe": self.read_git_value(qbit_source_dir, ["describe", "--always", "--dirty"]),
                "binary_path": qbit_binary,
                "binary_version": self.read_binary_version(qbit_binary),
            }
        )

        if self.reference_enabled:
            context = next(
                (ctx for key, ctx in self.fixture_by_key.items() if key.startswith(f"{REFERENCE_TARGET}:")),
                None,
            )
            if context is not None:
                reference_source = self.discover_source_dir(
                    self.options.reference_srcdir,
                    context.plan.bin_dir,
                )
                reference_binary = self.primary_node(context).binaries.node_argv()[0]
                metadata.append(
                    {
                        "target": REFERENCE_TARGET,
                        "label": self.options.reference_label,
                        "source_dir": reference_source,
                        "branch": None if reference_source is None else self.read_git_value(reference_source, ["rev-parse", "--abbrev-ref", "HEAD"]),
                        "commit": None if reference_source is None else self.read_git_value(reference_source, ["rev-parse", "HEAD"]),
                        "describe": None if reference_source is None else self.read_git_value(reference_source, ["describe", "--always", "--dirty"]),
                        "binary_path": reference_binary,
                        "binary_version": self.read_binary_version(reference_binary),
                    }
                )
        return metadata

    def serialize_json(self, proxy: Any, payload: Any) -> str:
        return proxy.auth_service_proxy_instance._json_dumps(payload)

    def rpc_request_path(self, proxy: Any) -> str:
        url = proxy.auth_service_proxy_instance._AuthServiceProxy__url
        return url.path or "/"

    def normalize_artifact_value(self, value: Any) -> Any:
        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, dict):
            return {str(key): self.normalize_artifact_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.normalize_artifact_value(item) for item in value]
        return value

    def response_shape(self, response: Any) -> dict[str, Any]:
        if not isinstance(response, dict):
            return {"response_type": type(response).__name__}
        result = response.get("result")
        shape: dict[str, Any] = {"response_type": "dict"}
        if isinstance(result, dict):
            shape["result_type"] = "dict"
            shape["result_keys"] = sorted(result.keys())
        elif isinstance(result, list):
            shape["result_type"] = "list"
            shape["result_length"] = len(result)
        else:
            shape["result_type"] = type(result).__name__
        return shape

    def measure_rpc_call(self, node: Any, method: str, params: list[Any]) -> dict[str, Any]:
        proxy = getattr(node, method)
        request = proxy.get_request(*params)
        request_json = self.serialize_json(proxy, request)
        start = time.perf_counter()
        try:
            response, http_status = proxy.auth_service_proxy_instance._request("POST", self.rpc_request_path(proxy), request_json.encode("utf-8"))
            latency_ms = (time.perf_counter() - start) * 1000.0
            error = response.get("error") if isinstance(response, dict) else None
            error_class = "success"
            if error is not None:
                error_class = f"rpc_error:{error.get('code', 'unknown')}"
            elif http_status != HTTPStatus.OK:
                error_class = f"http_error:{int(http_status)}"

            sample = {
                "latency_ms": round_float(latency_ms),
                "http_status": int(http_status),
                "success_error_class": error_class,
                "request_size_bytes": len(request_json.encode("utf-8")),
                "response_size_bytes": len(proxy.auth_service_proxy_instance._last_response_bytes),
                "response_shape": self.response_shape(response),
            }
            if error is not None:
                sample["error_message"] = error.get("message")
            return sample
        except JSONRPCException as exc:
            latency_ms = (time.perf_counter() - start) * 1000.0
            error = exc.error or {}
            return {
                "latency_ms": round_float(latency_ms),
                "http_status": int(exc.http_status) if exc.http_status is not None else None,
                "success_error_class": f"transport_error:{error.get('code', 'unknown')}",
                "request_size_bytes": len(request_json.encode("utf-8")),
                "response_size_bytes": 0,
                "response_shape": {"response_type": "transport_error"},
                "error_message": error.get("message"),
            }

    def build_call(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return getattr(self, f"build_{benchmark.call_builder}")(benchmark, context, sample_index, mode)

    def build_static_params(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return benchmark.endpoint, list(benchmark.params)

    def build_shared_getbestblockhash(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getbestblockhash", []

    def build_shared_getblockcount(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblockcount", []

    def build_shared_getblockchaininfo(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblockchaininfo", []

    def build_shared_getblockhash(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblockhash", [context.state["sample_height"]]

    def build_shared_getblockheader(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblockheader", [context.state["sample_hash"], True]

    def build_shared_getblockstats(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblockstats", [context.state["sample_height"]]

    def build_qbit_getorphanmetrics_default(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getorphanmetrics", []

    def build_qbit_getconfirmationtarget_high(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getconfirmationtarget", [100000000, "high", 0.5, 7e20]

    def next_auxpow_time(self, context: FixtureContext) -> int:
        current_time = context.state.get("mock_time")
        if current_time is None:
            current_time = self.primary_node(context).getblockheader(self.primary_node(context).getbestblockhash())["time"]
        current_time += 600
        context.state["mock_time"] = current_time
        self.primary_node(context).setmocktime(current_time)
        return current_time

    def build_qbit_createauxblock(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        self.next_auxpow_time(context)
        return "createauxblock", [context.state["payout_address"]]

    def build_qbit_submitauxblock(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        parent_time = self.next_auxpow_time(context)
        node = self.primary_node(context)
        aux_template = node.createauxblock(context.state["payout_address"])
        auxpow = make_valid_auxpow_from_template(aux_template, parent_time=parent_time)
        return "submitauxblock", [aux_template["hash"], auxpow.to_hex()]

    def build_shared_getblock_verbose(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblock", [context.state["sample_hash"], 1]

    def build_shared_getrawtransaction_mempool(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getrawtransaction", [context.state["mempool_txid"], True]

    def build_shared_gettxout_confirmed(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        utxo = context.state["confirmed_utxo"]
        return "gettxout", [utxo["txid"], utxo["vout"]]

    def build_shared_gettxoutproof_confirmed(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "gettxoutproof", [[context.state["confirmed_txid"]], context.state["confirmed_block_hash"]]

    def build_shared_verifytxoutproof_confirmed(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "verifytxoutproof", [context.state["txout_proof"]]

    def build_shared_mempool_txid(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return benchmark.endpoint, [context.state["mempool_txid"]]

    def build_shared_gettxspendingprevout(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "gettxspendingprevout", [context.state["mempool_spent_prevouts"]]

    def build_shared_testmempoolaccept(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        tx = context.state["mini_wallet"].create_self_transfer()
        return "testmempoolaccept", [[tx["hex"]]]

    def build_stateful_sendrawtransaction(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        tx = context.state["mini_wallet"].create_self_transfer()
        return "sendrawtransaction", [tx["hex"]]

    def build_stateful_prioritisetransaction(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "prioritisetransaction", [context.state["mempool_txid"], 0, sample_index + 1]

    def build_modified_getblocktemplate(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "getblocktemplate", [{"rules": ["segwit"]}]

    def build_wallet_getaddressinfo(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "getaddressinfo", [context.state["receive_address"]]

    def build_wallet_getwalletinfo(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "getwalletinfo", []

    def build_wallet_getbalance(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "getbalance", []

    def build_wallet_getbalances(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "getbalances", []

    def build_wallet_listunspent(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "listunspent", []

    def build_wallet_listtransactions(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "listtransactions", []

    def build_wallet_getaddressesbylabel(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "getaddressesbylabel", [context.state["receive_label"]]

    def build_wallet_listlabels(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "listlabels", []

    def build_wallet_listlockunspent(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "listlockunspent", []

    def build_wallet_listdescriptors(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "listdescriptors", []

    def build_wallet_createwalletdescriptor(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        descriptor_type = "p2mr" if context.plan.target == QBIT_TARGET else "bech32m"
        return context.state["wallet_rpc"], "createwalletdescriptor", [descriptor_type]

    def build_wallet_createrawtransaction(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return "createrawtransaction", [[], [{context.state["receive_address"]: Decimal("0.10000000")}]]

    def build_wallet_createpsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return "createpsbt", [[], [{context.state["receive_address"]: Decimal("0.10000000")}]]

    def build_wallet_fundrawtransaction(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "fundrawtransaction", [
            context.state["raw_tx"],
            {"changeAddress": context.state["receive_address"], "changePosition": 1},
        ]

    def build_wallet_walletcreatefundedpsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "walletcreatefundedpsbt", [
            [],
            [{context.state["receive_address"]: Decimal("0.10000000")}],
            0,
            {"changeAddress": context.state["receive_address"], "changePosition": 1},
        ]

    def build_wallet_finalizepsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "finalizepsbt", [context.state["psbt"], False]

    def build_wallet_decoderawtransaction(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "decoderawtransaction", [context.state["raw_tx"]]

    def build_wallet_decodescript(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "decodescript", [context.state["receive_script_pubkey"]]

    def build_wallet_utxoupdatepsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "utxoupdatepsbt", [context.state["psbt"]]

    def build_wallet_combinepsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "combinepsbt", [[context.state["psbt"]]]

    def build_wallet_converttopsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "converttopsbt", [context.state["raw_tx"]]

    def build_wallet_decodepsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "decodepsbt", [context.state["psbt"]]

    def build_wallet_analyzepsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "analyzepsbt", [context.state["psbt"]]

    def build_wallet_walletprocesspsbt(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "walletprocesspsbt", [context.state["psbt"], False]

    def build_wallet_signrawtransactionwithwallet(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "signrawtransactionwithwallet", [context.state["funded_tx"]]

    def build_wallet_signrawtransactionwithkey_empty(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str) -> tuple[str, list[Any]]:
        return "signrawtransactionwithkey", [context.state["raw_tx"], []]

    def build_wallet_sendtoaddress(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "sendtoaddress", [context.state["receive_address"], Decimal("0.00010000")]

    def build_wallet_sendmany(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "sendmany", ["", {context.state["receive_address"]: Decimal("0.00010000")}]

    def build_wallet_send(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "send", [
            {context.state["receive_address"]: Decimal("0.00010000")},
            None,
            "unset",
            None,
            {"add_to_wallet": False},
        ]

    def build_wallet_sendall(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        wallet = context.state["wallet_rpc"]
        utxo = wallet.listunspent()[0]
        return context.state["wallet_rpc"], "sendall", [
            [context.state["receive_address"]],
            None,
            "unset",
            None,
            {
                "add_to_wallet": False,
                "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            },
        ]

    def build_wallet_setlabel(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "setlabel", [context.state["receive_address"], f"rpc-perf-{sample_index}"]

    def build_wallet_settxfee(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "settxfee", [Decimal("0.00001000")]

    def build_wallet_lockunspent(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        wallet = context.state["wallet_rpc"]
        output = context.state["lockunspent_output"]
        wallet.lockunspent(True, [output])
        return wallet, "lockunspent", [False, [output]]

    def build_wallet_createwallet(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        context.state["createwallet_counter"] += 1
        wallet_name = f"rpc_perf_created_{context.plan.target}_{mode}_{sample_index}_{context.state['createwallet_counter']}"
        return self.primary_node(context), "createwallet", [wallet_name]

    def build_qbit_exportpubkeydb(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["wallet_rpc"], "exportpubkeydb", []

    def build_qbit_importpubkeydb(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        context.state["importpubkeydb_counter"] += 1
        wallet_name = f"rpc_perf_import_watch_{mode}_{sample_index}_{context.state['importpubkeydb_counter']}"
        self.primary_node(context).createwallet(wallet_name=wallet_name, blank=True, disable_private_keys=True)
        watch_wallet = self.primary_node(context).get_wallet_rpc(wallet_name)
        return watch_wallet, "importpubkeydb", [context.state["exported_pubkeydb"], False, 0]

    def build_qbit_getnextpubkeydbaddress(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["watch_wallet_rpc"], "getnextpubkeydbaddress", []

    def build_qbit_listpubkeydbstatus(self, benchmark: BenchmarkCase, context: FixtureContext, sample_index: int, mode: str):
        return context.state["watch_wallet_rpc"], "listpubkeydbstatus", []

    def summarize_samples(self, samples: list[dict[str, Any]]) -> dict[str, Any]:
        latencies = [sample["latency_ms"] for sample in samples]
        response_sizes = [sample["response_size_bytes"] for sample in samples]
        request_sizes = [sample["request_size_bytes"] for sample in samples]
        error_classes = sorted({sample["success_error_class"] for sample in samples})
        http_statuses = sorted(
            {sample["http_status"] for sample in samples},
            key=lambda status: (-1 if status is None else status),
        )
        shapes = []
        seen_shapes = set()
        for sample in samples:
            shape = json.dumps(sample["response_shape"], sort_keys=True)
            if shape in seen_shapes:
                continue
            seen_shapes.add(shape)
            shapes.append(sample["response_shape"])
        return {
            "run_count": len(samples),
            "median_latency_ms": round_float(percentile(latencies, 50)),
            "p95_latency_ms": round_float(percentile(latencies, 95)),
            "latency_samples_ms": latencies,
            "median_request_size_bytes": round_bytes(percentile(request_sizes, 50)),
            "median_response_size_bytes": round_bytes(percentile(response_sizes, 50)),
            "request_size_samples_bytes": request_sizes,
            "response_size_samples_bytes": response_sizes,
            "success_error_class": error_classes[0] if len(error_classes) == 1 else f"mixed:{','.join(error_classes)}",
            "http_statuses": http_statuses,
            "response_shapes": shapes,
            "samples": samples,
        }

    def run_benchmark_mode(self, benchmark: BenchmarkCase, context: FixtureContext, target: str, mode: str, run_count: int) -> dict[str, Any]:
        self.log.info(f"Benchmark {benchmark.id} [{target}] mode={mode} runs={run_count}")
        samples = []
        for sample_index in range(run_count):
            if mode == "cold":
                self.reset_fixture_for_cold_sample(benchmark, context)
            call = self.build_call(benchmark, context, sample_index, mode)
            if len(call) == 2:
                rpc_proxy = self.primary_node(context)
                method, params = call
            else:
                rpc_proxy, method, params = call
            sample = self.measure_rpc_call(rpc_proxy, method, params)
            sample["sample_index"] = sample_index
            sample["method"] = method
            sample["params"] = self.normalize_artifact_value(params)
            samples.append(sample)

        summary = self.summarize_samples(samples)
        return {
            "benchmark_id": benchmark.id,
            "description": benchmark.description,
            "endpoint": benchmark.endpoint,
            "lane": benchmark.lane,
            "target": target,
            "fixture": benchmark.fixture,
            "comparison_mode": benchmark.comparison_mode,
            "fixture_reset_mode": benchmark.fixture_reset_mode,
            "mode": mode,
            **summary,
        }

    def build_comparisons(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        keyed_results = {(result["benchmark_id"], result["mode"], result["target"]): result for result in results}
        comparisons = []
        for benchmark in self.selected_benchmarks:
            if benchmark.comparison_mode == "none":
                continue
            for mode in benchmark.modes:
                qbit_result = keyed_results.get((benchmark.id, mode, QBIT_TARGET))
                reference_result = keyed_results.get((benchmark.id, mode, REFERENCE_TARGET))
                if qbit_result is None or reference_result is None:
                    continue
                comparisons.append(
                    {
                        "benchmark_id": benchmark.id,
                        "endpoint": benchmark.endpoint,
                        "lane": benchmark.lane,
                        "mode": mode,
                        "comparison_mode": benchmark.comparison_mode,
                        "policy": LANE_POLICIES[benchmark.lane],
                        "qbit_median_latency_ms": qbit_result["median_latency_ms"],
                        "reference_median_latency_ms": reference_result["median_latency_ms"],
                        "delta_median_latency_ms": round_float(qbit_result["median_latency_ms"] - reference_result["median_latency_ms"]),
                        "median_latency_ratio": None if reference_result["median_latency_ms"] == 0 else round_float(qbit_result["median_latency_ms"] / reference_result["median_latency_ms"]),
                        "qbit_p95_latency_ms": qbit_result["p95_latency_ms"],
                        "reference_p95_latency_ms": reference_result["p95_latency_ms"],
                        "delta_p95_latency_ms": round_float(qbit_result["p95_latency_ms"] - reference_result["p95_latency_ms"]),
                        "qbit_success_error_class": qbit_result["success_error_class"],
                        "reference_success_error_class": reference_result["success_error_class"],
                        "qbit_median_response_size_bytes": qbit_result["median_response_size_bytes"],
                        "reference_median_response_size_bytes": reference_result["median_response_size_bytes"],
                    }
                )
        return comparisons

    def write_summary(self, report: dict[str, Any]) -> Path:
        if self.options.summary_file is None:
            summary_path = self.default_summary_path()
        else:
            summary_path = Path(self.options.summary_file).expanduser()
        summary_path.parent.mkdir(parents=True, exist_ok=True)

        target_rows = [
            "| target | label | branch | commit | version |",
            "| --- | --- | --- | --- | --- |",
        ]
        for target in report["targets"]:
            target_rows.append(
                f"| {target['target']} | {target['label']} | {target['branch'] or ''} | "
                f"{(target['commit'] or '')[:12]} | {target['binary_version'] or ''} |"
            )

        comparison_rows = []
        if report["comparisons"]:
            comparison_rows.extend(
                [
                    "| benchmark | mode | qbit median ms | reference median ms | delta ms | qbit p95 ms | reference p95 ms | comparison mode |",
                    "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
                ]
            )
            for comparison in report["comparisons"]:
                comparison_rows.append(
                    f"| {comparison['benchmark_id']} | {comparison['mode']} | "
                    f"{comparison['qbit_median_latency_ms']} | {comparison['reference_median_latency_ms']} | "
                    f"{comparison['delta_median_latency_ms']} | {comparison['qbit_p95_latency_ms']} | "
                    f"{comparison['reference_p95_latency_ms']} | {comparison['comparison_mode']} |"
                )

        shared_results = [result for result in report["results"] if result["lane"] != "qbit_only_public"]
        shared_rows = []
        if shared_results:
            shared_rows.extend(
                [
                    "| benchmark | target | mode | median ms | p95 ms | response bytes | class |",
                    "| --- | --- | --- | ---: | ---: | ---: | --- |",
                ]
            )
            for result in shared_results:
                shared_rows.append(
                    f"| {result['benchmark_id']} | {result['target']} | {result['mode']} | "
                    f"{result['median_latency_ms']} | {result['p95_latency_ms']} | "
                    f"{result['median_response_size_bytes']} | {result['success_error_class']} |"
                )

        qbit_only_results = [result for result in report["results"] if result["lane"] == "qbit_only_public"]
        qbit_only_rows = []
        if qbit_only_results:
            qbit_only_rows.extend(
                [
                    "| benchmark | mode | median ms | p95 ms | response bytes | class |",
                    "| --- | --- | ---: | ---: | ---: | --- |",
                ]
            )
            for result in qbit_only_results:
                qbit_only_rows.append(
                    f"| {result['benchmark_id']} | {result['mode']} | {result['median_latency_ms']} | "
                    f"{result['p95_latency_ms']} | {result['median_response_size_bytes']} | {result['success_error_class']} |"
                )

        warning_lines = [f"- {warning}" for warning in report["warnings"]] or ["- none"]

        lines = [
            "# RPC Performance Summary",
            "",
            "## Targets",
            *target_rows,
            "",
            "## Warnings",
            *warning_lines,
            "",
            "## Shared Endpoint Comparisons",
        ]
        if comparison_rows:
            lines.extend(comparison_rows)
        else:
            lines.append("No qbit/reference comparisons were recorded in this run.")

        lines.extend(
            [
                "",
                "## Shared Endpoint Baselines",
            ]
        )
        if shared_rows:
            lines.extend(shared_rows)
        else:
            lines.append("No shared endpoint baselines were recorded in this run.")

        coverage = report["coverage"]
        lines.extend(
            [
                "",
                "## Coverage",
                "| scope | count |",
                "| --- | ---: |",
                f"| qbit public commands | {coverage['total_qbit_commands']} |",
                f"| benchmarked qbit commands | {len(coverage['benchmarked_commands'])} |",
                f"| planned qbit commands | {len(coverage['planned_commands'])} |",
                f"| unclassified qbit commands | {len(coverage['unclassified_commands'])} |",
            ]
        )
        if "qbit_only_commands" in coverage:
            lines.extend(
                [
                    f"| qbit-only public commands | {len(coverage['qbit_only_commands'])} |",
                    f"| benchmarked qbit-only commands | {len(coverage['benchmarked_qbit_only_commands'])} |",
                    f"| planned qbit-only commands | {len(coverage['planned_qbit_only_commands'])} |",
                    f"| shared public commands | {len(coverage['shared_commands'])} |",
                    f"| benchmarked shared commands | {len(coverage['benchmarked_shared_commands'])} |",
                    f"| planned shared commands | {len(coverage['planned_shared_commands'])} |",
                ]
            )

        lines.extend(
            [
                "",
                "## Qbit-Only Baselines",
            ]
        )
        if qbit_only_rows:
            lines.extend(qbit_only_rows)
        else:
            lines.append("No qbit-only benchmark results were recorded in this run.")

        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.log.info(f"Wrote Markdown summary to {summary_path}")
        return summary_path

    def write_report(self, report: dict[str, Any]) -> Path:
        if self.options.report_file is None:
            report_path = self.default_report_path()
        else:
            report_path = Path(self.options.report_file).expanduser()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.log.info(f"Wrote RPC performance report to {report_path}")
        return report_path

    def run_test(self):
        warnings = []
        if not self.reference_enabled:
            warnings.append(
                "Reference target disabled; shared endpoint results were captured for qbit only. "
                "Provide --reference-bin-dir to enable qbit vs Bitcoin Core v30.2 comparisons."
            )

        for context in self.fixture_contexts:
            self.prepare_fixture_context(context)

        inventory = self.collect_inventory()
        if self.options.inventory_file is not None:
            self.write_json_file(self.options.inventory_file, inventory)
        coverage = self.build_coverage_report(inventory)
        if self.options.coverage_file is not None:
            self.write_json_file(self.options.coverage_file, coverage)

        results = []
        for benchmark in self.selected_benchmarks:
            active_targets = [target for target in benchmark.target_support if target in self.active_targets]
            if not active_targets:
                warnings.append(f"Skipped {benchmark.id}: no active targets available")
                continue

            for target in active_targets:
                context = self.fixture_by_key[f"{target}:{benchmark.fixture}"]
                for mode in DEFAULT_MODES:
                    configured_runs = benchmark.modes.get(mode, 0)
                    run_count = self.scaled_run_count(configured_runs)
                    if run_count == 0:
                        continue
                    results.append(self.run_benchmark_mode(benchmark, context, target, mode, run_count))

        comparisons = self.build_comparisons(results)
        report = {
            "report_version": 1,
            "report_kind": "rpc",
            "report_only": True,
            "manifest_path": str(self.manifest_path),
            "benchmark_filter": self.options.benchmark_filter,
            "run_scale": self.options.run_scale,
            "warnings": warnings,
            "comparison_policies": LANE_POLICIES,
            "targets": self.build_target_metadata(),
            "environment": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "hostname": platform.node(),
                "cpu_count": os.cpu_count(),
                "tmpdir": self.options.tmpdir,
            },
            "inventory": inventory,
            "coverage": coverage,
            "manifest_lane_counts": {
                lane: sum(1 for benchmark in self.selected_benchmarks if benchmark.lane == lane)
                for lane in sorted({benchmark.lane for benchmark in self.selected_benchmarks})
            },
            "results": results,
            "comparisons": comparisons,
        }
        self.write_report(report)
        self.write_summary(report)


if __name__ == "__main__":
    RPCPerfTest(__file__).main()
