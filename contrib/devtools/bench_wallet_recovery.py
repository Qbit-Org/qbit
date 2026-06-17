#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Measure descriptor-backed P2MR wallet recovery latency on a fresh regtest node.

This is a manual report-only harness. It creates a fresh datadir per trial,
builds deterministic sparse P2MR wallet history, and measures:

- signer recovery via private ranged descriptor import
- watch-only recovery via exportpubkeydb/importpubkeydb

The harness writes a CSV and Markdown summary. It does not enforce timing
thresholds and is intended for local benchmarking and baseline capture.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class RecoveryProfile:
    name: str
    description: str
    external_targets: tuple[int, ...]
    internal_targets: tuple[int, ...]

    @property
    def external_range_end(self) -> int:
        return max(self.external_targets) + 10

    @property
    def internal_range_end(self) -> int:
        return max(self.internal_targets) + 10

    @property
    def external_next_index(self) -> int:
        return max(self.external_targets) + 1

    @property
    def internal_next_index(self) -> int:
        return max(self.internal_targets) + 1


PROFILES = {
    "small_warm": RecoveryProfile(
        name="small_warm",
        description="Small sparse matrix for warm-path sanity measurements.",
        external_targets=(0, 3, 7),
        internal_targets=(0, 2, 5),
    ),
    "medium_sparse": RecoveryProfile(
        name="medium_sparse",
        description="Sparse matrix matching feature_wallet_seed_recovery.py.",
        external_targets=(0, 31, 95),
        internal_targets=(0, 17, 63),
    ),
    "large_bound": RecoveryProfile(
        name="large_bound",
        description="Larger sparse matrix representative of operator recovery usage.",
        external_targets=(0, 127, 255),
        internal_targets=(0, 63, 191),
    ),
}

SIGNER_MODES = ("plain", "encrypted")
STOP_COMMAND_TIMEOUT = 10.0


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build", help="Build directory containing qbit binaries")
    parser.add_argument("--qbitd", dest="qbitd", type=Path, help="Path to qbitd")
    parser.add_argument("--bitcoind", dest="qbitd", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--qbit-cli", dest="qbit_cli", type=Path, help="Path to qbit-cli")
    parser.add_argument("--bitcoin-cli", dest="qbit_cli", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--profiles",
        default="small_warm,medium_sparse,large_bound",
        help=f"Comma-separated profile list (choices: {', '.join(PROFILES)})",
    )
    parser.add_argument(
        "--signer-modes",
        default="plain,encrypted",
        help=f"Comma-separated signer recovery modes (choices: {', '.join(SIGNER_MODES)})",
    )
    parser.add_argument("--keypool", type=int, default=200, help="Configured node keypool size")
    parser.add_argument("--trials", type=positive_int, default=3, help="Number of fresh-datadir trials to run")
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=REPO_ROOT / "build" / "reports" / "wallet-recovery-bench.csv",
        help="Destination for the CSV report",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=REPO_ROOT / "build" / "reports" / "wallet-recovery-bench-summary.md",
        help="Destination for the Markdown summary",
    )
    parser.add_argument(
        "--keep-datadirs",
        action="store_true",
        help="Keep per-trial datadirs instead of deleting them",
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=300.0,
        help="Seconds to wait for RPC readiness and long recovery calls",
    )
    return parser.parse_args()


def resolve_binary(explicit: Path | None, build_dir: Path, name: str) -> Path:
    if explicit:
        return explicit.resolve()
    aliases = {
        "qbitd": ["qbitd", "bitcoind"],
        "qbit-cli": ["qbit-cli", "bitcoin-cli"],
    }
    candidates = [
        path
        for binary_name in aliases.get(name, [name])
        for path in (
            build_dir / "bin" / binary_name,
            build_dir / "src" / binary_name,
            REPO_ROOT / "src" / binary_name,
        )
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError(f"unable to find {name}; tried: {', '.join(str(path) for path in candidates)}")


def parse_profile_list(raw: str) -> list[RecoveryProfile]:
    names = [name.strip() for name in raw.split(",") if name.strip()]
    if not names:
        raise ValueError("at least one profile must be selected")
    unknown = [name for name in names if name not in PROFILES]
    if unknown:
        raise ValueError(f"unknown profile(s): {', '.join(unknown)}")
    return [PROFILES[name] for name in names]


def parse_signer_modes(raw: str) -> list[str]:
    modes = [mode.strip() for mode in raw.split(",") if mode.strip()]
    if not modes:
        raise ValueError("at least one signer mode must be selected")
    unknown = [mode for mode in modes if mode not in SIGNER_MODES]
    if unknown:
        raise ValueError(f"unknown signer mode(s): {', '.join(unknown)}")
    return modes


def compact_json(value) -> str:
    return json.dumps(value, separators=(",", ":"))


def run_cli(
    cli: Path,
    datadir: Path,
    *args: str,
    wallet: str | None = None,
    rpcwait: bool = False,
    timeout: float | None = None,
) -> str:
    cmd = [str(cli), f"-datadir={datadir}", "-regtest"]
    if rpcwait:
        cmd.append("-rpcwait")
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(args)
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def run_cli_json(
    cli: Path,
    datadir: Path,
    *args: str,
    wallet: str | None = None,
    rpcwait: bool = False,
    timeout: float | None = None,
):
    out = run_cli(cli, datadir, *args, wallet=wallet, rpcwait=rpcwait, timeout=timeout)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def timed(func):
    start = time.perf_counter()
    result = func()
    return time.perf_counter() - start, result


def wait_for_rpc(cli: Path, datadir: Path, timeout: float) -> None:
    start = time.perf_counter()
    while True:
        try:
            run_cli_json(cli, datadir, "getblockcount", timeout=1.0)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        if time.perf_counter() - start > timeout:
            raise TimeoutError("timed out waiting for RPC readiness")
        time.sleep(0.1)


def shutdown_node(process: subprocess.Popen, cli: Path, datadir: Path) -> None:
    try:
        run_cli(cli, datadir, "stop", rpcwait=True, timeout=STOP_COMMAND_TIMEOUT)
    except Exception:
        process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def qbt(value: Decimal) -> str:
    return format(value, ".8f")


def to_decimal(value) -> Decimal:
    return Decimal(str(value))


def get_wallet_balance(cli: Path, datadir: Path, wallet: str) -> Decimal:
    balances = run_cli_json(cli, datadir, "getbalances", wallet=wallet)
    return to_decimal(balances["mine"]["trusted"])


def get_new_address(cli: Path, datadir: Path, wallet: str) -> str:
    return run_cli_json(
        cli,
        datadir,
        "-named",
        "getnewaddress",
        'label=""',
        "address_type=p2mr",
        wallet=wallet,
    )


def get_change_address(cli: Path, datadir: Path, wallet: str) -> str:
    return run_cli_json(
        cli,
        datadir,
        "-named",
        "getrawchangeaddress",
        "address_type=p2mr",
        wallet=wallet,
    )


def assert_p2mr_address(cli: Path, datadir: Path, wallet: str, address: str, *, is_change: bool | None = None) -> dict:
    info = run_cli_json(cli, datadir, "getaddressinfo", address, wallet=wallet)
    if not info["isscript"] or not info["iswitness"] or info["witness_version"] != 2:
        raise AssertionError(f"{wallet}: {address} is not a P2MR witness v2 address")
    if len(info["witness_program"]) != 64:
        raise AssertionError(f"{wallet}: unexpected witness program length for {address}")
    decoded = run_cli_json(cli, datadir, "decodescript", info["scriptPubKey"], wallet=wallet)
    if decoded["type"] != "witness_v2_p2mr":
        raise AssertionError(f"{wallet}: {address} decodes to {decoded['type']}, expected witness_v2_p2mr")
    if is_change is not None and info["ischange"] != is_change:
        raise AssertionError(f"{wallet}: {address} ischange={info['ischange']} expected {is_change}")
    return info


def collect_sparse_addresses(
    cli: Path,
    datadir: Path,
    wallet: str,
    getter,
    wanted_indexes: tuple[int, ...],
) -> dict[int, str]:
    addresses: dict[int, str] = {}
    for index in range(max(wanted_indexes) + 1):
        address = getter(cli, datadir, wallet)
        if index in wanted_indexes:
            addresses[index] = address
    if set(addresses) != set(wanted_indexes):
        raise AssertionError(f"{wallet}: sparse address collection mismatch")
    return addresses


def get_single_utxo(cli: Path, datadir: Path, wallet: str, address: str) -> dict:
    utxos = run_cli_json(
        cli,
        datadir,
        "-named",
        "listunspent",
        "minconf=0",
        f"addresses={compact_json([address])}",
        wallet=wallet,
    )
    if len(utxos) != 1:
        raise AssertionError(f"{wallet}: expected 1 UTXO for {address}, got {len(utxos)}")
    return utxos[0]


def unspent_map(cli: Path, datadir: Path, wallet: str, addresses: list[str]) -> dict[str, list[tuple[str, int, str]]]:
    result: dict[str, list[tuple[str, int, str]]] = {}
    for address in addresses:
        utxos = run_cli_json(
            cli,
            datadir,
            "-named",
            "listunspent",
            "minconf=0",
            f"addresses={compact_json([address])}",
            wallet=wallet,
        )
        result[address] = sorted(
            (utxo["txid"], utxo["vout"], qbt(to_decimal(utxo["amount"])))
            for utxo in utxos
        )
    return result


def count_transactions_since(cli: Path, datadir: Path, wallet: str, blockhash: str, *, include_change: bool) -> int:
    result = run_cli_json(
        cli,
        datadir,
        "-named",
        "listsinceblock",
        f"blockhash={blockhash}",
        f"include_change={'true' if include_change else 'false'}",
        wallet=wallet,
    )
    return len(result["transactions"])


def create_wallet(cli: Path, datadir: Path, wallet_name: str, **kwargs) -> dict:
    args = ["-named", "createwallet", f"wallet_name={wallet_name}"]
    for key, value in kwargs.items():
        if isinstance(value, bool):
            args.append(f"{key}={'true' if value else 'false'}")
        else:
            args.append(f"{key}={value}")
    return run_cli_json(cli, datadir, *args)


def ensure_wallet_unlocked(cli: Path, datadir: Path, wallet: str, passphrase: str) -> None:
    run_cli_json(cli, datadir, "walletpassphrase", passphrase, "600", wallet=wallet)


def make_receive_amounts(targets: tuple[int, ...]) -> dict[int, Decimal]:
    return {index: Decimal("1.0") + (Decimal(i) / Decimal("10")) for i, index in enumerate(targets)}


def make_spend_source_amounts(count: int) -> list[Decimal]:
    return [Decimal("2.0") + (Decimal(i) / Decimal("10")) for i in range(count)]


def make_change_spend_amounts(targets: tuple[int, ...]) -> dict[int, Decimal]:
    return {index: Decimal("0.5") + (Decimal(i) / Decimal("10")) for i, index in enumerate(targets)}


def pqc_ranged_desc(cli: Path, datadir: Path, master_xprv: str, *, internal: bool) -> str:
    change = 1 if internal else 0
    descriptor = f"mr(pk(pqc({master_xprv}/87h/1h/0h/{change}/*)))"
    checksum = run_cli_json(
        cli,
        datadir,
        "getdescriptorinfo",
        descriptor,
        timeout=30,
    )["checksum"]
    return f"{descriptor}#{checksum}"


def mine(cli: Path, datadir: Path, blocks: int, address: str) -> None:
    run_cli_json(cli, datadir, "generatetoaddress", str(blocks), address, timeout=300)


def mine_until_balance(cli: Path, datadir: Path, wallet: str, *, target: Decimal, timeout: float) -> None:
    start = time.perf_counter()
    while get_wallet_balance(cli, datadir, wallet) < target:
        mine(cli, datadir, 100, get_new_address(cli, datadir, wallet))
        if time.perf_counter() - start > timeout:
            raise TimeoutError("timed out waiting for miner balance")


def build_source_fixture(cli: Path, datadir: Path, profile: RecoveryProfile, timeout: float) -> dict:
    create_wallet(cli, datadir, "miner", descriptors=True)
    create_wallet(cli, datadir, "source", descriptors=True)

    miner_addr = get_new_address(cli, datadir, "miner")
    mine(cli, datadir, 101, miner_addr)

    receive_amounts = make_receive_amounts(profile.external_targets)
    spend_source_amounts = make_spend_source_amounts(len(profile.internal_targets))
    change_spend_amounts = make_change_spend_amounts(profile.internal_targets)
    required_balance = sum(receive_amounts.values()) + sum(spend_source_amounts) + Decimal("1.0")
    mine_until_balance(cli, datadir, "miner", target=required_balance, timeout=timeout)

    descriptors = run_cli_json(cli, datadir, "listdescriptors", wallet="source")["descriptors"]
    active_p2mr = [entry for entry in descriptors if entry["active"] and entry["desc"].startswith("mr(")]
    if len(active_p2mr) != 2:
        raise AssertionError("source wallet is missing the expected active P2MR descriptors")

    history_start = run_cli_json(cli, datadir, "getbestblockhash")
    source_xprv = run_cli_json(cli, datadir, "-named", "gethdkeys", "private=true", wallet="source")[0]["xprv"]

    sparse_receive = collect_sparse_addresses(cli, datadir, "source", get_new_address, profile.external_targets)
    sparse_change = collect_sparse_addresses(cli, datadir, "source", get_change_address, profile.internal_targets)
    for index in profile.external_targets:
        assert_p2mr_address(cli, datadir, "source", sparse_receive[index], is_change=False)
    for index in profile.internal_targets:
        assert_p2mr_address(cli, datadir, "source", sparse_change[index], is_change=True)

    receive_txids: dict[int, str] = {}
    for index in profile.external_targets:
        receive_txids[index] = run_cli_json(
            cli,
            datadir,
            "-named",
            "sendtoaddress",
            f"address={sparse_receive[index]}",
            f"amount={qbt(receive_amounts[index])}",
            wallet="miner",
        )

    spend_source_addrs = []
    for amount in spend_source_amounts:
        spend_source_addr = get_new_address(cli, datadir, "source")
        spend_source_addrs.append(spend_source_addr)
        run_cli_json(
            cli,
            datadir,
            "-named",
            "sendtoaddress",
            f"address={spend_source_addr}",
            f"amount={qbt(amount)}",
            wallet="miner",
        )

    mine(cli, datadir, 1, get_new_address(cli, datadir, "miner"))

    spend_source_utxos = [get_single_utxo(cli, datadir, "source", address) for address in spend_source_addrs]
    change_spend_txids: dict[int, str] = {}
    miner_recipient = get_new_address(cli, datadir, "miner")
    for internal_index, spend_utxo in zip(profile.internal_targets, spend_source_utxos):
        outputs = [{miner_recipient: float(change_spend_amounts[internal_index])}]
        inputs = [{"txid": spend_utxo["txid"], "vout": spend_utxo["vout"]}]
        send_result = run_cli_json(
            cli,
            datadir,
            "-named",
            "send",
            f"outputs={compact_json(outputs)}",
            f"inputs={compact_json(inputs)}",
            "add_inputs=false",
            "fee_rate=200",
            f"change_address={sparse_change[internal_index]}",
            wallet="source",
        )
        change_spend_txids[internal_index] = send_result["txid"]

    mine(cli, datadir, 1, get_new_address(cli, datadir, "miner"))

    sparse_addresses = [
        *[sparse_receive[index] for index in profile.external_targets],
        *[sparse_change[index] for index in profile.internal_targets],
    ]
    source_unspent = unspent_map(cli, datadir, "source", sparse_addresses)
    exported = run_cli_json(cli, datadir, "exportpubkeydb", wallet="source")
    exported_sparse_indexes = {(entry.get("change"), entry.get("index")) for entry in exported["pubkeys"]}
    for index in profile.external_targets:
        if (False, index) not in exported_sparse_indexes:
            raise AssertionError(f"source exportpubkeydb is missing external index {index}")
    for index in profile.internal_targets:
        if (True, index) not in exported_sparse_indexes:
            raise AssertionError(f"source exportpubkeydb is missing internal index {index}")

    return {
        "history_start": history_start,
        "master_xprv": source_xprv,
        "pubkeys": exported["pubkeys"],
        "pubkey_count": exported["count"],
        "sparse_receive": sparse_receive,
        "sparse_change": sparse_change,
        "sparse_addresses": sparse_addresses,
        "source_unspent": source_unspent,
        "source_balance": qbt(get_wallet_balance(cli, datadir, "source")),
        "source_tx_count": count_transactions_since(cli, datadir, "source", history_start, include_change=True),
        "receive_txids": receive_txids,
        "change_spend_txids": change_spend_txids,
    }


def make_recovery_requests(cli: Path, datadir: Path, profile: RecoveryProfile, master_xprv: str) -> list[dict]:
    return [
        {
            "desc": pqc_ranged_desc(cli, datadir, master_xprv, internal=False),
            "active": True,
            "range": [0, profile.external_range_end],
            "next_index": profile.external_next_index,
            "timestamp": 0,
            "internal": False,
        },
        {
            "desc": pqc_ranged_desc(cli, datadir, master_xprv, internal=True),
            "active": True,
            "range": [0, profile.internal_range_end],
            "next_index": profile.internal_next_index,
            "timestamp": 0,
            "internal": True,
        },
    ]


def get_active_p2mr_ranges(cli: Path, datadir: Path, wallet: str) -> dict:
    descriptors = run_cli_json(cli, datadir, "listdescriptors", wallet=wallet)["descriptors"]
    active = [entry for entry in descriptors if entry["active"] and entry["desc"].startswith("mr(")]
    external = next(entry for entry in active if not entry["internal"])
    internal = next(entry for entry in active if entry["internal"])
    return {
        "external_range": external["range"],
        "external_next_index": external["next_index"],
        "internal_range": internal["range"],
        "internal_next_index": internal["next_index"],
    }


def benchmark_signer_recovery(
    cli: Path,
    datadir: Path,
    profile: RecoveryProfile,
    fixture: dict,
    mode: str,
    timeout: float,
) -> dict:
    wallet_name = f"restored_signer_{mode}"
    if mode == "encrypted":
        create_wallet(cli, datadir, wallet_name, blank=True, passphrase="bench-pass", descriptors=True)
        ensure_wallet_unlocked(cli, datadir, wallet_name, "bench-pass")
    else:
        create_wallet(cli, datadir, wallet_name, blank=True, descriptors=True)

    requests = make_recovery_requests(cli, datadir, profile, fixture["master_xprv"])
    elapsed, result = timed(
        lambda: run_cli_json(
            cli,
            datadir,
            "importdescriptors",
            compact_json(requests),
            wallet=wallet_name,
            timeout=timeout,
        )
    )
    if not all(item["success"] for item in result):
        raise AssertionError(f"{wallet_name}: signer recovery failed: {result}")

    ranges = get_active_p2mr_ranges(cli, datadir, wallet_name)
    recovered_unspent = unspent_map(cli, datadir, wallet_name, fixture["sparse_addresses"])
    if recovered_unspent != fixture["source_unspent"]:
        raise AssertionError(f"{wallet_name}: recovered sparse UTXO set does not match source")

    for index, address in fixture["sparse_receive"].items():
        info = assert_p2mr_address(cli, datadir, wallet_name, address)
        if not info["ismine"]:
            raise AssertionError(f"{wallet_name}: missing external sparse address {index}")
    for index, address in fixture["sparse_change"].items():
        info = assert_p2mr_address(cli, datadir, wallet_name, address)
        if not info["ismine"]:
            raise AssertionError(f"{wallet_name}: missing internal sparse address {index}")

    balance = qbt(get_wallet_balance(cli, datadir, wallet_name))
    if balance != fixture["source_balance"]:
        raise AssertionError(f"{wallet_name}: recovered balance {balance} does not match source {fixture['source_balance']}")

    return {
        "lane": "signer",
        "recovery_mode": mode,
        "elapsed_seconds": round(elapsed, 6),
        "wallet_name": wallet_name,
        "balance": balance,
        "tx_count": count_transactions_since(cli, datadir, wallet_name, fixture["history_start"], include_change=True),
        "utxo_count": sum(len(v) for v in recovered_unspent.values()),
        "effective_external_range_start": ranges["external_range"][0],
        "effective_external_range_end": ranges["external_range"][1],
        "effective_external_next_index": ranges["external_next_index"],
        "effective_internal_range_start": ranges["internal_range"][0],
        "effective_internal_range_end": ranges["internal_range"][1],
        "effective_internal_next_index": ranges["internal_next_index"],
    }


def benchmark_watch_only_recovery(
    cli: Path,
    datadir: Path,
    fixture: dict,
    timeout: float,
) -> dict:
    wallet_name = "watch_sparse_bench"
    create_wallet(cli, datadir, wallet_name, blank=True, disable_private_keys=True, descriptors=True)
    elapsed, result = timed(
        lambda: run_cli_json(
            cli,
            datadir,
            "importpubkeydb",
            compact_json(fixture["pubkeys"]),
            "false",
            "0",
            wallet=wallet_name,
            timeout=timeout,
        )
    )
    if result["imported"] != fixture["pubkey_count"]:
        raise AssertionError(f"{wallet_name}: imported {result['imported']} pubkeys, expected {fixture['pubkey_count']}")

    watch_unspent = unspent_map(cli, datadir, wallet_name, fixture["sparse_addresses"])
    if watch_unspent != fixture["source_unspent"]:
        raise AssertionError(f"{wallet_name}: watch-only sparse UTXO set does not match source")

    for index, address in fixture["sparse_receive"].items():
        info = assert_p2mr_address(cli, datadir, wallet_name, address, is_change=False)
        if not info["ismine"]:
            raise AssertionError(f"{wallet_name}: missing external sparse address {index}")
    for index, address in fixture["sparse_change"].items():
        info = assert_p2mr_address(cli, datadir, wallet_name, address, is_change=True)
        if not info["ismine"]:
            raise AssertionError(f"{wallet_name}: missing internal sparse address {index}")

    return {
        "lane": "watch_only",
        "recovery_mode": "watch_only",
        "elapsed_seconds": round(elapsed, 6),
        "wallet_name": wallet_name,
        "balance": qbt(get_wallet_balance(cli, datadir, wallet_name)),
        "tx_count": count_transactions_since(cli, datadir, wallet_name, fixture["history_start"], include_change=True),
        "utxo_count": sum(len(v) for v in watch_unspent.values()),
        "effective_external_range_start": "",
        "effective_external_range_end": "",
        "effective_external_next_index": "",
        "effective_internal_range_start": "",
        "effective_internal_range_end": "",
        "effective_internal_next_index": "",
    }


def write_summary(rows: list[dict], destination: Path, profiles: list[RecoveryProfile], signer_modes: list[str]) -> None:
    grouped: dict[tuple[str, str, str], list[dict]] = {}
    for row in rows:
        grouped.setdefault((row["profile"], row["lane"], row["recovery_mode"]), []).append(row)

    lines = [
        "# Wallet Recovery Benchmark Summary",
        "",
        "Manual report-only baseline for descriptor-backed P2MR signer recovery and watch-only pubkeydb import.",
        "",
        "## Profiles",
        "",
    ]
    for profile in profiles:
        lines.append(f"- `{profile.name}`: {profile.description}")
    lines.extend([
        "",
        "## Results",
        "",
        "| Profile | Lane | Mode | Trials | Median s | Min s | Max s | Source Pubkeys | Balance | UTXOs | Effective External Range | Effective Internal Range |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ])

    order = []
    for profile in profiles:
        for mode in signer_modes:
            order.append((profile.name, "signer", mode))
        order.append((profile.name, "watch_only", "watch_only"))

    for key in order:
        group = grouped.get(key, [])
        if not group:
            continue
        timings = [row["elapsed_seconds"] for row in group]
        sample = group[0]
        ext_range = (
            f"{sample['effective_external_range_start']}..{sample['effective_external_range_end']} "
            f"(next={sample['effective_external_next_index']})"
            if sample["lane"] == "signer"
            else "-"
        )
        int_range = (
            f"{sample['effective_internal_range_start']}..{sample['effective_internal_range_end']} "
            f"(next={sample['effective_internal_next_index']})"
            if sample["lane"] == "signer"
            else "-"
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    sample["profile"],
                    sample["lane"],
                    sample["recovery_mode"],
                    str(len(group)),
                    f"{statistics.median(timings):.6f}",
                    f"{min(timings):.6f}",
                    f"{max(timings):.6f}",
                    str(sample["source_pubkey_count"]),
                    sample["balance"],
                    str(sample["utxo_count"]),
                    ext_range,
                    int_range,
                ]
            )
            + " |"
        )

    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    profiles = parse_profile_list(args.profiles)
    signer_modes = parse_signer_modes(args.signer_modes)

    build_dir = (REPO_ROOT / args.build_dir).resolve()
    qbitd = resolve_binary(args.qbitd, build_dir, "qbitd")
    qbit_cli = resolve_binary(args.qbit_cli, build_dir, "qbit-cli")
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    args.summary_file.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, object]] = []

    for profile in profiles:
        for trial in range(1, args.trials + 1):
            datadir = Path(tempfile.mkdtemp(prefix=f"wallet-recovery-{profile.name}-{trial}-", dir=args.output_csv.parent))
            process = subprocess.Popen(
                [
                    str(qbitd),
                    f"-datadir={datadir}",
                    "-regtest",
                    "-server",
                    "-listen=0",
                    "-discover=0",
                    "-dnsseed=0",
                    "-fixedseeds=0",
                    "-fallbackfee=0.0001",
                    "-p2mronly=1",
                    f"-keypool={args.keypool}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            try:
                wait_for_rpc(qbit_cli, datadir, args.wait_timeout)
                fixture = build_source_fixture(qbit_cli, datadir, profile, args.wait_timeout)

                for mode in signer_modes:
                    signer_row = benchmark_signer_recovery(qbit_cli, datadir, profile, fixture, mode, args.wait_timeout)
                    rows.append(
                        {
                            "trial": trial,
                            "profile": profile.name,
                            "profile_description": profile.description,
                            "lane": signer_row["lane"],
                            "recovery_mode": signer_row["recovery_mode"],
                            "elapsed_seconds": signer_row["elapsed_seconds"],
                            "node_keypool": args.keypool,
                            "source_pubkey_count": fixture["pubkey_count"],
                            "source_balance": fixture["source_balance"],
                            "balance": signer_row["balance"],
                            "utxo_count": signer_row["utxo_count"],
                            "tx_count": signer_row["tx_count"],
                            "source_tx_count": fixture["source_tx_count"],
                            "effective_external_range_start": signer_row["effective_external_range_start"],
                            "effective_external_range_end": signer_row["effective_external_range_end"],
                            "effective_external_next_index": signer_row["effective_external_next_index"],
                            "effective_internal_range_start": signer_row["effective_internal_range_start"],
                            "effective_internal_range_end": signer_row["effective_internal_range_end"],
                            "effective_internal_next_index": signer_row["effective_internal_next_index"],
                            "max_external_target": max(profile.external_targets),
                            "max_internal_target": max(profile.internal_targets),
                        }
                    )

                watch_row = benchmark_watch_only_recovery(qbit_cli, datadir, fixture, args.wait_timeout)
                rows.append(
                    {
                        "trial": trial,
                        "profile": profile.name,
                        "profile_description": profile.description,
                        "lane": watch_row["lane"],
                        "recovery_mode": watch_row["recovery_mode"],
                        "elapsed_seconds": watch_row["elapsed_seconds"],
                        "node_keypool": args.keypool,
                        "source_pubkey_count": fixture["pubkey_count"],
                        "source_balance": fixture["source_balance"],
                        "balance": watch_row["balance"],
                        "utxo_count": watch_row["utxo_count"],
                        "tx_count": watch_row["tx_count"],
                        "source_tx_count": fixture["source_tx_count"],
                        "effective_external_range_start": watch_row["effective_external_range_start"],
                        "effective_external_range_end": watch_row["effective_external_range_end"],
                        "effective_external_next_index": watch_row["effective_external_next_index"],
                        "effective_internal_range_start": watch_row["effective_internal_range_start"],
                        "effective_internal_range_end": watch_row["effective_internal_range_end"],
                        "effective_internal_next_index": watch_row["effective_internal_next_index"],
                        "max_external_target": max(profile.external_targets),
                        "max_internal_target": max(profile.internal_targets),
                    }
                )
            finally:
                shutdown_node(process, qbit_cli, datadir)
                if not args.keep_datadirs:
                    shutil.rmtree(datadir, ignore_errors=True)

    with args.output_csv.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    write_summary(rows, args.summary_file, profiles, signer_modes)
    print(f"Wrote {len(rows)} row(s) to {args.output_csv}")
    print(f"Wrote summary to {args.summary_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
