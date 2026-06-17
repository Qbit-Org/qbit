#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Measure P2MR wallet creation latency on a fresh -p2mronly=1 regtest node.

This is a manual report-only harness. It creates a fresh datadir per trial,
times the wallet RPCs that matter for UX, and can also wait for deferred
steady-state refill before writing a CSV report.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build", help="Build directory containing qbit binaries")
    parser.add_argument("--qbitd", dest="qbitd", type=Path, help="Path to qbitd")
    parser.add_argument("--bitcoind", dest="qbitd", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--qbit-cli", dest="qbit_cli", type=Path, help="Path to qbit-cli")
    parser.add_argument("--bitcoin-cli", dest="qbit_cli", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--keypool", type=int, default=1000, help="Configured steady-state keypool size")
    parser.add_argument("--trials", type=int, default=3, help="Number of fresh-datadir trials to run")
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=REPO_ROOT / "build" / "reports" / "wallet-create-bench.csv",
        help="Destination for the CSV report",
    )
    parser.add_argument(
        "--keep-datadirs",
        action="store_true",
        help="Keep per-trial datadirs instead of deleting them",
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=180.0,
        help="Seconds to wait for RPC readiness and steady-state refill",
    )
    parser.add_argument(
        "--skip-deferred-topup-wait",
        action="store_true",
        help="Do not wait for the deferred refill to complete",
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
            if run_cli_json(cli, datadir, "getblockcount") == 0:
                return
        except subprocess.CalledProcessError:
            pass
        if time.perf_counter() - start > timeout:
            raise TimeoutError("timed out waiting for RPC readiness")
        time.sleep(0.1)


def wallet_size_bytes(wallet_dir: Path) -> int:
    return sum(path.stat().st_size for path in wallet_dir.rglob("*") if path.is_file())


def parse_wallet_log_metrics(debug_log: Path, wallet_name: str) -> tuple[int | None, int | None]:
    initial_total_keypool = None
    deferred_topup_ms = None
    if not debug_log.exists():
        return initial_total_keypool, deferred_topup_ms

    keypool_pattern = re.compile(rf"\[{re.escape(wallet_name)}\] setKeyPool\.size\(\) = (\d+)")
    topup_pattern = re.compile(rf"\[{re.escape(wallet_name)}\] Deferred create-time keypool top up completed in\s+(\d+)ms")

    for line in debug_log.read_text(encoding="utf-8").splitlines():
        if initial_total_keypool is None:
            match = keypool_pattern.search(line)
            if match:
                initial_total_keypool = int(match.group(1))
        match = topup_pattern.search(line)
        if match:
            deferred_topup_ms = int(match.group(1))

    return initial_total_keypool, deferred_topup_ms


def wait_for_steady_state_keypool(
    cli: Path,
    datadir: Path,
    wallet_name: str,
    target_keypool: int,
    start_time: float,
    timeout: float,
    interval: float = 1.0,
) -> tuple[float, int]:
    while True:
        try:
            info = run_cli_json(cli, datadir, "getwalletinfo", wallet=wallet_name, timeout=1.0)
            if info["keypoolsize"] == target_keypool and info["keypoolsize_hd_internal"] == target_keypool:
                return time.perf_counter() - start_time, info["keypoolsize"] + info["keypoolsize_hd_internal"]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        if time.perf_counter() - start_time > timeout:
            raise TimeoutError("timed out waiting for the steady-state keypool refill")
        time.sleep(interval)


def main() -> int:
    args = parse_args()
    build_dir = (REPO_ROOT / args.build_dir).resolve()
    qbitd = resolve_binary(args.qbitd, build_dir, "qbitd")
    qbit_cli = resolve_binary(args.qbit_cli, build_dir, "qbit-cli")
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, object]] = []

    for trial in range(1, args.trials + 1):
        datadir = Path(tempfile.mkdtemp(prefix=f"wallet-create-bench-{trial}-", dir=args.output_csv.parent))
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

            create_wallet_seconds, _ = timed(
                lambda: run_cli_json(
                    qbit_cli,
                    datadir,
                    "-named",
                    "createwallet",
                    "wallet_name=bench",
                    "descriptors=true",
                )
            )
            deferred_topup_start = time.perf_counter()

            first_receive_seconds, first_receive = timed(
                lambda: run_cli_json(
                    qbit_cli,
                    datadir,
                    "-named",
                    "getnewaddress",
                    'label=""',
                    "address_type=p2mr",
                    wallet="bench",
                )
            )
            first_change_seconds, first_change = timed(
                lambda: run_cli_json(
                    qbit_cli,
                    datadir,
                    "-named",
                    "getrawchangeaddress",
                    "address_type=p2mr",
                    wallet="bench",
                )
            )

            blank_create_seconds, _ = timed(
                lambda: run_cli_json(
                    qbit_cli,
                    datadir,
                    "-named",
                    "createwallet",
                    "wallet_name=bench_blank",
                    "blank=true",
                    "descriptors=true",
                )
            )

            deferred_topup_seconds = None
            steady_state_total_keypool = None
            if not args.skip_deferred_topup_wait:
                deferred_topup_seconds, steady_state_total_keypool = wait_for_steady_state_keypool(
                    qbit_cli,
                    datadir,
                    "bench",
                    args.keypool,
                    deferred_topup_start,
                    args.wait_timeout,
                )
        finally:
            try:
                run_cli(qbit_cli, datadir, "stop", rpcwait=True)
            except Exception:
                process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        wallet_dir = datadir / "regtest" / "wallets" / "bench"
        debug_log = datadir / "regtest" / "debug.log"
        initial_total_keypool, _ = parse_wallet_log_metrics(debug_log, "bench")
        rows.append(
            {
                "trial": trial,
                "keypool": args.keypool,
                "createwallet_seconds": round(create_wallet_seconds, 6),
                "blank_createwallet_seconds": round(blank_create_seconds, 6),
                "initial_total_keypool": initial_total_keypool,
                "deferred_topup_seconds": None if deferred_topup_seconds is None else round(deferred_topup_seconds, 6),
                "steady_state_total_keypool": steady_state_total_keypool,
                "first_receive_seconds": round(first_receive_seconds, 6),
                "first_change_seconds": round(first_change_seconds, 6),
                "wallet_bytes": wallet_size_bytes(wallet_dir),
                "first_receive_address": first_receive,
                "first_change_address": first_change,
            }
        )

        if not args.keep_datadirs:
            shutil.rmtree(datadir, ignore_errors=True)

    with args.output_csv.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} trial(s) to {args.output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
