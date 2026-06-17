#!/usr/bin/env python3
# Copyright (c) 2026 The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check curated qbit node/operator default surfaces for stale defaults."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        encoding="utf8",
    ).stdout.strip()
)

EXPECTED_PRESENT = {
    Path("share/examples/qbit.conf"): [
        "## qbit.conf configuration file.",
        "# Listen for JSON-RPC connections on <port> (default: 8352, testnet3:",
        "# 18352, testnet4: 48352, signet: 38352, regtest: 18452)",
    ],
    Path("doc/man/qbit-cli.1"): [
        "Connect to JSON\\-RPC on <port> (default: 8352, testnet: 18352, testnet4:",
        "48352, signet: 38352, regtest: 18452)",
        "http://127.0.0.1:8352/wallet/<walletname>",
    ],
    Path("doc/man/qbitd.1"): [
        "Listen for JSON\\-RPC connections on <port> (default: 8352, testnet3:",
        "18352, testnet4: 48352, signet: 38352, regtest: 18452)",
    ],
    Path("doc/man/qbit-qt.1"): [
        "Listen for JSON\\-RPC connections on <port> (default: 8352, testnet3:",
        "18352, testnet4: 48352, signet: 38352, regtest: 18452)",
    ],
    Path("contrib/linearize/README.md"): [
        "Construct a linear, no-fork, best version of the qbit blockchain.",
        "* RPC: `port`  (Default: `8352`)",
    ],
    Path("contrib/linearize/example-linearize.cfg"): [
        "port=8352",
        "#port=18352",
        "#port=48352",
        "#port=18452",
        "#port=38352",
    ],
    Path("contrib/linearize/linearize-hashes.py"): [
        "settings['port'] = 8352",
    ],
    Path("contrib/photon/relay.conf.example"): [
        "rpc_port = 8352",
    ],
    Path("contrib/photon/src/config.h"): [
        "std::uint16_t rpc_port{8352};",
    ],
    Path("contrib/photon/src/rpc_client.h"): [
        "std::uint16_t port{8352};",
    ],
}

FORBIDDEN_PRESENT = {
    Path("share/examples/qbit.conf"): ["8332", "18332", "18443", "bitcoin.conf"],
    Path("doc/man/qbit-cli.1"): ["8332", "18332", "18443"],
    Path("doc/man/qbitd.1"): ["8332", "18332", "18443"],
    Path("doc/man/qbit-qt.1"): ["8332", "18332", "18443"],
    Path("contrib/linearize/README.md"): ["8332"],
    Path("contrib/linearize/example-linearize.cfg"): ["8332", "18332", "18443", "38332"],
    Path("contrib/linearize/linearize-hashes.py"): ["8332"],
    Path("contrib/photon/relay.conf.example"): ["rpc_port = 8332"],
    Path("contrib/photon/src/config.h"): ["rpc_port{8332}"],
    Path("contrib/photon/src/rpc_client.h"): ["port{8332}"],
}

FORBIDDEN_PATHS = [
    Path("share/examples/bitcoin.conf"),
]


def main() -> int:
    failures: list[str] = []

    for rel_path, needles in EXPECTED_PRESENT.items():
        path = ROOT / rel_path
        if not path.is_file():
            failures.append(f"missing required file: {rel_path}")
            continue

        contents = path.read_text(encoding="utf8")
        for needle in needles:
            if needle not in contents:
                failures.append(f"{rel_path}: missing expected text: {needle}")

    for rel_path, needles in FORBIDDEN_PRESENT.items():
        path = ROOT / rel_path
        if not path.is_file():
            continue

        contents = path.read_text(encoding="utf8")
        for needle in needles:
            if needle in contents:
                failures.append(f"{rel_path}: contains stale text: {needle}")

    for rel_path in FORBIDDEN_PATHS:
        if (ROOT / rel_path).exists():
            failures.append(f"unexpected stale path present: {rel_path}")

    if failures:
        print("qbit node-default lint failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
