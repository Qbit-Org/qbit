#!/usr/bin/env python3
# Copyright (c) The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check qbit public documentation for launch-chain integration drift."""

import re
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            encoding="utf8",
        ).strip()
    )


ROOT = repo_root()

FILE_RULES = {
    "doc/integration/README.md": {
        "required": ["docs.qbit.org"],
        "forbidden": ["REST-interface.md"],
    },
    "doc/integration/exchange-integrator-quickstart.md": {
        "required": ["getconfirmationtarget", "BTC-equivalent", "docs.qbit.org"],
    },
    "doc/integration/mining-pool-quickstart.md": {
        "forbidden": ["qbit-mining-bootstrap"],
    },
    "doc/integration/rpc-delta-reference.md": {
        "required": ["docs.qbit.org", "BTC-equivalent"],
    },
    "share/examples/qbit.conf": {
        "required": [
            "#addresstype=<type>",
            "#changetype=<type>",
            "# Enable unauthenticated REST interface on the RPC port",
        ],
        "forbidden": [
            "#addresstype=1",
            "#changetype=1",
            "Accept public REST requests",
        ],
    },
    "doc/man/qbit-tx.1": {
        "forbidden": ["bitcoin transactions"],
    },
    "test/README.md": {
        "forbidden": ["bitcoind", "bitcoin-qt", "Bitcoin Core must be built"],
    },
}

PORT_CHECK_PATHS = [
    "doc/integration",
    "doc/build",
    "depends/README.md",
    "depends/description.md",
    "test/README.md",
    "share/examples/qbit.conf",
    "doc/man",
]

BITCOIN_PORT_RE = re.compile(r"(?<![0-9A-Fa-f])(?:8332|8333|18332|18444)(?![0-9A-Fa-f])")


def iter_text_files(path: Path):
    if path.is_file():
        yield path
        return

    for child in path.rglob("*"):
        if child.is_file() and child.suffix in {".1", ".md", ".conf"}:
            yield child


def main() -> int:
    errors = []

    for rel_path, rules in FILE_RULES.items():
        path = ROOT / rel_path
        if not path.is_file():
            errors.append(f"{rel_path}: missing required file")
            continue
        text = path.read_text(encoding="utf8")
        for needle in rules.get("required", []):
            if needle not in text:
                errors.append(f"{rel_path}: missing required public-doc text: {needle!r}")
        for needle in rules.get("forbidden", []):
            if needle in text:
                errors.append(f"{rel_path}: stale public-doc text remains: {needle!r}")

    for rel_path in PORT_CHECK_PATHS:
        for path in iter_text_files(ROOT / rel_path):
            text = path.read_text(encoding="utf8", errors="ignore")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if BITCOIN_PORT_RE.search(line):
                    errors.append(
                        f"{path.relative_to(ROOT)}:{line_no}: stale Bitcoin default port in public docs"
                    )

    if errors:
        print("\n".join(errors))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
