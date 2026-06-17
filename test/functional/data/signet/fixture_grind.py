#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replay deterministic signet header grinding fixtures for functional tests."""

import json
import sys
from pathlib import Path

PATH_BASE_TEST_FUNCTIONAL = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PATH_BASE_TEST_FUNCTIONAL))

from test_framework.messages import CBlockHeader, from_hex, uint256_from_compact  # noqa: E402


def validate_fixture(unsolved_hex, solved_hex, name):
    unsolved = from_hex(CBlockHeader(), unsolved_hex)
    solved = from_hex(CBlockHeader(), solved_hex)
    if unsolved.serialize()[:-4] != solved.serialize()[:-4]:
        raise ValueError(f"{name}: fixture may only change the nonce")
    if solved.hash_int > uint256_from_compact(solved.nBits):
        raise ValueError(f"{name}: solved header does not satisfy proof of work")


def load_fixtures():
    fixture_path = Path(__file__).with_name("grind_fixture_headers.json")
    with fixture_path.open(encoding="utf8") as fixture_file:
        raw_fixtures = json.load(fixture_file)

    fixtures = {}
    for fixture in raw_fixtures:
        unsolved = fixture["unsolved_header"]
        solved = fixture["solved_header"]
        if unsolved in fixtures:
            raise ValueError(f"Duplicate unsolved fixture header: {fixture['name']}")
        validate_fixture(unsolved, solved, fixture["name"])
        fixtures[unsolved] = solved
    return fixtures


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: fixture_grind.py <hex-header>")

    fixtures = load_fixtures()
    header_hex = sys.argv[1].strip()
    solved_header = fixtures.get(header_hex)
    if solved_header is None:
        header = from_hex(CBlockHeader(), header_hex)
        target = uint256_from_compact(header.nBits)
        while header.hash_int > target:
            header.nNonce += 1
        solved_header = header.serialize().hex()

    print(solved_header)


if __name__ == "__main__":
    main()
