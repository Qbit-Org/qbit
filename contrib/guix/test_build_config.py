# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression checks for Guix release build configuration."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SH = REPO_ROOT / "contrib" / "guix" / "libexec" / "build.sh"


class GuixBuildConfigTest(unittest.TestCase):
    def test_testnet_release_builds_enable_mainnet_guard(self) -> None:
        script = BUILD_SH.read_text(encoding="utf8")

        self.assertRegex(
            script,
            re.compile(
                r'case "\$DISTNAME" in\s+'
                r'qbit-\*-testnet\*\) qbit_testnet_only_release_default=ON ;;',
                re.MULTILINE,
            ),
        )
        self.assertIn(
            '-DQBIT_TESTNET_ONLY_RELEASE=$QBIT_TESTNET_ONLY_RELEASE',
            script,
        )
        self.assertIn(
            'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-'
            '$qbit_testnet_only_release_default}"',
            script,
        )


if __name__ == "__main__":
    unittest.main()
