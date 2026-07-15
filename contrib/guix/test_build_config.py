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
    def test_release_builds_default_mainnet_guard_off(self) -> None:
        script = BUILD_SH.read_text(encoding="utf8")

        self.assertNotRegex(script, re.compile(r'qbit-\*-testnet', re.MULTILINE))
        self.assertIn(
            '-DQBIT_TESTNET_ONLY_RELEASE=$QBIT_TESTNET_ONLY_RELEASE',
            script,
        )
        self.assertIn(
            'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-OFF}"',
            script,
        )

    def test_release_builds_disable_pqc_runtime_controls(self) -> None:
        script = BUILD_SH.read_text(encoding="utf8")

        self.assertIn(
            '-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=OFF',
            script,
        )


if __name__ == "__main__":
    unittest.main()
