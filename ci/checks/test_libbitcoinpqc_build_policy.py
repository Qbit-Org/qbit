#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression tests for qbit's integrated libbitcoinpqc build policy."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_ERROR = (
    "SPX_ENABLE_TEST_BENCH_ENV_KNOBS is test/benchmark-only and cannot be enabled "
    "in an integrated qbit build."
)

FIXTURE_CMAKELISTS = r"""
cmake_minimum_required(VERSION 3.22)
project(qbit_libbitcoinpqc_policy C CXX)

if(NOT DEFINED QBIT_SOURCE_DIR)
  message(FATAL_ERROR "QBIT_SOURCE_DIR is required")
endif()

list(APPEND CMAKE_MODULE_PATH "${QBIT_SOURCE_DIR}/cmake/module")
add_library(sanitize_interface INTERFACE)
set(APPEND_CPPFLAGS "")
set(APPEND_CFLAGS "")

include("${QBIT_SOURCE_DIR}/cmake/libbitcoinpqc.cmake")
add_libbitcoinpqc(libbitcoinpqc)

get_target_property(bitcoinpqc_definitions bitcoinpqc COMPILE_DEFINITIONS)
if(NOT "SPX_PRODUCTION_BUILD=1" IN_LIST bitcoinpqc_definitions)
  message(FATAL_ERROR
    "Integrated bitcoinpqc target is missing SPX_PRODUCTION_BUILD=1: ${bitcoinpqc_definitions}"
  )
endif()
if("SPX_ENABLE_TEST_BENCH_ENV_KNOBS=1" IN_LIST bitcoinpqc_definitions)
  message(FATAL_ERROR
    "Integrated bitcoinpqc target enables test/benchmark environment knobs: ${bitcoinpqc_definitions}"
  )
endif()
"""


class LibbitcoinpqcBuildPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.fixture_source = self.tmp_path / "source"
        self.fixture_source.mkdir()
        (self.fixture_source / "libbitcoinpqc").symlink_to(
            REPO_ROOT / "src" / "libbitcoinpqc",
            target_is_directory=True,
        )
        (self.fixture_source / "CMakeLists.txt").write_text(
            FIXTURE_CMAKELISTS,
            encoding="utf8",
        )

    def cmake_configure(
        self,
        build_name: str,
        *definitions: str,
    ) -> subprocess.CompletedProcess[str]:
        cmake = shutil.which("cmake")
        self.assertIsNotNone(cmake, "cmake is required")
        ninja = shutil.which("ninja")
        self.assertIsNotNone(ninja, "ninja is required")

        command = [
            cmake,
            "-S",
            str(self.fixture_source),
            "-B",
            str(self.tmp_path / build_name),
            "-G",
            "Ninja",
            f"-DQBIT_SOURCE_DIR={REPO_ROOT}",
            "-DCMAKE_BUILD_TYPE=Debug",
            *definitions,
        ]
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def cmake_build(self, build_name: str) -> subprocess.CompletedProcess[str]:
        cmake = shutil.which("cmake")
        self.assertIsNotNone(cmake, "cmake is required")
        return subprocess.run(
            [
                cmake,
                "--build",
                str(self.tmp_path / build_name),
                "--target",
                "bitcoinpqc",
                "--verbose",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_policy_failure(self, result: subprocess.CompletedProcess[str]) -> None:
        combined = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, combined)
        normalized = re.sub(r"\s+", " ", combined)
        self.assertIn(POLICY_ERROR, normalized)

    def test_normal_configuration_builds_production_target(self) -> None:
        configured = self.cmake_configure("production")
        self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)

        built = self.cmake_build("production")
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertIn("-DSPX_PRODUCTION_BUILD=1", built.stdout + built.stderr)
        self.assertNotIn(
            "-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=1",
            built.stdout + built.stderr,
        )

    def test_explicit_runtime_controls_fail_configuration(self) -> None:
        configured = self.cmake_configure(
            "runtime-controls",
            "-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=ON",
        )
        self.assert_policy_failure(configured)

    def test_stale_runtime_controls_cache_remains_fail_closed(self) -> None:
        enabled = self.cmake_configure(
            "stale-cache",
            "-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=ON",
        )
        self.assert_policy_failure(enabled)

        stale = self.cmake_configure("stale-cache")
        self.assert_policy_failure(stale)

        disabled = self.cmake_configure(
            "stale-cache",
            "-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=OFF",
        )
        self.assertEqual(disabled.returncode, 0, disabled.stdout + disabled.stderr)

    def test_compiler_flag_injection_fails_library_build(self) -> None:
        configured = self.cmake_configure(
            "compiler-injection",
            "-DCMAKE_C_FLAGS=-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=1",
        )
        self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)

        built = self.cmake_build("compiler-injection")
        combined = built.stdout + built.stderr
        self.assertNotEqual(built.returncode, 0, combined)
        self.assertIn(
            "SPX_PRODUCTION_BUILD cannot be combined with "
            "SPX_ENABLE_TEST_BENCH_ENV_KNOBS",
            combined,
        )


if __name__ == "__main__":
    unittest.main()
