#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# The macos-arm64-unit job of .github/workflows/ci-pq.yml: build only the
# unit-test binary natively on an Apple Silicon runner, without Docker, and run
# the post-quantum suites. This is the target that runs native AArch64 ML-KEM.
export CONTAINER_NAME="ci_mac_native_pq"  # macos does not use a container, but the env var is needed for logging
export CMAKE_GENERATOR="Ninja"
export CI_OS_NAME="macos"
export NO_DEPENDS=1
export OSX_SDK=""
export RUN_UNIT_TESTS=true
export RUN_FUNCTIONAL_TESTS=false
export CI_BUILD_TARGET=test_bitcoin
# The suites this job must run; ctest_evidence.py fails the job unless each was
# selected, executed and passed. CTEST_REGEX is derived from the same list.
export CTEST_EXPECTED_SUITES="mlkem_tests bip324_tests net_tests"
export CTEST_REGEX="^(${CTEST_EXPECTED_SUITES// /|})\$"
# WITH_MLKEM_NATIVE=ON makes losing the native AArch64 backend a configure error
# instead of a quiet fall back to portable C.
export BITCOIN_CONFIG="-DBUILD_GUI=OFF -DENABLE_WALLET=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DREDUCE_EXPORTS=ON -DWITH_MLKEM_NATIVE=ON"
