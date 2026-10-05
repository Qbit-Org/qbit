#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

# The aarch64-unit job of .github/workflows/ci-pq.yml: build only the unit-test
# binary natively on an AArch64 runner and run the post-quantum transport suites.
export CONTAINER_NAME=ci_native_aarch64_pq
ci_set_base_image_name_tag "ubuntu:24.04"
export PACKAGES="libboost-dev libevent-dev"
export NO_DEPENDS=1
export RUN_UNIT_TESTS=true
export RUN_FUNCTIONAL_TESTS=false
export CI_BUILD_TARGET=test_bitcoin
# The suites this job must run; ctest_evidence.py fails the job unless each was
# selected, executed and passed. CTEST_REGEX is derived from the same list.
export CTEST_EXPECTED_SUITES="bip324_tests net_tests"
export CTEST_REGEX="^(${CTEST_EXPECTED_SUITES// /|})\$"
# -Wno-psabi silences GCC's AArch64 "parameter passing ... changed" notes.
export BITCOIN_CONFIG="\
 -DBUILD_GUI=OFF -DENABLE_WALLET=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DREDUCE_EXPORTS=ON \
 -DCMAKE_CXX_FLAGS='-Wno-psabi' \
"
