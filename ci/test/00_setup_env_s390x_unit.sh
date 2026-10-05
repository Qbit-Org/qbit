#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

# The s390x-unit job of .github/workflows/ci-pq.yml: cross-compile only the
# unit-test binary for big-endian s390x on the x64 runner, with depends, and run
# the post-quantum suites under qemu-s390x. ctest adds the emulator to each test
# command, so only the tests run emulated; test_qbit is never run directly.
export HOST=s390x-linux-gnu
export CONTAINER_NAME=ci_s390x_pq
ci_set_base_image_name_tag "ubuntu:24.04"
export PACKAGES="g++-s390x-linux-gnu qemu-user"
export DEP_OPTS="NO_QT=1 NO_QR=1 NO_ZMQ=1 NO_WALLET=1 NO_USDT=1 NO_IPC=1"
export RUN_UNIT_TESTS=true
export RUN_FUNCTIONAL_TESTS=false
export CI_BUILD_TARGET=test_bitcoin
# The suites this job must run; ctest_evidence.py fails the job unless each was
# selected, executed and passed. CTEST_REGEX is derived from the same list.
export CTEST_EXPECTED_SUITES="mlkem_tests bip324_tests net_tests"
export CTEST_REGEX="^(${CTEST_EXPECTED_SUITES// /|})\$"
export BITCOIN_CONFIG="\
 -DBUILD_GUI=OFF -DENABLE_WALLET=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DREDUCE_EXPORTS=ON \
 -DCMAKE_CROSSCOMPILING_EMULATOR='qemu-s390x;-L;/usr/s390x-linux-gnu' \
"
