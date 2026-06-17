#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

export CONTAINER_NAME=ci_native_previous_releases
ci_set_base_image_name_tag "ubuntu:22.04"
# Use minimum supported python3.10 and gcc-11, see doc/dependencies.md
export PACKAGES="gcc-11 g++-11 python3-zmq"
export DEP_OPTS="CC=gcc-11 CXX=g++-11"
# Run extended tests so that coverage does not fail, but exclude the very slow dbcrash.
# qbit intentionally has no assumeUTXO snapshots yet, so loadtxoutset cannot
# succeed, and Bitcoin previous-release wallet migration tests are skipped due
# to the qbit regtest genesis mismatch.
export TEST_RUNNER_EXTRA="--previous-releases --coverage --coverage-exclude loadtxoutset,migratewallet --extended --exclude feature_dbcrash"
export GOAL="install"
export CI_LIMIT_STACK_SIZE=1
export DOWNLOAD_PREVIOUS_RELEASES="true"
export BITCOIN_CONFIG="\
 -DWITH_ZMQ=ON -DBUILD_GUI=ON -DREDUCE_EXPORTS=ON \
 -DCMAKE_BUILD_TYPE=Debug \
 -DCMAKE_C_FLAGS='-funsigned-char' \
 -DCMAKE_C_FLAGS_DEBUG='-g2 -O2' \
 -DCMAKE_CXX_FLAGS='-funsigned-char' \
 -DCMAKE_CXX_FLAGS_DEBUG='-g2 -O2' \
 -DAPPEND_CPPFLAGS='-DBOOST_MULTI_INDEX_ENABLE_SAFE_MODE' \
"
