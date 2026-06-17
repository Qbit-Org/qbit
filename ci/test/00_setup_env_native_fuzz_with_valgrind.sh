#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

ci_set_base_image_name_tag "ubuntu:24.04"
export CONTAINER_NAME=ci_native_fuzz_valgrind
export PACKAGES="libevent-dev libboost-dev libsqlite3-dev valgrind libcapnp-dev capnproto"
export NO_DEPENDS=1
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=false
export RUN_FUZZ_TESTS=true
export FUZZ_TESTS_CONFIG="--valgrind"
export GOAL="all"
export BITCOIN_CONFIG="\
 -DBUILD_FOR_FUZZING=ON \
 -DCMAKE_CXX_FLAGS='-Wno-error=array-bounds' \
"
