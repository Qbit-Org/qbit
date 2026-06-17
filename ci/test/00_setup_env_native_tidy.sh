#!/usr/bin/env bash
#
# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

ci_set_base_image_name_tag "ubuntu:24.04"
export CONTAINER_NAME=ci_native_tidy
export TIDY_LLVM_V="20"
export APT_LLVM_V="${TIDY_LLVM_V}"
export PACKAGES="clang-${TIDY_LLVM_V} libclang-${TIDY_LLVM_V}-dev llvm-${TIDY_LLVM_V}-dev libomp-${TIDY_LLVM_V}-dev clang-tidy-${TIDY_LLVM_V} jq libevent-dev libboost-dev libzmq3-dev systemtap-sdt-dev qt6-base-dev qt6-tools-dev qt6-l10n-tools libqrencode-dev libsqlite3-dev libcapnp-dev capnproto"
export NO_DEPENDS=1
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=false
export RUN_FUZZ_TESTS=false
export RUN_CHECK_DEPS=true
export RUN_TIDY=true
# check-deps.sh currently requires a Makefile-based build directory.
export CMAKE_GENERATOR="Unix Makefiles"
export GOAL="install"
export BITCOIN_CONFIG="\
 -DWITH_ZMQ=ON -DBUILD_GUI=ON -DBUILD_BENCH=ON -DWITH_USDT=ON \
 -DCMAKE_C_COMPILER=clang-${TIDY_LLVM_V} \
 -DCMAKE_CXX_COMPILER=clang++-${TIDY_LLVM_V} \
 -DCMAKE_C_FLAGS_RELWITHDEBINFO='-O0 -g0' \
 -DCMAKE_CXX_FLAGS_RELWITHDEBINFO='-O0 -g0' \
"
