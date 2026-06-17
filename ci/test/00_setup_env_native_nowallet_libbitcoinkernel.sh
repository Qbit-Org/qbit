#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

export CONTAINER_NAME=ci_native_nowallet_libbitcoinkernel
ci_set_base_image_name_tag "debian:bookworm"
# Use minimum supported python3.10 (or best-effort 3.11) and clang-16, see doc/dependencies.md
export PACKAGES="python3-zmq python3-pip clang-16 llvm-16 libc++abi-16-dev libc++-16-dev"
export PIP_PACKAGES="--break-system-packages pycapnp"
export DEP_OPTS="NO_WALLET=1 CC=clang-16 CXX='clang++-16 -stdlib=libc++'"
export GOAL="install"
export BITCOIN_CONFIG="-DREDUCE_EXPORTS=ON -DBUILD_UTIL_CHAINSTATE=ON -DBUILD_KERNEL_LIB=ON -DBUILD_SHARED_LIBS=ON"
