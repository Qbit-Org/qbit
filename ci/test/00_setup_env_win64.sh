#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

export CONTAINER_NAME=ci_win64
ci_set_base_image_name_tag "ubuntu:24.04"  # Check that https://packages.ubuntu.com/noble/g++-mingw-w64-x86-64-posix (version 13.x, similar to guix) can cross-compile
export HOST=x86_64-w64-mingw32
export PACKAGES="g++-mingw-w64-x86-64-posix nsis"
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=false
export BUILD_BENCH=ON
export GOAL="deploy"
export BITCOIN_CONFIG="-DREDUCE_EXPORTS=ON -DBUILD_GUI_TESTS=OFF \
-DCMAKE_CXX_FLAGS='-Wno-error=maybe-uninitialized'"
