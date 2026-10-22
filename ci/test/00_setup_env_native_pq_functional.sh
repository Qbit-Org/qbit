#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

# The pq-functional job of .github/workflows/ci-pq.yml: the whole functional
# suite with hybrid post-quantum v2 transport between all nodes. Framework Python
# peers stay legacy BIP324 peers, so the suite pays no pure-Python KEM cost;
# p2p_v2_pq*.py exercise the Python hybrid peer in every run.
export CONTAINER_NAME=ci_native_pq_functional
ci_set_base_image_name_tag "ubuntu:24.04"
export PACKAGES="python3-zmq libevent-dev libboost-dev libzmq3-dev libsqlite3-dev"
export NO_DEPENDS=1
export GOAL="install"
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=true
export TEST_RUNNER_EXTRA="--v2pqtransport"
export BITCOIN_CONFIG="\
 -DWITH_ZMQ=ON -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DREDUCE_EXPORTS=ON \
"
