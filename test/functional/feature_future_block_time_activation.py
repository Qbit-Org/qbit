#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the height-activated qbit future block-time limit."""

import time

from test_framework.blocktools import (
    MAX_FUTURE_BLOCK_TIME,
    MAX_FUTURE_BLOCK_TIME_LEGACY,
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
    create_coinbase,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import getnewdestination, p2mr_op_true_script


ACTIVATION_HEIGHT = 12
P2MR_WEIGHT_V2_HEIGHT = ACTIVATION_HEIGHT + 2


class FutureBlockTimeActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = [
            f"-testactivationheight=futuretime@{ACTIVATION_HEIGHT}",
            f"-testactivationheight=p2mrweightv2@{P2MR_WEIGHT_V2_HEIGHT}",
        ]
        self.extra_args = [args, args]

    def setup_network(self):
        self.setup_nodes()

    def make_block(self, node, block_time):
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(
            tmpl=template,
            ntime=block_time,
            coinbase=create_coinbase(template["height"], script_pubkey=p2mr_op_true_script()),
        )
        block.solve()
        return block

    def assert_candidate_rule(self, node, *, limit, active):
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(template["future_block_time"], {
            "limit_seconds": limit,
            "v2_active": active,
            "v2_activation_height": ACTIVATION_HEIGHT,
        })
        # The two rules share no state even when production heights coincide.
        assert_equal(template["p2mr_validation_weight"]["v2_active"], False)
        _, _, payout_address = getnewdestination("p2mr")
        aux_template = node.createauxblock(payout_address)
        assert_equal(aux_template["future_block_time"], template["future_block_time"])

    def test_activation_boundaries(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())
        now = int(time.time())
        node.setmocktime(now)
        self.generate(node, ACTIVATION_HEIGHT - 2, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)

        self.log.info("The candidate immediately below activation uses the legacy two-hour limit")
        self.assert_candidate_rule(node, limit=MAX_FUTURE_BLOCK_TIME_LEGACY, active=False)
        too_new_legacy = self.make_block(node, now + MAX_FUTURE_BLOCK_TIME_LEGACY + 1)
        exact_legacy = self.make_block(node, now + MAX_FUTURE_BLOCK_TIME_LEGACY)
        peer.send_blocks_and_test([too_new_legacy], node, force_send=True, success=False, reject_reason="time-too-new")
        peer.send_blocks_and_test([exact_legacy], node, force_send=True, success=True)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)

        self.log.info("The activation candidate uses the ten-minute limit")
        self.assert_candidate_rule(node, limit=MAX_FUTURE_BLOCK_TIME, active=True)
        info = node.getblockchaininfo()["future_block_time"]
        assert_equal(info["active_for_tip"], False)
        assert_equal(info["active_for_next_block"], True)
        assert_equal(info["tip_limit_seconds"], MAX_FUTURE_BLOCK_TIME_LEGACY)
        assert_equal(info["next_block_limit_seconds"], MAX_FUTURE_BLOCK_TIME)
        assert_equal(info["blocks_remaining"], 0)

        exact_v2 = self.make_block(node, now + MAX_FUTURE_BLOCK_TIME)
        peer.send_blocks_and_test([exact_v2], node, force_send=True, success=True)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)

        self.log.info("A future-time rejection remains transient")
        node.invalidateblock(exact_v2.hash_hex)
        too_new_v2 = self.make_block(node, now + MAX_FUTURE_BLOCK_TIME + 1)
        peer.send_blocks_and_test([too_new_v2], node, force_send=True, success=False, reject_reason="time-too-new")
        node.setmocktime(now + 1)
        peer.send_blocks_and_test([too_new_v2], node, force_send=True, success=True)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)

        self.log.info("A reorg below activation restores legacy tip state")
        node.invalidateblock(too_new_v2.hash_hex)
        info = node.getblockchaininfo()["future_block_time"]
        assert_equal(info["active_for_tip"], False)
        assert_equal(info["active_for_next_block"], True)

        self.log.info("Loaded-tip validation uses the legacy limit below activation")
        activation_args = self.extra_args[0]
        self.stop_node(0)
        node.assert_start_raises_init_error(activation_args + [f"-mocktime={now - 1}"])
        self.start_node(0, activation_args + [f"-mocktime={now}"])
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)

        node.reconsiderblock(exact_v2.hash_hex)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)

        self.log.info("Loaded-tip validation uses the v2 limit at activation")
        self.stop_node(0)
        node.assert_start_raises_init_error(activation_args + [f"-mocktime={now - 1}"])
        self.start_node(0, activation_args + [f"-mocktime={now}"])
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)

    def test_mtp_transition_headroom(self):
        node = self.nodes[1]
        peer = node.add_p2p_connection(P2PDataStore())
        now = int(time.time())
        node.setmocktime(now)
        self.generate(node, ACTIVATION_HEIGHT - 7, sync_fun=self.no_op)

        self.log.info("Six legacy-valid future timestamps can exhaust activation headroom")
        for _ in range(6):
            block = self.make_block(node, now + MAX_FUTURE_BLOCK_TIME_LEGACY)
            peer.send_blocks_and_test([block], node, force_send=True, success=True)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(node.getblockchaininfo()["mediantime"], now + MAX_FUTURE_BLOCK_TIME_LEGACY)

        info = node.getblockchaininfo()["future_block_time"]
        assert_equal(info["next_block_min_time"], now + MAX_FUTURE_BLOCK_TIME_LEGACY + 1)
        assert info["next_block_time_headroom_seconds"] < 0
        error = "time-too-new"
        assert_raises_rpc_error(-1, error, node.getblocktemplate, NORMAL_GBT_REQUEST_PARAMS)
        _, _, payout_address = getnewdestination("p2mr")
        assert_raises_rpc_error(-1, error, node.createauxblock, payout_address)

        self.log.info("Templates recover exactly when wall time catches up")
        node.setmocktime(now + MAX_FUTURE_BLOCK_TIME_LEGACY + 1 - MAX_FUTURE_BLOCK_TIME)
        info = node.getblockchaininfo()["future_block_time"]
        assert_equal(info["next_block_time_headroom_seconds"], 0)
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(template["curtime"], info["next_block_min_time"])
        node.createauxblock(payout_address)

    def run_test(self):
        self.test_activation_boundaries()
        self.test_mtp_transition_headroom()


if __name__ == "__main__":
    FutureBlockTimeActivationTest(__file__).main()
