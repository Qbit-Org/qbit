#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.blocktools import (
    MAX_FUTURE_BLOCK_TIME,
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
    create_coinbase,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


DIFFICULTY_ADJUSTMENT_INTERVAL = 24 * 60 * 60 // 60
MAX_TIMEWARP = 60


class MiningAsertTimestampEdgesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-asert=1", "-test=bip94"],
            ["-legacyretarget=1", "-test=bip94"],
        ]

    def setup_network(self):
        self.setup_nodes()

    def make_block(self, prev_hash, height, ntime):
        block = create_block(int(prev_hash, 16), create_coinbase(height), ntime)
        block.solve()
        return block

    def make_template_block(self, node, ntime):
        block = create_block(
            tmpl=node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS),
            ntime=ntime,
        )
        block.solve()
        return block

    def mine_to_height(self, node, target_height):
        height = node.getblockcount()
        assert height <= target_height
        if height < target_height:
            self.generate(node, target_height - height, sync_fun=self.no_op)

    def submit_old_floor_candidate(self, node, expected):
        tip_hash = node.getbestblockhash()
        tip = node.getblock(tip_hash)
        candidate_time = tip["time"] - MAX_TIMEWARP - 1
        assert candidate_time > tip["mediantime"]

        next_height = node.getblockcount() + 1
        node.setmocktime(tip["time"] + 1)
        block = self.make_template_block(node, candidate_time)
        assert_equal(node.submitblock(block.serialize().hex()), expected)
        if expected is None:
            node.waitforblockheight(next_height)
            assert_equal(node.getblockcount(), next_height)
        else:
            assert_equal(node.getblockcount(), next_height - 1)

    def submit_floor_candidate(self, node):
        tip_hash = node.getbestblockhash()
        tip = node.getblock(tip_hash)
        candidate_time = max(tip["mediantime"] + 1, tip["time"] - MAX_TIMEWARP)

        next_height = node.getblockcount() + 1
        node.setmocktime(tip["time"] + 1)
        block = self.make_template_block(node, candidate_time)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        node.waitforblockheight(next_height)
        assert_equal(node.getblockcount(), next_height)

    def mine_forward_parent(self, node):
        tip = node.getblock(node.getbestblockhash())
        future_time = max(tip["time"], tip["mediantime"]) + 1200
        node.setmocktime(future_time)
        block = self.make_template_block(node, future_time)
        next_height = node.getblockcount() + 1
        assert_equal(node.submitblock(block.serialize().hex()), None)
        node.waitforblockheight(next_height)
        assert_equal(node.getblockcount(), next_height)

    def test_asert_timestamp_edges(self):
        node = self.nodes[0]
        self.generate(node, 20, sync_fun=self.no_op)

        tip_hash = node.getbestblockhash()
        tip = node.getblock(tip_hash)
        next_height = node.getblockcount() + 1

        self.log.info("MTP edge: nTime == MTP should be rejected")
        too_old = self.make_block(tip_hash, next_height, tip["mediantime"])
        assert_equal(node.submitblock(too_old.serialize().hex()), "time-too-old")

        self.log.info("MTP edge: nTime == MTP + 1 should be accepted")
        mtp_plus_one = self.make_block(tip_hash, next_height, tip["mediantime"] + 1)
        assert_equal(node.submitblock(mtp_plus_one.serialize().hex()), None)
        node.waitforblockheight(next_height)

        self.log.info("Create a valid parent with a forward timestamp")
        parent_hash = node.getbestblockhash()
        parent = node.getblock(parent_hash)
        parent_height = node.getblockcount()
        future_time = parent["mediantime"] + MAX_FUTURE_BLOCK_TIME
        node.setmocktime(future_time - MAX_FUTURE_BLOCK_TIME)
        future_parent = self.make_block(parent_hash, parent_height + 1, future_time)
        assert_equal(node.submitblock(future_parent.serialize().hex()), None)
        node.waitforblockheight(parent_height + 1)

        self.log.info("Out-of-order timestamp vs parent is accepted when still above MTP")
        current_parent_hash = node.getbestblockhash()
        current_parent = node.getblock(current_parent_hash)
        out_of_order_time = max(current_parent["mediantime"] + 1, future_time - MAX_FUTURE_BLOCK_TIME // 2)
        assert out_of_order_time < future_time

        child_height = node.getblockcount() + 1
        out_of_order = self.make_block(current_parent_hash, child_height, out_of_order_time)
        assert_equal(node.submitblock(out_of_order.serialize().hex()), None)
        node.waitforblockheight(child_height)

        accepted = node.getblock(node.getbestblockhash())
        assert accepted["time"] < future_time

    def test_bip94_boundary(self):
        asert_node = self.nodes[0]
        legacy_node = self.nodes[1]

        self.log.info("Mine both nodes to n-2 before the qbit difficulty-adjustment boundary")
        for node in [asert_node, legacy_node]:
            self.mine_to_height(node, DIFFICULTY_ADJUSTMENT_INTERVAL - 3)
            self.mine_forward_parent(node)
            assert_equal(node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL - 2)

        self.log.info("n-1: old-but-above-MTP timestamps are accepted on ASERT and legacy")
        self.submit_old_floor_candidate(asert_node, None)
        self.submit_old_floor_candidate(legacy_node, None)
        assert_equal(asert_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        assert_equal(legacy_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL - 1)

        self.log.info("n: ASERT skips the inherited BIP94 timewarp floor")
        self.submit_old_floor_candidate(asert_node, None)
        assert_equal(asert_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL)

        self.log.info("n: legacy retargeting still enforces the inherited BIP94 timewarp floor")
        self.submit_old_floor_candidate(legacy_node, "time-timewarp-attack")
        assert_equal(legacy_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        self.submit_floor_candidate(legacy_node)
        assert_equal(legacy_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL)

        self.log.info("n+1: the inherited BIP94 floor is only a boundary rule")
        self.submit_old_floor_candidate(asert_node, None)
        self.submit_old_floor_candidate(legacy_node, None)
        assert_equal(asert_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL + 1)
        assert_equal(legacy_node.getblockcount(), DIFFICULTY_ADJUSTMENT_INTERVAL + 1)

    def run_test(self):
        self.test_asert_timestamp_edges()
        self.test_bip94_boundary()


if __name__ == "__main__":
    MiningAsertTimestampEdgesTest(__file__).main()
