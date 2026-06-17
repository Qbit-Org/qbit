#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise mixed permissionless and AuxPoW propagation across a linear network."""

from test_framework.auxpow import make_valid_auxpow_from_template
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_not_equal,
    ensure_for,
)
from test_framework.wallet import getnewdestination


class FeatureIntegrationCadenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-dnsseed=0", "-fixedseeds=0", "-asert"] for _ in range(self.num_nodes)]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
        self.sync_all()

    def advance_mock_time(self, seconds=600):
        self.mock_time += seconds
        for node in self.nodes:
            node.setmocktime(self.mock_time)

    def submit_permissionless_block(self, node):
        gbt = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(
            hashprev=int(gbt["previousblockhash"], 16),
            coinbase=create_coinbase(gbt["height"]),
            ntime=gbt["curtime"],
            version=gbt["version"],
            tmpl=gbt,
        )
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        return block.hash_hex

    def submit_merged_block(self, node, payout_address):
        aux_template = node.createauxblock(payout_address)
        auxpow = make_valid_auxpow_from_template(aux_template, parent_time=self.mock_time)
        assert_equal(node.submitauxblock(aux_template["hash"], auxpow.to_hex()), None)
        return aux_template["hash"]

    def assert_synced_tip(self, *, expected_height=None, expected_hash=None):
        if expected_height is None:
            expected_height = self.nodes[0].getblockcount()
        if expected_hash is None:
            expected_hash = self.nodes[0].getbestblockhash()
        for node in self.nodes:
            assert_equal(node.getblockcount(), expected_height)
            assert_equal(node.getbestblockhash(), expected_hash)

    def run_test(self):
        permissionless_miner = self.nodes[0]
        relay = self.nodes[1]
        merged_miner = self.nodes[2]
        _, _, payout_address = getnewdestination("bech32")

        self.log.info("Bootstrap the network past genesis and align mock time")
        self.generate(permissionless_miner, 1)
        self.mock_time = permissionless_miner.getblockheader(permissionless_miner.getbestblockhash())["time"] + 600
        for node in self.nodes:
            node.setmocktime(self.mock_time)
        self.assert_synced_tip(expected_height=1)

        self.log.info("Permissionless blocks propagate across the full topology")
        for _ in range(3):
            self.advance_mock_time()
            permissionless_tip = self.submit_permissionless_block(permissionless_miner)
            permissionless_height = permissionless_miner.getblockcount()
            self.sync_blocks()
            self.assert_synced_tip(expected_height=permissionless_height, expected_hash=permissionless_tip)
        self.assert_synced_tip(expected_height=4)

        self.log.info("AuxPoW blocks propagate across the full topology")
        for _ in range(3):
            self.advance_mock_time()
            merged_tip = self.submit_merged_block(merged_miner, payout_address)
            merged_height = merged_miner.getblockcount()
            self.sync_blocks()
            self.assert_synced_tip(expected_height=merged_height, expected_hash=merged_tip)
        self.assert_synced_tip(expected_height=7)

        self.log.info("Interleaved permissionless and AuxPoW mining stays consistent")
        for _ in range(3):
            self.advance_mock_time()
            permissionless_tip = self.submit_permissionless_block(permissionless_miner)
            permissionless_height = permissionless_miner.getblockcount()
            self.sync_blocks()
            self.assert_synced_tip(expected_height=permissionless_height, expected_hash=permissionless_tip)

            self.advance_mock_time()
            merged_tip = self.submit_merged_block(merged_miner, payout_address)
            merged_height = merged_miner.getblockcount()
            self.sync_blocks()
            self.assert_synced_tip(expected_height=merged_height, expected_hash=merged_tip)

        self.log.info("A partition with competing block types converges to the longer chain")
        partition_base_height = permissionless_miner.getblockcount()
        self.disconnect_nodes(2, 1)

        for _ in range(2):
            self.advance_mock_time()
            left_tip = self.submit_permissionless_block(permissionless_miner)
            left_height = permissionless_miner.getblockcount()
            self.sync_blocks([permissionless_miner, relay])
            for node in (permissionless_miner, relay):
                assert_equal(node.getblockcount(), left_height)
                assert_equal(node.getbestblockhash(), left_tip)
        left_tip = permissionless_miner.getbestblockhash()
        left_height = permissionless_miner.getblockcount()

        self.advance_mock_time()
        reorged_auxpow_tip = self.submit_merged_block(merged_miner, payout_address)
        assert_equal(merged_miner.getblockcount(), partition_base_height + 1)
        assert_not_equal(left_tip, reorged_auxpow_tip)

        ensure_for(
            duration=3,
            f=lambda: (
                permissionless_miner.getbestblockhash() == left_tip
                and relay.getbestblockhash() == left_tip
                and merged_miner.getbestblockhash() == reorged_auxpow_tip
            ),
        )

        self.connect_nodes(2, 1)
        self.sync_blocks()
        self.assert_synced_tip(expected_height=left_height, expected_hash=left_tip)
        assert_equal(merged_miner.getblock(reorged_auxpow_tip)["confirmations"], -1)

        self.log.info("AuxPoW mining resumes cleanly after the reorg")
        self.advance_mock_time()
        recovered_auxpow_tip = self.submit_merged_block(merged_miner, payout_address)
        self.sync_blocks()
        self.assert_synced_tip(expected_height=left_height + 1, expected_hash=recovered_auxpow_tip)


if __name__ == "__main__":
    FeatureIntegrationCadenceTest(__file__).main()
