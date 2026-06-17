#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for skipping signature validation on old blocks.

Test logic for skipping signature validation on blocks which we've assumed
valid (https://github.com/bitcoin/bitcoin/pull/9484)

We build a chain that includes an invalid signature for one of the
transactions:

    0:        genesis block
    1:        block 1 with coinbase transaction output.
    2-101:    bury that block with 100 blocks so the coinbase transaction
              output can be spent
    102:      a block containing a transaction spending the coinbase
              transaction output. The transaction has an invalid signature.
    103-...:  bury the bad block with more than two weeks' worth of
              equivalent work.

Start three nodes:

    - node0 has no -assumevalid parameter. It will reject block 102 and only
      sync as far as block 101.
    - node1 has -assumevalid set to the hash of block 102. Try to sync to
      the chain tip. node1 will sync all the way to the tip.
    - node2 has -assumevalid set to the hash of block 102. Try to sync to a
      much shorter chain. node2 will reject block 102 since it is not buried
      by at least two weeks' work.
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair


class AssumeValidTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.rpc_timeout = 120

    def setup_network(self):
        self.add_nodes(3)
        # Start node0. We don't start the other nodes yet since
        # we need to pre-mine a block with an invalid transaction
        # signature so we can pass in the block hash as assumevalid.
        self.start_node(0)

    def send_blocks_until_disconnected(self, p2p_conn, blocks=None):
        """Keep sending blocks to the node until we're disconnected."""
        target_blocks = self.blocks if blocks is None else blocks
        for i in range(len(target_blocks)):
            if not p2p_conn.is_connected:
                break
            try:
                p2p_conn.send_without_ping(msg_block(target_blocks[i]))
            except IOError:
                assert not p2p_conn.is_connected
                break

    def send_headers(self, p2p_conn, blocks):
        for i in range(0, len(blocks), 2000):
            headers_message = msg_headers()
            headers_message.headers = [CBlockHeader(b) for b in blocks[i:i + 2000]]
            p2p_conn.send_without_ping(headers_message)
        # Do not wait for full header processing here. On deep chains this can
        # take long enough for the node to time out waiting for requested blocks.

    def submit_headers(self, node, blocks):
        for block in blocks:
            node.submitheader(CBlockHeader(block).serialize().hex())

    def run_test(self):
        # validation.cpp uses a strict "greater than two weeks" equivalent-work gate.
        # qbit sets nPowTargetSpacing to 60s in chainparams for all supported chains.
        # getmininginfo does not expose this consensus parameter.
        target_spacing = 60
        two_weeks = 60 * 60 * 24 * 7 * 2
        min_bury_depth = (two_weeks // target_spacing) + 1
        bury_depth = min_bury_depth + 100
        mature_chain_tip = COINBASE_MATURITY + 1

        # Build the blockchain
        self.tip = int(self.nodes[0].getbestblockhash(), 16)
        self.block_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time'] + target_spacing

        self.blocks = []

        # Get a pubkey for the coinbase TXO
        _, coinbase_pubkey = generate_keypair()

        # Create the first block with a coinbase output to our key
        height = 1
        block = create_block(self.tip, create_coinbase(height, coinbase_pubkey), self.block_time)
        self.blocks.append(block)
        self.block_time += target_spacing
        block.solve()
        # Save the coinbase for later
        self.block1 = block
        self.tip = block.hash_int
        height += 1

        # Bury the block deep enough so the coinbase output is spendable.
        for _ in range(COINBASE_MATURITY):
            block = create_block(self.tip, create_coinbase(height), self.block_time)
            block.solve()
            self.blocks.append(block)
            self.tip = block.hash_int
            self.block_time += target_spacing
            height += 1

        # Create a transaction spending the coinbase output with an invalid (null) signature
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.block1.vtx[0].txid_int, 0), scriptSig=b""))
        tx.vout.append(CTxOut(self.block1.vtx[0].vout[0].nValue - 1_000, CScript([OP_TRUE])))

        assumed_block = create_block(self.tip, create_coinbase(height), self.block_time, txlist=[tx])
        assumed_height = height
        self.block_time += target_spacing
        assumed_block.solve()
        self.blocks.append(assumed_block)
        self.tip = assumed_block.hash_int
        self.block_time += target_spacing
        height += 1

        # Bury the assumed-valid block deep enough to exceed the two-week gate.
        for _ in range(bury_depth):
            block = create_block(self.tip, create_coinbase(height), self.block_time)
            block.solve()
            self.blocks.append(block)
            self.tip = block.hash_int
            self.block_time += target_spacing
            height += 1

        # Start node1 and node2 with assumevalid so they accept a block with a bad signature.
        self.start_node(1, extra_args=["-assumevalid=" + assumed_block.hash_hex])
        self.start_node(2, extra_args=["-assumevalid=" + assumed_block.hash_hex])

        p2p0 = self.nodes[0].add_p2p_connection(P2PInterface())
        node0_blocks = self.blocks[0:assumed_height + 100]
        self.send_headers(p2p0, node0_blocks)

        # First deliver only the valid prefix to avoid disconnect races on slower CI builders.
        for block in node0_blocks[:mature_chain_tip]:
            p2p0.send_without_ping(msg_block(block))
        p2p0.sync_with_ping(timeout=120)
        assert_equal(self.nodes[0].getblockcount(), mature_chain_tip)

        # Send blocks to node0. The assumed block will be rejected.
        self.send_blocks_until_disconnected(p2p0, node0_blocks[mature_chain_tip:])
        self.wait_until(lambda: not p2p0.is_connected, timeout=60)
        assert_equal(self.nodes[0].getblockcount(), mature_chain_tip)

        p2p1 = self.nodes[1].add_p2p_connection(P2PInterface())
        with self.nodes[1].assert_debug_log(expected_msgs=['Disabling signature validations at block #1', f'Enabling signature validations at block #{assumed_height + 1}']):
            # Populate the full header chain first so assumevalid has enough chain work context.
            self.submit_headers(self.nodes[1], self.blocks)
            # Feed blocks in bounded bursts to avoid large p2p send queue stalls.
            for i in range(0, len(self.blocks), 500):
                for block in self.blocks[i:i + 500]:
                    p2p1.send_without_ping(msg_block(block))
                p2p1.sync_with_ping(timeout=300)
            self.wait_until(lambda: self.nodes[1].getblockcount() == len(self.blocks), timeout=1800)
        assert_equal(self.nodes[1].getblock(self.nodes[1].getbestblockhash())['height'], len(self.blocks))

        p2p2 = self.nodes[2].add_p2p_connection(P2PInterface())
        node2_blocks = self.blocks[0:assumed_height + 98]
        self.send_headers(p2p2, node2_blocks)

        for block in node2_blocks[:mature_chain_tip]:
            p2p2.send_without_ping(msg_block(block))
        p2p2.sync_with_ping(timeout=120)
        assert_equal(self.nodes[2].getblockcount(), mature_chain_tip)

        # Send blocks to node2. The assumed block will be rejected.
        self.send_blocks_until_disconnected(p2p2, node2_blocks[mature_chain_tip:])
        self.wait_until(lambda: not p2p2.is_connected, timeout=60)
        assert_equal(self.nodes[2].getblockcount(), mature_chain_tip)


if __name__ == '__main__':
    AssumeValidTest(__file__).main()
