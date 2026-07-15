#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test requested block bodies below configured minimum chain work."""

import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import CBlockHeader
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


MINIMUM_CHAIN_WORK = 0x10


class RequestedBlockMinimumChainWorkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [
            [f"-minimumchainwork=0x{MINIMUM_CHAIN_WORK:x}", "-checkblockindex=0"],
            [],
            [f"-minimumchainwork=0x{MINIMUM_CHAIN_WORK:x}", "-checkblockindex=0", "-fastprune", "-prune=1"],
            [f"-minimumchainwork=0x{MINIMUM_CHAIN_WORK:x}", "-checkblockindex=0"],
        ]
        # This test uses long, synthetic timestamp sequences to exercise
        # minimum-chain-work behavior, not future-time validation.
        for args in self.extra_args:
            args.append("-testactivationheight=futuretime@10000000")

    def submit_header(self, node, block):
        node.submitheader(CBlockHeader(block).serialize().hex())
        return int(node.getblockheader(block.hash_hex)["chainwork"], 16)

    def submit_headers_until_work(
        self, node, prev_hash, start_height, block_time, work_floor
    ):
        blocks = []
        chain_work = 0
        while chain_work < work_floor:
            block = create_block(
                hashprev=prev_hash,
                coinbase=create_coinbase(start_height),
                ntime=block_time,
            )
            block.solve()
            chain_work = self.submit_header(node, block)
            blocks.append(block)
            prev_hash = block.hash_int
            start_height += 1
            block_time += 1
        return blocks, chain_work, block_time

    def assert_block_not_available(self, node, block_hash):
        assert_raises_rpc_error(-1, "Block not available", node.getblock, block_hash)

    def block_available(self, node, block_hash):
        try:
            return node.getblock(block_hash)["hash"] == block_hash
        except JSONRPCException:
            return False

    def peer_id_for_connection(self, node, peer):
        sockname = peer._transport.get_extra_info("socket").getsockname()
        addr = f"{sockname[0]}:{sockname[1]}"
        addrbind = f"{peer.dstaddr}:{peer.dstport}"
        info = [p for p in node.getpeerinfo() if p["addr"] == addr and p["addrbind"] == addrbind]
        assert_equal(len(info), 1)
        return info[0]["id"]

    def run_test(self):
        node = self.nodes[0]
        genesis_hash = node.getblockhash(0)
        block_time = int(time.time()) + 1

        self.log.info("Submit a below-minimum-chainwork header through the trusted RPC path")
        low_work_block = create_block(
            hashprev=int(genesis_hash, 16),
            coinbase=create_coinbase(1),
            ntime=block_time,
        )
        low_work_block.solve()
        low_work_chain_work = self.submit_header(node, low_work_block)
        assert low_work_chain_work < MINIMUM_CHAIN_WORK

        assert_equal(node.getbestblockhash(), genesis_hash)
        self.assert_block_not_available(node, low_work_block.hash_hex)

        self.log.info("Do not schedule an explicit fetch for an isolated below-floor block")
        peer = node.add_p2p_connection(P2PDataStore())
        peer.block_store[low_work_block.hash_int] = low_work_block
        peer.last_block_hash = low_work_block.hash_int
        peer_id = self.peer_id_for_connection(node, peer)

        assert_raises_rpc_error(
            -1,
            "Block does not meet minimum chain work",
            node.getblockfrompeer,
            low_work_block.hash_hex,
            peer_id,
        )
        peer.sync_with_ping()
        assert low_work_block.hash_int not in peer.getdata_requests
        assert_equal(node.getbestblockhash(), genesis_hash)
        self.assert_block_not_available(node, low_work_block.hash_hex)

        self.log.info("Allow fetching the same below-floor block once it is on a sufficiently-worked header chain")
        prev_block = low_work_block
        height = 2
        chain_work = low_work_chain_work
        while chain_work < MINIMUM_CHAIN_WORK:
            block_time += 1
            next_block = create_block(
                hashprev=prev_block.hash_int,
                coinbase=create_coinbase(height),
                ntime=block_time,
            )
            next_block.solve()
            chain_work = self.submit_header(node, next_block)
            prev_block = next_block
            height += 1

        assert_equal(node.getblockfrompeer(low_work_block.hash_hex, peer_id), {})
        peer.wait_until(lambda: low_work_block.hash_int in peer.getdata_requests)
        self.wait_until(lambda: self.block_available(node, low_work_block.hash_hex))

        self.log.info("Allow fetching below-floor blocks from non-best sufficiently-worked header chains")
        fork_node = self.nodes[3]
        fork_peer = fork_node.add_p2p_connection(P2PDataStore())
        fork_peer_id = self.peer_id_for_connection(fork_node, fork_peer)
        fork_genesis_hash = fork_node.getblockhash(0)
        fork_genesis_int = int(fork_genesis_hash, 16)

        fork_b_blocks, fork_b_chain_work, fork_time = self.submit_headers_until_work(
            fork_node,
            fork_genesis_int,
            1,
            int(time.time()) + 1,
            MINIMUM_CHAIN_WORK,
        )
        fork_b_first = fork_b_blocks[0]
        fork_b_first_chain_work = int(
            fork_node.getblockheader(fork_b_first.hash_hex)["chainwork"], 16
        )
        assert fork_b_first_chain_work < MINIMUM_CHAIN_WORK
        assert fork_b_chain_work >= MINIMUM_CHAIN_WORK

        fork_a_blocks = []
        fork_a_prev_hash = fork_genesis_int
        fork_a_height = 1
        fork_a_chain_work = 0
        fork_time += 1000
        while fork_a_chain_work <= fork_b_chain_work:
            fork_a_block = create_block(
                hashprev=fork_a_prev_hash,
                coinbase=create_coinbase(fork_a_height),
                ntime=fork_time,
            )
            fork_a_block.solve()
            fork_a_chain_work = self.submit_header(fork_node, fork_a_block)
            fork_a_blocks.append(fork_a_block)
            fork_a_prev_hash = fork_a_block.hash_int
            fork_a_height += 1
            fork_time += 1

        assert_equal(fork_node.getbestblockhash(), fork_genesis_hash)
        assert_equal(fork_node.getblockchaininfo()["headers"], len(fork_a_blocks))
        assert fork_a_blocks[-1].hash_hex != fork_b_blocks[-1].hash_hex

        fork_peer.block_store[fork_b_first.hash_int] = fork_b_first
        fork_peer.last_block_hash = fork_b_first.hash_int
        assert_equal(fork_node.getblockfrompeer(fork_b_first.hash_hex, fork_peer_id), {})
        fork_peer.wait_until(lambda: fork_b_first.hash_int in fork_peer.getdata_requests)
        self.wait_until(lambda: self.block_available(fork_node, fork_b_first.hash_hex))

        self.log.info("Allow fetching pruned below-floor active-chain blocks even when best header is on another fork")
        full_node = self.nodes[1]
        pruned_node = self.nodes[2]

        self.generate(full_node, 650, sync_fun=self.no_op)
        self.connect_nodes(1, 2)
        self.sync_blocks([full_node, pruned_node])

        active_tip_hash = pruned_node.getbestblockhash()
        active_height = pruned_node.getblockcount()
        pruned_block_hash = pruned_node.getblockhash(2)
        pruned_block_chain_work = int(pruned_node.getblockheader(pruned_block_hash)["chainwork"], 16)
        assert pruned_block_chain_work < MINIMUM_CHAIN_WORK
        assert int(pruned_node.getblockheader(active_tip_hash)["chainwork"], 16) >= MINIMUM_CHAIN_WORK

        pruned_node.pruneblockchain(300)
        assert_raises_rpc_error(-1, "Block not available (pruned data)", pruned_node.getblock, pruned_block_hash)

        fork_prev_hash = int(pruned_node.getblockhash(0), 16)
        fork_time = int(time.time()) + 1
        for fork_height in range(1, active_height + 2):
            fork_block = create_block(
                hashprev=fork_prev_hash,
                coinbase=create_coinbase(fork_height),
                ntime=fork_time,
            )
            fork_block.solve()
            pruned_node.submitheader(CBlockHeader(fork_block).serialize().hex())
            fork_prev_hash = fork_block.hash_int
            fork_time += 1

        assert_equal(pruned_node.getbestblockhash(), active_tip_hash)
        assert_equal(pruned_node.getblockchaininfo()["headers"], active_height + 1)

        peer_id = pruned_node.getpeerinfo()[0]["id"]
        assert_equal(pruned_node.getblockfrompeer(pruned_block_hash, peer_id), {})
        self.wait_until(lambda: self.block_available(pruned_node, pruned_block_hash))


if __name__ == '__main__':
    RequestedBlockMinimumChainWorkTest(__file__).main()
