#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test validated block download timeout during shallow IBD.
"""

import time

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    MSG_BLOCK,
    MSG_TYPE_MASK,
)
from test_framework.p2p import (
    CBlockHeader,
    msg_headers,
    P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


BLOCK_DOWNLOAD_TIMEOUT_INTERVAL = 60


class P2PBlockWithholder(P2PDataStore):
    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            assert_equal(inv.type & MSG_TYPE_MASK, MSG_BLOCK)


class P2PIBDValidatedBlockTimeoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        self.mocktime = int(time.time()) + 1
        node.setmocktime(self.mocktime)

        tip = int(node.getbestblockhash(), 16)
        block_time = node.getblock(node.getbestblockhash())["time"] + 1
        block = create_block(tip, create_coinbase(height=1), block_time)
        block.solve()

        peer = node.add_outbound_p2p_connection(
            P2PBlockWithholder(),
            p2p_idx=0,
            connection_type="outbound-full-relay",
        )

        self.log.info("Request one validated block without filling the 1024-block stall window")
        with node.assert_debug_log(
            expected_msgs=["Timeout downloading block"],
            unexpected_msgs=["Stall started"],
        ):
            peer.send_without_ping(msg_headers([CBlockHeader(block)]))
            self.wait_until(lambda: block.hash_int in peer.getdata_requests)

            self.log.info("Check the peer stays connected at the exact qbit timeout boundary")
            node.setmocktime(self.mocktime + BLOCK_DOWNLOAD_TIMEOUT_INTERVAL)
            peer.sync_with_ping()
            assert_equal(node.num_test_p2p_connections(), 1)

            self.log.info("Check the peer disconnects after the qbit timeout boundary")
            node.setmocktime(self.mocktime + BLOCK_DOWNLOAD_TIMEOUT_INTERVAL + 1)
            peer.wait_for_disconnect()


if __name__ == "__main__":
    P2PIBDValidatedBlockTimeoutTest(__file__).main()
