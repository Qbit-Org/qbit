#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block NOTFOUND handling for in-flight downloads."""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    CInv,
    MSG_WITNESS_BLOCK,
    msg_headers,
    msg_notfound,
)
from test_framework.p2p import (
    P2PDataStore,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class NotFoundBlockPeer(P2PDataStore):
    def __init__(self, block_hash):
        super().__init__()
        self.block_hash = block_hash
        self.notfound_sent = False

    def on_getdata(self, message):
        notfound = []
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            if inv.hash == self.block_hash:
                notfound.append(inv)
        if notfound:
            self.notfound_sent = True
            self.send_without_ping(msg_notfound(vec=notfound))

    def on_getheaders(self, message):
        pass

    def sent_notfound(self):
        with p2p_lock:
            return self.notfound_sent


class P2PBlockNotFoundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def make_next_block(self):
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block_time = node.getblock(node.getbestblockhash())["time"] + 1
        block = create_block(tip, create_coinbase(height), block_time)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        block = self.make_next_block()

        self.log.info("Spurious block NOTFOUND is ignored when no matching block is in flight")
        spurious_peer = node.add_p2p_connection(P2PDataStore())
        spurious_peer.send_and_ping(msg_notfound(vec=[CInv(MSG_WITNESS_BLOCK, block.hash_int)]))
        assert_equal(node.num_test_p2p_connections(), 1)
        spurious_peer.peer_disconnect()
        spurious_peer.wait_for_disconnect()

        self.log.info("Unexpected NOTFOUND for an in-flight block disconnects the peer")
        notfound_peer = node.add_p2p_connection(NotFoundBlockPeer(block.hash_int))
        notfound_peer.send_without_ping(msg_headers(headers=[CBlockHeader(block)]))
        self.wait_until(lambda: notfound_peer.sent_notfound())
        notfound_peer.wait_for_disconnect()


if __name__ == "__main__":
    P2PBlockNotFoundTest(__file__).main()
