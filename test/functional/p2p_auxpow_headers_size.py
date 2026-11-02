#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that 'headers' messages carrying large AuxPoW payloads stay within the
protocol message limit, and that headers sync continues across messages that
were cut short by size rather than by count."""

from test_framework.auxpow import (
    BLOCK_VERSION_AUXPOW,
    make_valid_auxpow_from_template,
)
from test_framework.messages import (
    CBlockHeader,
    CTransaction,
    CTxOut,
    MAX_HEADERS_RESULTS,
    MAX_PROTOCOL_MESSAGE_LENGTH,
    MSG_BLOCK,
    deser_compact_size,
    deser_uint256_vector,
    msg_getheaders,
    msg_sendheaders,
)
from test_framework.p2p import (
    MESSAGEMAP,
    P2PInterface,
    p2p_lock,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
    getnewdestination,
)

MAX_BLOCK_SERIALIZED_SIZE = 2_000_000
# A 'headers' message with fewer than MAX_HEADERS_RESULTS headers, but at least
# this size, may have been cut short by size.
THRESHOLD_HEADERS_MESSAGE_SIZE = MAX_PROTOCOL_MESSAGE_LENGTH - MAX_BLOCK_SERIALIZED_SIZE
# Three headers with a parent coinbase output this large exceed one message,
# while each block stays below the block weight limit.
LARGE_AUXPOW_SCRIPT_SIZE = 1_400_000
LARGE_AUXPOW_BLOCKS = 4


class msg_auxpow_headers:
    """A 'headers' message whose headers may carry an AuxPoW payload."""
    __slots__ = ("hashes", "payload_size")
    msgtype = b"headers"

    def __init__(self):
        self.hashes = []
        self.payload_size = 0

    def deserialize(self, f):
        self.payload_size = len(f.getvalue())
        for _ in range(deser_compact_size(f)):
            header = CBlockHeader()
            header.deserialize(f)
            if header.nVersion & BLOCK_VERSION_AUXPOW:
                CTransaction().deserialize(f)  # parent coinbase
                deser_uint256_vector(f)  # coinbase merkle branch
                f.read(4)  # coinbase branch index
                deser_uint256_vector(f)  # chain merkle branch
                f.read(4)  # chain index
                CBlockHeader().deserialize(f)  # parent header
            assert_equal(deser_compact_size(f), 0)
            self.hashes.append(header.hash_int)
        assert_equal(f.tell(), self.payload_size)

    def __repr__(self):
        return f"msg_auxpow_headers(count={len(self.hashes)}, payload_size={self.payload_size})"


class AuxpowHeadersPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.headers_messages = []
        self.block_invs = []

    def on_headers(self, message):
        self.headers_messages.append(message)

    def on_inv(self, message):
        # Record block announcements without requesting the blocks.
        self.block_invs.extend(inv.hash for inv in message.inv if inv.type == MSG_BLOCK)


class AuxpowHeadersSizeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-asert", "-p2mronly=1"]] * self.num_nodes

    def setup_network(self):
        self.setup_nodes()

    def advance_mock_time(self, seconds=600):
        self.mock_time += seconds
        for node in self.nodes:
            node.setmocktime(self.mock_time)

    def mine_large_auxpow_block(self, payout_address):
        node = self.nodes[0]
        self.advance_mock_time()
        template = node.createauxblock(payout_address)
        auxpow = make_valid_auxpow_from_template(template, parent_time=self.mock_time)
        # Only the qbit block weight limit bounds the parent coinbase.
        auxpow.coinbase_tx.vout.append(CTxOut(0, CScript(bytes(LARGE_AUXPOW_SCRIPT_SIZE))))
        auxpow.update_parent_merkle_root()
        auxpow.solve_parent_pow()
        assert_equal(node.submitauxblock(template["hash"], auxpow.to_hex()), None)
        assert_equal(node.getbestblockhash(), template["hash"])
        return int(template["hash"], 16)

    def request_headers(self, peer, locator_hash):
        with p2p_lock:
            received = len(peer.headers_messages)
        getheaders = msg_getheaders()
        getheaders.locator.vHave = [locator_hash]
        peer.send_without_ping(getheaders)
        peer.wait_until(lambda: len(peer.headers_messages) > received)
        with p2p_lock:
            return peer.headers_messages[received]

    def run_test(self):
        # The default 'headers' message cannot parse AuxPoW payloads.
        MESSAGEMAP[b"headers"] = msg_auxpow_headers

        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_P2MR_OP_TRUE)
        self.mock_time = node.getblockheader(node.getbestblockhash())["time"]
        self.advance_mock_time()
        self.generate(wallet, 10, sync_fun=self.no_op)
        _, _, payout_address = getnewdestination("p2mr")

        self.log.info("Mine AuxPoW blocks whose headers do not fit in one message")
        large_hashes = [self.mine_large_auxpow_block(payout_address) for _ in range(LARGE_AUXPOW_BLOCKS)]
        for block_hash in large_hashes:
            block_size = node.getblock(f"{block_hash:064x}")["size"]
            assert_greater_than(block_size, LARGE_AUXPOW_SCRIPT_SIZE)
            assert_greater_than(MAX_BLOCK_SERIALIZED_SIZE, block_size)
        self.advance_mock_time()
        self.generate(wallet, 2, sync_fun=self.no_op)
        chain = [int(node.getblockhash(height), 16) for height in range(1, node.getblockcount() + 1)]
        tip = chain[-1]

        self.log.info("A getheaders response is cut short by size and stays within the message limit")
        peer = node.add_p2p_connection(AuxpowHeadersPeer())
        genesis = int(node.getblockhash(0), 16)
        first = self.request_headers(peer, genesis)
        assert_greater_than_or_equal(MAX_PROTOCOL_MESSAGE_LENGTH, first.payload_size)
        assert_greater_than_or_equal(first.payload_size, THRESHOLD_HEADERS_MESSAGE_SIZE)
        assert_greater_than(len(chain), len(first.hashes))
        assert_greater_than(MAX_HEADERS_RESULTS, len(first.hashes))
        assert_equal(first.hashes, chain[:len(first.hashes)])
        rest = self.request_headers(peer, first.hashes[-1])
        assert_greater_than_or_equal(MAX_PROTOCOL_MESSAGE_LENGTH, rest.payload_size)
        assert_equal(first.hashes + rest.hashes, chain)

        self.log.info("A headers announcement too large for one message falls back to inv")
        peer.send_and_ping(msg_sendheaders())
        node.invalidateblock(f"{large_hashes[0]:064x}")
        self.advance_mock_time()
        fork_hash = int(self.generate(wallet, 1, sync_fun=self.no_op)[0], 16)
        peer.wait_until(lambda: any(fork_hash in message.hashes for message in peer.headers_messages))
        node.reconsiderblock(f"{large_hashes[0]:064x}")
        assert_equal(int(node.getbestblockhash(), 16), tip)
        peer.wait_until(lambda: tip in peer.block_invs)
        peer.sync_with_ping()
        with p2p_lock:
            for message in peer.headers_messages:
                assert_greater_than_or_equal(MAX_PROTOCOL_MESSAGE_LENGTH, message.payload_size)
        node.disconnect_p2ps()

        self.log.info("Nodes sync across headers messages cut short by size")
        tip_chainwork = node.getblockheader(f"{tip:064x}")["chainwork"]
        # Node 2 syncs through the low-work headers presync and redownload phases.
        self.restart_node(2, extra_args=self.extra_args[2] + [f"-mocktime={self.mock_time}", f"-minimumchainwork={tip_chainwork}"])
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 0)
        self.sync_blocks()
        for receiver in self.nodes[1:]:
            assert_equal(int(receiver.getbestblockhash(), 16), tip)
            assert_equal(len(receiver.getpeerinfo()), 1)


if __name__ == '__main__':
    AuxpowHeadersSizeTest(__file__).main()
