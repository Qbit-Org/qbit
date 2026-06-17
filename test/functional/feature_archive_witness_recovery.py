#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Cover archive-assisted witness recovery routing, fallback, and reorg behavior."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    MSG_BLOCK,
    MSG_WITNESS_BLOCK,
    NODE_NETWORK,
    NODE_WITNESS,
    NODE_WITNESS_PRUNED,
    from_hex,
    msg_block,
    msg_headers,
    msg_no_witness_block,
    msg_notfound,
)
from test_framework.p2p import P2PDataStore, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal, ensure_for
from test_framework.wallet import MiniWallet


WITNESS_PRUNE_DEPTH = COINBASE_MATURITY
MAX_HEADERS_CHUNK = 2000
MAX_DIRECT_FETCH_HEADERS = 16


class SpyHistoryPeer(P2PDataStore):
    def __init__(self, blocks, retained_floor, *, historical_witness_notfound=False):
        super().__init__()
        self._retained_floor = retained_floor
        self._historical_witness_notfound = historical_witness_notfound
        self._request_log = []
        self._height_by_hash = {}
        with p2p_lock:
            for height, block in blocks:
                self.block_store[block.hash_int] = block
                self._height_by_hash[block.hash_int] = height
            self.last_block_hash = blocks[-1][1].hash_int

    def on_inv(self, message):
        pass

    def on_getdata(self, message):
        notfound = []
        for inv in message.inv:
            self._request_log.append((inv.hash, inv.type))
            if inv.hash not in self.block_store:
                notfound.append(inv)
                continue
            if inv.type == MSG_WITNESS_BLOCK and self.is_historical(inv.hash) and self._historical_witness_notfound:
                notfound.append(inv)
                continue

            block = self.block_store[inv.hash]
            if inv.type == MSG_WITNESS_BLOCK:
                self.send_without_ping(msg_block(block))
            elif inv.type == MSG_BLOCK:
                self.send_without_ping(msg_no_witness_block(block))
        if notfound:
            self.send_without_ping(msg_notfound(vec=notfound))

    def is_historical(self, block_hash_int):
        return self._height_by_hash[block_hash_int] < self._retained_floor

    def requests(self):
        with p2p_lock:
            return list(self._request_log)

    def historical_requests(self):
        return [req for req in self.requests() if self.is_historical(req[0])]

    def recent_requests(self):
        return [req for req in self.requests() if not self.is_historical(req[0])]


class ArchiveWitnessRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        self.rpc_timeout = 600
        self.extra_args = [
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune", "-prunewitnesses=1"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_blocks(self.nodes[:3])

    def mine_blocks_with_witness_txs(self, node, wallet, count):
        for _ in range(count):
            wallet.send_self_transfer(from_node=node)
            self.generate(node, 1, sync_fun=self.no_op)

    @staticmethod
    def assert_stripped_matches_no_witness(stripped_hex, full_hex):
        full_block = from_hex(CBlock(), full_hex)
        full_witness = full_block.serialize()
        full_no_witness = full_block.serialize(False)
        assert_not_equal(full_witness, full_no_witness)
        assert_equal(bytes.fromhex(stripped_hex), full_no_witness)

    def collect_blocks(self, node):
        blocks = []
        for height in range(node.getblockcount() + 1):
            block_hash = node.getblockhash(height)
            block = from_hex(CBlock(), node.getblock(block_hash, False))
            blocks.append((height, block))
        return blocks

    def announce_headers(self, peer, blocks):
        headers_only = [CBlockHeader(block) for _, block in blocks]
        for idx in range(0, len(headers_only), MAX_HEADERS_CHUNK):
            msg = msg_headers()
            msg.headers = headers_only[idx:idx + MAX_HEADERS_CHUNK]
            peer.send_and_ping(msg)

    def announce_handoff_headers(self, requester, peer, blocks):
        # Keep the archive peer within the node's direct-fetch window so the
        # handoff does not trigger the large-reorg path during IBD stall recovery.
        next_height = requester.getblockcount() + 1
        while next_height < len(blocks):
            stop = min(len(blocks), next_height + MAX_DIRECT_FETCH_HEADERS)
            msg = msg_headers()
            msg.headers = [CBlockHeader(block) for _, block in blocks[next_height:stop]]
            peer.send_without_ping(msg)

            target_height = stop - 1
            self.wait_until(
                lambda: requester.getblockcount() >= target_height or not peer.is_connected,
                timeout=120,
            )
            assert peer.is_connected, f"archive peer disconnected while handing off through height {target_height}"
            next_height = requester.getblockcount() + 1

    def run_routing_assertions(self, chain_blocks, retained_floor, tip_height):
        requester = self.nodes[3]
        archive_peer = requester.add_p2p_connection(
            SpyHistoryPeer(chain_blocks, retained_floor),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        pruned_peer = requester.add_p2p_connection(
            SpyHistoryPeer(chain_blocks, retained_floor, historical_witness_notfound=True),
            services=NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED,
        )

        self.announce_headers(archive_peer, chain_blocks[1:])
        self.announce_headers(pruned_peer, chain_blocks[1:])

        self.wait_until(lambda: archive_peer.historical_requests(), timeout=120)
        self.wait_until(lambda: requester.getblockcount() >= retained_floor - 1, timeout=240)
        archive_peer.peer_disconnect()
        archive_peer.wait_for_disconnect(timeout=30)

        self.wait_until(lambda: requester.getblockcount() == tip_height, timeout=240)

        historical_archive = archive_peer.historical_requests()
        assert historical_archive
        assert all(inv_type == MSG_WITNESS_BLOCK for _, inv_type in historical_archive)
        assert not pruned_peer.historical_requests()
        assert pruned_peer.recent_requests()

    def run_assumevalid_requires_archive_assertions(self, chain_blocks, retained_floor, tip_height, assumevalid_hash):
        self.restart_node(4, extra_args=["-dnsseed=0", "-fixedseeds=0", "-fastprune", f"-assumevalid={assumevalid_hash}"])
        requester = self.nodes[4]
        pruned_peer = requester.add_p2p_connection(
            SpyHistoryPeer(chain_blocks, retained_floor, historical_witness_notfound=True),
            services=NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED,
        )

        self.announce_headers(pruned_peer, chain_blocks[1:])
        self.wait_until(
            lambda: requester.getpeerinfo() and requester.getpeerinfo()[0]["synced_headers"] >= tip_height,
            timeout=120,
        )
        self.wait_until(
            lambda: (
                requester.getpeerinfo()
                and requester.getblockcount() < tip_height
                and not requester.getpeerinfo()[0]["inflight"]
            ),
            timeout=120,
        )
        stalled_blockcount = requester.getblockcount()
        ensure_for(
            duration=5,
            check_interval=0.1,
            f=lambda: requester.getblockcount() == stalled_blockcount,
        )

        # The pruned peer can be asked for blocks that only become "historical"
        # relative to the final retained floor once the requester learns the full tip.
        # Those requests must stay witness-bearing and must not grow after an
        # archive peer is available for the true historical range.
        pruned_historical = pruned_peer.historical_requests()
        assert pruned_historical
        assert all(inv_type == MSG_WITNESS_BLOCK for _, inv_type in pruned_historical)

        archive_peer = requester.add_p2p_connection(
            SpyHistoryPeer(chain_blocks, retained_floor),
            services=NODE_NETWORK | NODE_WITNESS,
        )

        self.announce_handoff_headers(requester, archive_peer, chain_blocks)
        self.wait_until(lambda: archive_peer.historical_requests(), timeout=120)
        self.wait_until(lambda: requester.getblockcount() == tip_height, timeout=240)

        historical = archive_peer.historical_requests()
        assert historical
        assert all(inv_type == MSG_WITNESS_BLOCK for _, inv_type in historical)
        assert pruned_peer.historical_requests() == pruned_historical

    def run_recovery_reorg_assertions(self, pruned_hash, pruned_height):
        requester = self.nodes[0]
        archive_source = self.nodes[1]
        old_chain_source = self.nodes[2]

        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)

        fork_height = pruned_height - 1
        fork_next_hash = archive_source.getblockhash(fork_height + 1)
        old_tip_height = old_chain_source.getblockcount()
        old_tip_hash = old_chain_source.getbestblockhash()

        archive_source.invalidateblock(fork_next_hash)
        self.generate(archive_source, old_tip_height - fork_height + 2, sync_fun=self.no_op)
        archive_tip_hash = archive_source.getbestblockhash()
        archive_tip_height = archive_source.getblockcount()

        self.connect_nodes(0, 1)
        self.sync_blocks([requester, archive_source])
        assert_equal(requester.getbestblockhash(), archive_tip_hash)
        self.disconnect_nodes(0, 1)

        assert_equal(old_chain_source.getbestblockhash(), old_tip_hash)
        self.generate(old_chain_source, archive_tip_height - old_tip_height + 2, sync_fun=self.no_op)
        assert old_chain_source.getblockcount() > archive_tip_height

        old_chain_blocks = self.collect_blocks(old_chain_source)
        retained_floor = old_chain_source.getblockcount() - WITNESS_PRUNE_DEPTH
        new_tail_blocks = old_chain_blocks[old_tip_height + 1:]

        fallback_peer = requester.add_p2p_connection(
            SpyHistoryPeer(old_chain_blocks, retained_floor, historical_witness_notfound=True),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.announce_headers(fallback_peer, new_tail_blocks)
        self.wait_until(lambda: fallback_peer.historical_requests(), timeout=120)
        fallback_request_count = len(fallback_peer.historical_requests())

        ensure_for(
            duration=5,
            check_interval=0.1,
            f=lambda: requester.getbestblockhash() == archive_tip_hash,
        )

        archive_peer = requester.add_p2p_connection(
            SpyHistoryPeer(old_chain_blocks, retained_floor),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.announce_headers(archive_peer, new_tail_blocks)

        self.wait_until(lambda: archive_peer.historical_requests(), timeout=120)
        self.wait_until(lambda: requester.getbestblockhash() == old_chain_source.getbestblockhash(), timeout=240)
        ensure_for(
            duration=5,
            check_interval=0.1,
            f=lambda: len(fallback_peer.historical_requests()) == fallback_request_count,
        )

        self.assert_stripped_matches_no_witness(
            requester.getblock(pruned_hash, False),
            old_chain_source.getblock(pruned_hash, False),
        )
        assert int(requester.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED

    def run_test(self):
        requester = self.nodes[0]
        archive_source = self.nodes[1]
        old_chain_source = self.nodes[2]
        wallet = MiniWallet(archive_source)

        self.log.info("Build a witness-bearing history and wait for local compaction on the requester")
        self.generate(wallet, WITNESS_PRUNE_DEPTH + 5, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])

        start_height = requester.getblockcount()
        self.mine_blocks_with_witness_txs(archive_source, wallet, 300)
        self.generate(archive_source, 900, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])

        pruned_height = start_height + 20
        pruned_hash = requester.getblockhash(pruned_height)
        tip_height = archive_source.getblockcount()
        retained_floor = tip_height - WITNESS_PRUNE_DEPTH
        assumevalid_hash = old_chain_source.getblockhash(tip_height - 5)

        def requester_is_witness_pruned():
            if "WITNESS_PRUNED" not in requester.getnetworkinfo()["localservicesnames"]:
                return False
            try:
                self.assert_stripped_matches_no_witness(
                    requester.getblock(pruned_hash, False),
                    archive_source.getblock(pruned_hash, False),
                )
            except AssertionError:
                return False
            return True

        self.wait_until(requester_is_witness_pruned, timeout=120)

        chain_blocks = self.collect_blocks(old_chain_source)

        self.log.info("Assert exact historical/recent request routing with archive and witness-pruned peers")
        self.run_routing_assertions(chain_blocks, retained_floor, tip_height)

        self.log.info("Assert assumevalid-covered history still requires an archive peer")
        self.run_assumevalid_requires_archive_assertions(chain_blocks, retained_floor, tip_height, assumevalid_hash)

        self.log.info("Assert temporary recovery plus NOTFOUND fallback in a deep reorg scenario")
        self.run_recovery_reorg_assertions(pruned_hash, pruned_height)


if __name__ == "__main__":
    ArchiveWitnessRecoveryTest(__file__).main()
