#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise mixed archive / witness-pruned / regular sync behavior."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CBlock, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal, assert_raises_rpc_error, ensure_for
from test_framework.wallet import MiniWallet


WITNESS_PRUNE_DEPTH = COINBASE_MATURITY
VERBOSE_WITNESS_PRUNED_ERROR = (
    "Verbose block view unavailable: witness data for this historical block was pruned; "
    "use verbosity=0 to fetch stored block bytes."
)


class IntegrationArchivePrunedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.rpc_timeout = 600
        self.extra_args = [
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune", "-prunewitnesses=1", "-debug=net"],
            ["-dnsseed=0", "-fixedseeds=0"],
            ["-dnsseed=0", "-fixedseeds=0"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
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

    def find_peer(self, node, peer_index):
        marker = f"testnode{peer_index}"
        for peer in node.getpeerinfo():
            if marker in peer.get("subver", ""):
                return peer
        return None

    @staticmethod
    def assert_verbose_block_equal(left_node, right_node, block_hash, verbosity):
        assert_equal(left_node.getblock(block_hash, verbosity), right_node.getblock(block_hash, verbosity))

    def run_test(self):
        archive_node = self.nodes[0]
        pruned_node = self.nodes[1]
        regular_node = self.nodes[2]
        sync_node = self.nodes[3]
        wallet = MiniWallet(archive_node)

        self.log.info("Build witness-bearing history across archive -> pruned -> regular")
        self.generate(wallet, WITNESS_PRUNE_DEPTH + 5, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])

        witness_start_height = archive_node.getblockcount() + 1
        self.mine_blocks_with_witness_txs(archive_node, wallet, 300)
        self.generate(archive_node, 900, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[:3])

        historical_height = witness_start_height + 20
        historical_hash = archive_node.getblockhash(historical_height)
        archive_block_hex = archive_node.getblock(historical_hash, False)

        self.log.info("Wait for compaction and verify mixed historical availability past prune depth")

        def historical_split():
            if "WITNESS_PRUNED" not in pruned_node.getnetworkinfo()["localservicesnames"]:
                return False
            try:
                self.assert_stripped_matches_no_witness(pruned_node.getblock(historical_hash, False), archive_block_hex)
            except AssertionError:
                return False
            return regular_node.getblock(historical_hash, False) == archive_block_hex

        self.wait_until(historical_split, timeout=120)
        assert_equal(regular_node.getblock(historical_hash, False), archive_block_hex)
        assert_not_equal(pruned_node.getblock(historical_hash, False), archive_block_hex)

        self.log.info("Verbose getblock rejects witness-pruned history and stays canonical on full-history peers")
        for verbosity in range(1, 4):
            assert_raises_rpc_error(-1, VERBOSE_WITNESS_PRUNED_ERROR, pruned_node.getblock, historical_hash, verbosity)
            self.assert_verbose_block_equal(regular_node, archive_node, historical_hash, verbosity)

        self.log.info("A regular node that already has history still tracks new blocks through the pruned relay")
        tip_hash = self.generate(archive_node, 1, sync_fun=self.no_op)[0]
        self.sync_blocks(self.nodes[:3])
        assert_equal(regular_node.getbestblockhash(), tip_hash)

        tip_height = archive_node.getblockcount()
        retained_floor = tip_height - WITNESS_PRUNE_DEPTH
        assert historical_height < retained_floor

        self.log.info("A fresh full-validation node stalls when only witness-pruned history is reachable")
        self.connect_nodes(3, 1)
        self.wait_until(lambda: self.find_peer(sync_node, 1) is not None)
        self.wait_until(lambda: self.find_peer(pruned_node, 3) is not None)

        def pruned_headers_synced():
            pruned_peer = self.find_peer(sync_node, 1)
            return pruned_peer is not None and pruned_peer["synced_headers"] >= tip_height

        self.wait_until(pruned_headers_synced, timeout=60)
        ensure_for(
            duration=5,
            check_interval=0.1,
            f=lambda: sync_node.getblockcount() == 0,
        )

        pruned_sync_peer_id = self.find_peer(pruned_node, 3)["id"]
        pruned_log_start = pruned_node.debug_log_size(encoding="utf-8")
        retained_blocks = [
            (height, archive_node.getblockhash(height))
            for height in range(retained_floor, tip_height + 1)
        ]

        self.log.info("Adding a full-history regular peer restores sync and takes over historical requests")
        self.connect_nodes(3, 2)
        self.wait_until(lambda: self.find_peer(sync_node, 2) is not None)

        self.wait_until(lambda: sync_node.getblockcount() > 0, timeout=120)

        self.log.info("The witness-pruned peer completes sync once requests reach its retained window")
        self.wait_until(lambda: sync_node.getblockcount() == tip_height, timeout=240)
        assert_equal(sync_node.getbestblockhash(), tip_hash)

        served_retained_block = None

        def pruned_served_retained_block():
            nonlocal served_retained_block
            with open(pruned_node.debug_log_path, encoding="utf-8", errors="replace") as debug_log:
                debug_log.seek(pruned_log_start)
                log = debug_log.read()
            for height, block_hash in retained_blocks:
                expected_log = f"received getdata for: witness-block {block_hash} peer={pruned_sync_peer_id}"
                if expected_log in log:
                    served_retained_block = (height, block_hash)
                    return True
            return False

        self.wait_until(pruned_served_retained_block, timeout=30)
        self.log.info(
            "Witness-pruned peer served retained block %s at height %d",
            served_retained_block[1],
            served_retained_block[0],
        )

        self.log.info("Historical blocks stay full on the recovered regular node even with pruned peers in the topology")
        sync_block_hex = sync_node.getblock(historical_hash, False)
        assert_equal(sync_block_hex, archive_block_hex)
        self.assert_stripped_matches_no_witness(pruned_node.getblock(historical_hash, False), sync_block_hex)
        for verbosity in range(1, 4):
            self.assert_verbose_block_equal(sync_node, archive_node, historical_hash, verbosity)


if __name__ == "__main__":
    IntegrationArchivePrunedTest(__file__).main()
