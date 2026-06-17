#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that unsupported utxo db causes an init error.

Previous releases are required by this test, see test/README.md.
"""

import shutil

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


class UnsupportedUtxoDbTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(
            self.num_nodes,
            versions=[
                140300,  # Last release with previous utxo db format
                None,  # For MiniWallet, without migration code
            ],
        )

    def run_test(self):
        self.start_node(0)
        self.start_node(1)
        if self.nodes[0].getblockhash(0) != self.nodes[1].getblockhash(0):
            self.stop_nodes()
            raise SkipTest("previous release uses an incompatible regtest genesis block")
        self.stop_node(1)

        self.log.info("Create previous version (v0.14.3) utxo db")
        # Legacy nodes may reject the framework's deterministic mining address.
        # Pick a valid address for the legacy node without relying on wallet RPCs.
        candidate_addresses = [
            self.nodes[0].get_deterministic_priv_key().address,
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        ]
        legacy_mining_address = next(
            (addr for addr in candidate_addresses if self.nodes[0].validateaddress(addr)["isvalid"]),
            None,
        )
        assert legacy_mining_address is not None
        block = self.generatetoaddress(self.nodes[0], 1, legacy_mining_address, sync_fun=self.no_op)[-1]
        assert_equal(self.nodes[0].getbestblockhash(), block)
        assert_equal(self.nodes[0].gettxoutsetinfo()["total_amount"], 50)
        self.stop_nodes()

        self.log.info("Check init error")
        legacy_utxos_dir = self.nodes[0].chain_path / "chainstate"
        legacy_blocks_dir = self.nodes[0].blocks_path
        recent_utxos_dir = self.nodes[1].chain_path / "chainstate"
        recent_blocks_dir = self.nodes[1].blocks_path
        shutil.copytree(legacy_utxos_dir, recent_utxos_dir)
        shutil.copytree(legacy_blocks_dir, recent_blocks_dir)
        self.nodes[1].assert_start_raises_init_error(
            expected_msg="Error: Unsupported chainstate database format found. "
            "Please restart with -reindex-chainstate. "
            "This will rebuild the chainstate database.",
        )

        self.log.info("Drop legacy utxo db")
        self.start_node(1, extra_args=["-reindex-chainstate"])
        assert_equal(self.nodes[1].getbestblockhash(), block)
        assert_equal(self.nodes[1].gettxoutsetinfo()["total_amount"], 50)


if __name__ == "__main__":
    UnsupportedUtxoDbTest(__file__).main()
