#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_not_equal,
    assert_raises_rpc_error,
    sha256sum_file,
)


class DumptxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def check_expected_network(self, node, active):
        rev_file = node.blocks_path / "rev00000.dat"
        bogus_file = node.blocks_path / "bogus.dat"
        rev_file.rename(bogus_file)
        assert_raises_rpc_error(
            -1, 'Could not roll back to requested height.', node.dumptxoutset, 'utxos.dat', rollback=99)
        assert_equal(node.getnetworkinfo()['networkactive'], active)

        # Cleanup
        bogus_file.rename(rev_file)

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)
        chainstates = node.getchainstates()["chainstates"]
        assert_equal(len(chainstates), 1)
        assert_equal(chainstates[0]["blocks"], node.getblockcount())

        FILENAME = 'txoutset.dat'
        out = node.dumptxoutset(FILENAME, "latest")
        expected_path = node.chain_path / FILENAME

        assert expected_path.is_file()

        assert_equal(out['coins_written'], COINBASE_MATURITY)
        assert_equal(out['base_height'], COINBASE_MATURITY)
        assert_equal(out['path'], str(expected_path))
        assert_equal(out['base_hash'], node.getblockhash(COINBASE_MATURITY))

        snapshot_file_hash = sha256sum_file(str(expected_path)).hex()

        # Dumping twice at the same tip should produce identical snapshots.
        second_filename = "txoutset_again.dat"
        out_second = node.dumptxoutset(second_filename, "latest")
        second_path = node.chain_path / second_filename
        assert second_path.is_file()
        assert_equal(out_second['coins_written'], out['coins_written'])
        assert_equal(out_second['base_height'], out['base_height'])
        assert_equal(out_second['base_hash'], out['base_hash'])
        assert_equal(out_second['txoutset_hash'], out['txoutset_hash'])
        assert_equal(out_second['nchaintx'], out['nchaintx'])
        assert_equal(sha256sum_file(str(second_path)).hex(), snapshot_file_hash)

        utxo_info = node.gettxoutsetinfo("hash_serialized_3")
        assert_equal(out['txoutset_hash'], utxo_info['hash_serialized_3'])
        assert_equal(out['nchaintx'], COINBASE_MATURITY + 1)

        # Advancing the tip should change the serialized snapshot.
        self.generate(node, 1)
        third_filename = "txoutset_after_tip.dat"
        out_third = node.dumptxoutset(third_filename, "latest")
        third_path = node.chain_path / third_filename
        assert third_path.is_file()
        assert_equal(out_third['base_height'], COINBASE_MATURITY + 1)
        assert_not_equal(out_third['base_hash'], out['base_hash'])
        assert_not_equal(out_third['txoutset_hash'], out['txoutset_hash'])
        assert_not_equal(sha256sum_file(str(third_path)).hex(), snapshot_file_hash)

        # Specifying a path to an existing or invalid file will fail.
        assert_raises_rpc_error(
            -8, '{} already exists'.format(FILENAME),  node.dumptxoutset, FILENAME, "latest")
        invalid_path = node.datadir_path / "invalid" / "path"
        assert_raises_rpc_error(
            -8, "Couldn't open file {}.incomplete for writing".format(invalid_path), node.dumptxoutset, invalid_path, "latest")

        self.log.info("Test that dumptxoutset with unknown dump type fails")
        assert_raises_rpc_error(
            -8, 'Invalid snapshot type "bogus" specified. Please specify "rollback" or "latest"', node.dumptxoutset, 'utxos.dat', "bogus")

        self.log.info("Test that dumptxoutset failure does not leave the network activity suspended when it was on previously")
        self.check_expected_network(node, True)

        self.log.info("Test that dumptxoutset failure leaves the network activity suspended when it was off")
        node.setnetworkactive(False)
        self.check_expected_network(node, False)
        node.setnetworkactive(True)


if __name__ == '__main__':
    DumptxoutsetTest(__file__).main()
