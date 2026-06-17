#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that fast rescan using block filters for descriptor wallets detects
   top-ups correctly and finds the same transactions than the slow variant."""
from test_framework.address import address_to_scriptpubkey
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import get_generate_key


KEYPOOL_SIZE = 100   # smaller than default size to speed-up test
NUM_BLOCKS = 6       # number of blocks to mine


def is_p2mr_descriptor(descriptor: str) -> bool:
    return descriptor.startswith(("mr(", "rawmr("))


class WalletFastRescanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def get_wallet_txids(self, node: TestNode, wallet_name: str) -> list[str]:
        w = node.get_wallet_rpc(wallet_name)
        txs = w.listtransactions('*', 1000000)
        return [tx['txid'] for tx in txs]

    def assert_imported_p2mr_roles(self, node: TestNode, wallet_name: str, pubkey_entries: list[dict]) -> None:
        if not pubkey_entries:
            return
        wallet = node.get_wallet_rpc(wallet_name)
        change_entries = [entry for entry in pubkey_entries if entry.get("change", False)]
        if change_entries:
            change_addr = node.deriveaddresses(descsum_create(f"mr(pk({change_entries[0]['pubkey']}))"))[0]
            assert_equal(wallet.getaddressinfo(change_addr)["ischange"], True)
        receive_entries = [entry for entry in pubkey_entries if not entry.get("change", False)]
        if receive_entries:
            receive_addr = node.deriveaddresses(descsum_create(f"mr(pk({receive_entries[0]['pubkey']}))"))[0]
            assert_equal(wallet.getaddressinfo(receive_addr)["ischange"], False)

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        # Mature the default-cache coinbase UTXOs
        self.ensure_cached_coinbase_mature(self.nodes[0])

        self.log.info("Create descriptor wallet with backup")
        WALLET_BACKUP_FILENAME = node.datadir_path / 'wallet.bak'
        node.createwallet(wallet_name='topup_test')
        w = node.get_wallet_rpc('topup_test')
        default_descriptor_count = len(w.listdescriptors()['descriptors'])
        fixed_key = get_generate_key()
        print(w.importdescriptors([{"desc": descsum_create(f"wpkh({fixed_key.privkey})"), "timestamp": "now"}]))
        descriptors = w.listdescriptors()['descriptors']
        private_descriptors = w.listdescriptors(True)['descriptors']
        public_descriptor_imports = [{"desc": descriptor['desc'], "timestamp": 0} for descriptor in descriptors if not is_p2mr_descriptor(descriptor['desc'])]
        p2mr_pubkeys = w.exportpubkeydb()['pubkeys']
        assert_equal(len(descriptors), default_descriptor_count + 1)
        w.backupwallet(WALLET_BACKUP_FILENAME)

        self.log.info("Create txs sending to end range address of each descriptor, triggering top-ups")
        for i in range(NUM_BLOCKS):
            self.log.info(f"Block {i+1}/{NUM_BLOCKS}")
            for desc_info in private_descriptors:
                if 'range' in desc_info:
                    start_range, end_range = desc_info['range']
                    addr = w.deriveaddresses(desc_info['desc'], [end_range, end_range])[0]
                    spk = address_to_scriptpubkey(addr)
                    self.log.info(f"-> range [{start_range},{end_range}], last address {addr}")
                else:
                    spk = bytes.fromhex(fixed_key.p2wpkh_script)
                    self.log.info(f"-> fixed non-range descriptor address {fixed_key.p2wpkh_addr}")
                wallet.send_to(from_node=node, scriptPubKey=spk, amount=10000)
            self.generate(node, 1)

        self.log.info("Import wallet backup with block filter index")
        with node.assert_debug_log(['fast variant using block filters']):
            node.restorewallet('rescan_fast', WALLET_BACKUP_FILENAME)
        txids_fast = self.get_wallet_txids(node, 'rescan_fast')

        self.log.info("Import non-active descriptors with block filter index")
        node.createwallet(wallet_name='rescan_fast_nonactive', disable_private_keys=True, blank=True)
        with node.assert_debug_log(['fast variant using block filters']):
            w = node.get_wallet_rpc('rescan_fast_nonactive')
            assert all(result['success'] for result in w.importdescriptors(public_descriptor_imports))
            if p2mr_pubkeys:
                assert_equal(w.importpubkeydb(p2mr_pubkeys, False, 0)['imported'], len(p2mr_pubkeys))
                self.assert_imported_p2mr_roles(node, 'rescan_fast_nonactive', p2mr_pubkeys)
        txids_fast_nonactive = self.get_wallet_txids(node, 'rescan_fast_nonactive')

        self.restart_node(0, [f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=0'])
        self.log.info("Import wallet backup w/o block filter index")
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            node.restorewallet("rescan_slow", WALLET_BACKUP_FILENAME)
        txids_slow = self.get_wallet_txids(node, 'rescan_slow')

        self.log.info("Import non-active descriptors w/o block filter index")
        node.createwallet(wallet_name='rescan_slow_nonactive', disable_private_keys=True, blank=True)
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            w = node.get_wallet_rpc('rescan_slow_nonactive')
            assert all(result['success'] for result in w.importdescriptors(public_descriptor_imports))
            if p2mr_pubkeys:
                assert_equal(w.importpubkeydb(p2mr_pubkeys, False, 0)['imported'], len(p2mr_pubkeys))
                self.assert_imported_p2mr_roles(node, 'rescan_slow_nonactive', p2mr_pubkeys)
        txids_slow_nonactive = self.get_wallet_txids(node, 'rescan_slow_nonactive')

        self.log.info("Verify that all rescans found the same txs in slow and fast variants")
        expected_txs = len(descriptors) * NUM_BLOCKS
        assert_equal(len(txids_slow), expected_txs)
        assert_equal(len(txids_fast), expected_txs)
        assert_equal(len(txids_slow_nonactive), expected_txs)
        assert_equal(len(txids_fast_nonactive), expected_txs)
        assert_equal(sorted(txids_slow), sorted(txids_fast))
        assert_equal(sorted(txids_slow_nonactive), sorted(txids_fast_nonactive))


if __name__ == '__main__':
    WalletFastRescanTest(__file__).main()
