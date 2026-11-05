#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet load on startup.

Verify that a bitcoind node can maintain list of wallets loading on startup
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class WalletStartupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        self.start_nodes()

    def run_test(self):
        self.log.info('Should start without any wallets')
        assert_equal(self.nodes[0].listwallets(), [])
        assert_equal(self.nodes[0].listwalletdir(), {'wallets': []})

        self.log.info('New default wallet should load by default when there are no other wallets')
        self.nodes[0].createwallet(wallet_name='', load_on_startup=False)
        self.restart_node(0)
        assert_equal(self.nodes[0].listwallets(), [''])

        self.log.info('Test load on startup behavior')
        self.nodes[0].createwallet(wallet_name='w0', load_on_startup=True)
        self.nodes[0].createwallet(wallet_name='w1', load_on_startup=False)
        self.nodes[0].createwallet(wallet_name='w2', load_on_startup=True)
        self.nodes[0].createwallet(wallet_name='w3', load_on_startup=False)
        self.nodes[0].createwallet(wallet_name='w4', load_on_startup=False)
        self.nodes[0].unloadwallet(wallet_name='w0', load_on_startup=False)
        self.nodes[0].unloadwallet(wallet_name='w4', load_on_startup=False)
        self.nodes[0].loadwallet(filename='w4', load_on_startup=True)
        assert_equal(set(self.nodes[0].listwallets()), set(('', 'w1', 'w2', 'w3', 'w4')))
        self.restart_node(0)
        assert_equal(set(self.nodes[0].listwallets()), set(('', 'w2', 'w4')))
        self.nodes[0].unloadwallet(wallet_name='', load_on_startup=False)
        self.nodes[0].unloadwallet(wallet_name='w4', load_on_startup=False)
        self.nodes[0].loadwallet(filename='w3', load_on_startup=True)
        self.nodes[0].loadwallet(filename='')
        self.restart_node(0)
        assert_equal(set(self.nodes[0].listwallets()), set(('w2', 'w3')))

        self.test_deferred_p2mr_keypool_top_up_resumes()

    def test_deferred_p2mr_keypool_top_up_resumes(self):
        self.log.info('A deferred P2MR keypool top-up resumes for wallets loaded on startup')
        node = self.nodes[0]
        node.unloadwallet(wallet_name='w2', load_on_startup=False)
        node.unloadwallet(wallet_name='w3', load_on_startup=False)
        warm_keypool_size = 16
        keypool_size = 48
        p2mr_args = ['-p2mronly=1', f'-keypool={keypool_size}']
        self.restart_node(0, extra_args=p2mr_args)

        # A new P2MR wallet warms 16 keys and defers the rest by 30 seconds.
        node.createwallet(wallet_name='deferred', load_on_startup=True)
        wallet = node.get_wallet_rpc('deferred')
        assert_equal(wallet.getwalletinfo()['keypoolsize'], warm_keypool_size)

        # Pay an address past the warm pool, as another copy of the seed could
        # hand it out, then restart before the deferred top-up starts.
        p2mr_desc = next(
            entry['desc']
            for entry in wallet.listdescriptors(True)['descriptors']
            if entry['active'] and not entry['internal'] and entry['desc'].startswith('mr(')
        )
        far_index = 30
        far_address = node.deriveaddresses(p2mr_desc, [far_index, far_index])[0]
        self.generatetoaddress(node, 1, far_address, sync_fun=self.no_op)
        assert not wallet.getaddressinfo(far_address)['ismine']
        self.restart_node(0, extra_args=p2mr_args)
        assert_equal(node.listwallets(), ['deferred'])
        wallet = node.get_wallet_rpc('deferred')
        assert_equal(wallet.getwalletinfo()['keypoolsize'], warm_keypool_size)

        node.mockscheduler(30)
        self.wait_until(lambda: (
            wallet.getwalletinfo()['keypoolsize'] == keypool_size and
            wallet.getwalletinfo()['keypoolsize_hd_internal'] == keypool_size
        ))
        assert wallet.getaddressinfo(far_address)['ismine']

        # The top-up watches new addresses but does not find past payments.
        assert_equal(wallet.getbalances()['mine']['immature'], 0)
        wallet.rescanblockchain()
        assert_greater_than(wallet.getbalances()['mine']['immature'], 0)

if __name__ == '__main__':
    WalletStartupTest(__file__).main()
