#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test HD wallet keypool restore across supported output types.

Node0 provides transactions and block generation. Each remaining node backs up
its default wallet, exhausts one output-type keypool, restores the backup, and
verifies that used keys up through the restored gap are marked as spent."""
import shutil
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

OUTPUT_TYPES = {
    "legacy": {
        "validateaddress": {"isscript": False, "iswitness": False},
        "hdkeypath": "m/44h/1h/0h/0/110",
    },
    "p2sh-segwit": {
        "validateaddress": {"isscript": True, "iswitness": False},
        "hdkeypath": "m/49h/1h/0h/0/110",
    },
    "bech32": {
        "validateaddress": {"isscript": False, "iswitness": True},
        "hdkeypath": "m/84h/1h/0h/0/110",
    },
    "bech32m": {
        "validateaddress": {"isscript": True, "iswitness": True, "witness_version": 1},
        "hdkeypath": "m/86h/1h/0h/0/110",
    },
    "p2mr": {
        "validateaddress": {"isscript": True, "iswitness": True, "witness_version": 2},
        "hdkeypath": "m/87h/1h/0h/0/110",
    },
}


class KeypoolRestoreTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = len(OUTPUT_TYPES) + 1
        self.extra_args = [[]]
        for _ in range(self.num_nodes - 1):
            self.extra_args.append(['-keypool=100'])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.ensure_mature_coinbase(self.nodes[0])

        self.log.info("Make backups of the descriptor wallets under test")
        for idx in range(1, self.num_nodes):
            wallet_path = self.nodes[idx].wallets_path / self.default_wallet_name / self.wallet_data_filename
            wallet_backup_path = self.nodes[idx].datadir_path / "wallet.bak"
            self.stop_node(idx)
            shutil.copyfile(wallet_path, wallet_backup_path)
            self.start_node(idx, self.extra_args[idx])
            self.connect_nodes(0, idx)

        for offset, (output_type, output_data) in enumerate(OUTPUT_TYPES.items(), start=1):
            self.log.info("Generate keys for wallet with address type: {}".format(output_type))
            idx = offset
            wallet_path = self.nodes[idx].wallets_path / self.default_wallet_name / self.wallet_data_filename
            wallet_backup_path = self.nodes[idx].datadir_path / "wallet.bak"
            for _ in range(90):
                addr_oldpool = self.nodes[idx].getnewaddress(address_type=output_type)
            for _ in range(20):
                addr_extpool = self.nodes[idx].getnewaddress(address_type=output_type)

            # Make sure we're creating the outputs we expect
            address_details = self.nodes[idx].validateaddress(addr_extpool)
            for key, value in output_data["validateaddress"].items():
                assert_equal(address_details[key], value)

            self.log.info("Send funds to wallet")
            oldpool_amount = Decimal("1")
            extpool_amount = Decimal("0.5")
            self.nodes[0].sendtoaddress(addr_oldpool, oldpool_amount)
            self.generate(self.nodes[0], 1)
            self.nodes[0].sendtoaddress(addr_extpool, extpool_amount)
            self.generate(self.nodes[0], 1)

            self.log.info("Restart node with wallet backup")
            self.stop_node(idx)
            shutil.copyfile(wallet_backup_path, wallet_path)
            self.start_node(idx, self.extra_args[idx])
            self.connect_nodes(0, idx)
            self.sync_all()

            self.log.info("Verify keypool is restored and balance is correct")
            assert_equal(self.nodes[idx].getbalance(), oldpool_amount + extpool_amount)
            assert_equal(self.nodes[idx].listtransactions()[0]['category'], "receive")
            # Check that we have marked all keys up to the used keypool key as used
            next_addr = self.nodes[idx].getnewaddress(address_type=output_type)
            if output_type == "p2mr":
                p2mr_desc = next(
                    desc["desc"]
                    for desc in self.nodes[idx].listdescriptors(True)["descriptors"]
                    if desc["active"] and not desc["internal"] and desc["desc"].startswith("mr(")
                )
                assert_equal(self.nodes[idx].deriveaddresses(p2mr_desc, [110, 110])[0], next_addr)
            else:
                assert_equal(self.nodes[idx].getaddressinfo(next_addr)['hdkeypath'], output_data["hdkeypath"])


if __name__ == '__main__':
    KeypoolRestoreTest(__file__).main()
