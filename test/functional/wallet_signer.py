#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test external signer.

Verify that a bitcoind node can use an external signer command
See also rpc_signer.py for tests without wallet context.
"""
import os
import sys

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class WalletSignerTest(BitcoinTestFramework):
    def mock_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'signer.py')
        return sys.executable + " " + path

    def mock_no_connected_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'no_signer.py')
        return sys.executable + " " + path

    def mock_invalid_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'invalid_signer.py')
        return sys.executable + " " + path

    def mock_multi_signers_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'multi_signers.py')
        return sys.executable + " " + path

    def set_test_params(self):
        self.num_nodes = 2

        self.extra_args = [
            [],
            [f"-signer={self.mock_signer_path()}", '-keypool=10'],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_external_signer()
        self.skip_if_no_wallet()

    def set_mock_result(self, node, res):
        with open(os.path.join(node.cwd, "mock_result"), "w", encoding="utf8") as f:
            f.write(res)

    def clear_mock_result(self, node):
        os.remove(os.path.join(node.cwd, "mock_result"))

    def run_test(self):
        # Mature the default-cache coinbase UTXOs
        self.ensure_cached_coinbase_mature(self.nodes[0])

        self.test_valid_signer()
        self.test_disconnected_signer()
        self.restart_node(1, [f"-signer={self.mock_invalid_signer_path()}", "-keypool=10"])
        self.test_invalid_signer()
        self.restart_node(1, [f"-signer={self.mock_multi_signers_path()}", "-keypool=10"])
        self.test_multiple_signers()

    def test_valid_signer(self):
        self.log.debug(f"-signer={self.mock_signer_path()}")

        # Create new wallets for an external signer.
        # disable_private_keys and descriptors must be true:
        assert_raises_rpc_error(-4, "Private keys must be disabled when using an external signer", self.nodes[1].createwallet, wallet_name='not_hww', disable_private_keys=False, external_signer=True)
        self.nodes[1].createwallet(wallet_name='hww', disable_private_keys=True, external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        # Flag can't be set afterwards (could be added later for non-blank descriptor based watch-only wallets)
        self.nodes[1].createwallet(wallet_name='not_hww', disable_private_keys=True, external_signer=False)
        not_hww = self.nodes[1].get_wallet_rpc('not_hww')
        assert_equal(not_hww.getwalletinfo()["external_signer"], False)
        assert_raises_rpc_error(-8, "Wallet flag is immutable: external_signer", not_hww.setwalletflag, "external_signer", True)


        self.set_mock_result(self.nodes[1], '0 {"invalid json"}')
        assert_raises_rpc_error(-1, 'Unable to parse JSON',
            self.nodes[1].createwallet, wallet_name='hww2', disable_private_keys=True, external_signer=True
        )
        self.clear_mock_result(self.nodes[1])

        assert_equal(hww.getwalletinfo()["keypoolsize"], 40)
        expected_addrs = {
            "bech32": self.nodes[1].deriveaddresses(descsum_create("wpkh([00000001/84h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"))[0],
            "p2sh-segwit": self.nodes[1].deriveaddresses(descsum_create("sh(wpkh([00000001/49h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7))"))[0],
            "legacy": self.nodes[1].deriveaddresses(descsum_create("pkh([00000001/44h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"))[0],
            "bech32m": self.nodes[1].deriveaddresses(descsum_create("tr([00000001/86h/1h/0h/0/0]c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"))[0],
            "bech32_fail": self.nodes[1].deriveaddresses(descsum_create("wpkh([00000001/84h/1h/0h/0/1]03a20a46308be0b8ded6dff0a22b10b4245c587ccf23f3b4a303885be3a524f172)"))[0],
        }

        address1 = hww.getnewaddress(address_type="bech32")
        assert_equal(address1, expected_addrs["bech32"])
        address_info = hww.getaddressinfo(address1)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/84h/1h/0h/0/0")

        address2 = hww.getnewaddress(address_type="p2sh-segwit")
        assert_equal(address2, expected_addrs["p2sh-segwit"])
        address_info = hww.getaddressinfo(address2)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/49h/1h/0h/0/0")

        address3 = hww.getnewaddress(address_type="legacy")
        assert_equal(address3, expected_addrs["legacy"])
        address_info = hww.getaddressinfo(address3)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/44h/1h/0h/0/0")

        address4 = hww.getnewaddress(address_type="bech32m")
        assert_equal(address4, expected_addrs["bech32m"])
        address_info = hww.getaddressinfo(address4)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], True)
        assert_equal(address_info['hdkeypath'], "m/86h/1h/0h/0/0")

        self.log.info('Test walletdisplayaddress')
        for address in [address1, address2, address3]:
            result = hww.walletdisplayaddress(address)
            assert_equal(result, {"address": address})

        # Handle error thrown by script
        self.set_mock_result(self.nodes[1], "2")
        assert_raises_rpc_error(-1, 'RunCommandParseJSON error',
            hww.walletdisplayaddress, address1
        )
        self.clear_mock_result(self.nodes[1])

        # Returned address MUST match:
        address_fail = hww.getnewaddress(address_type="bech32")
        assert_equal(address_fail, expected_addrs["bech32_fail"])
        assert_raises_rpc_error(-1, 'Signer echoed unexpected address wrong_address',
            hww.walletdisplayaddress, address_fail
        )

        self.log.info('Prepare mock PSBT')
        self.nodes[0].sendtoaddress(address4, 1)
        self.generate(self.nodes[0], 1)

        # Load private key into wallet to generate a signed PSBT for the mock
        self.nodes[1].createwallet(wallet_name="mock", disable_private_keys=False, blank=True)
        mock_wallet = self.nodes[1].get_wallet_rpc("mock")
        assert mock_wallet.getwalletinfo()['private_keys_enabled']

        result = mock_wallet.importdescriptors([{
            "desc": descsum_create("tr([00000001/86h/1h/0']qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0/*)"),
            "timestamp": 0,
            "range": [0,1],
            "internal": False,
            "active": True
        },
        {
            "desc": descsum_create("tr([00000001/86h/1h/0']qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/1/*)"),
            "timestamp": 0,
            "range": [0, 0],
            "internal": True,
            "active": True
        }])
        assert_equal(result[0]["success"], True)
        assert_equal(result[1]["success"], True)
        assert_equal(mock_wallet.getwalletinfo()["txcount"], 1)
        dest = self.nodes[0].getnewaddress(address_type='bech32')
        mock_psbt = mock_wallet.walletcreatefundedpsbt([], {dest:0.5}, 0, {'replaceable': True}, True)['psbt']
        mock_psbt_signed = mock_wallet.walletprocesspsbt(psbt=mock_psbt, sign=True, sighashtype="ALL", bip32derivs=True)
        mock_tx = mock_psbt_signed["hex"]
        assert mock_wallet.testmempoolaccept([mock_tx])[0]["allowed"]

        assert_equal(hww.getwalletinfo()["txcount"], 1)

        assert hww.testmempoolaccept([mock_tx])[0]["allowed"]

        with open(os.path.join(self.nodes[1].cwd, "mock_psbt"), "w", encoding="utf8") as f:
            f.write(mock_psbt_signed["psbt"])

        self.log.info('Test send using hww1')

        # Don't broadcast transaction yet so the RPC returns the raw hex
        res = hww.send(outputs={dest:0.5},add_to_wallet=False)
        assert res["complete"]
        assert_equal(res["hex"], mock_tx)

        self.log.info('Test sendall using hww1')

        res = hww.sendall(recipients=[{dest:0.5}, hww.getrawchangeaddress()], add_to_wallet=False)
        assert res["complete"]
        assert_equal(res["hex"], mock_tx)
        # Broadcast transaction so we can bump the fee
        hww.sendrawtransaction(res["hex"])

        self.log.info('Prepare fee bumped mock PSBT')

        # Now that the transaction is broadcast, bump fee in mock wallet:
        orig_tx_id = res["txid"]
        mock_psbt_bumped = mock_wallet.psbtbumpfee(orig_tx_id)["psbt"]
        mock_psbt_bumped_signed = mock_wallet.walletprocesspsbt(psbt=mock_psbt_bumped, sign=True, sighashtype="ALL", bip32derivs=True)

        with open(os.path.join(self.nodes[1].cwd, "mock_psbt"), "w", encoding="utf8") as f:
            f.write(mock_psbt_bumped_signed["psbt"])

        self.log.info('Test bumpfee using hww1')

        # Bump fee
        res = hww.bumpfee(orig_tx_id)
        assert_greater_than(res["fee"], res["origfee"])
        assert_equal(res["errors"], [])


    def test_disconnected_signer(self):
        self.log.info('Test disconnected external signer')

        # First create a wallet with the signer connected
        self.nodes[1].createwallet(wallet_name='hww_disconnect', disable_private_keys=True, external_signer=True)
        hww = self.nodes[1].get_wallet_rpc('hww_disconnect')
        assert_equal(hww.getwalletinfo()["external_signer"], True)

        # Fund wallet
        self.nodes[0].sendtoaddress(hww.getnewaddress(address_type="bech32m"), 1)
        self.generate(self.nodes[0], 1)

        # Restart node with no signer connected
        self.log.debug(f"-signer={self.mock_no_connected_signer_path()}")
        self.restart_node(1, [f"-signer={self.mock_no_connected_signer_path()}", "-keypool=10"])
        self.nodes[1].loadwallet('hww_disconnect')
        hww = self.nodes[1].get_wallet_rpc('hww_disconnect')

        # Try to spend
        dest = hww.getrawchangeaddress()
        assert_raises_rpc_error(-25, "External signer not found", hww.send, outputs=[{dest:0.5}])

    def test_invalid_signer(self):
        self.log.debug(f"-signer={self.mock_invalid_signer_path()}")
        self.log.info('Test invalid external signer')
        assert_raises_rpc_error(-1, "Invalid descriptor", self.nodes[1].createwallet, wallet_name='hww_invalid', disable_private_keys=True, external_signer=True)

    def test_multiple_signers(self):
        self.log.debug(f"-signer={self.mock_multi_signers_path()}")
        self.log.info('Test multiple external signers')

        assert_raises_rpc_error(-1, "More than one external signer found", self.nodes[1].createwallet, wallet_name='multi_hww', disable_private_keys=True, external_signer=True)

if __name__ == '__main__':
    WalletSignerTest(__file__).main()
