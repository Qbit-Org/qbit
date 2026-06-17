#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descriptor wallet function."""

try:
    import sqlite3
except ImportError:
    pass

import re

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_equal,
    assert_raises_rpc_error
)
from test_framework.wallet_util import WalletUnlock


def active_descriptor_keypool_counts(wallet):
    descriptors = wallet.listdescriptors()["descriptors"]
    external = sum(
        1 for descriptor in descriptors
        if descriptor.get("active") and "range" in descriptor and not descriptor.get("internal", False)
    )
    internal = sum(
        1 for descriptor in descriptors
        if descriptor.get("active") and "range" in descriptor and descriptor.get("internal", False)
    )
    return external, internal


def assert_parent_descriptor(desc, prefix, derivation_path, internal):
    assert desc.startswith(prefix)
    origin = desc.split("[", maxsplit=1)[1].split("]", maxsplit=1)[0]
    assert_equal(origin.split("/", maxsplit=1)[1], derivation_path)
    suffix = desc.split("]", maxsplit=1)[1]
    assert ("/1/*" if internal else "/0/*") in suffix


def assert_p2mr_address_index(node, wallet, address, internal, expected_index):
    p2mr_desc = next(
        desc["desc"]
        for desc in wallet.listdescriptors(True)["descriptors"]
        if desc["active"] and desc["internal"] == internal and desc["desc"].startswith("mr(")
    )
    assert_equal(node.deriveaddresses(p2mr_desc, [expected_index, expected_index])[0], address)


class WalletDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.keypool_size = 100
        self.extra_args = [[f'-keypool={self.keypool_size}']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py_sqlite3()

    def test_parent_descriptors(self):
        self.log.info("Check that parent_descs is the same for all RPCs and is normalized")
        self.nodes[0].createwallet(wallet_name="parent_descs")
        wallet = self.nodes[0].get_wallet_rpc("parent_descs")
        default_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        addr = wallet.getnewaddress()
        parent_desc = wallet.getaddressinfo(addr)["parent_desc"]

        # Verify that the parent descriptor is normalized
        # First remove the checksum
        desc_verify = parent_desc.split("#")[0]
        # Next extract the extended public key
        desc_verify = re.sub(r"(?:xpub|tpub|qpub|tqpb|qrpb)\w+?(?=/)", "", desc_verify)
        # Extract origin info
        origin_match = re.search(r'\[([\da-fh/]+)\]', desc_verify)
        origin_part = origin_match.group(1) if origin_match else ""
        # Split on "]" for everything after the origin info
        after_origin = desc_verify.split("]", maxsplit=1)[-1]
        # Look for the hardened markers “h” inside each piece
        # We don't need to check for aspostrophe as normalization will not output aspostrophe
        found_hardened_in_origin = "h" in origin_part
        found_hardened_after_origin = "h" in after_origin
        assert_equal(found_hardened_in_origin, True)
        assert_equal(found_hardened_after_origin, False)

        # Send some coins so we can check listunspent, listtransactions, listunspent, and gettransaction
        since_block = self.nodes[0].getbestblockhash()
        txid = default_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1)

        unspent = wallet.listunspent()
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]["parent_descs"], [parent_desc])

        txs = wallet.listtransactions()
        assert_equal(len(txs), 1)
        assert_equal(txs[0]["parent_descs"], [parent_desc])

        txs = wallet.listsinceblock(since_block)["transactions"]
        assert_equal(len(txs), 1)
        assert_equal(txs[0]["parent_descs"], [parent_desc])

        tx = wallet.gettransaction(txid=txid, verbose=True)
        assert_equal(tx["details"][0]["parent_descs"], [parent_desc])

        wallet.unloadwallet()

    def run_test(self):
        self.ensure_mature_coinbase(self.nodes[0])

        # Make a descriptor wallet
        self.log.info("Making a descriptor wallet")
        self.nodes[0].createwallet(wallet_name="desc1")
        wallet = self.nodes[0].get_wallet_rpc("desc1")

        # Descriptor wallets prefill one keypool range per active ranged descriptor.
        self.log.info("Checking wallet info")
        wallet_info = wallet.getwalletinfo()
        external_descriptors, internal_descriptors = active_descriptor_keypool_counts(wallet)
        assert_equal(wallet_info['format'], 'sqlite')
        assert_equal(wallet_info['keypoolsize'], self.keypool_size * external_descriptors)
        assert_equal(wallet_info['keypoolsize_hd_internal'], self.keypool_size * internal_descriptors)
        assert 'keypoololdest' not in wallet_info

        # Check that getnewaddress works
        self.log.info("Test that getnewaddress and getrawchangeaddress work")
        addr = wallet.getnewaddress("", "legacy")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('pkh(')
        assert_equal(addr_info['hdkeypath'], 'm/44h/1h/0h/0/0')

        addr = wallet.getnewaddress("", "p2sh-segwit")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('sh(wpkh(')
        assert_equal(addr_info['hdkeypath'], 'm/49h/1h/0h/0/0')

        addr = wallet.getnewaddress("", "bech32")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('wpkh(')
        assert_equal(addr_info['hdkeypath'], 'm/84h/1h/0h/0/0')

        addr = wallet.getnewaddress("", "bech32m")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('tr(')
        assert_equal(addr_info['hdkeypath'], 'm/86h/1h/0h/0/0')

        addr = wallet.getnewaddress("", "p2mr")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('mr(')
        assert_p2mr_address_index(self.nodes[0], wallet, addr, False, 0)

        # Check that getrawchangeaddress works
        addr = wallet.getrawchangeaddress("legacy")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('pkh(')
        assert_equal(addr_info['hdkeypath'], 'm/44h/1h/0h/1/0')

        addr = wallet.getrawchangeaddress("p2sh-segwit")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('sh(wpkh(')
        assert_equal(addr_info['hdkeypath'], 'm/49h/1h/0h/1/0')

        addr = wallet.getrawchangeaddress("bech32")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('wpkh(')
        assert_equal(addr_info['hdkeypath'], 'm/84h/1h/0h/1/0')

        addr = wallet.getrawchangeaddress("bech32m")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('tr(')
        assert_equal(addr_info['hdkeypath'], 'm/86h/1h/0h/1/0')

        addr = wallet.getrawchangeaddress("p2mr")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('mr(')
        assert_p2mr_address_index(self.nodes[0], wallet, addr, True, 0)

        # Make a wallet to receive coins at
        self.nodes[0].createwallet(wallet_name="desc2")
        recv_wrpc = self.nodes[0].get_wallet_rpc("desc2")
        send_wrpc = self.nodes[0].get_wallet_rpc("desc1")

        # Generate some coins
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, send_wrpc.getnewaddress())
        funding_target = 11
        while send_wrpc.getbalance() < funding_target:
            self.generatetoaddress(self.nodes[0], 1, send_wrpc.getnewaddress())

        # Make transactions
        self.log.info("Test sending and receiving")
        addr = recv_wrpc.getnewaddress()
        send_wrpc.sendtoaddress(addr, 10)

        self.log.info("Test encryption")
        # Get the master fingerprint before encrypt
        info1 = send_wrpc.getaddressinfo(send_wrpc.getnewaddress())

        # Encrypt wallet 0
        send_wrpc.encryptwallet('pass')
        with WalletUnlock(send_wrpc, "pass"):
            addr = send_wrpc.getnewaddress()
            info2 = send_wrpc.getaddressinfo(addr)
            assert_not_equal(info1['hdmasterfingerprint'], info2['hdmasterfingerprint'])
        assert 'hdmasterfingerprint' in send_wrpc.getaddressinfo(send_wrpc.getnewaddress())
        info3 = send_wrpc.getaddressinfo(addr)
        assert_equal(info2['desc'], info3['desc'])

        self.log.info("Test that getnewaddress still works after keypool is exhausted in an encrypted wallet")
        for _ in range(500):
            send_wrpc.getnewaddress()

        self.log.info("Test that unlock is needed when deriving only hardened keys in an encrypted wallet")
        with WalletUnlock(send_wrpc, "pass"):
            send_wrpc.importdescriptors([{
                "desc": descsum_create("wpkh(qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm/0h/*h)"),
                "timestamp": "now",
                "range": [0,10],
                "active": True
            }])
        # Exhaust keypool of 100
        for _ in range(100):
            send_wrpc.getnewaddress(address_type='bech32')
        # This should now error
        assert_raises_rpc_error(-12, "Keypool ran out, please call keypoolrefill first", send_wrpc.getnewaddress, '', 'bech32')

        self.log.info("Test born encrypted wallets")
        self.nodes[0].createwallet('desc_enc', False, False, 'pass', False, True)
        enc_rpc = self.nodes[0].get_wallet_rpc('desc_enc')
        enc_rpc.getnewaddress() # Makes sure that we can get a new address from a born encrypted wallet

        self.log.info("Test blank descriptor wallets")
        self.nodes[0].createwallet(wallet_name='desc_blank', blank=True)
        blank_rpc = self.nodes[0].get_wallet_rpc('desc_blank')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', blank_rpc.getnewaddress)

        self.log.info("Test descriptor wallet with disabled private keys")
        self.nodes[0].createwallet(wallet_name='desc_no_priv', disable_private_keys=True)
        nopriv_rpc = self.nodes[0].get_wallet_rpc('desc_no_priv')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', nopriv_rpc.getnewaddress)

        self.log.info("Test descriptor exports")
        self.nodes[0].createwallet(wallet_name='desc_export')
        exp_rpc = self.nodes[0].get_wallet_rpc('desc_export')
        self.nodes[0].createwallet(wallet_name='desc_import', disable_private_keys=True)
        imp_rpc = self.nodes[0].get_wallet_rpc('desc_import')

        addr_types = [
            ('legacy', False, 'pkh(', '44h/1h/0h', True),
            ('p2sh-segwit', False, 'sh(wpkh(', '49h/1h/0h', True),
            ('bech32', False, 'wpkh(', '84h/1h/0h', True),
            ('bech32m', False, 'tr(', '86h/1h/0h', True),
            ('p2mr', False, 'mr(pk(pqc(', '87h/1h/0h', False),
            ('legacy', True, 'pkh(', '44h/1h/0h', True),
            ('p2sh-segwit', True, 'sh(wpkh(', '49h/1h/0h', True),
            ('bech32', True, 'wpkh(', '84h/1h/0h', True),
            ('bech32m', True, 'tr(', '86h/1h/0h', True),
            ('p2mr', True, 'mr(pk(pqc(', '87h/1h/0h', False),
        ]

        for addr_type, internal, desc_prefix, deriv_path, watchonly_import_supported in addr_types:
            int_str = 'internal' if internal else 'external'

            self.log.info("Testing descriptor address type for {} {}".format(addr_type, int_str))
            if internal:
                addr = exp_rpc.getrawchangeaddress(address_type=addr_type)
            else:
                addr = exp_rpc.getnewaddress(address_type=addr_type)
            desc = exp_rpc.getaddressinfo(addr)['parent_desc']
            assert_parent_descriptor(desc, desc_prefix, deriv_path, internal)

            self.log.info("Testing the same descriptor is returned for address type {} {}".format(addr_type, int_str))
            for i in range(0, 10):
                if internal:
                    addr = exp_rpc.getrawchangeaddress(address_type=addr_type)
                else:
                    addr = exp_rpc.getnewaddress(address_type=addr_type)
                test_desc = exp_rpc.getaddressinfo(addr)['parent_desc']
                assert_equal(desc, test_desc)

            self.log.info("Testing import of exported {} descriptor".format(addr_type))
            import_result = imp_rpc.importdescriptors([{
                'desc': desc,
                'active': True,
                'next_index': 11,
                'timestamp': 'now',
                'internal': internal
            }])[0]

            if not watchonly_import_supported:
                assert_equal(import_result["success"], False)
                assert_equal(
                    import_result["error"]["message"],
                    "Cannot import public P2MR descriptor: BIP32 extended public keys cannot derive SPHINCS+/P2MR public keys. Use exportpubkeydb/importpubkeydb for watch-only P2MR tracking.",
                )
                continue

            assert_equal(import_result["success"], True)

            for i in range(0, 10):
                if internal:
                    exp_addr = exp_rpc.getrawchangeaddress(address_type=addr_type)
                    imp_addr = imp_rpc.getrawchangeaddress(address_type=addr_type)
                else:
                    exp_addr = exp_rpc.getnewaddress(address_type=addr_type)
                    imp_addr = imp_rpc.getnewaddress(address_type=addr_type)
                assert_equal(exp_addr, imp_addr)

        self.log.info("Test that loading descriptor wallet containing legacy key types throws error")
        self.nodes[0].createwallet(wallet_name="crashme")
        self.nodes[0].unloadwallet("crashme")
        wallet_db = self.nodes[0].wallets_path / "crashme" / self.wallet_data_filename
        conn = sqlite3.connect(wallet_db)
        with conn:
            # add "cscript" entry: key type is uint160 (20 bytes), value type is CScript (zero-length here)
            conn.execute('INSERT INTO main VALUES(?, ?)', (b'\x07cscript' + b'\x00'*20, b'\x00'))
        conn.close()
        assert_raises_rpc_error(-4, "Unexpected legacy entry in descriptor wallet found.", self.nodes[0].loadwallet, "crashme")

        self.test_parent_descriptors()

if __name__ == '__main__':
    WalletDescriptorTest(__file__).main()
