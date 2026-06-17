#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction signing using the signrawtransactionwithkey RPC."""

from test_framework.messages import (
    COIN,
)
from test_framework.address import (
    address_to_scriptpubkey,
    key_to_p2pkh,
    p2a,
    script_to_p2sh,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIGPQC,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    script_to_p2sh_p2wsh_script,
    script_to_p2wsh_script,
)
from test_framework.wallet import (
    getnewdestination,
    MiniWallet,
)
from test_framework.wallet_util import (
    generate_keypair,
)

from decimal import (
    Decimal,
)

INPUTS = [
    # Valid pay-to-pubkey scripts
    {'txid': '9b907ef1e3c26fc71fe4a4b3580bc75264112f95050014157059c736f0202e71', 'vout': 0,
     'scriptPubKey': '76a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac'},
    {'txid': '83a4f6a6b73660e13ee6cb3c6063fa3759c50c9b7521d0536022961898f4fb02', 'vout': 0,
     'scriptPubKey': '76a914669b857c03a5ed269d5d85a1ffac9ed5d663072788ac'},
]

class SignRawTransactionWithKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def get_outputs(self):
        return {key_to_p2pkh("02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7", main=self.chain == "main"): 0.1}

    def send_to_address(self, addr, amount):
        script_pub_key = address_to_scriptpubkey(addr)
        tx = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pub_key, amount=int(amount * COIN))
        return tx["txid"], tx["sent_vout"]

    def spendable_wallet_amount(self):
        return self.wallet.get_utxo(mark_as_spent=False, confirmed_only=True)["value"] - Decimal("0.001")

    def assert_signing_completed_successfully(self, signed_tx):
        assert 'errors' not in signed_tx
        assert 'complete' in signed_tx
        assert_equal(signed_tx['complete'], True)

    def successful_signing_test(self):
        """Create and sign a valid raw transaction with one input.

        Expected results:

        1) The transaction has a complete set of signatures
        2) No script verification error occurred"""
        self.log.info("Test valid raw transaction with one input")
        privKeys = ['RgKHYqn95ma1eDAJnJ9nJXP7hoDsj95bLVF3i2KpdF9ciaTBVSJw', 'RgznetBef65Hhir9n48jQfcMAZXx9BHppydoFqJZbtsJGHjGAhdH']
        rawTx = self.nodes[0].createrawtransaction(INPUTS, self.get_outputs())
        rawTxSigned = self.nodes[0].signrawtransactionwithkey(rawTx, privKeys, INPUTS)

        self.assert_signing_completed_successfully(rawTxSigned)

    def witness_script_test(self):
        self.log.info("Test signing transaction to P2SH-P2WSH addresses without wallet")
        # Create a new P2SH-P2WSH 1-of-1 multisig address:
        embedded_privkey, embedded_pubkey = generate_keypair(wif=True)
        p2sh_p2wsh_address = self.nodes[0].createmultisig(1, [embedded_pubkey.hex()], "p2sh-segwit")
        # send transaction to P2SH-P2WSH 1-of-1 multisig address
        send_amount = min(Decimal("49.999"), self.spendable_wallet_amount())
        self.send_to_address(p2sh_p2wsh_address["address"], send_amount)
        self.generate(self.nodes[0], 1)
        # Get the UTXO info from scantxoutset
        unspent_output = self.nodes[0].scantxoutset('start', [p2sh_p2wsh_address['descriptor']])['unspents'][0]
        spk = script_to_p2sh_p2wsh_script(p2sh_p2wsh_address['redeemScript']).hex()
        unspent_output['witnessScript'] = p2sh_p2wsh_address['redeemScript']
        unspent_output['redeemScript'] = script_to_p2wsh_script(unspent_output['witnessScript']).hex()
        assert_equal(spk, unspent_output['scriptPubKey'])
        # Now create and sign a transaction spending that output on node[0], which doesn't know the scripts or keys
        spending_tx = self.nodes[0].createrawtransaction([unspent_output], {getnewdestination()[2]: unspent_output["amount"] - Decimal("0.001")})
        spending_tx_signed = self.nodes[0].signrawtransactionwithkey(spending_tx, [embedded_privkey], [unspent_output])
        self.assert_signing_completed_successfully(spending_tx_signed)

        # Now test with P2PKH and P2PK scripts as the witnessScript
        for tx_type in ['P2PKH', 'P2PK']:  # these tests are order-independent
            self.verify_txn_with_witness_script(tx_type)

    def keyless_signing_test(self):
        self.log.info("Test that keyless 'signing' of pay-to-anchor input succeeds")
        send_amount = min(Decimal("49.999"), self.spendable_wallet_amount())
        [txid, vout] = self.send_to_address(p2a(), send_amount)
        spending_tx = self.nodes[0].createrawtransaction(
            [{"txid": txid, "vout": vout}],
            [{getnewdestination()[2]: send_amount - Decimal("0.001")}])
        spending_tx_signed = self.nodes[0].signrawtransactionwithkey(spending_tx, [], [])
        self.assert_signing_completed_successfully(spending_tx_signed)
        assert self.nodes[0].testmempoolaccept([spending_tx_signed["hex"]])[0]["allowed"]
        # 'signing' a P2A prevout is a no-op, so signed and unsigned txs shouldn't differ
        assert_equal(spending_tx, spending_tx_signed["hex"])

    def verify_txn_with_witness_script(self, tx_type):
        self.log.info("Test with a {} script as the witnessScript".format(tx_type))
        embedded_privkey, embedded_pubkey = generate_keypair(wif=True)
        witness_script = {
            'P2PKH': key_to_p2pkh_script(embedded_pubkey).hex(),
            'P2PK': key_to_p2pk_script(embedded_pubkey).hex()
        }.get(tx_type, "Invalid tx_type")
        redeem_script = script_to_p2wsh_script(witness_script).hex()
        addr = script_to_p2sh(redeem_script)
        script_pub_key = address_to_scriptpubkey(addr).hex()
        # Fund that address
        send_amount = min(Decimal("10"), self.spendable_wallet_amount())
        [txid, vout] = self.send_to_address(addr, send_amount)
        # Now create and sign a transaction spending that output on node[0], which doesn't know the scripts or keys
        spending_tx = self.nodes[0].createrawtransaction([{'txid': txid, 'vout': vout}], {getnewdestination()[2]: send_amount - Decimal("0.001")})
        spending_tx_signed = self.nodes[0].signrawtransactionwithkey(spending_tx, [embedded_privkey], [{'txid': txid, 'vout': vout, 'scriptPubKey': script_pub_key, 'redeemScript': redeem_script, 'witnessScript': witness_script, 'amount': send_amount}])
        self.assert_signing_completed_successfully(spending_tx_signed)
        self.nodes[0].sendrawtransaction(spending_tx_signed['hex'])

    def get_p2mr_signing_fixture(self):
        if hasattr(self, "_p2mr_signing_fixture"):
            return self._p2mr_signing_fixture

        self.nodes[0].createwallet(wallet_name="p2mr_signer")
        wallet = self.nodes[0].get_wallet_rpc("p2mr_signer")
        xprv = wallet.gethdkeys(private=True)[0]["xprv"]
        key_expr = f"pqc({xprv}/87h/1h/0h/0/0)"
        wrong_key_expr = f"pqc({xprv}/87h/1h/0h/0/1)"
        address = wallet.getnewaddress(address_type="p2mr")
        address_info = wallet.getaddressinfo(address)
        pubkey_hex = address_info["desc"].removeprefix("mr(pk(").split("))#", 1)[0]
        leaf_script = CScript([bytes.fromhex(pubkey_hex), OP_CHECKSIGPQC]).hex()
        control_block = "c1"
        self._p2mr_signing_fixture = {
            "address": address,
            "key_expr": key_expr,
            "wrong_key_expr": wrong_key_expr,
            "leaf_script": leaf_script,
            "control_block": control_block,
        }
        return self._p2mr_signing_fixture

    def pqc_signing_test(self):
        self.log.info("Test signing a P2MR spend with an explicit PQC key expression")
        fixture = self.get_p2mr_signing_fixture()
        send_amount = min(Decimal("10"), self.spendable_wallet_amount())
        txid, vout = self.send_to_address(fixture["address"], send_amount)
        self.generate(self.nodes[0], 1)
        spending_tx = self.nodes[0].createrawtransaction([{'txid': txid, 'vout': vout}], {getnewdestination()[2]: send_amount - Decimal("0.001")})
        prevout = {
            'txid': txid,
            'vout': vout,
            'scriptPubKey': address_to_scriptpubkey(fixture["address"]).hex(),
            'amount': send_amount,
            'p2mrScript': fixture["leaf_script"],
            'p2mrControlBlock': fixture["control_block"],
        }
        spending_tx_signed = self.nodes[0].signrawtransactionwithkey(spending_tx, [fixture["key_expr"]], [prevout])
        self.assert_signing_completed_successfully(spending_tx_signed)
        self.nodes[0].sendrawtransaction(spending_tx_signed['hex'])

    def pqc_failure_modes_test(self):
        self.log.info("Test malformed PQC keys, wrong PQC keys, and tampered P2MR metadata")
        fixture = self.get_p2mr_signing_fixture()
        send_amount = min(Decimal("9"), self.spendable_wallet_amount())
        txid, vout = self.send_to_address(fixture["address"], send_amount)
        self.generate(self.nodes[0], 1)
        spending_tx = self.nodes[0].createrawtransaction([{'txid': txid, 'vout': vout}], {getnewdestination()[2]: send_amount - Decimal("0.001")})
        prevout = {
            'txid': txid,
            'vout': vout,
            'scriptPubKey': address_to_scriptpubkey(fixture["address"]).hex(),
            'amount': send_amount,
            'p2mrScript': fixture["leaf_script"],
            'p2mrControlBlock': fixture["control_block"],
        }

        assert_raises_rpc_error(-5, "Invalid PQC private key", self.nodes[0].signrawtransactionwithkey, spending_tx, ["pqc(not_a_valid_key)"], [prevout])

        wrong_key_signed = self.nodes[0].signrawtransactionwithkey(spending_tx, [fixture["wrong_key_expr"]], [prevout])
        assert_equal(wrong_key_signed["complete"], False)
        assert_equal(wrong_key_signed["errors"][0]["error"], "Witness program was passed an empty witness")

        tampered_prevout = dict(prevout)
        tampered_prevout["p2mrControlBlock"] = tampered_prevout["p2mrControlBlock"] + ("00" * 32)
        assert_raises_rpc_error(-8, "p2mrScript/p2mrControlBlock does not match scriptPubKey", self.nodes[0].signrawtransactionwithkey, spending_tx, [fixture["key_expr"]], [tampered_prevout])

        invalid_control_bit_prevout = dict(prevout)
        invalid_control_bit_prevout["p2mrControlBlock"] = "c0"
        assert_raises_rpc_error(-8, "P2MR control byte bit 0 must be set", self.nodes[0].signrawtransactionwithkey, spending_tx, [fixture["key_expr"]], [invalid_control_bit_prevout])

    def invalid_sighashtype_test(self):
        self.log.info("Test signing transaction with invalid sighashtype")
        tx = self.nodes[0].createrawtransaction(INPUTS, self.get_outputs())
        privkeys = [self.nodes[0].get_deterministic_priv_key().key]
        assert_raises_rpc_error(-8, "'all' is not a valid sighash parameter.", self.nodes[0].signrawtransactionwithkey, tx, privkeys, sighashtype="all")

    def invalid_private_key_and_tx(self):
        self.log.info("Test signing transaction with an invalid private key")
        tx = self.nodes[0].createrawtransaction(INPUTS, self.get_outputs())
        privkeys = ["123"]
        assert_raises_rpc_error(-5, "Invalid private key", self.nodes[0].signrawtransactionwithkey, tx, privkeys)
        self.log.info("Test signing transaction with an invalid tx hex")
        privkeys = [self.nodes[0].get_deterministic_priv_key().key]
        assert_raises_rpc_error(-22, "TX decode failed. Make sure the tx has at least one input.", self.nodes[0].signrawtransactionwithkey, tx + "00", privkeys)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # Mature the default-cache coinbase UTXOs
        self.ensure_cached_coinbase_mature(self.nodes[0])

        self.successful_signing_test()
        self.witness_script_test()
        self.keyless_signing_test()
        self.pqc_signing_test()
        self.pqc_failure_modes_test()
        self.invalid_sighashtype_test()
        self.invalid_private_key_and_tx()


if __name__ == '__main__':
    SignRawTransactionWithKeyTest(__file__).main()
