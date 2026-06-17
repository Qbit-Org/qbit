#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test restricted-output outer witness namespace activation on regtest."""

from decimal import Decimal

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.address import program_to_witness
from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script_util import program_to_witness_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
    p2mr_op_true_script,
)


OUTERWITNESS_ACTIVATION_HEIGHT = 1102


def reserved_witness_script(version, fill=0x42):
    return program_to_witness_script(version, bytes([fill] * 32))


def p2mr_script(fill=0x24):
    return program_to_witness_script(2, bytes([fill] * 32))


def spend_reserved_tx(tx):
    spend_tx = CTransaction()
    spend_tx.vin = [CTxIn(COutPoint(int(tx.txid_hex, 16), 0))]
    spend_tx.vout = [CTxOut(tx.vout[0].nValue - 1000, p2mr_script())]
    return spend_tx


def prevout_for_tx(tx):
    return [{
        "txid": tx.txid_hex,
        "vout": 0,
        "scriptPubKey": tx.vout[0].scriptPubKey.hex(),
        "amount": Decimal(tx.vout[0].nValue) / COIN,
    }]


class FeatureOuterWitnessActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-p2mronly=1",
            f"-testactivationheight=outerwitness@{OUTERWITNESS_ACTIVATION_HEIGHT}",
        ]]

    def make_block(self, txs, *, coinbase_script=None):
        tip = self.nodes[0].getbestblockhash()
        next_height = self.nodes[0].getblockcount() + 1
        block_time = self.nodes[0].getblockheader(tip)["mediantime"] + 1
        block = create_block(
            int(tip, 16),
            create_coinbase(next_height, script_pubkey=coinbase_script or p2mr_op_true_script()),
            block_time,
            txlist=txs,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_P2MR_OP_TRUE)
        self.generate(wallet, 4, sync_fun=self.no_op)
        spendable_utxos = wallet.get_utxos(include_immature_coinbase=True, mark_as_spent=False)[:4]
        assert_equal(len(spendable_utxos), 4)

        target_height = OUTERWITNESS_ACTIVATION_HEIGHT - 2
        current_height = node.getblockcount()
        assert current_height <= target_height
        if current_height < target_height:
            self.generate(wallet, target_height - current_height, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), target_height)
        for utxo in spendable_utxos:
            utxo["confirmations"] = node.getblockcount() - utxo["height"] + 1

        pre_mempool_utxo = spendable_utxos[0]
        pre_block_utxo = spendable_utxos[1]
        post_block_utxo = spendable_utxos[2]
        post_mempool_utxo = spendable_utxos[3]

        self.log.info("Pre-activation: reserved outputs fail the restricted-output consensus gate in mempool")
        pre_mempool_tx = wallet.create_self_transfer(utxo_to_spend=pre_mempool_utxo)["tx"]
        pre_mempool_tx.vout[0].scriptPubKey = reserved_witness_script(3)
        pre_reject = node.testmempoolaccept([pre_mempool_tx.serialize().hex()], maxfeerate=0)[0]
        assert_equal(pre_reject["allowed"], False)
        assert_equal(pre_reject["reject-reason"], "tx-output-not-p2mr")

        self.log.info("Pre-activation: reserved outputs are rejected from blocks")
        pre_block_tx = wallet.create_self_transfer(utxo_to_spend=pre_block_utxo)["tx"]
        pre_block_tx.vout[0].scriptPubKey = reserved_witness_script(16)
        invalid_block = self.make_block([pre_block_tx])
        prev_tip = node.getbestblockhash()
        assert_equal(node.submitblock(invalid_block.serialize().hex()), "bad-txns-output-not-p2mr")
        assert_equal(node.getbestblockhash(), prev_tip)

        self.log.info("Pre-activation: reserved prevouts are rejected by signing RPCs")
        assert_raises_rpc_error(
            -8,
            "Only restricted-output-mode prevout scriptPubKeys are supported on this chain",
            node.signrawtransactionwithkey,
            spend_reserved_tx(pre_block_tx).serialize().hex(),
            [],
            prevout_for_tx(pre_block_tx),
        )

        self.log.info("Advance to the outerwitness activation height")
        self.generate(wallet, 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), OUTERWITNESS_ACTIVATION_HEIGHT - 1)

        self.log.info("Post-activation: reserved outputs can enter blocks")
        post_block_tx = wallet.create_self_transfer(utxo_to_spend=post_block_utxo)["tx"]
        post_block_tx.vout[0].scriptPubKey = reserved_witness_script(3)
        valid_block = self.make_block([post_block_tx])
        assert_equal(node.submitblock(valid_block.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), valid_block.hash_hex)

        self.log.info("Post-activation: reserved addresses and descriptors are accepted by tooling RPCs")
        reserved_address = program_to_witness(3, bytes([0x42] * 32))
        assert_equal(node.validateaddress(reserved_address)["isvalid"], True)
        reserved_desc = descsum_create(f"addr({reserved_address})")
        assert_equal(node.getdescriptorinfo(reserved_desc)["isrange"], False)
        assert_equal(node.deriveaddresses(reserved_desc), [reserved_address])

        self.log.info("Post-activation: reserved prevouts are accepted by signing RPC prevout parsing")
        reserved_spend_tx = spend_reserved_tx(post_block_tx)
        signed = node.signrawtransactionwithkey(
            reserved_spend_tx.serialize().hex(),
            [],
            prevout_for_tx(post_block_tx),
        )
        assert_equal(signed["complete"], False)

        self.log.info("Post-activation: reserved outputs remain non-standard for mempool creation")
        post_mempool_tx = wallet.create_self_transfer(utxo_to_spend=post_mempool_utxo)["tx"]
        post_mempool_tx.vout[0].scriptPubKey = reserved_witness_script(4)
        post_reject = node.testmempoolaccept([post_mempool_tx.serialize().hex()], maxfeerate=0)[0]
        assert_equal(post_reject["allowed"], False)
        assert_equal(post_reject["reject-reason"], "scriptpubkey")

        self.log.info("Post-activation: spending reserved outputs remains non-standard in mempool")
        reserved_spend_reject = node.testmempoolaccept([reserved_spend_tx.serialize().hex()], maxfeerate=0)[0]
        assert_equal(reserved_spend_reject["allowed"], False)
        assert_equal(reserved_spend_reject["reject-reason"], "bad-txns-nonstandard-inputs")


if __name__ == "__main__":
    FeatureOuterWitnessActivationTest(__file__).main()
