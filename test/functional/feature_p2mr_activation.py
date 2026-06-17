#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test regtest-only P2MR activation-height override."""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_2,
    OP_TRUE,
    TaggedHash,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


P2MR_ACTIVATION_HEIGHT = 1102
P2MR_LEAF_VERSION = 0xC0


def p2mr_tapleaf_hash(script: CScript, leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    return TaggedHash("P2MRLeaf", bytes([leaf_version]) + ser_string(bytes(script)))


class FeatureP2MRActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.extra_args = [[
            f"-testactivationheight=p2mr@{P2MR_ACTIVATION_HEIGHT}",
            "-acceptnonstdtxn=1",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def fund_p2mr_output(self, merkle_root: bytes, amount: int = 200_000) -> dict:
        assert_equal(len(merkle_root), 32)
        script_pub_key = CScript([OP_2, merkle_root])
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pub_key, amount=amount)
        self.generate(self.wallet, 1)
        return {
            "txid": funding["txid"],
            "vout": funding["sent_vout"],
            "amount": amount,
        }

    def create_spend_tx(self, utxo: dict, witness_stack: list[bytes], fee: int = 1_000) -> CTransaction:
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(utxo["amount"] - fee, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

    def make_witness_block(self, tx: CTransaction):
        tip = self.nodes[0].getbestblockhash()
        next_height = self.nodes[0].getblockcount() + 1
        block_time = self.nodes[0].getblockheader(tip)["mediantime"] + 1
        block = create_block(int(tip, 16), create_coinbase(next_height), block_time, txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.ensure_cached_coinbase_mature(node)

        target_height = P2MR_ACTIVATION_HEIGHT - 3
        current_height = node.getblockcount()
        assert current_height <= target_height
        if current_height < target_height:
            self.generate(node, target_height - current_height)
        assert_equal(node.getblockcount(), target_height)

        leaf_script = CScript([OP_TRUE])
        merkle_root = p2mr_tapleaf_hash(leaf_script)
        invalid_control = bytes([P2MR_LEAF_VERSION])  # Low bit unset: invalid when P2MR rules are active.

        self.log.info("Pre-activation: invalid P2MR control byte is accepted in a block")
        pre_utxo = self.fund_p2mr_output(merkle_root)
        assert_equal(node.getblockcount(), P2MR_ACTIVATION_HEIGHT - 2)
        pre_tx = self.create_spend_tx(pre_utxo, [bytes(leaf_script), invalid_control])
        pre_block = self.make_witness_block(pre_tx)
        assert_equal(None, node.submitblock(pre_block.serialize().hex()))
        assert_equal(node.getbestblockhash(), pre_block.hash_hex)
        assert_equal(node.getblockcount(), P2MR_ACTIVATION_HEIGHT - 1)

        self.log.info("Post-activation: the same invalid P2MR spend is rejected")
        post_utxo = self.fund_p2mr_output(merkle_root)
        assert_equal(node.getblockcount(), P2MR_ACTIVATION_HEIGHT)
        post_tx = self.create_spend_tx(post_utxo, [bytes(leaf_script), invalid_control])
        post_block = self.make_witness_block(post_tx)

        prev_tip = node.getbestblockhash()
        assert_equal(
            "block-script-verify-flag-failed (P2MR control byte bit 0 must be set)",
            node.submitblock(post_block.serialize().hex()),
        )
        assert_equal(node.getbestblockhash(), prev_tip)


if __name__ == '__main__':
    FeatureP2MRActivationTest(__file__).main()
