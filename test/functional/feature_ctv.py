#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional coverage for P2MR OP_CHECKTEMPLATEVERIFY spends."""

from copy import deepcopy

from test_framework.blocktools import (
    COINBASE_MATURITY,
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
    sha256,
)
from test_framework.script import (
    CScript,
    OP_2,
    OP_CHECKTEMPLATEVERIFY,
    OP_TRUE,
    TaggedHash,
    default_ctv_hash,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


P2MR_LEAF_VERSION = 0xC0
TEMPLATE_MISMATCH = "Transaction template hash does not match"
OP_SUCCESS_DISCOURAGED = "OP_SUCCESSx reserved for soft-fork upgrades"


def p2mr_tapleaf_hash(script: CScript, leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    return TaggedHash("P2MRLeaf", bytes([leaf_version]) + ser_string(bytes(script)))


def p2mr_control_block(leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    return bytes([leaf_version | 1])


def ctv_leaf(ctv_hash: bytes) -> CScript:
    assert_equal(len(ctv_hash), 32)
    return CScript([ctv_hash, OP_CHECKTEMPLATEVERIFY])


def p2mr_op_true_leaf() -> CScript:
    return CScript([OP_TRUE])


def sequences_hash(tx: CTransaction) -> str:
    return sha256(b"".join(txin.nSequence.to_bytes(4, "little") for txin in tx.vin)).hex()


def outputs_hash(tx: CTransaction) -> str:
    return sha256(b"".join(txout.serialize() for txout in tx.vout)).hex()


def script_sigs_hash(tx: CTransaction) -> str:
    return sha256(b"".join(ser_string(txin.scriptSig) for txin in tx.vin)).hex()


class FeatureCTVTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

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

    def spend_output(self, amount: int, fee: int = 1_000) -> CTxOut:
        return CTxOut(amount - fee, self.wallet.get_output_script())

    def tx_template(self, *, amount: int = 200_000, fee: int = 1_000, version: int = 2,
                    locktime: int = 0, sequences: list[int] | None = None,
                    outputs: list[CTxOut] | None = None) -> CTransaction:
        sequences = sequences or [0]
        tx = CTransaction()
        tx.version = version
        tx.nLockTime = locktime
        tx.vin = [
            CTxIn(COutPoint(i + 1, i), nSequence=sequence)
            for i, sequence in enumerate(sequences)
        ]
        tx.vout = outputs or [self.spend_output(amount, fee)]
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        return tx

    def create_spend_tx(self, utxos: list[dict], outputs: list[CTxOut],
                        witness_stacks: list[list[bytes]], *,
                        sequences: list[int] | None = None,
                        version: int = 2, locktime: int = 0) -> CTransaction:
        assert_equal(len(utxos), len(witness_stacks))
        sequences = sequences or [0] * len(utxos)
        assert_equal(len(utxos), len(sequences))

        tx = CTransaction()
        tx.version = version
        tx.nLockTime = locktime
        tx.vin = [
            CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), nSequence=sequence)
            for utxo, sequence in zip(utxos, sequences)
        ]
        tx.vout = outputs
        tx.wit.vtxinwit = [CTxInWitness() for _ in utxos]
        for index, witness_stack in enumerate(witness_stacks):
            tx.wit.vtxinwit[index].scriptWitness.stack = witness_stack
        return tx

    def create_single_input_ctv_spend(self, *, amount: int = 200_000, fee: int = 1_000,
                                      version: int = 2, locktime: int = 0,
                                      sequence: int = 0,
                                      outputs: list[CTxOut] | None = None,
                                      ctv_arg: bytes | None = None) -> tuple[CTransaction, bytes]:
        outputs = outputs or [self.spend_output(amount, fee)]
        template_tx = self.tx_template(
            amount=amount,
            fee=fee,
            version=version,
            locktime=locktime,
            sequences=[sequence],
            outputs=deepcopy(outputs),
        )
        expected_hash = default_ctv_hash(template_tx, 0)
        leaf_script = ctv_leaf(ctv_arg or expected_hash)
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script), amount=amount)
        tx = self.create_spend_tx(
            [utxo],
            deepcopy(outputs),
            [[bytes(leaf_script), p2mr_control_block()]],
            sequences=[sequence],
            version=version,
            locktime=locktime,
        )
        return tx, expected_hash

    def create_two_input_ctv_spend(self, *, ctv_hash_input_index: int,
                                   ctv_actual_input_index: int,
                                   sequences: list[int] | None = None,
                                   amount: int = 200_000,
                                   fee: int = 1_000,
                                   ctv_hash_override: bytes | None = None) -> CTransaction:
        assert ctv_hash_input_index in (0, 1)
        assert ctv_actual_input_index in (0, 1)
        sequences = sequences or [0xffffffff, 0xffffffff]
        total_amount = amount * 2
        outputs = [self.spend_output(total_amount, fee)]
        template_tx = self.tx_template(
            amount=total_amount,
            fee=fee,
            sequences=sequences,
            outputs=deepcopy(outputs),
        )
        ctv_hash = ctv_hash_override or default_ctv_hash(template_tx, ctv_hash_input_index)

        ctv_script = ctv_leaf(ctv_hash)
        true_script = p2mr_op_true_leaf()
        ctv_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(ctv_script), amount=amount)
        true_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(true_script), amount=amount)

        if ctv_actual_input_index == 0:
            utxos = [ctv_utxo, true_utxo]
            witnesses = [
                [bytes(ctv_script), p2mr_control_block()],
                [bytes(true_script), p2mr_control_block()],
            ]
        else:
            utxos = [true_utxo, ctv_utxo]
            witnesses = [
                [bytes(true_script), p2mr_control_block()],
                [bytes(ctv_script), p2mr_control_block()],
            ]

        return self.create_spend_tx(
            utxos,
            outputs,
            witnesses,
            sequences=sequences,
        )

    def create_wrong_length_ctv_spend(self, ctv_arg_size: int) -> CTransaction:
        leaf_script = CScript([bytes([0x01]) * ctv_arg_size, OP_CHECKTEMPLATEVERIFY])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))
        return self.create_spend_tx(
            [utxo],
            [self.spend_output(utxo["amount"])],
            [[bytes(leaf_script), p2mr_control_block()]],
        )

    def assert_mempool_accepts(self, tx: CTransaction):
        tx_hex = tx.serialize().hex()
        result = self.nodes[0].testmempoolaccept([tx_hex])[0]
        assert_equal(result["allowed"], True)
        return self.nodes[0].sendrawtransaction(tx_hex)

    def assert_mempool_rejects(self, tx: CTransaction, expected_reason: str):
        tx_hex = tx.serialize().hex()
        result = self.nodes[0].testmempoolaccept([tx_hex])[0]
        assert_equal(result["allowed"], False)
        assert expected_reason in result["reject-reason"], result["reject-reason"]
        assert_raises_rpc_error(-26, expected_reason, self.nodes[0].sendrawtransaction, tx_hex)

    def assert_testmempool_rejects(self, tx: CTransaction, expected_reason: str):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert expected_reason in result["reject-reason"], result["reject-reason"]

    def make_witness_block(self, tx: CTransaction):
        tip = self.nodes[0].getbestblockhash()
        next_height = self.nodes[0].getblockcount() + 1
        block_time = self.nodes[0].getblockheader(tip)["mediantime"] + 1
        block = create_block(int(tip, 16), create_coinbase(next_height), block_time, txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        return block

    def test_valid_ctv_spend_mempool_and_mine(self):
        self.log.info("Valid P2MR CTV spend enters mempool and mines")
        tx, _ = self.create_single_input_ctv_spend()
        txid = self.assert_mempool_accepts(tx)
        mined = self.generate(self.wallet, 1)[0]
        assert txid in self.nodes[0].getblock(mined)["tx"]

    def test_ctv_template_mismatch_rejections(self):
        self.log.info("Reject P2MR CTV spends when committed transaction fields mutate")
        tx, _ = self.create_single_input_ctv_spend()

        for mutate in [
            lambda tx_mut: setattr(tx_mut, "version", tx_mut.version + 1),
            lambda tx_mut: setattr(tx_mut, "nLockTime", tx_mut.nLockTime + 1),
            lambda tx_mut: setattr(tx_mut.vin[0], "nSequence", tx_mut.vin[0].nSequence + 1),
            lambda tx_mut: setattr(tx_mut.vout[0], "nValue", tx_mut.vout[0].nValue - 1),
            lambda tx_mut: (setattr(tx_mut.vout[0], "nValue", tx_mut.vout[0].nValue - 5_000),
                            tx_mut.vout.append(CTxOut(5_000, self.wallet.get_output_script()))),
        ]:
            mutated = deepcopy(tx)
            mutate(mutated)
            self.assert_mempool_rejects(mutated, TEMPLATE_MISMATCH)

        two_output_tx, _ = self.create_single_input_ctv_spend(outputs=[
            CTxOut(99_000, self.wallet.get_output_script()),
            CTxOut(100_000, self.wallet.get_output_script()),
        ])
        swapped_outputs = deepcopy(two_output_tx)
        swapped_outputs.vout[0], swapped_outputs.vout[1] = swapped_outputs.vout[1], swapped_outputs.vout[0]
        self.assert_mempool_rejects(swapped_outputs, TEMPLATE_MISMATCH)

    def test_ctv_input_count_and_index_commitments(self):
        self.log.info("Reject P2MR CTV spends when input count or input index changes")
        one_input_template = self.tx_template(amount=400_000, fee=1_000, sequences=[0xffffffff])
        one_input_hash = default_ctv_hash(one_input_template, 0)
        input_count_mismatch = self.create_two_input_ctv_spend(
            ctv_hash_input_index=0,
            ctv_actual_input_index=0,
            ctv_hash_override=one_input_hash,
        )
        self.assert_mempool_rejects(input_count_mismatch, TEMPLATE_MISMATCH)

        input_index_mismatch = self.create_two_input_ctv_spend(
            ctv_hash_input_index=0,
            ctv_actual_input_index=1,
        )
        self.assert_mempool_rejects(input_index_mismatch, TEMPLATE_MISMATCH)

    def test_wrong_length_policy_and_consensus(self):
        self.log.info("Wrong-length CTV argument is nonstandard but consensus-valid")
        for ctv_arg_size in (31, 33):
            tx = self.create_wrong_length_ctv_spend(ctv_arg_size)
            self.assert_mempool_rejects(tx, OP_SUCCESS_DISCOURAGED)

            block = self.make_witness_block(tx)
            assert_equal(None, self.nodes[0].submitblock(block.serialize().hex()))
            assert_equal(self.nodes[0].getbestblockhash(), block.hash_hex)
            self.wallet.rescan_utxos()

    def test_bare_ctv_scriptpubkey_not_standard(self):
        self.log.info("Bare CTV scriptPubKeys are not standard outputs")
        tx = self.wallet.create_self_transfer(fee_rate=0)["tx"]
        tx.vout[0].nValue -= 2_000
        tx.vout.append(CTxOut(1_000, CScript([OP_CHECKTEMPLATEVERIFY])))
        self.assert_testmempool_rejects(tx, "scriptpubkey")
        self.wallet.rescan_utxos()

    def test_getdefaultctvhash_rpc(self):
        self.log.info("getdefaultctvhash matches independent Python CTV hashing")
        tx = self.tx_template(
            amount=500_000,
            fee=1_000,
            version=3,
            locktime=17,
            sequences=[0xfffffffe, 42],
            outputs=[
                CTxOut(250_000, self.wallet.get_output_script()),
                CTxOut(249_000, CScript([bytes([0x02, 0x03, 0x04])])),
            ],
        )
        tx.vin[1].scriptSig = CScript([bytes([0xaa, 0xbb, 0xcc])])
        tx_hex = tx.serialize().hex()

        expected_input_0 = default_ctv_hash(tx, 0).hex()
        expected_input_1 = default_ctv_hash(tx, 1).hex()
        assert_equal(self.nodes[0].getdefaultctvhash(tx_hex, 0), expected_input_0)
        assert_equal(self.nodes[0].getdefaultctvhash(tx_hex, 1), expected_input_1)

        verbose = self.nodes[0].getdefaultctvhash(tx_hex, 1, True)
        assert_equal(verbose["ctvhash"], expected_input_1)
        assert_equal(verbose["version"], 3)
        assert_equal(verbose["locktime"], 17)
        assert_equal(verbose["script_sigs_hash_included"], True)
        assert_equal(verbose["script_sigs_hash"], script_sigs_hash(tx))
        assert_equal(verbose["input_count"], 2)
        assert_equal(verbose["sequences_hash"], sequences_hash(tx))
        assert_equal(verbose["output_count"], 2)
        assert_equal(verbose["outputs_hash"], outputs_hash(tx))
        assert_equal(verbose["input_index"], 1)

        no_scriptsig = deepcopy(tx)
        no_scriptsig.vin[1].scriptSig = b""
        no_scriptsig_verbose = self.nodes[0].getdefaultctvhash(no_scriptsig.serialize().hex(), 0, True)
        assert_equal(no_scriptsig_verbose["ctvhash"], default_ctv_hash(no_scriptsig, 0).hex())
        assert_equal(no_scriptsig_verbose["script_sigs_hash_included"], False)
        assert "script_sigs_hash" not in no_scriptsig_verbose

        assert_raises_rpc_error(
            -8,
            "Input index 2 is out of range",
            self.nodes[0].getdefaultctvhash,
            tx_hex,
            2,
        )

    def test_delayed_p2mr_activation_controls_ctv(self):
        self.log.info("CTV follows delayed P2MR activation without its own deployment")
        activation_height = self.nodes[0].getblockcount() + 3
        self.restart_node(0, [
            f"-testactivationheight=p2mr@{activation_height}",
            "-acceptnonstdtxn=1",
        ])
        self.wallet = MiniWallet(self.nodes[0])

        wrong_hash = bytes([0x55]) * 32
        invalid_leaf = ctv_leaf(wrong_hash)

        self.log.info("Pre-activation mismatched CTV is accepted because P2MR rules are inactive")
        pre_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(invalid_leaf))
        pre_tx = self.create_spend_tx(
            [pre_utxo],
            [self.spend_output(pre_utxo["amount"])],
            [[bytes(invalid_leaf), p2mr_control_block()]],
        )
        pre_block = self.make_witness_block(pre_tx)
        assert self.nodes[0].getblockcount() < activation_height
        assert_equal(None, self.nodes[0].submitblock(pre_block.serialize().hex()))
        assert_equal(self.nodes[0].getbestblockhash(), pre_block.hash_hex)

        self.log.info("Post-activation mismatched CTV is rejected")
        post_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(invalid_leaf))
        assert self.nodes[0].getblockcount() >= activation_height
        post_tx = self.create_spend_tx(
            [post_utxo],
            [self.spend_output(post_utxo["amount"])],
            [[bytes(invalid_leaf), p2mr_control_block()]],
        )
        post_block = self.make_witness_block(post_tx)
        prev_tip = self.nodes[0].getbestblockhash()
        assert_equal(
            f"block-script-verify-flag-failed ({TEMPLATE_MISMATCH})",
            self.nodes[0].submitblock(post_block.serialize().hex()),
        )
        assert_equal(self.nodes[0].getbestblockhash(), prev_tip)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.wallet.generate(COINBASE_MATURITY + 1)

        self.test_valid_ctv_spend_mempool_and_mine()
        self.test_ctv_template_mismatch_rejections()
        self.test_ctv_input_count_and_index_commitments()
        self.test_wrong_length_policy_and_consensus()
        self.test_bare_ctv_scriptpubkey_not_standard()
        self.test_getdefaultctvhash_rpc()
        self.test_delayed_p2mr_activation_controls_ctv()


if __name__ == '__main__':
    FeatureCTVTest(__file__).main()
