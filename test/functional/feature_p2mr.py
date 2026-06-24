#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional coverage for P2MR wallet flows and script-path spends."""

import re
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY, MAX_STANDARD_TX_WEIGHT
from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
)
from test_framework.mempool_util import TRUC_CHILD_MAX_VSIZE
from test_framework.script import (
    CScript,
    OP_0,
    OP_2,
    OP_CHECKDATASIGADDPQC,
    OP_CHECKDATASIGPQC,
    OP_CHECKSIGADD,
    OP_DROP,
    OP_DUP,
    OP_EQUAL,
    OP_FALSE,
    OP_CHECKSIGPQC,
    OP_NOT,
    OP_NUMEQUAL,
    OP_RESERVED,
    OP_SWAP,
    OP_TRUE,
    TaggedHash,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_fee_amount,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import WalletUnlock


P2MR_LEAF_VERSION = 0xC0
P2MR_ARBITRARY_UNKNOWN_LEAF_VERSION = 0x8E
PQC_SIG_SIZE = 3680
MAX_STANDARD_P2MR_STACK_ITEM_SIZE = 16 * 1024
MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES = 128 * 1024
P2MR_DUST_THRESHOLD_SAT = 2855


def p2mr_tapleaf_hash(script: CScript, leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    return TaggedHash("P2MRLeaf", bytes([leaf_version]) + ser_string(bytes(script)))


def p2mr_tapbranch_hash(left: bytes, right: bytes) -> bytes:
    return TaggedHash("P2MRBranch", left + right if left < right else right + left)


def p2mr_control_block(merkle_branch: bytes = b"", leaf_version: int = P2MR_LEAF_VERSION) -> bytes:
    # P2MR control blocks use the same leaf-version mask as tapscript and require bit 0 to be set.
    return bytes([leaf_version | 1]) + merkle_branch


class FeatureP2MRTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.keypool_size = 200
        self.extra_args = [[f"-keypool={self.keypool_size}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sat_vb_to_btc_kvb(self, feerate_sat_vb: int) -> Decimal:
        return Decimal(feerate_sat_vb) / Decimal("100000")

    def assert_p2mr_address(self, wallet, address, *, is_change=None):
        info = wallet.getaddressinfo(address)
        assert_equal(info["isscript"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["witness_version"], 2)
        assert_equal(len(info["witness_program"]), 64)
        assert_equal(info["scriptPubKey"], f"5220{info['witness_program']}")
        assert_equal(wallet.decodescript(info["scriptPubKey"])["type"], "witness_v2_p2mr")
        assert_equal(wallet.validateaddress(address)["scriptPubKey"], info["scriptPubKey"])
        assert_equal(info["solvable"], True)
        if is_change is not None:
            assert_equal(info["ischange"], is_change)
        return info

    def extract_p2mr_pubkey(self, desc: str) -> str:
        match = re.fullmatch(r"mr\(pk\(([0-9a-f]{64})\)\)#.+", desc)
        assert match is not None, desc
        return match.group(1)

    def explicit_p2mr_descriptor(self, pubkey: str) -> str:
        return descsum_create(f"mr(pk({pubkey}))")

    def pqc_wallet_xprv_range(self, master_xprv: str, *, internal: bool = False) -> str:
        change = 1 if internal else 0
        return f"{master_xprv}/87h/1h/0h/{change}/*"

    def find_wallet_p2mr_index(self, node, master_xprv: str, target_addr: str, *, internal: bool = False, max_index: int = 20) -> int:
        candidate_desc = descsum_create(f"mr(pk(pqc({self.pqc_wallet_xprv_range(master_xprv, internal=internal)})))")
        for index in range(max_index):
            candidate_addr = node.deriveaddresses(candidate_desc, [index, index])[0]
            if candidate_addr == target_addr:
                return index
        raise AssertionError(f"could not find descriptor index for {target_addr}")

    def assert_wallet_p2mr_address_index(self, node, wallet, address: str, expected_index: int, *, internal: bool = False):
        p2mr_desc = next(
            entry["desc"]
            for entry in wallet.listdescriptors(True)["descriptors"]
            if entry["active"] and entry["internal"] == internal and entry["desc"].startswith("mr(")
        )
        assert_equal(node.deriveaddresses(p2mr_desc, [expected_index, expected_index])[0], address)

    def assert_p2mr_shaped(self, decoded_tx, *, min_vsize: int = 3000):
        witness = decoded_tx["vin"][0]["txinwitness"]
        assert_greater_than(len(witness), 2)
        sig = bytes.fromhex(witness[0])
        script = bytes.fromhex(witness[-2])
        control = bytes.fromhex(witness[-1])
        assert len(sig) in (PQC_SIG_SIZE, PQC_SIG_SIZE + 1)
        assert_greater_than(len(script), 33)
        assert_greater_than(len(control), 0)
        assert_equal(control[0] & 1, 1)
        assert_greater_than(decoded_tx["vsize"], min_vsize)
        assert_greater_than(decoded_tx["weight"], min_vsize)

    def assert_large_p2mr_spend(self, decoded_tx):
        self.assert_p2mr_shaped(decoded_tx)

    def mine(self, miner, blocks=1):
        self.generatetoaddress(self.nodes[0], blocks, miner.getnewaddress())

    def fund_p2mr_output(self, merkle_root: bytes, amount: int = 200_000) -> dict:
        assert_equal(len(merkle_root), 32)
        script_pub_key = CScript([OP_2, merkle_root])
        funding = self.script_wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pub_key, amount=amount)
        self.generate(self.script_wallet, 1)
        return {
            "txid": funding["txid"],
            "vout": funding["sent_vout"],
            "amount": amount,
        }

    def create_spend_tx(self, utxo: dict, witness_stack: list[bytes], fee: int = 1_000) -> CTransaction:
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(utxo["amount"] - fee, self.script_wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

    def p2mr_stack_items_for_total_bytes(self, total_bytes: int) -> list[bytes]:
        stack_items = []
        while total_bytes > 0:
            item_size = min(MAX_STANDARD_P2MR_STACK_ITEM_SIZE, total_bytes)
            stack_items.append(bytes([0x42]) * item_size)
            total_bytes -= item_size
        return stack_items

    def assert_rejected(self, tx: CTransaction, expected_reason: str):
        try:
            self.nodes[0].sendrawtransaction(tx.serialize().hex())
        except JSONRPCException as e:
            assert expected_reason in e.error["message"], e.error["message"]
        else:
            raise AssertionError("transaction unexpectedly accepted")

    def find_utxo_for_address(self, wallet, txid: str, address: str) -> dict:
        decoded = wallet.gettransaction(txid, verbose=True)["decoded"]
        for vout in decoded["vout"]:
            if vout["scriptPubKey"].get("address") == address:
                return {
                    "txid": txid,
                    "vout": vout["n"],
                    "amount": Decimal(str(vout["value"])),
                }
        raise AssertionError(f"no output for {address} in {txid}")

    def find_wallet_utxo(self, wallet, txid: str, address: str, *, minconf: int = 0) -> dict:
        for utxo in wallet.listunspent(minconf=minconf, addresses=[address]):
            if utxo["txid"] == txid:
                return utxo
        raise AssertionError(f"no wallet UTXO for {address} in {txid}")

    def create_signed_p2mr_wallet_tx(self, wallet, *, utxo: dict, outputs: list[dict], version: int = 3, fee_rate: int = 200) -> dict:
        return wallet.send(
            outputs=outputs,
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
            add_inputs=False,
            fee_rate=fee_rate,
            change_address=wallet.getrawchangeaddress(address_type="p2mr"),
            version=version,
            add_to_wallet=False,
        )

    def create_raw_signed_p2mr_wallet_tx(self, wallet, *, utxo: dict, outputs: list[dict], version: int) -> dict:
        raw = wallet.createrawtransaction(
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
            outputs=outputs,
            version=version,
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        return signed

    def spend_descriptor_utxo(self, wallet, utxo: dict, recipient: str, fee: Decimal = Decimal("0.00001000")) -> tuple[str, bytes, bytes]:
        spend_amount = utxo["amount"] - fee
        assert_greater_than(spend_amount, Decimal("0"))

        raw = wallet.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{recipient: spend_amount}],
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)

        spend_tx = tx_from_hex(signed["hex"])
        witness_stack = spend_tx.wit.vtxinwit[0].scriptWitness.stack
        return self.nodes[0].sendrawtransaction(signed["hex"]), witness_stack[-2], witness_stack[-1]

    def test_truc_real_p2mr_parent_child_policy(self, node, miner, p2mr_wallet):
        self.log.info("Exercise real signed P2MR spends under qbit TRUC child policy")
        fund_addr = p2mr_wallet.getnewaddress(address_type="p2mr")
        fund_txid = miner.sendtoaddress(fund_addr, Decimal("2.00000000"))
        self.mine(miner, 1)
        fund_utxo = self.find_wallet_utxo(p2mr_wallet, fund_txid, fund_addr, minconf=1)

        parent_outputs = [p2mr_wallet.getnewaddress(address_type="p2mr") for _ in range(16)]
        parent = p2mr_wallet.send(
            outputs=[{address: Decimal("0.05000000")} for address in parent_outputs],
            inputs=[{"txid": fund_utxo["txid"], "vout": fund_utxo["vout"]}],
            add_inputs=False,
            fee_rate=200,
            change_address=p2mr_wallet.getrawchangeaddress(address_type="p2mr"),
            version=3,
        )
        parent_txid = parent["txid"]
        parent_decoded = p2mr_wallet.gettransaction(parent_txid, verbose=True)["decoded"]
        self.assert_p2mr_shaped(parent_decoded)
        assert parent_txid in node.getrawmempool()

        parent_utxos = [
            self.find_wallet_utxo(p2mr_wallet, parent_txid, address)
            for address in parent_outputs
        ]

        first_child = p2mr_wallet.send(
            outputs=[{p2mr_wallet.getnewaddress(address_type="p2mr"): Decimal("0.03000000")}],
            inputs=[{"txid": parent_utxos[0]["txid"], "vout": parent_utxos[0]["vout"]}],
            add_inputs=False,
            fee_rate=200,
            change_address=p2mr_wallet.getrawchangeaddress(address_type="p2mr"),
            version=3,
        )
        first_child_txid = first_child["txid"]
        first_child_decoded = p2mr_wallet.gettransaction(first_child_txid, verbose=True)["decoded"]
        self.assert_p2mr_shaped(first_child_decoded)
        assert first_child_txid in node.getrawmempool()

        second_child = self.create_signed_p2mr_wallet_tx(
            p2mr_wallet,
            utxo=parent_utxos[1],
            outputs=[{p2mr_wallet.getnewaddress(address_type="p2mr"): Decimal("0.03000000")}],
            version=3,
            fee_rate=1,
        )
        second_child_decoded = node.decoderawtransaction(second_child["hex"])
        self.assert_p2mr_shaped(second_child_decoded)
        second_child_result = node.testmempoolaccept([second_child["hex"]])[0]
        assert_equal(second_child_result["allowed"], False)
        assert "reject-reason" in second_child_result
        assert second_child_decoded["txid"] not in node.getrawmempool()
        assert first_child_txid in node.getrawmempool()

        v2_child = self.create_raw_signed_p2mr_wallet_tx(
            p2mr_wallet,
            utxo=parent_utxos[2],
            outputs=[{p2mr_wallet.getnewaddress(address_type="p2mr"): Decimal("0.03000000")}],
            version=2,
        )
        v2_child_decoded = node.decoderawtransaction(v2_child["hex"])
        self.assert_p2mr_shaped(v2_child_decoded)
        assert_raises_rpc_error(
            -26,
            "TRUC-violation, non-version=3 tx",
            node.sendrawtransaction,
            v2_child["hex"],
        )

        oversize_child = p2mr_wallet.send(
            outputs=[{p2mr_wallet.getnewaddress(address_type="p2mr"): Decimal("0.50000000")}],
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in parent_utxos[3:16]],
            add_inputs=False,
            fee_rate=200,
            change_address=p2mr_wallet.getrawchangeaddress(address_type="p2mr"),
            version=3,
            add_to_wallet=False,
        )
        oversize_child_decoded = node.decoderawtransaction(oversize_child["hex"])
        self.assert_p2mr_shaped(oversize_child_decoded)
        assert_greater_than(oversize_child_decoded["vsize"], TRUC_CHILD_MAX_VSIZE)
        assert_raises_rpc_error(
            -26,
            "TRUC-violation, version=3 child tx",
            node.sendrawtransaction,
            oversize_child["hex"],
        )

        self.mine(miner, 1)
        assert_greater_than(p2mr_wallet.gettransaction(parent_txid)["confirmations"], 0)
        assert_greater_than(p2mr_wallet.gettransaction(first_child_txid)["confirmations"], 0)

    def test_single_leaf_spend(self):
        self.log.info("Single-leaf P2MR spend with OP_TRUE leaf")
        leaf_script = CScript([OP_TRUE])
        merkle_root = p2mr_tapleaf_hash(leaf_script)
        utxo = self.fund_p2mr_output(merkle_root)

        witness_stack = [bytes(leaf_script), p2mr_control_block()]
        tx = self.create_spend_tx(utxo, witness_stack)
        txid = self.script_wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx.serialize().hex())
        mined = self.generate(self.script_wallet, 1)[0]
        assert txid in self.nodes[0].getblock(mined)["tx"]

    def test_reject_control_bit(self):
        self.log.info("Reject P2MR control byte without required low bit")
        leaf_script = CScript([OP_TRUE])
        merkle_root = p2mr_tapleaf_hash(leaf_script)
        utxo = self.fund_p2mr_output(merkle_root)

        invalid_control = bytes([P2MR_LEAF_VERSION])
        tx = self.create_spend_tx(utxo, [bytes(leaf_script), invalid_control])
        self.assert_rejected(tx, "P2MR control byte bit 0 must be set")

    def test_reject_commitment_mismatch(self):
        self.log.info("Reject P2MR spend when witness script does not match committed Merkle root")
        committed_script = CScript([OP_TRUE])
        spend_script = CScript([OP_FALSE])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(committed_script))

        tx = self.create_spend_tx(utxo, [bytes(spend_script), p2mr_control_block()])
        self.assert_rejected(tx, "Witness program hash mismatch")

    def test_multi_leaf_spend(self):
        self.log.info("Spend from a two-leaf P2MR tree using a non-trivial Merkle branch")
        left_script = CScript([OP_TRUE])
        right_script = CScript([OP_FALSE])
        left_hash = p2mr_tapleaf_hash(left_script)
        right_hash = p2mr_tapleaf_hash(right_script)
        merkle_root = p2mr_tapbranch_hash(left_hash, right_hash)

        utxo = self.fund_p2mr_output(merkle_root)

        left_control = p2mr_control_block(right_hash)
        tx = self.create_spend_tx(utxo, [bytes(left_script), left_control])
        txid = self.script_wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx.serialize().hex())
        mined = self.generate(self.script_wallet, 1)[0]
        assert txid in self.nodes[0].getblock(mined)["tx"]

    def test_validation_weight_rejection(self):
        self.log.info("Reject underweight P2MR witness that attempts multiple CHECKSIGADD operations")
        malformed_pubkey_a = bytes([0x11] * 33)
        malformed_pubkey_b = bytes([0x22] * 33)
        leaf_script = CScript([
            OP_0,
            malformed_pubkey_a,
            OP_CHECKSIGADD,
            malformed_pubkey_b,
            OP_CHECKSIGADD,
            OP_2,
            OP_EQUAL,
        ])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        # Tiny non-empty signatures force validation-weight accounting to underflow immediately.
        tx = self.create_spend_tx(utxo, [b"\x01", b"\x01", bytes(leaf_script), p2mr_control_block()])
        self.assert_rejected(tx, "Too much signature validation relative to witness weight")

    def test_checkdatasigpqc_empty_signature(self):
        self.log.info("Spend P2MR CHECKDATASIGPQC leaf with empty signature false path")
        msg_hash = bytes([0x42] * 32)
        pqc_pubkey = bytes([0x33] * 32)
        leaf_script = CScript([msg_hash, pqc_pubkey, OP_CHECKDATASIGPQC, OP_NOT])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        tx = self.create_spend_tx(utxo, [b"", bytes(leaf_script), p2mr_control_block()])
        txid = self.script_wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx.serialize().hex())
        mined = self.generate(self.script_wallet, 1)[0]
        assert txid in self.nodes[0].getblock(mined)["tx"]

    def test_checkdatasigaddpqc_empty_threshold(self):
        self.log.info("Spend P2MR CHECKDATASIGADDPQC leaf with empty-signature threshold")
        msg_hash = bytes([0x43] * 32)
        pqc_pubkey_a = bytes([0x34] * 32)
        pqc_pubkey_b = bytes([0x35] * 32)
        leaf_script = CScript([
            msg_hash,
            OP_0,
            pqc_pubkey_a,
            OP_CHECKDATASIGADDPQC,
            msg_hash,
            OP_SWAP,
            pqc_pubkey_b,
            OP_CHECKDATASIGADDPQC,
            OP_0,
            OP_NUMEQUAL,
        ])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        tx = self.create_spend_tx(utxo, [b"", b"", bytes(leaf_script), p2mr_control_block()])
        txid = self.script_wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx.serialize().hex())
        mined = self.generate(self.script_wallet, 1)[0]
        assert txid in self.nodes[0].getblock(mined)["tx"]

    def test_checkdatasigpqc_validation_errors(self):
        self.log.info("Reject malformed P2MR CHECKDATASIGPQC data signature spends")
        msg_hash = bytes([0x44] * 32)
        pqc_pubkey = bytes([0x36] * 32)

        invalid_sig_size_script = CScript([msg_hash, pqc_pubkey, OP_CHECKDATASIGPQC])
        invalid_sig_size_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(invalid_sig_size_script))
        invalid_sig_size_tx = self.create_spend_tx(
            invalid_sig_size_utxo,
            [bytes(PQC_SIG_SIZE + 1), bytes(invalid_sig_size_script), p2mr_control_block()],
        )
        self.assert_rejected(invalid_sig_size_tx, "Invalid PQC signature size")

        invalid_msg_hash_script = CScript([bytes([0x45] * 31), pqc_pubkey, OP_CHECKDATASIGPQC])
        invalid_msg_hash_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(invalid_msg_hash_script))
        invalid_msg_hash_tx = self.create_spend_tx(
            invalid_msg_hash_utxo,
            [bytes(PQC_SIG_SIZE), bytes(invalid_msg_hash_script), p2mr_control_block()],
        )
        self.assert_rejected(invalid_msg_hash_tx, "Push value size limit exceeded")

        invalid_pubkey_script = CScript([msg_hash, bytes([0x46] * 33), OP_CHECKDATASIGPQC])
        invalid_pubkey_utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(invalid_pubkey_script))
        invalid_pubkey_tx = self.create_spend_tx(
            invalid_pubkey_utxo,
            [bytes(PQC_SIG_SIZE), bytes(invalid_pubkey_script), p2mr_control_block()],
        )
        self.assert_rejected(invalid_pubkey_tx, "Public key is neither compressed or uncompressed")

    def test_malformed_max_size_signature_rejection(self):
        self.log.info("Reject malformed max-size P2MR v1 signature item")
        pqc_pubkey = bytes([0x33] * 32)
        leaf_script = CScript([pqc_pubkey, OP_CHECKSIGPQC])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        malformed_sig = b"\x01" + bytes(PQC_SIG_SIZE)
        tx = self.create_spend_tx(utxo, [malformed_sig, bytes(leaf_script), p2mr_control_block()])
        self.assert_rejected(tx, "Invalid PQC signature hash type")

    def test_stack_item_policy_rejection(self):
        self.log.info("Reject oversized P2MR witness stack item under standard policy")
        leaf_script = CScript([OP_DUP, OP_DROP, OP_DROP, OP_TRUE])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        oversized_arg = bytes([0x42]) * (MAX_STANDARD_P2MR_STACK_ITEM_SIZE + 1)
        tx = self.create_spend_tx(utxo, [oversized_arg, bytes(leaf_script), p2mr_control_block()])
        self.assert_rejected(tx, "bad-witness-nonstandard")

    def test_large_stack_policy_acceptance(self):
        self.log.info("Accept large standard P2MR witness stack under transaction weight policy")
        assert_equal(MAX_STANDARD_TX_WEIGHT, 400_000)
        stack_items = self.p2mr_stack_items_for_total_bytes(MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES)
        leaf_script = CScript([OP_DROP] * len(stack_items) + [OP_TRUE])
        utxo = self.fund_p2mr_output(
            p2mr_tapleaf_hash(leaf_script),
            amount=300_000,
        )

        tx = self.create_spend_tx(
            utxo,
            stack_items + [bytes(leaf_script), p2mr_control_block()],
            fee=50_000,
        )
        assert tx.get_weight() <= MAX_STANDARD_TX_WEIGHT
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], True)
        txid = self.nodes[0].sendrawtransaction(tx.serialize().hex())
        assert txid in self.nodes[0].getrawmempool()

    def test_op_success_policy_rejection(self):
        self.log.info("Reject P2MR OP_SUCCESS leaf under standard policy")
        leaf_script = CScript([OP_RESERVED])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        tx = self.create_spend_tx(utxo, [bytes(leaf_script), p2mr_control_block()])
        self.assert_rejected(tx, "OP_SUCCESSx reserved for soft-fork upgrades")

    def test_unknown_leaf_policy_rejection(self):
        self.log.info("Reject arbitrary unknown P2MR leaf version under standard policy")
        leaf_script = CScript([OP_TRUE])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script, P2MR_ARBITRARY_UNKNOWN_LEAF_VERSION))

        tx = self.create_spend_tx(utxo, [
            bytes(leaf_script),
            p2mr_control_block(leaf_version=P2MR_ARBITRARY_UNKNOWN_LEAF_VERSION),
        ])
        self.assert_rejected(tx, "Taproot version reserved for soft-fork upgrades")

    def test_non_32_byte_pubkey_consensus_rejection(self):
        self.log.info("Reject non-32-byte P2MR pubkey size")
        malformed_pubkey = bytes([0x44] * 33)
        leaf_script = CScript([malformed_pubkey, OP_CHECKSIGPQC])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(leaf_script))

        dummy_sig = bytes(PQC_SIG_SIZE)
        tx = self.create_spend_tx(utxo, [dummy_sig, bytes(leaf_script), p2mr_control_block()])
        self.assert_rejected(tx, "Public key is neither compressed or uncompressed")

    def test_data_pqc_hash_rpc(self, node, p2mr_wallet):
        self.log.info("Sign and verify an arbitrary data hash with a wallet-owned P2MR pubkey leaf")
        address = p2mr_wallet.getnewaddress(address_type="p2mr")
        message_hash = "11" * 32
        proof = p2mr_wallet.signdatapqchash(address, message_hash)

        assert_equal(proof["address"], address)
        assert_equal(proof["message_hash"], message_hash)
        assert_equal(proof["domain"], "QbitDataSigPQC")
        assert_equal(proof["algorithm"], "SLH-DSA-SHA2-128s-bounded30")
        assert_equal(proof["proof_mode"], "p2mr-pubkey")
        assert_equal(len(proof["pubkey"]), 64)
        assert_equal(len(proof["signature"]), PQC_SIG_SIZE * 2)
        assert_equal(proof["leaf_version"], P2MR_LEAF_VERSION)
        assert_equal(proof["leaf_script"], f"20{proof['pubkey']}b3")
        assert_equal(proof["control_block"], "c1")
        assert_equal(proof["pqc_signature_count"], 1)
        assert_equal(proof["pqc_key_states"][0]["pubkey"], proof["pubkey"])

        verified = node.verifydatapqchash(proof)
        assert_equal(verified["valid"], True)
        assert_equal(verified["address"], address)
        assert_equal(verified["message_hash"], message_hash)
        assert_equal(verified["pubkey"], proof["pubkey"])
        assert_equal(verified["proof_mode"], "p2mr-pubkey")
        assert_equal(verified["p2mr_merkle_root"], proof["p2mr_merkle_root"])
        assert_equal(verified["datasig_hash"], proof["datasig_hash"])

        explicit_proof = p2mr_wallet.signdatapqchash(address, message_hash, {
            "pubkey": proof["pubkey"],
            "leaf_script": proof["leaf_script"],
            "control_block": proof["control_block"],
            "include_pqc_usage": False,
        })
        assert_equal(node.verifydatapqchash(explicit_proof)["valid"], True)
        assert "pqc_signature_count" not in explicit_proof

        wrong_message = dict(proof)
        wrong_message["message_hash"] = "22" * 32
        invalid = node.verifydatapqchash(wrong_message)
        assert_equal(invalid["valid"], False)
        assert_equal(invalid["error"], "signature does not verify")

        wrong_signature = dict(proof)
        wrong_signature["signature"] = proof["signature"][:-2] + ("00" if proof["signature"][-2:] != "00" else "01")
        invalid = node.verifydatapqchash(wrong_signature)
        assert_equal(invalid["valid"], False)
        assert_equal(invalid["error"], "signature does not verify")

        wrong_leaf = dict(proof)
        wrong_leaf["leaf_script"] = f"20{'00' * 32}b3"
        invalid = node.verifydatapqchash(wrong_leaf)
        assert_equal(invalid["valid"], False)
        assert_equal(invalid["error"], "leaf_script is not a single-key P2MR pubkey leaf for pubkey")

        wrong_address = dict(proof)
        wrong_address["address"] = p2mr_wallet.getnewaddress(address_type="p2mr")
        invalid = node.verifydatapqchash(wrong_address)
        assert_equal(invalid["valid"], False)
        assert_equal(invalid["error"], "leaf_script/control_block do not match address")

        bad_control = dict(proof)
        bad_control["control_block"] = "c0"
        assert_raises_rpc_error(
            -8,
            "P2MR control byte bit 0 must be set",
            node.verifydatapqchash,
            bad_control,
        )
        bad_mode = dict(proof)
        bad_mode["proof_mode"] = "raw-pubkey"
        assert_raises_rpc_error(
            -8,
            "Only proof_mode \"p2mr-pubkey\" is currently supported",
            node.verifydatapqchash,
            bad_mode,
        )
        assert_raises_rpc_error(
            -8,
            "message_hash must be exactly 32 bytes",
            p2mr_wallet.signdatapqchash,
            address,
            "11" * 31,
        )
        assert_raises_rpc_error(
            -4,
            "No supported single-key P2MR pubkey leaf was found for this address",
            p2mr_wallet.signdatapqchash,
            address,
            message_hash,
            {"pubkey": "00" * 32},
        )

        self.log.info("Spend a CHECKDATASIGPQC leaf with the signdatapqchash signature")
        datasig_leaf = CScript([bytes.fromhex(proof["pubkey"]), OP_CHECKDATASIGPQC])
        utxo = self.fund_p2mr_output(p2mr_tapleaf_hash(datasig_leaf))
        tx = self.create_spend_tx(
            utxo,
            [bytes.fromhex(proof["signature"]), bytes.fromhex(message_hash), bytes(datasig_leaf), p2mr_control_block()],
        )
        txid = self.script_wallet.sendrawtransaction(from_node=node, tx_hex=tx.serialize().hex())
        mined = self.generate(self.script_wallet, 1)[0]
        assert txid in node.getblock(mined)["tx"]

    def test_two_of_three_multisig_psbt(self, node, miner, amount: Decimal):
        self.log.info("Exercise a real 2-of-3 P2MR multisig PSBT spend")
        signer_wallets = []
        signer_pubkeys = []
        for index in range(3):
            wallet_name = f"p2mr_multisig_signer_{index}"
            node.createwallet(wallet_name)
            signer = node.get_wallet_rpc(wallet_name)
            try:
                created = signer.createwalletdescriptor("p2mr")
                assert_greater_than(len(created["descs"]), 0)
            except JSONRPCException as e:
                assert "Descriptor already exists" in e.error["message"]

            exported = signer.exportpubkeydb()
            assert_greater_than(exported["count"], 0)
            signer_pubkeys.append(exported["pubkeys"][0]["pubkey"])
            signer_wallets.append(signer)

        multisig_desc = descsum_create(f"mr(multi_a(2,{','.join(signer_pubkeys)}))")
        node.createwallet("p2mr_multisig_watch", blank=True, disable_private_keys=True)
        multisig_watch = node.get_wallet_rpc("p2mr_multisig_watch")
        imported_watch = multisig_watch.importdescriptors([{
            "desc": multisig_desc,
            "timestamp": "now",
        }])
        assert_equal(imported_watch[0]["success"], True)

        multisig_addr = node.deriveaddresses(multisig_desc)[0]
        self.assert_p2mr_address(multisig_watch, multisig_addr)

        funding_txid = miner.sendtoaddress(multisig_addr, amount)
        self.mine(miner, 1)
        assert_greater_than(multisig_watch.gettransaction(funding_txid)["confirmations"], 0)

        psbt = multisig_watch.walletcreatefundedpsbt(
            [],
            [{miner.getnewaddress(): amount}],
            0,
            {
                "includeWatching": True,
                "subtractFeeFromOutputs": [0],
                "fee_rate": 200,
            },
        )

        one_signature = signer_wallets[0].walletprocesspsbt(
            psbt=psbt["psbt"],
            sign=True,
            sighashtype="DEFAULT",
            bip32derivs=True,
            finalize=False,
        )
        assert_equal(one_signature["complete"], False)
        assert_equal(node.finalizepsbt(one_signature["psbt"])["complete"], False)

        second_signature = signer_wallets[1].walletprocesspsbt(
            psbt=psbt["psbt"],
            sign=True,
            sighashtype="DEFAULT",
            bip32derivs=True,
            finalize=False,
        )
        assert_equal(second_signature["complete"], False)

        combined = node.combinepsbt([one_signature["psbt"], second_signature["psbt"]])
        finalized = node.finalizepsbt(combined)
        assert_equal(finalized["complete"], True)
        assert_equal(node.testmempoolaccept([finalized["hex"]])[0]["allowed"], True)

        spend_txid = node.sendrawtransaction(finalized["hex"])
        assert spend_txid in node.getrawmempool()
        self.mine(miner, 1)
        assert_greater_than(multisig_watch.gettransaction(spend_txid)["confirmations"], 0)

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.mine(miner, COINBASE_MATURITY + 1)

        node.createwallet("p2mr_wallet")
        p2mr_wallet = node.get_wallet_rpc("p2mr_wallet")
        p2mr_master_xprv = p2mr_wallet.gethdkeys(private=True)[0]["xprv"]
        node.createwallet("desc_watch", blank=True, disable_private_keys=True)
        desc_watch = node.get_wallet_rpc("desc_watch")
        node.createwallet("pubdb_watch", blank=True, disable_private_keys=True)
        pubdb_watch = node.get_wallet_rpc("pubdb_watch")
        node.createwallet("pubdb_watch_internal", blank=True, disable_private_keys=True)
        pubdb_watch_internal = node.get_wallet_rpc("pubdb_watch_internal")
        node.createwallet("pubdb_watch_legacy", blank=True, disable_private_keys=True)
        pubdb_watch_legacy = node.get_wallet_rpc("pubdb_watch_legacy")
        node.createwallet("leaf_source_k1")
        leaf_source_k1 = node.get_wallet_rpc("leaf_source_k1")
        node.createwallet("leaf_source_k2")
        leaf_source_k2 = node.get_wallet_rpc("leaf_source_k2")

        self.log.info("1/20 createwalletdescriptor(type=p2mr) creates active descriptors")
        created_descs = []
        try:
            created = p2mr_wallet.createwalletdescriptor("p2mr")
            created_descs = created["descs"]
        except JSONRPCException as e:
            assert "Descriptor already exists" in e.error["message"]
            created_descs = [
                entry["desc"] for entry in p2mr_wallet.listdescriptors()["descriptors"]
                if entry["active"] and entry["desc"].startswith("mr(")
            ]
        assert len(created_descs) >= 1
        for desc in created_descs:
            assert desc.startswith("mr(")
        external_parent_desc = next(desc for desc in created_descs if "/0/*" in desc)
        internal_parent_desc = next(desc for desc in created_descs if "/1/*" in desc)

        self.log.info("2/20 getnewaddress(address_type=p2mr) returns witness v2 P2MR")
        first_p2mr_addr = p2mr_wallet.getnewaddress(address_type="p2mr")
        first_p2mr_info = self.assert_p2mr_address(p2mr_wallet, first_p2mr_addr, is_change=False)
        assert first_p2mr_info["desc"].startswith("mr(")
        assert_equal(first_p2mr_info["parent_desc"], external_parent_desc)
        assert_equal(node.getdescriptorinfo(first_p2mr_info["desc"])["descriptor"], first_p2mr_info["desc"])
        assert_equal(node.getdescriptorinfo(first_p2mr_info["parent_desc"])["descriptor"], first_p2mr_info["parent_desc"])
        first_external_index = self.find_wallet_p2mr_index(node, p2mr_master_xprv, first_p2mr_addr)
        assert_equal(first_external_index, 0)

        self.log.info("P2MR recipients below the qbit dust threshold are rejected by wallet send")
        p2mr_dust_amount = Decimal(P2MR_DUST_THRESHOLD_SAT - 1) / Decimal("100000000")
        assert_raises_rpc_error(
            -6,
            "Transaction amount too small",
            miner.sendtoaddress,
            first_p2mr_addr,
            p2mr_dust_amount,
        )

        first_change_addr = p2mr_wallet.getrawchangeaddress(address_type="p2mr")
        first_change_info = self.assert_p2mr_address(p2mr_wallet, first_change_addr, is_change=True)
        assert_equal(first_change_info["parent_desc"], internal_parent_desc)
        first_internal_index = self.find_wallet_p2mr_index(node, p2mr_master_xprv, first_change_addr, internal=True)
        assert_equal(first_internal_index, 0)

        miner_balance = miner.getbalance()
        fund_amount = (miner_balance / Decimal("4")).quantize(Decimal("0.00000001"))
        assert_greater_than(fund_amount, Decimal("0.0005"))
        spend_amount = (fund_amount / Decimal("4")).quantize(Decimal("0.00000001"))
        change_probe_amount = (fund_amount / Decimal("8")).quantize(Decimal("0.00000001"))
        psbt_amount = (fund_amount / Decimal("16")).quantize(Decimal("0.00000001"))
        multisig_amount = (fund_amount / Decimal("32")).quantize(Decimal("0.00000001"))
        raw_fund_amount = (fund_amount / Decimal("20")).quantize(Decimal("0.00000001"))
        watchonly_amount = (fund_amount / Decimal("12")).quantize(Decimal("0.00000001"))

        self.script_wallet = MiniWallet(node)
        miner.sendtoaddress(self.script_wallet.get_address(), Decimal("1"))
        self.mine(miner, 1)
        self.script_wallet.rescan_utxos()
        assert self.script_wallet.get_utxos(mark_as_spent=False)

        self.log.info("3/20 signdatapqchash/verifydatapqchash sign and verify P2MR pubkey proofs")
        self.test_data_pqc_hash_rpc(node, p2mr_wallet)

        self.log.info("4/20 send/receive to P2MR address")
        incoming_txid = miner.sendtoaddress(first_p2mr_addr, fund_amount)
        self.mine(miner, 1)
        assert_greater_than(p2mr_wallet.gettransaction(incoming_txid)["confirmations"], 0)
        assert_greater_than(p2mr_wallet.getbalance(), Decimal("0"))

        self.log.info("5/20 spend from P2MR wallet")
        spend_txid = p2mr_wallet.sendtoaddress(miner.getnewaddress(), spend_amount, fee_rate=200)
        spend_tx = p2mr_wallet.gettransaction(spend_txid, verbose=True)
        spend_entry = node.getmempoolentry(spend_txid)
        assert_equal(spend_entry["vsize"], spend_tx["decoded"]["vsize"])
        assert_equal(spend_entry["weight"], spend_tx["decoded"]["weight"])
        assert_fee_amount(-spend_tx["fee"], spend_tx["decoded"]["vsize"], self.sat_vb_to_btc_kvb(200))
        self.assert_large_p2mr_spend(spend_tx["decoded"])
        self.mine(miner, 1)
        assert_greater_than(p2mr_wallet.gettransaction(spend_txid)["confirmations"], 0)

        self.test_truc_real_p2mr_parent_child_policy(node, miner, p2mr_wallet)

        self.log.info("6/20 change output selection prefers P2MR when P2MR SPKM is active")
        change_probe_txid = p2mr_wallet.sendtoaddress(first_p2mr_addr, change_probe_amount, fee_rate=200)
        decoded = p2mr_wallet.gettransaction(change_probe_txid, verbose=True)["decoded"]
        change_outputs = []
        for vout in decoded["vout"]:
            addr = vout["scriptPubKey"].get("address")
            if not addr:
                continue
            if p2mr_wallet.getaddressinfo(addr).get("ischange", False):
                change_outputs.append(vout)
        assert_equal(len(change_outputs), 1)
        assert_equal(change_outputs[0]["scriptPubKey"]["type"], "witness_v2_p2mr")
        change_info = self.assert_p2mr_address(
            p2mr_wallet,
            change_outputs[0]["scriptPubKey"]["address"],
            is_change=True,
        )
        assert_equal(change_info["parent_desc"], internal_parent_desc)
        change_index = self.find_wallet_p2mr_index(
            node,
            p2mr_master_xprv,
            change_outputs[0]["scriptPubKey"]["address"],
            internal=True,
        )
        assert change_index >= first_internal_index
        self.mine(miner, 1)

        self.log.info("7/20 import and derive a multi-leaf mr() descriptor")
        hdkey_k1 = leaf_source_k1.gethdkeys({"active_only": True})[0]["xpub"]
        hdkey_k2 = leaf_source_k2.gethdkeys({"active_only": True})[0]["xpub"]
        try:
            assert len(leaf_source_k1.createwalletdescriptor("p2mr", {"hdkey": hdkey_k1})["descs"]) >= 1
        except JSONRPCException as e:
            assert "Descriptor already exists" in e.error["message"]
        try:
            assert len(leaf_source_k2.createwalletdescriptor("p2mr", {"hdkey": hdkey_k2})["descs"]) >= 1
        except JSONRPCException as e:
            assert "Descriptor already exists" in e.error["message"]
        source_addr_k1 = leaf_source_k1.getnewaddress(address_type="p2mr")
        source_addr_k2 = leaf_source_k2.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(leaf_source_k1, source_addr_k1)
        self.assert_p2mr_address(leaf_source_k2, source_addr_k2)
        k1 = self.extract_p2mr_pubkey(leaf_source_k1.getaddressinfo(source_addr_k1)["desc"])
        k2 = self.extract_p2mr_pubkey(leaf_source_k2.getaddressinfo(source_addr_k2)["desc"])
        tree_desc = descsum_create(f"mr({{pk({k1}),pk({k2})}})")
        import_tree = desc_watch.importdescriptors([{
            "desc": tree_desc,
            "timestamp": "now",
        }])
        assert_equal(import_tree[0]["success"], True)
        tree_addr = node.deriveaddresses(tree_desc)[0]
        tree_info = node.validateaddress(tree_addr)
        assert_equal(tree_info["isvalid"], True)
        assert_equal(tree_info["witness_version"], 2)

        self.log.info("8/20 descriptor-backed multi-leaf spends cover both pk() leaves")
        master_xprv_k1 = leaf_source_k1.gethdkeys(private=True)[0]["xprv"]
        master_xprv_k2 = leaf_source_k2.gethdkeys(private=True)[0]["xprv"]
        k1_index = self.find_wallet_p2mr_index(node, master_xprv_k1, source_addr_k1)
        k2_index = self.find_wallet_p2mr_index(node, master_xprv_k2, source_addr_k2)
        signer_k1_desc = descsum_create(
            f"mr({{pk(pqc({self.pqc_wallet_xprv_range(master_xprv_k1)})),pk({k2})}})"
        )
        signer_k2_desc = descsum_create(
            f"mr({{pk({k1}),pk(pqc({self.pqc_wallet_xprv_range(master_xprv_k2)}))}})"
        )

        node.createwallet("tree_signer_k1", blank=True)
        tree_signer_k1 = node.get_wallet_rpc("tree_signer_k1")
        node.createwallet("tree_signer_k2", blank=True)
        tree_signer_k2 = node.get_wallet_rpc("tree_signer_k2")
        assert_equal(tree_signer_k1.importdescriptors([{
            "desc": signer_k1_desc,
            "timestamp": "now",
            "range": [k1_index, k1_index],
        }])[0]["success"], True)
        assert_equal(tree_signer_k2.importdescriptors([{
            "desc": signer_k2_desc,
            "timestamp": "now",
            "range": [k2_index, k2_index],
        }])[0]["success"], True)
        assert_equal(node.deriveaddresses(signer_k1_desc, [k1_index, k1_index])[0], tree_addr)
        assert_equal(node.deriveaddresses(signer_k2_desc, [k2_index, k2_index])[0], tree_addr)

        tree_fund_txid_1 = miner.sendtoaddress(tree_addr, Decimal("0.015"))
        tree_fund_txid_2 = miner.sendtoaddress(tree_addr, Decimal("0.016"))
        self.mine(miner, 1)

        tree_utxo_1 = self.find_utxo_for_address(miner, tree_fund_txid_1, tree_addr)
        tree_utxo_2 = self.find_utxo_for_address(miner, tree_fund_txid_2, tree_addr)

        leaf_script_1 = CScript([bytes.fromhex(k1), OP_CHECKSIGPQC])
        leaf_script_2 = CScript([bytes.fromhex(k2), OP_CHECKSIGPQC])
        control_1 = p2mr_control_block(p2mr_tapleaf_hash(leaf_script_2))
        control_2 = p2mr_control_block(p2mr_tapleaf_hash(leaf_script_1))

        leaf_spend_txid_1, actual_script_1, actual_control_1 = self.spend_descriptor_utxo(
            tree_signer_k1,
            tree_utxo_1,
            miner.getnewaddress(),
        )
        leaf_spend_txid_2, actual_script_2, actual_control_2 = self.spend_descriptor_utxo(
            tree_signer_k2,
            tree_utxo_2,
            miner.getnewaddress(),
        )
        expected_leaf_paths = {
            (bytes(leaf_script_1), control_1),
            (bytes(leaf_script_2), control_2),
        }
        actual_leaf_paths = {
            (actual_script_1, actual_control_1),
            (actual_script_2, actual_control_2),
        }
        assert_equal(actual_leaf_paths, expected_leaf_paths)
        assert leaf_spend_txid_1 != leaf_spend_txid_2
        multi_leaf_block = self.generate(node, 1)[0]
        block_txs = node.getblock(multi_leaf_block)["tx"]
        assert leaf_spend_txid_1 in block_txs
        assert leaf_spend_txid_2 in block_txs
        assert_equal(node.gettxout(tree_utxo_1["txid"], tree_utxo_1["vout"]), None)
        assert_equal(node.gettxout(tree_utxo_2["txid"], tree_utxo_2["vout"]), None)

        self.log.info("9/20 multisig leaf descriptor derivation (multi_a)")
        multi_desc = descsum_create(f"mr(multi_a(2,{k1},{k2}))")
        import_multi = desc_watch.importdescriptors([{
            "desc": multi_desc,
            "timestamp": "now",
        }])
        assert_equal(import_multi[0]["success"], True)
        derived_multi = node.deriveaddresses(multi_desc)
        assert_equal(len(derived_multi), 1)
        validate_multi = node.validateaddress(derived_multi[0])
        assert_equal(validate_multi["isvalid"], True)
        assert_equal(validate_multi["witness_version"], 2)

        self.log.info("10/20 2-of-3 multisig PSBT requires two signatures")
        self.test_two_of_three_multisig_psbt(node, miner, multisig_amount)

        self.log.info("11/20 exportpubkeydb returns P2MR pubkeys")
        exported_again = p2mr_wallet.exportpubkeydb()
        assert_equal(exported_again["count"], len(exported_again["pubkeys"]))
        assert_greater_than(exported_again["count"], 0)
        assert all("account" in entry for entry in exported_again["pubkeys"])
        assert all(entry["account"] == 0 for entry in exported_again["pubkeys"])
        assert all("change" in entry for entry in exported_again["pubkeys"])
        assert all("index" in entry for entry in exported_again["pubkeys"])
        external_entries = [entry for entry in exported_again["pubkeys"] if not entry["change"]]
        internal_entries = [entry for entry in exported_again["pubkeys"] if entry["change"]]
        assert_greater_than(len(external_entries), 0)
        assert_greater_than(len(internal_entries), 0)

        self.log.info("12/20 importpubkeydb imports watch-only P2MR descriptors and tracks received funds")
        imported = pubdb_watch.importpubkeydb(exported_again["pubkeys"])
        assert_equal(imported["imported"], exported_again["count"])
        imported_descs = [entry["desc"] for entry in pubdb_watch.listdescriptors()["descriptors"] if entry["desc"].startswith("mr(")]
        assert_equal(len(imported_descs), exported_again["count"])
        imported_addr = node.deriveaddresses(self.explicit_p2mr_descriptor(external_entries[0]["pubkey"]))[0]
        self.assert_p2mr_address(pubdb_watch, imported_addr)
        imported_info = pubdb_watch.getaddressinfo(imported_addr)
        assert_equal(imported_info["ismine"], True)
        assert_equal(imported_info["ischange"], False)
        starting_trusted = pubdb_watch.getbalances()["mine"]["trusted"]

        watch_receive_txid = miner.sendtoaddress(imported_addr, watchonly_amount)
        self.mine(miner, 1)
        self.wait_until(lambda: any(utxo["txid"] == watch_receive_txid for utxo in pubdb_watch.listunspent(addresses=[imported_addr])))
        watch_utxo = next(utxo for utxo in pubdb_watch.listunspent(addresses=[imported_addr]) if utxo["txid"] == watch_receive_txid)
        assert_equal(watch_utxo["amount"], watchonly_amount)
        assert_greater_than(pubdb_watch.gettransaction(watch_receive_txid)["confirmations"], 0)
        assert_equal(pubdb_watch.getbalances()["mine"]["trusted"], starting_trusted + watchonly_amount)

        self.log.info("13/20 importpubkeydb watch-only wallets cannot sign and still cover internal descriptors")
        watch_spend = pubdb_watch.send(
            outputs=[{miner.getnewaddress(): watchonly_amount}],
            fee_rate=200,
            include_watching=True,
            inputs=[{"txid": watch_utxo["txid"], "vout": watch_utxo["vout"]}],
            add_inputs=False,
            subtract_fee_from_outputs=[0],
        )
        assert_equal(watch_spend["complete"], False)
        assert "psbt" in watch_spend
        assert "txid" not in watch_spend
        watch_processed = pubdb_watch.walletprocesspsbt(watch_spend["psbt"], True, "DEFAULT", True)
        assert_equal(watch_processed["complete"], False)
        assert_equal(pubdb_watch.finalizepsbt(watch_processed["psbt"])["complete"], False)

        self.log.info("14/20 a single importpubkeydb call recreates receive and change watch-only descriptors")
        imported_internal = pubdb_watch_internal.importpubkeydb(exported_again["pubkeys"], False, 0)
        assert_equal(imported_internal["imported"], exported_again["count"])
        internal_descs = [entry for entry in pubdb_watch_internal.listdescriptors()["descriptors"] if entry["desc"].startswith("mr(")]
        assert_equal(len(internal_descs), exported_again["count"])
        internal_addr = node.deriveaddresses(self.explicit_p2mr_descriptor(internal_entries[0]["pubkey"]))[0]
        self.assert_p2mr_address(pubdb_watch_internal, internal_addr)
        assert_equal(pubdb_watch_internal.getaddressinfo(internal_addr)["ismine"], True)
        assert_equal(pubdb_watch_internal.getaddressinfo(internal_addr)["ischange"], True)
        external_addr = node.deriveaddresses(self.explicit_p2mr_descriptor(external_entries[0]["pubkey"]))[0]
        assert_equal(pubdb_watch_internal.getaddressinfo(external_addr)["ischange"], False)
        reexported_watch = pubdb_watch_internal.exportpubkeydb()
        assert_equal(reexported_watch["count"], exported_again["count"])
        reexported_by_pubkey = {entry["pubkey"]: entry for entry in reexported_watch["pubkeys"]}
        assert_equal(set(reexported_by_pubkey), {entry["pubkey"] for entry in exported_again["pubkeys"]})
        for entry in exported_again["pubkeys"]:
            assert_equal(reexported_by_pubkey[entry["pubkey"]]["account"], entry["account"])
            assert_equal(reexported_by_pubkey[entry["pubkey"]]["change"], entry["change"])
            assert_equal(reexported_by_pubkey[entry["pubkey"]]["index"], entry["index"])
        legacy_import = pubdb_watch_legacy.importpubkeydb([{"pubkey": external_entries[0]["pubkey"]}], True, 0)
        assert_equal(legacy_import["imported"], 1)
        assert_equal(pubdb_watch_legacy.getaddressinfo(external_addr)["ischange"], True)
        assert_raises_rpc_error(
            -4,
            "importpubkeydb requires a wallet with private keys disabled",
            p2mr_wallet.importpubkeydb,
            exported_again["pubkeys"],
        )

        self.log.info("15/20 descriptor roundtrip via getaddressinfo + deriveaddresses")
        roundtrip_addr = first_p2mr_addr
        roundtrip_desc = p2mr_wallet.getaddressinfo(roundtrip_addr)["desc"]
        assert_equal(node.deriveaddresses(roundtrip_desc), [roundtrip_addr])

        self.log.info("16/20 PSBT funding/signing/finalization with P2MR wallet inputs")
        psbt = p2mr_wallet.walletcreatefundedpsbt(
            [],
            [{miner.getnewaddress(): psbt_amount}],
            0,
            {
                "includeWatching": True,
                "fee_rate": 200,
            },
        )
        decoded_unsigned_psbt = node.decodepsbt(psbt["psbt"])["tx"]
        processed = p2mr_wallet.walletprocesspsbt(psbt["psbt"], True, "DEFAULT", True)
        assert_equal(processed["complete"], True)
        final = node.finalizepsbt(processed["psbt"])
        assert_equal(final["complete"], True)
        final_decoded = node.decoderawtransaction(final["hex"])
        assert_greater_than(final_decoded["weight"], decoded_unsigned_psbt["weight"])
        assert_fee_amount(psbt["fee"], final_decoded["vsize"], self.sat_vb_to_btc_kvb(200))
        self.assert_large_p2mr_spend(final_decoded)
        psbt_txid = node.sendrawtransaction(final["hex"])
        psbt_entry = node.getmempoolentry(psbt_txid)
        assert_equal(psbt_entry["vsize"], final_decoded["vsize"])
        assert_equal(psbt_entry["weight"], final_decoded["weight"])
        self.mine(miner, 1)
        assert_greater_than(p2mr_wallet.gettransaction(psbt_txid)["confirmations"], 0)

        self.log.info("17/20 plain regtest keeps witness v0 as the default address type")
        default_addr = p2mr_wallet.getnewaddress()
        default_info = p2mr_wallet.getaddressinfo(default_addr)
        assert_equal(default_info["witness_version"], 0)
        assert_equal(node.decodescript(default_info["scriptPubKey"])["type"], "witness_v0_keyhash")

        self.log.info("18/20 fee estimation remains available with active P2MR descriptors")
        raw = p2mr_wallet.createrawtransaction([], [{miner.getnewaddress(): raw_fund_amount}])
        funded = p2mr_wallet.fundrawtransaction(raw, {"fee_rate": 200, "change_type": "p2mr"})
        funded_decoded = node.decoderawtransaction(funded["hex"])
        assert_greater_than(funded["fee"], Decimal("0"))
        assert funded["changepos"] >= 0
        assert_equal(funded_decoded["vout"][funded["changepos"]]["scriptPubKey"]["type"], "witness_v2_p2mr")

        self.log.info("Additional script-path P2MR spend and policy coverage")
        self.test_single_leaf_spend()
        self.test_reject_control_bit()
        self.test_reject_commitment_mismatch()
        self.test_multi_leaf_spend()
        self.test_validation_weight_rejection()
        self.test_checkdatasigpqc_empty_signature()
        self.test_checkdatasigaddpqc_empty_threshold()
        self.test_checkdatasigpqc_validation_errors()
        self.test_malformed_max_size_signature_rejection()
        self.test_unknown_leaf_policy_rejection()
        self.test_non_32_byte_pubkey_consensus_rejection()
        self.test_stack_item_policy_rejection()
        self.test_large_stack_policy_acceptance()
        self.test_op_success_policy_rejection()

        self.log.info("19/20 regtest -p2mronly=1 still defaults a fresh descriptor wallet to P2MR")
        self.restart_node(0, self.extra_args[0] + ["-p2mronly=1"])
        node = self.nodes[0]
        node.createwallet(wallet_name="p2mr_default_wallet", descriptors=True)
        p2mr_default_wallet = node.get_wallet_rpc("p2mr_default_wallet")
        p2mr_default_addr = p2mr_default_wallet.getnewaddress()
        p2mr_default_info = p2mr_default_wallet.getaddressinfo(p2mr_default_addr)
        self.assert_p2mr_address(p2mr_default_wallet, p2mr_default_addr)
        assert p2mr_default_info["desc"].startswith("mr(")
        assert "parent_desc" not in p2mr_default_info
        assert_equal(node.decodescript(p2mr_default_info["scriptPubKey"])["type"], "witness_v2_p2mr")
        node.syncwithvalidationinterfacequeue()
        node.unloadwallet("p2mr_default_wallet")

        self.log.info("20/20 born-encrypted P2MR wallets warm a small pool and refill on unlock")
        warm_keypool_size = 16
        node.createwallet(wallet_name="p2mr_default_wallet_enc", passphrase="pass", descriptors=True)
        p2mr_default_wallet_enc = node.get_wallet_rpc("p2mr_default_wallet_enc")
        enc_info = p2mr_default_wallet_enc.getwalletinfo()
        assert_equal(enc_info["keypoolsize"], warm_keypool_size)
        assert_equal(enc_info["keypoolsize_hd_internal"], warm_keypool_size)

        enc_addr = p2mr_default_wallet_enc.getnewaddress(address_type="p2mr")
        enc_change_addr = p2mr_default_wallet_enc.getrawchangeaddress(address_type="p2mr")
        self.assert_p2mr_address(p2mr_default_wallet_enc, enc_addr)
        self.assert_p2mr_address(p2mr_default_wallet_enc, enc_change_addr, is_change=True)

        for _ in range(warm_keypool_size - 1):
            p2mr_default_wallet_enc.getnewaddress(address_type="p2mr")
        assert_raises_rpc_error(
            -12,
            "Keypool ran out, please call keypoolrefill first",
            p2mr_default_wallet_enc.getnewaddress,
            "",
            "p2mr",
        )

        def keypool_is_fully_refilled():
            info = p2mr_default_wallet_enc.getwalletinfo()
            return info["keypoolsize"] == self.keypool_size and info["keypoolsize_hd_internal"] == self.keypool_size

        with WalletUnlock(p2mr_default_wallet_enc, "pass"):
            self.wait_until(keypool_is_fully_refilled, timeout=120)
            refilled_addr = p2mr_default_wallet_enc.getnewaddress(address_type="p2mr")
            self.assert_p2mr_address(p2mr_default_wallet_enc, refilled_addr)
            self.assert_wallet_p2mr_address_index(node, p2mr_default_wallet_enc, refilled_addr, warm_keypool_size)

        node.syncwithvalidationinterfacequeue()
        node.unloadwallet("p2mr_default_wallet_enc")


if __name__ == "__main__":
    FeatureP2MRTest(__file__).main()
