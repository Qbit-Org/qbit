#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise P2MR PSBT signing and finalization workflows."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.psbt import PSBT, PSBT_IN_P2MR_LEAF_SCRIPT, PSBT_IN_P2MR_SCRIPT_SIG
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

P2MR_DEFAULT_SIG_BYTES = 3680
P2MR_MAX_SIG_BYTES = P2MR_DEFAULT_SIG_BYTES + 1
P2MR_SINGLE_KEY_SPEND_SIZE = 3763


class WalletP2MRPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_wallet(self, name, disable_private_keys=False):
        self.nodes[0].createwallet(wallet_name=name, disable_private_keys=disable_private_keys)
        return self.nodes[0].get_wallet_rpc(name)

    def fund_p2mr_utxo(self, wallet, amount):
        p2mr_address = wallet.getnewaddress(address_type="p2mr")
        txid = wallet.sendtoaddress(p2mr_address, amount)
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        for utxo in wallet.listunspent(addresses=[p2mr_address]):
            if utxo["txid"] == txid:
                return utxo
        raise AssertionError(f"Missing funded P2MR utxo for {txid}")

    def create_p2mr_psbt(self, wallet, utxo, destination):
        return wallet.walletcreatefundedpsbt(
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
            outputs={destination: Decimal("1")},
            options={
                "add_inputs": False,
                "changeAddress": wallet.getrawchangeaddress(),
                "fee_rate": 1,
            },
        )["psbt"]

    def find_utxo(self, wallet, txid, address=None):
        utxos = wallet.listunspent(addresses=[address]) if address else wallet.listunspent()
        for utxo in utxos:
            if utxo["txid"] == txid:
                return utxo
        raise AssertionError(f"Missing funded utxo for {txid}")

    def assert_broadcasts(self, tx_hex):
        txid = self.nodes[0].sendrawtransaction(tx_hex)
        mined_block = self.generate(self.nodes[0], 1, sync_fun=self.no_op)[0]
        assert txid in self.nodes[0].getblock(mined_block)["tx"]

    def assert_p2mr_input_state(self, psbt_b64, *, num_leaf_scripts, num_script_path_sigs):
        psbt = PSBT.from_base64(psbt_b64)
        leaf_scripts = 0
        script_path_sigs = 0
        for key in psbt.i[0].map:
            if isinstance(key, bytes) and key:
                if key[0] == PSBT_IN_P2MR_LEAF_SCRIPT:
                    leaf_scripts += 1
                elif key[0] == PSBT_IN_P2MR_SCRIPT_SIG:
                    script_path_sigs += 1
        assert_equal(leaf_scripts, num_leaf_scripts)
        assert_equal(script_path_sigs, num_script_path_sigs)

    def get_p2mr_script_path_sigs(self, psbt_b64):
        psbt = PSBT.from_base64(psbt_b64)
        return [
            value for key, value in psbt.i[0].map.items()
            if isinstance(key, bytes) and key and key[0] == PSBT_IN_P2MR_SCRIPT_SIG
        ]

    def corrupt_p2mr_script_path_sig(self, psbt_b64):
        psbt = PSBT.from_base64(psbt_b64)
        sig_keys = [
            key for key in psbt.i[0].map
            if isinstance(key, bytes)
            and key
            and key[0] == PSBT_IN_P2MR_SCRIPT_SIG
        ]
        assert_equal(len(sig_keys), 1)
        sig = bytearray(psbt.i[0].map[sig_keys[0]])
        assert len(sig) >= 1
        sig[0] ^= 1
        psbt.i[0].map[sig_keys[0]] = bytes(sig)
        return psbt.to_base64()

    def add_invalid_p2mr_control_block(self, psbt_b64):
        psbt = PSBT.from_base64(psbt_b64)
        leaf_keys = [
            key for key in psbt.i[0].map
            if isinstance(key, bytes)
            and len(key) > 1
            and key[0] == PSBT_IN_P2MR_LEAF_SCRIPT
        ]
        assert_equal(len(leaf_keys), 1)
        psbt.i[0].map[bytes([PSBT_IN_P2MR_LEAF_SCRIPT, 0xC0])] = psbt.i[0].map[leaf_keys[0]]
        return psbt.to_base64()

    def remove_p2mr_leaf_scripts(self, psbt_b64):
        psbt = PSBT.from_base64(psbt_b64)
        leaf_keys = [
            key for key in psbt.i[0].map
            if isinstance(key, bytes)
            and len(key) > 1
            and key[0] == PSBT_IN_P2MR_LEAF_SCRIPT
        ]
        assert_equal(len(leaf_keys), 1)
        for key in leaf_keys:
            del psbt.i[0].map[key]
        return psbt.to_base64()

    def assert_missing_only_p2mr_signature(self, analyzed_psbt, *, next_role):
        assert_equal(analyzed_psbt["next"], next_role)
        input_state = analyzed_psbt["inputs"][0]
        assert_equal(input_state["has_utxo"], True)
        assert_equal(input_state["is_final"], False)
        assert_equal(input_state["next"], next_role)
        missing = input_state["missing"]
        assert_equal(sorted(missing.keys()), ["p2mr_signatures"])
        assert_equal(len(missing["p2mr_signatures"]), 1)

    def assert_missing_p2mr_spend_data(self, analyzed_psbt):
        assert_equal(analyzed_psbt["next"], "updater")
        input_state = analyzed_psbt["inputs"][0]
        assert_equal(input_state["has_utxo"], True)
        assert_equal(input_state["is_final"], False)
        assert_equal(input_state["next"], "updater")
        assert "missing" not in input_state

    def run_test(self):
        sender = self.create_wallet("sender")
        receiver = self.create_wallet("receiver")
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 5, sender.getnewaddress(), sync_fun=self.no_op)

        self.log.info("Sign a P2MR PSBT without finalizing, then finalize separately")
        partial_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        partial_psbt = self.create_p2mr_psbt(sender, partial_utxo, receiver.getnewaddress())
        self.assert_p2mr_input_state(partial_psbt, num_leaf_scripts=1, num_script_path_sigs=0)
        decoded_unsigned = self.nodes[0].decodepsbt(partial_psbt)["inputs"][0]
        assert "p2mr_scripts" in decoded_unsigned
        assert "p2mr_script_path_sigs" not in decoded_unsigned
        assert "final_scriptwitness" not in decoded_unsigned
        analyzed_unsigned = self.nodes[0].analyzepsbt(partial_psbt)
        self.assert_missing_only_p2mr_signature(analyzed_unsigned, next_role="signer")

        self.log.info("Estimate P2MR PSBT size using the max signature item size")
        nondefault_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        nondefault_psbt = self.create_p2mr_psbt(sender, nondefault_utxo, receiver.getnewaddress())
        estimated_vsize = self.nodes[0].analyzepsbt(nondefault_psbt)["estimated_vsize"]
        nondefault_signed = sender.walletprocesspsbt(
            psbt=nondefault_psbt,
            sign=True,
            sighashtype="ALL",
            finalize=True,
        )
        assert_equal(nondefault_signed["complete"], True)
        decoded_nondefault = self.nodes[0].decoderawtransaction(nondefault_signed["hex"])
        assert_equal(decoded_nondefault["vsize"], estimated_vsize)
        assert_equal(len(bytes.fromhex(decoded_nondefault["vin"][0]["txinwitness"][0])), P2MR_MAX_SIG_BYTES)

        self.log.info("Clamp undersized explicit P2MR input_weights to the P2MR spend size")
        weighted_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        weighted_outputs = {receiver.getnewaddress(): Decimal("1")}
        weighted_options = {
            "add_inputs": False,
            "changeAddress": sender.getrawchangeaddress(),
            "fee_rate": 1,
        }
        low_weight_psbt = sender.walletcreatefundedpsbt(
            inputs=[{"txid": weighted_utxo["txid"], "vout": weighted_utxo["vout"], "weight": 42}],
            outputs=weighted_outputs,
            options=weighted_options,
        )
        p2mr_weight_psbt = sender.walletcreatefundedpsbt(
            inputs=[{"txid": weighted_utxo["txid"], "vout": weighted_utxo["vout"], "weight": P2MR_SINGLE_KEY_SPEND_SIZE}],
            outputs=weighted_outputs,
            options=weighted_options,
        )
        high_weight_psbt = sender.walletcreatefundedpsbt(
            inputs=[{"txid": weighted_utxo["txid"], "vout": weighted_utxo["vout"], "weight": P2MR_SINGLE_KEY_SPEND_SIZE + 1000}],
            outputs=weighted_outputs,
            options=weighted_options,
        )
        assert_equal(low_weight_psbt["fee"], p2mr_weight_psbt["fee"])
        assert_greater_than(high_weight_psbt["fee"], p2mr_weight_psbt["fee"])

        unsigned_finalized = self.nodes[0].finalizepsbt(partial_psbt)
        assert_equal(unsigned_finalized["complete"], False)
        assert "hex" not in unsigned_finalized
        self.assert_p2mr_input_state(unsigned_finalized["psbt"], num_leaf_scripts=1, num_script_path_sigs=0)
        assert "final_scriptwitness" not in self.nodes[0].decodepsbt(unsigned_finalized["psbt"])["inputs"][0]
        self.assert_missing_only_p2mr_signature(self.nodes[0].analyzepsbt(unsigned_finalized["psbt"]), next_role="signer")

        updated = sender.walletprocesspsbt(psbt=partial_psbt, sign=False, finalize=False)
        assert_equal(updated["complete"], False)
        self.assert_p2mr_input_state(updated["psbt"], num_leaf_scripts=1, num_script_path_sigs=0)

        processed = sender.walletprocesspsbt(psbt=partial_psbt, sign=True, finalize=False)
        assert_equal(processed["complete"], False)
        self.assert_p2mr_input_state(processed["psbt"], num_leaf_scripts=1, num_script_path_sigs=1)
        script_path_sigs = self.get_p2mr_script_path_sigs(processed["psbt"])
        assert_equal(len(script_path_sigs), 1)
        assert_equal(len(script_path_sigs[0]), P2MR_DEFAULT_SIG_BYTES)
        decoded_partial = self.nodes[0].decodepsbt(processed["psbt"])["inputs"][0]
        assert "final_scriptwitness" not in decoded_partial
        analyzed_partial = self.nodes[0].analyzepsbt(processed["psbt"])
        assert_equal(analyzed_partial["inputs"][0]["next"], "finalizer")

        self.log.info("Require a PSBT updater before a P2MR signer when leaf spend data is missing")
        missing_spend_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        missing_spend_psbt = self.remove_p2mr_leaf_scripts(
            self.create_p2mr_psbt(sender, missing_spend_utxo, receiver.getnewaddress())
        )
        self.assert_p2mr_input_state(missing_spend_psbt, num_leaf_scripts=0, num_script_path_sigs=0)
        decoded_missing = self.nodes[0].decodepsbt(missing_spend_psbt)["inputs"][0]
        assert "p2mr_scripts" not in decoded_missing
        assert "p2mr_script_path_sigs" not in decoded_missing
        assert "final_scriptwitness" not in decoded_missing
        self.assert_missing_p2mr_spend_data(self.nodes[0].analyzepsbt(missing_spend_psbt))
        missing_finalized = self.nodes[0].finalizepsbt(missing_spend_psbt)
        assert_equal(missing_finalized["complete"], False)
        assert "hex" not in missing_finalized
        self.assert_missing_p2mr_spend_data(self.nodes[0].analyzepsbt(missing_finalized["psbt"]))

        missing_updated = sender.walletprocesspsbt(psbt=missing_spend_psbt, sign=False, finalize=False)
        assert_equal(missing_updated["complete"], False)
        self.assert_p2mr_input_state(missing_updated["psbt"], num_leaf_scripts=1, num_script_path_sigs=0)
        decoded_missing_updated = self.nodes[0].decodepsbt(missing_updated["psbt"])["inputs"][0]
        assert "p2mr_scripts" in decoded_missing_updated
        assert "p2mr_script_path_sigs" not in decoded_missing_updated
        assert "final_scriptwitness" not in decoded_missing_updated
        self.assert_missing_only_p2mr_signature(self.nodes[0].analyzepsbt(missing_updated["psbt"]), next_role="signer")

        self.log.info("Reject a conflicting sighash on a partially signed P2MR PSBT")
        assert_raises_rpc_error(
            -22,
            "Specified sighash value does not match value stored in PSBT",
            sender.walletprocesspsbt,
            processed["psbt"],
            True,
            "SINGLE",
        )

        finalized = self.nodes[0].finalizepsbt(processed["psbt"])
        assert_equal(finalized["complete"], True)
        self.assert_broadcasts(finalized["hex"])

        self.log.info("Reject invalid P2MR control blocks when finalizing")
        poisoned_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        poisoned_psbt = self.create_p2mr_psbt(sender, poisoned_utxo, receiver.getnewaddress())
        poisoned_signed = sender.walletprocesspsbt(psbt=poisoned_psbt, sign=True, finalize=False)
        assert_raises_rpc_error(
            -22,
            "P2MR control byte bit 0 must be set",
            self.nodes[0].finalizepsbt,
            self.add_invalid_p2mr_control_block(poisoned_signed["psbt"]),
        )

        self.log.info("Reject invalid cached P2MR signatures without replacing them")
        invalid_cached_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        invalid_cached_psbt = self.create_p2mr_psbt(sender, invalid_cached_utxo, receiver.getnewaddress())
        valid_cached = sender.walletprocesspsbt(psbt=invalid_cached_psbt, sign=True, finalize=False)
        assert_equal(valid_cached["complete"], False)
        tracked_address = invalid_cached_utxo["address"]
        count_after_initial_sign = sender.getaddressinfo(tracked_address)["pqc_signature_count"]
        assert_equal(count_after_initial_sign, 1)
        poisoned_cached_psbt = self.corrupt_p2mr_script_path_sig(valid_cached["psbt"])
        analyzed_poisoned = self.nodes[0].analyzepsbt(poisoned_cached_psbt)
        assert "Invalid cached P2MR script signature in PSBT input" in analyzed_poisoned["error"]
        assert_raises_rpc_error(
            -25,
            "Invalid cached P2MR script signature in PSBT input",
            sender.walletprocesspsbt,
            poisoned_cached_psbt,
            True,
            "DEFAULT",
            True,
            False,
        )
        assert_equal(sender.getaddressinfo(tracked_address)["pqc_signature_count"], count_after_initial_sign)

        self.log.info("Finalize a P2MR PSBT directly through walletprocesspsbt")
        direct_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        direct_psbt = self.create_p2mr_psbt(sender, direct_utxo, receiver.getnewaddress())

        direct = sender.walletprocesspsbt(psbt=direct_psbt, sign=True, finalize=True)
        assert_equal(direct["complete"], True)
        self.assert_broadcasts(direct["hex"])

        self.log.info("Transport a P2MR PSBT across wallets and preserve qbit fields through combinepsbt")
        coordinator = self.create_wallet("coordinator", disable_private_keys=True)
        shared_utxo = self.fund_p2mr_utxo(sender, Decimal("5"))
        imported = coordinator.importpubkeydb(sender.exportpubkeydb()["pubkeys"], False, 0)
        assert_equal(imported["imported"] > 0, True)
        assert any(
            utxo["txid"] == shared_utxo["txid"] and utxo["vout"] == shared_utxo["vout"]
            for utxo in coordinator.listunspent()
        )

        coordinator_psbt = coordinator.walletcreatefundedpsbt(
            inputs=[{"txid": shared_utxo["txid"], "vout": shared_utxo["vout"]}],
            outputs={receiver.getnewaddress(): Decimal("1")},
            options={
                "add_inputs": False,
                "changeAddress": sender.getrawchangeaddress(),
                "fee_rate": 1,
            },
        )["psbt"]
        self.assert_p2mr_input_state(coordinator_psbt, num_leaf_scripts=1, num_script_path_sigs=0)

        signer_psbt = sender.walletprocesspsbt(psbt=coordinator_psbt, sign=True, finalize=False)
        assert_equal(signer_psbt["complete"], False)
        self.assert_p2mr_input_state(signer_psbt["psbt"], num_leaf_scripts=1, num_script_path_sigs=1)

        combined = coordinator.combinepsbt([coordinator_psbt, signer_psbt["psbt"]])
        self.assert_p2mr_input_state(combined, num_leaf_scripts=1, num_script_path_sigs=1)
        finalized_combined = self.nodes[0].finalizepsbt(combined)
        assert_equal(finalized_combined["complete"], True)
        self.assert_broadcasts(finalized_combined["hex"])


if __name__ == "__main__":
    WalletP2MRPSBTTest(__file__).main()
