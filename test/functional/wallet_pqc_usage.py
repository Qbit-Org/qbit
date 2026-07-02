#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet PQC usage fields across signing RPC surfaces."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


PQC_SIGNATURE_LIMIT = 1 << 30


class WalletPQCUsageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-walletpqcparallel=1", "-walletpqcsignthreads=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_wallet(self, name, disable_private_keys=False, load_on_startup=False, blank=False):
        self.nodes[0].createwallet(
            wallet_name=name,
            disable_private_keys=disable_private_keys,
            load_on_startup=load_on_startup,
            blank=blank,
        )
        return self.nodes[0].get_wallet_rpc(name)

    def active_p2mr_private_descriptor_requests(self, wallet):
        requests = []
        for entry in wallet.listdescriptors(True)["descriptors"]:
            if not entry["active"] or not entry["desc"].startswith("mr("):
                continue
            request = {
                "desc": entry["desc"],
                "active": True,
                "internal": entry["internal"],
                "timestamp": 0,
            }
            if "range" in entry:
                request["range"] = entry["range"]
            if "next_index" in entry:
                request["next_index"] = entry["next_index"]
            requests.append(request)
        assert_equal(len(requests), 2)
        return requests

    def fund_p2mr_utxo(self, funder, signer, amount=Decimal("5")):
        address = signer.getnewaddress(address_type="p2mr")
        self.wait_pqc_key_validation_ready(funder)
        txid = funder.sendtoaddress(address, amount)
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        for utxo in signer.listunspent(addresses=[address]):
            if utxo["txid"] == txid:
                return address, utxo
        raise AssertionError(f"missing P2MR utxo {txid} for {address}")

    def assert_no_pqc_fields(self, result):
        assert "pqc_key_states" not in result
        assert "pqc_overall_limit_state" not in result
        assert "pqc_signature_count" not in result
        assert "pqc_signature_limit" not in result
        assert "pqc_signatures_remaining" not in result
        assert "pqc_limit_state" not in result
        assert "warnings" not in result

    def assert_pqc_fields(self, result, min_signature_count=1):
        assert "pqc_key_states" in result
        states = result["pqc_key_states"]
        assert_equal(len(states), 1)

        key_state = states[0]
        assert_equal(result["pqc_overall_limit_state"], key_state["pqc_limit_state"])
        assert_equal(result["pqc_signature_count"], key_state["pqc_signature_count"])
        assert_equal(result["pqc_signature_limit"], key_state["pqc_signature_limit"])
        assert_equal(result["pqc_signatures_remaining"], key_state["pqc_signatures_remaining"])
        assert_equal(result["pqc_limit_state"], key_state["pqc_limit_state"])
        assert_equal(result["pqc_signature_limit"], PQC_SIGNATURE_LIMIT)
        assert_equal(result["pqc_signatures_remaining"], PQC_SIGNATURE_LIMIT - result["pqc_signature_count"])
        assert result["pqc_signature_count"] >= min_signature_count
        assert_equal(result["pqc_limit_state"], "normal")
        assert "warnings" not in result

    def assert_pqc_signature_count(self, wallet, address, expected_count):
        info = wallet.getaddressinfo(address)
        self.assert_pqc_fields(info, min_signature_count=expected_count)
        assert_equal(info["pqc_signature_count"], expected_count)
        return info

    def create_raw_spend(self, utxos, destination, fee=None):
        if isinstance(utxos, dict):
            utxos = [utxos]
        if fee is None:
            fee = Decimal("0.00001000") * len(utxos)
        amount = sum((utxo["amount"] for utxo in utxos), start=Decimal("0")) - fee
        return self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in utxos],
            [{destination: amount}],
        )

    def sign_and_broadcast_raw(self, signer, utxos, destination):
        raw = self.create_raw_spend(utxos, destination)
        self.wait_pqc_key_validation_ready(signer)
        signed = signer.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        txid = self.nodes[0].sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        return signed, txid

    def create_p2mr_psbt(self, signer, utxo, destination):
        return signer.walletcreatefundedpsbt(
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
            outputs={destination: Decimal("1")},
            options={
                "add_inputs": False,
                "changeAddress": signer.getrawchangeaddress(),
                "fee_rate": 1,
            },
        )["psbt"]

    def test_getaddressinfo(self, funder):
        signer = self.create_wallet("pqc_info_signer")
        address, _ = self.fund_p2mr_utxo(funder, signer)
        info = signer.getaddressinfo(address)
        self.assert_pqc_fields(info, min_signature_count=0)

        watch = self.create_wallet("pqc_info_watch", disable_private_keys=True)
        watch.importpubkeydb(signer.exportpubkeydb()["pubkeys"], False, 0)
        watch_info = watch.getaddressinfo(address)
        self.assert_no_pqc_fields(watch_info)

    def test_sendtoaddress_and_sendmany(self, funder, receiver):
        default_sender = self.create_wallet("pqc_sendtoaddress_default")
        _, utxo = self.fund_p2mr_utxo(funder, default_sender)
        txid = default_sender.sendtoaddress(receiver.getnewaddress(), Decimal("1"))
        assert_equal(len(txid), 64)

        verbose_sender = self.create_wallet("pqc_sendtoaddress_verbose")
        _, _ = self.fund_p2mr_utxo(funder, verbose_sender)
        verbose_result = verbose_sender.sendtoaddress(address=receiver.getnewaddress(), amount=Decimal("1"), verbose=True)
        self.assert_pqc_fields(verbose_result)

        sendmany_default_sender = self.create_wallet("pqc_sendmany_default")
        _, _ = self.fund_p2mr_utxo(funder, sendmany_default_sender)
        sendmany_txid = sendmany_default_sender.sendmany(dummy="", amounts={receiver.getnewaddress(): Decimal("1")})
        assert_equal(len(sendmany_txid), 64)

        sendmany_sender = self.create_wallet("pqc_sendmany_verbose")
        _, _ = self.fund_p2mr_utxo(funder, sendmany_sender)
        sendmany_result = sendmany_sender.sendmany(dummy="", amounts={receiver.getnewaddress(): Decimal("1")}, verbose=True)
        self.assert_pqc_fields(sendmany_result)

    def test_send_and_sendall(self, funder, receiver):
        send_sender = self.create_wallet("pqc_send")
        _, _ = self.fund_p2mr_utxo(funder, send_sender)
        send_result = send_sender.send(outputs={receiver.getnewaddress(): Decimal("1")})
        self.assert_pqc_fields(send_result)

        sendall_sender = self.create_wallet("pqc_sendall")
        _, _ = self.fund_p2mr_utxo(funder, sendall_sender)
        sendall_result = sendall_sender.sendall(recipients=[receiver.getnewaddress()])
        self.assert_pqc_fields(sendall_result)

    def test_rawtx_and_psbt(self, funder, receiver):
        raw_sender = self.create_wallet("pqc_signraw")
        _, raw_utxo = self.fund_p2mr_utxo(funder, raw_sender)
        raw = self.create_raw_spend(raw_utxo, receiver.getnewaddress())
        signed = raw_sender.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        self.assert_pqc_fields(signed)

        signed_again = raw_sender.signrawtransactionwithwallet(signed["hex"])
        assert_equal(signed_again["complete"], True)
        if "pqc_key_states" not in signed_again:
            assert_equal(signed_again["hex"], signed["hex"])
            self.assert_no_pqc_fields(signed_again)
        else:
            # A repeated signing RPC may either leave the PSBT/rawtx untouched or
            # still report local PQC usage for the wallet key that was eligible
            # to sign. The usage report is therefore the stable contract here,
            # not whether the serialized transaction bytes changed.
            self.assert_pqc_fields(signed_again, min_signature_count=signed["pqc_signature_count"])

        psbt_sender = self.create_wallet("pqc_walletprocesspsbt")
        _, psbt_utxo = self.fund_p2mr_utxo(funder, psbt_sender)
        psbt = self.create_p2mr_psbt(psbt_sender, psbt_utxo, receiver.getnewaddress())

        no_sign = psbt_sender.walletprocesspsbt(psbt=psbt, sign=False, finalize=False)
        assert_equal(no_sign["complete"], False)
        self.assert_no_pqc_fields(no_sign)

        signed_psbt = psbt_sender.walletprocesspsbt(psbt=psbt, sign=True, finalize=False)
        assert_equal(signed_psbt["complete"], False)
        self.assert_pqc_fields(signed_psbt)

    def test_signdatapqchash(self):
        signer = self.create_wallet("pqc_hash_signer", load_on_startup=True)
        address = signer.getnewaddress(address_type="p2mr")
        self.wait_pqc_key_validation_ready(signer)
        self.assert_pqc_signature_count(signer, address, 0)

        proof = signer.signdatapqchash(address, "55" * 32)
        assert_equal(proof["address"], address)
        self.assert_pqc_fields(proof, min_signature_count=1)
        assert_equal(proof["pqc_signature_count"], 1)
        assert_equal(proof["pqc_key_states"][0]["pubkey"], proof["pubkey"])
        self.assert_pqc_signature_count(signer, address, 1)

        hidden_usage = signer.signdatapqchash(address, "56" * 32, {"include_pqc_usage": False})
        self.assert_no_pqc_fields(hidden_usage)
        self.assert_pqc_signature_count(signer, address, 2)

        assert_raises_rpc_error(
            -4,
            "No supported single-key P2MR pubkey leaf was found for this address",
            signer.signdatapqchash,
            address,
            "57" * 32,
            {"pubkey": "00" * 32},
        )
        self.assert_pqc_signature_count(signer, address, 2)

        watch = self.create_wallet("pqc_hash_watch", disable_private_keys=True)
        watch.importpubkeydb(signer.exportpubkeydb()["pubkeys"], False, 0)
        assert_raises_rpc_error(
            -4,
            "Private key is not available for the selected P2MR pubkey leaf",
            watch.signdatapqchash,
            address,
            "58" * 32,
            {
                "pubkey": proof["pubkey"],
                "leaf_script": proof["leaf_script"],
                "control_block": proof["control_block"],
            },
        )
        self.assert_pqc_signature_count(signer, address, 2)

        passphrase = "pass"
        self.nodes[0].createwallet(wallet_name="pqc_hash_locked", passphrase=passphrase)
        locked = self.nodes[0].get_wallet_rpc("pqc_hash_locked")
        locked.walletpassphrase(passphrase, 60)
        locked_address = locked.getnewaddress(address_type="p2mr")
        self.wait_pqc_key_validation_ready(locked)
        locked.walletlock()
        assert_raises_rpc_error(
            -13,
            "Please enter the wallet passphrase",
            locked.signdatapqchash,
            locked_address,
            "59" * 32,
        )
        locked.walletpassphrase(passphrase, 60)
        locked_proof = locked.signdatapqchash(locked_address, "5a" * 32)
        self.assert_pqc_fields(locked_proof, min_signature_count=1)
        self.assert_pqc_signature_count(locked, locked_address, 1)

    def test_signdatapqchash_plaintext_validation_block(self):
        source_name = "pqc_hash_validation_source"
        source = self.create_wallet(source_name)
        source.keypoolrefill(200)
        address = source.getnewaddress(address_type="p2mr")
        backup_file = self.nodes[0].datadir_path / "pqc_hash_validation_source.bak"
        source.backupwallet(backup_file)
        self.nodes[0].unloadwallet(source_name)

        restored_name = "pqc_hash_validation_restored"
        self.nodes[0].restorewallet(restored_name, backup_file)
        restored = self.nodes[0].get_wallet_rpc(restored_name)
        self.wait_until(
            lambda: restored.getwalletinfo()["pqc_key_validation"]["signing_blocked"],
            timeout=10,
        )
        assert_raises_rpc_error(
            -4,
            "plaintext PQC wallet key validation",
            restored.signdatapqchash,
            address,
            "5b" * 32,
        )
        restored.unloadwallet()

    def test_counter_lifecycle(self, funder, receiver):
        wallet_name = "pqc_counter_lifecycle"
        signer = self.create_wallet(wallet_name, load_on_startup=True)
        tracked_address = signer.getnewaddress(address_type="p2mr")

        for _ in range(3):
            funder.sendtoaddress(tracked_address, Decimal("2"))
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)

        tracked_utxos = signer.listunspent(addresses=[tracked_address])
        assert_equal(len(tracked_utxos), 3)

        # Two inputs from the same P2MR address exercise the supported duplicate-key merge path:
        # both per-input providers carry the same local PQC key, and the merged signer must keep
        # advancing the single authoritative counter.
        merged_result, _ = self.sign_and_broadcast_raw(signer, tracked_utxos[:2], receiver.getnewaddress())
        self.assert_pqc_fields(merged_result, min_signature_count=2)
        assert_equal(merged_result["pqc_signature_count"], 2)
        self.assert_pqc_signature_count(signer, tracked_address, 2)

        backup_file = self.nodes[0].datadir_path / "pqc_counter_snapshot.bak"
        signer.backupwallet(backup_file)

        self.nodes[0].unloadwallet(wallet_name)
        load_result = self.nodes[0].loadwallet(wallet_name)
        assert_equal(load_result["name"], wallet_name)
        signer = self.nodes[0].get_wallet_rpc(wallet_name)
        self.assert_pqc_signature_count(signer, tracked_address, 2)
        self.wait_pqc_key_validation_ready(signer)

        remaining_utxos = signer.listunspent(addresses=[tracked_address])
        assert_equal(len(remaining_utxos), 1)
        post_backup_result, post_backup_txid = self.sign_and_broadcast_raw(signer, remaining_utxos, receiver.getnewaddress())
        self.assert_pqc_fields(post_backup_result, min_signature_count=3)
        assert_equal(post_backup_result["pqc_signature_count"], 3)
        self.assert_pqc_signature_count(signer, tracked_address, 3)

        self.restart_node(0)
        assert wallet_name in self.nodes[0].listwallets()
        signer = self.nodes[0].get_wallet_rpc(wallet_name)
        self.assert_pqc_signature_count(signer, tracked_address, 3)

        # restorewallet reloads the wallet database snapshot from backup time. The rescan can recover
        # post-backup transaction history, but wallet-owned PQC counters only survive from what that
        # backup had already persisted.
        restored_name = "pqc_counter_snapshot"
        restore_result = self.nodes[0].restorewallet(restored_name, backup_file)
        assert_equal(restore_result["name"], restored_name)
        restored = self.nodes[0].get_wallet_rpc(restored_name)
        assert restored.gettransaction(post_backup_txid)["confirmations"] > 0
        self.assert_pqc_signature_count(restored, tracked_address, 2)

    def test_descriptor_recovery_counter_reset(self, funder, receiver):
        signer = self.create_wallet("pqc_descriptor_source")
        tracked_address = signer.getnewaddress(address_type="p2mr")

        for _ in range(2):
            funder.sendtoaddress(tracked_address, Decimal("2"))
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)

        tracked_utxos = signer.listunspent(addresses=[tracked_address])
        assert_equal(len(tracked_utxos), 2)

        source_result, _ = self.sign_and_broadcast_raw(signer, tracked_utxos[0], receiver.getnewaddress())
        self.assert_pqc_fields(source_result, min_signature_count=1)
        assert_equal(source_result["pqc_signature_count"], 1)
        self.assert_pqc_signature_count(signer, tracked_address, 1)

        recovered = self.create_wallet("pqc_descriptor_recovered", blank=True)
        import_result = recovered.importdescriptors(self.active_p2mr_private_descriptor_requests(signer))
        assert_equal(len(import_result), 2)
        assert all(item["success"] for item in import_result)

        recovered_info = self.assert_pqc_signature_count(recovered, tracked_address, 0)
        assert_equal(recovered_info["ismine"], True)

        remaining_utxos = recovered.listunspent(addresses=[tracked_address])
        assert_equal(len(remaining_utxos), 1)

        # Descriptor recovery recreates local signing authority for the same PQC
        # key, but it does not inherit the source wallet's persisted PQC counter.
        recovered_result, _ = self.sign_and_broadcast_raw(recovered, remaining_utxos, receiver.getnewaddress())
        self.assert_pqc_fields(recovered_result, min_signature_count=1)
        assert_equal(recovered_result["pqc_signature_count"], 1)
        self.assert_pqc_signature_count(recovered, tracked_address, 1)

        # The original signer did not participate in the recovered-wallet spend,
        # so its local persisted counter remains at the source wallet's value.
        self.assert_pqc_signature_count(signer, tracked_address, 1)

    def run_test(self):
        funder = self.create_wallet("pqc_funder", load_on_startup=True)
        receiver = self.create_wallet("pqc_receiver", load_on_startup=True)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 5, funder.getnewaddress(), sync_fun=self.no_op)

        self.test_getaddressinfo(funder)
        self.test_sendtoaddress_and_sendmany(funder, receiver)
        self.test_send_and_sendall(funder, receiver)
        self.test_rawtx_and_psbt(funder, receiver)
        self.test_signdatapqchash()
        self.test_signdatapqchash_plaintext_validation_block()
        self.test_counter_lifecycle(funder, receiver)
        funder = self.nodes[0].get_wallet_rpc("pqc_funder")
        receiver = self.nodes[0].get_wallet_rpc("pqc_receiver")
        self.wait_pqc_key_validation_ready(funder)
        self.test_descriptor_recovery_counter_reset(funder, receiver)


if __name__ == "__main__":
    WalletPQCUsageTest(__file__).main()
