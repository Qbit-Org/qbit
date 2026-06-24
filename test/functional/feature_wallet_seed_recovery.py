#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise descriptor-based P2MR signer recovery with sparse receive/change usage."""

import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class FeatureWalletSeedRecoveryTest(BitcoinTestFramework):
    FULL_RECOVERY_KEYPOOL = 200
    STRICT_RECOVERY_KEYPOOL = 1

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.rpc_timeout = 600
        self.extra_args = [
            ["-dnsseed=0", "-fixedseeds=0", f"-keypool={self.FULL_RECOVERY_KEYPOOL}", "-walletpqcparallel=1", "-walletpqcsignthreads=0"],
            ["-dnsseed=0", "-fixedseeds=0", f"-keypool={self.FULL_RECOVERY_KEYPOOL}", "-walletpqcparallel=1", "-walletpqcsignthreads=0"],
            ["-dnsseed=0", "-fixedseeds=0", f"-keypool={self.STRICT_RECOVERY_KEYPOOL}", "-walletpqcparallel=1", "-walletpqcsignthreads=0"],
            ["-dnsseed=0", "-fixedseeds=0", "-walletpqcparallel=1", "-walletpqcsignthreads=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)
        self.sync_blocks(self.nodes)

    def mine(self, blocks=1):
        return self.generatetoaddress(self.nodes[0], blocks, self.miner.getnewaddress())

    def assert_p2mr_address(self, wallet, address, *, is_change=None):
        info = wallet.getaddressinfo(address)
        assert_equal(info["isscript"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["witness_version"], 2)
        assert_equal(len(info["witness_program"]), 64)
        assert_equal(wallet.decodescript(info["scriptPubKey"])["type"], "witness_v2_p2mr")
        if is_change is not None:
            assert_equal(info["ischange"], is_change)
        return info

    def pqc_ranged_desc(self, master_xprv, *, internal):
        change = 1 if internal else 0
        return descsum_create(f"mr(pk(pqc({master_xprv}/87h/1h/0h/{change}/*)))")

    def collect_sparse_addresses(self, wallet, getter_name, wanted_indexes):
        addresses = {}
        getter = getattr(wallet, getter_name)
        for index in range(max(wanted_indexes) + 1):
            address = getter(address_type="p2mr")
            if index in wanted_indexes:
                addresses[index] = address
        assert_equal(set(addresses), set(wanted_indexes))
        return addresses

    def get_single_utxo(self, wallet, address):
        utxos = wallet.listunspent(addresses=[address])
        assert_equal(len(utxos), 1)
        return utxos[0]

    def unspent_map(self, wallet, addresses):
        return {
            address: sorted(
                (utxo["txid"], utxo["vout"], utxo["amount"])
                for utxo in wallet.listunspent(addresses=[address])
            )
            for address in addresses
        }

    def assert_history_contains(self, entries, txid, address):
        assert any(
            entry["txid"] == txid and entry.get("address") == address and entry["category"] == "receive"
            for entry in entries
        )

    def import_recovery_descriptors(
        self,
        wallet,
        master_xprv,
        *,
        external_range_end,
        internal_range_end,
        external_next_index=0,
        internal_next_index=0,
    ):
        requests = [
            {
                "desc": self.pqc_ranged_desc(master_xprv, internal=False),
                "active": True,
                "range": [0, external_range_end],
                "next_index": external_next_index,
                "timestamp": 0,
                "internal": False,
            },
            {
                "desc": self.pqc_ranged_desc(master_xprv, internal=True),
                "active": True,
                "range": [0, internal_range_end],
                "next_index": internal_next_index,
                "timestamp": 0,
                "internal": True,
            },
        ]
        result = wallet.importdescriptors(requests)
        assert_equal(len(result), len(requests))
        assert all(item["success"] for item in result)
        return result

    def ensure_p2mr_descriptor(self, wallet):
        try:
            created_descs = wallet.createwalletdescriptor("p2mr")["descs"]
        except JSONRPCException as e:
            assert "Descriptor already exists" in e.error["message"]
            created_descs = [
                entry["desc"] for entry in wallet.listdescriptors()["descriptors"]
                if entry["active"] and entry["desc"].startswith("mr(")
            ]
        assert_greater_than(len(created_descs), 0)
        return created_descs

    def log_recovery_duration(self, label, start_time, **fields):
        elapsed = time.monotonic() - start_time
        details = ", ".join(f"{key}={value}" for key, value in fields.items())
        self.log.info(f"{label} completed in {elapsed:.2f}s ({details})")

    def collect_warnings(self, import_result):
        return [warning for item in import_result for warning in item.get("warnings", [])]

    def expected_effective_range_end(self, requested_range_end, *, next_index, keypool_size):
        return max(requested_range_end + 1, next_index + keypool_size) - 1

    def expanded_range_warning(
        self,
        *,
        internal,
        requested_range_start=0,
        requested_range_end,
        effective_range_end,
    ):
        side = "internal" if internal else "external"
        return (
            f"Requested active {side} descriptor range [{requested_range_start},{requested_range_end}] "
            f"was expanded to effective range [{requested_range_start},{effective_range_end}] "
            "to satisfy wallet keypool lookahead"
        )

    def active_descriptor(self, wallet, *, internal):
        matches = [
            entry
            for entry in wallet.listdescriptors()["descriptors"]
            if entry["active"] and entry["internal"] == internal and entry["desc"].startswith("mr(")
        ]
        assert_equal(len(matches), 1)
        return matches[0]

    def assert_active_descriptor_state(
        self,
        wallet,
        *,
        internal,
        expected_range_start=0,
        expected_range_end,
        expected_next_index,
    ):
        descriptor = self.active_descriptor(wallet, internal=internal)
        assert_equal(descriptor["range"], [expected_range_start, expected_range_end])
        assert_equal(descriptor["next_index"], expected_next_index)
        return descriptor

    def assert_missing_only_p2mr_signature(self, analyzed_psbt, *, next_role):
        assert_equal(analyzed_psbt["next"], next_role)
        input_state = analyzed_psbt["inputs"][0]
        assert_equal(input_state["has_utxo"], True)
        assert_equal(input_state["is_final"], False)
        assert_equal(input_state["next"], next_role)
        missing = input_state["missing"]
        assert_equal(sorted(missing.keys()), ["p2mr_signatures"])
        assert_equal(len(missing["p2mr_signatures"]), 1)

    def run_test(self):
        source_node = self.nodes[0]
        recovered_node = self.nodes[1]
        strict_node = self.nodes[2]
        watch_node = self.nodes[3]
        self.miner = source_node.get_wallet_rpc(self.default_wallet_name)

        external_targets = [0, 31, 95]
        internal_targets = [0, 17, 63]
        spend_source_amounts = [
            Decimal("2.00000000"),
            Decimal("2.10000000"),
            Decimal("2.20000000"),
        ]
        receive_amounts = {
            0: Decimal("1.00000000"),
            31: Decimal("1.10000000"),
            95: Decimal("1.20000000"),
        }
        spend_amounts = {
            0: Decimal("0.50000000"),
            17: Decimal("0.60000000"),
            63: Decimal("0.70000000"),
        }
        required_miner_balance = sum(receive_amounts.values()) + sum(spend_source_amounts) + Decimal("1.00000000")

        self.log.info("Build a mature chain and ensure the funding wallet has enough spendable balance")
        self.mine(COINBASE_MATURITY + 1)
        while self.miner.getbalance() < required_miner_balance:
            self.mine(1)

        self.log.info("Create the source signer wallet")
        source_node.createwallet("source_wallet")
        source_wallet = source_node.get_wallet_rpc("source_wallet")
        self.ensure_p2mr_descriptor(source_wallet)
        source_master_xprv = source_wallet.gethdkeys(private=True)[0]["xprv"]
        history_start = source_node.getbestblockhash()

        self.log.info("Advance the source wallet to sparse external and internal P2MR indexes")
        sparse_receive_addrs = self.collect_sparse_addresses(source_wallet, "getnewaddress", external_targets)
        sparse_change_addrs = self.collect_sparse_addresses(source_wallet, "getrawchangeaddress", internal_targets)
        for index in external_targets:
            self.assert_p2mr_address(source_wallet, sparse_receive_addrs[index], is_change=False)
        for index in internal_targets:
            self.assert_p2mr_address(source_wallet, sparse_change_addrs[index], is_change=True)

        self.log.info("Fund sparse receive addresses and separate spend-source UTXOs")
        receive_txids = {}
        for index in external_targets:
            receive_txids[index] = self.miner.sendtoaddress(sparse_receive_addrs[index], receive_amounts[index])

        spend_source_addrs = []
        for amount in spend_source_amounts:
            spend_source_addr = source_wallet.getnewaddress(address_type="p2mr")
            spend_source_addrs.append(spend_source_addr)
            self.miner.sendtoaddress(spend_source_addr, amount)

        self.mine(1)

        self.log.info("Use dedicated inputs to force change onto sparse internal addresses")
        spend_source_utxos = [
            self.get_single_utxo(source_wallet, address) for address in spend_source_addrs
        ]
        change_spend_txids = {}
        for internal_index, spend_utxo in zip(internal_targets, spend_source_utxos):
            txid = source_wallet.send(
                outputs=[{self.miner.getnewaddress(): spend_amounts[internal_index]}],
                inputs=[{"txid": spend_utxo["txid"], "vout": spend_utxo["vout"]}],
                add_inputs=False,
                fee_rate=200,
                change_address=sparse_change_addrs[internal_index],
            )["txid"]
            change_spend_txids[internal_index] = txid

        self.mine(1)

        sparse_receive_utxos = {
            index: self.get_single_utxo(source_wallet, sparse_receive_addrs[index]) for index in external_targets
        }
        sparse_change_utxos = {
            index: self.get_single_utxo(source_wallet, sparse_change_addrs[index]) for index in internal_targets
        }
        assert all(utxo["txid"] == receive_txids[index] for index, utxo in sparse_receive_utxos.items())
        assert all(utxo["txid"] == change_spend_txids[index] for index, utxo in sparse_change_utxos.items())

        expected_total_balance = sum(receive_amounts.values()) + sum(
            utxo["amount"] for utxo in sparse_change_utxos.values()
        )
        assert_equal(source_wallet.getbalance(), expected_total_balance)
        source_external_next_index = self.active_descriptor(source_wallet, internal=False)["next_index"]
        source_internal_next_index = self.active_descriptor(source_wallet, internal=True)["next_index"]

        self.log.info("Export the source wallet pubkey database and confirm sparse metadata is present")
        exported = source_wallet.exportpubkeydb()
        assert_equal(exported["count"], len(exported["pubkeys"]))
        exported_sparse_indexes = {
            (entry.get("change"), entry.get("index")) for entry in exported["pubkeys"]
        }
        for index in external_targets:
            assert (False, index) in exported_sparse_indexes
        for index in internal_targets:
            assert (True, index) in exported_sparse_indexes

        sparse_addresses = [
            *[sparse_receive_addrs[index] for index in external_targets],
            *[sparse_change_addrs[index] for index in internal_targets],
        ]
        source_unspent_map = self.unspent_map(source_wallet, sparse_addresses)

        self.log.info("Recover the signer wallet on a clean node from private ranged P2MR descriptors")
        recovered_node.createwallet("restored_signer", blank=True)
        restored_wallet = recovered_node.get_wallet_rpc("restored_signer")
        recover_start = time.monotonic()
        restored_result = self.import_recovery_descriptors(
            restored_wallet,
            source_master_xprv,
            external_range_end=105,
            internal_range_end=73,
            external_next_index=96,
            internal_next_index=64,
        )
        self.log_recovery_duration(
            "restored signer import",
            recover_start,
            external_range_end=105,
            internal_range_end=73,
            pubkeys=exported["count"],
        )
        warning_external_range_end = self.expected_effective_range_end(
            105,
            next_index=96,
            keypool_size=self.FULL_RECOVERY_KEYPOOL,
        )
        warning_internal_range_end = self.expected_effective_range_end(
            73,
            next_index=64,
            keypool_size=self.FULL_RECOVERY_KEYPOOL,
        )
        assert_equal(
            sorted(self.collect_warnings(restored_result)),
            sorted([
                self.expanded_range_warning(
                    internal=False,
                    requested_range_start=0,
                    requested_range_end=105,
                    effective_range_end=warning_external_range_end,
                ),
                self.expanded_range_warning(
                    internal=True,
                    requested_range_start=0,
                    requested_range_end=73,
                    effective_range_end=warning_internal_range_end,
                ),
            ]),
        )
        restored_external_range_end = self.expected_effective_range_end(
            105,
            next_index=source_external_next_index,
            keypool_size=self.FULL_RECOVERY_KEYPOOL,
        )
        restored_internal_range_end = self.expected_effective_range_end(
            73,
            next_index=source_internal_next_index,
            keypool_size=self.FULL_RECOVERY_KEYPOOL,
        )
        # Blank-wallet descriptor recovery does not recreate address-book labels for historical
        # receive addresses, so parent_desc is a more stable ownership check than ischange here.
        restored_external_desc = self.assert_active_descriptor_state(
            restored_wallet,
            internal=False,
            expected_range_end=restored_external_range_end,
            expected_next_index=source_external_next_index,
        )["desc"]
        restored_internal_desc = self.assert_active_descriptor_state(
            restored_wallet,
            internal=True,
            expected_range_end=restored_internal_range_end,
            expected_next_index=source_internal_next_index,
        )["desc"]

        for index in external_targets:
            restored_info = self.assert_p2mr_address(restored_wallet, sparse_receive_addrs[index])
            assert_equal(restored_info["ismine"], True)
            assert_equal(restored_info["parent_desc"], restored_external_desc)
        for index in internal_targets:
            restored_info = self.assert_p2mr_address(restored_wallet, sparse_change_addrs[index])
            assert_equal(restored_info["ismine"], True)
            assert_equal(restored_info["parent_desc"], restored_internal_desc)

        restored_unspent_map = self.unspent_map(restored_wallet, sparse_addresses)
        assert_equal(restored_unspent_map, source_unspent_map)
        assert_equal(restored_wallet.getbalance(), source_wallet.getbalance())

        restored_history = restored_wallet.listsinceblock(
            blockhash=history_start,
            include_change=True,
        )["transactions"]
        for index in external_targets:
            self.assert_history_contains(restored_history, receive_txids[index], sparse_receive_addrs[index])
            assert_greater_than(restored_wallet.gettransaction(receive_txids[index])["confirmations"], 0)
        for index in internal_targets:
            self.assert_history_contains(restored_history, change_spend_txids[index], sparse_change_addrs[index])
            assert_greater_than(restored_wallet.gettransaction(change_spend_txids[index])["confirmations"], 0)

        self.log.info("Assert low-keypool short-range recovery keeps the requested horizon and misses higher sparse indexes")
        strict_node.createwallet("restored_signer_short", blank=True)
        short_wallet = strict_node.get_wallet_rpc("restored_signer_short")
        short_start = time.monotonic()
        short_result = self.import_recovery_descriptors(
            short_wallet,
            source_master_xprv,
            external_range_end=20,
            internal_range_end=10,
        )
        self.log_recovery_duration(
            "short-range signer import",
            short_start,
            external_range_end=20,
            internal_range_end=10,
            pubkeys=exported["count"],
        )
        assert_equal(self.collect_warnings(short_result), [])
        self.assert_active_descriptor_state(
            short_wallet,
            internal=False,
            expected_range_end=20,
            expected_next_index=1,
        )
        self.assert_active_descriptor_state(
            short_wallet,
            internal=True,
            expected_range_end=10,
            expected_next_index=1,
        )
        assert_equal(short_wallet.getaddressinfo(sparse_receive_addrs[0])["ismine"], True)
        assert_equal(short_wallet.getaddressinfo(sparse_change_addrs[0])["ismine"], True)
        assert_equal(short_wallet.getaddressinfo(sparse_receive_addrs[31])["ismine"], False)
        assert_equal(short_wallet.getaddressinfo(sparse_receive_addrs[95])["ismine"], False)
        assert_equal(short_wallet.getaddressinfo(sparse_change_addrs[17])["ismine"], False)
        assert_equal(short_wallet.getaddressinfo(sparse_change_addrs[63])["ismine"], False)

        self.log.info("Recover sparse receive/change history into a clean watch-only wallet via pubkeydb")
        watch_node.createwallet("watch_sparse", blank=True, disable_private_keys=True)
        watch_wallet = watch_node.get_wallet_rpc("watch_sparse")
        watch_start = time.monotonic()
        imported_watch = watch_wallet.importpubkeydb(exported["pubkeys"], False, 0)
        self.log_recovery_duration(
            "watch-only pubkeydb import",
            watch_start,
            pubkeys=exported["count"],
            external_indexes=max(external_targets),
            internal_indexes=max(internal_targets),
        )
        assert_equal(imported_watch["imported"], exported["count"])

        for index in external_targets:
            self.assert_p2mr_address(watch_wallet, sparse_receive_addrs[index], is_change=False)
            assert_equal(watch_wallet.getaddressinfo(sparse_receive_addrs[index])["ismine"], True)
        for index in internal_targets:
            self.assert_p2mr_address(watch_wallet, sparse_change_addrs[index], is_change=True)
            assert_equal(watch_wallet.getaddressinfo(sparse_change_addrs[index])["ismine"], True)

        watch_unspent_map = self.unspent_map(watch_wallet, sparse_addresses)
        assert_equal(watch_unspent_map, source_unspent_map)

        watch_history = watch_wallet.listsinceblock(
            blockhash=history_start,
            include_change=True,
        )["transactions"]
        for index in external_targets:
            self.assert_history_contains(watch_history, receive_txids[index], sparse_receive_addrs[index])
            assert_greater_than(watch_wallet.gettransaction(receive_txids[index])["confirmations"], 0)
        for index in internal_targets:
            self.assert_history_contains(watch_history, change_spend_txids[index], sparse_change_addrs[index])
            assert_greater_than(watch_wallet.gettransaction(change_spend_txids[index])["confirmations"], 0)

        watch_receive_utxo = self.get_single_utxo(watch_wallet, sparse_receive_addrs[0])
        watch_spend = watch_wallet.send(
            outputs=[{self.miner.getnewaddress(): watch_receive_utxo["amount"]}],
            fee_rate=200,
            include_watching=True,
            inputs=[{"txid": watch_receive_utxo["txid"], "vout": watch_receive_utxo["vout"]}],
            add_inputs=False,
            subtract_fee_from_outputs=[0],
        )
        assert_equal(watch_spend["complete"], False)
        assert "psbt" in watch_spend
        assert "txid" not in watch_spend
        watch_input = watch_wallet.decodepsbt(watch_spend["psbt"])["inputs"][0]
        assert "p2mr_scripts" in watch_input
        assert "p2mr_script_path_sigs" not in watch_input
        assert "final_scriptwitness" not in watch_input
        self.assert_missing_only_p2mr_signature(watch_wallet.analyzepsbt(watch_spend["psbt"]), next_role="signer")
        watch_processed = watch_wallet.walletprocesspsbt(
            watch_spend["psbt"],
            True,
            "DEFAULT",
            True,
        )
        assert_equal(watch_processed["complete"], False)
        watch_processed_input = watch_wallet.decodepsbt(watch_processed["psbt"])["inputs"][0]
        assert "p2mr_scripts" in watch_processed_input
        assert "p2mr_script_path_sigs" not in watch_processed_input
        assert "final_scriptwitness" not in watch_processed_input
        self.assert_missing_only_p2mr_signature(watch_wallet.analyzepsbt(watch_processed["psbt"]), next_role="signer")
        watch_finalized = watch_wallet.finalizepsbt(watch_processed["psbt"])
        assert_equal(watch_finalized["complete"], False)
        assert "hex" not in watch_finalized
        assert "psbt" in watch_finalized
        watch_finalized_input = watch_wallet.decodepsbt(watch_finalized["psbt"])["inputs"][0]
        assert "final_scriptwitness" not in watch_finalized_input
        self.assert_missing_only_p2mr_signature(watch_wallet.analyzepsbt(watch_finalized["psbt"]), next_role="signer")

        self.log.info("Recovered signer can spend again after sparse recovery succeeds")
        resend_amount = (restored_wallet.getbalance() / Decimal("2")).quantize(Decimal("0.00000001"))
        assert_greater_than(resend_amount, Decimal("0.00001000"))
        restored_spend_txid = restored_wallet.sendtoaddress(
            self.miner.getnewaddress(),
            resend_amount,
            fee_rate=200,
        )
        self.sync_mempools(self.nodes)
        assert restored_spend_txid in source_node.getrawmempool()
        self.mine(1)
        self.sync_blocks(self.nodes)
        assert_greater_than(restored_wallet.gettransaction(restored_spend_txid)["confirmations"], 0)


if __name__ == "__main__":
    FeatureWalletSeedRecoveryTest(__file__).main()
