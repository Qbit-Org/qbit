#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise P2MR wallet and watch-only state across reorgs."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class FeatureP2MRReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.noban_tx_relay = True
        self.extra_args = [["-keypool=200"] for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_p2mr_wallet(self, node, wallet_name):
        node.createwallet(wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)
        try:
            created_descs = wallet.createwalletdescriptor("p2mr")["descs"]
        except JSONRPCException as e:
            assert "Descriptor already exists" in e.error["message"]
            created_descs = [
                entry["desc"] for entry in wallet.listdescriptors()["descriptors"]
                if entry["active"] and entry["desc"].startswith("mr(")
            ]
        assert_greater_than(len(created_descs), 0)
        return wallet

    def assert_p2mr_address(self, wallet, address, *, is_change):
        info = wallet.getaddressinfo(address)
        assert_equal(info["isscript"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["witness_version"], 2)
        assert_equal(len(info["witness_program"]), 64)
        assert_equal(wallet.decodescript(info["scriptPubKey"])["type"], "witness_v2_p2mr")
        assert_equal(info["ismine"], True)
        assert_equal(info["ischange"], is_change)
        return info

    def mine(self, node_index, wallet, *, blocks=1, sync_nodes=None):
        sync_fun = self.no_op if sync_nodes is None else lambda: self.sync_all(sync_nodes)
        return self.generatetoaddress(
            self.nodes[node_index],
            blocks,
            wallet.getnewaddress(),
            sync_fun=sync_fun,
        )

    def reconnect_and_sync_blocks(self):
        self.connect_nodes(1, 2)
        self.sync_blocks(self.nodes)

    @staticmethod
    def history_entries(history, txid, *, address=None, category=None):
        return [
            entry for entry in history
            if entry["txid"] == txid
            and (address is None or entry.get("address") == address)
            and (category is None or entry["category"] == category)
        ]

    def assert_history_removed(self, wallet, orphan_tip, txid, *, address, category, include_change=False):
        result = wallet.listsinceblock(orphan_tip, include_change=include_change)
        removed = self.history_entries(result["removed"], txid, address=address, category=category)
        assert_equal(len(removed), 1)
        active = self.history_entries(result["transactions"], txid, address=address, category=category)
        for entry in active:
            assert_equal(entry["confirmations"], 0)

    def assert_no_confirmed_utxo(self, wallet, address, txid):
        utxos = wallet.listunspent(minconf=0, addresses=[address])
        assert not any(utxo["txid"] == txid and utxo["confirmations"] > 0 for utxo in utxos)

    def run_test(self):
        miner = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        alt_miner = self.nodes[2].get_wallet_rpc(self.default_wallet_name)
        left_nodes = self.nodes[:2]
        right_nodes = self.nodes[2:]

        self.log.info("Build a mature chain so the funding wallet can create spendable reorg scenarios")
        self.mine(0, miner, blocks=COINBASE_MATURITY + 5)
        self.sync_all()

        self.log.info("Create a signer wallet and matching watch-only importpubkeydb wallet")
        signer = self.create_p2mr_wallet(self.nodes[0], "p2mr_signer")
        orphan_receive_addr = signer.getnewaddress(address_type="p2mr")
        stable_receive_addr = signer.getnewaddress(address_type="p2mr")
        change_addr = signer.getrawchangeaddress(address_type="p2mr")
        self.assert_p2mr_address(signer, orphan_receive_addr, is_change=False)
        self.assert_p2mr_address(signer, stable_receive_addr, is_change=False)
        self.assert_p2mr_address(signer, change_addr, is_change=True)

        exported = signer.exportpubkeydb()
        assert_greater_than(exported["count"], 0)

        self.nodes[1].createwallet("p2mr_watch", blank=True, disable_private_keys=True)
        watch = self.nodes[1].get_wallet_rpc("p2mr_watch")
        imported = watch.importpubkeydb(exported["pubkeys"], False, 0)
        assert_equal(imported["imported"], exported["count"])
        self.assert_p2mr_address(watch, orphan_receive_addr, is_change=False)
        self.assert_p2mr_address(watch, stable_receive_addr, is_change=False)
        self.assert_p2mr_address(watch, change_addr, is_change=True)

        self.log.info("1/2 reorg out a confirmed P2MR receive and surface it through listsinceblock removed")
        orphan_amount = Decimal("1.25000000")
        self.split_network()

        orphan_receive_txid = miner.sendtoaddress(orphan_receive_addr, orphan_amount)
        self.sync_mempools(left_nodes)
        orphan_receive_tip = self.mine(0, miner, blocks=1, sync_nodes=left_nodes)[0]
        self.wait_until(lambda: signer.gettransaction(orphan_receive_txid)["confirmations"] > 0)
        self.wait_until(lambda: watch.gettransaction(orphan_receive_txid)["confirmations"] > 0)
        assert any(
            utxo["txid"] == orphan_receive_txid and utxo["confirmations"] > 0
            for utxo in signer.listunspent(addresses=[orphan_receive_addr])
        )
        assert any(
            utxo["txid"] == orphan_receive_txid and utxo["confirmations"] > 0
            for utxo in watch.listunspent(addresses=[orphan_receive_addr])
        )

        self.mine(2, alt_miner, blocks=2, sync_nodes=right_nodes)
        self.reconnect_and_sync_blocks()

        self.wait_until(lambda: signer.gettransaction(orphan_receive_txid)["confirmations"] == 0)
        self.wait_until(lambda: watch.gettransaction(orphan_receive_txid)["confirmations"] == 0)
        assert_equal(signer.getbalances()["mine"]["trusted"], Decimal("0"))
        assert_equal(watch.getbalances()["mine"]["trusted"], Decimal("0"))
        self.assert_no_confirmed_utxo(signer, orphan_receive_addr, orphan_receive_txid)
        self.assert_no_confirmed_utxo(watch, orphan_receive_addr, orphan_receive_txid)
        self.assert_history_removed(
            signer,
            orphan_receive_tip,
            orphan_receive_txid,
            address=orphan_receive_addr,
            category="receive",
        )
        self.assert_history_removed(
            watch,
            orphan_receive_tip,
            orphan_receive_txid,
            address=orphan_receive_addr,
            category="receive",
        )
        assert "removed" not in signer.listsinceblock(orphan_receive_tip, include_removed=False)

        self.log.info("Create a stable confirmed P2MR UTXO for the spend/change invalidation scenario")
        stable_receive_txid = miner.sendtoaddress(stable_receive_addr, Decimal("1.50000000"))
        self.mine(0, miner, blocks=1)
        self.sync_all()
        self.wait_until(lambda: signer.gettransaction(stable_receive_txid)["confirmations"] > 0)
        self.wait_until(lambda: watch.gettransaction(stable_receive_txid)["confirmations"] > 0)

        self.log.info("2/2 reorg out a confirmed P2MR spend and its P2MR change, then reconfirm it cleanly")
        self.split_network()

        spend_amount = Decimal("0.60000000")
        spend_txid = signer.send(
            outputs=[{miner.getnewaddress(): spend_amount}],
            fee_rate=200,
            options={"change_address": change_addr},
        )["txid"]
        self.sync_mempools(left_nodes)
        spend_tx = signer.gettransaction(spend_txid, verbose=True)
        assert any(vout["scriptPubKey"].get("address") == change_addr for vout in spend_tx["decoded"]["vout"])

        orphan_spend_tip = self.mine(0, miner, blocks=1, sync_nodes=left_nodes)[0]
        self.wait_until(lambda: signer.gettransaction(spend_txid)["confirmations"] > 0)
        self.wait_until(lambda: watch.gettransaction(spend_txid)["confirmations"] > 0)
        assert any(
            utxo["txid"] == spend_txid and utxo["confirmations"] > 0
            for utxo in signer.listunspent(addresses=[change_addr])
        )
        assert any(
            utxo["txid"] == spend_txid and utxo["confirmations"] > 0
            for utxo in watch.listunspent(addresses=[change_addr])
        )

        self.mine(2, alt_miner, blocks=2, sync_nodes=right_nodes)
        self.reconnect_and_sync_blocks()

        spend_hex = signer.gettransaction(spend_txid)["hex"]
        self.wait_until(lambda: signer.gettransaction(spend_txid)["confirmations"] == 0)
        self.wait_until(lambda: watch.gettransaction(spend_txid)["confirmations"] == 0)
        self.assert_no_confirmed_utxo(signer, change_addr, spend_txid)
        self.assert_no_confirmed_utxo(watch, change_addr, spend_txid)
        self.assert_history_removed(
            signer,
            orphan_spend_tip,
            spend_txid,
            address=change_addr,
            category="receive",
            include_change=True,
        )
        self.assert_history_removed(
            watch,
            orphan_spend_tip,
            spend_txid,
            address=change_addr,
            category="receive",
            include_change=True,
        )

        if spend_txid not in self.nodes[2].getrawmempool():
            self.nodes[2].sendrawtransaction(spend_hex)
        self.sync_mempools(self.nodes)
        self.mine(0, miner, blocks=1)
        self.sync_all()

        self.wait_until(lambda: signer.gettransaction(spend_txid)["confirmations"] > 0)
        self.wait_until(lambda: watch.gettransaction(spend_txid)["confirmations"] > 0)
        assert any(
            utxo["txid"] == spend_txid and utxo["confirmations"] > 0
            for utxo in signer.listunspent(addresses=[change_addr])
        )
        assert any(
            utxo["txid"] == spend_txid and utxo["confirmations"] > 0
            for utxo in watch.listunspent(addresses=[change_addr])
        )


if __name__ == "__main__":
    FeatureP2MRReorgTest(__file__).main()
