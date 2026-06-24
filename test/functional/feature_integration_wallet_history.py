#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet recovery across archive / witness-pruned / full-history nodes."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CBlock, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_not_equal,
)
from test_framework.wallet import MiniWallet


WITNESS_PRUNE_DEPTH = COINBASE_MATURITY


class IntegrationWalletHistoryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.rpc_timeout = 600
        self.extra_args = [
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune", "-keypool=200"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune", "-prunewitnesses=1"],
            ["-dnsseed=0", "-fixedseeds=0", "-blockfilterindex=1"],
            ["-dnsseed=0", "-fixedseeds=0", "-blockfilterindex=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
        self.connect_nodes(3, 2)
        self.sync_blocks(self.nodes)

    def mine(self, blocks=1):
        return self.generatetoaddress(self.nodes[0], blocks, self.miner.getnewaddress(), sync_fun=self.no_op)

    def mine_blocks_with_witness_txs(self, node, wallet, count):
        for _ in range(count):
            wallet.send_self_transfer(from_node=node)
            self.mine(1)

    @staticmethod
    def assert_stripped_matches_no_witness(stripped_hex, full_hex):
        full_block = from_hex(CBlock(), full_hex)
        full_witness = full_block.serialize()
        full_no_witness = full_block.serialize(False)
        assert_not_equal(full_witness, full_no_witness)
        assert_equal(bytes.fromhex(stripped_hex), full_no_witness)

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

    def assert_history_contains(self, entries, txid, address):
        assert any(
            entry["txid"] == txid and entry.get("address") == address and entry["category"] == "receive"
            for entry in entries
        )

    def run_test(self):
        archive_node = self.nodes[0]
        pruned_node = self.nodes[1]
        watch_node = self.nodes[2]
        restore_node = self.nodes[3]
        self.miner = archive_node.get_wallet_rpc(self.default_wallet_name)
        history_wallet = MiniWallet(archive_node)

        self.log.info("Build an initial mature chain before creating the source wallet backup")
        self.mine(WITNESS_PRUNE_DEPTH + 5)
        self.sync_blocks(self.nodes)
        self.miner.sendtoaddress(history_wallet.get_address(), Decimal("1"))
        self.mine(1)
        self.sync_blocks(self.nodes)
        history_wallet.rescan_utxos()

        self.log.info("Create the source wallet and back it up before any historical P2MR transactions exist")
        archive_node.createwallet("source_wallet")
        source_wallet = archive_node.get_wallet_rpc("source_wallet")
        try:
            created_descs = source_wallet.createwalletdescriptor("p2mr")["descs"]
        except JSONRPCException as e:
            assert "Descriptor already exists" in e.error["message"]
            created_descs = [
                entry["desc"] for entry in source_wallet.listdescriptors()["descriptors"]
                if entry["active"] and entry["desc"].startswith("mr(")
            ]
        assert_greater_than(len(created_descs), 0)

        receive_addr = source_wallet.getnewaddress(address_type="p2mr")
        change_addr = source_wallet.getrawchangeaddress(address_type="p2mr")
        self.assert_p2mr_address(source_wallet, receive_addr, is_change=False)
        self.assert_p2mr_address(source_wallet, change_addr, is_change=True)

        backup_file = archive_node.datadir_path / "source_wallet_pre_history.bak"
        source_wallet.backupwallet(backup_file)
        history_start = archive_node.getbestblockhash()

        self.log.info("Create confirmed post-backup P2MR history with a known internal change address")
        fund_amount = Decimal("5")
        incoming_txid = self.miner.sendtoaddress(receive_addr, fund_amount)
        self.mine(1)
        self.sync_blocks(self.nodes)
        assert_greater_than(source_wallet.gettransaction(incoming_txid)["confirmations"], 0)

        spend_amount = Decimal("1.5")
        spend_txid = source_wallet.send(
            outputs=[{self.miner.getnewaddress(): spend_amount}],
            fee_rate=200,
            options={"change_address": change_addr},
        )["txid"]
        spend_tx = source_wallet.gettransaction(spend_txid, verbose=True)
        assert any(vout["scriptPubKey"].get("address") == change_addr for vout in spend_tx["decoded"]["vout"])
        self.mine(1)
        self.sync_blocks(self.nodes)
        spend_tx = source_wallet.gettransaction(spend_txid, verbose=True)
        assert_greater_than(spend_tx["confirmations"], 0)

        spend_blockhash = spend_tx["blockhash"]
        exported = source_wallet.exportpubkeydb()
        assert_equal(exported["count"], len(exported["pubkeys"]))
        assert_greater_than(exported["count"], 0)
        assert any(not entry.get("change", False) for entry in exported["pubkeys"])
        assert any(entry.get("change", False) for entry in exported["pubkeys"])

        self.log.info("Age the wallet history past the witness prune depth")
        self.mine_blocks_with_witness_txs(archive_node, history_wallet, 300)
        self.mine(900)
        self.sync_blocks(self.nodes)

        historical_block_hex = archive_node.getblock(spend_blockhash, False)

        def historical_split():
            if "WITNESS_PRUNED" not in pruned_node.getnetworkinfo()["localservicesnames"]:
                return False
            try:
                self.assert_stripped_matches_no_witness(pruned_node.getblock(spend_blockhash, False), historical_block_hex)
            except AssertionError:
                return False
            return (
                watch_node.getblock(spend_blockhash, False) == historical_block_hex
                and restore_node.getblock(spend_blockhash, False) == historical_block_hex
            )

        self.wait_until(historical_split, timeout=180)

        self.log.info("A witness-pruned node can still recover history from stripped blocks")
        pruned_node.restorewallet("pruned_source_restore", backup_file)
        pruned_wallet = pruned_node.get_wallet_rpc("pruned_source_restore")
        assert_equal(pruned_wallet.getaddressinfo(receive_addr)["ismine"], True)
        assert_equal(pruned_wallet.getaddressinfo(change_addr)["ischange"], True)
        assert_greater_than(pruned_wallet.gettransaction(incoming_txid)["confirmations"], 0)
        assert_greater_than(pruned_wallet.gettransaction(spend_txid)["confirmations"], 0)

        self.log.info("A full-history watch-only wallet can recover both receive and change history via pubkeydb")
        watch_node.createwallet("watch_history", blank=True, disable_private_keys=True)
        watch_wallet = watch_node.get_wallet_rpc("watch_history")
        imported = watch_wallet.importpubkeydb(exported["pubkeys"], False, 0)
        assert_equal(imported["imported"], exported["count"])
        self.assert_p2mr_address(watch_wallet, receive_addr, is_change=False)
        self.assert_p2mr_address(watch_wallet, change_addr, is_change=True)
        assert_greater_than(watch_wallet.getbalances()["mine"]["trusted"], Decimal("0"))

        default_history = watch_wallet.listsinceblock(blockhash=history_start)["transactions"]
        self.assert_history_contains(default_history, incoming_txid, receive_addr)
        assert not any(entry.get("address") == change_addr for entry in default_history)

        change_history = watch_wallet.listsinceblock(blockhash=history_start, include_change=True)["transactions"]
        self.assert_history_contains(change_history, incoming_txid, receive_addr)
        self.assert_history_contains(change_history, spend_txid, change_addr)
        assert_greater_than(watch_wallet.gettransaction(incoming_txid)["confirmations"], 0)
        assert_greater_than(watch_wallet.gettransaction(spend_txid)["confirmations"], 0)
        recovered_change_utxo = watch_wallet.listunspent(addresses=[change_addr])
        assert_equal(len(recovered_change_utxo), 1)

        self.log.info("Recovered watch-only history remains non-signing and only produces an incomplete PSBT")
        watch_spend = watch_wallet.send(
            outputs=[{self.miner.getnewaddress(): recovered_change_utxo[0]["amount"]}],
            fee_rate=200,
            include_watching=True,
            inputs=[{"txid": recovered_change_utxo[0]["txid"], "vout": recovered_change_utxo[0]["vout"]}],
            add_inputs=False,
            subtract_fee_from_outputs=[0],
        )
        assert_equal(watch_spend["complete"], False)
        assert "psbt" in watch_spend
        assert "txid" not in watch_spend

        self.log.info("A full-history signer wallet can restore the old backup, recover history, and spend again")
        restore_node.restorewallet("restored_source", backup_file)
        restored_wallet = restore_node.get_wallet_rpc("restored_source")
        self.wait_pqc_key_validation_ready(restored_wallet)
        assert_equal(restored_wallet.getaddressinfo(receive_addr)["ismine"], True)
        assert_equal(restored_wallet.getaddressinfo(change_addr)["ischange"], True)
        assert_greater_than(restored_wallet.gettransaction(incoming_txid)["confirmations"], 0)
        assert_greater_than(restored_wallet.gettransaction(spend_txid)["confirmations"], 0)

        restored_balance = restored_wallet.getbalance()
        assert_greater_than(restored_balance, Decimal("0"))
        resend_amount = (restored_balance / Decimal("2")).quantize(Decimal("0.00000001"))
        assert_greater_than(resend_amount, Decimal("0.00001000"))

        restored_spend_txid = restored_wallet.sendtoaddress(
            self.miner.getnewaddress(),
            resend_amount,
            fee_rate=200,
        )
        self.sync_mempools([archive_node, pruned_node, watch_node, restore_node])
        assert restored_spend_txid in archive_node.getrawmempool()
        self.mine(1)
        self.sync_blocks(self.nodes)
        assert_greater_than(restored_wallet.gettransaction(restored_spend_txid)["confirmations"], 0)


if __name__ == "__main__":
    IntegrationWalletHistoryTest(__file__).main()
