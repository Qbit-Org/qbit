#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise imported P2MR pubkey-pool allocation and top-up flows."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)


class WalletPubKeyDBPoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-keypool=3",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, wallet, blocks=1):
        self.generatetoaddress(self.nodes[0], blocks, wallet.getnewaddress())

    def explicit_p2mr_address(self, pubkey_hex):
        descriptor = descsum_create(f"mr(pk({pubkey_hex}))")
        return self.nodes[0].deriveaddresses(descriptor)[0]

    def split_exported(self, exported):
        external = sorted(
            [entry for entry in exported["pubkeys"] if not entry["change"]],
            key=lambda entry: entry["index"],
        )
        internal = sorted(
            [entry for entry in exported["pubkeys"] if entry["change"]],
            key=lambda entry: entry["index"],
        )
        return external, internal

    def get_chain_status(self, watch, *, internal):
        chains = watch.listpubkeydbstatus()["chains"]
        matches = [entry for entry in chains if entry["account"] == 0 and entry["internal"] == internal]
        assert_equal(len(matches), 1)
        return matches[0]

    def reload_wallets(self):
        node = self.nodes[0]
        for wallet_name in ("funding", "signer", "watch"):
            node.loadwallet(wallet_name)
        return (
            node.get_wallet_rpc("funding"),
            node.get_wallet_rpc("signer"),
            node.get_wallet_rpc("watch"),
        )

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("funding")
        node.createwallet("signer")
        node.createwallet("watch", blank=True, disable_private_keys=True)
        funding = node.get_wallet_rpc("funding")
        signer = node.get_wallet_rpc("signer")
        watch = node.get_wallet_rpc("watch")

        self.log.info("Mine mature funding balance")
        self.mine(funding, COINBASE_MATURITY + 1)

        self.log.info("Warm signer P2MR receive/change descriptors and export an initial batch")
        signer.getnewaddress(address_type="p2mr")
        signer.getrawchangeaddress(address_type="p2mr")
        exported = signer.exportpubkeydb()
        external_entries, internal_entries = self.split_exported(exported)
        assert_greater_than_or_equal(len(external_entries), 3)
        assert_greater_than_or_equal(len(internal_entries), 2)

        initial_batch = external_entries[:3] + internal_entries[:1]
        imported = watch.importpubkeydb(initial_batch, False, "now")
        assert_equal(imported["imported"], len(initial_batch))
        assert_equal(watch.importpubkeydb(initial_batch, False, "now")["imported"], 0)
        assert_raises_rpc_error(
            -3,
            "Expected integer or \"now\" timestamp value",
            watch.importpubkeydb,
            initial_batch,
            False,
            1.5,
        )

        self.log.info("Status reports separate external/internal pools")
        external_status = self.get_chain_status(watch, internal=False)
        assert_equal(external_status["next_index"], 0)
        assert_equal(external_status["highest_imported_index"], 2)
        assert_equal(external_status["remaining"], 3)
        internal_status = self.get_chain_status(watch, internal=True)
        assert_equal(internal_status["next_index"], 0)
        assert_equal(internal_status["highest_imported_index"], 0)
        assert_equal(internal_status["remaining"], 1)

        self.log.info("A historically used imported address is skipped by the allocator")
        historical_addr = self.explicit_p2mr_address(external_entries[0]["pubkey"])
        historical_txid = funding.sendtoaddress(historical_addr, 1)
        self.mine(funding, 1)
        assert_equal(watch.gettransaction(historical_txid)["confirmations"] > 0, True)
        external_status = self.get_chain_status(watch, internal=False)
        assert_equal(external_status["next_index"], 1)
        assert_equal(external_status["remaining"], 2)

        self.log.info("Allocation advances sequentially and persists across restart")
        first_external = watch.getnextpubkeydbaddress()
        assert_equal(first_external["index"], 1)
        assert_equal(first_external["address"], self.explicit_p2mr_address(external_entries[1]["pubkey"]))
        assert_equal(first_external["remaining"], 1)
        self.restart_node(0, self.extra_args[0])
        node = self.nodes[0]
        funding, signer, watch = self.reload_wallets()
        external_status = self.get_chain_status(watch, internal=False)
        assert_equal(external_status["next_index"], 2)
        assert_equal(external_status["remaining"], 1)

        second_external = watch.getnextpubkeydbaddress()
        assert_equal(second_external["index"], 2)
        assert_equal(second_external["address"], self.explicit_p2mr_address(external_entries[2]["pubkey"]))
        assert_equal(second_external["remaining"], 0)
        assert_raises_rpc_error(
            -12,
            "Imported pubkey pool exhausted",
            watch.getnextpubkeydbaddress,
        )

        self.log.info("Internal allocations remain independent from the external cursor")
        internal_alloc = watch.getnextpubkeydbaddress(True)
        assert_equal(internal_alloc["index"], 0)
        assert_equal(internal_alloc["address"], self.explicit_p2mr_address(internal_entries[0]["pubkey"]))
        assert_equal(internal_alloc["remaining"], 0)
        assert_raises_rpc_error(
            -12,
            "Imported pubkey pool exhausted",
            watch.getnextpubkeydbaddress,
            True,
        )

        self.log.info("Signer keypoolrefill plus exportpubkeydb exposes future top-up entries")
        signer.keypoolrefill(6)
        topped_up_export = signer.exportpubkeydb()
        topup_external, topup_internal = self.split_exported(topped_up_export)
        assert_greater_than_or_equal(topup_external[-1]["index"], 5)
        assert_greater_than_or_equal(topup_internal[-1]["index"], 5)

        topup_batch = [entry for entry in topup_external if entry["index"] >= 3][:3]
        topup_batch += [entry for entry in topup_internal if entry["index"] >= 1][:2]
        assert_equal(len(topup_batch), 5)
        assert_equal(watch.importpubkeydb(topup_batch, False, "now")["imported"], len(topup_batch))
        assert_equal(watch.importpubkeydb(topup_batch, False, "now")["imported"], 0)

        self.log.info("Top-up extends the exhausted pool without disturbing the cursor")
        external_status = self.get_chain_status(watch, internal=False)
        assert_equal(external_status["next_index"], 3)
        assert_equal(external_status["highest_imported_index"], 5)
        assert_equal(external_status["remaining"], 3)
        resumed_external = watch.getnextpubkeydbaddress()
        assert_equal(resumed_external["index"], 3)
        assert_equal(resumed_external["address"], self.explicit_p2mr_address(topup_external[3]["pubkey"]))
        self.restart_node(0, self.extra_args[0])
        _, _, watch = self.reload_wallets()
        external_status = self.get_chain_status(watch, internal=False)
        assert_equal(external_status["next_index"], 4)
        assert_equal(external_status["remaining"], 2)


if __name__ == '__main__':
    WalletPubKeyDBPoolTest(__file__).main()
