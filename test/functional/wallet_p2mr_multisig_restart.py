#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2MR 2-of-3 multisig persistence across a node restart.

feature_p2mr.py exercises the 2-of-3 mr(multi_a(...)) PSBT spend itself. This
test adds the operational dimension that spend test does not cover (issue #665,
step 8): that after the participating wallets are stopped and reloaded from
disk, the per-signer PQC signature counters, the watch-only coordinator state,
and the spent-state of the multisig output all persist and stay consistent.

The decisive check funds two multisig UTXOs, spends one before a restart and the
other after, and asserts each participating signer's PQC counter continues
(0 -> 1 -> 2) rather than resetting. A reset would risk reusing a bounded PQC
signature index, so this is a safety-relevant invariant.
"""
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class WalletP2MRMultisigRestartTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-keypool=20", "-walletpqcparallel=1", "-walletpqcsignthreads=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, miner, blocks=1):
        self.generatetoaddress(self.nodes[0], blocks, miner.getnewaddress())

    def single_key_address(self, pubkey):
        """The P2MR single-key address committing to one signer's PQC pubkey."""
        return self.nodes[0].deriveaddresses(descsum_create(f"mr(pk({pubkey}))"))[0]

    def pqc_count(self, wallet, address):
        """Local PQC signature counter for a wallet-owned P2MR key, or 0."""
        info = wallet.getaddressinfo(address)
        states = info.get("pqc_key_states")
        if states:
            return states[0]["pqc_signature_count"]
        return info.get("pqc_signature_count", 0)

    def spend_one(self, coordinator, signer_a, signer_b, miner, utxo, label):
        """Run a full 2-of-3 spend of a single multisig UTXO and confirm it.

        Asserts one signature is incomplete and two independent signatures
        finalize. Returns the confirmed spend txid.
        """
        node = self.nodes[0]
        psbt = coordinator.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{miner.getnewaddress(): utxo["amount"]}],
            0,
            {
                "includeWatching": True,
                "subtractFeeFromOutputs": [0],
                "add_inputs": False,
                "fee_rate": 200,
            },
        )["psbt"]

        # Signer A alone is not enough.
        signed_a = signer_a.walletprocesspsbt(psbt=psbt, sign=True, finalize=False)
        assert_equal(signed_a["complete"], False)
        assert_equal(node.finalizepsbt(signed_a["psbt"])["complete"], False)

        # Signer B signs the original PSBT independently.
        signed_b = signer_b.walletprocesspsbt(psbt=psbt, sign=True, finalize=False)
        assert_equal(signed_b["complete"], False)

        combined = node.combinepsbt([signed_a["psbt"], signed_b["psbt"]])
        finalized = node.finalizepsbt(combined)
        assert_equal(finalized["complete"], True)
        assert_equal(node.testmempoolaccept([finalized["hex"]])[0]["allowed"], True)

        spend_txid = node.sendrawtransaction(finalized["hex"])
        self.mine(miner, 1)
        assert_greater_than(coordinator.gettransaction(spend_txid)["confirmations"], 0)
        self.log.info(f"  {label}: 2-of-3 spend {spend_txid[:16]}... confirmed")
        return spend_txid

    def run_test(self):
        node = self.nodes[0]
        miner = node.get_wallet_rpc(self.default_wallet_name)
        self.mine(miner, COINBASE_MATURITY + 1)

        self.log.info("Create three independent signer wallets and export one PQC key each")
        signers = []
        pubkeys = []
        for index in range(3):
            name = f"ms_signer_{index}"
            node.createwallet(name)
            signer = node.get_wallet_rpc(name)
            try:
                signer.createwalletdescriptor("p2mr")
            except JSONRPCException as e:
                assert "Descriptor already exists" in e.error["message"]
            pubkeys.append(signer.exportpubkeydb()["pubkeys"][0]["pubkey"])
            signers.append(signer)

        addr_a = self.single_key_address(pubkeys[0])
        addr_b = self.single_key_address(pubkeys[1])
        addr_c = self.single_key_address(pubkeys[2])

        # Fresh keys: every counter starts at zero.
        assert_equal(self.pqc_count(signers[0], addr_a), 0)
        assert_equal(self.pqc_count(signers[1], addr_b), 0)
        assert_equal(self.pqc_count(signers[2], addr_c), 0)

        self.log.info("Import the 2-of-3 mr(multi_a(...)) into a watch-only coordinator")
        multisig_desc = descsum_create(f"mr(multi_a(2,{','.join(pubkeys)}))")
        node.createwallet("ms_coordinator", blank=True, disable_private_keys=True)
        coordinator = node.get_wallet_rpc("ms_coordinator")
        assert_equal(
            coordinator.importdescriptors([{"desc": multisig_desc, "timestamp": "now"}])[0]["success"],
            True,
        )
        multisig_addr = node.deriveaddresses(multisig_desc)[0]
        assert_equal(coordinator.getaddressinfo(multisig_addr)["witness_version"], 2)

        self.log.info("Fund the multisig with two UTXOs")
        for _ in range(2):
            miner.sendtoaddress(multisig_addr, Decimal("1.0"))
        self.mine(miner, 1)
        utxos = sorted(
            coordinator.listunspent(1, 9999999, [multisig_addr]),
            key=lambda u: (u["txid"], u["vout"]),
        )
        assert_equal(len(utxos), 2)

        self.log.info("Spend UTXO #1 (signers 0 + 1) BEFORE restart")
        self.spend_one(coordinator, signers[0], signers[1], miner, utxos[0], "spend#1")
        assert_equal(self.pqc_count(signers[0], addr_a), 1)
        assert_equal(self.pqc_count(signers[1], addr_b), 1)
        assert_equal(self.pqc_count(signers[2], addr_c), 0)

        self.log.info("Restart the node; reload wallets from disk")
        self.restart_node(0)
        for name in ["ms_signer_0", "ms_signer_1", "ms_signer_2", "ms_coordinator", self.default_wallet_name]:
            try:
                node.loadwallet(name)
            except JSONRPCException as e:
                assert "already loaded" in e.error["message"].lower()
        miner = node.get_wallet_rpc(self.default_wallet_name)
        signers = [node.get_wallet_rpc(f"ms_signer_{i}") for i in range(3)]
        coordinator = node.get_wallet_rpc("ms_coordinator")
        for signer in signers:
            self.wait_pqc_key_validation_ready(signer)

        self.log.info("Counters and spent-state survived the restart")
        assert_equal(self.pqc_count(signers[0], addr_a), 1)
        assert_equal(self.pqc_count(signers[1], addr_b), 1)
        assert_equal(self.pqc_count(signers[2], addr_c), 0)
        remaining = coordinator.listunspent(1, 9999999, [multisig_addr])
        assert_equal(len(remaining), 1)
        assert_equal((remaining[0]["txid"], remaining[0]["vout"]), (utxos[1]["txid"], utxos[1]["vout"]))

        self.log.info("Spend UTXO #2 (signers 0 + 1) AFTER restart; counters must continue")
        self.spend_one(coordinator, signers[0], signers[1], miner, utxos[1], "spend#2")
        # The decisive check: counters continued from 1 to 2, they were not reset.
        assert_equal(self.pqc_count(signers[0], addr_a), 2)
        assert_equal(self.pqc_count(signers[1], addr_b), 2)
        assert_equal(self.pqc_count(signers[2], addr_c), 0)

        self.log.info("Spent-state is fully consistent")
        assert_equal(len(coordinator.listunspent(1, 9999999, [multisig_addr])), 0)
        assert_equal(coordinator.getbalances()["mine"]["trusted"], 0)


if __name__ == "__main__":
    WalletP2MRMultisigRestartTest(__file__).main()
