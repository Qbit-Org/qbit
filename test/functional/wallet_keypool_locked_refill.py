#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that an encrypted wallet hands out a full keypool of addresses while locked.

A locked wallet cannot derive P2MR keys. walletpassphrase therefore refills the
P2MR keypools to -keypool before it returns, and its timeout counts from the
end of that refill. Each cycle below unlocks the wallet, locks it again and
then hands out -keypool receive addresses.

With --previous-qbitd=<path to a v1.0.0 qbitd>, the test also creates a wallet
with that binary on the same datadir and runs the cycles on it.
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

KEYPOOL_SIZE = 200
CYCLES = 3
PASSPHRASE = "keypool refill passphrase"


class WalletKeypoolLockedRefillTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--previous-qbitd", dest="previous_qbitd", default=None,
                            help="path to a v1.0.0 qbitd; if set, also check a wallet that it created")

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.wallet_names = [False]
        # Only P2MR keypools, so that keypoolsize counts one descriptor.
        self.extra_args = [["-p2mronly=1", f"-keypool={KEYPOOL_SIZE}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_new_wallet()
        self.test_short_timeout()
        self.test_previous_release_wallet()

    def unlock_and_check_keypool(self, wallet, timeout):
        """Unlock, check that both P2MR keypools are full, and return the
        time the call took, when it returned and the wallet info."""
        start = time.time()
        wallet.walletpassphrase(PASSPHRASE, timeout)
        returned = time.time()
        info = wallet.getwalletinfo()
        assert_equal(info["keypoolsize"], KEYPOOL_SIZE)
        assert_equal(info["keypoolsize_hd_internal"], KEYPOOL_SIZE)
        return returned - start, returned, info

    def hand_out_keypool_while_locked(self, wallet, seen):
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        addresses = [wallet.getnewaddress(address_type="p2mr") for _ in range(KEYPOOL_SIZE)]
        assert_equal(len(set(addresses)), KEYPOOL_SIZE)
        assert not seen.intersection(addresses)
        seen.update(addresses)
        # The pool held exactly -keypool keys, and a locked wallet derives none.
        assert_raises_rpc_error(-12, "Keypool ran out", wallet.getnewaddress, address_type="p2mr")

    def run_cycles(self, wallet):
        seen = set()
        for cycle in range(1, CYCLES + 1):
            elapsed, _, _ = self.unlock_and_check_keypool(wallet, 600)
            self.log.info(f"  cycle {cycle}: walletpassphrase refilled the keypool in {elapsed:.1f}s")
            wallet.walletlock()
            self.hand_out_keypool_while_locked(wallet, seen)

    def test_new_wallet(self):
        self.log.info("A wallet created with a passphrase hands out -keypool addresses while locked, every cycle")
        node = self.nodes[0]
        node.createwallet(wallet_name="new", passphrase=PASSPHRASE)
        self.run_cycles(node.get_wallet_rpc("new"))

    def test_short_timeout(self):
        self.log.info("The unlock timeout counts from the end of the refill, and the wallet still relocks")
        wallet = self.nodes[0].get_wallet_rpc("new")
        # The receive pool is empty after the cycles above, so the call
        # derives -keypool keys before it returns.
        timeout = 5
        elapsed, returned, info = self.unlock_and_check_keypool(wallet, timeout)
        self.log.info(f"  walletpassphrase refilled the keypool in {elapsed:.1f}s")
        # The deadline was set when the refill ended, under a second before the
        # call returned. (When the refill takes more than a second or two, a
        # deadline counted from the start of the call fails this check; the
        # unit tests check the deadline exactly.)
        assert_greater_than_or_equal(info["unlocked_until"], int(returned) - 1 + timeout)
        assert_greater_than_or_equal(int(returned) + timeout, info["unlocked_until"])
        self.wait_until(lambda: wallet.getwalletinfo()["unlocked_until"] == 0)
        self.hand_out_keypool_while_locked(wallet, set())

        self.log.info("A timeout of 0 relocks right after the refill")
        self.unlock_and_check_keypool(wallet, 0)
        self.wait_until(lambda: wallet.getwalletinfo()["unlocked_until"] == 0)
        self.hand_out_keypool_while_locked(wallet, set())

    def test_previous_release_wallet(self):
        previous_qbitd = self.options.previous_qbitd
        if previous_qbitd is None:
            self.log.info("Skipping the previous-release wallet check; pass --previous-qbitd to run it")
            return
        self.log.info("A wallet created by the previous release hands out -keypool addresses while locked, every cycle")
        node = self.nodes[0]
        # Swap the qbitd binary in the node's command line, which can start
        # with a wrapper such as valgrind.
        qbitd_index = next((i for i, arg in enumerate(node.args) if os.path.basename(arg) in ("qbitd", "qbitd.exe")), None)
        if qbitd_index is None:
            self.log.info("Skipping the previous-release wallet check; the node is not started as qbitd")
            return
        current_qbitd = node.args[qbitd_index]
        self.stop_node(0)
        node.args[qbitd_index] = previous_qbitd
        self.start_node(0)
        node.createwallet(wallet_name="previous", passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("previous")
        # Leave the wallet as a deposit flow on the previous release would:
        # unlocked once, then part of its keypool handed out while locked.
        wallet.walletpassphrase(PASSPHRASE, 600)
        wallet.walletlock()
        for _ in range(KEYPOOL_SIZE // 4):
            wallet.getnewaddress(address_type="p2mr")
        self.stop_node(0)
        node.args[qbitd_index] = current_qbitd
        self.start_node(0)
        node.loadwallet("previous")
        self.run_cycles(node.get_wallet_rpc("previous"))


if __name__ == "__main__":
    WalletKeypoolLockedRefillTest(__file__).main()
