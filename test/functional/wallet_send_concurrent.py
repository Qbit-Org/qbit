#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test concurrent send calls that compete for wallet coins.

send selects coins before it signs, and signing a P2MR input takes long enough
for concurrent calls to select the same coin. Every call must either fail or
return a txid that is in the mempool, and the wallet must keep no transaction
that a concurrent call has already double-spent.

These checks hold however the calls interleave. src/wallet/test/spend_tests.cpp
orders calls with a test hook to check races that need a fixed order.
"""

from decimal import Decimal
import re
from threading import Barrier, Thread

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    get_rpc_proxy,
)

NUM_CALLS = 4
CONCURRENT_SPEND_ERROR = re.compile(r"Input [0-9a-f]{64}:\d+ was spent by concurrent transaction ([0-9a-f]{64})\. "
                                    r"This transaction was not added to the wallet or broadcast; the call can be retried\.")
INSUFFICIENT_FUNDS = "Insufficient funds"


class WalletSendConcurrentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.ensure_cached_coinbase_mature(node)
        self.funder = node.get_wallet_rpc(self.default_wallet_name)

        self.test_one_coin()
        self.test_many_coins()
        self.test_manual_replacement()

    def create_funded_wallet(self, name, num_coins):
        self.nodes[0].createwallet(wallet_name=name)
        wallet = self.nodes[0].get_wallet_rpc(name)
        addresses = [wallet.getnewaddress(address_type="p2mr") for _ in range(num_coins)]
        self.funder.send(outputs=[{address: 1} for address in addresses])
        self.generate(self.nodes[0], 1)
        assert_equal(len(wallet.listunspent()), num_coins)
        return wallet, addresses

    def call_concurrently(self, wallet_name, args_list):
        """Make one send call per entry of args_list at the same time, each on
        its own RPC connection.

        Returns each call's result, or the JSONRPCException it raised."""
        node = self.nodes[0]
        rpcs = [get_rpc_proxy(node.url, 0, timeout=600, coveragedir=node.coverage_dir) / f"wallet/{wallet_name}" for _ in args_list]
        barrier = Barrier(len(args_list))
        results = [None] * len(args_list)

        def call(index):
            barrier.wait()
            try:
                results[index] = rpcs[index].send(**args_list[index])
            except JSONRPCException as e:
                results[index] = e

        threads = [Thread(target=call, args=(index,)) for index in range(len(args_list))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def check_results(self, wallet, results, allow_insufficient_funds=False):
        """Check that each call either failed or returned a txid that is in
        the mempool, and that the wallet keeps no other unconfirmed
        transaction.

        Returns the txids of the calls that succeeded."""
        mempool = set(self.nodes[0].getrawmempool())
        txids = [result["txid"] for result in results if not isinstance(result, JSONRPCException)]
        errors = [result.error for result in results if isinstance(result, JSONRPCException)]
        self.log.info(f"  {len(txids)} returned a txid, {len(set(txids) & mempool)} of them in the mempool; {len(errors)} failed")
        for result in results:
            if not isinstance(result, JSONRPCException):
                assert_equal(result["complete"], True)
                assert result["txid"] in mempool, f"{result['txid']} was reported sent but is not in the mempool"
        for error in errors:
            assert_equal(error["code"], -4)
            if allow_insufficient_funds and error["message"] == INSUFFICIENT_FUNDS:
                continue
            match = CONCURRENT_SPEND_ERROR.fullmatch(error["message"])
            assert match, f"unexpected error {error}"
            # The error names a transaction another call returned.
            assert match.group(1) in txids
        # A losing call adds nothing to the wallet.
        unconfirmed = {tx["txid"] for tx in wallet.listtransactions("*", 1000) if tx["confirmations"] < 1}
        assert_equal(unconfirmed, set(txids))
        return txids

    def test_one_coin(self):
        self.log.info("Test that concurrent send calls spending a wallet's only coin succeed once")
        wallet_name = "one_coin"
        wallet, [address] = self.create_funded_wallet(wallet_name, 1)
        coin = wallet.listunspent()[0]
        count_before = wallet.getaddressinfo(address)["pqc_signature_count"]

        # Spend the whole coin, so a call that selects coins after another has
        # committed finds none, rather than spending that call's change.
        args_list = [{"outputs": [{self.funder.getnewaddress(): 1}], "subtract_fee_from_outputs": [0]} for _ in range(NUM_CALLS)]
        results = self.call_concurrently(wallet_name, args_list)
        txids = self.check_results(wallet, results, allow_insufficient_funds=True)
        assert_equal(len(txids), 1)
        winner = self.nodes[0].getrawtransaction(txids[0], True)
        assert_equal([(vin["txid"], vin["vout"]) for vin in winner["vin"]], [(coin["txid"], coin["vout"])])
        assert_equal(wallet.listunspent(minconf=0), [])

        # A call that lost may still have signed, so the signature counter can
        # rise by more than the one signature that was broadcast, never less.
        count_delta = wallet.getaddressinfo(address)["pqc_signature_count"] - count_before
        self.log.info(f"  signature counter rose by {count_delta}")
        assert_greater_than_or_equal(count_delta, 1)
        assert_greater_than_or_equal(NUM_CALLS, count_delta)
        self.generate(self.nodes[0], 1)

    def test_many_coins(self):
        self.log.info("Test concurrent send calls in a wallet with more coins than calls")
        wallet_name = "many_coins"
        wallet, _ = self.create_funded_wallet(wallet_name, 2 * NUM_CALLS)

        # Coins are not locked while a call signs, so concurrent calls can
        # still select the same coin, and all but one of those fail.
        args_list = [{"outputs": [{self.funder.getnewaddress(): Decimal("0.1")}]} for _ in range(NUM_CALLS)]
        results = self.call_concurrently(wallet_name, args_list)
        assert_greater_than_or_equal(len(self.check_results(wallet, results)), 1)
        self.generate(self.nodes[0], 1)

        self.log.info("Test that concurrent send calls spending separate coins all succeed")
        utxos = wallet.listunspent()[:NUM_CALLS]
        args_list = [{"outputs": [{self.funder.getnewaddress(): Decimal("0.1")}], "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"]}]} for utxo in utxos]
        results = self.call_concurrently(wallet_name, args_list)
        assert_equal(len(self.check_results(wallet, results)), NUM_CALLS)
        self.generate(self.nodes[0], 1)

    def test_manual_replacement(self):
        self.log.info("Test that send can still replace a wallet transaction by spending its inputs")
        wallet, _ = self.create_funded_wallet("manual_replacement", 1)
        coins = [{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in wallet.listunspent()]
        original = wallet.send(outputs=[{self.funder.getnewaddress(): Decimal("0.1")}], inputs=coins, fee_rate=1, replaceable=True)["txid"]
        assert original in self.nodes[0].getrawmempool()
        replacement = wallet.send(outputs=[{self.funder.getnewaddress(): Decimal("0.1")}], inputs=coins, fee_rate=10)
        assert_equal(replacement["complete"], True)
        mempool = self.nodes[0].getrawmempool()
        assert replacement["txid"] in mempool
        assert original not in mempool
        self.nodes[0].syncwithvalidationinterfacequeue()
        assert_equal(wallet.gettransaction(original)["walletconflicts"], [replacement["txid"]])
        self.generate(self.nodes[0], 1)


if __name__ == '__main__':
    WalletSendConcurrentTest(__file__).main()
