#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet fees without fee estimates: -fallbackfee, its compiled-in
default, and the rate at which change is discarded to the fee."""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# The framework writes this line into every node's config
FRAMEWORK_FALLBACK_FEE_LINE = "fallbackfee=0.0002\n"
SAT = Decimal("0.00000001")


class WalletRBFTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def restart(self, extra_args):
        self.restart_node(0, extra_args=extra_args)
        self.wait_pqc_key_validation_ready(self.nodes[0])
        assert "feerate" not in self.nodes[0].estimatesmartfee(1)

    def feerate_sat_per_kvb(self, txid):
        tx = self.nodes[0].gettransaction(txid, verbose=True)
        return -tx["fee"] / SAT * 1000 / tx["decoded"]["vsize"]

    def check_change_discard(self, utxo, *, kept, discarded):
        """Fund spends of utxo with P2MR change of each amount and check which change outputs are kept."""
        node = self.nodes[0]
        dest = node.getnewaddress(address_type="p2mr")

        def fund(leftover):
            raw = node.createrawtransaction([{"txid": utxo["txid"], "vout": utxo["vout"]}], {dest: utxo["amount"] - leftover})
            funded = node.fundrawtransaction(raw, {"add_inputs": False, "change_type": "p2mr"})
            if funded["changepos"] == -1:
                return funded["fee"], None
            return funded["fee"], node.decoderawtransaction(funded["hex"])["vout"][funded["changepos"]]["value"]

        # Leave far more than any discard threshold to learn the fee of the spend with change
        fee, change = fund(Decimal("0.01"))
        assert change is not None
        for amount in kept:
            assert_equal(fund(fee + amount), (fee, amount))
        for amount in discarded:
            assert_equal(fund(fee + amount), (fee + amount, None))

    def run_test(self):
        node = self.nodes[0]
        self.ensure_mature_coinbase(node)

        # sending a transaction without fee estimations must be possible by default on regtest
        node.sendtoaddress(node.getnewaddress(), 1)

        # A confirmed P2MR coin to spend with P2MR change, which costs about 3.8 kB to spend
        p2mr_address = node.getnewaddress(address_type="p2mr")
        txid = node.sendtoaddress(p2mr_address, 1)
        self.generate(node, 1)
        utxo = next(u for u in node.listunspent() if u["txid"] == txid and u["address"] == p2mr_address)
        # Keep the other sends from spending it; preset inputs may still use it
        node.lockunspent(False, [{"txid": utxo["txid"], "vout": utxo["vout"]}], True)
        assert "feerate" not in node.estimatesmartfee(1)

        self.log.info("Test that the framework's fallbackfee=0.0002 keeps discarding change at the -discardfee default")
        # 0.0001 QBT/kvB makes P2MR change below about 0.000384 QBT uneconomical
        self.check_change_discard(utxo, kept=[Decimal("0.0005")], discarded=[Decimal("0.0003")])

        # test sending a tx with disabled fallback fee (must fail)
        self.restart(["-fallbackfee=0"])
        assert_raises_rpc_error(-6, "Fee estimation failed", lambda: node.sendtoaddress(node.getnewaddress(), 1))
        assert_raises_rpc_error(-4, "Fee estimation failed", lambda: node.fundrawtransaction(node.createrawtransaction([], {node.getnewaddress(): 1})))
        assert_raises_rpc_error(-6, "Fee estimation failed", lambda: node.sendmany("", {node.getnewaddress(): 1}))

        self.log.info("Test the compiled-in -fallbackfee default")
        with open(node.bitcoinconf, encoding="utf8") as conf:
            assert FRAMEWORK_FALLBACK_FEE_LINE in conf.read()
        node.replace_in_config([(FRAMEWORK_FALLBACK_FEE_LINE, "")])
        self.restart([])
        result = node.sendtoaddress(node.getnewaddress(), 1, verbose=True)
        assert_equal(result["fee_reason"], "Fallback fee")
        assert 250 <= self.feerate_sat_per_kvb(result["txid"]) < 255

        self.log.info("Test that the default discard rate falls to the dust relay fee with the default fallback")
        # 0.0000075 QBT/kvB keeps P2MR change from about 0.0000288 QBT
        self.check_change_discard(utxo, kept=[Decimal("0.0003"), Decimal("0.00003")], discarded=[Decimal("0.0000275")])

        self.log.info("Test that an explicit -discardfee is used unchanged, even at the default value")
        self.restart(["-discardfee=0.0001"])
        self.check_change_discard(utxo, kept=[Decimal("0.0005")], discarded=[Decimal("0.0003")])

        self.log.info("Test -mintxfee above the fallback fee without estimates")
        self.restart(["-mintxfee=0.00001"])
        result = node.sendtoaddress(node.getnewaddress(), 1, verbose=True)
        assert_equal(result["fee_reason"], "Minimum Required Fee")
        assert 1000 <= self.feerate_sat_per_kvb(result["txid"]) < 1010
        # The discard rate follows -mintxfee, which spending the change will need too
        self.check_change_discard(utxo, kept=[Decimal("0.00004")], discarded=[Decimal("0.0000365")])
        self.restart(["-mintxfee=0.00001", "-fallbackfee=0"])
        assert_raises_rpc_error(-6, "Fee estimation failed", lambda: node.sendtoaddress(node.getnewaddress(), 1))


if __name__ == '__main__':
    WalletRBFTest(__file__).main()
