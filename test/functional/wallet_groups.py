#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet group functionality."""

from decimal import (
    Decimal,
    ROUND_DOWN,
)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    tx_from_hex,
)
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_greater_than,
)


class WalletGroupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.extra_args = [
            [],
            [],
            ["-avoidpartialspends"],
            ["-maxapsfee=0.00002719"],
            ["-maxapsfee=0.00002720"],
        ]

        for args in self.extra_args:
            args.append(f"-paytxfee={20 * 1e3 / 1e8}")  # apply feerate of 20 sats/vB across all nodes

        self.rpc_timeout = 480

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Setting up")
        # Mine some coins
        self.ensure_mature_coinbase(self.nodes[0])
        # The available matured balance depends on chain subsidy/parameters.
        # Top up until we can fund the initial sends.
        required_starting_balance = 9
        while self.nodes[0].getbalance() < required_starting_balance:
            self.generate(self.nodes[0], 1)

        # Get some addresses from the two nodes
        addr1 = [self.nodes[1].getnewaddress() for _ in range(3)]
        addr2 = [self.nodes[2].getnewaddress() for _ in range(3)]
        addrs = addr1 + addr2

        # Send 1 + 0.5 coin to each address
        [self.nodes[0].sendtoaddress(addr, 1.0) for addr in addrs]
        [self.nodes[0].sendtoaddress(addr, 0.5) for addr in addrs]

        self.generate(self.nodes[0], 1)

        # For each node, send 0.2 coins back to 0;
        # - node[1] should pick one 0.5 UTXO and leave the rest
        # - node[2] should pick one (1.0 + 0.5) UTXO group corresponding to a
        #   given address, and leave the rest
        self.log.info("Test sending transactions picks one UTXO group and leaves the rest")
        txid1 = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 0.2)
        tx1 = self.nodes[1].getrawtransaction(txid1, True)
        # txid1 should have 1 input and 2 outputs
        assert_equal(1, len(tx1["vin"]))
        assert_equal(2, len(tx1["vout"]))
        # one output should be 0.2, the other should be ~0.3
        v = [vout["value"] for vout in tx1["vout"]]
        v.sort()
        assert_approx(v[0], vexp=0.2, vspan=0.0001)
        assert_approx(v[1], vexp=0.3, vspan=0.0001)

        txid2 = self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 0.2)
        tx2 = self.nodes[2].getrawtransaction(txid2, True)
        # txid2 should have 2 inputs and 2 outputs
        assert_equal(2, len(tx2["vin"]))
        assert_equal(2, len(tx2["vout"]))
        # one output should be 0.2, the other should be ~1.3
        v = [vout["value"] for vout in tx2["vout"]]
        v.sort()
        assert_approx(v[0], vexp=0.2, vspan=0.0001)
        assert_approx(v[1], vexp=1.3, vspan=0.0001)

        self.log.info("Test avoiding partial spends if warranted, even if avoidpartialspends is disabled")
        self.sync_all()
        self.generate(self.nodes[0], 1)
        # Nodes 1-2 now have confirmed UTXOs (letters denote destinations):
        # Node #1:      Node #2:
        # - A  1.0      - D0 1.0
        # - B0 1.0      - D1 0.5
        # - B1 0.5      - E0 1.0
        # - C0 1.0      - E1 0.5
        # - C1 0.5      - F  ~1.3
        # - D ~0.3
        assert_approx(self.nodes[1].getbalance(), vexp=4.3, vspan=0.0001)
        assert_approx(self.nodes[2].getbalance(), vexp=4.3, vspan=0.0001)
        # Sending 1.4 btc should pick one 1.0 + one more. For node #1,
        # this could be (A / B0 / C0) + (B1 / C1 / D). We ensure that it is
        # B0 + B1 or C0 + C1, because this avoids partial spends while not being
        # detrimental to transaction cost
        txid3 = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1.4)
        tx3 = self.nodes[1].getrawtransaction(txid3, True)
        # tx3 should have 2 inputs and 2 outputs
        assert_equal(2, len(tx3["vin"]))
        assert_equal(2, len(tx3["vout"]))
        # the accumulated value should be 1.5, so the outputs should be
        # ~0.1 and 1.4 and should come from the same destination
        values = [vout["value"] for vout in tx3["vout"]]
        values.sort()
        assert_approx(values[0], vexp=0.1, vspan=0.0001)
        assert_approx(values[1], vexp=1.4, vspan=0.0001)

        input_txids = [vin["txid"] for vin in tx3["vin"]]
        input_addrs = [self.nodes[1].gettransaction(txid)['details'][0]['address'] for txid in input_txids]
        assert_equal(input_addrs[0], input_addrs[1])
        # Node 2 enforces avoidpartialspends so needs no checking here

        self.log.info("Test wallet option maxapsfee")
        addr_aps = self.nodes[3].getnewaddress()
        self.nodes[0].sendtoaddress(addr_aps, 1.0)
        self.nodes[0].sendtoaddress(addr_aps, 1.0)
        self.generate(self.nodes[0], 1)
        with self.nodes[3].assert_debug_log(["using non-grouped"]):
            txid4 = self.nodes[3].sendtoaddress(self.nodes[0].getnewaddress(), 0.1)
        tx4 = self.nodes[3].getrawtransaction(txid4, True)
        # tx4 should have 1 input and 2 outputs
        assert_equal(1, len(tx4["vin"]))
        assert_equal(2, len(tx4["vout"]))

        addr_aps2 = self.nodes[3].getnewaddress()
        [self.nodes[0].sendtoaddress(addr_aps2, 1.0) for _ in range(5)]
        self.generate(self.nodes[0], 1)
        with self.nodes[3].assert_debug_log(["using non-grouped"]):
            txid5 = self.nodes[3].sendtoaddress(self.nodes[0].getnewaddress(), 2.95)
        tx5 = self.nodes[3].getrawtransaction(txid5, True)
        # tx5 should have 3 inputs (1.0, 1.0, 1.0) and 2 outputs
        assert_equal(3, len(tx5["vin"]))
        assert_equal(2, len(tx5["vout"]))

        # Test wallet option maxapsfee with node 4.
        self.log.info("Test wallet option maxapsfee threshold behavior")
        addr_aps3 = self.nodes[4].getnewaddress()
        [self.nodes[0].sendtoaddress(addr_aps3, 1.0) for _ in range(5)]
        self.generate(self.nodes[0], 1)
        with self.nodes[4].assert_debug_log(["using non-grouped"]):
            txid6 = self.nodes[4].sendtoaddress(self.nodes[0].getnewaddress(), 2.95)
        tx6 = self.nodes[4].getrawtransaction(txid6, True)
        # tx6 should have 3 inputs and 2 outputs
        assert_equal(3, len(tx6["vin"]))
        assert_equal(2, len(tx6["vout"]))

        # Empty out node2's wallet
        self.nodes[2].sendall(recipients=[self.nodes[0].getnewaddress()])
        self.sync_all()
        self.generate(self.nodes[0], 1)

        self.log.info("Fill a wallet with 10,000 outputs corresponding to the same scriptPubKey")
        output_txs = 5
        outputs_per_tx = 2000
        total_outputs = output_txs * outputs_per_tx

        # Scale output values with available balance so this stays valid if chain
        # parameters (e.g. subsidy schedule) differ from defaults.
        available_balance = self.nodes[0].getbalance()
        total_output_amount = (available_balance / Decimal(2)).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        output_amount = (total_output_amount / total_outputs).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        output_amount = max(output_amount, Decimal("0.0001"))

        for _ in range(output_txs):
            raw_tx = self.nodes[0].createrawtransaction([{"txid":"0"*64, "vout":0}], [{addr2[0]: output_amount}])
            tx = tx_from_hex(raw_tx)
            tx.vin = []
            tx.vout = [tx.vout[0]] * outputs_per_tx
            funded_tx = self.nodes[0].fundrawtransaction(tx.serialize().hex())
            signed_tx = self.nodes[0].signrawtransactionwithwallet(funded_tx['hex'])
            self.nodes[0].sendrawtransaction(signed_tx['hex'])
            self.generate(self.nodes[0], 1)

        # Check that we can create a transaction that only requires ~100 of our
        # utxos, without pulling in all outputs and creating a transaction that
        # is way too big.
        self.log.info("Test creating txn that only requires ~100 of our UTXOs without pulling in all outputs")
        send_amount = (output_amount * 100 - Decimal("0.002")).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        assert send_amount > 0, send_amount
        txid = self.nodes[2].sendtoaddress(address=addr2[0], amount=send_amount)
        tx = self.nodes[2].getrawtransaction(txid, True)
        assert_greater_than(len(tx["vin"]), 50)
        assert len(tx["vin"]) < total_outputs


if __name__ == '__main__':
    WalletGroupTest(__file__).main()
