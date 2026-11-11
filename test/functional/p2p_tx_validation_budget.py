#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the per-peer budget for the time spent validating rejected transactions.

The time spent validating a transaction that is rejected for a reason in the
transaction itself is charged to the peer that sent it. While a peer is over
its budget, its transactions are dropped without validation and its
announcements are not requested, until the budget has refilled. The peer is
not disconnected or discouraged, and noban peers are exempt.

The test uses -txvalidationbudget=<peer_rate>,<peer_cap>,<pool_rate>,<pool_cap>
(microseconds) to set a budget small enough to reach with a few transactions:
each peer can use 1 us of own credit, earned at 1 us per second once connected,
and the shared pool holds 2 ms and does not refill. Sections that need the pool
full again restart the node.
"""

import json
import time
from pathlib import Path

from test_framework.messages import (
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.script import (
    CScript,
    OP_2,
    OP_CHECKSIGPQC,
    OP_FALSE,
    TaggedHash,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.wallet import MiniWallet

P2MR_LEAF_VERSION = 0xC0
TEST_BUDGET = "-txvalidationbudget=1,1,0,2000"
# More than the delay before a transaction announced by an inbound peer is requested.
INBOUND_REQUEST_DELAY = 3
# Upper bound on the rejected transactions a peer sends before it is over the test budget.
MAX_REJECTED_TXS = 1000
# Seconds after which a peer's own credit is positive again at 1 us per second, whatever its debt
# (balances do not go below -1 s).
CREDIT_REFILL_TIME = 1_000_001


def p2mr_leaf_hash(script):
    return TaggedHash("P2MRLeaf", bytes([P2MR_LEAF_VERSION]) + ser_string(bytes(script)))


def p2mr_control_block():
    return bytes([P2MR_LEAF_VERSION | 1])


class GetdataRecorder(P2PInterface):
    def __init__(self):
        super().__init__()
        self.requested = set()

    def on_getdata(self, message):
        for inv in message.inv:
            self.requested.add(inv.hash)


class TxValidationBudgetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[TEST_BUDGET]]

    def load_pqc_fixture(self):
        path = Path(self.config["environment"]["SRCDIR"]) / "src/test/data/p2mr_datapqchash_vectors.json"
        with path.open(encoding="utf-8") as fixture_file:
            return json.load(fixture_file)["vectors"][0]

    def fund_p2mr_leaf(self, leaf_script):
        script_pubkey = CScript([OP_2, p2mr_leaf_hash(leaf_script)])
        funding = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=1_000_000)
        return {"txid": funding["txid"], "vout": funding["sent_vout"], "amount": 1_000_000}

    def spend(self, coin, witness_stack):
        """A new transaction (with a new txid) that spends coin with witness_stack."""
        self.spend_count += 1
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]
        tx.vout = [CTxOut(coin["amount"] - 10_000 - self.spend_count, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

    def script_failure(self):
        """A spend whose leaf script fails."""
        return self.spend(self.false_coin, [bytes(self.false_leaf), p2mr_control_block()])

    def signature_failure(self):
        """A spend whose PQC signature does not verify."""
        return self.spend(self.pqc_coin, [self.corrupted_sig, bytes(self.pqc_leaf), p2mr_control_block()])

    def parent_and_failing_child(self, *, version=2, zero_fee=False):
        """A new transaction that pays to the leaf script that fails, and a child that spends it."""
        fee_args = {"fee": 0, "fee_rate": 0} if zero_fee else {}
        parent = self.wallet.create_self_transfer(version=version, **fee_args)["tx"]
        parent.vout[0].scriptPubKey = CScript([OP_2, p2mr_leaf_hash(self.false_leaf)])
        child = CTransaction()
        child.version = version
        child.vin = [CTxIn(COutPoint(parent.txid_int, 0))]
        child.vout = [CTxOut(parent.vout[0].nValue - 20_000, self.wallet.get_output_script())]
        child.wit.vtxinwit = [CTxInWitness()]
        child.wit.vtxinwit[0].scriptWitness.stack = [bytes(self.false_leaf), p2mr_control_block()]
        return parent, child

    def peer_info(self, peer):
        return next(p for p in self.nodes[0].getpeerinfo() if p["id"] == peer.peer_id)

    def connect_peer(self):
        peer = self.nodes[0].add_p2p_connection(GetdataRecorder())
        peer.peer_id = self.nodes[0].getpeerinfo()[-1]["id"]
        return peer

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.ensure_cached_coinbase_mature(node)
        self.spend_count = 0

        self.log.info("Create P2MR coins whose spends fail a script check or a PQC signature check")
        fixture = self.load_pqc_fixture()
        self.false_leaf = CScript([OP_FALSE])
        self.pqc_leaf = CScript([bytes.fromhex(fixture["pubkey"]), OP_CHECKSIGPQC])
        corrupted_sig = bytearray.fromhex(fixture["signature"])
        corrupted_sig[0] ^= 1
        self.corrupted_sig = bytes(corrupted_sig)
        self.false_coin = self.fund_p2mr_leaf(self.false_leaf)
        self.pqc_coin = self.fund_p2mr_leaf(self.pqc_leaf)
        self.generate(self.wallet, 1)

        self.test_peer_over_budget()
        self.test_orphans_wait()
        self.test_noban_peer_is_exempt()
        self.test_disabled_budget()
        self.test_invalid_option()

    def send_rejected(self, peer, *, count=None):
        """Send rejected transactions from peer, a script failure first, then signature failures:
        count of them, or until the peer is over its budget. Return the number sent."""
        node = self.nodes[0]
        expected_msgs = [
            "Script evaluated without error but finished with a false/empty top stack element",
            "PQC signature verification failed",
        ]
        with node.assert_debug_log(expected_msgs=expected_msgs):
            peer.send_and_ping(msg_tx(self.script_failure()))
            sent = 1
            while sent < (count or MAX_REJECTED_TXS):
                peer.send_and_ping(msg_tx(self.signature_failure()))
                sent += 1
                if count is None and self.peer_info(peer)["tx_validation_throttled"]:
                    break
        return sent

    def test_peer_over_budget(self):
        node = self.nodes[0]
        mocktime = int(time.time())
        node.setmocktime(mocktime)
        peer_a = self.connect_peer()
        peer_b = self.connect_peer()
        info = self.peer_info(peer_a)
        assert_equal(info["failed_tx_validation_time"], 0)
        assert_equal(info["tx_validation_throttled"], False)
        assert_equal(info["tx_dropped_while_throttled"], 0)
        # Let both peers earn the credit they can use.
        mocktime += 2
        node.setmocktime(mocktime)
        # A transaction that only peer A announces, before it goes over its budget.
        txid_early = 0xeeee
        peer_a.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=txid_early)]))

        self.log.info("A peer that keeps sending rejected transactions goes over its budget")
        with node.assert_debug_log(expected_msgs=[f"peer={peer_a.peer_id} is over its transaction validation budget"],
                                   unexpected_msgs=["Misbehaving", "discouraging"]):
            sent = self.send_rejected(peer_a)
        info = self.peer_info(peer_a)
        assert_equal(info["tx_validation_throttled"], True)
        assert_greater_than(info["failed_tx_validation_time"], 0)
        assert_equal(info["tx_dropped_while_throttled"], 0)
        # The exempt peers below send more than that.
        self.exempt_stream_size = 2 * sent + 10
        assert_equal(self.peer_info(peer_b)["failed_tx_validation_time"], 0)

        self.log.info("Its transactions are dropped without validation; it is not disconnected or discouraged")
        dropped_tx = self.wallet.create_self_transfer()
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[dropped_tx["txid"]]):
            peer_a.send_and_ping(msg_tx(dropped_tx["tx"]))
        assert dropped_tx["txid"] not in node.getrawmempool()
        info = self.peer_info(peer_a)
        assert_equal(info["tx_dropped_while_throttled"], 1)
        assert_equal(info["tx_validation_throttled"], True)
        assert peer_a.is_connected
        assert_equal(node.listbanned(), [])

        self.log.info("Transactions are not requested from it, including one it announced before, while another peer's are")
        txid_a = 0xaaaa
        txid_b = 0xbbbb
        peer_a.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=txid_a)]))
        peer_b.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=txid_b)]))
        mocktime += INBOUND_REQUEST_DELAY
        node.setmocktime(mocktime)
        peer_b.wait_until(lambda: txid_b in peer_b.requested)
        # Twice, so that a request sent in the same message handler pass as the first pong has arrived.
        peer_a.sync_with_ping()
        peer_a.sync_with_ping()
        with p2p_lock:
            assert txid_a not in peer_a.requested
            assert txid_early not in peer_a.requested
        assert_equal(self.peer_info(peer_a)["tx_validation_throttled"], True)

        self.log.info("The dropped transaction is not marked as rejected: another peer's copy is accepted")
        peer_b.send_and_ping(msg_tx(dropped_tx["tx"]))
        assert dropped_tx["txid"] in node.getrawmempool()

        self.log.info("Once its credit has refilled, the peer's transactions are validated again")
        mocktime += CREDIT_REFILL_TIME
        with node.assert_debug_log(expected_msgs=[f"peer={peer_a.peer_id} is within its transaction validation budget again; transactions dropped while over it: 1"]):
            node.setmocktime(mocktime)
            peer_a.sync_with_ping()
        later_tx = self.wallet.create_self_transfer()
        peer_a.send_and_ping(msg_tx(later_tx["tx"]))
        assert later_tx["txid"] in node.getrawmempool()
        info = self.peer_info(peer_a)
        assert_equal(info["tx_validation_throttled"], False)
        assert_equal(info["tx_dropped_while_throttled"], 1)
        assert_equal(len(node.getpeerinfo()), 2)

        node.setmocktime(0)
        node.disconnect_p2ps()
        self.generate(self.wallet, 1)

    def test_orphans_wait(self):
        node = self.nodes[0]
        self.log.info("The orphans of a peer over its budget wait until the budget has refilled")
        self.restart_node(0, extra_args=[TEST_BUDGET])
        mocktime = int(time.time())
        node.setmocktime(mocktime)
        peer_c = self.connect_peer()
        peer_d = self.connect_peer()
        mocktime += 2
        node.setmocktime(mocktime)

        parent, child = self.parent_and_failing_child()
        peer_c.send_and_ping(msg_tx(child))
        assert_equal(node.getorphantxs(), [child.txid_hex])
        self.send_rejected(peer_c)
        info = self.peer_info(peer_c)
        assert_equal(info["tx_validation_throttled"], True)
        charged = info["failed_tx_validation_time"]

        # Peer D provides the parent; reconsidering the orphan is peer C's work, which waits.
        peer_d.send_and_ping(msg_tx(parent))
        assert parent.txid_hex in node.getrawmempool()
        peer_c.sync_with_ping()
        assert_equal(node.getorphantxs(), [child.txid_hex])
        assert_equal(self.peer_info(peer_c)["failed_tx_validation_time"], charged)

        # Once peer C's credit has refilled, the orphan is reconsidered, rejected and charged to C.
        mocktime += CREDIT_REFILL_TIME
        node.setmocktime(mocktime)
        self.wait_until(lambda: node.getorphantxs() == [])
        assert_greater_than(self.peer_info(peer_c)["failed_tx_validation_time"], charged)
        assert child.txid_hex not in node.getrawmempool()
        assert_equal(len(node.getpeerinfo()), 2)
        node.disconnect_p2ps()

    def test_noban_peer_is_exempt(self):
        node = self.nodes[0]
        self.log.info("A noban peer sending the same transactions is never over its budget")
        self.restart_node(0, extra_args=[TEST_BUDGET, "-whitelist=noban@127.0.0.1"])
        peer = self.connect_peer()
        self.send_rejected(peer, count=self.exempt_stream_size)
        info = self.peer_info(peer)
        assert_equal(info["tx_validation_throttled"], False)
        assert_equal(info["tx_dropped_while_throttled"], 0)
        assert_greater_than(info["failed_tx_validation_time"], 0)
        valid_tx = self.wallet.create_self_transfer()
        peer.send_and_ping(msg_tx(valid_tx["tx"]))
        assert valid_tx["txid"] in node.getrawmempool()
        node.disconnect_p2ps()

    def test_disabled_budget(self):
        node = self.nodes[0]
        self.log.info("With the budget disabled, a peer is never over it; its time is still reported")
        self.restart_node(0, extra_args=["-txvalidationbudget=0"])
        peer = self.connect_peer()
        self.send_rejected(peer, count=self.exempt_stream_size)
        info = self.peer_info(peer)
        assert_equal(info["tx_validation_throttled"], False)
        assert_greater_than(info["failed_tx_validation_time"], 0)
        node.disconnect_p2ps()

        self.log.info("Package evaluation is charged to the sender of the package member that is rejected")
        sender = self.connect_peer()
        other = self.connect_peer()
        # Parents without fees, so they can only be accepted in a package with their child.
        parent, child = self.parent_and_failing_child(version=3, zero_fee=True)
        sender.send_and_ping(msg_tx(child))
        assert_equal(node.getorphantxs(), [child.txid_hex])
        with node.assert_debug_log(expected_msgs=["package evaluation for", "package rejected"]):
            sender.send_and_ping(msg_tx(parent))
        charged = self.peer_info(sender)["failed_tx_validation_time"]
        assert_greater_than(charged, 0)

        # The same when the parent was first received from another peer, which is not charged.
        parent, child = self.parent_and_failing_child(version=3, zero_fee=True)
        sender.send_and_ping(msg_tx(child))
        with node.assert_debug_log(expected_msgs=["min relay fee not met"], unexpected_msgs=["package evaluation for"]):
            other.send_and_ping(msg_tx(parent))
        with node.assert_debug_log(expected_msgs=["package evaluation for", "package rejected"]):
            sender.send_and_ping(msg_tx(parent))
        assert_greater_than(self.peer_info(sender)["failed_tx_validation_time"], charged)
        assert_equal(self.peer_info(other)["failed_tx_validation_time"], 0)
        mempool = node.getrawmempool()
        assert parent.txid_hex not in mempool
        assert child.txid_hex not in mempool
        node.disconnect_p2ps()

    def test_invalid_option(self):
        node = self.nodes[0]
        self.log.info("A malformed -txvalidationbudget value fails startup")
        self.stop_node(0)
        for value in ["1,2,3", "1,2,3,4,5", "-1,2,3,4", "a,b,c,d", "1,,3,4", "1,2,3,3600000001", "", "0,0,0,0", "0,1,1,1", "1,0,1,1"]:
            node.assert_start_raises_init_error(
                extra_args=[f"-txvalidationbudget={value}"],
                expected_msg=f"Error: Invalid -txvalidationbudget value '{value}': expected 0 to disable, or "
                             "<peer_rate>,<peer_cap>,<pool_rate>,<pool_cap> in microseconds, each from 0 to 3600000000, "
                             "with <peer_rate> and <peer_cap> at least 1",
                match=ErrorMatch.FULL_TEXT,
            )


if __name__ == '__main__':
    TxValidationBudgetTest(__file__).main()
