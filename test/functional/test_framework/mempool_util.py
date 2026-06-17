#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for mempool testing."""
import random

from .blocktools import (
    COINBASE_MATURITY,
)
from .messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    WITNESS_SCALE_FACTOR,
)
from .script import (
    CScript,
    OP_RETURN,
)
from .util import (
    assert_equal,
    assert_greater_than,
    create_lots_of_big_transactions,
    gen_return_txouts,
)
from .wallet import (
    MiniWallet,
)

# Default for -minrelaytxfee in sat/kvB
DEFAULT_MIN_RELAY_TX_FEE = 250
# Default for -incrementalrelayfee in sat/kvB
DEFAULT_INCREMENTAL_RELAY_FEE = 250

TRUC_MAX_VSIZE = 50000
TRUC_CHILD_MAX_VSIZE = 45500

MIN_MAX_MEMPOOL_SIZE_MB = 17

def assert_mempool_contents(test_framework, node, expected=None, sync=True):
    """Assert that all transactions in expected are in the mempool,
    and no additional ones exist. 'expected' is an array of
    CTransaction objects
    """
    if sync:
        test_framework.sync_mempools()
    if not expected:
        expected = []
    assert_equal(len(expected), len(set(expected)))
    mempool = node.getrawmempool(verbose=False)
    assert_equal(len(mempool), len(expected))
    for tx in expected:
        assert tx.txid_hex in mempool


def fill_mempool(test_framework, node, *, tx_sync_fun=None):
    """Fill mempool until eviction.

    Allows for simpler testing of scenarios with floating mempoolminfee > minrelay
    Requires -maxmempool=MIN_MAX_MEMPOOL_SIZE_MB.
    To avoid unintentional tx dependencies, the mempool filling txs are created with a
    tagged ephemeral miniwallet instance.
    """
    test_framework.log.info("Fill the mempool until eviction is triggered and the mempoolminfee rises")
    txouts = gen_return_txouts()
    minrelayfee = node.getnetworkinfo()['relayfee']
    assert_equal(node.getmempoolinfo()["maxmempool"], MIN_MAX_MEMPOOL_SIZE_MB * 1_000_000)

    tx_batch_size = 1
    approx_batch_vsize = 65_000
    pre_eviction_batches = (node.getmempoolinfo()["maxmempool"] * 85) // (100 * approx_batch_vsize)
    max_eviction_batches = 100
    num_of_batches = pre_eviction_batches + max_eviction_batches
    # Generate UTXOs to flood the mempool
    # 1 to create a tx initially that will be evicted from the mempool later
    # enough large transactions, each with a higher fee rate than the previous one,
    # to sync before eviction and then cross the limit with the final batches.
    # The pre-eviction batch count leaves slack for CI configurations whose
    # mempool usage is slightly higher than the transaction vsize estimate.
    ephemeral_miniwallet = MiniWallet(node, tag_name="fill_mempool_ephemeral_wallet")
    test_framework.generate(ephemeral_miniwallet, 1 + num_of_batches * tx_batch_size)

    # Mine enough blocks so that the UTXOs are allowed to be spent
    test_framework.generate(node, COINBASE_MATURITY - 1)

    # Get all UTXOs up front to ensure none of the transactions spend from each other, as that may
    # change their effective feerate and thus the order in which they are selected for eviction.
    confirmed_utxos = [ephemeral_miniwallet.get_utxo(confirmed_only=True) for _ in range(num_of_batches * tx_batch_size + 1)]
    assert_equal(len(confirmed_utxos), num_of_batches * tx_batch_size + 1)

    test_framework.log.debug("Create a mempool tx that will be evicted")
    tx_to_be_evicted_id = ephemeral_miniwallet.send_self_transfer(
        from_node=node, utxo_to_spend=confirmed_utxos.pop(0), fee_rate=minrelayfee)["txid"]

    def send_batch(fee):
        utxos = confirmed_utxos[:tx_batch_size]
        create_lots_of_big_transactions(ephemeral_miniwallet, node, fee, tx_batch_size, txouts, utxos)
        del confirmed_utxos[:tx_batch_size]

    # Increase the tx fee rate to give the subsequent transactions a higher priority in the mempool
    # The tx has an approx. vsize of 65k, i.e. multiplying the previous fee rate (in sats/kvB)
    # by 130 should result in a fee that corresponds to 2x of that fee rate
    base_fee = minrelayfee * 130
    batch_fees = [(i + 1) * base_fee for i in range(num_of_batches)]

    test_framework.log.debug("Fill up the mempool with txs with higher fee rate")
    sent_batches = 0
    for fee in batch_fees[:pre_eviction_batches]:
        send_batch(fee)
        sent_batches += 1
    tx_sync_fun() if tx_sync_fun else test_framework.sync_mempools()  # sync before any eviction
    assert_equal(node.getmempoolinfo()["mempoolminfee"], minrelayfee)

    for fee in batch_fees[pre_eviction_batches:]:
        send_batch(fee)
        sent_batches += 1
        mempool = node.getrawmempool()
        if tx_to_be_evicted_id not in mempool and len(mempool) < 1 + tx_batch_size * sent_batches:
            break
    tx_sync_fun() if tx_sync_fun else test_framework.sync_mempools()  # sync after all evictions

    test_framework.log.debug("The tx should be evicted by now")
    # The number of transactions created should be greater than the ones present in the mempool
    assert_greater_than(1 + tx_batch_size * sent_batches, len(node.getrawmempool()))
    # Initial tx created should not be present in the mempool anymore as it had a lower fee rate
    assert tx_to_be_evicted_id not in node.getrawmempool()

    test_framework.log.debug("Check that mempoolminfee is larger than minrelaytxfee")
    assert_equal(node.getmempoolinfo()['minrelaytxfee'], minrelayfee)
    assert_greater_than(node.getmempoolinfo()['mempoolminfee'], minrelayfee)

def tx_in_orphanage(node, tx: CTransaction) -> bool:
    """Returns true if the transaction is in the orphanage."""
    found = [o for o in node.getorphantxs(verbosity=1) if o["txid"] == tx.txid_hex and o["wtxid"] == tx.wtxid_hex]
    return len(found) == 1

def create_large_orphan():
    """Create huge orphan transaction"""
    tx = CTransaction()
    # Nonexistent UTXO
    tx.vin = [CTxIn(COutPoint(random.randrange(1 << 256), random.randrange(1, 100)))]
    tx.wit.vtxinwit = [CTxInWitness()]
    # Keep this transaction large but still below standard policy limits and
    # under the ~100k vsize threshold expected by orphanage DoS tests.
    witness_bytes = 98000 if WITNESS_SCALE_FACTOR == 1 else 390000
    tx.wit.vtxinwit[0].scriptWitness.stack = [CScript(b'X' * witness_bytes)]
    tx.vout = [CTxOut(100, CScript([OP_RETURN, b'a' * 20]))]
    return tx
