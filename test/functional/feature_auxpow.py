#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test merged-mining AuxPoW RPCs."""

from decimal import Decimal

from test_framework.address import p2a
from test_framework.auxpow import (
    MERGED_MINING_HEADER,
    QBIT_AUXPOW_CHAIN_ID,
    check_merkle_branch,
    make_valid_auxpow_from_template,
)
from test_framework.blocktools import (
    COINBASE_MATURITY,
    NORMAL_GBT_REQUEST_PARAMS,
)
from test_framework.messages import (
    COIN,
    ser_uint256,
    uint256_from_compact,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
    getnewdestination,
)


def difficulty_from_bits(bits):
    nbits = int(bits, 16)
    nshift = (nbits >> 24) & 0xff
    difficulty = Decimal(0x0000ffff) / Decimal(nbits & 0x00ffffff)
    while nshift < 29:
        difficulty *= Decimal(256)
        nshift += 1
    while nshift > 29:
        difficulty /= Decimal(256)
        nshift -= 1
    return difficulty


class FeatureAuxPowTest(BitcoinTestFramework):
    AUXPOW_TEMPLATE_CACHE_LIMIT = 12

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-asert",
            "-p2mronly=1",
            "-auxpowtemplateexpiry=1",
            f"-auxpowtemplatecachelimit={self.AUXPOW_TEMPLATE_CACHE_LIMIT}",
        ]]

    def advance_mock_time(self, seconds=600):
        self.mock_time += seconds
        self.nodes[0].setmocktime(self.mock_time)

    def make_auxpow(self, aux_template):
        return make_valid_auxpow_from_template(
            aux_template,
            parent_time=self.mock_time,
        )

    def assert_response_shape(self, aux_template):
        expected_keys = [
            "bits",
            "chainid",
            "coinbasevalue",
            "commitmentactivationheight",
            "commitmentorder",
            "hash",
            "height",
            "previousblockhash",
            "target",
        ]
        assert_equal(sorted(aux_template.keys()), expected_keys)
        assert_equal(aux_template["chainid"], QBIT_AUXPOW_CHAIN_ID)
        assert_equal(aux_template["commitmentactivationheight"], 0)
        assert_equal(aux_template["commitmentorder"], "display")
        assert_equal(aux_template["previousblockhash"], self.nodes[0].getbestblockhash())
        assert_equal(aux_template["height"], self.nodes[0].getblockcount() + 1)
        assert_equal(aux_template["target"], f"{uint256_from_compact(int(aux_template['bits'], 16)):064x}")

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_P2MR_OP_TRUE)
        self.generate(self.wallet, 101)

        self.mock_time = node.getblockheader(node.getbestblockhash())["time"] + 600
        node.setmocktime(self.mock_time)

        _, _, payout_address = getnewdestination("p2mr")

        self.log.info("createauxblock returns the expected response fields")
        aux_template = node.createauxblock(payout_address)
        self.assert_response_shape(aux_template)

        self.log.info("submitauxblock rejects malformed hashes before decoding the AuxPoW payload")
        assert_raises_rpc_error(-8, "hash must be of length 64", node.submitauxblock, "abc", "00")

        self.log.info("submitauxblock rejects malformed AuxPoW hex")
        assert_raises_rpc_error(-22, "AuxPow decode failed", node.submitauxblock, aux_template["hash"], "zz")

        self.log.info("Merged mining happy path: create, solve parent, submit")
        self.advance_mock_time()
        aux_template = node.createauxblock(payout_address)
        current_height = node.getblockcount()
        assert_equal(node.submitauxblock(aux_template["hash"], self.make_auxpow(aux_template).to_hex()), None)
        assert_equal(node.getblockcount(), current_height + 1)

        self.log.info("getmininginfo.next follows the permissionless candidate after an AuxPoW tip")
        native_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        mining_info = node.getmininginfo()
        assert_equal(mining_info["next"]["height"], native_template["height"])
        assert_equal(mining_info["next"]["bits"], native_template["bits"])
        assert_equal(mining_info["next"]["target"], native_template["target"])
        assert_equal(round(mining_info["next"]["difficulty"], 10), round(difficulty_from_bits(native_template["bits"]), 10))

        self.log.info("Reject AuxPoW payloads whose parent header misses the target")
        self.advance_mock_time()
        aux_template = node.createauxblock(payout_address)
        invalid_pow = self.make_auxpow(aux_template)
        invalid_pow.invalidate_parent_pow()
        assert_equal(node.submitauxblock(aux_template["hash"], invalid_pow.to_hex()), "bad-auxpow-parent-hash")
        assert_equal(node.getblockcount(), aux_template["height"] - 1)

        self.log.info("Reject AuxPoW payloads with malformed merged-mining commitments")
        invalid_commitment = self.make_auxpow(aux_template)
        invalid_commitment.coinbase_tx.vin[0].scriptSig = CScript([b"broken-commitment"])
        invalid_commitment.update_parent_merkle_root()
        invalid_commitment.solve_parent_pow()
        assert_equal(node.submitauxblock(aux_template["hash"], invalid_commitment.to_hex()), "bad-auxpow-commitment")
        assert_equal(node.getblockcount(), aux_template["height"] - 1)

        self.log.info("Reject AuxPoW commitments that use internal uint256 byte order")
        internal_order = self.make_auxpow(aux_template)
        chain_root = check_merkle_branch(
            leaf=int(aux_template["hash"], 16),
            branch=internal_order.chain_merkle_branch,
            index=internal_order.chain_index,
        )
        internal_order.coinbase_tx.vin[0].scriptSig = CScript([
            MERGED_MINING_HEADER
            + ser_uint256(chain_root)
            + (1 << len(internal_order.chain_merkle_branch)).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        ])
        internal_order.update_parent_merkle_root()
        internal_order.solve_parent_pow()
        assert_equal(node.submitauxblock(aux_template["hash"], internal_order.to_hex()), "bad-auxpow-commitment")
        assert_equal(node.getblockcount(), aux_template["height"] - 1)

        self.log.info("Rejected AuxPoW submissions remain retryable until accepted")
        assert_equal(node.submitauxblock(aux_template["hash"], self.make_auxpow(aux_template).to_hex()), None)
        assert_equal(node.getblockcount(), aux_template["height"])

        self.log.info("Cached aux blocks become stale after the active tip changes")
        self.advance_mock_time()
        stale_template = node.createauxblock(payout_address)
        stale_auxpow = self.make_auxpow(stale_template)
        self.advance_mock_time()
        self.generate(self.wallet, 1)
        assert_equal(node.submitauxblock(stale_template["hash"], stale_auxpow.to_hex()), "stale-prevblk")

        self.log.info("createauxblock keeps same-tip cached templates until age expiry")
        bounded_templates = []
        for _ in range(10):
            _, _, same_tip_address = getnewdestination("p2mr")
            bounded_templates.append(node.createauxblock(same_tip_address))
        oldest_template = bounded_templates[0]
        retained_template = bounded_templates[8]
        newest_template = bounded_templates[-1]
        assert_equal(oldest_template["previousblockhash"], newest_template["previousblockhash"])
        assert_equal(newest_template["previousblockhash"], node.getbestblockhash())
        oldest_invalid_pow = self.make_auxpow(oldest_template)
        oldest_invalid_pow.invalidate_parent_pow()
        assert_equal(node.submitauxblock(oldest_template["hash"], oldest_invalid_pow.to_hex()), "bad-auxpow-parent-hash")
        retained_invalid_pow = self.make_auxpow(retained_template)
        retained_invalid_pow.invalidate_parent_pow()
        assert_equal(node.submitauxblock(retained_template["hash"], retained_invalid_pow.to_hex()), "bad-auxpow-parent-hash")
        current_height = node.getblockcount()
        assert_equal(node.submitauxblock(newest_template["hash"], self.make_auxpow(newest_template).to_hex()), None)
        assert_equal(node.getblockcount(), current_height + 1)

        self.log.info("createauxblock evicts only the oldest same-tip cached template when the cache limit is exceeded")
        self.advance_mock_time()
        capped_templates = []
        for _ in range(self.AUXPOW_TEMPLATE_CACHE_LIMIT + 1):
            _, _, capped_address = getnewdestination("p2mr")
            capped_templates.append(node.createauxblock(capped_address))
        evicted_template = capped_templates[0]
        retained_template = capped_templates[1]
        newest_template = capped_templates[-1]
        assert_equal(evicted_template["previousblockhash"], newest_template["previousblockhash"])
        assert_equal(newest_template["previousblockhash"], node.getbestblockhash())
        evicted_invalid_pow = self.make_auxpow(evicted_template)
        evicted_invalid_pow.invalidate_parent_pow()
        assert_equal(node.submitauxblock(evicted_template["hash"], evicted_invalid_pow.to_hex()), "stale-prevblk")
        retained_invalid_pow = self.make_auxpow(retained_template)
        retained_invalid_pow.invalidate_parent_pow()
        assert_equal(node.submitauxblock(retained_template["hash"], retained_invalid_pow.to_hex()), "bad-auxpow-parent-hash")
        current_height = node.getblockcount()
        assert_equal(node.submitauxblock(newest_template["hash"], self.make_auxpow(newest_template).to_hex()), None)
        assert_equal(node.getblockcount(), current_height + 1)

        self.log.info("same-tip cached templates expire after -auxpowtemplateexpiry")
        self.advance_mock_time()
        expiring_template = node.createauxblock(payout_address)
        expiring_auxpow = self.make_auxpow(expiring_template)
        self.advance_mock_time(60)
        expiring_invalid_pow = self.make_auxpow(expiring_template)
        expiring_invalid_pow.invalidate_parent_pow()
        assert_equal(node.submitauxblock(expiring_template["hash"], expiring_invalid_pow.to_hex()), "bad-auxpow-parent-hash")
        self.advance_mock_time(1)
        assert_equal(node.submitauxblock(expiring_template["hash"], expiring_auxpow.to_hex()), "stale-prevblk")

        self.log.info("createauxblock requires P2MR payout addresses")
        for address_type in ("legacy", "p2sh-segwit", "bech32", "bech32m"):
            self.advance_mock_time()
            _, _, address = getnewdestination(address_type)
            assert_raises_rpc_error(
                -5,
                "Invalid address",
                node.createauxblock,
                address,
            )
        self.advance_mock_time()
        _, _, address = getnewdestination("p2mr")
        self.assert_response_shape(node.createauxblock(address))
        self.advance_mock_time()
        assert_raises_rpc_error(
            -5,
            "Coinbase payout address must be P2MR",
            node.createauxblock,
            p2a(),
        )

        self.log.info("coinbasevalue includes mempool fees")
        blocks_to_maturity = max(0, COINBASE_MATURITY - node.getblockcount())
        if blocks_to_maturity > 0:
            self.generate(self.wallet, blocks_to_maturity)
        self.mock_time = node.getblockheader(node.getbestblockhash())["time"] + 600
        node.setmocktime(self.mock_time)
        baseline_template = node.createauxblock(payout_address)
        fee_tx = self.wallet.send_self_transfer(from_node=node, fee_rate=Decimal("0.003"))
        self.advance_mock_time()
        fee_template = node.createauxblock(payout_address)
        assert_equal(
            fee_template["coinbasevalue"],
            baseline_template["coinbasevalue"] + int(fee_tx["fee"] * COIN),
        )


if __name__ == "__main__":
    FeatureAuxPowTest(__file__).main()
