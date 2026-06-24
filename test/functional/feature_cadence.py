#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test permissionless and merged Cadence mining side by side."""

from decimal import Decimal

from test_framework.auxpow import (
    BLOCK_VERSION_SIGNAL_MASK,
    make_valid_auxpow_from_block,
    make_valid_auxpow_from_template,
    make_version,
    reconstruct_createauxblock,
    serialize_auxpow_block,
)
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_approx, assert_equal
from test_framework.wallet import getnewdestination


class FeatureCadenceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-asert"]]

    def advance_mock_time(self, seconds=600):
        self.mock_time += seconds
        self.nodes[0].setmocktime(self.mock_time)

    def submit_permissionless_block(self):
        node = self.nodes[0]
        gbt = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(
            hashprev=int(gbt["previousblockhash"], 16),
            coinbase=create_coinbase(gbt["height"]),
            ntime=gbt["curtime"],
            version=gbt["version"],
            tmpl=gbt,
        )
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        return block

    def submit_merged_block(self, payout_address):
        node = self.nodes[0]
        aux_template = node.createauxblock(payout_address)
        auxpow = make_valid_auxpow_from_template(aux_template, parent_time=self.mock_time)
        assert_equal(node.submitauxblock(aux_template["hash"], auxpow.to_hex()), None)
        return aux_template

    def run_test(self):
        node = self.nodes[0]
        _, payout_script, payout_address = getnewdestination("bech32")

        self.mock_time = node.getblockheader(node.getbestblockhash())["time"] + 600
        node.setmocktime(self.mock_time)

        self.log.info("Permissionless getblocktemplate + submitblock still mines blocks")
        starting_height = node.getblockcount()
        self.advance_mock_time()
        self.submit_permissionless_block()
        assert_equal(node.getblockcount(), starting_height + 1)

        self.log.info("Merged createauxblock + submitauxblock mines blocks on the same chain")
        self.advance_mock_time()
        self.submit_merged_block(payout_address)
        assert_equal(node.getblockcount(), starting_height + 2)

        self.log.info("Permissionless and merged mining can alternate cleanly")
        self.advance_mock_time()
        self.submit_permissionless_block()
        self.advance_mock_time()
        self.submit_merged_block(payout_address)
        assert_equal(node.getblockcount(), starting_height + 4)

        self.log.info("ASERT getnetworkhashps -1 uses a one-block window for all lanes")
        for lane in ("all", "permissionless", "auxpow"):
            assert_equal(node.getnetworkhashps(-1, -1, lane), node.getnetworkhashps(1, -1, lane))

        self.log.info("Lane-specific getnetworkhashps values add up over the active-chain window")
        all_hashrate = node.getnetworkhashps(4, -1, "all")
        permissionless_hashrate = node.getnetworkhashps(4, -1, "permissionless")
        auxpow_hashrate = node.getnetworkhashps(4, -1, "auxpow")
        assert_approx(
            permissionless_hashrate + auxpow_hashrate,
            all_hashrate,
            vspan=max(abs(all_hashrate) * Decimal("1e-12"), Decimal("1e-12")),
        )

        self.log.info("getblocktemplate keeps the standard BIP22 fields after merged mining")
        gbt_after = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        for key in (
            "bits",
            "coinbaseaux",
            "coinbasevalue",
            "curtime",
            "height",
            "longpollid",
            "mutable",
            "noncerange",
            "previousblockhash",
            "rules",
            "transactions",
            "vbavailable",
            "vbrequired",
            "version",
        ):
            assert key in gbt_after

        self.log.info("Proposal-mode accepts a reconstructed createauxblock candidate")
        self.advance_mock_time()
        gbt_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        aux_template = node.createauxblock(payout_address)
        aux_block = reconstruct_createauxblock(
            aux_template=aux_template,
            gbt_template=gbt_template,
            payout_script_pubkey=payout_script,
        )
        assert_equal(aux_block.hash_hex, aux_template["hash"])
        proposal_auxpow = make_valid_auxpow_from_block(
            aux_block,
            chain_id=aux_template["chainid"],
            parent_time=self.mock_time,
            commitment_order=aux_template["commitmentorder"],
        )
        assert_equal(
            node.getblocktemplate(
                {
                    "data": serialize_auxpow_block(aux_block, proposal_auxpow),
                    "mode": "proposal",
                    "rules": ["segwit"],
                }
            ),
            None,
        )

        self.log.info("Proposal-mode still rejects wrong AuxPoW chain IDs")
        wrong_chain_block = reconstruct_createauxblock(
            aux_template=aux_template,
            gbt_template=gbt_template,
            payout_script_pubkey=payout_script,
        )
        wrong_chain_block.nVersion = make_version(
            chain_id=aux_template["chainid"] + 1,
            auxpow=True,
            version_bits=gbt_template["version"] & BLOCK_VERSION_SIGNAL_MASK,
        )
        wrong_chain_auxpow = make_valid_auxpow_from_block(
            wrong_chain_block,
            chain_id=aux_template["chainid"],
            parent_time=self.mock_time,
            commitment_order=aux_template["commitmentorder"],
        )
        assert_equal(
            node.getblocktemplate(
                {
                    "data": serialize_auxpow_block(wrong_chain_block, wrong_chain_auxpow),
                    "mode": "proposal",
                    "rules": ["segwit"],
                }
            ),
            "bad-auxpow-chainid",
        )

        self.log.info("Permissionless and AuxPoW templates stay synchronized after a merged-only streak")
        for _ in range(6):
            self.advance_mock_time(1)
            self.submit_merged_block(payout_address)
        gbt_after_streak = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        aux_after_streak = node.createauxblock(payout_address)
        assert_equal(aux_after_streak["previousblockhash"], gbt_after_streak["previousblockhash"])
        assert_equal(aux_after_streak["height"], gbt_after_streak["height"])

        self.advance_mock_time(1)
        self.submit_permissionless_block()
        assert_equal(node.getblockcount(), starting_height + 11)


if __name__ == "__main__":
    FeatureCadenceTest(__file__).main()
