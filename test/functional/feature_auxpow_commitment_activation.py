#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test AuxPoW commitment byte-order activation."""

from test_framework.auxpow import make_valid_auxpow_from_template
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
    getnewdestination,
)


AUXPOW_COMMITMENT_ACTIVATION_HEIGHT = 110


class FeatureAuxPowCommitmentActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-asert",
            "-p2mronly=1",
            f"-testactivationheight=auxpowcommitment@{AUXPOW_COMMITMENT_ACTIVATION_HEIGHT}",
        ]]

    def advance_mock_time(self, seconds=600):
        self.mock_time += seconds
        self.nodes[0].setmocktime(self.mock_time)

    def assert_template_commitment(self, aux_template, *, height, commitment_order):
        node = self.nodes[0]
        assert_equal(aux_template["height"], height)
        assert_equal(aux_template["commitmentactivationheight"], AUXPOW_COMMITMENT_ACTIVATION_HEIGHT)
        assert_equal(aux_template["commitmentorder"], commitment_order)
        assert_equal(aux_template["previousblockhash"], node.getbestblockhash())

    def submit_auxpow(self, aux_template, *, commitment_order):
        auxpow = make_valid_auxpow_from_template(
            aux_template,
            parent_time=self.mock_time,
            commitment_order=commitment_order,
        )
        return self.nodes[0].submitauxblock(aux_template["hash"], auxpow.to_hex())

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_P2MR_OP_TRUE)
        self.generate(self.wallet, AUXPOW_COMMITMENT_ACTIVATION_HEIGHT - 2)

        self.mock_time = node.getblockheader(node.getbestblockhash())["time"] + 600
        node.setmocktime(self.mock_time)
        _, _, payout_address = getnewdestination("p2mr")

        self.log.info("Pre-activation AuxPoW templates require internal uint256 byte order")
        pre_activation = node.createauxblock(payout_address)
        self.assert_template_commitment(
            pre_activation,
            height=AUXPOW_COMMITMENT_ACTIVATION_HEIGHT - 1,
            commitment_order="internal",
        )
        assert_equal(self.submit_auxpow(pre_activation, commitment_order="display"), "bad-auxpow-commitment")
        assert_equal(node.getblockcount(), AUXPOW_COMMITMENT_ACTIVATION_HEIGHT - 2)
        assert_equal(self.submit_auxpow(pre_activation, commitment_order="internal"), None)
        assert_equal(node.getblockcount(), AUXPOW_COMMITMENT_ACTIVATION_HEIGHT - 1)

        self.log.info("Activation height AuxPoW templates require display byte order")
        self.advance_mock_time()
        activation = node.createauxblock(payout_address)
        self.assert_template_commitment(
            activation,
            height=AUXPOW_COMMITMENT_ACTIVATION_HEIGHT,
            commitment_order="display",
        )
        assert_equal(self.submit_auxpow(activation, commitment_order="internal"), "bad-auxpow-commitment")
        assert_equal(node.getblockcount(), AUXPOW_COMMITMENT_ACTIVATION_HEIGHT - 1)
        assert_equal(self.submit_auxpow(activation, commitment_order="display"), None)
        assert_equal(node.getblockcount(), AUXPOW_COMMITMENT_ACTIVATION_HEIGHT)


if __name__ == "__main__":
    FeatureAuxPowCommitmentActivationTest(__file__).main()
