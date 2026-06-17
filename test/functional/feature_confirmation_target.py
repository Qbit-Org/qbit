#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getconfirmationtarget RPC."""

from decimal import Decimal

from test_framework.auxpow import make_valid_auxpow_from_template
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import getnewdestination


class ConfirmationTargetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.extra_args = [["-asert"]] * self.num_nodes

    def set_all_mocktimes(self, mock_time):
        for node in self.nodes:
            node.setmocktime(mock_time)

    def submit_merged_block(self, node, payout_address):
        self.mock_time += 1
        self.set_all_mocktimes(self.mock_time)
        aux_template = node.createauxblock(payout_address)
        auxpow = make_valid_auxpow_from_template(aux_template, parent_time=self.mock_time)
        assert_equal(node.submitauxblock(aux_template["hash"], auxpow.to_hex()), None)

    def run_test(self):
        node = self.nodes[0]
        _, _, payout_address = getnewdestination("bech32")

        self.log.info("AuxPoW-only chainwork is excluded from native confirmation security")
        self.mock_time = node.getblockheader(node.getbestblockhash())["time"]
        for _ in range(3):
            self.submit_merged_block(node, payout_address)
        self.sync_all()

        observed_aux_only = node.getconfirmationtarget(100000000, "high")
        assert "current_hashrate" not in observed_aux_only
        assert_equal(observed_aux_only["permissionless_hashrate"], 0)
        assert_greater_than(observed_aux_only["auxpow_hashrate"], 0)
        assert_equal(observed_aux_only["total_observed_hashrate"], observed_aux_only["auxpow_hashrate"])
        assert_equal(observed_aux_only["model"]["hashrate_source"], "observed_chainwork")
        assert_equal(observed_aux_only["model"]["auxpow_blocks_in_window"], 3)
        assert_approx(
            observed_aux_only["model"]["security_per_confirmation"],
            vexp=(
                Decimal(observed_aux_only["model"]["block_time_seconds"]) / Decimal(600)
                * (observed_aux_only["total_observed_hashrate"] / observed_aux_only["model"]["btc_hashrate"])
            ),
            vspan=1e-12,
        )

        aux_only = node.getconfirmationtarget(100000000, "high", 0.5, 7e20)
        assert "current_hashrate" not in aux_only
        assert_equal(aux_only["permissionless_hashrate"], 0)
        assert_greater_than(aux_only["auxpow_hashrate"], 0)
        assert_equal(aux_only["total_observed_hashrate"], aux_only["auxpow_hashrate"])
        assert_equal(aux_only["model"]["hashrate_source"], "override_merge_mining_pct")
        assert_approx(
            aux_only["model"]["security_per_confirmation"],
            vexp=aux_only["model"]["cadence_merged_fraction"] * aux_only["model"]["merge_mining_pct"],
            vspan=1e-12,
        )

        self.set_all_mocktimes(0)

        self.log.info("Mine permissionless blocks so native hashrate has data")
        self.generate(node, 200)
        self.sync_all()

        self.log.info("Basic call with default parameters")
        result = node.getconfirmationtarget(100000000)
        assert_equal(result["security_level"], "medium")
        assert_greater_than(result["required_confirmations"], 0)
        assert_greater_than(result["required_minutes"], 0)
        assert_greater_than_or_equal(result["equivalent_btc_confirmations"], 0)
        assert "current_hashrate" not in result
        assert_greater_than_or_equal(result["permissionless_hashrate"], 0)
        assert_greater_than_or_equal(result["auxpow_hashrate"], 0)
        assert_equal(result["total_observed_hashrate"], result["permissionless_hashrate"] + result["auxpow_hashrate"])
        assert_greater_than_or_equal(result["orphan_rate"], 0)
        assert_equal(result["value_qbt"], 1.0)

        # Model sub-object should be present.
        model = result["model"]
        assert_equal(model["btc_target_confirmations"], 3)
        assert_equal(model["block_time_seconds"], 60)
        assert_greater_than_or_equal(model["orphan_rate_penalty"], 1.0)
        assert_greater_than_or_equal(model["cadence_merged_fraction"], 0)
        assert_equal(model["hashrate_source"], "fallback_merge_mining_pct")
        assert_equal(model["auxpow_blocks_in_window"], 0)

        self.log.info("Security levels produce increasing confirmations")
        low = node.getconfirmationtarget(100000000, "low", 0.3)
        med = node.getconfirmationtarget(100000000, "medium", 0.3)
        high = node.getconfirmationtarget(100000000, "high", 0.3)
        maximum = node.getconfirmationtarget(100000000, "maximum", 0.3)

        assert_equal(low["security_level"], "low")
        assert_equal(med["security_level"], "medium")
        assert_equal(high["security_level"], "high")
        assert_equal(maximum["security_level"], "maximum")

        assert_greater_than(med["required_confirmations"], low["required_confirmations"])
        assert_greater_than(high["required_confirmations"], med["required_confirmations"])
        assert_greater_than(maximum["required_confirmations"], high["required_confirmations"])

        self.log.info("Higher merge mining reduces required confirmations")
        low_mm = node.getconfirmationtarget(100000000, "high", 0.05)
        high_mm = node.getconfirmationtarget(100000000, "high", 0.50)
        assert_greater_than(low_mm["required_confirmations"], high_mm["required_confirmations"])

        self.log.info("Value is informational (same confs for different values)")
        r1 = node.getconfirmationtarget(100000000, "high", 0.5)
        r2 = node.getconfirmationtarget(1000000000, "high", 0.5)
        assert_equal(r1["required_confirmations"], r2["required_confirmations"])
        assert_equal(r1["value_qbt"], 1.0)
        assert_equal(r2["value_qbt"], 10.0)

        self.log.info("Model parameters are consistent")
        result = node.getconfirmationtarget(100000000, "high", 0.5, 7e20)
        model = result["model"]
        assert_equal(model["btc_target_confirmations"], 6)
        assert_approx(model["cadence_merged_fraction"], vexp=75 / 375, vspan=0.0001)
        assert_equal(model["hashrate_source"], "override_merge_mining_pct")
        expected_security = (
            model["cadence_merged_fraction"] * model["merge_mining_pct"] +
            (1 - model["cadence_merged_fraction"]) * (result["permissionless_hashrate"] / model["btc_hashrate"])
        )
        assert_approx(model["security_per_confirmation"], vexp=expected_security, vspan=1e-9)

        self.log.info("Zero merge mining gives high confirmation count")
        result = node.getconfirmationtarget(100000000, "high", 0.0)
        assert_greater_than(result["required_confirmations"], 50)

        self.log.info("required_minutes matches required_confirmations * block_time / 60")
        result = node.getconfirmationtarget(100000000, "high", 0.5)
        expected_minutes = result["required_confirmations"] * result["model"]["block_time_seconds"] / 60.0
        assert_equal(result["required_minutes"], expected_minutes)

        self.log.info("Second node returns same results for same parameters")
        r0 = node.getconfirmationtarget(100000000, "high", 0.5, 7e20)
        r1 = self.nodes[1].getconfirmationtarget(100000000, "high", 0.5, 7e20)
        assert_equal(r0["required_confirmations"], r1["required_confirmations"])

        self.log.info("Invalid parameters are rejected")
        assert_raises_rpc_error(-8, "value_satoshis must be non-negative",
                                node.getconfirmationtarget, -1)
        assert_raises_rpc_error(-8, "security_level must be",
                                node.getconfirmationtarget, 100000000, "invalid")
        assert_raises_rpc_error(-8, "merge_mining_pct must be between",
                                node.getconfirmationtarget, 100000000, "medium", -0.1)
        assert_raises_rpc_error(-8, "merge_mining_pct must be between",
                                node.getconfirmationtarget, 100000000, "medium", 1.1)
        assert_raises_rpc_error(-8, "btc_hashrate must be positive",
                                node.getconfirmationtarget, 100000000, "medium", 0.5, -1)
        assert_raises_rpc_error(-8, "btc_hashrate must be positive",
                                node.getconfirmationtarget, 100000000, "medium", 0.5, 0)

        self.log.info("Orphan rate affects result after creating stale blocks")
        # Create stale blocks to increase orphan rate (requires 4-node split).
        self.split_network()
        self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[:2]))
        self.generate(self.nodes[2], 2, sync_fun=lambda: self.sync_all(self.nodes[2:]))
        self.join_network()
        self.sync_all()

        metrics = node.getorphanmetrics()
        result_after = node.getconfirmationtarget(100000000, "high", 0.5, 7e20)
        # Orphan rate should be reflected in the result.
        assert_equal(result_after["orphan_rate"], metrics["orphan_rate"])


if __name__ == '__main__':
    ConfirmationTargetTest(__file__).main()
