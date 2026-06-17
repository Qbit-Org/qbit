#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getorphanmetrics RPC and stale block accounting."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)


class OrphanMetricsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def assert_zero_metrics(self, node):
        metrics = node.getorphanmetrics()
        assert_equal(metrics["window_blocks"], 1000)
        assert_equal(metrics["window_stale"], 0)
        assert_equal(metrics["orphan_rate"], 0)
        assert_equal(metrics["lifetime_stale_blocks"], 0)
        assert_equal(metrics["lifetime_reorgs"], 0)
        assert_equal(metrics["deepest_reorg"], 0)
        assert_equal(metrics["last_stale_height"], -1)
        assert_equal(metrics["last_stale_time"], 0)
        assert_equal(metrics["persistent_stale_tip_count"], 0)
        assert_equal(metrics["alert"], False)
        assert_greater_than_or_equal(metrics["window_total"], 0)
        assert_greater_than_or_equal(metrics["lifetime_blocks_connected"], 0)

    def count_non_active_tips(self, node):
        return sum(1 for tip in node.getchaintips() if tip["status"] != "active")

    def assert_monotonic(self, previous, current):
        assert_greater_than_or_equal(current["lifetime_blocks_connected"], previous["lifetime_blocks_connected"])
        assert_greater_than_or_equal(current["lifetime_stale_blocks"], previous["lifetime_stale_blocks"])
        assert_greater_than_or_equal(current["lifetime_reorgs"], previous["lifetime_reorgs"])
        assert_greater_than_or_equal(current["deepest_reorg"], previous["deepest_reorg"])

    def run_test(self):
        self.log.info("Check baseline metrics are empty")
        for node in self.nodes:
            self.assert_zero_metrics(node)

        self.log.info("Create a single stale block via network split and rejoin")
        self.split_network()
        self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[:2]))
        self.generate(self.nodes[2], 2, sync_fun=lambda: self.sync_all(self.nodes[2:]))
        with self.nodes[0].assert_debug_log(expected_msgs=["Stale block detected: height="], timeout=10):
            self.join_network()
        self.sync_all()

        first = self.nodes[0].getorphanmetrics()
        assert_equal(first["lifetime_stale_blocks"], 1)
        assert_greater_than_or_equal(first["lifetime_reorgs"], 1)
        assert_greater_than_or_equal(first["deepest_reorg"], 1)

        self.log.info("Create a deeper reorg and verify counters increase")
        self.split_network()
        self.generate(self.nodes[0], 3, sync_fun=lambda: self.sync_all(self.nodes[:2]))
        self.generate(self.nodes[2], 5, sync_fun=lambda: self.sync_all(self.nodes[2:]))
        stale_tip_height = self.nodes[0].getblockcount()
        self.join_network()
        self.sync_all()

        second = self.nodes[0].getorphanmetrics()
        self.assert_monotonic(first, second)
        assert_equal(second["lifetime_stale_blocks"], first["lifetime_stale_blocks"] + 3)
        assert_greater_than_or_equal(second["lifetime_reorgs"], first["lifetime_reorgs"] + 1)
        assert_greater_than_or_equal(second["deepest_reorg"], 3)
        assert_equal(second["last_stale_height"], stale_tip_height)

        self.log.info("Create another reorg to verify counters stay monotonic")
        self.split_network()
        self.generate(self.nodes[0], 2, sync_fun=lambda: self.sync_all(self.nodes[:2]))
        self.generate(self.nodes[2], 4, sync_fun=lambda: self.sync_all(self.nodes[2:]))
        self.join_network()
        self.sync_all()
        third = self.nodes[0].getorphanmetrics()
        self.assert_monotonic(second, third)
        assert_greater_than_or_equal(third["lifetime_stale_blocks"], second["lifetime_stale_blocks"] + 2)

        self.log.info("Mine clean blocks and verify rolling windows show no stale activity")
        self.generate(self.nodes[0], 50)
        self.sync_all()
        window_10 = self.nodes[0].getorphanmetrics(10)
        assert_equal(window_10["window_blocks"], 10)
        assert_equal(window_10["window_total"], 10)
        assert_equal(window_10["window_stale"], 0)
        assert_equal(window_10["orphan_rate"], 0)

        self.log.info("Custom window parameter should only affect windowed fields")
        window_5 = self.nodes[0].getorphanmetrics(5)
        window_100 = self.nodes[0].getorphanmetrics(100)
        assert_equal(window_5["window_blocks"], 5)
        assert_equal(window_100["window_blocks"], 100)
        assert_equal(window_5["lifetime_blocks_connected"], window_100["lifetime_blocks_connected"])
        assert_equal(window_5["lifetime_stale_blocks"], window_100["lifetime_stale_blocks"])
        assert_equal(window_5["lifetime_reorgs"], window_100["lifetime_reorgs"])
        assert_equal(window_5["deepest_reorg"], window_100["deepest_reorg"])

        self.log.info("persistent_stale_tip_count should match getchaintips non-active tips")
        metrics = self.nodes[0].getorphanmetrics()
        assert_equal(metrics["persistent_stale_tip_count"], self.count_non_active_tips(self.nodes[0]))

        self.log.info("Restart should reset in-memory lifetime counters")
        self.restart_node(0)
        reset = self.nodes[0].getorphanmetrics()
        assert_equal(reset["window_stale"], 0)
        assert_equal(reset["lifetime_stale_blocks"], 0)
        assert_equal(reset["lifetime_reorgs"], 0)
        assert_equal(reset["deepest_reorg"], 0)
        assert_equal(reset["last_stale_height"], -1)
        assert_equal(reset["last_stale_time"], 0)
        assert_equal(reset["alert"], False)
        assert_equal(reset["persistent_stale_tip_count"], self.count_non_active_tips(self.nodes[0]))

        self.log.info("Invalid window parameters should fail")
        assert_raises_rpc_error(-8, "window must be between 1 and 10000", self.nodes[0].getorphanmetrics, 0)
        assert_raises_rpc_error(-8, "window must be between 1 and 10000", self.nodes[0].getorphanmetrics, -1)
        assert_raises_rpc_error(-8, "window must be between 1 and 10000", self.nodes[0].getorphanmetrics, 100000)


if __name__ == '__main__':
    OrphanMetricsTest(__file__).main()
