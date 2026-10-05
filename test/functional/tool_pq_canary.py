#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test contrib/pq-canary against real nodes.

Runs the evaluator's test suite, then the real pq-canary-sample.sh through
qbit-cli against the node under test and, when previous releases are present,
against a qbit v1.0.0 node, and checks what it records: NA, never 0, for
whatever a node does not report, a real 0 kept as 0, sample_ok=1 when the
required calls answered, and an unknown verdict from the evaluator for
evidence that does not cover the canary.
"""
import csv
import os
from pathlib import Path
import subprocess
import sys

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import release_info
from test_framework.util import assert_equal, p2p_port, rpc_port

V1_0_0 = 10000
NA = "NA"
# Columns that come from getpqtransportinfo.
PQ_COLUMNS = ["pq_enabled", "instance_id", "arith_backend", "keccak_backend", "since",
              "in_switched", "out_switched", "load_shedding_active", "in_ring_last_sequence", "out_ring_dropped"]


class PQCanaryToolTest(BitcoinTestFramework):
    def set_test_params(self):
        v1_0_0_bin = Path(self.options.previous_releases_path) / release_info(V1_0_0).tag / "bin"
        self.with_v1_0_0 = self.options.prev_releases and v1_0_0_bin.is_dir()
        self.num_nodes = 2 if self.with_v1_0_0 else 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()  # the sampler is a bash script
        self.skip_if_no_cli()

    def setup_network(self):
        # Unconnected, so the first samples see no peers at all.
        self.add_nodes(self.num_nodes, versions=[None, V1_0_0][:self.num_nodes])
        self.start_nodes()

    def run_test(self):
        self.tool_dir = Path(self.config["environment"]["SRCDIR"]) / "contrib" / "pq-canary"
        self.out = Path(self.options.tmpdir) / "canary"

        self.log.info("The evaluator's test suite passes")
        suite = subprocess.run([sys.executable, str(self.tool_dir / "test" / "test_pq_canary.py")], capture_output=True, text=True)
        assert_equal(suite.returncode, 0)

        self.test_node_under_test()
        if self.with_v1_0_0:
            self.test_v1_0_0()
        else:
            self.log.info("Skipping the v1.0.0 sample: the v1.0.0 release is not downloaded")
        self.test_rpc_outage()
        self.test_evaluator_reads_the_samples()

    def cli_argv(self, node):
        return node.binaries.rpc_argv() + [f"-datadir={node.datadir_path}"]

    def sample(self, host, argv, *, pinned=None, expect_status=0):
        args = ["bash", str(self.tool_dir / "pq-canary-sample.sh"), "--host", host, "--out", str(self.out / host)]
        if pinned is not None:
            args += ["--pinned", pinned]
        result = subprocess.run(args + ["--"] + argv, capture_output=True, text=True)
        assert_equal(result.returncode, expect_status)
        with open(self.out / host / "samples.csv", encoding="utf8", newline="") as samples:
            return list(csv.DictReader(samples))[-1]

    def check_pq_columns(self, node, host, row):
        """NA exactly when the node lacks getpqtransportinfo or connections_pq."""
        try:
            node.getpqtransportinfo()
            has_pq = True
        except JSONRPCException as e:
            assert_equal(e.error["code"], -32601)
            has_pq = False
        for column in PQ_COLUMNS:
            assert_equal(row[column] == NA, not has_pq)
        assert_equal(row["connections_pq"] == NA, "connections_pq" not in node.getnetworkinfo())
        assert_equal((self.out / host / "failures.jsonl").exists(), has_pq)

    def test_node_under_test(self):
        node = self.nodes[0]
        self.log.info("Sample the node under test: a real zero stays zero")
        row = self.sample("current", self.cli_argv(node))
        assert_equal(row["sample_ok"], "1")
        assert_equal(row["version"], str(node.getnetworkinfo()["version"]))
        assert_equal(row["connections_in"], "0")
        assert int(row["uptime"]) >= 0
        self.check_pq_columns(node, "current", row)
        assert_equal(row["pinned_present"], NA)  # not a pool node

        self.log.info("As a pool node, a pinned peer that is not connected is 0, not NA")
        row = self.sample("current-pool", self.cli_argv(node), pinned=f"127.0.0.1:{p2p_port(1)}")
        assert_equal((row["sample_ok"], row["pinned_present"], row["pinned_connection_type"]), ("1", "0", NA))

    def test_v1_0_0(self):
        self.log.info("Sample a v1.0.0 node: NA for the new fields, sample_ok=1")
        old = self.nodes[1]
        assert_equal(old.getnetworkinfo()["version"], V1_0_0)
        row = self.sample("v1.0.0", self.cli_argv(old))
        assert_equal(row["sample_ok"], "1")
        assert_equal(row["version"], str(V1_0_0))
        assert_equal(row["connections_in"], "0")
        assert_equal(row["connections_pq"], NA)
        for column in PQ_COLUMNS:
            assert_equal(row[column], NA)
        assert not (self.out / "v1.0.0" / "failures.jsonl").exists()

        self.log.info("The node under test pinned to v1.0.0 records the manual link without transport_pq")
        node = self.nodes[0]
        pinned = f"127.0.0.1:{p2p_port(1)}"
        node.addnode(pinned, "add")
        self.wait_until(lambda: any(peer["addr"] == pinned and peer["connection_type"] == "manual" for peer in node.getpeerinfo()))
        row = self.sample("current-pool", self.cli_argv(node), pinned=pinned)
        assert_equal((row["sample_ok"], row["pinned_present"], row["pinned_connection_type"]), ("1", "1", "manual"))
        peer = next(peer for peer in node.getpeerinfo() if peer["addr"] == pinned)
        assert_equal(row["pinned_transport_pq"] == NA, "transport_pq" not in peer)

    def test_rpc_outage(self):
        self.log.info("An unreachable node gives sample_ok=0 and NA, never 0")
        # No node listens on this RPC port.
        argv = self.cli_argv(self.nodes[0]) + [f"-rpcport={rpc_port(5)}", "-rpcclienttimeout=5"]
        row = self.sample("current", argv, expect_status=2)
        assert_equal(row["sample_ok"], "0")
        for column in ("uptime", "version", "connections_in", "connections_pq", "pq_enabled"):
            assert_equal(row[column], NA)

    def test_evaluator_reads_the_samples(self):
        self.log.info("The evaluator prints every figure, unknown for evidence that does not cover a canary")
        result = subprocess.run([sys.executable, str(self.tool_dir / "pq-canary-eval.py"), "--canary-start", "0",
                                 "--pool", str(self.out / "current-pool" / "samples.csv"),
                                 "--archive", str(self.out / "current" / "samples.csv")],
                                capture_output=True, text=True)
        assert_equal(result.returncode, 3)
        figures = [line for line in result.stdout.splitlines() if line.split(" ", 1)[0] in ("pass", "fail", "unknown")]
        assert_equal(len(figures), 4)
        assert result.stdout.rstrip().endswith("canary verdict (figures 1, 2 and 4): unknown"), result.stdout
        assert os.path.getsize(self.out / "current" / "samples.csv") > 0


if __name__ == '__main__':
    PQCanaryToolTest(__file__).main()
