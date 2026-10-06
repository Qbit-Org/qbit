#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the hybrid post-quantum v2 transport's options and startup line (#184 part 6).

- test_configuration: -v2pqtransport on the command line, in qbit.conf, negated and
  across restarts, observed on a live connection between two nodes; the warnings for a
  contradictory or non-numeric setting; -help; the three startup lines.
- test_portable_options: -mlkemportable and -test=mlkem_portable make the startup line
  report portable code; the test options are regtest only and print nothing to stderr.
"""
import re
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    append_config,
    assert_equal,
    write_config,
)

# The startup line: the state, then the active ML-KEM-1024 backends.
STARTUP_LINE = re.compile(
    r"v2 pq: (enabled|disabled \(-v2pqtransport=0\)|disabled \(-v2transport=0\)) "
    r"arith=(x86_64-avx2|aarch64-neon|portable) keccak=(x86_64-avx2|aarch64|portable)\n")
ENABLED = "enabled"
DISABLED_PQ = "disabled (-v2pqtransport=0)"
DISABLED_V2 = "disabled (-v2transport=0)"
CONTRADICTION_WARNING = ("Warning: -v2pqtransport=1 has no effect because -v2transport=0. "
                         "Set -v2transport=1 to use hybrid post-quantum v2 transport.")
TEST_OPTION_ERROR = "Error: -test=<option> can only be used with regtest"


def non_numeric_warning(value, read_as):
    return (f"Warning: -v2pqtransport={value} is not a number, so it is read as -v2pqtransport={read_as}. "
            "Set -v2pqtransport=1 or -v2pqtransport=0.")


class PQTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Whatever the suite's transport flag, these nodes use v2.
        self.extra_args = [["-v2transport=1"], ["-v2transport=1"]]

    def setup_network(self):
        # Connections are made by the tests.
        self.setup_nodes()

    def startup_line(self, node):
        """The state and backends of the node's latest startup line."""
        lines = STARTUP_LINE.findall(node.debug_log_path.read_text(encoding="utf-8"))
        assert lines, "no startup line"
        return lines[-1]

    def check_start(self, args, state, *, expected_stderr=""):
        """Start node 0 with args, check its startup line's state and stderr, and stop it."""
        self.start_node(0, extra_args=args)
        assert_equal(self.startup_line(self.nodes[0])[0], state)
        self.stop_node(0, expected_stderr=expected_stderr)

    def check_connection(self, *, hybrid):
        """Connect node 0 to node 1, check whether both switched to hybrid keys, and disconnect."""
        initiator = ["v2 pq: switched role=initiator"]
        responder = ["v2 pq: switched role=responder"]
        with self.nodes[0].assert_debug_log(initiator if hybrid else [], unexpected_msgs=[] if hybrid else initiator):
            with self.nodes[1].assert_debug_log(responder if hybrid else [], unexpected_msgs=[] if hybrid else responder):
                self.connect_nodes(0, 1)
        self.disconnect_nodes(0, 1)

    def test_configuration(self):
        node0, node1 = self.nodes

        self.log.info("Test the switch is off by default")
        assert_equal(self.startup_line(node0)[0], DISABLED_PQ)
        assert_equal(self.startup_line(node1)[0], DISABLED_PQ)
        self.check_connection(hybrid=False)

        self.log.info("Test -v2pqtransport=1 on one side only keeps the ECDH keys")
        with node0.assert_debug_log(["v2 pq: legacy_peer reason=no_features role=initiator"]):
            self.restart_node(0, extra_args=["-v2transport=1", "-v2pqtransport=1"])
            assert_equal(self.startup_line(node0)[0], ENABLED)
            self.check_connection(hybrid=False)

        self.log.info("Test v2pqtransport=1 in qbit.conf, with the command line's on the other side")
        append_config(node1.datadir_path, ["v2pqtransport=1"])
        self.restart_node(1)
        assert_equal(self.startup_line(node1)[0], ENABLED)
        self.check_connection(hybrid=True)

        self.log.info("Test -nov2pqtransport overrides qbit.conf")
        with node0.assert_debug_log(["v2 pq: legacy_peer reason=no_features role=initiator"]):
            self.restart_node(1, extra_args=["-v2transport=1", "-nov2pqtransport"])
            assert_equal(self.startup_line(node1)[0], DISABLED_PQ)
            self.check_connection(hybrid=False)

        self.log.info("Test a restart without it switches back on")
        self.restart_node(1)
        assert_equal(self.startup_line(node1)[0], ENABLED)
        self.check_connection(hybrid=True)
        node1.replace_in_config([("v2pqtransport=1\n", "")])
        self.restart_node(1)
        assert_equal(self.startup_line(node1)[0], DISABLED_PQ)

        self.log.info("Test an explicit -v2pqtransport=1 with -v2transport=0 warns, and has no effect")
        self.stop_node(0)
        self.check_start(["-v2transport=0", "-v2pqtransport=1"], DISABLED_V2, expected_stderr=CONTRADICTION_WARNING)
        # An empty value means 1.
        self.check_start(["-v2transport=0", "-v2pqtransport"], DISABLED_V2, expected_stderr=CONTRADICTION_WARNING)

        self.log.info("Test an explicit -v2pqtransport=0, or -v2transport=0 alone, doesn't warn")
        self.check_start(["-v2transport=0", "-v2pqtransport=0"], DISABLED_V2)
        self.check_start(["-v2transport=0", "-nov2pqtransport"], DISABLED_V2)
        self.check_start(["-v2transport=0"], DISABLED_V2)

        self.log.info("Test a non-numeric -v2pqtransport warns with the value it is read as")
        self.check_start(["-v2transport=1", "-v2pqtransport=true"], DISABLED_PQ, expected_stderr=non_numeric_warning("true", 0))
        self.check_start(["-v2transport=1", "-v2pqtransport=1abc"], ENABLED, expected_stderr=non_numeric_warning("1abc", 1))
        # Out of range: read as 1, the saturated value.
        self.check_start(["-v2transport=1", "-v2pqtransport=99999999999"], ENABLED,
                         expected_stderr=non_numeric_warning("99999999999", 1))
        # Whitespace and a sign are allowed, as InterpretBool reads them.
        self.check_start(["-v2transport=1", "-v2pqtransport=+1"], ENABLED)
        self.check_start(["-v2transport=1", "-v2pqtransport=-1"], ENABLED)

        self.log.info("Test -help lists -v2pqtransport, and -help-debug the hidden options")
        help_text = subprocess.run(node0.binaries.node_argv() + ["-help"], capture_output=True, text=True, check=True).stdout
        assert "  -v2pqtransport\n" in help_text
        assert "-mlkemportable" not in help_text
        help_debug = subprocess.run(node0.binaries.node_argv() + ["-help-debug"], capture_output=True, text=True, check=True).stdout
        assert "  -mlkemportable\n" in help_debug
        for option in ["pq_fail_first_packet (", "mlkem_portable ("]:
            assert option in help_debug

        self.start_node(0)

    def test_portable_options(self):
        node0 = self.nodes[0]

        self.log.info("Test -mlkemportable and -test=mlkem_portable select portable code")
        for option in ["-mlkemportable", "-test=mlkem_portable"]:
            self.restart_node(0, extra_args=["-v2transport=1", option])
            assert_equal(self.startup_line(node0)[1:], ("portable", "portable"))

        self.log.info("Test -test=pq_fail_first_packet starts cleanly")
        self.restart_node(0, extra_args=["-v2transport=1", "-v2pqtransport=1", "-test=pq_fail_first_packet"])
        assert_equal(self.startup_line(node0)[0], ENABLED)
        # Nothing is printed to stderr (checked at stop).
        self.stop_node(0)

        self.log.info("Test the test options are regtest only, and -mlkemportable works on any chain")
        conf_file = node0.datadir_path / "qbit.conf"
        write_config(conf_file, n=0, chain="signet")
        node0.chain = "signet"
        for option in ["-test=mlkem_portable", "-test=pq_fail_first_packet"]:
            node0.assert_start_raises_init_error(extra_args=[option], expected_msg=TEST_OPTION_ERROR)
        self.start_node(0, extra_args=["-v2transport=1", "-mlkemportable"])
        assert_equal(self.startup_line(node0), (DISABLED_PQ, "portable", "portable"))
        self.stop_node(0)
        write_config(conf_file, n=0, chain="regtest")
        node0.chain = "regtest"
        self.start_node(0)

    def run_test(self):
        self.test_configuration()
        self.test_portable_options()


if __name__ == '__main__':
    PQTransportTest(__file__).main()
