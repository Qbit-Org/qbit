#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -v2pqtransport and -mlkemportable from settings.json.

settings.json keeps JSON types, so true there is a plain ON, not the double negative -noX=0 that
ArgsManager also stores as true. Each case starts a node with the setting in settings.json, the
command line and qbit.conf, checks the effective value on the startup line and over RPC, and
checks that the startup warning appears exactly when it describes the setting that wins:
precedence is the command line, then settings.json, then qbit.conf.
"""
import json
import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

STARTUP_LINE = re.compile(
    r"v2 pq: (enabled|disabled \(-v2pqtransport=0\)|disabled \(-v2transport=0\)) "
    r"arith=(x86_64-avx2|aarch64-neon|portable) keccak=(x86_64-avx2|aarch64|portable)\n")
ENABLED = "enabled"
DISABLED_PQ = "disabled (-v2pqtransport=0)"
DEFAULT = ["-v2transport=1"]

PQ_ON = "hybrid transport is ON"
PQ_OFF = "hybrid transport is OFF"
PORTABLE = "ML-KEM-1024 uses portable code"


def non_numeric_warning(value, read_as, effect, option="v2pqtransport"):
    return (f"Warning: -{option}={value} is not a number and was read as -{option}={read_as}: {effect}. "
            f"Use -{option}=1 or -{option}=0.")


def double_negative_warning(effect, option="v2pqtransport"):
    return (f"Warning: -no{option} was given 0 or a non-numeric value, so it was read as -{option}=1: {effect}. "
            f"Use -{option}=0 to switch it off.")


class PQSettingsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [DEFAULT]
        # -v2pqtransport is only what each case sets.
        self.v2pqtransport_from_run_mode = False

    def setup_network(self):
        self.setup_nodes()

    def write_settings(self, settings):
        node = self.nodes[0]
        with open(node.chain_path / "settings.json", "w", encoding="utf8") as f:
            json.dump(settings, f)

    def write_config_lines(self, lines):
        """Replace the lines this test adds to qbit.conf."""
        conf = self.nodes[0].datadir_path / "qbit.conf"
        text = conf.read_text(encoding="utf8").split("# feature_pq_settings\n")[0]
        if lines:
            text += "# feature_pq_settings\n" + "".join(f"{line}\n" for line in lines)
        conf.write_text(text, encoding="utf8")

    def check_start(self, *, settings, args=(), config=(), state, portable=None, expected_stderr=""):
        """Start the node with settings.json, args and the qbit.conf lines, check the effective
        hybrid transport state (and the ML-KEM-1024 code, if given) and stderr, and stop it."""
        node = self.nodes[0]
        self.write_settings(settings)
        self.write_config_lines(config)
        self.start_node(0, extra_args=DEFAULT + list(args))
        lines = STARTUP_LINE.findall(node.debug_log_path.read_text(encoding="utf-8"))
        assert lines, "no startup line"
        assert_equal(lines[-1][0], state)
        info = node.getpqtransportinfo()
        assert_equal(info["status"], "enabled" if state == ENABLED else "disabled_v2pqtransport")
        backends = (info["arith_backend"], info["keccak_backend"])
        assert_equal(lines[-1][1:], backends)
        if portable is True:
            assert_equal(backends, ("portable", "portable"))
        elif portable is False:
            assert_equal(backends, self.default_backends)
        self.stop_node(0, expected_stderr=expected_stderr)

    def run_test(self):
        node = self.nodes[0]
        info = node.getpqtransportinfo()
        self.default_backends = (info["arith_backend"], info["keccak_backend"])
        self.log.info(f"ML-KEM-1024 code by default: {self.default_backends}")
        self.stop_node(0)

        self.log.info("Test settings.json true and false take effect without a warning")
        self.check_start(settings={"v2pqtransport": True}, state=ENABLED)
        self.check_start(settings={"v2pqtransport": False}, state=DISABLED_PQ)
        self.check_start(settings={"mlkemportable": True}, state=ENABLED, portable=True)
        self.check_start(settings={"mlkemportable": False}, state=ENABLED, portable=False)
        self.check_start(settings={"v2pqtransport": False, "mlkemportable": True}, state=DISABLED_PQ, portable=True)

        self.log.info("Test a settings.json string is read as on the command line")
        self.check_start(settings={"v2pqtransport": "true"}, state=DISABLED_PQ,
                         expected_stderr=non_numeric_warning("true", 0, PQ_OFF))
        self.check_start(settings={"v2pqtransport": "1"}, state=ENABLED)

        self.log.info("Test a double negative on the command line or in qbit.conf still warns")
        self.check_start(settings={}, args=["-nov2pqtransport=0"], state=ENABLED,
                         expected_stderr=double_negative_warning(PQ_ON))
        self.check_start(settings={}, config=["nov2pqtransport=0"], state=ENABLED,
                         expected_stderr=double_negative_warning(PQ_ON))
        self.check_start(settings={}, args=["-nomlkemportable=0"], state=ENABLED, portable=True,
                         expected_stderr=double_negative_warning(PORTABLE, "mlkemportable"))
        self.check_start(settings={}, config=["nomlkemportable=0"], state=ENABLED, portable=True,
                         expected_stderr=double_negative_warning(PORTABLE, "mlkemportable"))

        self.log.info("Test a command-line double negative overrides settings.json and warns")
        self.check_start(settings={"v2pqtransport": True}, args=["-nov2pqtransport=0"], state=ENABLED,
                         expected_stderr=double_negative_warning(PQ_ON))
        self.check_start(settings={"v2pqtransport": False}, args=["-nov2pqtransport=0"], state=ENABLED,
                         expected_stderr=double_negative_warning(PQ_ON))
        self.check_start(settings={"mlkemportable": True}, args=["-nomlkemportable=0"], state=ENABLED, portable=True,
                         expected_stderr=double_negative_warning(PORTABLE, "mlkemportable"))

        self.log.info("Test the command line overrides settings.json true without a warning")
        self.check_start(settings={"v2pqtransport": True}, args=["-nov2pqtransport"], state=DISABLED_PQ)
        self.check_start(settings={"v2pqtransport": True}, args=["-v2pqtransport=0"], state=DISABLED_PQ)

        self.log.info("Test settings.json overrides a double negative in qbit.conf, which then doesn't warn")
        self.check_start(settings={"v2pqtransport": True}, config=["nov2pqtransport=0"], state=ENABLED)
        self.check_start(settings={"v2pqtransport": False}, config=["nov2pqtransport=0"], state=DISABLED_PQ)
        self.check_start(settings={"mlkemportable": False}, config=["nomlkemportable=0"], state=ENABLED, portable=False)

        self.write_config_lines([])
        self.write_settings({})


if __name__ == '__main__':
    PQSettingsTest(__file__).main()
