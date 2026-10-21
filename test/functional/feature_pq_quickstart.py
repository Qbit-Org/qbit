#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the operator guide of hybrid post-quantum v2 transport, doc/user/network/pq-transport.md.

- test_quickstart: the guide's three quick-start steps run as written, in one bash shell, with this
  build's qbitd and qbit-cli first on PATH. Only the data directory and the four ports are replaced,
  by the framework's. Each step must print what the guide shows, where numbers, dates and the
  ML-KEM-1024 backend names may differ, and nothing on stderr. The two nodes are stopped and their
  data removed even when a step fails.
- test_switch: the qbit.conf line the guide gives switches the feature on, as the startup line and
  getpqtransportinfo show, and -nov2pqtransport on the command line overrides it; the startup
  warnings the guide shows are what qbitd prints.
- test_doc_tokens: the interface names the PQ transport docs quote exist, with options checked
  against this build's -help and -help-debug output (test/lint/lint-pq-doc-tokens.py).
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    append_config,
    assert_equal,
    p2p_port,
    rpc_port,
)

GUIDE = Path("doc") / "user" / "network" / "pq-transport.md"
LINT = Path("test") / "lint" / "lint-pq-doc-tokens.py"
STEPS = ("step 1", "step 2", "step 3")
# A step or its output: the marker comment, then a fenced code block.
BLOCK = re.compile(r"<!-- quickstart: (step \d(?: output)?) -->\n```[a-z]*\n(.*?)\n```", re.DOTALL)
# The guide's data directory and ports, and the nodes of this test whose ports replace them.
GUIDE_DATADIR_LINE = "Q=~/qbit-pq-quickstart"
GUIDE_PORTS = {"a": (18501, 18502), "b": (18511, 18512)}
PORT_NODES = {"a": 1, "b": 2}
# What may differ from the guide's example output.
VARIABLE = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ|(?:arith|keccak)=\S+|\b\d+\b|\s+)")
TIMESTAMP = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
BACKEND = r"(?:x86_64-avx2|aarch64-neon|aarch64|portable)"
STARTUP_LINE = re.compile(r"v2 pq: (enabled|disabled \(-v2pqtransport=0\)|disabled \(-v2transport=0\)) arith=")
SENTINEL = "@@feature_pq_quickstart: {}@@"


def line_pattern(line):
    """A regular expression for a line of the guide's output, where numbers, dates and backend
    names may differ, a number may be blank, and any run of spaces may have another length."""
    pattern = ""
    for piece in VARIABLE.split(line.rstrip()):
        if re.fullmatch(TIMESTAMP, piece):
            pattern += TIMESTAMP
        elif piece.startswith(("arith=", "keccak=")):
            pattern += piece.split("=", 1)[0] + "=" + BACKEND
        elif piece.isdigit():
            pattern += r"\d*"
        elif piece.isspace():
            pattern += r"\s+"
        else:
            pattern += re.escape(piece)
    return re.compile(pattern)


class PQQuickstartTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Whatever the suite's transport flags, -v2pqtransport is only what this test passes.
        self.extra_args = [["-v2transport=1"]]
        self.v2pqtransport_from_run_mode = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        # The quick start needs a POSIX shell and qbitd -daemon.
        self.skip_if_platform_not_posix()

    def setup_network(self):
        # The node is started by test_switch only.
        self.add_nodes(self.num_nodes, self.extra_args)

    def guide(self):
        return (Path(self.config["environment"]["SRCDIR"]) / GUIDE).read_text(encoding="utf8")

    def run_test(self):
        self.test_quickstart()
        self.test_switch()
        self.test_doc_tokens()

    def quickstart_blocks(self):
        """The guide's steps, with this test's data directory and ports, and their outputs."""
        blocks = dict(BLOCK.findall(self.guide()))
        assert_equal(sorted(blocks), sorted(STEPS + tuple(f"{step} output" for step in STEPS)))
        datadir = Path(self.options.tmpdir) / "qbit-pq-quickstart"
        steps = "\n".join(f"echo {SENTINEL.format(step)}\n{blocks[step]}" for step in STEPS)
        assert_equal(steps.count(GUIDE_DATADIR_LINE), 1)
        steps = steps.replace(GUIDE_DATADIR_LINE, f"Q={shlex.quote(str(datadir))}")
        ports = {}
        for name, (guide_p2p, guide_rpc) in GUIDE_PORTS.items():
            node = PORT_NODES[name]
            ports[name] = (p2p_port(node), rpc_port(node))
            for guide_port, port in zip((guide_p2p, guide_rpc), ports[name]):
                pattern = rf"\b{guide_port}\b"
                assert re.search(pattern, steps), f"the guide no longer uses port {guide_port}"
                steps = re.sub(pattern, str(port), steps)
        return datadir, ports, steps, {step: blocks[f"{step} output"] for step in STEPS}

    def stop_quickstart_nodes(self, datadir, ports):
        """Stop whatever the quick start left running, wait for it, and remove its data."""
        pid_files = {name: datadir / name / "regtest" / "qbitd.pid" for name in ports}
        for name, pid_file in pid_files.items():
            if pid_file.exists():
                subprocess.run([self.binary_paths.bitcoincli, "-regtest", f"-datadir={datadir / name}", f"-rpcport={ports[name][1]}", "stop"],
                               capture_output=True, timeout=30)
        deadline = time.time() + 60 * self.options.timeout_factor
        while any(pid_file.exists() for pid_file in pid_files.values()) and time.time() < deadline:
            time.sleep(0.5)
        for name, pid_file in pid_files.items():
            if pid_file.exists():
                self.log.warning(f"Node {name} of the quick start did not stop; killing it")
                os.kill(int(pid_file.read_text(encoding="utf8")), signal.SIGKILL)
            log = datadir / name / "regtest" / "debug.log"
            if log.exists():
                # Keep the log for a failure's diagnosis; the framework removes it after a success.
                shutil.copyfile(log, Path(self.options.tmpdir) / f"quickstart_{name}_debug.log")
        shutil.rmtree(datadir, ignore_errors=True)

    def test_quickstart(self):
        self.log.info("Test the guide's quick start runs as written and prints what the guide shows")
        datadir, ports, script, outputs = self.quickstart_blocks()
        bin_dir = Path(self.options.tmpdir) / "quickstart_bin"
        bin_dir.mkdir()
        (bin_dir / "qbitd").symlink_to(self.binary_paths.bitcoind)
        (bin_dir / "qbit-cli").symlink_to(self.binary_paths.bitcoincli)
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": self.options.tmpdir}
        try:
            # The guide's waits add up to at most 4 minutes.
            result = subprocess.run(["bash", "--noprofile", "--norc", "-c", script], env=env, capture_output=True, text=True,
                                    encoding="utf8", timeout=300 * self.options.timeout_factor)
            assert result.stderr == "", f"the quick start printed on stderr:\n{result.stderr}\nand on stdout:\n{result.stdout}"
            printed = result.stdout.split("\n")
            for step in STEPS:
                start = printed.index(SENTINEL.format(step)) + 1
                end = next((i for i in range(start, len(printed)) if printed[i].startswith("@@")), len(printed))
                actual = [line for line in printed[start:end] if line]
                expected = outputs[step].split("\n")
                matches = len(actual) == len(expected) and all(line_pattern(e).fullmatch(a.rstrip()) for e, a in zip(expected, actual))
                assert matches, f"{step} printed\n" + "\n".join(actual) + "\ninstead of what the guide shows:\n" + outputs[step]
            assert not datadir.exists(), "the quick start's clean-up left its data directory"
        finally:
            self.stop_quickstart_nodes(datadir, ports)

    def startup_state(self, node):
        lines = STARTUP_LINE.findall(node.debug_log_path.read_text(encoding="utf8"))
        assert lines, "no startup line"
        return lines[-1]

    def test_switch(self):
        node = self.nodes[0]
        guide = self.guide()

        self.log.info("Test the qbit.conf line the guide gives switches the feature on")
        conf = re.search(r"```ini\n(.*?)\n```", guide, re.DOTALL).group(1)
        assert_equal(conf, "v2pqtransport=1")
        append_config(node.datadir_path, [conf])
        self.start_node(0)
        assert_equal(self.startup_state(node), "enabled")
        assert_equal(node.getpqtransportinfo()["status"], "enabled")

        self.log.info("Test -nov2pqtransport on the command line overrides it")
        self.restart_node(0, extra_args=["-v2transport=1", "-nov2pqtransport"])
        assert_equal(self.startup_state(node), "disabled (-v2pqtransport=0)")
        assert_equal(node.getpqtransportinfo()["status"], "disabled_v2pqtransport")
        self.stop_node(0)
        node.replace_in_config([(f"{conf}\n", "")])

        self.log.info("Test the startup warnings the guide shows are what qbitd prints")
        shown = [line for line in guide.splitlines() if line.startswith("Warning: ")]
        settings = [["-v2pqtransport=true"], ["-nov2pqtransport=0"], ["-v2transport=0", "-v2pqtransport=1"]]
        assert_equal(len(shown), len(settings))
        for args, warning in zip(settings, shown):
            self.start_node(0, extra_args=["-v2transport=1"] + args)
            self.stop_node(0, expected_stderr=warning)

    def test_doc_tokens(self):
        self.log.info("Test the interface names the docs quote exist, with options from this build's -help output")
        lint = Path(self.config["environment"]["SRCDIR"]) / LINT
        result = subprocess.run([sys.executable, str(lint), "--qbitd", self.binary_paths.bitcoind, "--qbit-cli", self.binary_paths.bitcoincli],
                                capture_output=True, text=True, encoding="utf8", timeout=120 * self.options.timeout_factor)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "(options from -help and -help-debug)" in result.stdout, result.stdout


if __name__ == '__main__':
    PQQuickstartTest(__file__).main()
