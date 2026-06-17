#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end relay integration test for qbit-photon."""

import os
import subprocess
import time

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    get_datadir_path,
    p2p_port,
    rpc_port,
)

TEST_HMAC_KEY = "deadbeef" * 8  # 64 hex chars = 32 bytes


class PhotonRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

        self.zmq_port_a = p2p_port(self.num_nodes + 1)
        self.zmq_port_b = p2p_port(self.num_nodes + 2)
        self.udp_port_a = p2p_port(self.num_nodes + 3)
        self.udp_port_b = p2p_port(self.num_nodes + 4)

        self.extra_args = [
            [],
            [f"-zmqpubhashblock=tcp://127.0.0.1:{self.zmq_port_a}"],
            [f"-zmqpubhashblock=tcp://127.0.0.1:{self.zmq_port_b}"],
            [],
        ]

    def setup_network(self):
        self.setup_nodes()

        # Connect only within each partition. Nodes 1 and 2 must stay disconnected.
        self.connect_nodes(1, 0)
        self.connect_nodes(3, 2)

    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_zmq()
        self.skip_if_no_bitcoind_zmq()

        if not self._find_photon_binary():
            raise SkipTest(
                "qbit-photon binary not found (build with: "
                "cmake -S contrib/photon -B contrib/photon/build && "
                "cmake --build contrib/photon/build)"
            )

    def _find_photon_binary(self):
        env_path = os.environ.get("PHOTON_BIN")
        if env_path and os.path.isfile(env_path):
            return env_path

        srcdir = self.config["environment"]["SRCDIR"]
        candidate = os.path.join(srcdir, "contrib", "photon", "build", "qbit-photon")
        if os.path.isfile(candidate):
            return candidate

        return None

    def _write_photon_config(self, name, bind_port, zmq_port, node_index, peer_port):
        cookie_path = os.path.join(
            str(get_datadir_path(self.options.tmpdir, node_index)),
            "regtest",
            ".cookie",
        )
        node_rpc_port = rpc_port(node_index)

        config_path = os.path.join(self.options.tmpdir, f"photon-{name}.conf")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(f"[local]\nbind_port = {bind_port}\nlog_level = info\n\n")
            f.write(f"[qbitd]\nzmq_hashblock = tcp://127.0.0.1:{zmq_port}\n")
            f.write(f"rpc_host = 127.0.0.1\nrpc_port = {node_rpc_port}\n")
            f.write(f"rpc_cookiefile = {cookie_path}\nrpc_timeout_ms = 10000\n\n")
            f.write("[peer.remote]\nhost = 127.0.0.1\n")
            f.write(f"port = {peer_port}\nhmac_key = {TEST_HMAC_KEY}\n")

        return config_path

    def _start_photon(self, name, config_path):
        photon_bin = self._find_photon_binary()
        if photon_bin is None:
            raise AssertionError("qbit-photon binary disappeared during test")

        stdout_path = os.path.join(self.options.tmpdir, f"photon-{name}.stdout")
        stderr_path = os.path.join(self.options.tmpdir, f"photon-{name}.stderr")
        stdout_f = open(stdout_path, "w", encoding="utf-8")
        stderr_f = open(stderr_path, "w", encoding="utf-8")

        try:
            proc = subprocess.Popen(
                [photon_bin, "--config", config_path],
                stdout=stdout_f,
                stderr=stderr_f,
            )
        except Exception:
            stdout_f.close()
            stderr_f.close()
            raise

        self._photon_procs.append((proc, stdout_f, stderr_f, name, stdout_path, stderr_path))

    def _read_log_tail(self, path, lines=40):
        if not os.path.isfile(path):
            return "(missing log file)"

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.readlines()
        return "".join(content[-lines:]) or "(empty)"

    def _assert_photons_running(self):
        for proc, _stdout_f, _stderr_f, name, stdout_path, stderr_path in self._photon_procs:
            rc = proc.poll()
            if rc is None:
                continue

            raise AssertionError(
                f"qbit-photon {name} exited unexpectedly with status {rc}\n"
                f"--- stdout ({stdout_path}) ---\n{self._read_log_tail(stdout_path)}\n"
                f"--- stderr ({stderr_path}) ---\n{self._read_log_tail(stderr_path)}"
            )

    def _stop_all_photons(self):
        for proc, stdout_f, stderr_f, _name, _stdout_path, _stderr_path in self._photon_procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

            stdout_f.close()
            stderr_f.close()

        self._photon_procs = []

    def _stop_photon(self, name):
        remaining = []
        stopped = False
        for proc, stdout_f, stderr_f, proc_name, _stdout_path, _stderr_path in self._photon_procs:
            if proc_name != name:
                remaining.append((proc, stdout_f, stderr_f, proc_name, _stdout_path, _stderr_path))
                continue

            stopped = True
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

            stdout_f.close()
            stderr_f.close()

        self._photon_procs = remaining
        if not stopped:
            raise AssertionError(f"qbit-photon {name} was not running")

    def _restart_photon(self, name, config_path):
        self._stop_photon(name)
        self._start_photon(name, config_path)

    def run_test(self):
        self._photon_procs = []

        config_a = self._write_photon_config("A", self.udp_port_a, self.zmq_port_a, 1, self.udp_port_b)
        config_b = self._write_photon_config("B", self.udp_port_b, self.zmq_port_b, 2, self.udp_port_a)

        try:
            self._start_photon("A", config_a)
            self._start_photon("B", config_b)
            time.sleep(2)

            self._assert_photons_running()

            def assert_next_block_relayed():
                self.generate(self.nodes[0], 1, sync_fun=self.no_op)
                self.sync_blocks(self.nodes[:2])
                expected_hash = self.nodes[0].getbestblockhash()

                def relay_synced_tip():
                    self._assert_photons_running()
                    return self.nodes[2].getbestblockhash() == expected_hash

                self.wait_until(relay_synced_tip, timeout=30)
                self.sync_blocks(self.nodes[2:])
                assert_equal(self.nodes[3].getbestblockhash(), expected_hash)

            self.log.info("Test 1: Basic relay propagation")
            assert_next_block_relayed()

            self.log.info("Test 2: Multi-block burst")
            # Relay engine processes one outbound block at a time, so pace the burst
            # to avoid replacing in-flight payloads before chunk emission completes.
            for _ in range(10):
                self.generate(self.nodes[0], 1, sync_fun=self.no_op)
                time.sleep(0.15)
            self.sync_blocks(self.nodes[:2])

            def relay_synced_height():
                self._assert_photons_running()
                return self.nodes[2].getblockcount() == self.nodes[0].getblockcount()

            self.wait_until(relay_synced_height, timeout=60)
            self.sync_blocks(self.nodes[2:])

            tip_hash = self.nodes[0].getbestblockhash()
            tip_height = self.nodes[0].getblockcount()
            for node in self.nodes:
                assert_equal(node.getbestblockhash(), tip_hash)
                assert_equal(node.getblockcount(), tip_height)

            self.log.info("Test 3: Orphan metrics validation")
            metrics = self.nodes[2].getorphanmetrics()
            assert_equal(metrics["orphan_rate"], 0)
            assert_equal(metrics["alert"], False)
            assert_equal(metrics["lifetime_stale_blocks"], 0)

            self.log.info("Test 4: One-sided PHOTON restart recovers relay")
            self._restart_photon("A", config_a)
            time.sleep(2)
            assert_next_block_relayed()

            self.log.info("Test 5: Simultaneous PHOTON restart recovers relay")
            self._stop_all_photons()
            self._start_photon("A", config_a)
            self._start_photon("B", config_b)
            time.sleep(2)
            assert_next_block_relayed()
        finally:
            self._stop_all_photons()


if __name__ == '__main__':
    PhotonRelayTest(__file__).main()
