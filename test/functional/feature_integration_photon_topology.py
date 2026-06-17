#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise PHOTON inside a mixed archive / witness-pruned topology."""

import os
import subprocess
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CBlock, NODE_WITNESS_PRUNED, from_hex
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_not_equal,
    ensure_for,
    get_datadir_path,
    p2p_port,
    rpc_port,
)
from test_framework.wallet import MiniWallet


TEST_HMAC_KEY = "deadbeef" * 8  # 64 hex chars = 32 bytes
WITNESS_PRUNE_DEPTH = COINBASE_MATURITY
STALE_REORG_METRIC_KEYS = ("lifetime_stale_blocks", "lifetime_reorgs", "deepest_reorg")


class PhotonTopologyIntegrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        self.rpc_timeout = 600

        self.zmq_port_a = p2p_port(self.num_nodes + 1)
        self.zmq_port_b = p2p_port(self.num_nodes + 2)
        self.udp_port_a = p2p_port(self.num_nodes + 3)
        self.udp_port_b = p2p_port(self.num_nodes + 4)

        self.extra_args = [
            [],
            [f"-zmqpubhashblock=tcp://127.0.0.1:{self.zmq_port_a}", "-fastprune"],
            ["-fastprune", "-prunewitnesses=1"],
            [f"-zmqpubhashblock=tcp://127.0.0.1:{self.zmq_port_b}"],
            [],
        ]

    def setup_network(self):
        self.setup_nodes()

        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(1, 3)
        self.connect_nodes(3, 4)

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

    def _wait_for_photons_ready(self):
        def photons_ready():
            self._assert_photons_running()
            for _proc, _stdout_f, _stderr_f, _name, _stdout_path, stderr_path in self._photon_procs:
                if "startup complete; entering relay loop" not in self._read_log_tail(stderr_path, lines=80):
                    return False
            return True

        self.wait_until(photons_ready, timeout=30)

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

    def mine_blocks_with_witness_txs(self, node, wallet, count):
        for _ in range(count):
            wallet.send_self_transfer(from_node=node)
            self.generate(node, 1, sync_fun=self.no_op)

    @staticmethod
    def assert_stripped_matches_no_witness(stripped_hex, full_hex):
        full_block = from_hex(CBlock(), full_hex)
        full_witness = full_block.serialize()
        full_no_witness = full_block.serialize(False)
        assert_not_equal(full_witness, full_no_witness)
        assert_equal(bytes.fromhex(stripped_hex), full_no_witness)

    def count_non_active_tips(self, node):
        return sum(1 for tip in node.getchaintips() if tip["status"] != "active")

    def stale_reorg_metrics(self, node):
        metrics = node.getorphanmetrics()
        return {key: metrics[key] for key in STALE_REORG_METRIC_KEYS}

    def wait_for_witness_pruned_history(self, pruned_node, archive_node, historical_hash):
        def witness_pruned():
            services = int(pruned_node.getnetworkinfo()["localservices"], 16)
            if not services & NODE_WITNESS_PRUNED:
                return False

            pruned_hex = pruned_node.getblock(historical_hash, False)
            archive_hex = archive_node.getblock(historical_hash, False)
            try:
                self.assert_stripped_matches_no_witness(pruned_hex, archive_hex)
            except AssertionError:
                return False
            return True

        self.wait_until(witness_pruned, timeout=120)

    def run_test(self):
        self._photon_procs = []

        miner = self.nodes[0]
        archive_bridge = self.nodes[1]
        pruned_node = self.nodes[2]
        relay_bridge = self.nodes[3]
        right_miner = self.nodes[4]
        wallet = MiniWallet(miner)

        config_a = self._write_photon_config("left", self.udp_port_a, self.zmq_port_a, 1, self.udp_port_b)
        config_b = self._write_photon_config("right", self.udp_port_b, self.zmq_port_b, 3, self.udp_port_a)

        try:
            self.log.info("Build enough history to trigger witness pruning on the mixed-topology node")
            self.generate(wallet, WITNESS_PRUNE_DEPTH + 5, sync_fun=self.no_op)
            self.sync_all()

            start_height = miner.getblockcount()
            self.mine_blocks_with_witness_txs(miner, wallet, 300)
            historical_hash = miner.getblockhash(start_height + 20)
            self.generate(miner, 900)
            self.sync_all()

            self.wait_for_witness_pruned_history(pruned_node, archive_bridge, historical_hash)
            assert int(pruned_node.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED
            assert_equal(int(archive_bridge.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED, 0)

            pre_bridge_metrics = [self.stale_reorg_metrics(node) for node in self.nodes]

            self.log.info("Split the physical network and bridge the partitions with PHOTON")
            self.disconnect_nodes(1, 3)
            self.sync_blocks([miner, archive_bridge, pruned_node])
            self.sync_blocks([relay_bridge, right_miner])

            self._start_photon("left", config_a)
            self._start_photon("right", config_b)
            self._wait_for_photons_ready()

            for _ in range(2):
                self.generate(miner, 1, sync_fun=lambda: self.sync_blocks([miner, archive_bridge, pruned_node]))
                time.sleep(0.15)

            def photon_bridged_tip():
                self._assert_photons_running()
                return right_miner.getbestblockhash() == miner.getbestblockhash()

            self.wait_until(photon_bridged_tip, timeout=60)
            self.sync_blocks([relay_bridge, right_miner])

            bridged_tip = miner.getbestblockhash()
            bridged_height = miner.getblockcount()
            for node in self.nodes:
                assert_equal(node.getbestblockhash(), bridged_tip)
                assert_equal(node.getblockcount(), bridged_height)
            for node, expected_metrics in zip(self.nodes, pre_bridge_metrics):
                assert_equal(self.stale_reorg_metrics(node), expected_metrics)

            self.log.info("Stop PHOTON and assert the split stays isolated until direct rejoin")
            self._stop_all_photons()

            pre_failure_tip = right_miner.getbestblockhash()
            self.generate(miner, 1, sync_fun=lambda: self.sync_blocks([miner, archive_bridge, pruned_node]))
            left_only_tip = miner.getbestblockhash()

            ensure_for(duration=3, f=lambda: right_miner.getbestblockhash() == pre_failure_tip)
            assert_not_equal(left_only_tip, right_miner.getbestblockhash())

            self.generate(right_miner, 2, sync_fun=lambda: self.sync_blocks([relay_bridge, right_miner]))
            winning_tip = right_miner.getbestblockhash()
            winning_height = right_miner.getblockcount()
            assert_not_equal(left_only_tip, winning_tip)
            assert_equal(miner.getbestblockhash(), left_only_tip)

            pre_rejoin_metrics = archive_bridge.getorphanmetrics()

            self.log.info("Rejoin the partitions directly and verify convergence plus orphan-metric sanity")
            with archive_bridge.assert_debug_log(expected_msgs=["Stale block detected: height="], timeout=10):
                self.connect_nodes(1, 3)
                self.sync_all()

            for node in self.nodes:
                assert_equal(node.getbestblockhash(), winning_tip)
                assert_equal(node.getblockcount(), winning_height)

            post_rejoin_metrics = archive_bridge.getorphanmetrics()
            assert_greater_than_or_equal(post_rejoin_metrics["lifetime_stale_blocks"], pre_rejoin_metrics["lifetime_stale_blocks"] + 1)
            assert_greater_than_or_equal(post_rejoin_metrics["lifetime_reorgs"], pre_rejoin_metrics["lifetime_reorgs"] + 1)
            assert_greater_than_or_equal(post_rejoin_metrics["deepest_reorg"], 1)
            assert_equal(post_rejoin_metrics["persistent_stale_tip_count"], self.count_non_active_tips(archive_bridge))
            assert_equal(post_rejoin_metrics["alert"], False)

            self.log.info("Archive / pruned history semantics remain intact after PHOTON and rejoin")
            self.assert_stripped_matches_no_witness(
                pruned_node.getblock(historical_hash, False),
                archive_bridge.getblock(historical_hash, False),
            )
        finally:
            self._stop_all_photons()


if __name__ == "__main__":
    PhotonTopologyIntegrationTest(__file__).main()
