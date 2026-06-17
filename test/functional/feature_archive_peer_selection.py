#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise manual archive-peer selection and witness-pruned peer rejection."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    MSG_WITNESS_BLOCK,
    NODE_ARCHIVE,
    NODE_NETWORK,
    NODE_NETWORK_LIMITED,
    NODE_P2P_V2,
    NODE_WITNESS,
    NODE_WITNESS_PRUNED,
    from_hex,
    msg_headers,
    msg_notfound,
)
from test_framework.p2p import P2PDataStore, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import MAX_NODES, assert_equal, assert_not_equal, assert_raises_rpc_error, p2p_port, try_rpc
from test_framework.wallet import MiniWallet


WITNESS_PRUNE_DEPTH = COINBASE_MATURITY


class LateWitnessPrunedArchivePeer(P2PDataStore):
    def __init__(self, historical_hashes):
        super().__init__()
        self._historical_hashes = set(historical_hashes)
        self._historical_notfound = []

    def on_inv(self, message):
        pass

    def on_getheaders(self, message):
        pass

    def on_getdata(self, message):
        notfound = []
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            if inv.type == MSG_WITNESS_BLOCK and inv.hash in self._historical_hashes:
                self._historical_notfound.append(inv.hash)
                notfound.append(inv)
        if notfound:
            self.send_without_ping(msg_notfound(vec=notfound))

    def historical_notfound_sent(self):
        with p2p_lock:
            return bool(self._historical_notfound)


class ArchivePeerSelectionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.rpc_timeout = 600
        self.extra_args = [
            ["-dnsseed=0", "-fixedseeds=0"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune", "-prunewitnesses=1"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune"],
            ["-dnsseed=0", "-fixedseeds=0", "-fastprune", "-prune=1"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 2)

    @staticmethod
    def peer_marker(peer_index):
        return f"testnode{peer_index}"

    def find_peer(self, node, peer_index):
        marker = self.peer_marker(peer_index)
        for peer in node.getpeerinfo():
            if marker in peer.get("subver", ""):
                return peer
        return None

    def node_args(self, node_index):
        return list(self.extra_args[node_index])

    def restart_node0(self, extra_args):
        self.restart_node(0, extra_args=[*self.node_args(0), *extra_args], clear_addrman=True)

    def restart_clean_requester(self, node_index, extra_args):
        self.restart_node(node_index, extra_args=[*self.node_args(node_index), *extra_args], clear_addrman=True)

    @staticmethod
    def assert_archive_summary(result, *, advertised, archive_connections, configured, connected_configured):
        assert_equal(result["summary"], {
            "connected_advertised_archive_peers": advertised,
            "connected_archive_connections": archive_connections,
            "configured_archive_targets": configured,
            "connected_configured_archive_targets": connected_configured,
        })

    @staticmethod
    def assert_archive_view_keys(result, *sections):
        expected = {"summary"}
        expected.update(sections)
        assert_equal(set(result.keys()), expected)

    def assert_single_connected_archive_peer(self, result, *, archive_connection, advertises_archive):
        self.assert_archive_view_keys(result, "connected")
        assert_equal(len(result["connected"]), 1)
        peer = result["connected"][0]
        assert_equal(peer["archive_connection"], archive_connection)
        assert_equal(peer["advertises_archive"], advertises_archive)
        assert_equal("ARCHIVE" in peer["servicesnames"], advertises_archive)
        return peer

    def assert_single_configured_archive_target(self, result, *, target, connected, nodeid=None):
        self.assert_archive_view_keys(result, "configured")
        assert_equal(len(result["configured"]), 1)
        configured = result["configured"][0]
        assert_equal(configured["target"], target)
        assert_equal(configured["source"], "connectarchive")
        assert_equal(configured["connected"], connected)
        if nodeid is None:
            assert_equal("nodeid" in configured, False)
        else:
            assert_equal(configured["nodeid"], nodeid)

    def mine_blocks_with_witness_txs(self, node, wallet, count):
        for _ in range(count):
            wallet.send_self_transfer(from_node=node)
            self.generate(node, 1, sync_fun=self.no_op)

    def start_listening_peer(self, peer, *, services):
        p2p_idx = self.next_p2p_idx
        self.next_p2p_idx += 1
        if self.options.v2transport:
            services |= NODE_P2P_V2
        peer.peer_accept_connection(
            connect_cb=lambda address, port: None,
            connect_id=p2p_idx + 1,
            net=self.chain,
            timeout_factor=self.options.timeout_factor,
            supports_v2_p2p=self.options.v2transport,
            reconnect=False,
            services=services,
        )()
        return f"127.0.0.1:{p2p_port(MAX_NODES - (p2p_idx + 1))}"

    @staticmethod
    def wait_for_outbound_handshake(peer):
        peer.wait_for_connect()
        peer.wait_for_verack()

    def assert_connectarchive_rejects_services(self, label, services, expected_log):
        self.log.info(f"connectarchive rejects {label} service flags")
        peer = P2PDataStore()
        addr = self.start_listening_peer(peer, services=services)
        with self.nodes[0].assert_debug_log(expected_msgs=[expected_log], timeout=10):
            self.restart_node0([f"-connectarchive={addr}"])
            self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) == 0)

    def assert_connectarchive_accepts_services(self, label, services):
        self.log.info(f"connectarchive accepts {label} service flags")
        peer = P2PDataStore()
        addr = self.start_listening_peer(peer, services=services)
        self.restart_node0([f"-connectarchive={addr}"])
        self.wait_for_outbound_handshake(peer)
        self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) == 1)
        result = self.nodes[0].getarchivepeers()
        advertises_archive = bool(services & NODE_ARCHIVE)
        self.assert_archive_summary(result, advertised=int(advertises_archive), archive_connections=1, configured=1, connected_configured=1)
        connected = self.assert_single_connected_archive_peer(self.nodes[0].getarchivepeers("connected"), archive_connection=True, advertises_archive=advertises_archive)
        self.assert_single_configured_archive_target(self.nodes[0].getarchivepeers("configured"), target=addr, connected=True, nodeid=connected["nodeid"])

    @staticmethod
    def assert_stripped_matches_no_witness(stripped_hex, full_hex):
        full_block = from_hex(CBlock(), full_hex)
        full_witness = full_block.serialize()
        full_no_witness = full_block.serialize(False)
        assert_not_equal(full_witness, full_no_witness)
        assert_equal(bytes.fromhex(stripped_hex), full_no_witness)

    def run_test(self):
        self.next_p2p_idx = 0
        pruned_node = self.nodes[1]
        archive_node = self.nodes[2]
        pruned_addr = f"127.0.0.1:{p2p_port(1)}"
        archive_addr = f"127.0.0.1:{p2p_port(2)}"
        wallet = MiniWallet(pruned_node)

        self.log.info("Mine maturity blocks so MiniWallet has spendable UTXOs")
        self.generate(wallet, WITNESS_PRUNE_DEPTH + 5, sync_fun=self.no_op)
        self.sync_blocks([pruned_node, archive_node])

        self.log.info("Check getarchivepeers help, view selection, and disconnected configured targets")
        help_text = self.nodes[0].help("getarchivepeers")
        assert "getarchivepeers" in help_text
        assert "connected_advertised_archive_peers" in help_text
        assert_raises_rpc_error(-8, "Invalid view", self.nodes[0].getarchivepeers, "invalid")

        result = self.nodes[0].getarchivepeers()
        self.assert_archive_view_keys(result, "connected", "configured")
        self.assert_archive_summary(result, advertised=0, archive_connections=0, configured=0, connected_configured=0)
        assert_equal(result["connected"], [])
        assert_equal(result["configured"], [])

        summary = self.nodes[0].getarchivepeers("summary")
        self.assert_archive_view_keys(summary)
        self.assert_archive_summary(summary, advertised=0, archive_connections=0, configured=0, connected_configured=0)

        disconnected_target = "127.0.0.1:1"
        self.restart_node0([f"-connectarchive={disconnected_target}"])
        result = self.nodes[0].getarchivepeers("configured")
        self.assert_archive_summary(result, advertised=0, archive_connections=0, configured=1, connected_configured=0)
        self.assert_single_configured_archive_target(result, target=disconnected_target, connected=False)

        start_height = pruned_node.getblockcount()
        self.log.info("Mine witness-bearing blocks, then mine forward enough to make them prunable")
        self.mine_blocks_with_witness_txs(pruned_node, wallet, 300)
        self.generate(pruned_node, 900, sync_fun=self.no_op)
        self.sync_blocks([pruned_node, archive_node])

        pruned_height = start_height + 20
        pruned_hash = pruned_node.getblockhash(pruned_height)

        self.log.info("Wait for a historical block to be served stripped on the witness-pruning node")
        retained_floor = archive_node.getblockcount() - WITNESS_PRUNE_DEPTH

        def witness_stripped():
            node1_raw = pruned_node.getblock(pruned_hash, False)
            node2_raw = archive_node.getblock(pruned_hash, False)
            try:
                self.assert_stripped_matches_no_witness(node1_raw, node2_raw)
            except AssertionError:
                return False
            return True

        self.wait_until(witness_stripped, timeout=120)
        self.wait_until(lambda: int(pruned_node.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED, timeout=120)

        self.log.info("Sanity-check witness-pruned vs archive service signaling")
        assert int(pruned_node.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED
        assert_equal(int(pruned_node.getnetworkinfo()["localservices"], 16) & NODE_ARCHIVE, 0)
        assert_equal(int(archive_node.getnetworkinfo()["localservices"], 16) & NODE_WITNESS_PRUNED, 0)
        assert int(archive_node.getnetworkinfo()["localservices"], 16) & NODE_ARCHIVE

        self.log.info("Regular addnode connections to witness-pruned peers remain allowed")
        self.restart_node0([f"-addnode={pruned_addr}"])
        self.wait_until(lambda: self.find_peer(self.nodes[0], 1) is not None)
        self.wait_until(lambda: self.find_peer(pruned_node, 0) is not None)
        result = self.nodes[0].getarchivepeers()
        self.assert_archive_summary(result, advertised=0, archive_connections=0, configured=0, connected_configured=0)
        assert_equal(result["connected"], [])
        assert_equal(result["configured"], [])

        self.log.info("connectarchive rejects witness-pruned peers after the version handshake")
        with self.nodes[0].assert_debug_log(expected_msgs=["advertises NODE_WITNESS_PRUNED, disconnecting"], timeout=10):
            self.restart_node0([f"-connectarchive={pruned_addr}"])
            self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) == 0)

        self.assert_connectarchive_rejects_services(
            "limited-only archive peers",
            NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_ARCHIVE,
            "does not offer full archive services",
        )
        self.assert_connectarchive_rejects_services(
            "peers without witness service",
            NODE_NETWORK | NODE_ARCHIVE,
            "does not offer full archive services",
        )
        self.assert_connectarchive_rejects_services(
            "peers without network service",
            NODE_WITNESS | NODE_ARCHIVE,
            "does not offer full archive services",
        )
        self.assert_connectarchive_rejects_services(
            "peers advertising witness-pruned history",
            NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED,
            "advertises NODE_WITNESS_PRUNED, disconnecting",
        )
        self.assert_connectarchive_rejects_services(
            "peers without explicit archive service",
            NODE_NETWORK | NODE_WITNESS,
            "does not offer full archive services",
        )
        self.assert_connectarchive_accepts_services(
            "full archive/witness peers",
            NODE_NETWORK | NODE_WITNESS | NODE_ARCHIVE,
        )

        self.log.info("Regular addnode connections to archive-advertising peers appear as observed archive peers")
        archive_advertising_peer = P2PDataStore()
        archive_advertising_addr = self.start_listening_peer(
            archive_advertising_peer,
            services=NODE_NETWORK | NODE_WITNESS | NODE_ARCHIVE,
        )
        self.restart_node0([f"-addnode={archive_advertising_addr}"])
        self.wait_for_outbound_handshake(archive_advertising_peer)
        self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) == 1)
        result = self.nodes[0].getarchivepeers("connected")
        self.assert_archive_summary(result, advertised=1, archive_connections=0, configured=0, connected_configured=0)
        self.assert_single_connected_archive_peer(result, archive_connection=False, advertises_archive=True)

        self.log.info("connectarchive accepts archive peers")
        self.restart_node0([f"-connectarchive={archive_addr}"])
        self.wait_until(lambda: self.find_peer(self.nodes[0], 2) is not None)
        self.wait_until(lambda: self.find_peer(archive_node, 0) is not None)
        result = self.nodes[0].getarchivepeers()
        self.assert_archive_summary(result, advertised=1, archive_connections=1, configured=1, connected_configured=1)
        connected = self.assert_single_connected_archive_peer(self.nodes[0].getarchivepeers("connected"), archive_connection=True, advertises_archive=True)
        self.assert_single_configured_archive_target(self.nodes[0].getarchivepeers("configured"), target=archive_addr, connected=True, nodeid=connected["nodeid"])

        late_requester = self.nodes[3]
        self.log.info("Prepare a fast-pruned requester with historical block files removed")
        self.connect_nodes(2, 3)
        self.sync_blocks([archive_node, late_requester])
        pruneheight = late_requester.pruneblockchain(retained_floor)
        chain_pruneheight = late_requester.getblockchaininfo()["pruneheight"]
        assert chain_pruneheight >= pruneheight
        self.wait_until(lambda: try_rpc(-1, "Block not available (pruned data)", late_requester.getblock, pruned_hash), timeout=30)
        self.disconnect_nodes(2, 3)

        self.log.info("connectarchive disconnects peers that imply NODE_WITNESS_PRUNED via historical NOTFOUND")
        late_peer = LateWitnessPrunedArchivePeer([int(pruned_hash, 16)])
        late_addr = self.start_listening_peer(
            late_peer,
            services=NODE_NETWORK | NODE_WITNESS | NODE_ARCHIVE,
        )
        tip_block = from_hex(CBlock(), archive_node.getblock(archive_node.getbestblockhash(), False))
        with late_requester.assert_debug_log(expected_msgs=["implies NODE_WITNESS_PRUNED via NOTFOUND, disconnecting"], timeout=30):
            self.restart_clean_requester(3, [f"-connectarchive={late_addr}"])
            self.wait_for_outbound_handshake(late_peer)
            late_peer.send_and_ping(msg_headers(headers=[CBlockHeader(tip_block)]))
            self.wait_until(lambda: len(late_requester.getpeerinfo()) == 1)
            peer_id = late_requester.getpeerinfo()[0]["id"]
            assert_equal(late_requester.getblockfrompeer(pruned_hash, peer_id), {})
            self.wait_until(lambda: late_peer.historical_notfound_sent(), timeout=30)
            late_peer.wait_for_disconnect(timeout=30)
            self.wait_until(lambda: len(late_requester.getpeerinfo()) == 0)


if __name__ == "__main__":
    ArchivePeerSelectionTest(__file__).main()
