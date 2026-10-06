#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the hybrid post-quantum v2 transport's operator surface (#184 part 6).

Options and startup line:
- test_configuration: -v2pqtransport on the command line, in qbit.conf, negated and
  across restarts, observed on a live connection between two nodes; the warnings for a
  contradictory or non-numeric setting; -help; the three startup lines.
- test_portable_options: -mlkemportable and -test=mlkem_portable make the startup line
  report portable code; the test options are regtest only and print nothing to stderr.

RPC (getpqtransportinfo, and the getpeerinfo and getnetworkinfo fields):
- test_states: every getpqtransportinfo field with the switch off, with v2 off, on, and
  with an endpoint in the fallback set; instance_id changes on restart; each
  transport_pq_status.
- test_counts: exact per-direction counts of hybrid, legacy and failing connections.
  -test=pq_fail_first_packet on one node makes hybrid handshakes fail in both directions.
- test_abandoned: an initiator that reads the offer and closes, or stalls until the
  handshake times out, counts one abandoned offer and no switch.
- test_rings: 300 inbound failures keep the newest 256, with contiguous sequences, and
  don't evict the outbound ring's entry.
- test_connection_count: connections_pq counts the peers getpeerinfo shows with
  transport_pq, and is 0 with the switch off.
"""
from concurrent.futures import ThreadPoolExecutor
import re
import socket
import subprocess
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    append_config,
    assert_equal,
    p2p_port,
    write_config,
)
from test_framework.v2_p2p import (
    CHACHA20POLY1305_EXPANSION,
    HEADER_LEN,
    LENGTH_FIELD_LEN,
    EncryptedP2PState,
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

# Node arguments: v2 without and with the hybrid key exchange, and with failing confirmations.
NO_PQ = ["-v2transport=1"]
PQ = ["-v2transport=1", "-v2pqtransport=1"]
PQ_FAIL = PQ + ["-test=pq_fail_first_packet"]

# The offer: one 0xF0 record, CompactSize(1,569) || 0xF0 || a 1,568-byte encapsulation key.
OFFER_LEN = 1572
OFFER_PREFIX = bytes.fromhex("fd2106f0")
RING_SIZE = 256
FIRST_WINDOW = 3600


def non_numeric_warning(value, read_as):
    return (f"Warning: -v2pqtransport={value} is not a number, so it is read as -v2pqtransport={read_as}. "
            "Set -v2pqtransport=1 or -v2pqtransport=0.")


def zero_counts():
    """getpqtransportinfo's handshakes with nothing counted."""
    common = {"switched": 0, "legacy_peer": 0, "malformed_record": 0, "first_packet_failed": 0, "abandoned": 0, "internal_error": 0}
    return {
        "inbound": {**common, "shed": 0},
        "outbound": {**common, "closed_after_switch": 0, "fallback": 0},
    }


def empty_ring():
    return {"last_sequence": 0, "dropped": 0, "entries": []}


def local_endpoint(port):
    return {"kind": "address", "network": "ipv4", "address": "127.0.0.1", "port": port}


class OfferReader:
    """An initiator on a plain socket: it sends its key, reads the node's key, garbage and
    version packet, and never sends its own version packet."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=60)
        self.local_port = self.sock.getsockname()[1]
        self.state = EncryptedP2PState(initiating=True, net="regtest")
        self.recvbuf = b""
        self.sock.sendall(self.state.generate_keypair_and_garbage(garbage_len=0))

    def _recv_more(self):
        data = self.sock.recv(65536)
        assert data, "the node closed the connection"
        self.recvbuf += data

    def _recv_exact(self, n):
        while len(self.recvbuf) < n:
            self._recv_more()
        data, self.recvbuf = self.recvbuf[:n], self.recvbuf[n:]
        return data

    def read_version_contents(self):
        """The contents of the node's version packet."""
        st = self.state
        ellswift_theirs = self._recv_exact(64)
        st.initialize_v2_transport(st.v2_ecdh(st.privkey_ours, ellswift_theirs, st.ellswift_ours, True))
        terminator = st.peer["recv_garbage_terminator"]
        while terminator not in self.recvbuf:
            self._recv_more()
        garbage, self.recvbuf = self.recvbuf.split(terminator, 1)
        length = int.from_bytes(st.peer["recv_L"].crypt(self._recv_exact(LENGTH_FIELD_LEN)), "little")
        # The version packet authenticates the garbage.
        plaintext = st.peer["recv_P"].decrypt(garbage, self._recv_exact(HEADER_LEN + length + CHACHA20POLY1305_EXPANSION))
        assert plaintext is not None
        return plaintext[HEADER_LEN:]

    def close(self):
        """End the stream, so the node reads eof, and read until it closes too: nothing left unread
        turns the close into a reset."""
        self.sock.shutdown(socket.SHUT_WR)
        while self.sock.recv(65536):
            pass
        self.sock.close()


def abandon_offer(port):
    """An inbound v2 connection that sends a key and ends the stream: the node's offer is abandoned (eof)."""
    with socket.create_connection(("127.0.0.1", port), timeout=60) as sock:
        # Any 64 bytes are a valid ElligatorSwift key; a first byte unlike the network magic's is v2 at once.
        sock.sendall(bytes(64))
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(65536):
            pass


class PQTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # Whatever the suite's transport flag, these nodes use v2.
        self.extra_args = [NO_PQ] * self.num_nodes

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

    def handshakes(self, node):
        return node.getpqtransportinfo()["handshakes"]

    def wait_for_handshakes(self, node, before, *alternatives):
        """Wait until node's counts are before plus exactly one of the alternatives, each a dict
        of direction to counter increments, and return the index of the one that matched."""
        expected = []
        for increments in alternatives:
            counts = {direction: dict(values) for direction, values in before.items()}
            for direction, deltas in increments.items():
                for counter, delta in deltas.items():
                    counts[direction][counter] += delta
            expected.append(counts)
        self.wait_until(lambda: self.handshakes(node) in expected)
        return expected.index(self.handshakes(node))

    def wait_for_no_peers(self, *nodes):
        for node in nodes:
            self.wait_until(lambda: node.getpeerinfo() == [])

    def failing_connection(self, a, b, *, enters_fallback=False):
        """Connect node a to node b, whose hybrid handshake fails its key confirmation
        (-test=pq_fail_first_packet on either side), and wait until both removed the peer.

        The initiator's version packet and confirmation travel together, so the responder's
        check of that confirmation fails, and it closes before its own confirmation leaves: the
        initiator then counts closed_after_switch, or first_packet_failed if the responder's
        confirmation got out first. Returns the initiator's outcome. With enters_fallback, the
        failure completes a streak and the initiator also counts fallback."""
        initiator, responder = self.nodes[a], self.nodes[b]
        before_initiator, before_responder = self.handshakes(initiator), self.handshakes(responder)
        initiator.addnode(f"127.0.0.1:{p2p_port(b)}", "onetry")
        self.wait_for_handshakes(responder, before_responder, {"inbound": {"switched": 1, "first_packet_failed": 1}})
        outcomes = ["closed_after_switch", "first_packet_failed"]
        fallback = {"fallback": 1} if enters_fallback else {}
        matched = self.wait_for_handshakes(initiator, before_initiator,
                                           *[{"outbound": {"switched": 1, outcome: 1, **fallback}} for outcome in outcomes])
        self.wait_for_no_peers(initiator, responder)
        return outcomes[matched]

    def test_configuration(self):
        node0, node1, _ = self.nodes

        self.log.info("Test the switch is off by default")
        assert_equal(self.startup_line(node0)[0], DISABLED_PQ)
        assert_equal(self.startup_line(node1)[0], DISABLED_PQ)
        self.check_connection(hybrid=False)

        self.log.info("Test -v2pqtransport=1 on one side only keeps the ECDH keys")
        with node0.assert_debug_log(["v2 pq: legacy_peer reason=no_features role=initiator"]):
            self.restart_node(0, extra_args=PQ)
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
        # A sign is allowed, as InterpretBool reads it.
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
            info = node0.getpqtransportinfo()
            assert_equal((info["arith_backend"], info["keccak_backend"]), ("portable", "portable"))

        self.log.info("Test -test=pq_fail_first_packet starts cleanly")
        self.restart_node(0, extra_args=PQ_FAIL)
        assert_equal(self.startup_line(node0)[0], ENABLED)
        # Nothing is printed to stderr (checked at stop).
        self.stop_node(0)

        self.log.info("Test the test options are regtest only, and -mlkemportable works on any chain")
        conf_file = node0.datadir_path / "qbit.conf"
        regtest_conf = conf_file.read_text(encoding="utf-8")
        write_config(conf_file, n=0, chain="signet")
        node0.chain = "signet"
        for option in ["-test=mlkem_portable", "-test=pq_fail_first_packet"]:
            node0.assert_start_raises_init_error(extra_args=[option], expected_msg=TEST_OPTION_ERROR)
        self.start_node(0, extra_args=["-v2transport=1", "-mlkemportable"])
        assert_equal(self.startup_line(node0), (DISABLED_PQ, "portable", "portable"))
        self.stop_node(0)
        conf_file.write_text(regtest_conf, encoding="utf-8")
        node0.chain = "regtest"
        self.start_node(0)

    def check_info(self, node, *, start_time, enabled, status, **expected):
        """Check every getpqtransportinfo field: the configuration, the backends the startup line
        named, since, and the given fields (none counted, empty and inactive unless given)."""
        info = node.getpqtransportinfo()
        assert re.fullmatch("[0-9a-f]{64}", info.pop("instance_id"))
        since = info.pop("since")
        assert start_time <= since <= time.time() + 1
        _, arith, keccak = self.startup_line(node)
        assert_equal(info, {
            "enabled": enabled,
            "status": status,
            "arith_backend": arith,
            "keccak_backend": keccak,
            "handshakes": expected.get("handshakes", zero_counts()),
            "load_shedding": {"active": False, "threshold_per_s": 1000, "since": 0},
            "fallback_set": expected.get("fallback_set", []),
            "failure_streaks": expected.get("failure_streaks", []),
            "recent_failures": expected.get("recent_failures", {"inbound": empty_ring(), "outbound": empty_ring()}),
        })

    def peer(self, node, *, inbound):
        """The node's only peer of a direction."""
        peers = [peer for peer in node.getpeerinfo() if peer["inbound"] == inbound]
        assert_equal(len(peers), 1)
        return peers[0]

    def check_peers(self, a, b, status_a, status_b, **kwargs):
        """Connect node a to node b and check each side's transport_pq_status; then disconnect."""
        self.connect_nodes(a, b, **kwargs)
        for node, status, inbound in [(self.nodes[a], status_a, False), (self.nodes[b], status_b, True)]:
            peer = self.peer(node, inbound=inbound)
            assert_equal((peer["transport_pq"], peer["transport_pq_status"]), (status == "hybrid", status))
        self.disconnect_nodes(a, b)

    def test_states(self):
        node0, node1, node2 = self.nodes

        self.log.info("Test getpqtransportinfo with the switch off; getpeerinfo off on both sides")
        start_time = int(time.time())
        self.restart_node(0, extra_args=NO_PQ)
        self.check_info(node0, start_time=start_time, enabled=False, status="disabled_v2pqtransport")
        instance_ids = [node0.getpqtransportinfo()["instance_id"]]
        self.check_peers(0, 2, "off", "off")

        self.log.info("Test getpqtransportinfo with v2 off; getpeerinfo v1 on both sides")
        start_time = int(time.time())
        self.restart_node(0, extra_args=["-v2transport=0", "-v2pqtransport=1"])
        self.check_info(node0, start_time=start_time, enabled=False, status="disabled_v2transport")
        instance_ids.append(node0.getpqtransportinfo()["instance_id"])
        self.check_peers(0, 2, "v1", "v1", peer_advertises_v2=False)
        self.stop_node(0, expected_stderr=CONTRADICTION_WARNING)

        self.log.info("Test getpqtransportinfo with the switch on; getpeerinfo hybrid, legacy_peer and off")
        start_time = int(time.time())
        self.start_node(0, extra_args=PQ)
        self.restart_node(1, extra_args=PQ)
        self.check_info(node0, start_time=start_time, enabled=True, status="enabled")
        instance_ids.append(node0.getpqtransportinfo()["instance_id"])
        self.check_peers(0, 1, "hybrid", "hybrid")
        self.check_peers(0, 2, "legacy_peer", "off")
        self.check_peers(2, 0, "off", "legacy_peer")

        self.log.info("Test instance_id changes on restart")
        assert_equal(len(set(instance_ids)), len(instance_ids))

        self.log.info("Test getpqtransportinfo with an endpoint in the fallback set")
        start_time = int(time.time())
        self.restart_node(0, extra_args=PQ)
        self.restart_node(1, extra_args=PQ_FAIL)
        now = int(time.time())
        node0.setmocktime(now)
        endpoint = local_endpoint(p2p_port(1))
        reasons = {"closed_after_switch": ["eof", "reset"], "first_packet_failed": ["length", "tag"]}
        outcomes = []
        for streak in range(1, 4):
            outcomes.append(self.failing_connection(0, 1, enters_fallback=streak == 3))
            info = node0.getpqtransportinfo()
            if streak < 3:
                assert_equal(info["fallback_set"], [])
                assert_equal(len(info["failure_streaks"]), 1)
                assert info["failure_streaks"][0]["reason"] in reasons[outcomes[-1]]
                assert_equal(info["failure_streaks"], [{"endpoint": endpoint, "cause": outcomes[-1], "reason": info["failure_streaks"][0]["reason"],
                                                        "streak": streak, "last_failure": now, "next_window_seconds": FIRST_WINDOW}])
        entries = info["recent_failures"]["outbound"]["entries"]
        assert_equal(len(entries), 4)
        for outcome, entry in zip(outcomes, entries):
            assert entry["reason"] in reasons[outcome]
        # The fallback entry names the failure that completed the streak, on the same connection.
        assert_equal((entries[3]["reason"], entries[3]["peer_id"]), (outcomes[-1], entries[2]["peer_id"]))
        assert entries[0]["peer_id"] < entries[1]["peer_id"] < entries[2]["peer_id"]
        expected_entries = [{"sequence": sequence, "time": now, "endpoint": endpoint, "direction": "outbound", "connection_type": "manual",
                             "peer_id": entry["peer_id"], "outcome": outcome, "reason": entry["reason"]}
                            for sequence, (outcome, entry) in enumerate(zip(outcomes + ["fallback"], entries), start=1)]
        counts = zero_counts()
        counts["outbound"]["switched"] = 3
        for outcome in outcomes:
            counts["outbound"][outcome] += 1
        counts["outbound"]["fallback"] = 1
        self.check_info(node0, start_time=start_time, enabled=True, status="enabled",
                        handshakes=counts,
                        fallback_set=[{"endpoint": endpoint, "cause": outcomes[-1], "reason": entries[2]["reason"], "streak": 3,
                                       "entered": now, "expires": now + FIRST_WINDOW, "window_seconds": FIRST_WINDOW}],
                        failure_streaks=[],
                        recent_failures={"inbound": empty_ring(), "outbound": {"last_sequence": 4, "dropped": 0, "entries": expected_entries}})

        self.log.info("Test a connection to an endpoint in the fallback set runs plain v2: getpeerinfo fallback")
        self.check_peers(0, 1, "fallback", "legacy_peer")
        node0.setmocktime(0)

    def test_counts(self):
        node0, node1, node2 = self.nodes
        self.restart_node(0, extra_args=PQ)
        self.restart_node(1, extra_args=PQ)
        self.restart_node(2, extra_args=NO_PQ)

        self.log.info("Test a hybrid connection counts one switch on each side, and the same hybrid session id")
        before0, before1 = self.handshakes(node0), self.handshakes(node1)
        self.connect_nodes(0, 1)
        self.wait_for_handshakes(node0, before0, {"outbound": {"switched": 1}})
        self.wait_for_handshakes(node1, before1, {"inbound": {"switched": 1}})
        out_peer, in_peer = self.peer(node0, inbound=False), self.peer(node1, inbound=True)
        for peer in [out_peer, in_peer]:
            assert_equal((peer["transport_protocol_type"], peer["transport_pq"], peer["transport_pq_status"]), ("v2", True, "hybrid"))
        assert re.fullmatch("[0-9a-f]{64}", out_peer["session_id"])
        assert_equal(out_peer["session_id"], in_peer["session_id"])
        self.disconnect_nodes(0, 1)
        # Our own close of a confirmed connection counts nothing more.
        self.wait_for_handshakes(node0, before0, {"outbound": {"switched": 1}})
        self.wait_for_handshakes(node1, before1, {"inbound": {"switched": 1}})

        self.log.info("Test a legacy peer counts legacy_peer, in each direction; the side with the switch off counts nothing")
        before0, before2 = self.handshakes(node0), self.handshakes(node2)
        self.connect_nodes(0, 2)
        self.disconnect_nodes(0, 2)
        self.connect_nodes(2, 0)
        self.disconnect_nodes(2, 0)
        self.wait_for_handshakes(node0, before0, {"outbound": {"legacy_peer": 1}, "inbound": {"legacy_peer": 1}})
        assert_equal(self.handshakes(node2), before2)
        ring = node0.getpqtransportinfo()["recent_failures"]
        for direction in ["inbound", "outbound"]:
            assert_equal((ring[direction]["entries"][-1]["outcome"], ring[direction]["entries"][-1]["reason"]), ("legacy_peer", "no_features"))

        self.log.info("Test -test=pq_fail_first_packet fails hybrid handshakes in both directions")
        self.restart_node(1, extra_args=PQ_FAIL)
        before0, before1 = self.handshakes(node0), self.handshakes(node1)
        out0 = self.failing_connection(0, 1)
        out1 = self.failing_connection(1, 0)
        self.wait_for_handshakes(node0, before0, {"outbound": {"switched": 1, out0: 1}, "inbound": {"switched": 1, "first_packet_failed": 1}})
        self.wait_for_handshakes(node1, before1, {"outbound": {"switched": 1, out1: 1}, "inbound": {"switched": 1, "first_packet_failed": 1}})
        for node, peer_port, outcome in [(node0, p2p_port(1), out0), (node1, p2p_port(0), out1)]:
            rings = node.getpqtransportinfo()["recent_failures"]
            outbound, inbound = rings["outbound"]["entries"][-1], rings["inbound"]["entries"][-1]
            assert_equal((outbound["outcome"], outbound["direction"], outbound["endpoint"]), (outcome, "outbound", local_endpoint(peer_port)))
            assert_equal((inbound["outcome"], inbound["direction"], inbound["connection_type"]), ("first_packet_failed", "inbound", "inbound"))
            assert inbound["reason"] in ["length", "tag"]
        self.restart_node(1, extra_args=PQ)

    def test_abandoned(self):
        node0 = self.nodes[0]

        self.log.info("Test an initiator that reads the offer and closes counts one abandoned offer (eof)")
        self.restart_node(0, extra_args=PQ)
        reader = OfferReader(p2p_port(0))
        contents = reader.read_version_contents()
        assert_equal((len(contents), contents[:4]), (OFFER_LEN, OFFER_PREFIX))
        peer = self.peer(node0, inbound=True)
        assert_equal((peer["transport_protocol_type"], peer["transport_pq"], peer["transport_pq_status"], peer["session_id"]),
                     ("detecting", False, "pending", ""))
        reader.close()
        self.wait_for_no_peers(node0)
        self.wait_for_handshakes(node0, zero_counts(), {"inbound": {"abandoned": 1}})
        entry = node0.getpqtransportinfo()["recent_failures"]["inbound"]["entries"][-1]
        entry.pop("time")
        assert_equal(entry, {"sequence": 1, "endpoint": local_endpoint(reader.local_port), "direction": "inbound",
                             "connection_type": "inbound", "peer_id": peer["id"], "outcome": "abandoned", "reason": "eof"})

        self.log.info("Test an initiator that stalls after reading the offer counts one abandoned offer (timeout)")
        self.restart_node(0, extra_args=PQ + ["-peertimeout=3"])
        reader = OfferReader(p2p_port(0))
        assert_equal(len(reader.read_version_contents()), OFFER_LEN)
        self.wait_for_no_peers(node0)
        self.wait_for_handshakes(node0, zero_counts(), {"inbound": {"abandoned": 1}})
        assert_equal(node0.getpqtransportinfo()["recent_failures"]["inbound"]["entries"][-1]["reason"], "timeout")
        reader.close()

    def test_rings(self):
        node0 = self.nodes[0]
        self.restart_node(0, extra_args=PQ)
        self.restart_node(1, extra_args=PQ_FAIL)

        self.log.info("Test inbound failures don't evict the outbound ring's entry")
        self.failing_connection(0, 1)
        outbound = node0.getpqtransportinfo()["recent_failures"]["outbound"]
        assert_equal((outbound["last_sequence"], outbound["dropped"], len(outbound["entries"])), (1, 0, 1))
        inbound = node0.getpqtransportinfo()["recent_failures"]["inbound"]
        assert_equal(inbound, empty_ring())
        failures = 300
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(abandon_offer, [p2p_port(0)] * failures))
        self.wait_for_no_peers(node0)
        self.wait_until(lambda: node0.getpqtransportinfo()["handshakes"]["inbound"]["abandoned"] == failures)
        rings = node0.getpqtransportinfo()["recent_failures"]
        assert_equal(rings["outbound"], outbound)

        self.log.info("Test the inbound ring keeps the newest 256 entries, oldest first, with contiguous sequences")
        inbound = rings["inbound"]
        assert_equal((inbound["last_sequence"], inbound["dropped"], len(inbound["entries"])), (failures, failures - RING_SIZE, RING_SIZE))
        assert_equal([entry["sequence"] for entry in inbound["entries"]], list(range(failures - RING_SIZE + 1, failures + 1)))
        assert_equal({(entry["outcome"], entry["direction"]) for entry in inbound["entries"]}, {("abandoned", "inbound")})
        self.restart_node(1, extra_args=PQ)

    def test_connection_count(self):
        node0, node1, node2 = self.nodes

        self.log.info("Test connections_pq counts the hybrid peers getpeerinfo shows")
        self.restart_node(0, extra_args=PQ)
        self.restart_node(1, extra_args=PQ)
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        peers = node0.getpeerinfo()
        assert_equal(len(peers), 2)
        assert_equal(sum(peer["transport_pq"] for peer in peers), 1)
        networkinfo = node0.getnetworkinfo()
        assert_equal((networkinfo["connections"], networkinfo["connections_pq"]), (2, 1))
        assert_equal(node1.getnetworkinfo()["connections_pq"], 1)
        assert_equal(node2.getnetworkinfo()["connections_pq"], 0)
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)

        self.log.info("Test connections_pq is 0 with the switch off")
        self.restart_node(0, extra_args=NO_PQ)
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        assert_equal(sum(peer["transport_pq"] for peer in node0.getpeerinfo()), 0)
        networkinfo = node0.getnetworkinfo()
        assert_equal((networkinfo["connections"], networkinfo["connections_pq"]), (2, 0))

    def run_test(self):
        self.test_configuration()
        self.test_portable_options()
        self.test_states()
        self.test_counts()
        self.test_abandoned()
        self.test_rings()
        self.test_connection_count()


if __name__ == '__main__':
    PQTransportTest(__file__).main()
