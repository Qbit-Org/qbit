#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Test the bounded fallback to plain v2 after repeated hybrid post-quantum failures with one
endpoint (#184, doc/design/pq-transport.md).

- test_three_failures: three explicit outbound attempts whose key confirmation fails put the
  endpoint in the fallback set; the fourth connection is plain v2 with status fallback, and one
  warning line says so.
- test_malformed_offer_fallback: against a responder that always sends a malformed offer, the
  fourth connection succeeds, because a fallback connection neither parses nor validates offers.
- test_inbound_and_success_exclusion: inbound failures never lead to a fallback, and neither do
  outbound failures after a hybrid success with the same endpoint.
- test_expiry_and_restart: the hybrid negotiation is tried again once the window expires (and the
  next window is longer), and a restart clears all of it under a new instance_id.
- test_endpoint_separation: through a SOCKS5 proxy, two hostnames (in any letter case, with or
  without the root dot), one hostname on two ports, and one address on two ports each keep their
  own history: a name-proxy destination is its hostname and port, never the proxy.

addconnection can't open manual connections, so explicit outbound attempts use addnode onetry.
"""

import threading

from test_framework.p2p import P2PInterface
from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    assert_equal,
    assert_not_equal,
    p2p_port,
)

PQ_ON = ["-v2transport=1", "-v2pqtransport=1"]
FAIL_FIRST_PACKET = "-test=pq_fail_first_packet"
# Counted failures (the outbound counters that advance a streak) and the fallback windows.
COUNTED = ("outbound_malformed_record", "outbound_first_packet_failed", "outbound_closed_after_switch")
FIRST_WINDOW = 3600
SECOND_WINDOW = 4 * 3600
# The fake public address the SOCKS5 proxy maps to Python peers.
PROXIED_IP = "15.61.23.23"


def responder_port(idx):
    """The port a Python responder with connect_id idx listens on (NetworkThread.listen())."""
    return p2p_port(MAX_NODES - idx)


def counters(node):
    info = node.getpqtransportinfo()["handshakes"]
    return {f"{direction}_{key}": value for direction in ("inbound", "outbound") for key, value in info[direction].items()}


def counted_failures(node):
    return sum(counters(node)[key] for key in COUNTED)


def address_endpoint(address, port):
    return {"kind": "address", "network": "ipv4", "address": address, "port": port}


def name_endpoint(hostname, port):
    return {"kind": "name_proxy", "network": "name_proxy", "address": hostname, "port": port}


def bad_modulus_offer(state, offer):
    """An offer whose key fails the FIPS 203 modulus check: its first coefficient is 4095."""
    return offer[:4] + b"\xff" + bytes([offer[5] | 0x0f]) + offer[6:]


class MalformedOfferPeer(P2PInterface):
    """A hybrid Python responder that always offers a key failing the modulus check."""
    def make_v2_state(self, **kwargs):
        state = super().make_v2_state(**kwargs)
        state.make_offer_contents = bad_modulus_offer.__get__(state)
        return state


class BadConfirmationPeer(P2PInterface):
    """A hybrid Python initiator whose key confirmation is not a decoy."""
    def make_v2_state(self, **kwargs):
        state = super().make_v2_state(**kwargs)
        state.make_confirmation = lambda: state.v2_enc_packet(b"", aad=b"", ignore=False)
        return state


class P2PV2PQFallbackTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [PQ_ON, PQ_ON]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.test_three_failures()
        self.test_expiry_and_restart()
        self.test_malformed_offer_fallback()
        self.test_inbound_and_success_exclusion()
        self.test_endpoint_separation()

    def wait_no_peers(self, *nodes):
        for node in nodes:
            self.wait_until(lambda node=node: len(node.getpeerinfo()) == 0)

    def connect_responder(self, node, peer, *, idx, target=None):
        """Let a Python responder listen on its own port and make node open a manual connection to it
        (to target, through a proxy that leads there, if given)."""
        listening = threading.Event()
        peer.peer_accept_connection(connect_cb=lambda addr, port: listening.set(), connect_id=idx, net=node.chain,
                                    timeout_factor=node.timeout_factor, supports_v2_p2p=True,
                                    supports_v2_pq=True, reconnect=False)()
        node.p2ps.append(peer)
        # The RPC call comes from this thread, not the network thread's callback: the RPC connection is
        # not shared across threads.
        self.wait_until(listening.is_set)
        node.addnode(node=target or f"127.0.0.1:{responder_port(idx)}", command="onetry")
        return responder_port(idx)

    def test_three_failures(self):
        node_a, node_b = self.nodes
        self.log.info("Three failed key confirmations with one endpoint put it in the fallback set")
        self.restart_node(0, extra_args=PQ_ON + [FAIL_FIRST_PACKET])
        target = f"127.0.0.1:{p2p_port(1)}"
        b_before = counters(node_b)
        for attempt in range(1, 4):
            expected = ["v2 pq: switched role=initiator conn_type=manual peer="]
            unexpected = ["v2 pq: fallback"]
            if attempt == 3:
                expected.append("v2 pq: fallback cause=")
                unexpected = []
            with node_a.assert_debug_log(expected, unexpected_msgs=unexpected):
                node_a.addnode(node=target, command="onetry")
                self.wait_until(lambda: counted_failures(node_a) == attempt)
                self.wait_no_peers(node_a, node_b)
        a_counts = counters(node_a)
        assert_equal(a_counts["outbound_switched"], 3)
        assert_equal(a_counts["outbound_fallback"], 1)
        # node B saw node A's damaged confirmation each time; inbound failures never count.
        b_counts = counters(node_b)
        assert_equal(b_counts["inbound_first_packet_failed"] - b_before["inbound_first_packet_failed"], 3)
        assert_equal(b_counts["outbound_fallback"], 0)

        info = node_a.getpqtransportinfo()
        assert_equal(info["failure_streaks"], [])
        [entry] = info["fallback_set"]
        assert_equal(entry["endpoint"], address_endpoint("127.0.0.1", p2p_port(1)))
        assert entry["cause"] in ("first_packet_failed", "closed_after_switch")
        assert_equal((entry["streak"], entry["window_seconds"]), (3, FIRST_WINDOW))
        assert_equal(entry["expires"] - entry["entered"], FIRST_WINDOW)
        ring = info["recent_failures"]["outbound"]["entries"]
        assert_equal([e["outcome"] for e in ring][-1], "fallback")
        assert_equal(ring[-1]["reason"], entry["cause"])
        assert_equal(ring[-1]["endpoint"], entry["endpoint"])
        assert_equal(len([e for e in ring if e["outcome"] in ("first_packet_failed", "closed_after_switch")]), 3)
        with open(node_a.debug_log_path, encoding="utf-8") as log:
            warnings = [line for line in log if "v2 pq: fallback cause=" in line]
        assert_equal(len(warnings), 1)
        assert f"v2 pq: fallback cause={entry['cause']} until=" in warnings[0]
        assert "role=initiator conn_type=manual" in warnings[0]

        self.log.info("The fourth connection is plain v2, with status fallback")
        before = counters(node_a)
        with node_a.assert_debug_log([], unexpected_msgs=["v2 pq: switched", "v2 pq: fallback"]):
            self.connect_nodes(0, 1)
        [outbound] = node_a.getpeerinfo()
        [inbound] = node_b.getpeerinfo()
        assert_equal((outbound["transport_protocol_type"], outbound["transport_pq"], outbound["transport_pq_status"]),
                     ("v2", False, "fallback"))
        # A fallback connection sends empty contents, so node B sees a legacy initiator.
        assert_equal((inbound["transport_pq"], inbound["transport_pq_status"]), (False, "legacy_peer"))
        assert_equal(outbound["session_id"], inbound["session_id"])
        assert_equal(counters(node_a), before)
        self.disconnect_nodes(0, 1)

    def test_expiry_and_restart(self):
        node_a, node_b = self.nodes
        self.log.info("Once the window expires, the next connection tries the hybrid keys again")
        [entry] = node_a.getpqtransportinfo()["fallback_set"]
        for node in self.nodes:
            node.setmocktime(entry["expires"])
        with node_a.assert_debug_log(["v2 pq: switched role=initiator conn_type=manual"],
                                     unexpected_msgs=["v2 pq: fallback cause="]):
            node_a.addnode(node=f"127.0.0.1:{p2p_port(1)}", command="onetry")
            self.wait_until(lambda: counted_failures(node_a) == 4)
            self.wait_no_peers(node_a, node_b)
        info = node_a.getpqtransportinfo()
        assert_equal(info["fallback_set"], [])
        [streak] = info["failure_streaks"]
        assert_equal(streak["endpoint"], address_endpoint("127.0.0.1", p2p_port(1)))
        # The streak restarted, and the escalation stays: the next window is the second one.
        assert_equal((streak["streak"], streak["next_window_seconds"]), (1, SECOND_WINDOW))
        assert_equal(info["handshakes"]["outbound"]["fallback"], 1)

        self.log.info("A restart clears the history and starts a new counting period")
        instance_id = info["instance_id"]
        for node in self.nodes:
            node.setmocktime(0)
        self.restart_node(0, extra_args=PQ_ON)
        info = node_a.getpqtransportinfo()
        assert_not_equal(info["instance_id"], instance_id)
        assert_equal(len(info["instance_id"]), 64)
        assert_equal((info["fallback_set"], info["failure_streaks"]), ([], []))
        assert_equal(set(counters(node_a).values()), {0})
        self.connect_nodes(0, 1)
        assert_equal(node_a.getpeerinfo()[0]["transport_pq_status"], "hybrid")
        self.disconnect_nodes(0, 1)

    def test_malformed_offer_fallback(self):
        node_a = self.nodes[0]
        self.log.info("Three malformed offers from one responder put it in the fallback set")
        self.restart_node(0, extra_args=PQ_ON)
        port = None
        for attempt in range(1, 4):
            with node_a.assert_debug_log(["v2 pq: malformed_record reason=ek_modulus role=initiator conn_type=manual"]):
                peer = MalformedOfferPeer()
                port = self.connect_responder(node_a, peer, idx=1)
                self.wait_until(lambda: counters(node_a)["outbound_malformed_record"] == attempt)
                peer.wait_for_disconnect()
                self.wait_no_peers(node_a)
        [entry] = node_a.getpqtransportinfo()["fallback_set"]
        assert_equal(entry["endpoint"], address_endpoint("127.0.0.1", port))
        assert_equal((entry["cause"], entry["reason"], entry["streak"]), ("malformed_record", "ek_modulus", 3))

        self.log.info("The fourth connection ignores the malformed offer and completes as plain v2")
        before = counters(node_a)
        peer = MalformedOfferPeer()
        self.connect_responder(node_a, peer, idx=1)
        peer.wait_for_connect()
        peer.wait_for_verack()
        peer.sync_with_ping()
        [info] = node_a.getpeerinfo()
        assert_equal((info["transport_protocol_type"], info["transport_pq_status"]), ("v2", "fallback"))
        assert_equal((peer.v2_state.pq_status, peer.v2_state.received_version_contents), ("legacy_peer", b""))
        assert_equal(info["session_id"], peer.v2_state.peer["session_id"].hex())
        assert_equal(counters(node_a), before)
        node_a.disconnect_p2ps()
        self.wait_no_peers(node_a)

    def test_inbound_and_success_exclusion(self):
        node_a = self.nodes[0]
        self.log.info("Repeated inbound failures never lead to a fallback")
        self.restart_node(0, extra_args=PQ_ON)
        for attempt in range(1, 5):
            peer = node_a.add_p2p_connection(BadConfirmationPeer(), supports_v2_pq=True, wait_for_verack=False,
                                             wait_for_v2_handshake=False, expect_success=False)
            self.wait_until(lambda: counters(node_a)["inbound_first_packet_failed"] == attempt)
            peer.wait_for_disconnect()
            self.wait_no_peers(node_a)
        info = node_a.getpqtransportinfo()
        assert_equal((info["fallback_set"], info["failure_streaks"]), ([], []))
        assert_equal(counters(node_a)["outbound_fallback"], 0)
        peer = node_a.add_p2p_connection(P2PInterface(), supports_v2_pq=True)
        assert_equal(node_a.getpeerinfo()[0]["transport_pq_status"], "hybrid")
        node_a.disconnect_p2ps()
        self.wait_no_peers(node_a)

        self.log.info("Outbound failures after a hybrid success with the same endpoint never lead to a fallback")
        peer = P2PInterface()
        self.connect_responder(node_a, peer, idx=2)
        peer.wait_for_connect()
        peer.wait_for_verack()
        assert_equal(node_a.getpeerinfo()[0]["transport_pq_status"], "hybrid")
        node_a.disconnect_p2ps()
        self.wait_no_peers(node_a)
        for attempt in range(1, 5):
            peer = MalformedOfferPeer()
            self.connect_responder(node_a, peer, idx=2)
            self.wait_until(lambda: counters(node_a)["outbound_malformed_record"] == attempt)
            peer.wait_for_disconnect()
            self.wait_no_peers(node_a)
        info = node_a.getpqtransportinfo()
        assert_equal((info["fallback_set"], info["failure_streaks"]), ([], []))
        assert_equal(counters(node_a)["outbound_fallback"], 0)

    def test_endpoint_separation(self):
        node_a = self.nodes[0]
        self.log.info("Through a SOCKS5 proxy, every hostname, port and address keeps its own history")
        # Every destination leads to the same Python responder: only the endpoint node A accounts the
        # outcome to differs.
        conf = Socks5Configuration()
        conf.addr = ("127.0.0.1", p2p_port(self.num_nodes))
        conf.unauth = conf.auth = True
        conf.destinations_factory = lambda addr, port: {"actual_to_addr": "127.0.0.1", "actual_to_port": responder_port(3)}
        proxy = Socks5Server(conf)
        proxy.start()
        self.restart_node(0, extra_args=PQ_ON + [f"-proxy={conf.addr[0]}:{conf.addr[1]}"])

        attempts = [
            # (what node A connects to, the endpoint it is accounted to)
            ("alpha.pqtest:9001", name_endpoint("alpha.pqtest", 9001)),
            ("ALPHA.PQtest.:9001", name_endpoint("alpha.pqtest", 9001)),
            ("beta.pqtest:9001", name_endpoint("beta.pqtest", 9001)),
            ("alpha.pqtest:9002", name_endpoint("alpha.pqtest", 9002)),
            (f"{PROXIED_IP}:9001", address_endpoint(PROXIED_IP, 9001)),
            (f"{PROXIED_IP}:9001", address_endpoint(PROXIED_IP, 9001)),
            (f"{PROXIED_IP}:9002", address_endpoint(PROXIED_IP, 9002)),
            ("Alpha.pqtest:9001", name_endpoint("alpha.pqtest", 9001)),
        ]
        for i, (target, endpoint) in enumerate(attempts, start=1):
            self.log.info(f"- {target}")
            peer = MalformedOfferPeer()
            self.connect_responder(node_a, peer, idx=3, target=target)
            self.wait_until(lambda: counters(node_a)["outbound_malformed_record"] == i)
            peer.wait_for_disconnect()
            self.wait_no_peers(node_a)
            if i == 3:
                # A third failure, but with two endpoints: no fallback yet.
                assert_equal(node_a.getpqtransportinfo()["fallback_set"], [])

        info = node_a.getpqtransportinfo()
        [entry] = info["fallback_set"]
        assert_equal(entry["endpoint"], name_endpoint("alpha.pqtest", 9001))
        assert_equal((entry["cause"], entry["streak"]), ("malformed_record", 3))
        streaks = sorted((s["endpoint"]["kind"], s["endpoint"]["address"], s["endpoint"]["port"], s["streak"])
                         for s in info["failure_streaks"])
        assert_equal(streaks, [
            ("address", PROXIED_IP, 9001, 2),
            ("address", PROXIED_IP, 9002, 1),
            ("name_proxy", "alpha.pqtest", 9002, 1),
            ("name_proxy", "beta.pqtest", 9001, 1),
        ])

        self.log.info("Only the endpoint in the fallback set runs plain v2")
        before = counters(node_a)
        peer = MalformedOfferPeer()
        self.connect_responder(node_a, peer, idx=3, target="alpha.pqtest.:9001")
        peer.wait_for_connect()
        peer.wait_for_verack()
        assert_equal(node_a.getpeerinfo()[0]["transport_pq_status"], "fallback")
        node_a.disconnect_p2ps()
        self.wait_no_peers(node_a)
        assert_equal(counters(node_a), before)
        peer = MalformedOfferPeer()
        self.connect_responder(node_a, peer, idx=3, target="beta.pqtest:9001")
        self.wait_until(lambda: counters(node_a)["outbound_malformed_record"] == len(attempts) + 1)
        peer.wait_for_disconnect()
        self.wait_no_peers(node_a)
        proxy.stop()


if __name__ == '__main__':
    P2PV2PQFallbackTest(__file__).main()
