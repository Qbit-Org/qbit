#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Test the hybrid post-quantum v2 transport end to end (doc/design/pq-transport.md).

- test_node_roles: two upgraded nodes switch to hybrid keys in both connection directions, agree on
  the session id, and keep exchanging packets across the 224-packet rekey in each direction.
- test_python_roles: the test framework's independent Python implementation, as initiator and as
  responder, derives the same keys as the node, and the node draws fresh ML-KEM randomness for
  every connection.
- test_legacy_and_switches: legacy v2 peers, v1 peers and every switch combination get the
  transport_pq_status each role and setting calls for.
- test_pending_confirmation: a connection whose peer withholds its key confirmation reports pending
  with no session id, and hybrid only once the confirmation arrives.
"""

from test_framework.crypto.chacha20 import REKEY_INTERVAL
from test_framework.crypto.mlkem import EK_SIZE, CT_SIZE, mlkem1024_check_ek
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_not_equal,
)
from test_framework.v2_p2p import (
    PQ_RECORD_LEN,
    ParseKind,
    parse_version_contents,
)

PQ_ON = ["-v2transport=1", "-v2pqtransport=1"]
PQ_OFF = ["-v2transport=1", "-v2pqtransport=0"]
# A v2 ping: an encrypted length (3), the header (1), the short message id (1), the nonce (8) and the tag (16).
V2_PING_BYTES = 29


def node_view(node, p2p):
    """The node's getpeerinfo entry for a Python peer, found by the peer's own socket address."""
    sockname = p2p._transport.get_extra_info("socket").getsockname()
    infos = [info for info in node.getpeerinfo() if info["addr"] == f"{sockname[0]}:{sockname[1]}"]
    assert_equal(len(infos), 1)
    return infos[0]


class WithholdingPeer(P2PInterface):
    """A hybrid Python peer that holds back its key confirmation until send_pq_confirmation()."""
    def make_v2_state(self, **kwargs):
        state = super().make_v2_state(**kwargs)
        state.withhold_confirmation = True
        return state


class FixedKeyPeer(P2PInterface):
    """A hybrid Python responder whose ML-KEM key pair is the same on every connection."""
    def make_v2_state(self, **kwargs):
        state = super().make_v2_state(**kwargs)
        draws = [bytes([1]) * 32, bytes([2]) * 32]
        state.pq_random_bytes = lambda n: draws.pop(0)
        return state


class P2PV2PQTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [PQ_ON, PQ_ON]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.test_node_roles()
        self.test_python_roles()
        self.test_legacy_and_switches()
        self.test_pending_confirmation()

    def node_pair(self, a, b):
        """Connect node a to node b and return both sides' getpeerinfo entries."""
        self.connect_nodes(a, b)
        [outbound] = self.nodes[a].getpeerinfo()
        [inbound] = self.nodes[b].getpeerinfo()
        assert_equal((outbound["inbound"], inbound["inbound"]), (False, True))
        return outbound, inbound

    def test_node_roles(self):
        self.log.info("Two upgraded nodes switch to hybrid keys with either one initiating")
        for a, b in ((0, 1), (1, 0)):
            with self.nodes[a].assert_debug_log(["v2 pq: switched role=initiator"]), \
                 self.nodes[b].assert_debug_log(["v2 pq: switched role=responder"]):
                outbound, inbound = self.node_pair(a, b)
            for info in (outbound, inbound):
                assert_equal(info["transport_protocol_type"], "v2")
                assert_equal(info["transport_pq"], True)
                assert_equal(info["transport_pq_status"], "hybrid")
                assert_equal(len(info["session_id"]), 64)
            assert_equal(outbound["session_id"], inbound["session_id"])

            self.log.info(f"More than {REKEY_INTERVAL} packets flow each way under the hybrid keys (node{a} initiating)")
            count = REKEY_INTERVAL + 10
            for sender, peer in ((self.nodes[a], outbound), (self.nodes[b], inbound)):
                for _ in range(count):
                    sender.sendmsgtopeer(peer_id=peer["id"], msg_type="ping", msg="00" * 8)
            # Each node received at least `count` pings and `count` pongs: every one of them a packet
            # under the hybrid keys, past the first rekey in both directions.
            for node in (self.nodes[a], self.nodes[b]):
                self.wait_until(lambda node=node: all(
                    node.getpeerinfo()[0]["bytesrecv_per_msg"].get(msg, 0) >= count * V2_PING_BYTES
                    for msg in ("ping", "pong")))
                [info] = node.getpeerinfo()
                assert_equal(info["transport_pq_status"], "hybrid")
            assert_equal(self.nodes[a].getpeerinfo()[0]["session_id"], outbound["session_id"])
            self.disconnect_nodes(a, b)

    def check_hybrid(self, node, peer):
        """Both sides report the hybrid keys and the same session id."""
        info = node_view(node, peer)
        assert_equal(info["transport_protocol_type"], "v2")
        assert_equal(info["transport_pq"], True)
        assert_equal(info["transport_pq_status"], "hybrid")
        assert_equal(peer.v2_state.pq_status, "hybrid")
        assert_equal(info["session_id"], peer.v2_state.peer["session_id"].hex())
        assert_equal(peer.v2_state.hybrid_keys["session_id"], peer.v2_state.peer["session_id"])
        peer.sync_with_ping()

    def test_python_roles(self):
        node = self.nodes[0]
        self.log.info("A Python hybrid initiator and the node agree on the hybrid keys")
        offers = []
        for _ in range(2):
            peer = node.add_p2p_connection(P2PInterface(), supports_v2_pq=True)
            self.check_hybrid(node, peer)
            offer = peer.v2_state.received_version_contents
            assert_equal(len(offer), PQ_RECORD_LEN)
            kind, ek = parse_version_contents(offer)
            assert_equal((kind, len(ek)), (ParseKind.OWN_RECORD, EK_SIZE))
            assert mlkem1024_check_ek(ek)
            assert_equal(len(peer.v2_state.sent_version_contents), PQ_RECORD_LEN)
            offers.append(offer)
        self.log.info("The node offers a fresh encapsulation key on every connection")
        assert_not_equal(offers[0], offers[1])
        node.disconnect_p2ps()

        self.log.info("A Python hybrid responder and the node agree on the hybrid keys")
        accepts = []
        session_ids = []
        for i in range(2):
            # The same encapsulation key both times: the node must still encapsulate to fresh randomness.
            peer = node.add_outbound_p2p_connection(FixedKeyPeer(), p2p_idx=i, supports_v2_pq=True)
            self.check_hybrid(node, peer)
            accept = peer.v2_state.received_version_contents
            kind, ct = parse_version_contents(accept)
            assert_equal((len(accept), kind, len(ct)), (PQ_RECORD_LEN, ParseKind.OWN_RECORD, CT_SIZE))
            accepts.append(accept)
            session_ids.append(peer.v2_state.peer["session_id"])
        assert_equal(len(set(accepts)), 2)
        assert_equal(len(set(session_ids)), 2)
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def check_status(self, node, peer, status, received_contents_len):
        """The node's status for a legacy or switched-off pairing, and what the Python peer received."""
        info = node_view(node, peer)
        assert_equal(info["transport_pq"], False)
        assert_equal(info["transport_pq_status"], status)
        if status == "v1":
            assert_equal(info["transport_protocol_type"], "v1")
            return
        assert_equal(info["transport_protocol_type"], "v2")
        # The ECDH session id, as the Python peer derived it.
        assert_equal(info["session_id"], peer.v2_state.peer["session_id"].hex())
        assert_equal(peer.v2_state.hybrid_keys, None)
        assert_equal(len(peer.v2_state.received_version_contents), received_contents_len)
        peer.sync_with_ping()

    def test_legacy_and_switches(self):
        node = self.nodes[0]
        for setting, args in (("on", PQ_ON), ("off", PQ_OFF)):
            self.restart_node(0, extra_args=args)
            pq_on = setting == "on"
            self.log.info(f"Switch {setting}: legacy and hybrid Python v2 peers, both roles")
            # A legacy Python peer accepts the node's offer (non-empty contents) and answers with empty ones.
            peer = node.add_p2p_connection(P2PInterface())
            self.check_status(node, peer, "legacy_peer" if pq_on else "off", PQ_RECORD_LEN if pq_on else 0)
            assert_equal(peer.v2_state.sent_version_contents, b"")
            peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
            self.check_status(node, peer, "legacy_peer" if pq_on else "off", 0)
            if not pq_on:
                # A switched-off node never offers, and never accepts the offer of a hybrid peer.
                peer = node.add_p2p_connection(P2PInterface(), supports_v2_pq=True)
                self.check_status(node, peer, "off", 0)
                assert_equal(peer.v2_state.pq_status, "legacy_peer")
                peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, supports_v2_pq=True)
                self.check_status(node, peer, "off", 0)
                assert_equal(len(peer.v2_state.sent_version_contents), PQ_RECORD_LEN)
                assert_equal(peer.v2_state.pq_status, "legacy_peer")

            self.log.info(f"Switch {setting}: v1 Python peers, both roles")
            peer = node.add_p2p_connection(P2PInterface(), supports_v2_p2p=False)
            self.check_status(node, peer, "v1", None)
            peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=2, advertise_v2_p2p=False)
            self.check_status(node, peer, "v1", None)
            node.disconnect_p2ps()
            self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("Two nodes with each combination of switches")
        expected = {
            # (initiator on, responder on): (initiator status, responder status)
            (True, True): ("hybrid", "hybrid"),
            (True, False): ("legacy_peer", "off"),
            (False, True): ("off", "legacy_peer"),
            (False, False): ("off", "off"),
        }
        for (initiator_on, responder_on), statuses in expected.items():
            self.restart_node(0, extra_args=PQ_ON if initiator_on else PQ_OFF)
            self.restart_node(1, extra_args=PQ_ON if responder_on else PQ_OFF)
            outbound, inbound = self.node_pair(0, 1)
            assert_equal((outbound["transport_pq_status"], inbound["transport_pq_status"]), statuses)
            assert_equal(outbound["transport_pq"], statuses[0] == "hybrid")
            assert_equal(inbound["transport_pq"], statuses[1] == "hybrid")
            assert_equal(outbound["session_id"], inbound["session_id"])
            self.disconnect_nodes(0, 1)

        self.log.info("A v1 connection between two switched-on nodes reports v1")
        self.restart_node(1, extra_args=PQ_ON)
        self.restart_node(0, extra_args=PQ_ON)
        self.connect_nodes(0, 1, peer_advertises_v2=False)
        for node in self.nodes:
            [info] = node.getpeerinfo()
            assert_equal((info["transport_protocol_type"], info["transport_pq"], info["transport_pq_status"]),
                         ("v1", False, "v1"))
        self.disconnect_nodes(0, 1)

    def test_pending_confirmation(self):
        node = self.nodes[0]
        for role in ("initiator", "responder"):
            self.log.info(f"A Python {role} that withholds its key confirmation leaves the node pending")
            peer = WithholdingPeer()
            if role == "initiator":
                node.add_p2p_connection(peer, supports_v2_pq=True, wait_for_v2_handshake=False,
                                        wait_for_verack=False, expect_success=False)
            else:
                node.add_outbound_p2p_connection(peer, p2p_idx=0, supports_v2_pq=True, wait_for_v2_handshake=False)
            # The node switched and its confirmation verified at the Python peer.
            peer.wait_for_connect()
            peer.wait_until(lambda: peer.v2_state.peer_confirmed)
            info = node_view(node, peer)
            assert_equal((info["transport_protocol_type"], info["session_id"]), ("detecting", ""))
            assert_equal((info["transport_pq"], info["transport_pq_status"]), (False, "pending"))
            assert not peer.v2_state.tried_v2_handshake

            self.log.info(f"The connection reports hybrid once the {role}'s confirmation arrives")
            peer.send_pq_confirmation()
            peer.wait_until(lambda: peer.v2_state.tried_v2_handshake)
            peer.wait_for_verack()
            self.check_hybrid(node, peer)
            node.disconnect_p2ps()
            self.wait_until(lambda: len(node.getpeerinfo()) == 0)


if __name__ == '__main__':
    P2PV2PQTest(__file__).main()
