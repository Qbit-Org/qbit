#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Test how a node handles every way a hybrid post-quantum v2 negotiation can go wrong
(doc/design/pq-transport.md).

- test_records: version contents of every shape, as offers (the node initiates) and as accepts
  (the node responds): the connection is kept or dropped as specified, the log gives the exact
  reason, and the per-direction counters move by exactly the expected amounts.
- test_confirmation: a damaged key confirmation, or keys that don't match, disconnects at once,
  long before -peertimeout.
- test_decoys_and_partial_writes: decoys on both sides of the switch, coalesced writes and writes
  fragmented byte by byte all complete the hybrid handshake.
- test_unsolicited_accept: own-header bytes sent to a responder that made no offer are ignored.
- test_load_shedding: an inbound offer flood starts load shedding, a shed responder ignores an
  accept, outbound connections are unaffected, and the socket handler alone ends shedding once
  the flood stops. Shedding counts real seconds, so a machine too slow to outpace the threshold
  skips it.
"""

from concurrent.futures import ThreadPoolExecutor
import bisect
import os
import random
import socket
import threading
import time
import types

from test_framework.crypto.mlkem import CT_SIZE
from test_framework.messages import MAGIC_BYTES
from test_framework.p2p import NetworkThread, P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    assert_approx,
    assert_equal,
    p2p_port,
)
from test_framework.v2_p2p import (
    MAX_CONTENTS_LEN,
    PQ_RECORD_LEN,
    ser_pq_record,
)

PQ_ON = ["-v2transport=1", "-v2pqtransport=1"]
PQ_OFF = ["-v2transport=1", "-v2pqtransport=0"]
# The node's default load shedding threshold (DEFAULT_PQ_SHED_THRESHOLD_PER_S).
SHED_THRESHOLD = 1000
# Quiet seconds that end shedding (PQ_SHED_QUIET_PERIOD).
SHED_QUIET_SECONDS = 10
# The flood's connections in flight, and how long it may try to outpace the threshold.
FLOOD_THREADS = 8
FLOOD_SECONDS = 30


class ScriptedPeer(P2PInterface):
    """A Python v2 peer with some of its handshake steps replaced.

    Each keyword names an EncryptedP2PState attribute: a function replaces that method (it gets the
    state as its first argument), any other value replaces the attribute."""
    def __init__(self, **overrides):
        super().__init__()
        self.overrides = overrides

    def make_v2_state(self, **kwargs):
        state = super().make_v2_state(**kwargs)
        for name, value in self.overrides.items():
            assert hasattr(state, name), name
            setattr(state, name, types.MethodType(value, state) if callable(value) else value)
        return state


class TruncatingPeer(ScriptedPeer):
    """Sends only the first part of its version packet, then shuts down its sending side (EOF)."""
    def __init__(self, keep, **overrides):
        def send_version_packet(state, contents):
            state.sent_version_contents = contents
            return state.enc_handshake_packet(contents)[:keep]
        super().__init__(send_version_packet=send_version_packet, **overrides)
        self.closing = False

    def send_raw_message(self, raw_message_bytes):
        if self.closing:
            return  # nothing more after EOF
        super().send_raw_message(raw_message_bytes)
        if self.v2_state.sent_version_contents is not None:
            # Queued after the truncated packet, so the node receives it and then EOF. Reading on, rather
            # than closing, keeps the node's later bytes from turning the close into a reset.
            self.closing = True
            NetworkThread.network_event_loop.call_soon_threadsafe(lambda: self._transport and self._transport.write_eof())


class CoalescingPeer(ScriptedPeer):
    """Writes everything it sends within one network event as a single write."""
    def __init__(self, **overrides):
        super().__init__(**overrides)
        self.pending = b""

    def send_raw_message(self, raw_message_bytes):
        def queue():
            if not self.pending:
                NetworkThread.network_event_loop.call_soon(flush)
            self.pending += raw_message_bytes

        def flush():
            data, self.pending = self.pending, b""
            if self._transport and not self._transport.is_closing():
                self._transport.write(data)
        if not self.is_connected:
            raise IOError('Not connected')
        NetworkThread.network_event_loop.call_soon_threadsafe(queue)


class FragmentingPeer(ScriptedPeer):
    """Writes its handshake in pieces of 1, 2, 3 and 7 bytes, a millisecond apart."""
    def __init__(self, **overrides):
        super().__init__(**overrides)
        self.next_write = 0

    def send_raw_message(self, raw_message_bytes):
        def schedule():
            loop = NetworkThread.network_event_loop
            pos = 0
            sizes = [1, 2, 3, 7]
            while pos < len(raw_message_bytes):
                size = sizes[0] if not self.v2_state.tried_v2_handshake else len(raw_message_bytes)
                sizes = sizes[1:] + sizes[:1]
                self.next_write = max(self.next_write, loop.time()) + 0.001
                piece = raw_message_bytes[pos:pos + size]
                loop.call_at(self.next_write, lambda piece=piece: self._transport and self._transport.write(piece))
                pos += size
        if not self.is_connected:
            raise IOError('Not connected')
        NetworkThread.network_event_loop.call_soon_threadsafe(schedule)


def ignore_confirmation(state, response):
    """For peers whose keys won't match the node's: never complete, never fail on the node's packets."""
    return 0, True


def bad_modulus(ek):
    """ek with its first 12-bit coefficient set to 4095, which is not below q = 3329."""
    return b"\xff" + bytes([ek[1] | 0x0f]) + ek[2:]


def payload(record):
    """The payload of an offer or accept record."""
    assert_equal(len(record), PQ_RECORD_LEN)
    return record[4:]


def padding(contents_len):
    """An unknown 0xf1 record that pads contents of contents_len bytes to exactly MAX_CONTENTS_LEN."""
    remaining = MAX_CONTENTS_LEN - contents_len
    # CompactSize (5 bytes for these sizes) || header || payload
    record = ser_pq_record(bytes(remaining - 6), header=0xF1)
    assert_equal(len(record), remaining)
    return record


def counters(node):
    info = node.getpqtransportinfo()["handshakes"]
    return {f"{direction}_{key}": value for direction in ("inbound", "outbound") for key, value in info[direction].items()}


class P2PV2PQMisbehavingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [PQ_ON]

    def run_test(self):
        self.protect_outbound_endpoint()
        self.test_records()
        self.test_confirmation()
        self.test_decoys_and_partial_writes()
        self.test_unsolicited_accept()
        self.test_load_shedding()

    def protect_outbound_endpoint(self):
        """Outbound peers here all listen on one endpoint. A confirmed hybrid handshake protects it until
        restart, so that the failures below never put it in the fallback set (p2p_v2_pq_fallback.py
        tests that)."""
        node = self.nodes[0]
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0, supports_v2_pq=True)
        assert_equal(peer.v2_state.pq_status, "hybrid")
        self.disconnect_python_peers()

    def disconnect_python_peers(self):
        node = self.nodes[0]
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def expect(self, before, **deltas):
        """Wait until the node's counters moved by exactly deltas (missing keys: 0) since before."""
        node = self.nodes[0]
        expected = {key: value + deltas.pop(key, 0) for key, value in before.items()}
        assert_equal(deltas, {})  # every key named is a real counter
        self.wait_until(lambda: counters(node) == expected)

    def run_case(self, *, inbound, peer, kept, status=None, logs, deltas, **connect_args):
        """Connect a scripted Python peer and check the outcome.

        inbound: the Python peer initiates (the node responds); otherwise the node initiates.
        kept: the connection survives, with status as the node's transport_pq_status; otherwise the
            node drops it at once.
        logs: exact debug log lines (or prefixes) the case produces."""
        node = self.nodes[0]
        before = counters(node)
        with node.assert_debug_log(logs):
            if inbound:
                node.add_p2p_connection(peer, supports_v2_pq=peer.overrides.pop("pq", True),
                                        wait_for_verack=kept, wait_for_v2_handshake=kept, expect_success=kept,
                                        **connect_args)
            elif kept:
                node.add_outbound_p2p_connection(peer, p2p_idx=0, supports_v2_pq=peer.overrides.pop("pq", True),
                                                 **connect_args)
            else:
                # Not add_outbound_p2p_connection(): it waits to see the connection open, which a
                # connection the node drops at once may never be.
                listening = threading.Event()
                peer.peer_accept_connection(
                    connect_cb=lambda addr, port: listening.set(), connect_id=1, net=node.chain,
                    timeout_factor=node.timeout_factor, supports_v2_p2p=True,
                    supports_v2_pq=peer.overrides.pop("pq", True), reconnect=False)()
                node.p2ps.append(peer)
                self.wait_until(listening.is_set)
                node.addconnection(f"127.0.0.1:{p2p_port(MAX_NODES - 1)}", "outbound-full-relay", True)
            if kept:
                peer.sync_with_ping()
                [info] = node.getpeerinfo()
                assert_equal(info["transport_pq_status"], status)
                assert_equal(info["transport_pq"], status == "hybrid")
            else:
                # The node closes at once: -peertimeout is far longer than this wait.
                self.wait_until(lambda: peer.v2_state is not None and peer.v2_state.sent_version_contents is not None,
                                timeout=10)
                peer.wait_for_disconnect(timeout=10)
        self.disconnect_python_peers()
        self.expect(before, **deltas)

    def test_records(self):
        self.log.info("Offers of every shape: the node initiates")
        for name, contents, kept, logs, deltas in [
            ("ek one byte short", lambda offer: ser_pq_record(payload(offer)[:-1]), False,
             ["V2 transport error: malformed hybrid record (ek_length)",
              "v2 pq: malformed_record reason=ek_length role=initiator conn_type=outbound-full-relay peer="],
             {"outbound_malformed_record": 1}),
            ("ek one byte long", lambda offer: ser_pq_record(payload(offer) + b"\x00"), False,
             ["v2 pq: malformed_record reason=ek_length role=initiator"], {"outbound_malformed_record": 1}),
            ("ek fails the modulus check", lambda offer: ser_pq_record(bad_modulus(payload(offer))), False,
             ["V2 transport error: malformed hybrid record (ek_modulus)",
              "v2 pq: malformed_record reason=ek_modulus role=initiator"], {"outbound_malformed_record": 1}),
            ("a malformed own record before a valid one", lambda offer: ser_pq_record(payload(offer)[:-1]) + offer, False,
             ["v2 pq: malformed_record reason=ek_length role=initiator"], {"outbound_malformed_record": 1}),
            ("the first of two own records wins", lambda offer: offer + ser_pq_record(b"\x00"), True,
             ["v2 pq: switched role=initiator conn_type=outbound-full-relay peer="], {"outbound_switched": 1}),
            ("an unknown record, then the offer", lambda offer: ser_pq_record(b"\x01", header=0xF1) + offer, True,
             ["v2 pq: switched role=initiator"], {"outbound_switched": 1}),
            ("an offer followed by junk", lambda offer: offer + b"\x05", True,
             ["v2 pq: legacy_peer reason=parse_error role=initiator conn_type=outbound-full-relay peer="],
             {"outbound_legacy_peer": 1}),
            ("a zero record length", lambda offer: b"\x00" + offer, True,
             ["v2 pq: legacy_peer reason=parse_error role=initiator"], {"outbound_legacy_peer": 1}),
            ("a non-canonical record length", lambda offer: b"\xfd\x02\x00\xf0\x00", True,
             ["v2 pq: legacy_peer reason=parse_error role=initiator"], {"outbound_legacy_peer": 1}),
            ("a record length past the end", lambda offer: b"\xfd\xff\xff" + offer, True,
             ["v2 pq: legacy_peer reason=parse_error role=initiator"], {"outbound_legacy_peer": 1}),
            ("a record length above MAX_SIZE", lambda offer: b"\xfe\x01\x00\x00\x02" + offer, True,
             ["v2 pq: legacy_peer reason=parse_error role=initiator"], {"outbound_legacy_peer": 1}),
            ("a truncated record length", lambda offer: offer + b"\xfd\x21", True,
             ["v2 pq: legacy_peer reason=parse_error role=initiator"], {"outbound_legacy_peer": 1}),
            ("only an unknown record", lambda offer: ser_pq_record(b"\x01\x02", header=0xF1), True,
             ["v2 pq: legacy_peer reason=no_features role=initiator"], {"outbound_legacy_peer": 1}),
            ("only a reserved 0x00 record", lambda offer: ser_pq_record(b"", header=0x00), True,
             ["v2 pq: legacy_peer reason=no_features role=initiator"], {"outbound_legacy_peer": 1}),
            ("an offer padded to the largest contents", lambda offer: offer + padding(len(offer)), True,
             ["v2 pq: switched role=initiator"], {"outbound_switched": 1}),
        ]:
            self.log.info(f"- {name}")
            peer = ScriptedPeer(make_offer_contents=lambda state, offer, contents=contents: contents(offer))
            status = None if not kept else "hybrid" if "outbound_switched" in deltas else "legacy_peer"
            self.run_case(inbound=False, peer=peer, kept=kept, status=status, logs=logs, deltas=deltas)

        self.log.info("- a version packet longer than the largest contents")
        def too_long(state, contents):
            state.sent_version_contents = contents
            return state.peer['send_L'].crypt((MAX_CONTENTS_LEN + 1).to_bytes(3, 'little'))
        self.run_case(inbound=False, peer=ScriptedPeer(send_version_packet=too_long), kept=False,
                      logs=[f"V2 transport error: packet too large ({MAX_CONTENTS_LEN + 1} bytes)"], deltas={})
        self.log.info("- a truncated version packet, then EOF")
        self.run_case(inbound=False, peer=TruncatingPeer(keep=PQ_RECORD_LEN // 2), kept=False,
                      logs=["socket closed, disconnecting peer="], deltas={})

        self.log.info("Accepts of every shape: the node responds")
        for name, contents, kept, logs, deltas in [
            ("ct one byte short", lambda accept: ser_pq_record(payload(accept)[:-1]), False,
             ["V2 transport error: malformed hybrid record (ct_length)",
              "v2 pq: malformed_record reason=ct_length role=responder conn_type=inbound peer="],
             {"inbound_malformed_record": 1}),
            ("ct one byte long", lambda accept: ser_pq_record(payload(accept) + b"\x00"), False,
             ["v2 pq: malformed_record reason=ct_length role=responder"], {"inbound_malformed_record": 1}),
            ("a malformed own record before a valid one", lambda accept: ser_pq_record(b"") + accept, False,
             ["v2 pq: malformed_record reason=ct_length role=responder"], {"inbound_malformed_record": 1}),
            ("the first of two own records wins", lambda accept: accept + ser_pq_record(bytes(CT_SIZE)), True,
             ["v2 pq: switched role=responder conn_type=inbound peer="], {"inbound_switched": 1}),
            ("unknown records around the accept",
             lambda accept: ser_pq_record(b"", header=0x01) + accept + ser_pq_record(b"\xaa", header=0xF1), True,
             ["v2 pq: switched role=responder"], {"inbound_switched": 1}),
            ("an accept padded to the largest contents", lambda accept: accept + padding(len(accept)), True,
             ["v2 pq: switched role=responder"], {"inbound_switched": 1}),
        ]:
            self.log.info(f"- {name}")
            peer = ScriptedPeer(make_accept_contents=lambda state, accept, contents=contents: contents(accept))
            if not kept:
                peer.overrides["receive_confirmation"] = ignore_confirmation
            self.run_case(inbound=True, peer=peer, kept=kept, status="hybrid", logs=logs, deltas=deltas)

        # A peer whose contents don't parse, or carry no accept, is a legacy peer: it keeps the ECDH keys.
        accept_like = ser_pq_record(os.urandom(CT_SIZE))
        for name, contents, reason in [
            ("an accept followed by junk", accept_like + b"\x05", "parse_error"),
            ("a zero record length", b"\x00", "parse_error"),
            ("a non-canonical record length", b"\xfd\x02\x00\xf0\x00", "parse_error"),
            ("a record length past the end", b"\xfe\x00\x00\x01\x00" + accept_like, "parse_error"),
            ("a record length above MAX_SIZE", b"\xff" + (2**32).to_bytes(8, 'little') + accept_like, "parse_error"),
            ("a truncated record", accept_like[:-1], "parse_error"),
            ("only unknown records", ser_pq_record(b"", header=0xF1) + ser_pq_record(b"\x00" * 300, header=0x7F),
             "no_features"),
            ("empty contents", b"", "no_features"),
        ]:
            self.log.info(f"- {name}")
            self.run_case(inbound=True, peer=ScriptedPeer(transport_version=contents, pq=False), kept=True,
                          status="legacy_peer",
                          logs=[f"v2 pq: legacy_peer reason={reason} role=responder conn_type=inbound peer="],
                          deltas={"inbound_legacy_peer": 1})

        self.log.info("- a version packet longer than the largest contents")
        self.run_case(inbound=True, peer=ScriptedPeer(send_version_packet=too_long, pq=False), kept=False,
                      logs=[f"V2 transport error: packet too large ({MAX_CONTENTS_LEN + 1} bytes)",
                            "v2 pq: abandoned reason=version_length role=responder conn_type=inbound peer="],
                      deltas={"inbound_abandoned": 1})
        self.log.info("- a version packet with a damaged tag")
        def damaged_tag(state, contents):
            state.sent_version_contents = contents
            packet = state.enc_handshake_packet(contents)
            return packet[:-1] + bytes([packet[-1] ^ 0x80])
        self.run_case(inbound=True, peer=ScriptedPeer(send_version_packet=damaged_tag, pq=False), kept=False,
                      logs=["V2 transport error: packet decryption failure",
                            "v2 pq: abandoned reason=version_tag role=responder conn_type=inbound peer="],
                      deltas={"inbound_abandoned": 1})
        self.log.info("- a truncated version packet, then EOF")
        self.run_case(inbound=True, peer=TruncatingPeer(keep=10, pq=False), kept=False,
                      logs=["v2 pq: abandoned reason=eof role=responder conn_type=inbound peer="],
                      deltas={"inbound_abandoned": 1})

    def test_confirmation(self):
        def damage(kind):
            def make_confirmation(state):
                if kind == "length":
                    return state.v2_enc_packet(b"\x00", aad=b"", ignore=True)
                if kind == "not_decoy":
                    return state.v2_enc_packet(b"", aad=b"", ignore=False)
                confirmation = state.v2_enc_packet(b"", aad=b"", ignore=True)
                return confirmation[:-1] + bytes([confirmation[-1] ^ 1])
            return make_confirmation

        for inbound, role, conn_type in ((True, "responder", "inbound"), (False, "initiator", "outbound-full-relay")):
            direction = "inbound" if inbound else "outbound"
            for kind in ("length", "tag", "not_decoy"):
                self.log.info(f"A confirmation that fails the {kind} check: the node is the {role}")
                self.run_case(inbound=inbound, peer=ScriptedPeer(make_confirmation=damage(kind)), kept=False,
                              logs=[f"V2 transport error: key confirmation failed ({kind})",
                                    f"v2 pq: first_packet_failed reason={kind} role={role} conn_type={conn_type} peer="],
                              deltas={f"{direction}_switched": 1, f"{direction}_first_packet_failed": 1})

        # Keys that don't match decrypt the confirmation's length to a random value, which is not 0.
        self.log.info("A corrupted ct: the node decapsulates another secret and fails the confirmation at once")
        def corrupt_ct(state, accept):
            return accept[:-1] + bytes([accept[-1] ^ 1])
        self.run_case(inbound=True, peer=ScriptedPeer(make_accept_contents=corrupt_ct,
                                                      receive_confirmation=ignore_confirmation), kept=False,
                      logs=["V2 transport error: key confirmation failed (length)",
                            "v2 pq: first_packet_failed reason=length role=responder"],
                      deltas={"inbound_switched": 1, "inbound_first_packet_failed": 1})
        self.log.info("A responder that derives another shared secret: the node fails the confirmation at once")
        def wrong_secret(state):
            return bytes([state.mlkem_shared_secret[0] ^ 0xff]) + state.mlkem_shared_secret[1:]
        self.run_case(inbound=False, peer=ScriptedPeer(hybrid_shared_secret=wrong_secret,
                                                       receive_confirmation=ignore_confirmation), kept=False,
                      logs=["V2 transport error: key confirmation failed (length)",
                            "v2 pq: first_packet_failed reason=length role=initiator"],
                      deltas={"outbound_switched": 1, "outbound_first_packet_failed": 1})

    def test_decoys_and_partial_writes(self):
        def decoys(state):
            # The first one authenticates the garbage (AAD), the later ones and the version packet don't.
            return b"".join(state.enc_handshake_packet(bytes(size), ignore=True) for size in (1, 100, 1000))

        def confirmation_then_decoys(state):
            confirmation = state.v2_enc_packet(b"", aad=b"", ignore=True)
            return confirmation + b"".join(state.v2_enc_packet(bytes(size), ignore=True) for size in (0, 7, 500))

        for peer_class, overrides, what in [
            (ScriptedPeer, {"make_decoys": decoys}, "decoys before the version packet (ECDH keys)"),
            (ScriptedPeer, {"make_confirmation": confirmation_then_decoys},
             "decoys after the confirmation (hybrid keys)"),
            (ScriptedPeer, {"make_decoys": decoys, "make_confirmation": confirmation_then_decoys}, "both"),
            (CoalescingPeer, {"make_decoys": decoys}, "each burst coalesced into one write"),
            (FragmentingPeer, {"make_decoys": decoys}, "the handshake fragmented into 1- to 7-byte writes"),
        ]:
            for inbound, role in ((True, "responder"), (False, "initiator")):
                self.log.info(f"The node as {role}: {what}")
                direction = "inbound" if inbound else "outbound"
                self.run_case(inbound=inbound, peer=peer_class(**overrides), kept=True, status="hybrid",
                              logs=[f"v2 pq: switched role={role}"], deltas={f"{direction}_switched": 1})

    def test_unsolicited_accept(self):
        node = self.nodes[0]
        self.log.info("A switched-off responder ignores an accept it never asked for: no decapsulation, no switch")
        self.restart_node(0, extra_args=PQ_OFF)
        before = counters(node)
        with node.assert_debug_log([], unexpected_msgs=["v2 pq:", "malformed hybrid record"]):
            peer = node.add_p2p_connection(ScriptedPeer(transport_version=ser_pq_record(os.urandom(CT_SIZE))))
            [info] = node.getpeerinfo()
            assert_equal((info["transport_pq"], info["transport_pq_status"]), (False, "off"))
            assert_equal(info["session_id"], peer.v2_state.peer["session_id"].hex())
            assert_equal(peer.v2_state.received_version_contents, b"")
        self.disconnect_python_peers()
        assert_equal(counters(node), before)
        self.restart_node(0, extra_args=PQ_ON)
        self.protect_outbound_endpoint()

    def flood_offers(self, count):
        """Open count inbound v2 connections, several at a time, that each send just a 64-byte public key (the
        point at which a responder decides whether to offer), then close and wait for the node to close too.
        Returns when each connection ended (time.monotonic())."""
        node = self.nodes[0]
        magic = MAGIC_BYTES[node.chain]

        def one_offer(_):
            key = bytes([magic[0] ^ 0xff]) + random.randbytes(63)
            with socket.create_connection(("127.0.0.1", p2p_port(node.index))) as sock:
                sock.sendall(key)
                sock.shutdown(socket.SHUT_WR)
                while sock.recv(65536):
                    pass
            return time.monotonic()
        with ThreadPoolExecutor(max_workers=FLOOD_THREADS) as pool:
            return list(pool.map(one_offer, range(count)))

    def test_load_shedding(self):
        node = self.nodes[0]
        self.log.info(f"More than {SHED_THRESHOLD} offers within one second start load shedding")
        # The node counts offers per second of its steady clock, which setmocktime doesn't move: the flood
        # has to beat the threshold in real time. Flood in short bursts until the node sheds.
        before = counters(node)
        ended = []
        deadline = time.monotonic() + FLOOD_SECONDS * self.options.timeout_factor
        with node.assert_debug_log([f"v2 pq: load_shedding started threshold_per_s={SHED_THRESHOLD}"]):
            while not node.getpqtransportinfo()["load_shedding"]["active"] and time.monotonic() < deadline:
                ended += self.flood_offers(SHED_THRESHOLD // 2)
            if not node.getpqtransportinfo()["load_shedding"]["active"]:
                # Any 1 s window holding more than twice the threshold puts more than the threshold in one
                # of the node's seconds; a slower machine can't tell us anything.
                ended.sort()
                peak = max(bisect.bisect_left(ended, t + 1) - i for i, t in enumerate(ended))
                assert peak <= 2 * SHED_THRESHOLD, f"no shedding although {peak} offers ended within one second"
                self.log.warning(f"Skipping the load shedding test: at most {peak} offers ended within one second here")
                return
        # Each connection was one attempt, offered (then abandoned at EOF) or shed; the node offered the
        # first SHED_THRESHOLD of the second it started shedding in.
        self.wait_until(lambda: (counters(node)["inbound_abandoned"] + counters(node)["inbound_shed"]
                                 - before["inbound_abandoned"] - before["inbound_shed"]) == len(ended))
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        flood = counters(node)
        assert flood["inbound_abandoned"] - before["inbound_abandoned"] >= SHED_THRESHOLD
        assert flood["inbound_shed"] - before["inbound_shed"] >= 1
        assert_equal({key: value for key, value in flood.items() if key not in ("inbound_abandoned", "inbound_shed")},
                     {key: value for key, value in before.items() if key not in ("inbound_abandoned", "inbound_shed")})
        shedding = node.getpqtransportinfo()["load_shedding"]
        assert_equal((shedding["active"], shedding["threshold_per_s"]), (True, SHED_THRESHOLD))
        assert_approx(shedding["since"], time.time(), vspan=60)

        self.log.info("A shedding responder sends no offer: a hybrid initiator sees a legacy responder")
        peer = node.add_p2p_connection(P2PInterface(), supports_v2_pq=True)
        assert_equal((peer.v2_state.pq_status, peer.v2_state.received_version_contents), ("legacy_peer", b""))
        [info] = node.getpeerinfo()
        assert_equal((info["transport_pq"], info["transport_pq_status"]), (False, "off"))
        self.disconnect_python_peers()
        self.log.info("A shedding responder ignores an accept: no decapsulation, no switch")
        with node.assert_debug_log([], unexpected_msgs=["v2 pq: switched", "malformed hybrid record"]):
            peer = node.add_p2p_connection(ScriptedPeer(transport_version=ser_pq_record(os.urandom(CT_SIZE))))
            assert_equal(node.getpeerinfo()[0]["transport_pq_status"], "off")
            assert_equal(node.getpeerinfo()[0]["session_id"], peer.v2_state.peer["session_id"].hex())
        self.disconnect_python_peers()
        self.log.info("Outbound connections still negotiate while inbound offers are shed")
        node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0, supports_v2_pq=True)
        assert_equal(node.getpeerinfo()[0]["transport_pq_status"], "hybrid")
        self.disconnect_python_peers()
        self.expect(flood, inbound_shed=2, outbound_switched=1)
        assert node.getpqtransportinfo()["load_shedding"]["active"]

        self.log.info(f"With no offers at all, the socket handler ends shedding after {SHED_QUIET_SECONDS} quiet seconds")
        # Nothing connects from here on: only the socket handler's own clock check can end it.
        self.wait_until(lambda: not node.getpqtransportinfo()["load_shedding"]["active"],
                        timeout=SHED_QUIET_SECONDS + 30)
        assert_equal(node.getpqtransportinfo()["load_shedding"],
                     {"active": False, "threshold_per_s": SHED_THRESHOLD, "since": 0})
        with open(node.debug_log_path, encoding="utf-8") as log:
            assert_equal(sum("v2 pq: load_shedding stopped" in line for line in log), 1)
        self.log.info("Offers resume")
        peer = node.add_p2p_connection(P2PInterface(), supports_v2_pq=True)
        assert_equal((peer.v2_state.pq_status, len(peer.v2_state.received_version_contents)), ("hybrid", PQ_RECORD_LEN))
        self.disconnect_python_peers()

if __name__ == '__main__':
    P2PV2PQMisbehavingTest(__file__).main()
