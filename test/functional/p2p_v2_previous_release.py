#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Baseline qbit v1.0.0's v2 transport toward non-empty version-packet contents.

The hybrid post-quantum handshake (#184) puts an ML-KEM-1024 key or ciphertext
into the BIP324 version packet, whose contents v1.0.0 ignores. This test pins
that behavior on the v1.0.0 release binary, in both roles, before any node
change lands:

- test_version_contents: v1.0.0 completes the handshake and exchanges
  application messages when the peer's version packet carries 0, 1,572 or
  65,000 bytes of contents, or record-shaped contents (CompactSize(len) ||
  header || payload): one 0xF0 record exactly as the hybrid offer and accept
  carry it (fd 21 06 f0 || 1,568 bytes), a 0xF0 record followed by an unknown
  record, and a single 65,000-byte record. Each is sent after decoy packets,
  and again after a 10 s pause, and v1.0.0's session id stays the plain BIP324
  one. As initiator it sends its version packet and its VERSION message
  without waiting for ours.
- test_limits: v1.0.0 disconnects at once when a packet's length exceeds
  MAX_CONTENTS_LEN (4,000,013 bytes), not at that length, and disconnects a
  stalled handshake at -peertimeout.

The peer is a BIP324 implementation on a plain socket, so the test decides
every byte it sends and when.
"""
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import socket
import time

from test_framework.messages import (
    msg_ping,
    msg_verack,
    msg_version,
    ser_compact_size,
)
from test_framework.p2p import (
    MESSAGEMAP,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
    P2P_VERSION_RELAY,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    assert_equal,
    assert_greater_than_or_equal,
    p2p_port,
)
from test_framework.v2_p2p import (
    LENGTH_FIELD_LEN,
    MAX_GARBAGE_LEN,
    MSGTYPE_TO_SHORTID,
    SHORTID,
    EncryptedP2PState,
)

V1_0_0 = 10000
# V2Transport's limit: the long message type encoding (1 + 12 bytes) plus MAX_PROTOCOL_MESSAGE_LENGTH.
MAX_CONTENTS_LEN = 1 + 12 + 4_000_000
PQ_MLKEM1024 = 0xF0
MLKEM1024_PAYLOAD_LEN = 1568  # an encapsulation key or a ciphertext


def record(header, payload):
    """One version-contents record: CompactSize(len) || header || payload, len counting the header."""
    return ser_compact_size(1 + len(payload)) + bytes([header]) + payload


MLKEM1024_RECORD = record(PQ_MLKEM1024, bytes((i * 7 + 3) & 0xff for i in range(MLKEM1024_PAYLOAD_LEN)))
assert MLKEM1024_RECORD[:4] == bytes.fromhex("fd2106f0") and len(MLKEM1024_RECORD) == 1572
# Version-packet contents to send, by name: raw sizes and record-shaped contents.
CONTENTS = {
    "empty": b"",
    "1,572 zero bytes": bytes(len(MLKEM1024_RECORD)),
    "65,000 zero bytes": bytes(65_000),
    "one 0xF0 ML-KEM-1024 record": MLKEM1024_RECORD,
    "a 0xF0 record and an unknown 0xF1 record": MLKEM1024_RECORD + record(0xF1, bytes(100)),
    "one 65,000-byte record": record(0xF1, bytes(65_000 - 4)),
}
assert len(CONTENTS["one 65,000-byte record"]) == 65_000
DECOY_SIZES = [0, 37, 1000]
VERSION_DELAY = 10
DEFAULT_PEER_TIMEOUT = 60
STALL_PEER_TIMEOUT = 3


class RawV2Peer:
    """A BIP324 peer on a blocking socket, driven step by step by the test."""

    def __init__(self, sock, *, initiating, timeout):
        self.sock = sock
        self.sock.settimeout(timeout)
        self.state = EncryptedP2PState(initiating=initiating, net="regtest")
        self.recvbuf = b""
        self.send_aad = b""  # our garbage until our first packet is sent
        self.recv_aad = None  # their garbage until their first packet is authenticated
        # The port v1.0.0 sees for this connection: our source port when we connect
        # to it, our listening port when it connects to us.
        self.local_port = sock.getsockname()[1]

    @classmethod
    def connect(cls, port, *, timeout):
        return cls(socket.create_connection(("127.0.0.1", port), timeout=timeout), initiating=True, timeout=timeout)

    def send(self, data):
        self.sock.sendall(data)

    def _recv_more(self):
        data = self.sock.recv(65536)
        if not data:
            raise EOFError("peer closed the connection")
        self.recvbuf += data

    def _recv_exact(self, n):
        while len(self.recvbuf) < n:
            self._recv_more()
        data, self.recvbuf = self.recvbuf[:n], self.recvbuf[n:]
        return data

    def exchange_keys(self, garbage_len=100):
        """Send our key and garbage and read theirs; derive the BIP324 keys."""
        st = self.state
        if st.initiating:
            self.send(st.generate_keypair_and_garbage(garbage_len))
            ellswift_theirs = self._recv_exact(64)
        else:
            ellswift_theirs = self._recv_exact(64)
            self.send(st.generate_keypair_and_garbage(garbage_len))
        st.initialize_v2_transport(st.v2_ecdh(st.privkey_ours, ellswift_theirs, st.ellswift_ours, st.initiating))
        self.send_aad = st.sent_garbage

    def send_terminator_and_decoys(self, decoy_sizes):
        data = self.state.peer['send_garbage_terminator']
        for size in decoy_sizes:
            data += self.state.v2_enc_packet(bytes(size), aad=self.send_aad, ignore=True)
            self.send_aad = b""
        self.send(data)

    def send_version_packet(self, contents):
        self.send(self.state.v2_enc_packet(contents, aad=self.send_aad))
        self.send_aad = b""

    def send_length_only(self, length):
        """Send just the encrypted length of a packet with the given contents length."""
        self.send(self.state.peer['send_L'].crypt(length.to_bytes(LENGTH_FIELD_LEN, 'little')))

    def _receive_packet(self):
        """Return the next non-decoy packet's contents, skipping their garbage first."""
        if self.recv_aad is None:
            terminator = self.state.peer['recv_garbage_terminator']
            while (pos := self.recvbuf.find(terminator)) == -1:
                assert len(self.recvbuf) < MAX_GARBAGE_LEN + len(terminator), "no garbage terminator"
                self._recv_more()
            self.recv_aad = self.recvbuf[:pos]
            self.recvbuf = self.recvbuf[pos + len(terminator):]
        while True:
            length, contents = self.state.v2_receive_packet(self.recvbuf, aad=self.recv_aad)
            assert length != -1, "packet authentication failed"
            if length == 0:
                self._recv_more()
                continue
            self.recvbuf = self.recvbuf[length:]
            self.recv_aad = b""
            if contents is not None:
                return contents

    def receive_version_packet(self):
        return self._receive_packet()

    def send_message(self, message):
        msgtype = message.msgtype
        if msgtype in MSGTYPE_TO_SHORTID:
            data = MSGTYPE_TO_SHORTID[msgtype].to_bytes(1, 'big')
        else:
            data = b"\x00" + msgtype.ljust(12, b"\x00")
        self.send(self.state.v2_enc_packet(data + message.serialize()))

    def receive_message(self):
        contents = self._receive_packet()
        if contents[0] == 0:
            msgtype, payload = contents[1:13].rstrip(b"\x00"), contents[13:]
        else:
            msgtype, payload = SHORTID.get(contents[0], b"unknown"), contents[1:]
        if msgtype not in MESSAGEMAP:
            return msgtype, None
        message = MESSAGEMAP[msgtype]()
        message.deserialize(BytesIO(payload))
        return msgtype, message

    def wait_for_message(self, wanted):
        while True:
            msgtype, message = self.receive_message()
            if msgtype == wanted:
                return message

    def assert_stays_open(self, seconds):
        """Read for the given time and fail if the other side closes the connection."""
        timeout = self.sock.gettimeout()
        deadline = time.time() + seconds
        self.sock.settimeout(seconds)
        try:
            while time.time() < deadline:
                self._recv_more()
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(timeout)

    def wait_for_close(self):
        """Wait until the other side closes the connection; return the time it took."""
        start = time.time()
        try:
            while True:
                self._recv_more()
        except (EOFError, ConnectionError):
            return time.time() - start

    def close(self):
        self.sock.close()


def our_version_message():
    version = msg_version()
    version.nVersion = P2P_VERSION
    version.strSubVer = P2P_SUBVERSION
    version.relay = P2P_VERSION_RELAY
    version.nServices = P2P_SERVICES
    version.addrFrom.ip = "0.0.0.0"
    version.addrFrom.port = 0
    return version


class P2PV2PreviousReleaseTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-v2transport=1", f"-peertimeout={DEFAULT_PEER_TIMEOUT}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args, versions=[V1_0_0])
        self.start_nodes()

    def run_test(self):
        self.node = self.nodes[0]
        assert_equal(self.node.getnetworkinfo()["version"], V1_0_0)
        assert "P2P_V2" in self.node.getnetworkinfo()["localservicesnames"]
        self.timeout = 30 * self.options.timeout_factor

        self.test_version_contents()
        self.test_limits()

    def open_peers(self, roles):
        """Open one raw v2 connection per role: "responder" means v1.0.0 responds (we
        connect to it), "initiator" means v1.0.0 initiates (it connects to us)."""
        peers = []
        listeners = 0
        for role in roles:
            if role == "responder":
                peers.append(RawV2Peer.connect(p2p_port(0), timeout=self.timeout))
                continue
            # Ports of unused node indexes, distinct within one call and reused by later calls.
            listeners += 1
            assert listeners < MAX_NODES
            port = p2p_port(MAX_NODES - listeners)
            with socket.create_server(("127.0.0.1", port)) as listener:
                listener.settimeout(self.timeout)
                self.node.addconnection(f"127.0.0.1:{port}", "outbound-full-relay", True)
                sock, _ = listener.accept()
            peers.append(RawV2Peer(sock, initiating=False, timeout=self.timeout))
        return peers

    def peer_info(self, peer, role):
        """v1.0.0's getpeerinfo entry for a raw peer, or None once it dropped the peer."""
        inbound = role == "responder"
        infos = [p for p in self.node.getpeerinfo() if p["addr"] == f"127.0.0.1:{peer.local_port}" and p["inbound"] == inbound]
        return infos[0] if infos else None

    def run_handshake(self, peer, role, contents, delay):
        """Handshake with decoys and the given contents, then exchange application messages.

        Runs on a worker thread, so it uses only the socket, never RPC."""
        peer.exchange_keys()
        peer.send_terminator_and_decoys(DECOY_SIZES)
        early = []
        if role == "initiator":
            # v1.0.0 as initiator does not wait for our version packet: its version
            # packet and its VERSION message are already on the way.
            early.append(peer.receive_version_packet())
            peer.wait_for_message(b"version")
        if delay:
            time.sleep(delay)
        peer.send_version_packet(contents)
        if role == "responder":
            early.append(peer.receive_version_packet())
            peer.send_message(our_version_message())
            peer.wait_for_message(b"version")
        else:
            peer.send_message(our_version_message())
        peer.send_message(msg_verack())
        peer.wait_for_message(b"verack")
        ping = msg_ping(nonce=0x5a5a0000 + len(contents))
        peer.send_message(ping)
        while peer.wait_for_message(b"pong").nonce != ping.nonce:
            pass
        return early[0]

    def check_cases(self, delay):
        cases = [(role, name) for role in ("responder", "initiator") for name in CONTENTS]
        peers = self.open_peers([role for role, _ in cases])
        with ThreadPoolExecutor(len(cases)) as pool:
            futures = [pool.submit(self.run_handshake, peer, role, CONTENTS[name], delay) for peer, (role, name) in zip(peers, cases)]
            their_contents = [f.result() for f in futures]
        for peer, (role, name), contents in zip(peers, cases, their_contents):
            self.log.debug(f"v1.0.0 as {role}, contents: {name}, {delay} s delay")
            # v1.0.0 always sends empty contents.
            assert_equal(contents, b"")
            info = self.peer_info(peer, role)
            assert info is not None, f"v1.0.0 as {role} dropped a peer whose contents were {name}"
            assert_equal(info["transport_protocol_type"], "v2")
            # The contents do not touch key derivation: the session id is plain BIP324's.
            assert_equal(info["session_id"], peer.state.peer['session_id'].hex())
            peer.close()
        self.wait_until(lambda: not self.node.getpeerinfo())

    def test_version_contents(self):
        self.log.info("v1.0.0 accepts raw and record-shaped version contents after decoys, in both roles")
        self.check_cases(delay=0)
        self.log.info(f"... and after a {VERSION_DELAY} s pause before the version packet")
        self.check_cases(delay=VERSION_DELAY)

    def test_limits(self):
        for role in ("responder", "initiator"):
            self.log.info(f"v1.0.0 as {role} waits for a packet of exactly MAX_CONTENTS_LEN bytes")
            peer, = self.open_peers([role])
            peer.exchange_keys()
            peer.send_terminator_and_decoys([])
            peer.send_length_only(MAX_CONTENTS_LEN)
            peer.assert_stays_open(2)
            assert self.peer_info(peer, role) is not None
            peer.close()
            self.wait_until(lambda: not self.node.getpeerinfo())

            self.log.info(f"v1.0.0 as {role} disconnects at once above MAX_CONTENTS_LEN")
            with self.node.assert_debug_log([f"V2 transport error: packet too large ({MAX_CONTENTS_LEN + 1} bytes)"]):
                peer, = self.open_peers([role])
                peer.exchange_keys()
                peer.send_terminator_and_decoys([])
                peer.send_length_only(MAX_CONTENTS_LEN + 1)
                assert peer.wait_for_close() < self.timeout
            peer.close()
            self.wait_until(lambda: not self.node.getpeerinfo())

        self.log.info(f"v1.0.0 disconnects a stalled handshake at -peertimeout ({STALL_PEER_TIMEOUT} s), in both roles")
        self.restart_node(0, extra_args=["-v2transport=1", f"-peertimeout={STALL_PEER_TIMEOUT}"])
        for role in ("responder", "initiator"):
            # Until a version packet arrives the transport counts as detecting, hence "V2 handshake timeout".
            with self.node.assert_debug_log(["V2 handshake timeout"]):
                start = time.time()
                peer, = self.open_peers([role])
                # Keys only: no garbage terminator, no version packet.
                peer.exchange_keys()
                peer.wait_for_close()
                elapsed = time.time() - start
            self.log.debug(f"v1.0.0 as {role} disconnected the stalled handshake after {elapsed:.1f} s")
            # The check runs once m_connected + peertimeout < now, in whole seconds.
            assert_greater_than_or_equal(elapsed, STALL_PEER_TIMEOUT - 1)
            assert elapsed < STALL_PEER_TIMEOUT + 2 + 5 * self.options.timeout_factor, elapsed
            peer.close()
            self.wait_until(lambda: not self.node.getpeerinfo())


if __name__ == '__main__':
    P2PV2PreviousReleaseTest(__file__).main()
