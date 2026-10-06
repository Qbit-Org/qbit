#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for v2 P2P protocol (see BIP 324), with qbit's opt-in hybrid post-quantum key exchange
(doc/design/pq-transport.md)"""

from enum import Enum
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import random
import unittest

from .crypto.bip324_cipher import (
    FSChaCha20Poly1305,
    hybrid_ciphers,
    hybrid_derive_keys,
    hybrid_transcript_input,
    ser_compact_size,
)
from .crypto.chacha20 import FSChaCha20
from .crypto.ellswift import ellswift_create, ellswift_ecdh_xonly
from .crypto.hkdf import hkdf_sha256
from .crypto.mlkem import (
    CT_SIZE,
    EK_SIZE,
    mlkem1024_check_ek,
    mlkem1024_decaps,
    mlkem1024_encaps,
    mlkem1024_keygen,
)
from .key import TaggedHash
from .messages import MAGIC_BYTES


CHACHA20POLY1305_EXPANSION = 16
HEADER_LEN = 1
IGNORE_BIT_POS = 7
LENGTH_FIELD_LEN = 3
MAX_GARBAGE_LEN = 4095

# Hybrid post-quantum negotiation (doc/design/pq-transport.md).
PQ_MLKEM1024 = 0xF0  # record header of the ML-KEM-1024 offer (responder) and accept (initiator)
PQ_RECORD_LEN = 1572  # CompactSize(1569) || header || 1,568-byte payload
PQ_CONFIRMATION_LEN = 20  # encrypted length (3) || encrypted header (1) || tag (16)
# The largest packet contents a node accepts (src/net.cpp): a 0x00 byte, a 12-byte message type and
# MAX_PROTOCOL_MESSAGE_LENGTH bytes. It bounds the version packet contents too.
MAX_CONTENTS_LEN = 1 + 12 + 4_000_000
# ReadCompactSize's range check (MAX_SIZE in src/serialize.h).
MAX_COMPACT_SIZE = 0x02000000


class ParseKind(Enum):
    """What parse_version_contents() found, as PQHandshake::ParseContents reports it."""
    NO_RECORD = 0
    INVALID_GRAMMAR = 1
    OWN_RECORD = 2


def ser_pq_record(payload, header=PQ_MLKEM1024):
    """A version-contents record: CompactSize(1 + len(payload)) || header || payload."""
    return ser_compact_size(1 + len(payload)) + bytes([header]) + payload


def parse_version_contents(contents):
    """Parse version packet contents as records, the way a node does.

    The whole contents must parse; a zero, non-canonical, oversized or truncated length anywhere
    gives INVALID_GRAMMAR. Otherwise the first own (0xF0) record wins. Returns (kind, payload),
    where payload is the first own record's payload for OWN_RECORD and None otherwise."""
    pos = 0
    first = None
    while pos < len(contents):
        prefix = contents[pos]
        size = {0xfd: 2, 0xfe: 4, 0xff: 8}.get(prefix, 0)
        if pos + 1 + size > len(contents):
            return ParseKind.INVALID_GRAMMAR, None
        length = int.from_bytes(contents[pos + 1:pos + 1 + size], 'little') if size else prefix
        if size and length < {2: 253, 4: 0x10000, 8: 0x100000000}[size]:
            return ParseKind.INVALID_GRAMMAR, None  # non-canonical
        pos += 1 + size
        if length > MAX_COMPACT_SIZE or length == 0 or length > len(contents) - pos:
            return ParseKind.INVALID_GRAMMAR, None
        if contents[pos] == PQ_MLKEM1024 and first is None:
            first = contents[pos + 1:pos + length]
        pos += length
    if first is None:
        return ParseKind.NO_RECORD, None
    return ParseKind.OWN_RECORD, first

SHORTID = {
    1: b"addr",
    2: b"block",
    3: b"blocktxn",
    4: b"cmpctblock",
    5: b"feefilter",
    6: b"filteradd",
    7: b"filterclear",
    8: b"filterload",
    9: b"getblocks",
    10: b"getblocktxn",
    11: b"getdata",
    12: b"getheaders",
    13: b"headers",
    14: b"inv",
    15: b"mempool",
    16: b"merkleblock",
    17: b"notfound",
    18: b"ping",
    19: b"pong",
    20: b"sendcmpct",
    21: b"tx",
    22: b"getcfilters",
    23: b"cfilter",
    24: b"getcfheaders",
    25: b"cfheaders",
    26: b"getcfcheckpt",
    27: b"cfcheckpt",
    28: b"addrv2",
}

# Dictionary which contains short message type ID for the P2P message
MSGTYPE_TO_SHORTID = {msgtype: shortid for shortid, msgtype in SHORTID.items()}


class EncryptedP2PState:
    """A class for managing the state when v2 P2P protocol is used. Performs initial v2 handshake and encrypts/decrypts
    P2P messages. P2PConnection uses an object of this class.


    Args:
        initiating (bool): defines whether the P2PConnection is an initiator or responder.
            - initiating = True for inbound connections in the test framework   [TestNode <------- P2PConnection]
            - initiating = False for outbound connections in the test framework [TestNode -------> P2PConnection]

        net (string): chain used (regtest, signet etc..)

        supports_v2_pq (bool): negotiate qbit's hybrid post-quantum keys (doc/design/pq-transport.md). A
            responder offers an ML-KEM-1024 encapsulation key in its version packet; an initiator holds its
            version packet until the responder's arrives and accepts a valid offer. After a switch, each
            side's first packet under the hybrid keys is a key confirmation. Without it (the default), the
            peer is a legacy BIP324 peer: it sends empty version contents and ignores the peer's.

    Methods:
        perform an advanced form of diffie-hellman handshake to instantiate the encrypted transport. before exchanging
        any P2P messages, 2 nodes perform this handshake in order to determine a shared secret that is unique to both
        of them and use it to derive keys to encrypt/decrypt P2P messages.
            - initial v2 handshakes is performed by: (see BIP324 section #overall-handshake-pseudocode)
                1. initiator using initiate_v2_handshake(), complete_handshake() and authenticate_handshake()
                2. responder using respond_v2_handshake(), complete_handshake() and authenticate_handshake()
            - initialize_v2_transport() sets various BIP324 derived keys and ciphers.

        encrypt/decrypt v2 P2P messages using v2_enc_packet() and v2_receive_packet().
    """
    def __init__(self, *, initiating, net, supports_v2_pq=False):
        self.initiating = initiating  # True if initiator
        self.net = net
        self.peer = {}  # object with various BIP324 derived keys and ciphers
        self.privkey_ours = None
        self.ellswift_ours = None
        self.ellswift_theirs = None
        self.sent_garbage = b""
        self.received_garbage = b""
        self.received_prefix = b""  # received ellswift bytes till the first mismatch from 16 bytes v1_prefix
        self.tried_v2_handshake = False  # True when the initial handshake is over
        # stores length of packet contents to detect whether first 3 bytes (which contains length of packet contents)
        # has been decrypted. set to -1 if decryption hasn't been done yet.
        self.contents_len = -1
        self.found_garbage_terminator = False
        self.transport_version = b''
        # Hybrid post-quantum negotiation. Tests read these; subclasses may override the make_* methods.
        self.supports_v2_pq = supports_v2_pq
        # The version packet contents each side sent: None until sent or received.
        self.sent_version_contents = None
        self.received_version_contents = None
        # The negotiation outcome from this side's view: None while it runs, then "hybrid" or "legacy_peer"
        # (or "off" without supports_v2_pq).
        self.pq_status = None
        self.ecdh_secret = None  # the BIP324 ECDH secret, which the hybrid keys also use
        self.mlkem_dk = None  # responder: the decapsulation key of our offer
        self.mlkem_shared_secret = None
        self.hybrid_keys = None  # hybrid_derive_keys() output after a switch
        # The AAD of our next packet: the garbage we sent, until our first packet after the garbage terminator.
        self.send_aad = None
        # After a switch: our key confirmation, while withheld; whether we sent it; whether the peer's verified.
        self.withhold_confirmation = False
        self.held_confirmation = None
        self.confirmation_sent = False
        self.peer_confirmed = False
        self.confirmation_len = -1  # the decrypted length of the peer's key confirmation, once received

    @staticmethod
    def v2_ecdh(priv, ellswift_theirs, ellswift_ours, initiating):
        """Compute BIP324 shared secret.

        Returns:
        bytes - BIP324 shared secret
        """
        ecdh_point_x32 = ellswift_ecdh_xonly(ellswift_theirs, priv)
        if initiating:
            # Initiating, place our public key encoding first.
            return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_ours + ellswift_theirs + ecdh_point_x32)
        else:
            # Responding, place their public key encoding first.
            return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_theirs + ellswift_ours + ecdh_point_x32)

    def generate_keypair_and_garbage(self, garbage_len=None):
        """Generates ellswift keypair and 4095 bytes garbage at max"""
        self.privkey_ours, self.ellswift_ours = ellswift_create()
        if garbage_len is None:
            garbage_len = random.randrange(MAX_GARBAGE_LEN + 1)
        self.sent_garbage = random.randbytes(garbage_len)
        return self.ellswift_ours + self.sent_garbage

    def initiate_v2_handshake(self):
        """Initiator begins the v2 handshake by sending its ellswift bytes and garbage

        Returns:
        bytes - bytes to be sent to the peer when starting the v2 handshake as an initiator
        """
        return self.generate_keypair_and_garbage()

    def respond_v2_handshake(self, response):
        """Responder begins the v2 handshake by sending its ellswift bytes and garbage. However, the responder
        sends this after having received at least one byte that mismatches 16-byte v1_prefix.

        Returns:
        1. int - length of bytes that were consumed so that recvbuf can be updated
        2. bytes - bytes to be sent to the peer when starting the v2 handshake as a responder.
                 - returns b"" if more bytes need to be received before we can respond and start the v2 handshake.
                 - returns -1 to downgrade the connection to v1 P2P.
        """
        v1_prefix = MAGIC_BYTES[self.net] + b'version\x00\x00\x00\x00\x00'
        while len(self.received_prefix) < 16:
            byte = response.read(1)
            # return b"" if we need to receive more bytes
            if not byte:
                return len(self.received_prefix), b""
            self.received_prefix += byte
            if self.received_prefix[-1] != v1_prefix[len(self.received_prefix) - 1]:
                return len(self.received_prefix), self.generate_keypair_and_garbage()
        # return -1 to decide v1 only after all 16 bytes processed
        return len(self.received_prefix), -1

    def complete_handshake(self, response):
        """ Instantiates the encrypted transport and
        sends garbage terminator + optional decoy packets + transport version packet.
        Done by both initiator and responder.

        A hybrid initiator (supports_v2_pq) holds its version packet until the responder's arrives, and a
        hybrid responder offers an ML-KEM-1024 encapsulation key in its version packet.

        Returns:
        1. int - length of bytes that were consumed. returns 0 if all 64 bytes from ellswift haven't been received yet.
        2. bytes - bytes to be sent to the peer when completing the v2 handshake
        """
        ellswift_theirs = self.received_prefix + response.read(64 - len(self.received_prefix))
        # return b"" if we need to receive more bytes
        if len(ellswift_theirs) != 64:
            return 0, b""
        self.ellswift_theirs = ellswift_theirs
        self.ecdh_secret = self.v2_ecdh(self.privkey_ours, ellswift_theirs, self.ellswift_ours, self.initiating)
        self.initialize_v2_transport(self.ecdh_secret)
        # Send garbage terminator
        msg_to_send = self.peer['send_garbage_terminator']
        # Optionally send decoy packets after garbage terminator.
        self.send_aad = self.sent_garbage
        msg_to_send += self.make_decoys()
        if self.supports_v2_pq and self.initiating:
            # Hold the version packet: it answers the responder's offer, if any.
            return 64 - len(self.received_prefix), msg_to_send
        if self.supports_v2_pq:
            # Offer an encapsulation key, from two independent 32-byte draws (d || z).
            ek, self.mlkem_dk = mlkem1024_keygen(self.pq_random_bytes(32) + self.pq_random_bytes(32))
            contents = self.make_offer_contents(ser_pq_record(ek))
        else:
            contents = self.transport_version
        # Send version packet.
        msg_to_send += self.send_version_packet(contents)
        return 64 - len(self.received_prefix), msg_to_send

    def authenticate_handshake(self, response):
        """ Ensures that the received optional decoy packets and transport version packet are authenticated, and
        after a switch to hybrid keys, that the peer's key confirmation verifies.
        Marks the v2 handshake as complete. Done by both initiator and responder.

        The handshake is complete after the peer's version packet, or after a switch once the peer's key
        confirmation verified and ours was sent (see withhold_confirmation and release_confirmation()).

        Returns:
        1. int - length of bytes that were processed so that recvbuf can be updated
        2. bool - True if the authentication was successful/more bytes need to be received and False otherwise
        3. bytes - bytes to send to the peer: a hybrid initiator's version packet and either side's key confirmation
        """
        processed_length = 0
        to_send = b""

        # Detect garbage terminator in the received bytes
        if not self.found_garbage_terminator:
            received_garbage = response[:16]
            response = response[16:]
            processed_length = len(received_garbage)
            for i in range(MAX_GARBAGE_LEN + 1):
                if received_garbage[-16:] == self.peer['recv_garbage_terminator']:
                    # Receive, decode, and ignore version packet.
                    # This includes skipping decoys and authenticating the received garbage.
                    self.found_garbage_terminator = True
                    self.received_garbage = received_garbage[:-16]
                    break
                else:
                    # don't update recvbuf since more bytes need to be received
                    if len(response) == 0:
                        return 0, True, to_send
                    received_garbage += response[:1]
                    processed_length += 1
                    response = response[1:]
            else:
                # disconnect since garbage terminator was not seen after 4 KiB of garbage.
                return processed_length, False, to_send

        # Process optional decoy packets and transport version packet
        while self.received_version_contents is None:
            length, contents = self.v2_receive_packet(response, aad=self.received_garbage)
            if length == -1:
                return processed_length, False, to_send
            elif length == 0:
                return processed_length, True, to_send
            processed_length += length
            response = response[length:]
            self.received_garbage = b""
            # decoy packets have contents = None. the version packet (can be empty with contents = b"") has
            # contents != None.
            if contents is not None:
                self.received_version_contents = contents
                ok, version_bytes = self.process_version_contents(contents)
                to_send += version_bytes
                if not ok:
                    return processed_length, False, to_send

        # After a switch, the peer's first packet under the hybrid keys must be its key confirmation.
        if self.hybrid_keys is not None and not self.peer_confirmed:
            length, ok = self.receive_confirmation(response)
            if not ok:
                return processed_length, False, to_send
            processed_length += length
        self.check_handshake_complete()
        return processed_length, True, to_send

    def check_handshake_complete(self):
        """Mark the handshake complete once nothing is left to exchange before application messages."""
        if self.received_version_contents is None:
            return
        if self.hybrid_keys is None or (self.peer_confirmed and self.confirmation_sent):
            self.tried_v2_handshake = True

    def process_version_contents(self, contents):
        """Act on the peer's version packet contents.

        Returns:
        1. bool - False to disconnect
        2. bytes - bytes to send: a held version packet and our key confirmation
        """
        if not self.supports_v2_pq:
            # A legacy BIP324 peer ignores the contents, whatever they are.
            self.pq_status = "off"
            return True, b""
        kind, payload = parse_version_contents(contents)
        if self.initiating:
            if kind != ParseKind.OWN_RECORD:
                # A legacy responder (or contents that do not parse): send the held, empty version packet.
                self.pq_status = "legacy_peer"
                return True, self.send_version_packet(b"")
            if len(payload) != EK_SIZE or not mlkem1024_check_ek(payload):
                return False, b""
            self.mlkem_shared_secret, ct = mlkem1024_encaps(payload, self.pq_random_bytes(32))
            # The accept travels under the ECDH keys, then both directions switch.
            to_send = self.send_version_packet(self.make_accept_contents(ser_pq_record(ct)))
            return True, to_send + self.switch_to_hybrid()
        if kind != ParseKind.OWN_RECORD:
            # A legacy initiator: keep the ECDH keys.
            self.pq_status = "legacy_peer"
            self.mlkem_dk = None
            return True, b""
        if len(payload) != CT_SIZE:
            return False, b""
        self.mlkem_shared_secret = mlkem1024_decaps(self.mlkem_dk, payload)
        self.mlkem_dk = None
        return True, self.switch_to_hybrid()

    def switch_to_hybrid(self):
        """Replace all four packet ciphers and the session id with the hybrid ones, and return our key
        confirmation (or b"" if it is withheld)."""
        if self.initiating:
            contents_initiator, contents_responder = self.sent_version_contents, self.received_version_contents
            ellswift_initiator, ellswift_responder = self.ellswift_ours, self.ellswift_theirs
        else:
            contents_initiator, contents_responder = self.received_version_contents, self.sent_version_contents
            ellswift_initiator, ellswift_responder = self.ellswift_theirs, self.ellswift_ours
        transcript_hash = hashlib.sha256(hybrid_transcript_input(
            ellswift_initiator, ellswift_responder, contents_responder, contents_initiator)).digest()
        self.hybrid_keys = hybrid_derive_keys(self.ecdh_secret, self.hybrid_shared_secret(), transcript_hash,
                                              MAGIC_BYTES[self.net])
        (self.peer['send_L'], self.peer['send_P'],
         self.peer['recv_L'], self.peer['recv_P']) = hybrid_ciphers(self.hybrid_keys, initiator=self.initiating)
        self.peer['session_id'] = self.hybrid_keys['session_id']
        self.held_confirmation = self.make_confirmation()
        if self.withhold_confirmation:
            return b""
        return self.release_confirmation()

    def release_confirmation(self):
        """Return our key confirmation to send, after a switch. The caller sends it before any later packet."""
        assert self.held_confirmation is not None and not self.confirmation_sent
        confirmation, self.held_confirmation = self.held_confirmation, None
        self.confirmation_sent = True
        return confirmation

    def receive_confirmation(self, response):
        """Check the peer's first packet under the hybrid keys: an empty decoy with empty AAD.

        Returns:
        1. int - number of bytes consumed
        2. bool - False on a failed confirmation"""
        if self.confirmation_len == -1:
            if len(response) < LENGTH_FIELD_LEN:
                return 0, True
            self.confirmation_len = int.from_bytes(self.peer['recv_L'].crypt(response[:LENGTH_FIELD_LEN]), 'little')
            # A key mismatch decrypts to a random length: fail now rather than wait for its bytes.
            if self.confirmation_len != 0:
                return 0, False
        if len(response) < PQ_CONFIRMATION_LEN:
            return 0, True
        plaintext = self.peer['recv_P'].decrypt(b"", response[LENGTH_FIELD_LEN:PQ_CONFIRMATION_LEN])
        if plaintext is None or not plaintext[0] & (1 << IGNORE_BIT_POS):
            return 0, False
        self.peer_confirmed = True
        self.pq_status = "hybrid"
        return PQ_CONFIRMATION_LEN, True

    def send_version_packet(self, contents):
        """Encrypt our version packet under the ECDH keys."""
        self.sent_version_contents = contents
        return self.enc_handshake_packet(contents)

    def enc_handshake_packet(self, contents, ignore=False):
        """Encrypt a packet before our version packet is sent: the first one authenticates our garbage."""
        packet = self.v2_enc_packet(contents, aad=self.send_aad, ignore=ignore)
        self.send_aad = b""
        return packet

    # Overridable parts of the handshake, for tests of misbehaving peers.

    def make_decoys(self):
        """Decoy packets to send between our garbage terminator and our version packet."""
        return b"".join(self.enc_handshake_packet(random.randint(1, 100) * b'\x00', ignore=True)
                        for _ in range(random.randint(0, 10)))

    def make_offer_contents(self, offer):
        """The responder's version packet contents, given its offer record."""
        return offer

    def make_accept_contents(self, accept):
        """The initiator's version packet contents, given its accept record."""
        return accept

    def hybrid_shared_secret(self):
        """The ML-KEM-1024 shared secret the hybrid keys are derived from."""
        return self.mlkem_shared_secret

    def make_confirmation(self):
        """Our key confirmation: an empty decoy packet with empty AAD, the first packet under the hybrid keys."""
        return self.v2_enc_packet(b"", aad=b"", ignore=True)

    def pq_random_bytes(self, n):
        """Randomness for ML-KEM key generation and encapsulation."""
        return os.urandom(n)

    def initialize_v2_transport(self, ecdh_secret):
        """Sets the peer object with various BIP324 derived keys and ciphers."""
        peer = {}
        salt = b'bitcoin_v2_shared_secret' + MAGIC_BYTES[self.net]
        for name in ('initiator_L', 'initiator_P', 'responder_L', 'responder_P', 'garbage_terminators', 'session_id'):
            peer[name] = hkdf_sha256(salt=salt, ikm=ecdh_secret, info=name.encode('utf-8'), length=32)
        if self.initiating:
            self.peer['send_L'] = FSChaCha20(peer['initiator_L'])
            self.peer['send_P'] = FSChaCha20Poly1305(peer['initiator_P'])
            self.peer['send_garbage_terminator'] = peer['garbage_terminators'][:16]
            self.peer['recv_L'] = FSChaCha20(peer['responder_L'])
            self.peer['recv_P'] = FSChaCha20Poly1305(peer['responder_P'])
            self.peer['recv_garbage_terminator'] = peer['garbage_terminators'][16:]
        else:
            self.peer['send_L'] = FSChaCha20(peer['responder_L'])
            self.peer['send_P'] = FSChaCha20Poly1305(peer['responder_P'])
            self.peer['send_garbage_terminator'] = peer['garbage_terminators'][16:]
            self.peer['recv_L'] = FSChaCha20(peer['initiator_L'])
            self.peer['recv_P'] = FSChaCha20Poly1305(peer['initiator_P'])
            self.peer['recv_garbage_terminator'] = peer['garbage_terminators'][:16]
        self.peer['session_id'] = peer['session_id']

    def v2_enc_packet(self, contents, aad=b'', ignore=False):
        """Encrypt a BIP324 packet.

        Returns:
        bytes - encrypted packet contents
        """
        assert len(contents) <= 2**24 - 1
        header = (ignore << IGNORE_BIT_POS).to_bytes(HEADER_LEN, 'little')
        plaintext = header + contents
        aead_ciphertext = self.peer['send_P'].encrypt(aad, plaintext)
        enc_plaintext_len = self.peer['send_L'].crypt(len(contents).to_bytes(LENGTH_FIELD_LEN, 'little'))
        return enc_plaintext_len + aead_ciphertext

    def v2_receive_packet(self, response, aad=b''):
        """Decrypt a BIP324 packet

        Returns:
        1. int - number of bytes consumed (or -1 if error)
        2. bytes - contents of decrypted non-decoy packet if any (or None otherwise)
        """
        if self.contents_len == -1:
            if len(response) < LENGTH_FIELD_LEN:
                return 0, None
            enc_contents_len = response[:LENGTH_FIELD_LEN]
            self.contents_len = int.from_bytes(self.peer['recv_L'].crypt(enc_contents_len), 'little')
        response = response[LENGTH_FIELD_LEN:]
        if len(response) < HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION:
            return 0, None
        aead_ciphertext = response[:HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION]
        plaintext = self.peer['recv_P'].decrypt(aad, aead_ciphertext)
        if plaintext is None:
            return -1, None  # disconnect
        header = plaintext[:HEADER_LEN]
        length = LENGTH_FIELD_LEN + HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION
        self.contents_len = -1
        return length, None if (header[0] & (1 << IGNORE_BIT_POS)) else plaintext[HEADER_LEN:]


def _drive(state, recvbuf):
    """Feed recvbuf to state the way P2PConnection's v2 handshake driver does.

    Returns the unconsumed bytes and the bytes state sends."""
    to_send = b""
    if not state.peer:
        if not state.initiating and state.ellswift_ours is None:
            length, response = state.respond_v2_handshake(BytesIO(recvbuf))
            recvbuf = recvbuf[length:]
            assert response not in (-1, b"")
            to_send += response
        length, response = state.complete_handshake(BytesIO(recvbuf))
        recvbuf = recvbuf[length:]
        if not response:
            return recvbuf, to_send
        to_send += response
    length, ok, pending = state.authenticate_handshake(recvbuf)
    assert ok
    return recvbuf[length:], to_send + pending


def _run_handshake(initiator, responder):
    """Run a v2 handshake between two states in memory until neither has anything left to send."""
    to_responder, to_initiator = initiator.initiate_v2_handshake(), b""
    initiator_buf = responder_buf = b""
    while to_responder or to_initiator:
        responder_buf += to_responder
        responder_buf, to_initiator = _drive(responder, responder_buf) if not responder.tried_v2_handshake else (responder_buf, b"")
        initiator_buf += to_initiator
        initiator_buf, to_responder = _drive(initiator, initiator_buf) if not initiator.tried_v2_handshake else (initiator_buf, b"")
    return initiator_buf, responder_buf


class TestFrameworkV2P2P(unittest.TestCase):
    def test_parse_version_contents(self):
        """The contents parser follows the node's grammar: all records must parse, the first own record wins."""
        offer = ser_pq_record(bytes(EK_SIZE))
        self.assertEqual(offer[:4].hex(), "fd2106f0")
        self.assertEqual(len(offer), PQ_RECORD_LEN)
        for contents, expected in [
            (b"", (ParseKind.NO_RECORD, None)),
            (bytes.fromhex("02f100"), (ParseKind.NO_RECORD, None)),
            (bytes.fromhex("0100"), (ParseKind.NO_RECORD, None)),
            (offer, (ParseKind.OWN_RECORD, bytes(EK_SIZE))),
            (bytes.fromhex("01f0"), (ParseKind.OWN_RECORD, b"")),
            (bytes.fromhex("04f0aabbcc"), (ParseKind.OWN_RECORD, bytes.fromhex("aabbcc"))),
            (bytes.fromhex("02f111") + bytes.fromhex("02f022") + bytes.fromhex("02f033"), (ParseKind.OWN_RECORD, b"\x22")),
            (offer + b"\x00", (ParseKind.INVALID_GRAMMAR, None)),  # zero length after a valid record
            (offer + b"\x05", (ParseKind.INVALID_GRAMMAR, None)),  # truncated trailing record
            (bytes.fromhex("00"), (ParseKind.INVALID_GRAMMAR, None)),
            (bytes.fromhex("fd0200f000"), (ParseKind.INVALID_GRAMMAR, None)),  # non-canonical CompactSize
            (bytes.fromhex("fe0000010000"), (ParseKind.INVALID_GRAMMAR, None)),  # 65536, but nothing follows
            (bytes.fromhex("ff0100000000000000f0"), (ParseKind.INVALID_GRAMMAR, None)),  # non-canonical 8-byte
            (bytes.fromhex("fe01000002") + bytes(8), (ParseKind.INVALID_GRAMMAR, None)),  # above MAX_SIZE
            (bytes.fromhex("fd21"), (ParseKind.INVALID_GRAMMAR, None)),  # truncated CompactSize
            (offer[:-1], (ParseKind.INVALID_GRAMMAR, None)),  # truncated payload
        ]:
            self.assertEqual(parse_version_contents(contents), expected, contents[:8].hex())

    def test_vectors(self):
        """Two hybrid states fed the inputs of src/test/data/pq_transport_vectors.json reproduce its values."""
        vectors_path = Path(__file__).resolve().parents[3] / "src" / "test" / "data" / "pq_transport_vectors.json"
        vectors = json.loads(vectors_path.read_text(encoding="utf8"))["vectors"]
        self.assertEqual(len(vectors), 4)
        for vector in vectors:
            v = {key: bytes.fromhex(value) for key, value in vector.items() if key not in ("comment", "chain")}
            net = {"main": "mainnet", "regtest": "regtest"}[vector["chain"]]
            self.assertEqual(MAGIC_BYTES[net], v["magic"])

            class FixedState(EncryptedP2PState):
                def generate_keypair_and_garbage(self, garbage_len=None):
                    role = "initiator" if self.initiating else "responder"
                    self.privkey_ours, self.ellswift_ours = v[f"{role}_privkey"], v[f"{role}_ellswift"]
                    self.sent_garbage = random.randbytes(random.randrange(1, 64))
                    return self.ellswift_ours + self.sent_garbage

                def pq_random_bytes(self, n):
                    return self.draws.pop(0)

                def make_offer_contents(self, offer):
                    assert offer == ser_pq_record(v["ek"])
                    return v["contents_responder"]

                def make_accept_contents(self, accept):
                    assert accept == ser_pq_record(v["ct"])
                    return v["contents_initiator"]

            initiator = FixedState(initiating=True, net=net, supports_v2_pq=True)
            responder = FixedState(initiating=False, net=net, supports_v2_pq=True)
            initiator.draws = [v["mlkem_encaps_m"]]
            responder.draws = [v["mlkem_keygen_seed"][:32], v["mlkem_keygen_seed"][32:]]
            initiator.withhold_confirmation = responder.withhold_confirmation = True
            _run_handshake(initiator, responder)
            for state in (initiator, responder):
                self.assertEqual(state.ecdh_secret, v["ss_ecdh"])
                self.assertEqual(state.mlkem_shared_secret, v["ss_mlkem"])
                self.assertEqual(state.peer["session_id"], v["session_id"])
                for label in ("salt", "ikm", "prk", "initiator_L", "initiator_P", "responder_L", "responder_P"):
                    self.assertEqual(state.hybrid_keys[label], v[label])
            self.assertEqual(initiator.received_version_contents, v["contents_responder"])
            self.assertEqual(responder.received_version_contents, v["contents_initiator"])
            # Each side's held confirmation is hybrid packet 0, and its first application packet follows.
            self.assertEqual(initiator.held_confirmation, v["initiator_confirmation"])
            self.assertEqual(responder.held_confirmation, v["responder_confirmation"])
            self.assertEqual(initiator.v2_enc_packet(v["initiator_first_contents"]), v["initiator_first_packet"])
            self.assertEqual(responder.v2_enc_packet(v["responder_first_contents"]), v["responder_first_packet"])

    def test_roles(self):
        """Hybrid and legacy states interoperate in both roles, and only two hybrid states switch."""
        for initiator_pq, responder_pq in [(True, True), (True, False), (False, True), (False, False)]:
            initiator = EncryptedP2PState(initiating=True, net="regtest", supports_v2_pq=initiator_pq)
            responder = EncryptedP2PState(initiating=False, net="regtest", supports_v2_pq=responder_pq)
            _run_handshake(initiator, responder)
            self.assertTrue(initiator.tried_v2_handshake and responder.tried_v2_handshake)
            hybrid = initiator_pq and responder_pq
            self.assertEqual((initiator.hybrid_keys is not None, responder.hybrid_keys is not None), (hybrid, hybrid))
            self.assertEqual(initiator.peer["session_id"], responder.peer["session_id"])
            self.assertEqual(initiator.pq_status, "hybrid" if hybrid else "legacy_peer" if initiator_pq else "off")
            self.assertEqual(responder.pq_status, "hybrid" if hybrid else "legacy_peer" if responder_pq else "off")
            # A legacy initiator sends empty contents; so does a hybrid one toward a legacy responder.
            self.assertEqual(len(initiator.sent_version_contents), PQ_RECORD_LEN if hybrid else 0)
            self.assertEqual(len(responder.sent_version_contents), PQ_RECORD_LEN if responder_pq else 0)
            # Packets flow both ways, across a rekey.
            for i in range(300):
                contents = i.to_bytes(2, "little")
                packet = initiator.v2_enc_packet(contents)
                self.assertEqual(responder.v2_receive_packet(packet), (len(packet), contents))
                packet = responder.v2_enc_packet(contents)
                self.assertEqual(initiator.v2_receive_packet(packet), (len(packet), contents))

    def test_withheld_confirmation(self):
        """A withheld confirmation keeps the handshake open on that side until it is released."""
        initiator = EncryptedP2PState(initiating=True, net="regtest", supports_v2_pq=True)
        responder = EncryptedP2PState(initiating=False, net="regtest", supports_v2_pq=True)
        initiator.withhold_confirmation = True
        initiator_buf, responder_buf = _run_handshake(initiator, responder)
        self.assertTrue(initiator.peer_confirmed)
        self.assertFalse(initiator.tried_v2_handshake)
        self.assertFalse(responder.peer_confirmed)
        self.assertFalse(responder.tried_v2_handshake)
        confirmation = initiator.release_confirmation()
        self.assertEqual(len(confirmation), PQ_CONFIRMATION_LEN)
        initiator.check_handshake_complete()
        self.assertTrue(initiator.tried_v2_handshake)
        self.assertEqual(_drive(responder, responder_buf + confirmation), (b"", b""))
        self.assertTrue(responder.tried_v2_handshake)

    def test_bad_confirmation(self):
        """A confirmation with a nonzero length, a bad tag or a clear ignore bit fails."""
        for damage in ("length", "tag", "not_decoy"):
            initiator = EncryptedP2PState(initiating=True, net="regtest", supports_v2_pq=True)
            responder = EncryptedP2PState(initiating=False, net="regtest", supports_v2_pq=True)
            initiator.withhold_confirmation = True
            _, responder_buf = _run_handshake(initiator, responder)
            initiator.release_confirmation()
            if damage == "length":
                confirmation = initiator.v2_enc_packet(b"\x00", ignore=True)
            elif damage == "tag":
                confirmation = initiator.v2_enc_packet(b"", ignore=True)
                confirmation = confirmation[:-1] + bytes([confirmation[-1] ^ 1])
            else:
                confirmation = initiator.v2_enc_packet(b"", ignore=False)
            self.assertEqual(responder.authenticate_handshake(responder_buf + confirmation)[1], False)
