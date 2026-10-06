#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Generate the hybrid post-quantum v2 transport vectors (src/test/data/pq_transport_vectors.json).

The values come from the Python reference in test/functional/test_framework/crypto, imported by
path: bip324_cipher.py for the key recipe and packet encryption, mlkem.py for ML-KEM-1024, and
ellswift.py, secp256k1.py and hkdf.py for the BIP324 ECDH part. This script never calls the C++
code under test. Every input is derived from a fixed label, so the output is reproducible byte for
byte. The recipe is specified in doc/design/pq-transport.md.

Run without arguments to rewrite the file, or with --check (as the lint does) to fail when the
committed file differs from what the reference produces. Both modes also fail when a value the
specification quotes in a "pq-transport-vectors" block differs from the vectors.
"""

import argparse
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FUNCTIONAL_DIR = ROOT / "test" / "functional"
OUTPUT = ROOT / "src" / "test" / "data" / "pq_transport_vectors.json"
SPEC = ROOT / "doc" / "design" / "pq-transport.md"
# A block of "name = hex" lines quoting one vector, introduced by an HTML comment.
SPEC_BLOCK = re.compile(r"<!-- pq-transport-vectors: vector (\d+) -->\n```text\n(.*?)\n```", re.DOTALL)

PQ_MLKEM1024 = 0xF0
# Network magic in wire order (src/kernel/chainparams.cpp); bip324_tests checks it against the chain.
MAGIC = {"main": bytes.fromhex("444f24a8"), "regtest": bytes.fromhex("a66b1fda")}
# First application messages: a v2 short-id ping (18) and the matching pong (19).
PING = bytes([18]) + bytes.fromhex("0123456789abcdef")
PONG = bytes([19]) + bytes.fromhex("0123456789abcdef")


def load_reference():
    """Import the test framework's crypto modules from the source tree."""
    sys.path.insert(0, str(FUNCTIONAL_DIR))
    names = ("bip324_cipher", "ellswift", "hkdf", "mlkem", "secp256k1")
    return {name: importlib.import_module(f"test_framework.crypto.{name}") for name in names}


def seed(label, size=32):
    """Deterministic input bytes for a label."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"qbit pq transport vectors/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:size]


def tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def make_key(ref, label):
    """Deterministic private key and ElligatorSwift encoding of its public key."""
    secp, ellswift = ref["secp256k1"], ref["ellswift"]
    priv = int.from_bytes(seed(f"{label}/privkey"), "big") % (secp.GE.ORDER - 1) + 1
    x = (priv * secp.G).x
    counter = 0
    while True:
        u_seed = seed(f"{label}/ellswift/{counter}", 33)
        u = secp.FE(int.from_bytes(u_seed[:32], "big"))
        t = ellswift.xswiftec_inv(x, u, u_seed[32] & 7) if u != 0 else None
        if t is not None:
            assert ellswift.xswiftec(u, t) == x
            return priv.to_bytes(32, "big"), u.to_bytes() + t.to_bytes()
        counter += 1


def bip324_ecdh(ref, priv, ellswift_theirs, ellswift_ours, initiating):
    """The BIP324 ECDH secret (what CKey::ComputeBIP324ECDHSecret returns)."""
    x = ref["ellswift"].ellswift_ecdh_xonly(ellswift_theirs, priv)
    pubkeys = ellswift_ours + ellswift_theirs if initiating else ellswift_theirs + ellswift_ours
    return tagged_hash("bip324_ellswift_xonly_ecdh", pubkeys + x)


def record(ref, header, payload):
    """One version-contents record: CompactSize(1 + len(payload)) || header || payload."""
    return ref["bip324_cipher"].ser_compact_size(1 + len(payload)) + bytes([header]) + payload


class Exchange:
    """One side's view of a hybrid handshake, from the version contents onwards."""

    def __init__(self, ref, ss_ecdh, ellswift_i, ellswift_r, contents_first, contents_second, ss_mlkem, magic):
        cipher = ref["bip324_cipher"]
        # The transcript always lists the responder's contents first; a misbehaving side may not.
        self.transcript_input = cipher.hybrid_transcript_input(ellswift_i, ellswift_r, contents_first, contents_second)
        self.transcript_hash = hashlib.sha256(self.transcript_input).digest()
        self.keys = cipher.hybrid_derive_keys(ss_ecdh, ss_mlkem, self.transcript_hash, magic)

    def ciphers(self, ref, initiator):
        return ref["bip324_cipher"].hybrid_ciphers(self.keys, initiator)


def first_packets(ref, exchange, initiator, contents):
    """The key confirmation and the first application packet one side sends."""
    cipher = ref["bip324_cipher"]
    send_l, send_p, _, _ = exchange.ciphers(ref, initiator)
    confirmation = cipher.encrypt_packet(send_l, send_p, b"", ignore=True)
    assert len(confirmation) == 20
    return confirmation, cipher.encrypt_packet(send_l, send_p, contents)


def receive(ref, exchange, initiator, packets):
    """Decrypt packets in order as one side; return each result of decrypt_packet."""
    _, _, recv_l, recv_p = exchange.ciphers(ref, initiator)
    return [ref["bip324_cipher"].decrypt_packet(recv_l, recv_p, packet) for packet in packets]


def make_vector(ref, index, chain, comment, shape):
    mlkem, hkdf = ref["mlkem"], ref["hkdf"]
    magic = MAGIC[chain]
    priv_i, ellswift_i = make_key(ref, f"{index}/initiator")
    priv_r, ellswift_r = make_key(ref, f"{index}/responder")
    ss_ecdh = bip324_ecdh(ref, priv_i, ellswift_r, ellswift_i, initiating=True)
    assert ss_ecdh == bip324_ecdh(ref, priv_r, ellswift_i, ellswift_r, initiating=False)

    # Today's BIP324 values, which the switch must leave alone (garbage terminators) or replace
    # (session id).
    salt_ecdh = b"bitcoin_v2_shared_secret" + magic
    garbage_terminators = hkdf.hkdf_sha256(length=32, ikm=ss_ecdh, salt=salt_ecdh, info=b"garbage_terminators")
    ecdh_session_id = hkdf.hkdf_sha256(length=32, ikm=ss_ecdh, salt=salt_ecdh, info=b"session_id")

    keygen_seed = seed(f"{index}/mlkem_keygen", mlkem.SEED_SIZE)
    encaps_m = seed(f"{index}/mlkem_encaps", mlkem.MSG_SIZE)
    ek, dk = mlkem.mlkem1024_keygen(keygen_seed)
    assert mlkem.mlkem1024_check_ek(ek)
    ss_mlkem, ct = mlkem.mlkem1024_encaps(ek, encaps_m)
    assert mlkem.mlkem1024_decaps(dk, ct) == ss_mlkem

    offer = record(ref, PQ_MLKEM1024, ek)
    accept = record(ref, PQ_MLKEM1024, ct)
    assert offer[:4] == accept[:4] == bytes.fromhex("fd2106f0") and len(offer) == len(accept) == 1572
    if shape == "single":
        contents_r, contents_i = offer, accept
    elif shape == "extra_records":
        # The first 0xF0 record wins, wherever it sits: the initiator encapsulates to the offer's ek
        # and ignores the second 0xF0 record's (different, valid) ek. Unknown headers are ignored
        # too, but the transcript covers every record of both contents.
        other_ek, _ = mlkem.mlkem1024_keygen(seed(f"{index}/mlkem_keygen_duplicate", mlkem.SEED_SIZE))
        contents_r = offer + record(ref, PQ_MLKEM1024, other_ek) + record(ref, 0xF1, bytes.fromhex("0001"))
        contents_i = record(ref, 0x01, b"qbit") + accept
    else:
        # A 65,535-byte unknown record: its record length (65,536) and the responder's contents
        # length in the transcript (67,113) both take the 0xfe CompactSize form.
        assert shape == "large_contents"
        contents_r = offer + record(ref, 0xF1, bytes(65535))
        contents_i = accept
        assert contents_r[1572] == 0xFE and ref["bip324_cipher"].ser_compact_size(len(contents_r))[0] == 0xFE

    exchange = Exchange(ref, ss_ecdh, ellswift_i, ellswift_r, contents_r, contents_i, ss_mlkem, magic)
    if shape == "single":
        assert len(exchange.transcript_input) == 3278
    init_confirmation, init_first = first_packets(ref, exchange, True, PING)
    resp_confirmation, resp_first = first_packets(ref, exchange, False, PONG)
    assert receive(ref, exchange, False, [init_confirmation, init_first]) == [(0, (True, b"")), (len(PING), (False, PING))]
    assert receive(ref, exchange, True, [resp_confirmation, resp_first]) == [(0, (True, b"")), (len(PONG), (False, PONG))]

    vector = {
        "comment": comment,
        "chain": chain,
        "magic": magic.hex(),
        "initiator_privkey": priv_i.hex(),
        "initiator_ellswift": ellswift_i.hex(),
        "responder_privkey": priv_r.hex(),
        "responder_ellswift": ellswift_r.hex(),
        "ss_ecdh": ss_ecdh.hex(),
        "ecdh_session_id": ecdh_session_id.hex(),
        "initiator_garbage_terminator": garbage_terminators[:16].hex(),
        "responder_garbage_terminator": garbage_terminators[16:].hex(),
        "mlkem_keygen_seed": keygen_seed.hex(),
        "mlkem_encaps_m": encaps_m.hex(),
        "ek": ek.hex(),
        "ct": ct.hex(),
        "ss_mlkem": ss_mlkem.hex(),
        "contents_responder": contents_r.hex(),
        "contents_initiator": contents_i.hex(),
        "transcript_input": exchange.transcript_input.hex(),
        "transcript_hash": exchange.transcript_hash.hex(),
        "salt": exchange.keys["salt"].hex(),
        "ikm": exchange.keys["ikm"].hex(),
        "prk": exchange.keys["prk"].hex(),
    }
    for label in ref["bip324_cipher"].HYBRID_KEY_LABELS:
        vector[label] = exchange.keys[label].hex()
    vector.update({
        "initiator_confirmation": init_confirmation.hex(),
        "responder_confirmation": resp_confirmation.hex(),
        "initiator_first_contents": PING.hex(),
        "initiator_first_packet": init_first.hex(),
        "responder_first_contents": PONG.hex(),
        "responder_first_packet": resp_first.hex(),
    })
    state = {"ss_ecdh": ss_ecdh, "ellswift_i": ellswift_i, "ellswift_r": ellswift_r, "dk": dk, "ct": ct,
             "ss_mlkem": ss_mlkem, "contents_r": contents_r, "contents_i": contents_i, "magic": magic,
             "exchange": exchange, "confirmations": {True: init_confirmation, False: resp_confirmation}}
    return vector, state


def make_negative(ref, index, state, comment, initiator, contents_first, contents_second, ss_mlkem):
    """One side derives from a different transcript or secret than its honest peer.

    Records what that side derives and sends, and what each side decodes from the other's key
    confirmation: a nonzero length fails at once (reason length), a zero length on the tag."""
    bad = Exchange(ref, state["ss_ecdh"], state["ellswift_i"], state["ellswift_r"], contents_first, contents_second,
                   ss_mlkem, state["magic"])
    honest = state["exchange"]
    assert bad.keys["session_id"] != honest.keys["session_id"]
    confirmation, _ = first_packets(ref, bad, initiator, b"")
    [(length, result)] = receive(ref, bad, initiator, [state["confirmations"][not initiator]])
    [(peer_length, peer_result)] = receive(ref, honest, not initiator, [confirmation])
    assert result is None and peer_result is None
    negative = {
        "comment": comment,
        "vector": index,
        "role": "initiator" if initiator else "responder",
        "transcript_contents": [contents_first.hex(), contents_second.hex()],
        "ss_mlkem": ss_mlkem.hex(),
        "session_id": bad.keys["session_id"].hex(),
        "confirmation": confirmation.hex(),
        "decrypted_length": length,
        "failure": "length" if length else "tag",
        "peer_decrypted_length": peer_length,
        "peer_failure": "length" if peer_length else "tag",
    }
    return negative


def make_confirmation_failure(ref, index, state, comment, receiver_is_initiator, packet):
    """A first hybrid packet that fails the receiver's key confirmation check under the honest keys."""
    [(length, result)] = receive(ref, state["exchange"], receiver_is_initiator, [packet])
    if length:
        failure = "length"
    elif result is None:
        failure = "tag"
    else:
        assert result == (False, b"")
        failure = "not_decoy"
    return {
        "comment": comment,
        "vector": index,
        "receiver": "initiator" if receiver_is_initiator else "responder",
        "packet": packet.hex(),
        "decrypted_length": length,
        "failure": failure,
    }


def generate():
    ref = load_reference()
    cipher, mlkem = ref["bip324_cipher"], ref["mlkem"]
    vectors = []
    states = []
    for index, (chain, comment, shape) in enumerate((
        ("main", "Mainnet, one offer record and one accept record (the ordinary exchange).", "single"),
        ("regtest", "Regtest, one offer record and one accept record.", "single"),
        ("main", "Mainnet, extra records. The responder's contents are its offer, a second 0xf0 record with a "
                 "different valid ek, and an unknown 0xf1 record; the initiator encapsulates to the ek of the "
                 "first 0xf0 record and ignores the rest. The initiator's contents are an unknown 0x01 record "
                 "followed by its accept, which is still the first 0xf0 record there. The transcript covers every "
                 "record of both contents.", "extra_records"),
        ("main", "Mainnet; the responder's contents are its offer followed by an unknown 0xf1 record with a "
                 "65,535-byte zero payload, so that record's length (65,536) and the responder's contents length "
                 "in the transcript (67,113) both use the 0xfe CompactSize form.", "large_contents"),
    )):
        vector, state = make_vector(ref, index, chain, comment, shape)
        vectors.append(vector)
        states.append(state)

    state = states[0]
    bad_ct = bytes([state["ct"][0] ^ 0x01]) + state["ct"][1:]
    bad_ss = mlkem.mlkem1024_decaps(state["dk"], bad_ct)
    assert bad_ss != state["ss_mlkem"]
    flipped_ss = bytes([state["ss_mlkem"][0] ^ 0xFF]) + state["ss_mlkem"][1:]
    negatives = [
        make_negative(ref, 0, state, "Bit 0 of the ciphertext flipped in transit: the responder hashes the "
                      "damaged accept and decapsulation returns the implicit-rejection secret.",
                      False, state["contents_r"], record(ref, PQ_MLKEM1024, bad_ct), bad_ss),
        make_negative(ref, 0, state, "The initiator's ML-KEM shared secret has byte 0 inverted after "
                      "encapsulation (a local fault); EK and CT are untouched.",
                      True, state["contents_r"], state["contents_i"], flipped_ss),
        make_negative(ref, 0, state, "The responder hashes the two contents in the wrong order.",
                      False, state["contents_i"], state["contents_r"], state["ss_mlkem"]),
    ]

    # Damaged first packets under the honest keys of vector 0, one for each confirmation failure reason.
    init_confirmation = state["confirmations"][True]
    resp_send_l, resp_send_p, _, _ = state["exchange"].ciphers(ref, False)
    confirmation_failures = [
        make_confirmation_failure(ref, 0, state, "The initiator's confirmation with bit 0 of its first byte flipped: "
                                  "the length decrypts to 1.",
                                  False, bytes([init_confirmation[0] ^ 0x01]) + init_confirmation[1:]),
        make_confirmation_failure(ref, 0, state, "The initiator's confirmation with bit 0 of its last tag byte flipped: "
                                  "the length decrypts to 0 and the tag fails.",
                                  False, init_confirmation[:-1] + bytes([init_confirmation[-1] ^ 0x01])),
        make_confirmation_failure(ref, 0, state, "The responder's first hybrid packet is an authenticated empty packet "
                                  "without the ignore bit.",
                                  True, cipher.encrypt_packet(resp_send_l, resp_send_p, b"", ignore=False)),
    ]
    assert [failure["failure"] for failure in confirmation_failures] == ["length", "tag", "not_decoy"]

    document = {
        "comment": [
            "Hybrid post-quantum BIP324 v2 transport: the ML-KEM-1024 key recipe under version-contents "
            "header 0xf0, specified in doc/design/pq-transport.md.",
            "Generated by contrib/devtools/generate-pq-transport-vectors.py from the Python reference in "
            "test/functional/test_framework/crypto. Do not edit by hand.",
            "Byte strings are lowercase hex. Packets are BIP324 packets: encrypted length (3) || encrypted "
            "header and contents || tag (16). Each side's key confirmation is its hybrid packet 0, and its "
            "first application packet is hybrid packet 1.",
            "confirmation_failures are first hybrid packets that the named receiver must reject under the honest "
            "keys of the vector; negative_vectors are sides that derived from different inputs than their peer.",
        ],
        "header": f"{PQ_MLKEM1024:02x}",
        "salt_label": cipher.HYBRID_SALT_LABEL.decode(),
        "labels": list(cipher.HYBRID_KEY_LABELS),
        "vectors": vectors,
        "confirmation_failures": confirmation_failures,
        "negative_vectors": negatives,
    }
    return document


def check_spec(document):
    """Return every value the specification quotes that differs from the vectors."""
    spec = SPEC.relative_to(ROOT)
    blocks = SPEC_BLOCK.findall(SPEC.read_text(encoding="utf8"))
    if not blocks:
        return [f"{spec}: no quoted vector block found"]
    errors = []
    for index, body in blocks:
        if int(index) >= len(document["vectors"]):
            errors.append(f"{spec}: quotes vector {index}, which does not exist")
            continue
        vector = document["vectors"][int(index)]
        for line in body.splitlines():
            name, _, value = line.partition(" = ")
            if vector.get(name) != value:
                errors.append(f"{spec}: vector {index} quotes {name} = {value}, which does not match the vectors")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help=f"fail if {OUTPUT.relative_to(ROOT)} is stale")
    args = parser.parse_args()

    document = generate()
    text = json.dumps(document, indent=2) + "\n"
    spec_errors = check_spec(document)
    for error in spec_errors:
        print(error, file=sys.stderr)
    if args.check:
        current = OUTPUT.read_text(encoding="utf8") if OUTPUT.exists() else None
        if current != text:
            print(f"{OUTPUT.relative_to(ROOT)} does not match the Python reference. If the recipe change is "
                  "intended, it needs a new version-contents header (doc/design/pq-transport.md); then run "
                  f"{Path(__file__).relative_to(ROOT)} to regenerate it.", file=sys.stderr)
            sys.exit(1)
        if spec_errors:
            sys.exit(1)
        print(f"{OUTPUT.relative_to(ROOT)} and the values {SPEC.relative_to(ROOT)} quotes match the Python reference.")
        return
    OUTPUT.write_text(text, encoding="utf8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    if spec_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
