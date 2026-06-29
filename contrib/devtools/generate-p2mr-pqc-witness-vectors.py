#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Generate independent P2MR CHECKSIGPQC witness vectors.

This script intentionally does not import qbit's Python test framework or call
qbit wallet/signing/sighash helpers. It hand-serializes the transactions and
P2MR sighash messages, then uses libbitcoinpqc only for deterministic key
generation and signing of the computed P2MRSighash digest.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

P2MR_LEAF_VERSION_V1 = 0xC0
P2MR_CONTROL_BYTE_V1 = P2MR_LEAF_VERSION_V1 | 1
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_SWAP = 0x7C
OP_NUMEQUAL = 0x9C
OP_CHECKSIGPQC = 0xB3
OP_CHECKDATASIGPQC = 0xBC
OP_CHECKDATASIGADDPQC = 0xBD

PQC_PUBKEY_SIZE = 32
PQC_SECKEY_SIZE = 64
PQC_SIG_SIZE = 3680
PQC_KEYGEN_RANDOM_DATA_SIZE = 128


@dataclass(frozen=True)
class TxIn:
    prevout_hash: bytes
    prevout_n: int
    sequence: int
    witness: tuple[bytes, ...] = ()

    def serialize_prevout(self) -> bytes:
        return self.prevout_hash + uint32(self.prevout_n)

    def serialize_no_witness(self) -> bytes:
        return self.serialize_prevout() + ser_string(b"") + uint32(self.sequence)


@dataclass(frozen=True)
class TxOut:
    value: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return int64(self.value) + ser_string(self.script_pubkey)


@dataclass(frozen=True)
class Transaction:
    version: int
    vin: tuple[TxIn, ...]
    vout: tuple[TxOut, ...]
    locktime: int

    def serialize(self, *, with_witness: bool) -> bytes:
        has_witness = with_witness and any(txin.witness for txin in self.vin)
        out = int32(self.version)
        if has_witness:
            out += b"\x00\x01"
        out += compact_size(len(self.vin))
        out += b"".join(txin.serialize_no_witness() for txin in self.vin)
        out += compact_size(len(self.vout))
        out += b"".join(txout.serialize() for txout in self.vout)
        if has_witness:
            for txin in self.vin:
                out += compact_size(len(txin.witness))
                for item in txin.witness:
                    out += ser_string(item)
        out += uint32(self.locktime)
        return out

    def with_input_witness(self, index: int, witness: tuple[bytes, ...]) -> "Transaction":
        vin = list(self.vin)
        old = vin[index]
        vin[index] = TxIn(old.prevout_hash, old.prevout_n, old.sequence, witness)
        return Transaction(self.version, tuple(vin), self.vout, self.locktime)


class BitcoinPQCKeyPair(ctypes.Structure):
    _fields_ = [
        ("public_key", ctypes.c_void_p),
        ("secret_key", ctypes.c_void_p),
        ("public_key_size", ctypes.c_size_t),
        ("secret_key_size", ctypes.c_size_t),
    ]


class BitcoinPQCSignature(ctypes.Structure):
    _fields_ = [
        ("signature", ctypes.c_void_p),
        ("signature_size", ctypes.c_size_t),
    ]


def uint32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def int32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def int64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=True)


def compact_size(size: int) -> bytes:
    if size < 253:
        return bytes([size])
    if size <= 0xFFFF:
        return b"\xfd" + size.to_bytes(2, "little")
    if size <= 0xFFFFFFFF:
        return b"\xfe" + size.to_bytes(4, "little")
    return b"\xff" + size.to_bytes(8, "little")


def ser_string(data: bytes) -> bytes:
    return compact_size(len(data)) + data


def push_bytes(data: bytes) -> bytes:
    if len(data) > 75:
        raise ValueError("only direct pushes are supported")
    return bytes([len(data)]) + data


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + msg)


def build_p2mr_leaf_script(pubkey: bytes) -> bytes:
    if len(pubkey) != PQC_PUBKEY_SIZE:
        raise ValueError("bad PQC pubkey length")
    return bytes([PQC_PUBKEY_SIZE]) + pubkey + bytes([OP_CHECKSIGPQC])


def build_p2mr_datasig_script(pubkey: bytes) -> bytes:
    if len(pubkey) != PQC_PUBKEY_SIZE:
        raise ValueError("bad PQC pubkey length")
    return push_bytes(pubkey) + bytes([OP_CHECKDATASIGPQC])


def build_p2mr_datasigadd_script(threshold: int, pubkeys: tuple[bytes, ...], msg_hash: bytes) -> bytes:
    if len(msg_hash) != 32:
        raise ValueError("bad data signature message hash length")
    if threshold != 2:
        raise ValueError("only 2-of-n ADDPQC scripts are supported")

    script = b""
    for index, pubkey in enumerate(pubkeys):
        if len(pubkey) != PQC_PUBKEY_SIZE:
            raise ValueError("bad PQC pubkey length")
        script += push_bytes(msg_hash)
        script += bytes([OP_0 if index == 0 else OP_SWAP])
        script += push_bytes(pubkey)
        script += bytes([OP_CHECKDATASIGADDPQC])
    script += bytes([OP_2, OP_NUMEQUAL])
    return script


def p2mr_leaf_hash(leaf_script: bytes) -> bytes:
    return tagged_hash("P2MRLeaf", bytes([P2MR_LEAF_VERSION_V1]) + ser_string(leaf_script))


def p2mr_script_pubkey(root: bytes) -> bytes:
    if len(root) != 32:
        raise ValueError("bad P2MR root length")
    return bytes([OP_2, 32]) + root


def p2mr_signature_msg(tx: Transaction, spent_outputs: tuple[TxOut, ...], hash_type: int, input_index: int, leaf_hash: bytes) -> bytes:
    if len(tx.vin) != len(spent_outputs):
        raise ValueError("spent output count does not match input count")
    if input_index >= len(tx.vin):
        raise ValueError("input index out of range")

    output_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & 0x03
    input_type = hash_type & SIGHASH_ANYONECANPAY
    if hash_type not in (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
        raise ValueError(f"unsupported sighash type {hash_type:#x}")
    if output_type == SIGHASH_SINGLE and input_index >= len(tx.vout):
        raise ValueError("SIGHASH_SINGLE without matching output")

    msg = bytes([0x00, hash_type])
    msg += int32(tx.version)
    msg += uint32(tx.locktime)

    if input_type != SIGHASH_ANYONECANPAY:
        msg += sha256(b"".join(txin.serialize_prevout() for txin in tx.vin))
        msg += sha256(b"".join(int64(prevout.value) for prevout in spent_outputs))
        msg += sha256(b"".join(ser_string(prevout.script_pubkey) for prevout in spent_outputs))
        msg += sha256(b"".join(uint32(txin.sequence) for txin in tx.vin))

    if output_type == SIGHASH_ALL:
        msg += sha256(b"".join(txout.serialize() for txout in tx.vout))

    # P2MR script path, no annex.
    msg += bytes([0x02])

    if input_type == SIGHASH_ANYONECANPAY:
        msg += tx.vin[input_index].serialize_prevout()
        msg += spent_outputs[input_index].serialize()
        msg += uint32(tx.vin[input_index].sequence)
    else:
        msg += uint32(input_index)

    if output_type == SIGHASH_SINGLE:
        msg += sha256(tx.vout[input_index].serialize())

    msg += leaf_hash
    msg += b"\x00"
    msg += uint32(0xFFFFFFFF)
    return msg


def libbitcoinpqc_sources(root: Path) -> list[Path]:
    rel_sources = [
        "src/bitcoinpqc.c",
        "src/slh_dsa/utils.c",
        "src/slh_dsa/keygen.c",
        "src/slh_dsa/validate.c",
        "src/slh_dsa/sign.c",
        "src/slh_dsa/verify.c",
        "sphincsplus/ref/address.c",
        "sphincsplus/ref/fors.c",
        "sphincsplus/ref/hash_sha2.c",
        "sphincsplus/ref/merkle.c",
        "sphincsplus/ref/sha2.c",
        "sphincsplus/ref/sha2_armv8_sha.c",
        "sphincsplus/ref/sha2_x86_shani.c",
        "sphincsplus/ref/sign.c",
        "sphincsplus/ref/sign_stats.c",
        "sphincsplus/ref/thash_sha2_simple.c",
        "sphincsplus/ref/utils.c",
        "sphincsplus/ref/utilsx1.c",
        "sphincsplus/ref/wots.c",
        "sphincsplus/ref/wotsx1.c",
        "sphincsplus/ref/randombytes_custom.c",
    ]
    return [root / "src" / "libbitcoinpqc" / rel for rel in rel_sources]


def build_libbitcoinpqc(repo_root: Path) -> Path:
    lib_root = repo_root / "src" / "libbitcoinpqc"
    build_dir = repo_root / ".context" / "p2mr-pqc-vector-generator"
    build_dir.mkdir(parents=True, exist_ok=True)

    suffix = ".dylib" if platform.system() == "Darwin" else ".so"
    lib_path = build_dir / f"libbitcoinpqc_vector{suffix}"
    sources = libbitcoinpqc_sources(repo_root)
    newest_source_mtime = max(path.stat().st_mtime for path in sources)
    if lib_path.exists() and lib_path.stat().st_mtime > newest_source_mtime:
        return lib_path

    cmd = [
        os.environ.get("CC", "cc"),
        "-std=c99",
        "-O2",
        "-fPIC",
        "-I",
        str(lib_root / "include"),
        "-I",
        str(lib_root / "sphincsplus" / "ref"),
        "-DPARAMS=sphincs-sha2-128s-bounded30",
        "-DCUSTOM_RANDOMBYTES=1",
        "-DBITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS=1835008",
        "-DBITCOINPQC_WOTSC_MAX_COUNTER=65535",
        "-DSPX_PRODUCTION_BUILD=1",
    ]
    if platform.system() == "Darwin":
        cmd.append("-dynamiclib")
    else:
        cmd.append("-shared")
    cmd += [str(source) for source in sources]
    cmd += ["-o", str(lib_path)]

    subprocess.run(cmd, cwd=repo_root, check=True)
    return lib_path


def load_libbitcoinpqc(repo_root: Path) -> ctypes.CDLL:
    lib = ctypes.CDLL(str(build_libbitcoinpqc(repo_root)))
    lib.bitcoin_pqc_keygen.argtypes = [
        ctypes.POINTER(BitcoinPQCKeyPair),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    lib.bitcoin_pqc_keygen.restype = ctypes.c_int
    lib.bitcoin_pqc_keypair_free.argtypes = [ctypes.POINTER(BitcoinPQCKeyPair)]
    lib.bitcoin_pqc_keypair_free.restype = None
    lib.bitcoin_pqc_sign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(BitcoinPQCSignature),
    ]
    lib.bitcoin_pqc_sign.restype = ctypes.c_int
    lib.bitcoin_pqc_signature_free.argtypes = [ctypes.POINTER(BitcoinPQCSignature)]
    lib.bitcoin_pqc_signature_free.restype = None
    return lib


def deterministic_keypair(lib: ctypes.CDLL, seed_fill: int) -> tuple[bytes, bytes]:
    random_data = bytes([seed_fill]) * PQC_KEYGEN_RANDOM_DATA_SIZE
    random_array = (ctypes.c_uint8 * len(random_data)).from_buffer_copy(random_data)
    keypair = BitcoinPQCKeyPair()
    rc = lib.bitcoin_pqc_keygen(ctypes.byref(keypair), random_array, len(random_data))
    if rc != 0:
        raise RuntimeError(f"bitcoin_pqc_keygen failed: {rc}")
    try:
        if keypair.public_key_size != PQC_PUBKEY_SIZE or keypair.secret_key_size != PQC_SECKEY_SIZE:
            raise RuntimeError("unexpected libbitcoinpqc key size")
        pubkey = ctypes.string_at(keypair.public_key, keypair.public_key_size)
        secret = ctypes.string_at(keypair.secret_key, keypair.secret_key_size)
        return pubkey, secret
    finally:
        lib.bitcoin_pqc_keypair_free(ctypes.byref(keypair))


def sign_digest(lib: ctypes.CDLL, secret: bytes, digest: bytes) -> bytes:
    secret_array = (ctypes.c_uint8 * len(secret)).from_buffer_copy(secret)
    digest_array = (ctypes.c_uint8 * len(digest)).from_buffer_copy(digest)
    signature = BitcoinPQCSignature()
    rc = lib.bitcoin_pqc_sign(secret_array, len(secret), digest_array, len(digest), ctypes.byref(signature))
    if rc != 0:
        raise RuntimeError(f"bitcoin_pqc_sign failed: {rc}")
    try:
        if signature.signature_size != PQC_SIG_SIZE:
            raise RuntimeError("unexpected libbitcoinpqc signature size")
        return ctypes.string_at(signature.signature, signature.signature_size)
    finally:
        lib.bitcoin_pqc_signature_free(ctypes.byref(signature))


def base_transaction() -> Transaction:
    return Transaction(
        version=2,
        vin=(
            TxIn(bytes(range(0x00, 0x20)), 7, 0xFFFFFFFE),
            TxIn(bytes(range(0x20, 0x40)), 11, 0xFFFFFFFD),
        ),
        vout=(
            TxOut(900, bytes([OP_1])),
            TxOut(800, bytes([OP_0])),
        ),
        locktime=500000,
    )


def vector_specs() -> list[tuple[str, int, int]]:
    return [
        ("single_key_default_sighash", SIGHASH_DEFAULT, 0x20),
        ("single_key_sighash_none", SIGHASH_NONE, 0x21),
        ("single_key_sighash_single_matching_output", SIGHASH_SINGLE, 0x22),
        ("single_key_sighash_all_anyonecanpay", SIGHASH_ALL | SIGHASH_ANYONECANPAY, 0x23),
        ("single_key_sighash_none_anyonecanpay", SIGHASH_NONE | SIGHASH_ANYONECANPAY, 0x24),
        ("single_key_sighash_single_anyonecanpay", SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, 0x25),
    ]


def missing_output_vector_specs() -> list[tuple[str, int, int, int, tuple[TxOut, ...]]]:
    return [
        ("single_key_sighash_single_missing_first", SIGHASH_SINGLE, 0x26, 0, ()),
        ("single_key_sighash_single_missing_beyond", SIGHASH_SINGLE, 0x27, 1, (TxOut(900, bytes([OP_1])),)),
        (
            "single_key_sighash_single_anyonecanpay_missing_first",
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            0x28,
            0,
            (),
        ),
        (
            "single_key_sighash_single_anyonecanpay_missing_beyond",
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            0x29,
            1,
            (TxOut(900, bytes([OP_1])),),
        ),
    ]


def build_data_sig_fields(lib: ctypes.CDLL, pubkey_a: bytes, secret_a: bytes) -> dict[str, object]:
    message_hash = bytes([0x48]) * 32
    wrong_message_hash = bytes([0x49]) * 32
    data_sig_hash = tagged_hash("QbitDataSigPQC", message_hash)

    pubkey_b, secret_b = deterministic_keypair(lib, 0x21)
    pubkey_c, secret_c = deterministic_keypair(lib, 0x22)
    wrong_pubkey_a = bytes([pubkey_a[0] ^ 0x01]) + pubkey_a[1:]

    data_sig_leaf_script = build_p2mr_datasig_script(pubkey_a)
    data_sig_wrong_pubkey_leaf_script = build_p2mr_datasig_script(wrong_pubkey_a)
    n_of_n_leaf_script = build_p2mr_datasigadd_script(2, (pubkey_a, pubkey_b), message_hash)
    m_of_n_leaf_script = build_p2mr_datasigadd_script(2, (pubkey_a, pubkey_b, pubkey_c), message_hash)
    wrong_message_hash_leaf_script = build_p2mr_datasigadd_script(2, (pubkey_a, pubkey_b), wrong_message_hash)
    wrong_pubkey_leaf_script = build_p2mr_datasigadd_script(2, (wrong_pubkey_a, pubkey_b), message_hash)

    return {
        "dataSigProvenance": (
            "Generated by contrib/devtools/generate-p2mr-pqc-witness-vectors.py "
            "using deterministic libbitcoinpqc random_data fills 0x20, 0x21, and 0x22; "
            "data signature hashes, P2MR leaf commitments, and ADDPQC scripts are "
            "serialized independently without qbit signing, script, or P2MR helpers."
        ),
        "dataSigMessageHash": message_hash.hex(),
        "dataSigHash": data_sig_hash.hex(),
        "dataSigPubkey": pubkey_a.hex(),
        "dataSigSignature": sign_digest(lib, secret_a, data_sig_hash).hex(),
        "dataSigRawMessageSignature": sign_digest(lib, secret_a, message_hash).hex(),
        "dataSigLeafScript": data_sig_leaf_script.hex(),
        "dataSigControlBlock": f"{P2MR_CONTROL_BYTE_V1:02x}",
        "dataSigScriptPubKey": p2mr_script_pubkey(p2mr_leaf_hash(data_sig_leaf_script)).hex(),
        "dataSigWrongPubkeyLeafScript": data_sig_wrong_pubkey_leaf_script.hex(),
        "dataSigWrongPubkeyScriptPubKey": p2mr_script_pubkey(p2mr_leaf_hash(data_sig_wrong_pubkey_leaf_script)).hex(),
        "dataSigAdd": {
            "provenance": (
                "Generated by contrib/devtools/generate-p2mr-pqc-witness-vectors.py "
                "using deterministic libbitcoinpqc random_data fills 0x20, 0x21, and 0x22; "
                "dataSigHash is computed independently as a QbitDataSigPQC tagged hash, "
                "and P2MR scriptPubKeys commit to independently serialized ADDPQC leaf scripts."
            ),
            "messageHash": message_hash.hex(),
            "wrongMessageHash": wrong_message_hash.hex(),
            "dataSigHash": data_sig_hash.hex(),
            "controlBlock": f"{P2MR_CONTROL_BYTE_V1:02x}",
            "pubkeyA": pubkey_a.hex(),
            "pubkeyB": pubkey_b.hex(),
            "pubkeyC": pubkey_c.hex(),
            "signatureA": sign_digest(lib, secret_a, data_sig_hash).hex(),
            "signatureB": sign_digest(lib, secret_b, data_sig_hash).hex(),
            "signatureC": sign_digest(lib, secret_c, data_sig_hash).hex(),
            "rawMessageSignatureA": sign_digest(lib, secret_a, message_hash).hex(),
            "nOfNLeafScript": n_of_n_leaf_script.hex(),
            "nOfNScriptPubKey": p2mr_script_pubkey(p2mr_leaf_hash(n_of_n_leaf_script)).hex(),
            "mOfNLeafScript": m_of_n_leaf_script.hex(),
            "mOfNScriptPubKey": p2mr_script_pubkey(p2mr_leaf_hash(m_of_n_leaf_script)).hex(),
            "wrongMessageHashLeafScript": wrong_message_hash_leaf_script.hex(),
            "wrongMessageHashScriptPubKey": p2mr_script_pubkey(p2mr_leaf_hash(wrong_message_hash_leaf_script)).hex(),
            "wrongPubkeyLeafScript": wrong_pubkey_leaf_script.hex(),
            "wrongPubkeyScriptPubKey": p2mr_script_pubkey(p2mr_leaf_hash(wrong_pubkey_leaf_script)).hex(),
        },
    }


def build_spent_outputs(script_pubkey: bytes, input_index: int, input_count: int) -> tuple[TxOut, ...]:
    return tuple(
        TxOut(1000, script_pubkey) if index == input_index else TxOut(2000, bytes([OP_1]))
        for index in range(input_count)
    )


def build_vector(lib: ctypes.CDLL, name: str, hash_type: int, seed_fill: int) -> dict[str, object]:
    pubkey, secret = deterministic_keypair(lib, seed_fill)
    leaf_script = build_p2mr_leaf_script(pubkey)
    leaf_hash = p2mr_leaf_hash(leaf_script)
    script_pubkey = p2mr_script_pubkey(leaf_hash)

    tx_without_witness = base_transaction()
    spent_outputs = build_spent_outputs(script_pubkey, 0, len(tx_without_witness.vin))
    sigmsg = p2mr_signature_msg(tx_without_witness, spent_outputs, hash_type, 0, leaf_hash)
    sighash = tagged_hash("P2MRSighash", sigmsg)
    raw_signature = sign_digest(lib, secret, sighash)
    witness_signature = raw_signature if hash_type == SIGHASH_DEFAULT else raw_signature + bytes([hash_type])
    tx = tx_without_witness.with_input_witness(0, (witness_signature, leaf_script, bytes([P2MR_CONTROL_BYTE_V1])))

    vector = {
        "name": name,
        "provenance": (
            "Generated by contrib/devtools/generate-p2mr-pqc-witness-vectors.py "
            f"using deterministic libbitcoinpqc random_data fill 0x{seed_fill:02x}; "
            "transaction, P2MR leaf, and P2MRSighash serialization are computed by "
            "this standalone Python generator without qbit wallet/signing/sighash helpers."
        ),
        "annex": "none",
        "inputIndex": 0,
        "hashType": f"{hash_type:02x}",
        "epoch": "00",
        "spendType": "02",
        "keyVersion": "00",
        "codeSeparatorPosition": "ffffffff",
        "prevoutAmount": spent_outputs[0].value,
        "prevoutScriptPubKey": script_pubkey.hex(),
        "spentOutputs": [
            {"amount": txout.value, "scriptPubKey": txout.script_pubkey.hex()}
            for txout in spent_outputs
        ],
        "spendTx": tx.serialize(with_witness=True).hex(),
        "leafVersion": f"{P2MR_LEAF_VERSION_V1:02x}",
        "leafScript": leaf_script.hex(),
        "controlBlock": f"{P2MR_CONTROL_BYTE_V1:02x}",
        "leafHash": leaf_hash.hex(),
        "pubkey": pubkey.hex(),
        "signature": witness_signature.hex(),
        "p2mrSigMsg": sigmsg.hex(),
        "p2mrSighash": sighash.hex(),
        "wrongDomainSighash": tagged_hash("TapSighash", sigmsg).hex(),
    }
    if hash_type == SIGHASH_DEFAULT:
        vector.update(build_data_sig_fields(lib, pubkey, secret))
    return vector


def build_missing_output_vector(
    lib: ctypes.CDLL,
    name: str,
    hash_type: int,
    seed_fill: int,
    input_index: int,
    vout: tuple[TxOut, ...],
) -> dict[str, object]:
    pubkey, secret = deterministic_keypair(lib, seed_fill)
    leaf_script = build_p2mr_leaf_script(pubkey)
    leaf_hash = p2mr_leaf_hash(leaf_script)
    script_pubkey = p2mr_script_pubkey(leaf_hash)

    base_tx = base_transaction()
    tx_without_witness = Transaction(base_tx.version, base_tx.vin, vout, base_tx.locktime)
    spent_outputs = build_spent_outputs(script_pubkey, input_index, len(tx_without_witness.vin))
    placeholder_digest = tagged_hash("P2MRMissingOutputTest", bytes([hash_type, seed_fill, input_index]))
    raw_signature = sign_digest(lib, secret, placeholder_digest)
    witness_signature = raw_signature + bytes([hash_type])
    tx = tx_without_witness.with_input_witness(
        input_index,
        (witness_signature, leaf_script, bytes([P2MR_CONTROL_BYTE_V1])),
    )

    return {
        "name": name,
        "provenance": (
            "Generated by contrib/devtools/generate-p2mr-pqc-witness-vectors.py "
            f"using deterministic libbitcoinpqc random_data fill 0x{seed_fill:02x}; "
            "missing-output SIGHASH_SINGLE vectors intentionally omit p2mrSigMsg "
            "and p2mrSighash because P2MR rejects before defining a digest."
        ),
        "annex": "none",
        "inputIndex": input_index,
        "hashType": f"{hash_type:02x}",
        "expectedError": "P2MR_SIG_HASHTYPE",
        "epoch": "00",
        "spendType": "02",
        "keyVersion": "00",
        "codeSeparatorPosition": "ffffffff",
        "prevoutAmount": spent_outputs[input_index].value,
        "prevoutScriptPubKey": script_pubkey.hex(),
        "spentOutputs": [
            {"amount": txout.value, "scriptPubKey": txout.script_pubkey.hex()}
            for txout in spent_outputs
        ],
        "spendTx": tx.serialize(with_witness=True).hex(),
        "leafVersion": f"{P2MR_LEAF_VERSION_V1:02x}",
        "leafScript": leaf_script.hex(),
        "controlBlock": f"{P2MR_CONTROL_BYTE_V1:02x}",
        "leafHash": leaf_hash.hex(),
        "pubkey": pubkey.hex(),
        "signature": witness_signature.hex(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write vectors to this path instead of stdout")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    lib = load_libbitcoinpqc(repo_root)
    vectors = [build_vector(lib, *spec) for spec in vector_specs()]
    vectors += [build_missing_output_vector(lib, *spec) for spec in missing_output_vector_specs()]
    payload = json.dumps(vectors, indent=2) + "\n"

    if args.output:
        args.output.write_text(payload, encoding="utf8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
