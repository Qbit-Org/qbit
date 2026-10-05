#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Deterministically generate the qbit fuzz seed corpora and MANIFEST.json.

Every seed is described as the sequence of values its harness consumes from
FuzzedDataProvider. FdpEncoder turns that sequence into the exact bytes that
make the C++ provider return those values, so each file has documented case
semantics instead of being an opaque fuzzer output.

    test/fuzz/qbit_corpora/generate_seeds.py          # rewrite seeds + manifest
    test/fuzz/qbit_corpora/generate_seeds.py --check  # verify committed files
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # keep target directories free of __pycache__
sys.path.insert(0, str(Path(__file__).resolve().parent))
from overlay import (  # noqa: E402
    LIMITS,
    MANIFEST_NAME,
    MANIFEST_SCHEMA_VERSION,
    REQUIRED_TARGETS,
    SEED_NAME_PATTERN,
)

CORPORA_DIR = Path(__file__).resolve().parent

UINT8, UINT16, INT32, UINT32, INT64, UINT64 = "u8", "u16", "i32", "u32", "i64", "u64"
TYPE_RANGES = {
    UINT8: (8, 0, 2**8 - 1),
    UINT16: (16, 0, 2**16 - 1),
    INT32: (32, -(2**31), 2**31 - 1),
    UINT32: (32, 0, 2**32 - 1),
    INT64: (64, -(2**63), 2**63 - 1),
    UINT64: (64, 0, 2**64 - 1),
}
SIZE_T = UINT64


class FdpEncoder:
    """Encode values in the order a harness consumes them.

    FuzzedDataProvider reads byte arrays and strings from the front of the
    buffer and integers from the back, one byte at a time, most significant
    byte first. Once both streams are exhausted every further call returns its
    minimum (0, false or an empty vector).
    """

    def __init__(self) -> None:
        self._front = bytearray()
        self._back = bytearray()

    def raw(self, data: bytes) -> "FdpEncoder":
        """ConsumeBytes(len(data)) with enough data available."""
        self._front += data
        return self

    def random_length_bytes(self, data: bytes) -> "FdpEncoder":
        """ConsumeRandomLengthByteVector: backslash is escaped, backslash plus any other byte terminates."""
        for byte in data:
            self._front.append(byte)
            if byte == 0x5C:
                self._front.append(0x5C)
        self._front += b"\x5c\x00"
        return self

    def integral(self, value: int, type_name: str, lo: int | None = None, hi: int | None = None) -> "FdpEncoder":
        """ConsumeIntegralInRange<type>(lo, hi); defaults to the full type range."""
        bits, type_lo, type_hi = TYPE_RANGES[type_name]
        lo = type_lo if lo is None else lo
        hi = type_hi if hi is None else hi
        if not type_lo <= lo <= hi <= type_hi or not lo <= value <= hi:
            raise ValueError(f"{value} not in [{lo}, {hi}] for {type_name}")
        span = hi - lo
        byte_count = 0
        while byte_count * 8 < bits and (span >> (byte_count * 8)) > 0:
            byte_count += 1
        self._back += (value - lo).to_bytes(byte_count, "big")
        return self

    def boolean(self, value: bool) -> "FdpEncoder":
        return self.integral(int(value), UINT8)

    def pick(self, index: int, count: int) -> "FdpEncoder":
        """PickValueInArray / CallOneOf over `count` alternatives."""
        return self.integral(index, SIZE_T, 0, count - 1)

    def build(self) -> bytes:
        return bytes(self._front) + bytes(reversed(self._back))


def pattern(length: int, seed: int) -> bytes:
    return bytes((seed + i * 0x3D) & 0xFF for i in range(length))


def tagged(target_tag: bytes, selector: int, body: bytes) -> bytes:
    """Version 1 tagged input: b"QBFX", target tag, version, selector, FDP body."""
    return b"QBFX" + target_tag + b"\x01" + bytes([selector]) + body


# Fixture selectors: any low nibble other than 0xF selects the fixture body.
FIXTURE_SELECTOR = 0x00
GENERATION_SELECTORS = (0x0F, 0xFF)

# --- pqc -------------------------------------------------------------------

PQC_KEYGEN_RANDOM_DATA_SIZE = 128
PQC_SECKEY_SIZE = 64
PQC_SIG_SIZE = 3680
PQC_PUBKEY_SIZE = 32
PQC_MAX_SIGNATURES = 1 << 30


def pqc_legacy(*, import_mode: str) -> bytes:
    """Legacy pqc layout. Blocks 1-3 always generate two keys and sign twice.

    import_mode selects block 4: "valid" imports a generated secret and signs,
    "corrupted" flips a bit of a generated secret, "counter_exhausted" signs
    with a valid key at PQC_MAX_SIGNATURES, "short" imports a 16-byte secret.
    """
    enc = FdpEncoder()
    # Block 1: arbitrary public key, empty signature, message -> must not verify.
    enc.random_length_bytes(pattern(PQC_PUBKEY_SIZE, 0x11))
    enc.random_length_bytes(b"")
    enc.random_length_bytes(b"block1")
    # Block 2: generated key signs, verifies, and rejects a bit-flipped signature.
    enc.raw(pattern(PQC_KEYGEN_RANDOM_DATA_SIZE, 0x21))
    enc.random_length_bytes(b"block2")
    enc.integral(7, UINT32, 0, PQC_MAX_SIGNATURES - 1)
    enc.integral(1234, SIZE_T, 0, PQC_SIG_SIZE - 1)
    enc.integral(3, UINT8, 0, 7)
    # Block 3: second generated key signs and verifies.
    enc.raw(pattern(PQC_KEYGEN_RANDOM_DATA_SIZE, 0x31))
    enc.random_length_bytes(b"block3")
    enc.integral(0, UINT32, 0, PQC_MAX_SIGNATURES - 1)
    # Block 4: secret import.
    if import_mode == "short":
        enc.boolean(False)
        enc.integral(16, SIZE_T, 0, PQC_SECKEY_SIZE * 2)
        enc.raw(pattern(16, 0x41))
        enc.boolean(False)
    else:
        enc.boolean(True)
        enc.raw(pattern(PQC_SECKEY_SIZE, 0x41))
        enc.boolean(True)
        enc.raw(pattern(PQC_KEYGEN_RANDOM_DATA_SIZE, 0x51))
        if import_mode == "corrupted":
            enc.boolean(True)
            enc.integral(0, SIZE_T, 0, PQC_SECKEY_SIZE - 1)
            enc.integral(0, UINT8, 0, 7)
        else:
            enc.boolean(False)
    enc.random_length_bytes(b"block4")
    counter = PQC_MAX_SIGNATURES if import_mode == "counter_exhausted" else 5
    enc.integral(counter, UINT32, 0, PQC_MAX_SIGNATURES)
    return enc.build()


PQC_OP_SIG_BIT, PQC_OP_SIG_BYTE, PQC_OP_SIG_RESIZE, PQC_OP_PUBKEY_BIT, PQC_OP_OTHER_MESSAGE, PQC_OP_FUZZ_MESSAGE, PQC_OP_OTHER_KEY = range(7)
PQC_OP_COUNT = 7


def pqc_fixture(key_index: int, msg_index: int, ops: list[tuple]) -> bytes:
    enc = FdpEncoder()
    enc.integral(key_index, SIZE_T, 0, 1)
    enc.integral(msg_index, SIZE_T, 0, 1)
    for op, *values in ops:
        enc.boolean(True)
        enc.pick(op, PQC_OP_COUNT)
        if op == PQC_OP_SIG_BIT:
            sig_size, pos, bit = values
            enc.integral(pos, SIZE_T, 0, sig_size - 1)
            enc.integral(bit, UINT8, 0, 7)
        elif op == PQC_OP_SIG_RESIZE:
            enc.integral(values[0], SIZE_T, 0, PQC_SIG_SIZE + 1)
        elif op == PQC_OP_PUBKEY_BIT:
            pos, bit = values
            enc.integral(pos, SIZE_T, 0, PQC_PUBKEY_SIZE - 1)
            enc.integral(bit, UINT8, 0, 7)
        elif op == PQC_OP_FUZZ_MESSAGE:
            enc.random_length_bytes(values[0])
        elif op in (PQC_OP_OTHER_MESSAGE, PQC_OP_OTHER_KEY):
            pass
        else:
            raise ValueError(f"unsupported pqc fixture op {op}")
    enc.boolean(False)
    return tagged(b"P", FIXTURE_SELECTOR, enc.build())


def pqc_cases() -> list[dict]:
    legacy_valid = pqc_legacy(import_mode="valid")
    legacy_corrupted = pqc_legacy(import_mode="corrupted")
    return [
        case("legacy-generated-valid-sign-verify", "legacy", legacy_valid,
             "Untagged legacy layout: generate two keys, sign and verify, reject a flipped signature bit; "
             "import a generated secret (accepted by Set) and sign with counter 5."),
        case("legacy-import-corrupted-secret", "legacy", legacy_corrupted,
             "Untagged legacy layout; block 4 flips bit 0 of a generated secret, which Set must reject."),
        case("legacy-counter-exhausted", "legacy", pqc_legacy(import_mode="counter_exhausted"),
             "Untagged legacy layout; block 4 signs with a valid key at PQC_MAX_SIGNATURES, which must fail."),
        case("legacy-short-secret-import", "legacy", pqc_legacy(import_mode="short"),
             "Untagged legacy layout; block 4 imports a 16-byte secret, which Set must reject."),
        case("fixture-untouched-key0-msg0", "qbfx-v1-fixture", pqc_fixture(0, 0, []),
             "Fixture key 0 message 0 without mutation: the real signature must verify."),
        case("fixture-untouched-key1-msg1", "qbfx-v1-fixture", pqc_fixture(1, 1, []),
             "Fixture key 1 message 1 without mutation: the real signature must verify."),
        case("fixture-signature-bit-flip", "qbfx-v1-fixture",
             pqc_fixture(0, 1, [(PQC_OP_SIG_BIT, PQC_SIG_SIZE, 2048, 5)]),
             "Flip one signature bit: verification must fail."),
        case("fixture-signature-double-flip-restored", "qbfx-v1-fixture",
             pqc_fixture(1, 0, [(PQC_OP_SIG_BIT, PQC_SIG_SIZE, 17, 2), (PQC_OP_SIG_BIT, PQC_SIG_SIZE, 17, 2)]),
             "Flip the same signature bit twice: bytes are unchanged, so verification must succeed."),
        case("fixture-signature-truncated", "qbfx-v1-fixture",
             pqc_fixture(0, 0, [(PQC_OP_SIG_RESIZE, PQC_SIG_SIZE - 1)]),
             "Truncate the signature by one byte: verification must fail."),
        case("fixture-signature-extended", "qbfx-v1-fixture",
             pqc_fixture(1, 1, [(PQC_OP_SIG_RESIZE, PQC_SIG_SIZE + 1)]),
             "Extend the signature by one zero byte: verification must fail."),
        case("fixture-pubkey-bit-flip", "qbfx-v1-fixture",
             pqc_fixture(0, 0, [(PQC_OP_PUBKEY_BIT, 31, 7)]),
             "Flip the top bit of the last public key byte: verification must fail."),
        case("fixture-other-message", "qbfx-v1-fixture",
             pqc_fixture(1, 0, [(PQC_OP_OTHER_MESSAGE,)]),
             "Verify the signature against the key's other fixture message: verification must fail."),
        case("fixture-fuzzer-message", "qbfx-v1-fixture",
             pqc_fixture(0, 1, [(PQC_OP_FUZZ_MESSAGE, b"not the fixture message")]),
             "Verify against the hash of input-provided message bytes: verification must fail."),
        case("fixture-cross-key", "qbfx-v1-fixture",
             pqc_fixture(0, 0, [(PQC_OP_OTHER_KEY,)]),
             "Verify key 0's signature with key 1's public key: verification must fail."),
        case("generation-valid-sign-verify", "qbfx-v1-generation",
             tagged(b"P", GENERATION_SELECTORS[0], legacy_valid),
             "Tagged generation selector 0x0F followed by the legacy-generated-valid-sign-verify layout."),
        case("generation-import-corrupted-secret", "qbfx-v1-generation",
             tagged(b"P", GENERATION_SELECTORS[1], legacy_corrupted),
             "Tagged generation selector 0xFF followed by the legacy-import-corrupted-secret layout."),
    ]


# --- p2mr_script -------------------------------------------------------------

P2MR_MODE_COUNT = 16
MODE_VALID_CHECKSIGPQC, MODE_VERIFY_TRUE = 0, 1
MODE_CHECKDATASIGPQC_BOUNDARY = 5
MODE_CTV_WITH_CHECKSIGPQC = 15
HASH_TYPES = ("DEFAULT", "ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY")
SIGNING_MODES = (MODE_VALID_CHECKSIGPQC, MODE_VERIFY_TRUE, MODE_CTV_WITH_CHECKSIGPQC)


def p2mr_legacy(*, mode: int, mode_picks: tuple[tuple[int, int], ...] = (), sibling: bool = False,
                control: tuple | None = None, annex: bool = False, hash_type: str = "DEFAULT",
                corruption: tuple | None = None, flags: tuple[bool, bool, bool] = (False, False, False)) -> bytes:
    enc = FdpEncoder()
    enc.raw(pattern(PQC_KEYGEN_RANDOM_DATA_SIZE, 0x61))
    enc.pick(mode, P2MR_MODE_COUNT)
    for index, count in mode_picks:
        enc.pick(index, count)
    enc.boolean(False)  # keep the committed leaf as witness leaf
    enc.boolean(sibling)
    if sibling:
        enc.boolean(True)  # sibling leaf is OP_FALSE
    enc.boolean(control is not None)
    if control is not None:
        enc.pick(control[0], 3)
        if control[0] == 2:
            enc.integral(control[1], UINT8)
    enc.boolean(annex)
    if mode in SIGNING_MODES:
        enc.pick(HASH_TYPES.index(hash_type), len(HASH_TYPES))
        enc.boolean(corruption is not None)
        if corruption is not None:
            enc.pick(corruption[0], 4)
            if corruption[0] == 0:
                sig_size = PQC_SIG_SIZE + (hash_type != "DEFAULT")
                enc.integral(corruption[1], SIZE_T, 0, sig_size - 1)
    for flag in flags:
        enc.boolean(flag)
    return enc.build()


P2MR_OP_SIG_BIT, P2MR_OP_HASHTYPE_BYTE, P2MR_OP_DROP_HASHTYPE, P2MR_OP_LEAF_SCRIPT, P2MR_OP_CONTROL, P2MR_OP_ANNEX, \
    P2MR_OP_INSERT_ITEM, P2MR_OP_POP_ITEM, P2MR_OP_LOCKTIME, P2MR_OP_VALUE, P2MR_OP_SEQUENCE, P2MR_OP_FLAG = range(12)
P2MR_OP_COUNT = 12
P2MR_FIXTURES = ("checksigpqc-default", "checksigpqc-all", "verify-true-default", "verify-true-all", "ctv-checksigpqc-default", "ctv-checksigpqc-all")


def p2mr_fixture(fixture: str, ops: list[tuple]) -> bytes:
    enc = FdpEncoder()
    enc.pick(P2MR_FIXTURES.index(fixture), len(P2MR_FIXTURES))
    for op, *values in ops:
        enc.boolean(True)
        enc.pick(op, P2MR_OP_COUNT)
        if op == P2MR_OP_HASHTYPE_BYTE:
            enc.integral(values[0], UINT8)
        elif op == P2MR_OP_LOCKTIME:
            enc.integral(values[0], UINT32)
        else:
            raise ValueError(f"unsupported p2mr fixture op {op}")
    enc.boolean(False)
    return tagged(b"M", FIXTURE_SELECTOR, enc.build())


def p2mr_cases() -> list[dict]:
    legacy_valid = p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC)
    return [
        case("legacy-checksigpqc-default-valid", "legacy", legacy_valid,
             "Untagged legacy layout: generated key, <pubkey> OP_CHECKSIGPQC single leaf, SIGHASH_DEFAULT "
             "signature, no mutation; the spend is valid."),
        case("legacy-checksigpqc-all-valid", "legacy", p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, hash_type="ALL"),
             "As legacy-checksigpqc-default-valid with an explicit SIGHASH_ALL byte; the spend is valid."),
        case("legacy-verify-true-sibling-single-anyonecanpay-valid", "legacy",
             p2mr_legacy(mode=MODE_VERIFY_TRUE, sibling=True, hash_type="SINGLE|ANYONECANPAY"),
             "OP_CHECKSIGPQC OP_VERIFY OP_TRUE leaf next to an OP_FALSE sibling (65-byte control block), "
             "SIGHASH_SINGLE|ANYONECANPAY; the spend is valid."),
        case("legacy-ctv-checksigpqc-all-valid", "legacy", p2mr_legacy(mode=MODE_CTV_WITH_CHECKSIGPQC, hash_type="ALL"),
             "Matching OP_CHECKTEMPLATEVERIFY followed by OP_CHECKSIGPQC, SIGHASH_ALL; the spend is valid."),
        case("legacy-signature-bit-flip", "legacy",
             p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, corruption=(0, 100)),
             "SIGHASH_DEFAULT signature with byte 100 xor 0x01: rejected with SCRIPT_ERR_P2MR_SIG."),
        case("legacy-signature-truncated", "legacy", p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, corruption=(3,)),
             "SIGHASH_DEFAULT signature truncated by one byte: rejected with SCRIPT_ERR_P2MR_SIG_SIZE."),
        case("legacy-invalid-hashtype-appended", "legacy", p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, corruption=(1,)),
             "SIGHASH_DEFAULT signature with 0x04 appended: rejected with SCRIPT_ERR_P2MR_SIG_HASHTYPE."),
        case("legacy-control-block-bit0-cleared", "legacy", p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, control=(0,)),
             "Control byte xor 0x01: rejected with SCRIPT_ERR_P2MR_CONTROL_BIT0."),
        case("legacy-control-block-truncated", "legacy", p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, control=(1,)),
             "Control block missing its last byte: rejected with SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE."),
        case("legacy-checkdatasig-empty-signature", "legacy",
             p2mr_legacy(mode=MODE_CHECKDATASIGPQC_BOUNDARY, mode_picks=((0, 4), (1, 3), (1, 3))),
             "OP_CHECKDATASIGPQC with a 32-byte message, 32-byte key and empty signature; no signing, rejected."),
        case("legacy-annex-discouraged-flags", "legacy",
             p2mr_legacy(mode=MODE_VALID_CHECKSIGPQC, annex=True, flags=(True, True, True)),
             "Annex appended after annex-less signing, all discouragement flags set: rejected with SCRIPT_ERR_P2MR_SIG."),
        case("fixture-checksigpqc-default-untouched", "qbfx-v1-fixture", p2mr_fixture("checksigpqc-default", []),
             "Unmodified clone of the signed OP_CHECKSIGPQC SIGHASH_DEFAULT fixture: must verify."),
        case("fixture-ctv-checksigpqc-all-untouched", "qbfx-v1-fixture", p2mr_fixture("ctv-checksigpqc-all", []),
             "Unmodified clone of the signed CTV + OP_CHECKSIGPQC SIGHASH_ALL fixture: must verify."),
        case("fixture-ctv-locktime-changed", "qbfx-v1-fixture",
             p2mr_fixture("ctv-checksigpqc-default", [(P2MR_OP_LOCKTIME, 1)]),
             "CTV fixture with nLockTime 1: rejected with SCRIPT_ERR_TEMPLATE_MISMATCH."),
        case("fixture-verify-true-explicit-default-hashtype", "qbfx-v1-fixture",
             p2mr_fixture("verify-true-all", [(P2MR_OP_HASHTYPE_BYTE, 0x00)]),
             "SIGHASH_ALL fixture with its hash type byte set to 0x00: rejected with SCRIPT_ERR_P2MR_SIG_HASHTYPE."),
        case("generation-checksigpqc-default-valid", "qbfx-v1-generation",
             tagged(b"M", GENERATION_SELECTORS[0], legacy_valid),
             "Tagged generation selector 0x0F followed by the legacy-checksigpqc-default-valid layout."),
    ]


# --- asert -------------------------------------------------------------------

POW_LIMIT = 2**240 - 1  # 0000ffff...ff on TESTNET4
ASERT_REF_FALLBACK = 0  # zero selects the anchor target
MAX_SKEW = 2**46 - 1


def u256_le(value: int) -> bytes:
    return value.to_bytes(32, "little")


def asert_math(steps: list[tuple[int, int, int]]) -> bytes:
    enc = FdpEncoder()
    for ref, height_diff, skew in steps:
        enc.raw(u256_le(ref))
        enc.integral(height_diff, INT64, 0, 1_000_000)
        enc.integral(skew, INT64, -1_000_000_000, 1_000_000_000)
    return enc.build()


def asert_math_cases() -> list[dict]:
    mixed = []
    refs = (1, 2**128, POW_LIMIT, ASERT_REF_FALLBACK)
    heights = (0, 1, 288, 1_000_000)
    skews = (-1_000_000_000, -7200, 0, 7200, 1_000_000_000)
    for i in range(64):
        mixed.append((refs[i % 4], heights[(i // 4) % 4], skews[(i // 16 + i) % 5]))
    return [
        case("anchor-target-on-schedule", "fdp", asert_math([(ASERT_REF_FALLBACK, 1000, 0)]),
             "Zero reference target falls back to the anchor target; 1000 blocks exactly on schedule."),
        case("pow-limit-reference-slow-blocks", "fdp", asert_math([(POW_LIMIT, 1, 1_000_000_000)]),
             "powLimit reference with one block arriving 1e9 seconds late: result is clamped to powLimit."),
        case("minimum-target-fast-blocks", "fdp", asert_math([(1, 1_000_000, -1_000_000_000)]),
             "Reference target 1 with 1e6 blocks arriving 1e9 seconds early: result is clamped to at least 1."),
        case("above-pow-limit-fallback", "fdp", asert_math([(2**256 - 1, 0, 0), (POW_LIMIT + 1, 10, 600)]),
             "Reference targets above powLimit fall back to the anchor target."),
        case("mixed-reference-height-skew-grid", "fdp", asert_math(mixed),
             "64 steps cycling reference targets {1, 2^128, powLimit, fallback}, heights and skews."),
    ]


def asert_edge(steps: list[tuple[int, int, int, int]]) -> bytes:
    enc = FdpEncoder()
    for ref, half_life_index, height_index, skew_index in steps:
        enc.raw(u256_le(ref))
        enc.pick(half_life_index, 6)
        enc.pick(height_index, 6)
        enc.pick(skew_index, 7)
    return enc.build()


def asert_edge_grid(ref: int, half_life_indices: range) -> list[tuple[int, int, int, int]]:
    return [(ref, h, n, s) for h in half_life_indices for n in range(6) for s in range(7)]


def asert_edge_cases_cases() -> list[dict]:
    extremes = [(1, h, 5, s) for h in range(6) for s in (0, 1, 5, 6)]
    return [
        case("exhaustive-grid-fallback-short-half-lives", "fdp", asert_edge(asert_edge_grid(ASERT_REF_FALLBACK, range(0, 3))),
             "Anchor-target fallback over every height and skew choice for half-lives 1, 2 and 16."),
        case("exhaustive-grid-fallback-long-half-lives", "fdp", asert_edge(asert_edge_grid(ASERT_REF_FALLBACK, range(3, 6))),
             "Anchor-target fallback over every height and skew choice for half-lives 1024, nASERTHalfLife and INT32_MAX."),
        case("exhaustive-grid-pow-limit-short-half-lives", "fdp", asert_edge(asert_edge_grid(POW_LIMIT, range(0, 3))),
             "powLimit reference over every height and skew choice for half-lives 1, 2 and 16."),
        case("exhaustive-grid-pow-limit-long-half-lives", "fdp", asert_edge(asert_edge_grid(POW_LIMIT, range(3, 6))),
             "powLimit reference over every height and skew choice for half-lives 1024, nASERTHalfLife and INT32_MAX."),
        case("minimum-target-extreme-skews", "fdp", asert_edge(extremes),
             "Reference target 1, height difference 1e7, skews of +/-(2^46-1) and +/-half-life for every half-life."),
    ]


TARGET_SPACING_MAX = 240  # nPowTargetSpacing * 4


def asert_chain(deltas: list[int]) -> bytes:
    enc = FdpEncoder()
    for delta in deltas:
        enc.integral(delta, UINT32, 1, TARGET_SPACING_MAX)
    return enc.build()


def asert_chain_transition_cases() -> list[dict]:
    return [
        case("permissionless-lane-on-schedule", "fdp", asert_chain([75] * 2000),
             "2000 permissionless-lane blocks at the 75 second lane spacing."),
        case("fast-blocks-raise-difficulty", "fdp", asert_chain([1] * 1500),
             "1500 blocks one second apart: the target shrinks every block."),
        case("slow-blocks-reach-pow-limit", "fdp", asert_chain([TARGET_SPACING_MAX] * 1500),
             "1500 blocks 240 seconds apart: the target grows until it is clamped to powLimit."),
        case("alternating-fast-slow", "fdp", asert_chain([1, TARGET_SPACING_MAX] * 1000),
             "2000 blocks alternating 1 and 240 second spacing."),
        case("aggregate-cadence-then-slow", "fdp", asert_chain([60] * 1000 + [150] * 1000),
             "1000 blocks at the 60 second aggregate cadence followed by 1000 blocks at 150 seconds."),
    ]


# --- auxpow ------------------------------------------------------------------

TIME_MIN, TIME_MAX = 946684801, 4133980799  # ConsumeTime defaults
VERSION_TOP_BITS = 0x20000000


def encode_transaction(enc: FdpEncoder, *, inputs: int, outputs: int) -> None:
    """ConsumeTransaction(fdp, std::nullopt) with p2wsh_op_true, so no scripts are consumed."""
    enc.boolean(True)  # p2wsh_op_true
    enc.boolean(True)  # CURRENT_VERSION
    enc.integral(0, UINT32)  # nLockTime
    enc.integral(inputs, INT32, 0, 10)
    enc.integral(outputs, INT32, 0, 10)
    for i in range(inputs):
        enc.raw(pattern(32, 0x71 + i))
        enc.integral(0, UINT32, 0, 10)
        enc.boolean(True)
        enc.pick(0, 3)  # SEQUENCE_FINAL
    for _ in range(outputs):
        enc.integral(1000, INT64, -10, 50 * 100_000_000 + 10)


def encode_pure_header(enc: FdpEncoder, *, version: int) -> None:
    enc.integral(version, INT32)
    enc.raw(pattern(32, 0x81))
    enc.raw(pattern(32, 0x91))
    enc.integral(1_781_704_709, INT64, TIME_MIN, TIME_MAX)
    enc.integral(0x1F00FFFF, UINT32)
    enc.integral(0, UINT32)


def encode_auxpow(enc: FdpEncoder, *, branch_length: int = 0, chain_index: int = 0) -> None:
    encode_transaction(enc, inputs=0, outputs=0)
    enc.integral(branch_length, SIZE_T, 0, 16)
    for i in range(branch_length):
        enc.raw(pattern(32, i))
    enc.integral(0, INT32)
    enc.integral(branch_length, SIZE_T, 0, 16)
    for i in range(branch_length):
        enc.raw(pattern(32, 0x40 + i))
    enc.integral(chain_index, INT32)
    encode_pure_header(enc, version=VERSION_TOP_BITS)


def auxpow_input(*, payload: dict | None, header: str | None, checkblock: bool) -> bytes:
    enc = FdpEncoder()
    enc.boolean(payload is not None)
    if payload is not None:
        encode_auxpow(enc, **payload)
        enc.raw(pattern(32, 0xA1))  # aux block hash
        enc.integral(0x1F00FFFF, UINT32)  # target bits
        enc.integral(47, UINT16)  # expected chain id (mainnet)
        enc.integral(0, UINT32)  # nonce
        enc.pick(0, 3)  # CommitmentValidation::EITHER
        enc.boolean(False)  # check_pow
    enc.boolean(header is not None)
    if header is not None:
        encode_block_header(enc, auxpow=header == "auxpow-chainid-mismatch")
        enc.boolean(True)  # check_pow
    enc.boolean(checkblock)
    if checkblock:
        encode_block_header(enc, auxpow=False)
        enc.integral(1, SIZE_T, 1, 4)
        encode_transaction(enc, inputs=1, outputs=1)
        # CheckBlock(..., ConsumeBool(), ConsumeBool()) has compiler-dependent
        # argument evaluation order, so both values are equal.
        enc.boolean(False)
        enc.boolean(False)
        enc.boolean(False)  # auxpow::Validate check_pow
    return enc.build()


def encode_block_header(enc: FdpEncoder, *, auxpow: bool) -> None:
    encode_pure_header(enc, version=VERSION_TOP_BITS)
    enc.boolean(auxpow)
    if auxpow:
        encode_auxpow(enc)
        # MakeVersion(ConsumeIntegral<uint16_t>(), true, ConsumeIntegral<uint8_t>()) has
        # compiler-dependent argument evaluation order; three zero bytes decode as
        # chain id 0 and version bits 0 in either order.
        enc.integral(0, UINT16)
        enc.integral(0, UINT8)


def auxpow_cases() -> list[dict]:
    return [
        case("payload-non-coinbase-rejected", "fdp", auxpow_input(payload={}, header=None, checkblock=False),
             "Standalone auxpow payload whose transaction has no inputs: rejected as bad-auxpow-coinbase."),
        case("payload-long-branches-negative-chain-index", "fdp",
             auxpow_input(payload={"branch_length": 16, "chain_index": -1}, header=None, checkblock=False),
             "Payload with 16-hash coinbase and chain branches and chain index -1; exercises branch hashing "
             "and expected-index derivation before rejection."),
        case("header-permissionless-pow-check", "fdp", auxpow_input(payload=None, header="permissionless", checkblock=False),
             "Header without the auxpow version bit or payload, validated with check_pow set."),
        case("header-auxpow-chainid-mismatch", "fdp", auxpow_input(payload=None, header="auxpow-chainid-mismatch", checkblock=False),
             "Header with auxpow payload and chain id 0 (mainnet expects 47): rejected as bad-auxpow-chainid."),
        case("checkblock-single-non-coinbase-tx", "fdp", auxpow_input(payload=None, header=None, checkblock=True),
             "CheckBlock on a permissionless block whose only transaction is not a coinbase."),
        case("all-branches", "fdp", auxpow_input(payload={}, header="auxpow-chainid-mismatch", checkblock=True),
             "Payload validation, header validation and CheckBlock in one input."),
    ]


# --- manifest ----------------------------------------------------------------


# --- mlkem, mlkem_backend_diff -----------------------------------------------

MLKEM_SEED_BYTES = 64
MLKEM_COINS_BYTES = 32
MLKEM_EK_BYTES = 1568
MLKEM_CT_BYTES = 1568
MLKEM_DK_BYTES = 3168
MLKEM_Q = 3329
MLKEM_VECTORS = CORPORA_DIR.parents[2] / "src" / "test" / "data" / "mlkem1024_vectors.json"


def mlkem_vectors() -> dict:
    return json.loads(MLKEM_VECTORS.read_text(encoding="utf-8"))


def mlkem_set_coefficient(ek: bytes, poly: int, index: int, value: int) -> bytes:
    """Overwrite one 12-bit coefficient of an encapsulation key (FIPS 203 ByteEncode_12)."""
    out = bytearray(ek)
    pos = 384 * poly + 3 * (index // 2)
    if index % 2 == 0:
        out[pos] = value & 0xFF
        out[pos + 1] = (out[pos + 1] & 0xF0) | (value >> 8)
    else:
        out[pos + 1] = (out[pos + 1] & 0x0F) | ((value & 0x0F) << 4)
        out[pos + 2] = value >> 4
    return bytes(out)


def mlkem_input(*, ek: bytes | None = None, ct: bytes | None = None, dk: bytes | None = None,
                flip_bit: int | None = None) -> bytes:
    """The shared layout of both ML-KEM targets.

    Front: key generation seed d || z (64 bytes), encapsulation coins (32), an
    arbitrary encapsulation key (1568), ciphertext (1568) and decapsulation key
    (3168). Back: whether to flip a bit of the honest ciphertext, and which.
    The harness zero-fills fields cut off by the end of the input, so a seed
    may stop after any field. A bit flip needs every front field present.
    """
    enc = FdpEncoder()
    enc.raw(pattern(MLKEM_SEED_BYTES, 0x61))
    enc.raw(pattern(MLKEM_COINS_BYTES, 0x71))
    fields = [(ek, MLKEM_EK_BYTES), (ct, MLKEM_CT_BYTES), (dk, MLKEM_DK_BYTES)]
    if flip_bit is not None:
        fields = [(value if value is not None else bytes(size), size) for value, size in fields]
    while fields and fields[-1][0] is None:
        fields.pop()
    for value, size in fields:
        value = value if value is not None else bytes(size)
        if len(value) != size:
            raise ValueError(f"ML-KEM field of {len(value)} bytes, expected {size}")
        enc.raw(value)
    if flip_bit is not None:
        enc.boolean(True)
        enc.integral(flip_bit, SIZE_T, 0, MLKEM_CT_BYTES * 8 - 1)
    return enc.build()


def mlkem_cases() -> list[dict]:
    vectors = mlkem_vectors()
    base_ek = bytes.fromhex(vectors["cctv_modulus"]["base_ek"])
    acvp = vectors["acvp"]
    decaps = {tc["tcId"]: tc for tc in acvp["decapsulation"]}
    valid = next(tc for tc in decaps.values() if tc["reason"] == "valid decapsulation")
    modified = next(tc for tc in decaps.values() if tc["reason"] == "modified ciphertext")
    bad_dk = next(tc for tc in acvp["decapsulationKeyCheck"] if not tc["testPassed"])
    return [
        case("honest-round-trip", "fdp", mlkem_input(),
             "Key generation, encapsulation and decapsulation from fixed seed and coins agree; the all-zero "
             "encapsulation key is in range, and the all-zero decapsulation key fails its hash check."),
        case("cctv-base-key", "fdp", mlkem_input(ek=base_ek),
             "The key shared by the C2SP CCTV modulus vectors, every coefficient in range: accepted."),
        case("coefficient-3328", "fdp", mlkem_input(ek=mlkem_set_coefficient(base_ek, 0, 0, MLKEM_Q - 1)),
             "First coefficient q - 1 = 3328, the largest valid value: accepted."),
        case("coefficient-3329", "fdp", mlkem_input(ek=mlkem_set_coefficient(base_ek, 0, 0, MLKEM_Q)),
             "First coefficient q = 3329, the smallest invalid value: rejected, outputs cleared."),
        case("last-coefficient-4095", "fdp", mlkem_input(ek=mlkem_set_coefficient(base_ek, 3, 255, (1 << 12) - 1)),
             "Last coefficient of the last polynomial 4095: rejected, outputs cleared."),
        case("acvp-valid-decapsulation", "fdp",
             mlkem_input(ek=bytes.fromhex(valid["dk"])[1536:1536 + MLKEM_EK_BYTES], ct=bytes.fromhex(valid["c"]),
                         dk=bytes.fromhex(valid["dk"])),
             f"NIST ACVP decapsulation tcId {valid['tcId']} (valid): its key, ciphertext and decapsulation key."),
        case("acvp-modified-ciphertext", "fdp",
             mlkem_input(ek=bytes.fromhex(modified["dk"])[1536:1536 + MLKEM_EK_BYTES], ct=bytes.fromhex(modified["c"]),
                         dk=bytes.fromhex(modified["dk"])),
             f"NIST ACVP decapsulation tcId {modified['tcId']} (modified ciphertext): implicit rejection."),
        case("acvp-modified-key-hash", "fdp",
             mlkem_input(ct=bytes.fromhex(modified["c"]), dk=bytes.fromhex(bad_dk["dk"])),
             f"NIST ACVP decapsulation key check tcId {bad_dk['tcId']} (modified H): rejected, secret cleared."),
        case("honest-ciphertext-bit-flip", "fdp", mlkem_input(flip_bit=4321),
             "Flip bit 4321 of the honest ciphertext: decapsulation still yields a secret, a different one."),
    ]


# --- pq_records ---------------------------------------------------------------

PQ_VECTORS = CORPORA_DIR.parents[2] / "src" / "test" / "data" / "pq_transport_vectors.json"
PQ_MLKEM1024 = 0xF0


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def pq_record(header: int, payload: bytes) -> bytes:
    """A version-contents record: CompactSize(1 + len(payload)) || header || payload."""
    return compact_size(1 + len(payload)) + bytes([header]) + payload


def pq_records_cases() -> list[dict]:
    vectors = json.loads(PQ_VECTORS.read_text(encoding="utf-8"))["vectors"]
    ordinary, extra = vectors[0], vectors[2]
    offer = pq_record(PQ_MLKEM1024, bytes.fromhex(ordinary["ek"]))
    accept = pq_record(PQ_MLKEM1024, bytes.fromhex(ordinary["ct"]))
    unknown = pq_record(0xF1, b"qbit")
    minimal_unknown = pq_record(0x01, b"") * 1000
    return [
        case("offer", "raw", offer,
             "The ordinary offer of vector 0 of src/test/data/pq_transport_vectors.json: fd 21 06 f0 || ek."),
        case("accept", "raw", accept, "The ordinary accept of vector 0: fd 21 06 f0 || ct."),
        case("offer-duplicate-unknown", "raw", bytes.fromhex(extra["contents_responder"]),
             "Vector 2's responder contents: its offer, a second valid offer and an unknown 0xf1 record. The first wins."),
        case("unknown-then-accept", "raw", bytes.fromhex(extra["contents_initiator"]),
             "Vector 2's initiator contents: an unknown 0x01 record, then the accept."),
        case("reserved-and-unknown-headers", "raw", pq_record(0x00, b"") + pq_record(0xF1, b"\xaa") + pq_record(0xFF, b""),
             "Valid grammar without an own record: no features."),
        case("empty-own-record", "raw", pq_record(PQ_MLKEM1024, b""),
             "An own record with an empty payload: parses, and fails the role's length check later."),
        case("short-offer", "raw", pq_record(PQ_MLKEM1024, bytes.fromhex(ordinary["ek"])[:-1]),
             "A 1,567-byte own payload (ek_length or ct_length)."),
        case("long-offer", "raw", pq_record(PQ_MLKEM1024, bytes.fromhex(ordinary["ek"]) + b"\x00"),
             "A 1,569-byte own payload (ek_length or ct_length)."),
        case("malformed-first-then-offer", "raw", pq_record(PQ_MLKEM1024, b"\xaa\xbb") + offer,
             "A malformed first own record before a valid one: the first wins."),
        case("offer-trailing-byte", "raw", offer + b"\xfd",
             "A valid offer followed by a truncated CompactSize: invalid grammar, no features."),
        case("zero-length", "raw", unknown + b"\x00", "A record with len = 0 after a valid one: invalid grammar."),
        case("one-past-end", "raw", b"\x03\xf0\xaa",
             "A length one byte past the end of the contents: invalid grammar."),
        case("truncated-wide-length", "raw", b"\x02\x01\xaa\xfe\x00\x00",
             "A valid record, then a 0xfe CompactSize cut off after two of its four bytes: invalid grammar."),
        case("non-canonical-length", "raw", b"\xfd\x02\x00\xf0\xaa",
             "Length 2 in a 3-byte CompactSize: invalid grammar."),
        case("oversized-length", "raw", b"\xfe\x01\x00\x00\x02\xf0\xaa",
             "Length MAX_SIZE + 1 (0x02000001), which ReadCompactSize rejects: invalid grammar."),
        case("minimal-unknown-records", "raw", minimal_unknown + b"\x05",
             "1,000 one-byte unknown records ending in a truncated one: invalid grammar after a long valid prefix."),
    ]


# --- p2p_transport_bidirectional_v2, p2p_transport_bidirectional_v1v2 ---------

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
V2_MAX_GARBAGE_LEN = 4095
PQ_MODES = {"off": 0, "negotiate": 1, "fallback": 2}
# A responder never falls back, so the harness picks its mode from the first two only.
PQ_RESPONDER_MODES = 2
SIMULATION_MAX_MESSAGE = 75000
SIMULATION_ACTIONS = 6


def transport_key(label: str) -> bytes:
    key = hashlib.sha256(f"qbit fuzz seed key/{label}".encode()).digest()
    assert 0 < int.from_bytes(key, "big") < SECP256K1_ORDER
    return key


def v2_transport_side(enc: FdpEncoder, label: str, garbage_len: int, mode: str, initiator: bool) -> None:
    """MakeV2Transport: key, compression flag, garbage, ellswift entropy, PQ mode and ML-KEM seed."""
    enc.raw(transport_key(label))
    enc.boolean(True)
    enc.integral(garbage_len, SIZE_T, 0, V2_MAX_GARBAGE_LEN)
    if garbage_len <= 64:
        enc.raw(pattern(garbage_len, 0x31))
    enc.raw(hashlib.sha256(f"qbit fuzz seed ent/{label}".encode()).digest())
    if not initiator and PQ_MODES[mode] >= PQ_RESPONDER_MODES:
        raise ValueError(f"{label}: a responder cannot be in {mode} mode")
    enc.pick(PQ_MODES[mode], len(PQ_MODES) if initiator else PQ_RESPONDER_MODES)
    enc.raw(hashlib.sha256(f"qbit fuzz seed mlkem/{label}".encode()).digest())


def transport_v2_input(name: str, initiator: tuple[int, str], responder: tuple[int, str], tail: int) -> bytes:
    enc = FdpEncoder()
    enc.integral(int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big"), UINT64)
    v2_transport_side(enc, f"{name}/initiator", *initiator, initiator=True)
    v2_transport_side(enc, f"{name}/responder", *responder, initiator=False)
    # Both sides' first message ("version") sizes.
    enc.integral(1000, UINT32, 0, SIMULATION_MAX_MESSAGE)
    enc.integral(200, UINT32, 0, SIMULATION_MAX_MESSAGE)
    # Further bytes drive the interleaving loop from the back; the final flush completes the rest.
    enc.raw(pattern(tail, 0x47))
    return enc.build()


def transport_v2_cases() -> list[dict]:
    flush = "the final flush completes the handshake"
    loop = "a fixed 48-byte pattern drives the interleaving loop, then the final flush completes the handshake"
    cases = [
        ("negotiate-both", (0, "negotiate"), (0, "negotiate"), 0,
         f"Both sides negotiate, no garbage; {flush}: hybrid keys, confirmed both ways."),
        ("negotiate-both-max-garbage", (V2_MAX_GARBAGE_LEN, "negotiate"), (V2_MAX_GARBAGE_LEN, "negotiate"), 0,
         f"Both sides negotiate with 4,095 bytes of garbage each, so the held version packet's AAD is the longest; {flush}."),
        ("negotiate-both-interleaved", (64, "negotiate"), (17, "negotiate"), 48,
         f"Both sides negotiate, 64 and 17 bytes of garbage; {loop}: hybrid."),
        ("negotiate-both-interleaved-long-garbage", (1000, "negotiate"), (64, "negotiate"), 48,
         f"Both sides negotiate, 1,000 and 64 bytes of garbage; {loop}: hybrid."),
        ("initiator-negotiates-responder-off", (0, "negotiate"), (0, "off"), 0,
         f"The initiator holds its version packet for an empty one; {flush}: legacy_peer, ECDH keys."),
        ("initiator-negotiates-responder-off-interleaved", (64, "negotiate"), (5, "off"), 48,
         f"The initiator negotiates, the responder is off; {loop}: ECDH keys."),
        ("initiator-off-responder-offers", (0, "off"), (0, "negotiate"), 0,
         f"The responder offers to an initiator that is off and ignores it; {flush}: ECDH keys."),
        ("initiator-off-responder-offers-interleaved", (33, "off"), (64, "negotiate"), 48,
         f"The responder offers to an initiator that is off; {loop}: ECDH keys."),
        ("initiator-fallback-responder-offers", (0, "fallback"), (0, "negotiate"), 0,
         f"An initiator in fallback sends plain v2 and never parses the offer; {flush}: ECDH keys."),
        ("both-off", (0, "off"), (0, "off"), 0, f"Today's v2 on both sides; {flush}."),
        ("both-off-interleaved", (64, "off"), (64, "off"), 48, f"Today's v2 on both sides; {loop}."),
        ("initiator-fallback-responder-off", (2, "fallback"), (3, "off"), 0, f"Plain v2 on both sides; {flush}."),
        ("initiator-fallback-responder-offers-interleaved", (64, "fallback"), (17, "negotiate"), 48,
         f"An initiator in fallback never parses the offer; {loop}: ECDH keys."),
    ]
    return [case(name, "fdp", transport_v2_input(name, initiator, responder, tail), semantics)
            for name, initiator, responder, tail, semantics in cases]


def transport_v1v2_input(name: str, responder: tuple[int, str], v1_message: bool) -> bytes:
    enc = FdpEncoder()
    enc.integral(int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big"), UINT64)
    v2_transport_side(enc, f"{name}/responder", *responder, initiator=False)
    enc.integral(500, UINT32, 0, SIMULATION_MAX_MESSAGE)
    enc.integral(300, UINT32, 0, SIMULATION_MAX_MESSAGE)
    if v1_message:
        # One loop step: the v1 initiator takes its version message (the next message's type index
        # and size are drawn when it is queued); the final flush delivers it.
        enc.pick(0, SIMULATION_ACTIONS)
        enc.integral(0, UINT8)
        enc.integral(100, UINT32, 0, SIMULATION_MAX_MESSAGE)
    return enc.build()


def transport_v1v2_cases() -> list[dict]:
    return [
        case("v1-version-to-negotiating-responder", "fdp", transport_v1v2_input("v1-negotiate", (0, "negotiate"), True),
             "A v1 initiator's version message reaches a responder with the negotiation on: v1 detected, no key "
             "generated."),
        case("v1-version-to-off-responder", "fdp", transport_v1v2_input("v1-off", (64, "off"), True),
             "A v1 initiator's version message reaches a responder with the negotiation off: v1 detected."),
        case("v1-version-to-negotiating-responder-max-garbage", "fdp",
             transport_v1v2_input("v1-negotiate-max-garbage", (V2_MAX_GARBAGE_LEN, "negotiate"), True),
             "A v1 initiator's version message reaches a negotiating responder configured with 4,095 bytes of garbage, "
             "which it never sends: v1 detected."),
        case("v1-silent-negotiating-responder", "fdp", transport_v1v2_input("v1-silent", (0, "negotiate"), False),
             "A v1 initiator that sends nothing: the negotiating responder stays undecided and sends nothing."),
    ]


def case(name: str, fmt: str, data: bytes, semantics: str) -> dict:
    return {"name": name, "format": fmt, "data": data, "semantics": semantics}


CASE_BUILDERS = {
    "asert_chain_transition": asert_chain_transition_cases,
    "asert_edge_cases": asert_edge_cases_cases,
    "asert_math": asert_math_cases,
    "auxpow": auxpow_cases,
    "mlkem": mlkem_cases,
    "mlkem_backend_diff": mlkem_cases,
    "p2mr_script": p2mr_cases,
    "p2p_transport_bidirectional_v1v2": transport_v1v2_cases,
    "p2p_transport_bidirectional_v2": transport_v2_cases,
    "pq_records": pq_records_cases,
    "pqc": pqc_cases,
}


def build_all() -> tuple[dict, dict[str, list[dict]]]:
    assert tuple(sorted(CASE_BUILDERS)) == REQUIRED_TARGETS
    targets = {target: CASE_BUILDERS[target]() for target in REQUIRED_TARGETS}
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "license": "MIT",
        "generator": "test/fuzz/qbit_corpora/generate_seeds.py",
        "limits": LIMITS,
        "formats": {
            "fdp": "Untagged FuzzedDataProvider layout for targets without a tagged format.",
            "legacy": "Untagged pre-existing FuzzedDataProvider layout of pqc/p2mr_script, unchanged.",
            "qbfx-v1-fixture": "b'QBFX' + target tag ('P' pqc, 'M' p2mr_script) + 0x01 + selector whose low nibble "
                               "is not 0xF, then the FuzzedDataProvider layout of the cached-fixture body.",
            "qbfx-v1-generation": "b'QBFX' + target tag + 0x01 + selector whose low nibble is 0xF, then the legacy "
                                  "FuzzedDataProvider layout.",
            "raw": "The whole input is the data the target parses, without a FuzzedDataProvider layout.",
        },
        "targets": {
            target: [
                {
                    "file": c["name"],
                    "format": c["format"],
                    "size": len(c["data"]),
                    "sha256": hashlib.sha256(c["data"]).hexdigest(),
                    "semantics": c["semantics"],
                }
                for c in cases
            ]
            for target, cases in targets.items()
        },
    }
    check_generated(targets)
    return manifest, targets


def check_generated(targets: dict[str, list[dict]]) -> None:
    total = 0
    for target, cases in targets.items():
        names = [c["name"] for c in cases]
        if len(set(names)) != len(names) or not all(SEED_NAME_PATTERN.fullmatch(n) for n in names):
            raise SystemExit(f"{target}: seed names must be unique and match {SEED_NAME_PATTERN.pattern}")
        if not 1 <= len(cases) <= LIMITS["max_seeds_per_target"]:
            raise SystemExit(f"{target}: {len(cases)} seeds outside [1, {LIMITS['max_seeds_per_target']}]")
        target_bytes = 0
        for c in cases:
            if not 1 <= len(c["data"]) <= LIMITS["max_seed_bytes"]:
                raise SystemExit(f"{target}/{c['name']}: {len(c['data'])} bytes outside [1, {LIMITS['max_seed_bytes']}]")
            target_bytes += len(c["data"])
        if target_bytes > LIMITS["max_target_bytes"]:
            raise SystemExit(f"{target}: {target_bytes} bytes exceeds {LIMITS['max_target_bytes']}")
        total += target_bytes
    if total > LIMITS["max_total_bytes"]:
        raise SystemExit(f"total {total} bytes exceeds {LIMITS['max_total_bytes']}")


def manifest_text(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=False) + "\n"


def write(manifest: dict, targets: dict[str, list[dict]]) -> None:
    for target, cases in targets.items():
        target_dir = CORPORA_DIR / target
        target_dir.mkdir(exist_ok=True)
        expected = {c["name"] for c in cases}
        for stale in target_dir.iterdir():
            if stale.name not in expected:
                raise SystemExit(f"Refusing to leave unexpected entry {stale}; remove it manually.")
        for c in cases:
            (target_dir / c["name"]).write_bytes(c["data"])
    (CORPORA_DIR / MANIFEST_NAME).write_text(manifest_text(manifest), encoding="utf-8")


def check(manifest: dict, targets: dict[str, list[dict]]) -> list[str]:
    problems = []
    manifest_path = CORPORA_DIR / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.read_text(encoding="utf-8") != manifest_text(manifest):
        problems.append(f"{MANIFEST_NAME} differs from generated manifest")
    for target, cases in targets.items():
        target_dir = CORPORA_DIR / target
        present = {p.name for p in target_dir.iterdir()} if target_dir.is_dir() else set()
        expected = {c["name"] for c in cases}
        for extra in sorted(present - expected):
            problems.append(f"{target}/{extra}: not produced by the generator")
        for c in cases:
            path = target_dir / c["name"]
            if not path.is_file() or path.read_bytes() != c["data"]:
                problems.append(f"{target}/{c['name']}: missing or differs from generated bytes")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Verify committed seeds and manifest instead of writing them.")
    args = parser.parse_args()
    manifest, targets = build_all()
    if args.check:
        problems = check(manifest, targets)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    write(manifest, targets)
    return 0


if __name__ == "__main__":
    sys.exit(main())
