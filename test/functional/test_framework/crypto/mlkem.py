#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only implementation of ML-KEM-1024 (FIPS 203).

It is written from the FIPS 203 text, independently of the C library the node
uses, so the node's implementation can be checked against a second one. It uses
only Python's built-in hashlib for SHA3 and SHAKE, and imports nothing from the
C++ build.

Interface (all byte strings):
    mlkem1024_keygen(seed)     -> (ek, dk)  seed = d || z, 64 bytes
    mlkem1024_encaps(ek, m)    -> (ss, ct)  m is 32 bytes
    mlkem1024_decaps(dk, ct)   -> ss        implicit rejection on a bad ct
    mlkem1024_check_ek(ek)     -> bool      FIPS 203 section 7.2 input check

The functions are the deterministic ML-KEM.KeyGen_internal and
ML-KEM.Encaps_internal plus the FIPS 203 section 7.2 and 7.3 input checks;
callers supply the randomness (for example os.urandom). Inputs that fail a
check raise ValueError.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do not use for
anything but tests.
"""

import hashlib
import os
import unittest

# ML-KEM-1024 parameters (FIPS 203 section 8, table 2).
N = 256
Q = 3329
K = 4
ETA1 = 2
ETA2 = 2
DU = 11
DV = 5

EK_SIZE = 384 * K + 32                # 1568
DK_SIZE = 768 * K + 96                # 3168
CT_SIZE = 32 * (DU * K + DV)          # 1568
SS_SIZE = 32
SEED_SIZE = 64                        # d || z
MSG_SIZE = 32


def _bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


# zeta^BitRev7(i) and zeta^(2*BitRev7(i)+1) with zeta = 17 (FIPS 203 appendix A).
ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def _h(s):
    return hashlib.sha3_256(s).digest()


def _j(s):
    return hashlib.shake_256(s).digest(32)


def _g(c):
    out = hashlib.sha3_512(c).digest()
    return out[:32], out[32:]


def _prf(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def byte_encode(f, d):
    """ByteEncode_d (FIPS 203 algorithm 5): pack 256 d-bit integers, least significant bit first."""
    value = 0
    for i, a in enumerate(f):
        value |= a << (i * d)
    return value.to_bytes(32 * d, "little")


def byte_decode_raw(b, d):
    """ByteDecode_d without the final reduction mod q (used by the modulus check)."""
    assert len(b) == 32 * d
    value = int.from_bytes(b, "little")
    mask = (1 << d) - 1
    return [(value >> (i * d)) & mask for i in range(N)]


def byte_decode(b, d):
    """ByteDecode_d (FIPS 203 algorithm 6)."""
    f = byte_decode_raw(b, d)
    if d == 12:
        f = [a % Q for a in f]
    return f


def compress(f, d):
    """Compress_d: round(2^d / q * x) mod 2^d, rounding halves up."""
    return [(((x << (d + 1)) + Q) // (2 * Q)) & ((1 << d) - 1) for x in f]


def decompress(f, d):
    """Decompress_d: round(q / 2^d * y), rounding halves up."""
    return [(Q * y + (1 << (d - 1))) >> d for y in f]


def ntt(f):
    """NTT (FIPS 203 algorithm 9)."""
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def ntt_inv(f):
    """NTT^-1 (FIPS 203 algorithm 10)."""
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def multiply_ntts(f, g):
    """MultiplyNTTs (FIPS 203 algorithms 11 and 12)."""
    h = [0] * N
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _poly_add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def _poly_sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def sample_ntt(seed34):
    """SampleNTT (FIPS 203 algorithm 7): rejection-sample a polynomial from SHAKE128(seed34)."""
    assert len(seed34) == 34
    # hashlib has no incremental squeeze, but SHAKE output is prefix-stable, so
    # ask for a longer stream if the first one runs out.
    stream_len = 168 * 4
    while True:
        stream = hashlib.shake_128(seed34).digest(stream_len)
        a = []
        pos = 0
        while len(a) < N and pos + 3 <= stream_len:
            c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
            pos += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = c1 // 16 + 16 * c2
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < N:
                a.append(d2)
        if len(a) == N:
            return a
        stream_len *= 2


def sample_poly_cbd(b, eta):
    """SamplePolyCBD_eta (FIPS 203 algorithm 8)."""
    assert len(b) == 64 * eta
    bits = int.from_bytes(b, "little")
    f = []
    for i in range(N):
        x = sum((bits >> (2 * i * eta + j)) & 1 for j in range(eta))
        y = sum((bits >> (2 * i * eta + eta + j)) & 1 for j in range(eta))
        f.append((x - y) % Q)
    return f


def _sample_matrix(rho):
    """A_hat[i][j] = SampleNTT(rho || j || i)."""
    return [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def kpke_keygen(d):
    """K-PKE.KeyGen (FIPS 203 algorithm 13)."""
    rho, sigma = _g(d + bytes([K]))
    a_hat = _sample_matrix(rho)
    s = [sample_poly_cbd(_prf(ETA1, sigma, i), ETA1) for i in range(K)]
    e = [sample_poly_cbd(_prf(ETA1, sigma, K + i), ETA1) for i in range(K)]
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = []
    for i in range(K):
        acc = e_hat[i]
        for j in range(K):
            acc = _poly_add(acc, multiply_ntts(a_hat[i][j], s_hat[j]))
        t_hat.append(acc)
    ek_pke = b"".join(byte_encode(p, 12) for p in t_hat) + rho
    dk_pke = b"".join(byte_encode(p, 12) for p in s_hat)
    return ek_pke, dk_pke


def kpke_encrypt(ek_pke, m, r):
    """K-PKE.Encrypt (FIPS 203 algorithm 14)."""
    t_hat = [byte_decode(ek_pke[384 * i:384 * (i + 1)], 12) for i in range(K)]
    rho = ek_pke[384 * K:384 * K + 32]
    a_hat = _sample_matrix(rho)
    y = [sample_poly_cbd(_prf(ETA1, r, i), ETA1) for i in range(K)]
    e1 = [sample_poly_cbd(_prf(ETA2, r, K + i), ETA2) for i in range(K)]
    e2 = sample_poly_cbd(_prf(ETA2, r, 2 * K), ETA2)
    y_hat = [ntt(p) for p in y]
    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, multiply_ntts(a_hat[j][i], y_hat[j]))
        u.append(_poly_add(ntt_inv(acc), e1[i]))
    mu = decompress(byte_decode(m, 1), 1)
    acc = [0] * N
    for j in range(K):
        acc = _poly_add(acc, multiply_ntts(t_hat[j], y_hat[j]))
    v = _poly_add(_poly_add(ntt_inv(acc), e2), mu)
    c1 = b"".join(byte_encode(compress(p, DU), DU) for p in u)
    c2 = byte_encode(compress(v, DV), DV)
    return c1 + c2


def kpke_decrypt(dk_pke, c):
    """K-PKE.Decrypt (FIPS 203 algorithm 15)."""
    c1 = c[:32 * DU * K]
    c2 = c[32 * DU * K:]
    u = [decompress(byte_decode(c1[32 * DU * i:32 * DU * (i + 1)], DU), DU) for i in range(K)]
    v = decompress(byte_decode(c2, DV), DV)
    s_hat = [byte_decode(dk_pke[384 * i:384 * (i + 1)], 12) for i in range(K)]
    acc = [0] * N
    for i in range(K):
        acc = _poly_add(acc, multiply_ntts(s_hat[i], ntt(u[i])))
    w = _poly_sub(v, ntt_inv(acc))
    return byte_encode(compress(w, 1), 1)


def _check_bytes(name, value, size):
    if not isinstance(value, (bytes, bytearray)) or len(value) != size:
        raise ValueError(f"{name} must be {size} bytes")
    return bytes(value)


def mlkem1024_check_ek(ek):
    """FIPS 203 section 7.2 encapsulation-key check: the type (length) check and the modulus check.

    The modulus check requires every 12-bit coefficient of the encoded t_hat to be below q, which
    is the same as ByteEncode12(ByteDecode12(ek[0:1536])) == ek[0:1536].
    """
    if not isinstance(ek, (bytes, bytearray)) or len(ek) != EK_SIZE:
        return False
    return all(a < Q for i in range(K) for a in byte_decode_raw(bytes(ek[384 * i:384 * (i + 1)]), 12))


def mlkem1024_keygen(seed):
    """ML-KEM.KeyGen_internal (FIPS 203 algorithm 16) from seed = d || z. Returns (ek, dk)."""
    seed = _check_bytes("seed", seed, SEED_SIZE)
    d, z = seed[:32], seed[32:]
    ek_pke, dk_pke = kpke_keygen(d)
    ek = ek_pke
    dk = dk_pke + ek + _h(ek) + z
    return ek, dk


def mlkem1024_encaps(ek, m):
    """ML-KEM.Encaps_internal (FIPS 203 algorithm 17) after the section 7.2 checks. Returns (ss, ct)."""
    ek = _check_bytes("ek", ek, EK_SIZE)
    m = _check_bytes("m", m, MSG_SIZE)
    if not mlkem1024_check_ek(ek):
        raise ValueError("ek fails the modulus check")
    ss, r = _g(m + _h(ek))
    ct = kpke_encrypt(ek, m, r)
    return ss, ct


def mlkem1024_decaps(dk, ct):
    """ML-KEM.Decaps_internal (FIPS 203 algorithm 18) after the section 7.3 checks. Returns ss.

    A ciphertext of the right length that does not re-encrypt to itself yields the implicit
    rejection secret J(z || ct), as the standard requires.
    """
    dk = _check_bytes("dk", dk, DK_SIZE)
    ct = _check_bytes("ct", ct, CT_SIZE)
    dk_pke = dk[:384 * K]
    ek_pke = dk[384 * K:768 * K + 32]
    h = dk[768 * K + 32:768 * K + 64]
    z = dk[768 * K + 64:]
    if _h(ek_pke) != h:
        raise ValueError("dk fails the hash check")
    m_prime = kpke_decrypt(dk_pke, ct)
    ss_prime, r_prime = _g(m_prime + h)
    ss_reject = _j(z + ct)
    ct_prime = kpke_encrypt(ek_pke, m_prime, r_prime)
    if ct != ct_prime:
        return ss_reject
    return ss_prime


def _read_test_vectors():
    """Parse mlkem1024_test_vectors.txt into {kind: [fields]} (see that file's header)."""
    vectors_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "mlkem1024_test_vectors.txt")
    vectors = {}
    with open(vectors_file, encoding="utf8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            kind, *fields = line.split()
            vectors.setdefault(kind, []).append(dict(field.split("=", 1) for field in fields))
    return vectors


class TestMLKEM1024(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = _read_test_vectors()

    def test_ntt_roundtrip(self):
        f = [(i * 1009 + 7) % Q for i in range(N)]
        self.assertEqual(ntt_inv(ntt(f)), f)

    def test_acvp_keygen(self):
        """ACVP keyGen: exact ek and dk from d || z."""
        self.assertTrue(self.vectors["keyGen"])
        for v in self.vectors["keyGen"]:
            ek, dk = mlkem1024_keygen(bytes.fromhex(v["d"] + v["z"]))
            self.assertEqual((len(ek), len(dk)), (EK_SIZE, DK_SIZE))
            self.assertEqual(ek.hex(), v["ek"], f"tcId {v['tcId']}")
            self.assertEqual(dk.hex(), v["dk"], f"tcId {v['tcId']}")

    def test_acvp_encaps(self):
        """ACVP encapsulation: exact ct and shared secret from ek and m."""
        self.assertTrue(self.vectors["encapsulation"])
        for v in self.vectors["encapsulation"]:
            ek = bytes.fromhex(v["ek"])
            self.assertTrue(mlkem1024_check_ek(ek))
            ss, ct = mlkem1024_encaps(ek, bytes.fromhex(v["m"]))
            self.assertEqual((len(ss), len(ct)), (SS_SIZE, CT_SIZE))
            self.assertEqual(ct.hex(), v["c"], f"tcId {v['tcId']}")
            self.assertEqual(ss.hex(), v["k"], f"tcId {v['tcId']}")

    def test_acvp_decaps(self):
        """ACVP decapsulation, including modified ciphertexts that need the implicit-rejection secret."""
        reasons = set()
        for v in self.vectors["decapsulation"]:
            dk, ct = bytes.fromhex(v["dk"]), bytes.fromhex(v["c"])
            ss = mlkem1024_decaps(dk, ct)
            self.assertEqual(ss.hex(), v["k"], f"tcId {v['tcId']}")
            if v["reason"] == "modified_ciphertext":
                # The rejection secret is J(z || ct), with z the last 32 bytes of dk.
                self.assertEqual(ss, hashlib.shake_256(dk[-32:] + ct).digest(32))
            reasons.add(v["reason"])
        self.assertEqual(reasons, {"modified_ciphertext", "valid_decapsulation"})

    def test_acvp_encapsulation_key_check(self):
        """ACVP encapsulationKeyCheck: valid keys pass the section 7.2 check and encapsulate; the others are rejected."""
        vectors = self.vectors["encapsulationKeyCheck"]
        self.assertEqual({v["passed"] for v in vectors}, {"0", "1"})
        for v in vectors:
            ek = bytes.fromhex(v["ek"])
            passed = v["passed"] == "1"
            self.assertEqual(mlkem1024_check_ek(ek), passed, f"tcId {v['tcId']}")
            if passed:
                ss, ct = mlkem1024_encaps(ek, bytes(MSG_SIZE))
                self.assertEqual((len(ss), len(ct)), (SS_SIZE, CT_SIZE))
            else:
                with self.assertRaises(ValueError):
                    mlkem1024_encaps(ek, bytes(MSG_SIZE))

    def test_cctv_modulus(self):
        """C2SP CCTV keys with one coefficient in [q, 4095] fail the modulus check; q - 1 there passes."""
        base = None
        for v in self.vectors["modulus"]:
            if "ek" in v:
                ek = bytes.fromhex(v["ek"])
                base = ek
            else:
                ek = bytearray(base)
                for patch in v["patch"].split(","):
                    offset, data = patch.split(":")
                    ek[int(offset):int(offset) + len(data) // 2] = bytes.fromhex(data)
                ek = bytes(ek)
            self.assertEqual(hashlib.sha256(ek).hexdigest(), v["sha256"], f"line {v['line']}")
            self.assertEqual(len(ek), EK_SIZE)
            self.assertFalse(mlkem1024_check_ek(ek), f"line {v['line']}")
            with self.assertRaises(ValueError):
                mlkem1024_encaps(ek, bytes(MSG_SIZE))
            # Each key has exactly one coefficient >= q. Setting it to q - 1 = 3328, the largest
            # valid value, must make the key pass.
            polys = [byte_decode_raw(ek[384 * i:384 * (i + 1)], 12) for i in range(K)]
            bad = [(i, j) for i in range(K) for j in range(N) if polys[i][j] >= Q]
            self.assertEqual(len(bad), 1, f"line {v['line']}")
            i, j = bad[0]
            polys[i][j] = Q - 1
            fixed = b"".join(byte_encode(p, 12) for p in polys) + ek[384 * K:]
            self.assertTrue(mlkem1024_check_ek(fixed), f"line {v['line']}")
        self.assertEqual(len(self.vectors["modulus"]), 32)
        # A key at the boundary is usable, not only accepted by the check.
        ss, ct = mlkem1024_encaps(fixed, bytes(MSG_SIZE))
        self.assertEqual((len(ss), len(ct)), (SS_SIZE, CT_SIZE))

    def test_roundtrip_and_implicit_rejection(self):
        ek, dk = mlkem1024_keygen(bytes(range(SEED_SIZE)))
        ss, ct = mlkem1024_encaps(ek, bytes(range(100, 100 + MSG_SIZE)))
        self.assertEqual(mlkem1024_decaps(dk, ct), ss)
        for pos in (0, CT_SIZE - 1):
            bad_ct = bytearray(ct)
            bad_ct[pos] ^= 0x01
            bad_ct = bytes(bad_ct)
            ss_bad = mlkem1024_decaps(dk, bad_ct)
            self.assertNotEqual(ss_bad, ss)
            self.assertEqual(ss_bad, hashlib.shake_256(dk[-32:] + bad_ct).digest(32))

    def test_input_checks(self):
        ek, dk = mlkem1024_keygen(bytes(SEED_SIZE))
        _, ct = mlkem1024_encaps(ek, bytes(MSG_SIZE))
        for size in (0, SEED_SIZE - 1, SEED_SIZE + 1):
            with self.assertRaises(ValueError):
                mlkem1024_keygen(bytes(size))
        for bad_ek in (b"", ek[:-1], ek + b"\x00"):
            self.assertFalse(mlkem1024_check_ek(bad_ek))
            with self.assertRaises(ValueError):
                mlkem1024_encaps(bad_ek, bytes(MSG_SIZE))
        for bad_m in (b"", bytes(MSG_SIZE - 1), bytes(MSG_SIZE + 1)):
            with self.assertRaises(ValueError):
                mlkem1024_encaps(ek, bad_m)
        for bad_ct in (b"", ct[:-1], ct + b"\x00"):
            with self.assertRaises(ValueError):
                mlkem1024_decaps(dk, bad_ct)
        for bad_dk in (b"", dk[:-1], dk + b"\x00"):
            with self.assertRaises(ValueError):
                mlkem1024_decaps(bad_dk, ct)
        # FIPS 203 section 7.3 hash check: H(ek) stored in dk must match the embedded ek.
        bad_dk = bytearray(dk)
        bad_dk[768 * K + 32] ^= 0x01
        with self.assertRaises(ValueError):
            mlkem1024_decaps(bytes(bad_dk), ct)
        with self.assertRaises(ValueError):
            mlkem1024_encaps(list(ek), bytes(MSG_SIZE))
