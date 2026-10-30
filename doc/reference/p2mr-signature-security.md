# P2MR Signature Security Margin

This note is non-normative. It explains how the security margin of qbit's
P2MR v1 signature profile, `SLH-DSA-SHA2-128s-bounded30`, depends on how many
signatures each key produces. The consensus rules are in the
[qbit P2MR v1 Consensus Profile](../consensus/p2mr-v1.md). Nothing here changes
which signatures or transactions are valid.

## Summary

- A key keeps the profile's full 128-bit classical security level up to about
  `2^26` (67,108,864) signatures. The model's exact crossover is about
  `2^26.6` (about 104 million); `2^26` is the rounded-down planning figure.
- At the `2^30` (1,073,741,824) signature limit, the margin is about 118 bits
  classical.
- Rotate keys that sign at high volume well before `2^30`. To keep a 128-bit
  margin, move to a fresh key by about `2^26` signatures.
- qbit wallets count signatures for the keys they hold. Keys passed directly to
  `signrawtransactionwithkey` or `descriptorprocesspsbt` are not counted across
  calls, so the caller is responsible for the limit.

## Parameters

| Parameter | Value |
|---|---|
| Hash output `n` | 16 bytes |
| Hypertree height `h` | 30, so `2^30` leaves |
| Hypertree layers `d` | 5 |
| FORS trees `k` | 8, using FORS+C: 7 trees are signed and 1 is compressed |
| FORS tree height `a` | 16 |
| Winternitz parameter `w` | 256, using WOTS+C |

The parameters are set in
`src/libbitcoinpqc/sphincsplus/ref/params/params-sphincs-sha2-128s-bounded30.h`.
FORS+C and WOTS+C are the compression techniques from SPHINCS+C (see
[References](#references)).

## Single-use bound: 128 bits, not 112

FORS+C leaves the eighth FORS tree out of the signature. To make that safe, the
signer re-randomizes `R` until the eighth tree's 16-bit index in the message
digest is 0. `crypto_sign_verify` in `src/libbitcoinpqc/sphincsplus/ref/sign.c`
rejects any digest whose compressed index is not 0.

A forger must therefore meet that `2^-16` condition as well as match the 7
signed trees. The single-use bound is `k * a = 8 * 16 = 128` bits, not
`7 * 16 = 112` bits.

## Usage-Dependent Bound

Each signature picks its hypertree leaf from `H_msg(R, PK, M)`, uniformly among
the `2^30` leaves. Signatures that land on the same leaf use the same FORS key,
and each one reveals one secret leaf in every signed FORS tree. A forger who
finds a digest whose indices were all revealed earlier at its leaf can forge.

This note uses the standard SPHINCS+ estimate for that generic attack. After `q`
signatures by one key, a single `H_msg` query forges with probability:

```text
eps(q) = sum over r >= 1 of
         Poisson(r; q / 2^30) * 2^-16 * (1 - (1 - 2^-16)^r)^7
```

- `Poisson(r; q / 2^30)` is the probability that `r` earlier signatures used
  the forger's leaf. It approximates `Binomial(q, 2^-30)`, and for these
  parameters the two agree to within 0.001 bits.
- `2^-16` is the FORS+C condition that the compressed index is 0.
- `(1 - (1 - 2^-16)^r)^7` is the probability that each of the 7 signed indices
  was already revealed by one of the `r` signatures.

Classical security in bits is `-log2(eps(q))`. The bound is per key. `H_msg`
takes the public key as input, so each query attacks only one key.

The 16-byte hash output limits generic attacks on the scheme's other parts to
about 128 bits classical, whatever the usage. The overall level is therefore
about the smaller of 128 bits and the figure from this model.

### Script

The following Python 3 script reproduces the figures. It uses only the standard
library.

```python
#!/usr/bin/env python3
"""Generic FORS forgery bound for SLH-DSA-SHA2-128s-bounded30 (FORS+C)."""
import math

def bits(log2_q, h, k_signed, a, forced_zero_trees):
    lam = 2.0 ** (log2_q - h)       # expected signatures per hypertree leaf
    p_leaf = 2.0 ** -a              # chance one signature reveals a given FORS leaf
    eps = 0.0
    for r in range(1, 400):         # r = earlier signatures at the forger's leaf
        log_pois = -lam + r * math.log(lam) - math.lgamma(r + 1)
        covered = 1.0 - (1.0 - p_leaf) ** r
        eps += math.exp(log_pois) * covered ** k_signed
    eps *= p_leaf ** forced_zero_trees  # FORS+C: compressed index must be 0
    return -math.log2(eps)

def bounded30(log2_q):
    return bits(log2_q, h=30, k_signed=7, a=16, forced_zero_trees=1)

print("SLH-DSA-SHA2-128s-bounded30 (h=30, a=16, k=8 with FORS+C)")
print("signatures per key   classical bits")
for log2_q in (20, 25, 26, 27, 28, 29, 30, 31, 32):
    print(f"2^{log2_q:<18} {bounded30(log2_q):6.1f}")
lo, hi = 20.0, 30.0
while hi - lo > 1e-6:
    mid = (lo + hi) / 2
    lo, hi = (mid, hi) if bounded30(mid) > 128 else (lo, mid)
print(f"128-bit crossover    2^{lo:.2f} signatures")
print("Reference: SPHINCS+-128s (h=63, a=12, k=14) at 2^64 signatures:",
      f"{bits(64, h=63, k_signed=14, a=12, forced_zero_trees=0):.1f} bits")
```

Output:

```text
SLH-DSA-SHA2-128s-bounded30 (h=30, a=16, k=8 with FORS+C)
signatures per key   classical bits
2^20                  137.9
2^25                  131.3
2^26                  129.4
2^27                  127.2
2^28                  124.6
2^29                  121.7
2^30                  118.2
2^31                  114.2
2^32                  109.6
128-bit crossover    2^26.64 signatures
Reference: SPHINCS+-128s (h=63, a=12, k=14) at 2^64 signatures: 133.7 bits
```

### Results

| Signatures per key | Classical security from this model |
|---|---:|
| `2^20` (1,048,576) | about 137.9 bits |
| `2^25` (33,554,432) | about 131.3 bits |
| about `2^26.6` (about 104 million) | about 128 bits |
| `2^28` (268,435,456) | about 124.6 bits |
| `2^30` (1,073,741,824), the limit | about 118.2 bits |
| `2^31` | about 114.2 bits |
| `2^32` | about 109.6 bits |

Figures above 128 bits are the model's output. The 16-byte hash output still
caps the overall level at about 128 bits.

For comparison, the same model gives about 133.7 bits for standard
SPHINCS+-128s (`h = 63`, `k = 14`, `a = 12`) at its `2^64`-signature limit.

## Interpretation

- **The `128s` label holds for a single use.** One signature per leaf gives
  `k * a = 128` bits.
- **The full usage contract gives about 118 bits classical.** A key that signs
  all `2^30` permitted times ends near 118 bits.
- **Quantum figures are about half.** Under the usual Grover estimate for
  generic search, the quantum figures are roughly half as many bits. That is
  about 59 bits at `2^30` signatures, compared with about 64 bits at 128 bits
  classical.
- **Wallet warning states map onto this curve.** The wallet's `warning` state
  begins at `2^28` signatures, about 124.6 bits. Its `critical` state begins at
  `2^30 - 2^24` signatures, about 118.3 bits. See
  [PQC Signature Counters](../user/wallet/p2mr-wallets.md#pqc-signature-counters).
- **Ordinary use stays far from the limit.** A key that signs once per second
  for a year produces about `2^24.9` signatures, about 131 bits by this model.

### Shared leaves are expected

With `2^30` leaves, two signatures by the same key are likely to share a
`(tree, leaf)` pair after about `2^15` signatures. A 50% chance is reached at
about 38,600 signatures.

Signatures that share a leaf have an identical hypertree portion, because the
FORS public key at that leaf is the same. This is how SPHINCS+ is designed:
FORS is a few-time signature, and the bound above already counts the secret
leaves revealed by repeated use of a leaf. A shared leaf does not on its own
indicate a fault.

### Repeated digests

qbit derives the signing randomness from the secret key and the message.
Signing the same 32-byte digest again with the same key reproduces the same
signature and reveals nothing new. Wallet counters still count every signing
operation, so a counter is an upper bound on the number of distinct signatures.

## Who Enforces the `2^30` Limit

Consensus verifiers check only the public key, digest and signature. They do
not consult any usage counter. A signature made after a key has passed `2^30`
signatures still verifies. The limit is a usage contract that only signers can
enforce.

| Signing path | Signature counter |
|---|---|
| Wallet-held P2MR keys, for example `sendtoaddress`, `send`, `signrawtransactionwithwallet`, `walletprocesspsbt` and `signdatapqchash` | Persisted in the wallet database. Signing refuses a key once it reaches `2^30`. |
| `signrawtransactionwithkey` with `pqc(KEY)`, whether `KEY` is raw secret-key hex or an extended private key | Not tracked across calls. Each call starts from zero. |
| `descriptorprocesspsbt` with private descriptors | Not tracked across calls. Each call starts from zero. |
| The same key in another wallet, restored from an older backup, or exported with `listdescriptors true` | Each copy counts only its own signatures. |
| External signers (`-signer`) | Not tracked by qbit. External signer workflows are not yet validated for P2MR; see [External Signers](../user/wallet/p2mr-wallets.md#external-signers). |

When you sign outside a wallet that holds the key, keep your own per-key count.
Rotate to a fresh key well before `2^30`, and by about `2^26` to keep a 128-bit
margin.

## References

- SPHINCS+ submission to the NIST post-quantum project, version 3.1. It gives
  the FORS forgery estimate used in this note.
- A. Hülsing, M. Kudinov, E. Ronen and E. Yogev, "SPHINCS+C: Compressing
  SPHINCS+ With (Almost) No Cost", IEEE Symposium on Security and Privacy 2023.
  It defines FORS+C and WOTS+C.
- [`bounded30` signature-limit documentation](../../src/libbitcoinpqc/docs/bounded30-signature-limit.md)
  in the vendored library.
