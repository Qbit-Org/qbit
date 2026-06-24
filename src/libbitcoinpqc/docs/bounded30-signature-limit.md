# Bounded30 Signature Limit

This library is built for `sphincs-sha2-128s-bounded30` only. The active
parameter file is `sphincsplus/ref/params/params-sphincs-sha2-128s-bounded30.h`,
selected by the CMake definition `PARAMS=sphincs-sha2-128s-bounded30`.

The profile sets:

- `SPX_N = 16`
- `SPX_FULL_HEIGHT = 30`
- `SPX_D = 5`
- `SPX_FORS_HEIGHT = 16`
- `SPX_FORS_TREES = 8`
- `SPX_WOTS_W = 256`

The public API exposes the resulting fixed object sizes:

- public key: 32 bytes
- secret key: 64 bytes
- signature: 3680 bytes

The `bounded30` name and `SPX_FULL_HEIGHT = 30` mean the profile has `2^30`
hypertree leaves. The library's signing profile assumes callers do not exceed
the corresponding per-key usage bound. That bound is part of the cryptographic
usage contract for this stateless library profile.

## Library Responsibility

This repository enforces and tests the bounded30 profile selection and object
sizes. It also keeps key generation deterministic from caller-provided entropy
and signing deterministic from the secret key and message:

- `slh_dsa_keygen()` calls `crypto_sign_seed_keypair()`.
- `slh_dsa_sign()` derives signing randomness from `(secret key || message)`.
- Signing fails closed with `BITCOIN_PQC_ERROR_SIGNING_LIMIT` if the
  compile-time FORS+C or WOTS+C signing attempt cap is exceeded.
- `bitcoin_pqc_verify()` rejects signatures whose byte length is not exactly
  3680 before entering the SPHINCS+ verifier.

The default signing caps are:

- FORS+C salt grinding: 1,835,008 attempts (`28 * 65,536`).
- WOTS+C counter search: counter values 0 through 65,535.

The FORS+C default targets the profile's `1 / 2^16` per-attempt success
condition. A cap of `28 * 2^16` attempts leaves an approximate signing failure
probability of `(1 - 2^-16)^(28 * 2^16)`, or about `e^-28 ~= 2^-40.4`.

Release builds can override these at compile time with the CMake cache variables
or Cargo build environment variables `BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS` and
`BITCOINPQC_WOTSC_MAX_COUNTER`.

Verification is not given a reduced local policy cap; it uses the full WOTS+C
two-byte counter range needed by the bounded30 profile.

The Rust tests in `tests/golden_vector_tests.rs` and
`tests/bounded_mode_correctness_tests.rs` pin deterministic vectors, valid
verification, wrong-message rejection, wrong-key rejection, bit-flipped
signature rejection, truncated signature rejection, and oversized signature
rejection.

## What This Library Does Not Track

This repository does not persist per-key signing state, count signatures, reserve
hypertree leaves, or enforce a global `2^30` signing ceiling for a key across
processes. The C and Rust APIs are stateless with respect to signature counts.

Any stateful policy for key rotation, persisted counters, per-wallet usage
limits, or cross-process enforcement is outside this repository's responsibility.
This note intentionally makes no claims about downstream qbit behavior.
