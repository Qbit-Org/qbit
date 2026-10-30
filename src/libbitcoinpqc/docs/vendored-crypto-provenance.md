# Vendored Crypto Provenance

This document records what vendored crypto code is production-reachable in the
current C/Rust release surface and how future vendored crypto changes must be
handled. The compiled-file inventory in `docs/compiled-code-inventory.md`
remains the source of truth for the exact CMake target inputs.
For the broader public release boundary, see
`docs/public-release-surface.md`.

## Production-Reachable Files

The default CMake target `bitcoinpqc` compiles the repo-owned qbit wrapper and
SLH-DSA facade:

- `src/bitcoinpqc.c`
- `src/slh_dsa/utils.c`
- `src/slh_dsa/keygen.c`
- `src/slh_dsa/validate.c`
- `src/slh_dsa/sign.c`
- `src/slh_dsa/verify.c`

No additional `.c` files are permitted directly under `src/slh_dsa/` unless
they are intentionally added to the compiled source inventory and CI guard.

It compiles these SPHINCS+ reference files for
`sphincs-sha2-128s-bounded30`:

- `sphincsplus/ref/address.c`
- `sphincsplus/ref/fors.c`
- `sphincsplus/ref/hash_sha2.c`
- `sphincsplus/ref/merkle.c`
- `sphincsplus/ref/sha2.c`
- `sphincsplus/ref/sha2_armv8_sha.c`
- `sphincsplus/ref/sha2_x86_shani.c`
- `sphincsplus/ref/sign.c`
- `sphincsplus/ref/sign_stats.c`
- `sphincsplus/ref/thash_sha2_simple.c`
- `sphincsplus/ref/utils.c`
- `sphincsplus/ref/utilsx1.c`
- `sphincsplus/ref/wots.c`
- `sphincsplus/ref/wotsx1.c`

It also compiles the custom entropy adapter:

- `sphincsplus/ref/randombytes_custom.c`

On supported x86 or x86_64 GNU/Clang/AppleClang builds, CMake additionally
compiles these SHA2 AVX2 helper files with `-mavx2`:

- `sphincsplus/sha2-avx2/hash_sha2x8.c`
- `sphincsplus/sha2-avx2/thash_sha2_simplex8.c`
- `sphincsplus/sha2-avx2/utilsx8.c`
- `sphincsplus/sha2-avx2/sha256x8.c`
- `sphincsplus/sha2-avx2/sha256avx.c`

When `BITCOINPQC_ENABLE_TEST_HELPERS=ON` or the Cargo `test-helpers` feature is
enabled, `src/test_helpers.c` is compiled. That file is test-only and is not
part of the default production build.

## Reduced Vendored Snapshot

The public source tree removes vendored crypto payload that is not reachable from
the default C/Rust production target:

- unused SPHINCS+ parameter families other than
  `params-sphincs-sha2-128s-bounded30.h`
- SPHINCS+ Haraka and SHAKE implementations
- standalone SHA2-AVX2 signer files other than the five helper files listed
  above
- upstream SPHINCS+ standalone KAT, test, RNG, workflow, and Makefile entry
  points
- Dilithium/ML-DSA sources and wrappers

Do not restore removed vendored crypto payload unless the PR also updates
`CMakeLists.txt`, `docs/compiled-code-inventory.md`, this document, and release
evidence for the new intended surface.

## Upstream Provenance Status

SPHINCS+:

- Upstream project: `https://github.com/sphincs/sphincsplus`
- Local path: `sphincsplus/`
- Local metadata present: `sphincsplus/README.md`, `sphincsplus/LICENSE`, and
  `sphincsplus/LICENSES/`
- Exact upstream commit or tag: unknown in the current repository metadata;
  accepted for the `0.3.0` public release because the release ships the reduced
  vendored snapshot with local history, license metadata, and compiled-file
  inventory evidence.

The repo history shows the vendored SPHINCS+ tree present in the initial
repository commit, but that is not a substitute for an exact upstream baseline.
Before any future vendored SPHINCS+ update, recover or reconstruct the upstream
commit/tag baseline and record the local diff summary in this document.

## Local Modification Categories

Local changes are security-sensitive and should be reviewed by category:

- bounded30 parameter profile: `sphincs-sha2-128s-bounded30`, public size
  constants, and the `PARAMS=sphincs-sha2-128s-bounded30` CMake selection,
- WOTS+C: counter-search signing behavior, checksum target handling, and
  invariant/test helper exposure,
- FORS+C: compressed tree handling, salt grinding, verification rejection, and
  `SPX_FORS_SIG_TREES` behavior,
- SHA backend selection: scalar SHA2, ARM SHA acceleration, x86 SHA-NI, and the
  conditionally compiled SHA2 AVX2 x8 helpers,
- randombytes integration: user-provided entropy plumbing through
  `sphincsplus/ref/randombytes_custom.c` and `src/slh_dsa/utils.c`, including
  fail-closed abort behavior when the upstream void-returning hook is invoked
  without configured randomness and OS entropy cannot be read,
- qbit wrapper API: single-profile `bitcoin_pqc_*` C API and Rust wrapper
  surface,
- portability and sanitizer hardening: unsigned-overflow handling, integer
  conversion cleanup, unaligned vector access handling, and Windows-safe
  vendored tree adjustments.
- secret-key scratch zeroization: wiping SK_SEED and SK_PRF copies and the
  SHA-2 scratch derived from them before keygen, signing and PRF helpers
  return, and burning FORS worker thread stacks.

## Vendored Changes In 0.3.1

`0.3.1` changes these vendored SPHINCS+ files so that secret-key scratch does
not outlive keygen and signing calls. Keys, signatures and verification
results are unchanged, and the golden vectors pass unmodified.

- `sphincsplus/ref/sign.c`: `crypto_sign_seed_keypair` and
  `crypto_sign_signature` return through one cleanup path that zeroes the
  stack `spx_ctx` (an exact SK_SEED copy) and `optrand`; WOTS+C counter
  exhaustion also resets `*siglen` (#5).
- `sphincsplus/ref/hash_sha2.c`: `prf_addr` and `gen_message_random` zero
  their SK_SEED and SK_PRF-keyed scratch before returning (#5).
- `sphincsplus/ref/sha2.c`: `sha256_inc_finalize` and `sha512_inc_finalize`
  zero their padding buffers, and `sha256()` and `sha512()` zero their local
  state (#5, with #6 removing the per-block stack burn #5 had added).
- `sphincsplus/ref/fors.c`: each FORS worker thread burns its own stack
  before returning, because the burn on the calling thread cannot reach it.
  Worker threads run only when the test/benchmark knob `SPX_FORS_THREADS`
  is enabled (#6).
- `sphincsplus/sha2-avx2/hash_sha2x8.c`: `prf_addrx8` zeroes its eight
  SK_SEED copies and PRF outputs (#5).
- `sphincsplus/sha2-avx2/sha256avx.c`: `transpose` and `sha256_transform8x`
  zero their temporaries, message schedule and working state (#5).
- `sphincsplus/sha2-avx2/sha256x8.c`: `sha256x8_seeded` zeroes its context
  (#5).
- The `secure_zero_local` helpers in `sign.c`, `hash_sha2.c` and
  `hash_sha2x8.c` count down without wrapping `len` past zero, so
  `-fsanitize=unsigned-integer-overflow` builds do not trap (#14).

The stack burn, `bitcoin_pqc_burn_stack()` in `src/secure_zero.h`, is
repo-owned. It runs when `slh_dsa_keygen()`, `slh_dsa_sign_with_stats()`
(and so `slh_dsa_sign()`), `slh_dsa_secret_key_validate()` and
`slh_dsa_derandomize()` return (#6).

## Patch Policy

- No silent vendored crypto updates.
- Every vendored crypto update must include an upstream source reference and a
  local diff summary.
- Active crypto semantic changes require KAT or invariant test updates.
- Active parsing or verification changes require fuzz smoke evidence.
- Release notes must identify vendored crypto changes.
- Any newly production-reachable vendored file must be added to
  `docs/compiled-code-inventory.md` and this document in the same PR.
- Any new repo-owned C facade file must update `scripts/check-source-inventory.sh`
  in the same PR.
