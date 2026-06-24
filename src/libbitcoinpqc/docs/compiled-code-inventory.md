# Compiled Code Inventory

This repo builds one static C library target, `bitcoinpqc`, through `CMakeLists.txt`.
The active signing profile is selected at compile time with:

- `PARAMS=sphincs-sha2-128s-bounded30`
- `CUSTOM_RANDOMBYTES=1`
- `SPX_PRODUCTION_BUILD=1` by default

Production mode pins the SHA hashblock backend selector to the scalar
implementation while ignoring runtime backend-selection environment variables.
The `SPX_ENABLE_TEST_BENCH_ENV_KNOBS` opt-in described below restores runtime
backend selection for test and benchmark builds only.

The Cargo crate delegates to the same CMake target from `build.rs`, links the
resulting static library, and generates Rust FFI bindings only for the
`bitcoin_pqc_*` API surface in `include/libbitcoinpqc/bitcoinpqc.h`.

For the broader public source release boundary, see
`docs/public-release-surface.md`.

## Compiled Library Surface

`BITCOINPQC_SOURCES` contributes the repo-owned API wrapper and SLH-DSA facade:

- `src/bitcoinpqc.c`
- `src/slh_dsa/utils.c`
- `src/slh_dsa/keygen.c`
- `src/slh_dsa/validate.c`
- `src/slh_dsa/sign.c`
- `src/slh_dsa/verify.c`

No other `.c` files are permitted directly under `src/slh_dsa/`. The CI guard
`scripts/check-source-inventory.sh` enforces this exact facade inventory so
stale or experimental integration files cannot be revived by broad source-tree
copies.

The repo-owned C sources use the private header-only secure zeroization helper
`src/secure_zero.h` for secret-bearing cleanup paths.

`SLH_DSA_SOURCES` contributes the SPHINCS+ reference implementation files used
by the bounded30 profile:

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

`CUSTOM_RANDOMBYTES` contributes:

- `sphincsplus/ref/randombytes_custom.c`

The installed public headers are:

- `include/libbitcoinpqc/bitcoinpqc.h`
- `include/libbitcoinpqc/sign_stats.h`
- `include/libbitcoinpqc/slh_dsa.h`

Those headers expose the bounded30 sizes currently pinned by tests:

- public key: 32 bytes
- secret key: 64 bytes
- signature: 3680 bytes

## Conditional Compiled Sources

On supported x86/x86_64 compiler targets, CMake also compiles this AVX2 x8
helper set with `-mavx2` and defines `SPX_AVX2=1`:

- `sphincsplus/sha2-avx2/hash_sha2x8.c`
- `sphincsplus/sha2-avx2/thash_sha2_simplex8.c`
- `sphincsplus/sha2-avx2/utilsx8.c`
- `sphincsplus/sha2-avx2/sha256x8.c`
- `sphincsplus/sha2-avx2/sha256avx.c`

On non-Apple AArch64 builds, `sphincsplus/ref/sha2_armv8_sha.c` is compiled
with `-march=armv8-a+crypto`. The source is still part of `SLH_DSA_SOURCES`;
the special compile option is platform-specific.

When `BITCOINPQC_ENABLE_TEST_HELPERS=ON` is set directly in CMake, or the Cargo
feature `test-helpers` is enabled, `src/test_helpers.c` is appended to
`BITCOINPQC_SOURCES` and `BITCOINPQC_ENABLE_TEST_HELPERS=1` is defined. This is
test-only support and is not part of the default library build.

When `SPX_ENABLE_TEST_BENCH_ENV_KNOBS=ON` is set directly in CMake, or the Cargo
feature `test-bench-env-knobs` is enabled, the C target defines
`SPX_ENABLE_TEST_BENCH_ENV_KNOBS=1` instead of `SPX_PRODUCTION_BUILD=1`. This is
test/benchmark-only support for backend experiments; production builds ignore
the runtime knobs documented in `docs/runtime-crypto-env.md`.

## Removed Non-Production Code

The public source tree intentionally excludes non-production crypto and binding
payload that is not reachable from the default C/Rust build:

- ML-DSA/Dilithium sources and wrappers
- SPHINCS+ Haraka and SHAKE implementation families
- unused SPHINCS+ parameter headers other than
  `params-sphincs-sha2-128s-bounded30.h`
- upstream standalone KAT, test, RNG, and Makefile entry points under the
  vendored SPHINCS+ snapshot
- standalone SHA2-AVX2 signer files other than the x8 helper files listed above
- Python and Node.js binding packages

This inventory is intentionally limited to this repository. It does not describe
downstream qbit subtree imports, wallet behavior, or downstream CI gates.
