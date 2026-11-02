# Runtime Crypto Environment Policy

Production builds of `qbit-libbitcoinpqc` ignore runtime environment variables
that select SPHINCS+ crypto backends, SIMD paths, SHA acceleration paths, or FORS
worker counts. Consensus-reachable keygen, sign, and verify behavior must not
depend on process environment.

## Production Builds

The CMake library target defines `SPX_PRODUCTION_BUILD=1` by default. Rust builds
use the same CMake target through `build.rs`, so normal `cargo build`,
`cargo test`, and `cargo bench` builds are production-mode builds unless the
test/benchmark feature below is explicitly enabled.

Production mode pins SHA hashblock backend selection to the scalar
implementation. It still compiles out the runtime selection knobs below, so
process environment cannot switch production builds to `auto`, ARM SHA, x86
SHA-NI, or CommonCrypto backend modes.

In production mode, these runtime environment variables are ignored:

| Variable | Production status | Test/benchmark opt-in behavior |
|---|---|---|
| `SPX_DISABLE_SHA_ACCEL` | Ignored | Disables SHA acceleration when env knobs are explicitly enabled. |
| `SPX_DISABLE_SIMD` | Ignored | Disables SIMD/AVX2 dispatch when env knobs are explicitly enabled. |
| `SPX_OPT_PROFILE` | Ignored | `scalar` selects scalar SHA/SIMD behavior when env knobs are explicitly enabled. |
| `SPX_SHA_BACKEND` | Ignored | Selects `auto`, `scalar`, `arm`, `x86`, or `commoncrypto` when env knobs are explicitly enabled and the backend is compiled/available. |
| `SPX_FORS_THREADS` | Ignored | Selects the FORS signing worker count when env knobs are explicitly enabled; the count is capped by the compiled FORS tree count. |

## Test And Benchmark Opt-In

Backend experimentation is test/benchmark-only and must be enabled explicitly:

```bash
cmake -S . -B build \
  -DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=ON \
  -DBITCOINPQC_ENABLE_TEST_HELPERS=ON
cargo test --features test-bench-env-knobs,test-helpers \
  --test backend_differential_tests -- --nocapture
cargo bench --features test-bench-env-knobs
ENABLE_TEST_BENCH_ENV_KNOBS=1 ./scripts/x86_bench_5x.sh
```

`SPX_PRODUCTION_BUILD` and `SPX_ENABLE_TEST_BENCH_ENV_KNOBS` are mutually
exclusive. The source fails compilation if both macros are defined.

The differential test requires two independent Cargo features:

- `test-bench-env-knobs` permits a child process to request a backend through
  `SPX_SHA_BACKEND`.
- `test-helpers` adds private test-only observers that report the SHA-256 and
  SHA-512 implementations actually cached by the dispatchers.

A requested backend and an effective backend are not the same assertion. A
request for `x86`, for example, may safely fall back to scalar when the compiler
or CPU cannot supply the accelerated implementation. Differential output
therefore reports both requested and effective implementations. CommonCrypto
counts as accelerated coverage only when both SHA dispatchers report it. x86
counts when SHA-256 reports SHA-NI and SHA-512 reports SHA-NI or scalar:
bounded30 signs and verifies through SHA-256 only, and SHA-512 SHA-NI is far
rarer than SHA-256 SHA-NI. Fallback remains valid library behavior but is
reported as unavailable accelerator coverage.

The observers are passive: they inspect cached dispatcher pointers without
initializing them. Each differential child process first runs SHA-256 and
SHA-512 known-answer probes, then reads the effective implementation. The
explicit SHA-512 probe is required because the active bounded30 profile defines
`SPX_SHA512=0`: signing and verification never use SHA-512, and only key
generation's seed derivation does, so a verify-only child would otherwise leave
that dispatcher uninitialized.

CI can turn an accelerator expectation into a hard requirement with
`BACKEND_DIFFERENTIAL_REQUIRE`. macOS requires `commoncrypto`. An x86
requirement should only be set on a Linux runner whose compiler and CPU are
known to support SHA-256 SHA-NI; otherwise the test emits the
requested/effective capability report without claiming x86 coverage. Windows
MSVC runs scalar/auto correctness coverage and reports the x86 request as a
capability check rather than an x86 coverage claim. ARM remains excluded.

## Production And Downstream Behavior

The effective-backend observers are compiled only when
`BITCOINPQC_ENABLE_TEST_HELPERS=ON` or Cargo feature `test-helpers` is enabled.
They are not declared in installed public headers or exposed through the public
Rust API. Default builds add no observer symbols, dispatcher state, hot-path
branches, or environment-dependent behavior.

As a result, this testing support does not change production backend selection,
fallback behavior, key or signature bytes, verification results, serialization,
or runtime performance. Downstream users may observe stricter CI results where
an accelerator request was previously mistaken for proof that acceleration ran;
normal library behavior is unchanged.

## ARM SHA

ARM SHA acceleration remains experimental. The production build does not accept
`SPX_SHA_BACKEND=arm` or any other runtime environment setting to force ARM SHA.
Do not document or treat ARM SHA as production-supported unless separate backend
evidence is added for the target platform and build configuration.
