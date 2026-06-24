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
cmake -S . -B build -DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=ON
cargo test --features test-bench-env-knobs --test backend_differential_tests
cargo bench --features test-bench-env-knobs
ENABLE_TEST_BENCH_ENV_KNOBS=1 ./scripts/x86_bench_5x.sh
```

`SPX_PRODUCTION_BUILD` and `SPX_ENABLE_TEST_BENCH_ENV_KNOBS` are mutually
exclusive. The source fails compilation if both macros are defined.

## ARM SHA

ARM SHA acceleration remains experimental. The production build does not accept
`SPX_SHA_BACKEND=arm` or any other runtime environment setting to force ARM SHA.
Do not document or treat ARM SHA as production-supported unless separate backend
evidence is added for the target platform and build configuration.
