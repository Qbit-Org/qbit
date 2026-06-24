# qbit Profile Benchmarks

This directory contains benchmark targets for the qbit single-profile surface.

## Run Benchmarks

```bash
cargo bench
```

Default benchmark builds use production-mode crypto dispatch and ignore runtime
SPHINCS+ backend environment knobs. Backend attribution experiments must opt in:

```bash
cargo bench --features test-bench-env-knobs
```

## Outputs

- Human-readable report: `benches/REPORT.md`
- Machine-readable JSON artifact: `benches/benchmark-results.json`
- Raw Criterion output: `target/criterion/`

## Useful Filters

```bash
cargo bench -- slh_dsa_sha2_128s_bounded
cargo bench -- secp256k1_schnorr
cargo bench -- keygen
cargo bench -- sign
cargo bench -- verify
```

## Notes

- qbit integrations should focus on the bounded SLH-DSA-SHA2-128s profile.
- The benchmark harness asserts bounded SLH sizes (`pk=32`, `sk=64`, `sig=3680`) before running.
- Latest recorded bounded SLH speeds (Apple M3 Max, 2026-02-14): `sign=148.736574 ms`, `verify=0.614708 ms`; verify-budget estimates: `16.27 TPS` (1-thread), `65.07 TPS` (4-core ideal), `130.14 TPS` (8-core ideal).
- Attribution toggles are honored only with `--features test-bench-env-knobs`:
  `SPX_OPT_PROFILE={scalar|optimized}`, `SPX_DISABLE_SHA_ACCEL=1`,
  `SPX_DISABLE_SIMD=1`, `SPX_FORS_THREADS=<n>`, and
  `SPX_SHA_BACKEND={auto|scalar|arm|x86|commoncrypto}`.
- ARM SHA remains experimental and should not be treated as production-supported
  without separate backend evidence.
- Filtered runs generate partial artifacts scoped to benchmarks executed in that run.
