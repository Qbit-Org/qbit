# SLH-DSA Parameter Sweep

This repository includes a reproducible sweep script for the SPHINCS+ bounded30 parameter candidates discussed in issue #9.

## Current Profile Snapshot

The branch is currently configured for:

- `h=30`, `d=5`, `k=8`, `a=16`
- WOTS+C enabled (`WOTS_LEN=16`)
- FORS+C enabled (`k_sig = k-1 = 7`)
- Bounded signature size: `3680` bytes

Latest recorded benchmark snapshot (`cargo bench`, Apple M3 Max, `2026-02-14T01:23:33Z`):

- Sign latency: `148.736574 ms/op` (`6.72 ops/sec`)
- Verify latency: `0.614708 ms/op` (`1626.79 ops/sec`)
- Estimated verify-budget TPS threshold (1% of 30s block): `16.27` (1-thread), `65.07` (4-core ideal), `130.14` (8-core ideal)

## What It Runs

- `A` baseline using `develop` source files (`params`, `wots.c`, `fors.c`, `slh_dsa.h`)
- `B..I` on this branch with:
  - WOTS+C from branch code
  - FORS+C disabled by default (full FORS signing)
  - candidate-specific `h,d,k,a`
- Per candidate:
  - optional smoke test (`algorithm_tests::test_keygen_sign_verify_roundtrip`)
  - benchmark via `cargo run --release --bin param_bench`

## Command

```bash
scripts/benchmark_param_sweep.sh
```

Optional output directory:

```bash
scripts/benchmark_param_sweep.sh .context/bench_runs
```

## Environment Knobs

- `RUN_SMOKE_TESTS=0` to skip smoke tests
- `PARAM_BENCH_SAMPLES` (default `5`)
- `PARAM_BENCH_TARGET_MS` (default `1500`)
- `PARAM_BENCH_MAX_INNER` (default `50`)
- `RUN_ID` to pin output subdirectory name

Example:

```bash
RUN_SMOKE_TESTS=1 PARAM_BENCH_SAMPLES=7 scripts/benchmark_param_sweep.sh
```

## Output

Given default output root `.context/bench_runs`, each run writes:

- `results/summary.tsv` (machine-readable)
- `results/comparison.md` (markdown table)
- `results/<ID>.json` (per-candidate benchmark metrics)
- `logs/<ID>_smoke.log`
- `logs/<ID>_bench.log`

The script restores modified source files on exit.
