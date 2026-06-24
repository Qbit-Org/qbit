# Performance Policy

This repository uses performance automation to collect release evidence for the
qbit bounded SLH-DSA-SHA2-128s-bounded30 profile. The initial policy is evidence
collection and conservative regression flagging, not strict microbenchmark
gating.

## Benchmark Command

The release smoke benchmark is:

```bash
cargo run --release --bin param_bench
```

The command prints a JSON document with:

- commit SHA and GitHub run metadata when available;
- OS/architecture, runner OS/architecture, CPU model, and detected SHA feature
  metadata;
- Rust, Cargo, C compiler, and CMake version metadata where available;
- backend-related environment values such as `SPX_OPT_PROFILE`,
  `SPX_DISABLE_SHA_ACCEL`, `SPX_DISABLE_SIMD`, `SPX_ENABLE_ARM_SHA`,
  `SPX_FORS_THREADS`, and `SPX_SHA_BACKEND`;
- public key, secret key, and signature sizes;
- keygen, sign, and verify latency;
- keygen, sign, and verify throughput, including verify ops/sec;
- `sign_grind` percentile distributions for FORS+C attempts, WOTS+C
  attempts, and per-message signing latency across a deterministic corpus.

`PARAM_BENCH_GRIND_SAMPLES` controls the deterministic signing corpus size for
the grind distribution. CI sets this explicitly for the existing
`param-benchmark` artifact job.

CI stores the JSON output as a workflow artifact instead of committing per-run
benchmark results.

## Initial Regression Policy

Do not fail PRs solely because a microbenchmark measurement regresses. Shared CI
runners are noisy and early baselines need multiple comparable runs.

For release review, compare benchmark artifacts only when host class, OS/arch,
compiler/toolchain, backend mode/env, and benchmark settings are comparable.
Flag, but do not automatically fail, a candidate release when either of these is
observed versus a selected comparable baseline:

- verify latency is more than 30% slower;
- sign latency is more than 30% slower.

Treat keygen latency as informational for now. Verify performance is the primary
production metric because it affects block-validation budget. Sign performance
is secondary but still release-relevant for wallet UX.

When a large regression is flagged, repeat the benchmark before drawing a
release conclusion. Prefer multiple artifacts from the same host class and
backend mode over a single noisy run.

## Release Checklist

Before publishing a qbit release claim:

- collect a `param_bench` JSON artifact for the release commit;
- confirm the artifact includes the `sign_grind` object and zero
  `cap_exceeded_failures`;
- record whether the run used default, scalar, x86 SHA, CommonCrypto, or other
  backend selection;
- compare verify and sign latency with the selected comparable baseline;
- document any flagged regression and the repeated-run evidence;
- keep ARM SHA acceleration out of production support claims unless the release
  includes reproducible scalar-vs-ARM evidence as described in
  `docs/platform-support.md`.
