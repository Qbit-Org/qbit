# Platform Support

This repository supports the qbit bounded SLH-DSA-SHA2-128s-bounded30 profile
only. Platform claims are limited to the build, test, and benchmark evidence
available for that profile.

## Status Definitions

- Supported: the platform/backend is expected to be usable for qbit production
  release candidates when the relevant CI jobs pass.
- Candidate: the platform/backend is expected to build or run, but release
  claims require fresh CI or manual evidence for the exact host/backend.
- Experimental: code may exist, but it is not production-supported and must not
  be described as a release guarantee.

## Support Matrix

| Platform/backend | Status | Evidence and notes |
|---|---|---|
| Linux x86_64 | Supported | Exercised by the Ubuntu CI job with build, clippy, format, Rust tests, scalar backend tests, threaded FORS tests, C smoke tests, UBSan smoke, and benchmark artifacts from `cargo run --release --bin param_bench`. Production builds pin scalar SHA hashblocks while x86 AVX2 helper code may still be compiled; runtime backend experiments require the test/benchmark env-knob opt-in. |
| macOS arm64 | Supported with current evidence | The repo has local Apple arm64 benchmark evidence in `benches/benchmark-results.json`, and macOS CI runs build/tests plus benchmark artifact collection. Release notes should cite the exact CI artifact or local run because GitHub-hosted macOS runner architecture can change over time. |
| macOS x86_64 | Candidate | Expected to use the same bounded profile and scalar production SHA path, but production claims require explicit macOS x86_64 CI or manual evidence for the release commit. Do not infer x86_64 support solely from an arm64 macOS run. |
| Windows MSVC x86_64 | Candidate until updated CI passes | The Windows MSVC job configures and builds the C library with Visual Studio 2022, runs `cargo build`, and now runs `cargo test`. Once that job is green for the release commit, Windows MSVC can be treated as test-supported for the scalar SPHINCS path. AVX2 SPHINCS sources are not enabled under MSVC. |
| Linux aarch64 scalar | Candidate | Expected scalar path for non-Apple AArch64 when ARM SHA is disabled or unavailable. Production claims require Linux aarch64 CI or documented manual evidence for build, tests, backend differential tests, and `param_bench` output. |
| Linux aarch64 ARM SHA | Experimental, not production-supported | `SPX_ENABLE_ARM_SHA` is an opt-in CMake setting and is off by default. The ARM SHA source is present and non-Apple AArch64 builds apply `-march=armv8-a+crypto`, but `spx_sha2_arm_can_use_sha256()` currently returns disabled. Do not claim ARM SHA production support until reproducible scalar-vs-ARM differential and benchmark evidence exists for the release commit. |

## ARM SHA Evidence Requirement

ARM SHA acceleration must remain experimental until the repo contains or links to
reproducible evidence showing all of the following on the same Linux aarch64
host class:

- scalar and ARM SHA builds from the same commit;
- backend differential tests passing across scalar and ARM SHA;
- known-answer or golden-vector coverage passing under both backends;
- `cargo run --release --bin param_bench` artifacts for both backends;
- metadata identifying commit SHA, OS/arch, CPU model, compiler/toolchain
  versions, backend mode/env, keygen/sign/verify latency, and verify ops/sec.

Until that evidence exists, ARM SHA is not a qbit production requirement and is
not part of the supported release surface.
