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
| Linux x86_64 | Supported | Exercised by the Ubuntu CI job with build, clippy, format, Rust tests, scalar backend tests, threaded FORS tests, C smoke tests, UBSan smoke, and benchmark artifacts from `cargo run --release --bin param_bench`. Backend differential CI reports the requested and effective SHA-256/SHA-512 implementations. It does not claim x86 acceleration merely because `x86` was requested; require x86 only on a provisioned runner whose compiler and CPU are known to select x86 SHA-NI for SHA-256. Production builds pin scalar SHA hashblocks while x86 AVX2 helper code may still be compiled. |
| macOS arm64 | Supported with current evidence | The repo has local Apple arm64 benchmark evidence in `benches/benchmark-results.json`, and macOS CI runs build/tests, requires effective CommonCrypto selection for both SHA dispatchers in the differential test, and collects benchmark artifacts. Release notes should cite the exact CI artifact or local run because GitHub-hosted macOS runner architecture can change over time. |
| macOS x86_64 | Candidate | Expected to use the same bounded profile and scalar production SHA path, but production claims require explicit macOS x86_64 CI or manual evidence for the release commit. Do not infer x86_64 support solely from an arm64 macOS run. |
| Windows MSVC x86_64 | Candidate until updated CI passes | The Windows MSVC job configures and builds the C library with Visual Studio 2022, runs `cargo build` and `cargo test`, and runs scalar/auto backend differential correctness coverage. It also reports requested/effective x86 capability, but fallback does not count as accelerated coverage and the job does not claim x86 SHA-NI coverage. Once that job is green for the release commit, Windows MSVC can be treated as test-supported for the scalar SPHINCS path. AVX2 SPHINCS sources are not enabled under MSVC. |
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

## Backend Differential Evidence

Backend evidence is based on the implementation observed after explicit
SHA-256 and SHA-512 known-answer probes, not on architecture checks or the
requested backend alone. The active bounded30 signing profile has
`SPX_SHA512=0`, so signing and verification never initialize the SHA-512
dispatcher and the SHA-512 probe is required to establish its effective
implementation. x86 coverage requires SHA-256 SHA-NI and accepts a scalar
SHA-512 fallback; CommonCrypto coverage requires both dispatchers.

macOS CI sets `BACKEND_DIFFERENTIAL_REQUIRE=commoncrypto`, making fallback a
failure. Linux CI emits capability evidence without an unconditional x86
requirement because hosted and self-hosted CPU instruction sets may differ; a
release owner may require x86 only after provisioning or verifying a runner
that supports SHA-256 SHA-NI. Windows MSVC reports x86 fallback
as unavailable accelerated coverage and continues to validate scalar/auto.
ARM remains outside the differential matrix until a real ARM backend and runner
satisfy the evidence requirements above.
