# Benchmark Report: bounded SLH-DSA-SHA2-128s

## Host Metadata
- Generated (UTC): 2026-02-14T01:23:33Z
- Commit: `b4044cc36c89`
- Worktree Clean At Start: yes
- Toolchain: `rustc 1.84.0 (9fc6b4312 2025-01-07)`
- CPU: Apple M3 Max
- SHA-NI: n/a (non-x86 host)
- ARM SHA2: detected
- OS/Arch: macos/aarch64
- Runtime Env Knobs: ignored (production build)
- Optimization Env: `SPX_OPT_PROFILE=unset`, `SPX_DISABLE_SHA_ACCEL=unset`, `SPX_DISABLE_SIMD=unset`, `SPX_FORS_THREADS=unset`, `SPX_DISABLE_THREADS=unset`, `SPX_ENABLE_ARM_SHA=unset`, `SPX_SHA_BACKEND=unset`

## Repro Command
- `cargo bench`

## Size Confirmation
| Algorithm | Public Key (bytes) | Secret Key (bytes) | Signature (bytes) |
|---|---:|---:|---:|
| bounded_slh_dsa_sha2_128s | 32 | 64 | 3680 |
| secp256k1_schnorr | 32 | 32 | 64 |

## Latency and Throughput
| Algorithm | Operation | Latency (ms/op) | Throughput (ops/sec) |
|---|---|---:|---:|
| bounded_slh_dsa_sha2_128s | keygen | 11.734108 | 85.22 |
| bounded_slh_dsa_sha2_128s | sign | 148.736574 | 6.72 |
| bounded_slh_dsa_sha2_128s | verify | 0.614708 | 1626.79 |
| secp256k1_schnorr | keygen | 0.010401 | 96147.59 |
| secp256k1_schnorr | sign | 0.011130 | 89846.61 |
| secp256k1_schnorr | verify | 0.018529 | 53969.50 |

## Impact Analysis
- Verification budget: 0.300 seconds per 30-second block (1%).
- TPS threshold formula: `TPS > 0.01 / verify_latency_seconds`.
| Algorithm | Verify Latency (ms/op) | TPS @1-thread | TPS @4-core (ideal) | TPS @8-core (ideal) |
|---|---:|---:|---:|---:|
| bounded_slh_dsa_sha2_128s | 0.614708 | 16.27 | 65.07 | 130.14 |
| secp256k1_schnorr | 0.018529 | 539.70 | 2158.78 | 4317.56 |

## Target Check
| Target | Result | Status |
|---|---|---|
| Signing <= 500 ms | 148.736574 ms | PASS |
| Verification <= 0.5 ms | 0.614708 ms | FAIL |
| Verification with SHA-NI <= 0.1 ms | Not measured on this host (n/a (non-x86 host)) | N/A |

## Learnings
- Bounded SLH-DSA signing is within the wallet UX target.
- Verification is the primary bottleneck for block-validation budgets on this host.
- At a 1% verify budget on 30-second blocks, bounded SLH-DSA reaches budget saturation near 16.27 TPS single-threaded.
- secp256k1 Schnorr verify is approximately 33.2x faster than bounded SLH-DSA verify in this environment.

## Constraints
- This repository is currently configured as a bounded-only profile build, so unbounded SLH and SHA2-vs-SHAKE benchmark comparisons are not included.
- Reported 4-core and 8-core TPS are idealized linear scaling estimates, not directly measured multicore throughput.
- SHA-NI impact is not measured on this ARM host; an x86 run is required for that measurement.
