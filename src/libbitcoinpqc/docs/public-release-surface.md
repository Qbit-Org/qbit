# Public Release Surface

This document identifies the source surfaces that remain in the public release
tree for `qbit-libbitcoinpqc`, and separates them from downstream qbit subtree
pruning.

The canonical public source release should be cut from the full repository tag,
not from `qbit-subtree`. The subtree branch is a derived import artifact for
qbit's C/CMake vendoring path; it removes release evidence that should remain
available to public reviewers.

## Supported Product Surface

The production-supported product surface for the current cycle is:

- Native C API headers in `include/libbitcoinpqc/bitcoinpqc.h`,
  `include/libbitcoinpqc/slh_dsa.h`, and
  `include/libbitcoinpqc/sign_stats.h`
- CMake target `bitcoinpqc`
- Cargo package `qbit-libbitcoinpqc`, which exports the Rust crate
  `bitcoinpqc` and builds and links the same CMake target from `build.rs`

The active profile is `SLH-DSA-SHA2-128s-bounded30`. Public API entry points are
single-profile and do not expose algorithm selection.

The source-of-truth production C inventory is
`docs/compiled-code-inventory.md`. Any production-reachable C file must be
listed there, added to `CMakeLists.txt`, and covered by
`scripts/check-source-inventory.sh` when it is a repo-owned facade file.

## Release Evidence Kept In The Public Repo

The following paths are not product APIs, but remain in the public source
repository because they explain or verify the release:

- `.github/workflows/ci.yml`
- `Cargo.toml`, `Cargo.lock`, `build.rs`, `src/lib.rs`, and
  `src/bindings_include.rs`
- `tests/`, `fuzz/`, and `benches/`
- `docs/`
- `scripts/check-source-inventory.sh`,
  `scripts/check-no-tracked-symlinks.sh`, and
  `scripts/check-workflow-action-pins.rb`
- release and benchmark helper scripts under `scripts/`
- examples and README material that exercise the supported C/Rust APIs

These files are intentionally pruned from `qbit-subtree`, but that does not make
them unused for a public source release.

## Removed Non-Production Surfaces

This sweep compared the tracked tree, `CMakeLists.txt`, `build.rs`,
`Cargo.toml`, `scripts/check-source-inventory.sh`, current CI references, and
`scripts/prune-for-qbit-subtree.sh`.

The public source tree now removes these non-production surfaces:

- Python binding package under `python/`
- Node.js binding package under `nodejs/`
- ML-DSA/Dilithium sources and wrappers:
  `dilithium/`, `src/ml_dsa/`, and `include/libbitcoinpqc/ml_dsa.h`
- SPHINCS+ Haraka and SHAKE implementation families
- upstream SPHINCS+ standalone KAT, test, RNG, workflow, benchmark, vector, and
  Makefile entry points
- inactive SPHINCS+ parameter headers other than
  `params-sphincs-sha2-128s-bounded30.h`
- inactive SHA2-AVX2 standalone signer files other than the five conditional x8
  helper files compiled by `CMakeLists.txt`

The SHAKE-AVX2 CI-only Keccak alignment guard was removed with
`sphincsplus/shake-avx2/`; it was not production-reachable.

## What Not To Treat As Unused

Do not remove these paths just because the qbit subtree prune removes them:

- `.github/`, `docs/`, `tests/`, `fuzz/`, `benches/`, and release scripts:
  these are public release evidence.
- `Cargo.toml`, `Cargo.lock`, `build.rs`, `src/lib.rs`, and
  `src/bindings_include.rs`: these define the supported Rust API.
- `src/test_helpers.c`: test-only, but intentionally compiled by the
  `test-helpers` feature and CMake test-helper option.
- `sphincsplus/sha2-avx2/hash_sha2x8.c`,
  `sphincsplus/sha2-avx2/thash_sha2_simplex8.c`,
  `sphincsplus/sha2-avx2/utilsx8.c`,
  `sphincsplus/sha2-avx2/sha256x8.c`, and
  `sphincsplus/sha2-avx2/sha256avx.c`: conditionally production-reachable on
  supported x86/x86_64 compiler targets.

## Relationship To `qbit-subtree`

`scripts/prune-for-qbit-subtree.sh` intentionally performs a stronger prune for
downstream qbit import. It removes not only non-production crypto payload, but
also Rust packaging, CI, docs, tests, fuzzing, benchmarks, examples, and helper
scripts.

For public release work, use this document and
`docs/compiled-code-inventory.md` to identify the reviewed public release
surface. Use `scripts/prune-for-qbit-subtree.sh` only when producing the
downstream subtree import artifact.
