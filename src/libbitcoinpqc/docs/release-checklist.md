# Release Checklist

Use this checklist for qbit-libbitcoinpqc release candidates. Downstream qbit
import, wallet, and integration work is tracked outside this repository.

This checklist also captures release evidence for the current R2 hardening
cycle. The production-supported surface for this cycle is the native C library
and the Rust crate that links it.

## Production Scope

- Active profile: `SLH-DSA-SHA2-128s-bounded30`.
- Native build target: CMake target `bitcoinpqc`.
- Rust build target: Cargo package `qbit-libbitcoinpqc`, which exports the
  Rust crate `bitcoinpqc` and builds and links the same CMake target from
  `build.rs`.
- Public release surface source of truth:
  `docs/public-release-surface.md`.
- Production inventory source of truth: `docs/compiled-code-inventory.md`.
- Vendored crypto source evidence: `docs/vendored-crypto-provenance.md`.

Do not include dev-dependencies used only by tests, examples, benchmarks, or
fuzzing in the production SBOM for this cycle.

## Blocking Release Gates

Do not cut a production release until all applicable gates have evidence:

- Active external workflow `uses:` refs are SHA-pinned and verified by
  `ruby scripts/check-workflow-action-pins.rb`, or a documented exception
  and reviewed guard allowlist exist.
- Rust advisory audit passes with `cargo audit --deny warnings`.
- The release tag is signed and release artifacts are built from that tag.
- Checksums are produced for every published archive or binary.
- A CycloneDX SBOM is generated for the C/Rust production surface.
- Compiler and toolchain provenance is captured, including `rustc -Vv`,
  `cargo -V`, `cmake --version`, host OS, and build commands.

## Required Evidence

Capture these artifacts for each release candidate:

- `git rev-parse HEAD`
- `rustc -Vv`
- `cargo -V`
- `cmake --version`
- `cargo fmt -- --check`
- `ruby scripts/check-workflow-action-pins.rb`
- `cargo audit --deny warnings`
- Low-cap signing-limit CI test output:
  `BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS=1 CARGO_TARGET_DIR=target/low-fors cargo test --verbose --test signing_stats_tests low_fors_cap`
  and
  `BITCOINPQC_WOTSC_MAX_COUNTER=0 CARGO_TARGET_DIR=target/low-wots cargo test --verbose --test signing_stats_tests low_wots_cap`
- CycloneDX SBOM JSON for the C/Rust production surface
- Signed release tag verification, for example `git tag -v <tag>`
- Checksums for published archives or binaries
- Test output selected by the release owner for the release candidate
- `cargo run --release --bin param_bench` JSON with `sign_grind` present,
  `forsc_max_attempts` equal to 1,835,008, and `cap_exceeded_failures` equal
  to zero
- Confirmation that `docs/compiled-code-inventory.md` still matches
  `CMakeLists.txt`
- Confirmation that `docs/public-release-surface.md` still matches the release
  scope and any intentional public-tree removals
- Confirmation that vendored crypto changes, if any, are described in
  `docs/vendored-crypto-provenance.md`

## Required Tests

- `cargo fmt -- --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo test --features serde`
- `cargo test --features secret-key-serde`
- `cargo test --features test-helpers`
- Windows CI: `cargo build --verbose` and `cargo test --verbose`

## C API Checks

- Confirm keypair and signature output structs are zero-initialized before use.
- Confirm reused output structs fail with `BITCOIN_PQC_ERROR_BAD_ARG` unless freed first.
- Confirm `bitcoin_pqc_keypair_free` and `bitcoin_pqc_signature_free` are idempotent.
- Confirm zero-length message sign/verify works through Rust and the C ABI.

## Signing Side-Channel Posture

- Confirm release notes state deterministic signing is not side-channel
  hardening.
- Confirm production signing guidance limits signing to trusted local wallet
  processes, dedicated signing hosts, or comparably isolated key-custody
  infrastructure.
- Confirm release materials do not claim signing support for hostile shared
  hardware, physical side-channel attackers, or fault injection.
- Confirm randomized or hedged signing is not described as available unless an
  explicit API and review track have landed.

## Fuzz Smoke

Run the repo-local fuzz inventory:

```bash
cargo install cargo-fuzz --locked
./fuzz/run_all_fuzzers.sh -runs=1
```

For longer release candidates, run each target with a time budget recorded in the release notes.

## Sanitizer Smoke

Run UBSan smoke for native C paths:

```bash
CC=clang CXX=clang++ \
CFLAGS="-fsanitize=undefined,unsigned-integer-overflow -fno-sanitize-recover=undefined,unsigned-integer-overflow -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=undefined,unsigned-integer-overflow" \
cargo test --test sha2_backend_tests --test backend_differential_tests --test bounded_mode_correctness_tests
```

Run ASan smoke where the local platform supports the Rust/C link mode:

```bash
CC=clang CXX=clang++ \
CFLAGS="-fsanitize=address -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=address" \
RUSTFLAGS="-Zsanitizer=address" \
cargo +nightly test --target "$(rustc -vV | sed -n 's|host: ||p')"
```

If ASan cannot link on the release host, record the linker/platform blocker and run the UBSan smoke plus fuzz smoke instead.

## CycloneDX SBOM

CycloneDX JSON is the machine-readable SBOM format for the C/Rust production
surface. The generated Cargo SBOM records Rust package dependencies and build
dependencies; it does not fully describe locally vendored C crypto source.
Use `docs/vendored-crypto-provenance.md` as the manual provenance companion.

Install the pinned SBOM generator version if needed:

```bash
cargo install cargo-cyclonedx --version 0.5.9 --locked
```

Generate the production SBOM:

```bash
cargo cyclonedx \
  --manifest-path Cargo.toml \
  --format json \
  --target all \
  --spec-version 1.5 \
  --features serde,secret-key-serde \
  --override-filename bitcoinpqc-production-sbom
```

Then move the generated file into the release evidence bundle:

```bash
mkdir -p release-evidence
mv bitcoinpqc-production-sbom.json release-evidence/
```

Notes:

- `--features serde,secret-key-serde` includes the optional Rust serialization
  paths in the production Rust dependency inventory. The `serde` feature covers
  public keys and signatures; `secret-key-serde` is the explicit opt-in for
  `SecretKey` and `KeyPair`.
- Do not use `--all-features` for the production SBOM because `test-helpers`
  and `ide` are not production release features.
- Cargo dev-dependencies used by tests, examples, and benchmarks are outside
  the production SBOM for this cycle.
- Test, example, benchmark, and fuzz dependencies are excluded from the
  production SBOM for this cycle.

## Supply-Chain Checks

Run the Rust advisory audit before release:

```bash
cargo install cargo-audit --version 0.22.1 --locked
cargo audit --deny warnings
```

The CI workflow runs the same audit command on Ubuntu. `cargo-deny` is not a
release gate yet because this repository does not currently have a checked-in
`deny.toml`; add one before making license/source policy decisions enforceable
through `cargo deny check`.

Also review dependency and supply-chain inputs before release:

- Review and document any non-failing audit warnings before release.
- Run `ruby scripts/check-workflow-action-pins.rb` and review GitHub Actions
  refs under the policy in `docs/versioning-and-supply-chain.md`.
- Record vendored C source provenance and any local patches in the release notes.

## GitHub Actions Pinning

Active workflows must pin every external `uses:` action reference to a full
commit SHA. Keep a trailing comment with the human-readable tag or branch used
to select the SHA. Bump action pins only in reviewable PRs, and include the
resolved source tag or branch in the PR description.

The CI guard parses workflow YAML, so commented examples and YAML block scalar
text are not release inputs. Do not rely on a commented workflow snippet as
release evidence.

Toolchains may still intentionally track channels such as Rust `stable` or
`nightly`. When a release depends on that moving channel behavior, capture
`rustc -Vv` in the release evidence bundle.

Any exception to action SHA pinning must be documented in this file with:

- the unpinned action reference,
- why pinning is not practical,
- the date the exception was approved,
- the follow-up owner or issue.

There are no approved release-evidence exceptions as of 2026-04-20.

## Crypto Change Gate

Do not make silent vendored crypto updates. Before release, inspect changes
under `sphincsplus/`, `src/slh_dsa/`, `include/`, and `CMakeLists.txt`.

For active crypto semantic changes, require KAT or invariant test updates. For
active parsing or verification changes, require fuzz smoke evidence. Dormant
vendored-code changes must not be described as production hardening unless the
code becomes reachable from the default C/Rust production build.

## Version Checks

- Confirm `Cargo.toml` and `CMakeLists.txt` agree on the core library version.
- Confirm README profile sizes still match the C header constants.

## Tags, Artifacts, SBOM, Provenance

- Create a signed release tag.
- Build release artifacts from the signed tag, not from an untagged working tree.
- Attach checksums for published archives or binaries.
- Produce or attach an SBOM for published artifacts.
- Record artifact provenance: commit SHA, toolchain versions, host OS, and build commands.

## Downstream Handoff

- Provide downstream qbit workspaces with the release tag, commit SHA, profile constants, validation commands, and known platform limitations.
- Call out any C ABI behavior changes, especially output ownership behavior.
- Carry forward the signing side-channel posture and shared-hardware
  restriction from `docs/side-channel-policy.md`.
- Do not claim downstream qbit subtree, wallet, or integration validation from this repository alone.
