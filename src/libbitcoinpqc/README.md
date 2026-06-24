# qbit-libbitcoinpqc

`qbit-libbitcoinpqc` is a qbit-focused fork of `libbitcoinpqc`.

It is not a general-purpose multi-algorithm signature library. This fork is maintained for the qbit profile and consensus integration work only.

## Profile Status

- Active profile: bounded SLH-DSA-SHA2-128s-bounded30 for qbit.
- API selection is intentionally constrained in qbit integrations.
- The public API is single-profile and does not take an algorithm selector.

## Production-Supported Surfaces

For the current hardening cycle, the production-supported release surfaces are:

- The native C API.
- The Rust crate API.

These are the surfaces used for qbit production integration, release criteria,
security review, and production packaging in this cycle. The public source tree
does not include Python or Node.js binding packages.

## Security Scope

The reviewed hardening scope covers functional correctness, malformed input
rejection, fuzz/sanitizer-backed memory-safety hardening, verification
determinism, and avoiding obvious secret leaks. Deterministic signing is
intentional under this policy, but it is not a side-channel-hardening
guarantee.

For the current qbit launch posture, production signing should run only in a
trusted local wallet process, dedicated signing host, or comparably isolated
key-custody environment. Do not claim signing support for hostile shared
hardware, physical side-channel attackers, or fault injection from this release.
Randomized or hedged signing is not exposed by the current API and is deferred
to a separate explicit API and review track.

See [docs/side-channel-policy.md](docs/side-channel-policy.md) for the reviewed
side-channel scope and deferred guarantees.

## Parameter Choices And Rationale

qbit constrains signatures to a single bounded profile to simplify consensus validation and sizing.

- Signature family: SLH-DSA-128s
- Hash profile target: SHA-256 based profile for qbit planning and rollout
- Active signing parameters:
  - Hypertree: `h=30`, `d=5`
  - FORS: `k=8`, `a=16`, FORS+C enabled (`k_sig = k-1 = 7`)
  - WOTS+: `w=256`, WOTS+C enabled (`WOTS_LEN=16`)
- Default signing caps:
  - FORS+C salt grinding: `1,835,008` attempts (`28 * 65,536`)
  - WOTS+C counter search: counter values `0` through `65,535`
- Fixed sizes used by the current C ABI/profile:
  - Public key: `32` bytes
  - Secret key: `64` bytes
  - Signature: `3680` bytes

Design rationale and rollout discussion are tracked in downstream integration notes.

Parameter-sweep reproducibility script and output format:
`docs/parameter-benchmark-sweep.md`

Platform support policy: `docs/platform-support.md`
Performance evidence and regression policy: `docs/performance-policy.md`

## Performance Snapshot (Latest Recorded)

Source: `cargo bench` output in `benches/REPORT.md` and `benches/benchmark-results.json`  
Host/date: Apple M3 Max, `2026-02-14T01:23:33Z`

| Operation | Latency (ms/op) | Throughput (ops/sec) |
|---|---:|---:|
| bounded_slh_dsa_sha2_128s keygen | 11.734108 | 85.22 |
| bounded_slh_dsa_sha2_128s sign | 148.736574 | 6.72 |
| bounded_slh_dsa_sha2_128s verify | 0.614708 | 1626.79 |

Estimated verify-budget TPS thresholds (1% of 30s block, ideal scaling):
- 1 thread: `16.27` TPS
- 4 cores: `65.07` TPS
- 8 cores: `130.14` TPS

## Build

### Prerequisites

- CMake 3.10+
- C compiler with C99 support
- Rust toolchain (`cargo`)

### Core Build Commands

```bash
# Build C and Rust libraries
make c-lib rust-lib

# Run Rust tests
cargo test

# Run helper-dependent FORS invariant tests
cargo test --features test-helpers --test forsc_invariant_tests

# Run dependency advisory checks
cargo audit
```

Alternative direct commands on Linux/macOS:

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cargo build --release
```

Production builds ignore runtime SPHINCS+ backend environment knobs such as
`SPX_SHA_BACKEND`, `SPX_DISABLE_SHA_ACCEL`, `SPX_DISABLE_SIMD`,
`SPX_OPT_PROFILE`, and `SPX_FORS_THREADS`, and pin SHA hashblocks to the scalar
backend. Test and benchmark builds can opt into those knobs explicitly for
backend experiments; see
`docs/runtime-crypto-env.md`.

### Windows (MSVC)

Windows support is currently validated in CI with a native MSVC toolchain.
For this first wedge, MSVC stays on the scalar SPHINCS path; AVX2 SPHINCS
sources are not enabled under MSVC yet.

Prerequisites:

- Visual Studio 2022 with the MSVC C/C++ toolchain
- CMake 3.10+
- Rust toolchain (`cargo`)
- LLVM/Clang with `libclang` available for `bindgen`

From a fresh checkout in an x64 Native Tools command prompt:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
cargo build --verbose
cargo test --verbose
```

That is the supported Windows path for now. Shared-library packaging and
AVX2-on-MSVC runtime support are intentionally out of scope.

## Fuzzing

Fuzzing uses `cargo-fuzz` and LLVM/libFuzzer toolchains.

```bash
cargo install cargo-fuzz --locked
```

### Available Fuzz Targets

The authoritative fuzz inventory is maintained in `fuzz/Cargo.toml`.
`./fuzz/run_all_fuzzers.sh --list` prints the target set used by the
local and CI smoke helper.

### Running Fuzz Tests

```bash
# Check fuzz inventory drift
./fuzz/check_fuzz_inventory.sh

# Run a specific fuzz target
cargo +nightly fuzz run keypair_generation -- -runs=10000

# List available fuzz targets
./fuzz/run_all_fuzzers.sh --list

# Run a fuzz target for a specific amount of time (in seconds)
cargo +nightly fuzz run keypair_generation -- -max_total_time=60

# Run all targets sequentially
./fuzz/run_all_fuzzers.sh

# Smoke the full inventory once
./fuzz/run_all_fuzzers.sh -runs=1
```

See `fuzz/README.md` for more details on fuzz testing.

## C API Example

C API ownership rules:

- `bitcoin_pqc_keypair_t` and `bitcoin_pqc_signature_t` must be zero-initialized before passing them to `bitcoin_pqc_keygen` or `bitcoin_pqc_sign`.
- Output structs may be reused only after the corresponding free function has been called.
- Passing a nonzero or already-owned output struct to `bitcoin_pqc_keygen` or `bitcoin_pqc_sign` returns `BITCOIN_PQC_ERROR_BAD_ARG` and leaves the struct unchanged.
- `bitcoin_pqc_keypair_free` and `bitcoin_pqc_signature_free` accept `NULL`, zeroize allocated buffers before release, reset pointers and sizes to zero, and are safe to call repeatedly on the same struct after the first free.
- Zero-length messages are supported. At the C ABI boundary, `message` may be `NULL` only when `message_size == 0`.
- Key generation uses caller-provided entropy. Signing is deterministic from
  the secret key and message and does not request operating-system entropy.
- Successful key generation returns a self-consistent generated pair. The
  SLH-DSA secret key layout is `[SK_SEED || SK_PRF || PUB_SEED || root]`, the
  public key layout is `[PUB_SEED || root]`, and the root is computed during
  keygen. Trusted callers that immediately adopt same-call keygen output do not
  need to call the secret-key validator only to recompute that root.
- `slh_dsa_secret_key_validate` and `bitcoin_pqc_secret_key_validate` are for
  imported, deserialized, or otherwise untrusted exact-size secret material
  before it is accepted.
- The internal SPHINCS+ `randombytes` hook aborts with a fatal diagnostic if it
  is invoked without configured deterministic/caller-provided randomness and
  operating-system entropy is unavailable; it never substitutes all-zero bytes
  as successful randomness.

```c
#include <libbitcoinpqc/bitcoinpqc.h>

uint8_t random_data[256];
/* Fill random_data with cryptographically secure entropy */

bitcoin_pqc_keypair_t keypair = {0};
bitcoin_pqc_error_t rc = bitcoin_pqc_keygen(
    &keypair,
    random_data,
    sizeof(random_data)
);
if (rc != BITCOIN_PQC_OK) {
    bitcoin_pqc_keypair_free(&keypair);
    return;
}

const uint8_t message[] = "Message to sign";
bitcoin_pqc_signature_t signature = {0};
rc = bitcoin_pqc_sign(
    (const uint8_t *)keypair.secret_key,
    keypair.secret_key_size,
    message,
    sizeof(message) - 1,
    &signature
);

if (rc == BITCOIN_PQC_OK) {
    rc = bitcoin_pqc_verify(
        (const uint8_t *)keypair.public_key,
        keypair.public_key_size,
        message,
        sizeof(message) - 1,
        signature.signature,
        signature.signature_size
    );
}

bitcoin_pqc_signature_free(&signature);
bitcoin_pqc_keypair_free(&keypair);
```

`bitcoin_pqc_keypair_t` and `bitcoin_pqc_signature_t` outputs must be
zero-initialized before first use. Call the matching free function before
reusing an output struct; the free functions reset fields to zero and are safe
to call on zeroed structs or structs returned by this library. Key generation
requires at least 128 bytes of caller-provided entropy, and all provided bytes
are mixed into the internal SLH-DSA seed with domain separation and
input-length binding. Successful key generation returns a self-consistent
public/secret pair, and trusted callers may adopt that same-call output without
immediately revalidating the secret-key root. Validation remains required for
imported, deserialized, or otherwise untrusted exact-size secret material.
Signing is deterministic from the secret key and message, so normal signing
does not depend on operating-system entropy. The library cannot clear
caller-owned entropy buffers; callers should protect and zeroize those buffers
after key generation when they contain sensitive seed material. For signing and
verification, `message == NULL` is valid only when `message_size == 0`.

## Rust API Example

```rust
use bitcoinpqc::{generate_keypair, sign, verify};

let mut random_data = vec![0u8; 128];
getrandom::fill(&mut random_data).unwrap();

let keypair = generate_keypair(&random_data).unwrap();
let message = b"Message to sign";
let signature = sign(&keypair.secret_key, message).unwrap();
verify(&keypair.public_key, message, &signature).unwrap();
```

`SecretKey` keeps its bytes private. Normal callers should parse secret keys
with `SecretKey::try_from_slice` or `SecretKey::from_str` and pass them to
`sign`. `SecretKey::as_secret_bytes()` is the explicitly named escape hatch for
raw key export or interoperability code; do not log, serialize, or retain copies
of that data unless the calling protocol requires it.

The Rust `serde` feature serializes/deserializes public keys and signatures
only. Secret key and whole `KeyPair` serde support requires the explicit
`secret-key-serde` feature because it emits raw secret key material as hex.

## Versioning And Release Checks

Rust and CMake package metadata currently identify the core library as `0.3.0`.

Release readiness and supply-chain validation are tracked in:

- `docs/public-release-surface.md`
- `docs/versioning-and-supply-chain.md`
- `docs/release-checklist.md`

## License

MIT. See `LICENSE`.
