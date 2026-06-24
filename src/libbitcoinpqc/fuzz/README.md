# Fuzz Testing for libbitcoinpqc

This directory contains [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the Rust API and the native C API it calls.

## Setup

```bash
cargo install cargo-fuzz --locked
```

## Targets

1. `keypair_generation` - Fuzz key generation with random entropy input.
2. `sign_verify` - Fuzz message signing and roundtrip verification.
3. `huge_message_api` - Fuzz large message inputs through both Rust and C API signing/verification paths.
4. `concurrent_sign_verify` - Smoke fuzz concurrent sign/verify calls and thread-local signing randomness isolation.
5. `key_parsing` - Fuzz arbitrary bytes as public/secret keys.
6. `signature_parsing` - Fuzz arbitrary bytes as signatures against a valid public key.
7. `verify_invalid` - Mutate valid signatures and ensure verification rejects.
8. `malformed_inputs` - Exercise short, oversized, valid-length-mutated, and uniform key/signature edge cases.
9. `message_to_indices` - Fuzz production FORS message indexing via sign/verify differentials.
10. `message_to_indices_direct` - Fuzz the test-helper FFI for `message_to_indices` and `forsc_compressed_index`.
11. `wotsc_direct` - Fuzz WOTS+C counter search, checksum target handling, counter byte order, malformed root-sized inputs, and helper boundary behavior.

## Run One Target

Use nightly as required by `cargo-fuzz`:

```bash
cargo +nightly fuzz run <target> -- -runs=10000
```

Examples:

```bash
cargo +nightly fuzz run keypair_generation -- -runs=10000
cargo +nightly fuzz run sign_verify -- -runs=10000
cargo +nightly fuzz run huge_message_api -- -runs=1000
cargo +nightly fuzz run concurrent_sign_verify -- -runs=1000
cargo +nightly fuzz run key_parsing -- -runs=10000
cargo +nightly fuzz run signature_parsing -- -runs=10000
cargo +nightly fuzz run verify_invalid -- -runs=10000
cargo +nightly fuzz run malformed_inputs -- -runs=1000
cargo +nightly fuzz run message_to_indices -- -runs=10000
cargo +nightly fuzz run message_to_indices_direct -- -runs=10000
cargo +nightly fuzz run wotsc_direct -- -runs=10000
```

## Run All Targets

Use the helper script:

```bash
./fuzz/run_all_fuzzers.sh
```

By default this runs each target with `-runs=10000`.

List the inventory used by the helper and CI with:

```bash
./fuzz/run_all_fuzzers.sh --list
```

You can pass custom libFuzzer args to all targets, for example:

```bash
./fuzz/run_all_fuzzers.sh -runs=1
./fuzz/run_all_fuzzers.sh -max_total_time=60
```

`./fuzz/run_all_fuzzers.sh -runs=1` is the intended inventory smoke test
after adding, removing, or renaming targets. `./fuzz/check_fuzz_inventory.sh`
checks that `fuzz/Cargo.toml`, `fuzz/run_all_fuzzers.sh`, and the CI smoke
job agree.

For release candidates, run the inventory check, a full smoke pass, and a
longer pass across the same inventory:

```bash
./fuzz/check_fuzz_inventory.sh
./fuzz/run_all_fuzzers.sh -runs=1
./fuzz/run_all_fuzzers.sh -max_total_time=60
```

## Sanitizer Runs

`cargo-fuzz` enables AddressSanitizer for Rust fuzz targets by default. The native C code is built through CMake from `build.rs`, so pass Clang sanitizer flags through the C build environment when you want sanitizer coverage in the C objects as well. Remove `fuzz/target` when changing sanitizer flags so CMake reconfigures from a clean cache.

Inventory smoke with the default cargo-fuzz ASan configuration:

```bash
./fuzz/run_all_fuzzers.sh -runs=1
```

Native C UBSan on macOS with Apple Clang:

```bash
rm -rf fuzz/target
UBSAN_RT="$(clang -print-resource-dir)/lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib"
RT_DIR="$(clang -print-resource-dir)/lib/darwin"
CC=clang \
CFLAGS="-g -O1 -fsanitize=undefined -fno-omit-frame-pointer" \
CXXFLAGS="-g -O1 -fsanitize=undefined -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=undefined" \
RUSTFLAGS="-C link-arg=${UBSAN_RT} -C link-arg=-Wl,-rpath,${RT_DIR}" \
cargo +nightly fuzz run -s none keypair_generation -- -runs=1
```

ASan plus UBSan for native C code reached from a Rust fuzz target, when Clang and the Rust sanitizer runtime are compatible:

```bash
rm -rf fuzz/target
CC=clang \
CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
CXXFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=address,undefined" \
RUSTFLAGS="-C link-arg=-fsanitize=undefined" \
cargo +nightly fuzz run -s address huge_message_api -- -runs=1000
```

On macOS with Apple Clang, do not mix Apple Clang C ASan objects with Rust nightly's ASan runtime unless the compiler-rt runtimes are known to match. A link error mentioning `___asan_version_mismatch_check_apple_clang_*` means the runtime mix is incompatible; use the default cargo-fuzz ASan smoke plus the native C UBSan command above, or rebuild with a matching non-Apple LLVM/Clang toolchain.

ThreadSanitizer smoke coverage for concurrent signing and verification:

```bash
rm -rf fuzz/target
CC=clang \
CFLAGS="-g -O1 -fsanitize=thread -fno-omit-frame-pointer" \
CXXFLAGS="-g -O1 -fsanitize=thread -fno-omit-frame-pointer" \
LDFLAGS="-fsanitize=thread" \
cargo +nightly fuzz run -s thread concurrent_sign_verify -- -runs=1000
```

## Crash Artifact Triage

The previous `fuzz/artifacts/sign_verify/crash-256ac14220a2ca53e6006f2ed7f036b98864e08a` file was a 155-byte stale artifact. It was replayed on April 17, 2026 with:

```bash
cargo +nightly fuzz run sign_verify fuzz/artifacts/sign_verify/crash-256ac14220a2ca53e6006f2ed7f036b98864e08a
```

The replay executed the input once and exited successfully, so it no longer reproduced a crash in the current code. The artifact was removed to avoid seeding future runs with obsolete crash evidence.
