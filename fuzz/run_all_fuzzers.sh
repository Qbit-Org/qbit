#!/usr/bin/env bash

set -euo pipefail

# Names must match fuzz/Cargo.toml; fuzz/check_fuzz_inventory.sh enforces this.
TARGETS=(
  keypair_generation
  sign_verify
  huge_message_api
  concurrent_sign_verify
  key_parsing
  signature_parsing
  verify_invalid
  malformed_inputs
  message_to_indices
  message_to_indices_direct
  wotsc_direct
)

if [[ "${1:-}" == "--list" ]]; then
  printf '%s\n' "${TARGETS[@]}"
  exit 0
fi

FUZZ_ARGS=("$@")
if [ ${#FUZZ_ARGS[@]} -eq 0 ]; then
  FUZZ_ARGS=(-runs=10000)
fi

echo "Running all fuzz targets with args: ${FUZZ_ARGS[*]}"
for target in "${TARGETS[@]}"; do
  echo "--- Starting fuzzer: ${target} ---"
  cargo +nightly fuzz run "${target}" -- "${FUZZ_ARGS[@]}"
  echo "--- Finished fuzzer: ${target} ---"
done
