#!/usr/bin/env bash
#
# Curate libbitcoinpqc for qbit subtree import.
# Keeps only the C/CMake runtime payload required by qbit.

set -euo pipefail
export LC_ALL=C

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: run inside a git work tree" >&2
  exit 1
fi

TOP="$(git rev-parse --show-toplevel)"
cd "${TOP}"

prune_cmake_testing() {
  if [[ ! -f CMakeLists.txt ]]; then
    return
  fi

  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/libbitcoinpqc-cmake.XXXXXX")"
  awk '
    /^include\(CTest\)$/ {
      next
    }
    /^if\(BUILD_TESTING\)$/ {
      skip = 1
      depth = 1
      next
    }
    skip && /^if\(/ {
      depth++
      next
    }
    skip && /^endif\(\)$/ {
      depth--
      if (depth == 0) {
        skip = 0
      }
      next
    }
    !skip {
      print
    }
  ' CMakeLists.txt > "${tmp}"
  mv "${tmp}" CMakeLists.txt
}

if [[ "${1-}" == "--help" ]]; then
  cat <<'USAGE'
Usage: scripts/prune-for-qbit-subtree.sh

Prunes non-runtime payload from libbitcoinpqc for qbit subtree use.
Run from any location inside the repository.
USAGE
  exit 0
fi

# Remove directories and files not required for qbit's C/CMake subtree usage.
PRUNE_PATHS=(
  .github
  .vscode
  benches
  docs
  examples
  fuzz
  tests
  Cargo.lock
  Cargo.toml
  Makefile
  build.rs
  build.sh
  src/bin
  src/bindings_include.rs
  src/lib.rs
  scripts/benchmark_param_sweep.sh
  scripts/check-no-tracked-symlinks.sh
  scripts/check-source-inventory.sh
  scripts/check-workflow-action-pins.rb
  scripts/x86_bench_5x.sh
)

for item in "${PRUNE_PATHS[@]}"; do
  if [[ -e "${item}" ]]; then
    rm -rf "${item}"
  fi
done

prune_cmake_testing

if [[ -d sphincsplus/ref/params ]]; then
  find sphincsplus/ref/params \
    -type f \
    ! -name params-sphincs-sha2-128s-bounded30.h \
    -delete
fi

if [[ -d sphincsplus/sha2-avx2/params ]]; then
  find sphincsplus/sha2-avx2/params \
    -type f \
    ! -name params-sphincs-sha2-128s-bounded30.h \
    -delete
fi

rm -f scripts/prune-for-qbit-subtree.sh
rmdir scripts 2>/dev/null || true

echo "Prune complete."
