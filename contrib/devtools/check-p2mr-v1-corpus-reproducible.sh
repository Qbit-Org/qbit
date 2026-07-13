#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

export LC_ALL=C
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd -P)"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/p2mr-v1-repro.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

temp_root="${tmpdir}/source"
temp_data="${temp_root}/src/test/data"
mkdir -p "${temp_data}"

python3 "${repo_root}/contrib/devtools/test_p2mr_v1_generators.py"

python_output="${tmpdir}/python-witness.json"
rust_output="${tmpdir}/rust-witness.json"
python3 "${repo_root}/contrib/devtools/generate-p2mr-v1-corpus.py" \
  --output-dir "${temp_data}"
python3 "${repo_root}/contrib/devtools/generate-p2mr-pqc-witness-vectors.py" \
  --output "${python_output}"

cargo run --locked --offline --quiet \
  --manifest-path "${repo_root}/contrib/testgen/p2mr_checksigpqc_vectors/Cargo.toml" -- \
  --output "${rust_output}"
python3 "${repo_root}/contrib/devtools/merge-p2mr-pqc-witness-vectors.py" \
  --python "${python_output}" \
  --rust "${rust_output}" \
  --output "${temp_data}/p2mr_pqc_witness_vectors.json"

python3 "${repo_root}/contrib/devtools/update-p2mr-v1-manifest.py" \
  --source-root "${temp_root}" \
  --manifest src/test/data/p2mr_v1_manifest.json

python3 "${repo_root}/contrib/devtools/test_p2mr_v1_reproducibility.py" \
  --repo-root "${repo_root}" \
  --generated-data "${temp_data}"
