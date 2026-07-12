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

corpus_files=(
  p2mr_cross_profile_vectors.json
  p2mr_pqc_witness_vectors.json
  p2mr_script_boundary_vectors.json
  p2mr_vectors.json
  p2mr_v1_manifest.json
)
for file in "${corpus_files[@]}"; do
  cp "${repo_root}/src/test/data/${file}" "${temp_data}/${file}"
done

python_output="${tmpdir}/python-witness.json"
rust_output="${tmpdir}/rust-witness.json"
python3 "${repo_root}/contrib/devtools/generate-p2mr-pqc-witness-vectors.py" \
  --input "${temp_data}/p2mr_pqc_witness_vectors.json" \
  --output "${python_output}"

cargo run --locked --offline --quiet \
  --manifest-path "${repo_root}/contrib/testgen/p2mr_checksigpqc_vectors/Cargo.toml" -- \
  --input "${python_output}" \
  --output "${rust_output}"
mv "${rust_output}" "${temp_data}/p2mr_pqc_witness_vectors.json"

python3 "${repo_root}/contrib/devtools/update-p2mr-v1-manifest.py" \
  --source-root "${temp_root}" \
  --manifest src/test/data/p2mr_v1_manifest.json

failed=0
for file in "${corpus_files[@]}"; do
  if ! cmp -s "${repo_root}/src/test/data/${file}" "${temp_data}/${file}"; then
    echo "P2MR v1 corpus is not reproducible: src/test/data/${file}" >&2
    failed=1
  fi
done
if [[ "${failed}" != 0 ]]; then
  exit 1
fi

echo "P2MR v1 generated corpus and manifest are reproducible."
