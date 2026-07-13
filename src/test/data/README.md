Description
------------

This directory contains data-driven tests for various aspects of Bitcoin.

P2MR v1 conformance corpus
--------------------------

`p2mr_v1_manifest.json` identifies the qbit P2MR v1 corpus, pins the exact-byte
SHA256 digest and authoritative case count of every included file, and links to
the normative profile in `doc/consensus/p2mr-v1.md`. The corpus currently covers
commitments and control blocks (`p2mr_vectors.json`), PQC sighash witnesses
(`p2mr_pqc_witness_vectors.json`), script/control/leaf/opcode/resource boundaries
(`p2mr_script_boundary_vectors.json`), and the defining qbit/BIP-360 boundary
cases (`p2mr_cross_profile_vectors.json`). Pinned BIP-360 results are comparison
metadata; qbit unit tests execute every qbit P2MR v1 boundary case under both
consensus and standard-policy flags. Cryptographic boundary cases refer to exact
artifacts in the independently generated witness corpus instead of generating
fresh expectations inside the C++ consumer.

A boundary artifact selector is the exact tuple `fixture_file`, `fixture_id`,
and `artifact`. `fixture_file` names a manifest-covered corpus file,
`fixture_id` must match exactly one stable vector ID in that file, and
`artifact` selects a consumer-defined field group such as
`transaction-checksigpqc`, `checkSigAdd`, `dataSig`, or `dataSigAdd`. Consumers
must reject unknown files, missing or duplicate IDs, and unknown artifacts.

Regenerate every corpus file from independent source generators into temporary
files, merge the disjoint witness-generator outputs, then update the manifest
only after reviewing the vector diff:

```
python3 contrib/devtools/generate-p2mr-v1-corpus.py \
  --output-dir /tmp/p2mr-data
python3 contrib/devtools/generate-p2mr-pqc-witness-vectors.py \
  --output /tmp/p2mr-python.json
cargo run --locked \
  --manifest-path contrib/testgen/p2mr_checksigpqc_vectors/Cargo.toml -- \
  --output /tmp/p2mr-rust.json
python3 contrib/devtools/merge-p2mr-pqc-witness-vectors.py \
  --python /tmp/p2mr-python.json --rust /tmp/p2mr-rust.json \
  --output /tmp/p2mr-data/p2mr_pqc_witness_vectors.json
python3 contrib/devtools/update-p2mr-v1-manifest.py
python3 contrib/devtools/update-p2mr-v1-manifest.py --check
```

License
--------

The data files in this directory are distributed under the MIT software
license, see the accompanying file COPYING or
https://www.opensource.org/licenses/mit-license.php.
