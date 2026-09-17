# qbit fuzz seed corpora

Flat binary seed inputs for the qbit-specific fuzz targets that have no
upstream `qa-assets` corpus:

| Target | Directory |
| --- | --- |
| `asert_chain_transition` | [`asert_chain_transition/`](asert_chain_transition) |
| `asert_edge_cases` | [`asert_edge_cases/`](asert_edge_cases) |
| `asert_math` | [`asert_math/`](asert_math) |
| `auxpow` | [`auxpow/`](auxpow) |
| `p2mr_script` | [`p2mr_script/`](p2mr_script) |
| `pqc` | [`pqc/`](pqc) |

## Provenance

Every seed is produced by [`generate_seeds.py`](generate_seeds.py) from the
case descriptions in that script; no bytes are copied from fuzzer output or
third-party corpora. The seeds, [`MANIFEST.json`](MANIFEST.json) and the
scripts are distributed under the MIT license (see `COPYING`).

`MANIFEST.json` records the size, SHA-256 and meaning of each seed. Limits
enforced by the generator and by [`overlay.py`](overlay.py): at most 16 seeds
per target, 8 KiB per seed, 64 KiB per target and 384 KiB in total. Target
directories contain only seed files.

```sh
test/fuzz/qbit_corpora/generate_seeds.py          # regenerate seeds and manifest
test/fuzz/qbit_corpora/generate_seeds.py --check  # verify committed files
```

## Input formats

Seeds encode the values each harness reads from `FuzzedDataProvider`: byte
arrays and strings from the front of the input, integers from the back.

`pqc` and `p2mr_script` accept two layouts:

- **Legacy** (untagged): the original harness layout, unchanged. It generates
  SLH-DSA keys from input bytes and signs on every run.
- **QBFX version 1** (tagged): `QBFX`, a target tag (`P` for `pqc`, `M` for
  `p2mr_script`), version byte `0x01` and a selector byte, followed by the
  provider layout of the selected body. A selector whose low nibble is `0xF`
  (1/16 of values) runs the legacy generation body on the remaining bytes. Any
  other selector runs the fixture body. The fixture body verifies and mutates
  real keys and signatures that are built once per process, on first use.
  Tagged inputs with another version byte are ignored.

The fixture bodies check that an unmodified fixture verifies. `pqc` also
checks that any modified signature, public key or message is rejected. Legacy
and generation seeds keep key generation and signing covered in every replay.

## Use in CI

[`overlay.py`](overlay.py) copies each seed to
`<fuzz_corpora>/<target>/qbit-<name>` after `qa-assets` is cloned or reused.
The managed names are exactly `qbit-<file>` for each `file` that the current
`MANIFEST.json` lists under that target. A regular file at a managed name is
replaced, so rerunning the overlay updates the seeds in place. All other files
are kept byte-for-byte, including `qbit-*` files that the current manifest does
not list, such as seeds removed from or renamed in the manifest; delete those
from a reused corpus by hand if they are no longer wanted. A target path that
is not a directory, or a symlink, directory or other non-regular file at a
managed name, is an error; all target paths and managed names are checked
before any file is written.
`test/fuzz/test_runner.py --require_qbit_corpus` then fails unless all six
targets are selected, each has at least one regular input file, and the fuzz
binary reports replaying them.
