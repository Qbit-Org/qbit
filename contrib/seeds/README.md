# Seeds

Utilities to generate the fixed-seed blobs compiled into qbit
([src/chainparamsseeds.h](/src/chainparamsseeds.h)).

## Current Repo Policy

qbit ships fixed seeds only from qbit-owned, release-approved inputs. The
current checked-in seed artifacts are:

- `nodes_main.txt`
- `nodes_test.txt`
- `nodes_signet.txt`
- `src/chainparamsseeds.h`

These networks remain placeholders until qbit has release-approved seed inputs.
`nodes_testnet4.txt` contains the public testnet4 reset archive-capable fixed
seeds.

Do not repopulate these files from Bitcoin-derived data sources.

## When qbit Seed Data Exists

For broader seed sets, once qbit-owned crawler outputs are available, the
workflow is:

1. Collect qbit crawler output for the target network into `seeds_*.txt`.
2. Update `PATTERN_AGENT` in `makeseeds.py` to match the accepted qbit user
   agent versions.
3. Confirm the crawler data includes the archive-capable service-bit baseline
   required by `makeseeds.py`:
   `NODE_NETWORK | NODE_WITNESS | NODE_ARCHIVE`.
4. Update `MIN_BLOCKS` in `makeseeds.py` and any `-m/--minblocks` overrides.
5. Filter the qbit crawler output into `nodes_*.txt`.
6. Regenerate `src/chainparamsseeds.h`.

Example commands from `/contrib/seeds` once qbit-owned inputs exist:

```bash
python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt > nodes_main.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_signet.txt > nodes_signet.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_test.txt > nodes_test.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_testnet4.txt > nodes_testnet4.txt
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```
