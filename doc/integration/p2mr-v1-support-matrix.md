# qbit P2MR v1 Integration Support Matrix

> This file is generated from `p2mr-v1-support-matrix.json`. The checked-in
> inventory is a draft planning artifact, not final release evidence. Mainnet
> publication requires a separate finalized snapshot for the exact signed tag target.

- Profile: `qbit-p2mr-v1`
- Profile version: `1`
- Status: `draft`
- Corpus manifest SHA256: `36e69d48387d7e9f36e9cfe3eef939cf375137cb6e45af1514345ea969b7e62e`

| Component | Category | Owner/contact | Version | Profile | Result | Release surface | Evidence | Limitations | Reviewed at |
|---|---|---|---|---|---|---|---|---|---|
| qbit consensus validation | reference-implementation | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Must be rerun on the exact signed release tag target. | — |
| qbit descriptor wallet | wallet | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Descriptor creation, expansion, address derivation, and spend behavior require exact-release evidence. | — |
| qbit watch-only pubkey database workflow | wallet | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Export/import, watch-only recognition, and recovery require exact-release evidence. | — |
| qbit raw transaction signing | signer | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | PQC key expressions, sighash modes, and final witness construction require exact-release evidence. | — |
| qbit PSBT encode/decode/sign/finalize flow | psbt-tool | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Dedicated and proprietary P2MR PSBT fields require end-to-end exact-release evidence. | — |
| qbit Qt send/sign/verify surfaces | wallet | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Only P2MR-applicable Qt surfaces belong in final release evidence. | — |
| qbit mining payout construction and block validation | miner-pool | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Coinbase payout creation and validation require exact-release pool/miner evidence. | — |
| Python P2MR v1 corpus generator | corpus-generator | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Deterministic regeneration must be shown for the exact release corpus. | — |
| Rust P2MR v1 corpus generator | corpus-generator | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | Deterministic regeneration must be shown for the exact release corpus. | — |
| Standalone qbit P2MR v1 oracle | alternative-validator | Qbit-Org/qbit | — | qbit-p2mr-v1 | not-tested | supported | — | This is a standalone corpus oracle, not a full node or general-purpose consensus validator. | — |
| No external exchange integration claimed | exchange | No external owner claimed | — | qbit-p2mr-v1 | not-applicable | not-claimed | — | A guide exists, but no third-party exchange implementation has supplied conformance evidence. | — |
| No external explorer integration claimed | explorer | No external owner claimed | — | qbit-p2mr-v1 | not-applicable | not-claimed | — | No third-party explorer implementation has supplied qbit P2MR v1 conformance evidence. | — |

`not-claimed` means qbit makes no mainnet support claim for that row. It is
not a passing test result. A finalized release snapshot must mark every claimed
surface `supported` and `pass`, with stable public evidence. Required in-tree
rows must set `version` to the exact release source commit; external rows use the
exact version of the component that was tested.
