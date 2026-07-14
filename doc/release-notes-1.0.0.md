Qbit v1.0.0 Release Notes
=========================

Qbit: Post-quantum peer to peer digital value

Mainnet is here.

Qbit v1.0.0 launches peer-to-peer digital value for the post-quantum era.
From block zero, Qbit is built around quantum-resistant spend authorization,
proof-of-work issuance, and long-horizon self-custody. Post-quantum protection
is a foundation of the network, not a future migration left for holders,
wallets, exchanges, and custodians to coordinate after the fact.

QBT begins with no premine and mining-only distribution under a fixed
210,000,000 QBT cap. Cadence combines open SHA-256 mining with AuxPoW merge
mining, allowing independent miners to participate while giving established
Bitcoin mining infrastructure a direct path to help secure Qbit. P2MR keeps
spend keys hidden until use and authorizes spending with hash-based,
quantum-resistant signatures.

This release carries Qbit from public testnet into its production network. It
is the starting point for a community-run chain designed to protect ownership
over a longer horizon while retaining the open participation, verifiability,
and self-custody expected of peer-to-peer digital value. Read more about the
design and long-term vision at [qbit.org](https://qbit.org/).

Draft launch status
===================

This release note is intentionally checked in before the two launch-time
consensus commitments are finalized. The current source must not be tagged or
published as v1.0.0 until both blockers are resolved:

- replace the development mainnet genesis block and draft ASERT launch anchor
  with the approved, mined mainnet values; and
- replace the conspicuous mainnet AuxPoW chain-ID placeholder with the approved
  production allocation.

The public testnet4 genesis block and AuxPoW chain ID remain unchanged.

How to Upgrade
==============

Shut down the older qbit process and wait until it exits completely before
installing v1.0.0.

Any data created with a pre-launch mainnet genesis block is incompatible with
the launched chain. Remove or move aside pre-launch mainnet chainstate, block,
index, mempool, and peer-discovery data before starting the final v1.0.0
binary. Do not delete wallet files or wallet backups.

Testnet4 operators can continue using the existing testnet4 data directory
with `-testnet4` or `-chain=testnet4`.

Mainnet network identity
========================

Mainnet is the default chain for a standard v1.0.0 build. No chain-selection
flag is required.

| Item | Value |
|---|---|
| Chain option | default, or `-chain=main` |
| Default P2P port | `8355` |
| Default RPC/REST port | `8352` |
| Address HRP | `qb` |
| DNS seed 1 | `flux-mainnet.qbit.org` |
| DNS seed 2 | `phase-mainnet.qbit.org` |
| Archive fallback 1 | `positron-mainnet.qbit.org:8355` |
| Archive fallback 2 | `graviton-mainnet.qbit.org:8355` |
| AuxPoW chain ID | Pending final launch allocation |
| Genesis block | Pending final launch commitment |

Mainnet-capable binaries are the build default. Operators who intentionally
need a binary that rejects mainnet must build with
`-DQBIT_TESTNET_ONLY_RELEASE=ON`. The distribution archive name does not
silently enable that restriction.

Changes since v0.1.2-testnet4
=============================

This release contains all changes after the signed `v0.1.2-testnet4` tag,
together with the mainnet launch configuration completed for v1.0.0. The
principal changes in that range are listed below. The following
`Overall v1.0.0 summary` describes the resulting launch network as a whole.

### P2MR consensus, conformance, and wallet safety

- Published the normative qbit P2MR v1 consensus profile and added a
  reproducible corpus, an independent Rust oracle, exact-release evidence, and
  a fail-closed conformance gate (#118).
- Activated corrected P2MR validation-weight accounting on testnet4 at block
  60,000; v1.0.0 applies the corrected accounting on mainnet from genesis
  (#109).
- Rejected malformed future P2MR leaf versions in qbit-qt, bound imported
  proofs to the expected signer, bounded proof parsing, and reduced portable
  proof exports to verifier-required data (#82, #85, #95, #96).
- Preserved wallet-local PQC usage and budget reporting when a Qt signing
  attempt consumes a reservation and later fails (#128).
- Expanded restricted-output `fundrawtransaction` coverage so disallowed
  prebuilt outputs fail before wallet funding (#86).

### Consensus, mining, and peer-to-peer hardening

- Rejected AuxPoW substitutions whose parent proof is valid for the wrong qbit
  block height (#106).
- Cached Cadence lane predecessors to avoid repeated chain walks during
  lane-local difficulty processing (#108).
- Based assume-valid burial estimates on aggregate Cadence work and based
  peer-to-peer anti-DoS thresholds on recent chainwork (#88, #89).
- Added regression coverage that reliably reaps nodes after expected startup
  failures (#111).

### Wallet and qbit-qt reliability

- Fixed wallet shutdown lifetime and model-adoption ordering issues that could
  deadlock qbit-qt (#87, #90).
- Prevented wallet progress dialogs from being closed while their operation is
  still active (#97).
- Prohibited test-only PQC runtime controls from production qbit builds (#107).

### Release engineering, CI, and public documentation

- Bound builder attestations to the reconstructed archive from the signed-tag
  source, made resumed draft notes deterministic, and replaced automated
  publication with a validation-first local publisher (#84, #116, #117).
- Required published releases to become immutable and rechecked their final
  asset names and digests after publication (#117).
- Split release-tag creation from immutability policy, recorded public trust
  data for v0.1.2-testnet4, and enabled the protected v1.0.0 validation line
  (#66, #68, #73).
- Split the MSan dependency build, resolved high- and medium-severity scanner
  findings, and added stronger release and source-policy test coverage
  (#67, #72, #74).
- Updated the generated RPC documentation to display the qbit version and full
  project logo (#119).

### Mainnet launch configuration completed for v1.0.0

- Changed the release version to v1.0.0 and made mainnet the default chain in
  ordinary source and Guix builds. Testnet-only binaries remain an explicit
  opt-in build mode.
- Added production mainnet DNS seeds, compiled fixed seeds, and documented
  archive-node fallbacks while preserving the existing testnet4 identity.
- Set the launch blockchain and chainstate size estimates to zero so initial
  storage guidance does not imply pre-existing mainnet history.
- Added a fail-closed mainnet posture validator and a phase-aware Core Checks
  job. Staging accepts exactly the declared genesis/ASERT and AuxPoW chain-ID
  blockers; final CI and the publisher require complete success and reject
  incomplete bootstrap wiring or missing default-mainnet assertions.
- Added mainnet operator, mining-pool, exchange, bootstrap, compatibility, and
  release-verification guidance.

Overall v1.0.0 summary
======================

### Consensus and authorization

- qbit launches with the versioned qbit P2MR v1 consensus profile.
- P2MR spend authorization uses the bounded SLH-DSA-SHA2-128s profile and
  qbit-specific commitment and signature domains.
- The independently reproducible P2MR v1 conformance corpus, Rust oracle, and
  commit-bound release evidence gate the release.
- Corrected P2MR validation-weight accounting is active on mainnet from
  genesis.
- Restricted-output mode is active from genesis for public launch-chain
  spendable outputs.

### Mining

- Mainnet uses a 60-second aggregate Cadence target split between a 75-second
  permissionless lane and a 300-second AuxPoW lane.
- Both lanes use independent ASERT difficulty tracking with a two-hour
  half-life.
- Permissionless mining uses `getblocktemplate` and `submitblock`.
- Merged mining uses `createauxblock` and `submitauxblock`; pool software must
  follow the commitment order and chain ID returned by the node.

### Bootstrap and archive operation

- Mainnet ships two DNS seed hostnames and two compiled fixed seed addresses.
- Project-operated archive nodes are published as explicit
  `-connectarchive` fallbacks for degraded automatic discovery.
- Full block and witness history remains the default operating mode.
- Archive nodes advertise `NODE_ARCHIVE`; witness pruning is explicit opt-in
  behavior and advertises `NODE_WITNESS_PRUNED`.

### Release security

- Mainnet publication fails closed unless the signed tag target has a distinct
  production AuxPoW chain ID, final sourced genesis/ASERT data, exact bootstrap
  seed generation, and tested default-mainnet build behavior.
- Release source is bound to a verified signed annotated tag and a distinct
  trusted validation ref.
- Builder attestations bind each counted artifact set to the reconstructed
  source archive.
- Release publication is performed by the validation-first local publisher.
- Publication requires an immutable GitHub Release and revalidates the final
  asset names and digests after immutability is observed.

Compatibility
=============

qbit is not wire-, consensus-, address-, wallet-, or data-directory-compatible
with Bitcoin Core. Bitcoin addresses and Bitcoin payment URIs are not valid
qbit payment destinations.

Public testnet4 remains available with:

```bash
qbitd -testnet4
qbit-cli -testnet4 getblockchaininfo
```

Release verification
====================

Download artifacts only from the release page linked through qbit.org. Verify
`SHA256SUMS.asc` against `SHA256SUMS`, then verify each downloaded artifact
against `SHA256SUMS`. The release page is the source of truth for supported
platform artifacts, signer policy, builder attestations, and the final release
state.

Known issues
============

The checked-in P2MR v1 integration support matrix is a release gate. Mainnet
publication requires exact-release evidence for every component designated as
required by that matrix.

Credits and acknowledgements
============================

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for the qbit mainnet launch.
