Qbit v0.1.1-testnet4 Release Notes
===================================

Qbit: Post-quantum peer to peer digital value

Qbit version v0.1.1-testnet4 is available from the release page for that
version.

This is a public testnet4 maintenance release based on the changes since
v0.1.0-testnet4. It preserves the reset testnet4 lineage from v0.1.0 and
focuses on AuxPoW mining compatibility and upgrade behavior, wallet and PQC
signing reliability, Qt send responsiveness and status visibility, and public
release/CI hardening.

Testnet-era release artifacts are for public testnet use only unless the
release page explicitly says otherwise. Qbit mainnet is not launched. Do not
treat any in-tree mainnet genesis block, hash, seed placeholder, or endpoint
placeholder as an official mainnet launch commitment.

Testnet coins have no economic value, and the public testnet may be reset or
replaced during rehearsal.

Please report bugs using the Qbit issue tracker.

How to Upgrade
==============

Shut down the older qbit process first and wait until it exits completely.
Then install the new binaries from the GitHub Release page.

This release does not require a testnet4 chain reset for nodes upgrading from
v0.1.0-testnet4.

On Linux, replace the existing `qbitd`, `qbit-cli`, `qbit-tx`, `qbit-util`,
and `qbit-wallet` binaries with the new versions.

On macOS, replace the installed Qbit application bundle or unpack the updated
archive into the desired location.

On Windows, run the installer if one is provided for the release, or replace
the unpacked binaries with the new release artifacts.

Compatibility
=============

The public Qbit testnet4 chain is selected with:

```bash
qbitd -testnet4
qbit-cli -testnet4 getblockchaininfo
```

Official testnet release binaries are expected to reject no-flag mainnet
startup and explicit `-chain=main` startup. Use `-testnet4` or
`-chain=testnet4` for the public testnet.

Supported and tested platforms for this release are the artifacts attached to
the GitHub Release page. The release page is the source of truth for available
platform builds, checksums, signatures, and attestations.

Public testnet4 network identity remains the v0.1.0-testnet4 reset testnet4
identity unless the release page explicitly says otherwise.

Mining pools and AuxPoW adapters should upgrade before the testnet4 AuxPoW
display-commitment activation height. `createauxblock` now reports the active
commitment byte order and the activation height so pool software can follow the
node result instead of inferring the encoding.

The AuxPoW display-commitment change is a scheduled testnet4 consensus rule
transition at height `20500`. Nodes and mining software that remain on older
rules after that height may be unable to follow corrected AuxPoW blocks.

| Item | Value |
|---|---|
| Chain flag | `-testnet4` or `-chain=testnet4` |
| Default P2P port | `48355` |
| Default RPC/REST port | `48352` |
| Address HRP | `tq` |
| AuxPoW chain ID | `31430` |
| AuxPoW display-commitment activation height | `20500` |

Notable changes
===============

### Consensus and mining

- Corrected the AuxPoW parent-coinbase commitment byte order used by merged
  mining templates and validation.
- Preserved existing testnet4 AuxPoW history by validating the original
  internal byte order before height `20500` and the corrected display byte
  order at and after height `20500`.
- Added `commitmentorder` and `commitmentactivationheight` fields to
  `createauxblock` results. Before activation the commitment order is
  `internal`; at activation and later it is `display`.
- Added regtest control for the AuxPoW commitment transition through
  `-testactivationheight=auxpowcommitment@<height>` and covered the
  n-1/n boundary with functional and unit tests.

### Node operation and upgrade behavior

- Archive nodes with legacy AuxPoW block-index entries can recover missing
  persisted AuxPoW payloads from retained block files during startup.
- Legacy pruned datadirs that are missing both persisted AuxPoW payloads and
  historical block data now trigger a one-time automatic full reindex/resync so
  the node can redownload and revalidate the missing AuxPoW history.
- `-reindex-chainstate` is rejected for that legacy pruned AuxPoW recovery
  path because it cannot restore missing historical block data. Use a full
  reindex/resync when the node reports this condition.

### Wallet, RPC, and PQC signing

- Added wallet RPC `signdatapqchash` for signing a caller-supplied 32-byte
  hash with a PQC key committed by a wallet-owned P2MR address.
- Added utility RPC `verifydatapqchash` for verifying those P2MR/PQC data-hash
  signature proofs without requiring wallet access.
- Hardened P2MR data-hash signing so scriptPubKey manager lookup failures do
  not fall through to the wrong signing context.
- For multi-leaf P2MR data-hash signing, the wallet now continues to later
  matching single-key leaves after a runtime PQC signing failure on an earlier
  matching leaf. Explicitly selecting a failing leaf still returns a signing
  failure.
- Authenticated encrypted PQC key records and improved fast restore/loading of
  persisted PQC keys.
- Added phase-aware signing progress for transaction preparation, PQC counter
  reservation, input signing, and finalization.
- Added default-on parallel P2MR/PQC wallet signing, controlled by
  `-walletpqcparallel` and `-walletpqcsignthreads`, with serial fallback for
  ineligible transactions.
- Batch-reserved PQC signature counters for parallel signing, assigned
  deterministic counters to worker jobs, and finalized witnesses after raw PQC
  signatures complete.
- Reduced signing-provider collection overhead for transactions with many P2MR
  inputs.
- Plaintext descriptor PQC records now load into a pending validation state and
  are fully validated after wallet load before private signing use.
- PQC signing, send/sign RPCs, and wallet encryption are blocked while
  plaintext PQC key validation is pending or failed.
- `getwalletinfo` reports `pqc_key_validation` status and progress fields so
  operators can see whether plaintext PQC key validation is pending, complete,
  or failed.
- Added PQC and Qt send-preparation timing logs to make slow-signing diagnosis
  easier.
- Aligned the public RPC atomic unit naming with the GUI's `bits` terminology.

### Qt

- Moved Qt send preparation off the GUI thread so large P2MR/PQC transactions
  no longer block the interface while signing work is prepared.
- Made send cancellation stop in-flight asynchronous preparation.
- Shows phase-aware send-preparation labels and progress for PQC counter
  reservation, input signing, and transaction finalization.
- During Qt send preparation, Cancel remains available until PQC counters are
  reserved. After reservation, the preparation dialog removes Cancel and
  finishes preparing the transaction; users can still decline the final send
  confirmation before broadcast.
- Hid the receive-address type selector when P2MR is the only available receive
  type.
- Prevented stale sync-progress displays from reaching a visible `100%` before
  the node has actually completed synchronization.
- Shows plaintext PQC key-validation status and encryption guidance for
  unencrypted wallets.
- Uses a theme-aware overview background logo so the GUI remains legible in
  light and dark themes.
- Shows the Qt client version in the status bar next to the display unit
  selector.

### Release and CI

- Bumped release metadata to `v0.1.1-testnet4`.
- Added and hardened public contribution templates, public contribution
  guidance, and release-tag signature/ruleset documentation.
- Added public Core Checks and trusted-runner gating, including release
  validator coverage for retained public release tests.
- Improved local release publication linkage fallback handling and release tag
  signature enforcement documentation.

Known issues
============

No new release-specific known issues are added by v0.1.1-testnet4. Testnet4
remains a public rehearsal network and may still be reset or replaced during
the testnet era.

Credits
========

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this release.
