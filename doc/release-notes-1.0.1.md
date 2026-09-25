Qbit v1.0.1 Release Notes
=========================

Qbit: Post-quantum peer to peer digital value

Qbit version v1.0.1 is available from the release page for that version.
Release candidates carry an `-rc<N>` suffix, for example `v1.0.1-rc1`, and are
published as pre-releases.

This is a mainnet maintenance release built from the reviewed `1.x.x` branch
changes since the signed `v1.0.0` tag. It focuses on wallet and qbit-qt
reliability, the wallet fallback-fee default, visibility of consumed PQC
signing capacity, validation and fuzz tooling, and release and CI hardening.
It contains no consensus rule change, no scheduled network activation, no
change to the mainnet or testnet4 network identity, and no wallet database
format change.

Please report bugs using the Qbit issue tracker.

How to Upgrade
==============

Shut down the older qbit process and wait until it exits completely before
installing v1.0.1. Then install the new binaries from the GitHub Release page.

Existing v1.0.0 mainnet and testnet4 data directories, wallets, and wallet
backups continue to work without a reindex, chain reset, or wallet migration.

On Linux, replace the existing `qbitd`, `qbit-cli`, `qbit-tx`, `qbit-util`,
and `qbit-wallet` binaries with the new versions.

On macOS, replace the installed Qbit application bundle or unpack the updated
archive into the desired location.

On Windows, run the installer if one is provided for the release, or replace
the unpacked binaries with the new release artifacts.

Behavior changes to review before upgrading
-------------------------------------------

- The wallet `-fallbackfee` default changed from disabled to the minimum relay
  fee rate. Operators who relied on transaction creation failing when no fee
  estimate is available must set `-fallbackfee=0` explicitly (#151).
- `gettransaction`, `listtransactions`, and default `listsinceblock` output
  now include a fee-only `send` entry, with `amount` of zero and a negative
  `fee` and without `address`, `label`, or `vout`, for a self-transfer whose
  outputs are all change. Integrations that assume every `send` entry has an
  address or a non-zero amount should be checked (#150).

Compatibility
=============

qbit is not wire-, consensus-, address-, wallet-, or data-directory-compatible
with Bitcoin Core. Bitcoin addresses and Bitcoin payment URIs are not valid
qbit payment destinations.

Mainnet remains the default chain for a standard build. The mainnet network
identity is unchanged from v1.0.0:

| Item | Value |
|---|---|
| Chain option | default, or `-chain=main` |
| Default P2P port | `8355` |
| Default RPC/REST port | `8352` |
| Address HRP | `qb` |
| AuxPoW chain ID | `47` |
| Genesis block | `0000000000004d60aa5d46013991d0a0e2995d89ee98e53068ae196d763e79f2` |

Public testnet4 remains available with:

```bash
qbitd -testnet4
qbit-cli -testnet4 getblockchaininfo
```

Mainnet-capable binaries are the build default. A binary that rejects mainnet
must be built with `-DQBIT_TESTNET_ONLY_RELEASE=ON`; the distribution archive
name does not enable that restriction.

Supported and tested platforms for this release are the artifacts attached to
the GitHub Release page. The release page is the source of truth for available
platform builds, checksums, signatures, and attestations.

Changes since v1.0.0
====================

This release contains all changes merged to `1.x.x` after the signed `v1.0.0`
tag. Pull request numbers refer to the Qbit-Org/qbit repository.

### Wallet fixes

- Removed a wallet/SQLite lock cycle that could freeze qbit-qt immediately
  after a correct passphrase was entered. Address-availability changes are now
  published only after descriptor locks and database transactions are
  released, unlock returns promptly, and a pending initial P2MR keypool refill
  is completed through deduplicated scheduler steps (#143, fixes #138).
- Descriptor top-ups now stage newly derived scripts and publish wallet
  ownership and cache updates only after the backing database transaction
  commits. A top-up inside a caller-owned transaction publishes once on
  commit, and an abort restores descriptor, keypool, cache, and PQC state
  (#144, fixes #139). Top-up publication was further made commit-atomic and
  lifetime-safe, and reservation notifications are delivered after the
  descriptor lock is released (#143, #144).
- Fee-bearing self-transfers whose outputs are all classified as change now
  appear once in wallet history. The GUI shows a "Payment to self" row with
  the net fee debit, and the transaction RPCs return a fee-only `send` entry.
  `listsinceblock` with `include_change=true` still returns the output-level
  entries. Balances and UTXO accounting are unchanged (#150, fixes #147).
- A transaction that spends from more than one P2MR descriptor now batches
  counter reservations per descriptor instead of falling back to one durable
  counter commit per signature for the first descriptor. Strictly foreign
  inputs are skipped rather than failing the plan, a provider never reports a
  transaction complete while a foreign input is still unsigned, and declining
  a signing prompt cancels the whole wallet signing operation. Counters an
  earlier descriptor already committed stay consumed; retrying the same
  transaction reuses its witnesses (#163, refs #155).
- Fee bumping now re-reads live coins and mempool spenders from one snapshot
  before committing a replacement. A replacement whose input is already spent
  by a mempool transaction outside its own replacement lineage, or that is no
  longer final at the current chain tip after a reorg during asynchronous
  signing, is rejected instead of being recorded and then failing to
  broadcast (#163).
- Foreign P2MR witnesses that are already satisfied, including valid
  nonstandard leaves, are recognized as complete instead of incomplete
  during batched signing (#163).
- qbit-qt cancels active send workers before wallet views are torn down and
  joins already-cancelled workers during destruction (#137).

### Fallback fee

- The wallet `-fallbackfee` now defaults to the minimum relay fee rate
  (250 sat/kvB, that is 0.0000025 QBT/kvB) instead of being disabled.
  Previously, when the fee estimator had no data, which is the normal state on
  a young chain with an empty mempool, transaction creation failed with
  "Fee estimation failed. Fallbackfee is disabled." Wallets now pay the relay
  floor in that case. The fallback is used only when no smart fee estimate is
  available; live estimates take precedence as soon as the estimator has
  observed confirming transactions, and the final feerate is still clamped to
  at least the node's required and mempool minimum feerates, so the fallback
  cannot underpay relay policy. Set `-fallbackfee=0` to restore the previous
  behavior of failing instead (#151).

### Signing-usage visibility and qbit-qt responsiveness

- PSBT signing started from the PSBT operations dialog runs on a cloned-wallet
  worker instead of the GUI thread, with queued progress for preparation,
  counter reservation, signing, finalization, and verification. Cancellation
  is allowed before a durable PQC counter reservation and disabled after it.
  A PSBT completed after a late cancel is preserved, a cancelled wallet unlock
  is handled, and the dialog reports the PQC signing capacity the attempt
  consumed (#145, fixes #140).
- P2MR fee-bump signing runs off the GUI thread. Signing failure, commit
  failure, and success each present the PQC usage the attempt consumed, and
  cancellation and teardown races were closed (#167).
- Transaction-signing flows preserve and display consumed PQC usage. A shared
  formatter renders the overall state, every affected key with its counter,
  limit, remaining capacity, and limit state, and every usage warning. An
  empty report renders nothing, so an absent report is never shown as zero
  consumption. A failed Send preparation keeps its original reason and
  severity and appends the attempt's usage before the prepared transaction is
  discarded, and the PSBT dialog reports failure outcomes as failures. The
  wallet interface now assigns the usage report before returning a
  transaction-creation error. Portable transactions and PSBTs are unchanged;
  usage stays wallet-local (#167, refs #141).
- Fee-bump preparation dialogs guard the wallet model's lifetime across their
  nested event loops, so unloading the wallet during one of those dialogs no
  longer touches a destroyed model (#167).
- When the Sign/Verify dialog's own verification of a freshly generated P2MR
  data-hash proof fails, the error status now appends the wallet-local PQC
  usage the attempt consumed. No proof JSON is written or exported for a
  rejected proof (#161, refs #129).
- `pending merge` A successful fee bump now shows the PQC usage it consumed
  in a dismissible panel above the transaction list, labelled with the
  replacement txid and the local commit time, so the report remains visible
  on desktops without a notification backend (no D-Bus, no tray). The
  existing non-modal information message and modal warning are unchanged
  (#177, fixes #168).
- `pending merge` Encrypting an existing wallet from qbit-qt runs on a worker
  thread. The passphrase dialog stays open as a busy indicator and ignores a
  second submit, GUI reads that would block on the wallet lock are served
  from cached state or deferred until encryption finishes, and unlock,
  fee-bump, and payment-request actions are refused or queued while it runs.
  A clean failure still reports "Your wallet was not encrypted"; an exception
  after the database may already have been written stops the application
  rather than misreporting the outcome. The wallet's own encryption logic is
  unchanged (#178, fixes #172).

### Validation and performance work

- Successful P2MR PQC transaction-signature checks are cached in a new PQC
  domain of the shared signature cache, following the Schnorr pattern. Only a
  verified success is inserted, so a fresh mempool admission verifies each PQC
  signature once in the policy pass and reuses the result in the consensus
  pass. Interpreter checks, validation-weight charges, script flags, the
  full-script cache, and data signatures are unchanged, and a benchmark for
  the two-pass admission pattern was added (#162).
- No throughput, initial block download, or signing-latency measurement
  accompanies this release. The signature cache and descriptor batching above
  are described by their behavior only; this release does not claim a speedup.
- Header synchronization clamps a negative commitment window, which can occur
  when a chain start is ahead of the local clock, instead of converting it to
  an oversized unsigned bound (#137).
- The `pqc` and `p2mr_script` fuzz targets accept versioned fixture inputs
  that verify and mutate real SLH-DSA signatures and signed P2MR spends, and
  deterministic seed corpora with a manifest were added for the six
  qbit-specific targets. The fuzz runner can require corpus replay for those
  targets and run a seeded libFuzzer mutation phase. CI replays the corpora;
  the nightly native-fuzz job runs the mutation phase once its workflow
  revision reaches `main` (see Known limitations) (#164, #165).
- `pending merge` The fuzz coverage checker's `pqc_sign_refused` source anchor
  is re-anchored to the current refusal line, and anchor resolution gained
  its own tests. This restores the `--anchors-only` check; it does not by
  itself produce instrumented coverage evidence (#176, refs #173).

### Release engineering, CI, and documentation

- Added a Pages workflow for a versioned RPC documentation site. It builds
  each immutable, signed non-candidate release from its tag target next to
  rolling development documentation, verifies the release signer against the
  release key policy, and requires each build's reported project version to
  match its tag. Release candidates are not published to the versioned site.
  The site is not deployed yet (#148).
- The local release publisher fails closed when the paginated release asset
  listing cannot be read, instead of treating an empty or partial listing as
  a valid draft and uploading assets it believed were missing (#170,
  refs #125).
- The Required Merge Gate runs the merge-profile classifier tests and a
  workflow contract before producing routing outputs (#160), and its check-run
  poller retries transient API failures with a bounded budget, paginates check
  runs, and fails closed with a distinct message when checks cannot be read or
  the deadline passes (#171, refs #169).
- Scheduled nightly, IBD, and RPC performance workflows resolve the maintained
  `1.x.x` branch to one commit per run and report the requested ref, resolved
  commit, and actual checkout separately (#165, refs #152). The IBD workflow
  forwards its reserved timeout inputs to the harness and records whether each
  was actually forwarded (#159, refs #158).
- Corrected the v1.0.0 release-trust record to list every job of the original
  Full Validation run with its conclusion, quote the accepted deviation as
  recorded, remove a retained-file reference that did not exist at the tag,
  and separate the historical `v1.0.0` source from later maintenance results
  (#175, fixes #156). The record itself was created by #136.
- Stabilized the REST chain-info comparison and Qt shutdown tests (#137,
  #149).

Release verification
====================

Download artifacts only from the release page linked through qbit.org. Verify
`SHA256SUMS.asc` against `SHA256SUMS`, then verify each downloaded artifact
against `SHA256SUMS`. The release page is the source of truth for supported
platform artifacts, signer policy, builder attestations, and the final release
state.

TODO(maintainer): replace this sentence with the P2MR v1 "Conforms to ...
source commit <SHA>" statement required for mainnet by the release process,
using this release's signed tag target (it differs between rc1 and final).

Known limitations
=================

- The PSBT operations dialog and the Sign/Verify dialog write a key's PQC
  limit state differently: the PSBT dialog uses a translatable label such as
  "Normal", while the Sign/Verify dialog shows the raw state name such as
  "NORMAL". The meaning is identical; only the wording differs (#166).
- TODO(maintainer): platform signing disposition for macOS and Windows
  artifacts (#70). Either record that the artifacts are signed and notarized,
  or record the unsigned-platform waiver applied to this release. Signed tags,
  checksums, and builder attestations apply either way.
- Instrumented fuzz coverage evidence for the release source is not yet
  available. The source-anchor mismatch reported in #173 is a test-tool
  failure, not evidence that PQC verification fails. Its fix (#176, pending
  merge) restores the anchor check, but the llvm-cov coverage run and
  libFuzzer mutation phase still need a clang/LLVM host (#173).
- The scheduled-validation source selection (#165) and IBD timeout forwarding
  (#159) are present on `1.x.x`, but GitHub schedules run the default branch.
  Their deployment is complete only after the same workflow revisions reach
  `main` and a scheduled run reports the maintained source (#152, #158).
- The v1.0.1 release readiness inspection (#174) exercised a testnet4 wallet on
  macOS. Linux and Windows desktop notification behavior and a packaged-binary
  smoke check on each supported platform are separate release evidence.

Credits and acknowledgements
============================

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this maintenance release.
