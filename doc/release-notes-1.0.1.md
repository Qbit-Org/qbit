Qbit v1.0.1 Release Notes
=========================

Qbit: Post-quantum peer to peer digital value

Qbit version v1.0.1 is available from the release page for that version.

This is a mainnet maintenance release built from the reviewed `1.x.x` branch
changes since the signed `v1.0.0` tag. It focuses on wallet and qbit-qt
reliability, the wallet fallback-fee default, visibility of consumed PQC
signing capacity, validation and fuzz tooling, and release and CI hardening.
It also carries fixes from the v1.0.1 release review: a standard-policy limit
on P2MR stack memory, signature caching for P2MR data signatures, `headers`
messages that stay within the message size limit, and a vendored PQC library
update that clears its own copies of secret-key material from the stack it
releases. qbit's HD key derivation still leaves seed material on the stack
(see Known limitations). The updated library also performs consensus
signature verification; keys, signatures, and verification results are
unchanged.
It adds one standardness rule for P2MR spends, but contains no consensus rule
change, no scheduled network activation, no change to the mainnet or testnet4
network identity, and no wallet database format change.

Please report bugs using the Qbit issue tracker.

How to Upgrade
==============

Shut down the older qbit process and wait until it exits completely before
installing v1.0.1. Then install the new binaries from the GitHub Release page.

Existing v1.0.0 mainnet and testnet4 data directories, wallets, and wallet
backups continue to work without a reindex, chain reset, or wallet migration.

On Linux, replace the installed `qbit`, `qbitd`, `qbit-qt`, `qbit-cli`,
`qbit-tx`, `qbit-util`, and `qbit-wallet` binaries, and any other files
installed from the previous release archive, with the versions from the new
archive.

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
- An `encryptwallet` call that overlaps another encryption of the same wallet
  now fails deterministically with error code `-15`
  (`RPC_WALLET_WRONG_ENC_STATE`), the code a call on an already encrypted
  wallet already returned. Previously it could fail with `-16` "Failed to
  encrypt". Other `encryptwallet` failures keep their previous error codes
  (#183).
- Standard policy now rejects a P2MR v1 spend whose main stack plus alt-stack
  holds more than 1 MiB after any opcode, with the reject reason
  `mempool-script-verify-flag-failed (Standard P2MR stack byte limit
  exceeded)` and no peer penalty. Only scripts that copy stack elements can
  reach the limit. Such a spend is still consensus-valid, so a block that
  contains it is still accepted, and nodes running v1.0.0 still relay it.
  Wallet signing and PSBT finalization check the same standard rules and
  report such a spend as incomplete (#263, refs #257).

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
  transaction on the batched path reuses its witnesses. Signing that falls
  back to the serial path does not (see Known limitations) (#163, refs #155).
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
- Wallet encryption now checks that the wallet is not already encrypted, and
  validates its PQC state, under the wallet locks, so two overlapping
  encryption requests can no longer both proceed and abort the process. A new
  master key is kept in memory only after it has been written inside a
  database transaction, and a failed write aborts that transaction. Readers of
  the active descriptor managers now hold the wallet lock. If another request
  encrypts the wallet first, qbit-qt's Encrypt Wallet dialog reports that the
  wallet was already encrypted and the entered passphrase was not used. There
  is no wallet format or encryption semantics change (#183, fixes #179).

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
- A successful fee bump now shows the PQC usage it consumed
  in a dismissible panel above the transaction list, labelled with the
  replacement txid and the local commit time, so the report remains visible
  on desktops without a notification backend (no D-Bus, no tray). The
  existing non-modal information message and modal warning are unchanged
  (#177, fixes #168).
- Encrypting an existing wallet from qbit-qt runs on a worker
  thread. The passphrase dialog stays open as a busy indicator and ignores a
  second submit, GUI reads that would block on the wallet lock are served
  from cached state or deferred until encryption finishes, and unlock,
  fee-bump, and payment-request actions are refused or queued while it runs.
  A clean failure still reports "Your wallet was not encrypted"; an exception
  after the database may already have been written stops the application
  rather than misreporting the outcome. The wallet's own encryption logic is
  unchanged (#178, fixes #172).
- While an existing wallet is being encrypted, repainting the transaction list
  or overview page resolves address labels from the address book rows qbit-qt
  already holds, instead of waiting for the wallet lock until encryption
  finishes (#182, fixes #180).

### Validation and performance work

- Successful P2MR PQC transaction-signature checks are cached in a new PQC
  domain of the shared signature cache, following the Schnorr pattern. Only a
  verified success is inserted, so a fresh mempool admission verifies each PQC
  signature once in the policy pass and reuses the result in the consensus
  pass. Interpreter checks, validation-weight charges, script flags, and the
  full-script cache are unchanged, data signatures were left uncached, and a
  benchmark for the two-pass admission pattern was added (#162). #265 below
  caches data signatures in a separate domain.
- No throughput or initial block download measurement accompanies this
  release. The signature caches and descriptor batching are described by their
  behavior only; this release does not claim a speedup. The #268 entry below
  gives the measured signing and verification cost of the PQC library update.
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
- The fuzz coverage checker's `pqc_sign_refused` source anchor
  is re-anchored to the current refusal line, and anchor resolution gained
  its own tests. This restores the `--anchors-only` check; it does not by
  itself produce instrumented coverage evidence (#176, refs #173).

### Mempool, P2P, and PQC library hardening

- Standard policy limits the bytes a P2MR v1 script holds on its main stack
  plus alt-stack to 1 MiB after each opcode, through the new
  `SCRIPT_VERIFY_P2MR_STACK_BYTES` flag and its own script error. Consensus
  bounds the runtime stack only by its 1,000-item count, and each initial
  witness item may be up to 16 KiB, so element-copying opcodes could grow one
  input's stack to about 16 MiB without any validation-weight cost. The limit
  is above 128 KiB of initial items plus 1,000 maximum-size pushes, so only
  scripts that copy stack elements reach it. The P2MR v1 profile, the
  conformance corpus, and the independent oracle cover the new limit. Block
  validity is unchanged (#263, refs #257).
- `OP_CHECKDATASIGPQC` and `OP_CHECKDATASIGADDPQC` checks now use the
  signature cache, like P2MR transaction signatures since #162. A data
  signature does not commit to the spending transaction, so a peer could
  resubmit one valid signature in an unlimited number of mutated transactions,
  each costing a full SLH-DSA verification during mempool admission. Such
  replays now cost one verification. Only verified successes are cached, in a
  separately salted domain, so an entry for a transaction signature can never
  satisfy a data-signature check or the reverse. Validity, validation weight,
  script errors, and script flags are unchanged. Failed checks are still not
  cached (see Known limitations) (#265, refs #259).
- A block header carries its whole AuxPoW proof, including the parent chain's
  coinbase transaction, so a reply to `getheaders` covering blocks with large
  AuxPoW payloads could exceed the 4,000,000 bytes a peer accepts in one
  message. The receiving peer dropped the connection, so new or catching-up
  nodes could not sync headers past those blocks. Nodes now end a `headers`
  message before it would exceed that limit, always sending at least one
  header, and announce a new block with `inv` when its headers do not fit in
  one message. A node keeps requesting headers after a `headers` message with
  2,000 headers, as before, or of at least 2,000,000 bytes, since such a
  message may have been cut short. This applies to normal headers sync and to
  low-work headers sync (presync and redownload). Replies made of ordinary
  headers are unchanged: 2,000 headers per message, byte for byte as before.
  The serving node must run v1.0.1 for its replies to fit. A receiving node
  running v1.0.0 takes a message cut short for size as the end of the peer's
  headers: during low-work headers sync it does not continue past it, and
  otherwise it continues only at the next block announcement. Some cases can
  still stall headers sync between v1.0.1 nodes (see Known limitations).
  Consensus rules and the protocol version are unchanged (#266, refs #258).
- The vendored libbitcoinpqc library is updated from v0.3.0 to v0.3.2.
  Generating, importing, or signing with a PQC key previously left copies of
  the secret SLH-DSA seeds, and hashing scratch derived from them, in stack
  memory the library had released. The library's key generation, secret-key
  validation, and signing now wipe those copies and overwrite the stack they
  used before returning. This does not reach the stack frame of qbit's own HD
  key derivation (see Known limitations). The library also reports a failed
  memory allocation during key generation or signing as a distinct
  out-of-memory error, and signing with a secret key that fails validation as
  a key error rather than a signature error. qbit treats every library error
  as a failed operation, as before, so wallet and RPC behavior does not
  change. Keys and signatures are byte-identical to those produced by v1.0.0,
  and verification accepts and rejects the same signatures. #268 reports that
  key generation, secret-key validation, and signing take about 10 to 12%
  longer and verification about 1% longer. Those figures were measured on
  v0.3.1, whose production code differs from v0.3.2 only in error mapping and
  in the stack-wipe size of unoptimized builds. Each key generation,
  validation, or signing call now needs about 17 KiB of free stack (#268,
  refs #260).

### Release engineering, CI, and documentation

- Reworked the Pages workflow that publishes the RPC documentation at
  docs.qbit.org to build a versioned site. It builds each immutable, signed
  non-candidate release from its tag target next to rolling development
  documentation, verifies the release signer against the release key policy,
  and requires each build's reported project version to match its tag.
  Release candidates are not published to the versioned site. The versioned
  site is not deployed yet; docs.qbit.org still serves the documentation
  deployed by the earlier workflow (#148).
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
- Reorganized the P2MR v1 consensus profile (`doc/consensus/p2mr-v1.md`) for
  readability and fixed its hash-type table, whose combined `SIGHASH_*` rows
  were cut off when rendered. Every requirement, value, and error name is
  unchanged (#252). Later edits reword its signature-counter sentence to
  separate wallet-held keys from caller-supplied keys (#264) and add the 1 MiB
  stack-byte policy limit (#263); neither changes a consensus requirement.
- Added a non-normative note, `doc/reference/p2mr-signature-security.md`, on
  how the security margin of the `SLH-DSA-SHA2-128s-bounded30` signature
  profile depends on how many signatures a key produces. A key keeps the full
  128-bit classical level up to about `2^26` signatures, and about 118 bits at
  the `2^30` per-key limit; rotate high-volume keys well before the limit. The
  note includes a script that reproduces these figures. The help for
  `signrawtransactionwithkey` and `descriptorprocesspsbt` now states that PQC
  signature counts for keys passed to these RPCs are not tracked across calls.
  Each call treats every key as unused, so the caller must keep each key
  within its limit of 1,073,741,824 signatures. The `importdescriptors` help
  now states that an imported key's counter does not include signatures made
  outside this wallet. Signing behavior is unchanged (#264, refs #261).
- The vendored libbitcoinpqc tree now equals its upstream release tag. The
  `RUSTSEC-2026-0204` `crossbeam-epoch` lockfile update that qbit carried on
  top of v0.3.0 is upstream since v0.3.1, so the subtree check no longer
  accepts any downstream change (#268).
- Stabilized the REST chain-info comparison and Qt shutdown tests (#137,
  #149, #164).

Release verification
====================

Download artifacts only from the release page linked through qbit.org. Verify
`SHA256SUMS.asc` against `SHA256SUMS`, then verify each downloaded artifact
against `SHA256SUMS`. The release page is the source of truth for supported
platform artifacts, signer policy, builder attestations, and the final release
state.

Mainnet publication requires completed qbit P2MR v1 conformance evidence for
the exact signed tag target. The release page states the corpus digest, source
commit, and independent oracle report digest. Those values are produced from the
tagged commit, so they cannot be recorded in this file.

Known limitations
=================

- The PSBT operations dialog and the Sign/Verify dialog write a key's PQC
  limit state differently: the PSBT dialog uses a translatable label such as
  "Normal", while the Sign/Verify dialog shows the raw state name such as
  "NORMAL". The meaning is identical; only the wording differs (#166).
- Unsigned-platform waiver: the macOS and Windows artifacts for this release
  are not code-signed or notarized. They are published with `-unsigned` in
  their names, and codesigning payloads are not published. macOS Gatekeeper
  and Windows SmartScreen may warn when they are first opened. The signed
  release tag, the signed `SHA256SUMS`, and the builder attestations still
  apply to every artifact; verify downloads as described in "Release
  verification". This waiver remains until macOS and Windows signing accounts
  are available (#70).
- Fresh fuzz evidence on the release source is required before the release
  is tagged. It is tracked in #173 and #174 and is not recorded in this file.
  The earlier evidence summarized below was produced before #263, #265, #266,
  and #268 merged, and does not cover their changes:
  - #263 and #265 change the script interpreter that the `p2mr_script` target
    runs, and #263 adds its new flag to that target's fuzzed flag sets.
  - #268 replaces the vendored library whose key generation, secret-key
    validation, signing, and verification the `pqc` and `p2mr_script` targets
    call.
  - #266 changes `headers` handling in `net_processing`, which none of the
    six qbit-specific targets reaches. The inherited `process_message` and
    `p2p_headers_presync` targets reach it but were not part of that
    evidence. No fuzz target reaches the PQC domains of the signature cache
    that #162 and #265 use.
  - The other changes merged after the #176 source (#177, #178, #182, #183,
    #252, and #264) touch only wallet, qbit-qt, RPC help, test, and
    documentation code, which none of the six qbit-specific targets reaches.

  The earlier evidence was produced with LLVM 20.1.8 on the #176 source. The
  llvm-cov coverage checker met every expectation, including the
  `pqc_sign_refused` refusal path. libFuzzer with ASan and UBSan replayed all
  53 seed inputs for the six qbit-specific targets and ran a mutation phase of
  at least 120 seconds per target, with no crashes or sanitizer reports.
  Because SLH-DSA signing is slow, the `p2mr_script` and `pqc` targets reached
  only a few hundred mutated executions under ASan. No multi-hour campaign,
  sanitizer-free libFuzzer run, macOS run, or other LLVM version was used
  (#173).
- Consensus still bounds a P2MR runtime stack only by its 1,000-item count,
  so a block may contain a spend above the 1 MiB standard-policy limit. A
  consensus limit, or a validation-weight charge for copied bytes, needs an
  activated soft fork and is left for a later release (#263, refs #257).
- Failed PQC signature checks are not cached. Anyone holding one valid
  signature can derive unlimited distinct invalid PQC signatures that each
  still cost a full verification, on both the data-signature and
  transaction-signature paths. Because this release does not penalize peers
  that relay consensus-invalid transactions, a peer can cost a node about
  0.5 µs of message-handling and `cs_main` time per witness byte. Discouraging
  peers whose P2MR PQC signatures fail, or budgeting script-validation cost
  per peer, are possible follow-ups (#265, refs #259).
- Large AuxPoW payloads still have these limits, deferred to later releases
  (#266, refs #258):
  - No consensus rule limits the size of an AuxPoW payload yet. Adding one
    needs an activated soft fork.
  - The block index still keeps every AuxPoW payload in memory.
  - Nodes running v1.0.0 still stall or abort headers sync through ranges with
    large AuxPoW headers. They take a message cut short for size as the end of
    the peer's headers, and when they serve headers they still send the
    oversized message, which upgraded nodes also reject.
  - Low-work headers sync still gives up on a peer if the AuxPoW payloads it
    holds while redownloading exceed its existing 36 MB per-peer bound. That
    bound was derived for 2,000-header messages and has not been re-derived
    for messages cut short by size.
  - The block index keeps the first copy of a header it receives, with that
    copy's AuxPoW. Producing a stored copy whose AuxPoW is larger than its
    block's takes a second valid parent-chain proof of work. If a reply is cut
    short just before such a header, the reply can be smaller than 2,000,000
    bytes, and the receiver then treats it as the end of the peer's headers.
    Review of #266 found that, below the minimum chain work, this can
    disconnect an outbound peer during initial block download and stop
    low-work presync at the same height on every retry, even when both nodes
    run v1.0.1.
- The scheduled-validation source selection (#165), the nightly native-fuzz
  mutation phase (#164, #165), and IBD timeout forwarding (#159) are present
  on `1.x.x`, but GitHub schedules run the default branch. Their deployment is
  complete only after the same workflow revisions reach `main` and a
  scheduled run reports the maintained source (#152, #158).
- qbit's own HD key derivation (`DerivePQCKey`) still leaves HD master-seed
  material and HKDF state on the stack it releases, in its own frame, which
  the library's stack wipe (#268) does not reach. The stack-wipe unit test
  checks only for SK_SEED and SK_PRF copies, so its passing `DerivePQCKey`
  case does not cover this. #270, which clears that frame, is not part of
  this release (refs #260).
- When wallet signing falls back to the serial path, for example for a
  transaction that mixes P2MR and non-P2MR inputs, it re-signs the
  already-complete P2MR inputs it owns and consumes fresh signature counters.
  This predates v1.0.1 and is unchanged (#163).
- The v1.0.1 release readiness inspection (#174) exercised a testnet4 wallet on
  macOS. Linux and Windows desktop notification behavior and a packaged-binary
  smoke check on each supported platform are separate release evidence.

Credits and acknowledgements
============================

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this maintenance release.
