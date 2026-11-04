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
messages that stay within the message size limit, a vendored PQC library
update and a qbit-side stack wipe that together clear copies of secret-key
material from the stack they release, wallet encryption that a background
keypool refill can no longer deadlock or follow with unencrypted key writes
(wallet files can still keep some unencrypted keys; see Known limitations),
and witness checks for blocks submitted over the IPC mining interface. The
updated library also performs consensus signature verification; keys,
signatures, and verification results are unchanged.
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

If you encrypted a wallet with v1.0.0, especially soon after creating it, its
file may still hold unencrypted PQC private keys, which anyone with the file
or a backup made from it can read without the passphrase (#277, #283). This
release stops new ones from being written, but it does not detect or
re-encrypt the ones v1.0.0 wrote, signing with such a key rewrites its
unencrypted record, and backups copy it. On an encrypted wallet, a non-zero
`pqc_key_validation.plaintext_records` in `getwalletinfo` shows that the
wallet holds such keys; a zero count does not prove that the file holds
none. Consider creating a new wallet with a passphrase using this release,
moving your funds to it, and no longer using the old wallet or its backups.

Downgrading to v1.0.0 remains possible. This release adds no wallet record
types, so v1.0.0 can still open wallets and data directories that v1.0.1 has
used, but a downgraded node loses the fixes in this release, including the
wallet encryption fixes (#277).

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
  address, a `vout`, or a non-zero amount should be checked (#150).
- An `encryptwallet` call that overlaps another encryption of the same wallet
  now fails deterministically with error code `-15`
  (`RPC_WALLET_WRONG_ENC_STATE`), the code a call on an already encrypted
  wallet already returned. Previously it could fail with `-16` "Failed to
  encrypt". Other `encryptwallet` failures keep their previous error codes
  (#183).
- `bumpfee` can now fail where it previously broadcast a replacement: when
  signing changed anything other than the input signatures, and when the
  replacement no longer passes the checks repeated at commit time. Automated
  callers should expect these new `RPC_WALLET_ERROR` failures (see Updated
  RPCs) (#167, includes #146).
- Standard policy now rejects a P2MR v1 spend whose main stack plus alt-stack
  holds more than 1 MiB after any opcode, with the reject reason
  `mempool-script-verify-flag-failed (Standard P2MR stack byte limit
  exceeded)` and no peer penalty. Only scripts that copy stack elements can
  reach the limit. Such a spend is still consensus-valid, so a block that
  contains it is still accepted, and nodes running v1.0.0 still relay it.
  Wallet signing and PSBT finalization check the same standard rules and
  report such a spend as incomplete (#263, refs #257).
- `submitSolution` on the IPC mining interface (`qbit-node -ipcbind`) now
  rejects blocks that fail the coinbase witness checks it used to skip (see
  Mining interface). IPC clients must submit the complete coinbase,
  including its witness; unlike the `submitblock` RPC, `submitSolution` does
  not add the witness reserved value (#289, fixes #278).

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
  released. Unlocking in qbit-qt returns promptly. `createwallet`,
  `loadwallet`, and unlocking in qbit-qt complete a pending initial P2MR
  keypool refill through deduplicated scheduler steps. The `walletpassphrase`
  RPC still completes the refill before it returns, and an unencrypted
  wallet loaded at startup does not resume it (see Known limitations) (#143,
  fixes #138).
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
- Encrypting a wallet while a background P2MR keypool refill was running, for
  example soon after the wallet was created or once enough addresses had been
  handed out to start a refill, could deadlock `encryptwallet` and leave the
  wallet unresponsive. A refill that had read its keys before encryption
  could also write them after it, unencrypted, so the wallet reported itself
  as encrypted and locked while its database held unencrypted PQC private
  keys (`walletdescriptorpqckey` records), and loading the wallet accepted
  them. Encryption now waits for a refill that is already writing keys. A
  refill that read its keys before encryption stops without writing them, as
  a refill of a locked wallet does. Keys added after encryption, including by
  later refills, are stored encrypted. Both bugs date from v1.0.0. The wallet
  file format is unchanged. This release does not detect or re-encrypt
  unencrypted PQC keys that v1.0.0 already wrote (see How to Upgrade)
  (#277).

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

### Updated RPCs

- `bumpfee` now checks that signing changed nothing in the replacement except
  its input signatures. If an external signer, or any other signing step,
  returns a replacement with other changes, `bumpfee` fails instead of
  broadcasting it: an external-signer wallet reports "Transaction incomplete.
  Try psbtbumpfee instead." and other wallets report "Can't sign
  transaction." Fee bumps from qbit-qt use the same check (#167,
  includes #146).
- `bumpfee` revalidates the replacement against the live wallet, chain, and
  mempool when it commits it. It fails if an input is no longer available or
  is already spent, or the replacement no longer spends every original input.
  It also fails if the fee is no longer above the original fee, or no longer
  meets the incremental relay fee, the mempool minimum fee rate, or wallet fee
  policy, including `-maxtxfee`; if the replacement is too large; or, unless
  `-walletrejectlongchains=0` is set, if it no longer meets mempool chain
  limits (#167, includes #146). #163 adds the mempool-spender and finality
  checks (see Wallet fixes).
- `gettransaction`, `listtransactions`, and default `listsinceblock` can
  return a `send` entry without `vout`, `address`, or `label` (see Behavior
  changes) (#150).

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
  cancellation and teardown races were closed (#167, includes #146).
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
  its own tests (#176, refs #173). #270 later moved two other anchored lines
  in `src/crypto/pqc.cpp`. They are re-anchored, and Core Checks now runs the
  `--anchors-only` check, the fuzz runner tests, and the seed-corpus check
  for every source change, so a change that breaks an anchor fails CI
  (#342). These checks do not by themselves produce instrumented coverage
  evidence.

### Mining interface

- `submitSolution` on the IPC mining interface (`qbit-node -ipcbind`) now
  checks the witness commitment of the coinbase the client submits. The block
  template kept the result of the witness checks run when it was created, so
  those checks were skipped for the client's coinbase: the size of the
  witness reserved value, the match between the commitment and the block's
  transactions, and the rule against witness data in a block without a
  commitment. A coinbase that failed any of them could make the node accept a
  block as its tip that its peers reject. Such a block is now rejected and
  `submitSolution` returns false. The `submitblock` RPC and consensus rules
  are unchanged. This is a backport of bitcoin/bitcoin#33745 (#289, fixes
  #278).

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
  used before returning. The library also reports a failed
  memory allocation during key generation or signing as a distinct
  out-of-memory error, and signing with a secret key that fails validation as
  a key error rather than a signature error. qbit treats every library error
  as a failed operation, as before, so wallet and RPC behavior does not
  change. Keys and signatures are byte-identical to those produced by v1.0.0,
  and verification accepts and rejects the same signatures. In measurements
  made for the v1.0.1 release review, key generation takes about 11 to 14%
  longer and signing about 14 to 18% longer. Verification is unchanged where
  SHA-256 uses the x86 SHA-NI backend, and about 6.5% slower on the scalar SHA
  backend, which x86 CPUs without SHA-NI and aarch64, armhf, riscv64, and
  ppc64 Linux builds use. These figures do not cover Apple silicon Macs, which
  hash through CommonCrypto, or secret-key validation; #268's earlier
  measurement of v0.3.1 put validation about 12% slower, like key generation.
  Each key generation, validation, or signing call inside the library needs
  about 17 KiB of free stack (#268, refs #260).
- After each PQC key generation, secret-key validation, signing, and HD key
  derivation call, qbit now overwrites 32 KiB of the stack the call released.
  This clears the HD master-seed material and HKDF state that qbit's own HD
  key derivation (`DerivePQCKey`) left in its stack frame, which the
  library's wipe does not reach, and adds margin to the library's own wipe.
  Each of these calls therefore needs at least 32 KiB of free stack, plus its
  own frames (#270, refs #260).

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
  #268, and #270 merged, and does not cover their changes:
  - #263 and #265 change the script interpreter that the `p2mr_script` target
    runs, and #263 adds its new flag to that target's fuzzed flag sets.
  - #268 replaces the vendored library whose key generation, secret-key
    validation, signing, and verification the `pqc` and `p2mr_script` targets
    call.
  - #270 changes the qbit key wrapper in `src/crypto/pqc.cpp` whose key
    generation, secret-key validation, and signing those two targets call.
  - #266 changes `headers` handling in `net_processing`, which none of the
    six qbit-specific targets reaches. The inherited `process_message` and
    `p2p_headers_presync` targets reach it but were not part of that
    evidence. No fuzz target reaches the PQC domains of the signature cache
    that #162 and #265 use.
  - The other changes merged after the #176 source (#177, #178, #182, #183,
    #252, #264, #277, #289, and #342) touch only wallet, qbit-qt,
    mining-interface, RPC help, test, CI, and documentation code, which none
    of the six qbit-specific targets reaches.

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
- When wallet signing falls back to the serial path, for example for a
  transaction that mixes P2MR and non-P2MR inputs, it re-signs the
  already-complete P2MR inputs it owns and consumes fresh signature counters.
  This predates v1.0.1 and is unchanged (#163).
- PQC signature counters are kept per descriptor. A private key held in two
  descriptors of one wallet has a separate counter in each, and each counter
  is capped on its own, so the wallet does not enforce the `2^30` per-key
  limit across those descriptors. Likewise, the same key in another wallet,
  in a wallet restored from an older backup, or exported with
  `listdescriptors true` counts only its own signatures. This predates
  v1.0.1.
- qbit-qt's Send dialog signs the transaction while preparing it, before the
  confirmation dialog opens. Rejecting the confirmation, or choosing Create
  Unsigned (offered for a wallet with private keys when PSBT controls are
  enabled), discards that signed transaction, but the PQC capacity it
  consumed stays consumed and is not shown unless a usage warning applies. A
  PSBT made with Create Unsigned consumes capacity again when it is signed.
  This predates v1.0.1.
- Concurrent `send` or `sendall` calls, or concurrent
  `walletcreatefundedpsbt` and `walletprocesspsbt` flows, on one wallet can
  select the same coin, because coins are not held locked while PQC signing
  runs. Every call reports success (`complete: true`, with a txid for `send`
  and `sendall`), but only one of the transactions can confirm, and each
  signature still consumes counter capacity. Serialize sending calls per
  wallet, or set `lockUnspents` when funding PSBTs concurrently (#281). The
  qbit-qt Send flow likewise does not check, before committing, whether an
  RPC call spent its inputs while the confirmation dialog was open (#290).
- A new P2MR wallet fills most of its keypool in a refill that runs in the
  background 30 seconds after the wallet is created or loaded, or, for an
  encrypted wallet, at its first unlock (inline when it is unlocked with
  `walletpassphrase`; see the next item). If the node stops before the refill
  finishes, an unencrypted wallet loaded at the next startup through
  `-wallet` or `load_on_startup` does not resume it and watches only its
  first 16 receive and 16 change addresses, so payments to later addresses
  of the same seed, for example from a restored copy, are not seen. An
  encrypted wallet resumes it at its first unlock. If the node may have
  stopped during an unencrypted wallet's first refill, for example within a
  few minutes of creating or loading it, run `keypoolrefill` once the wallet
  is loaded again, and if another copy of the wallet may have used later
  addresses, run `rescanblockchain` afterwards (#284).
- The `walletpassphrase` RPC completes a pending initial refill and tops the
  keypool up to its `-keypool` size before it returns, and `encryptwallet` and
  encryption from qbit-qt derive the new keypool before they finish. Each
  holds the wallet lock meanwhile, which at the default `-keypool` can take
  tens of seconds. Other wallet calls wait, and the wallet's handling of new
  blocks is delayed, which can slow block processing. Unlocking in qbit-qt
  runs a pending initial refill in the background, and does not refill a
  run-down pool at unlock (#304).
- Wallet files can keep key material that encryption should have removed. A
  wallet encrypted by v1.0.0 can hold unencrypted PQC private keys (#283; see
  How to Upgrade). After `encryptwallet`, the deleted unencrypted keys stay
  readable in the file's free space until the file is rewritten, which never
  happens if the process stops while the new keypool is derived (#285).
  `walletpassphrasechange` leaves the master key wrapped with the old
  passphrase in the file's free space (#294). A failed write or erase while
  descriptor ECDSA keys are encrypted is ignored (#296). Treat wallet files
  and backups from before or around an encryption or passphrase change as
  unencrypted; to be safe, create a new wallet with a passphrase using this
  release and move your funds to it.
- `listwalletdir`, qbit-qt's Open Wallet menu, and opening a loaded wallet's
  file through a symbolic or hard link release the exclusive lock on loaded
  SQLite wallets, so a second `qbitd`, `qbit-qt`, or `qbit-wallet` can open a
  live wallet. Two writers lose PQC counter updates and corrupt the wallet
  (#280). `importmempool`, `loadtxoutset`, and qbit-qt's PSBT dialogs can do
  the same when given a loaded wallet's file, and the PSBT save dialog can
  overwrite it (#295). Never let two processes share a wallet directory, and
  never pass a loaded wallet's file to these commands or dialogs.
- PQC signature counters can roll back. Restoring an older backup, or loading
  an older copy of a wallet file, does so with no warning, and the restored
  copy can sign alongside the live wallet (#282). Re-importing a descriptor
  resets the counter of a key whose record failed validation (#279). The
  loader still accepts encrypted key records without a counter tag or with an
  older one, so anyone who can write to the wallet file can roll a counter
  back (#288). Keep only one copy of a wallet that signs.
- Locking does not wait for all background work. `walletlock` does not stop a
  background P2MR keypool refill that is already running, which keeps its
  copy of the master key until it finishes (#286), and it can return while
  copies of decrypted signing keys are still being freed (#287). A qbit-qt
  address-book deletion that coincides with another wallet write can
  deadlock the wallet (#293).
- A local client of the IPC mining interface (`qbit-node -ipcbind`) can stop
  `qbit-node`. When `submitSolution` rejects a block version that has the
  AuxPoW bit set, the template keeps that version, and the next `getBlock` or
  `getBlockHeader` call on it aborts the process (#291). `-ipcbind=unix`
  listens on `qbit-node.sock` in the network's data directory (`<datadir>`
  on mainnet, `<datadir>/testnet4` on testnet4), while the option's help
  names `<datadir>/node.sock` (#292). Restrict access to the IPC socket, pass
  `-ipcbind=unix:<path>` with an explicit path, do not submit AuxPoW versions
  over IPC, and discard a template after such a rejection.
- The depth of the libbitcoinpqc and qbit stack wipes is verified only on
  Linux x86_64 and i686. The unit tests that check them skip Windows and
  sanitizer builds, and CI runs no macOS or ARM unit tests. On macOS the
  library hashes through CommonCrypto, whose SHA context it does not wipe, so
  it relies on the library's 16 KiB stack burn and qbit's 32 KiB wipe to
  clear that context (#268, #270, refs #260).
- The v1.0.1 release readiness inspection (#174) exercised a testnet4 wallet on
  macOS. Linux and Windows desktop notification behavior and a packaged-binary
  smoke check on each supported platform are separate release evidence.

Credits and acknowledgements
============================

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this maintenance release.
