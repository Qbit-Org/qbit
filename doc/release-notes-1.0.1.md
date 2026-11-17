Qbit v1.0.1 Release Notes
=========================

Qbit: Post-quantum peer to peer digital value

Qbit version v1.0.1 is available from the release page for that version.

This is a mainnet maintenance release built from the `1.x.x` branch changes
since the signed `v1.0.0` tag. It focuses on wallet and qbit-qt
reliability, the wallet fallback-fee default, visibility of consumed PQC
signing capacity, validation and fuzz tooling, and release and CI hardening.
It also carries fixes from the v1.0.1 release review: a standard-policy limit
on P2MR stack memory, signature caching for P2MR data signatures, `headers`
messages that stay within the message size limit, a vendored PQC library
update and a qbit-side stack wipe that together clear copies of secret-key
material from the stack they release, wallet encryption that a background
keypool refill can no longer deadlock or follow with unencrypted key writes
(older wallet files and backups can still hold unencrypted keys; see Known
limitations), and witness checks for blocks submitted over the IPC mining interface. The
updated library also performs consensus signature verification; keys,
signatures, and verification results are unchanged.
Fixes merged during release testing keep loaded wallet files locked, make a
`send` whose coins a concurrent call spent fail instead of reporting success,
resume pending P2MR keypool refills at startup, let `walletpassphrase` refill
P2MR keypools without holding the wallet lock, remove deleted unencrypted keys
from the wallet file right after encryption, make wallet encryption fail when
an unencrypted descriptor key record cannot be removed, re-encrypt the PQC keys
that v1.0.0 left unencrypted in encrypted wallets, keep more small change when
no fee estimate is available, keep PSBT signing results across shutdown, keep a
wallet locked or unlocked when `walletpassphrasechange` changes its passphrase,
stop qbit-qt from aborting when accessibility tools press Send again during a
send confirmation, make it ignore Sign pressed the same way while a PSBT is
being signed, keep it responding while an `encryptwallet` call runs, make it
wait for open dialogs before it quits or unloads a wallet, update the GUI
release builds to Qt 6.8.4, and add debug symbol archives for macOS. Nodes now
take the `NODE_WITNESS_PRUNED` service flag only from a peer's own `version`
message, budget the time they spend validating each peer's transactions that
are then rejected, attribute each received block to the peer that sent it, and
check blocks fetched to restore pruned witness data before they store them. The
qbit-photon block relay bounds the inbound state each peer can hold, checks
blocks before it submits them, and announces blocks under the low-order bits of
their hash, so that it no longer skips most native-lane blocks.
`submitSolution` on the IPC mining interface returns false for a missing or
unreadable coinbase, and qbit-qt adds a play-money poker game.
It adds two standardness rules for P2MR spends, but contains no consensus rule
change, no scheduled network activation, and no change to the mainnet or
testnet4 network identity. The wallet database format is unchanged apart from
one new record, which v1.0.0 ignores.

Please report bugs using the Qbit issue tracker.

How to Upgrade
==============

Shut down the older qbit process and wait until it exits completely before
installing v1.0.1. Then install the new binaries from the GitHub Release page.

Existing v1.0.0 mainnet and testnet4 data directories, wallets, and wallet
backups continue to work without a reindex, chain reset, or wallet migration.

If a node reports a block as invalid that its peers accept, run `reconsiderblock <hash>` after upgrading.

If you encrypted a wallet with v1.0.0, especially soon after creating it, its
file may still hold unencrypted PQC private keys, which anyone with the file
or a backup made from it can read without the passphrase (#277, #283). This
release stops new ones from being written, and re-encrypts the ones v1.0.0
wrote the next time the wallet is unlocked (#301). After upgrading, check
`pqc_key_validation.reencryption_required` in `getwalletinfo`. While it is
`true`, the wallet refuses to sign and to be backed up (see Behavior
changes). Unlock the wallet once: with `walletpassphrase`, or in qbit-qt,
which has no separate unlock action, by entering the passphrase when it asks
for it, for example for a send, or by running `walletpassphrase` in its
console. Then check that `reencryption_required` is `false` before you make a
new backup. Re-encryption cannot change older copies: wallet files and
backups made before it still contain those keys. If you are not sure that
the wallet file and all of its backups stayed private, create a new wallet
with a passphrase using this release, move your funds to it, and delete the
old backups (see Known limitations).

The first time this release loads a wallet that v1.0.0 encrypted, it rewrites
the wallet file once (see Wallet fixes). This needs free disk space of up to
twice the size of the wallet file: about the file's size again beside the
wallet, for its `-journal` file, and about the same in the temporary
directory, which may be on another filesystem (#300).

Downgrading to v1.0.0 remains possible. This release adds one wallet record,
which v1.0.0 ignores, so v1.0.0 can still open wallets and data directories
that v1.0.1 has used, but a downgraded node loses the fixes in this release,
including the wallet encryption fixes (#277, #300, #301, #418).

On Linux, replace the installed `qbit`, `qbitd`, `qbit-qt`, `qbit-cli`,
`qbit-tx`, `qbit-util`, and `qbit-wallet` binaries from the archive's `bin`
directory, the `libexec/qbit-node` and `libexec/qbit-gui` binaries (the
IPC-enabled node and GUI that `qbit -m` runs), and any other files installed
from the previous release archive, with the versions from the new archive.

On macOS, replace the installed Qbit application bundle or unpack the updated
archive into the desired location.

On Windows, run the installer if one is provided for the release, or replace
the unpacked binaries with the new release artifacts.

Behavior changes to review before upgrading
-------------------------------------------

- The wallet `-fallbackfee` default changed from disabled to the minimum relay
  fee rate. When no fee estimate is available, the wallet now pays at least
  that rate instead of failing, and peers with a stricter policy, or a
  congested network, may not relay or mine such a transaction until its fee is
  bumped (see Fallback fee). Operators who relied on transaction creation
  failing when no fee estimate is available must set `-fallbackfee=0`
  explicitly (#151).
- `gettransaction`, `listtransactions`, and default `listsinceblock` output
  now include a fee-only `send` entry, with `amount` of zero and a negative
  `fee` and without `address`, `label`, or `vout`, for a self-transfer whose
  outputs are all change. Integrations that assume every `send` entry has an
  address, a `vout`, or a non-zero amount should be checked (#150).
- If another encryption of the same wallet completes first, for example a
  concurrent `encryptwallet` call or qbit-qt's Encrypt Wallet dialog,
  `encryptwallet` now fails with error code `-15`
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
- Standard policy now also limits hashing of large P2MR v1 stack elements.
  Each `OP_RIPEMD160`, `OP_SHA1`, `OP_SHA256`, `OP_HASH160`, or `OP_HASH256`
  that a P2MR v1 script applies to a stack element longer than 520 bytes
  costs one unit per started 64-byte block of the element, from a per-input
  budget equal to the input's initial validation weight, separate from the
  signature charges. A spend that exceeds the budget is rejected with the
  reject reason `mempool-script-verify-flag-failed (Standard P2MR hashing
  limit exceeded)`. Elements that fit in a pushed literal cost nothing, so
  only scripts that hash initial witness items longer than 520 bytes are
  affected. Such a spend is still consensus-valid, so a block that contains
  it is still accepted, and nodes running v1.0.0 still relay it. Wallet
  signing and PSBT finalization check the same standard rules and report
  such a spend as incomplete (#415).
- Nodes now budget the time they spend validating a peer's transactions that
  are then rejected for a reason in the transaction itself, including the
  two P2MR standardness rules above. A peer over its budget is not
  disconnected or discouraged, but until the budget refills its
  transactions are dropped without validation and requested from other
  peers, and no transactions are requested from it; afterwards, those it
  announced or sent meanwhile are requested from it unless the node already
  has them. Peers with the `noban` permission and manual connections are
  exempt. The budget can be changed only with the debug option
  `-txvalidationbudget=<peer_rate>,<peer_cap>,<pool_rate>,<pool_cap>`
  (in microseconds; default `500,100000,50000,500000`; `0` disables it),
  which is meant for tests and is listed only by `-help-debug`; a malformed
  value stops the node at startup (see "Mempool, P2P, and PQC library
  hardening") (#386, #422, fixes #275).
- `submitSolution` on the IPC mining interface (`qbit-node -ipcbind`) now
  rejects blocks that fail the coinbase witness checks it used to skip (see
  Mining interface). IPC clients must submit the complete coinbase,
  including its witness; unlike the `submitblock` RPC, `submitSolution` does
  not add the witness reserved value (#289, fixes #278).
- On Linux, macOS, and other non-Windows systems, `restorewallet` and qbit-qt's
  Restore Wallet action now refuse a backup file that is the database of a
  wallet loaded by the same node, with "Run backupwallet first and restore
  from that backup." Run `backupwallet` first and restore from that copy
  (#297, fixes #280).
- `send` now fails with error code `-4` (`RPC_WALLET_ERROR`), returns no txid,
  and adds nothing to the wallet when another call spent one of its inputs
  while it was signing. Callers that run `send` concurrently on one wallet
  should expect this error; the call can be retried (see Wallet fixes) (#298,
  fixes #281).
- `walletpassphrase` refills the P2MR keypools to `-keypool` before it
  returns, as v1.0.0 did, and the unlock timeout counts from the end of the
  refill, so even a short timeout leaves the keypools full. The refill no
  longer holds the wallet lock, so most other calls on the wallet keep
  working, but `walletlock`, `walletpassphrasechange`, another
  `walletpassphrase`, `unloadwallet`, rescans, and descriptor imports on that
  wallet wait until it has finished. If the refill fails, `walletpassphrase`
  now returns error code `-4` (`RPC_WALLET_ERROR`), and the wallet stays
  unlocked until the timeout or `walletlock` (see Wallet fixes) (#299, #411,
  fixes #304).
- `keypoolrefill` now reports a failed database commit with error code `-4`
  (`RPC_WALLET_ERROR`) instead of `-1` (#299, fixes #319).
- When no fee estimate is available and `-discardfee` is not set, the wallet
  now keeps small change that it used to add to the fee (see Fallback fee)
  (#346, fixes #306).
- Every wallet encrypted by v1.0.0 is rewritten once, the first time this
  release loads it. This adds to that load's duration in proportion to the
  file's size, and needs free disk space (see How to Upgrade). In release
  testing, the first load of a 29 MB wallet with 5,250 transactions took
  about 0.12 seconds longer (0.43 against 0.30 seconds); later loads do not
  rewrite (#300, fixes #285).
- `backupwallet` and qbit-qt's backup now rewrite a wallet file whose
  post-encryption rewrite is still pending before they copy it, and refuse
  the backup with an error if that rewrite fails (#300, fixes #285).
- An encrypted wallet that still holds unencrypted PQC key records refuses to
  sign with any key until it has been unlocked once. Signing RPCs and qbit-qt
  return an error that says so, and `getwalletinfo` reports
  `pqc_key_validation.reencryption_required: true` and
  `pqc_key_validation.signing_blocked: true` (#301, fixes #283).
- `backupwallet` and qbit-qt's backup refuse to copy such a wallet.
  `backupwallet` fails with error code `-13` (`RPC_WALLET_UNLOCK_NEEDED`), so
  a scheduled backup job for an affected wallet fails after the upgrade until
  the wallet has been unlocked once. Check such jobs for error `-13` (#301).

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
  keypool refill through deduplicated scheduler steps. #299 and #411 later
  made the `walletpassphrase` refill hold the wallet lock only briefly at a
  time, and #299 made wallets loaded at startup resume a pending refill (see
  below) (#143, fixes #138).
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
- Foreign P2MR witnesses that already pass standard script verification,
  including those for leaves the signing planner does not recognize, are
  treated as complete instead of incomplete during batched signing (#163).
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
  file format is unchanged. Unencrypted PQC keys that v1.0.0 already wrote
  are detected and re-encrypted at the next unlock (see the #301 entry below
  and How to Upgrade) (#277).
- On Linux, macOS, and other non-Windows systems, `listwalletdir`, qbit-qt's
  Open Wallet menu, and loading a loaded wallet's file again through a
  symbolic or hard link released the exclusive lock the node holds on each
  loaded wallet. A second `qbitd`, `qbit-qt`, or `qbit-wallet` process could
  then open a wallet that was still in use, and with two processes writing to
  one wallet, PQC signature counter updates could be lost and the wallet file
  corrupted. The node now keeps track of the wallet files it has open and
  recognizes them without opening them, so their locks stay held;
  `listwalletdir` output is unchanged. `restorewallet` and qbit-qt's Restore
  Wallet action now refuse a backup file that is a loaded wallet's database,
  because copying it also released the lock and the restored copy would sign
  alongside the original (see Behavior changes). Windows behavior is
  unchanged: closing a file there does not release the lock (#297, fixes
  #280).
- Concurrent `send` calls on one wallet could select the same coin, because
  `send` signs without holding the wallet lock, which takes about 200 ms per
  P2MR input. Every call returned `complete: true` and a txid, but only one
  of the transactions entered the mempool; the others stayed in the wallet
  and could never confirm. `send` now checks, under the wallet lock it holds
  to commit, that no other wallet transaction started spending one of its
  inputs while the call was running. Abandoned and conflicted transactions do
  not count. A call that loses this race fails with error code `-4`, names
  the transaction that won, returns no txid, and adds nothing to the wallet
  or the mempool. If it was called with `lock_unspents=true`, it unlocks the
  coins it locked, except those locked before the call. The call can be
  retried. It has already signed, so it has still used a signature counter
  value for each P2MR input: counters may over-count this way, but never
  under-count. Replacing a wallet transaction by passing its inputs to `send`
  in `inputs` still works.
  Two calls that make identical requests, with the same destination and
  amount, can build the same transaction. Both calls can then return success
  with the same txid, and only one payment is made; the losing call does not
  always fail with error `-4`. In release testing this happened in most
  rounds of two identical concurrent calls, as it did with v1.0.0. To make two
  equal payments, make the calls one after the other.
  `sendall`, `sendtoaddress`, and `sendmany`, which hold the wallet lock from
  coin selection through commit, are unchanged, and so is the qbit-qt Send
  flow (see Known limitations) (#298, fixes #281).
- A new P2MR wallet derives 16 receive and 16 change keys when it is created,
  and fills the rest of its keypool (`-keypool`, 1000 by default) in a top-up
  that starts 30 seconds later or, for an encrypted wallet, at its first
  unlock. If the node stopped before that top-up finished, an unencrypted
  wallet loaded at startup through `-wallet` or `load_on_startup` never
  resumed it, and watched as few as its first 16 receive and 16 change
  addresses, so payments to later addresses of the same seed, for example
  from a restored backup or another copy of the wallet, were not seen.
  Wallets loaded at startup now resume the pending top-up 30 seconds after
  the wallets start, as `loadwallet` already did. This includes wallets left
  in this state by v1.0.0. The resumed top-up watches the new addresses from
  then on, but does not find payments already made to them: if another copy
  of the wallet may have used later addresses, run `rescanblockchain` once
  `keypoolsize` in `getwalletinfo` has reached `-keypool`. Block processing
  slows while such top-ups run (see Known limitations) (#299, fixes #284).
- The first `walletpassphrase` of a wallet created with a passphrase derived
  the rest of its P2MR keypool, about 2,000 keys at the default `-keypool`,
  before it returned, and an unlock after a P2MR keypool had run down refilled
  it to `-keypool` first. The call held the wallet lock meanwhile, so other
  calls on that wallet waited, and so did the block-processing callbacks of
  all wallets, which on a busy node could delay block connection.
  `walletpassphrase` still refills the P2MR receive and change keypools,
  including a pending initial top-up, to `-keypool` before it returns, because
  a locked wallet cannot derive P2MR keys: until it is unlocked again, it can
  hand out only the P2MR addresses already in its keypool, and `getnewaddress`
  then fails with error `-12`, "Keypool ran out". The call now derives the
  keys in short steps that each hold the wallet lock only briefly, so most
  other calls on the wallet and the block-processing callbacks keep running
  meanwhile. The unlock timeout counts from the end of the refill, so even a
  short timeout leaves the keypools full, unless addresses or change are used
  while the wallet is unlocked. The refill takes roughly 15 ms per missing key
  on a typical machine: about 3 seconds for 200 addresses handed out since the
  last unlock. The first unlock of a wallet created with a passphrase derives
  about twice `-keypool` keys, so its duration grows with `-keypool`: about 30
  seconds at the default `-keypool=1000`, and about 5 minutes at
  `-keypool=10000`. Meanwhile, `walletlock`, `walletpassphrasechange`, another
  `walletpassphrase`, `unloadwallet`, rescans, and descriptor imports on that
  wallet wait for the refill, as do locking the wallet and changing its
  passphrase in qbit-qt, and unlocking it in qbit-qt while unencrypted PQC
  keys that v1.0.0 wrote still need re-encrypting (see the #301 entry below).
  If a refill step fails, for example on a database write error,
  `walletpassphrase` now returns error `-4`; the wallet is still unlocked in
  that case, and locks again when the timeout expires or on `walletlock`. If
  addresses are handed out from the same wallet during the refill about as
  fast as it derives keys, the refill stops after about twice the steps an
  empty keypool needs, counted for each keypool, and the rest continues in the
  background while the wallet stays unlocked. Other keypools are still topped
  up before the call returns. Unlocking a wallet in qbit-qt does not refill a
  partly used P2MR keypool; it only resumes a pending initial top-up in the
  background (#355). Background refills, such as those started at wallet load
  or by `getnewaddress`, pause while the wallet is locked and are completed by
  the next `walletpassphrase`; when a lock pauses one, `debug.log` says that
  the refill "paused after a failed background step", which is expected and
  not an error. `getnewaddress` and transaction creation keep working during a
  refill, deriving one key at a time past the last derived address. The
  exchange integration guide now recommends calling `keypoolrefill` before
  `walletlock`, so that addresses and change used while the wallet was
  unlocked are replaced before it locks (#299, #411, fixes #304).
- Locking an encrypted wallet, through `walletlock`, qbit-qt, or the
  `walletpassphrase` timeout, now waits until transaction signing has freed
  its temporary copies of decrypted ECDSA and PQC keys, and until a running
  background keypool step has freed its copies, usually within a second.
  Transaction signing, as used by `sendtoaddress`, `sendmany`, `bumpfee`,
  and `signrawtransactionwithwallet`, could let the lock return while those
  copies were still in memory; PSBT signing already freed them first. The
  copies were, and still are, wiped when freed (#299, fixes #287 and #304).
- If the wallet database could not commit a keypool top-up, for example
  because the disk was full, the top-up threw an exception after it had
  rolled its changes back. In a background P2MR refill, which can run for a
  minute or more after a wallet is created, loaded, or unlocked, this stopped
  `qbitd` or `qbit-qt`. Such a failure is now reported as an ordinary top-up
  error. A background refill logs the reason and that it "paused after a
  failed background step", and starts again at the next unlock,
  `loadwallet`, or restart, or, for a low-watermark refill, at the next new
  address. `keypoolrefill` reports the failure with error code `-4` instead
  of `-1`. `getnewaddress`, block processing, and wallet loading carry on
  with the keys already derived; once those are used up, `getnewaddress`
  fails with "Keypool ran out". The node still stops if the rollback itself
  fails (#299, fixes #319).
- `encryptwallet` deleted a wallet's unencrypted private keys, then spent
  about 30 seconds generating a new keypool, and only then rewrote the wallet
  file. The deleted keys stayed readable in the file until that rewrite, and
  if the process stopped during those 30 seconds, or the rewrite failed,
  nothing removed them later. For a wallet encrypted in place, these are the
  keys that control its existing funds. The file is now rewritten right
  after the keys are deleted, and the wallet records that this succeeded. An
  encrypted wallet without that record is rewritten when it is next loaded,
  before any other work on it starts; if that rewrite fails, the wallet still
  loads with a warning, and the rewrite is tried again at the next load.
  `encryptwallet` adds a warning to its result if its rewrite failed. The
  rewrite also empties the wallet's `-journal` file, which otherwise kept
  copies of the deleted keys for as long as the wallet stayed loaded.
  `qbit-wallet` does not rewrite wallets; while the rewrite keeps failing, a
  copy without the deleted keys can be made by unloading the wallet and
  running `qbit-wallet -wallet=<name> -dumpfile=<file> dump` and
  `qbit-wallet -wallet=<new name> -dumpfile=<file> createfromdump`, with the
  same `-datadir` and chain options as for `qbitd` (an empty name for the
  default wallet). The dump file holds all of the wallet's records,
  including its encrypted keys, so keep it as safe as a backup. The rewrite
  cannot reach copies made earlier: a backup taken before encryption, or by
  v1.0.0 during or after an interrupted encryption or after a failed
  rewrite, can still contain unencrypted keys (#300, fixes #285).
- If anything failed after `encryptwallet` had committed the encryption, such
  as a write error while generating the new seed's keys, the RPC returned
  error `-1` although the wallet was encrypted, the wallet stayed unlocked
  with no relock, and descriptors from the failed step stayed in memory
  without their records on disk. The wallet is now locked whenever the call
  returns, those descriptors are removed again, and the RPC succeeds with a
  result that starts with `wallet encrypted; Warning:` and says that the new
  HD seed was not set up. New addresses then still come from the previous
  seed. qbit-qt still reports a fatal error and quits in this case, and the
  wallet loads encrypted and locked at the next start (#300).
- When `encryptwallet`, or encrypting a wallet in qbit-qt, replaced a
  descriptor's unencrypted private key record with its encrypted record, it
  ignored whether writing the encrypted record or erasing the unencrypted one
  had succeeded. If either failed, the wallet still reported itself as
  encrypted while the unencrypted private key record stayed in the wallet
  file. Such a failure now fails the encryption. As with any other failure
  while the wallet's keys are being encrypted, `qbitd` or `qbit-qt` then
  stops with an assertion failure, without saving any part of the
  encryption. After a restart the wallet loads unencrypted, with all of its
  keys, and it can be encrypted again once the cause of the database error
  has been fixed. PQC keys are handled the same way. The wallet file format
  is unchanged (#418, fixes #296).
- A wallet encrypted before its first background keypool fill finished kept a
  16-address lookahead for its previous seed, so later payments to that
  seed's addresses, for example from a backup taken before encryption, were
  not detected. `encryptwallet` now fills those descriptors first, which can
  make it take up to twice as long in that window. Wallets already encrypted
  in that window keep the short lookahead (#300).
- Removing an address book entry in qbit-qt took the wallet database's
  writer before the wallet lock, the reverse of the order other wallet
  writes use, so a removal that coincided with another wallet write, such as
  wallet encryption or an incoming transaction, could deadlock the wallet.
  It now takes the wallet lock first (#300, fixes #293).
- v1.0.0 could write unencrypted PQC private keys into a wallet that was
  being encrypted while a background keypool refill ran (#277). This release
  now detects and re-encrypts them. `getwalletinfo` reports
  `pqc_key_validation.reencryption_required`, which is `true` while an
  encrypted wallet still holds unencrypted PQC key records, including records
  still being validated after the wallet loaded, and qbit-qt shows a warning
  icon in the status bar. The next unlock, with `walletpassphrase` or in
  qbit-qt (see How to Upgrade), replaces every validated unencrypted record
  with an encrypted one in one database transaction, keeping each key's
  signature counter (the higher one if the key also had an encrypted record),
  and then rewrites the wallet file as `encryptwallet` does. An affected
  wallet therefore logs "Rewrote the wallet file after encryption" twice:
  once when this release first loads it, and again at its first unlock. In
  qbit-qt, that second rewrite briefly blocks the window, in release testing
  for about 0.08 seconds on a 2 MB wallet, longer for larger files. Records
  still being validated at the unlock are re-encrypted as soon as validation
  finishes if the wallet is still unlocked, and otherwise at the next unlock.
  Nothing happens until you unlock. If re-encryption fails, no record
  changes, the wallet keeps refusing to sign, and `debug.log` records the
  reason; the next unlock tries again. Records that failed validation are
  never re-encrypted. Unencrypted wallets are not affected (#301, fixes
  #283).
- `walletpassphrasechange` no longer locks or unlocks the wallet. It locked
  the wallet before it checked the old passphrase, so a change that failed,
  for example because the old passphrase was wrong, locked a wallet that had
  been unlocked. The wallet now keeps its lock state: an unlocked
  wallet stays unlocked until its `walletpassphrase` timeout, and a locked
  wallet stays locked. qbit-qt's Change Passphrase still locks the wallet
  before it changes the passphrase, as before (#379).

### Fallback fee

- The wallet `-fallbackfee` now defaults to the minimum relay fee rate
  (250 sat/kvB, that is 0.0000025 QBT/kvB) instead of being disabled.
  Previously, when the fee estimator had no data, which is the normal state on
  a young chain with an empty mempool, transaction creation failed with
  "Fee estimation failed. Fallbackfee is disabled." Wallets now pay the
  fallback rate in that case. The fallback is used only when no smart fee
  estimate is available; live estimates take precedence as soon as the
  estimator has observed confirming transactions. A node that was stopped for
  more than 60 hours discards its saved fee estimates at startup, so its
  wallets use the fallback again until it has observed new ones (#151).
- When it uses the fallback, the wallet never pays less than the highest of
  this node's minimum relay fee, `-mintxfee`, and current mempool minimum fee.
  Those are only this node's limits: peers with a higher minimum, or a
  congested network, may not relay or mine a transaction paid at the fallback
  rate, and it can stay unconfirmed until its fee is bumped. A `bumpfee`
  without an explicit fee rate raises the rate by at least 5,000 sat/kvB, and
  bumping a P2MR transaction re-signs every input, which consumes PQC signing
  capacity. Services that prefer transaction creation to fail when no estimate
  is available should set `-fallbackfee=0`, which restores the previous
  behavior (#151).
- When no fee estimate is available and `-discardfee` is not set, the wallet
  now decides whether change is worth keeping at the rate it pays without
  estimates: `-fallbackfee`, raised to `-mintxfee` and the minimum relay fee,
  with the dust relay fee as the floor. It used the `-discardfee` default of
  0.0001 QBT/kvB before, 40 times the default fallback rate, so P2MR change
  below about 0.00038 QBT was added to the fee, which could make the fee up
  to about 40 times the fee of the transaction itself. With the default
  settings, at the 250 sat/kvB fallback rate, P2MR change is now added to the
  fee only below about 0.000025 to 0.00003 QBT. In release testing on
  regtest, change of 0.00003 QBT and above was kept and change of 0.000025
  QBT and below went to the fee; a send that left 0.0002 QBT of change kept
  it and paid a 966 sat fee, where it used to pay 20,966 sat, and
  `fee_reason` was "Fallback fee". Nothing changes if `-discardfee` is set,
  even to its default value, if `-fallbackfee=0`, or while a fee estimate is
  available. The `-discardfee` help describes the new limit (#346, fixes
  #306).
- qbit-qt's Send page now shows its "Warning: Fee estimation is currently not
  possible." label whenever there is no fee estimate, including when
  `-mintxfee` or the mempool minimum fee raises the fee rate above the
  fallback fee. It used to hide the warning in that case and show a
  confirmation estimate ("within N blocks") that did not exist. The RPC
  `fee_reason` field is unchanged: it names the rule that set the final fee
  rate, so it reads "Fallback fee" only when the fallback rate itself applies,
  and otherwise, for example, "Minimum Required Fee" or "Mempool Min Fee"
  (#346, fixes #322).

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
- `send` fails with error code `-4` when a concurrent call spent one of its
  inputs while it was signing (see Wallet fixes) (#298). The
  `walletcreatefundedpsbt` help now says to set `lockUnspents` when funding
  PSBTs concurrently (#298).
- `restorewallet` refuses a backup file that is the database of a loaded
  wallet, except on Windows (see Behavior changes) (#297).
- `walletpassphrase` refills the P2MR keypools before it returns without
  holding the wallet lock, and returns error code `-4` if the refill fails,
  leaving the wallet unlocked until the timeout. Its help says roughly how
  long the refill takes, which calls wait for it, that the timeout counts
  from its end, and what an early stop or a failure means (see Wallet fixes)
  (#299, #411).
- `keypoolrefill` reports a failed database commit with error code `-4`
  instead of `-1` (#299).
- The `importdescriptors` help now says that PQC signature counters are kept
  per descriptor, and do not include signatures the same key made in other
  descriptors of this wallet, in other wallets, or outside this wallet (#346,
  fixes #323).
- `encryptwallet` succeeds with a result that starts with
  `wallet encrypted; Warning:` when the encryption was committed but a later
  step failed, and adds a warning to its result when the wallet file could
  not be rewritten (see Wallet fixes) (#300).
- `backupwallet` rewrites a wallet whose post-encryption rewrite is pending
  before it copies it, and refuses the backup if that fails (#300).
- `getwalletinfo` adds `pqc_key_validation.reencryption_required` (#301).
- `backupwallet` refuses to copy a wallet while
  `pqc_key_validation.reencryption_required` is `true`, with error code
  `-13`. It has a new optional second argument, `allow_unencrypted_pqc_keys`
  (default `false`), to make the backup anyway, for example for a wallet with
  records that failed validation, which are never re-encrypted. Anyone with
  such a backup can read those keys without the passphrase. qbit-qt has no
  such option; `qbit-wallet` `dump` can copy such a wallet, and its dump file
  contains those keys too (#301).
- `walletpassphrasechange` keeps the wallet's lock state, also when it fails
  (see Wallet fixes) (#379).
- `getpeerinfo` reports three new fields once the version handshake with a
  peer has completed: `failed_tx_validation_time` (the total time in
  microseconds spent validating the peer's transactions that were rejected
  for a reason in the transaction itself, also for exempt peers),
  `tx_validation_throttled` (whether the peer's transactions are currently
  not validated), and `tx_dropped_while_throttled` (the number of
  transactions received from the peer that were dropped without validation
  because the peer was over its budget) (see "Mempool, P2P, and PQC library
  hardening") (#386, #422).

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
  (#177, fixes #168). The panel's time is the time the replacement was
  committed, not the later time the panel was shown after a usage warning
  (#344).
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
- Encrypting a wallet with the `encryptwallet` RPC, for example from
  `qbit-cli` or qbit-qt's console, while qbit-qt had the wallet open stalled
  qbit-qt until the encryption finished. Encryption generates new keys while
  it holds the wallet locks, which can take minutes with a large `-keypool`,
  and the status bar, the overview page, the transaction list, and the
  Receive page waited for those locks, so the window stopped repainting and
  responding. The wallet now announces when an encryption starts and
  finishes, whoever started it, and qbit-qt handles an encryption started
  outside it the way it handles one started from its Encrypt Wallet dialog:
  the window keeps repainting and responding; the encryption status, the PQC
  key validation status, and address labels are shown as they were before
  the encryption; new transactions, keypool changes, and status changes are
  applied once the encryption has finished; and unlocking, sending, signing,
  fee bumping, and encrypting from the Encrypt Wallet dialog are refused
  with a "Wallet encryption in progress" message. When the encryption
  finishes, whether it succeeds or fails, qbit-qt reads the wallet again and
  shows it as encrypted and locked, or as it was before. Some actions still
  wait for the encryption (see Known limitations) (#352).
- Quitting qbit-qt while the Load PSBT dialog is signing now cancels the
  signing if it has not reserved PQC signature counters yet, so shutdown no
  longer waits for the whole signing and no counters are consumed. Signing
  that has already reserved counters cannot be stopped and still finishes.
  Every window is hidden by then, so qbit-qt writes the outcome to
  `debug.log`, including the signature counts, limit states, and warnings of
  each PQC key used, and saves a signed PSBT to the data directory as
  `unshown-psbt-<txid>-<time>.psbt`, which File > Load PSBT can open. The log
  line names the file; the PSBT itself is not written to the log. This
  includes a partial signature added to a multisig input, which consumes a
  counter without completing the input. A PSBT that the dialog signed but
  that was not copied, saved, or broadcast before shutdown is saved the same
  way. The PSBT dialog can no longer be closed while it is signing, which
  used to block the GUI until the signing finished and discard its result.
  After Cancel, the progress dialog stays on screen until signing has
  actually stopped, or until it finishes if the cancellation came too late to
  prevent the counter reservation. Saving a PSBT to a file that cannot be
  written now reports a failure instead of "PSBT saved to disk." When the
  wallet is unloaded while the PSBT dialog is signing, a successful signature
  is now kept and reported as signed, with a note that the wallet was
  unloaded, and the PSBT can still be copied, saved, or broadcast; it used to
  be discarded and reported as a failure (#344).
- In the PSBT operations dialog, Sign now does nothing while a signing
  attempt is in progress, from the passphrase prompt until signing finishes,
  so one Sign makes at most one signing attempt. Mouse and keyboard input
  cannot reach the dialog behind the passphrase prompt, but an accessibility
  client, such as VoiceOver, or a UI automation tool still can; pressing Sign
  through one started a second signing attempt with a second passphrase
  prompt, a bug present since v1.0.0. Copy and Save are unavailable for the
  whole attempt. qbit-qt also no longer uses freed memory when the dialog is
  closed this way while its passphrase prompt is open; the signing attempt
  then ends before it signs and the wallet stays locked (#353, fixes #350).
- qbit-qt could abort while a send confirmation was open, a bug present since
  v1.0.0. Mouse and keyboard input cannot reach the Send page behind the
  confirmation, but an accessibility client, such as VoiceOver, or a UI
  automation tool still can. Pressing Send through one prepared a second
  transaction and opened a second confirmation; confirming the second one
  broadcast its transaction, and confirming the first one then aborted
  qbit-qt. Pressing Clear All the same way and then confirming aborted it
  too. No funds were at risk: qbit-qt broadcast only a transaction confirmed
  in its own confirmation. Send now does nothing while a send is in progress,
  from the passphrase prompt until the confirmation closes, so one Send sends
  at most one transaction. The send also keeps the inputs selected with coin
  control when Send was pressed, even if the form is cleared or coin control
  is changed while the passphrase prompt is open. qbit-qt also no longer uses
  freed memory when it is asked to quit while a send confirmation is open,
  and Send no longer stays unavailable after an internal error is reported
  while a send is being started (#348).
- qbit-qt could crash, or use freed memory, when it was asked to quit while a
  dialog was waiting for an answer, such as the send confirmation, the "PSBT
  copied" box, the warning shown after a send, or the passphrase prompt. The
  quit could come from the platform (on macOS: Dock > Quit, logout, or a
  Quit Apple event), or from File > Exit pressed through an accessibility
  client behind the dialog; shutdown then deleted the wallet views while the
  dialog's code was still running. A quit from the platform or from
  File > Exit now waits until every message box or dialog whose code is
  waiting for an answer has been answered, and qbit-qt shuts down right
  after that. While it waits, qbit-qt shows its main window and brings that
  dialog to the front. Unloading a wallet, for example with `unloadwallet`,
  waits for such dialogs the same way, even when a progress dialog covers
  one. Nothing is sent or signed because of the quit: cancelling the dialog
  cancels the operation, as before. Dialogs that stay open without holding
  up the code that opened them, such as the PSBT dialog, Coin Control, the
  options dialog, and progress dialogs, do not delay a quit from the
  platform or from File > Exit; shutdown still cancels transaction
  preparation and fee bumps that can be cancelled, and waits for those that
  cannot. Wallet encryption and PSBT signing cannot be cancelled once they
  have started: such a quit during either starts the shutdown at once, the
  shutdown waits for the work to finish, and the "Wallet encrypted" box is
  not shown; a PSBT signed this way is saved to the data directory, as
  described for #344 above. A second quit request while one is waiting, or
  while the node is shutting down, is ignored; a second Quit from the
  platform used to request the node shutdown again. A platform quit made
  while the first-run data directory dialog is open is carried out once that
  dialog has closed and startup has created the main window; it used to
  crash qbit-qt. On macOS, a logout started while such a dialog is open is
  cancelled, as before, and qbit-qt now quits once the dialog is closed. On
  Windows, logging off already waited for open dialogs. RPC `stop` and
  SIGTERM keep their rule (see Known limitations). Most context menus, such
  as those of the address book and the peers table, hold a quit until they
  close, and RPC `stop` and SIGTERM now also wait for them. A wallet's rescan
  progress dialog no longer stays open after the wallet is unloaded, where it
  kept RPC `stop` and SIGTERM from shutting qbit-qt down until it was
  cancelled (#354, fixes #349).
- Release builds of qbit-qt now use Qt 6.8.4 instead of Qt 6.7.3. This fixes
  a crash on macOS when quitting qbit-qt after an accessibility client, such
  as VoiceOver or a UI automation tool, had inspected its windows. The crash
  was a use-after-free in Qt's macOS accessibility cache (QTBUG-134784),
  which Qt 6.8.4 fixes; the build also applies a later Qt fix for a related
  use-after-free (QTBUG-149612). Saved GUI settings and window layouts are
  read and written as before (#347).
- qbit-qt has a new Window > Poker Lobby entry: no-limit Texas Hold'em
  against computer players at heads-up, 6-max, and full-ring tables. Chips
  are play money with no value. The game never touches the wallet, sends
  nothing over the network, and does nothing until the lobby is opened. The
  lobby and table follow the two poker windows Satoshi Nakamoto designed for
  the first Bitcoin client, which were never connected to a game and were
  removed in 2009. See `doc/user/poker.md` (#378).

### Validation and performance work

- Successful P2MR PQC transaction-signature checks are cached in a new PQC
  domain of the shared signature cache, following the Schnorr pattern. Only a
  verified success is inserted, so a fresh mempool admission verifies each PQC
  signature once in the policy pass and reuses the result in the consensus
  pass. Interpreter checks, validation-weight charges, script flags, and the
  full-script cache are unchanged, data signatures were left uncached, and a
  benchmark for the two-pass admission pattern was added (#162). #265 below
  caches data signatures in a separate domain.
- The signature caches and descriptor batching are described by their
  behavior only; this release does not claim a speedup. The #268 entry below
  gives the measured signing and verification cost of the PQC library update:
  because of its verification cost, a mainnet `-reindex-chainstate` on one
  x86-64 machine took about 5 to 8% longer than with v1.0.0.
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
- `submitSolution` now returns false when its coinbase argument is missing,
  empty, or cannot be read as a transaction. The template is left unchanged
  and can still be used. With `-debug=ipc`, a coinbase that cannot be read is
  logged. Valid submissions behave as before (#419).

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
- Standard policy also limits hashing of P2MR v1 stack elements longer than
  520 bytes, through the new `SCRIPT_VERIFY_P2MR_HASH_WEIGHT` flag and its
  own script error. Each `OP_RIPEMD160`, `OP_SHA1`, `OP_SHA256`,
  `OP_HASH160`, or `OP_HASH256` applied to such an element costs one unit
  per started 64-byte block of the element. The units come from a per-input
  budget equal to the input's initial validation weight, separate from the
  signature charges, and elements that fit in a pushed literal cost nothing
  (see Behavior changes). The flag applies to mempool admission and the
  other users of the standard script verification flags. Consensus rules
  are unchanged. `CastToBool`, which every script evaluation uses, now scans
  64 bytes at a time; its results are unchanged (#415).
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
  and verification accepts and rejects the same signatures. qbit builds the
  library in production mode on every platform, which fixes its SHA-256 and
  SHA-512 block functions to the library's portable code: its x86 SHA-NI,
  ARMv8 SHA, and Apple CommonCrypto backends are never used. On x86 CPUs with
  AVX2, key generation and signing also use the library's eight-way AVX2
  SHA-256 code; verification does not. In measurements of production-mode
  builds on x86-64 Linux with AVX2, made for the v1.0.1 release review, key
  generation takes about 11 to 15% longer and signing about 11 to 18% longer.
  Verification takes about 7 to 8% longer in a micro-benchmark of
  production-mode builds on x86-64, because v0.3.2 also wipes the buffers of
  each SHA-256 and SHA-512 hash it finalizes. On the same x86-64 machine, a
  `-reindex-chainstate` of mainnet, which includes block validation, took
  about 5 to 8% longer than with v1.0.0. Other CPUs and platforms were not
  measured, including aarch64 and other non-x86 Linux
  builds, Macs, and x86 CPUs without AVX2. Secret-key validation was not
  measured either; #268's earlier measurement of v0.3.1 put it about 12%
  slower, like key generation. A key generation, validation, or signing call
  made directly to the library needs about 17 KiB of free stack; qbit's own
  calls need more (see the next entry) (#268, refs #260).
- After each PQC key generation, secret-key validation, signing, and HD key
  derivation call, qbit now overwrites 32 KiB of the stack the call released.
  This clears the HD master-seed material and HKDF state that qbit's own HD
  key derivation (`DerivePQCKey`) left in its stack frame, which the
  library's wipe does not reach, and adds margin to the library's own wipe.
  Each of these calls therefore needs at least 32 KiB of free stack, plus its
  own frames (#270, refs #260).
- A node now keeps the `NODE_WITNESS_PRUNED` service flag for an address
  only when the peer itself advertised it in its `version` message on a
  connection the node made. The flag is removed from the addresses in `addr`
  and `addrv2` messages before they are stored or relayed, so a flag that
  arrives in a relayed address is neither stored nor used when the node
  decides which addresses to avoid. The node also does not restore the flag
  when it loads `peers.dat`, because the file does not record how the flag
  was learned; it is learned again the next time the node connects to the
  peer. With `-debug=addrman`, the log says for how many addresses it was
  not restored. A peer's own `version` message is handled as before, and so
  are other service flags. The `peers.dat` format is unchanged, so v1.0.0
  can still read the file (#380).
- The time the node spends validating a transaction received from a peer is
  now measured, and charged to that peer when the transaction is rejected
  for a reason in the transaction itself (invalid by consensus,
  non-standard, or with a mutated or missing witness). This includes
  transactions from `tx` messages, orphan reconsideration, and package
  evaluation. Rejections that depend on the node's chain or mempool state,
  such as missing inputs, conflicts, fee and mempool limits, are not
  charged. Transactions submitted over RPC are never charged (#386, #422,
  fixes #275).
  - Each peer earns 500 µs of credit per second of connection, up to 100 ms,
    and can use it once it has reached 100 ms. Until then, and while its
    credit is used up, the peer draws on a node-wide pool of 500 ms that
    refills at 50 ms per second. Each connection can draw at most a tenth of
    the pool: 50 ms at once, refilled at 5 ms per second, so it takes at
    least ten connections drawing at that rate to keep the pool empty. A new
    connection starts with a full share, so what new connections draw is
    bounded by the pool. With the default 125 connections this bounds the
    charged time to about 11% of the message-handling thread over time,
    apart from the one transaction that takes a peer's credit, its share of
    the pool, or the pool below zero, which is charged in full down to a
    floor of -1 s. Raising `-maxconnections` raises the bound by 0.5 ms per
    second for each extra connection. The node's periodic coins cache flush,
    which mempool acceptance also runs at its end, is run just before the
    measured time starts, so it is not charged unless it falls due during
    the validation itself.
  - While a peer has no credit it can use and cannot draw on the pool, the
    node stops validating that peer's transactions until the budget refills:
    transactions it sends are dropped without validation and requested from
    other peers that announce them, transactions are not requested from it
    (including those it announced earlier), and its orphan transactions
    wait. Once the peer is within its budget again, the transactions it
    announced or sent meanwhile are requested from it, unless the node
    already has them, for example from another peer. A dropped transaction
    is not added to the reject filters, so the same transaction from another
    peer is validated as usual. The peer is not disconnected or discouraged.
    Peers with the `noban` permission and manual connections are exempt.
  - A debug log line (`-debug=net`) marks when a peer goes over its budget
    and when it is within it again, with the number of transactions dropped
    meanwhile. `getpeerinfo` reports the charged time and the throttle state
    of each peer (see Updated RPCs).
- Block data received from peers is now attributed to the peer that sent it.
  Each `block` message's sender is recorded as the block's source, replacing
  any earlier one, so the result of processing a block is attributed to the
  peer whose block was processed. The compact block paths are unchanged. A
  block's size and weight failures that depend on its AuxPoW payload, which
  counts toward block size and weight but is not covered by the block hash,
  are now classified using the size of the committed portion; failures of the
  committed portion keep their existing classification. The node connects the
  copy of a block that it validated and stored. A block fetched to restore
  pruned witness data is now checked before it is stored, with the checks
  applied to any other received block whose header is already known: its
  AuxPoW payload against the commitment rules for its height, then the usual
  block checks. A peer whose copy fails is treated as misbehaving and is not
  asked for witness recovery again on that connection. A recovered copy that
  passes these checks but still fails to connect marks the block invalid, as
  it would on a node that kept its witness data. Only nodes that have pruned
  witness data request witness recovery. Consensus rules, the wire format, and
  the file formats are unchanged (#414).

### PHOTON

- The qbit-photon block relay now bounds the inbound block state each relay
  peer can hold. Decoder memory is charged at what the FEC codecs allocate
  for a block's announced parameters, rather than at the block's size, and
  is capped at 5 MiB per block, 10 MiB per peer, and 64 MiB in total; a
  2,000,000-byte block with the default parameters is charged about 4.8 MiB.
  Incomplete blocks are capped at 4 per peer and 128 in total. At a limit, a
  peer first gives up its own oldest incomplete blocks; another peer's block
  is displaced only if it has received no new chunk for 10 seconds, and
  otherwise the new block is refused. `contrib/photon/relay-node.service`
  now sets `MemoryMax=256M` (#381).
- Before it submits a reconstructed block to qbitd, qbit-photon checks that
  the block's header hash matches the identifier the block was announced
  under, and asks qbitd where the block's parent is, with
  `getbestblockhash`, and `getblockheader` and `getblockhash` when the parent
  is not the best block. The parent must be the best block, one of its
  ancestors at most 6 blocks deep, or a block on a competing branch with at
  least the chain work of the best chain's block 6 below the tip, so
  children of competing tips are still relayed. A block that fails these
  checks is dropped without calling `submitblock`. The `[qbitd]`
  `rpc_timeout_ms` setting (default 5000) now bounds each RPC call to qbitd
  in total, and the whole parent check, instead of each receive (#381).
- Each relay peer has a fault score. A malformed header or a block that
  cannot be used adds a point, a block that qbitd accepts removes two, and
  one point decays every minute. At 8 points, qbit-photon refuses that
  peer's inbound blocks for 60 seconds, doubling on each repeat up to 30
  minutes; other peers are not affected. A local qbitd that does not answer,
  or that is still catching up, never counts against a peer. The stats line
  now reports each `submitblock` outcome separately (`submit_duplicate`,
  `submit_inconclusive`, `submit_rejected`, `submit_timeout`, and
  `submit_error`), with new `block_*`, `inbound_entries`,
  `inbound_decoder_bytes`, and `peer_suspensions` fields, and is followed by
  a `peer relay stats` line for each peer that has sent block traffic.
  `contrib/photon/RUNBOOK.md` describes the limits, the checks, and the log
  fields. The relay wire format is unchanged. Relays running v1.0.0 and
  v1.0.1 interoperate in both directions; during a rollout, a v1.0.0
  receiver may send a block back once under the earlier identifier (see the
  next entry) (#381, #410).
- qbit-photon now announces a block under the low-order 64 bits of its hash,
  the last 16 hex digits of the hash as qbitd prints it, instead of the
  leading 64 bits. A native-lane block's proof of work is on its own hash,
  so its leading bits take only a few values, and most native-lane blocks
  were taken for a block already relayed and not relayed on. A relay accepts
  a block announced under either form, and a block that arrives under both
  forms reaches qbitd once and is not relayed back out. Relays running
  v1.0.0 use the identifier only as a key and receive every block announced
  under the new form; after their qbitd accepts such a block, they may send
  it on once more under the earlier form, and relays running v1.0.1
  recognize that copy, once they have decoded it, as a block they already
  have, without counting it against the sender. The packet format and
  protocol version are unchanged (#410, fixes #388).
- The parent check before a block is submitted to qbitd also changed. If
  qbitd knows the parent only as a header on a branch with more chain work
  than its best block, at most 6 blocks above it, the block is submitted and
  qbitd connects it after the parent; if qbitd stores it without connecting
  it yet, that does not count against the sender. A parent further ahead
  still means qbitd is catching up, and the block is dropped. A block whose
  parent qbitd does not know is dropped, but a peer's first such block
  within 60 seconds does not count against it, since the parent may still be
  on its way to qbitd. If qbitd does not answer the parent check or
  `submitblock`, qbit-photon keeps the block and tries it once more after
  qbitd next answers a call or announces a block, for up to 2 minutes; it
  keeps one block at a time, and a newer block replaces it unless it builds
  on it. The stats line adds `block_parent_pending`, `block_parent_unknown`
  (previously counted in `block_parent_rejected`), `node_retries`, and
  `held_dropped` (#410).

### Release engineering, CI, and documentation

- Reworked the Pages workflow that publishes the RPC documentation at
  docs.qbit.org to build a versioned site. It builds each immutable, signed
  non-candidate release from its tag target next to rolling development
  documentation, verifies the release signer against the release key policy,
  and requires each build's reported project version to match its tag.
  Release candidates are not published to the versioned site. The versioned
  site is not deployed yet: docs.qbit.org serves the documentation deployed
  by the earlier workflow until this workflow reaches `main` (#148).
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
  now states that PQC signature counters are kept per descriptor, so an
  imported key's counter does not include signatures made in other
  descriptors, in other wallets, or outside this wallet (#346). Signing
  behavior is unchanged (#264, refs #261).
- The vendored libbitcoinpqc tree now equals its upstream release tag. The
  `RUSTSEC-2026-0204` `crossbeam-epoch` lockfile update that qbit carried on
  top of v0.3.0 is upstream since v0.3.1, so the subtree check no longer
  accepts any downstream change (#268).
- Each macOS release now has a debug symbol archive,
  `qbit-<version>-x86_64-apple-darwin-debug.tar.gz` and
  `qbit-<version>-arm64-apple-darwin-debug.tar.gz`, alongside the Linux and
  Windows debug archives. It holds a `.dSYM` bundle for every binary in
  `bin/` and `libexec/`, which `atos`, `lldb`, and other macOS tools use to
  turn the addresses in a crash report into function names, source files,
  and line numbers. A bundle matches a binary when `dwarfdump --uuid` prints
  the same UUID for both; each bundle matches its binary in the release
  tarball, in the signed tarball and zip when those are published, and the
  `qbit-qt` binary inside `qbit-qt.app`. The release binaries and the other
  macOS archives are unchanged. Releases up to v1.0.0 have no macOS debug
  archive (#343).
- Added templates of the two rulesets that protect `main` of
  `Qbit-Org/qbit-guix.sigs`, the attestation repository that releases read
  at a pinned commit, in
  `contrib/guix/repo-templates/qbit-guix.sigs/rulesets/`.
  `signed-commits.json` requires a verified signature on every commit, with
  no bypass actors, and `public-main.json` blocks deletion and
  non-fast-forward updates and requires pull requests merged with merge
  commits only. The templates equal the rulesets applied on 2026-11-09, and
  the template README says how to apply and check them. GitHub does not
  apply ruleset files from a repository, so the templates change nothing by
  themselves (#371).
- Added public tools in `contrib/release-process/` to stage the release
  artifacts and derive `SHA256SUMS` from the counted builder attestations
  (`stage-release-artifacts.py`), to sign `SHA256SUMS` once per operator
  (`sign-sha256sums.py`), and to combine the signatures into
  `SHA256SUMS.asc` (`combine-sha256sums-signatures.py`), replacing private
  tooling and a manual concatenation. They use the publisher's validators
  in `ci/release/`, read the key policy and those validators from git
  objects at the trusted ref, and run the publisher's checks that need
  nothing staged before anyone signs. Run on the public v1.0.0 attestations
  and signatures, they reproduce v1.0.0's `SHA256SUMS` and `SHA256SUMS.asc`
  byte for byte. `contrib/release-process/README.md` documents them. The
  local publisher, `publish-local-release.sh`, now also reads its key policy
  and validators from git objects, ignores replace refs and grafts, refuses
  a shallow or partial checkout, and requires git 2.31 or newer; its flags
  are unchanged (#374).
- The release key policy now lives only in `contrib/keys/operator-keys/`,
  read at the release's trusted ref. The copy in the qbit-guix.sigs
  repository template is removed, and `contrib/guix/init-supporting-repos.sh`
  seeds the qbit-guix.sigs `operator-keys/` mirror from the canonical
  directory, or rebuilds it with `--resync-operator-keys`.
  `contrib/keys/README.md` describes the policy, the mirror, and how
  downstream projects should pin and verify it. A pull request that changes
  the policy must continue the base branch's policy: the next
  `policy_sequence`, `previous_policy_sha256` equal to the base `keys.json`
  digest, and approvals verified against the base certificates. A changed
  certificate must keep its primary key, its subkeys, and its signature
  records. The release-signature and builder quorums count distinct primary
  keys, and a signature counts only when gpg's `GOODSIG` and `VALIDSIG`
  agree and gpg reports no revoked or expired key or other error for it. The
  Required Merge Gate runs these checks. Because they live in code a pull
  request can change, a new Key Policy Gate workflow
  (`.github/workflows/key-policy-gate.yml`) also runs them with the base
  branch's own code, a new `.github/CODEOWNERS` assigns the key policy, the
  release validators, the CI checks, and the workflows to the release
  maintainers, and the `main` and `1.x.x` ruleset templates now require the
  gate and code-owner review. GitHub runs that workflow only from `main`, so
  the gate runs, and the rulesets can require it, only after this release
  has reached `main` (see "Arming the gate" in `contrib/keys/README.md`).
  The policy itself, `qbit-release-keys-mainnet-000002`, is unchanged, and
  the v1.0.0 release signatures and builder attestations still verify
  (#375).
- Replaced the release documentation. `doc/release/release-process.md` is now
  a checklist runbook for a mainnet release from a release branch,
  `doc/release/publisher-reference.md` describes what the publisher and its
  validators check and what is left to process, and a Release issue form
  (`.github/ISSUE_TEMPLATE/release.yml`) mirrors the runbook. Several
  statements in the earlier documentation no longer matched the code,
  including the branch a release is cut from and the claim that the
  publisher enforces the P2MR v1 release-note sentence: the publisher only
  checks that the notes file is valid UTF-8. The issue form appears on
  GitHub once it reaches the default branch (#376).
- The 32-bit ARM unit-test shards of Nightly CI now have 300 minutes instead
  of 180. Their emulated build, which restores no cache, used most of the
  old limit, and shard 2/2 hit it. A contract test,
  `ci/checks/test_scheduled_validation_contract.py`, checks that each ARM
  shard's build budget plus its per-test timeout fits its job's limit, and
  that the shards' test ranges are contiguous and start at 1 (#377).
- Core Checks now runs the mainnet publication posture check
  (`ci/release/verify_mainnet_release_posture.py`) for the `source` and
  `release-policy` profiles on `main` and on every release branch of major
  version 1 or later, such as `1.x.x`, `1.1.0`, and `1.0.0`, instead of only
  on `1.0.0`; `0.x` branches are testnet lines. Each branch runs its own copy
  of the workflow, so `main` gets the rule only when this change reaches it.
  The job calls the validator directly: `verify_mainnet_ci_posture.py` and
  `mainnet_ci_posture.json`, which only passed its result through, are
  removed. Core Checks no longer lists the nonexistent `develop` branch and
  now also runs for `1.1.0` (#385).
- The release validators in `ci/release/`, the Key Policy Gate, and the RPC
  documentation's tag check now read gpg's status output and key listings,
  and `git verify-tag --raw`, as bytes split at line feeds only, with one
  parser. They refuse the whole output if it is not UTF-8, does not end in
  a line feed, or holds any other line separator, such as CR, U+0085,
  U+2028, or U+2029, and they accept only status lines of the shape gpg
  documents. Which signatures count is unchanged. A certificate whose user
  ID holds U+0085, U+2028, or U+2029 cannot be used in the key policy; none
  of the current certificates has one. `git verify-tag --raw` is now given
  the tag's full ref name or object ID, and its status lines are read from
  standard error only. `contrib/keys/README.md` describes the rules, and
  recommends ASCII for signature notations (#387).
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
  "Normal", while the Sign/Verify dialog shows the untranslated state name
  such as "normal". The meaning is identical; only the wording differs (#166).
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
  #268, #270, #380, #386, #414, #415, and #422 merged, and does not cover
  their changes:
  - #263 and #265 change the script interpreter that the `p2mr_script` target
    runs, and #263 adds its new flag to that target's fuzzed flag sets.
  - #415 changes the same interpreter, including `CastToBool`, which every
    script evaluation calls, but its new flag is not in the `p2mr_script`
    target's fuzzed flag sets. The inherited `script_interpreter` target
    calls `CastToBool` directly, and the inherited `eval_script`,
    `script_flags`, and `miniscript` targets reach it through the
    interpreter, but they were not part of that evidence.
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
  - #380 changes address handling in `net_processing` and `addrman`, which
    none of the six qbit-specific targets reaches. The inherited `addrman`,
    `addrman_serdeser`, `data_stream_addr_man`, `process_message`, and
    `process_messages` targets reach it but were not part of that evidence.
  - #386 and #422 change transaction handling in `net_processing`, which
    none of the six qbit-specific targets reaches. The inherited
    `process_message` and `process_messages` targets reach it but were not
    part of that evidence.
  - #414 changes block checks in `validation.cpp` and block handling in
    `net_processing`. Of the six qbit-specific targets, only `auxpow`
    reaches part of it, the size checks in `CheckBlock`. The inherited
    `block` target also reaches those checks, and the inherited
    `process_message` and `process_messages` targets reach the block
    handling, but they were not part of that evidence.
  - The other changes merged after the #176 source (#177, #178, #182, #183,
    #252, #264, #277, #289, #297, #298, #299, #300, #301, #342, #343, #344,
    #345, #346, #347, #348, #352, #353, #354, #358, #360, #361, #362, #367,
    #368, #371, #374, #375, #376, #377, #378, #379, #381, #385, #387, #410,
    #411, #418, and #419) touch only
    wallet, qbit-qt, Qt build, release build, mining-interface, RPC help and
    argument conversion, test, CI, release tooling, developer tooling,
    qbit-photon, and documentation code, which none of the six
    qbit-specific targets reaches. #346 also adds a field to the fee
    calculation result declared in `src/policy/fees.h`, which none of those
    targets includes.

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
  transaction-signature paths. This release does not disconnect or
  discourage peers that relay consensus-invalid transactions, and such a
  transaction costs a node about 0.5 µs of message-handling and `cs_main`
  time per witness byte. The per-peer budget for validating rejected
  transactions bounds the total time charged this way to about 11% of the
  message-handling thread with the default 125 connections (see "Mempool,
  P2P, and PQC library hardening") (#265, #386, refs #259).
- Large AuxPoW payloads still have these limits, deferred to later releases
  (#266, refs #258):
  - No consensus rule limits the size of an AuxPoW payload yet. Adding one
    needs an activated soft fork.
  - The block index still keeps every AuxPoW payload in memory.
  - Nodes running v1.0.0 still stall or abort headers sync through ranges with
    large AuxPoW headers. They take a message cut short for size as the end of
    the peer's headers, and when they serve headers they still send the
    oversized message, which upgraded nodes also reject. In release testing
    on regtest with large AuxPoW blocks, a v1.0.0 node that synced only from
    v1.0.1 peers stopped at a `headers` reply cut short for size and did not
    continue its low-work headers presync. On testnet4, a new v1.0.0 node
    synced to the tip from only a v1.0.1 node, and a new v1.0.1 node from
    only a v1.0.0 node. On mainnet, mixed v1.0.0 and v1.0.1 nodes synced in
    both directions, and no headers reply was cut short; the largest
    2,000-header window is about 0.72 MB. A network with such ranges
    converges once its nodes upgrade to v1.0.1, apart from the cases in the
    next two items. Upgrade nodes that accept inbound connections first; no
    configuration change is needed.
  - Low-work headers sync holds at most 36 MB of AuxPoW payload while
    redownloading, so it cannot complete, from any peer, through a range where
    roughly 15,000 to 17,000 consecutive headers carry more than that. It
    fails in that range with every peer and retries at each block
    announcement, downloading the range again each time. The failure is logged
    only with `-debug=net`. A node uses low-work headers sync for a chain with
    less work than `-minimumchainwork`, which is zero by default, or than its
    tip minus the work of its last 144 blocks. The 36 MB bound was derived for
    2,000-header messages and has not been re-derived for messages cut short
    by size (#309).
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
- If an RPC call spends the same coins while qbit-qt's send confirmation is
  open, confirming the GUI send reports no error: qbit-qt clears its form and
  lists its own transaction, although only the RPC call's transaction is
  broadcast. Only one payment is made, and the GUI's transaction cannot
  confirm. The qbit-qt Send flow does not check, before committing, whether
  its inputs were spent while the confirmation was open. Do not spend from
  one wallet through RPC and qbit-qt at the same time (#290).
- Concurrent `walletcreatefundedpsbt` and `walletprocesspsbt` flows on one
  wallet can select the same coin, because coins are not held locked while
  PQC signing runs. Only one of the transactions can confirm, and each
  signature still consumes counter capacity. Set `lockUnspents` when funding
  PSBTs concurrently (#281, #298).
- While P2MR keypool top-ups run, block processing during initial block
  download slows sharply. Wallets loaded at startup whose initial top-up is
  still pending now resume it 30 seconds after the wallets start (see Wallet
  fixes), so a node that is still syncing can spend that time processing
  blocks much more slowly. In release testing on regtest, a syncing node
  processed about 6 blocks per second while three wallets' pending top-ups
  ran, which took about 79 seconds together, against 270 to 290 blocks per
  second once their keypools were full and about 2,200 with no wallets
  loaded. Block processing returned to its normal rate when the top-ups
  finished. These regtest figures show the relative effect; they are not
  mainnet sync rates (#299).
- `encryptwallet` and encryption from qbit-qt derive the new keypool before
  they finish, and hold the wallet lock meanwhile; encrypting a populated
  wallet at the default `-keypool` took about 70 seconds in release testing.
  Other calls on that wallet wait, and the wallet's handling of new blocks is
  delayed, which can slow block processing. While an `encryptwallet` RPC
  runs on a wallet that qbit-qt has open, qbit-qt keeps responding (see
  #352 above), but these actions still need the wallet and wait for the
  encryption to finish, as in v1.0.0, and the window does not respond until
  it has: creating a new receiving address or removing a payment request;
  adding, editing, or deleting an address book entry; opening the coin
  control dialog, changing the amounts on the Send page while coins are
  selected in coin control, or entering a custom change address; opening the
  details of a transaction, or its context menu in the transaction list;
  loading a PSBT; backing up or closing the wallet; and opening the wallet in
  qbit-qt while it is being encrypted, for example right after `loadwallet`
  or `createwallet` (#174, #352).
- A wallet created with a passphrase, by `createwallet` or by qbit-qt's
  Create Wallet, keeps `bech32` as its default address type until it is
  loaded again, for example after `unloadwallet` and `loadwallet` or a
  restart. Until then, `getnewaddress` without an address type fails with
  "Output type 'bech32' is not available on this chain";
  `getnewaddress "" p2mr` works, and qbit-qt's Receive tab is not affected.
  This predates v1.0.1 (#363).
- qbit-qt does not shut down while a dialog is open. `qbit-cli stop` and
  SIGTERM shut qbit-qt down only while no modal dialog is open, including
  progress dialogs and dialogs such as the PSBT dialog, so they wait until a
  running PSBT signing or send preparation has finished and the PSBT dialog
  or send confirmation it opens has been closed. This is the existing
  design, and Bitcoin Core does the same. Close open dialogs before stopping
  an unattended qbit-qt node. A quit from the platform or from File > Exit
  waits only for dialogs that need an answer (see #354 above); no dialog is
  answered or closed automatically. On macOS, Dock > Quit does nothing while
  a progress dialog is open, such as the one shown while a PSBT is signed or
  a send is prepared; choose Quit again once it has closed.
- While the file dialog of the PSBT dialog's Save is open, an accessibility
  client, such as VoiceOver, or a UI automation tool can still press Sign or
  Close in the PSBT dialog behind it; mouse and keyboard input cannot. Sign
  then makes a signing attempt, which consumes PQC signing capacity, but Save
  writes the PSBT without the new signatures, and Close can make qbit-qt use
  the freed dialog. Do not press PSBT dialog buttons through such tools while
  saving (#364).
- With coin control enabled and no fee estimate, the coin-control panel on
  the Send page can show a small change amount, such as about 0.00001 QBT,
  that the wallet then adds to the fee. The fee and total in the send
  confirmation are correct (#365).
- Wallet files can keep key material that encryption should have removed.
  `walletpassphrasechange` leaves the master key wrapped with the old
  passphrase in the file's free space (#294). Copies of a wallet made before
  this release rewrote or re-encrypted it can still hold unencrypted keys
  (#300, #301). Treat wallet files and backups from before or around an
  encryption or passphrase change as unencrypted; to be safe, create a new
  wallet with a passphrase using this release and move your funds to it.
- Encryption still generates the replacement seed only after the
  post-encryption rewrite. If the process stops before the new seed is
  written, the wallet stays encrypted but keeps using its old seed for new
  addresses, whose keys were unencrypted on disk until the rewrite. If
  `encryptwallet` was interrupted, consider creating a new wallet with a
  passphrase and moving your funds (#300).
- Re-encryption cannot make the PQC keys that v1.0.0 left unencrypted secret
  again. Older wallet files and every backup made before re-encryption still
  contain them. The affected keys are those a background refill added beyond
  the wallet's keypool at encryption. For a wallet that got a new seed at
  encryption, they belong to its old descriptors and were never handed out
  as addresses, so funds are exposed only if those addresses are paid
  anyway, for example by a copy restored from a backup made before
  encryption. A blank wallet with imported descriptors keeps them active
  through encryption, so the affected keys are its next receive and change
  addresses and may already hold funds. If you are not sure that the wallet
  file and all of its backups stayed private, create a new wallet with a
  passphrase using this release, move your funds to it, and delete the old
  backups. For a blank wallet with imported descriptors, stop receiving to
  those descriptors as well (#301).
- `importmempool`, `loadtxoutset`, and qbit-qt's PSBT dialogs release the
  exclusive lock on a loaded SQLite wallet when given that wallet's file, so
  a second `qbitd`, `qbit-qt`, or `qbit-wallet` can then open the live
  wallet, and the PSBT save dialog can overwrite it (#295). Two writers lose
  PQC counter updates and corrupt the wallet. Never let two processes share a
  wallet directory, and never pass a loaded wallet's file to these commands
  or dialogs.
- PQC signature counters can roll back. Restoring an older backup, or loading
  an older copy of a wallet file, does so with no warning, and the restored
  copy can sign alongside the live wallet (#282). Re-importing a descriptor
  resets the counter of a key whose record failed validation (#279). The
  loader still accepts encrypted key records without a counter tag or with an
  older one, so anyone who can write to the wallet file can roll a counter
  back (#288). Keep only one copy of a wallet that signs.
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
  sanitizer builds, and CI runs no unit tests on macOS or on ARM, riscv64, or
  ppc64, so the depth is unverified on macOS, Windows, and Linux on ARM,
  riscv64, and ppc64, and in sanitizer builds (#268, #270, refs #260).

Credits and acknowledgements
============================

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this maintenance release.
