Unencrypted PQC keys in encrypted wallets
=========================================

v1.0.0 could write unencrypted PQC private keys (`walletdescriptorpqckey`
records) into a wallet that was being encrypted while a background P2MR
keypool refill ran (see the release note for #277). Such a wallet reported
itself as encrypted, used and rewrote those records whenever it signed with
their keys, and copied them into every backup. Anyone with the wallet file or
one of those backups can read these keys without the passphrase.

The release note for #277 says that this release does not detect or
re-encrypt unencrypted PQC keys that v1.0.0 already wrote. It now does both,
as described below.

How to check
------------

- With v1.0.0, an encrypted wallet is affected if `getwalletinfo` shows
  `pqc_key_validation.plaintext_records` greater than 0.
- With this release, `getwalletinfo` reports the new field
  `pqc_key_validation.reencryption_required`. It is `true` while an encrypted
  wallet still holds unencrypted PQC key records, including records that are
  still being validated after the wallet loaded. The GUI shows a warning icon
  in the status bar for such a wallet.

Unencrypted wallets are not affected by this change: for them
`reencryption_required` is always `false`, and `plaintext_records`,
`encryption_recommended` and signing behave as before.

What this release does
----------------------

- While `reencryption_required` is `true`, the wallet refuses to sign with
  any key: signing RPCs and the GUI return an error that says so, and
  `pqc_key_validation.signing_blocked` is `true`. The unencrypted records are
  never rewritten. Depending on the call, a locked wallet returns this error
  or asks for its passphrase first; either way, unlocking it is the remedy.
- The next time you unlock the wallet with `walletpassphrase` or in the GUI,
  it replaces every validated unencrypted record with an encrypted one in a
  single database transaction, keeping each key's signature counter. If a key
  also had an encrypted record, the wallet keeps that key and the higher of the
  two counters. It then rewrites the wallet file to clear the old records from
  its free space, and records the rewrite as `encryptwallet` does (see the
  release note for #285). If the node stops before the rewrite completes, or
  the rewrite fails, the wallet is rewritten the next time it is loaded, and
  `backupwallet` rewrites it before copying it.
  Nothing happens until you unlock: the passphrase is needed. The rewrite this
  release makes when it first loads a wallet encrypted by v1.0.0 does not
  remove these records, because they are still in use.
- Records still being validated when you unlock are re-encrypted as soon as
  validation finishes, if the wallet is still unlocked, and otherwise at the
  next unlock.
- If re-encryption fails, no record is changed, the wallet keeps reporting
  and refusing, and `debug.log` records the reason. The next unlock tries
  again. Records that failed validation are never re-encrypted, and signing
  stays disabled until the wallet is restored or repaired.

Backups
-------

- `backupwallet` and the GUI's backup now refuse to copy a wallet while
  `reencryption_required` is `true`, because the copy would contain the
  unencrypted keys. `backupwallet` fails with error code -13
  (`RPC_WALLET_UNLOCK_NEEDED`), and the error says what to do. Unlock the
  wallet once so that it re-encrypts the keys, check that
  `reencryption_required` is `false`, and then make the backup.
- A scheduled `backupwallet` job for an affected wallet therefore starts
  failing after the upgrade, and keeps failing until the wallet has been
  unlocked once. Check such jobs for error -13.
- `backupwallet` has a new optional second argument,
  `allow_unencrypted_pqc_keys` (default `false`). Set it to `true` to make the
  backup anyway, for example for a wallet with records that failed
  validation, which are never re-encrypted. Anyone with such a backup can read
  those keys without the passphrase.
- The GUI has no such option. To copy a wallet whose records failed
  validation, unload it and run
  `qbit-wallet -wallet=<name> -dumpfile=<file> dump`, with the same
  `-datadir` and chain options as for `qbitd` (an empty name for the default
  wallet), and restore the dump with
  `qbit-wallet -wallet=<new name> -dumpfile=<file> createfromdump`. The dump
  file contains those keys too.

Which funds are at risk
-----------------------

The affected keys are keys the refill added, beyond the wallet's keypool at
the time of encryption.

- A wallet that was not blank when it was encrypted got a new seed at
  encryption. The affected keys belong to its old descriptors, which are no
  longer used for new addresses, and were never handed out as addresses.
  Funds are exposed only if those addresses are paid anyway, for example
  because a copy of the wallet restored from a backup made before encryption
  handed them out.
- A blank wallet with imported descriptors keeps them active through
  encryption. The affected keys are then its upcoming receive and change
  addresses, so funds the wallet received after encryption may sit on them.

Re-encrypting the wallet cannot make these keys secret again. Older wallet
files and every backup made from an affected wallet before its re-encryption
still contain them, and nothing in this release can change those copies. If you are not sure that the
wallet file and all of its backups stayed private, create a new wallet with a
passphrase using this release, move your funds to it, and then delete the old
backups. For a blank wallet with imported descriptors, stop receiving to those
descriptors as well.
