Removing unencrypted keys from a wallet file after encryption
=============================================================

`encryptwallet` deleted a wallet's unencrypted private keys, then spent about
30 seconds generating a new keypool, and only then rewrote the wallet file.
The deleted keys stayed readable in the file until that rewrite. If the
process stopped during those 30 seconds, or the rewrite failed, nothing removed
them later. For a wallet encrypted in place, these are the keys that control
its existing funds.

The file is now rewritten immediately after the keys are deleted, and the
wallet records that this succeeded. An encrypted wallet without that record is
rewritten when it is next loaded, before any other work on it starts. If that
rewrite fails, the wallet still loads, with a warning, and the rewrite is tried
again at the next load.

Backups copy a wallet file's free space byte for byte, so `backupwallet` and the
GUI's backup now run a pending rewrite first. If it fails, the backup is refused
with an error. `encryptwallet` adds a warning to its result if its rewrite
failed.

Rewriting needs free disk space of up to twice the size of the wallet file. Part
of that is a temporary copy in the temporary directory, which may be on another
filesystem. The rewrite now also empties the wallet's `-journal` file, which
otherwise kept copies of the deleted keys for as long as the wallet stayed
loaded.

Every wallet encrypted by v1.0.0 is rewritten once, the first time this release
loads it, which adds to that load's duration in proportion to the file's size.
`qbit-wallet` does not rewrite wallets. The new record is ignored by v1.0.0, so
downgrading still works.

Rewriting cannot reach copies made earlier. These can still contain unencrypted
keys:

- a backup taken before encryption;
- a backup taken by v1.0.0 during or after an interrupted encryption, and before
  upgrading: upgrading rewrites the wallet file, not older copies;
- a backup taken by v1.0.0 after a failed rewrite and before the wallet's next
  load. This release no longer makes such a backup.

Encryption still generates the replacement seed only after this rewrite. If the
process stops before the new seed is written, the wallet stays encrypted but
keeps using its old seed for new addresses, and the old seed's keys were
unencrypted on disk until the rewrite. Consider creating a new wallet with a
passphrase and moving your funds if `encryptwallet` was interrupted.
