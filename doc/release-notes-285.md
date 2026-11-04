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

Failures after the encryption
-----------------------------

If anything failed after `encryptwallet` had committed the encryption, such as
a write error while generating the new seed's keys, the RPC returned error `-1`
although the wallet was encrypted. The wallet also stayed unlocked with no
relock, and descriptors from the failed step stayed in memory without their
records on disk, so new addresses could come from a descriptor that the next
start would load inactive. The wallet is now locked whenever the call returns,
those descriptors are removed again, and the RPC succeeds with a result that
starts with `wallet encrypted; Warning:` and says that the new HD seed was not
set up. New addresses then still come from the previous seed, as after an
interrupted encryption, unless the new seed's descriptors were already written.
In this case qbit-qt still reports a fatal error and quits, and `debug.log` has
the reason; the wallet loads encrypted and locked at the next start.

A new P2MR wallet fills most of its keypool in the background during its first
minute or so. Only active descriptors were filled, so a wallet encrypted before
that finished kept a 16-address lookahead for its previous seed, and later
payments to that seed's addresses, for example from a backup taken before
encryption, were not detected. `encryptwallet` now fills those descriptors
first, which can make it take up to twice as long in that window. Wallets that
were already encrypted in that window keep the short lookahead.
