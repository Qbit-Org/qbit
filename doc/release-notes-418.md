Wallet encryption checks that unencrypted descriptor keys are removed
=====================================================================

When `encryptwallet`, or encrypting a wallet in the GUI, replaced a
descriptor's unencrypted private key record with its encrypted record, it
ignored whether writing the encrypted record or erasing the unencrypted one
had succeeded. If either failed, the wallet still reported itself as
encrypted while the unencrypted private key record stayed in the wallet file
(#296).

Such a failure now fails the encryption. As with any other failure while the
wallet's keys are being encrypted, `qbitd` or `qbit-qt` then stops with an
assertion failure, without saving any part of the encryption. After a restart
the wallet loads unencrypted, with all of its keys. It can be encrypted again
once the cause of the database error has been fixed.

PQC keys are handled the same way.
