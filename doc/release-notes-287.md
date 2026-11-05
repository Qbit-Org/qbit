Locking a wallet waits until signing has freed its decrypted keys
==================================================================

To sign a transaction, an encrypted wallet copies decrypted ECDSA and PQC
keys into temporary signing providers. Locking the wallet, through
`walletlock` or when a `walletpassphrase` timeout expires, waits for active
signing operations before it clears the master key. Transaction signing, as
used by `sendtoaddress`, `sendmany`, `bumpfee` and
`signrawtransactionwithwallet`, ended its signing operation before freeing
those copies, so the lock could return while they were still in memory. The
copies include every PQC key of the descriptors used, so freeing them takes
longer as the keypool grows. PSBT signing already freed its copies first.

Transaction signing now frees the copies before the lock can complete. The
copies were, and still are, wiped when freed; only the order relative to the
lock has changed.
