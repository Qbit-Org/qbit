`walletpassphrase` no longer holds the wallet lock while it refills P2MR keypools
================================================================================

The first `walletpassphrase` of a wallet created with a passphrase derived
the rest of its P2MR keypool before it returned: about 2,000 keys, or roughly
30 seconds, at the default `-keypool=1000`. An unlock after a P2MR keypool
had drained also refilled it to `-keypool` before returning. All that time
the RPC held the wallet lock, so every other RPC on that wallet waited, and so
did the validation callbacks of all wallets, which on a busy node could also
delay block connection.

`walletpassphrase` still refills the P2MR keypools, including a pending
initial top-up, before it returns (see the notes for #411). It now derives the
keys in short steps that each hold the wallet lock only briefly, so most other
RPCs on the wallet and the validation callbacks keep running meanwhile.

Locking the wallet, through `walletlock`, qbit-qt or the `walletpassphrase`
timeout, now waits for a background keypool step that is running, usually
under a second, so that the step's copies of the decrypted keys are freed
before the lock completes. Background steps include those started at wallet
load, by unlocking in qbit-qt and by `getnewaddress`.

While `walletpassphrase` is still refilling, `walletlock`,
`walletpassphrasechange`, another `walletpassphrase`, `unloadwallet`, rescans
and descriptor imports on that wallet wait until the refill has finished, as
do locking the wallet and changing its passphrase in qbit-qt. The refill of a
new wallet's first unlock derives about twice `-keypool` keys, so this wait
grows with `-keypool`: about 30 seconds at the default, and about 5 minutes at
`-keypool=10000`.
