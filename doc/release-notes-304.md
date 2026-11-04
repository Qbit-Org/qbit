`walletpassphrase` refills P2MR keypools in the background
==========================================================

The first `walletpassphrase` of a wallet created with a passphrase derived
the rest of its P2MR keypool before it returned: about 2,000 keys, or roughly
30 seconds, at the default `-keypool=1000`. An unlock after a P2MR keypool
had drained also refilled it to `-keypool` before returning. All that time
the RPC held the wallet lock, so every other RPC on that wallet waited, and so
did the validation callbacks of all wallets, which on a busy node could also
delay block connection. The unlock timeout started only after the refill.

`walletpassphrase` now returns as soon as the wallet is unlocked. A pending
initial P2MR top-up, or the refill of a P2MR keypool that has dropped to its
low watermark (a tenth of `-keypool`, but at least 16 keys), runs in short
background steps that do not hold the wallet lock. The steps pause while the
wallet is locked and resume at the next unlock, so with a short timeout the
refill can take several unlocks. Other keypools are still topped up before
the call returns.

Locking the wallet, through `walletlock`, qbit-qt or the `walletpassphrase`
timeout, now waits for a background step that is running, usually under a
second, so that the step's copies of the decrypted keys are freed before the
lock completes. This also applies to the background steps started by
unlocking in qbit-qt or by `getnewaddress`.

Scripts that read `keypoolsize` or `keypoolsize_hd_internal` from
`getwalletinfo` right after `walletpassphrase` may now see a value below
`-keypool` until the refill finishes. `getnewaddress` and transaction
creation keep working meanwhile: past the last derived address they derive
one key at a time. A P2MR keypool above its low watermark is no longer filled
to `-keypool` at unlock; use `keypoolrefill` for that.
