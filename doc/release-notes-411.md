`walletpassphrase` refills P2MR keypools before it returns
==========================================================

A locked wallet cannot derive P2MR keys. Until it is unlocked again, it can
hand out only the P2MR addresses already in its keypool, and `getnewaddress`
then fails with error `-12`, `Keypool ran out`. `walletpassphrase` therefore
refills the P2MR receive and change keypools to `-keypool` before it returns,
as v1.0.0 did. The timeout counts from the end of the refill, so even a short
timeout leaves the keypools full, unless addresses or change are used while
the wallet is unlocked.

The refill takes roughly 15 ms per missing key on a typical machine: about
3 seconds for 200 addresses handed out since the last unlock. The first unlock
of a wallet created with a passphrase derives about twice `-keypool` keys, so
its duration grows with `-keypool`: about 30 seconds at the default
`-keypool=1000`, and about 5 minutes at `-keypool=10000`. Meanwhile,
`walletlock`, `walletpassphrasechange`, another `walletpassphrase`,
`unloadwallet`, rescans and descriptor imports on that wallet wait for the
refill, as do locking the wallet and changing its passphrase in qbit-qt, and
unlocking it in qbit-qt while unencrypted PQC keys that v1.0.0 wrote still
need re-encrypting (see the notes for #283).

If a refill step fails, for example on a database write error,
`walletpassphrase` now returns error `-4`. The wallet is still unlocked in
that case, and locks again when the timeout expires or on `walletlock`. If
addresses are handed out from the same wallet during the refill about as fast
as it derives keys, the refill stops after about twice the steps an empty
keypool needs, counted for each keypool, and the rest continues in the
background while the wallet stays unlocked.

Unlocking a wallet in qbit-qt does not refill a partly used P2MR keypool; it
only resumes a pending initial top-up in the background (#355).

The exchange integration guide now recommends calling `keypoolrefill` before
`walletlock`, so that addresses and change used while the wallet was unlocked
are replaced before it locks.
