P2MR keypool top-up resumes for wallets loaded at startup
==========================================================

A new P2MR wallet derives 16 receive and 16 change keys when it is created and
fills the rest of its keypool (`-keypool`, 1000 by default) in a top-up that
starts 30 seconds later, or, for an encrypted wallet, when it is first
unlocked. If the node stopped before that top-up finished, an unencrypted
wallet loaded at node startup through `-wallet` or `load_on_startup` did not
resume it on any later restart. It finished only after `keypoolrefill` or an
`unloadwallet` and `loadwallet` cycle.

Until then the wallet watched as few as its first 16 receive and 16 change
addresses, depending on how far the top-up had got, plus any addresses it
handed out itself: `getnewaddress` past the last derived address still worked,
deriving one key at a time. Payments and change sent to later addresses of the
same seed, for example by a restored backup or another copy of the wallet,
were not seen. `getwalletinfo` shows such a wallet with a `keypoolsize` well
below `-keypool`.

Wallets loaded at startup now resume the pending top-up 30 seconds after the
wallets start, as `loadwallet` already did. This includes wallets left in this
state by earlier versions. A locked encrypted wallet still finishes the top-up
when it is first unlocked, as before. The resumed top-up watches the new
addresses from then on, but does not find payments already made to them: run
`rescanblockchain` once `keypoolsize` has reached `-keypool`.
