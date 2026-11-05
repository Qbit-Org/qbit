A failed commit in a background keypool refill no longer stops the node
=======================================================================

If the wallet database could not commit a keypool top-up, for example
because the disk was full, the top-up threw an exception even after it had
rolled its changes back. In the background P2MR refills, which can run for a
minute or more after a wallet is created, loaded or unlocked, this terminated
`qbitd` or `qbit-qt`.

Such a failure is now reported as an ordinary top-up error. A background
refill logs the reason and "paused after a failed background step", and
starts again at the next unlock, `loadwallet` or restart, or, for a
low-watermark refill, at the next new address. The node still stops if the
rollback itself fails, as before.

Top-ups that run inline now return the failure as well. `keypoolrefill`
reports it with error code -4 instead of -1. `getnewaddress`, block
processing and wallet loading carry on with the keys already derived, as they
already did after a failed database write, instead of failing the call or the
load, or stopping the node from a validation callback. Once those keys are
used up, `getnewaddress` fails with "Keypool ran out".
