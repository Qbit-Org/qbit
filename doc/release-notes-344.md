Qt PSBT signing at shutdown and wallet unload
=============================================

Quitting qbit-qt while the Load PSBT dialog is signing now cancels the signing
if it has not reserved PQC signature counters yet, so shutdown no longer waits
for the whole signing and no counters are consumed. Signing that has already
reserved counters cannot be stopped and still finishes. Every window is hidden
by then, so qbit-qt writes the outcome to `debug.log`, including the signature
counts, limit states and warnings of each PQC key used, and saves a signed PSBT
to the data directory as `unshown-psbt-<txid>-<time>.psbt`, where File > Load
PSBT can open it. The log line names the file; the PSBT itself is not written
to the log. This includes a partial signature added to a multisig input, which
consumes a counter without completing the input. A PSBT that the dialog signed
but that was not copied, saved or broadcast before shutdown is saved the same
way.

The PSBT dialog can no longer be closed while it is signing, which used to
block the GUI until the signing finished and discard its result. After Cancel,
the progress dialog stays on screen until signing has actually stopped, or
until it finishes if the cancellation came too late to prevent the counter
reservation. Saving a PSBT to a file that cannot be written now reports a
failure instead of "PSBT saved to disk."

When the wallet is unloaded while the PSBT dialog is signing, a successful
signature is now kept and reported as signed, with a note that the wallet was
unloaded, and the PSBT can still be copied, saved or broadcast. It used to be
discarded and reported as a failure.

The PQC usage panel shown in the transaction list after a fee bump is now
labelled with the local time the replacement was committed, rather than the
time the panel was shown, which could be later when a usage warning was shown
first.
