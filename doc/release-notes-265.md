P2MR data-signature checks use the signature cache
==================================================

`OP_CHECKDATASIGPQC` and `OP_CHECKDATASIGADDPQC` checks now use the
signature cache, like P2MR transaction signatures since #162. Previously every
data-signature check ran a full SLH-DSA verification. A data signature does not
commit to the spending transaction, so a peer could resubmit one valid
signature in an unlimited number of mutated transactions, each costing a full
verification during mempool admission. Such replays now cost one verification.

Only verified successes are cached, in a separately salted domain, so an entry
for a transaction signature can never satisfy a data-signature check or the
reverse. Validity, validation weight and script errors are unchanged; this is
not a consensus change.

Known limitation: failures are not cached. Anyone holding one valid signature
can derive unlimited distinct invalid PQC signatures that each still cost a
full verification, on both the data-signature and transaction-signature paths.
Because this release does not penalize peers that relay consensus-invalid
transactions, a peer can cost a node about 0.5 µs of message-handling and
`cs_main` time per witness byte. Discouraging peers whose P2MR PQC signatures
fail, or budgeting script-validation cost per peer, are possible follow-ups.
