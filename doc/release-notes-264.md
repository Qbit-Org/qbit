PQC signature security margin and raw-key usage limits documented
=================================================================

A new reference note, `doc/reference/p2mr-signature-security.md`, explains how the security margin of the `SLH-DSA-SHA2-128s-bounded30`
signature profile depends on how many signatures a key produces. A key keeps
the full 128-bit classical level up to about `2^26` signatures, and about 118
bits at the `2^30` per-key limit. Rotate high-volume keys well before the
limit. The note includes a script that reproduces these figures.

The help for `signrawtransactionwithkey` and `descriptorprocesspsbt` now states
that PQC signature counts for keys passed to these RPCs are not tracked across
calls. Each call treats every key as unused, so the caller must keep each key
within its limit of 1,073,741,824 signatures. The `importdescriptors` help now
states that an imported key's counter does not include signatures made outside
this wallet. Only signing behavior is documented; it has not changed.
