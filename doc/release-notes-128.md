Qt failed P2MR/PQC signing usage
================================

The qbit-qt Sign/Verify dialog now reports wallet-local PQC signature counts,
remaining budgets, limit states, and warnings when a P2MR data-signing attempt
fails after consuming one or more committed counter reservations. This helps
operators identify affected keys and make rotation decisions even when no
portable proof was produced.

Failed attempts continue to produce no proof output. Successful portable proofs
remain limited to verifier-required fields and do not include wallet-local usage
or retry-key metadata.
