Qt P2MR/PQC proof privacy
=========================

The qbit-qt Sign/Verify dialog now displays and copies only the fields required
to verify a P2MR/PQC data-signature proof. Wallet-local PQC signature counts,
limits, remaining budget, usage states, warnings, and public keys observed in
failed leaf retry attempts are no longer included in Qt proof JSON.

PQC usage warnings and remaining-budget information continue to be shown in
the local signer status. Existing proof JSON containing the former optional
fields remains accepted by both qbit-qt and the `verifydatapqchash` RPC.

The `signdatapqchash` RPC now omits wallet-local PQC usage fields by default so
its result remains bounded and portable. Set `include_pqc_usage=true` to include
those fields for local diagnostics.
