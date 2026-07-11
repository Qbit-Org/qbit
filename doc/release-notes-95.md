Qt P2MR/PQC proof privacy
=========================

The qbit-qt Sign/Verify dialog now displays and copies only the fields required
to verify a P2MR/PQC data-signature proof. Wallet-local PQC signature counts,
limits, remaining budget, usage states, warnings, and public keys observed in
failed leaf retry attempts are no longer included in Qt proof JSON.

PQC usage warnings and remaining-budget information continue to be shown in
the local signer status. Existing proof JSON containing the former optional
fields remains accepted by both qbit-qt and the `verifydatapqchash` RPC.

The `signdatapqchash` RPC response and its `include_pqc_usage` default are
unchanged. Set `include_pqc_usage=false` when using that RPC result as a
portable proof.
