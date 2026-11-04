Concurrent `send` calls no longer all report success for one coin
=================================================================

`send` selects coins, then signs without holding the wallet lock, which takes
about 200 ms per P2MR input. Concurrent `send` calls could therefore select the
same coin, and every one of them returned `complete: true` and a txid. Only one
of those transactions entered the mempool; the others stayed in the wallet and
could never confirm.

`send` now checks, under the wallet lock it holds to commit, that no wallet
transaction started spending one of its inputs while the call was running.
Abandoned and conflicted transactions do not count, as elsewhere in the
wallet. A call that loses the race fails with error code -4
(`RPC_WALLET_ERROR`), names the transaction that won, returns no txid, and adds
nothing to the wallet or the mempool. If it was called with
`lock_unspents=true`, it unlocks the coins it locked, except those that were
locked before the call. The call can be retried; a retry selects coins again.
The losing call has already signed, so it has still used a signature counter
value for each P2MR input it signed. Counters may over-count in this way but
never under-count.

Replacing a wallet transaction by passing its inputs to `send` in `inputs`
still works: a transaction that already spent those inputs when the call
started does not make it fail. When several such calls race to replace the
same transaction, one succeeds and the others fail as above, provided each
started before the first of them committed. A call that starts after another
has committed treats that transaction as the one it replaces, as before; if it
does not pay enough to replace it, the mempool rejects it, but the call still
returns a txid, as an underpriced replacement does today.

Other wallet commands that send are unchanged by this fix, including
`sendall`, `sendtoaddress` and `sendmany`, which hold the wallet lock from coin
selection through commit, and the GUI send flow. Calls to `send` with
`add_to_wallet=false` or `psbt=true`, and calls whose transaction is not fully
signed, broadcast nothing and behave as before.

The help for `walletcreatefundedpsbt` now says to set `lockUnspents` when
funding PSBTs concurrently. (#281)
