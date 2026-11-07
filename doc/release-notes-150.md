Wallet history
--------------

Fee-bearing self-transfers whose outputs are all classified as change now
appear once in default wallet history. The GUI shows a “Payment to self” row
with the net fee debit. `gettransaction.details`, `listtransactions`, and
`listsinceblock` return a fee-only `send` entry with zero `amount` and a negative
`fee`. This transaction-level entry omits `address`, `label`, and `vout`.

`listsinceblock` with `include_change=true` continues to return the existing
output-level send and receive entries. Wallet balances and UTXO accounting are
unchanged. (#147)
