Per-peer budget for validating rejected transactions
====================================================

P2P and network changes
-----------------------

- The time the node spends validating a transaction received from a peer is
  now measured, and charged to that peer when the transaction is rejected for a
  reason in the transaction itself (invalid by consensus, non-standard, or with
  a mutated or missing witness). This includes transactions from `tx`
  messages, orphan reconsideration and package evaluation. Rejections that
  depend on the node's chain or mempool state, such as missing inputs,
  conflicts, fee and mempool limits, are not charged. Transactions submitted
  over RPC are never charged.

- Each peer earns 500 µs of credit per second of connection, up to 100 ms, and
  can use it once it has reached 100 ms. Until then, and while its credit is
  used up, the peer draws on a node-wide pool of 500 ms that refills at 50 ms
  per second. With the default 125 connections this bounds the charged time to
  about 11 % of the message-handling thread over time, apart from the one
  transaction that takes a peer's credit or the pool below zero, which is
  charged in full down to a floor of -1 s. Raising `-maxconnections` raises
  the bound by 0.5 ms per second for each extra connection. The node's
  periodic coins cache flush, which mempool acceptance also runs at its end,
  is run just before the measured time starts, so it is not charged unless it
  falls due during the validation itself.

- While a peer has no credit it can use and the pool is empty, the node stops
  validating that peer's transactions until the budget refills: transactions
  it sends are dropped without validation and requested from other peers that
  announce them, transactions are not requested from it (including those it
  announced earlier), and its orphan transactions wait. A dropped transaction
  is not added to the reject filters, so the same transaction from another
  peer is validated as usual. The peer is not disconnected or discouraged.
  Peers with the `noban` permission and manual connections are exempt.

- A debug log line (`-debug=net`) marks when a peer goes over its budget and
  when it is within it again, with the number of transactions dropped
  meanwhile.

Updated RPCs
------------

- `getpeerinfo` reports three new fields once the version handshake with a
  peer has completed: `failed_tx_validation_time` (the total time in
  microseconds spent validating the peer's transactions that were rejected for
  a reason in the transaction itself, also for exempt peers),
  `tx_validation_throttled` (whether the peer's transactions are currently not
  validated) and `tx_dropped_while_throttled` (the number of transactions
  received from the peer that were dropped without validation because the
  peer was over its budget).
