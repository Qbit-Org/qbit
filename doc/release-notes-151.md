Wallet fallback fee enabled by default
======================================

The wallet's `-fallbackfee` now defaults to the minimum relay fee rate
(250 sat/kvB, i.e. 0.0000025 QBT/kvB) instead of being disabled. Previously,
when the fee estimator had no data — the normal state on a young chain with an
empty mempool — transaction creation failed with "Fee estimation failed.
Fallbackfee is disabled." Wallets now pay the relay floor in that case.

The fallback is only used when no smart fee estimate is available; live
estimates take precedence as soon as the estimator has observed confirming
transactions. The final feerate is still clamped to at least the node's
required and mempool minimum feerates, so the fallback can never underpay
relay policy. Set `-fallbackfee=0` to restore the previous behavior of
failing instead.
