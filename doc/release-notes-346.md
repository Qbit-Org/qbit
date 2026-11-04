Wallet fees without fee estimates
=================================

- When the fee estimator has no estimate and `-discardfee` is not set, the
  wallet now decides whether change is worth keeping at the rate it pays
  without estimates: `-fallbackfee`, raised to `-mintxfee` and the minimum
  relay fee. That rate stands in for the missing estimate, just as a live
  estimate already limits `-discardfee`. The dust relay fee is still the
  floor. With the default settings the discard rate is therefore the dust
  relay fee (0.0000075 QBT/kvB) instead of the `-discardfee` default
  (0.0001 QBT/kvB). P2MR change is now kept from about 0.0000288 QBT. Before,
  change below about 0.00038 QBT went to the fee, which was up to about 40
  times the fee of the transaction itself. Nothing changes if `-discardfee`
  is set (even to its default value), if `-fallbackfee=0`, or while a fee
  estimate is available.

- The GUI send dialog now shows its "Warning: Fee estimation is currently
  not possible." label whenever there is no fee estimate, including when
  `-mintxfee` or the mempool minimum fee raises the fee rate above the
  fallback fee. Previously it hid the warning in that case and showed a
  confirmation estimate ("within N blocks") that did not exist. The RPC
  `fee_reason` field is unchanged: it still names the rule that set the
  final fee rate, for example "Minimum Required Fee" or "Mempool Min Fee".
