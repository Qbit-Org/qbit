# Future block time v2 and chain freshness

Qbit uses a 60-second aggregate target, 75-second permissionless and
300-second AuxPoW lane targets, and a two-hour lane-local ASERT half-life.
Future block time v2 and the accompanying freshness review replace inherited
Bitcoin wall-clock assumptions with qbit-specific limits while keeping
historical wallet searches safe.

## Consensus rule

| Network | First v2 block | Limit before v2 | Limit at and after v2 |
| --- | ---: | ---: | ---: |
| main | 0 | n/a | 10 minutes |
| testnet4 | 60,000 | 2 hours | 10 minutes |
| test, signet, regtest | 0 | n/a | 10 minutes |

Regtest may override the activation with
`-testactivationheight=futuretime@<height>`.

The candidate block height selects the rule. On testnet4, blocks through
height 59,999 may be no later than node time plus two hours. Block 60,000 and
later may be no later than node time plus ten minutes. A block exactly at the
applicable limit is valid; one second beyond it is temporarily rejected as
`time-too-new` and may be reconsidered after wall time advances.

Ten minutes is ten aggregate target intervals, eight permissionless target
intervals, two AuxPoW target intervals, and one twelfth of the ASERT half-life.
A ten-minute timestamp displacement changes the target of the following block
in the same lane by approximately `2^(600/7200)`, or 5.95%, compared with a
factor of two for a two-hour displacement. The timestamp does not change the
difficulty of the block carrying it.

Future block time v2 and P2MR validation-weight v2 both activate at testnet4
height 60,000, but they are independent consensus parameters. Regtest can set
their heights separately.

## Activation timestamp headroom

A valid block timestamp must be greater than the preceding median time past
and no later than node time plus the applicable future-time limit. If six of
the final eleven preactivation blocks are substantially future-dated, median
time past can temporarily exceed the v2 upper bound at height 60,000. Mining
RPCs then report that no valid timestamp is available until wall time catches
up; the consensus rule has no activation exception.

Before activation, operators must:

- synchronize node and pool clocks with reliable NTP sources;
- monitor the final eleven block timestamps and median time past;
- inspect `future_block_time.next_block_time_headroom_seconds` in
  `getblockchaininfo`; and
- stop creating deliberately future-dated templates under the legacy rule.

## RPC observability

`getblockchaininfo.future_block_time` reports both limits, activation height,
tip and next-block activation state, blocks remaining, and next-block minimum,
maximum, and headroom timestamps.

`getblocktemplate.future_block_time` and
`createauxblock.future_block_time` report the limit and activation state for
that candidate. Both mining paths fail rather than return an impossible
candidate when median time past exceeds the current upper bound.

## Non-consensus freshness limits

The same review sets the following local policy and display values. These take
effect when a new binary is installed and are not height-activated.

| Behavior | Qbit value | Invariant |
| --- | ---: | --- |
| GUI synced-state gap | 10 minutes | Mark stale after ten missed aggregate targets |
| Fee-estimation tip age | 20 minutes | Stop learning after twenty missed aggregate targets |
| Default IBD tip age | 3 hours | Treat the tip as stale after 180 missed aggregate targets |
| Wallet anti-fee-sniping tip age | 1 hour | Disable height locktime after sixty missed aggregate targets |
| Verification-progress recent window | 15 minutes | Use height-derived progress only for a recent chain |

The wallet and RPC `TIMESTAMP_WINDOW` remains two hours and is defined
independently of the active future-time limit. It protects imports, rescans,
pruning timestamp searches, and existing history that was valid under the
legacy rule.

Qbit also retains its existing 60-second `MAX_TIMEWARP`, eleven-block median
time span, and headers-sync commitment period and redownload buffer. Header
sync deliberately budgets for the legacy two-hour history even after v2 is
active.
