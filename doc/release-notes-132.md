Future block time and chain freshness
=====================================

Testnet4 activates future block time v2 at block 60,000. Blocks below the
activation retain the two-hour maximum future timestamp; block 60,000 and
later use a ten-minute limit. This is independent of P2MR validation-weight v2
despite sharing its activation height. Mainnet, testnet3, signet, and default
regtest use the ten-minute rule from genesis; regtest can override it with
`-testactivationheight=futuretime@<height>`.

`getblockchaininfo`, `getblocktemplate`, and `createauxblock` report the
applicable future-time state. Operators should synchronize clocks and monitor
next-block timestamp headroom before activation because future-dated legacy
blocks can temporarily raise median time past above the new limit.

Qbit-specific non-consensus freshness settings now use a ten-minute GUI stale
gap, twenty-minute fee-estimation tip age, three-hour default IBD tip age,
one-hour wallet anti-fee-sniping tip age, and fifteen-minute recent-header
window for verification progress. The wallet and RPC historical timestamp
window remains independently fixed at two hours.
