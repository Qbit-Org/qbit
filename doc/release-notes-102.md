P2MR validation-weight accounting
---------------------------------

Testnet4 activates P2MR validation-weight v2 at block 60,000 without a chain
reset. The successful-PQC-signature debit changes from 3,730 to 3,683 units at
activation, allowing canonical high-threshold `mr(multi_a(...))`
satisfactions such as direct 5-of-5 leaves to validate without annex or script
padding. Mainnet uses the corrected accounting from genesis.

Wallet signing now rejects P2MR plans that exceed initial-stack resource
limits before producing stateful PQC signatures. Descriptor tooling identifies
trees without a wallet-constructible satisfaction; such descriptors may be
retained inactive for inspection but cannot be activated or derived for
funding through the normal RPC path.

All testnet4 miners, archive nodes, wallets, and other validating services must
upgrade before block 60,000. Older nodes reject blocks that exercise the new
validation budget and can remain on a stale fork.
