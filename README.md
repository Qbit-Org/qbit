qbit
=====

This repository contains the qbit node, wallet, GUI, and developer tooling.
qbit is based on Bitcoin Core v30.2, but it is a distinct chain with qbit
network identity, qbit binaries, qbit data directories, P2MR launch-chain
wallet outputs, PQC signing, ASERT/Cadence/AuxPoW mining, archive/full-history
defaults, opt-in witness pruning, and archive bootstrap fallback through
`-connectarchive`.

Current public status and launch resources are published through
https://qbit.org. Mainnet is not public yet; any mainnet-oriented examples in
this source tree are guidance for when qbit mainnet is announced.

Official public testnet release artifacts are for qbit testnet4. Start them
with `-testnet4` or `-chain=testnet4`; no-flag mainnet commands in this tree
are future-mainnet guidance only. The in-tree mainnet parameters, genesis
block, and any derived hash are development placeholders, not a qbit mainnet
launch commitment.

The qbit source is open, so third parties can fork it or run private networks.
Only qbit-published artifacts, tags, release notes, seed resources, and
qbit.org announcements define official qbit networks.

Start Here
----------

- Public testnet: [doc/user/public-testnet.md](doc/user/public-testnet.md)
- qbit differences from Bitcoin Core:
  [doc/user/bitcoin-core-differences.md](doc/user/bitcoin-core-differences.md)
- Running a node when the target network is announced:
  [doc/user/run-node.md](doc/user/run-node.md)
- Wallets, P2MR addresses, and backups:
  [doc/user/wallet/p2mr-wallets.md](doc/user/wallet/p2mr-wallets.md)
- Exchange and service integration:
  [doc/integration/exchange-integrator-quickstart.md](doc/integration/exchange-integrator-quickstart.md)
- Mining and pool integration:
  [doc/integration/mining-pool-quickstart.md](doc/integration/mining-pool-quickstart.md)
- Source build docs: [doc/build/](doc/build/)

Documentation Index
-------------------

The public documentation index is [doc/README.md](doc/README.md). It separates
primary user-facing docs from integration guides, technical references, and
source contributor references.

Security and Release Verification
---------------------------------

To report security issues, email contact@qbit.org (not for support). Use
https://qbit.org for public security, release, or network-resource
announcements.

Contributing
------------

The public contribution process is owned by the official qbit GitHub
repository at https://github.com/Qbit-Org/qbit. This tree intentionally does
not point contributors to Bitcoin Core issues, IRC, mailing lists, or review
process pages. See [CONTRIBUTING.md](CONTRIBUTING.md) for the source
contributor guidance that applies inside this repository.

License
-------

qbit is released under the terms of the MIT license. See [COPYING](COPYING) for
more information.
