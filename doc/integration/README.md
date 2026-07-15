# Integration Docs

These documents are for services, tools, pools, exchanges, custodians, miners,
and developers integrating with qbit.

Qbit v1.0.0 launches mainnet as the default chain. Public testnet4 remains
available through its explicit chain flags. The source is open, so third
parties can fork it or run private networks, but only qbit-published artifacts,
tags, release notes, seed resources, and qbit.org announcements define official
qbit networks.

## qbit Integration Guides

- [qbit P2MR v1 Consensus Profile](../consensus/p2mr-v1.md) — normative
  commitment, witness, script, signature, and resource rules, including the
  incompatibilities with its pinned ancestry profile.
- [Exchange and Integrator Quickstart](exchange-integrator-quickstart.md)
- [Mining and Pool Quickstart](mining-pool-quickstart.md)
- [RPC Delta and Migration Notes](rpc-delta-reference.md)
- [qbit P2MR v1 Integration Support Matrix](p2mr-v1-support-matrix.md) —
  current public inventory and exact-release evidence requirements. The
  checked-in matrix is intentionally a blocking draft, not mainnet signoff.

## Interface References

These are technical references. They are not replacements for release-specific
network, faucet, explorer, security, or support announcements from qbit.org.

- [Canonical RPC Reference](https://docs.qbit.org/)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [ZMQ](zmq.md)
- [Multiprocess](multiprocess.md)

The REST interface reference is intentionally not listed here yet. It remains
an inherited, unpromoted source reference until it is rewritten with qbit
launch-chain examples and caveats.
