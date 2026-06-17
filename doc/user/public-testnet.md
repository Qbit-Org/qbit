# Public Testnet Resources and Status

This page is for outside testers who want to join qbit public testnet through
public self-service guidance. It describes the current testnet4 identity, how to
start a node, which public infrastructure is required for onboarding, and what
to do while that infrastructure is not yet available.

qbit testnet is not Bitcoin testnet. Use qbit binaries, qbit network flags, and
qbit addresses only.

Official public testnet release artifacts are testnet-only. Use `-testnet4` or
`-chain=testnet4` for every daemon, CLI, wallet, and GUI invocation that joins
the public rehearsal network. Mainnet is not public or launched yet; no-flag
mainnet commands in other docs are future-mainnet guidance only.

## Current Status

The current public rehearsal network is qbit `testnet4`. The
`v0.1.0-testnet4` release starts a reset lineage and is not compatible with
earlier rc testnet4 chain data.

The qbit codebase defines testnet4 chain parameters, ports, address prefixes,
archive-node behavior, the `-testnet4` command-line flag, DNS seed hostnames,
and archive fallback endpoints. The current values in this page are confirmed
for the current public testnet4 reset rollout. No public faucet or explorer
exists at this time. If the release you are using has not published test-coin
distribution instructions, those resources are not available yet from this
document alone.

The in-tree mainnet parameters, genesis block, and any derived hash are
development placeholders. They are not an official qbit mainnet launch hash,
network identity, or release commitment. The in-tree mainnet AuxPoW chain ID
currently matches public testnet as a placeholder only; it must be replaced
with a distinct final value before mainnet is enabled or reset.

The qbit source is open, so third parties can fork it or run private networks.
Only qbit-published artifacts, tags, release notes, seed resources, and
qbit.org announcements define official qbit networks.

Before treating any testnet as live, check qbit.org for the release notes or
public launch announcement for:

- the exact release version and build identifier
- DNS seed hostnames
- fixed-seed status
- archive fallback endpoints
- test-coin distribution instructions, if any
- whether a public explorer is explicitly announced
- any reset or migration notice

## Network Identity

The current testnet4 reset parameter shape is:

| Item | Value |
|---|---|
| Chain flag | `-testnet4` or `-chain=testnet4` |
| Default P2P port | `48355` |
| Default RPC port | `48352` |
| Default onion bind port | `48356` |
| Address HRP | `tq` |
| Message start / network magic | `0xc7c41640` |
| AuxPoW chain ID | `31430` |
| Genesis block | `000000000000796fe86bbc0bf1b66a07e4b4c0676f74b54cf7e5ce8b3f1a0090` |
| Genesis bits | `0x1a7f1ab5` |
| Spendable address model | P2MR |

These values must match the binary you are running. If a launch release
publishes updated seed sets, use the values from that release for that network
instance.

This testnet4 genesis hash is a rehearsal-network value for the current reset
lineage. Do not treat it, or any in-tree mainnet placeholder hash, as a future
mainnet launch commitment unless a qbit release announcement explicitly freezes
it for that network.

## Start a Node

Start qbit on testnet4:

```bash
qbitd -testnet4
```

Use `qbit-cli` with the same network flag:

```bash
qbit-cli -testnet4 getblockchaininfo
qbit-cli -testnet4 getnetworkinfo
```

The node stores testnet4 data under the `testnet4` network directory inside your
qbit data directory. Do not reuse a Bitcoin Core data directory.

If you ran an earlier qbit testnet4 rc lineage, remove or archive the old
`testnet4` network directory before starting this reset release. Old chain data
will not connect to this reset lineage.

By default, qbit nodes keep full witness history and advertise archive
capability. Do not enable witness pruning unless you understand the tradeoff:

```bash
qbitd -testnet4 -prunewitnesses=1
```

Witness-pruned nodes save storage by pruning historical witness data beyond
coinbase maturity depth, but they are not suitable as full archive bootstrap
peers.

## Peer Discovery

The normal path is to start with default peer discovery enabled:

```bash
qbitd -testnet4
```

The current testnet4 reset release ships DNS seeds and compiled fixed seed IP
addresses. The node should discover peers automatically when the public seed
infrastructure is reachable.

Current reset public resources:

| Resource | Status |
|---|---|
| DNS seed 1 | `coherence-testnet4.qbit.org` |
| DNS seed 2 | `triplet-testnet4.qbit.org` |
| Fixed seeds | `57.129.86.61:48355`, `40.160.66.196:48355` |
| Archive endpoint 1 | `fermion-testnet4.qbit.org:48355` |
| Archive endpoint 2 | `boson-testnet4.qbit.org:48355` |
| Test-coin distribution | No public faucet is assumed; use qbit.org if one is announced |
| Explorer | No public explorer is assumed; use qbit.org if one is announced |

Fixed seeds and archive endpoints may refer to the same underlying
archive-capable nodes at launch, but they are different surfaces. Fixed seeds
are compiled into the release and used automatically as fallback peer addresses.
Archive endpoints are published `-connectarchive=<host:port>` values for manual
archive bootstrap fallback.

## Archive Fallback

Fresh full-validation nodes should be able to bootstrap from archive-capable
peers. If normal discovery is degraded and the project has published archive
fallback endpoints, use `-connectarchive`.

Command-line example:

```bash
qbitd -testnet4 \
  -connectarchive=fermion-testnet4.qbit.org:48355 \
  -connectarchive=boson-testnet4.qbit.org:48355
```

`qbit.conf` example:

```ini
testnet4=1
connectarchive=fermion-testnet4.qbit.org:48355
connectarchive=boson-testnet4.qbit.org:48355
```

Use `-connectarchive` for archive fallback. Do not replace it with `-connect`.
Archive connections are checked for `NODE_NETWORK`, `NODE_WITNESS`, and
`NODE_ARCHIVE`, and qbit disconnects peers that advertise or imply
`NODE_WITNESS_PRUNED`.

To inspect archive-relevant peer state:

```bash
qbit-cli -testnet4 getarchivepeers
qbit-cli -testnet4 getarchivepeers summary
```

`getarchivepeers` reports observed and configured state. A peer advertising
`NODE_ARCHIVE` is not cryptographic proof that it can serve every historical
block, but it is the service signal qbit uses for archive bootstrap.

## Verify Sync

Check chain identity and sync state:

```bash
qbit-cli -testnet4 getblockchaininfo
```

Look for:

- `"chain": "testnet4"`
- `blocks` increasing over time
- `headers` at least as high as `blocks`
- `initialblockdownload` becoming `false`
- `verificationprogress` near `1`
- `bestblockhash` matching the release or network status page, if one is
  published

Check peers:

```bash
qbit-cli -testnet4 getpeerinfo
qbit-cli -testnet4 getnetworkinfo
```

If you have no peers, confirm that DNS is enabled, that your firewall allows
outbound connections to port `48355`, and that the release has actually
published live seeds or fallback endpoints.

## Wallet and Test Coins

qbit public networks use P2MR for spendable outputs. Create or load a wallet and
request a P2MR testnet address:

```bash
qbit-cli -testnet4 createwallet "testnet-wallet"
qbit-cli -testnet4 getnewaddress "" "p2mr"
```

The address should use the `tq` HRP.

No public qbit faucet is assumed at this time. If a public test-coin
distribution path is published for the network, qbit.org is the source of
truth. Do not use Bitcoin testnet services; they operate on a different
network.

If no distribution path is published, test coins are not self-service unless
you mine them or receive them through the release's named support channel.

## Known Limitations

Until launch infrastructure is fully validated:

- DNS seed or archive endpoint availability may be interrupted during rollout.
- No qbit faucet exists yet.
- No qbit explorer exists yet.
- The network may be reset before a later release candidate.
- Test coins have no economic value and may be invalidated by a reset.

Do not assume that a local node can instantly mine testnet4 blocks the way a
regtest node can. Use regtest for local application development that requires
instant block production.

## Report Problems

When reporting a testnet problem, include:

- qbit version and build identifier
- operating system
- startup command or relevant `qbit.conf` entries
- whether you used default discovery or `-connectarchive`
- output from `qbit-cli -testnet4 getblockchaininfo`
- output from `qbit-cli -testnet4 getnetworkinfo`
- output from `qbit-cli -testnet4 getarchivepeers summary`
- relevant `debug.log` lines

Use the support channel named on qbit.org or in the release announcement. Do
not include private keys, wallet seed material, RPC passwords, or full
`qbit.conf` files containing credentials.
