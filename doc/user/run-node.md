# Run a qbit node

This is the normal node guide for qbit operators. qbit uses familiar full-node
concepts, but the network identity, address model, archive behavior, data
directory, and bootstrap expectations are qbit-specific.

This guide assumes `qbitd` and `qbit-cli` are installed and available on your
`PATH`. Current public release and network-resource status is published through
https://qbit.org.

## Pick a network

Mainnet is not public yet. Mainnet parameters below apply when qbit mainnet is
announced. Use the dedicated public testnet guide for the current
rehearsal-network commands. Official public testnet release artifacts are for
testnet4 and should be started with `-testnet4` or `-chain=testnet4`.

| Network | Chain option | P2P port | RPC port | Address HRP |
| --- | --- | ---: | ---: | --- |
| Public testnet4 | `-testnet4` or `-chain=testnet4` | 48355 | 48352 | `tq` |
| Future mainnet | default, or `-chain=main` after launch | 8355 | 8352 | `qb` |

The RPC port is for local control of your node. Do not expose RPC to the public
internet. If you want to help the P2P network, allow inbound TCP traffic to the
P2P port for the network you are running.

## Data directory and config file

qbit uses qbit-native data directories and `qbit.conf`, not Bitcoin Core's
`bitcoin.conf`.

| Platform | Default data directory | Config file |
| --- | --- | --- |
| Linux | `$HOME/.qbit/` | `$HOME/.qbit/qbit.conf` |
| macOS | `$HOME/Library/Application Support/Qbit/` | `$HOME/Library/Application Support/Qbit/qbit.conf` |
| Windows | `%LOCALAPPDATA%\Qbit\` | `%LOCALAPPDATA%\Qbit\qbit.conf` |

Future mainnet chain data is stored in the base data directory. Non-mainnet
chains use their own subdirectories.

## Start a normal mainnet node when launched

This section is future-mainnet guidance. For the current public testnet, use
the public testnet guide and include `-testnet4` on daemon and CLI commands.

Start with the default archive/full-history behavior:

```bash
qbitd -daemon
```

Check that the node is running:

```bash
qbit-cli getblockchaininfo
qbit-cli getnetworkinfo
```

For a first full-validation run, keep normal peer discovery enabled. Do not add
`-connect` unless you intentionally want to disable normal automatic
connections.

## Recommended first config

This is a conservative future-mainnet configuration for a normal operator node:

```ini
server=1
listen=1

# Keep normal peer discovery enabled.
dns=1
dnsseed=1
fixedseeds=1

# Leave witness pruning disabled for the default archive/full-history node.
# prunewitnesses=0

# Leave block pruning disabled if you want to serve historical data.
# prune=0
```

If the release you are running publishes project-operated archive fallback
endpoints through qbit.org, add them only when automatic bootstrap is degraded:

```ini
server=1
listen=1
dns=1
dnsseed=1
fixedseeds=1

connectarchive=positron-mainnet.qbit.org:8355
connectarchive=graviton-mainnet.qbit.org:8355
```

Use the endpoints published for your specific release or network reset. Do not
copy private or internal hostnames into public configuration.

## Archive mode is the default

By default, qbit keeps full block and witness history. A default node that has
not block-pruned or witness-pruned can advertise `NODE_ARCHIVE` and can help
fresh nodes bootstrap full validation.

This is different from treating old witness data as disposable. qbit signatures
are large, qbit has no witness discount, and historical witness data is part of
what other nodes may need for full validation and recovery.

Use archive mode for:

- public bootstrap nodes
- exchange, pool, and infrastructure nodes
- nodes that serve other operators
- any node where historical RPC access matters

## Witness pruning is opt-in

`-prunewitnesses=1` compacts historical witness data beyond coinbase maturity
depth, which is 1,000 blocks on current public qbit networks. It is a
storage-saving mode for operators who understand the tradeoff.

Example:

```bash
qbitd <chain option> -prunewitnesses=1
```

Consequences:

- The node stops being an archive/full-history peer.
- The node advertises `NODE_WITNESS_PRUNED` instead of `NODE_ARCHIVE`.
- The node is not suitable as a bootstrap/archive fallback endpoint.
- Historical verbose block or transaction requests that require pruned witness
  data can fail.
- `-txindex` is incompatible with witness-pruned history.
- Clearing the option later does not magically recreate data that was already
  compacted away. Plan on archive recovery from archive peers or a fresh archive
  sync if you need full history again.

`-prune=<n>` and `-prunewitnesses=1` are separate settings. Block pruning
removes old block files. Witness pruning compacts historical witness data. Do
not enable either mode on a node you intend to use as public archive
infrastructure.

## Bootstrap and seeds

The intended launch posture is:

1. start a normal qbit node with qbit-native defaults
2. discover peers through DNS seeds and fixed seeds
3. find archive-capable peers automatically
4. fall back to published `-connectarchive` endpoints if automatic bootstrap is
   degraded

The v1.0.0 launch source uses `flux-mainnet.qbit.org` and
`phase-mainnet.qbit.org` for automatic DNS discovery. Its fixed seeds are the
numeric launch addresses for `positron-mainnet.qbit.org:8355` and
`graviton-mainnet.qbit.org:8355`. Use qbit.org to confirm their current
operational status for the release and network you are running.

Fixed seeds and archive fallback endpoints are not the same configuration
surface. Fixed seeds are compiled into a release and are used automatically as a
last-resort source of peer addresses. Archive fallback endpoints are published
operator-facing `-connectarchive=<host:port>` values used when automatic
discovery is degraded.

If no live seeds are published for the network you are trying to join, a fresh
node may not discover peers automatically. In that case, use only project
published `seednode`, `addnode`, or `connectarchive` values for that network.

## Use `-connectarchive` for archive fallback

`-connectarchive=<host:port>` is the qbit-specific fallback path for archive
bootstrap. It can be specified more than once and uses addnode-style semantics:
it does not disable normal automatic outbound peer selection.

Example:

```bash
qbitd <chain option> \
  -connectarchive=positron-mainnet.qbit.org:8355 \
  -connectarchive=graviton-mainnet.qbit.org:8355
```

qbit checks these peers before treating them as archive fallback peers. A
`-connectarchive` peer must advertise `NODE_NETWORK`, `NODE_WITNESS`, and
`NODE_ARCHIVE`, and must not advertise or imply `NODE_WITNESS_PRUNED`. qbit
disconnects a configured archive peer that fails those checks.

Do not replace `-connectarchive` with `-connect` for this use case. `-connect`
restricts normal peer discovery and is the wrong default for public bootstrap
troubleshooting.

## Verify sync and network health

Use these RPCs during startup:

```bash
qbit-cli <chain option> getblockchaininfo
qbit-cli <chain option> getnetworkinfo
qbit-cli <chain option> getarchivepeers summary
```

Healthy signs in `getblockchaininfo`:

- `chain` is `main` only for future mainnet after launch, or `testnet4` for the
  current public rehearsal network
- `blocks` and `headers` are increasing during sync
- `blocks` catches up to `headers`
- `verificationprogress` approaches `1`
- `initialblockdownload` becomes `false` when initial sync is complete
- `pruned` is `false` for an archive node

Healthy signs in `getnetworkinfo`:

- `connections_out` is greater than zero
- `connections` is greater than zero
- `localservicesnames` includes `NETWORK`, `WITNESS`, and `ARCHIVE` on an
  archive node
- `localservicesnames` does not include `WITNESS_PRUNED` on an archive node
- `warnings` is empty or contains only warnings you understand

Healthy signs in `getarchivepeers summary`:

- `connected_advertised_archive_peers` is greater than zero when archive peers
  are available through discovery
- `configured_archive_targets` matches the number of `connectarchive` entries
  you configured
- `connected_configured_archive_targets` is greater than zero when using
  fallback endpoints

`NODE_ARCHIVE` is an advertisement, not mathematical proof that a peer can serve
every historical block. Treat `getarchivepeers` as a debugging and monitoring
tool, then confirm actual sync progress with `getblockchaininfo`.

## Firewall and inbound peers

Outbound-only nodes can sync without opening inbound firewall rules, assuming
peer discovery is working. To contribute capacity to the network, allow inbound
TCP traffic on the P2P port:

- future mainnet: TCP `8355`
- testnet4: TCP `48355`

Keep RPC bound to localhost unless you have a private network and explicit
authentication policy:

```ini
rpcbind=127.0.0.1
# Do not set rpcallowip=0.0.0.0/0.
```

## Disk and bandwidth planning

For an archive node, plan for full block history, full witness history, chain
state, indexes you enable, and logs. qbit's long-term storage profile is not the
same as Bitcoin Core because qbit has no witness discount and P2MR/PQC witness
data is larger than typical Bitcoin signatures.

No release-quality numeric storage or bandwidth estimate is available from this
document yet. Until release-specific measurements are published, treat Bitcoin
Core storage estimates as inapplicable and measure `blocks/`, `chainstate/`,
and any enabled `indexes/` on your own node.

Practical guidance:

- use SSD storage for the data directory
- leave free disk headroom for growth and reindex operations
- monitor `blocks/`, `chainstate/`, and optional `indexes/`
- avoid `-txindex=1` unless you need it
- avoid witness pruning on infrastructure nodes
- expect archive nodes with open inbound ports to use more upload bandwidth

Use only release-specific measured chain sizes as operational disk estimates.

## Resource tuning

For small machines, tune memory and peer count before changing archive history:

```ini
dbcache=300
maxmempool=100
maxconnections=40
```

Lower `dbcache` can make initial sync much slower. Lower `maxmempool` evicts
unconfirmed transactions sooner. `maxconnections` only affects automatic
connection limits; manual `addnode` connections have a separate limit.

`blocksonly=1` reduces transaction relay and mempool memory, but it is a
relay/privacy tradeoff, not an archive service mode. Do not use it on nodes
whose job is to support public bootstrap, exchange, pool, explorer, support,
recovery, or custody workflows.

## Troubleshooting

### No peers

Check:

```bash
qbit-cli <chain option> getnetworkinfo
qbit-cli <chain option> getpeerinfo
```

Common causes:

- the network's DNS seeds or fixed seeds have not been published yet
- `dnsseed=0`, `fixedseeds=0`, or `maxconnections=0` is set
- `-connect` is set, which disables normal automatic discovery
- firewall, proxy, Tor, I2P, or `onlynet` settings prevent reachable networks
- you are using endpoints from an older network reset

Use the current qbit.org release or network resources page for seed, addnode,
or archive fallback values.

### Full validation stalls

Check archive peer state:

```bash
qbit-cli <chain option> getarchivepeers
```

If no archive peers are connected and the project has published archive
fallback endpoints, restart with `-connectarchive=<host:port>` for at least two
endpoints.

### My node advertises witness-pruned service

Check whether you started with `-prunewitnesses=1` or reused a data directory
that had already compacted witness history. If the data was already compacted,
do not assume that changing the flag back will restore archive service. Use the
documented archive recovery path if available for your release, or perform a
fresh archive sync.

### RPC commands connect to the wrong chain

Pass the same chain option to `qbit-cli` that you used for `qbitd`:

```bash
qbit-cli <chain option> getblockchaininfo
```

If the daemon was started with a non-mainnet chain flag, pass the same chain
flag to `qbit-cli` or it will look in the wrong network data directory and may
fail to authenticate.

### Disk is filling up

If the node is intended to serve other users or infrastructure, add storage
rather than enabling pruning. If this is a personal non-infrastructure node,
you may choose block pruning or witness pruning after reading the consequences
above.

### Need a clean resync

Stop the node cleanly first:

```bash
qbit-cli <chain option> stop
```

Then move or delete only the chain data you want to resync. For future mainnet,
chain data is in the qbit data directory root. Keep wallet backups separate
from chain data cleanup.
