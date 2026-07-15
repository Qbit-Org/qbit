# Full-Validation Bootstrap

This guide is for operators who want a fresh qbit node to verify the chain
from genesis, for example by starting `qbitd` with `-assumevalid=0`.

This public guide is self-contained. Follow the published release and network
resource guidance for the supported user flow.

## Who This Is For

Use this guide if you want:

- a fresh full-validation node
- full historical verification from genesis
- the supported default path first, with a documented fallback if needed

This is not the normal quick-start path for every node operator. It is the
full-verification path for users who explicitly want to validate all history.

By default, qbit nodes retain full witness history. Witness-pruned peers are
explicit opt-in nodes, and this guide uses archive bootstrap checks to avoid
relying on them for fresh full validation.

## Supported Primary Path

At launch, the supported primary path is to start qbit normally in
full-validation mode and let peer discovery find archive-capable peers for you.

Example:

```bash
qbitd -assumevalid=0
```

Use this path as-is:

- do not add `-connect`
- do not add `-noconnect`
- leave normal DNS-based peer discovery enabled

If the automatic bootstrap path is healthy, qbit should discover at least one
archive/full-history peer and continue full validation without any manual peer
configuration. The automatic path requests peers that advertise
`NODE_ARCHIVE`.

## If The Primary Path Does Not Work

If full validation does not make progress because the automatic archive path is
unavailable or degraded, use the published archive fallback endpoints with
`-connectarchive`.

Example command:

```bash
qbitd -assumevalid=0 \
  -connectarchive=positron-mainnet.qbit.org:8355 \
  -connectarchive=graviton-mainnet.qbit.org:8355
```

Example `qbit.conf` fragment:

```ini
assumevalid=0
connectarchive=positron-mainnet.qbit.org:8355
connectarchive=graviton-mainnet.qbit.org:8355
```

Notes:

- `-connectarchive` may be specified more than once.
- `-connectarchive` is the supported fallback. Do not substitute `-connect`.
- If the published fallback endpoints are hostnames instead of numeric
  addresses, leave `-dns=1` enabled. This is the default.

## What qbit Checks For You

The fallback flow is specifically meant for archive/full-history peers.

If a peer configured with `-connectarchive` does not advertise `NODE_NETWORK`,
`NODE_WITNESS`, and `NODE_ARCHIVE`, or if it advertises `NODE_WITNESS_PRUNED`
or later implies it by returning historical `NOTFOUND` for a witness-block
request, qbit disconnects it instead of treating it as a valid archive
bootstrap peer.

## Runtime States

You can think about the supported bootstrap path in three states:

- `Normal`: the automatic path works and you do not need to add manual peer
  configuration.
- `Degraded`: the automatic path is unavailable or unreliable, but the
  published `-connectarchive` fallback still works.
- `Launch-blocking`: neither the automatic path nor the published fallback is
  available.

For users, the important distinction is whether the default path works or the
published fallback endpoints are needed. If neither path works, there is no
supported public full-validation bootstrap path for that network at that time.

## Mainnet launch resources

The v1.0.0 launch source includes these automatic DNS seeds:

- `flux-mainnet.qbit.org`
- `phase-mainnet.qbit.org`

The two archive fallbacks above are also compiled into v1.0.0 as fixed seed
addresses. Use qbit.org and the matching release notes to confirm current
network-resource status before relying on them operationally.
