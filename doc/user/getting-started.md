# Getting Started With qbit

This guide is the future-mainnet first-run path for qbit users. It covers the
mainnet-shaped flow: install qbit, start a node, check sync, create a P2MR
wallet, receive and send funds, and back up safely.

Mainnet is not public yet. This guide describes the mainnet-shaped workflow for
when qbit mainnet is announced. If you are joining the current public rehearsal
network, use the dedicated public testnet guide instead and pass `-testnet4` or
`-chain=testnet4` to qbit commands.

## 1. Download and Verify

Download qbit only from the qbit release announcement or release page linked
through https://qbit.org for the network you are joining. Do not use Bitcoin
Core release pages, checksums, signatures, or release keys for qbit.

Public docs should not be treated as a source for release artifact URLs or
signing keys until those values are published for a specific qbit release.

For each release, verify these items from the release announcement:

- the qbit binary or source artifact for your platform
- `SHA256SUMS`
- `SHA256SUMS.asc`
- the release signing key or key fingerprint

After downloading the artifact, checksum file, signature file, and signing key,
the verification shape is:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Then extract or install the verified qbit artifact using the instructions in
that release announcement.

Add the extracted `bin/` directory to your `PATH`, or run binaries by their full
path:

```bash
qbitd -version
qbit-cli -version
```

For GUI use, start `qbit-qt` instead of `qbitd`. The rest of this guide uses
`qbitd` and `qbit-cli`.

## 2. Choose a Network

When qbit mainnet is launched, mainnet is the default qbit chain. Until then,
no-flag mainnet commands in this guide are future-mainnet examples only. For
the current public testnet, always start with `-testnet4` or
`-chain=testnet4`; developer builds may still select the placeholder main chain
if no chain flag is provided.

```bash
qbitd -daemonwait
```

Use `qbit-cli` without a chain flag for mainnet after launch:

```bash
qbit-cli getblockchaininfo
```

Future mainnet values:

| Network | Start flag | P2P port | RPC port | Address prefix |
| --- | --- | ---: | ---: | --- |
| Future mainnet | none after launch | `8355` | `8352` | `qb` |

Use the dedicated public testnet guide for the current rehearsal network:

```bash
qbitd -testnet4 -daemonwait
qbit-cli -testnet4 getblockchaininfo
```

## 3. Let the Node Find Peers

For future mainnet, start normally first:

```bash
qbitd -daemonwait
```

Check future-mainnet network and sync state:

```bash
qbit-cli getnetworkinfo
qbit-cli getblockchaininfo
```

In `getblockchaininfo`, watch:

- `chain`: should be `main`
- `headers` and `blocks`: should advance as the node syncs
- `initialblockdownload`: becomes `false` after initial sync
- `verificationprogress`: approaches `1`

qbit retains full witness history by default. Do not enable
`-prunewitnesses=1` for a first node unless you intentionally want a
witness-pruned node and understand that it is not an archive bootstrap peer.

If future-mainnet seed infrastructure is not live yet, peer discovery may not
find peers. Use only the archive fallback endpoints published for the specific
release or network through qbit.org:

```bash
qbitd -daemonwait \
  -connectarchive=<archive-host-1>:8355 \
  -connectarchive=<archive-host-2>:8355
```

Then inspect archive peer state:

```bash
qbit-cli getarchivepeers summary
```

`-connectarchive` is the supported full-history fallback. It is stricter than
ordinary `-connect`: qbit disconnects configured archive peers that do not
advertise the required archive and witness services.

## 4. Know Where Files Live

qbit does not use Bitcoin Core's default data directory.

| Platform | qbit data directory |
| --- | --- |
| Linux | `$HOME/.qbit/` |
| macOS | `$HOME/Library/Application Support/Qbit/` |
| Windows | `%LOCALAPPDATA%\Qbit\` |

`qbit.conf` lives in the data directory and is not created automatically. You
can choose another location with `-datadir=<dir>` or another config file with
`-conf=<file>`.

Most data is chain-specific:

| Chain | Data subdirectory |
| --- | --- |
| Future mainnet | data directory root |

Other chains use their own subdirectories; see the dedicated guide for the
network you are using.

Wallets are SQLite databases. By default they live under the chain data
directory, usually in `wallets/<wallet-name>/`.

## 5. Create a Wallet

qbit does not automatically create a default wallet. Create one explicitly:

```bash
qbit-cli -named createwallet \
  wallet_name="first" \
  load_on_startup=true
```

Check it:

```bash
qbit-cli -rpcwallet=first getwalletinfo
```

If you did not set `load_on_startup=true`, load it after restarting:

```bash
qbit-cli loadwallet "first"
```

Back up the wallet with the RPC, not by copying an open wallet file:

```bash
qbit-cli -rpcwallet=first backupwallet /path/to/first-wallet-backup.dat
```

## 6. Get a qbit Address

On qbit launch chains, the wallet address type is P2MR. Use `p2mr` explicitly
while you are learning:

```bash
qbit-cli -rpcwallet=first getnewaddress "" "p2mr"
```

Mainnet P2MR addresses begin with `qb1z`.

Important qbit wallet rules:

- use `qbit:` payment URIs, not `bitcoin:` or `bitcoin://`
- do not request legacy, P2SH-SegWit, bech32 v0, or taproot receive addresses
  on launch chains
- P2MR uses post-quantum signing data; do not assume xpub-only watch-only flows
  work like Bitcoin Core

## 7. Receive Funds

Use the address from `getnewaddress` with a qbit sender:

```text
qb1z...
```

Check wallet balance and recent wallet activity:

```bash
qbit-cli -rpcwallet=first getbalances
qbit-cli -rpcwallet=first listtransactions "*" 10
```

For mined rewards, remember that qbit coinbase outputs mature after 1,000
blocks. Ordinary received transactions can be tracked with the normal wallet
RPCs while they confirm.

## 8. Send Funds

Send to a qbit P2MR address:

```bash
qbit-cli -rpcwallet=first -named sendtoaddress \
  address="<qb1z-recipient-address>" \
  amount=0.1
```

To set an explicit fee rate, use `fee_rate` in `bits/vB`:

```bash
qbit-cli -rpcwallet=first -named sendtoaddress \
  address="<qb1z-recipient-address>" \
  amount=0.1 \
  fee_rate=1
```

Check the transaction:

```bash
qbit-cli -rpcwallet=first listtransactions "*" 10
qbit-cli getmempoolentry <txid>
```

If fee estimation is not useful yet on a young network, use an explicit
`fee_rate` from current qbit.org network guidance.

## 9. Stop and Restart

Stop cleanly:

```bash
qbit-cli <chain option> stop
```

Restart the same chain:

```bash
qbitd -daemonwait
```

If your wallet was saved with `load_on_startup=true`, it will reload
automatically. Otherwise:

```bash
qbit-cli loadwallet "first"
```

## Troubleshooting

`qbit-cli` cannot connect:

- confirm `qbitd` is running
- use the same chain flag on `qbit-cli` that you used for `qbitd`
- for future mainnet, check that you are using the qbit mainnet RPC port,
  `8352`; for public testnet4, use `48352`

No peers or no header progress:

- run `qbit-cli <chain option> getnetworkinfo` and check `connections`
- run `qbit-cli <chain option> getarchivepeers summary`
- if public seeds are not live or are degraded, restart with the published
  `-connectarchive=<host>:<p2p-port>` fallback endpoints

Wallet RPC says no wallet is loaded:

- create a wallet with `createwallet`, or load an existing one with `loadwallet`
- use `-rpcwallet=<wallet-name>` when more than one wallet exists

Address type is rejected:

- use `getnewaddress "" "p2mr"`
- use addresses with the right qbit prefix: `qb` on future mainnet, `tq` on
  public testnet4
- use `qbit:` URIs; `bitcoin:` URIs are not valid qbit payment URIs

Sync or rescan fails on a pruned node:

- for a first node, leave normal block pruning and witness pruning disabled
- if you previously enabled pruning, you may need to redownload chain data for
  operations that require historical blocks or witnesses

You are unsure which chain you are on:

```bash
qbit-cli <chain option> getblockchaininfo | jq '.chain'
```

The `chain` value should be `main` only for future mainnet after launch. It
should be `testnet4` for the current public rehearsal network.
