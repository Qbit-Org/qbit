# Exchange and Integrator Quickstart

This guide is for exchanges, custodians, payment processors, and indexers that
already operate Bitcoin Core infrastructure and want to integrate qbit Core.
It focuses on the minimum production-shaped flow: run your own node, generate
and validate qbit deposit addresses, credit deposits after a confirmation
policy, send withdrawals, monitor chain risk, and keep wallet material backed
up.

qbit is not a drop-in Bitcoin network. Treat the points below as integration
requirements, not branding differences.

Mainnet is not public yet. Mainnet integration examples below apply when qbit
mainnet is announced. Current public release, network-resource, faucet,
explorer, and support status is published through https://qbit.org.
Official public testnet release artifacts are for testnet4; no-flag mainnet
commands in this guide are future-mainnet examples only.

## Network identity

| Network | Chain flag | P2P port | RPC port | Address HRP |
|---|---:|---:|---:|---|
| Future mainnet | none after launch | `8355` | `8352` | `qb` |
| Testnet4 | `-testnet4` or `-chain=testnet4` | `48355` | `48352` | `tq` |

Launch chains use P2MR addresses. Do not accept Bitcoin mainnet/testnet
addresses, Taproot addresses, legacy addresses, or `bitcoin:` payment URIs as
qbit deposit or withdrawal targets. The qbit payment URI scheme is `qbit:`.
Transaction construction and validation must follow the normative
[qbit P2MR v1 Consensus Profile](../consensus/p2mr-v1.md). qbit P2MR v1 is not
compatible with the ancestry profile pinned there, including its hash domains
and depth-zero behavior.

Launch readiness values to publish with each network/release:

- final public release download URL
- frozen protocol/spec URL
- seed hostnames and fixed-seed status for the target network
- project-operated archive fallback endpoints
- test-coin distribution status, if any, and whether a public explorer is explicitly announced

Use qbit.org as the source of truth for those values.

## Deploy the daemon

Run at least one qbit node that you control. For deposits and reconciliation,
prefer an archive/full-history node. Archive mode is the qbit default; do not
enable `-prunewitnesses=1` on the node that your accounting, block scanner, or
support tooling depends on.

For a future-mainnet integration node when qbit mainnet is launched:

```ini
# qbit.conf
server=1

# Keep RPC local or behind your own private network boundary.
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcauth=<generated-user>:<salt>$<hash>

# Optional, depending on your scanner design.
txindex=1

# Launch chains support only P2MR wallet outputs.
addresstype=p2mr
changetype=p2mr

# Archive/full-history is the default. Leave witness pruning disabled.
# prunewitnesses=0

# Add qbit.org-published fallback endpoints when launch infrastructure is live.
# connectarchive=<published-archive-host>:8355
```

Use `share/rpcauth` to generate `rpcauth` credentials. Cookie authentication is
fine for local same-user automation, but long-running integration services
usually use explicit `rpcauth`. Never expose the RPC port to the public
internet.

Start the daemon and check basic health. Use `-testnet4` for public testnet4,
or omit the chain option only after qbit mainnet is launched:

```sh
qbitd <chain option> -daemon

qbit-cli <chain option> getblockchaininfo
qbit-cli <chain option> getnetworkinfo
qbit-cli <chain option> getarchivepeers summary
```

For wallet RPCs, keep using the same chain option and use the wallet endpoint
explicitly. With `qbit-cli`, pass `-rpcwallet=<wallet-name>`. With JSON-RPC, call
`/wallet/<wallet-name>`.

## Create an integration wallet

For a simple hot-wallet integration, create a descriptor wallet and keep it
loaded on restart:

```sh
qbit-cli <chain option> -named createwallet \
  wallet_name=exchange-hot \
  descriptors=true \
  load_on_startup=true \
  passphrase="<strong-passphrase>"
```

Back up the wallet immediately after creation:

```sh
qbit-cli <chain option> -rpcwallet=exchange-hot backupwallet /secure/backups/exchange-hot.dat
```

qbit P2MR watch-only workflows are not xpub-only Bitcoin Core workflows. If you
operate separate online watch-only and offline signing environments, use
`exportpubkeydb` from the signing wallet and `importpubkeydb` into a wallet
created with private keys disabled. Do not assume that a public BIP32 xpub is a
portable P2MR watch-only interface.

## Generate and validate deposit addresses

Generate one fresh P2MR address per customer, account, or invoice:

```sh
addr=$(qbit-cli <chain option> -rpcwallet=exchange-hot getnewaddress "customer:12345" "p2mr")
qbit-cli <chain option> validateaddress "$addr"
qbit-cli <chain option> -rpcwallet=exchange-hot getaddressinfo "$addr"
```

Require all of the following before storing or displaying an address:

- `validateaddress` returns `isvalid: true`
- `validateaddress` returns `iswitness: true`
- `validateaddress` returns `witness_version: 2`
- the HRP matches the network you are integrating: `qb` for future mainnet
  after launch, `tq` for testnet4
- `getaddressinfo` shows the address belongs to the expected wallet when the address is internally generated

Do not validate qbit addresses with Bitcoin Core libraries unless they have
been explicitly updated for qbit's HRPs and P2MR witness v2 semantics. Do not
use string-prefix checks as your only validation.

## Process deposits

The safest deposit flow is the same shape as a conservative Bitcoin Core
integration, with qbit-specific address and confirmation policy:

1. Generate a fresh P2MR address and bind it to an internal account.
2. Detect inbound transactions through wallet RPCs such as `listsinceblock`,
   `listtransactions`, or `gettransaction`, or through your own block scanner.
3. Record the txid, vout, amount, destination address, block hash, block height,
   and current confirmation count.
4. Keep the deposit pending while it is unconfirmed.
5. Credit the account only after it meets the confirmation target returned by
   `getconfirmationtarget` for your selected BTC-equivalent security level,
   plus any stricter local risk floor.
6. Continue monitoring credited deposits for reorgs until your operational
   finality window has passed.

If you run a raw block scanner, remember that qbit fully counts witness data in
transaction weight and block weight. Do not reuse Bitcoin fee, size, or witness
discount assumptions.

## Choose confirmation targets

Exchange and custody integrations should use `getconfirmationtarget` as the
primary qbit confirmation-policy input. The RPC estimates how many qbit
confirmations are required to reach a chosen BTC-equivalent security level,
using qbit block timing, stale/orphan rate, Cadence lane data, and hashrate
information.

Example:

```sh
# 1 QBT = 100000000 satoshis
qbit-cli <chain option> getconfirmationtarget 100000000 "high"
```

Security levels are:

- `low`: modeled against 1 Bitcoin confirmation
- `medium`: modeled against 3 Bitcoin confirmations
- `high`: modeled against 6 Bitcoin confirmations
- `maximum`: modeled against 60 Bitcoin confirmations

Use the returned `required_confirmations` as the dynamic qbit network target.
Your own policy can still require a stricter local floor:

```text
effective_required_confirmations =
  max(local_minimum_confirmations, getconfirmationtarget.required_confirmations)
```

Recompute periodically and whenever stale-block or hashrate conditions change.
For high-value deposits, use a higher local floor and require manual review for
abnormal network conditions.

## Send withdrawals

Before sending a withdrawal:

1. Validate the destination with the same `validateaddress` checks used for
   deposits.
2. Reject addresses for the wrong HRP or any non-P2MR witness version.
3. Reject `bitcoin:` URIs and require `qbit:` where URI input is accepted.
4. Estimate fees with the qbit node you will broadcast from.
5. Use `testmempoolaccept` for pre-broadcast validation when constructing raw
   transactions or when withdrawal batching logic is complex.

For wallet-managed withdrawals:

```sh
qbit-cli <chain option> -rpcwallet=exchange-hot walletpassphrase "<strong-passphrase>" 120
qbit-cli <chain option> -rpcwallet=exchange-hot sendtoaddress "$destination" 1.25
qbit-cli <chain option> -rpcwallet=exchange-hot walletlock
```

P2MR signatures are large, and qbit does not apply a Bitcoin-style witness
discount. Withdrawal batching, consolidation, and fee policies must be tested
against qbit transaction sizes and mempool policy rather than copied from a
Bitcoin integration.

Wallet signing RPCs may return PQC usage fields such as
`pqc_signature_count`, `pqc_signature_limit`,
`pqc_signatures_remaining`, and `pqc_limit_state`. Treat `warning`,
`critical`, or `exhausted` states as operational events and rotate to fresh
addresses/keys according to your custody policy.

## Monitor chain and node risk

At minimum, alert on:

- node not synced: `getblockchaininfo.initialblockdownload`
- stalled height or stale best block time
- low peer count or loss of outbound connectivity
- archive fallback not connected when configured: `getarchivepeers summary`
- high stale/orphan rate or `getorphanmetrics.alert: true`
- nonzero or increasing `deepest_reorg`
- wallet locked when a withdrawal signer is expected to be available
- failed wallet backup jobs
- disk growth or block-storage errors on archive nodes

Useful RPCs:

```sh
qbit-cli <chain option> getblockchaininfo
qbit-cli <chain option> getnetworkinfo
qbit-cli <chain option> getpeerinfo
qbit-cli <chain option> getarchivepeers summary
qbit-cli <chain option> getorphanmetrics 1000
qbit-cli <chain option> getmempoolinfo
```

`getorphanmetrics` uses the word "orphan" for stale blocks, not orphan
transactions. It reports rolling stale-block rate, lifetime reorg count,
deepest observed reorg, last stale height/time, persistent stale tips, and an
alert boolean.

If witness pruning is enabled, verbose historical `getblock` calls can be
unavailable for blocks whose witness data was pruned. Exchange accounting,
auditing, and historical support tooling should use archive nodes.

## Handle reorgs

Deposits must remain reversible in your internal ledger until they are past
your confirmation policy. Store enough metadata to detect and reconcile reorgs:

- txid and output index
- credited amount
- assigned customer/account
- block hash and height where first seen confirmed
- current best-chain confirmation count
- final credited state and the policy version used

On a reorg, a previously credited transaction can lose confirmations or move to
a different block. Re-evaluate its current state with wallet or scanner data
before allowing withdrawal of the credited balance.

## Backups and recovery

Back up:

- wallet files after wallet creation and after material wallet configuration changes
- `qbit.conf` and RPC auth configuration
- any external address-allocation database that maps qbit addresses to customers
- watch-only pubkey databases created with `exportpubkeydb`
- operational records needed to replay deposit credits and withdrawals

Test restore procedures before accepting customer funds. A restore test should
verify that the node can sync, the wallet loads, known deposit addresses are
recognized, and a small withdrawal can be signed and broadcast in a rehearsal
environment before mainnet use.

## PSBT caveat

qbit Core supports current P2MR PSBT signing and finalization, but qbit P2MR
PSBT data uses a mixed model of dedicated P2MR fields and qbit-proprietary
fields where no stable generic encoding has been finalized. If your custody
stack depends on PSBTs, validate every tool in the path against qbit P2MR PSBTs
before using it for production funds. Do not assume Bitcoin-only PSBT libraries
will preserve or understand qbit P2MR fields.

## Unsupported Bitcoin Core assumptions

Do not carry these assumptions from Bitcoin Core into a qbit integration:

- `bc1`, `tb1`, legacy, P2SH-wrapped SegWit, and Taproot addresses are not
  launch-chain qbit deposit addresses.
- `bitcoin:` URIs are not qbit payment requests.
- P2MR watch-only operation is not a plain xpub import workflow.
- Bitcoin witness discount economics do not apply.
- Bitcoin confirmation counts are not directly equivalent to qbit confirmation
  counts; use a qbit-specific policy and `getconfirmationtarget`.
- Lightning Network compatibility is not inherited from Bitcoin Core.
- Public seed hostnames, archive endpoints, test-coin distribution, and any
  public explorer are launch infrastructure dependencies published through
  qbit.org; no faucet or explorer is assumed, and placeholders are not
  production inputs.

## References

- JSON-RPC interface: `doc/integration/JSON-RPC-interface.md`
- Canonical RPC reference: `https://docs.qbit.org/`
- RPC delta and migration notes: `doc/integration/rpc-delta-reference.md`
- Generated RPC documentation pipeline: `doc/rpc/`
- qbit protocol overview: `doc/user/bitcoin-core-differences.md`
- Public testnet resources and status: `doc/user/public-testnet.md`
- Full-validation bootstrap: `doc/user/full-validation-bootstrap.md`
- qbit configuration file: `doc/user/setup/bitcoin-conf.md`
- P2MR descriptors: `doc/user/wallet/descriptors.md`
- PSBT notes: `doc/user/wallet/psbt.md`
