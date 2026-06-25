# Mining and pool quickstart

This guide is for miners and pool operators who already know Bitcoin Core
mining RPCs, Stratum, and SHA-256d mining. qbit keeps the familiar
permissionless `getblocktemplate` / `submitblock` path, and adds a second
AuxPoW path for merged mining.

Mainnet is not public yet. Mainnet mining examples below apply when qbit
mainnet is announced. Current public release and network-resource status is
published through https://qbit.org.
Official public testnet release artifacts are for testnet4; no-flag mainnet
commands in this guide are future-mainnet examples only.

The qbit mining RPC surface is implemented in qbit Core. This guide documents
the qbit protocol and node requirements directly; do not assume generic Bitcoin
pool examples are valid for qbit without the checks below.

## What changes from Bitcoin Core

qbit mining has two block classes:

| Path | Parent chain | qbit RPCs | Expected operator |
|---|---|---|---|
| Permissionless / Cadence | qbit only | `getblocktemplate`, `submitblock` | SHA-256d miner or pool pointed at `qbitd` |
| AuxPoW merged mining | External SHA-256d parent chain | `createauxblock`, `submitauxblock` | Pool software that can insert and submit AuxPoW commitments |

Both paths use SHA-256d proof of work. qbit targets an aggregate 60 second
block interval. Mainnet launch parameters, when announced, use a 75 second
permissionless lane and a 300 second AuxPoW lane, with independent ASERT
difficulty tracking for each lane. Fork choice remains most accumulated work,
not longest height.

Current protocol constants relevant to miners:

| Parameter | Value |
|---|---|
| Aggregate target spacing | 60 seconds |
| Permissionless lane spacing | 75 seconds |
| AuxPoW lane spacing | 300 seconds |
| Difficulty algorithm | ASERT, 2 hour halflife |
| Public testnet AuxPoW chain ID | `31430` |
| Max block weight | 2,000,000 |
| Witness scale factor | 1 |
| Coinbase maturity | 1,000 blocks |
| Future mainnet P2P / RPC ports | `8355` / `8352` |
| Regtest P2P / RPC ports | `18460` / `18452` |
| Future mainnet P2MR address HRP | `qb` |
| Regtest P2MR address HRP | `qbrt` |

The in-tree mainnet AuxPoW chain ID currently matches public testnet as a
placeholder only. It is not a mainnet launch value and must be replaced with a
distinct final value before mainnet is enabled or reset.

## Coinbase payout addresses

Launch chains enforce restricted outputs. Your qbit coinbase payout must be a qbit-compatible output, normally a P2MR address from the qbit wallet.

Do not use Bitcoin address examples, `bc1...` examples, or `bech32` address-type examples in qbit mining configuration.

Use the chain option for the network you are testing or operating on:

```bash
qbit-cli <chain option> createwallet "pool"
qbit-cli <chain option> -rpcwallet=pool getnewaddress "coinbase" "p2mr"
```

On future mainnet after launch the address should start with `qb`. On public
testnet4 it should start with `tq`. On regtest it should start with `qbrt`.

For pool software, treat the qbit payout address as chain-specific configuration. The address used for `createauxblock`, `generatetoaddress`, or a pool coinbase output must decode as P2MR on public qbit networks. Non-P2MR addresses are rejected on launch chains.

## Permissionless pool flow

Permissionless mining is the closest path to Bitcoin Core pool integration. The pool talks only to `qbitd`.

1. Keep `qbitd` fully synced and out of initial block download.
2. Create or load a qbit wallet with a P2MR coinbase payout address.
3. Call `getblocktemplate` with SegWit support.
4. Construct a qbit block from the template.
5. Distribute SHA-256d work to miners.
6. Submit a solved qbit block with `submitblock`.

Template request:

```bash
qbit-cli <chain option> getblocktemplate '{"rules":["segwit"]}'
```

Important response fields are the same pool operators expect from BIP22/BIP23 style GBT: `version`, `previousblockhash`, `transactions`, `coinbasevalue`, `target`, `bits`, `height`, `curtime`, `mintime`, `noncerange`, and `default_witness_commitment` when present.

qbit-specific integration notes:

- qbit templates use the qbit version field layout. Preserve the low 8 deployment/versionbits returned by `getblocktemplate`.
- Permissionless templates also return `versionrollingmask`. Use that value, normally `1fffe000`, as the Stratum/BIP310 server mask for Bitcoin ASICBoost-compatible miners.
- If `versionrollingmask` is `00000000`, disable BIP310 version rolling for that template. This can occur with regtest `-blockversion` overrides that do not use BIP9 top bits or that signal AuxPoW.
- The `1fffe000` mask maps to qbit's chain-ID field. In permissionless blocks the AuxPoW flag is fixed off, so the chain-ID field is ignored by consensus while the top bits, reserved bits, AuxPoW flag, and low deployment/versionbits stay fixed.
- Base permissionless templates clear the AuxPoW flag and chain ID.
- `getblocktemplate` must include `{"rules":["segwit"]}` or it is rejected.
- On signet, include `signet` as well: `{"rules":["segwit","signet"]}`.
- `submitblock` returns `null` on acceptance, or a BIP22-style rejection string.
- Pool software should refresh templates on tip changes and mempool updates as it would for Bitcoin Core.

For Stratum v1 pools implementing BIP310 `version-rolling`, grant miners only the intersection of their requested mask and qbit's permissionless mask:

```text
granted_mask = requested_mask & 1fffe000
```

Do not advertise `000000ff` as the production version-rolling mask. That low byte is qbit's deployment/versionbits field and does not satisfy common stock Bitcoin ASIC firmware that expects the Bitcoin-style high-bit ASICBoost mask.

## AuxPoW merged-mining flow

AuxPoW mining uses a qbit child block candidate and a parent-chain block header that proves work for qbit. The parent coinbase commits to the qbit aux block hash using the conventional merged-mining commitment format. qbit validates the reusable proof-of-work and commitment, not whether the parent header was accepted by the parent chain.

High-level pool loop:

1. Get a P2MR qbit payout address.
2. Call `createauxblock <payout_address>` on `qbitd`.
3. Build or request a parent-chain block template from the parent node.
4. Insert the qbit AuxPoW commitment into the parent coinbase.
5. Distribute parent-chain SHA-256d work to miners.
6. When a share satisfies the qbit target, build the serialized AuxPoW payload.
7. Submit it to qbit with `submitauxblock <hash> <auxpow_hex>`.
8. If the same parent block also satisfies the parent-chain target, submit it to the parent chain too.

Create a qbit AuxPoW candidate:

```bash
QBIT_PAYOUT_ADDRESS="<p2mr-payout-address-for-this-chain>"
qbit-cli <chain option> createauxblock "$QBIT_PAYOUT_ADDRESS"
```

`createauxblock` returns:

| Field | Meaning |
|---|---|
| `hash` | Candidate aux block hash; pass this back to `submitauxblock` |
| `chainid` | qbit AuxPoW chain ID for the selected network, currently `31430` on public testnet |
| `previousblockhash` | qbit tip used by the candidate |
| `coinbasevalue` | qbit coinbase value in satoshis, including fees |
| `bits` | compact qbit target for this candidate |
| `height` | candidate qbit block height |
| `target` | expanded qbit target |

Submit a solved AuxPoW payload:

```bash
qbit-cli <chain option> submitauxblock "$AUX_HASH" "$AUXPOW_HEX"
```

`AUXPOW_HEX` may use qbit's canonical AuxPoW layout:

| Order | Field |
|---:|---|
| 1 | Parent coinbase transaction, serialized without witness |
| 2 | Coinbase merkle branch |
| 3 | Coinbase branch index, little-endian signed 32-bit integer |
| 4 | Aux chain merkle branch |
| 5 | Aux chain index, little-endian signed 32-bit integer |
| 6 | Parent block header |

For compatibility with Dogecoin/Namecoin-style AuxPoW serializers,
`submitauxblock` also accepts this legacy layout:

| Order | Field |
|---:|---|
| 1 | Parent coinbase transaction, serialized without witness |
| 2 | Legacy `hashBlock` field |
| 3 | Coinbase merkle branch |
| 4 | Coinbase branch index, little-endian signed 32-bit integer |
| 5 | Aux chain merkle branch |
| 6 | Aux chain index, little-endian signed 32-bit integer |
| 7 | Parent block header |

The legacy `hashBlock` field must be zero or match the parent block header
hash. qbit drops that compatibility field after RPC decoding, then stores,
validates, and relays the block using qbit's canonical AuxPoW layout.

`submitauxblock` returns `null` on acceptance. It returns a BIP22-style rejection string otherwise. A common stale result is `stale-prevblk`, which means the cached qbit candidate no longer builds on the active qbit tip, exceeded `-auxpowtemplateexpiry`, or was evicted by `-auxpowtemplatecachelimit`.

## Cadence lane resumption and monitoring

Cadence ASERT is lane-local. Permissionless and AuxPoW candidates each compute
their next target from the previous accepted block in the same lane, while fork
choice still uses total accumulated chainwork across the active chain.

If a lane has no blocks while the other lane continues advancing the chain, the
first returning block uses the prior same-lane history. After that late block is
accepted, follow-up blocks in the same lane may see a large ASERT relaxation
until the lane catches up. This is expected consensus behavior, not an
AuxPoW-only override. Low-difficulty blocks also contribute proportionally lower
chainwork.

Pool operators should monitor lane starvation before coordinated restarts or
large hashrate changes:

| Signal | Watch |
|---|---|
| Last accepted block per lane | Height, timestamp, bits, and active-chain confirmations for the latest permissionless and AuxPoW blocks |
| Lane hashrate | `getnetworkhashps 120 -1 permissionless` and `getnetworkhashps 120 -1 auxpow` |
| Candidate difficulty | `getblocktemplate` / `getmininginfo.next` for permissionless work; `createauxblock` `bits` and `target` for AuxPoW work |
| Submission health | Stale rate, rejection reason, and same-tip candidate expiry |

Recommended launch runbook thresholds:

| Quiet-lane duration | Action |
|---|---|
| 2 hours | Start operator watch and confirm at least one independent miner or pool is expected to resume |
| 6 hours | Warn the launch team before adding coordinated hashrate to the quiet lane |
| 12 hours | Treat as an incident; record candidate bits and expected ASERT relaxation before resumption |
| 24 hours | Require explicit launch/product signoff before a coordinated restart or public operator announcement |

These thresholds are operational policy, not consensus rules. They are intended
to make lane resumption visible during launch and testnet operations without
making AuxPoW behave differently from permissionless mining.

## AuxPoW commitment requirements

The qbit AuxPoW validator expects a Namecoin-style merged-mining commitment in the parent coinbase `scriptSig`.

The commitment is:

```text
0xfa 0xbe 0x6d 0x6d || aux_merkle_root || merkle_tree_size_le32 || nonce_le32
```

Validation requirements include:

- The qbit AuxPoW chain ID must match the selected network. Public testnet
  currently requires `31430`.
- The AuxPoW header must signal the AuxPoW flag.
- Permissionless blocks must not carry an AuxPoW payload.
- The parent block hash must satisfy the qbit target from the aux candidate.
- The parent coinbase transaction must be a coinbase.
- The coinbase merkle branch index must be `0`.
- The aux merkle branch length must not exceed `30`.
- If the merged-mining magic header is present, it must appear exactly once and immediately before the aux merkle root.
- If the magic header is omitted, the aux merkle root must appear within the legacy first-20-byte window of the parent coinbase `scriptSig`.
- The aux chain index must match the slot derived from the commitment nonce and qbit chain ID.

Most operators should not hand-build this payload for production. Use only
tooling that has been validated against qbit AuxPoW commitments and the target
network you are operating on.

## Regtest smoke flow

Use regtest for local integration before pointing a pool at mainnet. Regtest does not exactly match public-chain policy unless you enable the qbit test flags, so include P2MR/restricted-output settings when testing pool payout behavior.

Start one qbit regtest node:

```bash
qbitd -regtest -daemon \
  -server=1 \
  -asert=1 \
  -p2mronly=1 \
  -rpcuser=qbit \
  -rpcpassword=qbitpass
```

Create a pool wallet and P2MR payout address:

```bash
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass createwallet "pool"
PAYOUT=$(qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass -rpcwallet=pool getnewaddress "coinbase" "p2mr")
```

Permissionless smoke:

```bash
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass getblocktemplate '{"rules":["segwit"]}'
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass generatetoaddress 1 "$PAYOUT"
```

AuxPoW smoke:

```bash
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass createauxblock "$PAYOUT"
```

Then use your validated AuxPoW coordinator or test helper to construct a valid
`auxpow_hex` for the returned `hash`, `chainid`, `bits`, and `target`, and
submit it:

```bash
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass submitauxblock "$AUX_HASH" "$AUXPOW_HEX"
```

After acceptance:

```bash
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass getblockcount
qbit-cli -regtest -rpcuser=qbit -rpcpassword=qbitpass getmininginfo
```

## Mainnet operator flow

Use mainnet operator flow only after qbit.org publishes release artifacts and
network resources for qbit mainnet. Rehearse on regtest and the public testnet
guide first.

Minimum qbit node configuration:

```ini
server=1
rpcuser=<choose-a-user>
rpcpassword=<choose-a-password>
```

Recommended readiness checks before accepting miner traffic:

```bash
qbit-cli <chain option> getblockchaininfo
qbit-cli <chain option> getnetworkinfo
qbit-cli <chain option> getmininginfo
```

The pool should require:

- `initialblockdownload` is `false`.
- The node has active peers, unless intentionally running in a controlled private test.
- The wallet containing the pool payout address is loaded.
- The payout address is P2MR and has the expected network HRP.
- `getblocktemplate '{"rules":["segwit"]}'` succeeds for permissionless mining.
- `createauxblock "$PAYOUT"` succeeds for AuxPoW mining.

## Pool integration checkpoints

Before calling an integration production-ready, record evidence for these checkpoints:

| Checkpoint | Expected result |
|---|---|
| qbit node sync | `getblockchaininfo.initialblockdownload=false` |
| P2MR payout | `getnewaddress "coinbase" "p2mr"` returns the expected HRP |
| Permissionless template | `getblocktemplate '{"rules":["segwit"]}'` returns height, bits, target, and coinbasevalue |
| Permissionless submission | `submitblock` returns `null` for a solved qbit block |
| AuxPoW template | On public testnet, `createauxblock` returns `chainid=31430` and a qbit target |
| AuxPoW commitment | Parent coinbase contains exactly one `fabe6d6d` commitment before the aux root |
| AuxPoW submission | `submitauxblock` returns `null` for a valid payload |
| Stale handling | Tip changes and template expiry produce controlled refreshes, not repeated stale submissions |
| Version handling | Pool preserves qbit low 8 deployment/versionbits, keeps reserved and AuxPoW bits fixed, and grants `version-rolling.mask = requested_mask & 1fffe000` for permissionless Stratum jobs |
| Share difficulty | Pool share-difficulty defaults are appropriate for qbit targets, including low-difficulty test networks |
| Monitoring | Pool tracks accepted blocks, stale rates, node peers, IBD state, and wallet balances |

Treat pool stacks as unvalidated until they have end-to-end evidence for qbit
P2MR coinbase payouts, Cadence templates, version-rolling masks, AuxPoW
commitments, stale handling, and qbit submission RPCs on the target network.

## Useful RPCs for miners

| RPC | Use |
|---|---|
| `getblocktemplate` | Permissionless qbit block template |
| `submitblock` | Permissionless qbit block submission |
| `createauxblock` | AuxPoW qbit child candidate |
| `submitauxblock` | AuxPoW qbit child submission |
| `getmininginfo` | Current mining state, next permissionless/native target, chain name, and the total `all` network hashrate estimate |
| `getnetworkhashps` | Effective chainwork hashrate estimate in H/s; accepts lane `all`, `permissionless`, or `auxpow` |
| `getblockchaininfo` | Sync and IBD status |
| `getnetworkinfo` | Peer and network status |

`getnetworkhashps <nblocks> <height> <lane>` estimates observed chainwork per
second in H/s. `all` reports total active-chain work, `permissionless` reports
native qbit proof work only, and `auxpow` reports AuxPoW proof work only. The
lookup window is selected on the active chain for all lanes; lane-specific
estimates filter which blocks contribute work but use the same active-chain
elapsed-time window, not a lane-local timestamp window. A lane with no blocks
in the selected window reports `0`.

`getmininginfo.networkhashps` is the default total estimate, equivalent to
`getnetworkhashps 120 -1 all`.

`getmininginfo.next` is the next permissionless/native Cadence candidate. It is
not an AuxPoW work source; use `createauxblock` for AuxPoW candidate `bits` and
`target`.

Examples:

```bash
qbit-cli <chain option> getnetworkhashps 120 -1 all
qbit-cli <chain option> getnetworkhashps 120 -1 permissionless
qbit-cli <chain option> getnetworkhashps 120 -1 auxpow
```

## Launch Readiness Caveats

- Do not publish stale examples using `bc1...`, `bech32`, or Bitcoin Core address assumptions for qbit coinbase outputs.
- Public-chain qbit payouts should be P2MR. Regtest can be less restrictive unless `-p2mronly=1` is enabled.
- Public docs should rely only on qbit-owned public mining setup inputs.
- Live mainnet seed nodes, archive peers, mining distribution, and public
  endpoints are launch-readiness values supplied through qbit.org. No public
  faucet or explorer is assumed.
- Compatibility claims for NOMP, Braiins, or other pool stacks need their own end-to-end evidence. Do not imply broad compatibility based only on RPC shape.
- AuxPoW live-parent and signet support should be documented only after the parent-side bridge has been validated for that environment.
- `createauxblock` candidates are cached only while their previous block remains the active tip, they have not exceeded `-auxpowtemplateexpiry`, and they have not been evicted by `-auxpowtemplatecachelimit`.
- Coinbase rewards mature after 1,000 qbit blocks. Pool payout accounting must not treat fresh coinbase outputs as spendable before maturity.
