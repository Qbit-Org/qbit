# qbit RPC Delta and Migration Notes

This page is for developers and integrators who already know the Bitcoin Core RPC API and need to find the qbit-specific differences quickly.

It is not the canonical method reference. Use this page as the delta and
migration map, then use [docs.qbit.org](https://docs.qbit.org/) for canonical
method arguments, result schemas, examples, and command semantics.

## Reference Sources

- Canonical RPC reference: [docs.qbit.org](https://docs.qbit.org/)
- Generated RPC documentation assets: `doc/rpc/`
- qbit protocol overview: [What Changed From Bitcoin Core](../user/bitcoin-core-differences.md)
- Exchange and integrator quickstart: [Exchange and Integrator Quickstart](exchange-integrator-quickstart.md)
- Full-validation and archive bootstrap guide: [Full-Validation Bootstrap](../user/full-validation-bootstrap.md)
- P2MR watch-only pubkey database guide: [P2MR Watch-Only Pubkey Database Guide](../user/wallet/p2mr-pubkeydb.md)

The in-tree RPC documentation pipeline lives under `doc/rpc/`. Release builds
install generated RPC artifacts under `share/doc/qbit/rpc/`, and the public
canonical RPC reference is published at `docs.qbit.org`.

## What Changed Since Bitcoin Core v30.2

qbit keeps the Bitcoin Core RPC shape where that is still accurate, but adds or changes surfaces for:

- P2MR addresses and wallet descriptors
- post-quantum signing state and signature-budget reporting
- Cadence and AuxPoW mining
- archive-by-default node behavior and witness-pruned peers
- stale block metrics and qbit confirmation-target estimation

For protocol constants behind these RPCs, use the protocol specification rather
than older Bitcoin Core assumptions. Future mainnet launch values include
60-second aggregate target spacing, P2MR as the public spendable output model,
`qb` mainnet addresses, archive/full-history retention by default, and explicit
witness pruning via `-prunewitnesses=1`. Current official public testnet
release artifacts are for testnet4; use `-testnet4` or `-chain=testnet4` in
testnet examples.

## qbit-Only RPCs

### `createauxblock`

Canonical RPC reference: `createauxblock` at `docs.qbit.org`

Creates a merged-mining candidate block for the AuxPoW lane and pays the coinbase reward to the supplied qbit address.

Use this when integrating AuxPoW mining infrastructure. The candidate remains cached for `submitauxblock` while its previous block remains the active tip, the candidate has not exceeded `-auxpowtemplateexpiry`, and the same-tip cache has not evicted it under `-auxpowtemplatecachelimit`.

Request:

```bash
qbit-cli <chain option> createauxblock "<p2mr-payout-address>"
```

Important result fields:

- `hash`: candidate aux block hash to commit into parent-chain AuxPoW data
- `chainid`: configured qbit AuxPoW chain ID
- `previousblockhash`: qbit tip the candidate builds on
- `coinbasevalue`: total coinbase value in satoshis, including fees
- `bits` and `target`: candidate difficulty target
- `height`: candidate qbit block height

Integrator notes:

- The payout address must be valid for the active qbit network.
- On restricted-output launch chains, the coinbase output must be P2MR or an allowed restricted-output exemption.
- The RPC is unavailable before Cadence activation.

### `submitauxblock`

Canonical RPC reference: `submitauxblock` at `docs.qbit.org`

Submits the serialized AuxPoW payload for a cached candidate returned by `createauxblock`.

Request:

```bash
qbit-cli <chain option> submitauxblock "<hash-from-createauxblock>" "<auxpow-hex>"
```

Result:

- `null` when the block is accepted
- BIP22-style reject string when validation fails
- `stale-prevblk` when the cached candidate no longer builds on the active tip, exceeded `-auxpowtemplateexpiry`, or was evicted by `-auxpowtemplatecachelimit`

Integrator notes:

- Treat `stale-prevblk` as a normal race condition and request fresh work.
- Surface reject strings in pool logs; they are the fastest way to distinguish parent PoW, commitment, chain ID, and stale-template failures.

### `getorphanmetrics`

Canonical RPC reference: `getorphanmetrics` at `docs.qbit.org`

Returns stale block metrics over a rolling event window. In this RPC, "orphan" means stale blocks, not orphan transactions.

Request:

```bash
qbit-cli <chain option> getorphanmetrics
qbit-cli <chain option> getorphanmetrics 500
```

Important result fields:

- `window_total`: block events available in the requested window
- `window_stale`: stale block events in that window
- `orphan_rate`: stale rate used by confirmation-target calculations
- `lifetime_reorgs`: total observed reorganizations
- `deepest_reorg`: maximum observed reorg depth
- `persistent_stale_tip_count`: non-active chain tips known in the block index
- `alert`: true when stale rate exceeds the alert threshold

Integrator notes:

- Use this in exchange, custody, indexing, and network monitoring.
- `orphan_rate` feeds `getconfirmationtarget`, so stale-rate spikes can raise suggested confirmation counts.

### `getconfirmationtarget`

Canonical RPC reference: `getconfirmationtarget` at `docs.qbit.org`

Calculates a recommended qbit confirmation count using qbit block timing,
observed stale rate, observed or modeled AuxPoW participation, and a
BTC-equivalent security level.

Request:

```bash
qbit-cli <chain option> getconfirmationtarget 100000000 "high"
qbit-cli <chain option> getconfirmationtarget 1000000000 "maximum" 0.01
```

Arguments:

- `value_satoshis`: transaction value, returned for reference
- `security_level`: `low`, `medium`, `high`, or `maximum`
- `merge_mining_pct`: optional fallback or override fraction of Bitcoin hashrate merge-mining qbit, from `0.0` to `1.0`
- `btc_hashrate`: optional Bitcoin hashrate estimate in H/s

Important result fields:

- `required_confirmations`: recommended qbit confirmations
- `required_minutes`: estimated wait time
- `equivalent_btc_confirmations`: modeled Bitcoin-equivalent security
- `permissionless_hashrate`, `auxpow_hashrate`, `total_observed_hashrate`
- `orphan_rate`
- `model.hashrate_source`: `observed_chainwork`, `override_merge_mining_pct`, or `fallback_merge_mining_pct`
- `model.security_per_confirmation`
- `model.cadence_merged_fraction`

Integrator notes:

- For exchanges and custodians, start from this RPC instead of copying Bitcoin
  confirmation counts.
- Record the full response with deposit policy changes so support can explain why a confirmation target moved.
- If your policy overrides `merge_mining_pct`, document the source of that override.

### `getarchivepeers`

Canonical RPC reference: `getarchivepeers` at `docs.qbit.org`

Reports archive-relevant peer state for bootstrap, fallback debugging, and monitoring.

Request:

```bash
qbit-cli <chain option> getarchivepeers
qbit-cli <chain option> getarchivepeers "summary"
qbit-cli <chain option> getarchivepeers "connected"
qbit-cli <chain option> getarchivepeers "configured"
```

Views:

- `all`: summary plus connected and configured details
- `summary`: counts only
- `connected`: archive-relevant connected peers
- `configured`: configured `-connectarchive` targets

Important result fields:

- `summary.connected_advertised_archive_peers`
- `summary.connected_archive_connections`
- `summary.configured_archive_targets`
- `summary.connected_configured_archive_targets`
- `connected[].advertises_archive`
- `connected[].archive_connection`
- `configured[].connected`

Integrator notes:

- `NODE_ARCHIVE` is a peer advertisement, not cryptographic proof that a peer can serve all historical data.
- Use this RPC with bootstrap monitoring and manual `-connectarchive` fallback checks.

### `getdefaultctvhash`

Generated RPC reference: `getdefaultctvhash` in the generated RPC docs

Computes qbit's BIP119-style default `OP_CHECKTEMPLATEVERIFY` hash for one input of a serialized transaction.

Request:

```bash
qbit-cli <chain option> getdefaultctvhash "<raw-transaction-hex>" 0
qbit-cli <chain option> getdefaultctvhash "<raw-transaction-hex>" 0 true
```

Arguments:

- `hexstring`: serialized transaction hex.
- `input_index`: zero-based input index committed by CTV.
- `verbose`: optional; when true, returns the committed field breakdown.

Important result fields in verbose mode:

- `ctvhash`: default CTV hash, hex-encoded in script byte order.
- `version` and `locktime`.
- `script_sigs_hash_included` and optional `script_sigs_hash`.
- `input_count`, `sequences_hash`, `output_count`, `outputs_hash`, and `input_index`.

Integrator notes:

- This RPC is protocol-neutral. It does not construct transactions, sign inputs, infer wallet policy, or accept bridge/application fields.
- The RPC uses the same C++ helper as P2MR script execution, so it is the canonical node-exposed way to generate CTV test vectors.
- The hash commits to transaction version, locktime, optional scriptSig hash, input count, sequences hash, output count, outputs hash, and input index. It does not commit to prevouts, spent amounts, spent scripts, or witness data.

## Shared RPC Names With qbit-Specific Semantics

### `getblocktemplate`

Canonical RPC reference: `getblocktemplate` at `docs.qbit.org`

`getblocktemplate` still serves permissionless mining templates, but qbit mining semantics differ from Bitcoin Core because qbit has Cadence, AuxPoW, P2MR/restricted-output rules, ASERT difficulty, and no witness discount.

Integrator notes:

- Clients must pass the `segwit` rule as in Bitcoin Core.
- Template `weightlimit` reflects qbit's full-counting witness policy.
- Template `version`, `bits`, and `target` are qbit-specific and should not be derived from Bitcoin retarget assumptions.
- AuxPoW mining should use `createauxblock` / `submitauxblock`, not ordinary `getblocktemplate` submission flow.
- Coinbase payout construction must satisfy qbit restricted-output policy.

### `getnetworkinfo`

Canonical RPC reference: `getnetworkinfo` at `docs.qbit.org`

The result keeps the Bitcoin Core shape but `localservices` and `localservicesnames` now expose qbit archive and witness-pruning state.

Fields to watch:

- `localservices`
- `localservicesnames`
- `connections`
- `connections_out`
- `networkactive`
- `warnings`

qbit-specific service names of interest:

- `NODE_ARCHIVE`: node advertises archive/full-history service
- `NODE_WITNESS_PRUNED`: node has compacted away historical witness data

Integrator notes:

- Default qbit nodes are archive/full-history nodes.
- Nodes started with witness pruning can withdraw archive service and advertise witness-pruned service.
- For archive bootstrap diagnostics, prefer `getarchivepeers` over parsing only `getnetworkinfo`.

### `getblock`

Canonical RPC reference: `getblock` at `docs.qbit.org`

`getblock` has explicit behavior for historical blocks whose witness data has been pruned.

qbit behavior:

- `verbosity=0` returns stored serialized block bytes, which may omit witness data for witness-pruned historical blocks.
- Verbose views are rejected when required historical witness data has been pruned.
- `weight` fully counts witness data when verbose data is available.

Integrator notes:

- Indexers and any public explorer operators should run archive/full-history nodes.
- Do not assume a witness-pruned node can provide verbose historical blocks.
- If an integration requires historical witness data, monitor for `NODE_ARCHIVE` locally and reject `NODE_WITNESS_PRUNED` operating modes.

## P2MR Wallet, Address, Descriptor, and PSBT Surfaces

qbit public launch chains use P2MR as the spendable output model. Wallet and raw-transaction integrations should use P2MR-specific flows rather than Bitcoin legacy, Taproot, or ordinary SegWit assumptions.

Generated references:

- `getnewaddress`
- `getrawchangeaddress`
- `createwalletdescriptor`
- `exportpubkeydb`
- `importpubkeydb`
- `getaddressinfo`
- `validateaddress`
- `decodescript`
- `walletprocesspsbt`
- `decodepsbt`
- `analyzepsbt`
- `finalizepsbt`
- `signrawtransactionwithkey`

### Address Creation

Use `p2mr` explicitly in integration tests and examples:

```bash
qbit-cli <chain option> -rpcwallet=<wallet> getnewaddress "" "p2mr"
qbit-cli <chain option> -rpcwallet=<wallet> getrawchangeaddress "p2mr"
```

Do not assume Bitcoin address families are available on launch chains.

### Descriptor Creation

Use:

```bash
qbit-cli <chain option> -rpcwallet=<wallet> createwalletdescriptor "p2mr"
```

On P2MR-only chains, public P2MR descriptors derived from BIP32 extended public keys are omitted from public export results because BIP32 xpubs cannot derive SPHINCS+/P2MR public keys. For watch-only P2MR tracking, use `exportpubkeydb` and `importpubkeydb`.

### Watch-Only P2MR Tracking

Export explicit P2MR public keys from the spending wallet:

```bash
qbit-cli <chain option> -rpcwallet=<spending-wallet> exportpubkeydb
```

Import them into a private-keys-disabled watch-only wallet:

```bash
qbit-cli <chain option> -rpcwallet=<watch-only-wallet> importpubkeydb '[{"pubkey":"001122..."}]'
```

Exported records include:

- `pubkey`: 32-byte P2MR public key
- `account`: optional informational account number
- `change`: optional change/internal flag
- `index`: optional descriptor index

### Address Inspection

`getaddressinfo` may include PQC usage state for local wallet keys associated with the address.

Fields to watch:

- `scriptPubKey`
- `solvable`
- `desc`
- `parent_desc`
- `pqc_key_states`
- `pqc_overall_limit_state`
- `pqc_signature_count`
- `pqc_signature_limit`
- `pqc_signatures_remaining`
- `pqc_limit_state`

### Raw Transaction Signing

`signrawtransactionwithkey` accepts explicit `pqc(KEY)` expressions for P2MR signing. P2MR script-path prevout data can include:

- `p2mrScript`
- `p2mrControlBlock`
- `p2mrLeafVersion`

On P2MR-only chains, legacy WIF private keys are disabled for this path; use `pqc(KEY)` expressions.

### PSBT Handling

qbit PSBT support signs and finalizes current P2MR script-path inputs. The current implementation uses dedicated P2MR PSBT input data plus qbit-proprietary fields where there is not yet a stable generic encoding.

Integrator notes:

- Do not assume every external Bitcoin PSBT tool understands qbit P2MR fields.
- Preserve unknown and proprietary PSBT fields when passing PSBTs between systems.
- Use `decodepsbt` and `analyzepsbt` in test fixtures to verify P2MR data is present before signing.
- Use `walletprocesspsbt` on a qbit wallet for ordinary wallet signing.

## Signing Responses and PQC Usage Fields

Several wallet signing or transaction-creation RPCs can return PQC usage state when local PQC keys participate in the response.

Watch these fields wherever present:

- `pqc_key_states`
- `pqc_overall_limit_state`
- `pqc_signature_count`
- `pqc_signature_limit`
- `pqc_signatures_remaining`
- `pqc_limit_state`
- `warnings`

`pqc_limit_state` values are:

- `normal`
- `warning`
- `critical`
- `exhausted`

Integrator notes:

- Treat `critical` and `exhausted` as operationally significant.
- Surface `warnings` in wallet automation logs.
- Do not strip these fields from internal APIs that wrap qbit wallet RPCs.

## Suggested Integration Checks

At startup:

```bash
qbit-cli <chain option> getnetworkinfo
qbit-cli <chain option> getblockchaininfo
qbit-cli <chain option> getarchivepeers "summary"
```

For deposit policy:

```bash
qbit-cli <chain option> getorphanmetrics
qbit-cli <chain option> getconfirmationtarget <value_satoshis> "high"
```

For address support:

```bash
qbit-cli <chain option> -rpcwallet=<wallet> getnewaddress "" "p2mr"
qbit-cli <chain option> validateaddress "<address>"
qbit-cli <chain option> -rpcwallet=<wallet> getaddressinfo "<address>"
```

For watch-only P2MR:

```bash
qbit-cli <chain option> -rpcwallet=<spending-wallet> exportpubkeydb
qbit-cli <chain option> -rpcwallet=<watch-wallet> importpubkeydb '<exported-pubkeys-array>'
```

For AuxPoW mining:

```bash
qbit-cli <chain option> createauxblock "<p2mr-payout-address>"
qbit-cli <chain option> submitauxblock "<hash>" "<auxpow-hex>"
```

For mining hashrate telemetry:

```bash
qbit-cli <chain option> getnetworkhashps 120 -1 all
qbit-cli <chain option> getnetworkhashps 120 -1 permissionless
qbit-cli <chain option> getnetworkhashps 120 -1 auxpow
qbit-cli <chain option> getmininginfo
```

`getnetworkhashps` returns an effective chainwork hashrate estimate in H/s.
`all` reports total active-chain work per second, `permissionless` reports
native qbit proof work only, and `auxpow` reports AuxPoW proof work only.
`nblocks` and `height` choose an active-chain lookup window. Lane-specific
queries filter work by lane while using that same active-chain elapsed-time
window, not a lane-local timestamp window. `getmininginfo.networkhashps` is the
default `all` estimate.

`getmininginfo.next` preserves Bitcoin Core's singular response shape and is the
next permissionless/native Cadence candidate. Use `getblocktemplate` for full
permissionless work details. AuxPoW candidate `bits` and `target` are returned
by `createauxblock`, not by `getmininginfo.next`.

## Compatibility Notes for Bitcoin Core Integrators

- Do not hard-code Bitcoin Core ports, address prefixes, or address type assumptions.
- Do not treat Bitcoin confirmation counts as qbit confirmation policy.
- Do not assume historical verbose `getblock` works on witness-pruned nodes.
- Do not assume xpub-only watch-only flows are sufficient for P2MR.
- Do not assume external PSBT tooling preserves or understands qbit P2MR fields.
- Do not assume `getblocktemplate` covers both permissionless and AuxPoW mining.
- Do not treat `getmininginfo.next` as an AuxPoW work source; use
  `createauxblock` for AuxPoW candidate difficulty.

## Generated Docs Coverage

The generated RPC reference should include current entries for:

- `createauxblock`
- `submitauxblock`
- `getorphanmetrics`
- `getconfirmationtarget`
- `getarchivepeers`
- `getblocktemplate`
- `getnetworkinfo`
- `getblock`
- `createwalletdescriptor`
- `exportpubkeydb`
- `importpubkeydb`
- `getaddressinfo`
- `validateaddress`
- `decodescript`
- `walletprocesspsbt`
- `decodepsbt`
- `analyzepsbt`
- `finalizepsbt`
- `signrawtransactionwithkey`
