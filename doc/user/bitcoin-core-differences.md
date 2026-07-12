# What Changed From Bitcoin Core

qbit is based on Bitcoin Core v30.2, but it is not a Bitcoin network with different branding. It has different consensus rules, address rules, wallet assumptions, mining paths, service bits, and RPC surfaces. This page is for Bitcoin Core users who want to know which instincts still apply and which ones do not.

## Short Version

- qbit has its own network identity, ports, address HRPs, payment URI scheme, genesis blocks, and chain parameters. Any concrete genesis hash in pre-launch documentation should be treated as a placeholder until the launch specification freezes it.
- Mainnet is not public or launched yet. Official public testnet release artifacts are for testnet4; no-flag mainnet commands are future-mainnet guidance only.
- Public qbit launch chains are P2MR-only for spendable outputs. Do not expect legacy, P2SH-SegWit, native SegWit v0, or Taproot receive/change outputs to work as user payment outputs.
- qbit's live authorization path uses P2MR script-path spends with `OP_CHECKSIGPQC` and `SLH-DSA-SHA2-128s-bounded30` signatures, not secp256k1 ECDSA or BIP340 Schnorr signatures.
- qbit has no witness discount. A 3,680-byte PQC signature counts at full weight.
- qbit uses ASERT difficulty adjustment and Cadence mining lanes instead of Bitcoin's 2016-block retarget.
- qbit keeps full witness history by default. Witness pruning is an explicit opt-in mode.
- Some RPC names are inherited, but several have qbit-specific behavior. qbit also adds new RPCs for AuxPoW, archive peers, orphan metrics, confirmation targets, and P2MR watch-only workflows.
- Bitcoin Lightning is not a drop-in port. A qbit channel network would need new protocol work.

## Network Identity

Use qbit binaries and qbit config. Do not point Bitcoin Core tooling at a qbit data directory, and do not reuse a Bitcoin data directory for qbit.

| Network | P2P port | RPC/REST port | Address HRP | Notes |
|---|---:|---:|---|---|
| Public testnet4 | `48355` | `48352` | `tq` | Current public rehearsal network. |
| Future mainnet | `8355` | `8352` | `qb` | Reserved qbit mainnet identity for when mainnet is announced. |

Other qbit networks use distinct parameters and are documented separately.
The in-tree mainnet parameters, genesis block, derived hash, and message-start
bytes are development placeholders until a qbit mainnet launch announcement
freezes them. The in-tree mainnet AuxPoW chain ID currently matches public
testnet as a placeholder only; it must be replaced with a distinct final value
before mainnet is enabled or reset.

The qbit source is open, so third parties can fork it or run private networks.
Only qbit-published artifacts, tags, release notes, seed resources, and
qbit.org announcements define official qbit networks.

The payment URI scheme is `qbit:`. qbit deliberately rejects `bitcoin:`, `bitcoin://`, and `qbit://` payment URI variants.

## Consensus Parameters

qbit starts from Bitcoin Core mechanics where they still fit, but the chain parameters are different.

| Parameter | qbit value |
|---|---:|
| Aggregate target block spacing | 60 seconds |
| Cadence permissionless lane spacing | 75 seconds |
| Cadence AuxPoW lane spacing | 300 seconds |
| Max serialized block size | 2,000,000 bytes |
| Max block weight | 2,000,000 |
| Witness scale factor | 1 |
| Coinbase maturity | 1,000 blocks |
| Initial subsidy | 210 QBT |
| Subsidy step interval | 43,200 blocks |
| Subsidy stepdown | Compound floor, multiply by `598 / 625` each step |
| First zero-subsidy height | 20,736,000 |
| Total scheduled emission | 209,999,997.618768 QBT |
| Maximum money cap | 210,000,000 QBT |
| Difficulty adjustment | ASERT, `aserti3-2d`, 2 hour half-life |
| Public testnet AuxPoW chain ID | 31430 |
| Future mainnet AuxPoW chain ID | placeholder `31430`; not a launch value |

The `WITNESS_SCALE_FACTOR` is `1`, so qbit does not discount witness data. This matters because P2MR signatures are large. Fee estimation, block template sizing, transaction batching, channel designs, and any custom policy logic should treat witness bytes as full-weight data.

qbit also uses a clean-chain posture: major inherited consensus deployments are active from genesis where applicable, rather than activating at Bitcoin historical heights. Do not assume Bitcoin mainnet activation heights, chainwork, assume-valid data, assumeutxo data, or checkpoint history carry over.

## P2MR and SLH-DSA

qbit's live spendable output model is qbit P2MR v1, Pay to Merkle Root. A
P2MR output is a witness v2 output whose 32-byte witness program is the Merkle
root of a script tree. The normative byte-level rules are in the
[qbit P2MR v1 Consensus Profile](../consensus/p2mr-v1.md). qbit P2MR v1 is not
compatible with the ancestry profile pinned there; integrations must not
substitute its commitment, depth-zero, opcode, or sighash behavior.

P2MR resembles Taproot/Tapscript in some implementation structure, but it is not Taproot:

- P2MR is script-path only. There is no Taproot-style key-path spend.
- The committed script tree uses qbit P2MR leaf hashing and branch hashing.
- The current wallet-signable P2MR leaf version is `0xc0`.
- `OP_CHECKSIGPQC` is active in P2MR execution and verifies qbit's active PQC signature profile.
- `OP_CHECKDATASIGPQC` (`0xbc`) and `OP_CHECKDATASIGADDPQC` (`0xbd`) are active in P2MR execution for 32-byte external message-hash attestations under the `QbitDataSigPQC` domain.
- The data-signature opcodes do not commit to transaction data by themselves. Transaction-template or burn-proof protocols need a separate message-construction layer.
- `OP_CHECKSIG` and `OP_CHECKSIGVERIFY` are invalid in P2MR execution; use `OP_CHECKSIGPQC` or `OP_CHECKSIGPQC OP_VERIFY`.
- Outside P2MR execution, byte `0xb3` is invalid; it is qbit's P2MR-only PQC checksig opcode, not a general-purpose NOP slot.
- `OP_CHECKTEMPLATEVERIFY` is active only in P2MR execution at opcode byte `0xbb`. Bitcoin BIP 119's `OP_NOP4`/`0xb3` assignment is not used because qbit assigns `0xb3` to `OP_CHECKSIGPQC`.
- Outside P2MR execution, `OP_CHECKSIGPQC` is not a normal Bitcoin signature opcode.
- Outside P2MR execution, qbit's CTV byte remains part of the OP_SUCCESS upgrade space for Taproot-style scripts and is not a standard bare output form.

The active signature profile is bounded `SLH-DSA-SHA2-128s`:

| Item | Size / value |
|---|---:|
| PQC public key | 32 bytes |
| PQC secret key | 64 bytes |
| PQC signature | 3,680 bytes |
| P2MR v1 signature algorithm selector | None; the active leaf/opcode selects the fixed profile |
| Optional transaction-signature suffix | A nonzero sighash byte; `0x01` means `SIGHASH_ALL` |
| P2MR leaf version | `0xc0` |

### P2MR Data-Signature Opcodes

`OP_CHECKDATASIGPQC` and `OP_CHECKDATASIGADDPQC` verify PQC attestations over caller-supplied 32-byte message hashes, rather than over the qbit transaction sighash. They are intended for protocols where offchain attestors sign a structured message, such as a bridge message that also commits to a transaction template. qbit verifies the signature threshold and any separate script covenant/template checks; it does not independently prove external-chain finality, burn validity, or nullifier uniqueness.

Both opcodes are valid only during P2MR script execution. In other witness contexts, bytes `0xbc` and `0xbd` remain reserved OP_SUCCESS slots unless a future activation gives them different semantics.

The stack forms are:

```text
<sig> <msg_hash> <pubkey> OP_CHECKDATASIGPQC -> <bool>
<sig> <msg_hash> <num> <pubkey> OP_CHECKDATASIGADDPQC -> <num + success>
```

The data-signature checks use these consensus rules:

- `sig` must be empty or exactly 3,680 bytes.
- `msg_hash` must be exactly 32 bytes.
- `pubkey` must be exactly 32 bytes.
- Empty signatures do not verify; `OP_CHECKDATASIGPQC` pushes false and `OP_CHECKDATASIGADDPQC` contributes 0.
- Non-empty malformed or invalid signatures fail script execution.
- Verification uses `TaggedHash("QbitDataSigPQC", msg_hash)` and `CPQCPubKey::Verify(...)`.
- Each non-empty data-signature attempt consumes the same P2MR validation-weight charge as `OP_CHECKSIGPQC`: 3,730 units.

Standard relay/mining policy does not add a separate data-signature opcode policy layer. These opcodes inherit P2MR v1 witness and transaction policy:

| Policy limit | Value |
|---|---:|
| Maximum P2MR v1 initial witness stack item | 16 KiB |
| Maximum aggregate P2MR v1 initial witness stack bytes | 128 KiB |
| Maximum interpreter stack items | 1,000 |
| Maximum standard transaction weight | 400,000 |

The wallet tracks PQC signature usage. Bitcoin Core users should not treat qbit keys as ordinary secp256k1 keys with unlimited operational reuse. The active bounded profile has a finite signature budget per key, and wallet/RPC output can report `pqc_signature_count`, `pqc_signature_limit`, `pqc_signatures_remaining`, and `pqc_limit_state`.

## P2MR-Only Launch Policy

On public qbit launch and rehearsal chains, spendable user outputs are P2MR-only. A Bitcoin-style address type menu is the wrong model.

For normal receive and change outputs:

- Use `p2mr`.
- Expect qbit mainnet addresses with the `qb` HRP.
- Do not request `legacy`, `p2sh-segwit`, `bech32`, or `bech32m` wallet output types on public qbit chains.
- Do not expect old Bitcoin wallets or old non-P2MR qbit test wallets to remain compatible.

Regtest is different: it can be left unrestricted for tests, and P2MR-only behavior can be enabled there when test coverage needs to match launch-chain behavior.

The restricted-output rules are about spendable outputs. Non-payment outputs such as `OP_RETURN`, PayToAnchor, and reserved future witness-version forms may have special handling, but they are not ordinary user receive addresses.

## Wallet and Address Differences

The qbit wallet default path is descriptor-based P2MR.

Common qbit wallet examples:

```bash
qbit-cli createwallet "qbit-demo"
qbit-cli -rpcwallet=qbit-demo getnewaddress "" "p2mr"
qbit-cli -rpcwallet=qbit-demo getrawchangeaddress "p2mr"
qbit-cli -rpcwallet=qbit-demo createwalletdescriptor "p2mr"
```

Descriptor differences:

- `mr(...)` describes qbit P2MR outputs.
- `rawmr(...)` describes a raw P2MR Merkle root, without enough information by itself to sign.
- `pqc(...)` wraps private BIP32 key material for qbit wallet derivation.
- qbit wallet P2MR descriptors use purpose `87h`.
- A public `xpub`-only P2MR descriptor is not a portable watch-only derivation interface, because BIP32 public derivation cannot derive the needed SPHINCS+/P2MR public keys.

For watch-only P2MR tracking, use explicit public-key export/import:

```bash
qbit-cli -rpcwallet=signing-wallet exportpubkeydb
qbit-cli -rpcwallet=watchonly-wallet importpubkeydb '[...]'
```

PSBT support exists for P2MR, but Bitcoin Core PSBT tooling should not be assumed to understand qbit P2MR data. qbit currently uses dedicated P2MR PSBT fields plus qbit-proprietary fields where no stable generic encoding has been finalized.

## Archive Default and Witness Pruning

Bitcoin Core users are used to node pruning being explicit. qbit keeps that spirit, but the relevant historical data is witness-heavy.

qbit defaults to archive/full-history mode:

- `-prunewitnesses=0` is the default.
- Archive nodes advertise `NODE_ARCHIVE`.
- Peers that have compacted away historical witness data advertise `NODE_WITNESS_PRUNED`.
- `-connectarchive=<ip>` can be used to connect to peers that must advertise archive-capable service bits.
- `getarchivepeers` reports connected and configured archive peer state for bootstrap and monitoring.

Witness pruning is explicit:

```bash
qbitd -prunewitnesses=1
```

Witness-pruned nodes are not equivalent to archive nodes. A node that has pruned historical witness data may reject verbose historical `getblock` calls that require witness data it no longer has. Witness pruning is also incompatible with `-txindex`.

Because P2MR signatures are large and witness bytes are not discounted, archive storage expectations differ from Bitcoin Core expectations even when the command-line options look familiar.

## Mining, Cadence, and AuxPoW

qbit does not use Bitcoin's single proof-of-work lane plus 2016-block retarget.

qbit uses ASERT difficulty adjustment and Cadence lanes:

- Aggregate target spacing is 60 seconds.
- Permissionless qbit mining targets a 75 second lane.
- AuxPoW merged mining targets a 300 second lane.
- The lane split is intended to produce an aggregate 4:1 permissionless-to-AuxPoW cadence.
- Public testnet AuxPoW uses qbit chain ID `31430`.
- The in-tree mainnet AuxPoW chain ID is a placeholder and must not be treated
  as the future mainnet launch value.

A qbit block can be a permissionless block or an AuxPoW block. AuxPoW blocks carry an AuxPoW payload and must signal the expected version/chain-id semantics. Permissionless blocks must not include an AuxPoW payload.

Cadence ASERT is lane-local. If one lane is quiet while the other lane advances
the active chain, that quiet lane resumes from its prior same-lane history and
follow-up blocks may receive ASERT relaxation until the lane catches up. This is
expected consensus behavior for Cadence lanes; low-difficulty blocks contribute
proportionally lower chainwork.

Mining RPC differences include:

- `getblocktemplate` has Cadence/AuxPoW semantics.
- `getnetworkhashps` reports effective chainwork hashrate in H/s for `all`,
  `permissionless`, or `auxpow`. Lane-specific estimates filter work by lane
  while using the active-chain elapsed-time window; `getmininginfo.networkhashps`
  is the default `all` estimate.
- `getmininginfo.next` is the next permissionless/native Cadence candidate.
  AuxPoW candidate `bits` and `target` come from `createauxblock`.
- `createauxblock` creates an AuxPoW candidate.
- `submitauxblock` submits a serialized AuxPoW payload for a cached candidate.
- `-auxpowtemplateexpiry` controls how long same-tip AuxPoW candidates remain usable.
- `-auxpowtemplatecachelimit` bounds how many same-tip AuxPoW candidates remain cached.

Pool and merged-mining operators should not adapt Bitcoin pool instructions mechanically. Use qbit-specific mining documentation once published.

## RPC Surface Differences

Many inherited RPCs still exist, but several qbit-specific behaviors matter.

qbit-only or qbit-specific public RPCs include:

- `createauxblock`
- `submitauxblock`
- `getarchivepeers`
- `getorphanmetrics`
- `getconfirmationtarget`
- `getdefaultctvhash`
- `exportpubkeydb`
- `importpubkeydb`

Inherited RPC names with changed or qbit-specific semantics include:

- `getblocktemplate`, because of Cadence and AuxPoW.
- `getnetworkinfo`, because archive and witness-pruned service bits matter.
- `getblock`, because verbose historical witness data can be unavailable on witness-pruned nodes.
- `getnewaddress`, `getrawchangeaddress`, and `createwalletdescriptor`, because public launch chains are P2MR-only.
- `getaddressinfo`, `validateaddress`, `decodescript`, wallet signing, and PSBT RPCs, because P2MR carries additional script, key, signature, and watch-only data.

If you are integrating against qbit, start from qbit-generated RPC docs and qbit examples, not from Bitcoin Core examples with command names replaced.

## Known Non-Compatibilities

qbit is not compatible with Bitcoin addresses, Bitcoin payment URIs, Bitcoin blocks, Bitcoin transactions, Bitcoin wallets, or Bitcoin network peers.

Specific incompatibilities Bitcoin Core users commonly ask about:

- `bitcoin:` payment URIs are rejected. Use `qbit:`.
- Bitcoin `bc1...`, `tb1...`, Base58 P2PKH, Base58 P2SH, and Taproot-style receive flows are not the public qbit payment path.
- A Bitcoin Core wallet backup is not a qbit wallet migration path.
- Ordinary xpub-only watch-only flows are not enough for P2MR watch-only tracking.
- Generic Bitcoin PSBT tools should not be assumed to preserve or understand qbit P2MR fields.
- Bitcoin Lightning is not a drop-in port. Bitcoin Lightning relies on secp256k1 public-key algebra, key tweaking, ECDH, adaptor-signature-adjacent constructions, compact signatures, and BOLT transport assumptions. qbit's active SLH-DSA/P2MR path is hash-based and non-algebraic, so a qbit Lightning-like network would need a new channel protocol.
- Hardware wallet, external signer, pool, exchange, custody, and indexing integrations need qbit-specific validation before being treated as supported.

## What Still Feels Like Bitcoin Core

Some operational instincts still carry over:

- qbit has `qbitd`, `qbit-cli`, `qbit-qt`, `qbit-tx`, `qbit-wallet`, and related command-line tools corresponding to familiar Bitcoin Core tools.
- RPC authentication, wallet loading, data directories, configuration files, P2P networking, mempool policy, block validation, and functional test patterns remain recognizable.
- Standard node security guidance still applies: do not expose RPC to the public internet, protect wallet backups, keep private keys offline where practical, and verify binaries before running them.

The important difference is that the familiar scaffolding runs a different protocol. Treat qbit as a new chain with Bitcoin Core ancestry, not as Bitcoin with new ticker text.
