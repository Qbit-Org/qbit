Qbit v0.1.0-testnet4 Release Notes
===================================

Qbit: Post-quantum peer to peer digital value

Crypto is vulnerable to quantum theft, but it doesn't have to be. For the first
time, digital value can be secured natively with quantum-resistant signatures
from block zero.

Qbit version v0.1.0-testnet4 is available from the release page for that
version.

This release provides the public Qbit testnet4 node, wallet, GUI, mining, relay,
RPC, documentation, and release-verification surface. It includes Qbit-specific
network identity, consensus rules, wallet signing, mining flows, address
behavior, relay tooling, and operator workflows for public testnet
participation.

Testnet-era release artifacts are for public testnet use only unless the
release page explicitly says otherwise. Qbit mainnet is not launched. Do not
treat any in-tree mainnet genesis block, hash, seed placeholder, or endpoint
placeholder as an official mainnet launch commitment.

Testnet coins have no economic value, and the public testnet may be reset or
replaced during rehearsal.

This release starts a reset testnet4 lineage. It is not compatible with earlier
testnet4 rc chain data; operators who ran an earlier rc should remove or
archive their old `testnet4` network directory before starting this release.

Please report bugs using the Qbit issue tracker.

Compatibility
=============

The public Qbit testnet4 chain is selected with:

```bash
qbitd -testnet4
qbit-cli -testnet4 getblockchaininfo
```

Official testnet release binaries are expected to reject no-flag mainnet
startup and explicit `-chain=main` startup. Use `-testnet4` or
`-chain=testnet4` for the public testnet.

Supported and tested platforms for this release are the artifacts attached to
the GitHub Release page. The release page is the source of truth for available
platform builds, checksums, signatures, and attestations.

Public testnet4 identity in this release:

| Item | Value |
|---|---|
| Chain flag | `-testnet4` or `-chain=testnet4` |
| Default P2P port | `48355` |
| Default RPC/REST port | `48352` |
| Default onion bind port | `48356` |
| Address HRP | `tq` |
| Message start / network magic | `0xc7c41640` |
| Genesis hash | `000000000000796fe86bbc0bf1b66a07e4b4c0676f74b54cf7e5ce8b3f1a0090` |
| Genesis bits | `0x1a7f1ab5` |
| Initial Cadence lane bits | `0x1a7f1ab5` |
| Spendable address model | P2MR |
| DNS seeds | `coherence-testnet4.qbit.org`, `triplet-testnet4.qbit.org` |
| Fixed seeds | `57.129.86.61:48355`, `40.160.66.196:48355` |
| Archive endpoints | `fermion-testnet4.qbit.org:48355`, `boson-testnet4.qbit.org:48355` |
| Minimum chain work | `0000000000000000000000000000000000000000000000000000000000000000` |
| Default assume-valid block | `0000000000000000000000000000000000000000000000000000000000000000` |

No public faucet or explorer is assumed by this release note. Use only
resources explicitly published for this release.

Notable changes
===============

### Network identity and operator defaults

- Qbit ships Qbit-native executable names: `qbitd`, `qbit-cli`, `qbit-qt`,
  `qbit-tx`, `qbit-util`, and `qbit-wallet`.
- The default config filename is `qbit.conf`. Default data directories are
  `~/.qbit/` on Linux, `~/Library/Application Support/Qbit/` on macOS, and
  `%LOCALAPPDATA%\Qbit\` on Windows.
- Default RPC/REST ports are Qbit-specific: `8352` for mainnet, `18352` for
  testnet3, `48352` for testnet4, `38352` for signet, and `18452` for regtest.
- Qbit init, service, manpage, CMake, package, Qt, NSIS, and product metadata
  have been aligned around Qbit names and assets.
- Payment URIs use `qbit:`. The wallet and GUI reject incompatible payment URI
  variants for Qbit payments.

### Consensus and policy

- Qbit defines its own public-chain genesis blocks, address prefixes,
  message-start bytes, ports, seeds, and chain parameters.
- Blocks target a 60 second aggregate cadence with ASERT difficulty adjustment
  and a 2 hour half-life.
- Cadence mining is active from genesis on public Qbit chains. Permissionless
  mining targets a 75 second lane, and AuxPoW merged mining targets a 300
  second lane.
- Public Qbit chains use P2MR as the spendable output model. P2MR is a witness
  v2, 32-byte Merkle-root output with script-path spending only.
- `OP_CHECKSIGPQC` is active inside P2MR execution and verifies bounded
  SLH-DSA-SHA2-128s signatures. Current PQC keys are 32-byte public keys,
  64-byte secret keys, and 3,680-byte signatures.
- P2MR-only script validation rejects `OP_CHECKSIGPQC` outside P2MR and rejects
  executed legacy signature opcodes inside P2MR. P2MR authorization uses
  canonical PQC checksig, verify, and threshold forms.
- P2MR-only data-signature opcodes `OP_CHECKDATASIGPQC` (`0xbc`) and
  `OP_CHECKDATASIGADDPQC` (`0xbd`) support 32-byte message-hash attestations.
- P2MR-only `OP_CHECKTEMPLATEVERIFY` is available at opcode byte `0xbb`, with
  node-canonical default CTV hash support.
- Qbit has no witness discount. `WITNESS_SCALE_FACTOR` is `1`, and max block
  weight is `2,000,000`.
- Coinbase maturity is `1,000` blocks.
- The block subsidy starts at `210 QBT`, steps every `43,200` blocks, and uses
  a compound floor stepdown of `598 / 625` until the `210,000,000 QBT` money cap
  is reached.
- Public-chain restricted-output mode accepts ordinary spendable P2MR outputs,
  reserved future witness forms, `OP_RETURN`, and PayToAnchor outputs. Legacy,
  P2SH-SegWit, native SegWit v0, and Taproot receive/change outputs are not the
  public Qbit payment path.
- Public testnet4 starts this reset release without a post-genesis
  minimum-chainwork floor or assume-valid checkpoint. Those values should only
  be raised after a validated reset-chain checkpoint exists.
- Regtest defaults follow Qbit's P2MR-only restricted-output behavior unless a
  test explicitly opts out.

### Wallet, address, PSBT, and RPC behavior

- Descriptor wallets are the supported wallet type. Legacy wallet creation is
  not supported.
- Wallet receive and change flows use P2MR on launch and rehearsal chains:

  ```bash
  qbit-cli -testnet4 -rpcwallet=<wallet> getnewaddress "" "p2mr"
  qbit-cli -testnet4 -rpcwallet=<wallet> getrawchangeaddress "p2mr"
  ```

- Qbit adds P2MR descriptors and script support, including `mr(...)`,
  `rawmr(...)`, `pk(...)`, `multi_a(...)`, `sortedmulti_a(...)`, and `pqc(...)`
  where appropriate.
- P2MR signing uses stateful PQC signature counters. Wallet and signing RPCs
  can report `pqc_signature_count`, `pqc_signature_limit`,
  `pqc_signatures_remaining`, `pqc_limit_state`, and related warning fields.
- Do not run two active copies of the same signing wallet. Restore and backup
  procedures must preserve wallet state, including PQC signature counters.
- Plain xpub-only watch-only flows are not enough for Qbit P2MR. Use
  `exportpubkeydb`, `importpubkeydb`, `getnextpubkeydbaddress`, and
  `listpubkeydbstatus` for watch-only P2MR address allocation.
- Qbit supports P2MR PSBT signing and finalization, including dedicated P2MR
  data and Qbit-proprietary fields. Non-Qbit PSBT tooling should not be assumed
  to preserve or understand those fields.
- Wallet transaction construction, PSBT, input, spend, coin-control, and fee
  estimate paths account for Qbit P2MR signature sizes.
- Wallet-created payment outputs to reserved future witness versions are
  rejected before send, funding, PSBT, or bumpfee RPCs can report ordinary
  success.
- Imported PQC secret material is validated before it reaches wallet storage,
  and deterministic PQC key derivation uses the trusted key-generation public
  key output.
- Parallel PQC wallet signing is supported while preserving per-wallet lock
  ordering and failure handling.
- Qbit adds or changes public RPCs for Qbit-specific operation, including
  `createauxblock`, `submitauxblock`, `getarchivepeers`, `getorphanmetrics`,
  `getconfirmationtarget`, `exportpubkeydb`, `importpubkeydb`,
  `getnextpubkeydbaddress`, `listpubkeydbstatus`, and `getdefaultctvhash`.
- Existing RPCs such as `getblocktemplate`, `getnetworkinfo`, `getblock`,
  `getnewaddress`, `getrawchangeaddress`, `validateaddress`, `getaddressinfo`,
  `walletprocesspsbt`, `decodepsbt`, and `signrawtransactionwithkey` have
  Qbit-specific behavior where P2MR, PQC signing, archive service bits, witness
  pruning, Cadence, or AuxPoW apply.

### Mining and confirmation policy

- Permissionless mining continues to use `getblocktemplate` and `submitblock`,
  but templates use Qbit Cadence, ASERT, restricted-output, and full-witness
  weight rules.
- AuxPoW merged mining is exposed through `createauxblock` and
  `submitauxblock`. Public testnet's AuxPoW chain ID is `31430`.
- ASICBoost-compatible version-mask handling is available for Qbit mining
  templates. Custom and AuxPoW templates suppress inappropriate rolling masks
  where miners must not mutate Qbit chain-id, reserved, or AuxPoW layout bits.
- `getnetworkhashps` can report estimates for `all`, `permissionless`, or
  `auxpow` lanes.
- `getconfirmationtarget` estimates Qbit confirmation targets from transaction
  value, requested security level, observed stale rate, and observed or modeled
  hashrate. Exchanges and custodians should use it as an input to local deposit
  policy.
- Fresh coinbase rewards mature after 1,000 Qbit blocks. Pool and custody
  accounting must not treat newly mined rewards as immediately spendable.
- PayToAnchor mining payouts are rejected, and mining/RPC policy is tightened
  around Qbit output-script expectations.

### Node operation and archive bootstrap

- Qbit defaults to archive/full-history witness retention. Witness pruning is
  an explicit opt-in mode with `-prunewitnesses=1`.
- Archive-capable nodes advertise `NODE_ARCHIVE`. Witness-pruned nodes
  advertise `NODE_WITNESS_PRUNED`.
- `-connectarchive=<host:port>` provides a stricter archive bootstrap fallback.
  Peers configured this way must advertise the expected archive and witness
  service bits and must not advertise or imply witness-pruned history.
- `getarchivepeers` reports archive-relevant connected peers and configured
  archive fallback targets.
- Witness pruning is incompatible with `-txindex`. Indexers, explorers,
  exchanges, and support tooling that require historical witness data should
  run archive nodes.
- Verbose historical `getblock` calls can fail on witness-pruned history when
  the node no longer has the needed witness data.
- P2P sync handling preserves AuxPoW payloads during headers presync and
  redownload while bounding retained serialized AuxPoW bytes. Validated block
  download timeouts have been adjusted for Qbit's slower block-validation paths.

### PHOTON relay

- `qbit-photon` is available as a standalone relay daemon for authenticated UDP
  block relay between Qbit nodes.
- Deploy `qbit-photon` only when authenticated peer links and local qbitd
  RPC/ZMQ access are configured.
- PHOTON subscribes to qbitd ZMQ block notifications, fetches blocks over qbitd
  RPC, relays encoded block data to configured peers, and submits reconstructed
  blocks to local qbitd.
- PHOTON includes FEC support, peer freshness checks, replay protection,
  bounded inbound relay state, restart diagnostics, and per-peer session
  isolation so stale sessions do not poison current relay delivery.
- Release tooling includes a separate PHOTON build path.

### Release, CI, documentation, and supply chain

- Qbit Guix build and attestation tooling includes Qbit-specific artifact
  naming and independent builder attestation support.
- Signed-release publication gates validate pinned trusted refs, signer set
  size, release artifacts, builder attestations, and key metadata.
- The libbitcoinpqc Qbit subtree has been refreshed and supported with AVX2,
  TSAN, upstream fuzz, low-cap failure, and wrapper evidence workflows.
- CI coverage has been expanded for Windows builds, Windows Qt diagnostics,
  public testnet4 transport parameters, block-weight assumptions, scanner
  dependencies, and disk-pressure failure modes.
- Public docs have been reorganized around Qbit users, integrators, operators,
  release verification, exchange/custody operation, mining pool integration,
  RPC deltas, P2MR wallet workflows, and full-validation bootstrap.
- Generated Qbit RPC documentation can be installed with release artifacts
  under `share/doc/qbit/rpc/` and published manually through the RPC docs
  workflow.

Credits
========

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this release.
