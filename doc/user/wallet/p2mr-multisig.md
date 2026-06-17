# P2MR Multisig (`mr(multi_a(...))`)

> [!NOTE]
> This is an advanced custody reference. For ordinary single-signer P2MR wallet
> use, start with [Wallets, P2MR Addresses, and Backups](p2mr-wallets.md). P2MR
> multisig is a qbit-native, script-path threshold flow. It is not the same as
> any inherited Bitcoin Core multisig recipe, and it must be run with
> qbit-aware tooling end to end.

Mainnet is not public yet. Mainnet examples below apply when qbit mainnet is
announced. Use the dedicated [public testnet guide](../public-testnet.md) for
the current rehearsal network's chain flag and address HRP.

P2MR multisig lets a group require a threshold of independent post-quantum
signatures (for example, 2 of 3) to spend an output. It is built from qbit's
P2MR script path and post-quantum (PQC) signing, so it inherits qbit-specific
behavior that ordinary Bitcoin multisig tooling does not understand. Read this
whole page before putting real value behind a P2MR multisig address.

## What P2MR Multisig Is

A normal P2MR output commits to a single spending rule: one PQC public key that
must sign. P2MR multisig commits instead to a threshold rule encoded as a P2MR
leaf script:

```text
<pubkey_A> OP_CHECKSIGPQC <pubkey_B> OP_CHECKSIGADD <pubkey_C> OP_CHECKSIGADD <k> OP_NUMEQUAL
```

The first key is checked with `OP_CHECKSIGPQC`, each additional key adds to a
running tally with `OP_CHECKSIGADD`, and `OP_NUMEQUAL` requires the tally to
equal the threshold `k`. A 2-of-3 output therefore needs exactly two valid PQC
signatures out of the three committed keys.

This is the same accumulator pattern as Taproot `multi_a` (BIP 342), but the
opcode is the qbit post-quantum `OP_CHECKSIGPQC`, the keys are 32-byte SLH-DSA
(SPHINCS+) public keys, the signatures are raw SLH-DSA signatures (about 3,680
bytes each), and the output is a witness-version-2 P2MR output, not a Taproot
or `wsh` output.

The wallet descriptor that produces this output is:

```text
mr(multi_a(2,<pubkey_A>,<pubkey_B>,<pubkey_C>))
```

`sortedmulti_a(...)` is accepted and canonicalizes to `multi_a(...)` with the
keys in sorted order, so two coordinators who list the same keys in a different
order still derive the same address.

## How It Differs From Bitcoin Multisig

These differences are the whole reason this page exists. Each one breaks a habit
carried over from Bitcoin multisig tutorials.

- **Keys are literal PQC public keys, not xpubs.** Inside `mr(multi_a(...))`
  every key is a literal 32-byte PQC public key (64 hex characters). Ranged
  `pqc(...)` expressions and BIP32 extended public keys are not allowed there.
  SLH-DSA public keys cannot be derived from an xpub, so the Bitcoin pattern of
  building a multisig descriptor from a few xpubs does not apply. Each signer
  exports the exact PQC public key they will use.
- **There is no `createmultisig` recipe.** Do not use `createmultisig` or
  `addmultisigaddress`. Build the address from a `mr(multi_a(...))` descriptor
  imported into a watch-only wallet (below).
- **PSBTs are qbit PSBTs.** P2MR partial signatures and leaf data ride in
  qbit-specific PSBT fields. Generic Bitcoin PSBT software can silently drop
  them. See [PSBT Tooling Expectations](#psbt-tooling-expectations).
- **Each signer's key has a finite, stateful signature budget.** PQC keys carry
  a per-key signature counter that the signer's wallet must persist. See
  [PQC Counters In Multisig](#pqc-counters-in-multisig).
- **The output is post-quantum.** A `wsh(sortedmulti(...))`, legacy `multi`,
  Taproot, or MuSig output is an inherited Bitcoin output and is not a P2MR
  launch-chain output. Funds sent to those are not protected by qbit's
  post-quantum signing model.

## Roles

A P2MR multisig deployment separates two kinds of participant:

- **Signers.** Each signer runs their own wallet that holds one PQC private key
  and its signature counter. Signers should be separated across machines,
  data directories, and wallet files so that no single compromise yields a
  spend, and so the stateful counters never collide. A signer only ever exports
  a public key and adds a signature to a PSBT.
- **Coordinator (watch-only).** A wallet created with private keys disabled that
  imports the `mr(multi_a(...))` descriptor. It can derive the address, watch
  for funding, build spend PSBTs, combine partial signatures, and finalize. It
  holds no signing material, so it cannot move funds by itself. Any participant
  can run a coordinator; it is a role, not a trusted third party.

The examples below show every role as a separate named wallet for readability.
In a real deployment the signer wallets live on separate, ideally offline,
machines.

## End-To-End Workflow

This mirrors the flow exercised by qbit's `feature_p2mr.py` functional test.
Commands use the mainnet-shaped form; on the public rehearsal network add the
network flag (for example `-testnet4`) shown in the
[public testnet guide](../public-testnet.md).

### 1. Each signer generates a P2MR signer public key

On each signer wallet (run on its own node/data directory):

```bash
qbit-cli -rpcwallet=signer-a createwalletdescriptor "p2mr"
qbit-cli -rpcwallet=signer-a exportpubkeydb
```

`exportpubkeydb` returns a `pubkeys` array. Pick one record and keep its
`pubkey` field (64 hex characters). That literal value is signer A's multisig
key. Repeat on signer B and signer C to collect three independent keys.

Do this on three genuinely separate signer wallets. Three keys from one wallet
is not a 2-of-3; it is one wallet with three keys.

### 2. Build and import the 2-of-3 descriptor into a watch-only coordinator

Assemble the descriptor from the three exported keys, add a checksum, then
import it into a private-keys-disabled coordinator wallet:

```bash
qbit-cli getdescriptorinfo "mr(multi_a(2,<pubkey_A>,<pubkey_B>,<pubkey_C>))"

qbit-cli -named createwallet \
  wallet_name="coordinator" \
  disable_private_keys=true \
  blank=true \
  load_on_startup=true

qbit-cli -rpcwallet=coordinator importdescriptors \
  '[{"desc":"mr(multi_a(2,<pubkey_A>,<pubkey_B>,<pubkey_C>))#<checksum>","timestamp":"now"}]'
```

Use the checksummed descriptor string from `getdescriptorinfo`. Derive the
receive address from the same descriptor:

```bash
qbit-cli deriveaddresses "mr(multi_a(2,<pubkey_A>,<pubkey_B>,<pubkey_C>))#<checksum>"
```

`multi_a` with literal keys is not ranged, so this returns a single P2MR
address. Confirm it is a witness script address with
`qbit-cli -rpcwallet=coordinator getaddressinfo "<address>"`.

### 3. Fund the address and wait for confirmations

Send to the derived P2MR multisig address and confirm the coordinator sees it:

```bash
qbit-cli -rpcwallet=coordinator gettransaction "<funding_txid>"
```

Wait until the coordinator reports a positive `confirmations` count before
spending.

### 4. The coordinator creates a spend PSBT from watch-only inputs

```bash
qbit-cli -rpcwallet=coordinator walletcreatefundedpsbt \
  '[]' \
  '[{"<destination_address>":<amount>}]' \
  0 \
  '{"includeWatching":true,"subtractFeeFromOutputs":[0]}'
```

`includeWatching` is required because the coordinator has no private keys. The
result `psbt` is the unsigned PSBT to hand to the signers.

A coordinator that imported only the single `mr(multi_a(...))` descriptor has no
change address of its own. Either spend the whole input (as above,
`subtractFeeFromOutputs` makes the one output absorb the fee so no change is
needed) or pass an explicit `changeAddress` in the options. Do not expect the
watch-only coordinator to invent a change output by itself.

### 5. Signer A signs, and the PSBT remains incomplete

```bash
qbit-cli -named -rpcwallet=signer-a walletprocesspsbt \
  psbt="<psbt_from_coordinator>" sign=true finalize=false
```

Sign without finalizing (`finalize` defaults to `true`, so pass `finalize=false`
during the handoff). The response reports `"complete": false`. Confirming the
threshold is not yet met:

```bash
qbit-cli finalizepsbt "<psbt_signed_by_a>"
```

This also returns `"complete": false` and no `hex`. One signature out of a
2-of-3 cannot be finalized. This is the security property working as intended.

### 6. Signer B signs independently, then combine and finalize

Signer B signs the **original coordinator PSBT** (not A's output), so the two
signatures are produced independently:

```bash
qbit-cli -named -rpcwallet=signer-b walletprocesspsbt \
  psbt="<psbt_from_coordinator>" sign=true finalize=false
```

This is still `"complete": false` on its own. Now combine the two partially
signed PSBTs and finalize:

```bash
qbit-cli combinepsbt '["<psbt_signed_by_a>","<psbt_signed_by_b>"]'
qbit-cli finalizepsbt "<combined_psbt>"
```

With two independent signatures present, `finalizepsbt` returns
`"complete": true` and the final transaction `hex`.

### 7. Validate, broadcast, mine, and confirm

```bash
qbit-cli testmempoolaccept '["<final_tx_hex>"]'
qbit-cli sendrawtransaction "<final_tx_hex>"
```

After the transaction is mined, confirm it from the coordinator:

```bash
qbit-cli -rpcwallet=coordinator gettransaction "<spend_txid>"
```

### 8. Restart and verify persistence

Stop and restart each participating node/wallet, then verify that state
survived the restart:

- **Coordinator:** `getbalances`, `listtransactions`, and `gettransaction
  <spend_txid>` show the spend confirmed and the funding output spent.
- **Each signer:** the PQC signature counter for the key that signed has
  advanced and persisted (next section). Counters are wallet-local state; they
  are not rebuilt by a rescan, so this check must be done on each signer's own
  wallet.
- **Spent state:** the multisig UTXO no longer appears as spendable
  (`listunspent` on the coordinator does not list the consumed output).

## PSBT Tooling Expectations

qbit supports P2MR PSBT creation, signing, combining, analysis, and
finalization, but a P2MR PSBT is a **qbit PSBT**, not a generic Bitcoin PSBT.

P2MR uses a mixed encoding. Some data uses dedicated P2MR PSBT input fields
(the per-key script-path signatures and the leaf scripts/control blocks), and
some uses a qbit proprietary PSBT namespace (the committed Merkle root). The
practical consequences:

- **Keep P2MR PSBTs inside qbit tooling.** Create, process, combine, and
  finalize with qbit Core (`walletcreatefundedpsbt`, `walletprocesspsbt`,
  `combinepsbt`, `finalizepsbt`). The independent signatures from each signer
  combine correctly inside qbit's `combinepsbt`.
- **Do not route a P2MR PSBT through generic Bitcoin PSBT software.** A tool
  that does not understand qbit's P2MR fields can silently drop them when it
  re-serializes the PSBT, discarding signatures or the data needed to finalize.
  Inspecting with `decodepsbt`/`analyzepsbt` is fine; mutating or re-saving
  with a non-qbit tool is not safe.
- **Hand off the whole PSBT.** Move the full PSBT between participants. Do not
  try to extract and reassemble individual signatures with non-qbit tooling.

See the [PSBT Technical Reference](psbt.md) for the broader PSBT surface.

## PQC Counters In Multisig

Every PQC key has a finite, stateful signature budget. For current P2MR v1
(`0xc0`) keys the hard limit is `1,073,741,824` (2^30) signatures per key,
tracked locally by the wallet that owns the key. This is qbit-specific and has
direct multisig consequences:

- **Each signer burns budget from their own key.** When signer A signs a
  multisig input, A's key counter advances by one; when signer B signs, B's
  counter advances by one. A key that does not sign is untouched. A 2-of-3
  spend consumes exactly two signatures total, one from each participating
  signer, even though three keys are committed.
- **Only the needed signatures are consumed.** qbit signing stops once the
  threshold is reachable, so signers do not waste budget producing more
  signatures than the threshold requires.
- **Counters are wallet-local and not reconstructible.** They are not rebuilt
  by a chain rescan, by the descriptor, by xpubs, or by a pubkey-database
  export. Each signer must protect their own counter with their own wallet
  backup.
- **Never run two live copies of a signer wallet.** Two copies of the same
  signing wallet can hand out the same counter value twice and diverge. Keep
  exactly one live signer copy, and do not restore an old backup and keep
  signing from it while another copy may also sign.
- **Watch the usage thresholds.** Inspect a key's usage on its own wallet (for
  example with `getaddressinfo` on a wallet-owned P2MR address, or from the
  `pqc_*` fields returned by signing RPCs such as `walletprocesspsbt`). Rotate
  to fresh keys well before a key reaches its limit. The `normal`/`warning`/
  `critical`/`exhausted` thresholds are documented in
  [Wallets, P2MR Addresses, and Backups](p2mr-wallets.md#pqc-signature-counters).

Because the threshold quorum is fixed at address-creation time and the keys are
literal, rotating a P2MR multisig means creating a **new** `mr(multi_a(...))`
address from fresh signer keys and moving funds to it. There is no in-place key
rotation for an existing multisig output.

## Why Inherited Bitcoin Multisig Tutorials Are Not Launch-Chain Guidance

Most multisig material online targets Bitcoin Core or Bitcoin wallets. On a
qbit launch chain that guidance is wrong in ways that can lose funds:

- `createmultisig`, `addmultisigaddress`, `wsh(sortedmulti(...))`, legacy
  `multi(...)`, Taproot `tr(...,multi_a(...))`, MuSig, and Miniscript produce
  **inherited Bitcoin outputs**, not P2MR outputs. They use ECDSA/Schnorr keys
  and are not protected by qbit's post-quantum signing.
- xpub-based multisig setup does not work for P2MR. PQC public keys cannot be
  derived from extended public keys; each signer must export an explicit PQC
  public key.
- Generic PSBT tools, hardware wallets, and external signers (`-signer=<cmd>`)
  do not understand P2MR fields or PQC signature counters. They are not
  supported launch-chain multisig tooling unless a specific toolchain has been
  validated for P2MR and PQC behavior and qbit owners have published it as
  supported.

When you need qbit multisig, use the qbit-native `mr(multi_a(...))` flow on this
page. Treat any Bitcoin multisig tutorial as inapplicable.

## Status And Limitations

- This flow has qbit functional and unit test coverage for the core 2-of-3
  PSBT spend path. It remains an advanced custody workflow. Validate the full
  path on your target rehearsal network, with real separated signers, before
  committing meaningful value.
- The quorum and key set are fixed when the address is created. Changing
  signers or threshold means a new address and a fund migration.
- External signer and hardware-wallet workflows are not supported P2MR multisig
  guidance yet.

## Quick Checklist

- Generate three independent signer keys on three separate signer wallets with
  `createwalletdescriptor "p2mr"` + `exportpubkeydb`.
- Build `mr(multi_a(2,A,B,C))`, checksum it with `getdescriptorinfo`, and import
  it into a `disable_private_keys` coordinator wallet.
- Fund the derived P2MR address and wait for confirmations on the coordinator.
- Coordinator builds the PSBT with `walletcreatefundedpsbt` and
  `includeWatching`.
- One signature is incomplete; two independent signatures combine and finalize.
- Keep every P2MR PSBT inside qbit tooling; never route it through generic
  Bitcoin PSBT software.
- Back up each signer wallet; protect the PQC counters; keep one live signer
  copy.
- Do not use inherited Bitcoin multisig, xpub-multisig, hardware-wallet, or
  external-signer recipes for P2MR funds.

## Related Docs

- [Wallets, P2MR Addresses, and Backups](p2mr-wallets.md)
- [P2MR Watch-Only Pubkey Database Guide](p2mr-pubkeydb.md)
- [Output Descriptors Technical Reference](descriptors.md)
- [PSBT Technical Reference](psbt.md)
