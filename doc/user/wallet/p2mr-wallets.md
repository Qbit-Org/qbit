# Wallets, P2MR Addresses, and Backups

This is the canonical wallet guide for ordinary qbit launch-chain use. It
covers P2MR receive and change addresses, `qbit:` payment URIs, wallet
creation, signing-wallet backups, PQC signature counters, and the safe pointer
to qbit's watch-only pubkey database flow.

qbit wallet behavior is intentionally narrower than Bitcoin Core on launch
chains. The normal spendable address type is P2MR, the normal payment URI scheme
is `qbit:`, and P2MR private-key wallets carry stateful PQC signature counters
that must be protected with the wallet.

Examples below target mainnet unless they include a testnet4 chain flag. Use
the dedicated public testnet guide for testnet4-specific network details.

## Address Rules

Public qbit launch chains use P2MR as the spendable output model. Wallet
receive and change addresses should be P2MR only.

Use:

```bash
qbit-cli -rpcwallet=main getnewaddress "" "p2mr"
qbit-cli -rpcwallet=main getrawchangeaddress "p2mr"
```

The explicit `"p2mr"` argument is useful in examples and automation, even
though launch-chain wallets default to P2MR where possible.

Do not request inherited Bitcoin address families on launch chains:

```text
legacy
p2sh-segwit
bech32
bech32m
taproot receive paths
ordinary multisig receive paths
```

Those names may still appear in inherited reference material or in regtest-only
testing flows, but they are not the user-facing qbit launch-chain wallet model.
Unrestricted regtest can still use the inherited address families unless
`-p2mronly=1` is set; do not treat unrestricted regtest behavior as portable to
public qbit networks. P2MR script-path multisig is a separate advanced flow; do
not use Bitcoin Core `createmultisig` or `wsh(sortedmulti(...))` tutorials as a
qbit launch-chain receive-address recipe. See [P2MR Multisig](p2mr-multisig.md)
for the qbit-native `mr(multi_a(...))` threshold flow.

## Address Prefixes

P2MR addresses are encoded with the chain's qbit HRP:

| Network | HRP |
| --- | --- |
| mainnet | `qb` |

Use the dedicated public testnet guide for rehearsal-network HRPs.

For payments, use the `qbit:` URI scheme:

```text
qbit:qb1...
qbit:qb1...?amount=1.25
```

Do not use `bitcoin:`, `bitcoin://`, or `qbit://`. qbit accepts `qbit:` only.

## Create a Wallet

qbit creates descriptor wallets. Legacy wallet creation is not supported.

```bash
qbit-cli -named createwallet \
  wallet_name="main" \
  load_on_startup=true
```

To encrypt the wallet at creation time:

```bash
qbit-cli -named createwallet \
  wallet_name="main" \
  passphrase="use a real passphrase here" \
  load_on_startup=true
```

Then confirm the wallet is loaded and descriptor-based:

```bash
qbit-cli -rpcwallet=main getwalletinfo
```

Create a fresh receive address:

```bash
qbit-cli -rpcwallet=main getnewaddress "" "p2mr"
```

Use a new receive address for each payer. This is normal qbit wallet hygiene,
and it matters more in qbit because each P2MR key also has a finite PQC
signature budget.

## What P2MR Descriptors Look Like

qbit wallet descriptors use the `mr(...)` family. A normal wallet-created P2MR
descriptor derives a PQC key through a wrapped BIP32 private-key path:

```text
mr(pk(pqc(.../87h/.../0/*)))
```

The visible purpose field is `87h`. You usually do not need to construct this
descriptor manually; qbit creates the active receive and change descriptors for
a normal wallet.

Important difference from Bitcoin Core watch-only workflows: a public
`pqc(xpub...)` descriptor is not a portable P2MR watch-only derivation interface.
BIP32 extended public keys cannot derive SPHINCS+/P2MR public keys. On P2MR-only
chains, RPCs such as `listdescriptors` and `createwalletdescriptor` may omit
public P2MR descriptors that rely on BIP32 extended public keys and direct you
to the pubkey database flow instead.

## Back Up the Signing Wallet

Use `backupwallet` to copy the wallet database:

```bash
qbit-cli -rpcwallet=main backupwallet /secure/backups/qbit-main.wallet.bak
```

Restore with:

```bash
qbit-cli restorewallet "main-restored" /secure/backups/qbit-main.wallet.bak true
```

For a normal qbit signing wallet, the wallet backup is the recovery artifact.
Do not assume that an exported public descriptor or xpub-style record is enough
to recover a spendable P2MR wallet.

Back up after wallet creation, after encryption/passphrase changes, after
important wallet maintenance, and periodically after signing activity. Also
treat the signing wallet as stateful after spends: qbit persists PQC signature
counters in the wallet database. Do not run two copies of the same signing
wallet at the same time, and do not restore an old backup and continue signing
from it while a newer copy of the same wallet may also sign. That can make the
two copies disagree about the current PQC signature counters.

## PQC Signature Counters

P2MR v1 current-version leaves use version `0xc0` and bounded SLH-DSA keys.
Each local PQC key has a hard P2MR v1 signature limit of `1,073,741,824`
signatures, tracked by the wallet.

PQC counters are wallet-local signing state. They are not reconstructed by a
chain rescan, by descriptors, by xpubs, or by pubkey database exports. Old
backups, descriptor recovery, and separate live signer copies can produce stale
or divergent local counts.

Use `getaddressinfo` on a wallet-owned P2MR address to inspect local state:

```bash
qbit-cli -rpcwallet=main getaddressinfo "qb1..."
```

User-visible wallet and signing RPCs may report:

```text
pqc_key_states
pqc_signature_count
pqc_signature_limit
pqc_signatures_remaining
pqc_limit_state
pqc_overall_limit_state
warnings
```

Each `pqc_key_states` item includes:

```text
pubkey
pqc_signature_count
pqc_signature_limit
pqc_signatures_remaining
pqc_limit_state
```

The limit states are:

| State | Used signatures |
| --- | ---: |
| `normal` | fewer than `268,435,456` |
| `warning` | `268,435,456` through `1,056,964,607` |
| `critical` | `1,056,964,608` through `1,073,741,823` |
| `exhausted` | `1,073,741,824` or more |

These thresholds are public contract for P2MR v1 `0xc0` signing keys.

Prefer the structured `pqc_key_states` array when building integrations.
Top-level single-key aliases such as `pqc_signature_count` are present only
when exactly one PQC key is in the report.

Signing RPCs can include PQC usage state when local P2MR signing happened:

- `sendtoaddress` with `verbose=true`
- `sendmany` with `verbose=true`
- `send`
- `sendall`
- `signrawtransactionwithwallet`
- `walletprocesspsbt` with `sign=true`

`send` and `sendall` are experimental RPCs. `signrawtransactionwithkey` can use
explicit `pqc(KEY)` material but does not expose or persist wallet counter
state.

Signing RPCs may also return a `warnings` array. Display or log warning text,
but do not parse it as a stable programmatic interface.

If a wallet reports `warning` or `critical` usage for a key, stop reusing that
receive address and move funds to fresh P2MR addresses while signing budget
remains. If a key reaches `exhausted`, it can no longer produce valid new
signatures.

## Watch-Only and Offline Workflows

Do not use the ordinary Bitcoin Core xpub watch-only recipe for P2MR. qbit's
P2MR watch-only flow exports explicit PQC public keys from the signing wallet
and imports those public keys into a private-keys-disabled wallet.

For the full workflow, see the
[P2MR Watch-Only Pubkey Database Guide](p2mr-pubkeydb.md).

On the signing wallet:

```bash
qbit-cli -rpcwallet=main exportpubkeydb
```

The result contains a `pubkeys` array. If you need a larger watch-only receive
pool, refill the signing wallet's keypool before exporting:

```bash
qbit-cli -rpcwallet=main keypoolrefill 1000
qbit-cli -rpcwallet=main exportpubkeydb
```

Move the exported `pubkeys` array to the watch-only node. The watch-only wallet
must be created with private keys disabled:

```bash
qbit-cli -named createwallet \
  wallet_name="watch" \
  disable_private_keys=true \
  blank=true \
  load_on_startup=true
```

Import the exported P2MR pubkey records:

```bash
qbit-cli -rpcwallet=watch importpubkeydb '[{"pubkey":"<64-hex-character-p2mr-pubkey>","account":0,"change":false,"index":0}]'
```

If you saved the full `exportpubkeydb` result to a file, import the `pubkeys`
array from that result:

```bash
qbit-cli -rpcwallet=watch importpubkeydb "$(jq -c '.pubkeys' pubkeydb.json)"
```

Allocate the next imported receive address from the watch-only pubkey pool:

```bash
qbit-cli -rpcwallet=watch getnextpubkeydbaddress false 0
```

Check whether the imported pool needs to be topped up:

```bash
qbit-cli -rpcwallet=watch listpubkeydbstatus
```

When the watch-only pool is low, export more pubkeys from the signing wallet and
import them before generating more watch-only receive addresses.

## PSBT Compatibility

qbit supports P2MR PSBT signing and finalization, but the P2MR PSBT encoding is
currently a mixed model: some data uses dedicated P2MR PSBT fields, and some
qbit-specific data still uses qbit proprietary fields while the long-term
standardized format is being settled.

For now, treat P2MR PSBTs as qbit PSBTs. Do not assume generic Bitcoin PSBT
software can safely inspect, modify, combine, or finalize every qbit P2MR PSBT.
Keep unsigned and partially signed PSBTs with the qbit tooling that created
them unless you have explicitly validated the other tool's P2MR support.

## External Signers

qbit retains the `-signer=<cmd>` option surface, but external signer workflows
are not public launch-chain wallet guidance yet. Do not use inherited Bitcoin
Core hardware-wallet instructions for P2MR funds until P2MR/PQC signing,
address display, PSBT handling, backup behavior, and PQC counter behavior have
been validated with qbit-aware tooling.

## Quick Checklist

- Create descriptor wallets with `createwallet`; do not create legacy wallets.
- Use `getnewaddress "" "p2mr"` for receive addresses.
- Use `getrawchangeaddress "p2mr"` only for raw-transaction workflows.
- Use `qbit:` payment URIs only.
- Do not use Bitcoin legacy, P2SH-SegWit, Bech32 v0, Bech32m/Taproot, or legacy
  multisig receive flows on launch chains.
- Back up the wallet database with `backupwallet`.
- Keep only one live signer copy of a P2MR wallet.
- Use `exportpubkeydb` and `importpubkeydb` for P2MR watch-only tracking.
- Do not use external signer or hardware-wallet recipes unless qbit-specific
  release docs explicitly mark that workflow as supported.
- Pay attention to PQC signature usage warnings and rotate to fresh addresses
  before a key reaches its limit.
