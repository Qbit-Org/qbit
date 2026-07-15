# P2MR Watch-Only Pubkey Database Guide

This is the canonical qbit guide for watch-only and offline-shaped P2MR
workflows. Use it when you need an online deposit wallet, watch-only accounting
wallet, or offline signer shape without putting private keys on the online
node.

For qbit P2MR wallets, do not use an xpub-only descriptor as the portable
watch-only interface. Use qbit's explicit P2MR pubkey database flow instead:

- `exportpubkeydb` on the signing wallet
- `importpubkeydb` on a private-keys-disabled watch-only wallet
- `getnextpubkeydbaddress` to allocate imported receive/change addresses
- `listpubkeydbstatus` to monitor remaining imported address capacity

Examples that omit a chain flag target mainnet. Use the public testnet guide
for testnet4 flags and HRPs.

## Why xpub Is Not Enough

Bitcoin Core watch-only setups usually share an extended public key and let the
watch-only wallet derive receive and change public keys.

qbit P2MR signing uses SPHINCS+/P2MR public keys derived by the qbit wallet. A
BIP32 extended public key cannot derive those SPHINCS+/P2MR public keys. Public
`pqc(xpub/...)` descriptors may appear in wallet metadata, but they are not a
portable watch-only derivation interface.

The qbit alternative is to export the actual 32-byte P2MR public keys that the
signing wallet has prepared, then import those explicit pubkeys into a
watch-only wallet.

## When To Use This Flow

Use the pubkey database flow when you need:

- an online deposit wallet that can generate P2MR receive addresses without
  holding private keys
- an accounting or indexing wallet that tracks P2MR receive/change history
- an offline signing setup where the signer remains separate from the online
  watcher
- a custody workflow that pre-allocates a bounded set of receive addresses

Do not use this flow as a replacement for wallet backups. The pubkey database
lets a watch-only wallet observe funds. It cannot sign and cannot recover the
signing wallet's private material or PQC signature counters.

## Roles

This guide uses two wallets:

| Wallet | Holds private keys | Purpose |
| --- | --- | --- |
| `signer` | yes | Creates P2MR keys, signs transactions, owns the real wallet backup |
| `watch` | no | Imports explicit P2MR pubkeys, allocates receive/change addresses, tracks activity |

Keep the signer backed up and protected. Treat the watch wallet as operational
state: it contains address allocation cursors and imported public-key records,
but not spending authority.

## Create The Signing Wallet

Create a normal descriptor wallet and keep it loaded on restart:

```bash
qbit-cli -named createwallet \
  wallet_name="signer" \
  load_on_startup=true
```

Back it up immediately:

```bash
qbit-cli -rpcwallet=signer backupwallet /secure/backups/qbit-signer.wallet.bak
```

Warm both receive and change P2MR descriptors so export data includes both
chains:

```bash
qbit-cli -rpcwallet=signer getnewaddress "" "p2mr"
qbit-cli -rpcwallet=signer getrawchangeaddress "p2mr"
```

If you know the watch wallet needs many addresses before the next top-up,
increase the signer's keypool before exporting:

```bash
qbit-cli -rpcwallet=signer keypoolrefill 1000
```

## Export P2MR Pubkeys

Export the prepared P2MR public keys:

```bash
qbit-cli -rpcwallet=signer exportpubkeydb > pubkeydb.json
```

The result has this shape:

```json
{
  "count": 2,
  "pubkeys": [
    {
      "pubkey": "<32-byte-p2mr-pubkey-hex>",
      "account": 0,
      "change": false,
      "index": 0
    },
    {
      "pubkey": "<32-byte-p2mr-pubkey-hex>",
      "account": 0,
      "change": true,
      "index": 0
    }
  ]
}
```

Fields:

| Field | Meaning |
| --- | --- |
| `pubkey` | 32-byte P2MR public key as hex |
| `account` | P2MR account number when known |
| `change` | `false` for receive/external, `true` for change/internal |
| `index` | signer-side descriptor index when known |

Move `pubkeydb.json` to the watch-only environment using your normal secure
file-transfer process. It is public-key material, not private key material, but
it still reveals future address capacity and should be treated as sensitive
operational metadata.

## Create The Watch-Only Wallet

Create the watch wallet with private keys disabled:

```bash
qbit-cli -named createwallet \
  wallet_name="watch" \
  disable_private_keys=true \
  blank=true \
  load_on_startup=true
```

`importpubkeydb` only works with a wallet that has private keys disabled. This
is intentional: the imported pubkey database is a watch-only surface.

## Import The Pubkey Database

Import the exported `pubkeys` array:

```bash
qbit-cli -rpcwallet=watch importpubkeydb "$(jq -c '.pubkeys' pubkeydb.json)"
```

The result reports how many pubkeys were newly imported:

```json
{
  "imported": 1000
}
```

Re-importing the same records is idempotent; already imported records are not
duplicated.

If you are building JSON manually, each entry must include a 32-byte P2MR
pubkey:

```bash
qbit-cli -rpcwallet=watch importpubkeydb \
  '[{"pubkey":"<64-hex-character-p2mr-pubkey>","account":0,"change":false,"index":0}]'
```

`importpubkeydb` accepts optional `internal` and `timestamp` arguments:

```bash
qbit-cli -rpcwallet=watch importpubkeydb "$(jq -c '.pubkeys' pubkeydb.json)" false now
```

Use `timestamp=now` only when you know the imported pubkeys have no prior
history. Use an earlier timestamp or full rescan strategy when recovering
historical activity.

## Check Imported Capacity

Check receive/change pools:

```bash
qbit-cli -rpcwallet=watch listpubkeydbstatus
```

The result reports each imported account/chain:

```json
{
  "chains": [
    {
      "account": 0,
      "internal": false,
      "next_index": 0,
      "highest_imported_index": 999,
      "remaining": 1000,
      "low_watermark": 100,
      "needs_topup": false
    }
  ]
}
```

Watch these fields:

- `internal=false`: receive/external address pool
- `internal=true`: change/internal address pool
- `next_index`: next allocatable imported index
- `remaining`: addresses still available in that pool
- `needs_topup`: import more pubkeys before allocating many more addresses

## Allocate Receive Addresses

Allocate the next imported receive address:

```bash
qbit-cli -rpcwallet=watch getnextpubkeydbaddress
```

The result includes the address and the backing P2MR pubkey:

```json
{
  "address": "qb1z...",
  "pubkey": "<32-byte-p2mr-pubkey-hex>",
  "internal": false,
  "account": 0,
  "index": 0,
  "remaining": 999
}
```

Store the returned `address`, `pubkey`, `account`, `index`, and your internal
customer/account mapping together. Do not derive addresses separately with
string manipulation.

To allocate from a nonzero account:

```bash
qbit-cli -rpcwallet=watch getnextpubkeydbaddress false 1
```

## Allocate Change Addresses

Most wallet-managed sends should be signed by the signing wallet, which can
choose its own change. Use internal allocations from the watch wallet only for
workflows that explicitly construct or inspect watch-only PSBTs.

Allocate an imported change/internal address:

```bash
qbit-cli -rpcwallet=watch getnextpubkeydbaddress true
```

External and internal cursors are independent. Running out of receive addresses
does not imply the change pool is exhausted, and vice versa.

## Receive And Monitor Funds

The watch wallet can track imported P2MR addresses:

```bash
qbit-cli -rpcwallet=watch getbalances
qbit-cli -rpcwallet=watch listtransactions "*" 20
qbit-cli -rpcwallet=watch listunspent
```

For a specific address:

```bash
qbit-cli -rpcwallet=watch getaddressinfo "qb1z..."
```

Expected watch-only behavior:

- the wallet recognizes imported P2MR addresses
- balances and transactions are observable
- private keys are not present
- signing is incomplete unless the PSBT is moved to the signer

## Top Up The Watch Wallet

When `listpubkeydbstatus` reports low remaining capacity, top up from the
signer:

```bash
qbit-cli -rpcwallet=signer keypoolrefill 2000
qbit-cli -rpcwallet=signer exportpubkeydb > pubkeydb-topup.json
qbit-cli -rpcwallet=watch importpubkeydb "$(jq -c '.pubkeys' pubkeydb-topup.json)"
```

The watch wallet imports only records it does not already have. Existing
allocation cursors are preserved.

Operational rule: top up before exhaustion. If `getnextpubkeydbaddress` returns
an imported pubkey pool exhausted error, stop assigning addresses from that
wallet until new pubkeys are imported.

## Offline Signing Shape

A typical online/offline flow is:

1. Offline signer creates or maintains the `signer` wallet.
2. Signer exports pubkeys with `exportpubkeydb`.
3. Online watch wallet imports pubkeys with `importpubkeydb`.
4. Online watch wallet allocates receive addresses with `getnextpubkeydbaddress`.
5. Online watch wallet creates an unsigned or incomplete PSBT when spending is
   required.
6. PSBT is moved to the signer.
7. Signer signs with qbit wallet RPCs.
8. Signed transaction or finalized PSBT returns to the online environment for
   broadcast.

Keep P2MR PSBTs inside qbit-aware tooling unless every tool in the path has
been validated for qbit P2MR fields.

## Backups And Recovery

Back up the signing wallet with `backupwallet`. That is the recovery artifact
for private keys and PQC signature counters:

```bash
qbit-cli -rpcwallet=signer backupwallet /secure/backups/qbit-signer.wallet.bak
```

Also back up:

- exported pubkeydb files used for watch-only imports
- watch wallet database, if it contains allocation cursors you rely on
- your external mapping from allocated address to customer/account/invoice
- PSBT and transaction audit records for custody workflows

The pubkey database does not replace the signer backup. It can reconstruct
watch-only tracking for exported pubkeys, but it cannot spend.

## Rescan And Historical Recovery

If the imported pubkeys may already have history, import with an appropriate
timestamp and plan for rescanning. Importing with `now` is fast but will not
find old activity.

For sparse receive/change recovery from a signer wallet:

```bash
qbit-cli -rpcwallet=signer exportpubkeydb > recovery-pubkeydb.json
qbit-cli -rpcwallet=watch importpubkeydb "$(jq -c '.pubkeys' recovery-pubkeydb.json)" false 0
```

Use an archive/full-history node for recovery that depends on historical
witness data. Witness-pruned nodes may not be able to answer every historical
query your recovery process needs.

## Common Errors

`importpubkeydb requires a wallet with private keys disabled`

Create the watch wallet with `disable_private_keys=true` and `blank=true`.

`Imported pubkey pool exhausted`

Run `keypoolrefill` and `exportpubkeydb` on the signer, import the new records
into the watch wallet, then retry allocation.

`Cannot import public P2MR descriptor`

Do not import a public `pqc(xpub/...)` P2MR descriptor as the watch-only
interface. Use `exportpubkeydb` and `importpubkeydb`.

The watch wallet sees funds but cannot sign

That is expected. Move a PSBT to the signing wallet for signing.

## Checklist

- Use `exportpubkeydb`, not xpub-only P2MR descriptors.
- Create the watch wallet with private keys disabled.
- Import the `pubkeys` array, not the whole wrapper object.
- Allocate receive addresses with `getnextpubkeydbaddress`.
- Monitor `listpubkeydbstatus` and top up before exhaustion.
- Keep signer wallet backups separate and current.
- Keep only one live signer copy active for signing operations.
- Treat qbit P2MR PSBTs as qbit-specific unless other tooling has been
  validated.
