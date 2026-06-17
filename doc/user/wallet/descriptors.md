# Output Descriptors Technical Reference

> [!NOTE]
> This is a technical reference. For first-run wallet usage, start with
> [Wallets, P2MR Addresses, and Backups](p2mr-wallets.md). Public qbit launch
> chains use P2MR for ordinary receive and change outputs.

Output descriptors describe script templates that wallet and node RPCs can
derive, scan, import, or use to update PSBTs. qbit inherits the descriptor
language, but the public launch payment path is narrower than Bitcoin Core:
ordinary user funds should use P2MR.

Common descriptor-aware RPCs include:

- `getdescriptorinfo`
- `deriveaddresses`
- `importdescriptors`
- `listdescriptors`
- `scantxoutset`
- `scanblocks`
- `getdescriptoractivity`
- `utxoupdatepsbt`
- `descriptorprocesspsbt`
- `generatetodescriptor` on regtest

## P2MR Descriptors

qbit P2MR descriptors use `mr(...)` at the top level.

Examples:

```text
mr(pk(1111111111111111111111111111111111111111111111111111111111111111))
mr(pk(pqc([d34db33f/87h/1h/0h]xprv.../0/*)))
mr(multi_a(2,1111111111111111111111111111111111111111111111111111111111111111,2222222222222222222222222222222222222222222222222222222222222222))
rawmr(0000000000000000000000000000000000000000000000000000000000000000)
```

Current qbit Core P2MR wallet descriptors are pinned to:

- witness version 2 P2MR outputs
- current P2MR leaf version `0xc0`
- 32-byte PQC public keys
- raw SLH-DSA/Sphincs+ signatures
- PQC `OP_CHECKSIGPQC` and P2MR `multi_a`/`sortedmulti_a` script leaves
- `OP_CHECKSIG` and `OP_CHECKSIGVERIFY` are invalid in P2MR execution; use
  `OP_CHECKSIGPQC` or `OP_CHECKSIGPQC OP_VERIFY` for single-key leaves

`rawmr(MERKLE_ROOT)` describes a P2MR output by Merkle root only. It is useful
for explicit raw-root or watch-only handling, but it does not contain the leaf
scripts or private signing data needed to spend.

## P2MR Keys

Inside `mr(pk(KEY))`, `KEY` can be a literal 32-byte PQC public key encoded as
64 hex characters.

Inside `mr(pk(pqc(BIP32_KEY)))`, `pqc(...)` wraps private BIP32 key material
used by qbit Core to derive the committed PQC public key. qbit Core wallet
descriptors use purpose `87h` for this path.

Public `pqc(xpub/...)` descriptors may appear in wallet metadata, but they are
not a portable watch-only derivation interface. BIP32 public derivation cannot
derive SLH-DSA/P2MR public keys. For watch-only P2MR tracking, use
[`exportpubkeydb` and `importpubkeydb`](p2mr-pubkeydb.md).

Inside `mr(multi_a(...))` and `mr(sortedmulti_a(...))`, keys are literal
32-byte PQC public keys. Ranged `pqc(...)` key expressions are not supported
there.

## P2MR Upgrade Hooks

Future signature systems must use a future P2MR leaf version, opcode, or outer
witness version.

Reserved or unknown P2MR leaf versions are consensus upgrade hooks. Standard
relay policy rejects them today, and qbit wallet signing does not synthesize
witnesses for them. Treat reserved or unknown P2MR forms as miner-directed
technical workflows, not ordinary wallet-signable payments.

## Inherited Descriptor Forms

qbit still parses inherited descriptor forms such as:

- `pk(KEY)`
- `pkh(KEY)`
- `wpkh(KEY)`
- `sh(SCRIPT)`
- `wsh(SCRIPT)`
- `tr(KEY)` and `tr(KEY,TREE)`
- `multi(...)` and `sortedmulti(...)`
- `multi_a(...)` and `sortedmulti_a(...)` inside `tr`
- `addr(ADDR)`
- `raw(HEX)`

These forms remain useful for tests, regtest, compatibility, scanning, and
technical integration work. They are not the normal launch-chain receive/change
wallet path.

Do not use inherited `wsh(sortedmulti(...))`, Taproot, MuSig, or Miniscript
examples as qbit public launch wallet recipes. A narrow qbit Core
`mr(multi_a(...))` P2MR multisig PSBT flow has test coverage; see
[P2MR Multisig](p2mr-multisig.md) for that advanced custody workflow. Ordinary
user funds should still use single-signer P2MR wallets.

## Descriptor Syntax

Descriptors consist of a script expression, optionally followed by an
8-character checksum:

```text
SCRIPT
SCRIPT#CHECKSUM
```

`KEY` expressions may include origin information:

```text
[fingerprint/path]key/path/*
```

The key may be a supported public key, private key, `xpub`, or `xprv`,
depending on the descriptor form. Hardened derivation requires private key
material.

Use `getdescriptorinfo` to canonicalize descriptors and add checksums before
importing them.

## Related Docs

- [Wallets, P2MR Addresses, and Backups](p2mr-wallets.md)
- [P2MR Watch-Only Pubkey Database Guide](p2mr-pubkeydb.md)
- [P2MR Multisig](p2mr-multisig.md)
- [PSBT Technical Reference](psbt.md)
