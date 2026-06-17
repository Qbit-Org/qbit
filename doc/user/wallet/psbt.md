# PSBT Technical Reference

> [!NOTE]
> This is a technical reference. qbit Core supports P2MR PSBT creation,
> signing, combining, analysis, and finalization when every tool in the path is
> qbit-aware. Do not use generic Bitcoin PSBT tools for P2MR funds unless that
> exact toolchain has been validated with qbit P2MR data.

qbit inherits the Partially Signed Bitcoin Transaction (PSBT) format defined by
[BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) and
exposes the same RPC interface for working with PSBTs, but P2MR adds
qbit-specific signing data. Treat P2MR PSBTs as qbit PSBTs.

## Supported P2MR Scope

qbit PSBT support signs and finalizes current P2MR script-path inputs:

- witness v2 P2MR outputs
- current P2MR leaf version `0xc0`
- 32-byte PQC public keys
- raw SLH-DSA/Sphincs+ signatures
- qbit-aware P2MR PSBT fields

Reserved P2MR leaf versions and reserved outer witness versions remain upgrade
hooks. They are non-standard under default relay policy, and wallet PSBT
signing/finalization does not synthesize witnesses for them.

PSBTs may still carry raw P2MR roots or explicit leaf/control data for
watch-only and custom workflows. Treat reserved or unknown P2MR forms as
explicit miner-directed workflows, not ordinary wallet-signable P2MR.

## RPCs

Common PSBT RPCs still exist:

- `walletcreatefundedpsbt`
- `walletprocesspsbt`
- `descriptorprocesspsbt`
- `utxoupdatepsbt`
- `finalizepsbt`
- `combinepsbt`
- `decodepsbt`
- `analyzepsbt`
- `createpsbt`
- `converttopsbt`
- `joinpsbts`

For ordinary P2MR wallet use, prefer wallet RPCs that keep qbit P2MR metadata
inside qbit Core. Use `decodepsbt` and `analyzepsbt` for diagnostics, but do
not assume third-party tools understand every qbit P2MR field.

## Watch-Only And Offline-Shaped Flow

For qbit's supported watch-only shape, use the P2MR pubkey database workflow:

1. The signer wallet owns private PQC keys and signature counters.
2. The signer exports public receive/change records with `exportpubkeydb`.
3. The online watch wallet imports those records with `importpubkeydb`.
4. The watch wallet creates a PSBT.
5. The signer wallet processes and signs the PSBT.
6. qbit tooling finalizes and broadcasts the transaction.

See [P2MR Watch-Only Pubkey Database Guide](p2mr-pubkeydb.md).

## Multisig And External Signers

A narrow qbit Core `mr(multi_a(...))` P2MR multisig PSBT flow has test
coverage; see [P2MR Multisig](p2mr-multisig.md) for the end-to-end workflow,
including how P2MR partial signatures and leaf data ride in qbit-specific PSBT
fields. Ordinary user funds should still use single-signer P2MR wallets.

Inherited `wsh(sortedmulti(...))`, Miniscript, Taproot, MuSig, and generic
external signer workflows are not ordinary qbit launch-chain wallet guidance.

qbit retains the `-signer=<cmd>` option surface, but external signer workflows
are not public launch-chain wallet guidance until P2MR/PQC signing, address
display, PSBT handling, and signer backup behavior have been validated with
qbit-aware tooling.

## Safety Rules

- Keep P2MR PSBTs with qbit-aware tooling unless another toolchain has been
  validated end to end.
- Do not assume Bitcoin PSBT libraries preserve qbit P2MR proprietary fields.
- Do not use inherited Bitcoin multisig or hardware-wallet tutorials for qbit
  P2MR funds.
- Keep the signing wallet backup current; PSBTs do not replace PQC signature
  counter state.

## Related Docs

- [Wallets, P2MR Addresses, and Backups](p2mr-wallets.md)
- [P2MR Watch-Only Pubkey Database Guide](p2mr-pubkeydb.md)
- [P2MR Multisig](p2mr-multisig.md)
- [Output Descriptors Technical Reference](descriptors.md)
