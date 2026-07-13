# P2MR data-hash signing

`signdatapqchash` and `verifydatapqchash` provide qbit-native signing for
caller-supplied 32-byte data hashes with PQC keys committed by P2MR addresses.
They do not extend legacy `signmessage`/`verifymessage`; those RPCs are
ECDSA compact-recovery interfaces and do not apply to P2MR/PQC keys.

## Scope

The initial proof mode is `p2mr-pubkey`.

In this mode, the wallet signs a 32-byte `message_hash` with a local PQC key
from a committed P2MR single-key leaf:

```text
<pubkey> OP_CHECKSIGPQC
```

The data signature itself is verified over:

```text
ComputeQbitDataSigPQCHash(message_hash)
```

That function applies the `QbitDataSigPQC` tagged-hash domain. The 32-byte RPC
argument is not a limit on the original data size; callers sign arbitrary data
by hashing it first under their own application or protocol domain and passing
that digest to qbit.

## Wallet Signing Flow

`signdatapqchash "address" "message_hash" ( options )` is a wallet RPC.

The RPC:

1. decodes `address` and requires a `WitnessV2P2MR` destination,
2. parses `message_hash` as exactly 32 bytes,
3. locates wallet-owned P2MR spend data for the address,
4. selects a committed P2MR v1 `<pubkey> OP_CHECKSIGPQC` leaf,
5. optionally constrains selection by `pubkey`, `leaf_script`, and
   `control_block`,
6. recomputes the leaf hash and P2MR Merkle root to confirm the proof path,
7. signs `ComputeQbitDataSigPQCHash(message_hash)` through the wallet signing
   provider, and
8. returns the signature plus enough proof material for stateless verification.

Signing uses the same wallet PQC signing provider path as transaction signing,
so stateful PQC signature counters advance. The RPC omits wallet-local PQC usage
fields by default, keeping its result bounded and portable. Set
`include_pqc_usage=true` to include those fields for local diagnostics. They can
reveal exact remaining signature budgets and public keys from failed signing
attempts when the wallet retries a later P2MR leaf.

The RPC response includes:

- `address`
- `message_hash`
- `datasig_hash`
- `domain`
- `algorithm`
- `proof_mode`
- `pubkey`
- `signature`
- `leaf_version`
- `leaf_script`
- `control_block`
- `p2mr_merkle_root`
- optional PQC usage fields

`datasig_hash`, `domain`, `algorithm`, and `p2mr_merkle_root` are informational
RPC result fields. Verification recomputes the data-signature hash and P2MR
Merkle root instead of trusting them.

## Portable Proof Schema

A portable `p2mr-pubkey` proof contains only the fields required for stateless
verification:

- `address`
- `message_hash`
- `signature`
- `pubkey`
- `leaf_script`
- `control_block`
- `leaf_version`
- `proof_mode`

qbit-qt displays and copies this minimal schema. PQC usage data remains local:
after every signing attempt that advances a counter, the signer status shows
the overall usage state and each affected key's exact count, remaining budget,
and limit state, followed by any threshold or reminder warnings. This reporting
also applies when signing ultimately fails after one or more committed counter
reservations; no portable proof is produced on failure. Counts, limits,
warnings, and keys observed during retry attempts are not part of the proof
JSON. Proofs created by older qbit-qt versions can contain those additional
fields. Qt accepts them when the complete proof document is at most 32,768
characters, while RPC verification continues to accept them. For larger legacy
exports, remove wallet-local usage fields before importing the proof into
qbit-qt.

## Verification Flow

`verifydatapqchash "p2mr_proof"` is a non-wallet utility RPC.

The proof must include the portable proof fields:

- `address`
- `message_hash`
- `signature`
- `pubkey`
- `leaf_script`
- `control_block`
- `leaf_version`
- `proof_mode`

The verifier:

1. requires `proof_mode == "p2mr-pubkey"`,
2. decodes `address` and requires a P2MR destination,
3. parses `message_hash`, `signature`, and `pubkey` at their consensus sizes,
4. requires `leaf_script` to match `<pubkey> OP_CHECKSIGPQC`,
5. requires P2MR v1 leaf version,
6. validates the control block shape, low-bit marker, and leaf-version mask,
7. recomputes `ComputeP2MRLeafHash(leaf_version, leaf_script)`,
8. recomputes `ComputeP2MRMerkleRoot(control_block, leaf_hash)` and compares it
   with the address Merkle root, and
9. verifies the PQC signature over `ComputeQbitDataSigPQCHash(message_hash)`.

Malformed inputs throw RPC errors. Cryptographic or proof mismatches return:

```json
{"valid": false, "error": "..."}
```

Valid proofs return:

```json
{
  "valid": true,
  "address": "...",
  "message_hash": "...",
  "datasig_hash": "...",
  "pubkey": "...",
  "proof_mode": "p2mr-pubkey",
  "p2mr_merkle_root": "..."
}
```

## Relationship To `OP_CHECKDATASIGPQC`

`OP_CHECKDATASIGPQC` verifies the same `QbitDataSigPQC` data-signature domain.
The implemented RPC proof mode deliberately binds the pubkey through the
existing default wallet P2MR pubkey leaf, because default wallets already create
and track those addresses.

A signature returned by `signdatapqchash` can also satisfy a P2MR script that
uses the matching pubkey with a witness-supplied message hash:

```text
Witness: <signature> <message_hash>
Script:  <pubkey> OP_CHECKDATASIGPQC
```

Descriptor support for first-class reusable data-signing leaves can be added in
a later change without changing the `QbitDataSigPQC` signature domain.
