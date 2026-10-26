# qbit P2MR v1 Consensus Profile

| Field | Value |
|---|---|
| Profile name | qbit P2MR v1 |
| Profile identifier | `qbit-p2mr-v1` |
| Specification version | 1 |
| Status | Pre-genesis frozen profile |
| Initial reference implementation | `988756471aeecdf4463c04be49da2b7b89a98c21` |
| Ancestry reference | BIP-360 v0.12.0 at `6740c533e8dce4e912f17ee85a6f627644e1b783` |

> **Compatibility warning:** qbit P2MR v1 is not BIP-360 compatible. The
> ancestry reference explains design history only. Its hash domains,
> depth-zero behavior, opcode assignments, and other rules must not be used to
> validate qbit P2MR v1.

This document specifies the consensus behavior of the initial reference
commit. **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as defined in
RFC 2119. A specification revision cannot redefine version 1 behavior: changing
which transactions version 1 accepts requires a separately reviewed consensus
decision and a new or explicitly amended profile contract.

## 1. Terminology and byte conventions

Byte strings are written in hex in byte order, two lowercase characters per
byte, with no implied integer byte reversal. Concatenation is written `||`.

Fixed-width integers are signed or unsigned little-endian at the stated width,
as in inherited qbit transaction serialization. A `uint256` hash serializes as
its 32 committed bytes. An outpoint serializes as its 32-byte transaction
identifier followed by a 4-byte little-endian output index.

`CompactSize(x)` is the canonical variable-length unsigned-integer encoding:

| Range | Encoding |
|---|---|
| `0..252` | the value as one byte |
| `253..65535` | `0xfd` followed by 2-byte little-endian value |
| `65536..4294967295` | `0xfe` followed by 4-byte little-endian value |
| larger values | `0xff` followed by 8-byte little-endian value |

Encoding a value with a longer form than its row requires is non-canonical. A
serialized byte vector is `CompactSize(length) || bytes`.

Tagged hashing, for an ASCII `tag` and byte string `msg`, is:

```text
TaggedHash(tag, msg) =
    SHA256(SHA256(tag) || SHA256(tag) || msg)
```

Branch children are sorted by lexicographic comparison of their 32 raw bytes,
not by displayed hash text or integer value.

Terms:

- *Witness program*: the 32-byte payload in the funding output.
- *Native v2/32 program*: a native (non-P2SH) witness version 2 program of
  exactly 32 bytes.
- *Leaf script*: the script revealed by the spending witness.
- *Control block*: one control byte followed by zero or more 32-byte Merkle
  path nodes.
- *Merkle path*: the path nodes, listing siblings from the leaf upward.
- *Annex*: the optional final witness element identified in section 3.
- *Initial stack*: the witness elements remaining, in order, after the
  optional annex, control block, and leaf script are removed.

Witness elements are listed in serialized order, first to last. The last
element is examined first for an annex and then, after any annex removal, as the
control block. Stack order is preserved: the last initial-stack element is the
top of the stack.

## 2. Activation and output recognition

qbit P2MR v1 applies only when all of the following are true:

1. witness verification is enabled;
2. the output is a native, non-P2SH witness version 2 program;
3. the witness program is exactly 32 bytes; and
4. `SCRIPT_VERIFY_P2MR_RULES` is active.

`GetBlockScriptFlags()` adds `SCRIPT_VERIFY_P2MR_RULES` for blocks at height
`Consensus::Params::P2MRHeight` or above. Before activation, a native v2/32
program follows inherited forward-compatible witness behavior and succeeds
without applying this profile.

`SCRIPT_VERIFY_P2MR_RULES` is also a mandatory mempool flag, so mempool
admission applies qbit P2MR v1 to native v2/32 spends even on a test chain
configured with a later block activation height. Standard flags additionally
enforce the policy distinctions in section 11.

Public launch chains activate P2MR at height 0. Regtest also defaults to 0, but
`-testactivationheight=p2mr@<height>` MAY override it for activation testing.
The option is regtest-only; the height must be non-negative and below the
maximum signed integer.

P2SH wrapping MUST NOT activate qbit P2MR v1. A P2SH-wrapped v2/32 witness
program is outside this profile even when its inner bytes have the native
shape.

Restricted-output mode is a separate funding-output rule that accepts a native
v2/32 output by its outer shape. The 32-byte payload is opaque at output
creation: it does not reveal whether its creator used the
`P2MRLeaf`/`P2MRBranch` domains, another domain, a known script, or no
spendable construction. Spend validation establishes the commitment later.
The mode also permits its explicitly configured `OP_RETURN`, PayToAnchor, and
activated reserved-outer-witness exemptions; those outputs are not P2MR.

## 3. Witness and annex parsing

Once P2MR rules are active, an empty witness MUST fail with
`WITNESS_PROGRAM_WITNESS_EMPTY`. Parsing then proceeds in this order:

1. If at least two witness elements exist and the last element is non-empty
   with first byte `0x50`, remove that last element as the annex.
2. When an annex is present, compute
   `annex_hash = SHA256(CompactSize(len(annex)) || annex)`.
3. Require at least two elements after optional annex removal. Otherwise fail
   with `WITNESS_PROGRAM_WITNESS_EMPTY`.
4. Pop the final remaining element as the control block.
5. Pop the new final element as the leaf script.
6. Treat all remaining elements, in their existing order, as the initial
   stack.

Signatures commit to the annex through `annex_hash`. The annex is not executed
and is not part of the initial stack. A one-element witness beginning with
`0x50` has no annex, because annex recognition requires at least two elements.

Validation fails at the first failing stage, in this order:

| Stage | Failure condition |
|---|---|
| Witness presence | no witness, or fewer than two elements after annex removal |
| Control shape | length is not `1 + 32*m` for `0 <= m <= 128` |
| Control marker | control-byte bit 0 is not set |
| Commitment | computed Merkle root differs from the witness program |
| Initial resources | known-v1 initial stack exceeds section 10 limits |
| Script | parsing, opcode, signature, lock, conditional, or validation-weight error |
| Clean stack | execution leaves other than exactly one main-stack item |
| Truth | the sole final item casts to false |

## 4. Control blocks and leaf versions

A control block MUST have length `1 + 32*m` for an integer `m` from 0 through
128 inclusive, so at most 4097 bytes. Bit 0 of the first byte MUST be 1. The
committed leaf version is:

```text
leaf_version = control[0] & 0xfe
```

The even version assignments are:

| Version or range | Classification |
|---|---|
| `0xc0` | active qbit P2MR v1 script semantics |
| `0xc2..0xde` | production-reserved, even values only |
| `0xe0..0xee` | staged-signature-system, even values only |
| `0xf0..0xfc` | experimental or deployment staging, even values only |
| `0xfe` | extension-envelope reserved version |

These labels reserve namespaces without assigning executable semantics. Once
the control marker and commitment validate, every leaf version other than
`0xc0` succeeds under consensus without executing its script. Standard policy
rejects these upgradable leaf versions through
`SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`.

## 5. Commitment construction

For the committed even leaf version and exact leaf-script bytes:

```text
leaf_hash = TaggedHash(
    "P2MRLeaf",
    leaf_version || CompactSize(script_length) || script
)

branch_hash(a, b) = TaggedHash(
    "P2MRBranch",
    min_lex(a, b) || max_lex(a, b)
)
```

Start with `root = leaf_hash`. For each 32-byte path node in the control
block, in order after the control byte, set `root = branch_hash(root, node)`.
The final `root` MUST equal the 32-byte witness program byte for byte.

There is no internal key, x-only key, parity adjustment, or output-key tweak.
Only the masked leaf version of the control byte enters the root, via the leaf
hash.

### Non-normative cross-profile illustration

For leaf version `0xc0` and the one-byte script `00` (`OP_0`), the tagged-hash
message is `c00100`. The two tags produce different roots:

```text
TapLeaf:  e7e4d593fcb72926eedbe0d1e311f41acd6f6ef161dcba081a75168ec4dcd379
P2MRLeaf: fae97225114b26d9ef3e3bea70f90d08fec30d9833c50b23e4a6cf8c33e6b200
```

The first value belongs only to the pinned ancestry comparison; qbit P2MR v1
uses the second.

## 6. Depth-zero behavior

`m = 0` does not bypass script execution. The one-byte control block `c1`
commits a `0xc0` leaf with no sibling nodes; once the root comparison succeeds,
qbit MUST execute the leaf script.

For example, a v2 witness program equal to the qbit `P2MRLeaf` root above,
spent with witness `[00, c1]`, passes commitment validation, executes `OP_0`,
and fails with `EVAL_FALSE`.

BIP-360 v0.12.0 at the pinned ancestry commit instead returns success for the
matching depth-zero construction without executing the leaf. qbit P2MR v1 does
not.

## 7. Transaction signature message and encoding

### Hash-type values

The only accepted hash-type bytes are:

| Byte | Meaning |
|---|---|
| `0x00` | `SIGHASH_DEFAULT` (same output selection as `SIGHASH_ALL`) |
| `0x01` | `SIGHASH_ALL` |
| `0x02` | `SIGHASH_NONE` |
| `0x03` | `SIGHASH_SINGLE` |
| `0x81` | `SIGHASH_ALL \| SIGHASH_ANYONECANPAY` |
| `0x82` | `SIGHASH_NONE \| SIGHASH_ANYONECANPAY` |
| `0x83` | `SIGHASH_SINGLE \| SIGHASH_ANYONECANPAY` |

All other values MUST fail with `P2MR_SIG_HASHTYPE`. `SIGHASH_SINGLE` on an
input with no output at the same index MUST fail before a digest is defined;
qbit P2MR v1 does not use the legacy `uint256::ONE` result.

### Component hashes

Component hashes are single SHA256:

```text
sha_prevouts       = SHA256(outpoint_0 || ... || outpoint_n)
sha_amounts        = SHA256(amount_0 || ... || amount_n)
sha_scriptpubkeys  = SHA256(ser_script_0 || ... || ser_script_n)
sha_sequences      = SHA256(sequence_0 || ... || sequence_n)
sha_outputs        = SHA256(txout_0 || ... || txout_n)
```

Outpoints are serialized as in section 1 (36 bytes). Amounts are signed 8-byte
little-endian and sequences are 4-byte little-endian. `ser_script` is a
CompactSize length followed by the exact scriptPubKey bytes. A serialized
output is its amount followed by `ser_script`.

When applicable:

```text
sha_annex         = SHA256(CompactSize(len(annex)) || annex)
sha_single_output = SHA256(serialized_output_at_input_index)
```

### Message layout

The signature message is the concatenation below, with fixed-width integers
little-endian:

```text
0x00                                      # epoch
hash_type                                 # one byte
transaction_version                       # int32
transaction_lock_time                     # uint32

[if not ANYONECANPAY]
    sha_prevouts                           # 32 bytes
    sha_amounts                            # 32 bytes
    sha_scriptpubkeys                      # 32 bytes
    sha_sequences                          # 32 bytes

[if output mode is ALL, including DEFAULT]
    sha_outputs                            # 32 bytes

spend_type                                # one byte: 0x02, or 0x03 with annex

[if ANYONECANPAY]
    current_outpoint                       # 36 bytes
    current_spent_output                   # amount || serialized scriptPubKey
    current_sequence                       # uint32
[otherwise]
    input_index                            # uint32

[if annex present]
    sha_annex                              # 32 bytes

[if output mode is SINGLE]
    sha_single_output                      # 32 bytes

p2mr_leaf_hash                            # 32 bytes
0x00                                      # key version
last_executed_codeseparator_position      # uint32
```

With extension flag 1, `spend_type = (1 << 1) + annex_present`: `0x02`
without an annex, `0x03` with one. The code-separator position is the
zero-based opcode position of the last executed `OP_CODESEPARATOR`, or
`0xffffffff` if none has executed.

The signature digest is:

```text
TaggedHash("P2MRSighash", serialized_signature_message)
```

### Witness signature encoding

qbit P2MR v1 has **no on-witness algorithm-selection byte**; the active
`0xc0` leaf and opcode semantics select the algorithm. Transaction-signature
opcodes accept two nonempty forms:

- exactly 3,680 raw signature bytes, meaning `SIGHASH_DEFAULT`; or
- 3,680 raw signature bytes followed by one nonzero hash-type byte from the
  table above.

A 3,681-byte value ending in `0x00` is invalid. A trailing `0x01` means
`SIGHASH_ALL`, not an algorithm identifier.

An empty signature with a valid 32-byte public key is a permitted unsuccessful
check: it incurs no signature charge and pushes false (or adds zero). It is not
a valid signature encoding.

## 8. P2MR v1 script language

The interpreter decodes bytecode exactly as listed below. Direct pushes
`0x01..0x4b` push that many following bytes; `OP_PUSHDATA1` through
`OP_PUSHDATA4` use 1-, 2-, or 4-byte little-endian lengths. Unless the
OP_SUCCESS short circuit below applies, a pushed literal MUST NOT exceed 520
bytes, even though initial witness items may be larger.

| Bytes | Opcode category and qbit P2MR v1 behavior |
|---|---|
| `00`, `01..4b`, `4c..4e`, `4f`, `51..60` | empty/data pushes, `PUSHDATA`, `1NEGATE`, and integers 1..16 |
| `61` | `NOP` |
| `63..64`, `67..69`, `6a` | `IF`, `NOTIF`, `ELSE`, `ENDIF`, `VERIFY`, `RETURN`; IF inputs MUST be empty or exactly `01` |
| `6b..7d`, `82` | inherited alt-stack, stack-manipulation, and `SIZE` operations |
| `87..88` | `EQUAL`, `EQUALVERIFY` |
| `8b..8c`, `8f..94`, `9a..a5` | inherited active numeric and comparison operations; numeric operands normally use at most 4 bytes |
| `a6..aa` | `RIPEMD160`, `SHA1`, `SHA256`, `HASH160`, `HASH256` |
| `ab` | `CODESEPARATOR`; updates the committed opcode position |
| `ac..ad` | legacy `CHECKSIG` and `CHECKSIGVERIFY`; fail in P2MR with `P2MR_CHECKSIG` |
| `ae..af` | `CHECKMULTISIG` and `CHECKMULTISIGVERIFY`; invalid in P2MR |
| `b0`, `b4..b9` | upgrade NOPs; consensus NOP, discouraged by standard policy when executed |
| `b1` | `CHECKLOCKTIMEVERIFY` |
| `b2` | `CHECKSEQUENCEVERIFY` |
| `b3` | `CHECKSIGPQC`: `(sig pubkey -- bool)` using sections 7 and 9 |
| `ba` | `CHECKSIGADD`: `(sig num pubkey -- num + success)` using PQC verification in P2MR |
| `bb` | `CHECKTEMPLATEVERIFY`; checks a 32-byte top item against qbit's default template hash; other sizes are consensus no-ops and policy-discouraged |
| `bc` | `CHECKDATASIGPQC`: `(sig msg_hash pubkey -- bool)` |
| `bd` | `CHECKDATASIGADDPQC`: `(sig msg_hash num pubkey -- num + success)` |

These bytes are OP_SUCCESS under qbit P2MR v1:

```text
50, 62, 7e..81, 83..86, 89..8a, 8d..8e, 95..99,
be..fe
```

`bb`, `bc`, and `bd` fall in the inherited `bb..fe` success range, but qbit
removes them from OP_SUCCESS in P2MR and executes them as above.

Script pre-scan decodes the script before execution:

- A malformed instruction reached before any OP_SUCCESS fails.
- A well-formed oversized push is not rejected by pre-scan, which neither
  materializes nor executes pushes.
- Decoding an OP_SUCCESS opcode makes consensus validation succeed
  immediately, overriding script-execution, pushed-literal, runtime-stack,
  script-size, disabled-opcode, and final-stack checks.
- OP_SUCCESS does not bypass witness parsing, control/commitment validation,
  or the initial-stack limits, all of which run before pre-scan.

Standard policy rejects OP_SUCCESS through
`SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`.

`7e..81`, `83..86`, `8d..8e`, and `95..99` are the legacy-disabled splice,
bitwise, multiplication, division, modulo, and shift opcodes. They MUST remain
disabled in legacy script contexts. In P2MR these bytes are deliberately
OP_SUCCESS, not active forms of the legacy operations.

Any byte not decoded by the table or the OP_SUCCESS set is a bad opcode; in
particular `VERIF` (`65`), `VERNOTIF` (`66`), and `ff`. Stack plus alt-stack
MUST never exceed 1,000 items. P2MR v1 has no 201-opcode limit and no
10,000-byte script-size limit; the other limits in section 10 apply.

The data-signature opcodes require a 32-byte `msg_hash`, a 32-byte public key,
and an empty or exactly 3,680-byte signature. They verify
`TaggedHash("QbitDataSigPQC", msg_hash)` and do not commit to the spending
transaction unless the leaf separately enforces such a commitment. A nonempty
malformed or invalid data signature fails the script; an empty one pushes false
(or adds zero).

## 9. PQC verification profile

The active `0xc0` leaf and opcode semantics select exactly one verification
profile:

| Property | qbit P2MR v1 value |
|---|---|
| Profile | `SLH-DSA-SHA2-128s-bounded30` |
| Public key | 32 bytes |
| Signature | 3,680 bytes |
| Verification message | 32-byte digest |
| Maximum signing-usage contract | `2^30` signatures per key |

Consensus verification calls the fixed single-profile library. There is no
runtime, public-key, signature, or witness algorithm selector. A public key of
any size other than 32 bytes fails. Section 7 defines the transaction-signature
digest and optional sighash suffix; section 8 defines the separate
data-signature digest and forbids a sighash suffix.

qbit wallet signing counters enforce the `2^30` contract operationally.
Secret-key serialization, seed derivation, counter persistence, reservation,
backup, and wallet refusal are wallet-safety rules, not script-verification
inputs.
Consensus verifiers receive only the public key, digest, and signature, and
consult no usage counter.

## 10. Resource limits and final result

For a known `0xc0` leaf, after annex, script, and control removal:

| Limit | Value | Classification |
|---|---:|---|
| Initial stack items | 1,000 | consensus and policy |
| Each initial item | 16 KiB | consensus and policy |
| Aggregate initial-item bytes | 128 KiB | consensus and policy |
| Main stack plus alt-stack while executing | 1,000 items | consensus |
| Literal pushed by script bytecode when OP_SUCCESS does not short circuit | 520 bytes | consensus |
| Validation-weight initial value | serialized full witness size + 50 | consensus |
| Charge for each nonempty PQC signature attempt | 3,683 | consensus |
| Standard transaction weight | 400,000 | policy |
| Maximum block weight | 2,000,000 | consensus |
| Maximum serialized block size | 2,000,000 bytes | consensus buffer/size rule |
| Witness scale factor | 1 | consensus serialization weight |

The serialized full witness size includes the element count and every length
prefix and element, including annex, script, and control block. Each nonempty
`CHECKSIGPQC`, P2MR `CHECKSIGADD`, `CHECKDATASIGPQC`, or `CHECKDATASIGADDPQC`
attempt subtracts 3,683 before deeper signature validation; a negative
remainder fails.

Compared with legacy script limits:

- **Replaced:** the generic 520-byte limit on *initial witness stack items*,
  by the 16 KiB per-item and 128 KiB aggregate limits.
- **Removed:** the 10,000-byte script-size and 201-opcode-count limits.
- **Kept**, unless the OP_SUCCESS short circuit applies: the 520-byte limit on
  literals pushed by the script, the 1,000-item combined runtime stack limit,
  conditional correctness, numeric encoding rules, validation weight, and
  transaction/block limits.

OP_SUCCESS has only the exceptions in section 8 and cannot bypass the
initial-stack limits, which are checked before pre-scan.

Successful execution MUST leave exactly one main-stack item, and it MUST cast
to true. Extra items fail `CLEANSTACK`; an empty or false sole item fails
`EVAL_FALSE`. With witness scale factor 1, witness bytes, including large PQC
signatures, receive no weight discount.

Consensus has no transaction-weight ceiling below the block limits; a
transaction must fit in a valid block. Default standard policy applies the
400,000 transaction-weight limit.

## 11. Consensus, policy, and wallet behavior

Policy means the default standard mempool and mining rules, not block
consensus. Wallet support is narrower still.

| Construction | Consensus | Policy | Wallet |
|---|---|---|---|
| Native v2/32, `0xc0`, no annex, active opcodes, within all limits, true clean result | Valid | Standard, subject to ordinary transaction policy | Depends on the descriptor/script form |
| Annex present | Valid; signatures commit to it | Nonstandard: witness policy rejects annexes | Not used by ordinary construction |
| Reserved or otherwise unknown committed leaf version | Valid after marker and commitment checks; script not executed | Nonstandard: upgradable-leaf policy | Signing/finalization refuses it |
| Non-exception OP_SUCCESS byte | Immediate success | Nonstandard: discourage-OP_SUCCESS policy | Not a supported spending construction |
| `OP_CHECKTEMPLATEVERIFY` with non-32-byte top item | No-op | Nonstandard: discourage-OP_SUCCESS policy | — |
| P2SH-wrapped v2/32 witness program | Never qbit P2MR v1. Unrestricted chain: inherited unknown-witness behavior. Restricted-output mode: the outer P2SH output cannot be funded | Nonstandard | — |
| Native unknown witness version other than the assigned v2/32 | Outside this profile; forward-compatible success. Restricted-output mode permits funding reserved v3..v16 only after its separate outer-witness activation | Normally nonstandard | — |
| Empty/insufficient witness, malformed control, marker bit clear, or commitment mismatch | Invalid | — | — |
| Known `0xc0` leaf over an initial-stack or runtime resource limit | Invalid | Same initial-stack bounds | — |
| Known `0xc0` leaf with script error, extra final items, or false result | Invalid | — | — |
| Restricted-output native v2/32 funding output with arbitrary 32 bytes | Accepted by restricted-output shape rules; spendability not proven | — | `rawmr()` and unknown roots are expert-only and generally unsupported |
| Restricted-output `OP_RETURN`, PayToAnchor, or activated reserved outer witness output | May be an allowed funding exemption; not qbit P2MR v1 | Own treatment | Own treatment |

## 12. Conformance and change control

`src/test/data/p2mr_v1_manifest.json` is the authoritative inventory of the
versioned qbit P2MR v1 corpus. It binds exact fixture bytes, case counts, the
initial reference implementation, and the pinned ancestry comparison. The qbit
unit suites and the standalone oracle under `contrib/testgen/p2mr_v1_oracle/`
consume that corpus independently.

Release conformance is stricter than a passing development-branch test. The
release validator binds the manifest, every listed corpus file, the canonical
oracle report, the qbit test result, the consensus review, and the finalized
integration inventory to the exact signed tag target. The public
[integration support matrix](../integration/p2mr-v1-support-matrix.md) is the
human-readable view of that inventory; its checked-in `draft` status is not
release evidence and cannot satisfy the mainnet publication gate.

A release claiming `qbit-p2mr-v1` conformance MUST identify its exact reviewed
source commit, specification version, corpus manifest digest, qbit result,
independent oracle report digest, and integration inventory digest. Any
contradiction between implementation and specification MUST be recorded and
reviewed, and MUST NOT be resolved by silently changing version 1 transaction
validity.

## Ancestry reference

The non-normative ancestor used for historical comparison is
[BIP-360 v0.12.0 at commit
`6740c533e8dce4e912f17ee85a6f627644e1b783`](https://github.com/bitcoin/bips/blob/6740c533e8dce4e912f17ee85a6f627644e1b783/bip-0360.mediawiki).
No floating branch of that document is a normative dependency of this profile.
