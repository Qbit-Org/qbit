# P2MR OP_CHECKTEMPLATEVERIFY

qbit implements vanilla `OP_CHECKTEMPLATEVERIFY` for P2MR v1 script-path spends.

## Opcode

qbit assigns CTV to opcode byte `0xbb`.

Bitcoin BIP 119 proposes `OP_NOP4` / `0xb3`, but qbit cannot reuse that byte because `0xb3` is `OP_CHECKSIGPQC`. The `0xbb` byte is taken from the OP_SUCCESS upgrade range and is activated only for P2MR v1 script execution.

## Scope

CTV is active when all of these are true:

- the spend is a native witness v2 P2MR spend;
- the P2MR leaf version is v1 (`0xc0`);
- `SCRIPT_VERIFY_P2MR_RULES` is active.

There is no independent CTV deployment height, activation parameter, or buried deployment. On launch chains where P2MR is active from genesis, CTV is active from genesis as part of P2MR v1 rules.

Outside P2MR v1 execution:

- Taproot-style script execution still treats `0xbb` as OP_SUCCESS.
- Legacy/base and witness v0 script execution do not gain a new bare CTV opcode.
- Bare CTV scriptPubKeys are not made standard by the CTV implementation.

## Stack Semantics

When executed in P2MR v1:

- Empty stack fails with `SCRIPT_ERR_INVALID_STACK_OPERATION`.
- A 32-byte top stack item is compared to the default CTV hash for the spending transaction and current input index.
- A 32-byte mismatch fails with `SCRIPT_ERR_TEMPLATE_MISMATCH`.
- A matching 32-byte argument remains on the stack.
- A non-32-byte argument is a consensus no-op, but is nonstandard under `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`.

Example single-condition leaf:

```text
<ctv_hash> OP_CHECKTEMPLATEVERIFY
```

Example CTV plus P2MR signature leaf:

```text
<ctv_hash> OP_CHECKTEMPLATEVERIFY OP_DROP <pqc_pubkey> OP_CHECKSIGPQC
```

## Default Hash

The default CTV hash is single SHA256 over these fields, in order:

1. transaction version as 4 little-endian bytes;
2. transaction locktime as 4 little-endian bytes;
3. optional single-SHA256 of every input `scriptSig` serialized as `ser_string(scriptSig)`, included only when at least one input has a non-empty `scriptSig`;
4. input count as uint32;
5. single-SHA256 of all input `nSequence` values;
6. output count as uint32;
7. single-SHA256 of all serialized outputs;
8. current input index as uint32.

The hash does not commit to input prevouts, spent amounts, spent scripts, or witness data.

Use `getdefaultctvhash` to compute the node's canonical value:

```bash
qbit-cli getdefaultctvhash "<raw-transaction-hex>" 0
qbit-cli getdefaultctvhash "<raw-transaction-hex>" 0 true
```

Verbose mode returns the committed field breakdown for test-vector and integration debugging. The RPC is intentionally generic; it does not construct application transactions, sign inputs, or accept bridge-specific fields.
