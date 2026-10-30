# P2MR Script Policy Limits

The [qbit P2MR v1 Consensus Profile](../consensus/p2mr-v1.md), section 10,
lists the consensus resource limits for a known `0xc0` leaf. Default standard
policy applies those limits and the additional limit below to unconfirmed
transactions. Block validation does not apply it.

| Limit | Value | Classification |
|---|---:|---|
| Main stack plus alt-stack bytes while executing | 1 MiB (1,048,576 bytes) | policy only |

The limit is the sum of the sizes of all items on the main stack and the
alt-stack. It is checked when script execution starts and after every opcode.
It is enforced by the `SCRIPT_VERIFY_P2MR_RUNTIME_STACK_BYTES` script
verification flag, which is part of the standard flags and not part of the
mandatory flags.

A spend that exceeds it fails standard script verification with
`mempool-script-verify-flag-failed (P2MR stack and altstack bytes exceed the
standard runtime limit)` and is rejected as nonstandard. The same spend remains
consensus-valid when it is mined.

Consensus limits stack and alt-stack together to 1,000 items but places no
limit on their bytes during execution. Opcodes such as `OP_DUP`, `OP_2DUP`,
`OP_3DUP`, `OP_OVER`, `OP_2OVER`, `OP_PICK`, `OP_TUCK` and `OP_IFDUP` copy whole
items, so a 16 KiB initial item can be copied up to the item limit, holding
about 16 MiB per input. The policy limit is eight times the 128 KiB aggregate
initial-stack limit, so a script that does not copy large items cannot reach it.

Until a later release activates a consensus limit, block validation still
accepts up to about 16 MiB of runtime stack per input. With the maximum of 16
script verification threads, that is about 256 MiB held at once.

This limit is not part of the P2MR v1 consensus profile. The profile is bound by
the release conformance process, which requires the specification text at the
release tag to match the reviewed specification commit, so policy-only limits
are documented here instead.
