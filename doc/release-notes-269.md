P2MR runtime stack byte limit (policy)
======================================

Default standard policy now limits the bytes held on the main stack plus the
alt-stack while a P2MR script runs to 1 MiB (1,048,576 bytes). P2MR v1 already
limits initial witness items to 16 KiB each and 128 KiB in total, but at
runtime it limited only the number of stack items (1,000). Opcodes that copy
items, such as `OP_DUP`, `OP_PICK` or `OP_2OVER`, could therefore grow a small
witness to about 16 MiB per input during verification.

Unconfirmed transactions that exceed the limit are rejected as nonstandard
with `mempool-script-verify-flag-failed (P2MR stack and altstack bytes exceed
the standard runtime limit)` and are not relayed or mined by default. Scripts
that do not copy large items cannot reach the limit, which is eight times the
128 KiB initial-stack limit. This is not a consensus change: blocks containing
such spends remain valid. See
[P2MR Script Policy Limits](policy/p2mr-script-limits.md).

Known limitation: block validation still accepts up to about 16 MiB of runtime
stack per P2MR input, about 256 MiB held at once with 16 script verification
threads (`-par=16`), until a later release activates a consensus limit.
