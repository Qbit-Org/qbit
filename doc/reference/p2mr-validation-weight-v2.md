# P2MR validation-weight v2

P2MR validation-weight v2 aligns the validation debit for a successful PQC
signature operation with the marginal serialized witness size of a default
SLH-DSA-SHA2-128s-bounded30 signature.

The original qbit P2MR rule debits 3,730 validation units for every non-empty
PQC signature operation. Validation-weight v2 debits 3,683 units, equal to the
3,680-byte signature plus its three-byte CompactSize length. The per-input
validation budget remains the serialized input witness size plus 50 units.
The rule applies equally to transaction-signature and data-signature P2MR
opcodes.

## Network activation

| Network | First v2 block |
| --- | ---: |
| main | 0 |
| testnet4 | 60,000 |
| test, signet, regtest | 0 |

Regtest may override the height with
`-testactivationheight=p2mrweightv2@<height>`.

For testnet4, blocks below height 60,000 retain the 3,730-unit rule. Blocks at
height 60,000 and above use 3,683. This is a consensus relaxation, so testnet4
miners and validating nodes must upgrade before activation. The activation
does not change the testnet4 genesis block, network identity, or validity of
the pre-activation chain.

## Descriptor resource boundary

The 128 KiB P2MR v1 initial-stack limit is unchanged. A supported signature
item may contain a 3,680-byte signature plus a one-byte non-default sighash
type, so a canonical `multi_a` satisfaction can contain at most 35 non-empty
signatures. Wallet and descriptor tooling must not activate a descriptor tree
unless it has at least one wallet-constructible leaf within that limit.

## Operator observability

`getblockchaininfo` reports the legacy and v2 debits, activation height,
current and next-block state, and blocks remaining under
`p2mr_validation_weight`.
`getblocktemplate` and `createauxblock` include the debit, activation state,
and activation height that apply to the returned mining candidate under the
same key.
