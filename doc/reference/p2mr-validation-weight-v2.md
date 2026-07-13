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

## Block-wide verification bound

For a block with `I` P2MR inputs, let `W` be the sum of their serialized
witness-stack sizes. Qbit does not discount witness data
(`WITNESS_SCALE_FACTOR` is 1), and every transaction input uses at least 41
bytes outside that stack: a 36-byte outpoint, a one-byte empty `scriptSig`
length, and a four-byte sequence. The 2,000,000-weight block limit therefore
implies:

```
W + 41I <= 2,000,000
I <= floor(2,000,000 / 41) = 48,780
```

The sum `B` of the inputs' initial validation budgets is `W + 50I`, so:

```
B <= 2,000,000 + (50 - 41) * 48,780 = 2,439,020
```

Validation budget is local to each input. Summing those budgets and ignoring
unusable per-input remainders can only overestimate the number of successful
PQC checks, giving these conservative block-wide ceilings:

| Rule | Debit per non-empty PQC signature operation | Conservative ceiling |
| --- | ---: | ---: |
| Legacy | 3,730 | `floor(2,439,020 / 3,730) = 653` |
| v2 | 3,683 | `floor(2,439,020 / 3,683) = 662` |

Validation-weight v2 raises this conservative ceiling by nine checks. Actual
blocks cannot attain these ceilings: the derivation gives all block weight to
the selected inputs, reserves none for block and transaction framing, outputs,
or required P2MR leaf scripts and control blocks, and ignores validation budget
stranded in individual inputs. Those omissions all make the attainable count
lower.

The [maintained bounded-SLH-DSA benchmark](../../src/libbitcoinpqc/benches/REPORT.md)
sets a target of at most 0.5 ms per verification. At that target the legacy and
v2 ceilings represent 326.5 ms and 331.0 ms of serial PQC verification,
respectively, a 4.5 ms increase. The current checked-in Apple M3 Max result is
0.614708 ms per verification, which maps to approximately 401.4 ms, 406.9 ms,
and a 5.5 ms increase. The v2 figure is about 0.68% of qbit's 60-second
aggregate target block interval. The percentage uses current chain parameters;
the benchmark report's generic impact scenario still assumes 30-second blocks.
These products estimate only the raw, single-threaded signature-verification
component on the measured host; they are not a total block-validation-time
guarantee.

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
