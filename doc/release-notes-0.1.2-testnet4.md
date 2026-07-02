Qbit v0.1.2-testnet4 Release Notes
===================================

Qbit: Post-quantum peer to peer digital value

Qbit version v0.1.2-testnet4 is available from the release page for that
version.

This is a public testnet4 maintenance release based on the changes since
v0.1.1-testnet4. It preserves the reset testnet4 lineage from v0.1.0 and
focuses on AuxPoW mining compatibility, P2MR wallet and Qt signing behavior,
witness-pruned startup safety, P2MR/PQC script and data-signature coverage,
release/CI hardening, and public testnet operator documentation.

Testnet-era release artifacts are for public testnet use only unless the
release page explicitly says otherwise. Qbit mainnet is not launched. Do not
treat any in-tree mainnet genesis block, hash, seed placeholder, or endpoint
placeholder as an official mainnet launch commitment.

Testnet coins have no economic value, and the public testnet may be reset or
replaced during rehearsal.

Please report bugs using the Qbit issue tracker.

How to Upgrade
==============

Shut down the older qbit process first and wait until it exits completely.
Then install the new binaries from the GitHub Release page.

This release does not require a testnet4 chain reset for nodes upgrading from
v0.1.1-testnet4.

On Linux, replace the existing `qbitd`, `qbit-cli`, `qbit-tx`, `qbit-util`,
and `qbit-wallet` binaries with the new versions.

On macOS, replace the installed Qbit application bundle or unpack the updated
archive into the desired location.

On Windows, run the installer if one is provided for the release, or replace
the unpacked binaries with the new release artifacts.

Compatibility
=============

The public Qbit testnet4 chain is selected with:

```bash
qbitd -testnet4
qbit-cli -testnet4 getblockchaininfo
```

Official testnet release binaries are expected to reject no-flag mainnet
startup and explicit `-chain=main` startup. Use `-testnet4` or
`-chain=testnet4` for the public testnet.

Supported and tested platforms for this release are the artifacts attached to
the GitHub Release page. The release page is the source of truth for available
platform builds, checksums, signatures, and attestations.

Public testnet4 network identity remains the v0.1.0-testnet4 reset testnet4
identity unless the release page explicitly says otherwise.

There are no scheduled consensus activation changes in v0.1.2-testnet4.
Mining pools, exchanges, explorers, wallets, and other testnet4 operators can
upgrade without a chain reset.

| Item | Value |
|---|---|
| Chain flag | `-testnet4` or `-chain=testnet4` |
| Default P2P port | `48355` |
| Default RPC/REST port | `48352` |
| Address HRP | `tq` |
| AuxPoW chain ID | `31430` |

Notable changes
===============

### Consensus, mining, and node operation

- `submitauxblock` now accepts legacy Dogecoin-style AuxPoW payloads that
  include the extra parent-block hash field, normalizes them into qbit's
  canonical AuxPoW layout, and validates/stores the canonical form.
- Permissionless `getblocktemplate` responses now sanitize regtest
  `-blockversion` overrides that accidentally set the AuxPoW signalling flag.
  Permissionless templates remain canonical with `chain_id=0`, `auxpow=false`,
  and preserved low versionbits.
- The mining pool quickstart now documents the `commitmentorder` and
  `commitmentactivationheight` fields returned by `createauxblock`, and tells
  pool software to follow the node-returned commitment order instead of
  Namecoin, Dogecoin, or serializer assumptions.
- Witness-pruned `-reindex-chainstate` startup now validates the supplied
  `-assumevalid` hash before any local chainstate or snapshot chainstate wipe
  can run. Null, unknown, off-best-header-chain, insufficient-work, and too-low
  hashes fail before destructive startup paths.

### Wallet, RPC, and PQC signing

- Qt Sign/Verify is enabled again on P2MR-only chains, with P2MR data-proof
  labels instead of legacy message-signing labels.
- Qt Sign/Verify can sign UTF-8 text after hashing it, or sign raw 32-byte
  hashes directly, with wallet-owned P2MR/PQC keys. It emits proof JSON
  compatible with `signdatapqchash`.
- Qt Sign/Verify can verify pasted P2MR/PQC proof JSON compatible with
  `verifydatapqchash`.
- Qt signing locally verifies generated proofs before displaying them and shows
  PQC signature-budget state after signing.
- P2MR data-proof verification is shared between the Qt verifier and the
  `verifydatapqchash` RPC path.
- Wallet-backed PQC data-hash signing now treats persisted counter
  reservations as consumed once the reservation succeeds, even if the later raw
  signing operation fails.
- `signdatapqchash` reports and logs consumed PQC counter ranges for
  data-hash signing attempts that fail after a reservation has already been
  persisted.
- P2MR data-hash signing now distinguishes exhausted PQC signature budgets from
  missing private keys when a selected leaf cannot be signed.
- Provider, wallet unit, and functional RPC coverage now exercise successful
  and failing PQC data-hash signing counter paths.
- New qbit-qt wallets now default to encrypted creation for ordinary private-key
  wallets. The Create Wallet dialog labels encryption as recommended and
  explains that encryption protects private keys while enabling authenticated
  wallet loads that avoid repeated plaintext PQC key validation.
- P2MR `getnewaddress` and `MarkUnusedAddresses` flows avoid full synchronous
  keypool top-ups when ranged P2MR descriptors remain above the low watermark.
  They schedule bounded low-watermark refills while preserving exhaustion,
  locked-wallet, recovery, and rescan behavior.
- Explicit wallet output types must now be both chain-allowed and backed by a
  matching wallet manager on P2MR-only chains.
- `fundrawtransaction` now rejects prebuilt raw outputs that are not allowed in
  restricted-output mode before wallet funding. P2MR, `OP_RETURN`, and
  PayToAnchor outputs remain accepted where policy permits them.
- `deriveaddresses` RPC help now labels `rawmr(<merkle root>)` as an
  expert-only arbitrary-root descriptor form whose roots cannot be proved or
  signed by the wallet.

### P2MR descriptors and future leaves

- Added an end-to-end `feature_p2mr.py` regression for `rawmr(<future-leaf-root>)`
  outputs.
- Covered public descriptor derivation, wallet funding, signer refusal for a
  non-`0xc0` future leaf, standard mempool rejection, and mandatory block
  acceptance for the same reveal spend.
- Added focused unit and functional coverage around reserved P2MR leaf-version
  policy, masked future leaf control bytes, and PSBT signing/finalization
  refusal for reserved leaf versions.
- Added independent JSON vectors for P2MR leaf hashing, branch hashing, control
  blocks, Merkle roots, scriptPubKeys, and mainnet/regtest addresses.
- P2MR commitment-vector tests now cover malformed control blocks, wrong leaf
  versions, wrong CompactSize or script-length commitments, mutated siblings,
  unsorted branch roots, and wrong root commitments.
- Descriptor, RPC, script, and PSBT tests now reuse the independent P2MR
  commitment vectors.

### P2MR script, sighash, and data-signature coverage

- Added fixed byte-vector P2MR script-path tests for a single-leaf spend and a
  two-leaf branch spend.
- Added a fixed byte-vector CTV spend test that avoids deriving the accepted
  spend from production commitment helpers.
- Added independent P2MR/PQC witness-vector coverage for the default
  `OP_CHECKSIGPQC` spend path, including mutated signatures, wrong sighash
  domains, bad hashtype suffixes, and wrong script/pubkey commitments.
- Added an independent annex-present P2MR `OP_CHECKSIGPQC` witness vector with
  annex spend-type encoding, annex hash commitment, no-annex contrast data, and
  annex-specific near-miss failures.
- Added independent fixed P2MR `OP_CHECKSIGPQC` witness vectors for non-default
  sighash modes, including `SIGHASH_NONE`, `SIGHASH_SINGLE`, and
  `ANYONECANPAY` combinations.
- The fixed P2MR PQC witness fixture now pins serialized spend transactions,
  spent outputs, P2MR leaf/control data, public keys, signatures, raw
  `p2mrSigMsg` data, and final `p2mrSighash` values.
- Added reproducible generator coverage for the P2MR PQC witness vectors so
  the checked-in fixtures can be regenerated independently.
- Added codeseparator-specific P2MR `OP_CHECKSIGPQC` vectors for default and
  non-default `OP_CODESEPARATOR` positions, including same-leaf branches with
  different codeseparator positions.
- Added negative coverage for wrong codeseparator positions, domains, public
  keys, scripts, and signatures.
- Added explicit `SIGHASH_SINGLE` P2MR cases covering both matched-output
  acceptance and missing-output rejection.
- P2MR `SIGHASH_SINGLE` tests now assert failure for missing outputs instead
  of allowing the legacy `uint256::ONE` behavior.
- Added independent `OP_CHECKDATASIGPQC` P2MR witness-vector coverage for
  accepted data-signature spends and near misses involving corrupted
  signatures, wrong domains, mutated witness message hashes, mutated leaves,
  and wrong public keys.
- Added independent `OP_CHECKDATASIGADDPQC` P2MR witness-vector coverage for
  threshold data signatures, including n-of-n success, m-of-n success with
  empty-signature skips, threshold failure, invalid non-empty signatures, wrong
  message hashes, wrong committed keys, wrong domains, and mutated leaves.
- Added pinned P2MR data-hash proof fixtures for the `QbitDataSigPQC` domain,
  including C++ fixture validation, wallet signing reproduction, and
  `verifydatapqchash` functional coverage for malformed or mutated proof data.

### Release and CI

- Release publication validation now requires the signed release tag target to
  be an ancestor of the configured `trusted_release_ref`.
- Public release-trust documentation records the `v0.1.1-testnet4` signed tag
  object and target from public git state.
- Public branch rulesets now use a path-aware Required Merge Gate profile so
  source, release-policy, RPC docs, public docs, and GitHub metadata changes
  receive appropriate validation.
- Scheduled/manual RPC performance, IBD performance, and lint image prewarm
  workflows now target the public `0.1.x` profile.
- CI Docker BuildKit setup is covered by a tested helper, preserves the
  internal registry configuration where needed, and adds resolver fallback for
  public package hosts.
- CI profiles are portable across public and internal repository contexts,
  including hosted/public images and trusted-runner paths where appropriate.
- Nightly CI and RPC performance workflows were hardened by pinning scanner
  tooling for the available Rust version, separating qbit-only test-node
  capabilities from Bitcoin Core reference nodes, and sharding long ARM unit
  tests.
- P2MR-heavy wallet unit tests were split into smaller CTest-visible shards so
  expensive keypool, descriptor, encryption, validation, signing, and
  trusted-record coverage receives separate timeout budgets.
- The libbitcoinpqc subtree verifier now checks that `src/libbitcoinpqc`
  matches the peeled upstream tag tree and recorded `git-subtree-split`, and
  the checker is wired into subtree lint and update tooling.
- Added a focused qbit single-PR review skill with qbit-specific consensus,
  networking, validation-evidence, and GitHub-ready review-output guidance.

Known issues
============

No new release-specific known issues are added by v0.1.2-testnet4. Testnet4
remains a public rehearsal network and may still be reset or replaced during
the testnet era.

Credits
========

Thanks to everyone who contributed code, testing, review, infrastructure, and
release coordination for this release.
