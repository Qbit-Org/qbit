# Public Release Process

This document describes the normal public qbit release path after the public
repository cutover.

The normal release model is:

```text
public protected branch -> public release branch/tag -> public release workflow
```

Bridge, embargo, and security-publication exports from private source are
exceptional flows. They are not the ordinary public release path.

## Release Source

The release source is a reviewed public commit reachable from a protected public
branch, usually `main` or a release branch such as `0.1.x`.

Release candidates and final releases use signed annotated tags in the public
qbit repository. Examples:

- `v0.1.0-testnet4-rc1`
- `v0.1.1-testnet4`

The tag target commit is the source commit used for release builds. Do not use a
private source commit, a sanitizer mapping, a branch name, a short SHA, or a tag
object SHA as the release source.

The release validator recreates `qbit-<version>.tar.gz` directly from that tag
target with the same `git archive --prefix="qbit-<version>/"` semantics used by
the Guix build. Every counted core and PHOTON builder manifest must contain the
resulting basename and SHA256. The source archive is builder evidence and is not
part of the staged GitHub Release upload set.

## Trusted Validation Ref

`trusted_release_ref` is the reviewed public commit used for release validation
tooling, release key policy, and public release-trust notes.

It must be the full 40-character commit SHA of a public commit. It must not be a
branch name, short SHA, tag ref, tag object SHA, or the release tag target
commit. This preserves a separate public source anchor and public validation
policy anchor for each release.

The release workflow checks out the signed tag for source and checks out
`trusted_release_ref` separately for validators and key policy.

Because the workflow runs `ci/release/verify_testnet_release_posture.py` from
the `trusted_release_ref` checkout, that commit must be recent enough to contain
the public `ci/release/` validators. A `trusted_release_ref` that predates their
relocation fails closed with a clear "missing script" error instead of
publishing.

## Public Release Tooling

The public release workflow is `.github/workflows/release-publish.yml`.

The workflow validates:

- the release tag is a signed annotated tag that GitHub verifies
- the tag signer is accepted by the qbit release key policy
- `trusted_release_ref` is a full public commit SHA and is not the tag object or
  tag target commit
- staged artifacts match `SHA256SUMS`
- `SHA256SUMS.asc` meets release-signature quorum
- `qbit-guix.sigs` builder attestations meet builder quorum and every counted
  manifest is bound to the source archive reconstructed from the signed tag
  target
- testnet posture evidence passes when `release_line=testnet`

Testnet posture evidence is mandatory for `release_line=testnet`: both the
publish workflow and the local publish fallback require the
`TESTNET_RELEASE_POSTURE_EVIDENCE` input and fail closed when it is missing.

## qbit P2MR v1 Conformance

Mainnet publication requires three separate absolute-path inputs on the
self-hosted runner:

- `p2mr_v1_conformance_evidence`, the release evidence envelope;
- `p2mr_v1_oracle_report`, the canonical standalone-oracle report; and
- `p2mr_v1_integration_matrix`, the finalized machine-readable support
  inventory.

For testnet, all three may be omitted, in which case the release does not claim
completed qbit P2MR v1 conformance. Supplying any one requires all three and
runs the same validation. Mainnet always requires all three. There is no
mainnet waiver.

The checked-in
[`p2mr-v1-support-matrix.json`](../integration/p2mr-v1-support-matrix.json)
is an intentionally blocking draft. It documents the required inventory but
cannot be supplied as final release evidence. Release operators must produce a
separate finalized snapshot whose `release_source_commit` is the exact signed
tag target. Every required in-tree surface must be `supported` and `pass` with
`version` equal to that tag-target commit, plus an environment, review date,
and stable public evidence.
Unsupported external categories remain explicit `not-claimed` rows; absence is
not evidence.

Before supplying the workflow inputs:

1. Freeze the signed annotated release tag and record its peeled commit SHA.
2. Run the complete qbit P2MR v1 unit suite on that exact commit.
3. Run the standalone oracle in release mode on that exact commit and preserve
   its canonical report.
4. Recalculate the tagged manifest and every manifest-listed corpus digest.
5. Complete the integration inventory with exact versions, environments,
   limitations, results, owners, and stable public evidence.
6. Re-run consensus review on the exact tag target and preserve a stable public
   review reference.
7. Build the evidence envelope using
   [`p2mr-v1-conformance-evidence.json`](examples/p2mr-v1-conformance-evidence.json)
   as a field example. Zero hashes and `example.invalid` references must all be
   replaced.
8. Run `ci/release/verify_p2mr_v1_conformance.py` locally with the tag checkout
   and the three finalized files.
9. Supply those same exact files to the publish workflow.
10. Preserve the profile version, tag target, manifest digest, oracle report
    digest, integration matrix digest, consensus review, and workflow run URL
    with the public release evidence.

The validator runs from `trusted_release_ref`, but reads the normative
specification, manifest, and corpus as Git blobs from the signed tag target. It
requires the qbit result, oracle report, consensus review, and finalized matrix
to name that same commit. Review of an ancestor is insufficient.

Release notes must use one of these precise forms:

```text
Conforms to qbit P2MR v1 corpus <digest> on source commit <SHA>; independent oracle report <digest>.
```

or:

```text
This release does not claim completed qbit P2MR v1 conformance.
```

Do not substitute `BIP-360 compatible`, `P2MR compatible`, or `P2MR tested`.

Any local publication path must run the builder validator with the public
release checkout as `--source-root` and the commit target obtained from the
verified annotated tag as `--expected-tag-target`. These inputs are required;
an older local caller that omits them fails before builder quorum is evaluated.

Public validators live under `ci/release/`. Release key metadata lives under
`contrib/keys/operator-keys/`.

## Public Evidence

Normal public release evidence should pin public data:

- release version and signed tag
- tag object, tag target commit, signer fingerprint, tagger identity, tag date,
  and tag verification result
- `trusted_release_ref`, rationale, and review or protected-branch evidence
- exact-byte `keys.json` SHA256, `policy_id`, and `policy_sequence`
- exact public `qbit-guix.sigs` commit used for final validation
- counted builder aliases/fingerprints and artifact sets
- canonical source archive basename, SHA256, and signed-tag target commit
- counted release signer aliases/fingerprints
- artifact manifest digest, combined signature digest, individual operator
  signature digests, and artifact count
- PHOTON inclusion status and validation result
- release publication URL and final GitHub Release state
- Release Publish workflow run URL, or local fallback reason plus exact command
  transcript, asset inventory, and verification output
- qbit P2MR v1 profile version, exact release source commit, corpus manifest
  digest, qbit conformance result, oracle report digest, finalized integration
  matrix digest, and exact-SHA consensus review evidence, or an explicit
  statement that completed qbit P2MR v1 conformance is not claimed

Normal public release evidence must not require private source commits,
sanitizer manifests, sanitizer mapping files, private qbit-tools state, operator
card-binding files, custody records, or filled internal evidence templates.

## Private Operational Material

The following remain internal operational material:

- release ceremony logs and filled evidence templates
- signer custody and operator card-binding records
- qbit-tools remote builder state paths
- private Apple SDK, platform signing, and detached-signature custody material
- bridge, embargo, and security-publication sanitizer mappings

Those records may be necessary for operators, but they are not part of the
normal public release source path.
