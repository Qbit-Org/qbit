# Public Release Process

This document describes the normal public qbit release path after the public
repository cutover.

The normal release model is:

```text
public protected branch -> signed release tag -> validated local publisher -> immutable GitHub Release
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
- `v1.0.0`

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

The release publisher must be run from a clean public checkout whose `HEAD`
exactly equals `trusted_release_ref`. The publisher uses that checkout's
validators and key policy, while source-binding validation reconstructs the
canonical archive from the signed tag target rather than the worktree.

The trusted commit must contain
`contrib/release-process/publish-local-release.sh`, the public `ci/release/`
validators, and `contrib/keys/operator-keys/`. A ref that predates those files
fails closed instead of publishing.

## Public Release Tooling

The only supported public publication entry point is
`contrib/release-process/publish-local-release.sh`. It publishes directly from
coordinator-held artifacts; GitHub Actions does not publish releases.

The publisher validates:

- the release tag ref resolves to the exact locally pinned annotated-tag object,
  that object directly targets the pinned commit, and GitHub reports its
  signature verification as exactly `verified=true` and `reason=valid`
- the tag signer is accepted by the qbit release key policy
- `trusted_release_ref` is a full public commit SHA and is not the tag object or
  tag target commit, and the tag target is its ancestor
- the trusted qbit checkout and pinned `qbit-guix.sigs` checkout are clean, and
  the latter commit is public and reachable from its configured public branch
- staged artifacts match `SHA256SUMS`
- `SHA256SUMS.asc` meets release-signature quorum
- `qbit-guix.sigs` builder attestations meet builder quorum and every counted
  manifest is bound to the source archive reconstructed from the signed tag
  target
- testnet posture evidence passes when `release_line=testnet`
- the signed tag target passes the fail-closed mainnet launch-posture validator
  when `release_line=mainnet`
- the draft release body exactly matches the explicit or generated release notes
  selected by the publisher
- the draft release asset names and GitHub-computed SHA256 digests exactly match
  the validator-approved upload set before publication
- the final published release is immutable, and its locked asset names and
  GitHub-computed SHA256 digests still exactly match the validated upload set
- the immutable release locked the same signed tag object and target checked
  before validation and immediately before publication

Testnet posture evidence is mandatory for `release_line=testnet`; the publisher
fails closed when `--testnet-posture-evidence` is missing.

## Mainnet launch posture gate

Mainnet publication automatically runs
`ci/release/verify_mainnet_release_posture.py` against the peeled signed-tag
target. The validator does not inspect mutable working-tree replacements for
tagged source files and has no waiver.

Core Checks also runs this same validator in the required `mainnet publication
posture` job for source and release-policy changes targeting the `1.0.0` branch.
This explicitly includes the lightweight profile used by changes to release
validators and publishing scripts. CI creates an annotated tag at the exact
checked-out candidate commit so that this early check exercises the validator's
immutable tag-target path.

`ci/release/mainnet_ci_posture.json` separates merge posture from publication
posture without weakening the publisher. In `staging` phase, Core Checks
requires the real validator to fail for exactly the declared launch blockers;
missing expected failures or additional bootstrap, default-chain, or source
failures fail CI. When the final commitments land, the same change must set the
policy to `final` and clear its expected failures, at which point Core Checks
requires the validator to succeed. A publication-ready result while the policy
still says `staging` also fails CI.

The local publisher does not read this CI phase policy. It remains the authority
for publication and independently requires unconditional validator success
against the real signed public tag after verifying that tag's GitHub signature
and ancestry. There is no staging mode or publication waiver.

It fails closed unless:

- the mainnet AuxPoW chain ID is non-placeholder, differs from testnet4, and
  has a unit-test assertion for that distinction;
- the mainnet genesis and ASERT launch artifact records final source provenance
  without draft, temporary, replacement, or placeholder markers;
- chainparams retain pinned genesis-hash, Merkle-root, and ASERT assertions;
- at least two unique DNS seeds and two unique numeric fixed seeds are present,
  the generated BIP155 fixed-seed bytes exactly match `nodes_main.txt`, and the
  bootstrap unit test asserts the published seed set and zero launch-size
  estimates; and
- CMake and Guix default `QBIT_TESTNET_ONLY_RELEASE` to `OFF`, Guix does not
  infer posture from an archive name, and unit tests assert that default and
  explicit mainnet selection are accepted in a standard build.

The v1.0.0 preparation branch is expected to build while the real publication
gate rejects its deliberate chain-ID and genesis/ASERT placeholders. Core
Checks accepts that state only when those are the exact two reported failure
categories. Both failures must become successes, and the CI policy must move to
`final`, before any mainnet draft release can be created or published.

## Mainnet-capable build default

Standard source and Guix builds default to
`QBIT_TESTNET_ONLY_RELEASE=OFF`, regardless of the distribution archive name.
This makes mainnet chain selection available in ordinary v1.0.0 binaries.

A testnet-only package remains available as an explicit opt-in by configuring
with `-DQBIT_TESTNET_ONLY_RELEASE=ON` or setting
`QBIT_TESTNET_ONLY_RELEASE=ON` for the Guix build. Such a binary rejects both
no-flag mainnet startup and explicit `-chain=main` startup. Release builders
must record the selected value; package naming must not be used as evidence of
the compiled chain posture.

## qbit P2MR v1 Conformance

Mainnet publication requires three separate absolute-path inputs to the local
publisher:

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
9. Supply those same exact files to `publish-local-release.sh` with
   `--p2mr-v1-conformance-evidence`, `--p2mr-v1-oracle-report`, and
   `--p2mr-v1-integration-matrix`.
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
the publisher passes both arguments and an older caller that omits them fails
before builder quorum is evaluated.

Public validators live under `ci/release/`. Release key metadata lives under
`contrib/keys/operator-keys/`.

## Publishing

The publisher requires `gh`, `git`, `gpg`, `python3`, and an authenticated GitHub
account with push access to the target repository. Push access is required even
in validation-only mode so the release listing includes drafts. Run it from the
repository root at the selected trusted release ref. A command with no
publication mode performs all local and remote validation without changing a
GitHub Release:

```sh
contrib/release-process/publish-local-release.sh \
  --tag "${TAG}" \
  --artifacts-dir /path/to/staged-release \
  --trusted-release-ref "$(git rev-parse HEAD)" \
  --guix-sigs-repo /path/to/qbit-guix.sigs \
  --guix-sigs-ref "${GUIX_SIGS_REF}" \
  --release-line testnet \
  --testnet-posture-evidence /path/to/testnet-posture.env \
  --notes-file "doc/release-notes-${TAG#v}.md" \
  --require-photon
```

Add `--create-draft` to create or resume a draft without publishing it. Add
`--publish` to create or resume a draft, verify its complete remote asset
inventory, and publish it. These modes are mutually exclusive. Existing assets
in a resumed draft must be a digest-matching subset of the new validated set;
the publisher never uses replacement uploads and never modifies an existing
published release.

Release notes follow the same policy for new and resumed drafts. When
`--notes-file` is provided, the publisher validates its UTF-8 encoding and
snapshots its exact bytes into the invocation work directory before the
long-running validators execute. Later changes to the source file cannot alter
the release body. When the option is omitted, the publisher obtains a body from
GitHub's generate-release-notes API and snapshots that generated body for the
invocation. The publisher replaces any existing draft body, fetches it back,
and requires an exact match before publication. A draft body that cannot be
corrected and verified remains unpublished. Manual changes to a resumed draft
are therefore not preserved; record curated notes in a file and pass
`--notes-file`.

New drafts default to the title `qbit <TAG>`, non-prerelease, and
`make-latest=false`. When resuming a draft, omitting `--release-name` preserves
its current title, and omitted prerelease and latest options preserve their
current state. Use `--release-name`, `--prerelease` or `--no-prerelease`, and an
explicit `--make-latest` mode to change those values. `--make-latest auto` maps
to GitHub's `make_latest=legacy` behavior, which selects the latest release by
creation date and semantic version rather than preserving the prior setting.

Draft releases are expected to remain mutable while their assets are assembled.
The publisher does not require `isImmutable=true` until `--publish` transitions
the draft to a published release. The exact remote tag ref, annotated-tag object,
commit target, and GitHub signature verification are checked before validation
and again immediately before that transition. The publisher then polls the
final release metadata for a bounded period and fails unless GitHub reports both
`isDraft=false` and `isImmutable=true`, polls the locked asset inventory and
digests for API propagation, and performs the exact tag check a final time before
reporting success. Validation-only mode likewise rejects an existing published
release that is not immutable, whose immutable state is missing, or whose final
tag pin differs. Release discovery uses a fully paginated listing so matching
drafts remain resumable. A release is considered absent only after that listing
succeeds without a matching tag; authentication, API, and other lookup failures
stop validation rather than skipping the remote release checks.

Release immutability must be enabled under the target repository's release
settings or enforced by its organization before publication. GitHub applies the
setting only to future releases; enabling it does not make an existing mutable
release immutable. When `--repo OWNER/REPO` overrides the default repository,
that target repository must independently satisfy the same policy. A publisher
failure after a mutable publication requires manual release remediation; rerunning
the publisher does not retrofit immutability or modify the published release.

### Immutable-publication recovery

A final tag-pin failure can occur after GitHub has already made the release
immutable. The publisher exits unsuccessfully and identifies the expected and
observed tag values; it cannot roll the publication back. Stop distributing the
release and preserve the complete publisher transcript, release URL and ID,
expected and observed tag object and target, and repository audit evidence. Do
not rerun the publisher expecting it to repair or replace the immutable release.

Handle the event through the release-integrity incident process. If policy calls
for removing the incorrect immutable release, remember that GitHub does not
allow its tag name to be reused afterward. Prepare a new version, create and
sign a new annotated tag, repeat the complete validation and publication flow,
and publish a correction notice that identifies the superseded release.

Unsigned platform or public codesigning payload waivers require the explicit
`--allow-unsigned-platform-artifacts` or `--allow-codesigning-artifacts` flags.
Use them only when the corresponding public release waiver has been recorded.

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
- publisher command transcript, asset inventory and digest verification output,
  release URL, and immutable release state
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
