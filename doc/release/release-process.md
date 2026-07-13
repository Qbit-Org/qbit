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

- the release tag is a signed annotated tag that GitHub verifies
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
- the draft release body exactly matches the explicit or generated release notes
  selected by the publisher
- the draft release asset names and GitHub-computed SHA256 digests exactly match
  the validator-approved upload set before publication

Testnet posture evidence is mandatory for `release_line=testnet`; the publisher
fails closed when `--testnet-posture-evidence` is missing.

Any local publication path must run the builder validator with the public
release checkout as `--source-root` and the commit target obtained from the
verified annotated tag as `--expected-tag-target`. These inputs are required;
the publisher passes both arguments and an older caller that omits them fails
before builder quorum is evaluated.

Public validators live under `ci/release/`. Release key metadata lives under
`contrib/keys/operator-keys/`.

## Publishing

The publisher requires `gh`, `git`, `gpg`, and `python3`. Run it from the
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
`--notes-file` is provided, its exact UTF-8 contents are authoritative. When it
is omitted, the publisher obtains a body from GitHub's generate-release-notes
API and uses that body as the authoritative notes for the invocation. The
publisher replaces any existing draft body, fetches it back, and requires an
exact match before publication. A draft body that cannot be corrected and
verified remains unpublished. Manual changes to a resumed draft are therefore
not preserved; record curated notes in a file and pass `--notes-file`.

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
