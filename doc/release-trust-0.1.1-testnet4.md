# qbit 0.1.1-testnet4 Release Trust Reference

This note prepares the reviewed policy/tooling commit used by the
`release-publish.yml` workflow for qbit 0.1.1-testnet4.

Release source status:

- Release tag: `v0.1.1-testnet4`
- Tag object: pending signed annotated tag creation after the public release
  source merge
- Tag target: pending final public release source commit

Do not use this note as final release evidence until the signed annotated tag
exists and the tag object and tag target have been recorded from public git
state.

The `trusted_release_ref` supplied to the publish workflow must be the full
40-character SHA of a reviewed commit in `Qbit-Org/qbit` whose history contains
the release tag target. It must not be the release tag object or the release tag
target commit.

The trusted commit must retain the public release validators, publish workflow,
testnet posture verifier, and operator key policy used to validate the final
artifact set:

- `.github/workflows/release-publish.yml`
- `ci/release/validate_release_artifacts.py`
- `ci/release/validate_builder_attestations.py`
- `ci/release/validate_key_metadata.py`
- `ci/release/verify_testnet_release_posture.py`
- `contrib/keys/operator-keys/keys.json`
- `contrib/keys/operator-keys/public-keys/operator-01-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-02-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-03-release.asc`

After the public release source has landed, the signed annotated tag exists, and
this note is reviewed and merged, use the resulting full 40-character
`Qbit-Org/qbit` commit SHA as `trusted_release_ref`.
