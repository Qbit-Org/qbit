# qbit 0.1.2-testnet4 Release Trust Reference

This note anchors the reviewed policy/tooling commit used by the
`release-publish.yml` workflow for qbit 0.1.2-testnet4.

Release source:

- Release tag: `v0.1.2-testnet4`
- Tag object: `bc715e6933507c4755d33628bf77a222ed0bb7f6`
- Tag target: `6f29b4a5e5d2ad41bd9cebd100439b43a8b81eef`

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

After this note is reviewed and merged, use the resulting full 40-character
`Qbit-Org/qbit` commit SHA as `trusted_release_ref`.
