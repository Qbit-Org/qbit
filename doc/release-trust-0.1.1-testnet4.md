# qbit 0.1.1-testnet4 Release Trust Reference

This note anchors the reviewed policy/tooling commit used by the
`release-publish.yml` workflow for qbit 0.1.1-testnet4.

Release source:

- Release tag: `v0.1.1-testnet4`
- Tag object: `cc268a7f1bde1d985e3898df164310b34caa571a`
- Tag target: `08b84765b3026d8684a76e3a3403b0aaf74c1610`

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
