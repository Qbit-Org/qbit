# qbit 0.1.0-testnet4 Release Trust Reference

This note anchors the reviewed policy/tooling commit used by the
`release-publish.yml` workflow for qbit 0.1.0-testnet4.

Release source:

- Release tag: `v0.1.0-testnet4`
- Tag object: `5eb0686968f4944f2d0c69bff46799c8d012b052`
- Tag target: `57bb53575f0d4931e77ac4a34b7e7f4c049f0636`

The `trusted_release_ref` supplied to the publish workflow must be the full
40-character SHA of a reviewed commit in `Qbit-Org/qbit` that is newer than the
release tag target. It must not be the release tag object or the release tag
target commit.

The trusted commit must retain the public release validators, publish workflow,
testnet posture verifier, and operator key policy used to validate the final
artifact set:

- `.github/workflows/release-publish.yml`
- `ci/release/validate_release_artifacts.py`
- `ci/release/validate_builder_attestations.py`
- `ci/release/validate_key_metadata.py`
- `contrib/release-process/verify-testnet-release-posture.py`
- `contrib/keys/operator-keys/keys.json`
- `contrib/keys/operator-keys/public-keys/operator-01-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-02-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-03-release.asc`

After this note is reviewed and merged, use the resulting full 40-character
`Qbit-Org/qbit` commit SHA as `trusted_release_ref`.
