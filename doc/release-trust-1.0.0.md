# qbit 1.0.0 Release Trust Reference

This note anchors the reviewed policy and validation commit used to publish
qbit 1.0.0 mainnet artifacts. The signed tag fixes the release source; this
later trust reference does not replace or modify that source.

## Release source

- Release tag: `v1.0.0`
- Annotated tag object: `c72d230476ffe94e2f672d925f34288159233dfc`
- Peeled tag target: `7ebcddb622d6e639041f005a189b048ec2a221fe`
- Tag signer: `operator-01`
- Signing fingerprint: `289EA3EC2F1939A24984840ED26CFC05586D371E`
- Tagger: `Alex <alex@swaplabs.xyz>`
- Tag date: `2026-07-15T16:34:36Z`
- GitHub verification: `verified=true`, `reason=valid`

The tag target is the current protected `Qbit-Org/qbit:main` commit. GitHub's
compare result between that commit and `main` is `identical`, with zero commits
ahead or behind.

## Public review and lineage

The complete release candidate was reviewed in
[Qbit-Org/qbit#135](https://github.com/Qbit-Org/qbit/pull/135). Its reviewed
head, `9ea1ac9ddddc5236356095a2592a397234efca56`, and the protected-`main`
squash result share tree `68fc87fbb1b428adc98ce98040aadfabc4f315ec`.
The squash result is the peeled tag target named above; the reviewed head is
not represented as its ancestor.

Exact-target
[Core Checks](https://github.com/Qbit-Org/qbit/actions/runs/29431717879)
completed successfully. Full Validation run
[29431717977](https://github.com/Qbit-Org/qbit/actions/runs/29431717977)
contains a failed Windows-native Qt job and is not represented as passing. The
release coordinator explicitly accepted skipping that requirement for this
release; all validators continue to fail closed and no tag or source identity
is changed by that deviation.

## Policy and validation authority

The active policy is `qbit-release-keys-mainnet-000002`, sequence 2, effective
from `v1.0.0`. The exact `contrib/keys/operator-keys/keys.json` SHA256 is
`f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`.
The public policy mirror is `Qbit-Org/qbit-guix.sigs` commit
`a7ed466bc24f016f5d1f2995758371cc55ebc5d2`.

The `trusted_release_ref` supplied to release validation and publication must
be the full 40-character SHA of the reviewed commit that merges this note into
`Qbit-Org/qbit`. It must differ from both the annotated tag object and peeled
tag target, and its history must contain the peeled tag target.

That trusted commit must retain the public release validators, publisher,
mainnet posture checks, P2MR gate, operator policy, and five public
certificates used to validate the final artifact set:

- `.github/workflows/release-publish.yml`
- `ci/release/validate_release_artifacts.py`
- `ci/release/validate_builder_attestations.py`
- `ci/release/validate_key_metadata.py`
- `ci/release/verify_mainnet_release_posture.py`
- `ci/release/verify_mainnet_ci_posture.py`
- `ci/release/verify_p2mr_v1_conformance.py`
- `contrib/release-process/publish-local-release.sh`
- `contrib/keys/operator-keys/keys.json`
- `contrib/keys/operator-keys/public-keys/operator-01-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-02-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-03-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-04-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-05-release.asc`

After this note is reviewed and merged, its resulting full commit SHA becomes
the fixed `trusted_release_ref` for qbit 1.0.0.
