# qbit Releases

This directory holds the public release and verification guidance for qbit
source and binary artifacts.

| Document | Use it for |
| --- | --- |
| [release-process.md](release-process.md) | The runbook for a mainnet release: roles, checklists and the publisher command. |
| [publisher-reference.md](publisher-reference.md) | What the publisher and the `ci/release/` validators enforce, and what is left to process. |
| [guix.md](guix.md) | Reproducible Guix builds and their outputs, including the debug symbol archives, and how builder attestations are bound to the signed tag. |
| [examples/p2mr-v1-conformance-evidence.json](examples/p2mr-v1-conformance-evidence.json) | A field example of the P2MR v1 evidence envelope. Its zero hashes and `example.invalid` references deliberately cannot validate. |

The public tools that stage, sign and combine `SHA256SUMS` and publish a
release are described in
[contrib/release-process/README.md](../../contrib/release-process/README.md),
and the release key policy in
[contrib/keys/README.md](../../contrib/keys/README.md).

Each release is tracked in an issue opened from the **Release** issue
template, [`.github/ISSUE_TEMPLATE/release.yml`](../../.github/ISSUE_TEMPLATE/release.yml).
Each published release has a trust record, `doc/release-trust-<version>.md`;
see the [v1.0.0 record](../release-trust-1.0.0.md).

## Release gates

Mainnet publication fails closed on two validators, and neither has a waiver:

- `ci/release/verify_mainnet_release_posture.py` checks the launch posture
  of the tag target;
- `ci/release/verify_p2mr_v1_conformance.py` checks the P2MR v1 conformance
  evidence for that same commit.

The publisher runs both itself, so CI results do not decide publication.
Core Checks also runs the posture validator, but only for `source` and
`release-policy` changes to a mainnet line, and on `main` only once it is
fast-forwarded after v1.0.1; for which runs exercise it, see
[the publisher reference](publisher-reference.md#mainnet-launch-posture). The
checked-in [integration support matrix](../integration/p2mr-v1-support-matrix.md)
stays a draft until a finalized snapshot is made for an exact tag target.

## Verifying release binaries

- Download the artifacts from the matching qbit GitHub Release.
- Verify `SHA256SUMS.asc` against `SHA256SUMS`.
- Verify the downloaded files against `SHA256SUMS`.

Some operator tooling, ceremony logs and key-custody procedures are private
operational material. They are not part of the public documentation, and
public verification does not depend on them.
