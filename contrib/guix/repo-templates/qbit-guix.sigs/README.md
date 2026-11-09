# qbit-guix.sigs

This repository stores qbit Guix attestation manifests from independent
operator build checks.

## Purpose

- Publish `noncodesigned.SHA256SUMS{,.asc}` and `all.SHA256SUMS{,.asc}` files
  for each release version and operator.
- Carry a derived, data-only copy of the qbit release signer policy, signer
  public certificates, and current policy approval material under
  `operator-keys/`, next to the attestations they verify.
- Support `./contrib/guix/guix-attest` and `./contrib/guix/guix-verify` via the
  `GUIX_SIGS_REPO` environment variable.

## Layout

```text
operator-keys/
operator-keys/keys.json
operator-keys/public-keys/<signer-alias>-release.asc
operator-keys/approvals/<policy-id>/policy.SHA256
operator-keys/approvals/<policy-id>/approval-note.md
operator-keys/approvals/<policy-id>/<approver-alias>.asc
<version>/operator-01/noncodesigned.SHA256SUMS
<version>/operator-01/noncodesigned.SHA256SUMS.asc
<version>/operator-01/all.SHA256SUMS
<version>/operator-01/all.SHA256SUMS.asc
```

Additional artifact namespaces, such as `photon-*.SHA256SUMS`, may appear when
the corresponding Guix helper is run with `ARTIFACT=...`.

## Workflow

1. Independent operators run `./contrib/guix/guix-build`.
2. Each operator runs `./contrib/guix/guix-attest` with
   `SIGNER=<gpg-selector>=operator-XX` so the GPG selector and public directory
   name are both explicit.
3. Each operator opens a PR adding their attestation directory for the release.
4. Another operator runs `./contrib/guix/guix-verify` against this repository
   before release publication.
5. The release coordinator runs
   `ci/release/validate_builder_attestations.py` from the qbit source checkout
   before publishing GitHub Release assets, passing the public release checkout
   as `--source-root` and the verified annotated-tag target as
   `--expected-tag-target`.

Every counted core and PHOTON manifest must contain the common
`qbit-<version>.tar.gz` entry. The validator reconstructs that archive from the
signed-tag target with the same Guix `git archive` prefix and requires its exact
basename and SHA256 before counting the manifest toward quorum. The source
archive remains attestation evidence and is not a staged GitHub Release asset.

The release signer key that signs `SHA256SUMS.operator-XX.asc` for GitHub
release artifacts can also sign that operator's Guix attestations when the
signer has `builder-attestation` capability in `operator-keys/keys.json`.
Release-signature quorum and builder-attestation quorum remain separate checks
over the active signer policy.

`operator-keys/` is not a trust source. The release key policy has one source
of truth: `contrib/keys/operator-keys/` in `Qbit-Org/qbit`, read at the
release's trusted ref (see `contrib/keys/README.md` there). Release validators
read the policy from that checkout; the release publisher also refuses a
`qbit-guix.sigs` commit whose `operator-keys/` differs from it, byte for byte.
Verifiers should take keys from qbit, not from this directory.

Keep `operator-keys/` strict machine data: exactly `keys.json`, the signer
certificates it references, and the current policy's
`approvals/<policy-id>/` material. Do not place README files, notes, hidden
files, stale certificates, older approval directories, or other human-only
documents under it.
