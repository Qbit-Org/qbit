# qbit-guix.sigs

This repository stores qbit Guix attestation manifests from independent
operator build checks.

## Purpose

- Publish `noncodesigned.SHA256SUMS{,.asc}` and `all.SHA256SUMS{,.asc}` files
  for each release version and operator.
- Provide a public, data-only mirror of qbit release signer policy,
  signer public certificates, and policy approval material under
  `operator-keys/`.
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
   before publishing GitHub Release assets.

The release signer key that signs `SHA256SUMS.operator-XX.asc` for GitHub
release artifacts can also sign that operator's Guix attestations when the
signer has `builder-attestation` capability in `operator-keys/keys.json`.
Release-signature quorum and builder-attestation quorum remain separate checks
over the active signer policy.

`operator-keys/` is machine-verified release key mirror data. Do not place
README files, notes, hidden files, stale certificates, unreferenced approval
files, or other human-only documents under that directory.
