# Bootstrappable qbit Builds

qbit release binaries are built by release operators with reproducible Guix
builds and checked against builder attestations before publication.

Public release evidence pins the exact `qbit-guix.sigs` commit used for
attestation validation.

## Source archive binding

Core and PHOTON Guix builds both create `qbit-<version>.tar.gz` from the build
checkout with:

```sh
git archive --prefix="qbit-<version>/" --output="qbit-<version>.tar.gz" HEAD
```

The archive is included in every generated builder manifest even though it is
not uploaded as a public release artifact. Before counting a signed manifest,
`ci/release/validate_builder_attestations.py` independently reconstructs the
archive from the verified annotated-tag target and requires the exact basename
and SHA256 in that manifest.

Release coordinators must provide both the source repository and the verified
tag target:

```sh
python3 ci/release/validate_builder_attestations.py \
  --artifacts-dir /path/to/staged-release \
  --tag "${TAG}" \
  --source-root /path/to/public-qbit-checkout \
  --expected-tag-target "${VERIFIED_TAG_TARGET}" \
  --release-line "${RELEASE_LINE}" \
  --guix-sigs-repo /path/to/qbit-guix.sigs
```

The validator requires an annotated local tag, confirms that it resolves to
the supplied commit, reconstructs the archive from that commit rather than the
worktree or `trusted_release_ref`, and reports the canonical source digest for
release evidence.
