# Bootstrappable qbit Builds

qbit release binaries are built by release builders with reproducible Guix
builds, and checked against builder attestations before publication. The
[release runbook](release-process.md) says when this happens in a release.

## Builders and attestations

Builders are the active `builder-attestation` signers for the release line in
[`contrib/keys/operator-keys/keys.json`](../../contrib/keys/operator-keys/keys.json).
Each builder builds the signed tag with the public scripts in
[contrib/guix](../../contrib/guix/), and then writes signed manifests:

1. `contrib/guix/guix-build` builds core.
2. `contrib/guix/guix-build-photon` builds PHOTON.
3. `contrib/guix/guix-attest` attests core, and again with `ARTIFACT=photon`
   for PHOTON. Set `GUIX_SIGS_REPO` to a `qbit-guix.sigs` clone and
   `SIGNER=<signing fingerprint>=<keys.json alias>`: the part after `=` names
   the output directory, and the validator reads `<version>/<alias>/`.

Each builder then adds its manifests to `Qbit-Org/qbit-guix.sigs` under
`<version>/<alias>/`: `noncodesigned.SHA256SUMS`, plus `all.SHA256SUMS` when
codesigned outputs exist, each with a detached `.asc` signature. PHOTON
manifests use the same names with a `photon-` prefix. The validator reads
`all.SHA256SUMS` when it exists and `noncodesigned.SHA256SUMS` otherwise. An
artifact set passes once the number of builders with matching manifests
reaches that release line's `builder_attestation_quorum` in `keys.json`.
Public release evidence pins the exact `qbit-guix.sigs` commit used for that
count.

Keep the build root, with its Guix output directories, until the release is
published and its `SHA256SUMS` matches your attestation: every published line
of each artifact set you attested appears, with the same digest, in your
manifest for that set. The coordinator stages the release artifacts from one
builder's output directories with
`contrib/release-process/stage-release-artifacts.py`
([runbook step 3](release-process.md#3-stage-sign-and-combine-sha256sums)).

For pre-tag smoke evidence, a candidate can be built with
`FORCE_VERSION=<version>`, so its artifacts have the names a tagged build
will produce.

## Build outputs

Each Linux host produces `qbit-<version>-<host>.tar.gz` and
`qbit-<version>-<host>-debug.tar.gz`. Windows produces
`qbit-<version>-win64-setup-unsigned.exe`, `qbit-<version>-win64-unsigned.zip`,
`qbit-<version>-win64-debug.zip` and `qbit-<version>-win64-codesigning.tar.gz`.

Each macOS host (`x86_64-apple-darwin`, `arm64-apple-darwin`) produces:

- `qbit-<version>-<host>-unsigned.tar.gz` with the stripped binaries
- `qbit-<version>-<host>-unsigned.zip` with `qbit-qt.app`
- `qbit-<version>-<host>-codesigning.tar.gz`, the input to `guix-codesign`
- `qbit-<version>-<host>-debug.tar.gz` with a `.dSYM` bundle per binary in
  `bin/` and `libexec/`

`contrib/guix/libexec/build.sh` installs the macOS binaries twice: stripped
for the release archives, and unstripped into a separate tree. It then runs
`dsymutil` on the unstripped copies. `dsymutil` comes from the same LLVM
package as the `llvm-strip` and `llvm-ar` used by depends: the pinned Guix
`clang-toolchain-18` includes LLVM 18. `guix-codesign` signs the stripped
binaries from the codesigning tarball. The debug archive stays in the
non-codesigned output, and its bundles match the signed binaries by UUID.
`contrib/guix/test_build_config.py` runs the packaging part of `build.sh`
with stand-in tools to check this layout.

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
release evidence. The publisher runs the same validator; see
[the publisher reference](publisher-reference.md#builder-attestations).
