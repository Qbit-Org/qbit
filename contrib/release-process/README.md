# Release staging, signing and publication tools

This directory holds the public tools that turn reproducible Guix builds into a
qbit GitHub Release:

| Step | Tool | Who runs it |
| --- | --- | --- |
| Stage the artifacts and derive `SHA256SUMS` from the counted builder attestations | `stage-release-artifacts.py` | each release operator, or the coordinator |
| Sign `SHA256SUMS` once per operator | `sign-sha256sums.py` | each release operator |
| Combine the per-operator signatures into `SHA256SUMS.asc` | `combine-sha256sums-signatures.py` | the coordinator |
| Validate and publish the release | `publish-local-release.sh` | the coordinator |

Builder-host orchestration (driving `contrib/guix` on a builder, Apple SDK
handling, pushing attestations to `qbit-guix.sigs`) is not part of these tools.

The staging, signing and combining tools reuse the publisher's validators in
`ci/release/`, so their outputs are exactly what `publish-local-release.sh`
accepts: `validate_builder_attestations.py` decides which builder attestations
count, and `validate_release_artifacts.py` decides which attested files are
public release assets and parses every `SHA256SUMS`.

## Trust anchor

Every tool takes `--trusted-release-ref SHA` and must be run from a clean qbit
checkout whose `HEAD` is that commit. The tools refuse to run otherwise. They
load the validators from `ci/release/` and the release key policy from
`contrib/keys/operator-keys/keys.json` of that checkout. There is no option or
environment variable that points them at another `keys.json`, so a vendored or
stale copy of the policy cannot be used by mistake. `--release-line` (`testnet`
or `mainnet`) is always required and selects the quorums and the eligible
signers from that policy.

Use a public commit of the release branch that contains these tools and the
release key policy and descends from the release tag target (for staging, the
tag must be present in the checkout). When the publisher's `trusted_release_ref`
already exists, use it, so that staging, signing and publication all read the
same policy.

```sh
git fetch --tags origin
git checkout --detach "$TRUSTED_RELEASE_REF"
git status --porcelain   # must print nothing
```

## Stage: `stage-release-artifacts.py`

```sh
contrib/release-process/stage-release-artifacts.py \
  --trusted-release-ref "$TRUSTED_RELEASE_REF" \
  --release-line mainnet \
  --tag v1.0.1 \
  --guix-sigs-dir ../qbit-guix.sigs \
  --builder-output-dir guix-build-1.0.1/output \
  --builder-output-dir guix-build-1.0.1/output-photon \
  --stage-dir ../staged-release
```

For each artifact set (`core`, and `photon` when any active builder attested
PHOTON; select explicitly with repeated `--artifact`), the tool:

1. verifies each active builder's `qbit-guix.sigs` manifest for the version
   (`all.SHA256SUMS`, else `noncodesigned.SHA256SUMS`, with a `photon-` prefix
   for PHOTON) against the builder's key in the trusted policy;
2. keeps the attested files the publisher accepts as release assets. The source
   tarball and the `*-codesigning.tar.gz` payloads are never staged, and
   `*-unsigned*` platform artifacts only with
   `--allow-unsigned-platform-artifacts` (`--allow-codesigning-artifacts` is
   the publisher's other waiver). Every file left out is reported on stderr;
3. stages the set that reaches the builder-attestation quorum, with the counted
   manifests bound to the source archive reconstructed from the signed tag. If
   one builder attested less (for example a skipped platform), the larger
   quorum-attested set wins and the builder is reported as not counted.
   Conflicting sets that both reach quorum are refused.

It then copies each artifact from the builder output directories into a scratch
directory next to `--stage-dir`, checks every copy against its attested digest,
writes `SHA256SUMS`, validates the result with the publisher's rules, and only
then renames the scratch directory to `--stage-dir`. A file in the builder
outputs that looks like a release asset but is not in the counted set, a
missing or duplicated artifact, or any digest mismatch stops the tool, and no
stage directory is left behind.

`SHA256SUMS` has one `<sha256>  <file name>` line per artifact (two spaces, LF
line endings), sorted by file name. That is the format of the v1.0.0 release.

Re-running with the same inputs is a no-op (`status=unchanged`). An existing
stage directory whose `SHA256SUMS` or artifacts differ, or that holds other
files, is never modified; move it aside to stage again. Per-operator signatures
and `SHA256SUMS.asc` in an existing stage directory are kept.

`--sha256sums-output FILE` replaces `--stage-dir` and `--builder-output-dir`: it
only derives `SHA256SUMS` from the attestations. Operators and the coordinator
can use it to compare manifests before anyone signs.

The tool prints `key=value` lines, including `stage_dir`, `artifact_count`,
one `artifact` line per file, `counted_core`/`counted_photon`,
`sha256sums_path` and `sha256sums_sha256`.

## Sign: `sign-sha256sums.py`

```sh
contrib/release-process/sign-sha256sums.py \
  --trusted-release-ref "$TRUSTED_RELEASE_REF" \
  --release-line mainnet \
  --stage-dir ../staged-release \
  --alias operator-02 \
  --expected-sha256sums-sha256 "$SHA256SUMS_SHA256"
```

The tool resolves `--alias` to its `signing_fingerprint` in the trusted policy;
the alias must be an active `release-signing` signer of the release line.
`--expected-fingerprint` is an optional cross-check. Before signing it checks
that `SHA256SUMS` parses, that every listed artifact is present with its digest,
that the directory holds nothing else (apart from per-operator signatures of
active signers and `SHA256SUMS.asc`), and, when given, that `SHA256SUMS` has
the expected digest. Pass the `sha256sums_sha256` from your own staging run so
that you only sign the manifest you derived yourself.

It signs with the operator's existing GnuPG setup (`GNUPGHOME`, smartcard or
keyring):

```sh
gpg --batch --armor --detach-sign --digest-algo SHA256 \
  --local-user '<signing_fingerprint>!' --output <scratch>/SHA256SUMS.<alias>.asc <scratch>/SHA256SUMS
```

The `!` makes GnuPG use exactly the policy's signing subkey even if the
certificate has a newer one. The tool never exports, imports or reads private
key material. It verifies the new signature against the public certificate from
the trusted policy, in a temporary keyring, and requires the signer fingerprint
to be exactly the policy's. Only then does it move `SHA256SUMS.<alias>.asc` into
the stage directory, the asset name the v1.0.0 release used. If any step fails,
no signature file is written.

Without `--yes` it shows the signer, fingerprint and `SHA256SUMS` digest and
asks for confirmation, and it refuses to run without a terminal. A valid
existing signature by the same signer is kept (`status=unchanged`); an existing
file that does not verify is never replaced.

## Combine: `combine-sha256sums-signatures.py`

```sh
contrib/release-process/combine-sha256sums-signatures.py \
  --trusted-release-ref "$TRUSTED_RELEASE_REF" \
  --release-line mainnet \
  --stage-dir ../staged-release
```

The directory must hold `SHA256SUMS` and the collected
`SHA256SUMS.<alias>.asc` files. Each file must be a single ASCII-armored
signature, named for an active release-signing signer of the release line and
verifying against `SHA256SUMS` with exactly that signer's fingerprint. The
signers must be distinct and at least the line's `release_signature_quorum`.
Any other `SHA256SUMS*` file, or any signature that fails these checks, stops
the tool. It does not hash the artifacts; the signing tool and the publisher do.

`SHA256SUMS.asc` is the byte concatenation of the per-operator files in alias
order, which is how v1.0.0's was made. It is verified as a combined signature
before it is moved into place. An existing `SHA256SUMS.asc` is kept only if it
is byte-identical (`status=unchanged`); otherwise the tool refuses to overwrite
it.

The stage directory is then ready for `publish-local-release.sh`.

## Failure behaviour

All outputs are written to a scratch directory next to their destination and
moved into place only after they verify, without replacing an existing file. A
failure or interruption leaves no partial `SHA256SUMS`, `SHA256SUMS.<alias>.asc`
or `SHA256SUMS.asc` at the destination. The tools exit non-zero and print one
`ERR:` line on failure.

## Reproducing v1.0.0

The tools reproduce the published v1.0.0 manifests byte-for-byte. The
`SHA256SUMS.asc` reproduction and the `SHA256SUMS` derivation rule are covered
by `ci/release/test_release_staging_tools.py` with the public v1.0.0 inputs
embedded. Deriving `SHA256SUMS` end to end also reconstructs the source archive
from the `v1.0.0` tag, so it is a manual check:

```sh
# A clean qbit checkout at a trusted ref that has these tools and the v1.0.0 tag.
gh release download v1.0.0 --repo Qbit-Org/qbit --pattern 'SHA256SUMS*' --dir v1.0.0
git -C ../qbit-guix.sigs checkout --detach c18adfe292cf54cbee73ff86d0f1d3619a8ffea3

contrib/release-process/stage-release-artifacts.py \
  --trusted-release-ref "$(git rev-parse HEAD)" --release-line mainnet --tag v1.0.0 \
  --guix-sigs-dir ../qbit-guix.sigs --allow-unsigned-platform-artifacts \
  --sha256sums-output derived/SHA256SUMS
cmp derived/SHA256SUMS v1.0.0/SHA256SUMS

mkdir combined && cp v1.0.0/SHA256SUMS v1.0.0/SHA256SUMS.operator-0?.asc combined/
contrib/release-process/combine-sha256sums-signatures.py \
  --trusted-release-ref "$(git rev-parse HEAD)" --release-line mainnet --stage-dir combined
cmp combined/SHA256SUMS.asc v1.0.0/SHA256SUMS.asc
```

The expected digests are
`14d885f6bb86ebcf41e764f5d5c31412ae75774ce5634f68bc7caf97c52102fe` for
`SHA256SUMS` (19 artifacts) and
`4bcaaa01a34693e56e611212cafe097720a8494bbede2b2d492a4744d8ee6b1e` for
`SHA256SUMS.asc`. All three operators attested the same 21 core files and the
same 3 PHOTON files. The 23 distinct names, minus the source tarball and the
three codesigning payloads, are the 19 published lines; v1.0.0 was published
with the unsigned-platform waiver.

## Tests

```sh
python3 ci/release/test_release_staging_tools.py
```

The tests generate throwaway keys in a temporary `GNUPGHOME` and build every
checkout, attestation and builder output they use. They need `git` and `gpg`.
