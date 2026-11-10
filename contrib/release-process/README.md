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
`ci/release/`: `validate_builder_attestations.py` decides which builder
attestations count, and `validate_release_artifacts.py` decides which attested
files are public release assets, parses every `SHA256SUMS` and decides which
signatures count. Staging also runs the publisher's checks that need nothing
staged, so a release that cannot be published fails before anyone signs: the
qbit-guix.sigs key-policy mirror (`validate_key_metadata.py` and
`validate_builder_attestations.py`, with the publisher's arguments) and the
release tag's signature by an active release key. The tag checked is the tag
object at `refs/tags/<tag>`, passed to `git verify-tag` by object id, and it
must name `<tag>`: a bare tag name would let a stray `refs/<tag>` or
`.git/<tag>`, which git resolves first and `git status` does not show, stand in
for it, and a signed tag of another release cannot be moved to this name.
`publish-local-release.sh` checks the tag the same way: it reads exactly
`refs/tags/<tag>` and calls the validator's `verify_tag_signature` on that
object instead of passing the bare name to `validate_release_artifacts.py
--verify-tag-signature`, and it refuses a checkout where the bare name
resolves to anything else, since the testnet posture check still takes it.
The publisher's GitHub checks
(public refs, the GitHub-verified tag, release immutability) and the mainnet,
testnet and P2MR posture checks still run only at publication.

Run the tools as `python3 -I -S -B <tool>`: no `PYTHONPATH`, user or site
packages, `sitecustomize`/`usercustomize` hooks or bytecode. They need only the
standard library. Started any other way, a tool runs itself again with those
flags, but startup hooks the first interpreter ran cannot be undone.

## Trust anchor

Every tool takes `--trusted-release-ref SHA` and must run from a clean qbit
checkout whose `HEAD` is that commit; it refuses to run otherwise. Clean means
more than an empty `git status`:

- no file under `contrib/release-process`, `ci/release` or `contrib/keys` is
  marked assume-unchanged or skip-worktree (`git ls-files -v` shows only `H`);
- `contrib/release-process` holds no untracked or ignored files, such as a
  stray `.pyc`;
- the running tool and `release_staging_common.py` are byte-identical to their
  blobs at the ref (a checkout that converts line endings, for example with
  `core.autocrlf=true`, is refused with a message saying so: use a checkout
  made with `core.autocrlf=false`);
- the checkout is not shallow and not a partial clone (the tools never fetch).

Every git command, the tools' and the validators', runs without the caller's
`GIT_*` variables (`GIT_DIR`, `GIT_INDEX_FILE`, object and config overrides),
with replace refs ignored (`GIT_NO_REPLACE_OBJECTS=1`) and an empty graft file,
so a local `git replace` or graft cannot make the tools read anything but the
commit's own objects. `git status` does not write the index
(`GIT_OPTIONAL_LOCKS=0`) or enter submodule checkouts
(`--ignore-submodules=dirty`), nothing pages (`GIT_PAGER=cat`), and nothing is
fetched (`GIT_NO_LAZY_FETCH=1`, and `GIT_ALLOW_PROTOCOL=none`, which outranks
any `protocol.*` config), so a partial-clone remote cannot turn a missing
object into an ssh or helper run; partial clones are refused up front.
`GIT_CONFIG_COUNT` overrides, which outrank the system, user and repository
config, keep that config from running programs or changing history: fsmonitor
off (`core.fsmonitor` empty), hooks off, `core.commitGraph=false` (a
commit-graph file can claim other parents, as a graft could), no signature
program except the validators' own for `git verify-tag` (only OpenPGP tags
verify), `git archive`'s gzip and file modes pinned to git's defaults
(`tar.tar.gz.command`, `tar.umask`), and every filter driver the checkout's
config defines gets empty `clean`, `smudge` and `process` commands, since `git
status` and `git archive` would run them. `advice.graftFileDeprecated=false`
only silences git's hint about the empty graft file. `GIT_CONFIG_COUNT` needs
git 2.31 or newer, and the tools refuse an older git.
`publish-local-release.sh` does the same for the trusted and qbit-guix.sigs
checkouts, and reads the qbit-guix.sigs files from the `--guix-sigs-ref`
commit's objects.

The validators (`ci/release/`) and the release key policy
(`contrib/keys/operator-keys/`: `keys.json` and the public certificates) are not
read from the working tree at all. The tools export their blobs at the ref into
a private scratch directory and load them from there, so index flags, ignored
files or stale bytecode in the checkout cannot change them. The tools never
import modules by name from their own directory and neither read nor write
`__pycache__`. No option or environment variable chooses which `keys.json`,
certificates or validators are read. `--gpg` (default: `gpg` on `PATH`) chooses
the gpg executable that makes every signature check and signature, so it
decides whether signatures verify; it exists for tests, the qbit-tools wrappers
never pass it, and the tools print a `note:` when it is not the default.
`--release-line` (`testnet` or `mainnet`) is always required and selects the
quorums and the eligible signers from that policy.

### One ref and one policy for a release

The publisher's `trusted_release_ref` is only defined after staging, so the
staging steps use their own pinned ref:

1. Before staging, the coordinator pins `STAGING_REF`: the full SHA of a public
   commit on the release branch that contains these tools and descends from the
   release tag target, and records it in the release issue. Staging, every
   signature and the combination all run with
   `--trusted-release-ref "$STAGING_REF"`, from a checkout that has the release
   tag:

   ```sh
   git fetch --tags origin
   git checkout --detach "$STAGING_REF"
   git status --porcelain   # must print nothing
   ```

2. Every tool prints `policy_sha256`, the SHA256 of `keys.json` at the ref.
   Record it in the release issue next to `sha256sums_sha256`, and compare both
   across operators before anyone signs.
3. At publication, `publish-local-release.sh` reports the policy it validated
   with (`Key policy: sha256=…`, the validator's `keys_json_sha256`). It must
   equal the recorded `policy_sha256`. If it does not, the signatures were
   checked against a different policy: stop, and stage and sign again at a ref
   with the publisher's policy.
4. The waivers passed to staging (`--allow-unsigned-platform-artifacts`,
   `--allow-codesigning-artifacts`) must be exactly the ones passed to
   `publish-local-release.sh`. Record them in the release issue too.

## Stage: `stage-release-artifacts.py`

```sh
python3 -I -S -B contrib/release-process/stage-release-artifacts.py \
  --trusted-release-ref "$STAGING_REF" \
  --release-line mainnet \
  --tag v1.0.1 \
  --guix-sigs-dir ../qbit-guix.sigs \
  --builder-output-dir guix-build-1.0.1/output \
  --builder-output-dir guix-build-1.0.1/output-photon \
  --stage-dir ../staged-release
```

`--guix-sigs-dir` is read as a directory, not pinned to a commit. Stage from
a clean qbit-guix.sigs checkout at the merged commit that will be the
publisher's `--guix-sigs-ref`: the publisher validates the files of that
commit, read from its git objects (and requires a clean checkout at it), so
signatures over a manifest staged from anything else are refused there.

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
   manifests bound to the source archive reconstructed from the signed tag.
   The tool does not count builders itself: `validate_artifact_attestations`
   from `ci/release/validate_builder_attestations.py`, the function the
   publisher uses, decides whether a set reaches the quorum. If one builder
   attested less (for example a skipped platform), the larger quorum-attested
   set wins and the builder is reported as not counted. Conflicting sets that
   both reach quorum are refused.

It then copies each artifact from the builder output directories into a scratch
directory next to `--stage-dir`, checks every copy against its attested digest,
writes `SHA256SUMS`, validates the result with the publisher's functions
(including the builder quorum again, over the written `SHA256SUMS`), and only
then renames the scratch directory to `--stage-dir`. A file in the builder
outputs that looks like a release asset but is not in the counted set, a
missing or duplicated artifact, or any digest mismatch stops the tool, and no
stage directory is left behind.

`SHA256SUMS` has one `<sha256>  <file name>` line per artifact (two spaces, LF
line endings), sorted by file name. That is the format of the v1.0.0 release.

Re-running with the same inputs is a no-op (`status=unchanged`), after the
existing stage passes the same publisher checks a new one gets (artifact names
and the builder attestations over its `SHA256SUMS`), since the attestations,
the key mirror or the policy may have changed since it was staged. An existing
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
python3 -I -S -B contrib/release-process/sign-sha256sums.py \
  --trusted-release-ref "$STAGING_REF" \
  --release-line mainnet \
  --stage-dir ../staged-release \
  --alias operator-02 \
  --expected-sha256sums-sha256 "$SHA256SUMS_SHA256"
```

The tool resolves `--alias` to its `signing_fingerprint` in the trusted policy;
the alias must be an active `release-signing` signer of the release line.
`--expected-fingerprint` is an optional cross-check.
`--expected-sha256sums-sha256` is required: the `sha256sums_sha256` from your
own staging run (`--sha256sums-output` is enough), so that you only sign the
manifest you derived yourself, never one someone else put in the stage
directory, with `--yes` or without. Before signing the tool checks that
`SHA256SUMS` has that digest, that it parses, that every listed artifact is
present with its digest, and that the directory holds nothing else (apart from
per-operator signatures of active signers and `SHA256SUMS.asc`).

It reads `SHA256SUMS` once into a private copy (mode 0600, in a 0700 scratch
directory) and checks the staged files, the expected digest and the signature
against those same bytes. The copy's digest is checked again immediately before
and after signing. It signs with the operator's existing GnuPG setup
(`GNUPGHOME`, smartcard or keyring), leaving gpg's stdin on the terminal:

```sh
gpg --batch --armor --detach-sign --digest-algo SHA256 \
  --local-user '<signing_fingerprint>!' --output <scratch>/SHA256SUMS.<alias>.asc <scratch>/SHA256SUMS
```

A curses or tty pinentry asks for the smartcard PIN on the terminal named by
`GPG_TTY`. The tool passes `GPG_TTY` through and sets it from its own terminal
when it is unset; set it yourself (`export GPG_TTY=$(tty)`) when stdin is not
the terminal. GUI pinentries such as pinentry-mac do not need it.

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
python3 -I -S -B contrib/release-process/combine-sha256sums-signatures.py \
  --trusted-release-ref "$STAGING_REF" \
  --release-line mainnet \
  --stage-dir ../staged-release
```

The directory must hold `SHA256SUMS` and the collected
`SHA256SUMS.<alias>.asc` files. Besides the artifacts `SHA256SUMS` lists (which
need not be present), anything else stops the tool, including a temporary file
left by a killed run. `SHA256SUMS.asc` is the byte concatenation of the
per-operator files in sorted alias order, which is how v1.0.0's was made.

The tool does not count signers itself. It accepts the set exactly when the
publisher's release-signature check accepts it: each file is checked with
`verify_manifest_signature_file` and the assembled `SHA256SUMS`, per-operator
files and `SHA256SUMS.asc` with `verify_manifest_signatures`, both from
`ci/release/validate_release_artifacts.py` at the trusted ref. Which signers
count, and the line's `release_signature_quorum`, are therefore whatever that
validator enforces, and so is the signature format: armor the publisher
accepts, CRLF line endings for example, combine and sign accept too. A test
asserts that the tool and that check agree on the same inputs. The combined
file is moved into place only after it passes. It does not hash the
artifacts; the signing tool and the publisher do.

An existing `SHA256SUMS.asc` is kept only if it is byte-identical
(`status=unchanged`); otherwise the tool refuses to overwrite it.

The stage directory is then ready for `publish-local-release.sh`.

## Failure behaviour

All outputs are assembled in a private scratch directory next to their
destination (`.<name>.tmp-*`) and moved into place only after they verify.
That directory is next to `--stage-dir`, so all three tools refuse a
`--stage-dir` that is a mount point (for example `/media/$USER/RELEASE` or
`/Volumes/RELEASE`), where it would be outside the mount and usually not
writable: keep the stage in a directory inside the mount. Where hard links are
not available (exFAT media, some network filesystems), the verified file is
written to a temporary file in the destination directory, flushed to disk and
renamed into place. The destination is never partially written, but on that
path refusing to overwrite is best effort: a file that appears between the
check and the rename is replaced.

SIGINT, SIGTERM, SIGHUP and I/O errors such as a full disk end a tool with a
single `ERR:` line. A signal that arrives while scratch is being removed waits
until it is gone. The message says what is actually on disk: whether scratch
was removed or which directory is left, and whether any output had already been
written. SIGKILL or a power loss can leave a scratch directory next to the stage
(the next run lists it in a `note:`) or a temporary file inside it; stage, sign
and combine refuse a stage directory holding such a file, or any file it should
not hold, and say which to delete.

The stage directory gets the mode a plain `mkdir` would give it (0755 under the
usual umask 022) and the files 0644, so a separate account can publish from
it; the publisher only reads the stage.

## Reproducing v1.0.0

The tools reproduce the published v1.0.0 manifests byte for byte. The
`SHA256SUMS.asc` reproduction and the `SHA256SUMS` derivation rule are covered
by `ci/release/test_release_staging_tools.py` with the public v1.0.0 inputs
embedded. Deriving `SHA256SUMS` end to end also reconstructs the source archive
from the `v1.0.0` tag, so it is a manual check. Its inputs are:

- `REF`: a Qbit-Org/qbit commit that contains these tools, taken from a release
  issue (its `STAGING_REF`) or the release branch, not from the checkout itself;
- `QBIT`: a clean checkout of Qbit-Org/qbit at `REF`, with the `v1.0.0` tag;
- the v1.0.0 policy: the run must print
  `policy_sha256=f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`,
  the `keys.json` SHA256 recorded in `doc/release-trust-1.0.0.md`;
- the published `SHA256SUMS*` assets of the v1.0.0 GitHub Release;
- qbit-guix.sigs commit `c18adfe292cf54cbee73ff86d0f1d3619a8ffea3`, the `main`
  merge of the last v1.0.0 attestation (pull request 10).

```sh
QBIT=/path/to/qbit
REF=<full commit SHA>
git -C "$QBIT" fetch --tags origin
git -C "$QBIT" checkout --detach "$REF"
test -z "$(git -C "$QBIT" status --porcelain)"

work=$(mktemp -d)
gh release download v1.0.0 --repo Qbit-Org/qbit --pattern 'SHA256SUMS*' --dir "$work/published"
git clone --quiet https://github.com/Qbit-Org/qbit-guix.sigs "$work/qbit-guix.sigs"
git -C "$work/qbit-guix.sigs" checkout --quiet --detach c18adfe292cf54cbee73ff86d0f1d3619a8ffea3

python3 -I -S -B "$QBIT"/contrib/release-process/stage-release-artifacts.py \
  --trusted-release-ref "$REF" --release-line mainnet --tag v1.0.0 \
  --guix-sigs-dir "$work/qbit-guix.sigs" --allow-unsigned-platform-artifacts \
  --sha256sums-output "$work/derived/SHA256SUMS" > "$work/stage.out"
grep -Fx policy_sha256=f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f "$work/stage.out"
cmp "$work/derived/SHA256SUMS" "$work/published/SHA256SUMS"

mkdir "$work/combined"
cp "$work/published/SHA256SUMS" "$work"/published/SHA256SUMS.operator-0?.asc "$work/combined/"
python3 -I -S -B "$QBIT"/contrib/release-process/combine-sha256sums-signatures.py \
  --trusted-release-ref "$REF" --release-line mainnet --stage-dir "$work/combined" > "$work/combine.out"
grep -Fx policy_sha256=f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f "$work/combine.out"
cmp "$work/combined/SHA256SUMS.asc" "$work/published/SHA256SUMS.asc"
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
