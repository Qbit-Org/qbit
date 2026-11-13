# Release Publisher Reference

This reference describes what `contrib/release-process/publish-local-release.sh`
and the `ci/release/` validators enforce, and what the
[release runbook](release-process.md) leaves to process. Line numbers drift,
so it names functions and checks rather than lines. When this page and the
script disagree, the script is authoritative; run it with `--help` for the
option list.

The release model is:

```text
reviewed release-branch commit -> signed annotated tag -> Guix builds and attestations
  -> signed SHA256SUMS -> trust record -> local publisher -> immutable GitHub Release
```

The local publisher is the only supported publication path. There is no
GitHub Actions publisher:
[#135](https://github.com/Qbit-Org/qbit/pull/135) removed it, so a release
has no workflow inputs and no workflow run.

## Release source and tags

The release source is the commit that the signed annotated tag points to (the
tag target). v1.0.1 is being cut from `1.x.x`, the active 1.x maintenance
branch; v1.0.0 was cut from `main`, which has been unchanged since the
v1.0.0 trust record. `1.1.0` was forked from `1.x.x` to prepare 1.1.0.
v1.0.1 reaches `main` by an admin fast-forward; the longer-term branch model
is pending an operator decision. The runbook lists the
[branches and release lines](release-process.md#branches-and-release-lines).

The publisher's `--release-line` must be `mainnet` or `testnet`. The artifact
validator also requires a testnet tag to contain `testnet` and a mainnet tag
not to. `--tag` must match `^v[A-Za-z0-9][A-Za-z0-9._-]*$`. The tags pushed so
far are `v0.1.0-testnet4`, `v0.1.1-testnet4`, `v0.1.2-testnet4` and `v1.0.0`.
Names such as `v1.0.1-rc1` or `v0.1.0-testnet4-rc1` are format examples. As
of 2026-11-10, the repository has no rc tags. Whether a release has release
candidates is decided per release.

**Testnet releases** require `--testnet-posture-evidence FILE`; the
publisher exits before validation without it. It passes the file to
`ci/release/verify_testnet_release_posture.py` together with the tag and the
staged artifacts, and forwards `--allow-unsigned-platform-artifacts` and
`--allow-codesigning-artifacts` to that validator. Whether testnet-only
releases continue is pending an operator decision.

Never use a branch name, a short SHA, a tag object SHA or an unpublished
commit as the release source.

## Tag pinning

At startup the publisher reads exactly `refs/tags/<TAG>` from the trusted
checkout (`git show-ref --verify`), and pins that tag object and its target
commit. It refuses the tag unless:

- the ref holds an annotated tag object, and that object's own `tag` header
  names `<TAG>`, so a signed tag of another release cannot stand in for it;
- the bare name `<TAG>` resolves to the same object. Git looks a bare name up
  as `.git/<TAG>` and `refs/<TAG>` before `refs/tags/<TAG>`, and `git status`
  shows neither.

It then checks GitHub (`verify_remote_tag_pin`):

- the remote ref `tags/<TAG>` is of type `tag`, and its object equals the
  pinned tag object;
- that tag object targets a commit, and the commit equals the pinned target;
- GitHub reports the signature as exactly `verified=true` and
  `reason=valid`.

It runs this check before validation, again immediately before `--publish`
makes the release public, and once more after publication. Separately, the
publisher passes the pinned tag object, not the tag name, to the artifact
validator's `verify_tag_signature`, which runs `git verify-tag` against the
policy's keys and requires a signature from an active `release-signing` key
for the release line. GitHub reports `verified=true` only when the signing key
is on a GitHub account whose verified email matches the tagger.

The `public-release-tags-v-immutability` ruleset blocks updating or deleting
`v*` tags, but organization admins can bypass it. The tag pin is what
detects a tag that was moved after it was pinned.

## Trusted release ref

`--trusted-release-ref` names the commit whose validators and key policy the
publisher uses. Source binding still reconstructs the source archive from the
tag target, not from this checkout.

**Enforced by the publisher:**

- the value is a full 40-character SHA;
- the publisher script runs from a git checkout whose `HEAD` equals that SHA;
- the checkout is clean, with untracked files counted (`git status
  --porcelain --untracked-files=normal --ignore-submodules=dirty`), and it is
  neither shallow nor a partial clone;
- no file under `contrib/release-process`, `ci/release` or `contrib/keys` is
  marked assume-unchanged or skip-worktree;
- the SHA holds every validator the publisher calls and
  `contrib/keys/operator-keys/keys.json`. The publisher exports `ci/release`
  and `contrib/keys/operator-keys` from the SHA's git objects and runs the
  validators from that export (`python3 -E -s -S -B`), so the working tree,
  the index and stale bytecode cannot change them;
- the SHA is neither the tag object nor the tag target;
- the tag target is on the SHA's first-parent history;
- GitHub serves the commit from the target repository (`remote_commit`,
  through the commits API).

Every git command the publisher and the validators run reads only real
objects. The caller's `GIT_*` variables are cleared, replace refs are ignored
(`GIT_NO_REPLACE_OBJECTS=1`), the graft file is empty, and nothing is fetched
(`GIT_NO_LAZY_FETCH=1`, `GIT_ALLOW_PROTOCOL=none`). `GIT_CONFIG_COUNT`
overrides keep the checkouts' config from running hooks, fsmonitor, filter
drivers or a signature program other than OpenPGP, and from using a
commit-graph. The publisher therefore requires git 2.31 or newer.
[contrib/release-process/README.md](../../contrib/release-process/README.md)
describes the same isolation for the staging tools.

The publisher also requires the SHA to be on the first-parent history of the
trusted release branch, `--trusted-release-branch` (default `main`; a release
line passes its own branch, such as `1.x.x`). GitHub must report that branch
as protected, with `non_fast_forward` and `deletion` among its active rules.
The publisher reads the branch's tip from GitHub, and the checkout must
already have that tip, because the publisher never fetches.

**Process, not enforced:** the publisher does not check reviews. By process,
`trusted_release_ref` is the commit that lands the trust-record PR on the
release branch, and the trust record states how it was chosen. A later
revision of the trust record never moves it.

## `qbit-guix.sigs` pin

`--guix-sigs-repo` and `--guix-sigs-ref` name a local clone of
`Qbit-Org/qbit-guix.sigs` and the commit to count. The publisher requires:

- a full 40-character SHA, and a clean clone whose `HEAD` equals it, which
  is not a partial clone and has no assume-unchanged or skip-worktree flags;
- the commit exists on GitHub (`--guix-sigs-github-repo`, default
  `Qbit-Org/qbit-guix.sigs`);
- the commit is on the first-parent history of `--guix-sigs-branch`, default
  `main`, which GitHub reports as protected with `non_fast_forward` and
  `deletion` rules, at the tip GitHub reports, which the clone must already
  have; a pull request head is refused;
- the clone's `operator-keys/` mirror matches the trusted key policy
  ([key policy](#key-policy)).

The validators read `operator-keys/` and the release's `<version>/`
attestations from that commit's git objects, exported to a work directory,
not from the clone's working tree.

## Staged artifact directory

`--artifacts-dir` must be a flat directory of regular files. The staging,
signing and combining tools in `contrib/release-process` build it with the
publisher's own validators (runbook
[step 3](release-process.md#3-stage-sign-and-combine-sha256sums)). It must
contain exactly:

- every artifact listed in `SHA256SUMS`, each with a matching digest;
- `SHA256SUMS` itself, which must not list itself or any signature file;
- one `SHA256SUMS.<alias>.asc` per counted signer, where each alias is an
  active `release-signing` signer for the release line;
- `SHA256SUMS.asc`, the concatenation of the individual `.asc` files in
  sorted alias order, as `combine-sha256sums-signatures.py` writes it. The
  validator checks that its valid signer set equals the set of valid
  individual signatures; it does not check the order.

Artifact names must start with `qbit-<version>-` or `qbit-photon-<version>-`
and end in `.tar.gz`, `.tar.xz`, `.zip`, `.dmg` or `.exe`. A name with an
`-unsigned` component needs `--allow-unsigned-platform-artifacts`, and a name
with a `-codesigning` component needs `--allow-codesigning-artifacts`.
At least one core artifact is required, and `--require-photon` also requires
a PHOTON artifact. The source archive `qbit-<version>.tar.gz` does not match
these name rules, so the staged `SHA256SUMS` must leave it out; it is builder
evidence only (see [guix.md](guix.md)). The release-signature quorum is
`release_signature_quorum` for the release line in `keys.json`, counted by
distinct primary keys ([key policy](#key-policy)). Every file in the
directory is uploaded.

## Builder attestations

`ci/release/validate_builder_attestations.py` looks for each builder's
manifest under `<version>/<alias>/` in the `qbit-guix.sigs` clone. It reads
`all.SHA256SUMS` or, failing that, `noncodesigned.SHA256SUMS`, with a
`photon-` prefix for PHOTON. It counts a builder only when:

- the alias is an active `builder-attestation` signer for the release line,
  and lists that artifact set in `artifact_sets`;
- the manifest's detached signature (`<manifest>.asc`) is a good signature
  by that builder's key ([key policy](#key-policy));
- the manifest covers every release artifact of that set, with matching
  digests;
- the manifest contains the canonical source archive, reconstructed from the
  tag target (see [guix.md](guix.md)).

Each artifact set needs `builder_attestation_quorum` builders with distinct
primary keys: builders whose signing keys share a primary key count once.
PHOTON is checked when `--require-photon` is given or the staged set contains
PHOTON artifacts.

## Key policy

The canonical release key policy is `contrib/keys/operator-keys/` at
`trusted_release_ref`: `keys.json` and the signers' public certificates.
[contrib/keys/README.md](../../contrib/keys/README.md) describes it, its
rotation chain, and every consumer. `qbit-guix.sigs` keeps `operator-keys/`
as a derived, non-authoritative mirror. The publisher requires the mirror at
the pinned commit to match the canonical policy, twice:
`validate_key_metadata.py --operator-policy-mirror` compares the validated
projections, policy SHA-256 included, and `validate_builder_attestations.py
--guix-operator-key-policy` requires exactly the canonical file set, byte for
byte. A mirror that differs stops the release. The mirror never grants trust:
attestations and release signatures are verified only with the
trusted-ref keys.

The validators count a signature only when gpg's `GOODSIG` and `VALIDSIG`
agree on the key, `VALIDSIG` names the primary key, and gpg reports nothing
against it (`REVKEYSIG`, `EXPKEYSIG`, `ERRSIG`, `BADSIG`, `EXPSIG`,
`NO_PUBKEY`). A signature by a revoked or expired key therefore never counts.
Release-signature and builder quorums count distinct primary keys. Validating
the policy itself requires each certificate to hold exactly one primary key
and the signer's signing key; an active signer's key must be
signing-capable and not revoked, and no two active signers may share a
primary key.

A pull request that changes `contrib/keys/` runs the key-policy checks in
the Required Merge Gate against the base branch's policy: the policy chain
(the next `policy_sequence`, and `previous_policy_sha256` equal to the base
`keys.json` digest) and certificate continuity. A changed certificate must
keep its primary key, its keys and its signature records, and may only add
to them, such as a refreshed self-signature or a subkey that the new
`keys.json` names. Because those checks live in code a pull request can
change, the Key Policy Gate (`.github/workflows/key-policy-gate.yml`) also
runs them with the base branch's own code, for pull requests into `main` and
`1.x.x`. It is armed after v1.0.1 reaches `main`
([runbook](release-process.md#after-the-release)).

## Debug symbol archives

Each platform's stripped release binaries have a debug symbol archive from the
same Guix build ([all build outputs](guix.md#build-outputs)):

| Platform | Archive | Contents |
| --- | --- | --- |
| Linux | `qbit-<version>-<host>-debug.tar.gz` | a `.dbg` file per binary in `bin/` and `libexec/` |
| Windows | `qbit-<version>-win64-debug.zip` | a `.dbg` file per binary in `bin/` and `libexec/` |
| macOS | `qbit-<version>-<host>-debug.tar.gz` | a `.dSYM` bundle per binary in `bin/` and `libexec/` |

The macOS archive starts with v1.0.1; v1.0.0 and earlier releases have none.
Its bundles are linked with `dsymutil` from unstripped copies of the binaries,
so the stripped binaries and the other macOS archives are unchanged. Stripping
and codesigning keep each binary's `LC_UUID`, so a bundle also matches the
codesigned binaries and the binary inside `qbit-qt.app`.

The debug archives are release artifacts. They are part of every builder's
`noncodesigned.SHA256SUMS` and `all.SHA256SUMS`, so builders reproduce and
attest them like the binaries. They are staged, listed in `SHA256SUMS` and
uploaded with the rest of the release. They contain no executables and need no
unsigned-platform waiver. The validators require nothing per platform, so a
staged release without a macOS debug archive also validates. If one is staged,
every counted builder manifest must cover it.

## Mainnet launch posture

For `--release-line mainnet`, the publisher runs
`ci/release/verify_mainnet_release_posture.py` against the tag target. It reads
the tagged files from git, not from the working tree, and it has no waiver. It
fails unless:

- the mainnet AuxPoW chain ID is final, differs from testnet4's, and a unit
  test asserts the difference;
- the genesis and ASERT launch artifact records final provenance, and
  chainparams keep their genesis-hash, Merkle-root and ASERT assertions;
- there are at least two unique `*.qbit.org` DNS seeds and two unique numeric
  fixed seeds, `src/chainparamsseeds.h` matches
  `contrib/seeds/nodes_main.txt`, both `m_assumed_*` size hints are `0`, and
  the bootstrap unit test asserts the seed set and the zero hints;
- CMake and Guix default `QBIT_TESTNET_ONLY_RELEASE` to `OFF`, and unit tests
  assert that default and explicit mainnet selection.

**CI coverage.** Core Checks runs the same validator in its `mainnet
publication posture` job, gated by `mainnet_publish_gate_required` in
`.github/workflows/core-checks.yml`, and the validator's exit status decides
the job. Each branch runs its own copy of that workflow. Since
[#385](https://github.com/Qbit-Org/qbit/pull/385), `1.x.x`'s copy runs the
job when the target branch is a mainnet line (`main`, or a release branch of
major version 1 or later, such as `1.x.x`, `1.1.0` or `1.0.0`; the `0.x`
lines are testnet) and the change profile is `source` or `release-policy`.
`1.1.0` and `1.0.0` gate themselves in their own copies, and `main` keeps
its older rule, which covers only `1.0.0`, until it is fast-forwarded after
v1.0.1. A commit whose change has another profile, such as docs only, skips
the job. It was skipped at the v1.0.0 tag target, and at the `1.x.x` commit
that [#174](https://github.com/Qbit-Org/qbit/issues/174) tested. Where it is
skipped, the runbook's
[manual posture check](release-process.md#candidate-checks) stands in for
it. CI results do not decide publication: the publisher runs the validator
itself, with no waiver.

## P2MR v1 conformance inputs

Mainnet publication requires three absolute paths:

- `--p2mr-v1-conformance-evidence`: the release evidence envelope;
- `--p2mr-v1-oracle-report`: the canonical standalone-oracle report;
- `--p2mr-v1-integration-matrix`: the finalized integration support
  inventory.

For testnet they are optional, but they must be given all together or not at
all. The publisher passes them to `ci/release/verify_p2mr_v1_conformance.py`.
That validator runs from the trusted checkout, but reads the specification,
manifest and corpus as git blobs from the tag target. It requires the qbit
result, the oracle report, the consensus review and the finalized matrix to
name that same commit; a review of an ancestor fails.

The checked-in
[`p2mr-v1-support-matrix.json`](../integration/p2mr-v1-support-matrix.json)
is a blocking draft and cannot be used as release evidence. The
[evidence example](examples/p2mr-v1-conformance-evidence.json) is a field
example whose zero hashes and `example.invalid` references cannot validate.

To prepare the inputs:

1. Record the tag target of the signed tag.
2. Run the complete qbit P2MR v1 unit suite on that commit.
3. Run the standalone oracle in release mode on that commit, and keep its
   canonical report.
4. Recalculate the tagged manifest digest and every corpus digest it lists.
5. Complete a finalized copy of the integration matrix whose
   `release_source_commit` is the tag target. Every required in-tree surface
   must be `supported` and `pass`, with `version` equal to the tag target,
   an `owner` and its `limitations`,
   plus an environment, a review date and stable public evidence. Leave
   unsupported external categories as explicit `not-claimed` rows.
6. Run the consensus review on the tag target and keep a stable public
   reference to it.
7. Build the evidence envelope from the field example, replacing every
   placeholder.
8. Run the validator locally with a checkout that has the tag:

   ```sh
   python3 ci/release/verify_p2mr_v1_conformance.py \
     --evidence /path/to/conformance-evidence.json \
     --source-root "$PWD" \
     --release-tag "${TAG}" \
     --oracle-report /path/to/oracle-report.json \
     --integration-matrix /path/to/integration-matrix.json
   ```

9. Pass the same files to the publisher.
10. Keep the profile version, the tag target, the manifest digest, the oracle
    report digest, the matrix digest and the consensus review reference for
    the trust record.

**Release-note sentence.** Policy requires the published notes to contain
exactly one of:

```text
Conforms to qbit P2MR v1 corpus <digest> on source commit <SHA>; independent oracle report <digest>.
```

```text
This release does not claim completed qbit P2MR v1 conformance.
```

Do not substitute "BIP-360 compatible", "P2MR compatible" or "P2MR tested".
**The publisher does not enforce this**: it checks only that the notes file
is valid UTF-8. v1.0.0's published notes use neither form. Check the draft
body after `--create-draft` and before `--publish`.

## Release notes

With `--notes-file`, the publisher checks that the file is valid UTF-8 and
copies its bytes into the run's work directory before the long validators
run, so later edits to the source file cannot change the release body.
Without it, the publisher asks GitHub's generate-notes API for a body and
keeps that. On `--create-draft` and `--publish` it replaces the draft body,
reads it back, and requires an exact match. Manual edits to a draft are
therefore lost on the next run; put curated notes in a file.

## Drafts, resuming and metadata

The publisher lists releases with full pagination. A release counts as absent
only when that listing succeeds without a match; a failed lookup stops the
run.

- **No release:** validation-only mode reports that a draft would be created.
  `--create-draft` and `--publish` create it with `gh release create --draft
  --verify-tag`.
- **Draft exists:** its assets must be a digest-matching subset of the
  validated set. The publisher keeps those assets, uploads the missing ones,
  and never replaces an asset.
- **Published release exists:** `--create-draft` and `--publish` refuse to
  change it. Validation-only mode checks that it is immutable, that its assets
  exactly match, and that its tag pin is unchanged.

Validation-only mode prints a `gh release upload` command for each asset
that is not yet in the draft.

| Option | New draft | Resumed draft |
| --- | --- | --- |
| `--release-name` | Default `qbit <TAG>` | Kept unless given |
| `--prerelease` / `--no-prerelease` | Not a prerelease unless `--prerelease` | Kept unless given |
| `--make-latest true` | `latest=true` | Set to `true` |
| `--make-latest false` | `latest=false` | Set to `false` |
| `--make-latest auto` | GitHub's `legacy` mode (newest by creation date and version) | Set to `legacy` |
| `--make-latest` omitted | `latest=false`, also sent when `--publish` publishes a draft it created in the same run | No value is sent |

## Assets, publication and immutability

Asset inventories are compared only after a complete, paginated listing
succeeds. The publisher compares names and the SHA256 digests GitHub
computed. While it resumes, uploads to or publishes a draft, it retries the
listing and comparison up to five times, two seconds apart, to allow for API
propagation. Validation-only mode against an already published release lists
its assets once, without retries. If the listing fails, the publisher stops
with an error that names the asset-list request, before any upload, edit or
publication.
If that happens after publication, rerun the publisher in validation-only
mode once the listing is readable.

`--publish` checks the complete draft inventory, checks the tag pin, and sets
`draft=false`. It then polls, up to five times, until GitHub reports
`isDraft=false` and `isImmutable=true`, checks that the locked assets still
match exactly, and checks the tag pin a last time.

Release immutability must be enabled in the target repository's release
settings, or enforced by the organization, before publication. GitHub applies
the setting only to new releases. With `--repo OWNER/REPO`, the target
repository must meet the same requirement. If a release is published without
immutability, the publisher fails, and rerunning it does not fix the release;
it needs manual remediation.

## Immutable-publication recovery

A final tag-pin failure can happen after GitHub has made the release
immutable. The publisher then exits with an error that names the expected and
observed tag values; it cannot roll the publication back.

1. Stop distributing the release.
2. Preserve the complete publisher transcript, the release URL and ID, the
   expected and observed tag object and target, and the repository's audit
   log.
3. Do not rerun the publisher to repair or replace the release.
4. Handle the event through the release-integrity incident process. If the
   immutable release is to be removed, GitHub will not allow its tag name to
   be reused. Prepare a new version, sign a new annotated tag, repeat the
   whole validation and publication, and publish a correction notice that
   names the superseded release.

## Waivers

| Waiver | Mechanism | Record it in |
| --- | --- | --- |
| Unsigned platform artifacts | `--allow-unsigned-platform-artifacts` | Release notes and trust record |
| Public codesigning payloads | `--allow-codesigning-artifacts` | Release notes and trust record |

There is no CI waiver: Full Validation and the Required Merge Gate must be
green on the final commit before tagging
([#181](https://github.com/Qbit-Org/qbit/pull/181)). The publisher does not
read CI results. Whether to have a CI waiver policy is left to the operator.

For history: v1.0.0 shipped `-unsigned` macOS and Windows artifacts without a
recorded platform-signing waiver, and was tagged while a Full Validation run
that later failed was still in progress. Both are recorded in
[its trust record](../release-trust-1.0.0.md). An earlier release's waiver
does not carry over to a new release.

## Public evidence

Public release evidence pins public data only:

- the release version and signed tag;
- the tag object, tag target, signer fingerprint, tagger, tag date and
  GitHub verification result;
- `trusted_release_ref`, how it was chosen, and its review evidence;
- the exact-byte `keys.json` sha256, `policy_id` and `policy_sequence`, and
  the `STAGING_REF` the staging tools ran at, with their `policy_sha256`,
  which must equal it;
- the exact `qbit-guix.sigs` commit used for validation;
- the counted builder aliases and fingerprints for each artifact set;
- the canonical source archive name and sha256, and the tag target it came
  from;
- the counted release-signer aliases and fingerprints. The publisher prints
  builder and signer aliases only; each fingerprint is that alias's
  `signing_fingerprint` in the `keys.json` at `trusted_release_ref`;
- the sha256 of `SHA256SUMS`, of `SHA256SUMS.asc` and of each individual
  signature, and the artifact count;
- whether PHOTON was included, and its validation result;
- the publisher's printed `Pinned refs`, `Key policy`, `Artifacts`,
  `Release signatures`, `Builder attestations`, `Builder source` and
  `Evidence` lines, and its `Published immutable release assets exactly match
  local names and SHA256 digests` line, taken from the saved output of each
  run, and the ref it ran from;
- the release URL and its final immutable state;
- the P2MR v1 profile version, the tag target, the corpus manifest digest,
  the qbit result, the oracle report digest, the finalized matrix digest and
  the consensus review reference, or a statement that conformance is not
  claimed;
- the CI runs at the tag target, and any unsigned-platform or codesigning
  waiver.

Public evidence must not depend on private source commits, private operator
tooling state, operator key-custody records, or filled internal evidence
templates.

## Private operational material

Some operator tooling, ceremony logs, custody records, builder state and
platform-signing material are private. They may be needed to run a release,
but public verification never depends on them.
