# Mainnet Release Runbook

This is the checklist for cutting a qbit mainnet release from a release
branch; v1.0.1 is being cut from `1.x.x`. Open a tracking issue from the
**Release** issue template and tick the items there. What each tool checks,
and what is left to process, is in the
[publisher reference](publisher-reference.md).

The examples use these placeholders:

| Placeholder | Meaning | Example |
| --- | --- | --- |
| `VERSION` | Release version | `1.0.1` |
| `TAG` | Signed annotated tag | `v1.0.1` |
| `PREVIOUS_TAG` | The previous release's tag | `v1.0.0` |
| `RELEASE_BRANCH` | Branch the release is cut from | `1.x.x` |
| `TAG_TARGET` | Full SHA of the commit the tag points to | |
| `SIGNING_FPR` | The tag signer's `signing_fingerprint` in `keys.json` | |
| `STAGING_REF` | Full SHA of the `RELEASE_BRANCH` commit the staging tools run from (step 3) | |
| `SHA256SUMS_SHA256` | The `sha256sums_sha256` the coordinator's staging run prints (step 3) | |
| `MY_SHA256SUMS_SHA256` | The `sha256sums_sha256` a signer's own derivation prints (step 3) | |
| `TRUSTED_RELEASE_REF` | Full SHA of the commit that lands the trust-record PR | |
| `GUIX_SIGS_REF` | Full SHA of the counted `qbit-guix.sigs` commit | |
| `FOLLOW_UP_REF` | Full SHA of the commit that lands the follow-up trust-record PR | |
| `MAIN_TARGET` | Full SHA of the `RELEASE_BRANCH` commit `main` is fast-forwarded to after the release | |

## Branches and release lines

As of 2026-11-10:

| Branch | State |
| --- | --- |
| `1.x.x` | Active 1.x maintenance branch; v1.0.1 is being prepared here. |
| `1.1.0` | Forked from `1.x.x` to prepare 1.1.0. |
| `main` | Default branch. v1.0.0 was cut from it. Unchanged since the v1.0.0 trust record (2026-07-15), and a strict ancestor of `1.x.x`. |
| `1.0.0`, `0.1.x` | Older release branches. |

The publisher accepts `--release-line mainnet` or `--release-line testnet`.
The published tags are `v0.1.0-testnet4`, `v0.1.1-testnet4` and
`v0.1.2-testnet4` (testnet), and `v1.0.0` (mainnet). v1.0.1 reaches `main`
by an admin fast-forward ([after the release](#after-the-release)). The
longer-term branch model, and whether testnet-only releases continue, are
pending operator decisions; this runbook does not set either. Whether a
release has release candidates is decided per release.

The release source, `TAG_TARGET`, is a reviewed public commit on the
first-parent history of a protected public branch, usually `RELEASE_BRANCH`:
normally GitHub's merge commit, not the pull request head
([1. Tag](#1-tag)).

Prerequisites for publishing with the publisher:

- `Qbit-Org/qbit-guix.sigs` `main` must be protected by a ruleset with the
  `deletion` and `non_fast_forward` rules; the publisher refuses every release
  while it is not. Its `public-main` ruleset carries both rules, and its
  `signed-commits` ruleset requires signed commits; both were applied on
  2026-11-09, and their templates are in
  `contrib/guix/repo-templates/qbit-guix.sigs/rulesets/`. A change to
  `public-main` must keep both rules.
- Every release-line branch passed as `--trusted-release-branch` must be
  protected by a branch ruleset with the `deletion` and `non_fast_forward`
  rules; a branch without both is refused.

## Roles

| Role | Who | Responsible for |
| --- | --- | --- |
| Release coordinator | Named in the tracking issue | Freeze, prep PR, go/no-go, `STAGING_REF`, staging and combining `SHA256SUMS`, trust record, closing the issue |
| Builders | Active signers in `keys.json` with the `builder-attestation` capability, `mainnet` in `release_lines`, and the artifact set (`core`, `photon`) in `artifact_sets` | Guix builds, attestation PRs into `Qbit-Org/qbit-guix.sigs`, and keeping their build roots until the release is published |
| Signers | Active signers in `keys.json` with the `release-signing` capability and `mainnet` in `release_lines` | Signing the tag (one signer) and `SHA256SUMS` (quorum) |
| Tag pusher | An organization admin, or a member of the team that the `public-release-tags-v-creation` ruleset allows | Pushing the signed tag; this need not be the signer |
| Publisher operator | A GitHub account with push access to `Qbit-Org/qbit` | Running `contrib/release-process/publish-local-release.sh` |

The quorums come from `release_lines.mainnet` in
[`contrib/keys/operator-keys/keys.json`](../../contrib/keys/operator-keys/keys.json).
Read them at the head of the release branch; the publisher later uses the
copy at `TRUSTED_RELEASE_REF`:

```sh
python3 -c 'import json; p = json.load(open("contrib/keys/operator-keys/keys.json")); print(p["policy_id"], p["policy_sequence"], p["release_lines"]["mainnet"])'
```

Under policy `qbit-release-keys-mainnet-000002` (sequence 2), mainnet needs 3
release signatures and 3 builder attestations per artifact set, from 5 active
signers. If the policy changes, the file is authoritative, not this sentence.

## Before the tag

### Freeze

- [ ] Announce the freeze of `RELEASE_BRANCH` in the tracking issue. After
  that, only the prep PR, the trust-record PR and fixes the coordinator
  accepts may merge. Record each accepted exception in the tracking issue.
- [ ] Record whether each change merged since the previous release had an
  approving review. List any merge without one for the trust record.

### Prep PR into `RELEASE_BRANCH`

- [ ] Bump the version in `CMakeLists.txt`: `CLIENT_VERSION_MAJOR`,
  `CLIENT_VERSION_MINOR` and `CLIENT_VERSION_BUILD`. A final release keeps
  `CLIENT_VERSION_RC 0`, `CLIENT_VERSION_PHASE ""` (a non-empty phase adds
  `-<phase>` to every version string) and `CLIENT_VERSION_IS_RELEASE "true"`;
  a release candidate sets `CLIENT_VERSION_RC`. Check `COPYRIGHT_YEAR`.
- [ ] Commit the version bump, then build that commit with the GUI, the
  wallet and every tool, because `gen-manpages.py` needs every binary
  including `bin/qbit-qt`, and `BUILD_GUI` is `OFF` by default. Build with no
  local changes: `git status --porcelain --untracked-files=no` must print
  nothing. With `CLIENT_VERSION_IS_RELEASE "true"` the binaries never report
  `-dirty`, so `gen-manpages.py` cannot detect a dirty build. Use a non-Debug
  build, because a Debug build adds Debug-only options, such as the `lock`
  debug category, to the help text the pages are generated from:

  ```sh
  cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=ON -DENABLE_WALLET=ON -DBUILD_CLI=ON -DBUILD_TX=ON -DBUILD_UTIL=ON -DBUILD_WALLET_TOOL=ON
  cmake --build build -j "$(nproc)"
  ```

- [ ] Regenerate the man pages (this needs `help2man` and writes
  `doc/man/*.1`) and the example configuration (this writes
  `share/examples/qbit.conf`):

  ```sh
  BUILDDIR="$PWD/build" contrib/devtools/gen-manpages.py
  BUILDDIR="$PWD/build" contrib/devtools/gen-qbit-conf.sh
  ```

  If the prep PR is rebased into a new month, regenerate the man pages so
  their `.TH` dates match the release.
- [ ] Fold the per-PR fragments, `doc/release-notes-<PR number>.md`, for PRs
  merged since `PREVIOUS_TAG` into `doc/release-notes-<VERSION>.md`, then
  delete them. A fragment that already existed at `PREVIOUS_TAG` belongs to an
  earlier release: check it against that release's notes and delete it
  without folding it in. This command sorts them. It fails, and sorts
  nothing, unless `PREVIOUS_TAG` is set and that tag exists locally:

  ```sh
  (
    set -eu
    cd "$(git rev-parse --show-toplevel)"
    git rev-parse --verify --quiet "refs/tags/${PREVIOUS_TAG}^{commit}" >/dev/null ||
      { echo "tag ${PREVIOUS_TAG} not found; run: git fetch origin tag ${PREVIOUS_TAG}" >&2; exit 1; }
    for f in $(git ls-files doc | grep -E '^doc/release-notes-[0-9]+\.md$'); do
      if git cat-file -e "refs/tags/${PREVIOUS_TAG}:${f}" 2>/dev/null; then echo "older: ${f}"; else echo "new: ${f}"; fi
    done
  )
  ```

- [ ] The notes cover behavior changes, upgrade and downgrade, known
  limitations, and every waiver, such as unsigned platform artifacts. The
  in-tree notes cannot name the tag target, so the P2MR v1 sentence goes in
  the publish-time copy (step 4).

### Chainparams maintenance (x.y.0 releases)

For an x.y.0 release, review `CMainParams` in `src/kernel/chainparams.cpp`
and record the outcome in the tracking issue:

- [ ] `consensus.nMinimumChainWork` and `consensus.defaultAssumeValid`.
- [ ] `chainTxData`.
- [ ] `m_assumed_blockchain_size` and `m_assumed_chain_state_size`.
  `ci/release/verify_mainnet_release_posture.py` currently requires both to be
  `0`, and requires the `ChainParams_MAIN_launch_bootstrap` test in
  `src/test/pow_tests.cpp` to assert that. Raising them needs a validator
  change first.
- [ ] DNS seeds and fixed seeds. The posture validator requires at least two
  unique `*.qbit.org` DNS seeds, requires `src/chainparamsseeds.h` to match
  `contrib/seeds/nodes_main.txt` byte for byte, and requires the bootstrap
  test to assert the seed set. See [contrib/seeds](../../contrib/seeds/README.md).

### Candidate checks

Run these on the exact commit you will tag. Any later merge restarts the list.

- [ ] **CI is green on the final commit.** Full Validation and the Required
  Merge Gate must be green on the final commit before tagging, as
  [#181](https://github.com/Qbit-Org/qbit/pull/181) requires; wait for both
  to finish. This runbook defines no CI waiver. For history: v1.0.0 was
  tagged while its Full Validation run was still in progress, and that run
  later failed 9 jobs ([v1.0.0 trust record](../release-trust-1.0.0.md)).
- [ ] **Nightly CI.** Scheduled runs take their workflow from the default
  branch, so dispatch Nightly CI on the release branch while its head is the
  candidate, and record the run:

  ```sh
  gh workflow run ci-nightly-heavy.yml --repo Qbit-Org/qbit --ref "${RELEASE_BRANCH}" -f run_scanners=true
  ```

- [ ] **Mainnet posture.** Core Checks runs the posture validator in its
  `mainnet publication posture` job for `source` and `release-policy`
  changes to a mainnet line
  ([CI coverage](publisher-reference.md#mainnet-launch-posture)), so the job
  is skipped on a commit whose own change was, for example, docs only. If
  the job ran and passed in a Core Checks push run on `RELEASE_BRANCH` whose
  head is `TAG_TARGET`, record the run; a pull-request run tests a merge
  preview, not `TAG_TARGET` itself. In every other case (skipped, failed,
  cancelled, or no push run at `TAG_TARGET`), run the validator yourself in a fresh worktree of
  `TAG_TARGET`; a failure blocks the tag. Without `--release-tag` it checks
  the working tree, so no tag is needed:

  ```sh
  (
    set -eu
    repo="$PWD"; dir="$(mktemp -d)"
    trap 'cd "$repo"; git worktree remove --force "$dir" 2>/dev/null || rmdir "$dir" 2>/dev/null || true' EXIT
    git worktree add --detach "$dir" "${TAG_TARGET}"
    cd "$dir"
    python3 ci/release/verify_mainnet_release_posture.py --source-root "$dir"
  )
  ```

  The manual check passes only if the block exits 0, after printing
  `Validated fail-closed mainnet release posture for working tree`.

- [ ] **Fuzz evidence** on the candidate source, following
  [fuzzing.md](../development/fuzzing.md#qbit-seed-corpora). Record, for the
  six qbit targets plus `process_message` and `p2p_headers_presync`:
  - the llvm-cov coverage checker (`test/fuzz/test_qbit_fuzz_coverage.py`);
  - the seed replay;
  - the mutation phase, with the execution count per target.
- [ ] **P2MR v1 suite.** The full qbit P2MR v1 unit suite ran on the
  candidate source, not on an ancestor.
- [ ] **Packaged candidate.** As pre-tag smoke evidence, build the candidate
  with Guix using `FORCE_VERSION=<VERSION>`, so that the artifacts carry
  their final names. Smoke-test them on each platform: install or upgrade,
  startup and sync, encrypted send and relock, PSBT, and a clean shutdown.
- [ ] **Platform signing.** Record whether the macOS and Windows artifacts
  are signed. If they are not, record an explicit unsigned-platform waiver
  for this release ([#70](https://github.com/Qbit-Org/qbit/issues/70)).

## During the release

### 1. Tag

With merge-commit merges, tag the merge commit that landed the release pull
request, not the pull request's head. Only the merge commit is a state the
branch actually had: `0.1.x` and `1.0.0` do not require a pull request to be up
to date before merging, `main` and `1.x.x` require it only once the Key Policy
Gate is armed ([after the release](#after-the-release)), and an admin can
bypass that rule, so a pull request head's tree can lack changes the branch had
when it merged. The publisher refuses a tag target that is not on the
first-parent history of `trusted_release_ref`. The release attestation is the
operator's signature on the annotated tag; the target commit's own signature
plays no part here.

- [ ] A signer with an active mainnet `release-signing` key signs an
  annotated tag on the exact commit with that key, and checks that the
  signature's fingerprint is the one in `keys.json`:

  ```sh
  git tag --sign --local-user "${SIGNING_FPR}!" --message "qbit ${TAG}" "${TAG}" "${TAG_TARGET}"
  git verify-tag --raw "${TAG}" 2>&1 | grep "VALIDSIG ${SIGNING_FPR} "
  ```

- [ ] The tag pusher pushes it. The `public-release-tags-v-creation` ruleset
  lets only organization admins and one maintainer team create `v*` tags:

  ```sh
  git push origin "refs/tags/${TAG}"
  ```

- [ ] GitHub reports the tag object as `verified=true` with `reason=valid`.
  That needs the signing key on a GitHub account whose verified email matches
  the tagger. Record the tag object, the tag target and the signer's
  fingerprint:

  ```sh
  gh api "repos/Qbit-Org/qbit/git/tags/$(git rev-parse "${TAG}^{tag}")" --jq '.verification'
  ```

The `public-release-tags-v-immutability` ruleset blocks updating or deleting
a `v*` tag for everyone except organization admins, who can bypass it. The
publisher's tag pin still detects a moved tag. The publisher accepts tags
that match `^v[A-Za-z0-9][A-Za-z0-9._-]*$`, and a mainnet tag must not
contain `testnet`. As of 2026-11-10, the repository has no rc tags.

### 2. Guix builds and attestations

- [ ] Each builder builds the tag with the public scripts in
  [contrib/guix](../../contrib/guix/) (see also [guix.md](guix.md)):
  `contrib/guix/guix-build` for core and `contrib/guix/guix-build-photon` for
  PHOTON. Then the builder attests each set with `contrib/guix/guix-attest`,
  setting `ARTIFACT=photon` for PHOTON. `SIGNER` must be
  `<signing fingerprint>=<keys.json alias>`, because the validator reads
  `<VERSION>/<alias>/`:

  ```sh
  env GUIX_SIGS_REPO=/path/to/qbit-guix.sigs SIGNER="<signing fingerprint>=<alias>" contrib/guix/guix-attest
  env GUIX_SIGS_REPO=/path/to/qbit-guix.sigs SIGNER="<signing fingerprint>=<alias>" ARTIFACT=photon contrib/guix/guix-attest
  ```

- [ ] Each builder opens a PR into `Qbit-Org/qbit-guix.sigs` that adds its
  signed manifests under `<VERSION>/<alias>/`.
- [ ] Attestation PRs merge until each artifact set meets the builder quorum.
  Record the `qbit-guix.sigs` commit on `main` that you will count; it
  becomes `GUIX_SIGS_REF`. `GUIX_SIGS_REF`, the publisher's
  `--guix-sigs-ref`, must be a state the `qbit-guix.sigs` branch actually
  had: the merge commit that landed the attestations, or the branch tip, on
  that branch's first-parent history. That is the same rule as for the release
  tag target; a pull request head in `qbit-guix.sigs` is refused.
- [ ] The packaged candidate's smoke-tested artifacts match the tagged
  build's `SHA256SUMS`.
- [ ] Builders keep their build roots: step 3 copies the artifacts from their
  Guix output directories, and the roots are removed only
  [after the release](#after-the-release).

### 3. Stage, sign and combine `SHA256SUMS`

Use the public tools in `contrib/release-process`, run as
[its README](../../contrib/release-process/README.md) shows: as
`python3 -I -S -B <tool>`, from a clean checkout of `STAGING_REF` that has
the release tag and is neither shallow nor a partial clone. They build the
[staged directory](publisher-reference.md#staged-artifact-directory) the
publisher validates, with the publisher's own validators. The paths are
examples.

- [ ] The coordinator pins `STAGING_REF`: the full SHA of a public commit on
  the first-parent history of `RELEASE_BRANCH` that contains the tools and
  has `TAG_TARGET` on its own first-parent history. Record it in the
  tracking issue. Staging, every signature and the
  combination run with `--trusted-release-ref "${STAGING_REF}"`.
- [ ] Record the waivers this release uses in the tracking issue. Staging
  takes exactly the same subset of `--allow-unsigned-platform-artifacts` and
  `--allow-codesigning-artifacts` that step 6 passes to the publisher, and
  no other. While the #70 unsigned-platform waiver is recorded, that is
  `--allow-unsigned-platform-artifacts` alone.
- [ ] Stage from a clean `qbit-guix.sigs` checkout at `GUIX_SIGS_REF`, the
  commit the publisher will count. The tool reads `--guix-sigs-dir` as a
  plain directory, so check the checkout first, and so does every signer
  who derives the manifest. The first command must print `GUIX_SIGS_REF`,
  and the other two nothing:

  ```sh
  git -C /srv/release/qbit-guix.sigs rev-parse HEAD
  GIT_NO_REPLACE_OBJECTS=1 GIT_GRAFT_FILE=/dev/null git -C /srv/release/qbit-guix.sigs status --porcelain --untracked-files=all --ignored
  git -C /srv/release/qbit-guix.sigs ls-files -v | grep -v '^H '
  ```

  The second command reads real objects, as the publisher does, so a
  replace ref or graft cannot hide a different tree.

  The artifacts come from one builder's Guix output directories, core and
  PHOTON; pass one builder's, not several, because the tool refuses
  duplicate file names. Name both artifact sets, so that staging fails, as
  the publisher's `--require-photon` would, when PHOTON is missing:

  ```sh
  # --allow-unsigned-platform-artifacts applies only while the #70
  # unsigned-platform waiver is recorded for this release; drop it otherwise.
  python3 -I -S -B contrib/release-process/stage-release-artifacts.py \
    --trusted-release-ref "${STAGING_REF}" \
    --release-line mainnet \
    --tag v1.0.1 \
    --guix-sigs-dir /srv/release/qbit-guix.sigs \
    --artifact core \
    --artifact photon \
    --builder-output-dir /srv/release/v1.0.1/guix-build/output \
    --builder-output-dir /srv/release/v1.0.1/guix-build/output-photon \
    --allow-unsigned-platform-artifacts \
    --stage-dir /srv/release/v1.0.1/staged
  ```

  The tool stages exactly the attested files the publisher accepts with the
  same waivers, and writes `SHA256SUMS` from the counted builder
  attestations. It never stages the source archive `qbit-<VERSION>.tar.gz`,
  and it refuses a `--stage-dir` that is a mount point. The staged set
  includes the
  [debug symbol archives](publisher-reference.md#debug-symbol-archives):
  `qbit-<VERSION>-<host>-debug.tar.gz` for each Linux and macOS host, and
  `qbit-<VERSION>-win64-debug.zip` for Windows. The macOS archives start with
  v1.0.1. Record the printed `policy_sha256`, `sha256sums_sha256`,
  `artifact_count`, `counted_core`, `counted_photon`, `source_archive` and
  `source_sha256` in the tracking issue.
- [ ] Before signing, each signer checks that `STAGING_REF` is on the
  first-parent history of `RELEASE_BRANCH` and that its release key policy
  (`keys.json` and the certificates in `public-keys/`) is the branch's. Being
  on the branch does not mean every change was reviewed: check the freeze's
  list of merges without an approving review too. The block must print `ok`:

  ```sh
  (
    set -eu
    git fetch origin
    branch="refs/remotes/origin/${RELEASE_BRANCH}"
    git rev-list --first-parent "$branch" | grep -Fx "${STAGING_REF}" >/dev/null || { echo "STAGING_REF is not on the first-parent history of ${RELEASE_BRANCH}" >&2; exit 1; }
    for p in keys.json public-keys; do
      test "$(git rev-parse "${STAGING_REF}:contrib/keys/operator-keys/$p")" = "$(git rev-parse "$branch:contrib/keys/operator-keys/$p")" || { echo "$p differs from ${RELEASE_BRANCH}" >&2; exit 1; }
    done
    echo ok
  )
  ```

- [ ] Each signer derives the manifest from the same inputs, replacing
  `--stage-dir` and `--builder-output-dir` with `--sha256sums-output FILE`,
  and checks that the printed `policy_sha256` and `sha256sums_sha256` equal
  the recorded values. Their own `sha256sums_sha256` is
  `MY_SHA256SUMS_SHA256`.
- [ ] Each signer signs a copy of the stage directory, passing
  `MY_SHA256SUMS_SHA256` from their own run, never the recorded value. The
  tool takes the fingerprint from the alias's `signing_fingerprint` in the
  policy at `STAGING_REF`:

  ```sh
  python3 -I -S -B contrib/release-process/sign-sha256sums.py \
    --trusted-release-ref "${STAGING_REF}" \
    --release-line mainnet \
    --stage-dir /srv/release/v1.0.1/staged \
    --alias <alias> \
    --expected-sha256sums-sha256 "${MY_SHA256SUMS_SHA256}"
  ```

  Record each run's `signer_fpr` and `signature_sha256`.
- [ ] Once signatures reach the signing quorum, the coordinator collects the
  `SHA256SUMS.<alias>.asc` files into the stage directory, checks that
  `sha256sum` of each equals its signer's recorded `signature_sha256` (a file
  re-encoded in transit still verifies, but no longer matches the record),
  and combines them. `SHA256SUMS.asc` is their concatenation in sorted alias
  order:

  ```sh
  python3 -I -S -B contrib/release-process/combine-sha256sums-signatures.py \
    --trusted-release-ref "${STAGING_REF}" \
    --release-line mainnet \
    --stage-dir /srv/release/v1.0.1/staged \
    --expected-sha256sums-sha256 "${SHA256SUMS_SHA256}"
  ```

  Record the printed `release_signature_aliases` and `combined_sha256`.
- [ ] Re-run the stage command unchanged. On the existing stage directory it
  checks every artifact against its digest and the builder attestations
  again, keeps the signatures, and must print `status=unchanged`.

### 4. P2MR v1 evidence

- [ ] Produce the evidence envelope, the oracle report and the finalized
  integration matrix on the exact tag target, and run the verifier locally
  ([steps](publisher-reference.md#p2mr-v1-conformance-inputs)). The consensus
  review must name the tag target itself, not an ancestor.
- [ ] Write the publish-time notes: a copy of `doc/release-notes-<VERSION>.md`
  outside the publisher checkout, with the conformance sentence naming the
  tag target and the digests.

### 5. Trust-record PR

- [ ] Open a PR into `RELEASE_BRANCH` that adds
  `doc/release-trust-<VERSION>.md`, modelled on
  [the v1.0.0 record](../release-trust-1.0.0.md). The commit that lands the
  PR on `RELEASE_BRANCH` becomes `TRUSTED_RELEASE_REF`. The
  [public evidence list](publisher-reference.md#public-evidence) is the
  authoritative list of fields; in summary, the record contains:
  - [ ] the tag, tag object and tag target; the signer's alias and
    fingerprint; the tagger, tag date and GitHub verification result;
  - [ ] how `trusted_release_ref` is chosen (the commit that lands this
    record on `RELEASE_BRANCH`), and the review evidence;
  - [ ] the `keys.json` sha256, `policy_id` and `policy_sequence`, and
    `STAGING_REF` with the staging tools' `policy_sha256`;
  - [ ] the exact `qbit-guix.sigs` commit, the counted builders' aliases and
    fingerprints for each artifact set, and the source archive's name, sha256
    and tag target;
  - [ ] the counted signers' aliases and fingerprints; the sha256 of
    `SHA256SUMS`, of `SHA256SUMS.asc` and of each individual signature; the
    artifact count; and whether PHOTON is included. The publisher runs at
    `TRUSTED_RELEASE_REF` only after this PR lands, so take these from the
    step 3 records: the counted builders from `counted_core` and
    `counted_photon`, the counted signers from `release_signature_aliases`,
    the digests from `sha256sums_sha256`, `signature_sha256` and
    `combined_sha256`, and the count from `artifact_count`. Take each
    fingerprint from that alias's `signing_fingerprint` in the `keys.json`
    this PR lands with, which is the copy the publisher trusts at
    `TRUSTED_RELEASE_REF`;
  - [ ] the P2MR v1 profile version, digests, results and consensus review;
  - [ ] the CI runs at the tag target, any unsigned-platform or codesigning
    waiver, and the review status recorded at the freeze.

  Release-trust records written from now on name GitHub's merge commit as the
  release source. Earlier records stay as they were written.
- [ ] Right before the PR merges, check that the release key policy on
  `RELEASE_BRANCH`, `keys.json` and the certificates in `public-keys/`, is
  still the one at `STAGING_REF`; a certificate can change under an
  unchanged `keys.json`. If it is not, the signatures were checked under
  another policy: do not merge; stage and sign again at a ref with the
  current policy, and update the record first. This must print `ok`:

  ```sh
  (
    set -eu
    git fetch origin
    for p in keys.json public-keys; do
      test "$(git rev-parse "${STAGING_REF}:contrib/keys/operator-keys/$p")" = "$(git rev-parse "refs/remotes/origin/${RELEASE_BRANCH}:contrib/keys/operator-keys/$p")" || { echo "$p differs from ${RELEASE_BRANCH}" >&2; exit 1; }
    done
    echo ok
  )
  ```

- [ ] Values that exist only after the PR lands or after publication go in a
  follow-up PR after step 6: the `trusted_release_ref` SHA; the publisher's
  printed evidence lines, from the saved output of each run; the ref it ran
  from; and the release URL and its immutable state. A follow-up never moves
  `trusted_release_ref`.

### 6. Publish

Run the publisher three times with the same arguments: with no mode flag
(validation only), then with `--create-draft`, then with `--publish`. Each run
repeats the full validation. Save the complete output of every run, including
repeated ones, outside the checkout; a log file inside the checkout would make
it dirty. For example, wrap each run as
`( set -o pipefail; contrib/release-process/publish-local-release.sh ... 2>&1 | tee -a /srv/release/v1.0.1/publisher.log )`,
with a log for this release only; `pipefail` keeps a failed run's nonzero
exit status. The output can contain local paths; only its evidence lines go
in the trust record.

- [ ] Prepare a clean, complete clone of `Qbit-Org/qbit` with
  `TRUSTED_RELEASE_REF` checked out and the tag fetched, and a clean
  `qbit-guix.sigs` clone at `GUIX_SIGS_REF`. Untracked files count as dirty,
  and the publisher refuses a shallow or partial clone
  ([checks](publisher-reference.md#trusted-release-ref)).
- [ ] Fetch `RELEASE_BRANCH` into the publisher clone and the `qbit-guix.sigs`
  branch into its clone. The publisher never fetches, and stops if a checkout
  lacks the tip GitHub reports for its branch. If a merge lands after that
  fetch, the publisher stops before it publishes anything; fetch again and
  rerun it:

  ```sh
  git fetch origin "${RELEASE_BRANCH}"
  git -C /srv/release/qbit-guix.sigs fetch origin main
  ```

  `TRUSTED_RELEASE_REF` must be on the first-parent history of the protected
  branch that the publisher checks: `main` by default, or the branch passed
  with `--trusted-release-branch`. For a release line such as `1.0.0` or
  `1.x.x`, take `TRUSTED_RELEASE_REF` from that line's own branch and pass
  `--trusted-release-branch` with that branch. GitHub must report that branch
  as protected, and its active rules must include `non_fast_forward` and
  `deletion`, so someone without admin rights cannot force-push away the
  history it anchors or delete the branch. qbit's branch rulesets give
  organization admins an always-bypass, so an admin can still rewrite that
  history: the release's attestation is the operator-signed tag, and this
  check guards against rewrites by non-admins. The publisher reads the tip
  commit GitHub's API reports for the branch and refuses a trusted ref off
  that line, such as a pull request head, which could carry validators and key
  policy from an older base. It checks `GUIX_SIGS_REF` the same way: it must
  be on the first-parent history of the `qbit-guix.sigs` branch, which GitHub
  reports as protected with `non_fast_forward` and `deletion` rules, at the
  exact tip GitHub reports. The publisher prints the trusted release branch it
  uses and, when `--trusted-release-branch` is not given, reminds that a
  release-line release must pass `--trusted-release-branch <line>`.
- [ ] From the root of the publisher clone, run validation only. The paths
  are examples:

  ```sh
  # --allow-unsigned-platform-artifacts applies only while the #70
  # unsigned-platform waiver is recorded for this release; drop it otherwise.
  contrib/release-process/publish-local-release.sh \
    --tag v1.0.1 \
    --release-line mainnet \
    --artifacts-dir /srv/release/v1.0.1/staged \
    --trusted-release-ref "${TRUSTED_RELEASE_REF}" \
    --trusted-release-branch "${RELEASE_BRANCH}" \
    --guix-sigs-repo /srv/release/qbit-guix.sigs \
    --guix-sigs-ref "${GUIX_SIGS_REF}" \
    --p2mr-v1-conformance-evidence /srv/release/v1.0.1/p2mr/conformance-evidence.json \
    --p2mr-v1-oracle-report /srv/release/v1.0.1/p2mr/oracle-report.json \
    --p2mr-v1-integration-matrix /srv/release/v1.0.1/p2mr/integration-matrix.json \
    --require-photon \
    --allow-unsigned-platform-artifacts \
    --notes-file /srv/release/v1.0.1/release-notes-1.0.1.md \
    --no-prerelease \
    --make-latest true
  ```

  - `--trusted-release-branch` names the protected branch that carries
    `TRUSTED_RELEASE_REF`, here `RELEASE_BRANCH`. Without it the publisher
    checks `main`. A publisher from before this check, whose `--help` lists
    no `--trusted-release-branch`, refuses the option as an unknown argument:
    leave it out when `TRUSTED_RELEASE_REF` predates it.
  - The three `--p2mr-v1-*` files must be given as absolute paths. Mainnet
    requires all three.
  - `--require-photon` requires PHOTON artifacts and a PHOTON builder quorum.
  - `--allow-unsigned-platform-artifacts` accepts `-unsigned` macOS and
    Windows artifacts. Pass it only when the release notes and the trust
    record carry this release's waiver.
  - `--notes-file` points outside the checkout for two reasons: the notes
    name the tag target, which the tagged tree cannot contain, and an
    untracked file inside the checkout would make it dirty.
  - `--make-latest true` marks the release as GitHub's latest. Without it, a
    new draft defaults to `false`, which leaves the previous release marked
    latest. Use `false` for a release on an older line.
  - For a release candidate, where the release has one: pass `--prerelease`
    and `--make-latest false` instead, and give each rc its own trust record
    (`doc/release-trust-<VERSION>-rcN.md`), as
    [#256](https://github.com/Qbit-Org/qbit/pull/256) plans for v1.1.0-rc1.
- [ ] Check the validation-only output against step 3 and the trust record.
  Its `Key policy: sha256=` must equal the recorded `policy_sha256`, and the
  certificates in `public-keys/` at `TRUSTED_RELEASE_REF` must be the ones at
  `STAGING_REF` (the same `git rev-parse` comparison as in step 5). Its
  `Release signatures` and `Builder attestations` aliases, its `Artifacts`
  total, the `tag_object`, `tag_target` and `guix_sigs_ref` on its `Pinned
  refs` line and the digest on its `Builder source` line must equal the ones
  the trust record states; and the waiver flags must be exactly the ones
  staging used. The staged files must
  still have the recorded digests, so `sha256sum` of the staged
  `SHA256SUMS`, `SHA256SUMS.asc` and each `SHA256SUMS.<alias>.asc` must
  match the record. If any differ, stop before `--create-draft` and raise it
  with the operator: the trust record does not describe what the publisher
  counts.
- [ ] Add `--create-draft`, then check that the draft body carries the P2MR v1
  sentence. The publisher does not check it.
- [ ] Replace `--create-draft` with `--publish`, and record the release URL
  for the trust record. The upload set is exactly the staged directory: the
  artifacts listed in `SHA256SUMS`, `SHA256SUMS` itself and its signatures.
  The publisher's `Published immutable release assets exactly match local
  names and SHA256 digests` line and the `Evidence` line's `file_count`,
  together with the recorded digests of `SHA256SUMS` and its signatures, pin
  every published asset.

### Immutable-publication recovery

If `--publish` fails its final tag check after GitHub has made the release
immutable, the publisher cannot roll the release back.

- [ ] Stop distributing the release.
- [ ] Preserve the publisher transcript, the release URL and ID, and the
  expected and observed tag object and target.
- [ ] Do not rerun the publisher to repair it. Follow the
  [recovery procedure](publisher-reference.md#immutable-publication-recovery).

## After the release

- [ ] Merge the follow-up trust-record PR.
- [ ] Builders remove their build roots only after the release is published
  and its `SHA256SUMS` matches their attestation: for each artifact set the
  builder attested, every published line of that set appears, with the same
  digest, in the builder's manifest for it (`all.SHA256SUMS` or
  `noncodesigned.SHA256SUMS`, and the `photon-` manifest for PHOTON). A
  builder whose manifest does not match raises it in the tracking issue.
- [ ] Integrate the release into `main` as the operator decides for that
  release. For v1.0.1 the decision is an admin fast-forward: an organization
  admin moves `main` to `MAIN_TARGET`, the release commit on the first-parent
  history of `RELEASE_BRANCH` that the operator names in the tracking issue,
  bypassing `main`'s ruleset. A fast-forward keeps the tag target and the
  trust records on `main` with their SHAs. The block pushes only if `main` is
  an ancestor of `MAIN_TARGET`, `MAIN_TARGET` is on the first-parent history
  of `RELEASE_BRANCH`, and it contains
  `TAG_TARGET`, `TRUSTED_RELEASE_REF` and the merged follow-up trust record
  (`FOLLOW_UP_REF`, the commit that landed it):

  ```sh
  (
    set -eu
    git fetch origin
    git merge-base --is-ancestor refs/remotes/origin/main "${MAIN_TARGET}" || { echo "main has commits that MAIN_TARGET lacks" >&2; exit 1; }
    git rev-list --first-parent "refs/remotes/origin/${RELEASE_BRANCH}" | grep -Fx "${MAIN_TARGET}" >/dev/null || { echo "MAIN_TARGET is not on the first-parent history of ${RELEASE_BRANCH}" >&2; exit 1; }
    for c in "${TAG_TARGET}" "${TRUSTED_RELEASE_REF}" "${FOLLOW_UP_REF}"; do
      git merge-base --is-ancestor "$c" "${MAIN_TARGET}" || { echo "MAIN_TARGET does not contain $c" >&2; exit 1; }
    done
    git push origin "${MAIN_TARGET}:refs/heads/main"
  )
  ```

- [ ] One time, after v1.0.1's fast-forward has brought
  `.github/workflows/key-policy-gate.yml` to `main`: arm the Key Policy
  Gate. Follow "Arming the gate" in
  [contrib/keys/README.md](../../contrib/keys/README.md) and the ruleset
  notes in
  [public-branch-and-rulesets.md](../development/public-branch-and-rulesets.md),
  in this order:
  1. an Actions event policy allows `pull_request_target` for the workflow,
     before 2026-12-02;
  2. the `main` and `1.x.x` rulesets require their per-base checks,
     `Key Policy Gate (main)` and `Key Policy Gate (1.x.x)`, from GitHub
     Actions (integration 15368), with code-owner review and up-to-date
     branches, as `.github/rulesets/` describes;
  3. `@Qbit-Org/release-maintainers` gets write access, so `CODEOWNERS`
     applies.

  No ruleset may require the gate before `main` has the workflow: until then
  no run posts the check, and pull requests would wait for it forever. Pull
  requests already open into `main` or `1.x.x` get a gate run only on their
  next event, so after step 2 push to, edit or reopen each one that shows
  the check as expected but missing. If
  v1.0.1 has not reached `main` well before 2026-12-02, raise the deadline
  with the operator.
- [ ] Check the RPC docs. The `github-pages` environment deploys only from
  `main`, so they deploy after the fast-forward: on its push to `main`, or
  when RPC Docs Pages is dispatched on `main` with `publish=true`. Until then
  `main` lacks `doc/rpc/versioned_site.py`, so the run that publishing
  triggers does not deploy. Confirm that docs.qbit.org lists the release.
- [ ] Bump the downstream pins. Each path below exists on that repository's
  `main` as of 2026-11-10:
  - [ ] `Qbit-Org/qbit-rpc`: `QBIT_CORE_VERSION` in
    `scripts/qbit-core-release.mjs`; the supported range in
    `packages/rpc/src/version.ts`, for a new minor version; and
    `scripts/qbit-release-keys/`, when the key policy changes.
  - [ ] `Qbit-Org/qbit-js`: the conformance pin, which is `CORE_TAG` and
    `CORE_COMMIT` in `scripts/check-core-fixtures.sh`, `DEFAULT_COMMIT` in
    `packages/protocol/scripts/gen-psbt-fixtures.py` and
    `gen-sighash-fixtures.py`, and `docs/conformance-playbook.md`. Follow that
    playbook.
  - [ ] `Qbit-Org/qbit-wallet`: `QBIT_RELEASE`, `QBIT_SOURCE_COMMIT` and the
    archive SHA256 arguments in `docker/regtest/qbitd-release.Dockerfile`.
  - [ ] `Qbit-Org/qbit-mining-bootstrap`: `QBIT_GIT_REF` in
    `config/upstream.env` and `.env.example`.
  - [ ] `Qbit-Org/qbit-electrs`: the qbit source refs in
    `doc/qbit-contract.md`.
- [ ] Close the tracking issue with links to the release, the trust record
  and the downstream PRs.
