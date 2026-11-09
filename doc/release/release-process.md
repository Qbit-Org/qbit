# Mainnet Release Runbook

This is the checklist for cutting a qbit mainnet release from a release
branch, which is `1.x.x` today. Open a tracking issue from the **Release**
issue template and tick the items there. What each tool checks, and what is
left to process, is in the [publisher reference](publisher-reference.md).

The examples use these placeholders:

| Placeholder | Meaning | Example |
| --- | --- | --- |
| `VERSION` | Release version | `1.0.1` |
| `TAG` | Signed annotated tag | `v1.0.1` |
| `RELEASE_BRANCH` | Branch the release is cut from | `1.x.x` |
| `TAG_TARGET` | Full SHA of the commit the tag points to | |
| `TRUSTED_RELEASE_REF` | Full SHA of the trust-record merge commit | |
| `GUIX_SIGS_REF` | Full SHA of the counted `qbit-guix.sigs` commit | |

## Branches and release lines

As of 2026-11-09:

| Branch | State |
| --- | --- |
| `1.x.x` | Active 1.x maintenance branch; v1.0.1 is being prepared here. |
| `1.1.0` | Forked from `1.x.x` to prepare 1.1.0. |
| `main` | Default branch. Unchanged since the v1.0.0 trust record (2026-07-15), and a strict ancestor of `1.x.x`. |
| `1.0.0`, `0.1.x` | Older release branches. |

The publisher accepts `--release-line mainnet` or `--release-line testnet`.
The published tags are `v0.1.0-testnet4`, `v0.1.1-testnet4` and
`v0.1.2-testnet4` (testnet), and `v1.0.0` (mainnet). The branch model, and
whether testnet-only releases continue, are pending operator decisions; this
runbook does not set either.

## Roles

| Role | Who | Responsible for |
| --- | --- | --- |
| Release coordinator | Named in the tracking issue | Freeze, prep PR, go/no-go, trust record, closing the issue |
| Builders | Active signers in `keys.json` with the `builder-attestation` capability, `mainnet` in `release_lines`, and the artifact set (`core`, `photon`) in `artifact_sets` | Guix builds and attestation PRs into `Qbit-Org/qbit-guix.sigs` |
| Signers | Active signers in `keys.json` with the `release-signing` capability and `mainnet` in `release_lines` | Signing the tag (one signer) and `SHA256SUMS` (quorum) |
| Publisher operator | A GitHub account with push access to `Qbit-Org/qbit` | Running `contrib/release-process/publish-local-release.sh` |

The quorums come from `release_lines.mainnet` in
[`contrib/keys/operator-keys/keys.json`](../../contrib/keys/operator-keys/keys.json).
Read them at the trusted release ref:

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
  `CLIENT_VERSION_RC 0` and `CLIENT_VERSION_IS_RELEASE "true"`. Check
  `COPYRIGHT_YEAR`.
- [ ] Build the bumped, committed tree as a non-Debug build, so that no
  binary reports `-dirty` and no Debug-only option appears. Then regenerate
  the man pages (this needs `help2man` and writes `doc/man/*.1`) and the
  example configuration (this writes `share/examples/qbit.conf`):

  ```sh
  BUILDDIR="$PWD/build" contrib/devtools/gen-manpages.py
  BUILDDIR="$PWD/build" contrib/devtools/gen-qbit-conf.sh
  ```

  If the prep PR is rebased into a new month, regenerate the man pages so
  their `.TH` dates match the release.
- [ ] Fold every per-PR fragment, `doc/release-notes-<PR number>.md`, into
  `doc/release-notes-<VERSION>.md`, then delete the fragments. This command
  lists the fragments without matching versioned notes such as
  `doc/release-notes-1.0.0.md`:

  ```sh
  git ls-files doc | grep -E '^doc/release-notes-[0-9]+\.md$'
  ```

- [ ] The notes cover behavior changes, upgrade and downgrade, known
  limitations, and every waiver, such as unsigned platform artifacts. The
  in-tree notes cannot name the tag target, so the P2MR v1 sentence goes in
  the publish-time copy (step 4).

### Chainparams maintenance (minor releases)

For a minor release, review `CMainParams` in `src/kernel/chainparams.cpp` and
record the outcome in the tracking issue:

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

- [ ] **CI is green on the tag-target commit.** Wait for Core Checks, Full
  Validation and the Required Merge Gate to finish. v1.0.0 was tagged while
  its Full Validation run was still in progress, and that run later failed 9
  jobs ([trust record](../release-trust-1.0.0.md)).
- [ ] **Waivers are written down.** If the coordinator waives a CI failure,
  the trust record lists the run, each failing job, its cause and who
  accepted it. The publisher does not read CI results.
- [ ] **Nightly CI.** Scheduled runs take their workflow from the default
  branch, so dispatch Nightly CI on the release branch while its head is the
  candidate, and record the run:

  ```sh
  gh workflow run ci-nightly-heavy.yml --repo Qbit-Org/qbit --ref "${RELEASE_BRANCH}" -f run_scanners=true
  ```

- [ ] **Mainnet posture.** Core Checks runs its `mainnet publication
  posture` job only for changes to `1.0.0`, so run the validator yourself. It
  needs an annotated tag, so work in a throwaway clone and never push that
  tag:

  ```sh
  git -c tag.gpgSign=false tag --annotate --message "posture check" v0.0.0-posture-check "${TAG_TARGET}"
  python3 ci/release/verify_mainnet_release_posture.py --source-root "$PWD" --release-tag v0.0.0-posture-check
  ```

- [ ] **Fuzz and P2MR v1 evidence.** The fuzz evidence and the full qbit P2MR
  v1 unit suite ran on the candidate source, not on an ancestor.
- [ ] **Packaged candidate.** Build the candidate with Guix using
  `FORCE_VERSION=<VERSION>`, so the artifacts carry their final names.
  Smoke-test them on each platform: install or upgrade, startup and sync,
  encrypted send and relock, PSBT, and a clean shutdown. The `v*` tag
  rulesets block moving or deleting a pushed tag, so this run stands in for a
  release candidate.
- [ ] **Platform signing.** Record whether the macOS and Windows artifacts
  are signed. If they are not, record an explicit unsigned-platform waiver
  for this release ([#70](https://github.com/Qbit-Org/qbit/issues/70)).

## During the release

### 1. Tag

- [ ] A signer with an active mainnet `release-signing` key signs an
  annotated tag on the exact commit and pushes it:

  ```sh
  git tag --sign --message "qbit ${TAG}" "${TAG}" "${TAG_TARGET}"
  git verify-tag "${TAG}"
  git push origin "refs/tags/${TAG}"
  ```

- [ ] GitHub reports the tag object as `verified=true` with `reason=valid`.
  Record the tag object, the tag target and the signer's fingerprint:

  ```sh
  gh api "repos/Qbit-Org/qbit/git/tags/$(git rev-parse "${TAG}^{tag}")" --jq '.verification'
  ```

The publisher accepts tags that match `^v[A-Za-z0-9][A-Za-z0-9._-]*$`, and a
mainnet tag must not contain `testnet`. Names such as `v1.0.1-rc1` are format
examples only; no rc tag has ever been pushed.

### 2. Guix builds and attestations

- [ ] Each builder builds the tag, core and PHOTON, with the builders' Guix
  tooling (see [contrib/guix](../../contrib/guix/) and [guix.md](guix.md)),
  and attests the outputs.
- [ ] Each builder opens a PR into `Qbit-Org/qbit-guix.sigs` that adds its
  signed manifests under `<VERSION>/<alias>/`.
- [ ] Attestation PRs merge until each artifact set meets the builder quorum.
  Record the `qbit-guix.sigs` commit on `main` that you will count; it
  becomes `GUIX_SIGS_REF`.
- [ ] The packaged candidate's smoke-tested artifacts match the tagged
  build's `SHA256SUMS`.

### 3. Stage and sign `SHA256SUMS`

- [ ] Signers stage the release artifacts, and each signer signs
  `SHA256SUMS`, until the signing quorum is met. The staged directory must
  have the [layout the validator requires](publisher-reference.md#staged-artifact-directory).
  The staged set includes the
  [debug symbol archives](publisher-reference.md#debug-symbol-archives) from
  the same builds, listed in `SHA256SUMS` and uploaded with the rest of the
  release: `qbit-<VERSION>-<host>-debug.tar.gz` for each Linux and macOS host,
  and `qbit-<VERSION>-win64-debug.zip` for Windows. The macOS archives start
  with v1.0.1, and none of them needs an unsigned-platform waiver.

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
  [the v1.0.0 record](../release-trust-1.0.0.md). Its merge commit becomes
  `TRUSTED_RELEASE_REF`. The record contains:
  - [ ] the tag, the tag object, the tag target, and the signer's alias and
    fingerprint;
  - [ ] `trusted_release_ref` and how it was chosen, namely the commit that
    merges this record into `RELEASE_BRANCH`;
  - [ ] the exact `qbit-guix.sigs` commit;
  - [ ] the `keys.json` sha256, `policy_id` and `policy_sequence`;
  - [ ] the counted builders for each artifact set, and the counted signers;
  - [ ] the asset count and the sha256 of `SHA256SUMS`;
  - [ ] the ref the publisher ran from;
  - [ ] the CI runs at the tag target, and every waiver, whether for unsigned
    platform artifacts, codesigning payloads or CI failures;
  - [ ] the review status recorded at the freeze.
- [ ] Values that exist only after the merge or the publication (the
  `trusted_release_ref` SHA, the ref the publisher ran from, and the release
  URL) go in a follow-up PR. A follow-up never moves `trusted_release_ref`.

### 6. Publish

Run the publisher three times with the same arguments: with no mode flag
(validation only), then with `--create-draft`, then with `--publish`. Each run
repeats the full validation.

- [ ] Prepare a clean clone of `Qbit-Org/qbit` with `TRUSTED_RELEASE_REF`
  checked out and the tag fetched, and a clean `qbit-guix.sigs` clone at
  `GUIX_SIGS_REF`. Untracked files count as dirty.
- [ ] From the root of the publisher clone, run validation only. The paths
  are examples:

  ```sh
  contrib/release-process/publish-local-release.sh \
    --tag v1.0.1 \
    --release-line mainnet \
    --artifacts-dir /srv/release/v1.0.1/staged \
    --trusted-release-ref "${TRUSTED_RELEASE_REF}" \
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

  - The three `--p2mr-v1-*` files must be given as absolute paths. Mainnet
    requires all three.
  - `--require-photon` requires PHOTON artifacts and a PHOTON builder quorum.
  - `--allow-unsigned-platform-artifacts` accepts `-unsigned` macOS and
    Windows artifacts. Pass it only when the release notes and the trust
    record carry the waiver.
  - `--notes-file` points outside the checkout for two reasons: the notes
    name the tag target, which the tagged tree cannot contain, and an
    untracked file inside the checkout would make it dirty.
  - `--make-latest true` marks the release as GitHub's latest. Without it, a
    new draft defaults to `false`, which leaves the previous release marked
    latest. Use `false` for a release on an older line.
- [ ] Add `--create-draft`, then check that the draft body carries the P2MR v1
  sentence. The publisher does not check it.
- [ ] Replace `--create-draft` with `--publish`. Keep the final `Evidence:`
  line and the release URL for the trust record.

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
- [ ] Integrate the release branch into the default branch. Today `main` is
  a strict ancestor of `1.x.x`, so the integration is a fast-forward. The
  branch model is pending an operator decision; follow the decision recorded
  in the tracking issue.
- [ ] Check the RPC docs. Publishing triggers the RPC Docs Pages workflow,
  which takes its publishing tools from the default branch. While that branch
  lacks `doc/rpc/versioned_site.py`, as `main` does today, that run fails. A
  push to `main` deploys the site, as does a manual run with `publish=true`.
  Confirm that docs.qbit.org lists the release.
- [ ] Bump the downstream pins. Each path below exists on that repository's
  `main` as of 2026-11-09:
  - [ ] `Qbit-Org/qbit-rpc`: `QBIT_CORE_VERSION` in
    `scripts/qbit-core-release.mjs`; the supported range in
    `packages/rpc/src/version.ts`, for a new minor version; and
    `scripts/qbit-release-keys/`, when the key policy changes.
  - [ ] `Qbit-Org/qbit-js`: the conformance pin, which is `CORE_TAG` and
    `CORE_COMMIT` in `scripts/check-core-fixtures.sh`, `DEFAULT_COMMIT` in
    `packages/protocol/scripts/gen-psbt-fixtures.py` and
    `gen-sighash-fixtures.py`, and `docs/conformance-playbook.md`. Follow that
    playbook.
  - [ ] `Qbit-Org/qbit-mining-bootstrap`: `QBIT_GIT_REF` in
    `config/upstream.env` and `.env.example`.
  - [ ] `Qbit-Org/qbit-electrs`: the qbit source refs in
    `doc/qbit-contract.md`.
- [ ] Close the tracking issue with links to the release, the trust record
  and the downstream PRs.
