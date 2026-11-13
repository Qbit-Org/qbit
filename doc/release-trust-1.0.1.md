# qbit 1.0.1 Release Trust Reference

This note anchors the reviewed policy and validation commit designated for
publishing qbit 1.0.1 mainnet artifacts. The signed tag fixes the release
source; this trust reference does not replace or modify that source.

## Release source

- Release tag: `v1.0.1`
- Annotated tag object: `a5dc57ae00eefcff453db0a335497b9a83be4ba0`
- Peeled tag target: `0439a7e5b37fb3f7e4ddfb735b68961445a882c8`
- Tag signer: `operator-01`
- Signing fingerprint: `289EA3EC2F1939A24984840ED26CFC05586D371E`
- Tag date: `2026-11-12T20:34:29Z`
- GitHub verification: `verified=true`, `reason=valid`

The signing fingerprint is `operator-01`'s `signing_fingerprint` in the
`keys.json` at the tag target, and `git verify-tag --raw v1.0.1` reports it
as `VALIDSIG`.

The tag target is one signed commit on `main` that squashes `1.x.x` at
`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`. It is the commit of
[Qbit-Org/qbit#427](https://github.com/Qbit-Org/qbit/pull/427), "qbit v1.0.1
mainnet release". Its only parent is
`70fea84f5becfb57463247af09790df5ddd424f8`, the head of `main` before the
release, which merged the first revision of the
[v1.0.0 record](release-trust-1.0.0.md). Its tree,
`35a01d570ceef5984ae84e15d4dc74adecb587be`, is identical to the tree of
`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`, the `1.x.x` head on which Full
Validation, the Required Merge Gate and Core Checks passed before the tag
(see [CI](#ci)).

At `2026-11-13T15:10:44Z` an organization admin fast-forwarded `main` from
`70fea84f5becfb57463247af09790df5ddd424f8` to the tag target. GitHub records
#427 as merged at `2026-11-13T15:10:46Z`, with the tag target as its merge
commit. `1.x.x` stays at `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`, and the
tag target is not on `1.x.x`.

## Public review and lineage

Between the `v1.0.0` tag target, `7ebcddb622d6e639041f005a189b048ec2a221fe`,
and `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`, `1.x.x` holds 76 commits and
no merge commit: the first revision of the v1.0.0 record
(`70fea84f5becfb57463247af09790df5ddd424f8`) and 75 pull requests, each
landed as one commit. #427 carried that tree to `main` as the single commit
named above.

### Freeze

`1.x.x` was frozen for v1.0.1. The exceptions the coordinator accepted are
recorded, with their commits, under "Freeze exceptions (2026-11-11)" and
"Freeze exceptions recorded 2026-11-12" in
[Qbit-Org/qbit#174](https://github.com/Qbit-Org/qbit/issues/174).
[#425](https://github.com/Qbit-Org/qbit/pull/425)
(`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`) merged at
`2026-11-12T17:35:21Z`, during the freeze, as an accepted exception. It is
not in the 2026-11-12 list, which covers `1.x.x` up to `6a3421d1d0`; the
[waivers comment](https://github.com/Qbit-Org/qbit/issues/174#issuecomment-6857581672)
records it.

## CI

The tag was created at `2026-11-12T20:34:29Z`. The runs below are every
workflow run GitHub lists for the tag target and for
`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`. Run states were last read at
`2026-11-13T17:33:17Z`; all of them had completed.

### At the tag target

| Workflow | Run | Event | Result |
| --- | --- | --- | --- |
| Core Checks | [43300104099](https://github.com/Qbit-Org/qbit/actions/runs/43300104099) | #427 pull request | `success`, completed `2026-11-12T20:39:51Z` |
| Full Validation | [43300103920](https://github.com/Qbit-Org/qbit/actions/runs/43300103920) | #427 pull request | `success` on attempt 2, completed `2026-11-12T23:02:37Z`; attempt 1 `failure` |
| Required Merge Gate | [43300103869](https://github.com/Qbit-Org/qbit/actions/runs/43300103869) | #427 pull request | `success` on attempt 2, completed `2026-11-13T15:09:36Z`; attempt 1 `failure` |
| RPC Docs Pages (427/merge) | [43300103871](https://github.com/Qbit-Org/qbit/actions/runs/43300103871) | #427 pull request | `success`, completed `2026-11-12T20:41:45Z` |
| Core Checks | [43449959669](https://github.com/Qbit-Org/qbit/actions/runs/43449959669) | `main` push | `success`, completed `2026-11-13T15:20:49Z` |
| RPC Docs Pages (main) | [43449959819](https://github.com/Qbit-Org/qbit/actions/runs/43449959819) | `main` push | `success`, completed `2026-11-13T15:27:17Z` |
| Full Validation | [43449959636](https://github.com/Qbit-Org/qbit/actions/runs/43449959636) | `main` push | `success`, completed `2026-11-13T17:31:56Z` |
| Required Merge Gate | [43449959717](https://github.com/Qbit-Org/qbit/actions/runs/43449959717) | `main` push | `success`, completed `2026-11-13T17:32:29Z` |

The first attempts of the #427 runs started at `2026-11-12T20:25:07Z`,
before the tag was created, and none had completed when it was. GitHub
reports the tag target as their head commit. As the runbook notes, a
pull-request run tests a merge preview: these runs built
`1475c22573d7d9c9ac5f81debc0451a0a6853713`, the tag target merged into
`70fea84f5becfb57463247af09790df5ddd424f8`, whose tree is the tag target's
tree, `35a01d570ceef5984ae84e15d4dc74adecb587be`. The `main` push
runs built the tag target itself.

- **Core Checks.** All eight jobs succeeded in both runs, including
  `mainnet publication posture` and `P2MR v1 conformance`. In the `main` push
  run these are jobs
  [131969409130](https://github.com/Qbit-Org/qbit/actions/runs/43449959669/job/131969409130)
  and
  [131969409379](https://github.com/Qbit-Org/qbit/actions/runs/43449959669/job/131969409379).
- **Full Validation, #427.** Attempt 1 concluded `failure`. Its jobs
  `no IPC, i686, DEBUG` and `MSan, depends, functional tests` both started at
  `2026-11-12T20:25:40Z` and completed at `21:00:41Z` and `21:00:42Z`. In both,
  the `CI script` step and every later step report no conclusion, and GitHub
  serves no log for either job. The `Full Validation Gate` job then failed in
  `Check validation results`. The release coordinator's record in #174 calls
  this consistent with a lost runner. Attempt 2 concluded `success`: 19 jobs
  succeeded, and `test each commit` and the macOS native job (reported as
  `matrix.job-name`) were skipped by their workflow conditions, as at
  `v1.0.0`.
- **Required Merge Gate, #427.** In attempt 1 the `Required Merge Gate` job
  failed in `Check required validation profile` at `2026-11-12T21:41:10Z`,
  after Full Validation's first attempt had concluded `failure`. Attempt 2
  succeeded.
- **Full Validation and Required Merge Gate, `main` push.** Both succeeded
  on their first attempt. Full Validation's 19 jobs succeeded and the same
  two conditional jobs were skipped. In the gate run, `classify validation
  profile`, `operator-key policy validation` and `Required Merge Gate`
  succeeded, and the four profile-specific validation jobs were skipped by
  their workflow conditions.
- **RPC Docs Pages (main).** All eight jobs succeeded, including
  `deploy rpc docs pages`.

### Before the tag, at the same tree

These runs are on `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`, the `1.x.x`
head. Its tree is the tag target's tree,
`35a01d570ceef5984ae84e15d4dc74adecb587be`, so every file these runs checked
out is byte-identical to the tag target's. What differs is the commit, its
history and the event: a push to `1.x.x`, not a pull request into or a push
to `main`.

| Workflow | Run | Event | Result |
| --- | --- | --- | --- |
| Core Checks | [43271044808](https://github.com/Qbit-Org/qbit/actions/runs/43271044808) | `1.x.x` push | `success`, completed `2026-11-12T17:47:12Z` |
| Full Validation | [43271045040](https://github.com/Qbit-Org/qbit/actions/runs/43271045040) | `1.x.x` push | `success`, completed `2026-11-12T19:19:37Z` |
| Required Merge Gate | [43271044819](https://github.com/Qbit-Org/qbit/actions/runs/43271044819) | `1.x.x` push | `success`, completed `2026-11-12T19:19:44Z` |
| Nightly CI | [43273463067](https://github.com/Qbit-Org/qbit/actions/runs/43273463067) | manual dispatch on `1.x.x` | `failure` (Scanner only), completed `2026-11-12T23:55:27Z` |

- **Core Checks.** All eight jobs succeeded, including
  [`mainnet publication posture`](https://github.com/Qbit-Org/qbit/actions/runs/43271044808/job/131367560153)
  and `P2MR v1 conformance`.
- **Full Validation.** 19 jobs succeeded, and the same two conditional jobs
  were skipped. It completed before the tag was created, as did the Required
  Merge Gate.
- **Nightly CI.** Dispatched at `2026-11-12T17:49:27Z`, and finished after
  the tag. The `Scanner` job concluded `failure` at `2026-11-12T18:30:17Z` in
  its `Run scanner evidence` step; the release coordinator triaged its
  findings as not release-blocking. The other five jobs passed. The second
  32-bit ARM unit-test shard failed in attempt 1 and passed in attempt 2, at
  `2026-11-12T23:55:26Z`.

### Not relied on

#427 was first opened at `2026-11-12T20:19:35Z` with
`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71` as its head. The pull-request runs
for that head were Core Checks
[43299183927](https://github.com/Qbit-Org/qbit/actions/runs/43299183927),
Full Validation
[43299183883](https://github.com/Qbit-Org/qbit/actions/runs/43299183883) and
Required Merge Gate
[43299183985](https://github.com/Qbit-Org/qbit/actions/runs/43299183985),
all `cancelled`, and RPC Docs Pages (427/merge)
[43299183863](https://github.com/Qbit-Org/qbit/actions/runs/43299183863),
which failed in the `Validate version source checkout` step of its
`build rpc docs (main)` job. This record does not rely on them.

## Policy and validation authority

The active policy is `qbit-release-keys-mainnet-000002`, sequence 2, effective
from `v1.0.0`. At the tag target, the exact
`contrib/keys/operator-keys/keys.json` SHA256 is
`f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`, unchanged
from v1.0.0. For mainnet it lists five active signers and requires three
release signatures and three builder attestations per artifact set.

- `STAGING_REF`: `0439a7e5b37fb3f7e4ddfb735b68961445a882c8`, the tag target.
- The staging tools' `policy_sha256` at `STAGING_REF`:
  `f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`, equal
  to the `keys.json` SHA256.
- The public policy mirror, `operator-keys/` in `Qbit-Org/qbit-guix.sigs` at
  `GUIX_SIGS_REF`: every file in it is byte-identical to the same path under
  `contrib/keys/operator-keys/` at the tag target. The mirror has no
  `KEYS.md`.

The runbook places `STAGING_REF` on the release branch. For v1.0.1 it is the
tag target, on `main`, and the runbook's release-branch checks are made
against `main` ([item 3](#3-main-was-fast-forwarded-before-publication)).

### `trusted_release_ref`

The `trusted_release_ref` designated for qbit 1.0.1 release validation and
publication is the commit that lands this record on `main`.

v1.0.1's record lands on `main`, not on `1.x.x` as the runbook's step 5
describes. The tag target is the squash commit on `main` and is not on
`1.x.x`, and the publisher requires the tag target to be an ancestor of
`trusted_release_ref`. A commit on `1.x.x` descends from
`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`, which has the same tree, but not
from the tag target, so the publisher would refuse it. The publisher also
requires `trusted_release_ref` to differ from both the annotated tag object
and the peeled tag target.

Its SHA exists only once this record has landed and is recorded in the
follow-up, which does not move it. Later revisions of this record do not
move it either. This record was prepared as one commit whose parent is the
tag target and which adds only this file. Whether the landed commit keeps
that shape, so that its tree differs from the tag target's only by this file:
`PENDING`, checked when it lands and recorded in the follow-up.

Review evidence for `trusted_release_ref`, the review of the pull request
that lands this record (#424) and who approved it: `PENDING`, recorded in the
follow-up.

Every path below exists at the tag target:

- `ci/release/validate_release_artifacts.py`
- `ci/release/validate_builder_attestations.py`
- `ci/release/validate_key_metadata.py`
- `ci/release/verify_mainnet_release_posture.py`
- `ci/release/verify_testnet_release_posture.py`
- `ci/release/verify_p2mr_v1_conformance.py`
- `contrib/release-process/publish-local-release.sh`
- `contrib/release-process/stage-release-artifacts.py`
- `contrib/release-process/sign-sha256sums.py`
- `contrib/release-process/combine-sha256sums-signatures.py`
- `contrib/release-process/release_staging_common.py`
- `contrib/keys/operator-keys/keys.json`
- `contrib/keys/operator-keys/public-keys/operator-01-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-02-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-03-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-04-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-05-release.asc`

## Builders, signers and artifacts

The `qbit-guix.sigs` commit used for validation (`GUIX_SIGS_REF`) is
`503230a08b17bba130a7ca33f5c263e6c073e2ac`, the head of
`Qbit-Org/qbit-guix.sigs` `main` after the three v1.0.1 attestation pull
requests merged:
[Qbit-Org/qbit-guix.sigs#12](https://github.com/Qbit-Org/qbit-guix.sigs/pull/12)
(`operator-03`),
[#13](https://github.com/Qbit-Org/qbit-guix.sigs/pull/13) (`operator-02`)
and [#14](https://github.com/Qbit-Org/qbit-guix.sigs/pull/14)
(`operator-01`).

The values below were printed by
`contrib/release-process/stage-release-artifacts.py --sha256sums-output` at
`STAGING_REF` and `GUIX_SIGS_REF`, with `--release-line mainnet --tag v1.0.1
--artifact core --artifact photon --allow-unsigned-platform-artifacts`.
Fingerprints are each alias's `signing_fingerprint` in the `keys.json` this
record lands with.

| Artifact set | Counted builder | Fingerprint |
| --- | --- | --- |
| core | `operator-01` | `289EA3EC2F1939A24984840ED26CFC05586D371E` |
| core | `operator-02` | `1B95A7AA02F5530BDB1CD92387012E62F6CC1393` |
| core | `operator-03` | `05A14A415C26F4216DC254FE52D5CC557D764586` |
| photon | `operator-01` | `289EA3EC2F1939A24984840ED26CFC05586D371E` |
| photon | `operator-02` | `1B95A7AA02F5530BDB1CD92387012E62F6CC1393` |
| photon | `operator-03` | `05A14A415C26F4216DC254FE52D5CC557D764586` |

The three builders' manifests in `1.0.1/<alias>/` are byte-identical:
`noncodesigned.SHA256SUMS` has SHA256
`8f2bb9693ad33a5b55f2cb79e6205f9dd9a9d2db278161f15f6a81d1d6e158f8` and
`photon-noncodesigned.SHA256SUMS` has SHA256
`e620493bf2c1da4a4a113bdab7a6f9ffcfda55cb28f4ab02bfbb12dd5a48111c` for each.

- Canonical source archive: `qbit-1.0.1.tar.gz`, SHA256
  `9b794c652bd8d94f861dcf6e0cf221230a5fa9f3d8b86658daee86bbbf0db89d`,
  reconstructed from the tag target
  `0439a7e5b37fb3f7e4ddfb735b68961445a882c8`. All six counted manifests list
  it with that digest.
- `SHA256SUMS`: SHA256
  `ce26c04834bd79b37a0fb263d6630796a0e1eb8027c796f77ba7af5546c02b82`.
- Artifact count: 21, of which 19 core and 2 PHOTON. The source archive and
  the three `-codesigning` payloads that the builders attested are not
  release artifacts and are not listed.
- PHOTON: included. Staging counted three PHOTON builders. The publisher's
  PHOTON validation, under `--require-photon`, runs after this record lands;
  its result goes in the follow-up.

The 21 artifacts are:

- `qbit-1.0.1-aarch64-linux-gnu-debug.tar.gz`
- `qbit-1.0.1-aarch64-linux-gnu.tar.gz`
- `qbit-1.0.1-arm-linux-gnueabihf-debug.tar.gz`
- `qbit-1.0.1-arm-linux-gnueabihf.tar.gz`
- `qbit-1.0.1-arm64-apple-darwin-debug.tar.gz`
- `qbit-1.0.1-arm64-apple-darwin-unsigned.tar.gz`
- `qbit-1.0.1-arm64-apple-darwin-unsigned.zip`
- `qbit-1.0.1-powerpc64-linux-gnu-debug.tar.gz`
- `qbit-1.0.1-powerpc64-linux-gnu.tar.gz`
- `qbit-1.0.1-riscv64-linux-gnu-debug.tar.gz`
- `qbit-1.0.1-riscv64-linux-gnu.tar.gz`
- `qbit-1.0.1-win64-debug.zip`
- `qbit-1.0.1-win64-setup-unsigned.exe`
- `qbit-1.0.1-win64-unsigned.zip`
- `qbit-1.0.1-x86_64-apple-darwin-debug.tar.gz`
- `qbit-1.0.1-x86_64-apple-darwin-unsigned.tar.gz`
- `qbit-1.0.1-x86_64-apple-darwin-unsigned.zip`
- `qbit-1.0.1-x86_64-linux-gnu-debug.tar.gz`
- `qbit-1.0.1-x86_64-linux-gnu.tar.gz`
- `qbit-photon-1.0.1-x86_64-linux-gnu-debug.tar.gz`
- `qbit-photon-1.0.1-x86_64-linux-gnu.tar.gz`

### Release signatures

Three release signers signed `SHA256SUMS`, which meets the mainnet quorum of
three. `combine-sha256sums-signatures.py` at `STAGING_REF` counts all three.
The fingerprint recorded is the alias's `signing_fingerprint` in the
`keys.json` this record lands with.

| Signer alias | Fingerprint | `SHA256SUMS.<alias>.asc` SHA256 |
| --- | --- | --- |
| `operator-01` | `289EA3EC2F1939A24984840ED26CFC05586D371E` | `776e1cd09b21976cc70578d4647e9222dc944f861da176dc808ac22f216998a2` |
| `operator-02` | `1B95A7AA02F5530BDB1CD92387012E62F6CC1393` | `bec900792c88929ac18e0c9383dfb7159f2e7f17ce7115000d205ae609369f0b` |
| `operator-03` | `05A14A415C26F4216DC254FE52D5CC557D764586` | `d4c3a8e7d632ec88cb10599c882a25df66331d620111ac23c2e351791bc8e1c2` |

- `release_signature_aliases`: `operator-01,operator-02,operator-03`.
- SHA256 of `SHA256SUMS.asc` (`combined_sha256`):
  `7fba6e8820e3d1ccc5a148539ce9ea063e7b56ab2cb211cbbbd1b376a05f5c7a`. It is
  the three signatures concatenated in alias order.

## P2MR v1 conformance

| Field | Value |
| --- | --- |
| Profile | `qbit-p2mr-v1`, profile version 1 |
| Source commit | `0439a7e5b37fb3f7e4ddfb735b68961445a882c8`, the tag target |
| Specification | `doc/consensus/p2mr-v1.md` at the tag target, SHA256 `0f2c2e9d563bb114b7f6805730e2008f742c3c73ac78148dc56b0ef383138ff1` |
| Corpus manifest | `src/test/data/p2mr_v1_manifest.json` at the tag target, SHA256 `00cd4e1cc25a0540e3a0d372737b490a66eeff2bea9b09f4cccccc5fa97cd7ab`, 80 cases |
| qbit result | `pass`, 80 cases: the full qbit P2MR v1 unit suite on the tag target. Public reference: Full Validation run [43449959636](https://github.com/Qbit-Org/qbit/actions/runs/43449959636) |
| Independent oracle report | SHA256 `8728d4a2b385d22175221b313077752a4c8768d518430d40630f7b9ed7c57c08`; `pass`, 80 cases; the standalone oracle run in release mode on the tag target |
| Finalized integration matrix | SHA256 `19f2760eb5152740870ae8131df65613c9f18fbaa292c41738c97b5aff99268d`; its `release_source_commit` is the tag target; 0 blocking failures and 0 unresolved claims of support |
| Evidence envelope | `PENDING`: SHA256 of the envelope; it changes when the consensus review reference is filled in, so it goes in the follow-up |
| Validator run against the signed tag | `PENDING`: the result of `verify_p2mr_v1_conformance.py --release-tag v1.0.1` with the three files, once the consensus review reference is filled in. With that reference still open, it was the validator's only error |
| Where the three files are published | The follow-up record PR will add `conformance-evidence.json`, `oracle-report.json` and `integration-matrix.json` under `doc/release/evidence/1.0.1/` in `Qbit-Org/qbit`, so that the digests can be recomputed. |

The specification and corpus manifest digests are computed from the git
blobs at the tag target; the verifier reads the same blobs. Both files are
byte-identical at `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`.

The `P2MR v1 conformance` job passed in both Core Checks runs at the tag
target ([CI](#at-the-tag-target)). The `main` push run kept its report,
`p2mr-v1-conformance-report.json`, in the artifact
`p2mr-v1-conformance-0439a7e5b37fb3f7e4ddfb735b68961445a882c8`.
GitHub keeps run artifacts for a limited period. The release oracle report
is byte-identical to that artifact's report.

The publish-time notes must carry exactly one of the two sentences the
[publisher reference](release/publisher-reference.md#p2mr-v1-conformance-inputs)
allows. The sentence used:

```text
Conforms to qbit P2MR v1 corpus 00cd4e1cc25a0540e3a0d372737b490a66eeff2bea9b09f4cccccc5fa97cd7ab on source commit 0439a7e5b37fb3f7e4ddfb735b68961445a882c8; independent oracle report 8728d4a2b385d22175221b313077752a4c8768d518430d40630f7b9ed7c57c08.
```

### Consensus review

The consensus review for this release is recorded here. The evidence
envelope's review reference is the permanent link to this section at
`trusted_release_ref`, so it is filled in after this record lands.

**Specification review.** On `2026-11-12` the following review was recorded
at `29c0ec9b6c447fe0952c7d4ec3879773784104ce`, a `1.x.x` commit whose
`doc/consensus/p2mr-v1.md` is the same blob as the tag target's:

- Reviewer: `kiwidream`.
- Reviewed: every change to `doc/consensus/p2mr-v1.md` from the `v1.0.0` tag
  target (`7ebcddb622d6e639041f005a189b048ec2a221fe`, SHA256
  `0ab5db9aabb08269050a59ba17a1190d50bde5ed1984e94903c62d2186e283a1`) to
  that commit (SHA256
  `0f2c2e9d563bb114b7f6805730e2008f742c3c73ac78148dc56b0ef383138ff1`). The
  diff is 229 lines added and 210 removed, made by four pull requests:
  [#252](https://github.com/Qbit-Org/qbit/pull/252),
  [#264](https://github.com/Qbit-Org/qbit/pull/264),
  [#263](https://github.com/Qbit-Org/qbit/pull/263) and
  [#181](https://github.com/Qbit-Org/qbit/pull/181).
- Result: approved.

Independence: the reviewer wrote #252, #264 and #181 and merged all four
pull requests; #263 had another author. For three of the four changes this
approval is therefore their author's, not a second person's.

At the tag target, `doc/consensus/p2mr-v1.md` is the same blob,
`edfcdec0bbb53a1e1537cf5807368d5b68342c96`, as at
`29c0ec9b6c447fe0952c7d4ec3879773784104ce`, so its diff from the `v1.0.0`
tag target is identical. No later `1.x.x` commit up to
`a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`, whose tree the tag target has,
changes the file:

```sh
git rev-parse 29c0ec9b6c447fe0952c7d4ec3879773784104ce:doc/consensus/p2mr-v1.md 0439a7e5b37fb3f7e4ddfb735b68961445a882c8:doc/consensus/p2mr-v1.md
git log --oneline 29c0ec9b6c447fe0952c7d4ec3879773784104ce..a7a70660ad6ecadbf77b89bc2fe85ba068a86a71 -- doc/consensus/p2mr-v1.md
```

The review covers the specification text only.

## Waivers and deviations

The release coordinator recorded the waivers and runbook deviations accepted
for v1.0.1 in
[Qbit-Org/qbit#174](https://github.com/Qbit-Org/qbit/issues/174#issuecomment-6857581672)
on `2026-11-13T15:35:49Z`. This section restates items 1 to 4 of that
comment. The release process defines no CI waiver, so the CI deviation in
item 2 is recorded as one.

### 1. Unsigned platform artifacts

The macOS and Windows artifacts for v1.0.1 are not code-signed or notarized.
They carry `-unsigned` in their names (six of the 21 artifacts), and
codesigning payloads are not published. Staging and publication pass
`--allow-unsigned-platform-artifacts` and no other waiver flag;
`--allow-codesigning-artifacts` is not used. The
[1.0.1 release notes](release-notes-1.0.1.md) carry the same waiver under
"Known limitations", and [#181](https://github.com/Qbit-Org/qbit/pull/181)
records it. It remains until macOS and Windows signing accounts are available
([#70](https://github.com/Qbit-Org/qbit/issues/70)). Confirmation against the
published asset set goes in the follow-up.

### 2. Tag on a squash commit, before that commit's own CI finished

- `1.x.x` at `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71` was squashed into the
  signed tag target (#427). The tag target's parent is
  `70fea84f5becfb57463247af09790df5ddd424f8`, and its tree is identical to
  that of `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`.
- The tag was pushed while #427's checks on the tag target were still
  running. The runbook requires Full Validation and the Required Merge Gate
  to be green on the final commit before tagging, and defines no CI waiver.
  The basis for this waiver is the identical tree.
- Before the tag, Full Validation, the Required Merge Gate and Core Checks,
  including `mainnet publication posture`, passed on
  `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`
  ([CI](#before-the-tag-at-the-same-tree)).
- After the tag, on the tag target: Core Checks passed, including
  `mainnet publication posture`; Full Validation passed on its second
  attempt; and the Required Merge Gate passed on its second attempt, at
  `2026-11-13T15:09:36Z`. The `main` push runs on the tag target, after
  the fast-forward in item 3, all passed on their first attempt; the last
  completed at `2026-11-13T17:32:29Z` ([CI](#at-the-tag-target)).
- Nightly CI on `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71` finished after the
  tag. Every job passed except `Scanner`, whose findings were triaged as not
  release-blocking.
- Fuzz evidence on the release source ran on
  `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71` before the tag. The
  [1.0.1 release notes](release-notes-1.0.1.md) state that it is tracked in
  [#173](https://github.com/Qbit-Org/qbit/issues/173) and #174 and is not
  recorded in the notes. The coordinator-approved results and execution
  counts are recorded below. The run used LLVM 20.1.8 on x86_64 Linux,
  with libFuzzer, AddressSanitizer, UndefinedBehaviorSanitizer,
  float-divide-by-zero and integer sanitizers, on `2026-11-12`.
  The source tree is byte-identical to the tag target's tree, as recorded
  above; this was a run on the pre-tag commit, not on the tag commit itself.
  The qa-assets revision was `2e9ddaf8b12b11485104d9b09eac0540ca6c0914`.

  The llvm-cov checker passed all 6 tests and all 17 named-seed cases;
  all 30 anchors resolved, and seed generation checks passed. All 20 targets
  replayed every supplied input, including all 53 qbit seeds. Every replay
  and mutation process exited 0, with no crash, timeout, OOM, leak or
  sanitizer report. The optional runner unit tests passed all 16 tests.

  Counts below are executions reported by libFuzzer, not unique inputs.
  Final counts include initialization; the last column subtracts it.
  Every mutation run executed inputs after initialization.

  | Target | Mutation budget | Final executions | Executions after initialization |
  | --- | ---: | ---: | ---: |
  | `asert_chain_transition` | 120 s | 73,653 | 73,647 |
  | `asert_edge_cases` | 120 s | 1,661,253 | 1,661,247 |
  | `asert_math` | 120 s | 2,381,375 | 2,381,369 |
  | `auxpow` | 120 s | 211,867 | 211,860 |
  | `p2mr_script` | 600 s | 442 | 424 |
  | `p2mr_script` | 120 s | 102 | 84 |
  | `pqc` | 600 s | 289 | 271 |
  | `pqc` | 120 s | 70 | 52 |
  | `process_message` | 120 s | 32,009 | 28,650 |
  | `process_message` | 600 s | 142,039 | 138,680 |
  | `p2p_headers_presync` | 120 s | 26,634 | 25,690 |
  | `process_messages` | 120 s | 27,282 | 21,683 |
  | `process_messages` | 600 s | 105,774 | 100,175 |
  | `addrman` | 600 s | 17,799 | 16,014 |
  | `addrman_serdeser` | 1800 s | 2,688 | 1,415 |
  | `data_stream_addr_man` | 120 s | 233,481 | 232,284 |
  | `block` | 600 s | 6,399 | 5,437 |
  | `script_interpreter` | 600 s | 3,570 | 3,056 |
  | `eval_script` | 120 s | 133,589 | 131,772 |
  | `script_flags` | 120 s | 10,933 | 8,593 |
  | `miniscript_stable` | 120 s | 42,248 | 40,320 |
  | `miniscript_smart` | 120 s | 18,105 | 16,194 |
  | `miniscript_string` | 120 s | 276,750 | 275,775 |
  | `miniscript_script` | 120 s | 55,287 | 54,406 |

  Mutation depth was limited for the two SLH-DSA targets: at 120 seconds,
  `p2mr_script` and `pqc` completed 84 and 52 executions after initialization;
  their 600-second runs completed 424 and 271. The longer networking runs
  were not a targeted campaign on the final source change, and coverage of
  its changed lines was not measured. No multi-hour campaign, unsanitized
  libFuzzer run or macOS fuzz run is claimed. These targets do not cover
  qbit-qt, wallet, mining-interface or PHOTON behavior. The earlier coverage
  negative control and the runner integration tests were not repeated.
  Two slow inputs were recorded, without a timeout or failure. The evidence
  manifest verified every retained file before this summary was prepared.
- The P2MR v1 suite also ran on `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`
  before the tag. The conformance evidence this record carries is produced
  on the tag target ([P2MR v1 conformance](#p2mr-v1-conformance)).

### 3. `main` was fast-forwarded before publication

- This replaces the decision of 2026-11-12 recorded in #174: publish first,
  then fast-forward `main`.
- At `2026-11-13T15:10:44Z` an organization admin fast-forwarded `main` from
  `70fea84f5becfb57463247af09790df5ddd424f8` to the tag target, so that the
  tag target, `STAGING_REF` and this record are on `main`. GitHub shows #427
  as merged, with the tag target as its merge commit.
- The push bypassed `main`'s ruleset. GitHub reported one bypassed rule:
  "New changes require approval from someone other than the last pusher".
- `1.x.x` stays at `a7a70660ad6ecadbf77b89bc2fe85ba068a86a71`; the tag target
  is not on `1.x.x`. The checks that the runbook makes against the release
  branch are made against `main` for this release, together with the tree
  identity in item 2.
- This record targets `main`.

### 4. Packaged-candidate smoke checks after the tag

The runbook and #181 list the packaged smoke checks before the tag. v1.0.1
had no release candidate, so no packaged build existed then. The
"Packaged-candidate run" in #174, with its checks B1 to B3, runs on the
attested Guix builds of `v1.0.1` and gates publication instead of the tag.

The release coordinator accepts the following results and coverage limits
for v1.0.1 publication. This acceptance does not turn a failed, partial or
unrun check into a pass. The reports cover the attested packaged artifacts
at the tag target; archive digests matched the release manifest and all
three builders at `GUIX_SIGS_REF`.

| Platform and environment | Result and coverage |
| --- | --- |
| Linux x86_64, Ubuntu 24.04 container, glibc 2.39, Xvfb without a window manager, tray or D-Bus service | PASS for the supplied Linux smoke runbook: headless and GUI startup, sync, encrypted send/relock, PSBT, fee bump, data proof, upgrade/downgrade and clean shutdown. Mainnet reference block hash and MuHash matched. RPC-started encryption with `keypool=3000` completed in 151.346 seconds while the tested GUI actions remained responsive. PHOTON coverage was version-only. |
| macOS 26.4 (25E246), Apple M5 Max, arm64 | PARTIAL overall. Pristine launch was blocked by macOS policy (FAIL); runtime checks used operator-approved ad-hoc signed copies. Startup/sync, send/relock, PSBT, upgrade, signing and ordinary clean shutdown passed. Dock Quit with PSBT Operations open did not request shutdown (FAIL). During RPC-started encryption with `keypool=3000`, the interface temporarily stopped responding (FAIL for responsiveness); encryption completed in 206.22 seconds, the interface recovered, the wallet was encrypted and locked, and a subsequent ordinary Quit exited cleanly. |
| macOS x86_64 under Rosetta 2 on the same Mac | PASS for the limited funded GUI smoke on pristine binaries: displayed balance matched, send confirmed, wallet relocked, and Quit exited cleanly. This was not a native Intel-Mac run or the full arm64 test matrix. |
| Windows; Linux aarch64, armhf, powerpc64 and riscv64 | NOT RUN in this packaged smoke campaign. |

Linux GUI checks required the usual GUI libraries and `libdbus-1-3` in the
container. Initial environment-related failures were retained; the supplied
checks passed with those runtime dependencies present. This was an Xvfb run,
not a separate physical-desktop test. A proof-dialog layout issue remained.

On macOS, both architectures' debug UUID and symbolication checks passed.
The arm64 run left encryption repaint under movement, parts of the
background-quit and Accessibility repetition matrices, and some recording
coverage incomplete. Dock Quit and RPC-encryption results above remain
failed checks despite the coordinator's acceptance of these limitations.
No qbit crash report was observed. The arm64 launch requirement and the
remaining GUI limitations are reflected in the publish-time notes.

The binary digests below identify the tested executables. Linux digests
were independently derived from the exact smoke-tested archives; macOS
pristine and ad-hoc digests are recorded in the packaged smoke report.

| Platform / binary | Pristine binary SHA256 | Runtime binary SHA256 when different |
| --- | --- | --- |
| Linux x86_64 / qbitd | `c52f801024a48bd1bb19804c065840cf93ab799dfc0b1af4644faef1be3fcd0a` | unchanged |
| Linux x86_64 / qbit-qt | `9a7ce0a8653585ea07cd607ff4d4ed1fd930b238e046812dc67e20f3c94c2ba2` | unchanged |
| Linux x86_64 / qbit-photon (version only) | `5616913ea5e33765f18f04eacf0505cf715c8fe2e924fdc9ce454bc3bcbd8832` | unchanged |
| macOS arm64 / qbitd | `2ccf9d668e99defdc7a1c527d07af30614d3840c5173baa9cd0aed127399b1fc` | `192e034ddb94ec798d0174a46ae81129de0f7fae646d85cca6c5d547e0c18efc` |
| macOS arm64 / qbit-qt | `01accd15befd6d3ab19f4a240dc085923eaafaad109f16230a21b7083dba89b1` | `da96848bac87e54d32866fe33738bb0da49eb0e8bdfac76d4aa568cce9faf344` |
| macOS x86_64 / qbitd | `6576f8b5298d659a334afba79755e6168af3fb628fd6ec24de2c0cfabac2c90b` | unchanged |
| macOS x86_64 / qbit-qt | `a0627a43cbb214e49fa2778c45acb48129ac6ac1ff88896513ebedefece69098` | unchanged |

## Recorded after this record lands

These values exist only after this record lands or after publication. A
follow-up records them and does not move `trusted_release_ref`:

- the `trusted_release_ref` SHA; that its parent is the tag target and its
  tree differs from the tag target's only by this file; that the key policy
  at it (`keys.json` and the certificates in `public-keys/`) is the one at
  `STAGING_REF`; and the review of the pull request that landed it;
- the permanent link to the [consensus review](#consensus-review) above,
  and the evidence envelope's SHA256;
- the publisher's printed `Pinned refs`, `Key policy`, `Artifacts`,
  `Release signatures`, `Builder attestations`, `Builder source` and
  `Evidence` lines, its `Published immutable release assets exactly match
  local names and SHA256 digests` line, and the ref it ran from;
- the publisher's PHOTON validation result;
- the release URL and its final immutable state, and confirmation that the
  published asset set carries the unsigned-platform waiver of item 1.
