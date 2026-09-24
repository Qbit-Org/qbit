# qbit 1.0.0 Release Trust Reference

This note anchors the reviewed policy and validation commit designated for
publishing qbit 1.0.0 mainnet artifacts. The signed tag fixes the release
source; this later trust reference does not replace or modify that source.

The first revision of this note merged as
`70fea84f5becfb57463247af09790df5ddd424f8`
([Qbit-Org/qbit#136](https://github.com/Qbit-Org/qbit/pull/136)). This
revision corrects that record under
[Qbit-Org/qbit#156](https://github.com/Qbit-Org/qbit/issues/156): it lists
every job of the Full Validation run, states the deviation exactly as it was
recorded, removes a retained-file reference that never existed at the tag
target, and separates the historical `v1.0.0` source from later maintenance
work. The correction changes only this document.

## Release source

- Release tag: `v1.0.0`
- Annotated tag object: `c72d230476ffe94e2f672d925f34288159233dfc`
- Peeled tag target: `7ebcddb622d6e639041f005a189b048ec2a221fe`
- Tag signer: `operator-01`
- Signing fingerprint: `289EA3EC2F1939A24984840ED26CFC05586D371E`
- Tagger: `Alex <alex@swaplabs.xyz>`
- Tag date: `2026-07-15T16:34:36Z`
- GitHub verification: `verified=true`, `reason=valid`

When the first revision of this note was reviewed, the tag target was the
protected `Qbit-Org/qbit:main` head and GitHub's compare result between them
was `identical`. Merging that revision advanced `main` by exactly one commit,
`70fea84f5becfb57463247af09790df5ddd424f8`, whose tree differs from the tag
target only by the addition of this file.

## Public review and lineage

The complete release candidate was reviewed in
[Qbit-Org/qbit#135](https://github.com/Qbit-Org/qbit/pull/135). Its reviewed
head, `9ea1ac9ddddc5236356095a2592a397234efca56`, and the protected-`main`
squash result share tree `68fc87fbb1b428adc98ce98040aadfabc4f315ec`.
The squash result is the peeled tag target named above; the reviewed head is
not represented as its ancestor.

Exact-target
[Core Checks](https://github.com/Qbit-Org/qbit/actions/runs/29431717879)
completed successfully. Its `mainnet publication posture` job was skipped:
the workflow enables that job only for changes targeting the `1.0.0` branch,
and this run was a `main` push, so no Core Checks run at the tag target
exercised the mainnet posture validator. The release process assigns that
check to the local publisher, whose run is not publicly recorded. Full
Validation run
[29431717977](https://github.com/Qbit-Org/qbit/actions/runs/29431717977)
at the same commit concluded `failure` and is not represented as passing. Its
complete job inventory follows.

## Full Validation run 29431717977

The run executed on the `main` push of the peeled tag target and completed at
`2026-07-15T17:54:18Z` with 10 successful, 9 failed, and 2 skipped jobs. The
table lists every job in the archived run. Cause keys are explained below the
table; each classification cites the archived job log, which was retained as
of `2026-09-24`. GitHub keeps run logs and artifacts for a limited period.

| Job | Conclusion | Failing step | Cause |
| --- | --- | --- | --- |
| [classify validation profile](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408113181) | success | | |
| [determine runners](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408200339) | success | | |
| [test each commit](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408113709) | skipped | | S |
| [macOS native (`matrix.job-name`)](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408113997) | skipped | | S |
| [Windows native, VS 2022](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408200425) | failure | Fail after Qt diagnostics | C |
| [Windows native, fuzz, VS 2022](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408200379) | success | | |
| [Linux->Windows cross, no tests](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408220999) | success | | |
| [Windows, test cross-built](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87417251066) | failure | Run unit tests | A |
| [CentOS, depends, gui](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221119) | failure | CI script | A, B |
| [No wallet, libbitcoinkernel](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221128) | failure | CI script | A, B |
| [ASan + LSan + UBSan + integer, no depends, USDT](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221144) | failure | CI script | A, B |
| [no IPC, i686, DEBUG](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221147) | failure | CI script | A, B |
| [TSan, depends, no gui](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221154) | failure | CI script | A |
| [MSan, depends, unit tests](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221330) | failure | CI script | A |
| [MSan, depends, functional tests](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221195) | success | | |
| [macOS-cross, gui, no tests](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221118) | success | | |
| [lint](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221058) | success | | |
| [tidy](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408221239) | success | | |
| [public-docs-lint](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408200355) | success | | |
| [rpc-docs](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87408200390) | success | | |
| [Full Validation Gate](https://github.com/Qbit-Org/qbit/actions/runs/29431717977/job/87430725864) | failure | Check validation results | D |

Cause keys:

- **A: stale AuxPoW slot-index test expectations (known).** The unit test
  `auxpow_tests/auxpow_expected_index_vectors_document_qbit_slot_math` failed
  four `BOOST_CHECK_EQUAL` checks at `src/test/auxpow_tests.cpp` lines
  400-406 (the fourth check spans lines 403-406 and the logs report it at
  line 403 or 406 depending on the toolchain) with identical values in every
  job that ran the unit suite: expected `12` and got `1`, expected `4` and
  got `9`, expected `882684108` and got `-414942079`, and expected
  `838473315` and got `614588952`. The later maintenance fix
  [Qbit-Org/qbit#137](https://github.com/Qbit-Org/qbit/pull/137) attributes
  this to expectations left stale by the finalized mainnet parameters and
  changed only the expected values in the test. `auxpow::GetExpectedIndex`
  was not changed.
- **B: stale nested-RPC genesis hash expectation (known).** In the four Linux
  jobs that build the GUI, `test_qbit-qt` reported
  `RPCNestedTests::rpcNestedTests()` failing at
  `src/qt/test/rpcnestedtests.cpp` line 85, where the test compared the
  genesis coinbase transaction hash returned by
  `getblock(getbestblockhash())[tx][0]` against a hard-coded constant. Every
  other Qt test group in those jobs passed. #137 replaced the constant with
  the value derived from the selected chain parameters and did not change the
  RPC code under test.
- **C: Windows-native Qt test exit (cause not established).** The step
  `Run Qt test with diagnostics` ran `test_qbit-qt.exe -v2` once per QPA
  platform and, after each nonzero exit, once more under ProcDump, six runs
  in total. The direct runs exited `1` under `QT_QPA_PLATFORM=offscreen`,
  `0xc0000409` under `windows`, and `1` under `minimal`. None of the six runs
  logged per-test output, so this record does not name the failing test;
  ProcDump logged only C++ exception notices without test context and wrote
  one dump per platform. As of `2026-09-24` those dumps were retained in the
  run artifact `windows-qt-crash-diagnostics-29431717977` (expires
  `2026-10-13`) and were not analyzed for this note. Because the job stopped
  at `Fail after Qt diagnostics`, its `Run test suite` and
  `Run functional tests` steps were skipped, so this leg produced no
  Windows-native unit or functional test result. #137 later changed Qt
  wallet-view teardown and `AppTests` cleanup and describes a blocked send
  worker that cascaded into later Qt test failures; that description is
  #137's stated root cause, not evidence from this job's log.
- **D: aggregate gate (known).** `Check validation results` reported
  `Windows native DLL result was failure`, `Windows cross-built tests result
  was failure`, and `CI matrix result was failure`. Every other gate input
  (`classify validation profile`, `determine runners`, `Linux->Windows
  cross`, `lint`, `public docs lint`, `rpc docs`) was `success`.
- **S: skipped by workflow condition (known).** At the tag target,
  `test each commit` runs only on a `pull_request` event, only when the
  `QBIT_ENABLE_TEST_EACH_COMMIT` repository variable is `true`, and only when
  the pull request head is in this repository or carries the
  `ci:qbit-trusted` label; this run was a `main` push, so it could not run.
  The macOS native job runs only when `QBIT_ENABLE_MACOS_NATIVE_ARM64` is
  `true`; because its matrix never expanded, the API reports its name
  literally as `matrix.job-name`. Both conditions carry a
  `Disabled by default` comment in the workflow. Neither skip is a failure.

A failed job is not by itself proof of a product defect. Causes A and B were
resolved by changing test expectations only. Cause C is unattributed; this
note does not claim that the tagged Windows binaries have or lack a defect
in that area.

## Accepted deviation

The `v1.0.0` tag was created at `2026-07-15T16:34:36Z`, while run 29431717977
was still in progress, and the release was published at
`2026-07-16T00:31:52Z` after the run had concluded `failure`. The deviation
was recorded in the #136 description as follows:

> Full Validation run 29431717977 contains a failed Windows-native Qt job. The
> release coordinator explicitly accepted skipping that requirement; the note
> records that the run is not passing, and no validator, tag, or source
> identity is weakened or changed.

That description understated the deviation: the run had nine failed jobs, not
one, and it recorded no cause. No separate written acceptance was found in the
#135 or #136 discussion; the recorded acceptance consists of the #136
description, approved by two reviewers, and the first revision of this note.
The public release process documents no waiver for a failed Full Validation
run; the only waivers it documents cover unsigned platform artifacts and
codesigning payloads ([release-process.md](release/release-process.md)). The
local publisher's validation list does not include workflow-run results, so
the deviation did not bypass or weaken any release validator, and it changed
no tag or source identity.

The published `v1.0.0` asset set includes macOS and Windows artifacts named
`-unsigned`. Neither this note nor the
[1.0.0 release notes](release-notes-1.0.0.md) record a platform-signing
waiver for this release; see
[Qbit-Org/qbit#70](https://github.com/Qbit-Org/qbit/issues/70).

## Policy and validation authority

The active policy is `qbit-release-keys-mainnet-000002`, sequence 2, effective
from `v1.0.0`. The exact `contrib/keys/operator-keys/keys.json` SHA256 is
`f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`.
The public policy mirror is `Qbit-Org/qbit-guix.sigs` commit
`a7ed466bc24f016f5d1f2995758371cc55ebc5d2`.

The `trusted_release_ref` designated for qbit 1.0.0 release validation and
publication is `70fea84f5becfb57463247af09790df5ddd424f8`, the protected-`main`
commit that merged the first revision of this note. It differs from both the
annotated tag object and the peeled tag target, and its history contains the
peeled tag target. That commit was created at `2026-07-15T23:23:40Z`, and the
release was published at `2026-07-16T00:31:52Z`; no public artifact records
the ref the publisher ran from. Later revisions of this note, including this
correction, do not move that ref.

That trusted commit retains the public release validators, local publisher,
mainnet posture checks, P2MR gate, operator policy, and five public
certificates used to validate the final artifact set. Every path below exists
at both the peeled tag target and the trusted commit:

- `ci/release/validate_release_artifacts.py`
- `ci/release/validate_builder_attestations.py`
- `ci/release/validate_key_metadata.py`
- `ci/release/verify_mainnet_release_posture.py`
- `ci/release/verify_mainnet_ci_posture.py`
- `ci/release/verify_p2mr_v1_conformance.py`
- `contrib/release-process/publish-local-release.sh`
- `contrib/keys/operator-keys/keys.json`
- `contrib/keys/operator-keys/public-keys/operator-01-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-02-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-03-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-04-release.asc`
- `contrib/keys/operator-keys/public-keys/operator-05-release.asc`

The first revision of this note also listed
`.github/workflows/release-publish.yml`. That workflow was removed by #135 and
did not exist at the tag target or at the trusted commit; the local publisher
script above is the only supported publication entry point.

## Later maintenance remediation

[Qbit-Org/qbit#137](https://github.com/Qbit-Org/qbit/pull/137) merged into
the `1.x.x` maintenance branch on `2026-07-17` as
`23e76df71ab27bb7cf0ab5d76d9cc8f72f0a7c2f`. It refreshed the test
expectations behind causes A and B, changed Qt wallet-view teardown and
`AppTests` cleanup, and clamped a header-sync commitment window. It is not
part of the `v1.0.0` tag target, is not reachable from `main` at the trusted
commit, and changes nothing about the published `v1.0.0` release.

Full Validation run
[35894000141](https://github.com/Qbit-Org/qbit/actions/runs/35894000141) at
`1.x.x` commit `c4b254e2d39f3a430b8b4a85798dd03ed47c3d98` concluded `success`
on `2026-09-23`: every job listed above that failed at the tag target
succeeded there, and the same two conditional jobs were skipped. Core Checks
run [35894000253](https://github.com/Qbit-Org/qbit/actions/runs/35894000253)
and Required Merge Gate run
[35894000393](https://github.com/Qbit-Org/qbit/actions/runs/35894000393)
also passed at that commit; the Core Checks `mainnet publication posture`
job was again skipped by the same branch condition. Those results describe
maintenance-branch source only. They do not change the `v1.0.0` tag, its
artifacts, or the result of run 29431717977, and integrators verifying
`v1.0.0` must use the release source identity recorded above.
