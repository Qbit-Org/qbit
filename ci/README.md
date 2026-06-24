# CI Scripts

This directory contains scripts for each build step in each build stage.

## CI Names And Trust Gate

Use neutral workflow names when discussing GitHub checks:

- `Core Checks`: baseline PR checks, backed by `core-checks.yml`.
- `Core Checks Gate`: the aggregated fail-closed gate for the baseline checks.
- `Full Validation`: self-hosted validation, backed by `ci.yml`.
- `Full Validation Gate`: the maintainer-controlled merge gate for Full
  Validation results.
- `Nightly CI`: scheduled and manually dispatched heavy validation, backed by
  `ci-nightly-heavy.yml`.

Fresh external pull requests into `main` are not auto-closed, auto-commented,
or auto-labeled. `Core Checks` run for those PRs first. Self-hosted
`Full Validation` waits until a maintainer applies the `ci:qbit-trusted` label;
contributors should not add or ask automation to add that label themselves.

The `ci:qbit-trusted` label persists across later pushes to the same pull
request, and `pull_request`-triggered runs cannot remove it because fork PR
runs hold a read-only token by design. After labeling a fork PR, maintainers
must re-review any new commits, and remove the label if a trusted fork PR is
updated with unreviewed changes so the next push does not re-run self-hosted
jobs on unreviewed code.

Branch rulesets require the single aggregate `Required Merge Gate` instead of
raw jobs or the raw `Core Checks Gate` and `Full Validation Gate` inputs. Do
not require `build smoke`, `focused unit suites`, `ci-matrix`, `lint`,
`windows-cross`, `test-each-commit`, or other raw jobs directly; those are
internal inputs to the gates and some are skipped when a fork PR is not
trusted. The required gate classifies changed paths and then fails closed: a
source-affecting PR cannot merge unless both source gates pass, while narrow
release-policy and documentation profiles must pass their focused validation.

Raw `Full Validation` self-hosted jobs select their runner pool by repository:
in the public `Qbit-Org/qbit` repo they require the
`self-hosted, linux, x64, qbit-trusted-ci` labels, and everywhere else they use
the standard `self-hosted, linux, x64` pool. The same workflow therefore runs
full validation in the public repo with no per-repo edits, and in the public
repo the qbit-tools autoscaler uses the `qbit-trusted-ci` label to count and
scale only trusted CI work. Fork-PR safety is enforced by the trust-gate
conditions, independent of the runner pool.
