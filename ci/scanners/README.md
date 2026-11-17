# Scanner Evidence

`run-scanners.py` collects scanner evidence for qbit without printing raw scanner output.

## Scanner Sets

- `minimum`: CodeQL, OSV, vendored inventory, gitleaks, zizmor, actionlint, Semgrep, Clang Static Analyzer, Syft, Grype, cargo-audit, release sanitizer, and fuzz hook inventory.
- `dependency-only`: OSV, Syft, Grype, cargo-audit, and vendored inventory.
- `secrets-only`: gitleaks with redaction enabled.
- `workflow-only`: zizmor, actionlint, and CodeQL.
- `sast-only`: CodeQL, Semgrep, and Clang Static Analyzer.
- `release-only`: release sanitizer dry run.

## Local Usage

```bash
python3 ci/scanners/run-scanners.py \
  --mode manual_dry_run \
  --scanner-set minimum
```

`ci/scanners/install-scanner-tools.sh` installs the external executables required by
`minimum` on Linux runners. It writes installed binary paths to
`$GITHUB_PATH` when running in GitHub Actions.

The vendored `src/libbitcoinpqc` provenance scanner verifies the recorded
`git-subtree-split` against the pinned public `Qbit-Org/qbit-libbitcoinpqc`
release tag documented in `doc/subtrees/libbitcoinpqc.md`.
`LIBBITCOINPQC_READ_TOKEN` is used for authenticated access when present, and
`UPSTREAM_GITHUB_TOKEN` is accepted as a compatibility fallback for existing
libbitcoinpqc evidence workflows.

For frozen review evidence, write summaries directly into the review record workspace:

```bash
python3 ci/scanners/run-scanners.py \
  --mode frozen_evidence \
  --review-id <review_id> \
  --freeze-commit <freeze_commit> \
  --source-commit <freeze_commit> \
  --history-diff-base-ref origin/main \
  --fail-policy infra-and-secrets
```

Git-history scanners are intentionally bounded. The runner resolves
`merge-base(--source-commit, --history-diff-base-ref)..--source-commit`; with
the default `origin/main` base, scheduled `0.1.x` runs scan the qbit
`main...0.1.x` history window instead of inherited upstream `main` history.

Without `--history-diff-base-ref`, gitleaks scans the whole history with
`--remerge-diff`, which shows, as added lines, how each conflicted merge
resolved its conflicts. qbit's history carries about 15.6k merge commits
inherited from upstream, so the first full-history scan can report
conflict-resolution lines from those merges as new findings. Triage them once
in `triage.jsonl` on that first full scan, or scan with a base ref. gitleaks
8.30.1 reports a finding in a conflicted file as `b/<path>`, so triage it under
that name. On this repository the full-history scan takes about 45 seconds,
against about 28 without `--remerge-diff`.

## Fail Policies

`--fail-policy` decides when the run exits non-zero:

- `never`: never.
- `infra-only`: a scanner failed or its tool is missing.
- `infra-and-secrets` (the nightly default): `infra-only`, or gitleaks reports
  an untriaged finding.
- `high-critical`: `infra-only`, or any scanner reports an untriaged high or
  critical finding. Every gitleaks finding counts as high.

The two policies that fail on secrets, `infra-and-secrets` and
`high-critical`, also fail when the gitleaks history scan is incomplete:
gitleaks was skipped, failed or missing, ran without `--remerge-diff` on a Git
older than 2.36, met a shallow boundary inside the scanned history, or the
history has octopus merges, which `--remerge-diff` cannot show. A scan that
missed part of the history cannot show that it holds no secret. Informational
coverage gaps, such as a skipped zizmor or a skipped build-backed scanner, fail
no policy.

## Artifact Policy

The runner captures command stdout/stderr and full scanner reports under each scanner's `raw/` directory. Treat `raw/` as private because scanner output can contain sensitive paths, redacted secret context, or unpublished vulnerability details.

Shareable evidence is limited to:

- `summary.json`
- `triage.jsonl`
- the aggregate `summary.json`
- this README

CI uploads only those files. Review-record export/import also copies only scanner summaries and triage files, never `evidence/scanners/*/raw/*`.
