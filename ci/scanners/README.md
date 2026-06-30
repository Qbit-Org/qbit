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

## Artifact Policy

The runner captures command stdout/stderr and full scanner reports under each scanner's `raw/` directory. Treat `raw/` as private because scanner output can contain sensitive paths, redacted secret context, or unpublished vulnerability details.

Shareable evidence is limited to:

- `summary.json`
- `triage.jsonl`
- the aggregate `summary.json`
- this README

CI uploads only those files. Review-record export/import also copies only scanner summaries and triage files, never `evidence/scanners/*/raw/*`.
