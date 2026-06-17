# libbitcoinpqc Subtree Runbook

This runbook defines the update flow for `src/libbitcoinpqc` in the qbit repository.

The update is a two-repo process:
- Curate `libbitcoinpqc-qbit` (`develop` -> `qbit-subtree`).
- Import `qbit-subtree` into qbit as a squashed subtree update.

Do not import from `libbitcoinpqc-qbit/develop` directly.

## Branch Roles

- `libbitcoinpqc-qbit:develop`:
  Full upstream development branch. Includes tests, bindings, docs, and tooling.
- `libbitcoinpqc-qbit:qbit-subtree`:
  Curated branch for qbit subtree imports. This branch is produced by pruning
  non-runtime payload after integrating `develop`.
- `qbit:src/libbitcoinpqc`:
  Squashed subtree mirror of `libbitcoinpqc-qbit:qbit-subtree`.

## Phase 1: Refresh `qbit-subtree` in `libbitcoinpqc-qbit`

Run in a clean `libbitcoinpqc-qbit` clone:

```bash
git fetch origin
git checkout -B qbit-subtree-update origin/qbit-subtree
git merge --no-ff origin/develop
scripts/prune-for-qbit-subtree.sh
git add -A
git commit -m "subtree: prune non-runtime payload for qbit"
git push origin HEAD:qbit-subtree
```

qbit intentionally does not keep a local copy of the prune helper under
`src/libbitcoinpqc/scripts/`. The canonical helper is
`libbitcoinpqc-qbit:develop:scripts/prune-for-qbit-subtree.sh`, and it deletes
itself from the curated `qbit-subtree` output after pruning. If
`scripts/prune-for-qbit-subtree.sh` is missing in your upstream working branch,
recover it from `origin/develop`, not from `origin/qbit-subtree`:

```bash
mkdir -p scripts
git show origin/develop:scripts/prune-for-qbit-subtree.sh > scripts/prune-for-qbit-subtree.sh
chmod +x scripts/prune-for-qbit-subtree.sh
```

## Phase 2: Import Curated Subtree into qbit

Run in a clean `qbit` worktree:

```bash
git fetch origin
git checkout <your-qbit-branch>
LIBBITCOINPQC_REMOTE_URL=git@github.com:<owner>/libbitcoinpqc-qbit.git \
contrib/devtools/update-libbitcoinpqc-subtree.sh
```

Verify full subtree integrity:

```bash
test/lint/git-subtree-check.sh -r src/libbitcoinpqc
```

## PR Checklist For Subtree Updates

When a PR touches `src/libbitcoinpqc`, confirm:

- [ ] Upstream fix was merged into `libbitcoinpqc-qbit/develop`.
- [ ] Curated `libbitcoinpqc-qbit/qbit-subtree` was refreshed with prune.
- [ ] qbit subtree was updated via `contrib/devtools/update-libbitcoinpqc-subtree.sh`.
- [ ] `test/lint/git-subtree-check.sh -r src/libbitcoinpqc` passes locally.

## Common Failures

1. Signature:
   `/tmp/.../src/libbitcoinpqc/sphincsplus/ref/sha2.c:... runtime error: left shift ...`
   Cause:
   Fix landed in `libbitcoinpqc-qbit/develop` but `qbit-subtree` was not refreshed.
   Fix:
   Re-run Phase 1, then re-run Phase 2.

2. Signature:
   `FAIL: subtree directory was touched without subtree merge`
   Cause:
   Manual edits in `src/libbitcoinpqc` bypassed subtree import.
   Fix:
   Re-import via `contrib/devtools/update-libbitcoinpqc-subtree.sh`.

3. Signature:
   `fatal: unable to access 'https://github.com/...': The requested URL returned error: 403`
   Cause:
   Private repo fetch over HTTPS without credentials.
   Fix:
   Use SSH remote URL override:
   `LIBBITCOINPQC_REMOTE_URL=git@github.com:<owner>/libbitcoinpqc-qbit.git`.

4. Signature:
   `subtree commit <hash> unavailable: cannot compare. Did you add and fetch the remote?`
   Cause:
   `git-subtree-check.sh -r` cannot find the upstream commit locally.
   Fix:
   Run the update script (or fetch the upstream ref) before the `-r` check.
