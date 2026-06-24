# libbitcoinpqc Subtree Runbook

This runbook defines the update flow for `src/libbitcoinpqc` in the qbit
repository.

The subtree source is `Qbit-Org/qbit-libbitcoinpqc`. Imports must use immutable
release tags from that repository, not the moving `main` branch.

## Current Pin

- Source repository: `https://github.com/Qbit-Org/qbit-libbitcoinpqc.git`
- Source tag: `v0.3.0`
- Peeled tag commit: `ac72d1ffa0ef486f08d37334a43f5db1adb731db`
- qbit subtree path: `src/libbitcoinpqc`

`v0.3.0` is an annotated tag. Git subtree metadata records the peeled commit,
so the expected `git-subtree-split` value is
`ac72d1ffa0ef486f08d37334a43f5db1adb731db`.

## Import Or Refresh The Subtree

Run in a clean `qbit` worktree:

```bash
git fetch origin
git checkout <your-qbit-branch>
contrib/devtools/update-libbitcoinpqc-subtree.sh
```

The helper defaults to `Qbit-Org/qbit-libbitcoinpqc` tag `v0.3.0`. To test a
future release candidate before changing the defaults:

```bash
LIBBITCOINPQC_REMOTE_REF=<tag> \
contrib/devtools/update-libbitcoinpqc-subtree.sh
```

or:

```bash
contrib/devtools/update-libbitcoinpqc-subtree.sh <tag>
```

Do not import from `main`; create and review a release tag in
`qbit-libbitcoinpqc` first.

## Verify Subtree Integrity

After importing, verify that the qbit subtree exactly matches the upstream
commit referenced by the subtree metadata:

```bash
git fetch https://github.com/Qbit-Org/qbit-libbitcoinpqc.git v0.3.0
test/lint/git-subtree-check.sh -r src/libbitcoinpqc
```

The check should report `GOOD` and show the subtree split commit as
`ac72d1ffa0ef486f08d37334a43f5db1adb731db` for the current pin.

## PR Checklist For Subtree Updates

When a PR touches `src/libbitcoinpqc`, confirm:

- [ ] The source commit is reachable from an immutable release tag in
  `Qbit-Org/qbit-libbitcoinpqc`.
- [ ] qbit imported that tag via `contrib/devtools/update-libbitcoinpqc-subtree.sh`.
- [ ] `test/lint/git-subtree-check.sh -r src/libbitcoinpqc` passes locally.
- [ ] Any default tag change in `contrib/devtools/update-libbitcoinpqc-subtree.sh`
  is intentional and matches this runbook.

## Common Failures

1. Signature:
   `FAIL: subtree directory was touched without subtree merge`
   Cause:
   Files under `src/libbitcoinpqc` were edited manually after the subtree import.
   Fix:
   Re-import via `contrib/devtools/update-libbitcoinpqc-subtree.sh`.

2. Signature:
   `subtree commit <hash> unavailable: cannot compare. Did you add and fetch the remote?`
   Cause:
   `git-subtree-check.sh -r` cannot find the upstream commit locally.
   Fix:
   Run the update script, or fetch the pinned tag from
   `Qbit-Org/qbit-libbitcoinpqc`, before the `-r` check.

3. Signature:
   `fatal: unable to access 'https://github.com/...': The requested URL returned error: 403`
   Cause:
   The repository requires credentials for HTTPS fetches.
   Fix:
   Use an authenticated remote URL override:
   `LIBBITCOINPQC_REMOTE_URL=git@github.com:Qbit-Org/qbit-libbitcoinpqc.git`.
