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

## Downstream Build Policy

qbit always compiles the integrated `bitcoinpqc` target with
`SPX_PRODUCTION_BUILD=1`. Configuring qbit with
`SPX_ENABLE_TEST_BENCH_ENV_KNOBS=ON` is prohibited because it would make
consensus-reachable PQC behavior selectable through test and benchmark
environment variables. The qbit CMake configuration fails rather than
silently overriding that request.

Backend experiments that require the runtime controls must configure
`src/libbitcoinpqc` as a standalone project. Upstream work to make differential
tests prove which accelerated implementation ran is tracked in
[`Qbit-Org/qbit-libbitcoinpqc#3`](https://github.com/Qbit-Org/qbit-libbitcoinpqc/issues/3).

`BITCOINPQC_WOTSC_MAX_COUNTER` is an operational signing cap used while
signing statistics are active, not a verifier protocol limit. Verification
continues to accept the full two-byte WOTS+C counter range. See the subtree's
[`bounded30` signature-limit documentation](../../src/libbitcoinpqc/docs/bounded30-signature-limit.md)
for the complete distinction.

## Refresh The Subtree

Refresh the subtree to a release with the helper, from a clean `qbit` worktree:

```bash
git fetch origin
git checkout <your-qbit-branch>
contrib/devtools/update-libbitcoinpqc-subtree.sh <tag>
```

The helper replaces `src/libbitcoinpqc` with the release's tree in one
main-line commit titled "Squashed 'src/libbitcoinpqc/' changes from
<old>..<new>" that carries the `git-subtree-dir` and `git-subtree-split`
trailers, as Qbit-Org/qbit#268 did. Without `<tag>`, it imports
`LIBBITCOINPQC_REMOTE_REF`, or else its pinned `DEFAULT_REMOTE_REF`. Do not
import from `main`; create and review a release tag in `qbit-libbitcoinpqc`
first.

The helper only refreshes an existing import: it reads the current split from
`HEAD`'s newest import commit and stops if there is none. A first import is a
maintainer task outside the helper.

Every check runs before the tree changes, and the helper stops at the first
one that fails:

- Git must be 2.45 or later, because the downstream-delta check passes trees,
  not commits, to `git merge-tree`.
- The worktree and the index must both match `HEAD`, with no untracked or
  ignored files under `src/libbitcoinpqc`, so nothing else lands in the import
  commit. List ignored files with `git clean -ndX src/libbitcoinpqc`.
- The current split is read from `HEAD`'s newest non-merge commit that carries
  `git-subtree-dir: src/libbitcoinpqc`, the same search the subtree check uses.
  It skips merge commits, whose pull request titles could quote the trailer,
  and takes no pathspec, so an import commit that only moved the split is
  found. A later non-merge commit that quotes the trailer can only make the
  check fail.
- The release tag must be an annotated tag with a good signature (`VALIDSIG`)
  from operator-01's signing key, `289EA3EC2F1939A24984840ED26CFC05586D371E`
  (listed in `contrib/keys/operator-keys/KEYS.md`), which signed `v0.3.0` and
  `v0.3.2`. The helper checks it against a throwaway keyring that holds only
  that certificate and is removed on every exit. A different signer needs a
  maintainer decision before the import.
- The signed tag object's own header must say `tag <tag>` and `type commit`, so
  an older signed tag published under a new name is refused. The helper reads
  the tag object ID once, right after the fetch, and uses it throughout.
- The release must descend from the current split, unless `--allow-downgrade`
  is given, so a mistyped older tag is not imported.
- No downstream delta may be dropped. The helper merges the qbit subtree into
  the release with `git merge-tree`, using the old release as the merge base.
  Where the result differs from the release, it lists the paths and stops; see
  [Reviewing A Downstream Delta](#reviewing-a-downstream-delta).

The import commit is made with the caller's own GnuPG environment, so a
maintainer whose commits are signed gets a signed import commit. When the
release's tree equals the vendored tree, as when a release upstreams qbit's
approved downstream delta, the import commit only moves `git-subtree-split`
and changes no file. The helper then runs
`test/lint/libbitcoinpqc-subtree-check.sh`, which resolves the exact
`refs/tags/<tag>`, and checks that the commit the lint verified is the tag's
commit. If either check fails, the helper undoes the import commit and exits
non-zero, so no unverified import commit is left behind; if the undo itself
fails, it says to run `git reset --hard HEAD~1`. Importing the tag that is
already imported changes nothing, but still runs the subtree check, so drift in
the vendored tree is reported.

| Flag or variable | Use |
| --- | --- |
| `--allow-downgrade` | Import a release that does not descend from the current split. |
| `--accept-upstream <path>` | Take the release's version of a listed path, relative to `src/libbitcoinpqc`. Name each listed path once; a path that differs and is not named still stops the import. |
| `LIBBITCOINPQC_REMOTE_URL` | Upstream repository. Default: `https://github.com/Qbit-Org/qbit-libbitcoinpqc.git`. |
| `LIBBITCOINPQC_REMOTE_REF` | Tag to import when none is given. |
| `--test-signer-cert <path>`, `--test-signer-fingerprint <fpr>` | Test-only flags, used together by `ci/checks/test_update_libbitcoinpqc_subtree.py`, that replace the pinned signer and print `TEST SIGNER IN USE`. Never use them for a release import. No environment variable can change the signer. |

### Reviewing A Downstream Delta

When the helper lists paths, the qbit subtree has a change that the release
lacks, or that conflicts with how the release changed the same file. The error
names the current split and the new split, and lists conflicted paths apart from
paths with qbit changes the release lacks. Each path is listed by its real name,
including renamed and non-ASCII paths. For each listed path:

1. Show qbit's change:
   `git diff <current-split>^{tree} HEAD:src/libbitcoinpqc -- <path>`.
2. Show the release's change: `git diff <current-split> <new-split> -- <path>`.
3. Decide:
   - If the release already fixes the same problem, possibly in a different
     way, rerun the helper with `--accept-upstream <path>`, and remove the
     delta from the approved list in
     [Verify Subtree Integrity](#verify-subtree-integrity) and the subtree
     check.
   - If the release lacks the change, prefer a new upstream release that has
     it. Otherwise rerun with `--accept-upstream <path>`, re-apply the change in
     a separate commit, and record it as an approved delta in both places.

Then update every pin location in a separate commit:

- `contrib/devtools/update-libbitcoinpqc-subtree.sh`: `DEFAULT_REMOTE_REF`;
- `test/lint/libbitcoinpqc-subtree-check.sh`: `REMOTE_REF` and the default in
  its usage text;
- `ci/scanners/run-scanners.py`: `LIBBITCOINPQC_UPSTREAM_TAG`;
- `test/fuzz/shared_target_mappings.json`: `tag` and `peeled_commit`;
- this runbook: the Current Pin section and the split commit in
  [Verify Subtree Integrity](#verify-subtree-integrity);
- `contrib/devtools/README.md`: the default tag.

`git grep -n -e <old tag> -e <old peeled commit> -- ':!src/libbitcoinpqc'`
lists the remaining mentions to review; release notes and the fixed fixtures in
`ci/scanners/test_run_scanners.py` keep theirs.

## Verify Subtree Integrity

After importing, verify that the qbit subtree exactly matches the upstream
commit referenced by the subtree metadata:

```bash
test/lint/libbitcoinpqc-subtree-check.sh
```

The check fetches the pinned tag if needed, should report `GOOD`, and should
show the subtree split commit as `ac72d1ffa0ef486f08d37334a43f5db1adb731db`
for the current pin.

The current qbit tree carries one approved downstream security delta on top of
the pinned upstream tag: `RUSTSEC-2026-0204-crossbeam-epoch-0.9.20`, which
updates only `src/libbitcoinpqc/Cargo.lock` from `crossbeam-epoch 0.9.18` to
`0.9.20`. The subtree check accepts exactly that lockfile hunk and no other
subtree drift. Drop the exception after `Qbit-Org/qbit-libbitcoinpqc` publishes
an immutable tag containing the same advisory fix and qbit imports it.

## PR Checklist For Subtree Updates

When a PR touches `src/libbitcoinpqc`, confirm:

- [ ] The source commit is the peeled commit of an immutable release tag in
  `Qbit-Org/qbit-libbitcoinpqc`.
- [ ] qbit imported that tag with `contrib/devtools/update-libbitcoinpqc-subtree.sh`,
  as one main-line import commit that keeps its `git-subtree-dir` and
  `git-subtree-split` trailers.
- [ ] `test/lint/libbitcoinpqc-subtree-check.sh` passes locally.
- [ ] Any pin change updates every location listed in
  [Refresh The Subtree](#refresh-the-subtree) and is
  intentional.
- [ ] Any use of `--allow-downgrade` or `--accept-upstream` is explained in the
  pull request.
- [ ] Any downstream security delta is listed above, is limited to the exact
  lint allowlist, and is removed once a fixed upstream release tag is imported.

## Common Failures

1. Signature:
   `FAIL: src/libbitcoinpqc tree differs from upstream tag <tag>`
   Cause:
   Files under `src/libbitcoinpqc` were edited manually after the subtree import.
   Fix:
   Re-import via `contrib/devtools/update-libbitcoinpqc-subtree.sh`.

2. Signature:
   `FAIL: subtree split <hash> does not match upstream tag commit <hash>`
   Cause:
   The recorded `git-subtree-split` metadata does not match the configured
   release tag.
   Fix:
   Re-import the intended release tag via
   `contrib/devtools/update-libbitcoinpqc-subtree.sh`.

3. Signature:
   `fatal: unable to access 'https://github.com/...': The requested URL returned error: 403`
   Cause:
   The repository requires credentials for HTTPS fetches.
   Fix:
   Use an authenticated remote URL override:
   `LIBBITCOINPQC_REMOTE_URL=git@github.com:Qbit-Org/qbit-libbitcoinpqc.git`.
