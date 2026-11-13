# libbitcoinpqc Subtree Runbook

This runbook defines the update flow for `src/libbitcoinpqc` in the qbit
repository.

The subtree source is `Qbit-Org/qbit-libbitcoinpqc`. Imports must use immutable
release tags from that repository, not the moving `main` branch.

## Current Pin

- Source repository: `https://github.com/Qbit-Org/qbit-libbitcoinpqc.git`
- Source tag: `v0.3.2`
- Peeled tag commit: `1965d0da1eb4d9e196613b8f3a5d0d866a221c53`
- qbit subtree path: `src/libbitcoinpqc`

`v0.3.2` is an annotated tag. Git subtree metadata records the peeled commit,
so the expected `git-subtree-split` value is
`1965d0da1eb4d9e196613b8f3a5d0d866a221c53`.

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

Since `v0.3.1`, `slh_dsa_keygen()`, `slh_dsa_sign()`,
`slh_dsa_sign_with_stats()`, `slh_dsa_secret_key_validate()` and
`slh_dsa_derandomize()` overwrite the stack they released before returning,
so SK_SEED, SK_PRF and SHA-2 scratch do not outlive the call. The burn is
`BITCOIN_PQC_BURN_STACK_BYTES`: 16 KiB when the library is compiled with
optimization and 288 KiB without it (208 KiB before `v0.3.2`). qbit compiles
the subtree with its RelWithDebInfo C flags (`-O2`) in every build type.
CMake places them after `CMAKE_C_FLAGS`, which is where `APPEND_CFLAGS` and
`APPEND_CPPFLAGS` go, so an appended `-O0` does not take effect: the
optimized size applies and each direct call into the library needs about
17 KiB of free stack. qbit's own wrappers need more: after each
`CPQCKey::MakeNewKey()`, `CPQCKey::Set()`, `CPQCKey::Sign()` and
`DerivePQCKey()` call, qbit overwrites `PQC_STACK_BURN_BYTES` (32 KiB) of the
stack the call released, so each of those calls needs at least 32 KiB of
free stack plus its own frames. Verification does not burn. qbit does not
shrink the stacks of the threads that sign, so they keep the platform
default, which is 512 KiB or more on qbit's release platforms. musl gives
threads only 128 KiB by default, which leaves less margin.

`v0.3.2` adds `BITCOIN_PQC_ERROR_OUT_OF_MEMORY` (`-6`), which keygen and sign
return when an allocation fails, and signing with a secret key that fails
`bitcoin_pqc_secret_key_validate()` now returns `BITCOIN_PQC_ERROR_BAD_KEY`
(`slh_dsa_sign()` returns `SLH_DSA_SIGN_ERROR_BAD_KEY`). qbit's callers treat
any nonzero result as a failure, so neither change alters how qbit signs.
Keys, signatures and verification results are unchanged from `v0.3.1`.

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
  check fail. The search runs in topological order, so a skewed committer date
  cannot make an older import win over one that descends from it.
- The release tag must be an annotated tag with a good signature (`VALIDSIG`)
  from operator-01's signing key, `289EA3EC2F1939A24984840ED26CFC05586D371E`
  (listed in `contrib/keys/operator-keys/KEYS.md`), which signed `v0.3.0`,
  `v0.3.1` and `v0.3.2`. The helper checks it against a throwaway keyring that
  holds only that certificate and is removed on every exit. A different signer
  needs a maintainer decision before the import. The subtree check runs the
  same check, from `test/lint/libbitcoinpqc-release-tag.sh`, so CI verifies the
  signer of the pinned tag too.
- The signed tag object's own header must say `tag <tag>` and `type commit`, so
  an older signed tag published under a new name is refused. The helper fetches
  the tag object into the private ref `refs/libbitcoinpqc-import/tag`, never
  `FETCH_HEAD`, reads its ID once, uses it throughout, and deletes the ref on
  exit.
- The release must descend from the current split, unless `--allow-downgrade`
  is given, so a mistyped older tag is not imported.
- No downstream delta may be dropped. The helper merges the qbit subtree into
  the release with `git merge-tree`, using the old release as the merge base.
  Where the result differs from the release, it lists the paths and stops; see
  [Reviewing A Downstream Delta](#reviewing-a-downstream-delta).

The import commit is made with the caller's own GnuPG environment, so a
maintainer whose commits are signed gets a signed import commit. When the
release's tree equals the vendored tree, the import commit only moves
`git-subtree-split` and changes no file. The helper then runs
`test/lint/libbitcoinpqc-subtree-check.sh`, which fetches the exact
`refs/tags/<tag>` and checks its signer and header the same way, and checks
that the commit the lint verified is the tag's commit. The import is done only
when both checks pass. Until then any exit, including an interrupt (Ctrl-C,
`SIGTERM` or `SIGHUP`), undoes the import commit, so no unverified import
commit is left behind; if the undo itself fails, the helper says to run
`git reset --hard <commit before the import>`. Importing the tag that is
already imported changes nothing, but still runs the subtree check, so drift in
the vendored tree is reported.

| Flag or variable | Use |
| --- | --- |
| `--allow-downgrade` | Import a release that does not descend from the current split. |
| `--accept-upstream <path>` | Take the release's version of a listed path, relative to `src/libbitcoinpqc`. Name each listed path once; a path that differs and is not named still stops the import. |
| `LIBBITCOINPQC_REMOTE_URL` | Upstream repository. Default: `https://github.com/Qbit-Org/qbit-libbitcoinpqc.git`. A relative path is read from the directory the helper starts in. |
| `LIBBITCOINPQC_REMOTE_REF` | Tag to import when none is given. |
| `--test-signer-cert <path>`, `--test-signer-fingerprint <fpr>` | Test-only flags, used together by `ci/checks/test_update_libbitcoinpqc_subtree.py`, that replace the pinned signer and print `TEST SIGNER IN USE`. The helper and the subtree check accept them only when the remote is a local repository (a path or a `file://` URL, after any `url.<base>.insteadOf` rewriting), so the real upstream is always checked against the pinned signer. No environment variable can change the signer. |

The prefix is fixed: neither the helper nor the subtree check reads
`LIBBITCOINPQC_PATH`.

### Reviewing A Downstream Delta

When the helper lists paths, the qbit subtree has a change that the release
lacks, or that conflicts with how the release changed the same file. The error
names the current split and the new split, and lists conflicted paths apart from
paths with qbit changes the release lacks. Each path is listed by its real name,
including renamed and non-ASCII paths. For each listed path:

1. Show qbit's change:
   `git diff <current-split>^{tree} HEAD:src/libbitcoinpqc -- <path>`.
2. Show the release's change: `git diff <current-split> <new-split> -- <path>`.
3. Decide. A downstream delta cannot land: the subtree check accepts none, and
   a committed edit under `src/libbitcoinpqc` fails it with
   `tree differs from latest subtree import commit <hash>`.
   - If the release already fixes the same problem, possibly in a different
     way, rerun the helper with `--accept-upstream <path>`. Use this flag only
     to accept the release's version.
   - If the release lacks the change, ship it through a new upstream release
     tag and import that tag instead.

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

### Signing The Import

Under the signed-commit policy, `squash-sign` squashes the pull request's
commits (the import, the pin and test changes, and the release notes) into one
operator-signed commit. The helper's import is one main-line commit that
carries the `git-subtree-dir` and `git-subtree-split` trailers, and
`squash-sign` keeps those trailers, so the lint still passes; that needs one
touch. See
[Signed Commits](../development/public-branch-and-rulesets.md#signed-commits).

For a large vendored import, the signature attests the pin, not a line-by-line
reading of the vendored code: the operator does not review an import of about
2,000 lines line by line. Before touching, the operator checks:

- the upstream commit: `git-subtree-split` is the peeled commit of the signed
  upstream release tag;
- the lint result: `test/lint/libbitcoinpqc-subtree-check.sh` reports `GOOD`,
  which compares the vendored tree with the upstream tree;
- the pin test: every pin location names the new tag, and the tests that read
  those pins pass.

A fork pull request that touches `src/libbitcoinpqc` is not merged or
recreated from the fork: a maintainer re-imports the release in a branch of
this repository.

## Verify Subtree Integrity

After importing, verify that the qbit subtree exactly matches the upstream
commit referenced by the subtree metadata:

```bash
test/lint/libbitcoinpqc-subtree-check.sh
```

The check fetches the pinned tag object, requires a good signature from
operator-01's pinned signing key and the tag's own header, should report
`GOOD`, and should show the subtree split commit as
`1965d0da1eb4d9e196613b8f3a5d0d866a221c53` for the current pin. It fetches
the whole upstream history, which is small, because a `--depth` fetch would
mark the qbit checkout shallow.

The check's search for the newest import commit, described in
[Refresh The Subtree](#refresh-the-subtree), walks every parent, not only the
first: with merge-commit merges, the import commit is the merge's second
parent, so a `--first-parent` search would skip it.

The current qbit tree carries no downstream delta: `HEAD:src/libbitcoinpqc`
must equal the tagged upstream tree. Since `v0.3.1`, upstream contains the
`RUSTSEC-2026-0204` `crossbeam-epoch 0.9.20` lockfile fix that qbit carried
as a downstream patch on `v0.3.0`, so the subtree check no longer accepts any
lockfile exception.

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
- [ ] `src/libbitcoinpqc` carries no downstream delta; any change it needs ships
  through a new upstream release tag.

## Common Failures

1. Signature:
   `FAIL: src/libbitcoinpqc tree differs from latest subtree import commit <hash>`
   Cause:
   A commit edited files under `src/libbitcoinpqc` after the subtree import.
   Fix:
   Rerunning the helper does not repair this. With the edit committed it stops
   with `already imports <tag>, but the subtree check failed`, and with an
   uncommitted edit it refuses the dirty worktree. Discard any uncommitted edit
   with `git restore src/libbitcoinpqc`. Then restore the prefix from the tree
   of the `git-subtree-split` commit the check printed, commit that, because the
   check reads `HEAD`, and rerun the check:

   ```bash
   git rm -r -q -- src/libbitcoinpqc
   git read-tree --prefix=src/libbitcoinpqc/ -u <git-subtree-split>^{tree}
   git commit -m "Restore src/libbitcoinpqc to the imported release"
   test/lint/libbitcoinpqc-subtree-check.sh
   ```

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

4. Signature:
   `<tag> is not a signed annotated tag` or
   `<tag> has no good signature from <fingerprint>`, then
   `error: <tag> is not a release tag signed by <fingerprint>; not importing`
   from the helper or
   `FAIL: <url> <tag> is not a release tag signed by <fingerprint>` from the
   subtree check
   Cause:
   The tag is lightweight, unsigned, or signed by a key other than operator-01's
   pinned signing key.
   Fix:
   Do not import it. Import a signed annotated tag from operator-01. A different
   signer needs a maintainer decision before the import.

5. Signature:
   `the fetched tag object is not <tag> pointing at a commit`, then the
   `is not a release tag signed by <fingerprint>` error above
   Cause:
   The signed tag object's own header does not say `tag <tag>` and `type commit`,
   as when an older signed tag is published under a new name.
   Fix:
   Do not import it. Publish a new signed tag whose header names it, and import
   that tag.

6. Signature:
   `error: importing <tag> would drop or override qbit changes under src/libbitcoinpqc`
   Cause:
   The qbit subtree has a change that the release lacks, or that conflicts with
   how the release changed the same file.
   Fix:
   Follow [Reviewing A Downstream Delta](#reviewing-a-downstream-delta).

7. Signature:
   `error: <tag> (<commit>) does not descend from the current split <hash>; pass --allow-downgrade to import it anyway`
   Cause:
   The tag is not a descendant of the current import, usually because the tag
   name was mistyped.
   Fix:
   Check the tag name. Pass `--allow-downgrade` only for an intended downgrade,
   and explain it in the pull request.
