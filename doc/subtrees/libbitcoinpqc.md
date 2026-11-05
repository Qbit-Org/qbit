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

## Import Or Refresh The Subtree

Import a release as one main-line commit that replaces `src/libbitcoinpqc`
with the upstream release tree and carries the `git-subtree-dir` and
`git-subtree-split` trailers, as Qbit-Org/qbit#268 did. Run in a clean `qbit`
worktree:

```bash
git fetch origin
git checkout <your-qbit-branch>
(
  set -euo pipefail
  tag=<tag>
  old_split=<old-split>
  upstream_url=https://github.com/Qbit-Org/qbit-libbitcoinpqc.git
  operator_01=289EA3EC2F1939A24984840ED26CFC05586D371E

  # The downstream-delta check below passes trees to git merge-tree.
  git_version="$(git version)"
  if [[ ! "${git_version}" =~ ^git\ version\ ([0-9]+)\.([0-9]+) ]] ||
     (( BASH_REMATCH[1] < 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] < 45) )); then
    echo "error: this import needs Git 2.45 or later; found ${git_version}" >&2
    exit 1
  fi

  # Refuse to run with local changes, which would land in the import commit,
  # or with ignored files under the prefix, which would survive the import.
  if ! git diff --quiet HEAD -- ||
     [[ -n "$(git ls-files --others --exclude-standard -- src/libbitcoinpqc)" ]]; then
    echo "error: commit or stash local changes before importing" >&2
    exit 1
  fi
  if [[ -n "$(git ls-files --others -- src/libbitcoinpqc)" ]]; then
    echo "error: ignored files under src/libbitcoinpqc; list them with" \
      "git clean -ndX src/libbitcoinpqc and remove them before importing" >&2
    exit 1
  fi

  # old_split must be the split that HEAD's newest import records.
  recorded_split="$(git log --grep='^git-subtree-dir: src/libbitcoinpqc/*$' \
    --format=%B -n 1 HEAD |
    awk '/^git-subtree-split: / && !found { found = $2 } END { print found }')"
  if [[ "${recorded_split}" != "${old_split}" ]]; then
    echo "error: old_split ${old_split} is not the recorded split" \
      "${recorded_split:-(none)}" >&2
    exit 1
  fi

  git fetch "${upstream_url}" "refs/tags/${tag}"
  tag_object="$(git rev-parse FETCH_HEAD)"

  # Check the tag with a throwaway keyring that holds only operator-01's
  # certificate. The nested subshell removes the keyring on every exit, and
  # the import below runs with the maintainer's own GnuPG environment.
  (
    GNUPGHOME="$(mktemp -d)"
    export GNUPGHOME
    trap 'gpgconf --kill all || true; gpgconf --remove-socketdir || true; rm -rf "${GNUPGHOME}"' EXIT
    gpg --batch --quiet --import \
      contrib/keys/operator-keys/public-keys/operator-01-release.asc
    if ! verify_status="$(git -c gpg.openpgp.program=gpg verify-tag --raw "${tag_object}" 2>&1)" ||
       ! grep -q "^\[GNUPG:\] VALIDSIG ${operator_01} " <<<"${verify_status}"; then
      printf '%s\n' "${verify_status}" >&2
      echo "error: ${tag} has no good signature from operator-01; not importing" >&2
      exit 1
    fi
    # The signed tag object must name this tag and point at a commit, so an
    # older signed tag published under a new name is refused.
    tag_header="$(git cat-file tag "${tag_object}" | sed -n '1,/^$/p')"
    if ! grep -qxF "tag ${tag}" <<<"${tag_header}" ||
       ! grep -qxF "type commit" <<<"${tag_header}"; then
      printf '%s\n' "${tag_header}" >&2
      echo "error: the fetched tag object is not ${tag} pointing at a commit" >&2
      exit 1
    fi
  )

  # A downstream delta on top of the old release must already be in the new
  # one: merging it into the new release must give exactly the new tree.
  if ! git cat-file -e "${old_split}^{commit}" 2>/dev/null; then
    git fetch "${upstream_url}" "${old_split}"
  fi
  old_upstream_tree="$(git rev-parse "${old_split}^{tree}")"
  qbit_tree="$(git rev-parse HEAD:src/libbitcoinpqc)"
  new_upstream_tree="$(git rev-parse "${tag_object}^{tree}")"
  merge_status=0
  merge_output="$(git merge-tree --write-tree --merge-base="${old_upstream_tree}" \
    "${qbit_tree}" "${new_upstream_tree}")" || merge_status=$?
  merged_tree="${merge_output%%[[:space:]]*}"
  if [[ "${merge_status}" -ne 0 || "${merged_tree}" != "${new_upstream_tree}" ]]; then
    echo "error: importing ${tag} would drop a downstream delta; paths that" \
      "differ from ${tag}:" >&2
    git diff --name-status "${new_upstream_tree}" "${merged_tree}" >&2 || true
    exit 1
  fi

  # Nothing below runs unless the checks above passed.
  upstream_commit="$(git rev-parse "${tag_object}^{commit}")"
  git rm -r -q src/libbitcoinpqc
  git read-tree --prefix=src/libbitcoinpqc/ -u "${upstream_commit}^{tree}"
  git commit \
    -m "Squashed 'src/libbitcoinpqc/' changes from ${old_split:0:10}..${upstream_commit:0:10}" \
    -m "git-subtree-dir: src/libbitcoinpqc
git-subtree-split: ${upstream_commit}"
  LIBBITCOINPQC_REMOTE_URL="${upstream_url}" LIBBITCOINPQC_REMOTE_REF="${tag}" \
    test/lint/libbitcoinpqc-subtree-check.sh
)
```

Set `tag` to the release tag and `old_split` to the current `git-subtree-split`
value; the block does not run while either placeholder is left in. The block
stops at the first failing command, and every check runs before `git rm`
changes the tree:

- Git must be 2.45 or later, because the downstream-delta check passes trees,
  not commits, to `git merge-tree`.
- The index and worktree must match `HEAD`, with no untracked files under
  `src/libbitcoinpqc`, so nothing else lands in the import commit. Ignored
  files under the prefix, such as build artefacts, are refused too; list them
  with `git clean -ndX src/libbitcoinpqc`.
- `old_split` must equal the `git-subtree-split` of `HEAD`'s newest import
  commit.
- The release tag must be an annotated tag with a good signature (`VALIDSIG`)
  from operator-01's signing key, `289EA3EC2F1939A24984840ED26CFC05586D371E`
  (listed in `contrib/keys/operator-keys/KEYS.md`), which signed `v0.3.0` and
  `v0.3.2`. Stop there: a different signer needs a maintainer decision before
  the import.
- The signed tag object's own `tag` header must name `tag`, and its `type` must
  be `commit`, so an older signed tag published under a new name is refused.
- No downstream delta may be dropped. `git read-tree` replaces the subtree with
  the upstream tree exactly, so the block merges the qbit subtree into the new
  release with `git merge-tree`, using the old release as the merge base. If
  the result differs from the new release's tree, the new tag lacks a
  downstream change, such as the approved `Cargo.lock` delta described in
  [Verify Subtree Integrity](#verify-subtree-integrity), and the block stops
  and lists the paths that differ.

The tag checks and the import use the tag object ID recorded right after the
fetch, so a background fetch that rewrites `FETCH_HEAD` cannot swap the object
between them. The tag checks run in a nested subshell with a throwaway keyring,
and its trap removes the keyring, its agent and its socket directory whether
the checks pass or fail; a failing `gpgconf` cannot stop the trap from removing
the keyring. They call `gpg` directly with `-c gpg.openpgp.program=gpg`,
because maintainers' hosts may set `gpg.openpgp.program` to a remote signing
client that would not see the throwaway keyring. `git commit` then runs with
the maintainer's own GnuPG environment, so a maintainer whose commits are
signed gets a signed import commit.

The block refreshes an existing import. A first import has no recorded split
or old subtree, so it would also need the split check, the downstream-delta
check and the `git rm` line removed.

Then update every pin location in a separate commit:

- `test/lint/libbitcoinpqc-subtree-check.sh`: `REMOTE_REF` and the default in
  its usage text;
- `ci/scanners/run-scanners.py`: `LIBBITCOINPQC_UPSTREAM_TAG`;
- `test/fuzz/shared_target_mappings.json`: `tag` and `peeled_commit`;
- this runbook: the Current Pin section and the split commit in
  [Verify Subtree Integrity](#verify-subtree-integrity).

`git grep -n -e <old tag> -e <old peeled commit> -- ':!src/libbitcoinpqc'`
lists the remaining mentions to review; release notes and the fixed fixtures in
`ci/scanners/test_run_scanners.py` keep theirs.

Do not import from `main`; create and review a release tag in
`qbit-libbitcoinpqc` first.

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

- [ ] The source commit is reachable from an immutable release tag in
  `Qbit-Org/qbit-libbitcoinpqc`.
- [ ] qbit imported that tag as one main-line commit, as described in
  [Import Or Refresh The Subtree](#import-or-refresh-the-subtree).
- [ ] Import commit keeps its `git-subtree-dir` and `git-subtree-split`
  trailers.
- [ ] `test/lint/libbitcoinpqc-subtree-check.sh` passes locally.
- [ ] Any pin change updates every location listed in
  [Import Or Refresh The Subtree](#import-or-refresh-the-subtree) and is
  intentional.
- [ ] Any downstream security delta is listed above, is limited to the exact
  lint allowlist, and is removed once a fixed upstream release tag is imported.

## Common Failures

1. Signature:
   `FAIL: src/libbitcoinpqc tree differs from upstream tag <tag>`
   Cause:
   Files under `src/libbitcoinpqc` were edited manually after the subtree import.
   Fix:
   Re-import as described in
   [Import Or Refresh The Subtree](#import-or-refresh-the-subtree).

2. Signature:
   `FAIL: subtree split <hash> does not match upstream tag commit <hash>`
   Cause:
   The recorded `git-subtree-split` metadata does not match the configured
   release tag.
   Fix:
   Re-import the intended release tag as described in
   [Import Or Refresh The Subtree](#import-or-refresh-the-subtree).

3. Signature:
   `fatal: unable to access 'https://github.com/...': The requested URL returned error: 403`
   Cause:
   The repository requires credentials for HTTPS fetches.
   Fix:
   Use an authenticated remote URL override:
   `LIBBITCOINPQC_REMOTE_URL=git@github.com:Qbit-Org/qbit-libbitcoinpqc.git`.
