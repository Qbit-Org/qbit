# mlkem-native Vendoring Runbook

This runbook defines how qbit vendors and updates
[mlkem-native](https://github.com/pq-code-package/mlkem-native), the ML-KEM
(FIPS 203) library behind the hybrid post-quantum BIP324 transport.

mlkem-native's C code is CBMC-proved memory-safe, and its x86_64 and AArch64
assembly is HOL-Light-proved correct and constant-time wherever it handles
secret data. Editing any vendored file voids those proofs, so qbit never edits
`src/mlkem-native`. All qbit-owned glue (configuration, backend selection,
the C++ wrapper and the build rules) lives outside it.

## Current Pin

- Source repository: `https://github.com/pq-code-package/mlkem-native.git`
- Source tag: `v2.0.0`
- Commit: `d1b2fe782888bdb761a50336012923180be7f502`
- Tree id of upstream `mlkem/`: `d9d581290ea1e6fa37462bfbc61b9b4266a2e9e5`
- Blob id of upstream `LICENSE`: `79c71b1fdcc53cc17b1df99a0f4d4d48121ac174`
- qbit path: `src/mlkem-native` (`mlkem/` and `LICENSE`, nothing else)

The machine-readable pin is
[`contrib/devtools/mlkem-native.pin`](../../contrib/devtools/mlkem-native.pin).
Keep this section in sync with it.

The whole upstream `mlkem/` directory is vendored, including backends qbit does
not build, so the identity check stays a single tree id and every file that
upstream's single-compilation-unit build (`mlkem_native.c`,
`mlkem_native_asm.S`) includes is present.

## Update Procedure

Run in a qbit worktree:

```bash
contrib/devtools/update-mlkem-native.sh            # the pinned tag
contrib/devtools/update-mlkem-native.sh v2.0.1     # a new release
```

The script fetches the tag or commit from `REMOTE_URL` (default: the pinned
repository), replaces `src/mlkem-native` with upstream's `mlkem/` and
`LICENSE` byte for byte, rewrites the pin from the object ids of the fetched
upstream commit, stages both, and checks that the staged tree has exactly those
ids. `REMOTE_REF` selects the ref when no argument is given. It refuses to
follow the pinned tag if upstream moved it to another commit.

Vendor only tagged releases. Read the upstream release notes and changelog
before updating, then work through the PR checklist below: qbit's backend
headers include upstream paths, so an update can need qbit-side changes even
though no vendored file is edited.

## Verify Integrity

```bash
test/lint/mlkem-native-check.sh
```

The check runs offline as part of the lint runner's `subtree` lint. It prints
`GOOD` when `HEAD:src/mlkem-native/mlkem` has the pinned tree id,
`HEAD:src/mlkem-native/LICENSE` has the pinned blob id, `src/mlkem-native`
holds nothing else, and the work tree has no changes under it. Otherwise it
prints `FAIL` with the signature, cause and fix.

## PR Checklist For Library Updates

When a PR touches `src/mlkem-native` or `contrib/devtools/mlkem-native.pin`,
confirm:

- [ ] The new commit is an upstream release tag, and its release notes and
  security advisories were read.
- [ ] The tree was produced by `contrib/devtools/update-mlkem-native.sh`, and
  this runbook's Current Pin matches the pin file.
- [ ] `test/lint/mlkem-native-check.sh` prints `GOOD`, and the full lint runner
  passes.
- [ ] Running the update script again at the new tag leaves no diff.

## Common Failures

1. Signature:
   `FAIL: src/mlkem-native/mlkem tree <id> differs from pinned tree <id>`
   (or the same for `LICENSE`)
   Cause:
   A vendored file was edited, added, removed or changed mode, or the pin was
   changed without re-vendoring.
   Fix:
   Never edit `src/mlkem-native`. Restore it with
   `contrib/devtools/update-mlkem-native.sh`. Changes belong upstream, or in
   qbit's glue outside the vendored directory.

2. Signature:
   `FAIL: uncommitted changes under src/mlkem-native`
   Cause:
   The work tree or index has edits, new files or deletions under the vendored
   directory.
   Fix:
   `git checkout HEAD -- src/mlkem-native && git clean -fdx -- src/mlkem-native`.

3. Signature:
   `FAIL: src/mlkem-native in HEAD holds entries other than LICENSE and mlkem`
   Cause:
   A qbit file was added next to the vendored tree.
   Fix:
   Move it out; qbit's ML-KEM glue lives in `src/crypto/mlkem*`.

4. Signature:
   `FAIL: <tag> resolves to <commit>, but contrib/devtools/mlkem-native.pin pins <commit>`
   Cause:
   Upstream moved the tag, or `REMOTE_URL` points at a different repository.
   Fix:
   Stop and investigate upstream before vendoring anything. To vendor a
   different commit deliberately, pass it to the script explicitly.

5. Signature:
   `FAIL: staged src/mlkem-native (...) differs from upstream (...)`
   Cause:
   A git attribute, filter or line-ending setting (for example
   `core.autocrlf`) rewrote vendored bytes on staging.
   Fix:
   Remove the setting that applies to `src/mlkem-native` and re-run the update
   script.

## Review Cadence

At least quarterly, check
[upstream releases](https://github.com/pq-code-package/mlkem-native/releases)
and [security advisories](https://github.com/pq-code-package/mlkem-native/security/advisories).
Update promptly for a security fix; otherwise update when a release brings a
proved improvement qbit uses.
