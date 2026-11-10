qbit Release Keys
=================

This directory publishes the public release-signing policy used by qbit release
validators, builders, and users.

Public trust model
------------------

`operator-keys/keys.json` is the public release trust root. It defines:

- the schema v2 policy identifier and monotonic `policy_sequence`
- release-line quorum rules for release signatures, builder attestations, and
  later policy changes
- the active, rotated, revoked, or lost signer roster
- each signer's standalone GPG signing fingerprint, public certificate file,
  release lines, capabilities, and artifact sets

Each signer certificate is published as a separate armored file under
`operator-keys/public-keys/` and is referenced by `keys.json`. Release signing
keys are standalone qbit release keys. Do not publish private keys, revocation
certificates, passphrases, custody notes, or backup material in this directory.

One source of truth
-------------------

**Location.** `contrib/keys/operator-keys/` in `Qbit-Org/qbit` is the only
source of truth for the release key policy: `keys.json`, the certificates it
references, and `approvals/<policy-id>/`. It is always read at a trusted ref:
the publisher's `trusted_release_ref` checkout for a publication, the signed
tag's tree for the policy in effect at a release, and the base branch's
policy for a change to it. Nothing else is a trust source, and this repository
keeps no second copy: the merge gate validates this directory alone.

**Access.** Each consumer verifies against this directory, never against a copy
of its own:

| Consumer | Reads the policy from | Check |
|---|---|---|
| `ci/release/` validators, `publish-local-release.sh` | the `trusted_release_ref` checkout (their default paths) | full schema, quorum, signatures |
| `required-merge-gate.yml` | the pull request, and the base branch's `contrib/keys/operator-keys` | key-policy continuity checks (below) |
| qbit-tools wizard and offline signer tooling | `QBIT_OPERATOR_KEYS_JSON`: this `keys.json` in the trusted-ref checkout | quorum and signer set read from it, never repeated; v1.0.0 also pins its SHA-256 |
| `qbit-guix.sigs` `operator-keys/` | a derived, non-authoritative mirror, seeded by `contrib/guix/init-supporting-repos.sh` | release-time tamper check: the publisher requires it byte-identical (below) |
| downstream repositories (qbit-rpc) | a pin: a qbit commit, `keys.json`'s SHA-256, each certificate's SHA-256 | every downloaded file must match its pinned digest |

Downstream repositories pin and fetch rather than vendor. The pinned
`keys.json` digest is the value `approvals/<policy-id>/policy.SHA256` carries
and the previous signers sign, and the one release evidence records, so a
reviewer checks a pin against qbit's own approval chain. `keys.json` does not
commit to certificate bytes, so each certificate's digest is pinned as well.
Files are fetched from an immutable commit, each refused unless it has its
pinned digest. A vendored copy with a CI drift check anchors the same bytes,
but keeps a second copy that local runs trust between drift checks, and its
reviewers compare files rather than one digest. A pin is a trust anchor: never
replace it with a download that is not checked against a pinned digest, or
with a branch name.

**Release-time tamper check.** `qbit-guix.sigs` keeps `operator-keys/` as a
derived, non-authoritative mirror of this directory, next to the attestations
it describes. `publish-local-release.sh` checks it for tampering against the
trusted policy, twice: `validate_key_metadata.py --operator-policy-mirror`
compares the validated projections, policy SHA-256 included, and
`validate_builder_attestations.py --guix-operator-key-policy` requires exactly
the canonical file set, byte for byte. `qbit-guix.sigs` has no CI or branch
protection of its own, so a mirror that differs was tampered with or not
re-synced, and the release does not publish. That is all the check does: it
never grants trust, and attestations and release signatures are verified with
the trusted-ref keys only.

**Rotation.** A new policy follows the chain:

1. Draft it from the current policy (qbit-tools
   `generate-key-metadata-fragments.sh` reads `QBIT_OPERATOR_KEYS_JSON`):
   `policy_sequence` one more, `previous_policy_sha256` the current
   `keys.json` SHA-256.
2. Land it here with `approvals/<policy-id>/policy.SHA256`, `approval-note.md`
   and detached approvals from the previous policy's signers, meeting each
   changed release line's previous `policy_change_quorum`.
3. Rebuild `qbit-guix.sigs/operator-keys/` from the trusted ref:
   `contrib/guix/init-supporting-repos.sh --resync-operator-keys <trusted-ref>
   <qbit-guix.sigs>` writes exactly `keys.json`, the referenced certificates
   and the current `approvals/<policy-id>/`, removes anything else, and runs
   the publisher's checks. The publisher refuses a stale copy.
4. Downstream pins move only when a downstream needs a release signed under
   the new policy. qbit-rpc's `node scripts/qbit-release.mjs pin <commit>`
   refuses a policy that is not the pinned one or its direct successor; the
   reviewer repeats the approval check with `validate_key_metadata.py
   --previous-operator-policy`.

**Key-policy continuity checks.** When a pull request touches the policy
path, a directory on it, or any `.gitattributes`, the merge gate checks the
pull request's `contrib/keys/operator-keys` against the base branch's
(`validate_key_metadata.py --base-operator-keys-dir`):

- Both policies are read from git objects, not from a checkout or an archive:
  every directory on the path must be a directory, and every file under it a
  regular file (mode 100644), so symlinks are refused, and no path may have
  more than one tree entry. No checkout or archive attribute (`text`, `eol`,
  `filter`, `ident`, `export-ignore`, ...) may be set or given a value for
  the policy's files at the head, read with `core.ignorecase` both off and on;
  an attribute may only be left unspecified or unset (`-text`), which changes
  no bytes. The head may not hold
  a path that equals the policy path, or `.gitattributes`, only after Unicode
  compatibility normalisation and case folding, since case-insensitive
  checkouts would treat it as the same file. The directory must hold exactly
  the policy's files: `keys.json`, `KEYS.md`, the certificates `keys.json`
  references, and `approvals/<policy-id>/` material. `KEYS.md`'s tables are
  generated from `keys.json` (`validate_key_metadata.py --write-keys-md`) and
  must match it (`--check-keys-md`).
- A `keys.json` that differs from the base's must follow the base policy
  directly: `policy_sequence` one more and `previous_policy_sha256` the base
  `keys.json` digest. Its approvals are verified against the base policy's
  signers and the base's certificates. Without a base policy, only a sequence
  1 bootstrap policy can be added, and only if no first-parent ancestor of the
  base ever had one.
- Approval material already at the base stays unchanged; a new
  `approvals/<policy-id>/` arrives only with that policy's `keys.json`. A
  policy that landed is replaced by a newer one, not reverted.
- The base's own `validate_key_metadata.py`, read from git objects, must also
  accept a change.
- Each signer certificate holds exactly one primary key with the signer's
  signing key (`--verify-public-key-certificates`). An active signer's
  signing key must be signing-capable and not revoked, and no two active
  signers may share a primary key. A rotated, revoked or lost signer's
  certificate may carry its key's revocation. A signer moves to another subkey
  of the same primary key with a new policy: its entry becomes `rotated`, with
  `replacement_signing_fingerprint`, beside a new active entry for the new
  subkey that uses the same certificate. A key may be in one certificate file
  only.
- When any base certificate file changes or goes, every certificate is
  checked; otherwise only certificates under new file names are. A checked
  certificate is compared with every base certificate holding any of its keys,
  primary or subkey, whatever its file name or its signers' aliases, and under
  an unchanged `keys.json` with the base's file of the same name too. Each must
  have the same primary key, and the certificate must keep all their keys and
  every signature record each of them has, each with the key or user ID it
  belongs to and counted as a multiset; it may only add records. A certificate
  sharing no key with the base is a new signer's and gets only the checks
  above. Under an unchanged `keys.json` no certificate may be new, and none
  may gain a subkey; with a new `keys.json` a certificate may gain only a
  subkey the new policy names as a signing key. To refresh an expiry, import
  the base certificate and the refreshed one into an empty keyring and export
  the result, which keeps both self-signatures; a plain re-export of the
  refreshed key drops the older one and is refused.

**Base-only gate.** The checks above live in code a pull request can change,
so the Key Policy Gate (`.github/workflows/key-policy-gate.yml`) runs them with
the base branch's own code only. It is triggered by `pull_request_target`, for
which GitHub runs the workflow as the default branch (`main`) defines it,
whatever branch a pull request targets. The job:

1. refuses, as a failure and never a skip, a pull request whose base branch is
   not `main` or `1.x.x`, the branches whose rulesets require the gate;
2. refuses a base commit that is not that branch's current tip (update the
   pull request with its base branch: a re-run reuses the old event);
3. checks out only that base commit, without credentials, fetches the pull
   request's head as git objects, and executes nothing from it;
4. runs the base commit's own `ci/release/key_policy_gate.py`, so each release
   line is checked by its own gate code.

The workflow itself runs as the default branch holds it: an approved change to
it on `1.x.x` takes effect only when `main` has it. Every release line's gate
script must therefore keep the command line the workflow uses (`target --base
--head --work`, run with `-I -B -X pycache_prefix`). The gate refuses a
version of its workflow that holds anything but the keys it needs (so no
condition, ignored failure, matrix, container, services, other shell or
defaults), sets environment variables other than the pull request's values,
takes the repository's default token permissions, uses any action but
`actions/checkout` pinned to a commit, or checks out anything but the base
commit without persisted credentials; what its `run:` steps do is for the
signers who approve the change to read, as is that the pinned commit is
`actions/checkout`'s own.

The check is named for its base, `Key Policy Gate (main)` or
`Key Policy Gate (1.x.x)`, and each branch's ruleset requires its own name.
Check results belong to a commit, not to a pull request, so two pull requests
with the same head share them: a run for a branch that is not allowed fails,
and a run for the other protected branch posts only that branch's name, so
neither can satisfy a pull request into `main` or `1.x.x`.

The script finds the paths the pull request changes against its merge base
with the base branch:

- A change to the key policy (any path the classifier routes to the key job)
  gets the checks above, run by the base's validator.
- A change to the gate's own code (`GATE_CODE_PREFIXES` and
  `GATE_CODE_PATHS` in the base's `key_policy_gate.py`) needs approvals by the
  base policy's signers, as below. Gate code is every file under `ci/release/`,
  `ci/checks/`, `.github/workflows/` and `.github/actions/`, whatever its type
  (every workflow counts, since any workflow could post a check under the
  gate's name), every `CODEOWNERS` file GitHub reads (`.github/`, the root,
  `docs/`), this README, and every `.gitattributes` at any depth, since
  attributes change how the gate's code is checked out. The directories
  themselves and their parents (`ci`, `.github`, `docs`, `contrib`, ...) are
  gate code too: a symlink in place of one is refused, and a file in place of
  one needs approvals. Paths are compared
  case-insensitively (NFKC, then case-folded), as a case-insensitive checkout
  would compare them. No attribute that changes a checkout's bytes (`text`,
  `eol`, `crlf`, `filter`, `ident`, `working-tree-encoding`) may be set or
  given a value for files under those four directories, even with approvals;
  unset (`-text`, `binary`) is allowed.
- Any other file under `contrib/keys/` is refused.
- The pull request's head may not hold a Python bytecode cache (a
  `__pycache__` directory or a `.pyc`/`.pyo` file) anywhere in its tree;
  `test/lint/lint-files.py` checks the same for tracked files.

Only `key-policy-gate.yml` may name a job `Key Policy Gate`. On a gate change
the gate parses every workflow with the distribution's PyYAML, refusing
repeated keys, explicit YAML tags (`!!str` and the like) and control or
separator characters in any of them, and refuses a workflow or job name that
can evaluate to the
check's name, compared case-insensitively and ignoring whitespace. An
expression in a name may only read a matrix value, such as
`${{ matrix.name }}`: a value the job's strategy gives as text is put in
exactly, a combination may also leave it empty, and a computed value or
matrix stands for any text. It also refuses `checks: write`,
`statuses: write` and `write-all`, and a workflow the pull request adds or
changes must declare its token permissions, for itself or for every job.
`ci-nightly-heavy.yml` and `lint-image-prewarm.yml` declare none yet, so the
pull request that next changes either must add them. This is a defence in
depth, not a guarantee: a required check is matched by name and app, so any
workflow run that may post checks or statuses on the pull request's head (its
own `pull_request` workflows, or a workflow on another branch) could post one
under the gate's name, and code can build a name at run time. Keep the
default workflow token read-only, and consider a ruleset that requires
`key-policy-gate.yml` by path rather than a check by name.

A gate change is approved in `contrib/keys/gate-approvals/<id>/`:

```text
gate.SHA256       "base  <sha256>\n", the SHA-256 of the base's gate code and
                  gate approval entries ("<mode> <type> <sha256 of the
                  entry's bytes, or a submodule's object id>\t<path>",
                  NUL-separated, in tree order); then
                  one line "<sha256>  <path>\n" for every gate code file in
                  the pull request's head, sorted by path; each sha256 is that
                  of the file's bytes, and no gate path may hold a character
                  that is not printable, such as a line break
approval-note.md  what the change is and why
<alias>.asc       detached signatures over gate.SHA256
```

`<id>` is the SHA-256 of `gate.SHA256`. The base's code computes the manifest
from the base's and the head's git objects and requires that directory, with
that exact `gate.SHA256`, and good signatures (as release validators count
them) with distinct primary keys, verified with the base's certificates, that
meet every release line's `policy_change_quorum` from that line's active
signers. The pull request must contain its base branch's tip. No other
gate-approval directory may change in the same pull request, so approvals only
accumulate, and every approved gate change adds one. The manifest's first line
covers them, so the base never returns to an earlier gate state, and an
approval covers exactly one change from one state: reverting a gate change and
making it again needs new signatures, and a later base state needs new
signatures too. Like policy approvals, gate approvals carry no expiry date.

The job runs the gate as `python3 -I -B -X pycache_prefix=<new empty
directory>`, and the gate refuses to start otherwise, before importing
anything but built-in modules; its own child processes run the same way.
`-I` keeps the script's directory off the module search path, and the gate
loads its two modules from their own files, so a file added beside it cannot
stand in for a module it imports. `-B` and a pycache prefix outside the
checkout keep Python from reading a bytecode cache from the checkout, which
`-I` alone does not. It runs again when a pull request's base branch
changes. It fetches the pull request without credentials, which works for this
public repository.

**Arming the gate.** GitHub runs only the default branch's copy of the
workflow, and from 2026-12-02 blocks `pull_request_target` in public
repositories unless an Actions event policy allows it (brownouts on 2026-11-09
and 2026-11-16, 16:00 to 18:00 UTC, show the block early). The gate is armed in
this order:

1. this change merges into `1.x.x`;
2. v1.0.1 is published;
3. an administrator fast-forwards `main` to the release, which brings the
   workflow to the default branch;
4. an Actions event policy allows `pull_request_target` for
   `.github/workflows/key-policy-gate.yml` (workflow file targeting), before
   2026-12-02;
5. the `main` and `1.x.x` rulesets require `Key Policy Gate (main)` and
   `Key Policy Gate (1.x.x)` respectively (GitHub Actions, integration 15368),
   with code-owner review and up-to-date branches, as `.github/rulesets/`
   describes;
6. `@Qbit-Org/release-maintainers` gets write access, so CODEOWNERS applies.

No ruleset may require the gate before step 3: until `main` holds the
workflow, no run posts the check, and pull requests would wait for it forever.
The gate does not check the pull request that adds it.

Once armed, each protected branch keeps its own gate approvals, and a pull
request may add only its own approvals directory. A pull request that carries
one branch's approvals into the other, such as a merge of `1.x.x` into `main`,
cannot pass the gate. Step 3's fast-forward works only while `main` has no
commit of its own; after that, a gate change reaches the other branch as a
pull request that carries the change without the first branch's approvals
directory, approved again for that branch.

Release validators count a signature only when gpg's GOODSIG and VALIDSIG
agree and gpg reports no revoked or expired key or other error for it
(REVKEYSIG, EXPKEYSIG, ERRSIG), and count a quorum by distinct primary keys,
so signers whose signing keys share a primary key count once. Once a signing
key expires its signatures stop counting, so refresh certificates before
expiry (operator-01's primary key expires on 2028-06-07).

Known limits:

- Approvals do not expire. They sign the new `keys.json` digest, which names
  its predecessor, so a successor that the previous signers approved can land
  for as long as the base still holds that predecessor. To withdraw consent,
  land a different successor.
- A `.gitattributes` rule written for files that do not exist yet, such as a
  future `approvals/<policy-id>/`, lands without effect, and later blocks the
  change that adds those files. The gate's error names the file and the
  attribute; remove or narrow the rule (`git check-attr -a -- <path>` shows
  it), since no attribute may be set under `contrib/keys/operator-keys`.

Certificate-only changes, a changed certificate under an unchanged
`keys.json`, need no separate approval: they are covered by the continuity
checks above (same primary key, same subkey set, no removed signature
records, approvals and verification with the base's certificates). Binding
certificate digests into `keys.json` could be considered at a future policy
rotation.

**Old releases.** v1.0.0 was signed under `qbit-release-keys-mainnet-000002`,
`keys.json` SHA-256
`f04ae262bd40cdda5c481fc18cef29b405878e66d06c33b49865ea42b38eaf9f`, recorded
in `doc/release-trust-1.0.0.md`. That policy stays verifiable at the tag's
tree (`7ebcddb622d6e639041f005a189b048ec2a221fe`), at its
`trusted_release_ref` (`70fea84f5becfb57463247af09790df5ddd424f8`), and by its
digest in this directory's history, which the next policy names as its
`previous_policy_sha256`, and so on along the chain. Verify an old release against the policy in effect
for it, not the latest: point the validators' `--operator-key-policy` and
`--operator-keys-dir` at that tree's `contrib/keys/operator-keys/`, or keep a
downstream pin on it. A later policy may rotate or revoke a certificate the old
release was signed with. A downstream pinned to policy 000002 keeps verifying
v1.0.0 until it moves its pin, and an unknown or incompatible policy (another
schema version, digest or `policy_id`) is refused, never read.

Policy transitions
------------------

The first schema v2 policy is trusted because it is present in the reviewed
source tree at the recorded `trusted_release_ref`. Later policy updates must
include previous-policy quorum approval material under:

```text
operator-keys/approvals/<policy-id>/
  policy.SHA256
  approval-note.md
  <approver-alias>.asc
```

`policy.SHA256` must contain exactly `<64-hex>  keys.json\n`, where the hash is
computed over the candidate `keys.json` bytes.

Publication rules
-----------------

- Keep `operator-keys/KEYS.md`, `operator-keys/keys.json`, and every referenced
  signer certificate in sync.
- Rebuild the derived `qbit-guix.sigs/operator-keys/` copy from this directory
  at the trusted ref with `contrib/guix/init-supporting-repos.sh
  --resync-operator-keys <trusted-ref> <qbit-guix.sigs>`: `keys.json`, every
  referenced certificate, and the current policy's `approvals/<policy-id>/`.
  Keep it strict: no README files, notes, hidden files, stale certificates,
  older approval directories, or unreferenced documents.
- Validate key metadata and the `qbit-guix.sigs` copy before relying on a
  policy. For the bootstrap policy, or release-time shape/copy checks where
  transition approval material is not available, use the explicit shape-only
  mode:

  ```sh
  python3 ci/release/validate_key_metadata.py \
    --operator-policy contrib/keys/operator-keys/keys.json \
    --operator-keys-dir contrib/keys/operator-keys \
    --operator-policy-mirror ../qbit-guix.sigs/operator-keys/keys.json \
    --operator-keys-dir-mirror ../qbit-guix.sigs/operator-keys \
    --require-public-key-files \
    --skip-policy-transition-validation
  ```

- For `policy_sequence > 1` rotation PRs, validate the transition approvals
  instead of using the skip flag:

  ```sh
  python3 ci/release/validate_key_metadata.py \
    --operator-policy contrib/keys/operator-keys/keys.json \
    --operator-keys-dir contrib/keys/operator-keys \
    --previous-operator-policy /path/to/previous/operator-keys/keys.json \
    --approval-dir contrib/keys/operator-keys/approvals/<policy-id> \
    --require-public-key-files
  ```

Migration checklist
-------------------

Before the first schema v2 release:

1. Land standalone signer public certificates under
   `contrib/keys/operator-keys/public-keys/`.
2. Land schema v2 `keys.json` with `policy_id`, `policy_sequence`,
   `previous_policy_sha256`, release-line quorum fields, and active `signers`.
3. Record the bootstrap policy hash for sequence 1. No prior approval is
   required for sequence 1 because trust comes from reviewed repo inclusion at
   `trusted_release_ref`.
4. For later sequences, land `policy.SHA256`, `approval-note.md`, and detached
   approvals from the previous active signer quorum.
5. Seed or re-sync the derived `qbit-guix.sigs/operator-keys/` copy from this
   directory.
6. Remove legacy public key files and fields that are not part of schema v2.
7. Run `validate_key_metadata.py`, `validate_release_artifacts.py`, and
   `validate_builder_attestations.py` against dry-run fixtures.
8. Record `policy_id`, `policy_sequence`, `keys.json` SHA256,
   `trusted_release_ref`, and the exact `qbit-guix.sigs` commit in release
   evidence.

Backup separation
-----------------

Backup and restore policies are separate from release signing. Backup examples
must use dedicated `cv25519 [E]` encryption subkeys for recovery roles, and
those subkeys do not count toward release-signature or builder-attestation
quorum.
