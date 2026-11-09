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
  regular file (mode 100644), so symlinks are refused. No checkout or archive
  attribute (`text`, `eol`, `filter`, `ident`, `export-ignore`, ...) may apply
  to the policy's files at the head. The directory must hold exactly the
  policy's files: `keys.json`, `KEYS.md`, the certificates `keys.json`
  references, and `approvals/<policy-id>/` material.
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
  subkey that uses the same certificate.
- A certificate of a continuing signer (same alias and signing key at the
  base) must keep its primary key and subkeys, and every signature record the
  base certificate has, each with the key or user ID it belongs to and counted
  as a multiset; it may only add records. Under an unchanged `keys.json` no
  certificate may be new, and none may gain a subkey; with a new `keys.json` a
  certificate may gain only a subkey the new policy names as a signing key. To
  refresh an expiry, import the base certificate and the refreshed one into an
  empty keyring and export the result, which keeps both self-signatures; a
  plain re-export of the refreshed key drops the older one and is refused.

Release validators count a signature only when gpg's GOODSIG and VALIDSIG
agree and gpg reports no revoked or expired key or other error for it
(REVKEYSIG, EXPKEYSIG, ERRSIG), and count a quorum by distinct primary keys,
so signers whose signing keys share a primary key count once. Once a signing
key expires its signatures stop counting, so refresh certificates before
expiry (operator-01's primary key expires on 2028-06-07).

Two further options for certificate-only changes are pending operator
decisions: approvals by `policy_change_quorum` signers over a manifest of
certificate digests, or schema v3 with a per-signer `public_key_sha256` in
`keys.json`, which would make any certificate change a policy change.

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
