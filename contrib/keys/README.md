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
tag's tree for the policy in effect at a release, and the base history for a
policy change. Nothing else is a trust source, and this repository keeps no
second copy: the merge gate validates this directory alone.

**Access.** Each consumer verifies against this directory, never against a copy
of its own:

| Consumer | Reads the policy from | Check |
|---|---|---|
| `ci/release/` validators, `publish-local-release.sh` | the `trusted_release_ref` checkout (their default paths) | full schema, quorum, signatures |
| `required-merge-gate.yml` | the pull request, with the previous policy found in base history by `previous_policy_sha256` | `validate_key_metadata.py` with transition approvals |
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
   changed release line's previous `policy_change_quorum`. The merge gate
   finds the previous policy in base history by digest and checks them.
3. Re-sync `qbit-guix.sigs/operator-keys/` from here: `keys.json`, the
   referenced certificates, and the current `approvals/<policy-id>/` only.
   The publisher refuses a stale copy.
4. Downstream pins move only when a downstream needs a release signed under
   the new policy. qbit-rpc's `node scripts/qbit-release.mjs pin <commit>`
   refuses a policy that is not the pinned one or its direct successor; the
   reviewer repeats the approval check with `validate_key_metadata.py
   --previous-operator-policy`.

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
- Re-sync the derived `qbit-guix.sigs/operator-keys/` copy from this directory:
  `keys.json`, every referenced certificate, and the current policy's
  `approvals/<policy-id>/`. Keep it strict: no README files, notes, hidden
  files, stale certificates, older approval directories, or unreferenced
  documents.
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
