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
- Mirror the same data-only `operator-keys/` tree into
  `qbit-guix.sigs/operator-keys/`.
- Keep `qbit-guix.sigs/operator-keys/` strict: no README files, notes, hidden
  files, stale certificates, or unreferenced documents.
- Validate key metadata and the mirror before relying on a policy. For the
  bootstrap policy, or release-time shape/mirror checks where transition
  approval material is not available, use the explicit shape-only mode:

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
    --operator-policy-mirror ../qbit-guix.sigs/operator-keys/keys.json \
    --operator-keys-dir-mirror ../qbit-guix.sigs/operator-keys \
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
5. Mirror `keys.json`, public signer certificates, and approvals into
   `qbit-guix.sigs/operator-keys/`.
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
