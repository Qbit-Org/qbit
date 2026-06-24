qbit Operator Key Index
=======================

This directory publishes the qbit release signer policy and public signer
certificates used for release verification.

Key model
---------

`operator-keys/keys.json` is the public trust anchor. It records the active
release signer set, release-line quorum settings, signer capabilities, artifact
sets, and policy transition requirements.

Each active signer has an independent public certificate listed in `keys.json`.
Release signing and builder attestation remain separate workflow checks. A
signer can count for a workflow only when the signer is active for the release
line and carries the matching capability.

Policy metadata
---------------

`operator-keys/keys.json` uses schema version 2. Required fields include:

- `policy_id`: stable identifier for this signer policy
- `policy_sequence`: monotonic policy sequence number
- `previous_policy_sha256`: `null` for sequence 1, otherwise the exact-byte
  SHA256 of the prior checked-in `keys.json`
- `effective_from_tag`: first release tag governed by the policy
- `release_lines`: quorum settings for each release line
- `signers`: public signer entries

Each signer entry records:

- `alias`: canonical public alias such as `operator-01`
- `status`: `active`, `rotated`, `revoked`, or `lost`
- `key_origin`: `qbit-generated`, `external-gpg`, or `external-yubikey`
- `public_key_file`: signer certificate path under `public-keys/`
- `signing_fingerprint`: full OpenPGP signing fingerprint counted for release
  signatures and Guix attestations
- `release_lines`: release lines where the signer is eligible
- `capabilities`: `release-signing`, `builder-attestation`, or both
- `artifact_sets`: artifact sets the signer attests, such as `core` or `photon`

Policy transitions
------------------

The sequence 1 policy is trusted because it is present in the reviewed qbit
source tree. Later policies require previous-policy quorum approval material in:

```text
approvals/<policy_id>/
  policy.SHA256
  approval-note.md
  <alias>.asc
```

`policy.SHA256` must contain exactly this line, including the trailing newline:

```text
<64-hex>  keys.json\n
```

The hash is computed over the checked-in `keys.json` bytes. Detached approval
signatures are counted against active signers from the previous policy.

Current testnet signers
-----------------------

| Signer Alias | Signing Fingerprint | Public Certificate | Release Line | Capabilities | Artifact Sets | Created | First Release |
|--------------|---------------------|--------------------|--------------|--------------|---------------|---------|---------------|
| operator-01 | 289EA3EC2F1939A24984840ED26CFC05586D371E | public-keys/operator-01-release.asc | testnet | release-signing, builder-attestation | core, photon | 2026-06-08 | v0.1.0-testnet4-rc3 |
| operator-02 | 1B95A7AA02F5530BDB1CD92387012E62F6CC1393 | public-keys/operator-02-release.asc | testnet | release-signing, builder-attestation | core, photon | 2026-06-08 | v0.1.0-testnet4-rc3 |
| operator-03 | 05A14A415C26F4216DC254FE52D5CC557D764586 | public-keys/operator-03-release.asc | testnet | release-signing, builder-attestation | core, photon | 2026-06-08 | v0.1.0-testnet4-rc3 |

Publication checklist
---------------------

Before relying on a signer policy:

- publish each signer certificate referenced by `keys.json`
- update `operator-keys/KEYS.md`
- update `operator-keys/keys.json`
- mirror the same machine-verifiable policy data into
  `qbit-guix.sigs/operator-keys/`
- keep the `qbit-guix.sigs/operator-keys/` mirror strict and data-only: no
  README files, notes, hidden files, unreferenced certificates, or stale
  approval material
- verify release signatures such as `SHA256SUMS.operator-01.asc` from a clean
  keyring
- verify Guix attestations under `<version>/operator-01/` from a clean keyring

Release evidence should pin the release tag, tag target, `trusted_release_ref`,
the exact-byte SHA256 of `keys.json`, the `qbit-guix.sigs` commit, and the
counted signer aliases/fingerprints.
The `trusted_release_ref` must be a public commit whose history contains the
release tag target, and it must not be the release tag object or tag target.

Backup separation
-----------------

Backup encryption keys remain separate from release signer policy. They must not
be listed as release signers and do not grant release-signature or
builder-attestation authority.
