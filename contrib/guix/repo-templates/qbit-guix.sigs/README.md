# qbit-guix.sigs

This repository stores qbit Guix attestation manifests from independent
operator build checks.

## Purpose

- Publish `noncodesigned.SHA256SUMS{,.asc}` and `all.SHA256SUMS{,.asc}` files
  for each release version and operator.
- Provide a public, data-only mirror of qbit release signer policy,
  signer public certificates, and policy approval material under
  `operator-keys/`.
- Support `./contrib/guix/guix-attest` and `./contrib/guix/guix-verify` via the
  `GUIX_SIGS_REPO` environment variable.

## Layout

```text
operator-keys/
operator-keys/keys.json
operator-keys/public-keys/<signer-alias>-release.asc
operator-keys/approvals/<policy-id>/policy.SHA256
operator-keys/approvals/<policy-id>/approval-note.md
operator-keys/approvals/<policy-id>/<approver-alias>.asc
<version>/operator-01/noncodesigned.SHA256SUMS
<version>/operator-01/noncodesigned.SHA256SUMS.asc
<version>/operator-01/all.SHA256SUMS
<version>/operator-01/all.SHA256SUMS.asc
```

Additional artifact namespaces, such as `photon-*.SHA256SUMS`, may appear when
the corresponding Guix helper is run with `ARTIFACT=...`.

## Workflow

1. Independent operators run `./contrib/guix/guix-build`.
2. Each operator runs `./contrib/guix/guix-attest` with
   `SIGNER=<gpg-selector>=operator-XX` so the GPG selector and public directory
   name are both explicit.
3. Each operator opens a PR adding their attestation directory for the release.
4. Another operator runs `./contrib/guix/guix-verify` against this repository
   before release publication.
5. The release coordinator runs
   `ci/release/validate_builder_attestations.py` from the qbit source checkout
   before publishing GitHub Release assets, passing the public release checkout
   as `--source-root` and the verified annotated-tag target as
   `--expected-tag-target`.

Every counted core and PHOTON manifest must contain the common
`qbit-<version>.tar.gz` entry. The validator reconstructs that archive from the
signed-tag target with the same Guix `git archive` prefix and requires its exact
basename and SHA256 before counting the manifest toward quorum. The source
archive remains attestation evidence and is not a staged GitHub Release asset.

The release signer key that signs `SHA256SUMS.operator-XX.asc` for GitHub
release artifacts can also sign that operator's Guix attestations when the
signer has `builder-attestation` capability in `operator-keys/keys.json`.
Release-signature quorum and builder-attestation quorum remain separate checks
over the active signer policy.

`operator-keys/` is machine-verified release key mirror data. Do not place
README files, notes, hidden files, stale certificates, unreferenced approval
files, or other human-only documents under that directory.

## Repository Rulesets

The qbit source repository keeps the templates for this repository's `main`
rulesets in `contrib/guix/repo-templates/qbit-guix.sigs/rulesets/`:

| Template | Enforces on `main` |
| --- | --- |
| `signed-commits.json` | A verified signature on every commit, with no bypass actors. |
| `public-main.json` | No deletion and no non-fast-forward updates. Pull requests are required, merged with the merge-commit method only. |

Releases read this repository at a trusted ref, so `main` must be protected
with both the `deletion` and `non_fast_forward` rules. The signed-commit
rollout's release publisher checks this and refuses to publish otherwise.

Because `main` needs a verified signature on every commit, an attestation pull
request merges only when each of its commits is signed. Squash and rebase
merges are off, so a pull request with an unsigned commit is first squashed
into one commit that a maintainer signs, then merged with a merge commit, as
the signed-commit rollout's `squash-sign` does.

GitHub does not apply ruleset files from a repository. From the root of a qbit
checkout, an organization admin sets the repository's merge methods, then
applies each template:

```bash
gh api -X PATCH repos/Qbit-Org/qbit-guix.sigs \
  -F allow_merge_commit=true -F allow_squash_merge=false -F allow_rebase_merge=false
gh api -X POST repos/Qbit-Org/qbit-guix.sigs/rulesets \
  --input contrib/guix/repo-templates/qbit-guix.sigs/rulesets/signed-commits.json
gh api -X POST repos/Qbit-Org/qbit-guix.sigs/rulesets \
  --input contrib/guix/repo-templates/qbit-guix.sigs/rulesets/public-main.json
```

To change a ruleset that already exists, find its ID, read it back, and PUT
the template to that ID instead of creating a second ruleset:

```bash
gh api repos/Qbit-Org/qbit-guix.sigs/rulesets --jq '.[] | [.id, .name] | @tsv'
gh api -X PUT repos/Qbit-Org/qbit-guix.sigs/rulesets/<ruleset-id> \
  --input contrib/guix/repo-templates/qbit-guix.sigs/rulesets/<template>.json
```

Then confirm that the branch rules and protection are live:

```bash
gh api repos/Qbit-Org/qbit-guix.sigs/rules/branches/main --jq '[.[].type]'
gh api repos/Qbit-Org/qbit-guix.sigs/branches/main --jq .protected
```

The first command's list, in any order, includes `required_signatures`,
`deletion`, `non_fast_forward` and `pull_request`; organization rulesets can add
more. The second prints `true`.

`contrib/guix/init-supporting-repos.sh` copies this README only into a new
checkout, so update an existing qbit-guix.sigs README by hand.
