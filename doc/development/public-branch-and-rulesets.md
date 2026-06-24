# Public Branch and Ruleset Model

This document defines the public repository branch, tag, and ruleset model for
qbit v0.1.x testnet releases.

## Public Branch Set

The public repository keeps a small branch surface:

| Ref | Purpose | Creation timing |
| --- | --- | --- |
| `main` | Default public pull request target and active public integration branch. | Exists at public repository launch. |
| `0.1.x` | Maintenance branch for v0.1.x testnet backports. | Create from the `v0.1.0-testnet4` tag target when the first v0.1.x patch, reset, or backport is needed. |
| `0.2.x` | Future maintenance/development line after v0.2.x opens. | Do not create during v0.1.x launch unless maintainers explicitly open that line. |
| `upstream/bitcoin-v30.2` | Optional locked Bitcoin Core reference branch. | Create only if maintainers want a public upstream reference. |

Temporary public branches are allowed only for bounded operations:

| Pattern | Purpose |
| --- | --- |
| `sync/public-snapshot/<date-or-version>` | Staging sanitized public snapshots before they are merged to `main`. |
| `backport/<topic>-to-0.1.x` | Preparing a public maintenance backport. |
| `release/v<version>` | Preparing release-only adjustments for a specific public tag. |

Do not publish private integration branches, review branches, agent branches,
tracker branches, or internal staging branches to the public repository.

## Tag Model

Public release tags use signed, annotated `v*` tags:

| Tag pattern | Purpose |
| --- | --- |
| `v0.1.0-testnet4-rcN` | Public release candidates for v0.1.0 testnet4. |
| `v0.1.0-testnet4` | Final v0.1.0 testnet4 release tag. |
| `v0.1.N-testnet4` | Future v0.1.x patch or reset tags, when needed. |

Tag updates and deletions are not part of normal release operations. If a tag
must be corrected before announcement, delete and recreate it only through the
release-maintainer path, and record the replacement rationale in the release
checklist.

## Ruleset Templates

Ruleset JSON templates are the public-safe files below:

| Template | Target | Baseline behavior |
| --- | --- | --- |
| `.github/rulesets/main.json` | `refs/heads/main` | Require pull requests, one approval, resolved conversations, squash/rebase merge methods only, linear history, `Required Merge Gate`, block deletion, and block non-fast-forward updates. |
| `.github/rulesets/0.1.x.json` | `refs/heads/0.1.x` | Restrict branch creation to bypass actors, require pull requests, one approval, resolved conversations, squash/rebase merge methods only, linear history, `Required Merge Gate`, block deletion, and block non-fast-forward updates. |
| `.github/rulesets/release-tags-v.json` | `refs/tags/v*` | Restrict tag creation, updates, and deletion to bypass actors. |
| `.github/rulesets/upstream-refs.json` | `refs/heads/upstream/**` | Lock optional upstream reference branches so only bypass actors can create, update, or delete them. |

## Repository Merge Settings

GitHub ruleset pull request merge-method restrictions apply to the target refs
selected by each ruleset. Enforce the same no-merge-commit policy for every
pull request by applying the repository-level merge-method settings template.
These settings are repository-wide defaults rather than branch-scoped rules:

| Template | Scope | Baseline behavior |
| --- | --- | --- |
| `.github/repository-settings/merge-methods.json` | All repository pull requests | Enable squash merges, keep rebase merges available as an optional linear method, and disable normal merge commits by default. |

The normal merge-commit button should stay disabled in routine operation. If an
unusual case needs a merge commit, a repository admin or release maintainer may
temporarily set `allow_merge_commit` to `true`, perform the merge, record the
reason in the relevant pull request or release checklist, and immediately
restore this default template.

Templates that restrict ref creation, update, or deletion intentionally use
`OrganizationAdmin` as the only portable bypass actor. Before applying them to
the public repository, maintainers should replace or supplement that bypass
with the final public release-maintainer team, user, or repository-role actor
IDs.

GitHub's ruleset `required_signatures` rule checks commit signatures, not the
release tag object. Do not rely on rulesets alone for the signed annotated tag
policy. The public release path must verify tag objects directly:

- `.github/workflows/release-publish.yml` rejects lightweight tags and requires
  GitHub-verified annotated tag signatures before publication.
- `ci/release/validate_release_artifacts.py --verify-tag-signature` verifies the
  release tag against the active qbit release-key policy for workflow and local
  publication paths.

Apply a template with the repository rulesets API after confirming the target
repository and bypass actors:

```sh
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit/rulesets/<ruleset-id> \
  --input .github/rulesets/main.json
```

Use the same command with the other template paths after reviewing their target
refs and ruleset IDs.

Apply the repository-wide merge-method policy with the repository API:

```sh
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit \
  --input .github/repository-settings/merge-methods.json
```

## Operational Notes

Required status checks are encoded only as the aggregate `Required Merge Gate`.
Do not protect public branches with the raw `Core Checks Gate` or
`Full Validation Gate` checks. Those checks are inputs to the required gate, and
the required gate chooses the correct validation profile after classifying the
changed paths. This keeps the required check present for every pull request
without relying on workflow-level `paths` or `paths-ignore` filters, which can
leave required workflows pending when GitHub skips them.

The required merge gate has five validation profiles:

| Profile | Applies to | Required validation |
| --- | --- | --- |
| Full source validation | Any source-affecting, mixed, unknown, or empty change set. | Require both `Core Checks Gate` and `Full Validation Gate` to complete successfully. |
| Release-policy validation | Pull requests whose changed paths are only release policy or trusted release reference files. | Run `git diff --check`, release validator tests for touched release validator/workflow files, operator key metadata validation when operator keys are touched, and a best-effort local YAML parse for `release-publish.yml` when PyYAML is available. |
| RPC docs validation | Pull requests whose changed paths are only RPC documentation pipeline files. | Run `git diff --check`, RPC docs unit tests, and require the existing `rpc-docs` build check. |
| Public docs validation | Pull requests whose changed paths are only public-facing documentation and release notes. | Run `git diff --check` and require the existing `public-docs-lint` check. |
| GitHub metadata validation | Pull requests whose changed paths are only public ruleset templates, repository settings, issue/PR templates, and the docs that explain those settings. | Run `git diff --check`, parse ruleset and repository-settings JSON, assert that public branch rulesets require only `Required Merge Gate`, and best-effort parse issue template YAML when PyYAML is available. |

The lightweight profiles are intentionally narrow. The release-policy allowlist
is:

- `.github/workflows/release-publish.yml`
- `ci/release/**`
- `contrib/keys/operator-keys/**`
- `doc/release-trust-*.md`

The RPC docs allowlist is:

- `doc/rpc/**`
- `test/rpc_docs/**`
- `cmake/script/normalize_rpc_docs_site_paths.py`

The public docs allowlist is:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `doc/README.md`
- `doc/deployment/**`
- `doc/design/**`
- `doc/integration/**`
- `doc/performance/**`
- `doc/policy/**`
- `doc/reference/**`
- `doc/user/**`
- `doc/release-notes-*.md`

The GitHub metadata allowlist is:

- `.github/ISSUE_TEMPLATE/**`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/repository-settings/**`
- `.github/rulesets/**`
- `ci/README.md`
- `doc/development/public-branch-and-rulesets.md`

Trusted-release-ref and release-trust pull requests that stay within the
release-policy allowlist can merge after release-policy validation and review
without waiting for full source CI. RPC docs pull requests that stay within the
RPC docs allowlist can merge after RPC docs validation and review without
waiting for full source CI. Public documentation pull requests that stay within
the public docs allowlist can merge after public docs validation and review
without waiting for full source CI. GitHub metadata pull requests that stay
within the metadata allowlist can merge after metadata validation and review
without waiting for full source CI. Any path outside the active profile
allowlist, including source, build, workflow, action, or test files, is
classified as full source validation. Mixed changes, including changes that
span more than one lightweight profile, also use full source validation.

Merge queue is not enabled in these templates. Enable it only after public CI
supports `merge_group` events.

Code-owner review is disabled in these templates because public owner and team
IDs are not frozen here. Enable `require_code_owner_review` only after a public
`CODEOWNERS` file exists and the referenced owners are valid in the public
repository.

## Backport Metadata

Backports to `0.1.x` should be maintainer-directed and should state:

- the original public pull request or commit
- the reason the change is needed on v0.1.x
- whether the change affects consensus, wallet behavior, P2P behavior, release
  artifacts, or documentation only
- the validation run against `0.1.x`

If the `0.1.x` branch has not been created yet, create it from the final
`v0.1.0-testnet4` tag target before opening the first backport pull request.
