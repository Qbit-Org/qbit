# Public Branch and Ruleset Model

This document defines the public repository branch, tag, and ruleset model for
qbit v0.1.x testnet releases.

## Public Branch Set

The public repository keeps a small branch surface:

| Ref | Purpose | Creation timing |
| --- | --- | --- |
| `main` | Default public pull request target and active public integration branch. | Exists at public repository launch. |
| `0.1.x` | Maintenance branch for v0.1.x testnet backports. | Create from the `v0.1.0-testnet4` tag target when the first v0.1.x patch, reset, or backport is needed. |
| `1.x.x` | Maintenance branch for v1.x backports. | Create from the applicable v1 release tag when the first v1.x patch or backport is needed. |
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

Tag updates and deletions are not part of normal release operations. Release
maintainers may create `v*` tags, but they must not be able to update or delete
them after creation. If a tag must be corrected before announcement, delete and
recreate it only through an organization-admin break-glass path, and record the
replacement rationale in the release checklist.

## Ruleset Templates

Ruleset JSON templates are the public-safe files below. A template takes effect
only after an organization admin applies it to the repository; until then GitHub
enforces the live rulesets. The merge-commit and signed-commit policy in this
document describes the repository after the operator applies these templates.

| Template | Target | Baseline behavior |
| --- | --- | --- |
| `.github/rulesets/main.json` | `refs/heads/main` | Require pull requests, one approval, resolved conversations, the merge-commit merge method only, `Required Merge Gate` and `Key Policy Gate (main)` (GitHub Actions, integration 15368), code-owner review, block deletion, and block non-fast-forward updates. Require the branch to be up to date before merging. |
| `.github/rulesets/0.1.x.json` | `refs/heads/0.1.x` | Restrict branch creation to bypass actors, require pull requests, one approval, resolved conversations, the merge-commit merge method only, `Required Merge Gate`, block deletion, and block non-fast-forward updates. Do not require the branch to be up to date before merging. |
| `.github/rulesets/1.0.0.json` | `refs/heads/1.0.0` | Restrict branch creation to bypass actors, require pull requests, one approval, resolved conversations, the merge-commit merge method only, `Required Merge Gate`, block deletion, and block non-fast-forward updates. Do not require the branch to be up to date before merging. |
| `.github/rulesets/1.x.x.json` | `refs/heads/1.x.x` | Restrict branch creation to bypass actors, require pull requests, one approval, resolved conversations, the merge-commit merge method only, `Required Merge Gate` and `Key Policy Gate (1.x.x)` (GitHub Actions, integration 15368), code-owner review, block deletion, and block non-fast-forward updates. Require the branch to be up to date before merging. |
| `.github/rulesets/signed-commits.json` | `refs/heads/main`, `refs/heads/0.1.x`, `refs/heads/1.0.0`, `refs/heads/1.x.x` | Require a verified signature on every commit pushed to these branches, with no bypass actors. See [Signed Commits](#signed-commits). |
| `.github/rulesets/release-tags-v-creation.json` | `refs/tags/v*` | Restrict tag creation to organization admins and the release-maintainers team. |
| `.github/rulesets/release-tags-v-immutability.json` | `refs/tags/v*` | Restrict tag updates and deletion to organization admins only. |
| `.github/rulesets/upstream-refs.json` | `refs/heads/upstream/**` | Lock optional upstream reference branches so only bypass actors can create, update, or delete them. |

## Repository Merge Settings

After the operator applies these templates, pull requests merge only with
"Create a merge commit". Squash and rebase merges are disabled, and the branch
rulesets no longer require linear history, which a merge commit cannot satisfy.

Merge commits are the only method that keeps the signature check on GitHub's
server. With the `signed-commits` ruleset active, GitHub refuses a merge-commit
merge of a pull request that contains an unsigned commit, even for an admin
merging with `--admin` ("Repository rule violations found. Commits must have
verified signatures."). It also refuses rebase merges under that rule. It allows
a squash merge of the same pull request through `--admin` or the REST API,
because GitHub signs the squash commit itself, so a squash merge would land
unsigned work under GitHub's signature. Each pull request therefore lands as its
one operator-signed commit (see [Signed Commits](#signed-commits)) plus GitHub's
merge commit.

GitHub ruleset pull request merge-method restrictions apply to the target refs
selected by each ruleset. Enforce the same merge-commit-only policy for every
pull request by applying the repository-level merge-method settings template.
These settings are repository-wide defaults rather than branch-scoped rules:

| Template | Scope | Baseline behavior |
| --- | --- | --- |
| `.github/repository-settings/merge-methods.json` | All repository pull requests | Enable merge commits, and disable squash and rebase merges. |

Do not re-enable squash or rebase merges to land a pull request. A squash merge
replaces the pull request's commits with one that GitHub signs, which bypasses
the operator signature, and the signature rule refuses rebase merges.

Templates that restrict ref creation, update, or deletion use
`OrganizationAdmin` as the portable bypass actor. The `v*` tag creation template
also includes a `Team` bypass actor for the release-maintainers team. GitHub
rulesets require the numeric team ID as `actor_id`; the current public
`release-maintainers` team ID is `18321137`.

The `v*` tag immutability template intentionally does not include the
release-maintainers team. Release maintainers can create release tags, but only
organization admins can update or delete them.

GitHub's ruleset `required_signatures` rule checks commit signatures, not the
release tag object. Do not rely on rulesets alone for the signed annotated tag
policy. The public release path must verify tag objects directly:

- `contrib/release-process/publish-local-release.sh` rejects lightweight tags
  and requires GitHub-verified annotated tag signatures before publication.
- `ci/release/validate_release_artifacts.py --verify-tag-signature` verifies the
  release tag against the active qbit release-key policy.

Apply a template with the repository rulesets API after confirming the target
repository, the ruleset ID, and the bypass actors. List the live rulesets and
their IDs with:

```sh
gh api repos/Qbit-Org/qbit/rulesets --jq '.[] | [.id, .name] | @tsv'
```

Update an existing ruleset with PUT to that ruleset's own ID:

```sh
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit/rulesets/<ruleset-id> \
  --input .github/rulesets/main.json
```

A PUT replaces the ruleset with the template, so compare the template with the
live ruleset (`gh api repos/Qbit-Org/qbit/rulesets/<ruleset-id>`) first. Use the
same command with the other template paths after reviewing their target refs and
ruleset IDs.

A template that has no live ruleset yet, such as
`.github/rulesets/signed-commits.json`, must create a new ruleset. Import it in
Settings → Rules → Rulesets → New ruleset → Import a ruleset, or POST it:

```sh
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit/rulesets \
  --input .github/rulesets/signed-commits.json
```

Do not PUT a new template to an existing ruleset's ID: that replaces the
existing ruleset, including its rules and bypass actors.

When migrating the live `v*` tag policy, replace the former combined
`public-release-tags-v` ruleset with both split rulesets. Confirm the
`release-maintainers` team ID before applying
`.github/rulesets/release-tags-v-creation.json`:

```sh
gh api orgs/Qbit-Org/teams/release-maintainers --jq .id
```

Apply the repository-wide merge-method policy with the repository API:

```sh
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit \
  --input .github/repository-settings/merge-methods.json
```

After applying, confirm the rules GitHub enforces on each public branch, here
`main`, and the same for `0.1.x`, `1.0.0`, and `1.x.x`:

```sh
gh api repos/Qbit-Org/qbit/rules/branches/main --jq '.[].type'
```

The output should include `required_signatures` and `pull_request`, and should
not include `required_linear_history`.

## Signed Commits

After the operator applies `.github/rulesets/signed-commits.json`, every commit
pushed to `main`, `0.1.x`, `1.0.0`, or `1.x.x` must carry a signature that
GitHub verifies. The rule lives in its own ruleset with no bypass actors, so the
`OrganizationAdmin` bypass on the other branch rulesets does not exempt anyone
from it. Add a new protected maintenance branch to its `include` list when that
branch is created.

The rule checks commits when they reach a protected branch, not while they sit
on a pull request branch:

- Draft and review commits on a pull request branch may be unsigned.
- Before merge, the operator runs `squash-sign apply` on the pull request, which
  reduces it to one commit signed with the operator's key. The pull request then
  lands as that commit plus GitHub's merge commit, which GitHub signs.
- Run `squash-sign apply` before the final approval. The rewrite is a push, so
  `dismiss_stale_reviews_on_push` and `require_last_push_approval` can require a
  fresh approval from someone other than the operator.
- A pull request opened under the earlier squash-only policy stays mergeable
  after the switch, but GitHub refuses its merge commit while any of its commits
  is unsigned. Run `squash-sign apply` on such a pull request, including one with
  several unsigned commits, before merging it.

The rule accepts any commit that GitHub verifies, including commits GitHub signs
itself: web UI edits, GraphQL `createCommitOnBranch`, and commits made with
`GITHUB_TOKEN` or by a GitHub App or bot. It does not prove that the operator
signed a commit. `squash-sign verify` and a daily `squash-sign audit`, which run
outside this repository, cover that gap.

No recurring upstream sync exists; upstream history arrived once, on
2026-06-17. `refs/heads/upstream/**` is outside the signature rule, so an
optional upstream reference branch can hold upstream history verbatim. A rare
verbatim import of third-party history into a signed branch uses a recorded
break-glass:

1. An organization admin sets the `signed-commits` ruleset enforcement to
   `disabled`.
2. The admin pushes the import.
3. The admin sets the ruleset enforcement back to `active` immediately.
4. The admin records the imported commit range and the reason in the release
   checklist.

## Operational Notes

The switch to merge commits and the `signed-commits` ruleset leave required
status checks unchanged: the branch rulesets require the same checks as before,
and `signed-commits.json` adds no status checks.

Required status checks are encoded as the aggregate `Required Merge Gate`; on
`main` and `1.x.x` also as `Key Policy Gate (main)` and `Key Policy Gate (1.x.x)`,
the base-only key-policy check (`.github/workflows/key-policy-gate.yml`, see
`contrib/keys/README.md`). Require the gate only once `main` holds the
workflow and an Actions event policy allows `pull_request_target` for it; the
README gives the order.
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
| Release-policy validation | Pull requests whose changed paths are only release policy or trusted release reference files. | Run `git diff --check`, release publisher and validator tests for touched publication or validator files, `bash -n` for publisher changes, and operator key metadata validation when operator keys are touched. |
| RPC docs validation | Pull requests whose changed paths are only RPC documentation pipeline files. | Run `git diff --check`, RPC docs unit tests, and require the existing `rpc-docs` build check. |
| Public docs validation | Pull requests whose changed paths are only public-facing documentation and release notes. | Run `git diff --check` and require the existing `public-docs-lint` check. |
| GitHub metadata validation | Pull requests whose changed paths are only public ruleset templates, repository settings, issue/PR templates, and the docs that explain those settings. | Run `git diff --check`, parse ruleset and repository-settings JSON, assert the public branch rulesets' required checks (`Required Merge Gate`, and `Key Policy Gate (main)` or `Key Policy Gate (1.x.x)` with code-owner review on `main` and `1.x.x`) and extra approval for unattributed changes, and best-effort parse issue template YAML when PyYAML is available. |

The lightweight profiles are intentionally narrow. The release-policy allowlist
is:

- `contrib/release-process/publish-local-release.sh`
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

Code-owner review is required on `main` and `1.x.x`: `.github/CODEOWNERS` gives
`contrib/keys/`, `ci/release/`, `ci/checks/`, `.github/workflows/`,
`.github/actions/` and every `.gitattributes` to
`@Qbit-Org/release-maintainers`. The other maintenance branches do not require
it yet. GitHub applies a team as code owner only once the team has write
access to the repository; until an organization owner grants it, code-owner
review requires nothing.

The branch templates carry every pull-request setting the live rulesets have,
including `require_extra_approval_for_unattributed_changes`, which the
metadata check requires on all four. Apply a template by editing the live
ruleset to match it, and compare the result with the live ruleset first, so no
live setting is dropped.

## Backport Metadata

Backports to `0.1.x` should be maintainer-directed and should state:

- the original public pull request or commit
- the reason the change is needed on v0.1.x
- whether the change affects consensus, wallet behavior, P2P behavior, release
  artifacts, or documentation only
- the validation run against `0.1.x`

If the `0.1.x` branch has not been created yet, create it from the final
`v0.1.0-testnet4` tag target before opening the first backport pull request.
