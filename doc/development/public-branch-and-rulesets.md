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
| `.github/rulesets/main.json` | `refs/heads/main` | Require pull requests, one approval, resolved conversations, merge commits only, `Core Checks Gate`, `Full Validation Gate`, block deletion, and block non-fast-forward updates. |
| `.github/rulesets/0.1.x.json` | `refs/heads/0.1.x` | Restrict branch creation to bypass actors, require pull requests, one approval, resolved conversations, merge commits only, `Core Checks Gate`, `Full Validation Gate`, block deletion, and block non-fast-forward updates. |
| `.github/rulesets/release-tags-v.json` | `refs/tags/v*` | Restrict tag creation, updates, and deletion to bypass actors. |
| `.github/rulesets/upstream-refs.json` | `refs/heads/upstream/**` | Lock optional upstream reference branches so only bypass actors can create, update, or delete them. |

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
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit/rulesets/<ruleset-id> \
  --input .github/rulesets/main.json
```

Use the same command with the other template paths after reviewing their target
refs and ruleset IDs.

## Operational Notes

Required status checks are encoded only as the aggregate `Core Checks Gate` and
`Full Validation Gate`. Do not protect public branches with raw job names,
because raw jobs are internal inputs to the gates and some are skipped until a
fork pull request is trusted by a maintainer.

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

