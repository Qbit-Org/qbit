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
| `1.1.0` | Release line for v1.1.0. Signature rule only (full protection tracked separately). | Exists. |
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
| `.github/rulesets/signed-commits.json` | `refs/heads/main`, `refs/heads/0.1.x`, `refs/heads/1.0.0`, `refs/heads/1.1.0`, `refs/heads/1.x.x` | Require a verified signature on every commit pushed to these branches, with no bypass actors. See [Signed Commits](#signed-commits). |
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
unsigned work under GitHub's signature. By process, each pull request lands as
one operator-signed commit made with `squash-sign` (see
[Signed Commits](#signed-commits)), plus GitHub's merge commit. GitHub itself
enforces only that every commit in the pull request is Verified; it does not
check whose key signed it.

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

Prefer editing an existing ruleset in the browser (Settings → Rules → Rulesets)
until it matches its template. A PUT replaces the whole ruleset, so it can reset
a key that exists only in the live ruleset. The branch templates carry the
live-only pull request keys seen on 2026-11-05 (`dismissal_restriction`,
`require_extra_approval_for_unattributed_changes`, and `required_reviewers`),
but compare the template with the live ruleset
(`gh api repos/Qbit-Org/qbit/rulesets/<ruleset-id>`) before any PUT. A PUT must
target that ruleset's own ID:

```sh
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit/rulesets/<ruleset-id> \
  --input .github/rulesets/main.json
```

Use the same command with the other template paths after reviewing their target
refs and ruleset IDs.

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

Apply the repository-wide merge-method policy with the repository API. During
the switch to merge commits, run it only at step 4 of the order below, after the
branch rulesets allow merge commits:

```sh
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  repos/Qbit-Org/qbit \
  --input .github/repository-settings/merge-methods.json
```

### Switching to Merge Commits

Apply the merge-commit and signed-commit templates in the order below. GitHub
blocks a merge when the methods a branch ruleset allows and the methods the
repository enables do not overlap, so this order keeps pull requests mergeable
at every step.

Until step 4 disables squash merging, GitHub still accepts a squash merge of a
pull request with unsigned commits, because it signs the squash commit itself.
Run steps 1 to 4 back to back, with no merges in between: signature enforcement
is real only after step 4.

1. Import `.github/rulesets/signed-commits.json` as a new ruleset. Confirm that
   it has no bypass actors and that its enforcement is `active`, and record its
   ID, the number at the end of the ruleset's settings URL. The checks in step 5
   and in [Rolling Back](#rolling-back) use it.
2. In Settings → General → Pull Requests, tick **Allow merge commits**. Leave
   squash merging enabled for now.
3. Edit each existing branch ruleset (`main`, `0.1.x`, `1.0.0`, and `1.x.x`):
   untick "Require linear history" and set the allowed merge methods to Merge
   only.
4. Untick **Allow squash merging** and **Allow rebase merging**. The repository
   now matches `.github/repository-settings/merge-methods.json`.
5. Verify the result with the assertions below. Each `jq -e` exits non-zero
   when an expectation fails, and the block stops at the first failure. A
   non-zero exit means stop: fix the setting, or roll back (see
   [Rolling Back](#rolling-back)).

   ```sh
   (
     set -euo pipefail
     repo=Qbit-Org/qbit
     ruleset_id=<signed-commits-id>
     gh api "repos/${repo}/rulesets/${ruleset_id}" | jq -e '
       .enforcement == "active" and .bypass_actors == []
       and .current_user_can_bypass == "never"'
     gh api "repos/${repo}" | jq -e '
       .allow_merge_commit == true and .allow_squash_merge == false
       and .allow_rebase_merge == false'
     for branch in main 0.1.x 1.0.0 1.x.x; do
       gh api "repos/${repo}/rules/branches/${branch}" |
         jq -e --argjson id "${ruleset_id}" '
           any(.[]; .type == "required_signatures" and .ruleset_id == $id)
           and all(.[]; .type != "required_linear_history")
           and any(.[]; .type == "pull_request")
           and all(.[] | select(.type == "pull_request");
                   .parameters.allowed_merge_methods == ["merge"])'
     done
     gh api "repos/${repo}/rules/branches/1.1.0" |
       jq -e --argjson id "${ruleset_id}" '
         any(.[]; .type == "required_signatures" and .ruleset_id == $id)'
   )
   ```

### Rolling Back

The merge-commit path was proven on `qbit-white-paper` before the switch:
spike pull request #6 merged a signed commit with a merge commit, and #7 ran the
full `squash-sign` flow. If merges still stall after the switch, roll back in
the order below. Each step leaves at least one merge method that both the
branch rulesets and the repository allow, so merges never freeze:

1. Set the `signed-commits` ruleset enforcement to `disabled` (Settings → Rules
   → Rulesets → `signed-commits`). Keep the ruleset so that it can be
   reactivated.
2. In Settings → General → Pull Requests, tick **Allow squash merging** and
   **Allow rebase merging**. Leave merge commits enabled for now.
3. Edit each branch ruleset (`main`, `0.1.x`, `1.0.0`, and `1.x.x`): set the
   allowed merge methods to Squash and Rebase, and tick "Require linear
   history".
4. Untick **Allow merge commits**.
5. Verify the rolled-back state with the assertions below. A non-zero exit
   means stop: a step did not apply. The per-branch assertions that no
   `required_signatures` rule applies are the real check, whichever ruleset
   carried the rule. The first assertion looks up the `signed-commits` ruleset
   by the ID recorded at apply time, across every page of rulesets, and
   requires that it still exists and is disabled, so it does not depend on the
   ruleset's name: a renamed ruleset that is still active fails it, and so does
   a deleted one.

   ```sh
   (
     set -euo pipefail
     repo=Qbit-Org/qbit
     ruleset_id=<signed-commits-id>
     gh api --paginate "repos/${repo}/rulesets" |
       jq -e -s --argjson id "${ruleset_id}" '
         add | any(.[]; .id == $id and .enforcement == "disabled")'
     gh api "repos/${repo}" | jq -e '
       .allow_merge_commit == false and .allow_squash_merge == true
       and .allow_rebase_merge == true'
     for branch in main 0.1.x 1.0.0 1.x.x; do
       gh api "repos/${repo}/rules/branches/${branch}" | jq -e '
         all(.[]; .type != "required_signatures")
         and any(.[]; .type == "required_linear_history")
         and any(.[]; .type == "pull_request")
         and all(.[] | select(.type == "pull_request");
                 any(.parameters.allowed_merge_methods[]; . == "squash"))'
     done
     gh api "repos/${repo}/rules/branches/1.1.0" |
       jq -e 'all(.[]; .type != "required_signatures")'
   )
   ```

Record the rollback in the release checklist: when it happened, the reason, the
pull requests that stalled, and, for each branch, the commit range that landed
while `signed-commits` was disabled, so that `squash-sign audit` can review it.
The templates in this repository still describe the merge-commit policy; reapply
it with [Switching to Merge Commits](#switching-to-merge-commits) once the cause
is fixed.

## Signed Commits

After the operator applies `.github/rulesets/signed-commits.json`, every commit
pushed to `main`, `0.1.x`, `1.0.0`, `1.1.0`, or `1.x.x` must carry a signature
that GitHub verifies. The rule lives in its own ruleset with no bypass actors,
so the `OrganizationAdmin` bypass on the other branch rulesets does not exempt
anyone from it.

`squash-sign` is the maintainers' fleet tool; it is not vendored in this
repository. It guarantees that each pull request it lands is one commit signed
with an operator's OpenPGP key (or, for a standard two-commit subtree update,
two commits that a person signed when they were created), that `verify` checked
before merge that a person's key, not GitHub, signed them, and that the pull
request lands with a merge commit. The maintainers track the results of the
daily `squash-sign audit` privately.

The `include` list names exact refs, not patterns. Creating a new long-lived
branch therefore requires adding it to `signed-commits.json` and to the live
ruleset; until then the branch accepts unsigned commits. The daily
`squash-sign audit` is the backstop: it reports protected branches that are
missing from the list. `backport/*` and `release/v*` are short-lived pull
request source branches, so they are deliberately not covered: drafts there may
be unsigned, and their work lands through `squash-sign`.

`1.1.0` has only the signature rule. No branch ruleset covers it, so it has no
pull request, deletion, force-push, or status-check protection: anyone with
write access can push a Verified commit to it directly, force-push it, or
delete it. Adding its full protection is tracked separately.

The rule checks commits when they reach a protected branch, not while they sit
on a pull request branch:

- Draft and review commits on a pull request branch may be unsigned.
- Before merge, an agent runs `squash-sign apply` on the pull request, which
  reduces it to one commit, and the operator signs that commit with one
  hardware-key touch. The pull request then lands as that commit plus GitHub's
  merge commit, which GitHub signs.
- Every pull request squashes this way, including one with more than one commit
  when all of its commits are signed, and any with an unsigned commit. Pull
  requests opened under the earlier squash-only policy stay mergeable after the
  switch once `squash-sign apply` has run; GitHub refuses the merge commit while
  any of their commits is unsigned.
- A backport also lands as one commit, and `squash-sign` keeps its original
  authors as `Co-authored-by` trailers.
- Run `squash-sign apply` before the final approval. The rewrite is a push, so
  `dismiss_stale_reviews_on_push` and `require_last_push_approval` can require a
  fresh approval from someone other than the pusher.

A `src/libbitcoinpqc` import follows the same rule. The import is one
main-line commit that carries the `git-subtree-dir` and `git-subtree-split`
trailers, as in Qbit-Org/qbit#268. `squash-sign` squashes the import, pin, and
release-notes commits into one operator-signed commit that keeps those
trailers, so `test/lint/libbitcoinpqc-subtree-check.sh` still passes, with one
touch. For a large vendored import, the signature attests the pin: the
`git-subtree-split` upstream commit, the lint, and the upstream tree
comparison. The operator does not attest a line-by-line reading of about 2,000
vendored lines. The
[libbitcoinpqc subtree runbook](../subtrees/libbitcoinpqc.md#signing-the-import)
lists what the operator checks before touching.

Only a standard two-commit git-subtree update keeps its commits: the
"Squashed '<prefix>/' changes" commit and the subtree merge. That shape is rare;
it applies to the subtrees inherited from Bitcoin Core, which have not been
updated since the fork. Both commits are signed when they are created, with
`git subtree pull --squash -S`, so the update needs two touches, and it lands
with `squash-sign merge --keep-commits`, which accepts it only when a person's
OpenPGP key signed both commits.

Contributors sign their own commits, and a signature from any key registered
on their GitHub account that GitHub verifies counts. `squash-sign`'s own
commits are always signed with an operator's OpenPGP key. `squash-sign` refuses
fork pull requests by design:

- A fork pull request that is a single commit Verified against the
  contributor's own key, not a web-flow commit made in GitHub's web UI, lands
  with the merge button as a merge commit.
- If a fork pull request has an unsigned commit or more than one commit, a
  maintainer does not rewrite the contributor's branch, but recreates the pull
  request from a branch in this repository with `squash-sign`. The original
  author keeps credit through a `Co-authored-by` trailer and in the new pull
  request's body, and the maintainer closes the fork pull request with a link
  to the new one.
- A fork pull request that touches a subtree is not recreated from the fork: a
  maintainer re-imports the subtree in a branch of this repository.

In repositories that merge with merge commits,
`squash-sign merge --admin-approvals` acts on the pull request's review
decision:

- `CHANGES_REQUESTED`: it always refuses.
- `APPROVED`, or no review required: it merges without `--admin`, so GitHub
  enforces every rule on its server.
- `REVIEW_REQUIRED`: it merges with `--admin` and zero approvals. On GitHub's
  server, `--admin` also bypasses the `Required Merge Gate` and every other
  rule in the branch rulesets that list `OrganizationAdmin` as a bypass actor,
  so `squash-sign` enforces the checks below on the client side only. Merging
  this way is an operator decision (G8).

It passes `--admin` only when all of these checks pass:

- The repository allows merge commits only.
- `squash-sign verify` passes.
- Every required status check is green, including checks bound to a GitHub App,
  where the check's `app.id` must match the required integration, and the
  branch is up to date with its base where the ruleset requires that.
- `--admin` would skip no other rule: no review thread is unresolved, and no
  rule for required deployments, code scanning, or a merge queue applies.

Agents never run plain `gh pr merge --admin`: it skips all of these checks,
because `OrganizationAdmin` bypasses the branch rulesets. The `signed-commits`
ruleset has no bypass actors, so GitHub still refuses unsigned commits, even for
admins.

The rule accepts any commit that GitHub marks Verified. GitHub signs only
commits it creates itself through its API or web UI: GraphQL
`createCommitOnBranch`, a commit created through the API with `GITHUB_TOKEN`,
and web UI edits. Those pass the rule without an operator signature. A bot that
creates a commit locally and runs `git push` sends an unsigned commit, which
GitHub refuses. `squash-sign verify` and a daily `squash-sign audit`, which run
outside this repository, cover the GitHub-signed gap by process; the server
does not. `contrib/verify-commits` assumes merge commits that a developer signs
with `github-merge.py`, while GitHub signs merge commits under this policy, so
that tool needs a separate review before it is used on this history.

No recurring upstream sync exists; upstream history arrived once, on
2026-06-17. `refs/heads/upstream/**` is outside the signature rule, so an
optional upstream reference branch can hold upstream history verbatim. A rare
verbatim import of third-party history into a signed branch uses a recorded
break-glass that lifts the rule on that branch only:

1. An organization admin edits the `signed-commits` ruleset and removes only the
   target branch's ref from its `include` list. Enforcement stays `active` on
   every other branch.
2. The admin pushes the import to that branch.
3. The admin adds the ref back to the `include` list immediately.
4. The admin runs the step 5 assertions in
   [Switching to Merge Commits](#switching-to-merge-commits), which must pass
   for every branch.
5. The admin records the branch, the imported commit range, and the reason in
   the release checklist, and confirms that only that range landed on the
   branch while it was excluded.

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
