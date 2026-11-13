# Skipping CI for a tree that already passed

A pull request lands as one signed commit made by `squash-sign apply`. That
commit has exactly the same tree as the head that was reviewed, but GitHub
records checks per commit, so it would run Full Validation (`ci.yml`) and Core
Checks (`core-checks.yml`) again from scratch. Label changes do the same.

Instead, a pull request run whose commit under test has a tree that already
passed the workflow, routed the same way, skips the workflow's expensive jobs.
Each workflow's gate job (`Full Validation Gate`, `Core Checks Gate`) still
runs and reports success, so `Required Merge Gate`, which waits for those two
checks, passes within minutes. A real change, a moved base or anything else
that changes the tree under test runs everything, as before.

The decision is made by `ci/checks/tree_pass_marker.py`; the workflows only
wire it up. Its tests, `ci/checks/test_tree_pass_marker.py`, run in Core
Checks' `same-tree skip contract` job for every change routed to `source`, the
only changes that can alter what they test. The marker never skips that job,
and Core Checks Gate requires it to succeed: a regression that skips without
a valid marker cannot also skip the job that would catch it. On the skip path
Core Checks Gate, and so Required Merge Gate, waits for that job: a checkout,
installing `python3-yaml` if the system Python lacks it (retried), and the
suite. The suite took between 65 and 71 seconds on a developer machine in
the last runs while this change was written, and 65 seconds in its review;
the job's time on a GitHub runner has not been measured. The suite does not
run in Required Merge Gate's `classify validation profile` job, which every
pull request waits for, docs-only ones included.

## What never skips

- Every event other than `pull_request`: pushes to protected branches, tags
  and release builds, `merge_group`, schedules and `workflow_dispatch`. These
  events also never save a marker.
- Required Merge Gate itself: classification, its contract tests, the
  operator-key, release-policy and docs validation, and its wait for the two
  gate checks run on every event.
- A re-run. "Re-run all jobs", or re-running the classify job, starts attempt
  2 or later of the run, and such an attempt always runs in full and saves a
  marker for itself when it passes. That holds for a re-run of a run that
  saved a marker, of a run that skipped on one, and of any other run.
  "Re-run failed jobs" re-runs only the failed jobs and the jobs that depend
  on them. Classification succeeded in the first attempt, so it is not re-run
  and that attempt's decision stands: a full run re-runs its failed jobs, and
  a run that skipped re-runs whichever of `lint commit range` and
  `same-tree skip contract` failed, and its gate.
- Any validation profile but `source`. Docs-only, release-policy and
  GitHub-metadata changes run as before.
- A pull request whose head branch has ever been used by another pull request
  (open, closed or merged).
- A pull request whose timeline or issue events hold any event about its
  base: any event whose name starts with `base_ref_` or
  `automatic_base_change_`. The known ones are:
  - `base_ref_changed`, a manual retarget;
  - `base_ref_force_pushed`, a force push to the base;
  - `base_ref_deleted`;
  - `automatic_base_change_succeeded` and `automatic_base_change_failed`,
    which GitHub records when it retargets a pull request itself after the
    base was merged and deleted. An automatic retarget leaves no
    `base_ref_changed`.

  GitHub's [issue event types][events] page documents `base_ref_changed` for
  both listings. It documents the two automatic ones for the issue events only,
  though the timeline returns them too, and it does not list
  `base_ref_force_pushed` or `base_ref_deleted`. The rule therefore matches
  the prefixes in both listings, not a list of names. Base force pushes are
  routine on some branches: once one happens during a pull request's life,
  that pull request never skips again.
- A pull request whose timeline or issue events hold `head_ref_deleted` or
  `head_ref_restored`: its head branch was deleted or restored while it
  existed. Deleting a head branch closes every pull request from it, and
  after the branch is re-created one of them might be reopened while runs of
  another are still on record. Neither step has been tried on GitHub: that
  the event is recorded on a pull request whose branch is deleted while it
  is open, and that such a pull request can be reopened, are assumptions
  here. Of 198 pull requests of this repository
  (#1 to #424), 19 have one of these events, every one recorded after the
  pull request closed or merged, when it no longer runs. Force pushes to the
  head (`head_ref_force_pushed`) are routine and do not count.
- Core Checks' `same-tree skip contract` job, which runs this mechanism's own
  tests (above).
- Full Validation's `lint commit range` job, which runs the lints that read
  history rather than the tree. The signed commit that lands has the same tree
  as the reviewed head but new history, so these lints must run on it. They
  are cheap, and the gate still requires them. Of the test runner's lints,
  three read history:
  - `commit_msg` reads the messages of the pull request's commits;
  - `scripted_diff` replays the scripted-diff commits among them;
  - `subtree` finds each subtree's last import with `git log --grep`
    (`test/lint/git-subtree-check.sh`; for `src/libbitcoinpqc`,
    `libbitcoinpqc_latest_import` in `test/lint/libbitcoinpqc-release-tag.sh`).
    It also fetches the libbitcoinpqc release tag from GitHub and checks its
    signature with `gpg`. The hosted `ubuntu-24.04` image carries `gpg`
    (its package list has `gnupg2` 2.4.4), so the job installs nothing; the
    lint job's container installs it.

  Every other lint reads the checked-out tree through `git ls-files`,
  `git grep` or the files themselves, and so do the `test/lint/lint-*.py`
  scripts. The full `lint` job runs all of them, these three included, and
  the marker may skip it.
- `test each commit` and the macOS native jobs of Full Validation, which are
  not part of its gate.
- `ci-nightly-heavy.yml`, the manual IBD and RPC performance workflows, and
  every other workflow.

## How it works

### The key

The `classify validation profile` job of each of the two workflows, after it
has classified the change, computes a key prefix:

```
qbit-tree-pass-v1-<workflow file>-s<salt>-t<tree>-g<routing>-r
```

- `<tree>` is the tree of `GITHUB_SHA`, the merge of the pull request head into
  its base that GitHub tests. It is never a commit SHA: the signed commit has a
  new SHA but the same tree. A different head tree or a moved base gives
  another merge tree.
- `<routing>` is a hash of the target branch and the changed-file list the
  classifier read. The same tree routed to fewer checks therefore never
  matches, for example after the pull request is retargeted.
- The workflow files, the local actions under `.github/actions/` and the CI
  scripts are part of the tree, so a change to any of them changes the key. On
  `pull_request` events GitHub runs the workflow file as it is in that same
  merge commit.

A saved marker is the prefix followed by `<run ID>-a<run attempt>` of the run
that saved it.

### Saving a marker

Each workflow ends with a `save pass marker` job. It starts only for a
`pull_request` run that classified the change as `source` and that the marker
did not skip, and only when the gate job succeeded. Its `Check every job
passed` step then checks the following and saves nothing unless all of them
hold:

- every job the marker stands for succeeded: classification, every expensive
  job, the jobs the marker never skips (`lint commit range`,
  `same-tree skip contract`) and the gate. The one exception is Core Checks'
  mainnet posture job, which may be skipped, but only when classification said
  that the target branch does not need it (`0.1.x`);
- the run's own skip decision was `false`, so a marker skip never saves;
- the checked-out commit under test still has the keyed tree;
- for Full Validation only, the pull request's merge ref, fetched at the end of
  the run, still has that tree. Full Validation's jobs check out the merge ref
  as it is when each job starts, not the event's commit, so a ref that moved
  during the run means some jobs tested another tree. Core Checks' jobs check
  out the event's commit, so the ref does not matter there.

Then the job uploads a small artifact to its own run, named `tree-pass-` and
the SHA-256 of the full marker key (run and attempt included). Only after that
upload succeeds does it save the marker in the Actions cache. Both steps use
`continue-on-error`: a failed upload or save only means the next run does the
work again. The artifact is kept for 30 days; the cache drops a marker after 7
days without use.

### Deciding to skip

The classify job looks the prefix up with `actions/cache/restore` in
lookup-only mode. It then skips only when all of these hold, and runs
everything otherwise:

1. the event is `pull_request`;
2. this is the run's first attempt (`GITHUB_RUN_ATTEMPT` is `1`): a re-run
   always runs in full;
3. the pull request does not carry the `ci:full-run` label;
4. the change is routed to the `source` profile;
5. the key was computed, the lookup step succeeded, and it returned an entry;
6. this pull request is the only one from its head branch, and has no base
   event and no head branch deletion or restoration. One request lists the
   pull requests from its head branch,
   `GET /repos/{repo}/pulls?head=<owner>:<branch>&state=all&per_page=2`. It
   must return exactly this pull request, with this head branch and head
   repository, and its creation time as `YYYY-MM-DDTHH:MM:SSZ`. Any other
   count refuses, so two entries are enough. Its
   timeline (`GET /repos/{repo}/issues/{n}/timeline`) and its issue events
   (`GET /repos/{repo}/issues/{n}/events`) are each read page by page, 100
   events at a time, until a page comes back empty, so neither relies on
   pagination links. Every event must have a type, and no type may start with
   `base_ref_` or `automatic_base_change_`;
7. some marker of this prefix, named `<prefix><run>-a<attempt>` with a run that
   is not this one, is confirmed by GitHub's records of that run:
   - the attempt (`GET /repos/{repo}/actions/runs/{run}/attempts/{attempt}`)
     is a `pull_request` run of the same workflow file, for the same head
     repository and branch, whose head commit has this head's tree;
   - in that attempt's jobs (`…/attempts/{attempt}/jobs`), the gate job and
     the `save pass marker` job each appear once and completed with `success`;
   - the run holds exactly one artifact with the name derived from the full
     key (`GET /repos/{repo}/actions/runs/{run}/artifacts?name=…`), and that
     artifact has not expired;
   - the run appears exactly once in this pull request's run listing (the
     one rule 8 reads), with a creation time and a latest attempt number at
     least as new as the attempt that saved;
   - the run was created after this pull request was: its creation time in
     the run listing is in a later second than the pull request's in rule
     6's listing. No run of this repository's pull requests was created
     less than 3 seconds after its pull request (80 pull request and
     workflow pairs, and 40 Full Validation pairs in the review of this
     change), so the same second is refused rather than left to a scripted
     race;
   - in the jobs of the run's latest attempt (`…/runs/{run}/jobs?filter=latest`)
     the gate job appears once, belongs to the attempt the listing numbers,
     and completed with `success`. A re-run of the vouching run that failed,
     or that is still running, stops the skip, and so does a jobs answer from
     an older attempt than the listing shows;
8. no later run of this pull request contradicts that pass. The decision
   lists the workflow's runs for the head branch,
   `GET /repos/{repo}/actions/workflows/<file>/runs?branch=<branch>&event=pull_request`,
   page by page, 100 at a time, until a page comes back empty, and keeps the
   runs from this head repository, whatever their head tree. The vouching
   run must be among them. The listing shows each run as its latest attempt,
   with the run's own creation time. A run other than this one and the
   vouching one is later when its run ID is higher than the vouching run's
   (in practice, a run created after it; the code compares the IDs), when
   its latest attempt started at or after the vouching run was created, or
   when it has not finished. Every later run must either have concluded
   `success` (a full pass, a marker skip, or a draft run that ran nothing) or
   show its gate job completed with `success` in its latest attempt
   (`…/runs/{run}/jobs?filter=latest`, the gate belonging to the attempt the
   listing numbers): jobs outside the gate, such as
   `test each commit`, can fail a run without saying anything about the tree.
   A listing whose `total_count` is more than the runs read, or reaches the
   1,000 runs GitHub returns at most for a filtered listing, refuses.

The vouching run's own conclusion is never read. A draft run skips every job,
the gate included, and still concludes `success`. A run cancelled after its
save job finished concludes `cancelled`. The gate and save jobs of the attempt
that saved are what count, and the gate of the latest attempt. Neither job ran
in a draft run, so the first case cannot vouch; both finished in the second,
so it can.

Rule 8 means that a skip stands on the newest execution in this pull
request: an earlier pass never answers for a later run that failed. Without
it, a `ci:full-run` run of the same tree could fail, the label come off, and
the `unlabeled` run skip on the older pass. A failure older than the vouching
run does not count: the pass came after it.

Rule 8 counts later runs of every head tree. A run record shows the head
commit, not the merge commit the run tested, and a run of another head tree
can test the same merge tree. For example, the vouching run tests head `h1`
merged with an older base, giving merge tree `M`. "Update branch" then makes
a head whose own tree is `M`, with the same key; its run cannot vouch for
`h1` (another head tree), runs in full and fails. If the author then pushes
`h1` back, its next run must not skip on the first pass. Once the base holds
part of the change, other head trees can merge to `M` too, so no head-tree
filter is exact. The cost is a full run after a later run of another tree
failed or was cancelled, for example after pushing a broken commit and then
reverting it. The usual landing (a green run, then the signed squash) has no
later runs at all.

"Later" is measured from the vouching run's creation, as the run listing
reports it, not from the start of the attempt that saved. A "Re-run failed
jobs" attempt starts when it is requested, but GitHub lists the jobs it did
not repeat under that attempt with their old times, so the work it vouches
for can be hours older than the attempt (run 42923201068: attempt 2 started
at 06:49, and its unrepeated jobs show 23:25 the day before). The run's
creation precedes every job of every attempt, so no work the marker vouches
for is older than it, however the run was re-run. A run with a higher ID
than the vouching run counts even if its latest attempt started earlier, and
a run that started between the vouching run's creation and a full re-run of
it counts too. Both err towards a full run.

Rule 8 reads GitHub's own run records rather than a fail marker: a cache
entry saved by a last job of a full run that has a failed job. Such a job
belongs to the failed run itself. To see a failure that came before a
cancellation it must run even in a cancelled run, and both workflows use
`cancel-in-progress`, so removing `ci:full-run` while the labeled run is still
going cancels it. If that job fails, or its cache save does, the failure goes
unrecorded and nothing says so. The entry can be evicted before the pass
marker it should override. And once saved it refuses the tree for good, even
after a later full run passed. The run listing has none of these gaps: a run
that failed, was cancelled, timed out or is still running is listed in that
state by GitHub itself, run records outlive the cache, and a later pass
supersedes an earlier failure. Its cost is one listing per decision, usually
one page and the empty one, and one jobs lookup for each later run that did
not conclude `success`.

The marker itself is only a claim. Any run in the pull request's cache scope
can save any key, including a run of a workflow file that an earlier push to
the same pull request changed. The artifact is what binds the key to the run:
a job can upload an artifact only to its own run, and the save job uploads
that name only for the key its own checks approved. Any other job of the
vouching run that runs the pull request's code could upload an artifact of
that name too. That code, workflow files included, is the vouching run's
head tree merged with its base, and the head-tree check makes that head tree
this pull request's head tree: the very tree being skipped. So a proof can
come only from code in the tree under decision, and the key it names records
the merge tree and the routing that run tested. A run of this head against
another base, into another branch or for another pull request saved a
different key, so it holds no artifact for this one.

That argument holds only if the run that saved ran the reviewed workflow
files. A `pull_request` run takes its workflow files from the merge of the
head into the base, and nothing in the run decides which base that is. Take a
run of another pull request from the same head branch, or of this pull
request while it targeted another branch. If that base carried workflow files
nobody reviewed, the run could upload an artifact of any name and report any
job green, and the head-tree check would still pass. Rule 6 excludes both
cases as far as GitHub records them. With no other pull request from the head
branch and no recorded base event, the vouching run (same head repository and
branch, rule 7) is a run of this pull request, against a base branch of the
same name that it never left. The run record's own `pull_requests` field
cannot serve: it shows pull requests as they are now and is empty for closed
ones. A routing hash in the key does not help either, because a changed
workflow computes the artifact name itself.

The listing alone would carry the case of an earlier pull request from the
same branch: a writer opens one into a base they control, with a changed
workflow whose run uploads the artifact for a later key, closes it, deletes
and re-creates the branch, opens this pull request, and saves that key here
from a temporary changed workflow. The listing has returned closed and merged
pull requests in every check so far, and then refuses (two pull requests).
Rule 7 also binds the run to this pull request by time: the vouching run
must have been created after this pull request was, both times as GitHub
reports them. A run created before this pull request, as a run of a pull
request closed before this one was opened normally is, is refused. Normally:
a run is created a few seconds after its event, so a run for the last event
of the earlier pull request could in principle be created after this one was
opened, and that case rests on the listing. The rule binds by
creation order, not by which pull request a run belongs to: a run of another
pull request from the same branch created after this one was opened passes
it, and is for the listing to refuse, or for the head branch events of rule 6
where the branch was deleted and restored. The run's creation time stayed the
run's own through re-runs: in 30 re-run runs of this repository's workflows
(28 partial, 2 full), the run listing and the run record both gave the run's
original creation time (within a second of its first attempt's record), not
the time of the re-run, and the review of this change checked four more full
re-runs. In 80 pull request and workflow pairs checked, no run was created
before its pull request; the earliest came 3 seconds after it.

Both listings are read through the REST API with a name-prefix rule rather
than through GraphQL's typed `timelineItems(itemTypes: …)`. The typed query is
documented, but it counts only the types it names, so a base event GitHub adds
later would pass unseen; the prefix rule refuses unknown names too. The cost
is reading every page of both listings, usually one page each plus the empty
one that ends it.

The lookup returns the newest entry of the prefix. If that entry fails the
checks, for example because it was saved by a run cancelled while its save job
was still running, the decision lists this pull request's markers of the same
prefix (`GET /repos/{repo}/actions/caches?key=…&ref=refs/pull/<n>/merge`,
newest first). It tries up to five in all, so a newer bad entry does not hide
an older valid one. The run that was cancelled while saving is later than the
older marker's run, but its gate passed, so rule 8 does not count it against
the older pass. Rule 8's run listing, once read, serves all of them. Only a
listing that succeeded is remembered: after a failed one, each candidate
reads it again. Every API call shares one 120-second budget. A failed marker
listing leaves only the entry the lookup returned. Any other API failure,
malformed answer or exhausted budget counts against that marker.

Every expensive job's `if` ends with
`needs.classify-changes.outputs.tree_pass_skip != 'true'`. That output is
`'true'` only when the decision step ran, succeeded and said so. The marker
steps use `continue-on-error`, so a cache miss, an expired or evicted entry, a
cache-service error, a refused API call or a bug in the script runs
everything.

The gate jobs accept a skipped job only when the marker skipped the run, and
only on a pull request. A failed or cancelled job, a skip in a run the marker
did not skip, a skipped `lint commit range` or `same-tree skip contract`, and
a marker skip reported for any other event fail the gate as before.

Core Checks runs in full for a draft, so a draft can save a Core Checks marker.
Full Validation skips its jobs for a draft and saves none.

## What remains possible

These are the cases the checks above do not exclude:

- **A base that accepted unreviewed pushes.** The two listings record
  retargets, force pushes and deletions of the base, but not ordinary pushes
  to it. The
  vouching run ran the head merged with the base as it was when that run was
  first created. A re-run reuses the run's original merge commit, so even a
  recent attempt may have run workflow files from an old state of the base.
  A writer who can push to the base without review could add unreviewed
  workflow files, let a run of this pull request vouch for the tree it will
  have later, and then revert them with no event recorded. Such a base also
  takes changes without review or required checks, so for a pull request into
  it the skip gives a writer nothing new. A base that only requires
  pull-request review, as `main`, `0.1.x`, `1.0.0` and `1.x.x` do, carries
  reviewed workflow files in every state. Of the branches the two workflows run
  for, `1.1.0` has no ruleset, and `develop` does not exist and no ruleset
  stops a writer from creating it.
- **A base deleted and re-created under the same name**, if GitHub records no
  event for it. Where `base_ref_deleted` is recorded, it turns skipping off.
  The protected branches above reject deletion.
- **A merge ref that moves and returns.** Full Validation's end-of-run check
  sees the merge ref's tree only at that moment. Suppose the base moves and a
  later base commit restores the earlier tree during one run (tree T, then T',
  then T again). Jobs that started in between tested T', and the marker still
  records T. This needs a base change and its tree-identical reversal during a
  single run.
- **Environment drift.** A marker records that a tree passed, not the
  environment it passed in. Runner images, distribution packages, toolchains,
  container images and external downloads such as `qa-assets` can change
  between the run that saved a marker and a later run that skips. Bump the salt
  when such a change must be revalidated, and expect the nightly workflow to
  catch drift.
- **Another pull request from the same branch, with runs created after this
  one was opened.** The time binding of rule 7 refuses runs created before
  this pull request, but not a run of another pull request from the same
  branch created after it: one opened later, or one open at the same time
  into another base. That case rests on the pull request listing of rule 6:
  it must return both, and then refuses. The same goes for a run created
  for the other pull request's last event after this one was opened. Where
  the branch was deleted and re-created to close the other pull request,
  the head branch events of rule 6 are meant to refuse too; that GitHub
  records them on a pull request that was open at the time is not verified.
- **A pull request converted from an issue (unverified).** GitHub's API can
  turn an existing issue into a pull request (`POST /pulls` with `issue`).
  If such a pull request's `created_at` were the issue's, a writer could give
  it a creation time earlier than a run of another pull request from the same
  branch, and that case would rest on the listing again. This has not been
  checked, because checking it would create an issue and a pull request.
- **Deleted runs.** A later run that failed counts only while GitHub lists
  it. Deleting a workflow run takes write access to the repository, and a
  deleted run no longer stops a skip.
- **Lost work only.** A deleted or expired proof, an evicted marker, a refused
  or slow API call, a failed listing with a bad newest entry, more than four
  newer bad entries, a reused head branch, a retarget, a head branch deleted
  or restored, a vouching run created before this pull request or in its
  second, a re-run, a later run
  of the pull request that did not pass (of any head tree and against any
  base, which rule 8 cannot tell apart, or one with a higher ID than the
  vouching run but started before it), a run still in progress, and a pull
  request with 1,000 or more runs of the workflow all lead to a full run,
  never to a skip.

## When a landing skips

`squash-sign apply` resets the branch to its merge-base with the base
(`git reset --soft`), commits the whole change as one signed commit, and
refuses if that commit's tree differs from the pull request head's
(`squash_sign.py` in the squash-sign skill). The squash therefore keeps the
head's tree and the head's merge-base. If the base has not moved since the
vouching run, GitHub merges the squash into the same base, the merge tree and
the key are unchanged, and the head-tree check (rule 7) passes, whether or
not the head was behind its base.

A landing therefore skips when all of these hold:

- the base has not moved since the vouching run, the last full run that
  passed and saved;
- that run's `save pass marker` job finished before the squash was pushed.
  Both workflows cancel a running run on a new push, so a squash pushed while
  the run is still saving cancels it before it saves. The save job starts
  after the gate and is expected to take a minute or less, but that is
  unmeasured until this runs on GitHub: wait until it shows as finished;
- no later run (rule 8: a higher run ID, or started since the vouching run
  was created) is unfinished or failed, for example a run started by adding
  or removing some other label that the squash push cancels;
- the squash's own run meets rules 1 to 6: a first attempt of a
  `pull_request` run, without the `ci:full-run` label (while that label is on,
  every run is full), routed to `source`, with a marker found, from the only
  pull request of its branch, and with no base event.

A squash placed on the base's tip instead, a mode proposed for squash-sign,
which the installed tool does not have, would take the base's changes into
its tree. Unless the head already contained the base, that tree would be the
vouching run's merge tree rather than its head tree, and the landing would
not skip.

As an expectation, not a promise: the review of this change looked at the
last 40 pull requests merged into `1.x.x`. In eight of them the last green Full
Validation run was the final head's own run, the base did not move before the
merge, and the pull request had no base event, no other pull request from its
branch and no labels: those landings would have skipped Full Validation had
the squash been pushed right after that run. A ninth, #360, also had an
unmoved base, but it was retargeted (`base_ref_changed` at
2026-11-07T21:59:37Z), so rule 6 refuses every skip in it. So with today's
habits about one landing in five would skip Full Validation. The sample says
nothing about Core Checks.

## Forcing a full run

- **Label:** add `ci:full-run` to the pull request. GitHub starts every
  workflow for the `labeled` event, and they run in full. A full run that
  passes saves a fresh marker. Removing the label starts another run. That
  run skips only if the labeled run had already finished and passed (or the
  tree passed earlier and nothing failed since). Removing the label while the
  labeled run is still going cancels it, since both workflows cancel a
  running run on a new event; the cancelled run did not pass, rule 8 counts
  it, and the unlabeled run runs in full.
- **Re-run all jobs** of any run: attempt 2 and later never skip, whether the
  run saved a marker, skipped on one, or did neither. A re-run that passes
  saves a marker for its own attempt. A re-run that fails stops later runs of
  the tree from skipping on that run's earlier pass (rule 7).
- **Salt:** `TREE_PASS_MARKER_SALT` in the `Compute pass marker key` step of
  `ci.yml` and `core-checks.yml`. Bump it to invalidate every marker of that
  workflow, for example after the runner image or a toolchain changed under a
  tree. The workflow file is part of the tree, so the bump changes every pull
  request's tree under test once it lands on the base branch. It cannot force
  a full run of one pull request without a commit; use the label for that.

## What the cache guarantees

From GitHub's [dependency caching reference][caching]:

- A cache created by a `pull_request` run is created for the merge ref
  (`refs/pull/<number>/merge`). It "can only be restored by re-runs of the pull
  request" and "cannot be restored by the base branch or other pull requests
  targeting that base branch". A marker therefore never reaches another pull
  request or a protected branch.
- A pull request run can also restore caches of its base branch and of the
  default branch. Markers are only saved by `pull_request` runs, so those
  scopes hold none, unless a workflow running there saves one. No workflow
  does, and a change that made one do so would be reviewed on the base branch.
- "You cannot change the contents of an existing cache": a marker is never
  overwritten, and each saving run attempt has its own key.
- Entries not accessed for seven days are removed, and the oldest entries are
  evicted when the repository's cache is full. Either way the next run does the
  work.
- "Cache contents are not signed or verified." That is why the decision trusts
  GitHub's records of the run and the run's own artifact, not the entry.

Cache access is not a `permissions:` scope: "`cache-mode` controls the cache
access granted to the job's token, and it is enforced with scoped cache
tokens". Neither workflow sets `cache-mode`, so its default for the trigger
applies; "The `pull_request` event is not affected" by the read-only default of
low-trust triggers, and its caches are scoped to the merge ref. Whether a pull
request from a fork may save a cache is not documented. If it may not, such a
pull request saves no marker and never skips. Uploading an artifact to the
run's own record needs no `permissions:` scope either.

The permissions added are on each workflow's `classify validation profile`
job only, as GitHub's table of [permissions for fine-grained tokens][perms]
lists them. `actions: read` covers the run attempt, its jobs, the latest
attempt's jobs, its artifacts, the workflow's run listing and the cache
listing. `pull-requests: read` covers the pull request listing,
the timeline and the issue events; the table lists the last two under both
Issues (read) and Pull requests (read). The save job's checkout
does not persist credentials. Full Validation's merge ref check fetches
anonymously, which works because this repository is public; in a private copy
that fetch fails, and Full Validation saves no marker.

[caching]: https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching
[perms]: https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens
[events]: https://docs.github.com/en/rest/using-the-rest-api/issue-event-types
