#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Skip a workflow's expensive jobs when the tree under test already passed it.

A pull request run of Full Validation (ci.yml) or Core Checks
(core-checks.yml) that does all of its work and passes saves a pass marker in
the GitHub Actions cache, and uploads a proof artifact to its own run. A later
run of the same workflow for the same pull request whose commit under test has
the same tree, routed the same way, finds the marker, checks it against
GitHub's records of the run that saved it, and skips the expensive jobs; the
workflow's gate job still reports success, so Required Merge Gate passes. See
doc/development/ci-same-tree-skip.md.

The workflows call three subcommands:

``key``
    In the first job, after classification: the marker key prefix for the
    commit under test (GITHUB_SHA, the merge of the head into the base). It
    binds the workflow, the salt, that commit's tree, and the routing inputs
    (target branch and changed-file list). Never a commit SHA. A saved marker
    is the prefix followed by ``<run ID>-a<run attempt>`` of the run that saved
    it.

``decide``
    After the cache lookup: whether to skip. Only the first attempt of a pull
    request run (a re-run always runs in full), without the force label,
    routed to full source validation, whose lookup found a marker for exactly
    this key, skips, and only once GitHub's records show, for the run attempt
    the marker names: the run is of this workflow file, for this pull
    request's head branch and repository, and its head commit has this head's
    tree; its gate job and its save job concluded success; the run holds an
    unexpired artifact whose name is derived from the full marker key; and the
    gate job of the run's latest attempt concluded success too. A job of a run
    can upload an artifact only to that run, and the head-tree check means the
    jobs of the run that vouches ran the code of this very tree, whose save
    job uploads that name only for the key its own checks approved. No later
    execution may contradict that pass either: every other run of this
    workflow for this pull request, whatever its head tree, whose run ID is
    higher than the vouching run's, or whose latest attempt started at or
    after the vouching run was created, or that has not finished, must have
    concluded success or have a successful gate in the latest attempt the run
    listing numbers. When the newest marker fails, older markers of the same
    prefix are tried. This pull request must also be the only one ever opened
    from its head branch, neither its timeline nor its issue events may hold
    an event about its base (retarget, base force push or deletion, automatic
    retarget) or about its head branch being deleted or restored, and the run
    that vouches must have been created after this pull request was, so that
    it is one of this pull request's own runs against its own base. Anything
    else, including every failure, runs everything.

``save-plan``
    In the last job: whether this run may save its marker. Only a pull request
    run that the marker did not skip, in which every job the marker stands for
    succeeded (or was skipped where its routing does not run it), whose commit
    under test still has the keyed tree, saves; for Full Validation the pull
    request's merge ref must also still have that tree.

Every decision is written to the GitHub output file, the verdict
(``skip=`` or ``save=``) last. Only a usage or environment error exits
non-zero; the workflows treat that as "run everything" and "do not save".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

KEY_NAMESPACE = "qbit-tree-pass"
KEY_FORMAT = "v1"
# The pull request label that forces a full run of every workflow.
FORCE_FULL_RUN_LABEL = "ci:full-run"
SKIP_EVENT = "pull_request"
# Only full source validation is ever skipped: it is the only profile whose
# polled checks are the workflows' gate jobs (see Required Merge Gate).
SKIP_PROFILE = "source"
# The cache path the lookup and the save both name; it is part of the cache
# version, so the two must agree.
MARKER_DIR = ".tree-pass-marker"
MARKER_FILE = "marker.json"
# The proof a saving run uploads to itself: this prefix and the SHA-256 of the
# full marker key.
ARTIFACT_PREFIX = "tree-pass-"
# Markers of one prefix that a decision checks, newest first, and the time it
# may spend on GitHub's API in all.
MAX_CANDIDATES = 5
DECIDE_BUDGET_SECONDS = 120

GIT_TIMEOUT_SECONDS = 120
API_TIMEOUT_SECONDS = 30

SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SALT_RE = re.compile(r"^[1-9][0-9]{0,8}$")
NUMBER_RE = re.compile(r"^[1-9][0-9]{0,18}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH_RE = re.compile(r"^\.github/workflows/(?P<file>[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml)$")
JOB_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
# Events about a pull request's base branch, in its timeline or its issue
# events. GitHub documents base_ref_changed for both listings and
# automatic_base_change_succeeded/_failed for the issue events only (the
# timeline returns them too), and does not document base_ref_force_pushed or
# base_ref_deleted. Any name with one of these prefixes, known or not, turns
# skipping off for the pull request.
BASE_EVENT_RE = re.compile(r"^(?:base_ref_|automatic_base_change_)")
# The head branch deleted or restored while the pull request existed. Deleting
# a head branch closes every pull request from it; with the branch re-created,
# a pull request can be reopened while runs of another pull request from that
# branch, created after it, are still on record. On this repository's pull
# requests these events were only ever recorded after the pull request closed
# or merged. Force pushes to the head (head_ref_force_pushed) are routine and
# do not count.
HEAD_BRANCH_EVENTS = frozenset({"head_ref_deleted", "head_ref_restored"})
# The timeline and the issue events are read page by page until a page comes
# back empty, so a listing is complete without trusting pagination links.
EVENT_PAGE_SIZE = 100
# The workflow's runs for the head branch are read the same way. GitHub returns
# at most 1,000 runs for a filtered listing, so a listing that reaches that
# many is never taken as complete.
RUN_PAGE_SIZE = 100
RUN_LISTING_LIMIT = 1000
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
JOB_OUTPUT_RE = re.compile(r"^(?P<job>[A-Za-z0-9_-]+)=(?P<output>[A-Za-z0-9_-]+)$")
PREFIX_RE = re.compile(
    rf"^{KEY_NAMESPACE}-{KEY_FORMAT}"
    r"-(?P<workflow>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"-s(?P<salt>[1-9][0-9]{0,8})"
    r"-t(?P<tree>[0-9a-f]{40}(?:[0-9a-f]{24})?)"
    r"-g(?P<routing>[0-9a-f]{64})"
    r"-r$"
)
MARKER_SUFFIX_RE = re.compile(r"^(?P<run>[1-9][0-9]{0,18})-a(?P<attempt>[1-9][0-9]{0,4})$")
SAFE_TEXT_RE = re.compile(r"[^A-Za-z0-9 ._:/@()=,'#+-]")


class MarkerError(Exception):
    """An input or environment problem: the caller runs everything and saves nothing."""


@dataclass(frozen=True)
class Decision:
    act: bool
    reason: str


# -- validation ---------------------------------------------------------------


def safe(text: object, limit: int = 160) -> str:
    """Text fit for a log line or an output value: one line, no workflow commands."""

    cleaned = SAFE_TEXT_RE.sub("?", str(text))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def require(pattern: re.Pattern[str], value: str | None, what: str) -> str:
    if value is None or not pattern.fullmatch(value):
        raise MarkerError(f"{what} is missing or malformed: {safe(value)!r}")
    return value


def workflow_path_from_ref(workflow_ref: str | None, repository: str) -> str:
    """The workflow file of GITHUB_WORKFLOW_REF (``<owner>/<repo>/<path>@<ref>``)."""

    if not workflow_ref or "@" not in workflow_ref:
        raise MarkerError(f"workflow ref is missing or malformed: {safe(workflow_ref)!r}")
    owner_repo_path = workflow_ref.rsplit("@", 1)[0]
    if not owner_repo_path.startswith(repository + "/"):
        raise MarkerError(f"workflow ref {safe(workflow_ref)!r} is not a workflow of {repository}")
    path = owner_repo_path[len(repository) + 1 :]
    return require(WORKFLOW_PATH_RE, path, "workflow path")


def workflow_id(path: str) -> str:
    match = WORKFLOW_PATH_RE.fullmatch(path)
    if match is None:
        raise MarkerError(f"workflow path is malformed: {safe(path)!r}")
    return match.group("file")


def routing_digest(base_ref: str, changed_files: bytes) -> str:
    """What routed the run: its target branch and the changed-file list it classified."""

    digest = hashlib.sha256()
    digest.update(f"{KEY_NAMESPACE} routing {KEY_FORMAT}\0".encode())
    digest.update(b"base_ref\0" + base_ref.encode("utf8", "surrogateescape") + b"\0")
    digest.update(b"changed_files_sha256\0" + hashlib.sha256(changed_files).hexdigest().encode() + b"\0")
    return digest.hexdigest()


def key_prefix(*, workflow_path: str, salt: str, tree: str, routing: str) -> str:
    prefix = f"{KEY_NAMESPACE}-{KEY_FORMAT}-{workflow_id(workflow_path)}-s{salt}-t{tree}-g{routing}-r"
    if PREFIX_RE.fullmatch(prefix) is None:
        raise MarkerError(f"computed an invalid key prefix: {safe(prefix)!r}")
    return prefix


def parse_labels(labels_json: str | None) -> list[str]:
    try:
        labels = json.loads(labels_json or "")
    except ValueError as error:
        raise MarkerError(f"pull request labels are not JSON: {safe(error)}") from None
    if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
        raise MarkerError("pull request labels are not a list of names")
    return labels


# -- git ----------------------------------------------------------------------


def git(*args: str, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MarkerError(f"git {args[0]} failed: {safe(error)}") from None
    if completed.returncode != 0:
        raise MarkerError(f"git {' '.join(args[:2])} failed: {safe(completed.stderr.strip())}")
    return completed.stdout.strip()


def checked_out_tree(sha: str, cwd: Path | None = None) -> str:
    """The tree of the checked-out commit, which must be ``sha``."""

    head = git("rev-parse", "--verify", "HEAD^{commit}", cwd=cwd)
    if head != sha:
        raise MarkerError(f"the checkout is at {safe(head)}, not the commit under test {sha}")
    return require(SHA_RE, git("rev-parse", "--verify", "HEAD^{tree}", cwd=cwd), "tree of the commit under test")


# -- key ----------------------------------------------------------------------


@dataclass(frozen=True)
class MarkerKey:
    prefix: str
    tree: str
    head_tree: str
    workflow_path: str


def compute_key(
    *,
    workflow_ref: str | None,
    repository: str | None,
    salt: str | None,
    sha: str | None,
    head_sha: str | None,
    base_ref: str | None,
    changed_files: Path,
    cwd: Path | None = None,
) -> MarkerKey:
    repository = require(REPOSITORY_RE, repository, "repository")
    workflow_path = workflow_path_from_ref(workflow_ref, repository)
    salt = require(SALT_RE, salt, "marker salt")
    sha = require(SHA_RE, sha, "commit under test")
    head_sha = require(SHA_RE, head_sha, "pull request head commit")
    if not base_ref or len(base_ref) > 255 or any(ord(char) < 0x20 or char == "\x7f" for char in base_ref):
        raise MarkerError(f"base branch is missing or malformed: {safe(base_ref)!r}")
    try:
        changed = changed_files.read_bytes()
    except OSError as error:
        raise MarkerError(f"changed-file list cannot be read: {safe(error)}") from None

    tree = checked_out_tree(sha, cwd)
    # A pull request is tested as GitHub's merge of its head into its base: a
    # merge commit whose parents are the base and the head.
    parents = git("rev-list", "--parents", "-n", "1", "HEAD", cwd=cwd).split()[1:]
    if len(parents) != 2 or head_sha not in parents:
        raise MarkerError(f"the commit under test is not a merge of the pull request head {head_sha}")
    head_tree = require(SHA_RE, git("rev-parse", "--verify", f"{head_sha}^{{tree}}", cwd=cwd), "head tree")
    prefix = key_prefix(
        workflow_path=workflow_path, salt=salt, tree=tree, routing=routing_digest(base_ref, changed)
    )
    return MarkerKey(prefix=prefix, tree=tree, head_tree=head_tree, workflow_path=workflow_path)



def marker_key(prefix: str, run_id: int, attempt: int) -> str:
    return f"{prefix}{run_id}-a{attempt}"


def artifact_name(key: str) -> str:
    """The proof artifact for ``key``: bound to the whole key, run and attempt included."""

    return ARTIFACT_PREFIX + hashlib.sha256(key.encode("utf8")).hexdigest()


def parse_marker(prefix: str, key: object) -> tuple[int, int] | None:
    """The run ID and attempt a marker of ``prefix`` names, or None if it is not one."""

    if not isinstance(key, str) or not key.startswith(prefix):
        return None
    match = MARKER_SUFFIX_RE.fullmatch(key[len(prefix) :])
    if match is None:
        return None
    return int(match.group("run")), int(match.group("attempt"))


# -- decide -------------------------------------------------------------------

# api(path, paginate, timeout) returns the JSON documents of a GitHub REST call:
# one, or one per page.
Api = Callable[[str, bool, float], list]


def decode_documents(text: str) -> list:
    decoder = json.JSONDecoder()
    documents = []
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        try:
            document, index = decoder.raw_decode(text, index)
        except ValueError:
            raise MarkerError("GitHub's API returned something other than JSON") from None
        documents.append(document)
    if not documents:
        raise MarkerError("GitHub's API returned nothing")
    return documents


def gh_api(path: str, paginate: bool, timeout: float) -> list:
    """Call GitHub's REST API through ``gh``, with the job's token."""

    command = ["gh", "api", "-H", "Accept: application/vnd.github+json"]
    if paginate:
        command.append("--paginate")
    command.append(path)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MarkerError(f"GitHub's API failed: {safe(error)}") from None
    if completed.returncode != 0:
        endpoint = path.split("?", 1)[0]
        raise MarkerError(
            f"GitHub's API failed for {safe(endpoint)} (exit {completed.returncode}): {safe(completed.stderr.strip())}"
        )
    return decode_documents(completed.stdout)


@dataclass(frozen=True)
class Expected:
    """What the run a marker names must match: this pull request run's own facts."""

    repository: str
    workflow_path: str
    head_tree: str
    head_repository_id: int
    head_ref: str
    gate_job: str
    save_job: str
    current_run: int
    pr_number: int
    head_owner: str
    # This pull request's creation time, from the pull request listing once
    # pull_request_problem has read and checked it.
    pr_created: str = ""


def mismatch(name: str, observed: object, expected: object) -> str | None:
    # Same type and value: a JSON true must not stand in for an ID (bool is an int).
    if type(observed) is not type(expected) or observed != expected:
        return f"{name} is {safe(observed)!r}, not {safe(expected)!r}"
    return None


def field(document: object, *path: str) -> object:
    for part in path:
        if not isinstance(document, dict):
            return None
        document = document.get(part)
    return document


def run_attempt_problem(record: object, run_id: int, attempt: int, expected: Expected) -> str | None:
    """The run attempt is of this workflow file, for this head, with this head's tree.

    A run whose head commit has this head's tree ran the workflow files under
    review now, merged with its base's. That is what makes its own jobs and
    its own artifacts worth reading.
    """

    if not isinstance(record, dict):
        return "the run attempt lookup did not return a run"
    checks = [
        ("id", field(record, "id"), run_id),
        ("attempt", field(record, "run_attempt"), attempt),
        ("repository", field(record, "repository", "full_name"), expected.repository),
        ("workflow", field(record, "path"), expected.workflow_path),
        ("event", field(record, "event"), SKIP_EVENT),
        ("head tree", field(record, "head_commit", "tree_id"), expected.head_tree),
        ("head repository", field(record, "head_repository", "id"), expected.head_repository_id),
        ("head branch", field(record, "head_branch"), expected.head_ref),
    ]
    for name, observed, wanted in checks:
        problem = mismatch(name, observed, wanted)
        if problem is not None:
            return problem
    return None


def job_list(pages: list) -> list | str:
    """The jobs of a paginated jobs lookup, or why they cannot be read."""

    jobs: list = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("jobs"), list):
            return "the jobs lookup returned a malformed page"
        jobs.extend(page["jobs"])
    return jobs


def job_problem(jobs: list, name: str, run_id: int, attempt: int | None) -> str | None:
    """The one job called ``name`` is the run's (and the attempt's) and concluded success."""

    found = [job for job in jobs if isinstance(job, dict) and job.get("name") == name]
    if len(found) != 1:
        return f"{len(found)} jobs are named {name!r}"
    job = found[0]
    checks: list[tuple[str, object, object]] = [("run", field(job, "run_id"), run_id)]
    if attempt is not None:
        checks.append(("attempt", field(job, "run_attempt"), attempt))
    checks += [("status", field(job, "status"), "completed"), ("conclusion", field(job, "conclusion"), "success")]
    for label, observed, wanted in checks:
        problem = mismatch(f"{name} {label}", observed, wanted)
        if problem is not None:
            return problem
    return None


def jobs_problem(pages: list, run_id: int, attempt: int, expected: Expected) -> str | None:
    """The attempt's gate job and save job both ran and concluded success.

    The run's own conclusion is not enough: a draft run, whose jobs are all
    skipped, concludes success, and a run cancelled after it saved concludes
    cancelled.
    """

    jobs = job_list(pages)
    if isinstance(jobs, str):
        return jobs
    for name in (expected.gate_job, expected.save_job):
        problem = job_problem(jobs, name, run_id, attempt)
        if problem is not None:
            return f"attempt {attempt}: {problem}"
    return None


def latest_gate_problem(pages: list, run_id: int, expected: Expected, attempt: int) -> str | None:
    """The gate job of the run's latest attempt (``jobs?filter=latest``) concluded success.

    A re-run that failed, or one still running, stops an earlier attempt's
    pass from counting. The gate must belong to ``attempt``, the latest
    attempt as the run listing numbers it: right after "Re-run all jobs"
    GitHub could still serve the previous attempt's jobs, and their green gate
    would stand in for a re-run that has not finished. A partial re-run lists
    the jobs it did not repeat under the new attempt (run 42923201068), so
    they match.
    """

    jobs = job_list(pages)
    if isinstance(jobs, str):
        return jobs
    problem = job_problem(jobs, expected.gate_job, run_id, attempt)
    return None if problem is None else f"latest attempt: {problem}"


def listed_attempt(run: object) -> int | None:
    """The latest attempt the run listing shows for ``run``, or None if it is not a positive integer."""

    attempt = field(run, "run_attempt")
    return attempt if type(attempt) is int and attempt >= 1 else None


def artifact_problem(pages: list, run_id: int, name: str) -> str | None:
    """The run holds exactly one unexpired artifact named for the key."""

    artifacts: list = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("artifacts"), list):
            return "the artifact lookup returned a malformed page"
        artifacts.extend(page["artifacts"])
    found = [item for item in artifacts if isinstance(item, dict) and item.get("name") == name]
    if len(found) != 1:
        return f"run {run_id} has {len(found)} proof artifacts for this marker"
    for label, observed, wanted in (
        ("proof expired", field(found[0], "expired"), False),
        ("proof run", field(found[0], "workflow_run", "id"), run_id),
    ):
        problem = mismatch(label, observed, wanted)
        if problem is not None:
            return problem
    return None


def marker_problem(
    key: str,
    prefix: str,
    expected: Expected,
    call: Callable[[str, bool], list],
    pull_runs: Callable[[], list],
) -> str | None:
    """Why the marker ``key`` cannot vouch for this tree, or None if GitHub confirms it."""

    named = parse_marker(prefix, key)
    if named is None:
        return f"the cache entry {safe(key)} is not a pass marker for this key"
    run_id, attempt = named
    if run_id == expected.current_run:
        return f"the marker was written by this run ({run_id})"
    base = f"repos/{expected.repository}/actions/runs/{run_id}"
    record = call(f"{base}/attempts/{attempt}", False)
    if len(record) != 1:
        return "the run attempt lookup returned more than one document"
    problem = run_attempt_problem(record[0], run_id, attempt, expected)
    if problem is None:
        problem = jobs_problem(call(f"{base}/attempts/{attempt}/jobs?per_page=100", True), run_id, attempt, expected)
    if problem is None:
        name = artifact_name(key)
        problem = artifact_problem(call(f"{base}/artifacts?name={name}&per_page=100", False), run_id, name)
    runs: list = []
    if problem is None:
        runs = pull_runs()
        problem = listed_vouching_problem(runs, run_id, attempt, expected)
    if problem is None:
        listed = next(run for run in runs if field(run, "id") == run_id)
        pages = call(f"{base}/jobs?filter=latest&per_page=100", True)
        # listed_vouching_problem checked that the listing numbers the attempt.
        problem = latest_gate_problem(pages, run_id, expected, listed_attempt(listed) or 0)
    if problem is None:
        problem = later_runs_problem(run_id, str(field(listed, "created_at")), expected, call, runs)
    return None if problem is None else f"run {run_id} attempt {attempt}: {problem}"


def listed_vouching_problem(runs: list, run_id: int, attempt: int, expected: Expected) -> str | None:
    """The vouching run is in this pull request's run listing once, with a creation time and an attempt number.

    The listing's creation time bounds rule 8, and its attempt number is the
    one the latest attempt's gate must belong to; it cannot be older than
    the attempt that saved.

    The run must also have been created after this pull request was, in a
    later second: a second binding of the run to this pull request,
    independent of the pull request listing. It refuses a run created before
    this pull request, as a run of an earlier pull request from the same head
    branch was. It binds by creation order, not by which pull request a run
    belongs to: a run of another pull request from the same branch created
    after this one is the listing's to refuse (and rule 6 refuses a deleted
    and restored head branch). No run of this repository's pull requests was
    created less than 3 seconds after its pull request, so the same second is
    refused too. Both times are as GitHub reports them; a run's creation time
    stayed the same through every re-run checked.
    """

    listed = [run for run in runs if field(run, "id") == run_id]
    if len(listed) != 1:
        return f"run {run_id} is not in this pull request's run listing"
    since = field(listed[0], "created_at")
    if not isinstance(since, str) or TIMESTAMP_RE.fullmatch(since) is None:
        return f"run {run_id} has no creation time"
    # Fails closed: without this pull request's creation time nothing passes.
    if not (expected.pr_created and since > expected.pr_created):
        return (
            f"run {run_id} was created at {since}, not after pull request #{expected.pr_number}"
            f" was ({expected.pr_created or 'unknown'})"
        )
    latest = listed_attempt(listed[0])
    if latest is None or latest < attempt:
        return f"run {run_id}'s latest attempt is listed as {safe(field(listed[0], 'run_attempt'))!r}"
    return None


def later_runs_problem(
    run_id: int, since: str, expected: Expected, call: Callable[[str, bool], list], runs: list
) -> str | None:
    """No run of this pull request since the vouching run was created failed, or is still unfinished.

    ``runs`` are this pull request's runs of the workflow, whatever their head
    tree, each as the listing shows its latest attempt. Every head tree
    counts: a run record does not show the merge tree its run tested, and a
    run of another head tree can test the same one (after "Update branch" the
    head tree is the merge tree; once the base holds part of the change,
    other head trees can merge to it too).

    A run counts as later when its run ID is higher than the vouching run's,
    its latest attempt started at or after the vouching run was created, or
    it has not finished. The vouching run's creation, as the listing shows it,
    is a bound no work of that run precedes, however it was re-run: GitHub
    lists the jobs a partial re-run did not repeat under the new attempt with
    their old times, and the attempt's own start is the time of the re-run.

    A later run that concluded success passed (or skipped on a marker, or ran
    nothing, as a draft does); any other conclusion counts only if the gate
    job of its latest attempt concluded success, because jobs outside the gate
    can fail a run without saying anything about the tree.
    """

    for run in runs:
        number = field(run, "id")
        if number in (run_id, expected.current_run):
            continue
        latest_started = field(run, "run_started_at")
        if not isinstance(latest_started, str) or TIMESTAMP_RE.fullmatch(latest_started) is None:
            return f"run {number} of this pull request has no start time"
        status, conclusion = field(run, "status"), field(run, "conclusion")
        if status == "completed" and number < run_id and latest_started < since:
            continue
        if status == "completed" and conclusion == "success":
            continue
        latest = listed_attempt(run)
        if latest is None:
            return f"run {number} of this pull request has no attempt number"
        pages = call(f"repos/{expected.repository}/actions/runs/{number}/jobs?filter=latest&per_page=100", True)
        problem = latest_gate_problem(pages, number, expected, latest)
        if problem is not None:
            return (
                f"run {number} of this pull request, later than this one, is {safe(status)}/{safe(conclusion)}"
                f" and did not pass ({problem})"
            )
    return None


def pull_request_runs(expected: Expected, call: Callable[[str, bool], list]) -> list:
    """This pull request's runs of the workflow, whatever their head tree.

    GET /repos/{repo}/actions/workflows/{file}/runs, filtered to the head
    branch and pull_request events, read page by page until an empty page.
    A run of the head branch from another repository (a fork with a branch of
    the same name) is not this pull request's; a listing that may be
    incomplete refuses.
    """

    query = urllib.parse.urlencode(
        {"branch": expected.head_ref, "event": SKIP_EVENT, "exclude_pull_requests": "true", "per_page": RUN_PAGE_SIZE}
    )
    path = f"repos/{expected.repository}/actions/workflows/{workflow_id(expected.workflow_path)}/runs?{query}"
    listed: dict[int, dict] = {}
    total = None
    page = 1
    while True:
        documents = call(f"{path}&page={page}", False)
        items = field(documents[0], "workflow_runs") if len(documents) == 1 else None
        count = field(documents[0], "total_count") if len(documents) == 1 else None
        if not isinstance(items, list) or len(items) > RUN_PAGE_SIZE or type(count) is not int:
            raise MarkerError("the run listing returned a malformed page")
        total = count if total is None else total
        if not items:
            break
        for item in items:
            number = field(item, "id")
            if type(number) is not int:
                raise MarkerError("the run listing returned a run without an ID")
            listed.setdefault(number, item)
        page += 1
    if total >= RUN_LISTING_LIMIT or len(listed) < total:
        raise MarkerError(f"the run listing may be incomplete ({len(listed)} of {total} runs read)")
    return [
        run
        for run in listed.values()
        if all(
            mismatch(name, field(run, *keys), wanted) is None
            for name, keys, wanted in (
                ("event", ("event",), SKIP_EVENT),
                ("workflow", ("path",), expected.workflow_path),
                ("head branch", ("head_branch",), expected.head_ref),
                ("head repository", ("head_repository", "id"), expected.head_repository_id),
            )
        )
    ]


def pull_request_problem(expected: Expected, call: Callable[[str, bool], list]) -> tuple[str | None, str]:
    """This pull request is the only one ever opened from its head branch, and its base never changed.

    Returns the problem, or None and this pull request's creation time as the
    listing shows it, which every vouching run must not predate.

    A pull request run takes its workflow files from the merge of the head into
    the base, and nothing in the run decides which base that is. A run of
    another pull request from the same head branch, or of this one while it
    targeted another branch, may have run workflow files nobody reviewed, and
    such a run can upload any artifact and report any job green. Only a run
    of this pull request whose base has no recorded event is trusted.

    One listing request of two entries is enough: anything but exactly one
    pull request refuses.
    """

    head = f"{expected.head_owner}:{expected.head_ref}"
    query = urllib.parse.urlencode({"head": head, "state": "all", "per_page": 2})
    listing = call(f"repos/{expected.repository}/pulls?{query}", False)
    if len(listing) != 1 or not isinstance(listing[0], list):
        return "the pull request listing returned a malformed page", ""
    pulls = listing[0]
    if len(pulls) != 1:
        numbers = [field(pull, "number") for pull in pulls]
        return f"head branch {safe(head)} has {len(pulls)} pull requests {safe(numbers)}, not only this one", ""
    for label, observed, wanted in (
        ("listed pull request", field(pulls[0], "number"), expected.pr_number),
        ("listed head branch", field(pulls[0], "head", "ref"), expected.head_ref),
        ("listed head repository", field(pulls[0], "head", "repo", "id"), expected.head_repository_id),
    ):
        problem = mismatch(label, observed, wanted)
        if problem is not None:
            return problem, ""
    created = field(pulls[0], "created_at")
    if not isinstance(created, str) or TIMESTAMP_RE.fullmatch(created) is None:
        return f"pull request #{expected.pr_number} has no creation time ({safe(created)!r})", ""
    for listing_name in ("timeline", "events"):
        path = f"repos/{expected.repository}/issues/{expected.pr_number}/{listing_name}"
        for item in every_page(path, listing_name, call):
            event = field(item, "event")
            if not isinstance(event, str):
                return f"the {listing_name} returned an event without a type", ""
            if BASE_EVENT_RE.match(event):
                return f"pull request #{expected.pr_number} has a base event ({safe(event)}) in its {listing_name}", ""
            if event in HEAD_BRANCH_EVENTS:
                return (
                    f"pull request #{expected.pr_number} has a head branch event ({event}) in its {listing_name}",
                    "",
                )
    return None, created


def every_page(path: str, name: str, call: Callable[[str, bool], list]) -> list:
    """Every item of a paged listing, read until a page comes back empty.

    The decision's shared deadline bounds the number of pages.
    """

    items: list = []
    page = 1
    while True:
        documents = call(f"{path}?per_page={EVENT_PAGE_SIZE}&page={page}", False)
        if len(documents) != 1 or not isinstance(documents[0], list) or len(documents[0]) > EVENT_PAGE_SIZE:
            raise MarkerError(f"the {name} returned a malformed page")
        if not documents[0]:
            return items
        items.extend(documents[0])
        page += 1


def listed_markers(prefix: str, expected: Expected, call: Callable[[str, bool], list]) -> list[str]:
    """This pull request's markers of ``prefix``, newest first."""

    ref = f"refs/pull/{expected.pr_number}/merge"
    query = urllib.parse.urlencode(
        {"key": prefix, "ref": ref, "sort": "created_at", "direction": "desc", "per_page": MAX_CANDIDATES}
    )
    pages = call(f"repos/{expected.repository}/actions/caches?{query}", False)
    keys = []
    for page in pages:
        caches = field(page, "actions_caches")
        if not isinstance(caches, list):
            raise MarkerError("the cache listing returned a malformed page")
        for entry in caches:
            key = field(entry, "key")
            if field(entry, "ref") == ref and isinstance(key, str) and key.startswith(prefix):
                keys.append(key)
    return keys


def decide(
    *,
    event: str | None,
    labels_json: str | None,
    profile: str | None,
    key_outcome: str | None,
    prefix: str | None,
    head_tree: str | None,
    workflow_path: str | None,
    lookup_outcome: str | None,
    matched_key: str | None,
    run_id: str | None,
    run_attempt: str | None,
    repository: str | None,
    head_repository_id: str | None,
    head_ref: str | None,
    head_owner: str | None,
    pr_number: str | None,
    gate_job: str | None,
    save_job: str | None,
    api: Api = gh_api,
    budget: float = DECIDE_BUDGET_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> Decision:
    """Whether to skip; every rule that does not hold runs everything."""

    def run(reason: str) -> Decision:
        return Decision(False, reason)

    if event != SKIP_EVENT:
        return run(f"a {safe(event)} event always runs in full")
    try:
        labels = parse_labels(labels_json)
    except MarkerError as error:
        return run(str(error))
    if FORCE_FULL_RUN_LABEL in labels:
        return run(f"the {FORCE_FULL_RUN_LABEL} label forces a full run")
    if profile != SKIP_PROFILE:
        return run(f"validation profile {safe(profile)} is never skipped")
    # "Re-run all jobs", or a re-run of this job, asks for the work to be done
    # again: it is never answered from a marker.
    if run_attempt is None or NUMBER_RE.fullmatch(run_attempt) is None:
        return run(f"the run attempt is missing or malformed: {safe(run_attempt)!r}")
    if run_attempt != "1":
        return run(f"attempt {run_attempt} is a re-run, which always runs in full")
    if key_outcome != "success" or prefix is None or PREFIX_RE.fullmatch(prefix) is None:
        return run(f"the marker key could not be computed (step {safe(key_outcome)})")
    if lookup_outcome != "success":
        return run(f"the marker lookup did not succeed (step {safe(lookup_outcome)})")
    if not matched_key:
        return run("no pass marker for this tree")
    try:
        if not head_ref or len(head_ref) > 255 or any(ord(char) < 0x20 or char == "\x7f" for char in head_ref):
            raise MarkerError("head branch is missing or malformed")
        for name, value in (("gate job", gate_job), ("save job", save_job)):
            require(JOB_NAME_RE, value, name)
        expected = Expected(
            repository=require(REPOSITORY_RE, repository, "repository"),
            workflow_path=require(WORKFLOW_PATH_RE, workflow_path, "workflow path"),
            head_tree=require(SHA_RE, head_tree, "head tree"),
            head_repository_id=int(require(NUMBER_RE, head_repository_id, "head repository ID")),
            head_ref=head_ref,
            gate_job=str(gate_job),
            save_job=str(save_job),
            current_run=int(require(NUMBER_RE, run_id, "run ID")),
            pr_number=int(require(NUMBER_RE, pr_number, "pull request number")),
            head_owner=require(LOGIN_RE, head_owner, "head owner"),
        )
    except MarkerError as error:
        return run(str(error))

    # One deadline for every API call this decision makes.
    deadline = clock() + budget

    def call(path: str, paginate: bool) -> list:
        remaining = deadline - clock()
        if remaining <= 0:
            raise MarkerError("the time for GitHub's API ran out")
        return api(path, paginate, min(API_TIMEOUT_SECONDS, remaining))

    try:
        problem, created = pull_request_problem(expected, call)
    except MarkerError as error:
        problem, created = str(error), ""
    if problem is not None:
        return run(problem)
    expected = replace(expected, pr_created=created)

    # The lookup returns the newest entry of the prefix. One that fails, such
    # as a marker of a run cancelled while it saved, must not hide an older
    # valid one, so this pull request's other markers are checked too.
    candidates = [matched_key]
    problems = []
    try:
        for key in listed_markers(prefix, expected, call):
            if len(candidates) >= MAX_CANDIDATES:
                break
            if key not in candidates:
                candidates.append(key)
    except MarkerError as error:
        problems.append(f"listing: {error}")

    # This pull request's runs, read once for every candidate. Only a listing
    # that succeeded is remembered: after a failure, the next candidate reads
    # it again, within the shared budget.
    listing: list[list] = []

    def pull_runs() -> list:
        if not listing:
            listing.append(pull_request_runs(expected, call))
        return listing[0]

    for key in candidates:
        try:
            problem = marker_problem(key, prefix, expected, call, pull_runs)
        except MarkerError as error:
            problem = str(error)
        if problem is None:
            writer, attempt = parse_marker(prefix, key) or (0, 0)
            return Decision(True, f"run {writer} attempt {attempt} already passed this tree with the same routing")
        problems.append(problem)
    return run("no confirmed pass marker: " + "; ".join(problems))


# -- save-plan ----------------------------------------------------------------


@dataclass(frozen=True)
class SavePlan:
    decision: Decision
    key: str = ""
    artifact: str = ""


def plan_save(
    *,
    event: str | None,
    needs_json: str | None,
    classify_job: str,
    run_id: str | None,
    run_attempt: str | None,
    sha: str | None,
    pr_number: str | None,
    optional_jobs: dict[str, str] | None = None,
    check_merge_ref: bool = False,
    cwd: Path | None = None,
) -> SavePlan:
    """Whether this run may save its marker, and the key and proof to save."""

    def no(reason: str) -> SavePlan:
        return SavePlan(Decision(False, reason))

    if event != SKIP_EVENT:
        return no(f"a {safe(event)} event never saves a marker")
    try:
        needs = json.loads(needs_json or "")
    except ValueError:
        return no("the job results are not JSON")
    if not isinstance(needs, dict) or not isinstance(needs.get(classify_job), dict):
        return no(f"the job results do not include {classify_job}")
    outputs = needs[classify_job].get("outputs")
    if not isinstance(outputs, dict):
        return no(f"{classify_job} has no outputs")
    optional_jobs = optional_jobs or {}

    def acceptable(name: str, job: object) -> bool:
        result = job.get("result") if isinstance(job, dict) else None
        if result == "success":
            return True
        # A job its routing does not run, such as the mainnet posture check
        # for a pull request into a testnet line: skipped only when the
        # classifier said so.
        output = optional_jobs.get(name)
        return result == "skipped" and output is not None and outputs.get(output) == "false"

    # Every job the marker stands for ran and succeeded: a skipped, failed or
    # cancelled job, or one whose result cannot be read, saves nothing.
    unsuccessful = [
        f"{safe(name)}={safe(job.get('result') if isinstance(job, dict) else job)}"
        for name, job in sorted(needs.items())
        if not acceptable(name, job)
    ]
    if unsuccessful:
        return no("not every job succeeded: " + ", ".join(unsuccessful))
    skipped = outputs.get("tree_pass_skip")
    if skipped != "false":
        return no(f"this run's own skip decision was {safe(skipped)!r}, not 'false'")
    prefix = outputs.get("tree_pass_key_prefix")
    if not isinstance(prefix, str) or (keyed := PREFIX_RE.fullmatch(prefix)) is None:
        return no("this run has no marker key")
    try:
        current = int(require(NUMBER_RE, run_id, "run ID"))
        attempt = int(require(NUMBER_RE, run_attempt, "run attempt"))
        number = require(NUMBER_RE, pr_number, "pull request number")
        sha = require(SHA_RE, sha, "commit under test")
        tree = checked_out_tree(sha, cwd)
        merge_tree = None
        if check_merge_ref:
            # Full Validation's jobs check out the pull request's merge ref when
            # they start, not the event's commit: they tested the keyed tree
            # only if that ref still has it now, at the end of the run.
            git("fetch", "--quiet", "--no-tags", "--depth=1", "origin", f"refs/pull/{number}/merge", cwd=cwd)
            merge_tree = git("rev-parse", "--verify", "FETCH_HEAD^{tree}", cwd=cwd)
    except MarkerError as error:
        return no(str(error))
    if tree != keyed.group("tree"):
        return no(f"the commit under test has tree {tree}, not the keyed tree {keyed.group('tree')}")
    if merge_tree is not None and merge_tree != tree:
        return no(f"the pull request merge ref moved to tree {safe(merge_tree)} during the run")
    key = marker_key(prefix, current, attempt)
    return SavePlan(Decision(True, f"every job passed tree {tree}"), key, artifact_name(key))


def parse_optional_jobs(values: list[str]) -> dict[str, str]:
    jobs = {}
    for value in values:
        match = JOB_OUTPUT_RE.fullmatch(value)
        if match is None:
            raise MarkerError(f"--optional-job must be <job>=<classify output>, not {safe(value)!r}")
        jobs[match.group("job")] = match.group("output")
    return jobs


# -- command line -------------------------------------------------------------


def write_outputs(path: str, values: dict[str, str]) -> None:
    for name, value in values.items():
        if "\n" in value or "\r" in value:
            raise MarkerError(f"output {name} spans lines")
    with open(path, "a", encoding="utf8") as handle:
        for name, value in values.items():
            handle.write(f"{name}={value}\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    key = commands.add_parser("key", help="compute the marker key prefix for the commit under test")
    key.add_argument("--workflow-ref", required=True)
    key.add_argument("--repository", required=True)
    key.add_argument("--salt", required=True)
    key.add_argument("--event", required=True)
    key.add_argument("--sha", required=True)
    key.add_argument("--head-sha", required=True)
    key.add_argument("--base-ref", required=True)
    key.add_argument("--changed-files", required=True, type=Path)
    key.add_argument("--github-output", required=True)

    decide_parser = commands.add_parser("decide", help="decide whether this tree already passed")
    for name in (
        "event",
        "labels-json",
        "profile",
        "key-outcome",
        "key-prefix",
        "head-tree",
        "workflow-path",
        "lookup-outcome",
        "matched-key",
        "run-id",
        "run-attempt",
        "repository",
        "head-repository-id",
        "head-ref",
        "head-owner",
        "pr-number",
        "gate-job",
        "save-job",
        "github-output",
    ):
        decide_parser.add_argument(f"--{name}", required=True)

    save = commands.add_parser("save-plan", help="decide whether this run saves its marker")
    for name in ("event", "needs-json", "classify-job", "run-id", "run-attempt", "sha", "pr-number", "github-output"):
        save.add_argument(f"--{name}", required=True)
    save.add_argument("--marker-dir", required=True, type=Path)
    save.add_argument("--optional-job", action="append", default=[], help="<job>=<classify output>: the job may be skipped when that output is 'false'")
    save.add_argument("--check-merge-ref", action="store_true", help="also require the pull request merge ref to have the keyed tree")
    return parser.parse_args(argv)


def main(argv: list[str], api: Api = gh_api) -> int:
    args = parse_args(argv)
    try:
        if args.command == "key":
            if args.event != SKIP_EVENT:
                print(f"A {safe(args.event)} event never looks up a pass marker.")
                write_outputs(args.github_output, {"key_prefix": ""})
                return 0
            marker = compute_key(
                workflow_ref=args.workflow_ref,
                repository=args.repository,
                salt=args.salt,
                sha=args.sha,
                head_sha=args.head_sha,
                base_ref=args.base_ref,
                changed_files=args.changed_files,
            )
            print(f"Pass marker key prefix: {marker.prefix}")
            write_outputs(
                args.github_output,
                {"key_prefix": marker.prefix, "head_tree": marker.head_tree, "workflow_path": marker.workflow_path},
            )
            return 0

        if args.command == "decide":
            decision = decide(
                event=args.event,
                labels_json=args.labels_json,
                profile=args.profile,
                key_outcome=args.key_outcome,
                prefix=args.key_prefix,
                head_tree=args.head_tree,
                workflow_path=args.workflow_path,
                lookup_outcome=args.lookup_outcome,
                matched_key=args.matched_key,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                repository=args.repository,
                head_repository_id=args.head_repository_id,
                head_ref=args.head_ref,
                head_owner=args.head_owner,
                pr_number=args.pr_number,
                gate_job=args.gate_job,
                save_job=args.save_job,
                api=api,
            )
            verdict = "skipping the expensive jobs" if decision.act else "running everything"
            print(f"::notice title=Tree pass marker::{verdict}: {safe(decision.reason, 300)}")
            write_outputs(
                args.github_output,
                {"reason": safe(decision.reason, 300), "skip": "true" if decision.act else "false"},
            )
            return 0

        plan = plan_save(
            event=args.event,
            needs_json=args.needs_json,
            classify_job=args.classify_job,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            sha=args.sha,
            pr_number=args.pr_number,
            optional_jobs=parse_optional_jobs(args.optional_job),
            check_merge_ref=args.check_merge_ref,
        )
        if plan.decision.act:
            args.marker_dir.mkdir(parents=True, exist_ok=True)
            record = {"key": plan.key, "artifact": plan.artifact, "reason": plan.decision.reason}
            (args.marker_dir / MARKER_FILE).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf8")
            print(f"Saving pass marker {plan.key} with proof {plan.artifact}: {plan.decision.reason}")
        else:
            print(f"Not saving a pass marker: {safe(plan.decision.reason, 300)}")
        write_outputs(
            args.github_output,
            {
                "reason": safe(plan.decision.reason, 300),
                "key": plan.key,
                "artifact": plan.artifact,
                "save": "true" if plan.decision.act else "false",
            },
        )
        return 0
    except (MarkerError, OSError) as error:
        print(f"::warning title=Tree pass marker::{safe(error, 300)}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
