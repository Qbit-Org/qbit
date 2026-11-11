#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Tests for the same-tree skip of Full Validation and Core Checks.

``ci/checks/tree_pass_marker.py`` decides; the workflows only wire it up.
These tests prove the decision table on the script itself, then run the real
workflow steps, lifted out of ``ci.yml`` and ``core-checks.yml``, against a
scratch repository holding GitHub-style pull request merge commits:

* the same tree skips, and still gets a successful gate check;
* a different tree, a moved base, another routing, the force label, every
  event but a pull request, and every failure of the lookup run everything;
* a marker is saved only by a pull request run that did all the work and
  passed, never by one that was skipped, failed or cancelled;
* a marker that names a run GitHub does not confirm, as an earlier push with
  a changed workflow could write, is not trusted.

GitHub itself is simulated: the cache action (lookup, prefix match, save),
the run lookup through ``gh`` and the ``needs``/``steps`` contexts. Whether
GitHub's services behave as modelled cannot be proved here; see
doc/development/ci-same-tree-skip.md for the validation plan on GitHub.
"""

from __future__ import annotations

import inspect
import json
import math
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))

import tree_pass_marker as marker  # noqa: E402  sibling module, path-dependent
from test_classifier_ci_contract import (  # noqa: E402  sibling module, path-dependent
    REPO_ROOT,
    WorkflowLoader,
    run_bash_step,
)

REPOSITORY = "example/qbit"
REPOSITORY_ID = 4242
HEAD_OWNER = "example"
PR = 7
BASE_BRANCH = "1.x.x"
HEAD_BRANCH = "topic"
CLASSIFY_JOB = "classify-changes"
SAVE_JOB = "save-pass-marker"
# The Core Checks job that runs this suite.
CONTRACT_JOB = "same-tree-skip-contract"
CACHE_PIN = "0057852bfaa89a56745cba8c7296529d2fc39830"

SAVE_JOB_NAME = "save pass marker"
# The lints that read history rather than the tree, which lint commit range
# runs even when the tree already passed.
HISTORY_LINTS = ("commit_msg", "scripted_diff", "subtree")
UPLOAD_PIN = "ea165f8d65b6e75b540449e92b4886f43607fa02"

# Each workflow the marker skips: its gate job, which Required Merge Gate
# polls by name; the jobs outside that gate, which the marker neither skips
# nor stands for ("unmarked"); the gate's inputs it never skips ("always");
# whether its jobs test the merge ref rather than the event's commit; and the
# jobs its routing may legitimately skip, with the classifier output that says
# so ("optional").
SKIPPING_WORKFLOWS = {
    ".github/workflows/ci.yml": {
        "gate": "full-validation-gate",
        "gate_name": "Full Validation Gate",
        "unmarked": {"test-each-commit", "macos-native-arm64"},
        "always": {"lint-commit-range"},
        "merge_ref": True,
        "optional": {},
    },
    ".github/workflows/core-checks.yml": {
        "gate": "core-checks-gate",
        "gate_name": "Core Checks Gate",
        "unmarked": set(),
        "always": {"same-tree-skip-contract"},
        "merge_ref": False,
        "optional": {"mainnet-publish-gate": "mainnet_publish_gate_required"},
    },
}


def marked_jobs(path: str) -> set[str]:
    """The jobs of ``path`` that the marker skips."""
    config = SKIPPING_WORKFLOWS[path]
    jobs = load(path)["jobs"]
    return set(jobs) - {CLASSIFY_JOB, config["gate"], SAVE_JOB} - config["unmarked"] - config["always"]
GATE_WORKFLOW = ".github/workflows/required-merge-gate.yml"
NEVER_SKIPPING_WORKFLOWS = (
    ".github/workflows/ci-nightly-heavy.yml",
    ".github/workflows/ibd-perf-manual.yml",
    ".github/workflows/rpc-perf-manual.yml",
    ".github/workflows/key-policy-gate.yml",
    ".github/workflows/lint-image-prewarm.yml",
    ".github/workflows/rpc-docs-pages.yml",
)
MARKER_STEPS = ("marker-key", "marker-lookup", "marker-decision")
NON_PULL_REQUEST_EVENTS = ("push", "merge_group", "workflow_dispatch", "schedule")

# Nothing from the developer's or runner's git configuration applies, and
# nothing in the scratch repositories is ever signed.
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "tree pass test",
    "GIT_AUTHOR_EMAIL": "tree-pass@example.invalid",
    "GIT_COMMITTER_NAME": "tree pass test",
    "GIT_COMMITTER_EMAIL": "tree-pass@example.invalid",
    "GIT_AUTHOR_DATE": "2026-11-10T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-11-10T00:00:00Z",
}


def load(relative: str) -> dict:
    return yaml.load((REPO_ROOT / relative).read_text(encoding="utf8"), Loader=WorkflowLoader)


# ---------------------------------------------------------------------------
# GitHub expressions: the subset the workflows use, with GitHub's semantics
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"\s*(?:"
    r"(?P<string>'(?:[^']|'')*')"
    r"|(?P<number>\d+(?:\.\d+)?)"
    r"|(?P<op>==|!=|&&|\|\||!|\(|\)|,)"
    r"|(?P<path>[A-Za-z_][A-Za-z0-9_-]*(?:\.(?:[A-Za-z_][A-Za-z0-9_-]*|\*))*)"
    r")"
)
_WHOLE = re.compile(r"^\s*\$\{\{(.*)\}\}\s*$", re.DOTALL)
_EMBEDDED = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
STATUS_FUNCTION = re.compile(r"\b(?:success|failure|cancelled|always)\s*\(")


def truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


def to_number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return 0.0
        try:
            return float(text)
        except ValueError:
            return math.nan
    return math.nan


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value)


def equal(left: Any, right: Any) -> bool:
    """GitHub's loose equality: strings ignore case, mixed types compare as numbers."""
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if type(left) is type(right) and not isinstance(left, (dict, list)):
        return left == right
    return to_number(left) == to_number(right)


class Expression:
    def __init__(self, text: str, context: dict, status: dict[str, bool] | None = None) -> None:
        self.tokens: list[tuple[str, str]] = []
        position = 0
        while position < len(text):
            if text[position].isspace():
                position += 1
                continue
            match = _TOKEN.match(text, position)
            if match is None or match.end() == position:
                raise ValueError(f"unsupported expression syntax near {text[position:]!r}")
            kind = match.lastgroup
            assert kind is not None
            self.tokens.append((kind, match.group(kind)))
            position = match.end()
        self.position = 0
        self.context = context
        self.status = status or {"success": True, "failure": False, "cancelled": False}

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self, expected: str | None = None) -> tuple[str, str]:
        token = self.peek()
        if token is None or (expected is not None and token[1] != expected):
            raise ValueError(f"expected {expected!r}, found {token!r}")
        self.position += 1
        return token

    def evaluate(self) -> Any:
        value = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"trailing tokens {self.tokens[self.position:]!r}")
        return value

    def parse_or(self) -> Any:
        value = self.parse_and()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.parse_and()
            value = value if truthy(value) else right
        return value

    def parse_and(self) -> Any:
        value = self.parse_equality()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.parse_equality()
            value = right if truthy(value) else value
        return value

    def parse_equality(self) -> Any:
        value = self.parse_unary()
        while self.peek() in (("op", "=="), ("op", "!=")):
            operator = self.take()[1]
            same = equal(value, self.parse_unary())
            value = same if operator == "==" else not same
        return value

    def parse_unary(self) -> Any:
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        kind, text = self.take()
        if (kind, text) == ("op", "("):
            value = self.parse_or()
            self.take(")")
            return value
        if kind == "string":
            return text[1:-1].replace("''", "'")
        if kind == "number":
            return float(text)
        if kind != "path":
            raise ValueError(f"unexpected token {text!r}")
        if self.peek() == ("op", "("):
            self.take()
            arguments = []
            while self.peek() != ("op", ")"):
                arguments.append(self.parse_or())
                if self.peek() == ("op", ","):
                    self.take()
            self.take(")")
            return self.call(text, arguments)
        if text in ("true", "false"):
            return text == "true"
        if text == "null":
            return None
        return self.lookup(self.context, text.split("."))

    def lookup(self, value: Any, parts: list[str]) -> Any:
        if not parts:
            return value
        head, rest = parts[0], parts[1:]
        if head == "*":
            items = value if isinstance(value, list) else list(value.values()) if isinstance(value, dict) else []
            found = [self.lookup(item, rest) for item in items]
            return [item for item in found if item is not None]
        if isinstance(value, dict):
            for key, item in value.items():
                if key.casefold() == head.casefold():
                    return self.lookup(item, rest)
        return None

    def call(self, name: str, arguments: list[Any]) -> Any:
        lowered = name.casefold()
        if lowered in ("success", "failure", "cancelled"):
            return self.status[lowered]
        if lowered == "always":
            return True
        if lowered == "contains":
            haystack, needle = arguments
            if isinstance(haystack, list):
                return any(equal(item, needle) for item in haystack)
            return to_text(needle).casefold() in to_text(haystack).casefold()
        if lowered == "tojson":
            return json.dumps(arguments[0], indent=2)
        if lowered == "fromjson":
            return json.loads(arguments[0])
        raise ValueError(f"unsupported function {name}")


def evaluate(text: str, context: dict, status: dict[str, bool] | None = None) -> Any:
    whole = _WHOLE.fullmatch(text)
    return Expression(whole.group(1) if whole else text, context, status).evaluate()


def render(value: Any, context: dict) -> str:
    """A workflow value as the runner passes it on: expressions evaluated, then text."""
    if not isinstance(value, str):
        return to_text(value)
    whole = _WHOLE.fullmatch(value)
    if whole is not None:
        return to_text(evaluate(whole.group(1), context))
    return _EMBEDDED.sub(lambda match: to_text(evaluate(match.group(1), context)), value)


def condition(text: Any, context: dict, status: dict[str, bool]) -> bool:
    """A job or step ``if``: without a status function, GitHub adds ``success() &&``."""
    if text is None:
        text = "success()"
    text = str(text)
    whole = _WHOLE.fullmatch(text)
    body = whole.group(1) if whole else text
    if not STATUS_FUNCTION.search(body):
        body = f"success() && ({body})"
    return truthy(evaluate(body, context, status))


def job_status(job: dict, results: dict[str, str]) -> dict[str, bool]:
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    return {
        "success": all(results.get(name) == "success" for name in needs),
        "failure": any(results.get(name) == "failure" for name in needs),
        "cancelled": False,
    }


# ---------------------------------------------------------------------------
# Scratch repository: GitHub-style pull request merge commits
# ---------------------------------------------------------------------------


class Repository:
    """An origin and a checkout holding a base, heads, and their test merges.

    * ``base``: the target branch; ``moved_base`` is a later base commit.
    * ``head``: the pull request head; ``amended`` is a different commit with
      the same tree, as ``squash-sign apply`` makes; ``changed`` changes it.
    * ``merge``/``amended_merge``/``changed_merge``/``moved_merge``: the merge
      of each head into the base, as GitHub tests a pull request.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.origin = root / "origin.git"
        self.work = root / "work"
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(root),
            "TMPDIR": os.environ.get("TMPDIR", tempfile.gettempdir()),
            **GIT_ENV,
        }
        self.git(root, "init", "--quiet", "--bare", str(self.origin))
        self.git(root, "init", "--quiet", str(self.work))
        self.git(self.work, "remote", "add", "origin", str(self.origin))
        # The workflow steps run the script from the checkout, as on GitHub.
        script = (CHECKS_DIR / "tree_pass_marker.py").read_text(encoding="utf8")
        base_files = {"src/a.cpp": "int a = 1;\n", "doc/notes.md": "notes 1\n", "ci/checks/tree_pass_marker.py": script}
        head_files = {**base_files, "src/a.cpp": "int a = 2;\n"}
        self.base = self.commit(base_files, [], "base")
        self.moved_base = self.commit({**base_files, "doc/notes.md": "notes 2\n"}, [self.base], "base moves")
        self.head = self.commit(head_files, [self.base], "change a")
        self.amended = self.commit(head_files, [self.base], "change a, squashed and signed")
        self.changed = self.commit({**base_files, "src/a.cpp": "int a = 3;\n"}, [self.base], "change a again")
        self.merge = self.commit(head_files, [self.base, self.head], "merge head")
        self.amended_merge = self.commit(head_files, [self.base, self.amended], "merge amended head")
        self.changed_merge = self.commit(
            {**base_files, "src/a.cpp": "int a = 3;\n"}, [self.base, self.changed], "merge changed head"
        )
        self.moved_merge = self.commit(
            {**head_files, "doc/notes.md": "notes 2\n"}, [self.moved_base, self.head], "merge head into moved base"
        )
        self.refs = {}
        for name, sha in (("base", self.base), ("moved", self.moved_base), ("head", self.head),
                          ("amended", self.amended), ("changed", self.changed), ("merge", self.merge),
                          ("amended-merge", self.amended_merge), ("changed-merge", self.changed_merge),
                          ("moved-merge", self.moved_merge)):
            self.git(self.work, "update-ref", f"refs/heads/{name}", sha)
            self.refs[sha] = f"refs/heads/{name}"
        self.git(self.work, "push", "--quiet", "origin", "refs/heads/*:refs/heads/*")
        self.checkouts = 0
        self.changed_files = root / "changed-files.txt"
        self.changed_files.write_text("src/a.cpp\n", encoding="utf8")

    def git(self, cwd: Path, *args: str, stdin: str | None = None) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=cwd, env=self.env, input=stdin, text=True, capture_output=True, check=False
        )
        if completed.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed: {completed.stderr}")
        return completed.stdout.strip()

    def tree_of(self, files: dict[str, str]) -> str:
        directories: dict[str, dict[str, str]] = {}
        blobs: dict[str, str] = {}
        for path, content in files.items():
            if "/" in path:
                top, rest = path.split("/", 1)
                directories.setdefault(top, {})[rest] = content
            else:
                blobs[path] = self.git(self.work, "hash-object", "-w", "--stdin", stdin=content)
        entries = [f"100644 blob {sha}\t{name}" for name, sha in blobs.items()]
        entries += [f"040000 tree {self.tree_of(sub)}\t{name}" for name, sub in directories.items()]
        return self.git(self.work, "mktree", stdin="\n".join(sorted(entries, key=lambda e: e.split("\t")[1])) + "\n")

    def commit(self, files: dict[str, str], parents: list[str], message: str) -> str:
        args = ["commit-tree", "--no-gpg-sign", self.tree_of(files), "-m", message]
        for parent in parents:
            args += ["-p", parent]
        return self.git(self.work, *args)

    def tree(self, rev: str) -> str:
        return self.git(self.work, "rev-parse", f"{rev}^{{tree}}")

    def check_out(self, sha: str) -> None:
        self.git(self.work, "checkout", "--quiet", "--force", "--detach", sha)

    def fresh_checkout(self, sha: str) -> Path:
        """A new depth-1 checkout of ``sha``, as actions/checkout makes in the save job."""
        self.checkouts += 1
        directory = self.root / f"checkout-{self.checkouts}"
        self.git(self.root, "init", "--quiet", str(directory))
        self.git(directory, "remote", "add", "origin", str(self.origin))
        self.git(directory, "fetch", "--quiet", "--depth=1", "origin", self.refs[sha])
        self.git(directory, "checkout", "--quiet", "--detach", "FETCH_HEAD")
        return directory

    def publish_merge_ref(self, sha: str, pr: int = PR) -> None:
        """Point the origin's ``refs/pull/<pr>/merge`` at ``sha``, as GitHub does."""
        self.git(self.work, "push", "--quiet", "--force", "origin", f"{sha}:refs/pull/{pr}/merge")


class RepositoryTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="tree-pass-")
        cls.repo = Repository(Path(cls._tmp.name))
        # In-process calls run git too; keep them off the developer's config.
        cls._env = mock.patch.dict(os.environ, GIT_ENV)
        cls._env.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._env.stop()
        cls._tmp.cleanup()

    def key_for(self, merge: str, head: str, **overrides: Any) -> marker.MarkerKey:
        self.repo.check_out(merge)
        arguments = {
            "workflow_ref": f"{REPOSITORY}/.github/workflows/ci.yml@refs/pull/{PR}/merge",
            "repository": REPOSITORY,
            "salt": "1",
            "sha": merge,
            "head_sha": head,
            "base_ref": BASE_BRANCH,
            "changed_files": self.repo.changed_files,
            "cwd": self.repo.work,
        }
        arguments.update(overrides)
        return marker.compute_key(**arguments)


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------


class KeyTest(RepositoryTestCase):
    def test_the_same_tree_under_another_commit_has_the_same_key(self) -> None:
        repo = self.repo
        self.assertNotEqual(repo.merge, repo.amended_merge)
        self.assertEqual(repo.tree(repo.merge), repo.tree(repo.amended_merge))
        first = self.key_for(repo.merge, repo.head)
        second = self.key_for(repo.amended_merge, repo.amended)
        self.assertEqual(first.prefix, second.prefix)
        self.assertEqual(first.head_tree, second.head_tree)

    def test_the_key_names_the_tree_under_test_and_never_a_commit(self) -> None:
        key = self.key_for(self.repo.merge, self.repo.head)
        self.assertEqual(marker.PREFIX_RE.fullmatch(key.prefix).group("tree"), self.repo.tree(self.repo.merge))
        for commit in (self.repo.merge, self.repo.head, self.repo.base):
            self.assertNotIn(commit, key.prefix)

    def test_a_different_tree_or_a_moved_base_has_another_key(self) -> None:
        repo = self.repo
        reference = self.key_for(repo.merge, repo.head).prefix
        self.assertNotEqual(self.key_for(repo.changed_merge, repo.changed).prefix, reference)
        self.assertNotEqual(self.key_for(repo.moved_merge, repo.head).prefix, reference)

    def test_routing_workflow_and_salt_are_part_of_the_key(self) -> None:
        repo = self.repo
        reference = self.key_for(repo.merge, repo.head).prefix
        other_list = repo.root / "other-changed-files.txt"
        other_list.write_text("src/a.cpp\ndoc/notes.md\n", encoding="utf8")
        variants = {
            "changed-file list": {"changed_files": other_list},
            "target branch": {"base_ref": "main"},
            "workflow": {"workflow_ref": f"{REPOSITORY}/.github/workflows/core-checks.yml@refs/pull/{PR}/merge"},
            "salt": {"salt": "2"},
        }
        for name, overrides in variants.items():
            with self.subTest(name):
                self.assertNotEqual(self.key_for(repo.merge, repo.head, **overrides).prefix, reference)

    def test_the_checkout_must_be_the_pull_request_merge_under_test(self) -> None:
        repo = self.repo
        cases = {
            "checkout is another commit": dict(merge=repo.merge, head=repo.head, sha=repo.amended_merge),
            "head is not a parent": dict(merge=repo.merge, head=repo.changed),
            "commit is not a merge": dict(merge=repo.head, head=repo.base),
        }
        for name, case in cases.items():
            with self.subTest(name):
                overrides = {"sha": case["sha"]} if "sha" in case else {}
                with self.assertRaises(marker.MarkerError):
                    self.key_for(case["merge"], case["head"], **overrides)

    def test_malformed_inputs_are_refused(self) -> None:
        repo = self.repo
        bad = {
            "salt": ("", "0", "-1", "1a", " 1", "1\n", "1234567890", None),
            "workflow_ref": (
                "",
                None,
                f"{REPOSITORY}/.github/workflows/ci.yml",
                f"other/repo/.github/workflows/ci.yml@refs/pull/{PR}/merge",
                f"{REPOSITORY}/ci/ci.yml@refs/pull/{PR}/merge",
                f"{REPOSITORY}/.github/workflows/sub/ci.yml@refs/pull/{PR}/merge",
            ),
            "repository": ("", None, "noslash", "a/b/c"),
            "sha": ("", None, "abc", repo.merge.upper()),
            "head_sha": ("", None, "z" * 40),
            "base_ref": ("", None, "main\nskip=true", "x" * 256),
            "changed_files": (repo.root / "missing.txt",),
        }
        for field, values in bad.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(marker.MarkerError):
                        self.key_for(repo.merge, repo.head, **{field: value})


# ---------------------------------------------------------------------------
# GitHub's REST API, as the decision reads it
# ---------------------------------------------------------------------------


class FakeApi:
    """Run attempts, their jobs, run artifacts and the cache listing.

    The state is plain JSON, so a fake ``gh`` in a workflow step can serve the
    same data (see ``GitHub``). ``fail`` is a regular expression: a call whose
    path matches it fails the way ``gh`` reports an HTTP error.
    """

    def __init__(self, state: dict | None = None) -> None:
        self.state = state or {"attempts": {}, "jobs": {}, "artifacts": {}, "caches": [], "fail": None,
                               "pulls": [], "timeline": {}, "events": {}}
        self.calls: list[str] = []
        self.paginated: list[str] = []
        if state is None:
            # This pull request, the only one from its head branch, with a
            # timeline that never changed its base.
            self.open_pull(PR)
            self.state["timeline"][str(PR)] = [
                {"event": "committed"}, {"event": "commented"}, {"event": "head_ref_force_pushed"},
                {"event": "labeled"}, {"event": "ready_for_review"},
            ]
            self.state["events"][str(PR)] = [
                {"event": "labeled"}, {"event": "head_ref_force_pushed"}, {"event": "ready_for_review"},
            ]

    def open_pull(self, number: int, *, ref: str = HEAD_BRANCH, owner: str = HEAD_OWNER,
                  repository_id: int = REPOSITORY_ID, state: str = "open",
                  created: str = "2026-01-01T00:00:00Z") -> None:
        # By default before every run the tests record.
        self.state["pulls"].append({
            "number": number, "state": state, "created_at": created,
            "head": {"ref": ref, "label": f"{owner}:{ref}", "repo": {"id": repository_id}},
        })

    # -- recording -------------------------------------------------------------

    def record_attempt(self, run_id: int, attempt: int, *, workflow: str, head_tree: str,
                       head_ref: str = HEAD_BRANCH, head_repository: int = REPOSITORY_ID,
                       event: str = "pull_request", jobs: dict[str, str] | None = None,
                       started: str | None = None) -> None:
        results = set((jobs or {}).values())
        if results & {"in_progress", "queued"}:
            status, conclusion = "in_progress", None
        else:
            status = "completed"
            conclusion = next((result for result in ("failure", "cancelled") if result in results), "success")
        if started is None:
            # Runs start in the order of their IDs, attempts of a run in order.
            import datetime
            moment = datetime.datetime(2026, 1, 1) + datetime.timedelta(seconds=run_id * 100 + attempt)
            started = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state["attempts"][f"{run_id}:{attempt}"] = {
            "id": run_id,
            "run_attempt": attempt,
            "repository": {"full_name": REPOSITORY},
            "path": workflow,
            "event": event,
            # GitHub reports the attempt's own conclusion too. The decision
            # never reads it for the run that vouches, only for later runs in
            # the run listing.
            "status": status,
            "conclusion": conclusion,
            "run_started_at": started,
            # An attempt record's created_at is that attempt's; the run
            # listing shows the run's own (see the listing below).
            "created_at": started,
            "head_commit": {"id": "e" * 40, "tree_id": head_tree},
            "head_repository": {"id": head_repository},
            "head_branch": head_ref,
            "pull_requests": [],
        }
        self.state["jobs"][f"{run_id}:{attempt}"] = [
            {"name": name, "run_id": run_id, "run_attempt": attempt,
             "status": "completed" if conclusion not in ("in_progress", "queued") else conclusion,
             "conclusion": conclusion if conclusion not in ("in_progress", "queued") else None}
            for name, conclusion in (jobs or {}).items()
        ]

    def upload(self, run_id: int, name: str, expired: bool = False) -> None:
        self.state["artifacts"].setdefault(str(run_id), []).append(
            {"id": len(self.state["artifacts"]) + 1, "name": name, "expired": expired, "workflow_run": {"id": run_id}}
        )

    def save_cache(self, key: str, path: str = marker.MARKER_DIR, ref: str = f"refs/pull/{PR}/merge") -> None:
        entry = {"key": key, "path": path, "ref": ref}
        if entry not in self.state["caches"]:
            self.state["caches"].append(entry)

    # -- serving -----------------------------------------------------------------

    def __call__(self, path: str, paginate: bool, timeout: float) -> list:
        self.calls.append(path)
        if paginate:
            self.paginated.append(path)
        if self.state.get("fail") and re.search(self.state["fail"], path):
            raise marker.MarkerError("HTTP 403: Resource not accessible by integration")
        endpoint, _, query = path.partition("?")
        params = dict(urllib.parse.parse_qsl(query))
        prefix = f"repos/{REPOSITORY}/"
        if not endpoint.startswith(prefix):
            raise marker.MarkerError(f"HTTP 404: {endpoint}")
        rest = endpoint[len(prefix):]
        if rest == "pulls":
            # ignore_head: an API that does not apply the head filter.
            wanted = {"open": ("open",), "closed": ("closed",), "all": ("open", "closed")}[params.get("state", "open")]
            # Newest first, as GitHub sorts by creation.
            found = [pull for pull in sorted(self.state["pulls"], key=lambda pull: -pull["number"])
                     if pull["state"] in wanted
                     and (self.state.get("ignore_head") or pull["head"]["label"] == params.get("head"))]
            pages = [found[:1], found[1:]] if paginate else [found[: int(params.get("per_page", 30))]]
            return pages
        if match := re.fullmatch(r"issues/(\d+)/(timeline|events)", rest):
            events = self.state[match.group(2)].get(match.group(1))
            if events is None:
                raise marker.MarkerError("HTTP 404: Not Found")
            size, page = int(params.get("per_page", 30)), int(params.get("page", 1))
            return [events[(page - 1) * size: page * size]]
        if not rest.startswith("actions/"):
            raise marker.MarkerError(f"HTTP 404: {endpoint}")
        rest = rest[len("actions/"):]
        if match := re.fullmatch(r"runs/(\d+)/attempts/(\d+)", rest):
            record = self.state["attempts"].get(f"{match.group(1)}:{match.group(2)}")
            if record is None:
                raise marker.MarkerError("HTTP 404: Not Found")
            return [record]
        latest = re.fullmatch(r"runs/(\d+)/jobs", rest)
        if latest and params.get("filter") != "latest":
            raise marker.MarkerError("HTTP 400: only filter=latest is modelled")
        if (match := re.fullmatch(r"runs/(\d+)/attempts/(\d+)/jobs", rest)) or latest:
            if latest:
                # The jobs of the run's latest attempt.
                attempts = [int(key.split(":")[1]) for key in self.state["attempts"]
                            if key.split(":")[0] == latest.group(1)]
                jobs = self.state["jobs"].get(f"{latest.group(1)}:{max(attempts)}") if attempts else None
            else:
                jobs = self.state["jobs"].get(f"{match.group(1)}:{match.group(2)}")
            if jobs is None:
                raise marker.MarkerError("HTTP 404: Not Found")
            # Two pages, the way --paginate concatenates them.
            pages = [jobs[: len(jobs) // 2], jobs[len(jobs) // 2:]] if paginate else [jobs]
            return [{"total_count": len(jobs), "jobs": page} for page in pages]
        if match := re.fullmatch(r"workflows/([A-Za-z0-9._-]+)/runs", rest):
            # Each run as its latest attempt, newest run first. ignore_branch:
            # an API that does not apply the branch filter.
            latest_attempts: dict[int, dict] = {}
            for record in self.state["attempts"].values():
                if record["id"] not in latest_attempts or record["run_attempt"] > latest_attempts[record["id"]]["run_attempt"]:
                    latest_attempts[record["id"]] = record
            # GitHub shows each run as its latest attempt, with the run's own
            # creation time (its first attempt's), as on run 42923201068.
            latest_attempts = {
                number: dict(record, created_at=self.state["attempts"].get(f"{number}:1", record)["created_at"])
                for number, record in latest_attempts.items()
            }
            found = [record for _, record in sorted(latest_attempts.items(), reverse=True)
                     if record["path"] == f".github/workflows/{match.group(1)}"
                     and record["event"] == params.get("event", record["event"])
                     and (self.state.get("ignore_branch") or record["head_branch"] == params.get("branch"))]
            found += self.state.get("extra_runs", [])
            size, page = int(params.get("per_page", 30)), int(params.get("page", 1))
            return [{"total_count": len(found), "workflow_runs": found[(page - 1) * size: page * size]}]
        if match := re.fullmatch(r"runs/(\d+)/artifacts", rest):
            found = [item for item in self.state["artifacts"].get(match.group(1), [])
                     if "name" not in params or item["name"] == params["name"]]
            return [{"total_count": len(found), "artifacts": found}]
        if rest == "caches":
            # ignore_ref: an API that does not apply the ref filter.
            ref = None if self.state.get("ignore_ref") else params.get("ref")
            found = [entry for entry in reversed(self.state["caches"])
                     if entry["key"].startswith(params.get("key", "")) and (ref is None or entry["ref"] == ref)]
            found = found[: int(params.get("per_page", 30))]
            return [{"total_count": len(found), "actions_caches": [
                {"id": index, "key": entry["key"], "ref": entry["ref"]} for index, entry in enumerate(found)]}]
        raise marker.MarkerError(f"HTTP 404: {endpoint}")


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

HEAD_TREE = "a" * 40
OTHER_TREE = "b" * 40
PREFIX = f"qbit-tree-pass-v1-ci.yml-s1-t{'c' * 40}-g{'d' * 64}-r"
OTHER_BASE_PREFIX = f"qbit-tree-pass-v1-ci.yml-s1-t{'f' * 40}-g{'d' * 64}-r"
OTHER_TARGET_PREFIX = f"qbit-tree-pass-v1-ci.yml-s1-t{'c' * 40}-g{'9' * 64}-r"
WRITER = 1000
CURRENT = 2000
CI = ".github/workflows/ci.yml"
GATE_NAME = "Full Validation Gate"
PASSED_JOBS = {"classify validation profile": "success", "lint": "success", GATE_NAME: "success", SAVE_JOB_NAME: "success"}


def passing_api(*, prefix: str = PREFIX, run_id: int = WRITER, attempt: int = 1, **changes: Any) -> FakeApi:
    """GitHub after run ``run_id`` attempt ``attempt`` passed and saved the marker for ``prefix``."""
    api = FakeApi()
    jobs = dict(PASSED_JOBS)
    jobs.update(changes.pop("jobs", {}))
    api.record_attempt(run_id, attempt, workflow=changes.pop("workflow", CI), head_tree=changes.pop("head_tree", HEAD_TREE),
                       jobs=jobs, **changes)
    key = marker.marker_key(prefix, run_id, attempt)
    api.upload(run_id, marker.artifact_name(key))
    api.save_cache(key)
    return api


def decide(api: FakeApi | None = None, **changes: Any) -> marker.Decision:
    api = api if api is not None else passing_api()
    arguments = {
        "event": "pull_request",
        "labels_json": json.dumps(["ci:qbit-trusted"]),
        "profile": "source",
        "key_outcome": "success",
        "prefix": PREFIX,
        "head_tree": HEAD_TREE,
        "workflow_path": CI,
        "lookup_outcome": "success",
        "matched_key": marker.marker_key(PREFIX, WRITER, 1),
        "run_id": str(CURRENT),
        "run_attempt": "1",
        "repository": REPOSITORY,
        "head_repository_id": str(REPOSITORY_ID),
        "head_ref": HEAD_BRANCH,
        "head_owner": HEAD_OWNER,
        "pr_number": str(PR),
        "gate_job": GATE_NAME,
        "save_job": SAVE_JOB_NAME,
        "api": api,
    }
    arguments.update(changes)
    return marker.decide(**arguments)


class DecideTest(unittest.TestCase):
    def assertRuns(self, decision: marker.Decision, reason: str = "") -> None:
        self.assertFalse(decision.act, decision)
        self.assertIn(reason, decision.reason)

    def test_a_tree_that_already_passed_skips(self) -> None:
        api = passing_api()
        decision = decide(api)
        self.assertTrue(decision.act, decision)
        base = f"repos/{REPOSITORY}/actions/runs/{WRITER}"
        self.assertIn(f"{base}/attempts/1", api.calls)
        self.assertIn(f"{base}/attempts/1/jobs?per_page=100", api.calls)
        name = marker.artifact_name(marker.marker_key(PREFIX, WRITER, 1))
        self.assertIn(f"{base}/artifacts?name={name}&per_page=100", api.calls)
        self.assertIn(f"{base}/jobs?filter=latest&per_page=100", api.paginated)
        self.assertNotIn(f"{base}", [call.partition("?")[0] for call in api.calls], "the run-level record is never read")
        listing = [call for call in api.calls if "/actions/workflows/" in call]
        self.assertEqual([dict(urllib.parse.parse_qsl(call.partition("?")[2])) for call in listing], [
            {"branch": HEAD_BRANCH, "event": "pull_request", "exclude_pull_requests": "true", "per_page": "100",
             "page": str(page)} for page in (1, 2)])
        self.assertTrue(all(call.startswith(f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs?") for call in listing))

    def test_every_event_but_a_pull_request_runs_in_full(self) -> None:
        for event in (*NON_PULL_REQUEST_EVENTS, "pull_request_target", "", None):
            with self.subTest(event=event):
                api = passing_api()
                self.assertRuns(decide(api, event=event), "always runs in full")
                self.assertEqual(api.calls, [])

    def test_the_force_label_runs_in_full(self) -> None:
        labels = json.dumps(["ci:qbit-trusted", marker.FORCE_FULL_RUN_LABEL])
        self.assertRuns(decide(labels_json=labels), "forces a full run")

    def test_unreadable_labels_run_in_full(self) -> None:
        for labels in ("", None, "not json", "{}", '"ci:full-run"', "[1]", "[null]"):
            with self.subTest(labels=labels):
                self.assertRuns(decide(labels_json=labels), "labels")

    def test_only_full_source_validation_is_skipped(self) -> None:
        for profile in ("release-policy", "rpc-docs", "public-docs", "github-metadata", "", None, "SOURCE"):
            with self.subTest(profile=profile):
                self.assertRuns(decide(profile=profile), "is never skipped")

    def test_a_key_that_could_not_be_computed_runs_in_full(self) -> None:
        for outcome, prefix in (("failure", PREFIX), ("skipped", PREFIX), ("cancelled", PREFIX), ("", PREFIX),
                                ("success", ""), ("success", None), ("success", PREFIX + "1"), ("success", "x-r")):
            with self.subTest(outcome=outcome, prefix=prefix):
                self.assertRuns(decide(key_outcome=outcome, prefix=prefix), "could not be computed")

    def test_every_lookup_failure_runs_in_full(self) -> None:
        for outcome in ("failure", "cancelled", "skipped", "", None):
            with self.subTest(outcome=outcome):
                self.assertRuns(decide(lookup_outcome=outcome), "lookup did not succeed")

    def test_a_cache_miss_runs_in_full(self) -> None:
        # The cache action sets no cache-matched-key on a miss, on an expired
        # entry, and on a cache-service error (which it logs as a warning).
        for matched in ("", None):
            with self.subTest(matched=matched):
                self.assertRuns(decide(matched_key=matched), "no pass marker")

    def test_an_entry_that_is_not_a_marker_for_this_key_runs_in_full(self) -> None:
        api = passing_api()
        api.state["caches"].clear()
        for matched in (PREFIX, f"{PREFIX}{WRITER}", f"{PREFIX}0-a1", f"{PREFIX}{WRITER}-a0", f"{PREFIX}{WRITER}-a1x",
                        f"{PREFIX}{WRITER}-a1\nskip=true", f"{OTHER_BASE_PREFIX}{WRITER}-a1",
                        f"{PREFIX.upper()}{WRITER}-a1", f"x{PREFIX}{WRITER}-a1"):
            with self.subTest(matched=matched):
                self.assertRuns(decide(api, matched_key=matched), "is not a pass marker for this key")

    def test_a_marker_from_this_run_runs_in_full(self) -> None:
        api = passing_api(run_id=CURRENT)
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, CURRENT, 1)), "written by this run")

    def test_an_api_failure_runs_in_full(self) -> None:
        for endpoint in ("/attempts/1$", "/jobs", "/artifacts", "."):
            with self.subTest(endpoint=endpoint):
                api = passing_api()
                api.state["fail"] = endpoint
                self.assertRuns(decide(api), "HTTP 403")

    def test_the_run_attempt_must_be_of_this_workflow_and_head(self) -> None:
        # The attempt record refuses each of these itself; rule 8's run
        # listing, which must hold the vouching run, would refuse most of
        # them again, so the reason is checked too.
        cases = {
            "another head tree": (dict(head_tree=OTHER_TREE), "head tree is"),
            "another workflow": (dict(workflow=".github/workflows/core-checks.yml"), "workflow is"),
            "another event": (dict(event="push"), "event is"),
            "a fork's head": (dict(head_repository=REPOSITORY_ID + 1), "head repository is"),
            "another head branch": (dict(head_ref="other"), "head branch is"),
        }
        for name, (changes, reason) in cases.items():
            with self.subTest(name):
                self.assertRuns(decide(passing_api(**changes)), f"run {WRITER} attempt 1: {reason}")
        record_cases = {
            "not a run": (None, "the run attempt lookup did not return a run"),
            "another run": ({"id": WRITER + 1}, "id is"),
            "another attempt": ({"run_attempt": 2}, "attempt is"),
            "another repository": ({"repository": {"full_name": "other/qbit"}}, "repository is"),
            "no head commit": ({"head_commit": None}, "head tree is"),
            "ID as text": ({"id": str(WRITER)}, "id is"),
            "repository ID as boolean": ({"head_repository": {"id": True}}, "head repository is"),
        }
        for name, (change, reason) in record_cases.items():
            with self.subTest(name):
                api = passing_api()
                record = api.state["attempts"][f"{WRITER}:1"]
                if change is None:
                    api.state["attempts"][f"{WRITER}:1"] = []
                else:
                    record.update(change)
                self.assertRuns(decide(api), f"run {WRITER} attempt 1: {reason}")

    def test_answers_of_the_wrong_type_are_refused(self) -> None:
        # JSON true equals 1 and 0 equals false in Python; neither may stand in.
        api = passing_api(run_id=1)
        api.state["attempts"]["1:1"]["id"] = True
        api.state["caches"].clear()
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, 1, 1)), "id is")
        api = passing_api()
        api.state["artifacts"][str(WRITER)][0]["expired"] = 0
        self.assertRuns(decide(api), "proof expired")
        api = passing_api()
        api.state["attempts"][f"{WRITER}:1"]["head_repository"]["id"] = float(REPOSITORY_ID)
        self.assertRuns(decide(api), "head repository")

    # -- the hole: a run that concluded success without testing anything ------

    def test_a_successful_run_that_ran_nothing_does_not_vouch(self) -> None:
        # A draft run: every job skipped, the gate and the save job included,
        # and still a run conclusion of success. Nothing saved its proof.
        api = FakeApi()
        api.record_attempt(WRITER, 1, workflow=CI, head_tree=HEAD_TREE, jobs={
            "classify validation profile": "success", "lint": "skipped", GATE_NAME: "skipped", SAVE_JOB_NAME: "skipped"})
        self.assertRuns(decide(api))
        # A no-op run that only classified, with no gate or save job at all.
        api = FakeApi()
        api.record_attempt(WRITER, 1, workflow=CI, head_tree=HEAD_TREE, jobs={"classify validation profile": "success"})
        self.assertRuns(decide(api))

    def test_a_pass_of_this_head_against_another_base_or_target_does_not_vouch(self) -> None:
        # The run passed this head merged with an older base, or into another
        # branch, and saved the marker of that key; a marker for this key that
        # names it has no proof.
        for name, prefix in (("older base", OTHER_BASE_PREFIX), ("other target branch", OTHER_TARGET_PREFIX)):
            with self.subTest(name):
                self.assertRuns(decide(passing_api(prefix=prefix)), "0 proof artifacts")

    def test_a_run_of_another_pull_request_on_the_same_head_branch_does_not_vouch(self) -> None:
        # Another pull request from the same branch, into another base: its
        # run saved its own key. Only a run that saved exactly this key could
        # vouch for it, and that run tested exactly this tree and routing.
        api = passing_api(prefix=OTHER_TARGET_PREFIX, run_id=WRITER)
        self.assertRuns(decide(api), "0 proof artifacts")

    def test_a_proof_with_a_failed_gate_does_not_vouch(self) -> None:
        for conclusion in ("failure", "cancelled", "skipped", "in_progress"):
            with self.subTest(conclusion=conclusion):
                self.assertRuns(decide(passing_api(jobs={GATE_NAME: conclusion})), GATE_NAME)
        # The attempt that saved must itself have passed the gate, even when a
        # later attempt of the run passed.
        api = passing_api(jobs={GATE_NAME: "failure"})
        self.later_run(api, WRITER, 2)
        self.assertRuns(decide(api), f"run {WRITER} attempt 1: attempt 1: {GATE_NAME} conclusion")

    def test_a_save_job_that_did_not_finish_does_not_vouch(self) -> None:
        # A run cancelled while it saved: the marker may exist, the save job
        # concluded cancelled.
        for conclusion in ("cancelled", "failure", "skipped", "in_progress"):
            with self.subTest(conclusion=conclusion):
                self.assertRuns(decide(passing_api(jobs={SAVE_JOB_NAME: conclusion})), SAVE_JOB_NAME)

    def test_the_jobs_must_be_of_the_attempt_that_saved(self) -> None:
        cases = {
            "gate missing": lambda jobs: [job for job in jobs if job["name"] != GATE_NAME],
            "gate twice": lambda jobs: jobs + [job for job in jobs if job["name"] == GATE_NAME],
            "gate of another attempt": lambda jobs: [dict(job, run_attempt=2) if job["name"] == GATE_NAME else job
                                                     for job in jobs],
            "save job of another run": lambda jobs: [dict(job, run_id=WRITER + 1) if job["name"] == SAVE_JOB_NAME else job
                                                     for job in jobs],
            "gate not completed": lambda jobs: [dict(job, status="queued") if job["name"] == GATE_NAME else job
                                                for job in jobs],
        }
        for name, change in cases.items():
            with self.subTest(name):
                api = passing_api()
                api.state["jobs"][f"{WRITER}:1"] = change(api.state["jobs"][f"{WRITER}:1"])
                self.assertRuns(decide(api))
        api = passing_api()
        api.state["jobs"][f"{WRITER}:1"] = None
        self.assertRuns(decide(api), "HTTP 404")

    def test_a_green_gate_without_the_proof_does_not_vouch(self) -> None:
        api = passing_api()
        api.state["artifacts"].clear()
        self.assertRuns(decide(api), "0 proof artifacts")

    def test_an_expired_proof_does_not_vouch(self) -> None:
        api = passing_api()
        api.state["artifacts"][str(WRITER)][0]["expired"] = True
        self.assertRuns(decide(api), "proof expired")

    def test_the_proof_must_be_this_runs_and_unique(self) -> None:
        api = passing_api()
        api.state["artifacts"][str(WRITER)][0]["workflow_run"] = {"id": WRITER + 1}
        self.assertRuns(decide(api), "proof run")
        api = passing_api()
        api.upload(WRITER, api.state["artifacts"][str(WRITER)][0]["name"])
        self.assertRuns(decide(api), "2 proof artifacts")

    def test_the_proof_is_bound_to_the_attempt(self) -> None:
        # Attempt 1 saved; attempt 2's gate and save job are green but it saved
        # nothing (for example its merge ref had moved). A marker naming
        # attempt 2 has no proof.
        api = passing_api()
        api.record_attempt(WRITER, 2, workflow=CI, head_tree=HEAD_TREE, jobs=dict(PASSED_JOBS))
        api.state["caches"].clear()
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, WRITER, 2)), "0 proof artifacts")

    # -- a re-run is never answered from a marker ------------------------------

    def test_a_rerun_always_runs_in_full(self) -> None:
        # "Re-run all jobs" of any run, one that saved a marker or one that
        # skipped on one, asks for the work again.
        for attempt in ("2", "3", "17"):
            with self.subTest(attempt=attempt):
                api = passing_api()
                self.assertRuns(decide(api, run_attempt=attempt), f"attempt {attempt} is a re-run")
                self.assertEqual(api.calls, [])
        for attempt in ("", None, "0", "01", "x", "1 ", "-1"):
            with self.subTest(attempt=attempt):
                api = passing_api()
                self.assertRuns(decide(api, run_attempt=attempt), "run attempt is missing or malformed")
                self.assertEqual(api.calls, [])

    # -- the pass must be the newest execution of this tree --------------------

    def later_run(self, api: FakeApi, run_id: int, attempt: int = 1, *, started: str | None = None,
                  **jobs: str) -> None:
        """Record another run attempt of this tree in this pull request: PASSED_JOBS with ``jobs`` changed."""
        names = {"gate": GATE_NAME, "save": SAVE_JOB_NAME, "lint": "lint", "classify": "classify validation profile",
                 "each_commit": "test each commit"}
        results = dict(PASSED_JOBS)
        results.update({names[name]: result for name, result in jobs.items()})
        api.record_attempt(run_id, attempt, workflow=CI, head_tree=HEAD_TREE, jobs=results, started=started)

    def test_a_failed_rerun_of_the_vouching_run_stops_the_skip(self) -> None:
        # Attempt 1 passed and saved; "Re-run all jobs" then failed, or is
        # still running. The latest attempt's gate decides.
        for gate in ("failure", "cancelled", "skipped", "in_progress", "queued"):
            with self.subTest(gate=gate):
                api = passing_api()
                self.later_run(api, WRITER, 2, gate=gate, save="skipped")
                self.assertRuns(decide(api), f"run {WRITER} attempt 1: latest attempt: {GATE_NAME}")
        # A re-run that passed again (and saved nothing, say) changes nothing.
        api = passing_api()
        self.later_run(api, WRITER, 2, save="skipped")
        self.assertTrue(decide(api).act)
        cases = {
            "no gate": lambda jobs: [job for job in jobs if job["name"] != GATE_NAME],
            "two gates": lambda jobs: jobs + [job for job in jobs if job["name"] == GATE_NAME],
            "gate of another run": lambda jobs: [dict(job, run_id=WRITER + 1) if job["name"] == GATE_NAME else job
                                                 for job in jobs],
        }
        for name, change in cases.items():
            with self.subTest(name):
                api = passing_api()
                self.later_run(api, WRITER, 2)
                api.state["jobs"][f"{WRITER}:2"] = change(api.state["jobs"][f"{WRITER}:2"])
                self.assertRuns(decide(api), "latest attempt")

    def test_the_latest_attempt_must_be_readable(self) -> None:
        api = passing_api()
        api.state["fail"] = r"/runs/\d+/jobs\?filter=latest"
        self.assertRuns(decide(api), "HTTP 403")
        def malformed(path: str, paginate: bool, timeout: float) -> list:
            return [{"jobs": None}] if "filter=latest" in path else api(path, paginate, timeout)
        api = passing_api()
        self.assertRuns(decide(malformed), "malformed page")

    def test_a_latest_gate_must_belong_to_the_attempt_the_listing_shows(self) -> None:
        # Right after "Re-run all jobs", GitHub could still serve the previous
        # attempt's jobs as the latest; their green gate must not stand in for
        # a re-run that has not finished.
        def stale(api: FakeApi, run_id: int, served: int):
            def call(path: str, paginate: bool, timeout: float) -> list:
                if path == f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?filter=latest&per_page=100":
                    path = f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{served}/jobs?per_page=100"
                return api(path, paginate, timeout)
            return call

        running = dict(lint="in_progress", gate="queued", save="queued")
        # The vouching run, re-run and still going.
        api = passing_api()
        self.later_run(api, WRITER, 2, **running)
        self.assertRuns(decide(stale(api, WRITER, 1)), f"latest attempt: {GATE_NAME} attempt is '1', not '2'")
        # A later run, re-run and still going.
        api = passing_api()
        self.later_run(api, WRITER + 3, 1)
        self.later_run(api, WRITER + 3, 2, **running)
        self.assertRuns(decide(stale(api, WRITER + 3, 1)), f"{GATE_NAME} attempt is '1', not '2'")
        # A partial re-run lists the jobs it did not repeat under the new
        # attempt, as on run 42923201068, so a finished one still counts.
        api = passing_api()
        self.later_run(api, WRITER, 2, save="skipped")
        self.assertTrue(decide(api).act)

        def listing(api: FakeApi, run_id: int, attempt: object):
            def call(path: str, paginate: bool, timeout: float) -> list:
                documents = api(path, paginate, timeout)
                if "/actions/workflows/" in path:
                    documents = [dict(documents[0], workflow_runs=[
                        dict(run, run_attempt=attempt) if run["id"] == run_id else run
                        for run in documents[0]["workflow_runs"]])]
                return documents
            return call

        # The listing must number the vouching run's latest attempt, and it
        # cannot be older than the attempt that saved.
        for attempt in (None, True, "1", 0, 1.0):
            with self.subTest(attempt=attempt):
                api = passing_api()
                self.assertRuns(decide(listing(api, WRITER, attempt)), f"run {WRITER}'s latest attempt is listed as")
        api = passing_api(attempt=2)
        self.assertRuns(decide(listing(api, WRITER, 1), matched_key=marker.marker_key(PREFIX, WRITER, 2)),
                        f"run {WRITER}'s latest attempt is listed as '1'")
        # A later run that needs its gate read must have an attempt number too.
        for attempt in (None, True, "2", 0):
            with self.subTest(later=attempt):
                api = passing_api()
                self.later_run(api, WRITER + 3, **running)
                self.assertRuns(decide(listing(api, WRITER + 3, attempt)),
                                f"run {WRITER + 3} of this pull request has no attempt number")

    def test_a_later_run_of_this_tree_that_did_not_pass_stops_the_skip(self) -> None:
        # A ci:full-run run of the same tree failed, was cancelled, or is
        # still running; the label came off and this run would skip on the
        # earlier pass.
        cases = {
            "failed": dict(lint="failure", gate="failure", save="skipped"),
            "cancelled": dict(lint="cancelled", gate="cancelled", save="skipped"),
            "gate failed alone": dict(gate="failure", save="skipped"),
            "running": dict(lint="in_progress", gate="queued", save="queued"),
            "running, gate skipped so far": dict(lint="in_progress", gate="skipped", save="skipped"),
        }
        for name, jobs in cases.items():
            with self.subTest(name):
                api = passing_api()
                self.later_run(api, WRITER + 3, **jobs)
                self.assertRuns(decide(api), f"run {WRITER + 3} of this pull request, later than this one")

    def test_a_later_run_that_passed_skipped_or_ran_nothing_does_not_stop_it(self) -> None:
        cases = {
            "passed": {},
            "skipped on a marker": dict(lint="skipped", save="skipped"),
            "a draft, which runs nothing": dict(lint="skipped", gate="skipped", save="skipped"),
            "red outside the gate": dict(each_commit="failure"),
            "gate passed, a job outside it still running": dict(each_commit="in_progress"),
        }
        for name, jobs in cases.items():
            with self.subTest(name):
                api = passing_api()
                self.later_run(api, WRITER + 3, **jobs)
                decision = decide(api)
                self.assertTrue(decision.act, decision)
                latest = [call for call in api.calls if f"runs/{WRITER + 3}/jobs?filter=latest" in call]
                # A run that concluded success needs no further lookup.
                self.assertEqual(bool(latest), name.startswith(("red", "gate passed")), api.calls)

    def test_an_earlier_failure_does_not_stop_a_later_pass(self) -> None:
        api = passing_api()
        self.later_run(api, WRITER - 3, lint="failure", gate="failure", save="skipped")
        self.assertTrue(decide(api).act)

    def test_which_runs_are_later(self) -> None:
        # The vouching run was created at 12:00 (passing_api records its
        # attempt 1 then).
        start = "2026-11-10T12:00:00Z"
        failed = dict(lint="failure", gate="failure", save="skipped")
        cases = {
            # An older run re-run after the vouching run was created, and
            # failed: its newest execution is later.
            "older run, re-run later": (WRITER - 3, 2, "2026-11-10T12:00:01Z", None, True),
            "older run, started the same second": (WRITER - 3, 1, start, None, True),
            "older run, started a second before": (WRITER - 3, 1, "2026-11-10T11:59:59Z", None, False),
            # A run created after the vouching run counts as later even if
            # its latest attempt started before the vouching run was created.
            "newer run, started before the vouching run": (WRITER + 3, 1, "2026-11-10T11:00:00Z", None, True),
            # An older run that has not finished.
            "older run, still running": (WRITER - 3, 1, "2026-11-10T11:00:00Z",
                                         dict(lint="in_progress", gate="queued", save="queued"), True),
        }
        for name, (run_id, attempt, started, jobs, stops) in cases.items():
            with self.subTest(name):
                api = passing_api(started=start)
                if attempt > 1:
                    self.later_run(api, run_id, 1, started="2026-11-10T10:00:00Z")
                self.later_run(api, run_id, attempt, started=started, **(jobs or failed))
                decision = decide(api)
                self.assertEqual(decision.act, not stops, decision)

    def test_a_partial_rerun_does_not_make_the_vouching_run_later(self) -> None:
        # The reviewer's case: run 1000 validated the tree at 12:00 but its
        # save job was cancelled; at 12:30 a re-run of older run 997 (same
        # tree) failed; at 13:00 a re-run of only 1000's save job saved the
        # marker "-a2". GitHub lists the jobs that re-run did not repeat under
        # attempt 2 with their old times, and attempt 2 starts at 13:00. The
        # run's own creation (12:00) is what 997's re-run is compared with.
        failed = dict(lint="failure", gate="failure", save="skipped")
        api = passing_api(attempt=2, started="2026-11-10T13:00:00Z")
        self.later_run(api, WRITER, 1, started="2026-11-10T12:00:00Z", save="cancelled")
        self.later_run(api, WRITER - 3, 1, started="2026-11-10T10:00:00Z", **failed)
        self.later_run(api, WRITER - 3, 2, started="2026-11-10T12:30:00Z", **failed)
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, WRITER, 2)),
                        f"run {WRITER - 3} of this pull request, later than this one")
        # Had 997 failed before 1000 was created, it would be earlier.
        api = passing_api(attempt=2, started="2026-11-10T13:00:00Z")
        self.later_run(api, WRITER, 1, started="2026-11-10T12:00:00Z", save="cancelled")
        self.later_run(api, WRITER - 3, 1, started="2026-11-10T11:30:00Z", **failed)
        self.assertTrue(decide(api, matched_key=marker.marker_key(PREFIX, WRITER, 2)).act)

    def test_a_later_failure_of_any_head_tree_stops_the_skip(self) -> None:
        # The reviewer's case: the vouching run tested head tree a..a merged
        # with an older base, giving merge tree c..c (the key's). "Update
        # branch" made a head whose own tree is c..c, the same key; that run
        # refused the skip (another head tree), ran in full and failed. The
        # author then pushed the first head back. A run record does not show
        # the merge tree, so a failed later run of any head tree counts.
        failed = {"classify validation profile": "success", "lint": "failure", GATE_NAME: "failure",
                  SAVE_JOB_NAME: "skipped"}
        merge_tree = marker.PREFIX_RE.fullmatch(PREFIX).group("tree")
        for name, tree in (("head tree is the merge tree", merge_tree), ("another head tree", OTHER_TREE)):
            with self.subTest(name):
                api = passing_api()
                api.record_attempt(WRITER + 3, 1, workflow=CI, head_tree=tree, jobs=failed)
                self.assertRuns(decide(api), f"run {WRITER + 3} of this pull request, later than this one")
                # A later run of another head tree that passed does not count.
                api = passing_api()
                api.record_attempt(WRITER + 3, 1, workflow=CI, head_tree=tree, jobs=dict(PASSED_JOBS))
                self.assertTrue(decide(api).act)

    def test_only_this_pull_requests_runs_count(self) -> None:
        failed = {"classify validation profile": "success", "lint": "failure", GATE_NAME: "failure",
                  SAVE_JOB_NAME: "skipped"}
        cases = {
            "a fork's branch of the same name": dict(head_repository=REPOSITORY_ID + 1),
            "another workflow": dict(workflow=".github/workflows/core-checks.yml"),
            "another head branch": dict(head_ref="other"),
            "another event": dict(event="push"),
        }
        for name, changes in cases.items():
            with self.subTest(name):
                api = passing_api()
                record = dict(workflow=CI, head_tree=HEAD_TREE, jobs=failed)
                record.update(changes)
                api.record_attempt(WRITER + 3, 1, **record)
                # Even an API that ignores the branch and event filters.
                api.state["ignore_branch"] = True
                api.state["extra_runs"] = [api.state["attempts"].pop(f"{WRITER + 3}:1")]
                decision = decide(api)
                self.assertTrue(decision.act, decision)
        # This run, which is still running, is not a later run.
        api = passing_api()
        self.later_run(api, CURRENT, lint="in_progress", gate="queued", save="queued")
        self.assertTrue(decide(api).act)

    def test_a_later_failure_on_any_page_of_the_listing_is_found(self) -> None:
        size = marker.RUN_PAGE_SIZE
        for position in (0, size - 1, size, 2 * size + 5):
            with self.subTest(position=position):
                api = passing_api()
                runs = 2 * size + 10
                # Later runs that passed, newest first; one failed.
                for index in range(runs):
                    run_id = WRITER + runs - index
                    if index == position:
                        self.later_run(api, run_id, lint="failure", gate="failure", save="skipped")
                    else:
                        api.record_attempt(run_id, 1, workflow=CI, head_tree=OTHER_TREE,
                                           jobs={GATE_NAME: "success"})
                self.assertRuns(decide(api), f"run {WRITER + runs - position} of this pull request")
                pages = [dict(urllib.parse.parse_qsl(call.partition("?")[2]))["page"]
                         for call in api.calls if "/actions/workflows/" in call]
                self.assertEqual(pages, ["1", "2", "3", "4"])

    def test_every_failure_to_read_the_runs_runs_in_full(self) -> None:
        api = passing_api()
        api.state["fail"] = "/actions/workflows/"
        self.assertRuns(decide(api), "HTTP 403")
        api = passing_api()
        self.later_run(api, WRITER + 3, lint="failure", gate="failure", save="skipped")
        api.state["fail"] = rf"runs/{WRITER + 3}/jobs"
        self.assertRuns(decide(api), "HTTP 403")

        def answering(change):
            def call(path: str, paginate: bool, timeout: float) -> list:
                documents = api(path, paginate, timeout)
                if "/actions/workflows/" in path:
                    page = int(dict(urllib.parse.parse_qsl(path.partition("?")[2]))["page"])
                    documents = change(page, documents)
                return documents
            return call

        # The vouching run, and a later run that failed, as the listing shows them.
        sample = passing_api()
        self.later_run(sample, WRITER + 3, lint="failure", gate="failure", save="skipped")
        vouching = sample.state["attempts"][f"{WRITER}:1"]
        failing = sample.state["attempts"][f"{WRITER + 3}:1"]

        def only(runs: list, total: int):
            """Page 1 holds the vouching run and ``runs`` and claims ``total`` more; page 2 is empty."""
            return lambda page, docs: [{"total_count": 1 + total,
                                        "workflow_runs": [vouching, *runs] if page == 1 else []}]

        def pages_of_others(total: int):
            """The vouching run and ``total`` - 1 runs that are not this pull request's, 100 to a page."""
            return lambda page, docs: [{"total_count": total, "workflow_runs": [
                vouching if index == 1 else {"id": 10**6 + index}
                for index in range((page - 1) * 100 + 1, min(page * 100, total) + 1)]}]

        cases = {
            "not a page": (lambda page, docs: [[]], "malformed page"),
            "two documents": (lambda page, docs: docs + docs, "malformed page"),
            "runs not a list": (lambda page, docs: [{"total_count": 1, "workflow_runs": {}}], "malformed page"),
            "no total": (lambda page, docs: [{"workflow_runs": docs[0]["workflow_runs"]}], "malformed page"),
            "total as text": (lambda page, docs: [{"total_count": "1", "workflow_runs": docs[0]["workflow_runs"]}],
                              "malformed page"),
            "total as boolean": (lambda page, docs: [{"total_count": True, "workflow_runs": docs[0]["workflow_runs"]}],
                                 "malformed page"),
            # Each of these hides the failed run, and claims a total that
            # matches what is left, so only its own check can refuse it.
            "longer page than asked": (only([{"id": index} for index in range(1, 101)], 100), "malformed page"),
            "a run without an ID": (only([{key: value for key, value in failing.items() if key != "id"}], 0),
                                    "without an ID"),
            "an ID as text": (only([dict(failing, id=str(WRITER + 3))], 0), "without an ID"),
            "an ID as boolean": (only([dict(failing, id=True)], 0), "without an ID"),
            "more runs than read": (lambda page, docs: [{"total_count": 2, "workflow_runs": docs[0]["workflow_runs"]}],
                                    "may be incomplete"),
            "the listing limit": (pages_of_others(marker.RUN_LISTING_LIMIT), "may be incomplete"),
            "the vouching run not listed": (lambda page, docs: [{"total_count": 0, "workflow_runs": []}],
                                            "is not in this pull request's run listing"),
        }
        for name, (change, reason) in cases.items():
            with self.subTest(name):
                api = passing_api()
                self.assertRuns(decide(answering(change)), reason)
        # Just under the limit, a complete listing is accepted.
        api = passing_api()
        self.assertTrue(decide(answering(pages_of_others(marker.RUN_LISTING_LIMIT - 1))).act)
        # A later run without a start time, and a vouching run without a
        # creation time.
        api = passing_api()
        self.later_run(api, WRITER + 3)
        api.state["attempts"][f"{WRITER + 3}:1"]["run_started_at"] = "2026-11-10 12:00:00"
        self.assertRuns(decide(api), "has no start time")
        for created in (None, "2026-11-10 12:00:00", 1762776000):
            with self.subTest(created=created):
                api = passing_api()
                api.state["attempts"][f"{WRITER}:1"]["created_at"] = created
                self.assertRuns(decide(api), f"run {WRITER} has no creation time")

    def test_the_runs_are_listed_once_for_every_candidate(self) -> None:
        api = passing_api()
        newest = marker.marker_key(PREFIX, WRITER + 5, 1)
        self.later_run(api, WRITER + 5, gate="failure", save="cancelled")
        api.upload(WRITER + 5, marker.artifact_name(newest))
        api.save_cache(newest)
        older = marker.marker_key(PREFIX, WRITER - 5, 1)
        self.later_run(api, WRITER - 5)
        api.upload(WRITER - 5, marker.artifact_name(older))
        api.save_cache(older)
        api.state["caches"].insert(0, api.state["caches"].pop())
        # The newest marker's gate failed; the next one's pass is followed by
        # that failed run, and so is the oldest's.
        self.assertRuns(decide(api, matched_key=newest), f"run {WRITER + 5} of this pull request")
        pages = [call for call in api.calls if "/actions/workflows/" in call]
        self.assertEqual(len(pages), 2, pages)
        # Only a listing that succeeded is remembered: after a failed one,
        # each candidate reads it again.
        api = passing_api()
        for run_id in (WRITER - 5, WRITER - 10):
            key = marker.marker_key(PREFIX, run_id, 1)
            self.later_run(api, run_id)
            api.upload(run_id, marker.artifact_name(key))
            api.save_cache(key)
        api.state["fail"] = "/actions/workflows/"
        self.assertRuns(decide(api), "HTTP 403")
        self.assertEqual(len([call for call in api.calls if "/actions/workflows/" in call]), 3)

    # -- the vouching run is this pull request's, against its only base ---------

    def test_another_pull_request_from_the_same_head_branch_runs_in_full(self) -> None:
        # Its run took its workflow files from the merge with its own base,
        # which may carry files nobody reviewed.
        for state in ("open", "closed"):
            with self.subTest(state=state):
                api = passing_api()
                api.open_pull(PR + 1, state=state)
                self.assertRuns(decide(api), "has 2 pull requests")
                self.assertFalse([call for call in api.calls if "/actions/runs/" in call])
        # Merged pull requests are closed ones the listing also returns.
        api = passing_api()
        api.open_pull(PR - 1, state="closed")
        api.state["pulls"][-1]["merged"] = True
        self.assertRuns(decide(api), "has 2 pull requests")

    def test_any_base_event_runs_in_full(self) -> None:
        # GitHub does not document these names. An automatic retarget leaves
        # only automatic_base_change_succeeded; a prefix rule also refuses a
        # name nobody has seen yet.
        for listing in ("timeline", "events"):
            for event in ("base_ref_changed", "base_ref_force_pushed", "base_ref_deleted",
                          "automatic_base_change_succeeded", "automatic_base_change_failed", "base_ref_renamed"):
                with self.subTest(listing=listing, event=event):
                    api = passing_api()
                    api.state[listing][str(PR)].insert(1, {"event": event})
                    self.assertRuns(decide(api), f"has a base event ({event}) in its {listing}")
            # A force push to the head, or a name that only contains the
            # words, does not count. (Deleting or restoring the head branch
            # does: test_a_deleted_or_restored_head_branch_runs_in_full.)
            api = passing_api()
            api.state[listing][str(PR)] += [{"event": name} for name in (
                "head_ref_force_pushed", "rebase_ref_changed", "head_ref_force_pushed", "head_ref_renamed")]
            self.assertTrue(decide(api).act)

    def test_a_deleted_or_restored_head_branch_runs_in_full(self) -> None:
        # Each event, in each listing, first, in the middle of a page, last on
        # a page and last of all, with other events after it but in the last
        # case, as for the base events.
        size = marker.EVENT_PAGE_SIZE
        total = 2 * size + 30
        for listing in ("timeline", "events"):
            for event in sorted(marker.HEAD_BRANCH_EVENTS):
                for position in (0, size // 2, size - 1, size, size + size // 2, total - 1):
                    with self.subTest(listing=listing, event=event, position=position):
                        api = passing_api()
                        events = [{"event": "head_ref_force_pushed" if index % 3 else "committed"}
                                  for index in range(total)]
                        events[position] = {"event": event}
                        api.state[listing][str(PR)] = events
                        self.assertRuns(decide(api), f"has a head branch event ({event}) in its {listing}")
                        self.assertFalse([call for call in api.calls if "/actions/" in call], api.calls)
        self.assertEqual(marker.HEAD_BRANCH_EVENTS, {"head_ref_deleted", "head_ref_restored"})

    def test_two_pull_requests_open_at_once_and_a_recreated_branch(self) -> None:
        # The review's case: #A and #B open at once from one branch into
        # different bases, so a push makes a run of #A after #B was opened,
        # and the time rule passes it. Deleting and re-creating the branch
        # closes both; #B is reopened, and suppose the listing then missed
        # #A. Deleting the branch while #B existed is on #B's record.
        for listing in ("timeline", "events"):
            with self.subTest(listing=listing):
                api = passing_api(started="2026-11-06T09:00:00Z")
                api.state["pulls"][0]["created_at"] = "2026-11-05T10:00:00Z"
                api.state[listing][str(PR)] += [{"event": "head_ref_deleted"}, {"event": "closed"},
                                                {"event": "head_ref_restored"}, {"event": "reopened"}]
                self.assertRuns(decide(api), f"has a head branch event (head_ref_deleted) in its {listing}")
        # Without those events the run passes every other check, which is
        # what the listing (two pull requests) is there for.
        api = passing_api(started="2026-11-06T09:00:00Z")
        api.state["pulls"][0]["created_at"] = "2026-11-05T10:00:00Z"
        self.assertTrue(decide(api).act)

    def test_a_base_event_anywhere_in_either_listing_runs_in_full(self) -> None:
        # Three pages of other events; the base event first, in the middle of
        # a page, last on a page and last of all, with other events after it
        # except in the last case.
        size = marker.EVENT_PAGE_SIZE
        total = 2 * size + 30
        for listing in ("timeline", "events"):
            for position in (0, size // 2, size - 1, size, size + size // 2, total - 1):
                with self.subTest(listing=listing, position=position):
                    api = passing_api()
                    events = [{"event": "commented" if index % 2 else "committed"} for index in range(total)]
                    events[position] = {"event": "base_ref_force_pushed"}
                    api.state[listing][str(PR)] = events
                    self.assertRuns(decide(api), f"has a base event (base_ref_force_pushed) in its {listing}")
            # Without one, every page is read up to the empty one, and the tree skips.
            api = passing_api()
            api.state[listing][str(PR)] = [{"event": "committed"} for _ in range(total)]
            self.assertTrue(decide(api).act)
            pages = [dict(urllib.parse.parse_qsl(call.partition("?")[2]))["page"]
                     for call in api.calls if call.partition("?")[0].endswith(f"/{listing}")]
            self.assertEqual(pages, ["1", "2", "3", "4"])

    def test_the_listing_must_name_exactly_this_pull_request(self) -> None:
        cases = {
            "none": lambda api: api.state["pulls"].clear(),
            "another number": lambda api: api.state["pulls"][0].update(number=PR + 1),
            "another head branch": lambda api: api.state["pulls"][0]["head"].update(ref="other"),
            "another head repository": lambda api: api.state["pulls"][0]["head"].update(repo={"id": REPOSITORY_ID + 1}),
            "a fork's deleted head": lambda api: api.state["pulls"][0]["head"].update(repo=None),
        }
        for name, change in cases.items():
            with self.subTest(name):
                api = passing_api()
                change(api)
                api.state["ignore_head"] = True
                self.assertRuns(decide(api))
        # An API that ignored the head filter and listed every pull request.
        api = passing_api()
        api.open_pull(PR + 5, ref="unrelated")
        api.state["ignore_head"] = True
        self.assertRuns(decide(api), "has 2 pull requests")

    def test_every_listing_or_timeline_failure_runs_in_full(self) -> None:
        for endpoint in ("/pulls", "/timeline", "/events"):
            with self.subTest(endpoint=endpoint):
                api = passing_api()
                api.state["fail"] = endpoint
                self.assertRuns(decide(api), "HTTP 403")
        for listing in ("timeline", "events"):
            with self.subTest(listing=listing, missing=True):
                api = passing_api()
                api.state[listing].clear()
                self.assertRuns(decide(api), "HTTP 404")
        def replacing(endpoint: str, pages: list):
            def call(path: str, paginate: bool, timeout: float) -> list:
                if endpoint not in path:
                    return api(path, paginate, timeout)
                # The given answer for the first page, an empty page after it.
                later = re.search(r"[?&]page=(\d+)$", path)
                return [[]] if later and later.group(1) != "1" else pages
            return call
        cases = {
            "pull request page is not a list": ("/pulls?", [{"number": PR}], "malformed page"),
            "pull request listing in two pages": ("/pulls?", [[{"number": PR}], []], "malformed page"),
            "timeline page is not a list": ("/timeline", [{"event": "committed"}], "malformed page"),
            "timeline item without a type": ("/timeline", [[{"event": "committed"}, {"id": 1}]], "without a type"),
            "timeline item not an object": ("/timeline", [["base_ref_changed"]], "without a type"),
            "events page is not a list": ("/events", [{"event": "committed"}], "malformed page"),
            "events in two documents": ("/events", [[{"event": "committed"}], []], "malformed page"),
            "events page longer than asked": ("/events", [[{"event": "committed"}] * (marker.EVENT_PAGE_SIZE + 1)],
                                              "malformed page"),
            "event without a type": ("/events", [[{"event": None}]], "without a type"),
        }
        for name, (endpoint, pages, reason) in cases.items():
            with self.subTest(name):
                api = passing_api()
                self.assertRuns(decide(replacing(endpoint, pages)), reason)

    def test_the_listing_is_one_request_of_two_entries(self) -> None:
        api = passing_api()
        self.assertTrue(decide(api).act)
        listing = [call for call in api.calls if "/pulls?" in call]
        self.assertEqual(len(listing), 1)
        self.assertEqual(dict(urllib.parse.parse_qsl(listing[0].partition("?")[2]))["per_page"], "2")
        self.assertFalse([call for call in api.paginated if "/pulls?" in call or "/issues/" in call])
        # An older pull request from the same branch: this one is listed
        # first, so one entry would hide the other.
        api = passing_api()
        api.open_pull(PR - 1, state="closed")
        self.assertRuns(decide(api), "has 2 pull requests")

    def test_a_truncated_listing_runs_in_full(self) -> None:
        # A later page that fails, or a listing that never ends before the
        # deadline, never counts as complete.
        for listing in ("/timeline", "/events"):
            with self.subTest(listing=listing):
                def truncated(path: str, paginate: bool, timeout: float) -> list:
                    if listing in path and "page=2" in path:
                        raise marker.MarkerError("HTTP 502 on page 2")
                    return api(path, paginate, timeout)
                api = passing_api()
                api.state[listing.strip("/")][str(PR)] = [{"event": "committed"}] * marker.EVENT_PAGE_SIZE
                self.assertRuns(decide(truncated), "page 2")

                calls = []
                def endless(path: str, paginate: bool, timeout: float) -> list:
                    calls.append(path)
                    if len(calls) > 200:
                        raise AssertionError("the listing was read without a deadline")
                    if listing in path:
                        return [[{"event": "committed"}] * marker.EVENT_PAGE_SIZE]
                    return api(path, paginate, timeout)
                api = passing_api()
                ticks = iter(float(second) for second in range(0, 100000, 5)).__next__
                self.assertRuns(decide(endless, clock=ticks, budget=100), "ran out")

    def test_a_head_branch_that_needs_encoding_is_listed_exactly(self) -> None:
        ref = "feature/a+b&state=open#c %41"
        api = passing_api(head_ref=ref)
        api.state["pulls"][0]["head"].update(ref=ref, label=f"{HEAD_OWNER}:{ref}")
        decision = decide(api, head_ref=ref)
        self.assertTrue(decision.act, decision)
        listing = next(call for call in api.calls if "/pulls?" in call)
        self.assertEqual(dict(urllib.parse.parse_qsl(listing.partition("?")[2])),
                         {"head": f"{HEAD_OWNER}:{ref}", "state": "all", "per_page": "2"})

    # -- the vouching run is no older than this pull request -------------------

    def test_the_vouching_run_must_not_predate_this_pull_request(self) -> None:
        # The run's creation (as the run listing shows it) against this pull
        # request's (as the pull request listing shows it): a second before
        # and the same second refuse; a later second skips. No run of this
        # repository's pull requests was created within 3 seconds of it.
        opened = "2026-11-10T12:00:00Z"
        for created, skips in (("2026-11-10T11:59:59Z", False), ("2026-11-09T12:00:00Z", False),
                               (opened, False), ("2026-11-10T12:00:01Z", True), ("2026-11-10T12:00:03Z", True)):
            with self.subTest(created=created):
                api = passing_api(started=created)
                api.state["pulls"][0]["created_at"] = opened
                decision = decide(api)
                self.assertEqual(decision.act, skips, decision)
                if not skips:
                    self.assertIn(f"run {WRITER} attempt 1: run {WRITER} was created at {created}, "
                                  f"not after pull request #{PR} was ({opened})", decision.reason)

    def test_a_pull_request_without_a_readable_creation_time_runs_in_full(self) -> None:
        for created in (None, "", "2026-11-10 12:00:00", "2026-11-10T12:00:00+00:00",
                        "2026-11-10T12:00:00.000Z", 1762776000, True, "missing"):
            with self.subTest(created=created):
                api = passing_api()
                if created == "missing":
                    del api.state["pulls"][0]["created_at"]
                else:
                    api.state["pulls"][0]["created_at"] = created
                self.assertRuns(decide(api), f"pull request #{PR} has no creation time")
                self.assertFalse([call for call in api.calls if "/actions/" in call], api.calls)

    def test_an_earlier_pull_requests_run_is_refused_even_if_the_listing_misses_it(self) -> None:
        # The open point's scenario. A writer opens #A from branch topic into
        # a base they control, with a changed ci.yml whose run (head tree H)
        # uploads the artifact for a future key; closes #A, deletes and
        # recreates topic, and opens this pull request from it. A temporary
        # changed workflow here saves the cache key naming #A's run, and a
        # later commit restores tree H. Suppose the listing no longer
        # returned the closed #A: one pull request, this one. Every other
        # record of #A's run matches (same workflow, event, head repository,
        # branch name and head tree; green jobs; the proof), so only the
        # creation times refuse it.
        api = passing_api(started="2026-11-01T09:00:00Z")
        self.assertEqual([pull["number"] for pull in api.state["pulls"]], [PR])
        api.state["pulls"][0]["created_at"] = "2026-11-05T10:00:00Z"
        self.assertRuns(decide(api), f"run {WRITER} was created at 2026-11-01T09:00:00Z, not after pull request #{PR}")
        # The same records with this pull request opened before the run: it skips.
        api = passing_api(started="2026-11-01T09:00:00Z")
        api.state["pulls"][0]["created_at"] = "2026-11-01T08:00:00Z"
        self.assertTrue(decide(api).act)
        # Re-running #A's run after this pull request was opened does not help:
        # the attempt is new, the run's creation time is not.
        api = passing_api(attempt=2, started="2026-11-06T09:00:00Z")
        self.later_run(api, WRITER, 1, started="2026-11-01T09:00:00Z")
        api.state["pulls"][0]["created_at"] = "2026-11-05T10:00:00Z"
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, WRITER, 2)),
                        f"run {WRITER} was created at 2026-11-01T09:00:00Z, not after pull request #{PR}")

    def test_every_candidate_must_not_predate_this_pull_request(self) -> None:
        # The newest marker's run fails on its jobs; the next one, the run of
        # an earlier pull request, is refused by its creation time.
        api = passing_api(started="2026-11-01T09:00:00Z")
        api.state["pulls"][0]["created_at"] = "2026-11-05T10:00:00Z"
        newest = marker.marker_key(PREFIX, WRITER + 5, 1)
        self.later_run(api, WRITER + 5, started="2026-11-06T09:00:00Z", save="cancelled")
        api.upload(WRITER + 5, marker.artifact_name(newest))
        api.save_cache(newest)
        decision = decide(api, matched_key=newest)
        self.assertRuns(decision, f"run {WRITER + 5} attempt 1: attempt 1: {SAVE_JOB_NAME}")
        self.assertIn(f"run {WRITER} attempt 1: run {WRITER} was created at 2026-11-01T09:00:00Z, not after pull request",
                      decision.reason)

    # -- the lookup returns the newest entry -----------------------------------

    def test_a_newest_entry_that_fails_does_not_hide_an_older_valid_one(self) -> None:
        api = passing_api()
        api.record_attempt(WRITER + 5, 1, workflow=CI, head_tree=HEAD_TREE,
                           jobs={**PASSED_JOBS, SAVE_JOB_NAME: "cancelled"})
        newest = marker.marker_key(PREFIX, WRITER + 5, 1)
        api.upload(WRITER + 5, marker.artifact_name(newest))
        api.save_cache(newest)
        decision = decide(api, matched_key=newest)
        self.assertTrue(decision.act, decision)
        self.assertIn(f"run {WRITER} attempt 1", decision.reason)

    def test_a_failed_listing_still_checks_the_entry_the_lookup_returned(self) -> None:
        api = passing_api()
        api.state["fail"] = "/caches"
        self.assertTrue(decide(api).act)

    def test_only_this_pull_requests_markers_are_listed_and_only_a_few(self) -> None:
        api = FakeApi()
        api.save_cache(marker.marker_key(PREFIX, 1, 1), ref=f"refs/pull/{PR + 1}/merge")
        for run in range(10, 10 + 2 * marker.MAX_CANDIDATES):
            api.save_cache(marker.marker_key(PREFIX, run, 1))
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, 99, 1)))
        tried = {int(match.group(1)) for call in api.calls if (match := re.search(r"runs/(\d+)/attempts/1$", call))}
        self.assertEqual(len(tried), marker.MAX_CANDIDATES)
        self.assertNotIn(1, tried)
        # Even an API that ignores the ref filter does not bring in another
        # pull request's markers.
        api = FakeApi()
        api.state["ignore_ref"] = True
        api.save_cache(marker.marker_key(PREFIX, 1, 1), ref=f"refs/pull/{PR + 1}/merge")
        self.assertRuns(decide(api, matched_key=marker.marker_key(PREFIX, 99, 1)))
        self.assertFalse([call for call in api.calls if "runs/1/" in call], api.calls)

    def test_one_deadline_bounds_every_call(self) -> None:
        clock = iter([0.0, 0.0, 10.0, 200.0, 200.0, 200.0, 200.0, 200.0, 200.0, 200.0]).__next__
        api = passing_api()
        self.assertRuns(decide(api, clock=clock, budget=100), "ran out")

    def test_malformed_run_context_runs_in_full(self) -> None:
        for field_name, value in (("run_id", ""), ("run_id", "abc"), ("repository", ""), ("head_tree", ""),
                                  ("workflow_path", "ci.yml"), ("head_repository_id", ""), ("head_ref", ""),
                                  ("pr_number", ""), ("gate_job", ""), ("save_job", "x\ny"),
                                  ("head_owner", ""), ("head_owner", "a/b"), ("head_ref", "a\nb")):
            with self.subTest(field=field_name, value=value):
                api = passing_api()
                self.assertFalse(decide(api, **{field_name: value}).act)
                self.assertEqual(api.calls, [])


class CommandLineTest(RepositoryTestCase):
    """The subcommands as the workflows run them: outputs, exit codes, gh."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(prefix="tree-pass-cli-")
        self.addCleanup(self._dir.cleanup)
        self.output = Path(self._dir.name) / "github-output"
        self.output.write_text("", encoding="utf8")

    def outputs(self) -> dict[str, str]:
        values = {}
        for line in self.output.read_text(encoding="utf8").splitlines():
            name, _, value = line.partition("=")
            values[name] = value
        return values

    def decide_argv(self, matched: str) -> list[str]:
        return [
            "decide", "--event", "pull_request", "--labels-json", "[]", "--profile", "source",
            "--key-outcome", "success", "--key-prefix", PREFIX, "--head-tree", HEAD_TREE,
            "--workflow-path", CI, "--lookup-outcome", "success", "--matched-key", matched,
            "--run-id", str(CURRENT), "--run-attempt", "1", "--repository", REPOSITORY,
            "--head-repository-id", str(REPOSITORY_ID),
            "--head-ref", HEAD_BRANCH, "--head-owner", HEAD_OWNER, "--pr-number", str(PR), "--gate-job", GATE_NAME,
            "--save-job", SAVE_JOB_NAME, "--github-output", str(self.output),
        ]

    def test_decide_writes_the_verdict_last_on_one_line(self) -> None:
        matched = f"{marker.marker_key(PREFIX, WRITER, 1)}\nskip=true"
        api = passing_api()
        api.state["caches"].clear()
        self.assertEqual(marker.main(self.decide_argv(matched), api=api), 0)
        lines = self.output.read_text(encoding="utf8").splitlines()
        self.assertEqual(len(lines), 2, lines)
        self.assertEqual(lines[-1], "skip=false")
        self.output.write_text("", encoding="utf8")
        self.assertEqual(marker.main(self.decide_argv(marker.marker_key(PREFIX, WRITER, 1)), api=passing_api()), 0)
        self.assertEqual(self.outputs()["skip"], "true")

    def test_key_without_a_pull_request_writes_no_key(self) -> None:
        for event in NON_PULL_REQUEST_EVENTS:
            with self.subTest(event=event):
                self.output.write_text("", encoding="utf8")
                argv = ["key", "--workflow-ref", "", "--repository", "", "--salt", "", "--event", event,
                        "--sha", "", "--head-sha", "", "--base-ref", "", "--changed-files", "missing",
                        "--github-output", str(self.output)]
                self.assertEqual(marker.main(argv), 0)
                self.assertEqual(self.outputs(), {"key_prefix": ""})

    def test_key_failure_exits_non_zero_with_no_key(self) -> None:
        argv = ["key", "--workflow-ref", "bad", "--repository", REPOSITORY, "--salt", "1",
                "--event", "pull_request", "--sha", "0" * 40, "--head-sha", "0" * 40,
                "--base-ref", BASE_BRANCH, "--changed-files", str(self.repo.changed_files),
                "--github-output", str(self.output)]
        self.assertEqual(marker.main(argv), 1)
        self.assertEqual(self.output.read_text(encoding="utf8"), "")

    def test_save_plan_rejects_a_malformed_optional_job(self) -> None:
        argv = ["save-plan", "--event", "pull_request", "--needs-json", "{}", "--classify-job", CLASSIFY_JOB,
                "--run-id", "1", "--run-attempt", "1", "--sha", "0" * 40, "--pr-number", str(PR),
                "--github-output", str(self.output), "--marker-dir", str(Path(self._dir.name) / "m"),
                "--optional-job", "mainnet-publish-gate"]
        self.assertEqual(marker.main(argv), 1)
        self.assertEqual(self.output.read_text(encoding="utf8"), "")

    def test_gh_is_called_with_the_job_token_and_every_failure_is_an_error(self) -> None:
        gh_dir = Path(self._dir.name) / "bin"
        gh_dir.mkdir()
        calls = Path(self._dir.name) / "gh-calls"
        reply = Path(self._dir.name) / "reply"
        (gh_dir / "gh").write_text(
            "#!/usr/bin/env bash\n"
            f'printf "%s\\n" "$*" >> {shlex.quote(str(calls))}\n'
            f'source {shlex.quote(str(reply))}\n',
            encoding="utf8",
        )
        (gh_dir / "gh").chmod(0o755)
        path = f"{gh_dir}{os.pathsep}{os.environ.get('PATH', '')}"
        cases = {
            "one document": ("echo '{\"a\": 1}'\n", [{"a": 1}]),
            "pages": ("echo '{\"jobs\": [1]}{\"jobs\": [2]}'\n", [{"jobs": [1]}, {"jobs": [2]}]),
            "forbidden": ("echo 'HTTP 403: Resource not accessible by integration' >&2; exit 1\n", None),
            "not JSON": ("echo '<html>'\n", None),
            "empty": ("exit 0\n", None),
        }
        for name, (script, expected) in cases.items():
            for paginate in (False, True):
                with self.subTest(name, paginate=paginate), mock.patch.dict(os.environ, {"PATH": path}):
                    reply.write_text(script, encoding="utf8")
                    calls.write_text("", encoding="utf8")
                    try:
                        documents = marker.gh_api("repos/x/y/actions/runs/1/attempts/1", paginate, 5)
                    except marker.MarkerError:
                        documents = None
                    self.assertEqual(documents, expected)
                    words = calls.read_text(encoding="utf8").split()
                    self.assertEqual(words[:4], ["api", "-H", "Accept:", "application/vnd.github+json"])
                    self.assertEqual("--paginate" in words, paginate)
                    self.assertEqual(words[-1], "repos/x/y/actions/runs/1/attempts/1")


# ---------------------------------------------------------------------------
# The save plan
# ---------------------------------------------------------------------------


class SavePlanTest(RepositoryTestCase):
    def setUp(self) -> None:
        self.repo.publish_merge_ref(self.repo.merge)
        self.key = self.key_for(self.repo.merge, self.repo.head)

    def needs(self, **outputs: str) -> dict:
        jobs = {name: {"result": "success", "outputs": {}} for name in ("build", "test", "posture", "gate")}
        jobs[CLASSIFY_JOB] = {
            "result": "success",
            "outputs": {"tree_pass_skip": "false", "tree_pass_key_prefix": self.key.prefix,
                        "mainnet_publish_gate_required": "true", **outputs},
        }
        return jobs

    def plan(self, needs: Any = None, **changes: Any) -> marker.SavePlan:
        arguments = {
            "event": "pull_request",
            "needs_json": json.dumps(self.needs() if needs is None else needs),
            "classify_job": CLASSIFY_JOB,
            "run_id": "31",
            "run_attempt": "2",
            "sha": self.repo.merge,
            "pr_number": str(PR),
            "check_merge_ref": True,
            "cwd": self.repo.fresh_checkout(self.repo.merge),
        }
        arguments.update(changes)
        return marker.plan_save(**arguments)

    def test_a_run_that_did_everything_and_passed_saves_with_its_attempt(self) -> None:
        plan = self.plan()
        self.assertTrue(plan.decision.act, plan.decision)
        self.assertEqual(plan.key, f"{self.key.prefix}31-a2")
        self.assertEqual(plan.artifact, "tree-pass-" + __import__("hashlib").sha256(plan.key.encode()).hexdigest())

    def test_any_job_that_did_not_succeed_saves_nothing(self) -> None:
        for job in ("build", "test", "posture", "gate", CLASSIFY_JOB):
            for result in ("failure", "cancelled", "skipped", ""):
                with self.subTest(job=job, result=result):
                    needs = self.needs()
                    needs[job]["result"] = result
                    plan = self.plan(needs)
                    self.assertFalse(plan.decision.act, plan.decision)
                    self.assertEqual((plan.key, plan.artifact), ("", ""))

    def test_a_job_its_routing_does_not_run_may_be_skipped(self) -> None:
        # Core Checks into a testnet line: the mainnet posture job is skipped
        # by design, and only then.
        optional = {"posture": "mainnet_publish_gate_required"}
        for required, result, saves in (("false", "skipped", True), ("true", "skipped", False), ("", "skipped", False),
                                        ("false", "failure", False), ("false", "cancelled", False),
                                        ("false", "success", True)):
            with self.subTest(required=required, result=result):
                needs = self.needs(mainnet_publish_gate_required=required)
                needs["posture"]["result"] = result
                self.assertIs(self.plan(needs, optional_jobs=optional).decision.act, saves)
        # Without the rule a skipped job saves nothing.
        needs = self.needs(mainnet_publish_gate_required="false")
        needs["posture"]["result"] = "skipped"
        self.assertFalse(self.plan(needs).decision.act)
        self.assertEqual(marker.parse_optional_jobs(["a-b=c_d"]), {"a-b": "c_d"})
        for bad in ("a", "a=", "=b", "a=b=c", "a b=c"):
            with self.subTest(bad=bad), self.assertRaises(marker.MarkerError):
                marker.parse_optional_jobs([bad])

    def test_a_run_the_marker_skipped_saves_nothing(self) -> None:
        for skipped in ("true", "", None, "False", "yes"):
            with self.subTest(skipped=skipped):
                needs = self.needs()
                needs[CLASSIFY_JOB]["outputs"]["tree_pass_skip"] = skipped
                self.assertFalse(self.plan(needs).decision.act)

    def test_only_a_pull_request_saves(self) -> None:
        for event in NON_PULL_REQUEST_EVENTS:
            with self.subTest(event=event):
                self.assertFalse(self.plan(event=event).decision.act)

    def test_malformed_results_save_nothing(self) -> None:
        for needs_json in ("", "[]", "{}", '{"build": {"result": "success"}}', "not json", '{"classify-changes": "success"}'):
            with self.subTest(needs_json=needs_json):
                self.assertFalse(self.plan(needs_json=needs_json).decision.act)
        needs = self.needs()
        needs[CLASSIFY_JOB]["outputs"]["tree_pass_key_prefix"] = "qbit-tree-pass-v1-r"
        self.assertFalse(self.plan(needs).decision.act)
        for field_name, value in (("run_id", ""), ("run_id", "0"), ("run_attempt", ""), ("run_attempt", "0"),
                                  ("pr_number", "x"), ("sha", "")):
            with self.subTest(field=field_name):
                self.assertFalse(self.plan(**{field_name: value}).decision.act)

    def test_a_marker_for_another_tree_is_not_saved(self) -> None:
        needs = self.needs()
        needs[CLASSIFY_JOB]["outputs"]["tree_pass_key_prefix"] = self.key_for(self.repo.changed_merge, self.repo.changed).prefix
        plan = self.plan(needs)
        self.assertFalse(plan.decision.act)
        self.assertIn("not the keyed tree", plan.decision.reason)

    def test_a_merge_ref_that_moved_saves_nothing_only_where_jobs_test_it(self) -> None:
        # Full Validation's jobs check out the merge ref when they start: if it
        # moved, some of them tested another tree. Core Checks' jobs test the
        # event's commit, so a moved merge ref does not matter there.
        self.repo.publish_merge_ref(self.repo.moved_merge)
        plan = self.plan(check_merge_ref=True)
        self.assertFalse(plan.decision.act)
        self.assertIn("merge ref moved", plan.decision.reason)
        self.assertTrue(self.plan(check_merge_ref=False).decision.act)

    def test_an_unreachable_merge_ref_saves_nothing(self) -> None:
        plan = self.plan(pr_number=str(PR + 1))
        self.assertFalse(plan.decision.act)
        self.assertIn("git fetch", plan.decision.reason)


# ---------------------------------------------------------------------------
# The workflows, run step by step against a simulated GitHub
# ---------------------------------------------------------------------------


class GitHub:
    """What one workflow sees of GitHub: the event, the cache, artifacts and run records.

    The workflow steps call a fake ``gh`` that serves ``self.api``'s state.
    """

    def __init__(self, root: Path, repo: Repository) -> None:
        self.root = root
        self.repo = repo
        self.api = FakeApi()
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.state = root / "api-state.json"
        # Self-contained: FakeApi's own source and the constants it reads,
        # without importing this module (and PyYAML) on every call.
        (self.bin / "gh").write_text(
            f"#!{sys.executable}\n"
            "import json, re, sys, urllib.parse\n"
            f"sys.path.insert(0, {str(CHECKS_DIR)!r})\n"
            "import tree_pass_marker as marker\n"
            "from typing import Any\n"
            f"REPOSITORY, REPOSITORY_ID, PR, HEAD_BRANCH, HEAD_OWNER = "
            f"{REPOSITORY!r}, {REPOSITORY_ID!r}, {PR!r}, {HEAD_BRANCH!r}, {HEAD_OWNER!r}\n"
            + inspect.getsource(FakeApi)
            + f"with open({str(self.state)!r}, encoding='utf8') as handle:\n"
            "    api = FakeApi(json.load(handle))\n"
            "arguments = sys.argv[1:]\n"
            "try:\n"
            "    documents = api(arguments[-1], '--paginate' in arguments, 0)\n"
            "except marker.MarkerError as error:\n"
            "    print(error, file=sys.stderr)\n"
            "    sys.exit(1)\n"
            "for document in documents:\n"
            "    print(json.dumps(document))\n",
            encoding="utf8",
        )
        (self.bin / "gh").chmod(0o755)

    def sync(self) -> None:
        self.state.write_text(json.dumps(self.api.state), encoding="utf8")

    def restore(self, inputs: dict[str, str], ref: str) -> dict[str, str]:
        """The cache action's lookup in one pull request's scope: exact key, then the newest prefix match."""
        path, key = inputs["path"], inputs["key"]
        entries = [entry["key"] for entry in self.api.state["caches"] if entry["path"] == path and entry["ref"] == ref]
        outputs = {"cache-primary-key": key}
        if key in entries:
            return {**outputs, "cache-hit": "true", "cache-matched-key": key}
        for prefix in [line for line in inputs.get("restore-keys", "").splitlines() if line]:
            matches = [entry for entry in entries if entry.startswith(prefix)]
            if matches:
                return {**outputs, "cache-hit": "false", "cache-matched-key": matches[-1]}
        return outputs

    def context(self, *, event: str, merge: str, head: str, labels: tuple[str, ...], draft: bool,
                base_ref: str, pr: int) -> dict:
        pull_request = {
            "number": pr,
            "draft": draft,
            "labels": [{"name": label} for label in labels],
            "head": {"sha": head, "ref": HEAD_BRANCH,
                     "repo": {"id": REPOSITORY_ID, "full_name": REPOSITORY, "owner": {"login": HEAD_OWNER}}},
            "base": {"sha": self.repo.base, "ref": base_ref},
        }
        github = {
            "event_name": event,
            "repository": REPOSITORY,
            "sha": merge,
            "base_ref": base_ref if event == "pull_request" else "",
            "token": "fake-token",
            "event": {"pull_request": pull_request} if event == "pull_request" else {},
        }
        return {"github": github, "vars": {}, "env": {}, "matrix": {}}


class WorkflowRun:
    """One run attempt of a skipping workflow: classify, jobs, gate, save; then GitHub's record of it."""

    def __init__(self, test: unittest.TestCase, hub: GitHub, workflow_path: str, *, run_id: int, event: str,
                 merge: str, head: str, labels: tuple[str, ...] = (), draft: bool = False, attempt: int = 1,
                 base_ref: str = BASE_BRANCH, pr: int = PR, mainnet: str = "true", lookup_fails: bool = False,
                 job_results: dict[str, str] | None = None, merge_ref_at_save: str | None = None,
                 save_conclusion: str | None = None) -> None:
        self.test = test
        self.hub = hub
        self.repo = hub.repo
        self.path = workflow_path
        self.config = SKIPPING_WORKFLOWS[workflow_path]
        self.workflow = load(workflow_path)
        self.jobs = self.workflow["jobs"]
        self.run_id = run_id
        self.attempt = attempt
        self.merge = merge
        self.head = head
        self.pr = pr
        self.mainnet = mainnet
        self.lookup_fails = lookup_fails
        self.job_results = job_results or {}
        self.merge_ref_at_save = merge_ref_at_save
        self.save_conclusion = save_conclusion
        self.context = hub.context(event=event, merge=merge, head=head, labels=labels, draft=draft,
                                   base_ref=base_ref, pr=pr)
        self.output_dir = Path(tempfile.mkdtemp(prefix="outputs-", dir=hub.root))
        self.changed_files = Path(tempfile.mkstemp(prefix="changed-", dir=hub.root)[1])
        self.changed_files.write_text("src/a.cpp\n", encoding="utf8")
        self.repo.check_out(merge)
        self.repo.publish_merge_ref(merge, pr)
        if not any(pull["number"] == pr for pull in hub.api.state["pulls"]):
            # Another pull request from the same head branch.
            hub.api.open_pull(pr)
            hub.api.state["timeline"][str(pr)] = [{"event": "committed"}]
        self.log: list[str] = []

    # -- helpers -----------------------------------------------------------

    def environment(self, step_env: dict | None, context: dict, output: Path) -> dict[str, str]:
        env = {name: render(value, context) for name, value in (step_env or {}).items()}
        env.update(
            {
                "PATH": f"{self.hub.bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "HOME": str(self.hub.root),
                "GITHUB_OUTPUT": str(output),
                "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_RUN_ID": str(self.run_id),
                "GITHUB_RUN_ATTEMPT": str(self.attempt),
                "GITHUB_SHA": self.merge,
                "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{self.path}@refs/pull/{self.pr}/merge",
                **GIT_ENV,
            }
        )
        return env

    def run_step(self, step: dict, context: dict, cwd: Path | None = None) -> dict:
        handle, name = tempfile.mkstemp(dir=self.output_dir)
        os.close(handle)
        output = Path(name)
        self.hub.sync()
        completed = run_bash_step(step["run"], cwd or self.repo.work, self.environment(step.get("env"), context, output))
        outputs = {}
        for line in output.read_text(encoding="utf8").splitlines():
            key, _, value = line.partition("=")
            outputs[key] = value
        self.log.append(completed.stdout + completed.stderr)
        return {"outcome": "success" if completed.returncode == 0 else "failure", "outputs": outputs}

    # -- the run -------------------------------------------------------------

    def classify(self) -> dict:
        """The classify job's marker steps, after the real classifier routed the change as source."""
        job = self.jobs[CLASSIFY_JOB]
        steps: dict[str, dict] = {
            "changed-files": {"outcome": "success", "outputs": {"changed_files": str(self.changed_files)}},
            "classify": {"outcome": "success", "outputs": {"profile": "source", "source_validation_required": "true"}},
            "release-target": {"outcome": "success", "outputs": {"mainnet_publish_gate_required": self.mainnet}},
        }
        for step in job["steps"]:
            if step.get("id") not in MARKER_STEPS:
                continue
            context = {**self.context, "steps": steps}
            if not condition(step.get("if"), context, {"success": True, "failure": False, "cancelled": False}):
                steps[step["id"]] = {"outcome": "skipped", "outputs": {}}
                continue
            if "run" in step:
                steps[step["id"]] = self.run_step(step, context)
            elif self.lookup_fails:
                steps[step["id"]] = {"outcome": "failure", "outputs": {}}
            else:
                inputs = {name: render(value, context) for name, value in step["with"].items()}
                self.test.assertEqual(inputs.get("lookup-only"), "true")
                steps[step["id"]] = {"outcome": "success",
                                     "outputs": self.hub.restore(inputs, f"refs/pull/{self.pr}/merge")}
        context = {**self.context, "steps": steps}
        self.classify_steps = steps
        outputs = {name: render(value, context) for name, value in job["outputs"].items()}
        # The classifier's own outputs, as the real job declares them.
        outputs.update({"profile": "source", "source_validation_required": "true"})
        if "mainnet_publish_gate_required" in job["outputs"]:
            outputs["mainnet_publish_gate_required"] = self.mainnet
        return outputs

    def run(self) -> "WorkflowRun":
        self.classify_outputs = self.classify()
        results: dict[str, str] = {CLASSIFY_JOB: "success"}
        needs_context: dict[str, dict] = {CLASSIFY_JOB: {"result": "success", "outputs": self.classify_outputs}}
        pending = [name for name in self.jobs if name not in (CLASSIFY_JOB, self.config["gate"], SAVE_JOB)]
        while pending:
            for name in list(pending):
                job = self.jobs[name]
                needs = job.get("needs") or []
                needs = [needs] if isinstance(needs, str) else needs
                if any(need not in results for need in needs):
                    continue
                context = {**self.context, "needs": {need: needs_context[need] for need in needs}}
                runs = condition(job.get("if"), context, job_status(job, results))
                results[name] = self.job_results.get(name, "success") if runs else "skipped"
                needs_context[name] = {"result": results[name], "outputs": {}}
                pending.remove(name)
        self.results = results

        gate = self.jobs[self.config["gate"]]
        context = {**self.context, "needs": {need: needs_context[need] for need in gate["needs"]}}
        self.gate_ran = condition(gate.get("if"), context, job_status(gate, results))
        self.gate_result = "skipped"
        if self.gate_ran:
            outcome = "success"
            for step in gate["steps"]:
                if not condition(step.get("if"), {**context, "steps": {}}, {"success": outcome == "success",
                                                                              "failure": outcome != "success",
                                                                              "cancelled": False}):
                    continue
                if self.run_step(step, {**context, "steps": {}})["outcome"] != "success":
                    outcome = "failure"
            self.gate_result = self.job_results.get(self.config["gate"], outcome)
        results[self.config["gate"]] = self.gate_result
        needs_context[self.config["gate"]] = {"result": self.gate_result, "outputs": {}}

        save = self.jobs[SAVE_JOB]
        context = {**self.context, "needs": {need: needs_context[need] for need in save["needs"]}}
        self.save_ran = condition(save.get("if"), context, job_status(save, results))
        self.saved: str | None = None
        self.proof: str | None = None
        save_result = "skipped"
        if self.save_ran:
            if self.merge_ref_at_save:
                self.repo.publish_merge_ref(self.merge_ref_at_save, self.pr)
            checkout = self.repo.fresh_checkout(self.merge)
            steps: dict[str, dict] = {}
            save_result = "success"
            for step in save["steps"]:
                step_context = {**context, "steps": steps}
                if not condition(step.get("if"), step_context, {"success": True, "failure": False, "cancelled": False}):
                    if "id" in step:
                        steps[step["id"]] = {"outcome": "skipped", "outputs": {}}
                    continue
                if "run" in step:
                    steps[step["id"]] = self.run_step(step, step_context, checkout)
                    if steps[step["id"]]["outcome"] != "success" and not step.get("continue-on-error"):
                        save_result = "failure"
                        break
                elif step["uses"].startswith("actions/upload-artifact@"):
                    inputs = {name: render(value, step_context) for name, value in step["with"].items()}
                    self.test.assertTrue((checkout / inputs["path"]).is_file(), inputs)
                    self.hub.api.upload(self.run_id, inputs["name"])
                    self.proof = inputs["name"]
                    steps[step["id"]] = {"outcome": "success", "outputs": {}}
                elif step["uses"].startswith("actions/cache/save@"):
                    inputs = {name: render(value, step_context) for name, value in step["with"].items()}
                    self.hub.api.save_cache(inputs["key"], path=inputs["path"], ref=f"refs/pull/{self.pr}/merge")
                    self.saved = inputs["key"]
        save_result = self.save_conclusion or save_result

        # GitHub's record of this attempt, as the next run's decision reads it.
        names = {CLASSIFY_JOB: "classify validation profile", self.config["gate"]: self.config["gate_name"],
                 SAVE_JOB: SAVE_JOB_NAME}
        conclusions = {names.get(name, name): result for name, result in results.items()}
        conclusions[SAVE_JOB_NAME] = save_result
        self.hub.api.record_attempt(self.run_id, self.attempt, workflow=self.path, head_tree=self.repo.tree(self.head),
                                    jobs=conclusions)
        return self

    # -- what GitHub would show ----------------------------------------------

    @property
    def skipped(self) -> bool:
        return self.classify_outputs["tree_pass_skip"] == "true"

    def expensive_results(self) -> dict[str, str]:
        return {name: result for name, result in self.results.items() if name in marked_jobs(self.path)}


class WorkflowSimulationTest(RepositoryTestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(prefix="tree-pass-hub-")
        self.addCleanup(self._dir.cleanup)
        self.hubs = 0
        self.hub = self.new_hub()

    def new_hub(self) -> GitHub:
        self.hubs += 1
        return GitHub(Path(self._dir.name) / f"hub-{self.hubs}", self.repo)

    def run_workflow(self, path: str, run_id: int, merge: str, head: str, **options: Any) -> WorkflowRun:
        return WorkflowRun(self, self.hub, path, run_id=run_id, event=options.pop("event", "pull_request"),
                           merge=merge, head=head, **options).run()

    def full_pass(self, path: str, run_id: int = 100, **options: Any) -> WorkflowRun:
        merge = options.pop("merge", self.repo.merge)
        first = self.run_workflow(path, run_id, merge, self.repo.head, **options)
        self.assertFalse(first.skipped, first.log)
        self.assertEqual(set(first.expensive_results().values()), {"success"}, first.results)
        self.assertEqual(first.gate_result, "success", first.log)
        prefix = first.classify_outputs["tree_pass_key_prefix"]
        self.assertEqual(first.saved, f"{prefix}{run_id}-a{first.attempt}", first.log)
        self.assertEqual(first.proof, marker.artifact_name(first.saved))
        return first

    def forge(self, path: str, run_id: int, attempt: int = 1, merge: str | None = None, head: str | None = None) -> str:
        """Save a marker for this pull request's next tree that names ``run_id``, without the run saving it."""
        probe = WorkflowRun(self, self.hub, path, run_id=99999, event="pull_request",
                            merge=merge or self.repo.amended_merge, head=head or self.repo.amended)
        key = marker.marker_key(probe.classify()["tree_pass_key_prefix"], run_id, attempt)
        self.hub.api.save_cache(key)
        return key

    def assertRanEverything(self, run: WorkflowRun) -> None:
        self.assertFalse(run.skipped, run.log)
        self.assertEqual(set(run.expensive_results().values()), {"success"}, run.results)
        self.assertEqual(run.gate_result, "success", run.log)

    def assertSkipped(self, run: WorkflowRun) -> None:
        self.assertTrue(run.skipped, run.log)
        self.assertEqual(set(run.expensive_results().values()), {"skipped"}, run.results)
        for name in run.config["always"]:
            self.assertEqual(run.results[name], "success", name)
        self.assertEqual(run.gate_result, "success", run.log)
        self.assertFalse(run.save_ran)

    def test_the_same_tree_skips_and_still_passes_the_gate_check(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path)
                second = self.run_workflow(path, 101, self.repo.amended_merge, self.repo.amended)
                self.assertSkipped(second)
                gate = SKIPPING_WORKFLOWS[path]["gate_name"].replace(" Gate", "")
                self.assertIn(f"{gate}::This tree already passed", "".join(second.log))
                # Labels change without changing the tree: skip too.
                self.assertSkipped(self.run_workflow(path, 102, self.repo.amended_merge, self.repo.amended,
                                                     labels=("ci:qbit-trusted",)))

    def test_the_commit_range_lints_run_and_gate_even_when_the_tree_passed(self) -> None:
        path = ".github/workflows/ci.yml"
        self.full_pass(path)
        failed = self.run_workflow(path, 103, self.repo.amended_merge, self.repo.amended,
                                   job_results={"lint-commit-range": "failure"})
        self.assertTrue(failed.skipped)
        self.assertEqual(failed.results["lint-commit-range"], "failure")
        self.assertNotEqual(failed.gate_result, "success", failed.log)

    def test_lint_commit_range_lints_the_merge_commits_range(self) -> None:
        # The step's script, run with a fake cargo that records the range and
        # the lints asked for. Without the export the test runner would lint
        # HEAD..HEAD on a pull request, which checks nothing and passes.
        step = load(".github/workflows/ci.yml")["jobs"]["lint-commit-range"]["steps"][-1]
        fake = Path(self._dir.name) / "fake-cargo"
        fake.mkdir()
        record = fake / "record"
        (fake / "cargo").write_text(
            "#!/usr/bin/env bash\n"
            f'printf "COMMIT_RANGE=%s\\n" "${{COMMIT_RANGE-<unset>}}" > {shlex.quote(str(record))}\n'
            f'printf "%s\\n" "$@" >> {shlex.quote(str(record))}\n'
            'exit "${FAKE_CARGO_EXIT:-0}"\n',
            encoding="utf8",
        )
        (fake / "cargo").chmod(0o755)

        def run(event: str, sha: str, cargo_exit: int = 0) -> tuple[subprocess.CompletedProcess[str], list[str] | None]:
            self.repo.check_out(sha)
            record.unlink(missing_ok=True)
            env = {name: render(value, {"github": {"event_name": event}}) for name, value in step["env"].items()}
            env.update({**self.repo.env, "PATH": f"{fake}{os.pathsep}{os.environ.get('PATH', '')}",
                        "FAKE_CARGO_EXIT": str(cargo_exit)})
            env.pop("COMMIT_RANGE", None)
            completed = run_bash_step(step["run"], self.repo.work, env)
            return completed, record.read_text(encoding="utf8").splitlines() if record.exists() else None

        completed, lines = run("pull_request", self.repo.merge)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(lines[0], "COMMIT_RANGE=HEAD~..HEAD")
        self.assertEqual(self.repo.git(self.repo.work, "rev-list", "HEAD~..HEAD"), self.repo.git(
            self.repo.work, "rev-list", f"{self.repo.base}..{self.repo.merge}").replace("\r", ""))
        self.assertEqual(lines[1:4], ["run", "--quiet", "--manifest-path"])
        self.assertEqual(sorted(line.removeprefix("--lint=") for line in lines if line.startswith("--lint=")),
                         sorted(HISTORY_LINTS))
        # A lint that fails fails the step: nothing may swallow cargo's exit.
        for event in ("pull_request", "push"):
            with self.subTest(event=event, cargo="fails"):
                completed, lines = run(event, self.repo.merge, cargo_exit=3)
                self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIsNotNone(lines)
        # A pull request checkout whose top commit is not the merge stops
        # before linting anything.
        completed, lines = run("pull_request", self.repo.head)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(lines)
        self.assertIn("must be the pull request's merge commit", completed.stdout + completed.stderr)
        # Other events keep the test runner's own default range.
        for event in ("push", "merge_group"):
            with self.subTest(event=event):
                completed, lines = run(event, self.repo.merge)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(lines[0], "COMMIT_RANGE=<unset>")

    def test_a_real_change_or_a_moved_base_runs_everything(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path)
                self.assertRanEverything(self.run_workflow(path, 110, self.repo.changed_merge, self.repo.changed))
                self.assertRanEverything(self.run_workflow(path, 111, self.repo.moved_merge, self.repo.head))

    def test_the_force_label_runs_everything(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path)
                forced = self.run_workflow(path, 120, self.repo.amended_merge, self.repo.amended,
                                           labels=(marker.FORCE_FULL_RUN_LABEL,))
                self.assertRanEverything(forced)
                # A forced full run that passes saves a marker of its own.
                self.assertEqual(forced.saved, f"{forced.classify_outputs['tree_pass_key_prefix']}120-a1")

    def test_every_lookup_failure_runs_everything(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path)
                self.assertRanEverything(self.run_workflow(path, 130, self.repo.amended_merge, self.repo.amended,
                                                           lookup_fails=True))
                # Every API call is refused (a missing actions: read).
                self.hub.api.state["fail"] = "."
                self.assertRanEverything(self.run_workflow(path, 131, self.repo.amended_merge, self.repo.amended))
                self.hub.api.state["fail"] = None
                # The entry expired or was evicted: the cache returns nothing.
                self.hub.api.state["caches"].clear()
                self.assertRanEverything(self.run_workflow(path, 132, self.repo.amended_merge, self.repo.amended))

    def test_a_key_failure_runs_everything(self) -> None:
        path = ".github/workflows/ci.yml"
        self.full_pass(path)
        run = WorkflowRun(self, self.hub, path, run_id=140, event="pull_request",
                          merge=self.repo.amended_merge, head=self.repo.amended)
        run.changed_files.unlink()
        run.run()
        self.assertEqual(run.classify_steps["marker-key"]["outcome"], "failure")
        self.assertEqual(run.classify_steps["marker-lookup"]["outcome"], "skipped")
        self.assertRanEverything(run)

    def test_events_other_than_a_pull_request_never_skip_or_save(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path)
                for event in NON_PULL_REQUEST_EVENTS:
                    with self.subTest(event=event):
                        run = self.run_workflow(path, 150, self.repo.amended_merge, self.repo.amended, event=event)
                        for step in MARKER_STEPS:
                            self.assertEqual(run.classify_steps[step]["outcome"], "skipped")
                        self.assertEqual(run.classify_outputs["tree_pass_skip"], "false")
                        self.assertNotIn("skipped", run.expensive_results().values())
                        self.assertFalse(run.save_ran)

    # -- forged markers ----------------------------------------------------------

    def test_a_draft_or_no_op_run_cannot_vouch_for_a_forged_marker(self) -> None:
        # The review's scenario: push the head while the pull request is a
        # draft, so Full Validation's run concludes success with every job
        # skipped; save a marker for the next tree that names that run from a
        # changed workflow; push the head back and mark the pull request ready.
        path = ".github/workflows/ci.yml"
        draft = self.run_workflow(path, 160, self.repo.merge, self.repo.head, draft=True)
        self.assertFalse(draft.gate_ran)
        self.assertIsNone(draft.saved)
        self.forge(path, 160)
        self.assertRanEverything(self.run_workflow(path, 161, self.repo.amended_merge, self.repo.amended))
        # Core Checks' no-op run: the marker skipped it, so it saved nothing.
        path = ".github/workflows/core-checks.yml"
        self.hub = self.new_hub()
        self.full_pass(path, run_id=162)
        no_op = self.run_workflow(path, 163, self.repo.amended_merge, self.repo.amended)
        self.assertSkipped(no_op)
        self.hub.api.state["caches"] = [entry for entry in self.hub.api.state["caches"] if "-r162-" not in entry["key"]]
        self.forge(path, 163)
        self.assertRanEverything(self.run_workflow(path, 164, self.repo.amended_merge, self.repo.amended))

    def test_a_pass_against_another_base_or_target_cannot_vouch(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                # The same head passed merged with the moved base, and into main.
                self.full_pass(path, run_id=170, merge=self.repo.moved_merge)
                self.full_pass(path, run_id=171, base_ref="main")
                self.forge(path, 170)
                self.forge(path, 171)
                self.assertRanEverything(self.run_workflow(path, 172, self.repo.amended_merge, self.repo.amended))

    def test_a_run_of_another_pull_request_on_the_same_branch_cannot_vouch(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                # Pull request 8, from the same head branch into main, passed.
                self.full_pass(path, run_id=175, base_ref="main", pr=PR + 1)
                self.forge(path, 175)
                self.assertRanEverything(self.run_workflow(path, 176, self.repo.amended_merge, self.repo.amended))

    def test_a_second_pull_request_or_a_retarget_always_runs_in_full(self) -> None:
        # Even an honest marker is not used once another pull request was
        # opened from the head branch, or once this one changed its base.
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path, case="second pull request"):
                self.hub = self.new_hub()
                self.full_pass(path, run_id=177)
                self.hub.api.open_pull(PR + 1, state="closed")
                run = self.run_workflow(path, 178, self.repo.amended_merge, self.repo.amended)
                self.assertRanEverything(run)
                self.assertIn("has 2 pull requests", "".join(run.log))
            with self.subTest(workflow=path, case="retarget"):
                self.hub = self.new_hub()
                self.full_pass(path, run_id=179)
                self.hub.api.state["timeline"][str(PR)].append({"event": "base_ref_changed"})
                run = self.run_workflow(path, 180, self.repo.amended_merge, self.repo.amended)
                self.assertRanEverything(run)
                self.assertIn("has a base event (base_ref_changed)", "".join(run.log))

    def test_a_run_older_than_the_pull_request_cannot_vouch(self) -> None:
        # Both workflows: a pass recorded before this pull request was created
        # (as a run of an earlier pull request from the same branch would be)
        # never vouches, even with a listing that shows only this pull request.
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                first = self.full_pass(path, run_id=400)
                created = self.hub.api.state["attempts"]["400:1"]["created_at"]
                self.hub.api.state["pulls"][0]["created_at"] = "2027-01-01T00:00:00Z"
                run = self.run_workflow(path, 401, self.repo.amended_merge, self.repo.amended)
                self.assertRanEverything(run)
                self.assertIn(f"run 400 was created at {created}, not after pull request #{PR}", "".join(run.log))
                self.assertIsNotNone(first.saved)

    def test_a_green_gate_without_the_proof_or_an_expired_proof_cannot_vouch(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                first = self.full_pass(path, run_id=180)
                self.hub.api.state["caches"].clear()
                self.hub.api.state["artifacts"].clear()
                self.forge(path, 180)
                self.assertRanEverything(self.run_workflow(path, 181, self.repo.amended_merge, self.repo.amended))
                self.hub.api.state["caches"].clear()
                self.hub.api.upload(180, first.proof, expired=True)
                self.hub.api.save_cache(first.saved)
                self.assertRanEverything(self.run_workflow(path, 182, self.repo.amended_merge, self.repo.amended))

    def test_a_proof_with_a_failed_gate_cannot_vouch(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                first = self.full_pass(path, run_id=185)
                jobs = self.hub.api.state["jobs"]["185:1"]
                for job in jobs:
                    if job["name"] == SKIPPING_WORKFLOWS[path]["gate_name"]:
                        job["conclusion"] = "failure"
                self.assertIsNotNone(first.saved)
                self.assertRanEverything(self.run_workflow(path, 186, self.repo.amended_merge, self.repo.amended))

    def test_a_run_cancelled_while_saving_does_not_hide_an_older_marker(self) -> None:
        # Required Merge Gate went green before the save job finished; the
        # signed push cancelled the run after its marker was saved. That
        # newest entry fails, and the older valid marker still counts.
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path, run_id=190)
                late = self.run_workflow(path, 191, self.repo.amended_merge, self.repo.amended,
                                         labels=(marker.FORCE_FULL_RUN_LABEL,), save_conclusion="cancelled")
                self.assertIsNotNone(late.saved)
                run = self.run_workflow(path, 192, self.repo.amended_merge, self.repo.amended)
                self.assertSkipped(run)
                self.assertIn("run 190 attempt 1 already passed", "".join(run.log))

    def test_a_cancelled_run_whose_save_job_finished_still_vouches(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                first = self.full_pass(path, run_id=195)
                # The run's own conclusion is not read: only its gate and save job.
                self.hub.api.state["attempts"]["195:1"]["conclusion"] = "cancelled"
                self.assertIsNotNone(first.saved)
                self.assertSkipped(self.run_workflow(path, 196, self.repo.amended_merge, self.repo.amended))

    # -- saving ------------------------------------------------------------------

    def test_a_rerun_of_the_writer_runs_in_full_and_saves_its_own_attempt(self) -> None:
        # "Re-run all jobs" keeps the run ID and is never answered from a
        # marker: it runs in full and saves a marker for its new attempt. So
        # does a re-run of a run that skipped.
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                first = self.full_pass(path)
                again = self.run_workflow(path, 100, self.repo.merge, self.repo.head, attempt=2)
                self.assertRanEverything(again)
                self.assertIn("attempt 2 is a re-run", "".join(again.log))
                self.assertEqual(again.saved, first.saved[: -len("-a1")] + "-a2")
                self.assertEqual(len(self.hub.api.state["caches"]), 2)
                self.assertSkipped(self.run_workflow(path, 101, self.repo.amended_merge, self.repo.amended))
                rerun = self.run_workflow(path, 101, self.repo.amended_merge, self.repo.amended, attempt=2)
                self.assertRanEverything(rerun)
                self.assertEqual(rerun.saved, f"{rerun.classify_outputs['tree_pass_key_prefix']}101-a2")

    def test_a_failed_rerun_of_the_vouching_run_stops_the_skip(self) -> None:
        # Attempt 1 passed and saved a marker; "Re-run all jobs" ran in full
        # and failed. The next run of the tree must not skip on attempt 1.
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                self.full_pass(path, run_id=300)
                failing = sorted(marked_jobs(path))[0]
                failed = self.run_workflow(path, 300, self.repo.merge, self.repo.head, attempt=2,
                                           job_results={failing: "failure"})
                self.assertNotEqual(failed.gate_result, "success", failed.log)
                run = self.run_workflow(path, 301, self.repo.amended_merge, self.repo.amended)
                self.assertRanEverything(run)
                self.assertIn("run 300 attempt 1: latest attempt", "".join(run.log))

    def test_a_later_full_run_of_the_tree_that_failed_stops_the_skip(self) -> None:
        # A ci:full-run run of the same tree failed or was cancelled; the
        # label came off. The unlabeled run must not skip on the older pass.
        for path in SKIPPING_WORKFLOWS:
            for result in ("failure", "cancelled"):
                with self.subTest(workflow=path, result=result):
                    self.hub = self.new_hub()
                    self.full_pass(path, run_id=310)
                    failing = sorted(marked_jobs(path))[-1]
                    forced = self.run_workflow(path, 311, self.repo.amended_merge, self.repo.amended,
                                               labels=(marker.FORCE_FULL_RUN_LABEL,), job_results={failing: result})
                    self.assertFalse(forced.skipped)
                    self.assertNotEqual(forced.gate_result, "success", forced.log)
                    run = self.run_workflow(path, 312, self.repo.amended_merge, self.repo.amended)
                    self.assertRanEverything(run)
                    self.assertIn("run 311 of this pull request, later than this one", "".join(run.log))
                    # That full run passes and saves; the next one skips on it.
                    self.assertSkipped(self.run_workflow(path, 313, self.repo.amended_merge, self.repo.amended))

    def test_a_stale_rerun_on_a_moved_merge_ref(self) -> None:
        # Full Validation's re-run checks out the merge ref as it is then; if
        # the base moved, it saves nothing. Core Checks re-runs test the
        # event's commit, so a moved merge ref does not stop its marker.
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                self.hub = self.new_hub()
                run = self.run_workflow(path, 200, self.repo.merge, self.repo.head, attempt=2,
                                        merge_ref_at_save=self.repo.moved_merge)
                self.assertEqual(run.gate_result, "success", run.log)
                if SKIPPING_WORKFLOWS[path]["merge_ref"]:
                    self.assertIsNone(run.saved)
                    self.assertIsNone(run.proof)
                else:
                    self.assertIsNotNone(run.saved)

    def test_a_run_that_did_not_fully_pass_saves_nothing(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            for job in sorted(marked_jobs(path) | SKIPPING_WORKFLOWS[path]["always"]):
                for result in ("failure", "cancelled"):
                    with self.subTest(workflow=path, job=job, result=result):
                        self.hub = self.new_hub()
                        run = self.run_workflow(path, 210, self.repo.merge, self.repo.head, job_results={job: result})
                        self.assertNotEqual(run.gate_result, "success", run.log)
                        self.assertIsNone(run.saved)
                        self.assertIsNone(run.proof)
                        self.assertEqual(self.hub.api.state["caches"], [])

    def test_a_skipped_or_cancelled_gate_saves_nothing(self) -> None:
        for path, config in SKIPPING_WORKFLOWS.items():
            for result in ("cancelled", "failure"):
                with self.subTest(workflow=path, result=result):
                    self.hub = self.new_hub()
                    run = self.run_workflow(path, 220, self.repo.merge, self.repo.head,
                                            job_results={config["gate"]: result})
                    self.assertIsNone(run.saved)

    def test_core_checks_into_a_testnet_line_saves(self) -> None:
        # The mainnet posture job is skipped by design for 0.1.x.
        path = ".github/workflows/core-checks.yml"
        run = self.run_workflow(path, 230, self.repo.merge, self.repo.head, base_ref="0.1.x", mainnet="false")
        self.assertEqual(run.results["mainnet-publish-gate"], "skipped")
        self.assertEqual(run.gate_result, "success", run.log)
        self.assertIsNotNone(run.saved, run.log)
        self.assertSkipped(self.run_workflow(path, 231, self.repo.amended_merge, self.repo.amended,
                                             base_ref="0.1.x", mainnet="false"))

    def test_a_draft_saves_only_what_it_ran(self) -> None:
        # Full Validation skips its jobs and its gate for a draft, so a draft
        # saves no Full Validation marker. Core Checks runs in full for a
        # draft, and a full pass of the tree is a pass however it was marked.
        ci, core = SKIPPING_WORKFLOWS
        run = self.run_workflow(ci, 240, self.repo.merge, self.repo.head, draft=True)
        self.assertEqual(set(run.expensive_results().values()), {"skipped"}, run.results)
        self.assertFalse(run.gate_ran)
        self.assertIsNone(run.saved)
        self.hub = self.new_hub()
        run = self.run_workflow(core, 241, self.repo.merge, self.repo.head, draft=True)
        self.assertRanEverything(run)
        self.assertEqual(run.saved, f"{run.classify_outputs['tree_pass_key_prefix']}241-a1")


# ---------------------------------------------------------------------------
# The wiring: what the simulation assumes about the workflow files
# ---------------------------------------------------------------------------


class WiringTest(unittest.TestCase):
    maxDiff = None

    def marker_steps(self, workflow: dict) -> dict[str, tuple[int, dict]]:
        steps = workflow["jobs"][CLASSIFY_JOB]["steps"]
        found = {step.get("id"): (index, step) for index, step in enumerate(steps) if step.get("id") in MARKER_STEPS}
        self.assertEqual(set(found), set(MARKER_STEPS))
        return found

    def test_the_marker_steps_follow_classification_and_cannot_fail_it(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                workflow = load(path)
                job = workflow["jobs"][CLASSIFY_JOB]
                steps = self.marker_steps(workflow)
                ids = [step.get("id") for step in job["steps"]]
                routing = [ids.index(name) for name in ("changed-files", "classify", "release-target") if name in ids]
                order = [steps[name][0] for name in MARKER_STEPS]
                self.assertEqual(order, sorted(order))
                self.assertGreater(order[0], max(routing))
                for name, (_, step) in steps.items():
                    self.assertIs(step.get("continue-on-error"), True, name)
                    self.assertIn("github.event_name == 'pull_request'", str(step.get("if")), name)
                key, lookup = steps["marker-key"][1], steps["marker-lookup"][1]
                self.assertEqual(lookup["uses"], f"actions/cache/restore@{CACHE_PIN}")
                self.assertEqual(lookup["with"]["path"], marker.MARKER_DIR)
                self.assertIs(lookup["with"]["lookup-only"], True)
                self.assertEqual(lookup["with"]["key"], "${{ steps.marker-key.outputs.key_prefix }}")
                self.assertEqual(lookup["with"]["restore-keys"], "${{ steps.marker-key.outputs.key_prefix }}")
                # The key hashes the very list the classifier routed by.
                self.assertEqual(key["env"]["CHANGED_FILES"], "${{ steps.changed-files.outputs.changed_files }}")
                classify = job["steps"][ids.index("classify")]
                self.assertIn('--changed-files "${{ steps.changed-files.outputs.changed_files }}"', classify["run"])
                # The salt is a number the script accepts, passed as it stands.
                self.assertRegex(key["env"]["TREE_PASS_MARKER_SALT"], marker.SALT_RE)
                self.assertIn('--salt "${TREE_PASS_MARKER_SALT}"', key["run"])
                decision = steps["marker-decision"][1]
                # The decision judges the saving run by this workflow's own gate and save jobs.
                config = SKIPPING_WORKFLOWS[path]
                self.assertIn(f"--gate-job '{config['gate_name']}'", decision["run"])
                self.assertIn(f"--save-job '{SAVE_JOB_NAME}'", decision["run"])
                self.assertEqual(workflow["jobs"][config["gate"]]["name"], config["gate_name"])
                self.assertEqual(workflow["jobs"][SAVE_JOB]["name"], SAVE_JOB_NAME)
                self.assertEqual(decision["env"]["PR_NUMBER"], "${{ github.event.pull_request.number }}")
                self.assertEqual(decision["env"]["HEAD_OWNER"], "${{ github.event.pull_request.head.repo.owner.login }}")
                self.assertEqual(decision["env"]["HEAD_REF"], "${{ github.event.pull_request.head.ref }}")
                self.assertEqual(decision["env"]["VALIDATION_PROFILE"], "${{ steps.classify.outputs.profile }}")
                self.assertEqual(decision["env"]["MATCHED_KEY"], "${{ steps.marker-lookup.outputs.cache-matched-key }}")
                self.assertEqual(decision["env"]["LOOKUP_OUTCOME"], "${{ steps.marker-lookup.outcome }}")
                # A re-run is never answered from a marker.
                self.assertIn('--run-attempt "${GITHUB_RUN_ATTEMPT}"', decision["run"])
                for step in (key, decision):
                    self.assertNotIn("${{", step["run"], "inputs reach the script through env only")

    def test_only_a_successful_decision_to_skip_skips(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            expression = load(path)["jobs"][CLASSIFY_JOB]["outputs"]["tree_pass_skip"]
            for outcome in ("success", "failure", "skipped", "cancelled", ""):
                for skip in ("true", "false", "", "TRUE ", None):
                    with self.subTest(workflow=path, outcome=outcome, skip=skip):
                        outputs = {} if skip is None else {"skip": skip}
                        steps = {"marker-decision": {"outcome": outcome, "outputs": outputs}}
                        expected = "true" if outcome == "success" and skip == "true" else "false"
                        self.assertEqual(render(expression, {"steps": steps}), expected)

    def test_every_expensive_job_is_skipped_by_the_marker_and_only_by_it(self) -> None:
        for path, config in SKIPPING_WORKFLOWS.items():
            jobs = load(path)["jobs"]
            marked = marked_jobs(path)
            self.assertTrue(marked)
            for name in sorted(marked | config["always"]):
                job = jobs[name]
                for skip, expected in (("true", name in config["always"]), ("false", True), ("", True)):
                    with self.subTest(workflow=path, job=name, skip=skip):
                        classify = {"result": "success", "outputs": {
                            "tree_pass_skip": skip, "source_validation_required": "true", "profile": "source",
                            "mainnet_publish_gate_required": "true"}}
                        needs = job.get("needs") or []
                        needs = [needs] if isinstance(needs, str) else needs
                        context = {
                            "github": {"event_name": "pull_request", "repository": REPOSITORY,
                                       "event": {"pull_request": {"draft": False, "labels": [],
                                                                  "head": {"repo": {"full_name": REPOSITORY}}}}},
                            "needs": {need: classify if need == CLASSIFY_JOB else {"result": "success"} for need in needs},
                        }
                        status = {"success": True, "failure": False, "cancelled": False}
                        self.assertIs(condition(job.get("if"), context, status), expected)
            for name in config["unmarked"] | config["always"]:
                with self.subTest(workflow=path, unmarked=name):
                    self.assertNotIn("tree_pass_skip", json.dumps(jobs[name]))

    def test_the_jobs_the_marker_never_skips_run_for_every_event_and_for_forks(self) -> None:
        # They run whenever the change routes to source: on every event, and
        # for a pull request from a fork as for one from this repository.
        for path, config in SKIPPING_WORKFLOWS.items():
            jobs = load(path)["jobs"]
            for name in sorted(config["always"]):
                for event in ("pull_request", *NON_PULL_REQUEST_EVENTS):
                    for head in (REPOSITORY, "someone/qbit"):
                        for skip in ("true", "false"):
                            with self.subTest(workflow=path, job=name, event=event, head=head, skip=skip):
                                context = {
                                    "github": {"event_name": event, "repository": REPOSITORY, "event": {
                                        "pull_request": {"draft": False, "labels": [],
                                                         "head": {"repo": {"full_name": head}}}}},
                                    "needs": {CLASSIFY_JOB: {"result": "success", "outputs": {
                                        "tree_pass_skip": skip, "source_validation_required": "true",
                                        "profile": "source"}}},
                                }
                                status = {"success": True, "failure": False, "cancelled": False}
                                self.assertIs(condition(jobs[name].get("if"), context, status), True)

    def test_the_jobs_the_marker_never_skips_cannot_fail_quietly(self) -> None:
        # No continue-on-error on the job or on any step: their failure must
        # reach the gate as failure.
        for path, config in SKIPPING_WORKFLOWS.items():
            jobs = load(path)["jobs"]
            for name in sorted(config["always"]):
                with self.subTest(workflow=path, job=name):
                    self.assertNotIn("continue-on-error", jobs[name])
                    for step in jobs[name]["steps"]:
                        self.assertNotIn("continue-on-error", step, step.get("name"))

    def test_the_contract_job_installs_pyyaml_only_when_missing_and_retries(self) -> None:
        step = next(step for step in load(".github/workflows/core-checks.yml")["jobs"][CONTRACT_JOB]["steps"]
                    if "apt-get" in str(step.get("run", "")))
        # Every apt-get runs through the repository's retry helper.
        commands = [line.strip() for line in step["run"].splitlines() if "apt-get" in line]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertRegex(command, r"^ci/retry/retry --tries=\d+ .*-- sudo apt-get ")
        with tempfile.TemporaryDirectory(prefix="tree-pass-apt-") as scratch:
            fake = Path(scratch)
            calls = fake / "calls"
            fail_once = fake / "fail-once"
            (fake / "sudo").write_text(
                "#!/usr/bin/env bash\n"
                f'printf "%s\\n" "$*" >> {shlex.quote(str(calls))}\n'
                f'if [[ -e {shlex.quote(str(fail_once))} ]]; then rm {shlex.quote(str(fail_once))}; exit 100; fi\n',
                encoding="utf8",
            )
            (fake / "sudo").chmod(0o755)
            env = {"PATH": f"{fake}{os.pathsep}{os.environ.get('PATH', '')}", "HOME": scratch}
            # With PyYAML in the system Python (as where this suite runs with
            # it) nothing is installed; without it, both commands run once.
            has_yaml = subprocess.run(["/usr/bin/python3", "-c", "import yaml"], capture_output=True,
                                      check=False).returncode == 0
            completed = run_bash_step(step["run"], REPO_ROOT, env)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            if has_yaml:
                self.assertFalse(calls.exists())
            else:
                self.assertEqual(calls.read_text(encoding="utf8").splitlines(), [
                    "apt-get update", "apt-get install -y --no-install-recommends python3-yaml"])
                calls.unlink()
            # Without it, a failed apt-get is retried and the step passes.
            script = step["run"].replace("/usr/bin/python3 -c 'import yaml'", "false")
            script = re.sub(r"--min=\d+ --max=\d+", "--min=0 --max=0", script)
            self.assertNotEqual(script, step["run"])
            fail_once.write_text("", encoding="utf8")
            completed = run_bash_step(script, REPO_ROOT, env)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(calls.read_text(encoding="utf8").splitlines(), [
                "apt-get update", "apt-get update",
                "apt-get install -y --no-install-recommends python3-yaml"])

    def test_the_lints_that_read_history_run_in_a_job_the_marker_never_skips(self) -> None:
        jobs = load(".github/workflows/ci.yml")["jobs"]
        job = jobs["lint-commit-range"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        step = job["steps"][-1]
        lints = re.findall(r"--lint=(\w+)", step["run"])
        self.assertEqual(sorted(lints), sorted(HISTORY_LINTS))
        # Each is a lint the test runner knows by that name.
        runner = (REPO_ROOT / "test/lint/test_runner/src/main.rs").read_text(encoding="utf8")
        for lint in HISTORY_LINTS:
            self.assertIn(f'name: "{lint}",', runner, lint)
        # What the step exports and runs is checked by running it
        # (test_lint_commit_range_lints_the_merge_commits_range). The subtree
        # lint's gpg comes with the hosted image; nothing is installed.
        self.assertEqual([step.get("uses", "").split("@")[0] or "run" for step in job["steps"]],
                         ["actions/checkout", "run"])
        self.assertEqual(job["steps"][0]["with"]["fetch-depth"], 0)
        # The lint job's own range: the same, from the same checkout of the merge.
        self.assertEqual(job["steps"][0]["with"]["ref"], jobs["lint"]["steps"][0]["with"]["ref"])

    def test_the_gate_and_the_save_job_stand_for_every_skipped_job(self) -> None:
        for path, config in SKIPPING_WORKFLOWS.items():
            with self.subTest(workflow=path):
                jobs = load(path)["jobs"]
                marked = marked_jobs(path) | config["always"]
                gate = jobs[config["gate"]]
                self.assertEqual(gate["name"], config["gate_name"])
                self.assertEqual(set(gate["needs"]), marked | {CLASSIFY_JOB})
                self.assertIn("always()", gate["if"])
                self.assertNotIn("tree_pass", gate["if"], "the gate job itself always runs")
                save = jobs[SAVE_JOB]
                self.assertEqual(set(save["needs"]), marked | {CLASSIFY_JOB, config["gate"]})
                checkout = save["steps"][0]
                self.assertRegex(checkout["uses"], r"^actions/checkout@[0-9a-f]{40}$")
                self.assertEqual(checkout["with"].get("persist-credentials"), False)
                self.assertNotIn("ref", checkout["with"], "the save job checks out the commit under test")
                plan = next(step for step in save["steps"] if step.get("id") == "plan")
                self.assertEqual(plan["env"]["NEEDS_JSON"], "${{ toJSON(needs) }}")
                self.assertIn("--classify-job classify-changes", plan["run"])
                self.assertIn(f"--marker-dir {marker.MARKER_DIR}", plan["run"])
                self.assertIn('--run-attempt "${GITHUB_RUN_ATTEMPT}"', plan["run"])
                self.assertEqual("--check-merge-ref" in plan["run"], config["merge_ref"])
                self.assertEqual(re.findall(r"--optional-job (\S+)", plan["run"]),
                                 [f"{job}={output}" for job, output in config["optional"].items()])
                ids = [step.get("id") for step in save["steps"]]
                proof = save["steps"][ids.index("proof")]
                self.assertEqual(proof["uses"], f"actions/upload-artifact@{UPLOAD_PIN}")
                self.assertEqual(proof["if"], "steps.plan.outputs.save == 'true'")
                self.assertIs(proof.get("continue-on-error"), True)
                self.assertEqual(proof["with"]["name"], "${{ steps.plan.outputs.artifact }}")
                self.assertEqual(proof["with"]["path"], f"{marker.MARKER_DIR}/{marker.MARKER_FILE}")
                self.assertIs(proof["with"]["include-hidden-files"], True)
                self.assertEqual(proof["with"]["if-no-files-found"], "error")
                store = next(step for step in save["steps"] if "uses" in step and "cache" in step["uses"])
                self.assertLess(ids.index("proof"), save["steps"].index(store), "the proof exists before the marker")
                self.assertEqual(store["uses"], f"actions/cache/save@{CACHE_PIN}")
                self.assertEqual(store["with"]["path"], marker.MARKER_DIR)
                self.assertEqual(store["with"]["key"], "${{ steps.plan.outputs.key }}")
                self.assertEqual(store["if"], "steps.plan.outputs.save == 'true' && steps.proof.outcome == 'success'")
                self.assertIs(store.get("continue-on-error"), True)

    def test_the_save_job_starts_only_after_a_full_pull_request_pass(self) -> None:
        # The first of two layers: the save plan checks every job again.
        for path, config in SKIPPING_WORKFLOWS.items():
            save = load(path)["jobs"][SAVE_JOB]
            for event in ("pull_request", *NON_PULL_REQUEST_EVENTS):
                for skip in ("false", "true", ""):
                    for gate in ("success", "failure", "cancelled", "skipped"):
                        for profile in ("source", "public-docs", "rpc-docs", "release-policy", "github-metadata", ""):
                            with self.subTest(workflow=path, event=event, skip=skip, gate=gate, profile=profile):
                                needs = {name: {"result": "success", "outputs": {}} for name in save["needs"]}
                                needs[CLASSIFY_JOB]["outputs"] = {"tree_pass_skip": skip, "profile": profile}
                                needs[config["gate"]]["result"] = gate
                                context = {"github": {"event_name": event}, "needs": needs}
                                results = {name: job["result"] for name, job in needs.items()}
                                expected = (event == "pull_request" and skip == "false" and gate == "success"
                                            and profile == "source")
                                self.assertIs(condition(save["if"], context, job_status(save, results)), expected)

    def test_the_gate_accepts_a_skip_only_when_the_marker_skipped(self) -> None:
        for path, config in SKIPPING_WORKFLOWS.items():
            jobs = load(path)["jobs"]
            gate = jobs[config["gate"]]
            step = next(step for step in gate["steps"] if "CLASSIFY_CHANGES_RESULT" in step.get("env", {}))
            results = {name: f"${{{{ needs.{name}.result }}}}" for name in gate["needs"]}
            leaves = [name for name, binding in step["env"].items()
                      if binding in results.values() and "classify-changes" not in binding]
            self.assertEqual(len(leaves), len(gate["needs"]) - 1, step["env"])
            always = [name for name, binding in step["env"].items()
                      if binding in [results[job] for job in config["always"]]]
            self.assertEqual(len(always), len(config["always"]))

            def run_gate(event: str, skip: str, **overrides: str) -> tuple[int, str]:
                env = {name: render(value, {
                    "github": {"event_name": event},
                    "needs": {
                        CLASSIFY_JOB: {"result": "success", "outputs": {
                            "tree_pass_skip": skip, "source_validation_required": "true", "profile": "source",
                            "mainnet_publish_gate_required": "true"}},
                        **{name: {"result": "skipped" if skip == "true" and name not in config["always"] else "success",
                                  "outputs": {}}
                           for name in gate["needs"] if name != CLASSIFY_JOB},
                    },
                }) for name, value in step["env"].items()}
                env.update(overrides)
                env["PATH"] = os.environ.get("PATH", "")
                completed = run_bash_step(step["run"], REPO_ROOT, env)
                return completed.returncode, completed.stdout + completed.stderr

            with self.subTest(workflow=path, case="marker skip"):
                code, output = run_gate("pull_request", "true")
                self.assertEqual(code, 0, output)
                self.assertIn("This tree already passed", output)
            with self.subTest(workflow=path, case="full run"):
                code, output = run_gate("pull_request", "false")
                self.assertEqual(code, 0, output)
                self.assertNotIn("already passed", output)
            for leaf in always:
                with self.subTest(workflow=path, case="a job the marker never skips was skipped", leaf=leaf):
                    code, output = run_gate("pull_request", "true", **{leaf: "skipped"})
                    self.assertNotEqual(code, 0, output)
                    self.assertIn("result was skipped.", output)
            for leaf in leaves:
                for result in ("failure", "cancelled"):
                    with self.subTest(workflow=path, case="failure in a marker skip", leaf=leaf, result=result):
                        code, output = run_gate("pull_request", "true", **{leaf: result})
                        self.assertNotEqual(code, 0, output)
                        self.assertIn(f"result was {result}.", output)
                for skip in ("false", "", "TRUE", "yes"):
                    with self.subTest(workflow=path, case="unexpected skip", leaf=leaf, skip=skip):
                        code, output = run_gate("pull_request", skip, **{leaf: "skipped"})
                        self.assertNotEqual(code, 0, output)
                        self.assertIn("result was skipped.", output)
            for event in NON_PULL_REQUEST_EVENTS:
                with self.subTest(workflow=path, case="skip outside a pull request", event=event):
                    code, output = run_gate(event, "true")
                    self.assertNotEqual(code, 0, output)
                    self.assertIn("only pull requests skip", output)
            with self.subTest(workflow=path, case="classification failed"):
                code, output = run_gate("pull_request", "true", CLASSIFY_CHANGES_RESULT="failure")
                self.assertNotEqual(code, 0, output)
            # A change routed to another profile runs none of these jobs, not
            # even the ones the marker never skips, and passes the gate.
            for profile in ("public-docs", "rpc-docs", "release-policy", "github-metadata"):
                with self.subTest(workflow=path, case="not source", profile=profile):
                    code, output = run_gate("pull_request", "false", SOURCE_VALIDATION_REQUIRED="false",
                                            VALIDATION_PROFILE=profile, MAINNET_PUBLISH_GATE_REQUIRED="false",
                                            **{leaf: "skipped" for leaf in leaves})
                    self.assertEqual(code, 0, output)
                    self.assertIn(f"Validation profile {profile} does not require", output)

    def test_permissions_stay_minimal(self) -> None:
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                workflow = load(path)
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                for name, job in workflow["jobs"].items():
                    expected = ({"contents": "read", "actions": "read", "pull-requests": "read"}
                                if name == CLASSIFY_JOB else None)
                    self.assertEqual(job.get("permissions"), expected, name)

    def test_the_marker_steps_use_the_action_versions_they_were_checked_with(self) -> None:
        # Only the marker's own steps are read: a pin bump in any other step,
        # of these workflows or of any other, is not this suite's business.
        # actions/cache's lookup-only, restore-keys and cache-matched-key and
        # upload-artifact's include-hidden-files were checked for these
        # releases, and the lookup and the save must agree on the cache version.
        expected = {"actions/cache/restore": CACHE_PIN, "actions/cache/save": CACHE_PIN,
                    "actions/upload-artifact": UPLOAD_PIN}
        for path in SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                jobs = load(path)["jobs"]
                steps = [step for step in jobs[CLASSIFY_JOB]["steps"] if step.get("id") in MARKER_STEPS]
                steps += jobs[SAVE_JOB]["steps"]
                pins = dict(str(step["uses"]).split("@", 1) for step in steps if "uses" in step)
                self.assertEqual(set(pins), set(expected) | {"actions/checkout"})
                for action, pin in pins.items():
                    self.assertRegex(pin, r"^[0-9a-f]{40}$", action)
                    if action in expected:
                        self.assertEqual(pin, expected[action], action)

    def test_rulesets_never_require_a_check_the_marker_skips(self) -> None:
        # A job skipped at job level reports skipped, which a required check
        # accepts, but a skipped matrix job reports only its unexpanded name.
        # The marker skips matrix jobs at job level, so no ruleset may require
        # any name they report.
        skippable: set[str] = set()
        for path in SKIPPING_WORKFLOWS:
            jobs = load(path)["jobs"]
            for name in marked_jobs(path):
                job = jobs[name]
                skippable.update({name, str(job.get("name", name))})
                for entry in (job.get("strategy") or {}).get("matrix", {}).get("include", []) or []:
                    rendered = re.sub(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}", lambda m: str(entry.get(m.group(1), "")),
                                      str(job.get("name", "")))
                    skippable.add(rendered)
        required = set()
        for path in sorted((REPO_ROOT / ".github/rulesets").glob("*.json")):
            for rule in json.loads(path.read_text(encoding="utf8")).get("rules", []):
                if rule.get("type") == "required_status_checks":
                    required.update(check["context"] for check in rule["parameters"]["required_status_checks"])
        self.assertIn("Required Merge Gate", required)
        self.assertFalse(required & skippable, sorted(required & skippable))

    def test_the_merge_gate_polls_only_gate_jobs_for_the_profile_that_skips(self) -> None:
        script = next(step["run"] for step in load(GATE_WORKFLOW)["jobs"]["required-merge-gate"]["steps"]
                      if "wait_for_checks" in str(step.get("run", "")))
        branch = re.search(r"^\s*source\)\n(?P<body>.*?)^\s*;;", script, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(branch)
        polled = re.findall(r'"([^"]+)"', re.search(r"wait_for_checks (.*)", branch.group("body")).group(1))
        gates = {config["gate_name"] for config in SKIPPING_WORKFLOWS.values()}
        self.assertEqual(set(polled), gates)
        self.assertEqual(marker.SKIP_PROFILE, "source")

    def test_core_checks_runs_this_suite_beside_its_other_jobs(self) -> None:
        # Not in Required Merge Gate's classification, which every pull
        # request waits for: in a Core Checks job that its gate requires.
        path = ".github/workflows/core-checks.yml"
        jobs = load(path)["jobs"]
        here = Path(__file__).name
        runs = [(name, index) for name, job in jobs.items() for index, step in enumerate(job.get("steps", []))
                if here in str(step.get("run", ""))]
        self.assertEqual(runs, [(CONTRACT_JOB, len(jobs[CONTRACT_JOB]["steps"]) - 1)])
        job = jobs[CONTRACT_JOB]
        self.assertEqual(job["needs"], CLASSIFY_JOB)
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        step = job["steps"][-1]
        for key in ("if", "continue-on-error", "uses", "shell"):
            self.assertNotIn(key, step)
        self.assertEqual(step["run"].strip(), f"/usr/bin/python3 ci/checks/{here} -v")
        self.assertIn("apt-get install -y --no-install-recommends python3-yaml", json.dumps(job["steps"][:-1]))
        self.assertIs(job["steps"][0]["with"]["persist-credentials"], False)
        # The marker never skips it, so a regression that skips wrongly
        # cannot skip the job that would catch it; the gate requires it to
        # succeed (the generic gate and save-job tests check how).
        self.assertNotIn("tree_pass_skip", json.dumps(job))
        self.assertIn(CONTRACT_JOB, SKIPPING_WORKFLOWS[path]["always"])
        self.assertNotIn(CONTRACT_JOB, marked_jobs(path))
        for other in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
            if other.name != Path(path).name:
                self.assertNotIn(here, other.read_text(encoding="utf8"), other.name)
        gate = json.dumps(load(GATE_WORKFLOW))
        for needle in ("tree_pass_skip", "marker-decision", "actions/cache", marker.FORCE_FULL_RUN_LABEL):
            self.assertNotIn(needle, gate, "the merge gate itself never skips")

    def test_heavy_and_manual_workflows_never_skip(self) -> None:
        for path in NEVER_SKIPPING_WORKFLOWS:
            with self.subTest(workflow=path):
                text = (REPO_ROOT / path).read_text(encoding="utf8")
                for needle in ("tree_pass", "tree-pass", "lookup-only", marker.FORCE_FULL_RUN_LABEL):
                    self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
