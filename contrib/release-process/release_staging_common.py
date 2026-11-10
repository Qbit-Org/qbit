# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shared helpers for the release SHA256SUMS staging, signing and combining tools.

The tools run from a clean qbit checkout whose HEAD is the trusted release ref.
The validators and the release key policy are read from the blobs at that ref,
exported into a private scratch directory, never from the working tree, and
there is deliberately no option or environment variable that points the tools
at a different keys.json. Every git command, including the validators' own,
runs without the caller's GIT_* settings, replace refs or grafts, and with
config overrides that stop the system, user or repository config from running
programs (hooks, fsmonitor, filters, non-OpenPGP signature programs).
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable, Iterator


CHECKSUMS_FILE = "SHA256SUMS"
COMBINED_SIGNATURE_FILE = "SHA256SUMS.asc"
COMMIT_SHA_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
SHA256_HEX_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
TOOLS_RELATIVE_DIR = "contrib/release-process"
VALIDATORS_RELATIVE_DIR = "ci/release"
OPERATOR_KEYS_RELATIVE_DIR = "contrib/keys/operator-keys"
TRUSTED_PATHS = (TOOLS_RELATIVE_DIR, VALIDATORS_RELATIVE_DIR, "contrib/keys")
EXPORTED_PATHS = (VALIDATORS_RELATIVE_DIR, OPERATOR_KEYS_RELATIVE_DIR)
VALIDATOR_MODULES = (
    "validate_key_metadata",
    "validate_release_artifacts",
    "validate_builder_attestations",
)
INTERRUPT_SIGNALS = tuple(
    getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)
)
GIT = shutil.which("git") or "git"
DEFAULT_GPG = shutil.which("gpg") or "gpg"
# Hidden files the tools create next to an output while writing it; one found
# inside a stage directory was left by a run that was killed outright.
INTERRUPTED_LEFTOVER_RE = re.compile(r"^\..+\.tmp-")
SIGN_MOUNT_POINT_ADVICE = (
    "the signature is assembled in a private directory next to --stage-dir, outside the mount, where "
    "it usually cannot be written; keep the stage in a directory inside the mount"
)

# A path no program or directory can exist at: /dev/null is not a directory.
NO_PROGRAM = os.path.join(os.devnull, "disabled")
# Config every git command runs with, whatever the system, user or repository
# config says: nothing may run a program or change which history is read.
SAFE_GIT_CONFIG = (
    # The graft file is the empty /dev/null; this only silences git's hint
    # that graft files are deprecated.
    ("advice.graftFileDeprecated", "false"),
    # Empty, not "false": git before 2.36 reads core.fsmonitor as a hook
    # command and would run "false"; every version reads empty as off.
    ("core.fsmonitor", ""),
    ("core.hooksPath", NO_PROGRAM),
    # A commit-graph file can claim other parents, as a graft could.
    ("core.commitGraph", "false"),
    # git verify-tag runs the program of the signature's format. The
    # validators pass gpg.program with git -c, which outranks these, for
    # OpenPGP; SSH and X.509 never verify.
    ("gpg.ssh.program", NO_PROGRAM),
    ("gpg.x509.program", NO_PROGRAM),
    # Any other OpenPGP check, such as a %G? export-subst placeholder in
    # git archive, runs nothing.
    ("gpg.program", NO_PROGRAM),
    # git archive's default file modes, so the source archive has the bytes
    # builders made (require_git pins its compression).
    ("tar.umask", "0002"),
)
# Environment every git command runs with, besides the config above: no pager,
# and no fetch of any kind, so a partial-clone remote in the checkout's config
# cannot make a missing object run ssh, a remote helper or a credential helper.
SAFE_GIT_ENVIRONMENT = (
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_GRAFT_FILE", os.devnull),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_PAGER", "cat"),
    ("GIT_NO_LAZY_FETCH", "1"),
    # Only the protocol "none", which does not exist; this outranks any
    # protocol.allow or protocol.<name>.allow config.
    ("GIT_ALLOW_PROTOCOL", "none"),
)
# GIT_CONFIG_COUNT arrived in git 2.31; older git would ignore the overrides.
MIN_GIT_VERSION = (2, 31)
# From git 2.38 git archive compresses .tar.gz itself unless
# tar.<format>.command says otherwise; before, its default was gzip -cn.
INTERNAL_GZIP_GIT_VERSION = (2, 38)
GIT_VERSION_RE = re.compile(r"git version (\d+)\.(\d+)")
# The driver name may be empty: [filter ""] is a valid driver for "filter=".
FILTER_KEY_RE = re.compile(rb"filter\.(.*)\.(?:clean|smudge|process|required)")

# Scratch directories this run created and has not removed yet, and outputs it
# has moved into place, so that an error reports what is actually on disk.
_SCRATCH: set[Path] = set()
_WRITTEN: list[Path] = []
# The config overrides set_git_config last passed to git.
_GIT_CONFIG: list[tuple[str, str]] = []


class ReleaseToolError(Exception):
    """Raised when a release tool must stop without producing output."""


class Interrupted(BaseException):
    """Raised from a signal handler so that scratch cleanup still runs."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


@dataclass(frozen=True)
class Validators:
    key_metadata: ModuleType
    release_artifacts: ModuleType
    builder_attestations: ModuleType

    @property
    def errors(self) -> tuple[type[Exception], ...]:
        return (
            self.key_metadata.MetadataError,
            self.release_artifacts.ReleaseValidationError,
            self.builder_attestations.BuilderValidationError,
        )


@dataclass(frozen=True)
class TrustedRelease:
    """The trusted checkout plus the validators and policy exported from its ref."""

    root: Path
    ref: str
    policy_path: Path
    keys_dir: Path
    validators_dir: Path
    validators: Validators


def one_line(error: object) -> str:
    return " ".join(str(error).split())


def emit(key: str, value: object) -> None:
    print(f"{key}={value}")


def note(message: str) -> None:
    print(f"note: {message}", file=sys.stderr)


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        if input_bytes is not None:
            result = subprocess.run(
                command, check=False, capture_output=True, cwd=cwd, env=env, input=input_bytes
            )
            return subprocess.CompletedProcess(
                result.args,
                result.returncode,
                result.stdout.decode("utf8", errors="replace"),
                result.stderr.decode("utf8", errors="replace"),
            )
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf8",
            errors="replace",
        )
    except OSError as exc:
        raise ReleaseToolError(f"Failed to run {command[0]}: {exc}") from exc


def git_output(git: str, cwd: Path, args: list[str], *, action: str) -> str:
    result = run_command([git, "-C", str(cwd), *args])
    if result.returncode != 0:
        detail = one_line(result.stderr or result.stdout)
        raise ReleaseToolError(f"Failed to {action}" + (f": {detail}" if detail else ""))
    return result.stdout


def git_bytes(git: str, cwd: Path, args: list[str], *, action: str, stdin: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            [git, "-C", str(cwd), *args], check=False, capture_output=True, input=stdin
        )
    except OSError as exc:
        raise ReleaseToolError(f"Failed to run {git}: {exc}") from exc
    if result.returncode != 0:
        detail = one_line(result.stderr.decode("utf8", errors="replace"))
        raise ReleaseToolError(f"Failed to {action}" + (f": {detail}" if detail else ""))
    return result.stdout


def set_git_config(overrides: list[tuple[str, str]]) -> None:
    """Pass ``overrides`` to every git command this process starts.

    GIT_CONFIG_COUNT/KEY/VALUE outrank the system, user and repository config;
    only an explicit ``git -c`` outranks them, which is how the validators
    pass gpg.program.
    """

    for name in [name for name in os.environ if name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))]:
        del os.environ[name]
    os.environ["GIT_CONFIG_COUNT"] = str(len(overrides))
    for index, (key, value) in enumerate(overrides):
        os.environ[f"GIT_CONFIG_KEY_{index}"] = key
        os.environ[f"GIT_CONFIG_VALUE_{index}"] = value


def harden_git_environment() -> None:
    """Make every git command, the tools' and the validators', read real objects.

    The caller's GIT_* variables (GIT_DIR, GIT_INDEX_FILE, object directories,
    config overrides, replace-ref bases, ...) are dropped, replace refs are
    ignored, the graft file is replaced by an empty one, git status never
    writes the index, nothing pages and nothing is fetched
    (SAFE_GIT_ENVIRONMENT). SAFE_GIT_CONFIG then overrides whatever the system,
    user or repository config says about programs git may run and history it
    reads; require_git pins git archive's compression and
    disable_filter_drivers adds the filter drivers a checkout defines.
    """

    for name in [name for name in os.environ if name.startswith("GIT_")]:
        del os.environ[name]
    os.environ.update(SAFE_GIT_ENVIRONMENT)
    _GIT_CONFIG[:] = list(SAFE_GIT_CONFIG)
    set_git_config(_GIT_CONFIG)


def add_git_config(overrides: list[tuple[str, str]]) -> None:
    known = {key for key, _value in _GIT_CONFIG}
    _GIT_CONFIG.extend(item for item in overrides if item[0] not in known)
    set_git_config(_GIT_CONFIG)


def require_git(git: str) -> None:
    """Refuse a git too old for the overrides, and pin git archive's compression.

    git archive pipes a .tar.gz through tar.tar.gz.command (tar.tgz.command),
    which config could set to any program; it is pinned to git's own default
    for this version. Config that only changes the archive's bytes (for example
    core.autocrlf or attributes in .git/info) cannot run anything; the archive
    then does not match the attested one and staging stops.
    """

    result = run_command([git, "version"])
    match = GIT_VERSION_RE.match(result.stdout) if result.returncode == 0 else None
    if match is None:
        raise ReleaseToolError(f"Cannot tell which git {git} is: {one_line(result.stderr or result.stdout)}")
    version = (int(match.group(1)), int(match.group(2)))
    if version < MIN_GIT_VERSION:
        raise ReleaseToolError(
            f"{git} is git {version[0]}.{version[1]}; the release tools need git "
            f"{MIN_GIT_VERSION[0]}.{MIN_GIT_VERSION[1]} or newer, whose GIT_CONFIG_COUNT keeps the "
            "checkout's config from running programs"
        )
    gzip = "git archive gzip" if version >= INTERNAL_GZIP_GIT_VERSION else "gzip -cn"
    add_git_config([("tar.tar.gz.command", gzip), ("tar.tgz.command", gzip)])


def disable_filter_drivers(git: str, root: Path) -> None:
    """Turn off every clean, smudge and process filter git config defines for ``root``.

    Attributes can route any path through a filter driver, and git status and
    git archive run them; a driver git has no command for is a no-op. Drivers
    are named in config, so they are read from it and each one gets empty
    commands and required=false.
    """

    listing = git_bytes(git, root, ["config", "--list", "--name-only", "-z"], action="read the git config")
    # Keys are bytes: a driver name, like any subsection, need not be UTF-8.
    # os.fsdecode is the inverse of how os.environ encodes, so git gets back
    # exactly those bytes whatever the locale.
    drivers = sorted(
        {os.fsdecode(match.group(1)) for raw in listing.split(b"\0") if (match := FILTER_KEY_RE.fullmatch(raw))}
    )
    add_git_config(
        [
            (f"filter.{driver}.{setting}", value)
            for driver in drivers
            for setting, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false"))
        ]
    )


@contextlib.contextmanager
def interrupts_blocked() -> Iterator[None]:
    """Hold SIGINT, SIGTERM and SIGHUP until the block ends, so cleanup finishes."""

    if not hasattr(signal, "pthread_sigmask"):
        yield
        return
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPT_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def remove_tree(path: Path) -> None:
    with interrupts_blocked():
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            _SCRATCH.discard(path)


@contextlib.contextmanager
def private_directory(prefix: str, parent: Path | None = None) -> Iterator[Path]:
    """Yield a new 0700 directory and remove it, uninterrupted, when done."""

    with interrupts_blocked():
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
        _SCRATCH.add(path)
    try:
        yield path
    finally:
        remove_tree(path)


def record_written(path: Path) -> None:
    _WRITTEN.append(path)


def disk_state() -> str:
    left = sorted(str(path) for path in _SCRATCH if path.exists())
    scratch = "scratch left behind, safe to delete: " + ", ".join(left) if left else "scratch copies were removed"
    written = "already written: " + ", ".join(map(str, _WRITTEN)) if _WRITTEN else "no output was written"
    return f"{scratch}; {written}"


def run_main(body: Callable[[], int]) -> int:
    """Run a tool body, turning failures and interruptions into one ERR: line.

    SIGINT, SIGTERM and SIGHUP raise Interrupted, so every scratch directory is
    removed by its context manager before the tool exits; signals arriving
    while a directory is being removed wait until it is gone. Signals that were
    ignored when the tool started (for example under nohup) stay ignored. The
    message reports what is actually left on disk.
    """

    def interrupted(signum: int, _frame: object) -> None:
        for handled in INTERRUPT_SIGNALS:
            signal.signal(handled, signal.SIG_IGN)
        raise Interrupted(signum)

    harden_git_environment()
    _SCRATCH.clear()
    _WRITTEN.clear()
    previous = {handled: signal.getsignal(handled) for handled in INTERRUPT_SIGNALS}
    for handled, disposition in previous.items():
        if disposition is not signal.SIG_IGN:
            signal.signal(handled, interrupted)
    try:
        return body()
    except ReleaseToolError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1
    except Interrupted as exc:
        print(f"ERR: interrupted by {signal.Signals(exc.signum).name}; {disk_state()}", file=sys.stderr)
        return 128 + exc.signum
    except OSError as exc:
        print(f"ERR: {exc}; {disk_state()}", file=sys.stderr)
        return 1
    finally:
        for handled, disposition in previous.items():
            if disposition is not None:
                signal.signal(handled, disposition)


def export_trusted_tree(git: str, root: Path, ref: str, destination: Path) -> None:
    """Write the blobs of EXPORTED_PATHS at ``ref`` into ``destination``.

    Reading the git objects rather than the working tree means index flags,
    ignored files and stale bytecode in the checkout cannot change what the
    validators or the policy are.
    """

    listing = git_bytes(
        git,
        root,
        ["ls-tree", "-r", "-z", "--full-tree", ref, "--", *EXPORTED_PATHS],
        action=f"list {', '.join(EXPORTED_PATHS)} at the trusted ref",
    )
    files: list[tuple[str, str]] = []
    prefixes = tuple(f"{path}/" for path in EXPORTED_PATHS)
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        try:
            mode, kind, oid = meta.decode("ascii").split()
            path = raw_path.decode("utf8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseToolError(f"Unexpected git ls-tree output at the trusted ref: {record!r}") from exc
        parts = PurePosixPath(path).parts
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or not path.startswith(prefixes)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ReleaseToolError(f"Trusted ref {ref} has a non-regular file at {path}")
        files.append((path, oid))
    if not files:
        raise ReleaseToolError(f"Trusted ref {ref} has none of {', '.join(EXPORTED_PATHS)}")

    batch = git_bytes(
        git,
        root,
        ["cat-file", "--batch"],
        action="read the trusted policy and validators",
        stdin="".join(f"{oid}\n" for _path, oid in files).encode("ascii"),
    )
    offset = 0
    for path, oid in files:
        try:
            header_end = batch.index(b"\n", offset)
            header = batch[offset:header_end].decode("ascii").split()
            if header == [oid, "missing"]:
                raise ReleaseToolError(f"The trusted checkout does not have the object of {path} ({oid})")
            if len(header) != 3 or header[0] != oid or header[1] != "blob":
                raise ValueError(header)
            size = int(header[2])
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseToolError(f"Unexpected git cat-file output for {path}") from exc
        content = batch[header_end + 1 : header_end + 1 + size]
        if len(content) != size or batch[header_end + 1 + size : header_end + 2 + size] != b"\n":
            raise ReleaseToolError(f"Truncated git cat-file output for {path}")
        offset = header_end + 1 + size + 1
        target = destination.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def refuse_partial_clone(git: str, root: Path, *, label: str) -> None:
    """Refuse a partial clone: git would fetch a missing object from its promisor remote.

    The environment forbids every fetch anyway; this says why up front.
    """

    def keys(config: list[str], *, unless: str | None = None) -> list[str]:
        lines = run_command([git, "-C", str(root), "config", *config]).stdout.splitlines()
        return [line.split()[0] for line in lines if line.strip() and (unless is None or not line.endswith(unless))]

    # extensions.partialClone names a remote, so any value counts.
    promisors = keys(["--get-regexp", r"^extensions\.partialclone$"]) + keys(
        ["--type=bool", "--get-regexp", r"^remote\..*\.promisor$"], unless=" false"
    )
    if promisors:
        raise ReleaseToolError(
            f"{label} must not be a partial clone ({', '.join(promisors)}): {root}; "
            "the release tools never fetch missing objects"
        )


def check_trusted_checkout(tool_path: Path, trusted_ref: str, *, git: str) -> tuple[Path, str]:
    """Return the root and HEAD of the checkout that holds ``tool_path``.

    The checkout must be at ``trusted_ref`` with nothing that git status hides:
    no index flags on the release paths, no ignored or untracked files beside
    the tools, and the running tool files byte-identical to their blobs.
    """

    if not COMMIT_SHA_RE.fullmatch(trusted_ref or ""):
        raise ReleaseToolError("--trusted-release-ref must be a full 40-character commit SHA")
    require_git(git)
    tool_path = tool_path.resolve()
    toplevel = git_output(
        git,
        tool_path.parent,
        ["rev-parse", "--show-toplevel"],
        action="locate the trusted qbit checkout",
    ).strip()
    root = Path(toplevel).resolve()
    if tool_path.parent != root / TOOLS_RELATIVE_DIR:
        raise ReleaseToolError(
            f"{tool_path.name} must run from {TOOLS_RELATIVE_DIR} of the trusted qbit checkout, "
            f"not {tool_path.parent}"
        )
    head = git_output(
        git,
        root,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        action="resolve the trusted qbit checkout HEAD",
    ).strip().lower()
    if head != trusted_ref.lower():
        raise ReleaseToolError(
            f"Trusted qbit checkout {root} is at {head}, not --trusted-release-ref "
            f"{trusted_ref.lower()}"
        )
    shallow = git_output(
        git, root, ["rev-parse", "--is-shallow-repository"], action="check whether the checkout is shallow"
    ).strip()
    if shallow != "false":
        raise ReleaseToolError(f"Trusted qbit checkout must not be shallow: {root}")
    refuse_partial_clone(git, root, label="Trusted qbit checkout")
    disable_filter_drivers(git, root)
    # --ignore-submodules=dirty: a gitlink still shows, but git status does not
    # run inside a submodule checkout, whose own config could name filters.
    status = git_output(
        git,
        root,
        ["status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=dirty"],
        action="check that the trusted qbit checkout is clean",
    )
    if status.strip():
        raise ReleaseToolError(f"Trusted qbit checkout must be clean: {root}")

    # git status does not show files marked assume-unchanged (lowercase tag)
    # or skip-worktree (S); only plain tracked entries (H) are acceptable.
    flagged = [
        entry[2:]
        for entry in git_output(
            git, root, ["ls-files", "-v", "-z", "--", *TRUSTED_PATHS], action="list release paths"
        ).split("\0")
        if entry and not entry.startswith("H ")
    ]
    if flagged:
        raise ReleaseToolError(
            "Trusted qbit checkout has index flags (assume-unchanged or skip-worktree) on: "
            + ", ".join(sorted(flagged))
        )
    stray = git_output(
        git,
        root,
        [
            "status", "--porcelain", "--ignored", "--untracked-files=all", "--ignore-submodules=dirty",
            "--", TOOLS_RELATIVE_DIR,
        ],
        action="check the release tools directory",
    ).strip()
    if stray:
        raise ReleaseToolError(
            f"{TOOLS_RELATIVE_DIR} of the trusted qbit checkout must not contain untracked or ignored "
            "files: " + ", ".join(line[3:] for line in stray.splitlines())
            + f"; remove them, for example with git clean -fdx -- {TOOLS_RELATIVE_DIR}"
        )
    for running in (tool_path, Path(__file__).resolve()):
        relative = f"{TOOLS_RELATIVE_DIR}/{running.name}"
        committed = git_bytes(
            git, root, ["cat-file", "blob", f"{head}:{relative}"], action=f"read {relative} at the trusted ref"
        )
        working = running.read_bytes()
        if working != committed:
            if working.replace(b"\r\n", b"\n") == committed.replace(b"\r\n", b"\n"):
                raise ReleaseToolError(
                    f"{relative} differs from its blob at the trusted ref only in line endings: the checkout "
                    "converts them (core.autocrlf or an eol attribute). Use a checkout made with "
                    "core.autocrlf=false; the policy and validators are read from git objects either way"
                )
            raise ReleaseToolError(f"{relative} differs from its blob at the trusted ref")
    return root, head


def load_validators(validators_dir: Path) -> Validators:
    """Import the validators in ``validators_dir``, never a copy from elsewhere."""

    validators_dir = validators_dir.resolve()
    for name in VALIDATOR_MODULES:
        if not (validators_dir / f"{name}.py").is_file():
            raise ReleaseToolError(f"Trusted ref is missing {VALIDATORS_RELATIVE_DIR}/{name}.py")
        loaded = sys.modules.get(name)
        if loaded is not None and Path(getattr(loaded, "__file__", "") or "").resolve().parent != validators_dir:
            del sys.modules[name]
    if str(validators_dir) in sys.path:
        sys.path.remove(str(validators_dir))
    sys.path.insert(0, str(validators_dir))
    modules = [importlib.import_module(name) for name in VALIDATOR_MODULES]
    for module in modules:
        if Path(module.__file__ or "").resolve().parent != validators_dir:
            raise ReleaseToolError(f"Validator {module.__name__} was not loaded from {validators_dir}")
    return Validators(*modules)


@contextlib.contextmanager
def open_trusted_release(tool_path: Path, trusted_ref: str, *, git: str) -> Iterator[TrustedRelease]:
    """Check the trusted checkout and export its validators and policy into scratch."""

    root, head = check_trusted_checkout(tool_path, trusted_ref, git=git)
    with private_directory("qbit-trusted-ref-") as export_root:
        export_trusted_tree(git, root, head, export_root)
        keys_dir = export_root / OPERATOR_KEYS_RELATIVE_DIR
        policy_path = keys_dir / "keys.json"
        if not policy_path.is_file():
            raise ReleaseToolError(f"Trusted ref {head} has no {OPERATOR_KEYS_RELATIVE_DIR}/keys.json")
        validators_dir = export_root / VALIDATORS_RELATIVE_DIR
        validators = load_validators(validators_dir)
        yield TrustedRelease(
            root=root,
            ref=head,
            policy_path=policy_path,
            keys_dir=keys_dir,
            validators_dir=validators_dir,
            validators=validators,
        )


@contextlib.contextmanager
def temporary_gnupg_home(prefix: str) -> Iterator[Path]:
    with private_directory(prefix) as home:
        yield home


def note_stale_scratch(destination: Path) -> None:
    """Point out scratch left behind by a run that was killed outright."""

    for leftover in sorted(destination.parent.glob(f".{destination.name}.tmp-*")):
        note(f"scratch left by an interrupted run, safe to delete: {leftover}")


def refuse_mount_point(stage_dir: Path, advice: str) -> None:
    """Refuse a --stage-dir that is a mount point: its scratch would be outside the mount."""

    if os.path.ismount(stage_dir):
        raise ReleaseToolError(f"--stage-dir {stage_dir} is a mount point; {advice}")


@contextlib.contextmanager
def scratch_dir_beside(destination: Path) -> Iterator[Path]:
    """Yield a private directory next to ``destination`` and always remove it.

    Outputs are assembled and verified there, then moved into place, so a failure
    never leaves a partial output at the destination path.
    """

    parent = destination.parent
    with contextlib.ExitStack() as stack:
        try:
            parent.mkdir(parents=True, exist_ok=True)
            path = stack.enter_context(private_directory(f".{destination.name}.tmp-", parent))
        except OSError as exc:
            raise ReleaseToolError(f"Cannot create a scratch directory in {parent}: {exc}") from exc
        yield path


def current_umask() -> int:
    mask = os.umask(0o022)
    os.umask(mask)
    return mask


def fsync_directory(path: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def publish_file_no_clobber(source: Path, destination: Path) -> None:
    """Move verified ``source`` bytes to ``destination`` without replacing anything."""

    try:
        os.link(source, destination)
        record_written(destination)
        fsync_directory(destination.parent)
        return
    except FileExistsError as exc:
        raise ReleaseToolError(f"Refusing to overwrite {destination}; it appeared while this tool ran") from exc
    except OSError:
        pass

    # Filesystems without hard links, or a destination on another filesystem:
    # write a complete temporary file next to the destination, flush it, and
    # rename it into place, so the destination is never partially written.
    # Refusing to overwrite is best effort here: a file that appears between
    # the check and the rename is replaced. A run killed outright can leave the
    # temporary file, which the next run refuses with instructions.
    data = source.read_bytes()
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp, 0o666 & ~current_umask())
        if destination.exists() or destination.is_symlink():
            raise ReleaseToolError(f"Refusing to overwrite {destination}; it appeared while this tool ran")
        os.replace(temp, destination)
        record_written(destination)
        fsync_directory(destination.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular_file(path: Path, *, label: str) -> bytes:
    if path.is_symlink():
        raise ReleaseToolError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise ReleaseToolError(f"{label} not found: {path}")
    return path.read_bytes()


def normalize_expected_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    if not SHA256_HEX_RE.fullmatch(value):
        raise ReleaseToolError("--expected-sha256sums-sha256 must be a 64-character hex SHA-256 digest")
    return value.lower()


def require_directory(path: Path, *, label: str) -> Path:
    if not path.is_dir():
        raise ReleaseToolError(f"{label} is not a directory: {path}")
    return path.resolve()


def check_stage_names(
    validators: Validators,
    stage_dir: Path,
    policy: Any,
    *,
    manifest: Path | None = None,
    require_artifacts: bool = True,
) -> dict[str, Any]:
    """Check which files a stage directory holds, with the publisher's rules.

    ``manifest`` is the SHA256SUMS to check against; it defaults to the stage's
    own file and is a scratch copy when the caller must act on exactly the bytes
    it verified. Besides the listed artifacts and SHA256SUMS the directory may
    hold only per-signer SHA256SUMS.<alias>.asc files of active release signers
    and SHA256SUMS.asc; anything else, in particular a temporary file left by a
    killed run, is refused before it can reach the publisher.
    """

    vra = validators.release_artifacts
    try:
        staged = vra.staged_file_names(stage_dir)
        entries = vra.parse_sha256sums(manifest or stage_dir / CHECKSUMS_FILE)
        signatures = vra.release_signature_paths(stage_dir, staged, policy)
    except validators.errors as exc:
        raise ReleaseToolError(str(exc)) from exc

    if (stage_dir / CHECKSUMS_FILE).is_symlink():
        raise ReleaseToolError(f"{CHECKSUMS_FILE} must not be a symlink: {stage_dir / CHECKSUMS_FILE}")
    allowed = set(entries) | {CHECKSUMS_FILE, COMBINED_SIGNATURE_FILE}
    allowed |= {path.name for path in signatures.values()}
    required = (set(entries) if require_artifacts else set()) | {CHECKSUMS_FILE}
    missing = sorted(required - staged)
    extra = sorted(staged - allowed)
    leftovers = [name for name in extra if INTERRUPTED_LEFTOVER_RE.match(name)]
    if leftovers:
        raise ReleaseToolError(
            f"Stage directory {stage_dir} holds files left by an interrupted run; delete them and run again: "
            + ", ".join(leftovers)
        )
    if missing:
        raise ReleaseToolError("Stage directory is missing files listed in SHA256SUMS: " + ", ".join(missing))
    if extra:
        raise ReleaseToolError("Stage directory contains files not covered by SHA256SUMS: " + ", ".join(extra))
    return entries


def verify_staged_files(
    validators: Validators,
    stage_dir: Path,
    policy: Any,
    *,
    manifest: Path | None = None,
) -> dict[str, Any]:
    """check_stage_names, then every listed artifact must have its listed digest."""

    vra = validators.release_artifacts
    entries = check_stage_names(validators, stage_dir, policy, manifest=manifest)
    for name, entry in sorted(entries.items()):
        artifact = stage_dir / name
        if artifact.is_symlink():
            raise ReleaseToolError(f"Staged artifact must not be a symlink: {artifact}")
        actual = vra.sha256_file(artifact)
        if actual != entry.digest:
            raise ReleaseToolError(f"SHA256 mismatch for {name}: expected {entry.digest}, got {actual}")
    return entries


def add_common_arguments(parser: Any) -> None:
    parser.add_argument(
        "--trusted-release-ref",
        required=True,
        help="Full commit SHA of the clean qbit checkout this tool runs from.",
    )
    parser.add_argument("--release-line", required=True, choices=("testnet", "mainnet"))
    parser.add_argument(
        "--gpg",
        default=DEFAULT_GPG,
        help=(
            "gpg executable that makes every signature check and signature (default: gpg on PATH). "
            "It cannot change which keys.json or certificates are read, but it decides whether "
            "signatures verify; it exists for tests."
        ),
    )


def note_non_default_gpg(gpg: str) -> None:
    if gpg != DEFAULT_GPG:
        note(f"--gpg {gpg} makes every signature check; it is not the default {DEFAULT_GPG}")
