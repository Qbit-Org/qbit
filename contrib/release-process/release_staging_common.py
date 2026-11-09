# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shared helpers for the release SHA256SUMS staging, signing and combining tools.

The tools run from a clean qbit checkout whose HEAD is the trusted release ref.
The validators and the release key policy are read from the blobs at that ref,
exported into a private scratch directory, never from the working tree, and
there is deliberately no option or environment variable that points the tools
at a different keys.json.
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
ARMORED_SIGNATURE_BEGIN = b"-----BEGIN PGP SIGNATURE-----\n"
ARMORED_SIGNATURE_END = b"-----END PGP SIGNATURE-----\n"
INTERRUPT_SIGNALS = tuple(
    getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)
)


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


def run_main(body: Callable[[], int]) -> int:
    """Run a tool body, turning failures and interruptions into one ERR: line.

    SIGINT, SIGTERM and SIGHUP raise Interrupted, so every scratch directory is
    removed by its context manager before the tool exits; signals that were
    ignored when the tool started (for example under nohup) stay ignored.
    """

    def interrupted(signum: int, _frame: object) -> None:
        for handled in INTERRUPT_SIGNALS:
            signal.signal(handled, signal.SIG_IGN)
        raise Interrupted(signum)

    for handled in INTERRUPT_SIGNALS:
        if signal.getsignal(handled) is not signal.SIG_IGN:
            signal.signal(handled, interrupted)
    try:
        return body()
    except ReleaseToolError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 1
    except Interrupted as exc:
        print(
            f"ERR: interrupted by {signal.Signals(exc.signum).name}; scratch copies were removed "
            "and no output was written",
            file=sys.stderr,
        )
        return 128 + exc.signum
    except OSError as exc:
        print(f"ERR: {exc}; scratch copies were removed and no output was written", file=sys.stderr)
        return 1


def path_traverses_symlink(root: Path, relative: str) -> bool:
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


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
        header_end = batch.index(b"\n", offset)
        header = batch[offset:header_end].decode("ascii").split()
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise ReleaseToolError(f"Unexpected git cat-file output for {path}")
        size = int(header[2])
        content = batch[header_end + 1 : header_end + 1 + size]
        offset = header_end + 1 + size + 1
        target = destination.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def check_trusted_checkout(tool_path: Path, trusted_ref: str, *, git: str) -> tuple[Path, str]:
    """Return the root and HEAD of the checkout that holds ``tool_path``.

    The checkout must be at ``trusted_ref`` with nothing that git status hides:
    no index flags on the release paths, no ignored or untracked files beside
    the tools, and the running tool files byte-identical to their blobs.
    """

    if not COMMIT_SHA_RE.fullmatch(trusted_ref or ""):
        raise ReleaseToolError("--trusted-release-ref must be a full 40-character commit SHA")
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
    status = git_output(
        git,
        root,
        ["status", "--porcelain", "--untracked-files=normal"],
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
        ["status", "--porcelain", "--ignored", "--untracked-files=all", "--", TOOLS_RELATIVE_DIR],
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
        if running.read_bytes() != committed:
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
    with tempfile.TemporaryDirectory(prefix="qbit-trusted-ref-") as scratch:
        export_root = Path(scratch)
        export_trusted_tree(git, root, head, export_root)
        keys_dir = export_root / OPERATOR_KEYS_RELATIVE_DIR
        policy_path = keys_dir / "keys.json"
        if not policy_path.is_file():
            raise ReleaseToolError(f"Trusted ref {head} has no {OPERATOR_KEYS_RELATIVE_DIR}/keys.json")
        validators = load_validators(export_root / VALIDATORS_RELATIVE_DIR)
        yield TrustedRelease(root=root, ref=head, policy_path=policy_path, keys_dir=keys_dir, validators=validators)


@contextlib.contextmanager
def temporary_gnupg_home(prefix: str) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix=prefix) as home:
        path = Path(home)
        path.chmod(0o700)
        yield path


def note_stale_scratch(destination: Path) -> None:
    """Point out scratch left behind by a run that was killed outright."""

    for leftover in sorted(destination.parent.glob(f".{destination.name}.tmp-*")):
        note(f"scratch left by an interrupted run, safe to delete: {leftover}")


@contextlib.contextmanager
def scratch_dir_beside(destination: Path) -> Iterator[Path]:
    """Yield a private directory next to ``destination`` and always remove it.

    Outputs are assembled and verified there, then moved into place, so a failure
    never leaves a partial output at the destination path.
    """

    parent = destination.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    except OSError as exc:
        raise ReleaseToolError(f"Cannot create a scratch directory in {parent}: {exc}") from exc
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


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
        fsync_directory(destination.parent)
        return
    except FileExistsError as exc:
        raise ReleaseToolError(f"Refusing to overwrite {destination}; it appeared while this tool ran") from exc
    except OSError:
        pass

    # Filesystems without hard links, or a destination on another filesystem:
    # write a complete temporary file next to the destination, flush it, and
    # rename it into place, so the destination is never partially written.
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


def require_single_armored_signature(path: Path, data: bytes) -> None:
    """Require one ASCII-armored detached signature, so concatenation stays well formed."""

    try:
        data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReleaseToolError(f"{path.name} is not an ASCII-armored signature") from exc
    if (
        not data.startswith(ARMORED_SIGNATURE_BEGIN)
        or not data.endswith(ARMORED_SIGNATURE_END)
        or data.count(b"-----BEGIN PGP") != 1
        or data.count(b"-----END PGP") != 1
        or b"\r" in data
    ):
        raise ReleaseToolError(
            f"{path.name} must contain exactly one ASCII-armored PGP signature block with LF line endings"
        )


def verify_staged_files(
    validators: Validators,
    stage_dir: Path,
    policy: Any,
    *,
    manifest: Path | None = None,
) -> dict[str, Any]:
    """Check a stage directory against SHA256SUMS with the publisher's rules.

    ``manifest`` is the SHA256SUMS to check against; it defaults to the stage's
    own file and is a scratch copy when the caller must act on exactly the bytes
    it verified. The directory may hold, besides the listed artifacts and
    SHA256SUMS, only per-signer SHA256SUMS.<alias>.asc files of active release
    signers and SHA256SUMS.asc. Every listed artifact must be a regular file
    with the listed digest.
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
    missing = sorted((set(entries) | {CHECKSUMS_FILE}) - staged)
    extra = sorted(staged - allowed)
    if missing:
        raise ReleaseToolError("Stage directory is missing files listed in SHA256SUMS: " + ", ".join(missing))
    if extra:
        raise ReleaseToolError("Stage directory contains files not covered by SHA256SUMS: " + ", ".join(extra))
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
    parser.add_argument("--gpg", default=shutil.which("gpg") or "gpg")
    parser.add_argument("--git", default=shutil.which("git") or "git")
