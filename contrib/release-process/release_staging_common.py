# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shared helpers for the release SHA256SUMS staging, signing and combining tools.

The tools run from a clean qbit checkout whose HEAD is the trusted release ref.
The validators and the release key policy are always read from that checkout:
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
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator


CHECKSUMS_FILE = "SHA256SUMS"
COMBINED_SIGNATURE_FILE = "SHA256SUMS.asc"
COMMIT_SHA_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
SHA256_HEX_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
TOOLS_RELATIVE_DIR = Path("contrib") / "release-process"
VALIDATORS_RELATIVE_DIR = Path("ci") / "release"
OPERATOR_KEYS_RELATIVE_DIR = Path("contrib") / "keys" / "operator-keys"
VALIDATOR_MODULES = (
    "validate_key_metadata",
    "validate_release_artifacts",
    "validate_builder_attestations",
)
ARMORED_SIGNATURE_BEGIN = b"-----BEGIN PGP SIGNATURE-----\n"
ARMORED_SIGNATURE_END = b"-----END PGP SIGNATURE-----\n"


class ReleaseToolError(Exception):
    """Raised when a release tool must stop without producing output."""


@dataclass(frozen=True)
class TrustedCheckout:
    root: Path
    ref: str
    policy_path: Path
    keys_dir: Path


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
) -> subprocess.CompletedProcess[str]:
    try:
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


def path_traverses_symlink(root: Path, relative: Path) -> bool:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def resolve_trusted_checkout(tool_path: Path, trusted_ref: str, *, git: str) -> TrustedCheckout:
    """Return the checkout that holds ``tool_path`` after checking it is the trusted ref.

    The checkout must be clean and its HEAD must equal ``trusted_ref`` so that the
    validators and keys.json the tools load are exactly the reviewed ones.
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

    policy_relative = OPERATOR_KEYS_RELATIVE_DIR / "keys.json"
    if path_traverses_symlink(root, policy_relative):
        raise ReleaseToolError(f"Release key policy path must not traverse a symlink: {root / policy_relative}")
    keys_dir = root / OPERATOR_KEYS_RELATIVE_DIR
    policy_path = root / policy_relative
    if not policy_path.is_file():
        raise ReleaseToolError(f"Trusted qbit checkout has no release key policy: {policy_path}")
    return TrustedCheckout(root=root, ref=head, policy_path=policy_path, keys_dir=keys_dir)


def load_validators(root: Path) -> Validators:
    """Import the ci/release validators of ``root``, never a copy from elsewhere."""

    validators_dir = (root / VALIDATORS_RELATIVE_DIR).resolve()
    for name in VALIDATOR_MODULES:
        if not (validators_dir / f"{name}.py").is_file():
            raise ReleaseToolError(f"Trusted qbit checkout is missing {VALIDATORS_RELATIVE_DIR / name}.py")
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
def temporary_gnupg_home(prefix: str) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix=prefix) as home:
        path = Path(home)
        path.chmod(0o700)
        yield path


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


def publish_file_no_clobber(source: Path, destination: Path) -> None:
    """Move verified ``source`` bytes to ``destination`` without replacing anything."""

    try:
        os.link(source, destination)
        return
    except FileExistsError as exc:
        raise ReleaseToolError(f"Refusing to overwrite {destination}; it appeared while this tool ran") from exc
    except OSError:
        pass

    # Filesystems without hard links: exclusive create, and remove the file
    # again if writing it fails.
    data = source.read_bytes()
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as exc:
        raise ReleaseToolError(f"Refusing to overwrite {destination}; it appeared while this tool ran") from exc
    except OSError as exc:
        raise ReleaseToolError(f"Cannot create {destination}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise


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


def verify_staged_files(validators: Validators, stage_dir: Path, policy: Any) -> dict[str, Any]:
    """Check a stage directory against its SHA256SUMS with the publisher's rules.

    The directory may hold, besides the listed artifacts and SHA256SUMS, only
    per-signer SHA256SUMS.<alias>.asc files of active release signers and
    SHA256SUMS.asc. Every listed artifact must be a regular file with the listed
    digest.
    """

    vra = validators.release_artifacts
    try:
        staged = vra.staged_file_names(stage_dir)
        entries = vra.parse_sha256sums(stage_dir / CHECKSUMS_FILE)
        signatures = vra.release_signature_paths(stage_dir, staged, policy)
    except validators.errors as exc:
        raise ReleaseToolError(str(exc)) from exc

    if (stage_dir / CHECKSUMS_FILE).is_symlink():
        raise ReleaseToolError(f"{CHECKSUMS_FILE} must not be a symlink: {stage_dir / CHECKSUMS_FILE}")
    allowed = set(entries) | {CHECKSUMS_FILE, COMBINED_SIGNATURE_FILE}
    allowed |= {path.name for path in signatures.values()}
    missing = sorted(set(entries) - staged)
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
