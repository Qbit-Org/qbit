#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Key-policy gate: check a change to the release key policy, and to the code
that checks it, reading the pull request only as git objects.

policy  checks contrib/keys/operator-keys at --head against --base: both trees
        are read from git objects, then this directory's
        validate_key_metadata.py and the base's own copy must accept the change.
target  is the base-only job (pull_request_target): run from a checkout of the
        base, it finds the paths --head changes against its merge base with
        --base, runs `policy` for a policy change, and requires approvals for a
        change to the gate's own code (GATE_CODE_PATHS).

Nothing from --head is executed or imported: its files are written out as data
for the validators and gpg to read.
"""

import sys

# Refuse before importing anything else (sys is built in): run as a script
# without -I, Python looks up modules in the script's directory before the
# standard library.
if __name__ == "__main__" and not sys.flags.isolated:
    print("::error::run the key-policy gate isolated: python3 -I ci/release/key_policy_gate.py ...")
    raise SystemExit(1)

import argparse  # noqa: E402
import functools  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    """Load `name` from exactly `path`, a gate code file, not from a search path.

    The gate runs with `python3 -I` and adds no directory to sys.path, so no
    file added beside it can stand in for a module it loads.
    """

    existing = sys.modules.get(name)
    if existing is not None and Path(getattr(existing, "__file__", "") or "").resolve() == path.resolve():
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if existing is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = existing
        raise
    return module


classify_merge_profile = load_module("classify_merge_profile", HERE.parent / "checks" / "classify_merge_profile.py")
key_metadata = load_module("validate_key_metadata", HERE / "validate_key_metadata.py")

POLICY_DIR = "contrib/keys/operator-keys"
GATE_APPROVALS_DIR = "contrib/keys/gate-approvals"
GATE_CHECK_NAME = "Key Policy Gate"
GATE_WORKFLOW = ".github/workflows/key-policy-gate.yml"
# The gate's own code and its description: a change to any of these, or to any
# workflow (a workflow can post a check under the gate's name), needs approvals
# by the base policy's signers over a manifest of their contents.
GATE_CODE_PREFIXES = (".github/workflows/", ".github/actions/")
GATE_CODE_PATHS = (
    ".github/CODEOWNERS",
    "ci/checks/classify_merge_profile.py",
    "ci/checks/test_key_policy_gate_contract.py",
    "ci/checks/test_key_policy_gate_target.py",
    "ci/release/key_policy_gate.py",
    "ci/release/validate_builder_attestations.py",
    "ci/release/validate_key_metadata.py",
    "ci/release/validate_release_artifacts.py",
    "contrib/keys/README.md",
)
CHECKOUT_ATTRIBUTES = (
    "text", "eol", "crlf", "filter", "ident", "working-tree-encoding", "export-ignore", "export-subst",
)
GATE_APPROVAL_FILE_RE = re.compile(r"^(gate\.SHA256|approval-note\.md|([a-z0-9][a-z0-9-]{2,31})\.asc)$")


class GateError(Exception):
    """A change the gate refuses."""


def git(*args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run(["git", *args], input=data, capture_output=True, check=False)
    if result.returncode != 0:
        raise GateError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


fold = classify_merge_profile.fold_path


def is_gate_code(path: str) -> bool:
    return path in GATE_CODE_PATHS or path.startswith(GATE_CODE_PREFIXES)


def split_nul(data: bytes) -> list[bytes]:
    return [item for item in data.split(b"\0") if item]


def tree_entry(rev: str, path: str) -> tuple[str, str, str] | None:
    """The single tree entry for `path` at `rev`, as (mode, type, oid); None when absent."""

    entries = split_nul(git("ls-tree", "-z", rev, "--", path))
    if not entries:
        return None
    if len(entries) > 1:
        raise GateError(f"{rev}:{path} has more than one tree entry")
    meta = entries[0].split(b"\t", 1)[0].decode()
    mode, kind, oid = meta.split()
    return mode, kind, oid


def blob_entries(rev: str, path: str) -> list[tuple[str, str, str, str]]:
    """Every entry under `path` at `rev` as (mode, type, oid, path), refusing repeated paths."""

    seen: set[str] = set()
    entries = []
    for item in split_nul(git("ls-tree", "-r", "-z", rev, "--", path)):
        meta, raw_path = item.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        name = raw_path.decode("utf8", errors="surrogateescape")
        if name in seen:
            raise GateError(f"{rev}:{name} has more than one tree entry")
        seen.add(name)
        entries.append((mode, kind, oid, name))
    return entries


def extract_policy(rev: str, dest: Path, *, check_attributes: bool) -> bool:
    """Write `rev`'s policy directory into `dest` from git objects; False when `rev` has none.

    Every directory on the path must be a tree and every file under it a
    regular 100644 blob. With `check_attributes`, no checkout or archive
    attribute may apply to its files, read with core.ignorecase off and on.
    """

    dest.mkdir(parents=True, exist_ok=True)
    parts = POLICY_DIR.split("/")
    for depth in range(1, len(parts) + 1):
        prefix = "/".join(parts[:depth])
        entry = tree_entry(rev, prefix)
        if entry is None:
            return False
        if entry[:2] != ("040000", "tree"):
            raise GateError(f"{rev}:{prefix} is not a directory: {' '.join(entry)}")
    names = []
    for mode, kind, oid, name in blob_entries(rev, POLICY_DIR):
        if (mode, kind) != ("100644", "blob"):
            raise GateError(f"{rev}:{name} is not a regular file (mode {mode})")
        relative = name[len(POLICY_DIR) + 1 :]
        if not relative or ".." in relative.split("/"):
            raise GateError(f"{rev}:{name} is not a policy file")
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git("cat-file", "blob", oid))
        names.append(name)
    if check_attributes:
        listing = b"\0".join(name.encode("utf8", errors="surrogateescape") for name in names) + b"\0"
        for ignorecase in ("false", "true"):
            output = git(
                "-c", f"core.ignorecase={ignorecase}", "check-attr", "--source", rev, "-z", "--stdin",
                *CHECKOUT_ATTRIBUTES, data=listing,
            )
            fields = output.split(b"\0")
            for index in range(0, len(fields) - 2, 3):
                path, attribute, value = (field.decode("utf8", errors="surrogateescape") for field in fields[index : index + 3])
                if value != "unspecified":
                    raise GateError(
                        f"{rev}:{path} has the {attribute} attribute ({value}) with core.ignorecase={ignorecase}. "
                        f"No .gitattributes rule may match files under {POLICY_DIR}: remove or narrow the rule that "
                        f"does (git check-attr -a -- '{path}' names it)."
                    )
    return True


def check_folded_paths(rev: str) -> None:
    """Refuse paths that equal the policy path, or .gitattributes, only after NFKC case folding."""

    parts = POLICY_DIR.split("/")
    guarded = {fold("/".join(parts[:depth])): "/".join(parts[:depth]) for depth in range(1, len(parts) + 1)}
    problems = []
    seen: dict[str, str] = {}
    for raw in split_nul(git("ls-tree", "-r", "-z", "--name-only", "--full-tree", rev)):
        path = raw.decode("utf8", errors="surrogateescape")
        components = path.split("/")
        for depth in range(1, len(components) + 1):
            prefix = "/".join(components[:depth])
            expected = guarded.get(fold(prefix))
            if expected is not None and prefix != expected:
                problems.append(f"{path} names {expected} with other letters")
                break
        if any(fold(part) == ".gitattributes" and part != ".gitattributes" for part in components):
            problems.append(f"{path} names .gitattributes with other letters")
        if path.startswith(POLICY_DIR + "/"):
            key = fold(path)
            if key in seen and seen[key] != path:
                problems.append(f"{path} and {seen[key]} are the same file on case-insensitive checkouts")
            seen.setdefault(key, path)
    if problems:
        raise GateError("; ".join(problems))


def file_map(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def python(script: Path) -> list[str]:
    """Run `script` isolated (-I): no script directory or user site on its path."""

    return [sys.executable, "-I", str(script)]


def run(command: list[str], name: str) -> None:
    sys.stdout.flush()
    if subprocess.run(command, check=False).returncode != 0:
        raise GateError(f"{name} refused the change")


def check_policy(base: str, head: str, work: Path) -> None:
    """The policy at `head` against the base's, with this directory's validator and the base's."""

    head_dir, base_dir = work / "head", work / "base"
    extract_policy(head, head_dir, check_attributes=True)
    extract_policy(base, base_dir, check_attributes=False)
    check_folded_paths(head)
    if (base_dir / "KEYS.md").is_file() and not (head_dir / "KEYS.md").is_file():
        raise GateError(f"{POLICY_DIR}/KEYS.md is at the base and must stay")
    head_args = [
        *python(HERE / "validate_key_metadata.py"),
        "--operator-policy", str(head_dir / "keys.json"),
        "--operator-keys-dir", str(head_dir),
        "--require-public-key-files",
        "--verify-public-key-certificates",
        "--check-keys-md",
        "--base-operator-keys-dir", str(base_dir),
    ]
    # Once any first-parent ancestor of the base had a policy, the base must have one.
    if git("rev-list", "--first-parent", "-n", "1", base, "--", f"{POLICY_DIR}/keys.json").strip():
        head_args.append("--base-history-had-policy")
    run(head_args, "validate_key_metadata.py")

    if file_map(head_dir) == file_map(base_dir):
        return
    # The base's own validator, read from git objects, with arguments every version of it accepts.
    validator = "ci/release/validate_key_metadata.py"
    entry = tree_entry(base, validator)
    if entry is None or entry[:2] not in {("100644", "blob"), ("100755", "blob")}:
        raise GateError(f"The base has no {validator} to check this change with.")
    base_validator = work / "base-validator.py"
    base_validator.write_bytes(git("cat-file", "blob", entry[2]))
    base_args = [
        *python(base_validator),
        "--operator-policy", str(head_dir / "keys.json"),
        "--operator-keys-dir", str(head_dir),
        "--require-public-key-files",
    ]
    if (base_dir / "keys.json").is_file():
        if (head_dir / "keys.json").read_bytes() == (base_dir / "keys.json").read_bytes():
            base_args.append("--skip-policy-transition-validation")
        else:
            base_args += ["--previous-operator-policy", str(base_dir / "keys.json")]
    print("Checking the change with the base's validator")
    run(base_args, "the base's validate_key_metadata.py")


@functools.lru_cache(maxsize=None)
def gate_files(rev: str) -> dict[str, bytes]:
    """The gate code files at `rev`: GATE_CODE_PATHS and every file under GATE_CODE_PREFIXES."""

    files: dict[str, bytes] = {}
    candidates = [(path, tree_entry(rev, path)) for path in GATE_CODE_PATHS]
    for prefix in GATE_CODE_PREFIXES:
        for mode, kind, oid, name in blob_entries(rev, prefix):
            candidates.append((name, (mode, kind, oid)))
    for path, entry in candidates:
        if entry is None:
            continue
        if entry[:2] not in {("100644", "blob"), ("100755", "blob")}:
            raise GateError(f"{rev}:{path} is not a regular file (mode {entry[0]})")
        files[path] = git("cat-file", "blob", entry[2])
    return files


def gate_manifest(base: str, head: str) -> bytes:
    """The manifest a gate change is approved over.

    Its first line names the base's gate code (`base  <sha256 of the base's
    file lines>`), so approvals hold only for the change from that base; then
    `<sha256>  <path>` for every gate code file at `head`, sorted by path.
    """

    def file_lines(rev: str) -> str:
        return "".join(f"{hashlib.sha256(data).hexdigest()}  {path}\n" for path, data in sorted(gate_files(rev).items()))

    base_lines = file_lines(base)
    return (f"base  {hashlib.sha256(base_lines.encode()).hexdigest()}\n" + file_lines(head)).encode()


def check_gate_check_name(head: str) -> None:
    """Only key-policy-gate.yml may define a job named like the required check."""

    pattern = re.compile(
        rf"^\s*-?\s*name:\s*[\"']?{re.escape(GATE_CHECK_NAME)}[\"']?\s*(#.*)?$", re.MULTILINE | re.IGNORECASE
    )
    for path, data in sorted(gate_files(head).items()):
        if path.startswith(GATE_CODE_PREFIXES) and path != GATE_WORKFLOW and pattern.search(data.decode("utf8", errors="replace")):
            raise GateError(f"{path} names something '{GATE_CHECK_NAME}'; only {GATE_WORKFLOW} may")


def check_gate_approvals(base: str, head: str, changed: list[str], work: Path) -> str:
    """A change to the gate's code needs its manifest signed by the base policy's quorum."""

    if subprocess.run(["git", "merge-base", "--is-ancestor", base, head], check=False).returncode != 0:
        raise GateError("bring the pull request up to date with its base branch before a gate change is approved")
    check_gate_check_name(head)
    manifest = gate_manifest(base, head)
    approval_dir = f"{GATE_APPROVALS_DIR}/{hashlib.sha256(manifest).hexdigest()}"
    stray = [path for path in changed if path.startswith(GATE_APPROVALS_DIR + "/") and not path.startswith(approval_dir + "/")]
    if stray:
        raise GateError(f"only {approval_dir}/ may change with this gate change, not {', '.join(stray)}")
    files: dict[str, bytes] = {}
    for mode, kind, oid, name in blob_entries(head, approval_dir):
        relative = name[len(approval_dir) + 1 :]
        if (mode, kind) != ("100644", "blob") or not GATE_APPROVAL_FILE_RE.fullmatch(relative):
            raise GateError(f"{head}:{name} is not a gate approval file")
        files[relative] = git("cat-file", "blob", oid)
    if files.get("gate.SHA256") != manifest:
        raise GateError(
            f"this change to the gate's code needs {approval_dir}/gate.SHA256 holding exactly:\n"
            + manifest.decode()
            + "with approval-note.md and <alias>.asc signatures by the base policy's signers"
        )
    if "approval-note.md" not in files:
        raise GateError(f"{approval_dir}/approval-note.md is missing")

    base_dir = work / "base"
    if not extract_policy(base, base_dir, check_attributes=False):
        raise GateError("the base has no key policy to approve a gate change with")
    projection = key_metadata.validate_operator_policy(
        base_dir / "keys.json", base_dir, require_files=False, validate_transition=False
    )
    active = {signer["alias"]: signer for signer in projection["signers"] if signer["status"] == "active"}
    manifest_path = work / "gate.SHA256"
    manifest_path.write_bytes(manifest)
    counted: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="key-policy-gate-gpg-") as home:
        Path(home).chmod(0o700)
        for signer in active.values():
            key_metadata.run_command(
                ["gpg", "--batch", "--homedir", home, "--import", str(base_dir / signer["public_key_file"])]
            )
        for relative, data in sorted(files.items()):
            if not relative.endswith(".asc"):
                continue
            alias = relative[: -len(".asc")]
            signer = active.get(alias)
            if signer is None:
                raise GateError(f"{approval_dir}/{relative}: {alias} is not an active signer of the base policy")
            signature = work / f"{alias}.asc"
            signature.write_bytes(data)
            result = key_metadata.run_command(
                ["gpg", "--batch", "--no-tty", "--homedir", home, "--trust-model", "always", "--status-fd", "1",
                 "--verify", str(signature), str(manifest_path)]
            )
            good = key_metadata.good_signatures(result.stdout)
            if result.returncode != 0 or [signing for signing, _primary in good] != [signer["signing_fingerprint"]]:
                raise GateError(f"{approval_dir}/{relative}: not a good signature by {alias} over gate.SHA256")
            primary = good[0][1]
            if primary in counted:
                raise GateError(f"{approval_dir}/{relative}: {alias} shares a primary key with {counted[primary]}")
            counted[primary] = alias
    # As for a policy change: each release line's own signers must meet that line's quorum.
    approvers = set(counted.values())
    if not approvers or not projection["release_lines"]:
        raise GateError(f"this change to the gate's code has no approvals in {approval_dir}")
    for line, settings in sorted(projection["release_lines"].items()):
        required = settings["policy_change_quorum"]
        line_approvers = approvers & key_metadata.active_aliases_for_line(projection, line)
        if len(line_approvers) < required:
            raise GateError(
                f"this change to the gate's code needs {required} approval(s) over {approval_dir}/gate.SHA256 "
                f"from the base policy's active {line} signers, got {len(line_approvers)}"
            )
    return f"gate change approved by {', '.join(sorted(counted.values()))}"


def check_target(base: str, head: str, work: Path) -> None:
    merge_base = git("merge-base", base, head).decode().strip()
    changed = [
        name.decode("utf8", errors="surrogateescape")
        for name in split_nul(git("diff", "--no-renames", "--name-only", "-z", merge_base, head))
    ]
    policy = [path for path in changed if classify_merge_profile.touches_operator_keys(path)]
    gate = [path for path in changed if is_gate_code(path)]
    approvals = [path for path in changed if path.startswith(GATE_APPROVALS_DIR + "/")]
    other = [
        path
        for path in changed
        if path.startswith("contrib/keys/")
        and not is_gate_code(path)
        and not path.startswith(POLICY_DIR + "/")
        and not path.startswith(GATE_APPROVALS_DIR + "/")
    ]
    if other:
        raise GateError(f"contrib/keys holds only the policy, its README and gate approvals, not {', '.join(other)}")
    if approvals and not gate:
        raise GateError("gate approvals arrive only with the change to the gate's code they approve")
    if policy:
        print(f"Key policy paths changed: {', '.join(policy)}")
        check_policy(base, head, work / "policy")
    if gate:
        print(f"Gate code changed: {', '.join(gate)}")
        print(check_gate_approvals(base, head, changed, work / "gate"))
    if not policy and not gate:
        print("No key policy or gate code path changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("policy", "target"))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    try:
        for rev in (args.base, args.head):
            git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        # Start from an empty work directory: nothing from an earlier run may be read.
        if args.work.exists():
            shutil.rmtree(args.work)
        args.work.mkdir(parents=True)
        if args.mode == "policy":
            check_policy(args.base, args.head, args.work)
        else:
            check_target(args.base, args.head, args.work)
        return 0
    except (GateError, key_metadata.MetadataError) as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
