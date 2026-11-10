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
        change to the gate's own code (see is_gate_code: every file under
        GATE_CODE_PREFIXES, GATE_CODE_PATHS, and every .gitattributes).

Nothing from --head is executed or imported: its files are written out as data
for the validators and gpg to read.
"""

import sys

GATE_USAGE = (
    "run the key-policy gate as: python3 -I -B -X pycache_prefix=<new empty directory outside the checkout and --work> "
    "ci/release/key_policy_gate.py ..."
)


def normal_path(path: str) -> str:
    """`path` made absolute against nothing: '.' and '..' resolved, repeated slashes dropped."""

    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def refuse_unsafe_interpreter(script: str) -> None:
    """Refuse to run unless no file in the checkout can stand in for code the gate runs.

    Without -I, Python looks up modules in the script's directory before the
    standard library. Without -B and a pycache prefix outside the checkout, it
    reads bytecode caches (__pycache__/*.pyc) beside the sources it imports,
    and a committed cache can carry code other than its source. Only built-in
    modules are imported before these checks.
    """

    import posix

    prefix = sys.pycache_prefix
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not prefix or not prefix.startswith("/"):
        print(f"::error::{GATE_USAGE}")
        raise SystemExit(1)
    script = script if script.startswith("/") else posix.getcwd() + "/" + script
    checkout = normal_path(script).rsplit("/", 3)[0]
    prefix = normal_path(prefix)
    try:
        entries = posix.listdir(prefix)
    except OSError:
        entries = ["?"]
    if prefix == checkout or prefix.startswith(checkout + "/") or entries:
        print(f"::error::{GATE_USAGE}")
        raise SystemExit(1)


if __name__ == "__main__":
    refuse_unsafe_interpreter(__file__)

import argparse  # noqa: E402
import datetime  # noqa: E402
import functools  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import re  # noqa: E402
import secrets  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import unicodedata  # noqa: E402
import traceback  # noqa: E402
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
# The base branches the gate checks, each under its own check name, which that
# branch's ruleset requires: "Key Policy Gate (main)", "Key Policy Gate (1.x.x)".
GATE_BASES = ("main", "1.x.x")
GATE_CHECK_NAMES = (GATE_CHECK_NAME, *(f"{GATE_CHECK_NAME} ({base})" for base in GATE_BASES))
GATE_JOB_NAME = f"{GATE_CHECK_NAME} (${{{{ github.event.pull_request.base.ref }}}})"
GATE_WORKFLOW = ".github/workflows/key-policy-gate.yml"
WORKFLOW_DIR = ".github/workflows/"
# The gate's own code and its description: a change to any file under these
# directories, whatever its type, to these files, or to any .gitattributes
# (attributes change how the gate's code is checked out) needs approvals by the
# base policy's signers over a manifest of their contents. Every workflow is
# gate code, since a workflow could post a check under the gate's name.
GATE_CODE_PREFIXES = ("ci/release/", "ci/checks/", WORKFLOW_DIR, ".github/actions/")
GATE_CODE_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", "contrib/keys/README.md")
# Attributes that change the bytes a checkout writes, and those that change an archive too.
CHECKOUT_CONTENT_ATTRIBUTES = ("text", "eol", "crlf", "filter", "ident", "working-tree-encoding")
CHECKOUT_ATTRIBUTES = CHECKOUT_CONTENT_ATTRIBUTES + ("export-ignore", "export-subst")
GATE_APPROVAL_FILE_RE = re.compile(r"^(gate\.SHA256|approval-note\.md|([a-z0-9][a-z0-9-]{2,31})\.asc)$")


class GateError(Exception):
    """A change the gate refuses."""


def git(*args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run(["git", *args], input=data, capture_output=True, check=False)
    if result.returncode != 0:
        raise GateError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


fold = classify_merge_profile.fold_path


FOLDED_GATE_CODE_PATHS = frozenset(fold(path) for path in GATE_CODE_PATHS)
FOLDED_GATE_CODE_PREFIXES = tuple(fold(prefix) for prefix in GATE_CODE_PREFIXES)
# The directories that hold gate code, and their parents: an entry there in
# place of the directory would move gate code out of the gate, so it is gate
# code too. A symlink or submodule there is refused as not a regular file; a
# regular file needs approvals like any other gate code.
FOLDED_GATE_CODE_PARENTS = frozenset(
    "/".join(parts[:depth])
    for parts in [fold(prefix).rstrip("/").split("/") for prefix in GATE_CODE_PREFIXES]
    for depth in range(1, len(parts) + 1)
) | frozenset(
    "/".join(parts[:depth])
    for parts in [fold(path).split("/") for path in GATE_CODE_PATHS]
    for depth in range(1, len(parts))
)


def is_attributes_file(path: str) -> bool:
    return fold(path.rsplit("/", 1)[-1]) == ".gitattributes"


def is_gate_code(path: str) -> bool:
    """Whether `path` is gate code, compared folded: on a case-insensitive checkout
    CI/release/x.py is the same file as ci/release/x.py."""

    folded = fold(path)
    return (
        folded in FOLDED_GATE_CODE_PATHS
        or folded.startswith(FOLDED_GATE_CODE_PREFIXES)
        or folded in FOLDED_GATE_CODE_PARENTS
        or is_attributes_file(path)
    )


def is_gate_approval_file(path: str) -> bool:
    return path.startswith(GATE_APPROVALS_DIR + "/")


def shown(text: str) -> str:
    """`text` with each character a log could act on (control, separator, format, not UTF-8) escaped."""

    return "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in text)


def is_bytecode(path: str) -> bool:
    """A Python bytecode cache, which no commit may carry."""

    parts = [fold(part) for part in path.split("/")]
    return "__pycache__" in parts or parts[-1].endswith((".pyc", ".pyo"))


def split_nul(data: bytes) -> list[bytes]:
    return [item for item in data.split(b"\0") if item]


@functools.lru_cache(maxsize=None)
def commit_tree(commit: str) -> tuple[tuple[tuple[str, str, str, str], ...], tuple[str, ...]]:
    """Every entry of `commit`'s tree as (mode, type, oid, path), and the paths that repeat."""

    seen: set[str] = set()
    entries, repeated = [], []
    # -t lists directories too, so two entries of one name are found at any depth.
    for item in split_nul(git("ls-tree", "-r", "-t", "-z", "--full-tree", commit)):
        meta, raw_path = item.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        name = raw_path.decode("utf8", errors="surrogateescape")
        if name in seen:
            repeated.append(name)
        seen.add(name)
        if kind != "tree":
            entries.append((mode, kind, oid, name))
    return tuple(entries), tuple(repeated)


@functools.lru_cache(maxsize=None)
def verified_commit(object_name: str) -> str:
    return git("rev-parse", "--verify", f"{object_name}^{{commit}}").decode().strip()


def resolve(rev: str) -> str:
    """The commit `rev` names; a full object name is verified once, other names every time (they move)."""

    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", rev):
        return verified_commit(rev)
    return git("rev-parse", "--verify", f"{rev}^{{commit}}").decode().strip()


def tree(rev: str) -> tuple[tuple[str, str, str, str], ...]:
    """Every entry of `rev`'s tree as (mode, type, oid, path), refusing repeated paths."""

    entries, repeated = commit_tree(resolve(rev))
    if repeated:
        raise GateError(f"{rev}:{repeated[0]} has more than one tree entry")
    return entries


def read_blobs(oids: list[str]) -> dict[str, bytes]:
    """The contents of blobs `oids`, read with one `git cat-file --batch`."""

    unique = sorted(set(oids))
    if not unique:
        return {}
    output = git("cat-file", "--batch", data=("\n".join(unique) + "\n").encode())
    blobs: dict[str, bytes] = {}
    index = 0
    for oid in unique:
        end = output.index(b"\n", index)
        header = output[index:end].decode(errors="replace").split()
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise GateError(f"cannot read blob {oid}: {' '.join(header)}")
        start = end + 1
        blobs[oid] = output[start : start + int(header[2])]
        index = start + int(header[2]) + 1
    return blobs


def tree_entry(rev: str, path: str) -> tuple[str, str, str] | None:
    """The single tree entry for `path` at `rev`, as (mode, type, oid); None when absent."""

    entries = split_nul(git("ls-tree", "-z", "--full-tree", rev, "--", path))
    if not entries:
        return None
    if len(entries) > 1:
        raise GateError(f"{rev}:{path} has more than one tree entry")
    meta = entries[0].split(b"\t", 1)[0].decode()
    mode, kind, oid = meta.split()
    return mode, kind, oid


def blob_entries(rev: str, path: str) -> list[tuple[str, str, str, str]]:
    """Every entry under directory `path` at `rev` as (mode, type, oid, path), refusing repeated paths there."""

    entries, repeated = commit_tree(resolve(rev))
    inside = [name for name in repeated if name == path or name.startswith(path + "/")]
    if inside:
        raise GateError(f"{rev}:{inside[0]} has more than one tree entry")
    return [entry for entry in entries if entry[3].startswith(path + "/")]


def extract_policy(rev: str, dest: Path, *, check_attributes: bool) -> bool:
    """Write `rev`'s policy directory into `dest` from git objects; False when `rev` has none.

    Every directory on the path must be a tree and every file under it a
    regular 100644 blob. With `check_attributes`, no checkout or archive
    attribute may be set for its files (unset is allowed), read with
    core.ignorecase off and on.
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
    entries = blob_entries(rev, POLICY_DIR)
    for mode, kind, _oid, name in entries:
        if (mode, kind) != ("100644", "blob"):
            raise GateError(f"{rev}:{name} is not a regular file (mode {mode})")
        relative = name[len(POLICY_DIR) + 1 :]
        if not relative or ".." in relative.split("/"):
            raise GateError(f"{rev}:{name} is not a policy file")
    blobs = read_blobs([oid for _mode, _kind, oid, _name in entries])
    names = []
    for _mode, _kind, oid, name in entries:
        target = dest / name[len(POLICY_DIR) + 1 :]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blobs[oid])
        names.append(name)
    if check_attributes:
        refuse_checkout_attributes(rev, names, f"files under {POLICY_DIR}")
    return True


def refuse_checkout_attributes(rev: str, names: list[str], what: str, attributes=CHECKOUT_ATTRIBUTES) -> None:
    """No attribute in `attributes` may be set for `names` at `rev` (unset is allowed), read with core.ignorecase off and on."""

    if not names:
        return
    listing = b"\0".join(name.encode("utf8", errors="surrogateescape") for name in names) + b"\0"
    for ignorecase in ("false", "true"):
        output = git(
            "-c", f"core.ignorecase={ignorecase}", "check-attr", "--source", rev, "-z", "--stdin",
            *attributes, data=listing,
        )
        fields = output.split(b"\0")
        for index in range(0, len(fields) - 2, 3):
            path, attribute, value = (field.decode("utf8", errors="surrogateescape") for field in fields[index : index + 3])
            if value not in ("unspecified", "unset"):
                raise GateError(
                    f"{rev}:{path} has the {attribute} attribute ({value}) with core.ignorecase={ignorecase}. "
                    f"No .gitattributes rule may set this attribute for {what} (unset, such as -text, is allowed): "
                    f"remove or narrow the rule that does (git check-attr -a -- '{path}' names it)."
                )


def check_folded_paths(rev: str) -> None:
    """Refuse paths that equal the policy path, or .gitattributes, only after NFKC case folding."""

    parts = POLICY_DIR.split("/")
    guarded = {fold("/".join(parts[:depth])): "/".join(parts[:depth]) for depth in range(1, len(parts) + 1)}
    problems = []
    seen: dict[str, str] = {}
    for _mode, _kind, _oid, path in tree(rev):
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
    """Run `script` as the gate runs: isolated (-I), reading no bytecode cache from the checkout."""

    if not sys.pycache_prefix:
        raise GateError(GATE_USAGE)
    return [sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix}", str(script)]


def run(command: list[str], name: str) -> None:
    sys.stdout.flush()
    # stderr joins stdout so that nothing the validator prints can reach the
    # log after the gate resumes workflow commands.
    if subprocess.run(command, check=False, stderr=subprocess.STDOUT).returncode != 0:
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
    base_validator.write_bytes(read_blobs([entry[2]])[entry[2]])
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
def commit_files(commit: str, wanted) -> tuple[tuple[str, bytes], ...]:
    """The files of `commit` whose paths `wanted` accepts, each of which must be a regular file."""

    entries = [entry for entry in tree(commit) if wanted(entry[3])]
    for mode, kind, _oid, path in entries:
        if (mode, kind) not in {("100644", "blob"), ("100755", "blob")}:
            raise GateError(f"{commit}:{path} is not a regular file (mode {mode})")
    blobs = read_blobs([oid for _mode, _kind, oid, _path in entries])
    return tuple((path, blobs[oid]) for _mode, _kind, oid, path in entries)


def gate_files(rev: str) -> dict[str, bytes]:
    """The gate code files at `rev`: see is_gate_code."""

    return dict(commit_files(resolve(rev), is_gate_code))


def gate_manifest(base: str, head: str) -> bytes:
    """The manifest a gate change is approved over.

    Its first line names the state the change starts from: `base  <sha256>`
    (see base_state). Every approved gate change adds an approvals directory,
    so no base state recurs, and an approval holds only for the one change
    from the state it names. Then `<sha256>  <path>` for every gate code file
    at `head`, sorted by path.
    """

    def file_lines(files: dict[str, bytes]) -> str:
        # One line per file, printable as it is: a path with a line break,
        # another control or format character, or bytes that are not UTF-8
        # could make two different sets of files read alike, to git or to a
        # signer reading the manifest.
        for path in files:
            if not path.isprintable():
                raise GateError(f"{shown(path)}: a gate path may hold only printable characters")
        return "".join(f"{hashlib.sha256(data).hexdigest()}  {path}\n" for path, data in sorted(files.items()))

    return f"base  {base_state(base)}\n".encode() + file_lines(gate_files(head)).encode("utf8")


def base_state(base: str) -> str:
    """The SHA-256 of the base's gate code and gate approval entries.

    Each entry is `<mode> <type> <sha256>\t<path>`, NUL-separated, in tree
    order, where the sha256 is that of the entry's bytes (a submodule's object
    id stands in for them). Nothing in the base is refused here: signers do
    not read these lines, and an entry that should not be there must not
    block the change that removes it.
    """

    entries, _repeated = commit_tree(resolve(base))
    chosen = [entry for entry in entries if is_gate_code(entry[3]) or is_gate_approval_file(entry[3])]
    blobs = read_blobs([oid for _mode, kind, oid, _path in chosen if kind == "blob"])
    listing = b"\0".join(
        f"{mode} {kind} {hashlib.sha256(blobs[oid]).hexdigest() if kind == 'blob' else oid}\t{path}".encode(
            "utf8", "surrogateescape"
        )
        for mode, kind, oid, path in chosen
    )
    return hashlib.sha256(listing).hexdigest()


@functools.lru_cache(maxsize=None)
def workflow_loader():
    """PyYAML's safe loader, reading plain scalars as GitHub's YAML 1.2 parser does."""

    try:
        import yaml
    except ImportError as exc:
        raise GateError("PyYAML (python3-yaml) is needed to read workflows") from exc

    class WorkflowLoader(yaml.SafeLoader):
        pass

    # GitHub reads YAML 1.2, where on, yes, off, dates and = are text: of
    # PyYAML's YAML 1.1 rules only numbers and merge keys (<<) apply here.
    kept = ("tag:yaml.org,2002:int", "tag:yaml.org,2002:float", "tag:yaml.org,2002:merge")
    WorkflowLoader.yaml_implicit_resolvers = {
        first: [(tag, regexp) for tag, regexp in resolvers if tag in kept]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    return yaml, WorkflowLoader


def refuse_repeated_keys(path: str, root) -> None:
    """No mapping in the composed document may hold one key twice; keys merged in (<<) may be overridden."""

    yaml, _loader = workflow_loader()
    seen: set[int] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            keys = set()
            for key_node, value_node in node.value:
                pending += [key_node, value_node]
                if key_node.tag == "tag:yaml.org,2002:merge":
                    continue
                if not isinstance(key_node, yaml.ScalarNode):
                    raise GateError(f"{path}: a mapping key that is not a scalar")
                if (key_node.tag, key_node.value) in keys:
                    raise GateError(f"{path}: the key {key_node.value!r} appears twice in one mapping")
                keys.add((key_node.tag, key_node.value))
        elif isinstance(node, yaml.SequenceNode):
            pending += node.value


def read_workflow(path: str, data: bytes):
    """A workflow parsed with workflow_loader, refusing repeated keys and tagged sets or pairs."""

    yaml, loader_class = workflow_loader()
    try:
        text = data.decode("utf8")
    except UnicodeDecodeError as exc:
        raise GateError(f"{path} cannot be read as YAML: {exc}") from exc
    # Readers differ on control and separator characters: PyYAML breaks lines
    # at U+0085, U+2028 and U+2029 and keeps a byte-order mark inside a key,
    # which other readers drop. Only a leading byte-order mark is allowed;
    # other text, such as a no-break space or an emoji joiner, is.
    odd = [
        character
        for character in text.removeprefix("\ufeff")
        if (character not in "\t\n\r" and unicodedata.category(character) in {"Cc", "Cs", "Zl", "Zp"})
        or character == "\ufeff"
    ]
    if odd:
        raise GateError(f"{path} holds a control or separator character: {shown(odd[0])}")
    try:
        loader = loader_class(text)
        try:
            root = loader.get_single_node()
            refuse_repeated_keys(path, root)
            document = loader.construct_document(root) if root is not None else None
        finally:
            loader.dispose()
    except GateError:
        raise
    except Exception as exc:  # PyYAML raises more than YAMLError for tagged scalars it cannot build
        raise GateError(f"{path} cannot be read as YAML: {type(exc).__name__}: {exc}") from exc
    # Tags such as !!set, !!omap, !!pairs, !!binary and !!timestamp build values
    # GitHub reads otherwise: only text, numbers, mappings and sequences pass.
    seen: set[int] = set()
    pending = [document]
    while pending:
        item = pending.pop()
        if isinstance(item, (set, frozenset, tuple, bytes, datetime.date)):
            raise GateError(f"{path}: YAML tags that build {type(item).__name__} values are not allowed")
        if isinstance(item, (dict, list)) and id(item) not in seen:
            seen.add(id(item))
            pending += [part for pair in item.items() for part in pair] if isinstance(item, dict) else item
    return document


def strings(node) -> list[str]:
    """Every string in a parsed YAML node, keys and values; a node shared by aliases is read once."""

    found: list[str] = []
    seen: set[int] = set()
    pending = [node]
    while pending:
        item = pending.pop()
        if isinstance(item, (dict, list)):
            if id(item) in seen:
                continue
            seen.add(id(item))
            pending += [part for pair in item.items() for part in pair] if isinstance(item, dict) else item
        elif isinstance(item, bytes):
            found.append(item.decode("utf8", errors="replace"))
        elif isinstance(item, str):
            found.append(item)
    return found


def declares(permissions) -> bool:
    """Whether a `permissions` value sets the token's permissions; empty or null leaves the default."""

    if permissions is None:
        return False
    return not (isinstance(permissions, str) and squeezed(permissions) in {"", "~", "null"})


def can_post_checks(permissions) -> bool:
    """Whether `permissions` lets the workflow token post a check run or a commit status."""

    if permissions is None:
        return False
    if isinstance(permissions, str):
        return squeezed(permissions) == "write-all"
    if isinstance(permissions, dict):
        return any(
            squeezed(str(key)) in {"checks", "statuses"} and squeezed(str(value)) == "write"
            for key, value in permissions.items()
        )
    return True


# An expression in a name may only read a matrix value, such as ${{ matrix.name }}:
# no literals, functions or operators, and no context a pull request, a
# dispatcher or a setting supplies (github.event, inputs, vars, needs).
NUMBER_RE = re.compile(
    r"[-+]?(?:0[xob][0-9a-f_]+|(?:[0-9][0-9_]*)?\.?[0-9_]*(?:e[-+]?[0-9]+)?|\.(?:inf|nan))", re.IGNORECASE
)
MATRIX_EXPRESSION_RE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def squeezed(text: str) -> str:
    """`text` folded and without whitespace, as names are compared here."""

    return "".join(fold(text).split())


def matrix_values(strategy, key: str) -> list[str] | None:
    """Every value `matrix.<key>` can take in `strategy`; None when one is computed or not text.

    The empty string is always one: a combination can lack the key or hold
    null, and GitHub renders either as empty text.
    """

    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return None
    include = matrix.get("include") or []
    if not isinstance(include, list) or not all(isinstance(entry, dict) for entry in include):
        return None
    def lookup(mapping: dict) -> list:
        # GitHub looks matrix properties up case-insensitively.
        return [value for name, value in mapping.items() if fold(str(name)) == fold(key)]

    found = {""}
    seen: set[int] = set()
    unique = {id(entry): entry for entry in include}.values()
    candidates = lookup(matrix) + [value for entry in unique for value in lookup(entry)]
    for candidate in candidates:
        if isinstance(candidate, list):
            if id(candidate) in seen:
                continue
            seen.add(id(candidate))
        for value in candidate if isinstance(candidate, list) else [candidate]:
            if value is None:
                continue
            # A number (or text YAML 1.2 reads as one, such as 0o1 or 1e0)
            # renders as GitHub prints it, not as written: it stands for any text.
            if not isinstance(value, str) or "${{" in value or NUMBER_RE.fullmatch(value.strip()):
                return None
            found.add(value)
    return sorted(found)


def names_the_gate(path: str, name: str, strategy) -> bool:
    """Whether a workflow or job `name` can evaluate to one of the gate's check names (GATE_CHECK_NAMES).

    Names are compared folded and without whitespace. An expression in a name
    may only read a matrix value; a value the strategy gives as text is put in
    exactly, and a computed value or matrix stands for any text.
    """

    if "${{" in MATRIX_EXPRESSION_RE.sub("", name):
        raise GateError(f"{path}: the name {name!r} may read only matrix values, such as ${{{{ matrix.name }}}}")
    # Each piece is a list of possible texts, or None for any text.
    pieces: list[list[str] | None] = []
    position = 0
    for match in MATRIX_EXPRESSION_RE.finditer(name):
        pieces.append([squeezed(name[position : match.start()])])
        values = matrix_values(strategy, match.group(1))
        pieces.append(None if values is None else [squeezed(value) for value in values])
        position = match.end()
    pieces.append([squeezed(name[position:])])
    return any(pieces_reach(pieces, squeezed(name)) for name in GATE_CHECK_NAMES)


def pieces_reach(pieces: list[list[str] | None], target: str) -> bool:
    """Whether the pieces, in order, can spell exactly `target` (None stands for any text)."""

    # The positions of the target that the pieces so far can end at.
    reached = {0}
    for piece in pieces:
        if not reached:
            return False
        if piece is None:
            reached = set(range(min(reached), len(target) + 1))
        else:
            reached = {start + len(text) for start in reached for text in piece if target.startswith(text, start)}
    return len(target) in reached


def check_gate_workflow(path: str, data: bytes) -> None:
    """key-policy-gate.yml runs only on pull_request_target, as one job named like the check, posting no checks itself."""

    workflow = read_workflow(path, data)
    if not isinstance(workflow, dict):
        raise GateError(f"{path} is not a workflow mapping")
    triggers = workflow.get("on")
    names = list(triggers) if isinstance(triggers, dict) else triggers if isinstance(triggers, list) else [triggers]
    if names != ["pull_request_target"]:
        raise GateError(f"{path} may run only on pull_request_target, not {names!r}")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or len(jobs) != 1:
        raise GateError(f"{path} must hold exactly one job")
    job = next(iter(jobs.values()))
    if not isinstance(job, dict) or job.get("name") != GATE_JOB_NAME:
        raise GateError(f"{path}: its job must be named exactly '{GATE_JOB_NAME}'")
    # A skipped job or step, or one whose failure is ignored, would pass.
    for key in ("if", "continue-on-error", "strategy", "uses", "needs"):
        if key in job:
            raise GateError(f"{path}: its job may not use {key}")
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        raise GateError(f"{path}: its job must run steps")
    checkouts = []
    for step in steps:
        if not isinstance(step, dict):
            raise GateError(f"{path}: a step is not a mapping")
        for key in ("if", "continue-on-error"):
            if key in step:
                raise GateError(f"{path}: a step may not use {key}")
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            checkouts.append(step)
    base_commit = "${{ github.event.pull_request.base.sha }}"
    if len(checkouts) != 1 or (checkouts[0].get("with") or {}).get("ref") != base_commit:
        raise GateError(f"{path}: its job must check out exactly the pull request's base commit ({base_commit})")
    if can_post_checks(workflow.get("permissions")) or can_post_checks(job.get("permissions")):
        raise GateError(f"{path} may not ask to post checks or statuses: the job's own result is the check")


def check_gate_check_name(head: str, changed: list[str]) -> None:
    """Only key-policy-gate.yml may name a job like the required check, or post checks.

    Every workflow at `head` is parsed, not searched as text. No workflow or
    job name may be able to evaluate to the check's name (see names_the_gate),
    and no workflow or job may ask for `checks: write`, `statuses: write` or
    `write-all`. A workflow the pull request adds or changes must also declare
    its token permissions, for itself or for every job, rather than take the
    repository's default. This cannot stop code that posts a check by other
    means at run time; see contrib/keys/README.md.
    """

    for path, data in sorted(gate_files(head).items()):
        # GitHub reads workflows only from the top of .github/workflows/.
        if not path.startswith(WORKFLOW_DIR) or "/" in path[len(WORKFLOW_DIR) :]:
            continue
        if path == GATE_WORKFLOW:
            check_gate_workflow(path, data)
            continue
        if not fold(path).endswith((".yml", ".yaml")):
            continue
        workflow = read_workflow(path, data)
        if not isinstance(workflow, dict):
            raise GateError(f"{path} is not a workflow mapping")
        jobs = workflow.get("jobs") or {}
        if not isinstance(jobs, dict):
            raise GateError(f"{path}: jobs is not a mapping")
        named = [(name, None) for name in strings(workflow.get("name"))]
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                raise GateError(f"{path}: job {job_id!r} is not a mapping")
            named += [(name, job.get("strategy")) for name in strings(job.get("name"))]
        if any(names_the_gate(path, name, strategy) for name, strategy in named):
            raise GateError(f"{path} names something '{GATE_CHECK_NAME}'; only {GATE_WORKFLOW} may")
        if can_post_checks(workflow.get("permissions")) or any(can_post_checks(job.get("permissions")) for job in jobs.values()):
            raise GateError(f"{path} asks to post checks or statuses; only {GATE_WORKFLOW} may post the gate's check")
        if path in changed and not declares(workflow.get("permissions")) and not all(
            declares(job.get("permissions")) for job in jobs.values()
        ):
            raise GateError(f"{path} must declare its token permissions, for the workflow or for every job")


def check_gate_approvals(base: str, head: str, changed: list[str], work: Path) -> str:
    """A change to the gate's code needs its manifest signed by the base policy's quorum."""

    if subprocess.run(["git", "merge-base", "--is-ancestor", base, head], check=False).returncode != 0:
        raise GateError("bring the pull request up to date with its base branch before a gate change is approved")
    check_gate_check_name(head, changed)
    manifest = gate_manifest(base, head)
    approval_dir = f"{GATE_APPROVALS_DIR}/{hashlib.sha256(manifest).hexdigest()}"
    stray = [path for path in changed if is_gate_approval_file(path) and not path.startswith(approval_dir + "/")]
    if stray:
        raise GateError(f"only {approval_dir}/ may change with this gate change, not {', '.join(stray)}")
    entries = blob_entries(head, approval_dir)
    for mode, kind, _oid, name in entries:
        if (mode, kind) != ("100644", "blob") or not GATE_APPROVAL_FILE_RE.fullmatch(name[len(approval_dir) + 1 :]):
            raise GateError(f"{head}:{name} is not a gate approval file")
    blobs = read_blobs([oid for _mode, _kind, oid, _name in entries])
    files = {name[len(approval_dir) + 1 :]: blobs[oid] for _mode, _kind, oid, name in entries}
    if files.get("gate.SHA256") != manifest:
        raise GateError(
            f"this change to the gate's code needs {approval_dir}/gate.SHA256 holding exactly:\n"
            + manifest.decode("utf8", "backslashreplace")
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
    bytecode = [path for _mode, _kind, _oid, path in tree(head) if is_bytecode(path)]
    if bytecode:
        raise GateError(f"Python bytecode caches may not be committed: {', '.join(map(shown, bytecode))}")
    merge_base = git("merge-base", base, head).decode().strip()
    changed = [
        name.decode("utf8", errors="surrogateescape")
        for name in split_nul(git("diff", "--no-renames", "--name-only", "-z", merge_base, head))
    ]
    policy = [path for path in changed if classify_merge_profile.touches_operator_keys(path)]
    gate = [path for path in changed if is_gate_code(path)]
    approvals = [path for path in changed if is_gate_approval_file(path)]
    other = [
        path
        for path in changed
        if path.startswith("contrib/keys/")
        and fold(path) != fold("contrib/keys/README.md")
        and not path.startswith(POLICY_DIR + "/")
        and not is_gate_approval_file(path)
    ]
    if other:
        raise GateError(f"contrib/keys holds only the policy, its README and gate approvals, not {', '.join(map(shown, other))}")
    if approvals and not gate:
        raise GateError("gate approvals arrive only with the change to the gate's code they approve")
    if policy:
        print(f"Key policy paths changed: {', '.join(map(shown, policy))}")
        check_policy(base, head, work / "policy")
    if gate:
        print(f"Gate code changed: {', '.join(map(shown, gate))}")
        # The gate's own checkout must hold its code byte for byte.
        refuse_checkout_attributes(
            head,
            sorted(path for path in gate_files(head) if fold(path).startswith(FOLDED_GATE_CODE_PREFIXES)),
            "the gate's code",
            CHECKOUT_CONTENT_ATTRIBUTES,
        )
        print(check_gate_approvals(base, head, changed, work / "gate"))
    if not policy and not gate:
        print("No key policy or gate code path changed")


def main() -> int:
    # Paths that are not UTF-8 are printed escaped, not as a crash.
    sys.stdout.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("policy", "target"))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    if not sys.pycache_prefix:
        print(f"::error::{GATE_USAGE}")
        return 1
    prefix, work = Path(sys.pycache_prefix).resolve(), args.work.resolve()
    if prefix == work or work in prefix.parents or prefix in work.parents:
        print(f"::error::{GATE_USAGE}")
        return 1
    # Paths and messages printed below come from the pull request: the runner
    # acts on none of them as a workflow command, only on the summary line.
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}", flush=True)
    status, summary = 0, ""
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
    except (GateError, getattr(key_metadata, "MetadataError", GateError)) as exc:
        message = str(exc)
        print(f"Refused: {message}")
        status, summary = 1, shown(message.splitlines()[0] if message else "refused")
    except Exception as exc:  # noqa: BLE001 - the gate refuses on anything unexpected, and says so
        traceback.print_exc(file=sys.stdout)
        status, summary = 1, shown(f"the gate failed: {type(exc).__name__}")
    print(f"::{token}::", flush=True)
    if status:
        # The runner decodes %XX in a command's text; % is escaped so a path cannot add line breaks.
        print(f"::error::{summary.replace('%', '%25')}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
