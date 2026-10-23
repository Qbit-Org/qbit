#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Check that the interface names the hybrid post-quantum v2 transport docs quote exist.

A document marks a token with an HTML comment directly followed by an inline code span:

    <!--pq:KIND-->`TOKEN`

where KIND is one of:

    opt    an option, as -name, -name=value or -noname (a value isn't checked): qbitd -help or
           -help-debug, or qbit-cli -help, lists the name
    rpc    an RPC method: registered with RPCHelpMan
    field  an RPC result field, or a dotted path of them: each set with pushKV()
    value  a value such as a status or a reason: exactly a C++ string literal
    log    a log or warning text: part of a C++ string literal, where … stands for each printf
           conversion (%s, %u, ...), starting and ending at word boundaries

The documents are the Markdown files under doc/ with a marker, except the archived release notes in
doc/release-notes/; the specification and the operator guide must be among them. Options are
checked against the -help and -help-debug output of the binaries given with --qbitd and --qbit-cli,
as test/functional/feature_pq_quickstart.py does, and otherwise against the AddArg() calls that
-help or -help-debug prints: all but those of OptionsCategory::HIDDEN. Everything else is checked
against the C++ sources in src/, without tests, benchmarks and subtrees.

A marker that doesn't parse fails, with its file and line, so a typo can't drop a token silently. So
does any other comment that starts with pq, except a block of quoted vectors in the specification that
contrib/devtools/generate-pq-transport-vectors.py reads.
Each run first tests the check itself: it renames an option, an RPC field and a log string in
memory, and without binaries hides the option, and makes sure each is caught, and feeds it
malformed markers.
"""

import argparse
import importlib.util
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

KINDS = ("opt", "rpc", "field", "value", "log")
REQUIRED_DOCS = ("doc/design/pq-transport.md", "doc/user/network/pq-transport.md")
ARCHIVED_RELEASE_NOTES = "doc/release-notes/"
SOURCE_SUFFIXES = (".cpp", ".h")
SUBTREES = ("src/crc32c/", "src/crypto/ctaes/", "src/ipc/libmultiprocess/", "src/leveldb/", "src/libbitcoinpqc/",
            "src/minisketch/", "src/mlkem-native/", "src/secp256k1/")

# Anything that looks like the start of a marker, so that a malformed one is reported, not skipped.
MARKER_START = re.compile(r"<!--\s*pq", re.IGNORECASE)
MARKER_PREFIX = "<!--pq:"
VECTORS_LIKE = re.compile(r"<!--\s*pq-transport-vectors", re.IGNORECASE)
FENCE = re.compile(r"^ {0,3}(```|~~~)")

# C++ comments, raw strings, numbers (with digit separators), character literals and string literals.
CPP_TOKEN = re.compile(r"""
      (?P<comment>//[^\n]*|/\*.*?\*/)
    | (?<![A-Za-z0-9_])R"(?P<delim>[^()\\\s]{0,16})\((?P<raw>.*?)\)(?P=delim)"
    | (?<![A-Za-z0-9_])\d[\w']*
    | '(?:\\.|[^\\'\n])*'
    | "(?P<str>(?:\\.|[^\\"\n])*)"
    """, re.VERBOSE | re.DOTALL)
ESCAPE = re.compile(r"\\(x[0-9a-fA-F]+|[0-7]{1,3}|.)", re.DOTALL)
SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}
PRINTF_CONVERSION = re.compile(r"%(?:%|[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|j|z|t|L)?[diouxXeEfFgGaAcspn])")
RPC_NAME = re.compile(r"RPCHelpMan\s*\{\s*\"([A-Za-z0-9_]+)\"")
PUSHKV = re.compile(r"pushKV\(\s*\"([^\"\\]+)\"")
ADDARG = re.compile(r"AddArg\(\s*\"(-[^\"=]+)")
HIDDEN_CATEGORY = re.compile(r"\bOptionsCategory::HIDDEN\b")
HELP_OPTION = re.compile(r"^  (-[A-Za-z0-9?][A-Za-z0-9_-]*)", re.MULTILINE)
OPTION_TOKEN = re.compile(r"-?[A-Za-z0-9?][A-Za-z0-9_-]*(=.*)?")
FIELD_TOKEN = re.compile(r"[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*")
WORD = re.compile(r"\w")


@dataclass(frozen=True)
class Token:
    path: str
    line: int
    kind: str
    text: str


@dataclass
class Corpus:
    options: set
    rpcs: set
    fields: set
    literals: set
    #: Every literal with its printf conversions written as …, separated by NUL.
    messages: str


# The source tree, found from this file rather than with git, so that a functional test can run the
# check in a tree without a git checkout.
ROOT = Path(__file__).resolve().parents[2]

# The document and the pattern of a block of quoted vectors that the generator checks, taken from it so
# that a block it doesn't read fails here.
VECTORS_GENERATOR = "contrib/devtools/generate-pq-transport-vectors.py"
_generator_spec = importlib.util.spec_from_file_location("generate_pq_transport_vectors", ROOT / VECTORS_GENERATOR)
_generator = importlib.util.module_from_spec(_generator_spec)
_generator_spec.loader.exec_module(_generator)
VECTORS_SPEC = _generator.SPEC.relative_to(ROOT).as_posix()
VECTORS_BLOCK = _generator.SPEC_BLOCK


def files(directory, suffixes):
    """The files under directory with one of the suffixes, as sorted paths relative to ROOT."""
    return sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / directory).rglob("*")
                  if path.suffix in suffixes and path.is_file())


def vector_blocks(path, text):
    """Where each block of quoted vectors that the generator reads starts, as (line, column)."""
    if path != VECTORS_SPEC:
        return set()
    starts = set()
    for match in VECTORS_BLOCK.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        starts.add((text.count("\n", 0, line_start) + 1, match.start() - line_start))
    return starts


def parse_markers(path, text):
    """The tokens marked in a document, and an error for each marker that doesn't parse."""
    tokens, errors = [], []
    fence_line = None
    blocks = vector_blocks(path, text)
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            fence_line = None if fence_line is not None else number
            continue
        for start in MARKER_START.finditer(line):
            where = f"{path}:{number}"
            if fence_line is not None:
                errors.append(f"{where}: marker inside a code block, where it isn't hidden: {line.strip()}")
                continue
            if (number, start.start()) in blocks:
                continue
            rest = line[start.start():]
            if not rest.startswith(MARKER_PREFIX):
                if VECTORS_LIKE.match(rest):
                    errors.append(f"{where}: not a block of quoted vectors that {VECTORS_GENERATOR} reads, which is "
                                  f"<!-- pq-transport-vectors: vector N --> before a ```text block in {VECTORS_SPEC}: {rest}")
                else:
                    errors.append(f"{where}: malformed marker, expected <!--pq:KIND-->: {rest}")
                continue
            end = rest.find("-->")
            if end == -1:
                errors.append(f"{where}: unterminated marker, no -->: {rest}")
                continue
            kind = rest[len(MARKER_PREFIX):end]
            if kind not in KINDS:
                errors.append(f"{where}: unknown marker kind '{kind}', expected one of {', '.join(KINDS)}")
                continue
            span = rest[end + len("-->"):]
            if not span.startswith("`"):
                errors.append(f"{where}: marker not directly followed by an inline code span: {rest}")
                continue
            close = span.find("`", 1)
            if close == -1:
                errors.append(f"{where}: unterminated code span after marker: {rest}")
                continue
            token = span[1:close]
            if not token.strip():
                errors.append(f"{where}: empty token after marker")
            elif token != token.strip():
                errors.append(f"{where}: token '{token}' has leading or trailing spaces")
            else:
                tokens.append(Token(path, number, kind, token))
    if fence_line is not None:
        errors.append(f"{path}:{fence_line}: code block not closed")
    return tokens, errors


def unescape(literal):
    def replace(match):
        escape = match.group(1)
        if escape[0] == "x":
            return chr(int(escape[1:], 16))
        if escape[0] in "01234567":
            return chr(int(escape, 8))
        return SIMPLE_ESCAPES.get(escape, escape)
    return ESCAPE.sub(replace, literal)


def scan_source(text):
    """The source without comments, and its string literals, adjacent ones concatenated."""
    code, literals = [], []
    pos, last_literal_end = 0, None
    for match in CPP_TOKEN.finditer(text):
        code.append(text[pos:match.start()])
        pos = match.end()
        if match.group("comment") is not None:
            code.append(" ")
            last_literal_end = None
            continue
        code.append(match.group(0))
        if match.group("raw") is not None:
            value = match.group("raw")
        elif match.group("str") is not None:
            value = unescape(match.group("str"))
        else:
            last_literal_end = None
            continue
        if last_literal_end is not None and not text[last_literal_end:match.start()].strip():
            literals[-1] += value
        else:
            literals.append(value)
        last_literal_end = match.end()
    code.append(text[pos:])
    return "".join(code), literals


def help_options(code):
    """The options of the AddArg() calls in code, without comments, that -help or -help-debug lists:
    all but those of OptionsCategory::HIDDEN."""
    if "AddArg" not in code:
        return set()
    # The code with its literals blanked, so that a parenthesis in one doesn't end a call early.
    bare = CPP_TOKEN.sub(lambda match: " " * len(match.group(0)), code)
    options = set()
    for match in ADDARG.finditer(code):
        start, depth = match.start() + len("AddArg"), 0
        for end in range(start, len(bare)):
            depth += {"(": 1, ")": -1}.get(bare[end], 0)
            if depth == 0:
                break
        if not HIDDEN_CATEGORY.search(bare, start, end + 1):
            options.add(match.group(1))
    return options


def read_sources():
    sources = {}
    for path in files("src", SOURCE_SUFFIXES):
        if path.startswith(SUBTREES) or {"test", "bench"} & set(Path(path).parts):
            continue
        sources[path] = (ROOT / path).read_text(encoding="utf8")
    return sources


def help_output(qbitd, qbit_cli):
    """What qbitd -help and -help-debug, and qbit-cli -help (it has no -help-debug), print."""
    outputs = []
    for argv in ([qbitd, "-help"], [qbitd, "-help-debug"], [qbit_cli, "-help"]):
        outputs.append(subprocess.run(argv, check=True, capture_output=True, text=True, encoding="utf8").stdout)
    return "\n".join(outputs)


def build_corpus(sources, help_text):
    rpcs, fields, options, literals = set(), set(), set(), set()
    for text in sources.values():
        code, file_literals = scan_source(text)
        rpcs.update(RPC_NAME.findall(code))
        fields.update(PUSHKV.findall(code))
        options.update(help_options(code))
        literals.update(file_literals)
    if help_text is not None:
        options = set(HELP_OPTION.findall(help_text))
    messages = "\0".join(PRINTF_CONVERSION.sub(lambda m: "%" if m.group(0) == "%%" else "…", literal) for literal in literals)
    return Corpus(options=options, rpcs=rpcs, fields=fields, literals=literals, messages=messages)


def option_name(token):
    name = token.split("=", 1)[0]
    return name if name.startswith("-") else "-" + name


def known_option(name, options):
    """Whether -name, or the option -noname negates, is in options."""
    return name in options or (name.startswith("-no") and "-" + name[3:] in options)


def at_word_boundaries(token, text):
    start = text.find(token)
    while start != -1:
        end = start + len(token)
        if ((start == 0 or not (WORD.match(token[0]) and WORD.match(text[start - 1]))) and
                (end == len(text) or not (WORD.match(token[-1]) and WORD.match(text[end])))):
            return True
        start = text.find(token, start + 1)
    return False


def check_token(token, corpus):
    """Why the token doesn't exist, or None."""
    text = token.text
    if token.kind == "opt":
        if not OPTION_TOKEN.fullmatch(text):
            return "is not an option"
        name = option_name(text)
        return None if known_option(name, corpus.options) else f"option {name} is not listed by -help or -help-debug"
    if token.kind == "rpc":
        return None if text in corpus.rpcs else "is not an RPC method"
    if token.kind == "field":
        if not FIELD_TOKEN.fullmatch(text):
            return "is not an RPC field"
        missing = [part for part in text.split(".") if part not in corpus.fields]
        return f"names no RPC result field {', '.join(missing)}" if missing else None
    if token.kind == "value":
        return None if text in corpus.literals else "is not a string literal in the code"
    assert token.kind == "log"
    return None if at_word_boundaries(text, corpus.messages) else "is not part of a log or warning string in the code"


def check(tokens, corpus):
    return [(token, reason) for token in tokens if (reason := check_token(token, corpus)) is not None]


def format_failure(token, reason):
    return f"{token.path}:{token.line}: {token.kind} token '{token.text}' {reason}"


def read_docs():
    docs = {}
    for path in files("doc", (".md",)):
        if path.startswith(ARCHIVED_RELEASE_NOTES):
            continue
        text = (ROOT / path).read_text(encoding="utf8")
        if MARKER_START.search(text):
            docs[path] = text
    return docs


def replace_all(text, old, new):
    assert old in text, f"self-test: '{old}' not found; update the self-test"
    return text.replace(old, new)


def self_test(docs_tokens, sources, help_text):
    """Problems with the check itself: a mutation it doesn't catch, or a malformed marker it accepts."""
    problems = []
    corpus = build_corpus(sources, help_text)

    def token_name(token):
        """A token's name: an option, or the option a negation negates, without a value."""
        if token.kind != "opt":
            return token.text
        option = option_name(token.text)
        return option if option in corpus.options else "-" + option[3:]

    def failing(mutated_sources, mutated_help):
        return {(token.kind, token_name(token)) for token, _ in check(docs_tokens, build_corpus(mutated_sources, mutated_help))}

    # Only what a mutation adds to the failures counts, so that a doc error is reported once.
    baseline = failing(sources, help_text)

    def mutate(path, old, new):
        return {**sources, path: replace_all(sources[path], old, new)}

    if help_text is None:
        renamed_option = (mutate("src/init.cpp", 'AddArg("-v2pqtransport"', 'AddArg("-v2pqtransportx"'), None)
    else:
        renamed_option = (sources, replace_all(help_text, "\n  -v2pqtransport\n", "\n  -v2pqtransportx\n"))
    mutations = [
        ("a renamed option", renamed_option, {("opt", "-v2pqtransport")}),
        ("a renamed RPC field", (mutate("src/rpc/net.cpp", 'pushKV("transport_pq_status"', 'pushKV("transport_pq_state"'), help_text),
         {("field", "transport_pq_status")}),
        ("a changed log string", (mutate("src/net.cpp", '"v2 pq: load_shedding started threshold_per_s=%u"',
                                         '"v2 pq: load_shedding began threshold_per_s=%u"'), help_text),
         {("log", "v2 pq: load_shedding started threshold_per_s=…")}),
    ]
    if help_text is None:
        # An option that -help-debug doesn't list either.
        mutations.append(("a hidden option", (mutate("src/init.cpp", "DEFAULT_V2_PQ_TRANSPORT), ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION)",
                                                     "DEFAULT_V2_PQ_TRANSPORT), ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN)"), None),
                          {("opt", "-v2pqtransport")}))
    for name, (mutated_sources, mutated_help), expected in mutations:
        caught = failing(mutated_sources, mutated_help) - baseline
        if caught != expected:
            problems.append(f"self-test: {name} should fail exactly {sorted(expected)}, but failed {sorted(caught)}")

    # Each case, on line 3 of a document, gives one error at the given line.
    malformed = [
        ("<!--pq:opt-->``", 3),
        ("<!--pq:opt-->` `", 3),
        ("<!--pq:opt-->` -v2pqtransport`", 3),
        ("<!--pq:option-->`-v2pqtransport`", 3),
        ("<!-- pq:opt -->`-v2pqtransport`", 3),
        ("<!--PQ:opt-->`-v2pqtransport`", 3),
        ("<!--pq:opt`-v2pqtransport`", 3),
        ("<!--pq:opt-->`-v2pqtransport", 3),
        ("<!--pq:opt--> `-v2pqtransport`", 3),
        ("```\n<!--pq:opt-->`-v2pqtransport`\n```", 4),
        ("```", 3),
        ("<!--pq-opt-->`-v2pqtransport`", 3),
        ("<!--pqopt-->`-v2pqtransport`", 3),
        ("<!--pq_field-->`transport_pq_status`", 3),
        ("<!-- pqopt -->`-v2pqtransport`", 3),
        # A block of quoted vectors anywhere but the specification, where the generator doesn't read it.
        ("<!-- pq-transport-vectors: vector 0 -->\n```text\nmagic = 444f24a8\n```", 3),
    ]
    for case, line in malformed:
        tokens, errors = parse_markers("self-test.md", "Some text.\n\n" + case + "\n")
        if tokens or len(errors) != 1 or not errors[0].startswith(f"self-test.md:{line}: "):
            problems.append(f"self-test: {case!r} should give one error at self-test.md:{line}, but gave {errors} and tokens {tokens}")

    # In the specification, a block of quoted vectors that the generator reads is no marker, and a near miss fails.
    block = "<!-- pq-transport-vectors: vector 0 -->\n```text\nmagic = 444f24a8\n```"
    vectors = [
        (block, None),
        ("Text " + block, None),
        (block.replace("vectors:", "vector:"), 3),
        (block.replace("<!-- pq", "<!--pq"), 3),
        (block.replace("```text", "```"), 3),
        (block.replace("-->\n", "-->\n\n"), 3),
    ]
    for case, line in vectors:
        tokens, errors = parse_markers(VECTORS_SPEC, "Some text.\n\n" + case + "\n")
        if line is None:
            if tokens or errors:
                problems.append(f"self-test: {case!r} in {VECTORS_SPEC} should pass, but gave {errors} and tokens {tokens}")
        elif tokens or len(errors) != 1 or not errors[0].startswith(f"{VECTORS_SPEC}:{line}: "):
            problems.append(f"self-test: {case!r} should give one error at {VECTORS_SPEC}:{line}, but gave {errors} and tokens {tokens}")

    exact = [
        ("opt", "-v2pqtransport", True), ("opt", "-v2pqtranspor", False), ("opt", "-nov2pqtransport", True),
        ("opt", "-checkpoints", False),
        ("rpc", "getpqtransportinfo", True), ("rpc", "getpqtransport", False),
        ("field", "transport_pq_status", True), ("field", "transport_pq_stat", False), ("field", "load_shedding.active", True),
        ("value", "hybrid", True), ("value", "hybri", False),
        ("log", "v2 pq: load_shedding started", True), ("log", "v2 pq: load_shedding start", False),
        ("log", "2 pq: load_shedding started", False), ("log", "v2 pq: load_shedding started threshold_per_s=%u", False),
    ]
    for kind, text, valid in exact:
        reason = check_token(Token("self-test.md", 1, kind, text), corpus)
        if (reason is None) != valid:
            problems.append(f"self-test: {kind} token '{text}' should {'pass' if valid else 'fail'}, but {reason or 'passed'}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--qbitd", help="check options against this qbitd's -help and -help-debug")
    parser.add_argument("--qbit-cli", help="and this qbit-cli's")
    args = parser.parse_args()
    if (args.qbitd is None) != (args.qbit_cli is None):
        parser.error("--qbitd and --qbit-cli go together")

    docs = read_docs()
    tokens, errors = [], []
    for path, text in docs.items():
        doc_tokens, doc_errors = parse_markers(path, text)
        tokens += doc_tokens
        errors += doc_errors
    for path in REQUIRED_DOCS:
        if not any(token.path == path for token in tokens):
            errors.append(f"{path}: no marked tokens")

    sources = read_sources()
    help_text = None if args.qbitd is None else help_output(args.qbitd, args.qbit_cli)
    errors += [format_failure(token, reason) for token, reason in check(tokens, build_corpus(sources, help_text))]
    errors += self_test(tokens, sources, help_text)

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print("^---- failure generated from lint-pq-doc-tokens.py: see test/lint/README.md", file=sys.stderr)
        sys.exit(1)
    options_from = "-help and -help-debug" if help_text is not None else "AddArg() calls"
    print(f"{len(tokens)} marked tokens in {len(docs)} documents exist (options from {options_from}); self-test passed")


if __name__ == "__main__":
    main()
