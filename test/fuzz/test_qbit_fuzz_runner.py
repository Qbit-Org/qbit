#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for test/fuzz/test_runner.py --require_qbit_corpus and --mutate_min_time, and the qbit seed corpora.

Transport tests run the real runner entry point in a temporary build tree
against a stub fuzz executable that records how it was spawned. They check
option handling, spawned commands and failure reporting only; no harness code
runs. Integration tests use a real fuzz executable and only run, and fail
rather than skip, when --build-dir is given.

    test/fuzz/test_qbit_fuzz_runner.py
    test/fuzz/test_qbit_fuzz_runner.py --build-dir <build> [--mutate-seconds N]
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
SRC_DIR = Path(__file__).resolve().parents[2]
RUNNER = SRC_DIR / "test" / "fuzz" / "test_runner.py"
CORPORA_DIR = SRC_DIR / "test" / "fuzz" / "qbit_corpora"
REQUIRED = ("asert_chain_transition", "asert_edge_cases", "asert_math", "auxpow", "p2mr_script", "pqc")
INTEGRATION = {}

STUB_SOURCE = r'''
import json
import os
import sys
import time
from pathlib import Path


def env_map(name):
    return dict(item.split(":", 1) for item in os.environ.get(name, "").split(",") if item)


target = os.environ.get("FUZZ", "")
mode = os.environ["STUB_MODE"]
argv = sys.argv[1:]
if "PRINT_ALL_FUZZ_TARGETS_AND_ABORT" in os.environ:
    print("\n".join(os.environ["STUB_TARGETS"].split(",")))
    sys.exit(0)
if argv == ["-help=1"]:
    if mode == "libfuzzer":
        print("Usage: this stub imitates libFuzzer", file=sys.stderr)
        sys.exit(0)
    print('Error processing input "-help=1"', file=sys.stderr)
    sys.exit(1)

flags = dict(a[1:].split("=", 1) for a in argv if a.startswith("-"))
dirs = [a for a in argv if not a.startswith("-")]
with open(os.environ["STUB_LOG"], "a", encoding="utf8") as f:
    f.write(json.dumps({"target": target, "argv": argv, "dirs_exist": [Path(d).is_dir() for d in dirs]}) + "\n")
time.sleep(float(env_map("STUB_SLEEP").get(target, 0)))
if target in env_map("STUB_EXIT"):
    print("stub failure", file=sys.stderr)
    sys.exit(int(env_map("STUB_EXIT")[target]))
report_count = target not in os.environ.get("STUB_NO_COUNT", "").split(",")
forced = env_map("STUB_FORCE_COUNT").get(target)

if mode == "native":
    count = sum(1 for d in dirs for p in Path(d).iterdir() if p.is_file())
    if report_count:
        print(f"{target}: succeeded against {forced or count} files in 0s.")
    sys.exit(0)

count = sum(1 for p in Path(dirs[-1]).rglob("*") if p.is_file()) if dirs else 0
count = int(forced) if forced is not None else count
print(f"INFO: Seed: 1234", file=sys.stderr)
if report_count:
    print(f"INFO: seed corpus: files: {count} min: 1b max: 1b total: 1b rss: 1Mb", file=sys.stderr)
if "max_total_time" in flags:
    if len(dirs) == 2:
        (Path(dirs[0]) / "new-unit").write_bytes(b"x")
    seconds = env_map("STUB_SECONDS").get(target, int(flags["max_total_time"]) + 1)
    print("#100\tDONE   cov: 1 ft: 1 corp: 1/1b", file=sys.stderr)
    print(f"Done 100 runs in {seconds} second(s)", file=sys.stderr)
else:
    print(f"#{count + 1}\tDONE   cov: 1 ft: 1 corp: 1/1b", file=sys.stderr)
    print(f"Done {count + 1} runs in 0 second(s)", file=sys.stderr)
'''


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(str(path.relative_to(root)).encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def make_corpus(root, counts):
    for target, count in counts.items():
        (root / target).mkdir(parents=True, exist_ok=True)
        for i in range(count):
            (root / target / f"input{i}").write_bytes(bytes([i]))
    return root


class RunnerTransportTest(unittest.TestCase):
    """Drive the real runner with a stub fuzz executable."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="qbit_fuzz_runner_test_"))
        self.addCleanup(shutil.rmtree, self.tmp)
        build = self.tmp / "build"
        (build / "test" / "fuzz").mkdir(parents=True)
        (build / "test" / "config.ini").write_text(
            f"[environment]\nSRCDIR={SRC_DIR}\nBUILDDIR={build}\n[components]\nENABLE_FUZZ_BINARY=true\n",
            encoding="utf8",
        )
        self.runner = build / "test" / "fuzz" / "test_runner.py"
        try:
            self.runner.symlink_to(RUNNER)  # as test/CMakeLists.txt does outside Windows
        except OSError:
            shutil.copy(RUNNER, self.runner)
        self.stub = self.tmp / "fuzz_stub.py"
        self.stub.write_text(f"#!{sys.executable}\n{STUB_SOURCE}", encoding="utf8")
        self.stub.chmod(0o755)
        self.log = self.tmp / "stub_log.jsonl"
        self.corpus = self.tmp / "corpus"

    def run_runner(self, *args, mode="libfuzzer", targets=REQUIRED + ("process_message",), stub_env=None, code=None):
        env = os.environ | {
            "BITCOINFUZZ": str(self.stub),
            "STUB_MODE": mode,
            "STUB_TARGETS": ",".join(targets),
            "STUB_LOG": str(self.log),
            **(stub_env or {}),
        }
        command = [sys.executable, str(self.runner), *map(str, args)]
        if code is not None:
            command = [sys.executable, "-c", code, str(self.runner), *map(str, args)]
        return subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)

    def spawned(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf8").splitlines()]

    def assert_failed(self, result, pattern, returncode=1):
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, returncode, output)
        self.assertRegex(output, pattern)

    def test_required_replay_rejects_zero_inputs(self):
        for target in REQUIRED:
            for case in ("missing", "empty", "subdir-only"):
                with self.subTest(target=target, case=case):
                    shutil.rmtree(self.corpus, ignore_errors=True)
                    self.log.unlink(missing_ok=True)
                    make_corpus(self.corpus, {t: 2 for t in REQUIRED if t != target})
                    if case in ("empty", "subdir-only"):
                        (self.corpus / target).mkdir()
                    if case == "subdir-only":
                        make_corpus(self.corpus / target, {"nested": 3})
                    result = self.run_runner("--require_qbit_corpus", self.corpus)
                    reason = "does not exist" if case == "missing" else "has no regular input files"
                    self.assert_failed(result, rf"Required qbit corpus check failed: {target}: corpus directory .* {reason}")
                    self.assertEqual(self.spawned(), [], "no fuzz input may run once the corpus check fails")

    def test_required_target_cannot_disappear(self):
        make_corpus(self.corpus, {t: 2 for t in REQUIRED})
        cases = {
            "not detected": dict(args=["--require_qbit_corpus", self.corpus], targets=tuple(t for t in REQUIRED if t != "auxpow"),
                                 pattern=r"auxpow: not compiled into the fuzz executable"),
            "subset selected": dict(args=["--require_qbit_corpus", self.corpus, "pqc", "p2mr_script"], targets=REQUIRED,
                                    pattern=r"asert_math: not selected"),
            "excluded": dict(args=["--require_qbit_corpus", "--exclude", "pqc", self.corpus], targets=REQUIRED,
                             pattern=r"pqc: not selected"),
        }
        for name, case in cases.items():
            with self.subTest(case=name):
                self.log.unlink(missing_ok=True)
                result = self.run_runner(*case["args"], targets=case["targets"])
                self.assert_failed(result, case["pattern"])
                self.assertEqual(self.spawned(), [])

        with self.subTest(case="ordinary subset without the flag"):
            self.log.unlink(missing_ok=True)
            shutil.rmtree(self.corpus)
            make_corpus(self.corpus, {"asert_math": 1})
            result = self.run_runner(self.corpus, "asert_math")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual([r["target"] for r in self.spawned()], ["asert_math"])
            self.assertNotIn("Required qbit corpus replay", result.stdout)

    def test_required_replay_reports_exact_counts(self):
        counts = {t: i + 1 for i, t in enumerate(REQUIRED)}
        make_corpus(self.corpus, counts | {"process_message": 1})
        for mode in ("libfuzzer", "native"):
            with self.subTest(mode=mode):
                result = self.run_runner("--require_qbit_corpus", self.corpus, mode=mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for target, count in counts.items():
                    self.assertIn(f"{target}: {count} regular input files present, {count} inputs replayed", result.stdout)
                self.assertNotIn("process_message: ", result.stdout.split("Required qbit corpus replay:")[1])

    def test_required_replay_fails_without_replay_evidence(self):
        make_corpus(self.corpus, {t: 2 for t in REQUIRED})
        cases = [
            ("libfuzzer", {"STUB_NO_COUNT": "pqc"}, r"pqc: 2 regular input files present, FAILED: the fuzz executable did not report"),
            ("native", {"STUB_NO_COUNT": "pqc"}, r"pqc: 2 regular input files present, FAILED: the fuzz executable did not report"),
            ("libfuzzer", {"STUB_FORCE_COUNT": "auxpow:0"}, r"auxpow: 2 regular input files present, FAILED: 0 inputs replayed"),
            ("native", {"STUB_FORCE_COUNT": "auxpow:1"}, r"auxpow: 2 regular input files present, FAILED: 1 inputs replayed"),
        ]
        for mode, stub_env, pattern in cases:
            with self.subTest(mode=mode, stub_env=stub_env):
                self.assert_failed(self.run_runner("--require_qbit_corpus", self.corpus, mode=mode, stub_env=stub_env), pattern)

    def test_replay_fails_when_fuzz_executable_fails(self):
        make_corpus(self.corpus, {t: 1 for t in REQUIRED})
        result = self.run_runner("--require_qbit_corpus", self.corpus, stub_env={"STUB_EXIT": "p2mr_script:77"})
        self.assert_failed(result, r"Failure generated from target with exit code 77")

    def test_seeded_mutation_uses_time_budget(self):
        make_corpus(self.corpus, {t: 3 for t in REQUIRED})
        before = tree_digest(self.corpus)
        result = self.run_runner("--require_qbit_corpus", "--mutate_min_time=60", self.corpus, *REQUIRED)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        mutation_runs = [r for r in self.spawned() if r["target"] in REQUIRED]
        self.assertEqual(sorted(r["target"] for r in mutation_runs), sorted(REQUIRED))
        for run in mutation_runs:
            argv = run["argv"]
            with self.subTest(target=run["target"]):
                self.assertIn("-max_total_time=60", argv)
                self.assertFalse(any(a.startswith("-runs=") for a in argv), argv)
                output_dir, input_dir = [a for a in argv if not a.startswith("-")]
                self.assertEqual(Path(input_dir), self.corpus / run["target"])
                self.assertEqual(run["dirs_exist"], [True, True])
                self.assertFalse(Path(output_dir).is_relative_to(self.corpus))
                self.assertFalse(Path(output_dir).exists(), "temporary output directory must be removed")
                self.assertRegex(result.stdout, rf"{run['target']}: rng seed 1234, 3 seed corpus inputs, 100 runs in 61s")
        self.assertEqual(tree_digest(self.corpus), before, "the corpus must not be modified")

    def test_mutation_rejects_invalid_budgets(self):
        make_corpus(self.corpus, {t: 1 for t in REQUIRED})
        for value in ("0", "-1", "abc", "1.5", "3601", "", " 60", "6_0", "+60", "060"):
            with self.subTest(value=value):
                self.assert_failed(self.run_runner(f"--mutate_min_time={value}", self.corpus), r"expected a whole number of seconds from 1 to 3600", returncode=2)
        for extra in (["--generate"], ["--m_dir", self.tmp], ["--empty_min_time=60"], ["--valgrind"]):
            with self.subTest(extra=extra):
                self.assert_failed(self.run_runner("--mutate_min_time=60", *extra, self.corpus), r"--mutate_min_time cannot be combined with", returncode=2)
        self.assertEqual(self.spawned(), [])
        for value in ("1", "3600"):
            with self.subTest(value=value):
                result = self.run_runner("--require_qbit_corpus", f"--mutate_min_time={value}", self.corpus, *REQUIRED)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mutation_fails_on_native_executable(self):
        make_corpus(self.corpus, {t: 1 for t in REQUIRED})
        result = self.run_runner("--require_qbit_corpus", "--mutate_min_time=60", self.corpus, *REQUIRED, mode="native")
        self.assert_failed(result, r"--mutate_min_time requires a fuzz executable built with libFuzzer")
        self.assertEqual(self.spawned(), [])

    def test_mutation_failures_are_reported_and_cleaned_up(self):
        make_corpus(self.corpus, {t: 1 for t in REQUIRED})
        cases = [
            ({"STUB_EXIT": "pqc:1"}, None, r"Failure generated from target with exit code 1"),
            ({"STUB_SECONDS": "auxpow:5"}, None, r"auxpow: stopped after 5s, before the 60s budget"),
            ({"STUB_NO_COUNT": "asert_math"}, None, r"asert_math: seed corpus inputs run: None, regular input files present: 1"),
        ]
        for stub_env, code, pattern in cases:
            with self.subTest(stub_env=stub_env):
                self.log.unlink(missing_ok=True)
                result = self.run_runner("--require_qbit_corpus", "--mutate_min_time=60", self.corpus, *REQUIRED, stub_env=stub_env, code=code)
                self.assert_failed(result, pattern)
                for run in self.spawned():
                    self.assertFalse(Path(run["argv"][-2]).exists(), "temporary output directory must be removed")

    def test_mutation_timeout_stops_child_promptly(self):
        make_corpus(self.corpus, {t: 1 for t in REQUIRED})
        code = ("import importlib.util, sys, time; path = sys.argv[1]; sys.argv = sys.argv[1:]; "
                "spec = importlib.util.spec_from_file_location('fuzz_runner', path); m = importlib.util.module_from_spec(spec); "
                "spec.loader.exec_module(m); m.MUTATION_TIMEOUT_GRACE_SECONDS = 1; m.main()")
        result = self.run_runner("--mutate_min_time=1", self.corpus, "pqc", stub_env={"STUB_SLEEP": "pqc:60"}, code=code)
        self.assert_failed(result, r"pqc: mutation phase did not exit within 2s and was stopped")


class QbitCorporaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="qbit_corpora_test_"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.manifest = json.loads((CORPORA_DIR / "MANIFEST.json").read_text(encoding="utf8"))

    def run_overlay(self, corpus_dir, corpora_dir=CORPORA_DIR):
        return subprocess.run([sys.executable, str(corpora_dir / "overlay.py"), str(corpus_dir)], capture_output=True, text=True, timeout=60)

    def test_committed_seeds_match_generator(self):
        result = subprocess.run([sys.executable, str(CORPORA_DIR / "generate_seeds.py"), "--check"], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_identifies_formats_and_limits(self):
        self.assertEqual(tuple(sorted(self.manifest["targets"])), REQUIRED)
        total = 0
        for target, entries in self.manifest["targets"].items():
            self.assertLessEqual(len(entries), 16)
            target_bytes = 0
            for entry in entries:
                data = (CORPORA_DIR / target / entry["file"]).read_bytes()
                self.assertLessEqual(len(data), 8 * 1024)
                target_bytes += len(data)
                tag = {"pqc": b"P", "p2mr_script": b"M"}.get(target)
                if entry["format"].startswith("qbfx-v1-"):
                    self.assertEqual(data[:6], b"QBFX" + tag + b"\x01", entry["file"])
                    self.assertEqual((data[6] & 0x0F) == 0x0F, entry["format"] == "qbfx-v1-generation", entry["file"])
                else:
                    self.assertFalse(data.startswith(b"QBFX"), entry["file"])
            self.assertLessEqual(target_bytes, 64 * 1024)
            total += target_bytes
            if target in ("pqc", "p2mr_script"):
                formats = {e["format"] for e in entries}
                self.assertEqual(formats, {"legacy", "qbfx-v1-fixture", "qbfx-v1-generation"})
        self.assertLessEqual(total, 384 * 1024)

    def test_overlay_keeps_existing_inputs_and_replaces_stale_overlay(self):
        corpus = make_corpus(self.tmp / "fuzz_corpora", {"pqc": 2, "process_message": 3})
        (corpus / "pqc" / "qbit-removed-case").write_bytes(b"stale")
        upstream_before = tree_digest(corpus / "process_message")
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                result = self.run_overlay(corpus)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((corpus / "pqc" / "qbit-removed-case").exists())
                self.assertEqual((corpus / "pqc" / "input1").read_bytes(), b"\x01")
                self.assertEqual(tree_digest(corpus / "process_message"), upstream_before)
                for target, entries in self.manifest["targets"].items():
                    names = sorted(p.name for p in (corpus / target).iterdir() if p.name.startswith("qbit-"))
                    self.assertEqual(names, sorted("qbit-" + e["file"] for e in entries))
                    for entry in entries:
                        self.assertEqual(hashlib.sha256((corpus / target / ("qbit-" + entry["file"])).read_bytes()).hexdigest(), entry["sha256"])
                self.assertIn("pqc: overlaid 16 qbit seed files, kept 2 existing input files", result.stdout)

    def test_overlay_refuses_unsafe_destinations_and_inputs(self):
        entry = self.manifest["targets"]["auxpow"][0]["file"]
        corpus = self.tmp / "fuzz_corpora"
        corpus.mkdir()
        (corpus / "auxpow" / f"qbit-{entry}").mkdir(parents=True)
        self.assertRegex(self.run_overlay(corpus).stderr, r"already exists and is not a replaceable overlay seed")
        self.assertRegex(self.run_overlay(self.tmp / "missing").stderr, r"corpus directory does not exist")

        for damage in ("modified", "extra-file", "subdirectory"):
            with self.subTest(damage=damage):
                copy = self.tmp / f"corpora-{damage}"
                shutil.copytree(CORPORA_DIR, copy, ignore=shutil.ignore_patterns("__pycache__"))
                if damage == "modified":
                    seed = copy / "pqc" / self.manifest["targets"]["pqc"][0]["file"]
                    seed.write_bytes(seed.read_bytes()[:-1] + b"\xff")
                elif damage == "extra-file":
                    (copy / "pqc" / "unlisted").write_bytes(b"x")
                else:
                    (copy / "pqc" / "nested").mkdir()
                fresh = self.tmp / f"out-{damage}"
                fresh.mkdir()
                result = self.run_overlay(fresh, corpora_dir=copy)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertRegex(result.stderr, r"sha256 does not match|do not match manifest entries")
                self.assertEqual(list(fresh.iterdir()), [], "nothing may be overlaid from an invalid seed tree")


class RealFuzzExecutableTest(unittest.TestCase):
    """Replay the committed seeds with a real fuzz executable through the build tree's runner."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="qbit_fuzz_integration_"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.corpus = self.tmp / "fuzz_corpora"
        self.corpus.mkdir()
        result = subprocess.run([sys.executable, str(CORPORA_DIR / "overlay.py"), str(self.corpus)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.manifest = json.loads((CORPORA_DIR / "MANIFEST.json").read_text(encoding="utf8"))
        self.runner = INTEGRATION["build_dir"] / "test" / "fuzz" / "test_runner.py"
        self.env = os.environ | ({"BITCOINFUZZ": str(INTEGRATION["fuzz_binary"])} if INTEGRATION["fuzz_binary"] else {})

    def run_runner(self, *args, timeout):
        return subprocess.run([sys.executable, str(self.runner), *map(str, args)], env=self.env, capture_output=True, text=True, timeout=timeout)

    def test_required_corpora_replay_nonzero(self):
        result = self.run_runner("--require_qbit_corpus", "-l", "DEBUG", "--par", "6", self.corpus, *REQUIRED, timeout=3600)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        for target, entries in self.manifest["targets"].items():
            match = re.search(rf"^{target}: (\d+) regular input files present, (\d+) inputs replayed$", result.stdout, re.MULTILINE)
            self.assertIsNotNone(match, f"{target} replay evidence missing:\n{output}")
            self.assertEqual(int(match.group(1)), len(entries))
            self.assertGreaterEqual(int(match.group(2)), len(entries))

    def test_mutation_phase_matches_engine(self):
        seconds = INTEGRATION["mutate_seconds"]
        result = self.run_runner("--require_qbit_corpus", f"--mutate_min_time={seconds}", "--par", "6", self.corpus, *REQUIRED, timeout=seconds + 3600)
        output = result.stdout + result.stderr
        if "Check if using libFuzzer ... True" in result.stdout:
            self.assertEqual(result.returncode, 0, output)
            for target in REQUIRED:
                self.assertRegex(result.stdout, rf"{target}: rng seed \d+, \d+ seed corpus inputs, \d+ runs in \d+s")
        else:
            self.assertEqual(result.returncode, 1, output)
            self.assertIn("--mutate_min_time requires a fuzz executable built with libFuzzer", output)
        self.assertEqual(result.returncode == 0, "Check if using libFuzzer ... True" in result.stdout)


def load_runner_module():
    spec = importlib.util.spec_from_file_location("fuzz_test_runner", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RunnerModuleTest(unittest.TestCase):
    def test_required_targets_match_corpora(self):
        self.assertEqual(load_runner_module().QBIT_REQUIRED_CORPUS_TARGETS, REQUIRED)
        self.assertEqual(sorted(p.name for p in CORPORA_DIR.iterdir() if p.is_dir() and p.name != "__pycache__"), list(REQUIRED))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", type=Path, help="Configured build tree with a fuzz executable; enables integration tests.")
    parser.add_argument("--fuzz-binary", type=Path, help="Fuzz executable to use instead of <build-dir>/bin/fuzz.")
    parser.add_argument("--mutate-seconds", type=int, default=5, help="Mutation budget per target for the integration test.")
    args, unittest_args = parser.parse_known_args()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (RunnerTransportTest, QbitCorporaTest, RunnerModuleTest):
        suite.addTests(loader.loadTestsFromTestCase(case))
    if args.build_dir:
        INTEGRATION.update(build_dir=args.build_dir.resolve(), fuzz_binary=args.fuzz_binary, mutate_seconds=args.mutate_seconds)
        suite.addTests(loader.loadTestsFromTestCase(RealFuzzExecutableTest))
    elif args.fuzz_binary:
        parser.error("--fuzz-binary requires --build-dir")
    if unittest_args:
        suite = unittest.TestSuite(t for t in _flatten(suite) if any(name in t.id() for name in unittest_args))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


if __name__ == "__main__":
    main()
