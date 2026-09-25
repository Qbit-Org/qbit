#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Check that named qbit seeds still reach key generation, signing and P2MR verification.

Each named seed runs alone in a fuzz executable built with
-fprofile-instr-generate -fcoverage-mapping. Its profile is exported with
llvm-cov, and the execution count is read at a column-precise anchor. A
single-line `if (...) return ...;` has separate regions for the condition and
the return, so line counts alone are not enough. Anchors are located by
source text in the checked-out tree, and a missing or ambiguous anchor fails
the test.

Legacy and generation seeds run in processes that never build the cached
fixtures, and target .init code runs before coverage counters are reset. So
key generation and signing counts for those seeds come from the input itself.

    test/fuzz/test_qbit_fuzz_coverage.py --fuzz-binary <coverage build>/bin/fuzz \\
        [--llvm-profdata llvm-profdata] [--llvm-cov llvm-cov] [--path-equivalence FROM,TO]
    test/fuzz/test_qbit_fuzz_coverage.py --anchors-only   # resolve anchors, no coverage
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[2]
CORPORA_DIR = SRC_DIR / "test" / "fuzz" / "qbit_corpora"
CONFIG = {}


@dataclass(frozen=True)
class Anchor:
    """Execution count at `token` on the last line of `lines`, which must occur exactly once, consecutively, in `file`."""
    file: str
    lines: tuple
    token: str


INTERPRETER = "src/script/interpreter.cpp"
ANCHORS = {
    # P2MR script path execution and PQC signature checking.
    "p2mr_execute_leaf": Anchor(INTERPRETER, ("return ExecuteWitnessScript(stack, exec_script, flags, SigVersion::P2MR, checker, execdata, serror);",), "return"),
    "p2mr_checksig_call": Anchor(INTERPRETER, ("if (success && !checker.CheckPQCSignature(sig, pubkey, sigversion, execdata, serror)) {",), "checker.CheckPQCSignature"),
    "p2mr_sig_size_reject": Anchor(INTERPRETER, ("if (sig.size() != PQC_SIG_SIZE && sig.size() != PQC_SIG_SIZE + 1) return set_error(serror, SCRIPT_ERR_P2MR_SIG_SIZE);",), "return"),
    "p2mr_hashtype_pop": Anchor(INTERPRETER, ("if (sig.size() == PQC_SIG_SIZE + 1) {", "hashtype = SpanPopBack(sig);"), "hashtype"),
    "p2mr_hashtype_invalid": Anchor(INTERPRETER, ("if (!SignatureHashP2MR(sighash, execdata, *txTo, nIn, hashtype, *this->txdata, m_mdb)) {", "return set_error(serror, SCRIPT_ERR_P2MR_SIG_HASHTYPE);"), "return"),
    "p2mr_verify_call": Anchor(INTERPRETER, ("if (!VerifyPQCSignature(sig, pubkey, sighash)) return set_error(serror, SCRIPT_ERR_P2MR_SIG);",), "VerifyPQCSignature"),
    "p2mr_verify_reject": Anchor(INTERPRETER, ("if (!VerifyPQCSignature(sig, pubkey, sighash)) return set_error(serror, SCRIPT_ERR_P2MR_SIG);",), "return"),
    "p2mr_verify_accept": Anchor(INTERPRETER, ("if (!VerifyPQCSignature(sig, pubkey, sighash)) return set_error(serror, SCRIPT_ERR_P2MR_SIG);", "return true;"), "return"),
    "ctv_mismatch": Anchor(INTERPRETER, ("return set_error(serror, SCRIPT_ERR_TEMPLATE_MISMATCH);",), "return"),
    "ctv_match": Anchor(INTERPRETER, ("return set_error(serror, SCRIPT_ERR_TEMPLATE_MISMATCH);", "}", "return true;"), "return"),
    "witness_script_accept": Anchor(INTERPRETER, ("if (stack.size() != 1) return set_error(serror, SCRIPT_ERR_CLEANSTACK);", "if (!CastToBool(stack.back())) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);", "return true;"), "return"),
    "p2mr_control_size_reject": Anchor(INTERPRETER, ("return set_error(serror, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);",), "return"),
    "p2mr_control_bit0_reject": Anchor(INTERPRETER, ("return set_error(serror, SCRIPT_ERR_P2MR_CONTROL_BIT0);",), "return"),
    # Signing: transaction signature creation and the PQC key wrapper.
    "sign_pqc_provider": Anchor("src/script/sign.cpp", ("if (!provider.SignPQC(pubkey, hash, raw_sig)) return false;",), "provider.SignPQC"),
    "sign_pqc_append_hashtype": Anchor("src/script/sign.cpp", ("sig = std::move(raw_sig);", "if (nHashType) sig.push_back(nHashType);"), "sig.push_back"),
    "pqc_set_reject": Anchor("src/crypto/pqc.cpp", ("slh_dsa_secret_key_validate(begin, SIZE) != 0) {", "ClearKeyData();"), "ClearKeyData"),
    "pqc_set_accept": Anchor("src/crypto/pqc.cpp", ("MakeKeyData();", "std::memcpy(m_keydata->data(), begin, SIZE);"), "std::memcpy"),
    "pqc_sign_refused": Anchor("src/crypto/pqc.cpp", ("if (!IsValid() || counter_inout >= PQC_MAX_SIGNATURES) return finish(false);",), "return"),
    "pqc_sign_call": Anchor("src/crypto/pqc.cpp", ("if (slh_dsa_sign(candidate_sig.data(), &siglen, hash.begin(), hash.size(), m_keydata->data()) != 0 ||",), "slh_dsa_sign"),
    "pqc_sign_accept": Anchor("src/crypto/pqc.cpp", ("sig = std::move(candidate_sig);",), "sig"),
    "pqc_verify_call": Anchor("src/crypto/pqc.h", ("return slh_dsa_verify(sig.data(), sig.size(), hash.begin(), hash.size(), m_data.data()) == 0;",), "slh_dsa_verify"),
    # Harness generation, signing and verification call sites.
    "p2mr_harness_keygen": Anchor("src/test/fuzz/p2mr_script.cpp", ("if (slh_dsa_keygen(pubkey_bytes.data(), seckey_bytes.data(), random_data.data(), random_data.size()) != 0) {",), "slh_dsa_keygen"),
    "p2mr_harness_sign": Anchor("src/test/fuzz/p2mr_script.cpp", ("if (!creator.CreatePQCSignature(provider, sig, *signing_pubkey, &spend.leaf_hash, SigVersion::P2MR)) return;",), "creator.CreatePQCSignature"),
    "p2mr_harness_verify": Anchor("src/test/fuzz/p2mr_script.cpp", ("(void)VerifySpend(spend_value, flags);",), "VerifySpend"),
    "p2mr_fixture_sign": Anchor("src/test/fuzz/p2mr_script.cpp", ("const bool signed_ok{creator.CreatePQCSignature(provider, sig, pubkey, &spend.leaf_hash, SigVersion::P2MR)};",), "creator.CreatePQCSignature"),
    "p2mr_fixture_verify": Anchor("src/test/fuzz/p2mr_script.cpp", ("const bool valid{VerifySpend(spend, flags)};",), "VerifySpend"),
    "pqc_harness_keygen": Anchor("src/test/fuzz/pqc.cpp", ("if (slh_dsa_keygen(pubkey_bytes.data(), seckey_bytes.data(), random_data.data(), random_data.size()) != 0) {",), "slh_dsa_keygen"),
    "pqc_harness_import_sign": Anchor("src/test/fuzz/pqc.cpp", ("const bool signed_ok{key.Sign(hash, sig, counter)};",), "key.Sign"),
    "pqc_fixture_sign": Anchor("src/test/fuzz/pqc.cpp", ("const bool signed_ok{key.Sign(out[key_index].hashes[msg_index], out[key_index].sigs[msg_index], counter)};",), "key.Sign"),
    "pqc_fixture_final_verify": Anchor("src/test/fuzz/pqc.cpp", ("const CPQCPubKey pubkey{pubkey_mut};",), "pubkey"),
}

HIT, MISS = "hit", "miss"


def at_least(n):
    return ("at least", n)


# Legacy and generation seeds must generate keys and sign from input bytes
# without touching the fixture code.
GENERATED = {
    "p2mr_harness_keygen": HIT, "p2mr_harness_sign": HIT, "sign_pqc_provider": HIT, "pqc_sign_call": HIT,
    "pqc_sign_accept": HIT, "p2mr_harness_verify": HIT, "p2mr_fixture_sign": MISS,
}
P2MR_ACCEPTED = {
    "p2mr_execute_leaf": HIT, "p2mr_checksig_call": HIT, "p2mr_verify_call": HIT, "pqc_verify_call": HIT,
    "p2mr_verify_accept": HIT, "witness_script_accept": HIT, "p2mr_verify_reject": MISS,
}
CASES = {
    "p2mr_script": {
        "legacy-checksigpqc-default-valid": GENERATED | P2MR_ACCEPTED | {"sign_pqc_append_hashtype": MISS, "p2mr_hashtype_pop": MISS},
        "legacy-checksigpqc-all-valid": GENERATED | P2MR_ACCEPTED | {"sign_pqc_append_hashtype": HIT, "p2mr_hashtype_pop": HIT},
        "legacy-ctv-checksigpqc-all-valid": GENERATED | P2MR_ACCEPTED | {"ctv_match": HIT, "ctv_mismatch": MISS},
        "legacy-signature-bit-flip": GENERATED | {"pqc_verify_call": HIT, "p2mr_verify_reject": HIT, "p2mr_verify_accept": MISS, "witness_script_accept": MISS},
        "legacy-signature-truncated": GENERATED | {"p2mr_sig_size_reject": HIT, "pqc_verify_call": MISS, "p2mr_verify_accept": MISS},
        "legacy-invalid-hashtype-appended": GENERATED | {"p2mr_hashtype_invalid": HIT, "pqc_verify_call": MISS},
        "legacy-control-block-bit0-cleared": GENERATED | {"p2mr_control_bit0_reject": HIT, "p2mr_execute_leaf": MISS},
        "legacy-control-block-truncated": GENERATED | {"p2mr_control_size_reject": HIT, "p2mr_execute_leaf": MISS},
        "generation-checksigpqc-default-valid": GENERATED | P2MR_ACCEPTED,
        # Building six fixtures verifies six spends; the input must verify once more.
        "fixture-checksigpqc-default-untouched": {
            "p2mr_fixture_sign": at_least(6), "p2mr_fixture_verify": HIT, "p2mr_verify_accept": at_least(7),
            "p2mr_harness_keygen": MISS, "p2mr_harness_sign": MISS, "p2mr_harness_verify": MISS,
        },
        "fixture-ctv-checksigpqc-all-untouched": {"p2mr_fixture_verify": HIT, "ctv_match": at_least(3), "p2mr_verify_accept": at_least(7)},
        "fixture-ctv-locktime-changed": {"p2mr_fixture_verify": HIT, "ctv_mismatch": HIT, "p2mr_harness_sign": MISS},
    },
    "pqc": {
        "legacy-generated-valid-sign-verify": {
            "pqc_harness_keygen": HIT, "pqc_set_accept": HIT, "pqc_sign_call": HIT, "pqc_sign_accept": HIT,
            "pqc_harness_import_sign": HIT, "pqc_verify_call": HIT, "pqc_set_reject": MISS, "pqc_fixture_sign": MISS,
        },
        "legacy-import-corrupted-secret": {
            "pqc_harness_keygen": HIT, "pqc_set_reject": HIT, "pqc_sign_refused": HIT, "pqc_sign_call": HIT, "pqc_fixture_sign": MISS,
        },
        "generation-valid-sign-verify": {"pqc_harness_keygen": HIT, "pqc_sign_call": HIT, "pqc_verify_call": HIT, "pqc_fixture_sign": MISS},
        # Building fixtures verifies four signatures; each input verifies twice more.
        "fixture-untouched-key0-msg0": {
            "pqc_fixture_sign": at_least(4), "pqc_fixture_final_verify": HIT, "pqc_verify_call": at_least(6), "pqc_harness_keygen": MISS,
        },
        "fixture-signature-bit-flip": {"pqc_fixture_final_verify": HIT, "pqc_verify_call": at_least(6), "pqc_harness_keygen": MISS},
    },
}


def resolve_anchor(anchor, source_dir):
    """Return (line, column), 1-based, of anchor.token on the anchor's last line."""
    text = (source_dir / anchor.file).read_text(encoding="utf8").splitlines()
    stripped = [line.strip() for line in text]
    n = len(anchor.lines)
    matches = [i for i in range(len(stripped) - n + 1) if tuple(stripped[i:i + n]) == anchor.lines]
    if len(matches) != 1:
        raise AssertionError(f"anchor {anchor} matched {len(matches)} times in {anchor.file}")
    index = matches[0] + n - 1
    column = text[index].find(anchor.token)
    if column < 0:
        raise AssertionError(f"token {anchor.token!r} not on line {index + 1} of {anchor.file}")
    return index + 1, column + 1


def count_at(segments, line, column):
    """Execution count of the region covering (line, column), or None if it has no count."""
    active = None
    for seg_line, seg_column, count, has_count, *_ in segments:
        if (seg_line, seg_column) > (line, column):
            break
        active = count if has_count else None
    return active


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, timeout=3600, **kwargs)


class AnchorResolutionTest(unittest.TestCase):
    """A stale or ambiguous anchor must fail rather than read counts from another region."""

    def resolve(self, anchor, source):
        source_dir = Path(tempfile.mkdtemp(prefix="qbit_fuzz_anchor_"))
        self.addCleanup(shutil.rmtree, source_dir)
        (source_dir / anchor.file).parent.mkdir(parents=True)
        (source_dir / anchor.file).write_text(source, encoding="utf8")
        return resolve_anchor(anchor, source_dir)

    def test_refusal_branch_resolves_to_its_return(self):
        # Sign() also has `return finish(false);` for a failed slh_dsa_sign, which must not be chosen.
        anchor = ANCHORS["pqc_sign_refused"]
        source = f"{{\n    {anchor.lines[0]}\n    if (failed) {{\n        return finish(false);\n    }}\n}}\n"
        self.assertEqual(self.resolve(anchor, source), (2, 4 + anchor.lines[0].index("return finish(false);") + 1))

    def test_multi_line_anchor_resolves_on_last_line(self):
        anchor = Anchor("src/crypto/pqc.cpp", ("return finish(false);", "return finish(true);"), "return")
        self.assertEqual(self.resolve(anchor, "{\nreturn finish(false);\n    return finish(true);\n}\n"), (3, 5))

    def test_missing_anchor_fails(self):
        anchor = ANCHORS["pqc_sign_refused"]
        stale = "if (!IsValid() || counter_inout >= PQC_MAX_SIGNATURES) return false;\n"
        with self.assertRaisesRegex(AssertionError, "matched 0 times"):
            self.resolve(anchor, stale)

    def test_ambiguous_anchor_fails(self):
        anchor = ANCHORS["pqc_sign_refused"]
        with self.assertRaisesRegex(AssertionError, "matched 2 times"):
            self.resolve(anchor, f"{anchor.lines[0]}\n{anchor.lines[0]}\n")

    def test_missing_token_fails(self):
        anchor = Anchor("src/crypto/pqc.cpp", ("return finish(false);",), "finish(true)")
        with self.assertRaisesRegex(AssertionError, "not on line 1"):
            self.resolve(anchor, "return finish(false);\n")


class CoverageContractTest(unittest.TestCase):
    def test_generation_and_verification_paths_remain_covered(self):
        if "fuzz_binary" not in CONFIG:
            self.fail("requires --fuzz-binary pointing at a coverage-instrumented fuzz executable")
        anchors = {name: resolve_anchor(anchor, CONFIG["source_dir"]) for name, anchor in ANCHORS.items()}
        work = Path(tempfile.mkdtemp(prefix="qbit_fuzz_coverage_"))
        self.addCleanup(shutil.rmtree, work)
        for target, cases in CASES.items():
            for case, expectations in cases.items():
                with self.subTest(target=target, case=case):
                    counts = self.collect_counts(work, target, case, {name: anchors[name] for name in expectations})
                    report = ", ".join(f"{name}={counts[name]}" for name in sorted(expectations))
                    print(f"{target}/{case}: {report}")
                    for name, expected in expectations.items():
                        count = counts[name]
                        if count is None:
                            self.fail(f"{target}/{case}: {name} at {ANCHORS[name].file}:{anchors[name]} has no coverage region")
                        if expected == HIT:
                            self.assertGreater(count, 0, f"{target}/{case}: {name} not executed")
                        elif expected == MISS:
                            self.assertEqual(count, 0, f"{target}/{case}: {name} executed {count} times")
                        else:
                            self.assertGreaterEqual(count, expected[1], f"{target}/{case}: {name} executed {count} times")

    def collect_counts(self, work, target, case, anchors):
        seed = CORPORA_DIR / target / case
        self.assertTrue(seed.is_file(), f"named seed {seed} is missing")
        raw = work / f"{target}-{case}.profraw"
        env = os.environ | {"FUZZ": target, "LLVM_PROFILE_FILE": str(raw)}
        result = run([str(CONFIG["fuzz_binary"]), str(seed)], env=env)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, f"{target}/{case} failed:\n{output}")
        self.assertTrue(f"{target}: succeeded against 1 files" in result.stdout or f"Executed {seed}" in output,
                        f"{target}/{case}: fuzz executable did not report running the seed:\n{output}")
        self.assertTrue(raw.is_file(), f"{target}/{case}: no profile written; is the executable coverage-instrumented?")

        profdata = raw.with_suffix(".profdata")
        merge = run([CONFIG["llvm_profdata"], "merge", "-sparse", str(raw), "-o", str(profdata)])
        self.assertEqual(merge.returncode, 0, merge.stderr)
        files = sorted({ANCHORS[name].file for name in anchors})
        export_cmd = [CONFIG["llvm_cov"], "export", str(CONFIG["fuzz_binary"]), f"-instr-profile={profdata}",
                      "-format=text", "-skip-expansions", "-skip-functions"]
        if CONFIG.get("path_equivalence"):
            export_cmd.append(f"-path-equivalence={CONFIG['path_equivalence']}")
        export = run(export_cmd + [str(CONFIG["source_dir"] / f) for f in files])
        self.assertEqual(export.returncode, 0, export.stderr)
        exported = {}
        for entry in json.loads(export.stdout)["data"][0]["files"]:
            for f in files:
                if Path(entry["filename"]).as_posix().endswith(f):
                    exported[f] = entry["segments"]
        missing = [f for f in files if f not in exported]
        self.assertFalse(missing, f"llvm-cov export has no coverage for {missing}; check --path-equivalence")
        return {name: count_at(exported[ANCHORS[name].file], *position) for name, position in anchors.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fuzz-binary", type=Path, help="Fuzz executable built with -fprofile-instr-generate -fcoverage-mapping.")
    parser.add_argument("--llvm-profdata", default="llvm-profdata")
    parser.add_argument("--llvm-cov", default="llvm-cov")
    parser.add_argument("--source-dir", type=Path, default=SRC_DIR, help="Source tree the executable was built from.")
    parser.add_argument("--path-equivalence", help="Passed to llvm-cov export when build paths differ from --source-dir.")
    parser.add_argument("--anchors-only", action="store_true", help="Only resolve anchors and named seeds and test anchor resolution; does not evaluate coverage.")
    args = parser.parse_args()

    if args.anchors_only:
        for name, anchor in ANCHORS.items():
            print(f"{name}: {anchor.file}:{':'.join(map(str, resolve_anchor(anchor, args.source_dir)))}")
        for target, cases in CASES.items():
            for case, expectations in cases.items():
                assert (CORPORA_DIR / target / case).is_file(), f"missing seed {target}/{case}"
                assert set(expectations) <= set(ANCHORS), f"unknown anchor in {target}/{case}"
        print("Anchors resolved. Coverage was NOT evaluated.")
        suite = unittest.TestLoader().loadTestsFromTestCase(AnchorResolutionTest)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1

    if args.fuzz_binary:
        CONFIG.update(fuzz_binary=args.fuzz_binary.resolve(), llvm_profdata=args.llvm_profdata, llvm_cov=args.llvm_cov,
                      source_dir=args.source_dir.resolve(), path_equivalence=args.path_equivalence)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([loader.loadTestsFromTestCase(AnchorResolutionTest), loader.loadTestsFromTestCase(CoverageContractTest)])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
