#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression tests for the from-scratch P2MR v1 corpus generators."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEVTOOLS = REPO_ROOT / "contrib/devtools"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P2MRV1GeneratorTest(unittest.TestCase):
    def test_non_signature_corpora_are_deterministic_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first"
            second = Path(tmp) / "second"
            generator = DEVTOOLS / "generate-p2mr-v1-corpus.py"
            subprocess.run([generator, "--output-dir", first], check=True)
            subprocess.run([generator, "--output-dir", second], check=True)

            expected_counts = {
                "p2mr_vectors.json": (4, 7),
                "p2mr_cross_profile_vectors.json": 2,
                "p2mr_script_boundary_vectors.json": 47,
            }
            for filename, expected_count in expected_counts.items():
                first_bytes = (first / filename).read_bytes()
                self.assertEqual(first_bytes, (second / filename).read_bytes())
                corpus = json.loads(first_bytes)
                if filename == "p2mr_vectors.json":
                    self.assertEqual(
                        (len(corpus["valid"]), len(corpus["invalid"])),
                        expected_count,
                    )
                else:
                    vectors = corpus["vectors"] if "vectors" in corpus else corpus["cases"]
                    self.assertEqual(len(vectors), expected_count)

            commitments = json.loads((first / "p2mr_vectors.json").read_bytes())
            self.assertEqual(
                commitments["valid"][0]["scriptPubKey"],
                "52205c4bb09e52c01be092fe020458a377ba81f004203e232a808f562e248827c7a0",
            )

            mutated = bytearray((first / "p2mr_vectors.json").read_bytes())
            mutated[-2] ^= 1
            self.assertNotEqual(bytes(mutated), (second / "p2mr_vectors.json").read_bytes())

    def test_witness_merger_rejects_missing_and_wrong_owner(self) -> None:
        merger = load_module(
            "merge_p2mr_pqc_witness_vectors",
            DEVTOOLS / "merge-p2mr-pqc-witness-vectors.py",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "generated.json"
            vectors: list[dict[str, Any]] = [
                {
                    "id": vector_id,
                    "name": vector_id,
                    "generator": {"id": "standalone-python", "version": 1},
                }
                for vector_id in sorted(merger.PYTHON_IDS)
            ]
            corpus: dict[str, Any] = {
                "schema_version": 1,
                "profile": "qbit-p2mr-v1",
                "profile_version": 1,
                "vectors": vectors,
            }
            path.write_text(json.dumps(corpus), encoding="utf8")
            loaded = merger.load_generated(path, "standalone-python", merger.PYTHON_IDS)
            self.assertEqual(set(loaded), merger.PYTHON_IDS)

            corpus["vectors"].pop()
            path.write_text(json.dumps(corpus), encoding="utf8")
            with self.assertRaisesRegex(ValueError, "generated ids differ"):
                merger.load_generated(path, "standalone-python", merger.PYTHON_IDS)

            corpus["vectors"] = vectors
            corpus["vectors"][0]["generator"]["id"] = "standalone-rust"
            path.write_text(json.dumps(corpus), encoding="utf8")
            with self.assertRaisesRegex(ValueError, "incorrect ownership"):
                merger.load_generated(path, "standalone-python", merger.PYTHON_IDS)

    def test_manifest_can_be_built_without_an_existing_manifest(self) -> None:
        manifest = load_module(
            "update_p2mr_v1_manifest",
            DEVTOOLS / "update-p2mr-v1-manifest.py",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "src/test/data"
            subprocess.run(
                [DEVTOOLS / "generate-p2mr-v1-corpus.py", "--output-dir", data],
                check=True,
            )
            (data / "p2mr_pqc_witness_vectors.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "profile": "qbit-p2mr-v1",
                        "profile_version": 1,
                        "vectors": [],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf8",
            )
            generated = json.loads(manifest.generated_manifest(root))
            self.assertEqual(generated["case_count"], 60)
            self.assertEqual(generated["case_counts"]["witness"], 0)


if __name__ == "__main__":
    unittest.main()
