#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for scanner evidence helpers."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCANNERS_PATH = REPO_ROOT / "ci/scanners/run-scanners.py"


def load_run_scanners():
    spec = importlib.util.spec_from_file_location("run_scanners", RUN_SCANNERS_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run_scanners = load_run_scanners()


class RunScannersTest(unittest.TestCase):
    def test_ls_remote_ref_oid_accepts_exact_peeled_tag_ref(self) -> None:
        stdout = "ac72d1\trefs/tags/v0.3.0^{}\n456aaf\trefs/tags/v0.3.0\n"

        self.assertEqual(
            run_scanners.ls_remote_ref_oid(stdout, "refs/tags/v0.3.0^{}"),
            "ac72d1",
        )

    def test_ls_remote_ref_oid_accepts_base_ref_for_peeled_query(self) -> None:
        stdout = "ac72d1\trefs/tags/v0.3.0\n"

        self.assertEqual(
            run_scanners.ls_remote_ref_oid(stdout, "refs/tags/v0.3.0^{}"),
            "ac72d1",
        )

    def test_ls_remote_ref_oid_does_not_accept_peeled_ref_for_base_query(self) -> None:
        stdout = "ac72d1\trefs/tags/v0.3.0^{}\n"

        self.assertEqual(
            run_scanners.ls_remote_ref_oid(stdout, "refs/tags/v0.3.0"),
            "",
        )


if __name__ == "__main__":
    unittest.main()
