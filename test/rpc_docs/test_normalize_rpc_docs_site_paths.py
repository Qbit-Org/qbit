# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Unit tests for RPC docs site path normalization."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
NORMALIZE_SPEC = importlib.util.spec_from_file_location(
    "normalize_rpc_docs_site_paths",
    REPO_ROOT / "cmake" / "script" / "normalize_rpc_docs_site_paths.py",
)
assert NORMALIZE_SPEC is not None
assert NORMALIZE_SPEC.loader is not None
normalize_rpc_docs_site_paths = importlib.util.module_from_spec(NORMALIZE_SPEC)
NORMALIZE_SPEC.loader.exec_module(normalize_rpc_docs_site_paths)


class NormalizeRpcDocsSitePathsTest(unittest.TestCase):
    def test_rewrite_file_handles_bare_root_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            site_root = Path(tmpdir)
            nested_dir = site_root / "methods"
            nested_dir.mkdir()

            html_path = nested_dir / "index.html"
            html_path.write_text('<a href="/">Home</a><img src="/" />', encoding="utf-8")

            css_path = nested_dir / "site.css"
            css_path.write_text('body { background-image: url("/"); }', encoding="utf-8")

            normalize_rpc_docs_site_paths._rewrite_file(html_path, site_root)
            normalize_rpc_docs_site_paths._rewrite_file(css_path, site_root)

            self.assertEqual(
                html_path.read_text(encoding="utf-8"),
                '<a href="..">Home</a><img src=".." />',
            )
            self.assertEqual(
                css_path.read_text(encoding="utf-8"),
                'body { background-image: url(".."); }',
            )


if __name__ == "__main__":
    unittest.main()
