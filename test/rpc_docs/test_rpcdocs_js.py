# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Tests for browser-independent RPC docs version routing."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
RPCDOCS_JS = REPO_ROOT / "doc" / "rpc" / "assets" / "rpcdocs.js"
NODE_AVAILABLE = shutil.which("node") is not None


@unittest.skipUnless(NODE_AVAILABLE, "Node.js is required to test RPC docs routing")
class RpcDocsJavaScriptTest(unittest.TestCase):
    def test_version_routing_preserves_existing_pages_and_falls_back(self) -> None:
        script = textwrap.dedent(
            """
            const assert = require("node:assert/strict");
            global.document = {
              currentScript: null,
              addEventListener: () => {},
            };
            global.window = {};
            require(process.argv[1]);

            const { relativePageForVersion, versionTargetUrl } =
              window.rpcDocsVersioning;
            const pagesRoot = new URL("https://example.test/qbit/");
            const currentBase = new URL("v1.0.0/", pagesRoot);
            const page = new URL(
              "https://example.test/qbit/v1.0.0/methods/getblock.html#result",
            );
            const relative = relativePageForVersion(page, currentBase);
            assert.equal(relative, "methods/getblock.html");

            const matching = {
              id: "v0.1.2-testnet4",
              url: "v0.1.2-testnet4/",
              pages: ["index.html", "methods/getblock.html"],
            };
            assert.equal(
              versionTargetUrl(matching, relative, pagesRoot, page.hash).href,
              "https://example.test/qbit/v0.1.2-testnet4/methods/getblock.html#result",
            );

            const missing = {
              id: "v0.1.0-testnet4",
              url: "v0.1.0-testnet4/",
              pages: ["index.html"],
            };
            assert.equal(
              versionTargetUrl(missing, relative, pagesRoot, page.hash).href,
              "https://example.test/qbit/v0.1.0-testnet4/",
            );
            """
        )
        result = subprocess.run(
            ["node", "-e", script, str(RPCDOCS_JS)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=f"{result.stdout}\n{result.stderr}")


if __name__ == "__main__":
    unittest.main()
