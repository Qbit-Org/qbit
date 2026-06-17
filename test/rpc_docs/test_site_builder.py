# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Unit tests for the RPC docs site builder."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_RPC_DIR = REPO_ROOT / "doc" / "rpc"
SITE_BUILDER_SPEC = importlib.util.spec_from_file_location(
    "site_builder", DOC_RPC_DIR / "site_builder.py"
)
assert SITE_BUILDER_SPEC is not None
assert SITE_BUILDER_SPEC.loader is not None
site_builder = importlib.util.module_from_spec(SITE_BUILDER_SPEC)
SITE_BUILDER_SPEC.loader.exec_module(site_builder)


FIXTURE_MANIFEST = DOC_RPC_DIR / "fixtures" / "rpc-docs-v1.sample.json"
BASELINE_MANIFEST = DOC_RPC_DIR / "baselines" / "v30.2" / "rpc-docs.json"
OVERLAY_FILE = DOC_RPC_DIR / "annotations" / "v30.2-delta.yml"


def make_method(name: str, category: str, component: str, summary: str) -> dict:
    return {
        "name": name,
        "category": category,
        "component": component,
        "visible": True,
        "summary_line": summary,
        "description": summary,
        "arguments": [],
        "results": [],
        "examples": [],
        "feature_flags": {
            "requires_wallet": component == "wallet",
            "requires_zmq": component == "zmq",
            "requires_external_signer": component == "signer",
        },
    }


class SiteBuilderTest(unittest.TestCase):
    def test_load_overlay_accepts_json_when_yaml_is_unavailable(self) -> None:
        overlay_text = """{
  "schema_version": "1",
  "baseline": "v30.2",
  "methods": {}
}
"""

        real_import = __import__

        def fail_yaml_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "yaml":
                raise ModuleNotFoundError("No module named 'yaml'")
            return real_import(name, globals, locals, fromlist, level)

        with tempfile.TemporaryDirectory() as tmpdir:
            overlay_path = Path(tmpdir) / "overlay.yml"
            overlay_path.write_text(overlay_text, encoding="utf-8")

            with mock.patch("builtins.__import__", side_effect=fail_yaml_import):
                overlay = site_builder.load_overlay(overlay_path, set())

        self.assertEqual(overlay["baseline"], site_builder.BASELINE_LABEL)
        self.assertEqual(overlay["methods"], {})

    def test_diff_manifest_methods_assigns_new_and_surface_statuses(self) -> None:
        unchanged = make_method("getblockcount", "blockchain", "core", "Return height.")
        new_method = make_method(
            "getconfirmationtarget",
            "blockchain",
            "core",
            "Return qbit confirmation target estimates.",
        )
        changed_method = make_method(
            "sendtoaddress",
            "wallet",
            "wallet",
            "Send funds to an address.",
        )
        changed_method["arguments"] = [
            {
                "name": "amount",
                "type": "amount",
                "required": True,
                "description": "Amount to send.",
                "aliases": [],
                "children": [],
            }
        ]
        baseline_changed_method = copy.deepcopy(changed_method)
        baseline_changed_method["arguments"] = []

        manifest = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "qbit",
            "project_version": "test",
            "methods": [unchanged, changed_method, new_method],
        }
        baseline = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "bitcoin",
            "project_version": site_builder.BASELINE_LABEL,
            "methods": [unchanged, baseline_changed_method],
        }

        statuses = site_builder.diff_manifest_methods(manifest, baseline)

        self.assertEqual(statuses["getconfirmationtarget"], [site_builder.STATUS_NEW])
        self.assertEqual(
            statuses["sendtoaddress"], [site_builder.STATUS_SURFACE_CHANGED]
        )
        self.assertEqual(statuses["getblockcount"], [])

    def test_diff_manifest_methods_ignores_examples_and_feature_gated_baseline_gaps(self) -> None:
        examples_changed = make_method(
            "getbestblockhash", "blockchain", "core", "Return the best block hash."
        )
        examples_changed["examples"] = ["qbit-cli getbestblockhash"]
        baseline_examples_changed = copy.deepcopy(examples_changed)
        baseline_examples_changed["examples"] = ["bitcoin-cli getbestblockhash"]

        zmq_method = make_method(
            "getzmqnotifications",
            "zmq",
            "zmq",
            "Return configured ZMQ notifications.",
        )

        manifest = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "qbit",
            "project_version": "test",
            "methods": [examples_changed, zmq_method],
        }
        baseline = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "bitcoin",
            "project_version": site_builder.BASELINE_LABEL,
            "methods": [baseline_examples_changed],
        }

        statuses = site_builder.diff_manifest_methods(
            manifest,
            baseline,
            baseline_feature_matrix={"wallet": True, "zmq": False, "external_signer": True},
        )

        self.assertEqual(statuses["getbestblockhash"], [])
        self.assertEqual(statuses["getzmqnotifications"], [])

    def test_validate_overlay_rejects_unknown_methods(self) -> None:
        overlay = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "baseline": site_builder.BASELINE_LABEL,
            "methods": {
                "doesnotexist": {
                    "status_override": site_builder.STATUS_SEMANTIC_CHANGED
                }
            },
        }

        with self.assertRaisesRegex(
            site_builder.OverlayValidationError, "overlay references unknown method"
        ):
            site_builder.validate_overlay(overlay, {"getblocktemplate"})

    def test_validate_overlay_rejects_null_status_override(self) -> None:
        overlay = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "baseline": site_builder.BASELINE_LABEL,
            "methods": {"getblocktemplate": {"status_override": None}},
        }

        with self.assertRaisesRegex(
            site_builder.OverlayValidationError, "overlay status_override"
        ):
            site_builder.validate_overlay(overlay, {"getblocktemplate"})

    def test_build_site_model_assigns_statuses_and_badges(self) -> None:
        wallet_method = make_method(
            "getwalletinfo", "wallet", "wallet", "Return wallet state."
        )
        modified_method = make_method(
            "getblocktemplate",
            "mining",
            "core",
            "Return qbit mining template data.",
        )
        baseline_modified_method = copy.deepcopy(modified_method)
        baseline_modified_method["arguments"] = []
        modified_method["arguments"] = [
            {
                "name": "template_request",
                "type": "obj",
                "required": False,
                "description": "Template request object.",
                "aliases": [],
                "children": [],
            }
        ]

        manifest = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "qbit",
            "project_version": "test",
            "methods": [modified_method, wallet_method],
        }
        baseline = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "bitcoin",
            "project_version": site_builder.BASELINE_LABEL,
            "methods": [baseline_modified_method, copy.deepcopy(wallet_method)],
        }
        overlay = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "baseline": site_builder.BASELINE_LABEL,
            "methods": {
                "getblocktemplate": {
                    "status_override": site_builder.STATUS_SEMANTIC_CHANGED,
                    "delta_summary": "Cadence semantics changed.",
                }
            },
        }

        site_model = site_builder.build_site_model(manifest, baseline, overlay)
        methods = {method["name"]: method for method in site_model["methods"]}
        categories = {entry["name"]: entry["counts"] for entry in site_model["categories"]}

        self.assertEqual(methods["getwalletinfo"]["status"], site_builder.STATUS_UNCHANGED)
        self.assertIn("Wallet", methods["getwalletinfo"]["badges"])
        self.assertEqual(
            methods["getblocktemplate"]["status"],
            site_builder.STATUS_SURFACE_CHANGED,
        )
        self.assertIn(
            f"Changed params/results since {site_builder.BASELINE_LABEL}",
            methods["getblocktemplate"]["badges"],
        )
        self.assertIn(
            f"Changed behavior since {site_builder.BASELINE_LABEL}",
            methods["getblocktemplate"]["badges"],
        )
        self.assertEqual(site_model["summary"]["unchanged"], 1)
        self.assertEqual(site_model["summary"]["surface_changed_since_v30_2"], 1)
        self.assertEqual(site_model["summary"]["semantic_changed_since_v30_2"], 1)
        self.assertEqual(categories["wallet"]["unchanged"], 1)
        self.assertEqual(categories["mining"]["surface_changed_since_v30_2"], 1)
        self.assertEqual(categories["mining"]["semantic_changed_since_v30_2"], 1)
        self.assertEqual(
            methods["getblocktemplate"]["change_types"],
            [
                site_builder.STATUS_SURFACE_CHANGED,
                site_builder.STATUS_SEMANTIC_CHANGED,
            ],
        )
        self.assertNotIn("logical_pr", methods["getblocktemplate"])
        self.assertNotIn("issue_links", methods["getblocktemplate"])
        self.assertNotIn("tags", methods["getblocktemplate"])

    def test_dynamic_baseline_label_flows_through_pages_and_badges(self) -> None:
        manifest = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "qbit",
            "project_version": "test",
            "methods": [make_method("getnewthing", "util", "core", "Return new thing.")],
        }
        baseline = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "project": "bitcoin",
            "project_version": "v31.0",
            "methods": [],
        }
        overlay = {
            "schema_version": site_builder.SCHEMA_VERSION,
            "baseline": "v31.0",
            "methods": {
                "getnewthing": {
                    "status_override": site_builder.STATUS_NEW,
                    "delta_summary": "New in qbit.",
                }
            },
        }

        site_model = site_builder.build_site_model(manifest, baseline, overlay)

        self.assertEqual(site_model["baseline"], "v31.0")
        self.assertEqual(
            site_model["methods"][0]["badges"],
            [site_builder.new_badge_label("v31.0")],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            docs_dir = site_builder.render_markdown_site(site_model, Path(tmpdir) / "rpc-site")
            index_text = (docs_dir / "index.md").read_text(encoding="utf-8")
            method_text = (docs_dir / "methods" / "getnewthing.md").read_text(encoding="utf-8")

            self.assertTrue((docs_dir / "changed-since-v31.0.md").exists())
            self.assertTrue((docs_dir / "new-since-v31.0.md").exists())
            self.assertTrue((docs_dir / "surface-changed-since-v31.0.md").exists())
            self.assertTrue((docs_dir / "semantic-changed-since-v31.0.md").exists())
            self.assertIn("committed v31.0 baseline", index_text)
            self.assertIn("[All changed methods](changed-since-v31.0.md)", index_text)
            self.assertIn("[New endpoints since v31.0](new-since-v31.0.md): 1", index_text)
            self.assertIn(
                "[Changed params/results since v31.0](surface-changed-since-v31.0.md): 0",
                index_text,
            )
            self.assertIn(
                "[Changed behavior since v31.0](semantic-changed-since-v31.0.md): 0",
                index_text,
            )
            self.assertIn("| New since v31.0 | 1 |", index_text)
            self.assertNotIn("## Tracking", method_text)
            self.assertNotIn("logical_pr", method_text)
            self.assertNotIn("issue_links", method_text)
            self.assertNotIn("tags", method_text)

    def test_render_method_card_escapes_html_fields(self) -> None:
        method = {
            "name": 'dangerous<method>&"',
            "category": "util<script>",
            "component": 'core"&',
            "status": site_builder.STATUS_NEW,
            "change_types": [site_builder.STATUS_NEW],
            "badges": [],
            "summary_line": 'summary <b>& "quoted"',
        }

        html = "\n".join(site_builder.render_method_card(method, "methods"))

        self.assertIn('dangerous&lt;method&gt;&amp;&quot;', html)
        self.assertIn('summary &lt;b&gt;&amp; &quot;quoted&quot;', html)
        self.assertIn('util&lt;script&gt; / core&quot;&amp;', html)
        self.assertNotIn("<script>", html)

    def test_build_site_cli_generates_html_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path("rpc-site")
            result = subprocess.run(
                [
                    sys.executable,
                    str(DOC_RPC_DIR / "build_site.py"),
                    "--manifest",
                    str(FIXTURE_MANIFEST),
                    "--baseline",
                    str(BASELINE_MANIFEST),
                    "--overlay",
                    str(OVERLAY_FILE),
                    "--out",
                    str(out_dir),
                ],
                cwd=tmpdir,
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"{result.stdout}\n{result.stderr}",
            )
            self.assertTrue((Path(tmpdir) / out_dir / "index.html").exists())
            self.assertTrue((Path(tmpdir) / out_dir / "assets" / "qbit.svg").exists())
            site_model_path = Path(tmpdir) / "rpc" / "site-model.json"
            self.assertTrue(site_model_path.exists())
            self.assertTrue((Path(tmpdir) / "rpc-site-src" / "mkdocs.yml").exists())
            self.assertTrue(
                (Path(tmpdir) / "rpc-site-src" / "docs" / "new-since-v30.2.md").exists()
            )
            self.assertTrue(
                (
                    Path(tmpdir)
                    / "rpc-site-src"
                    / "docs"
                    / "surface-changed-since-v30.2.md"
                ).exists()
            )
            self.assertTrue(
                (
                    Path(tmpdir)
                    / "rpc-site-src"
                    / "docs"
                    / "semantic-changed-since-v30.2.md"
                ).exists()
            )
            site_model_text = site_model_path.read_text(encoding="utf-8")
            method_page_text = (
                Path(tmpdir) / "rpc-site-src" / "docs" / "methods" / "getblocktemplate.md"
            ).read_text(encoding="utf-8")
            self.assertNotIn("logical_pr", site_model_text)
            self.assertNotIn("issue_links", site_model_text)
            self.assertNotIn("tags", site_model_text)
            self.assertNotIn("## Tracking", method_page_text)


if __name__ == "__main__":
    unittest.main()
