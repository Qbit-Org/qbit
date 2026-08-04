# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Unit tests for versioned RPC docs discovery and assembly."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_RPC_DIR = REPO_ROOT / "doc" / "rpc"
sys.path.insert(0, str(DOC_RPC_DIR))

import site_builder  # noqa: E402
import versioned_site  # noqa: E402


def release(tag: str, *, draft: bool = False, prerelease: bool = False) -> dict:
    return {
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
    }


def plan_entry(
    identifier: str, kind: str, source_sha: str = "1" * 40
) -> dict[str, str]:
    return {
        "id": identifier,
        "label": f"qbit {identifier}" if kind == "release" else "main development",
        "kind": kind,
        "path": identifier if kind == "release" else "main",
        "source_ref": f"refs/tags/{identifier}" if kind == "release" else "main",
        "source_sha": source_sha,
    }


class VersionDiscoveryTest(unittest.TestCase):
    def test_selects_final_qbit_releases_in_version_order(self) -> None:
        releases = [
            release("v0.1.2-testnet4"),
            release("v1.0.0"),
            release("v0.1.0-testnet4"),
            release("v1.1.0-rc1"),
            release("v2.0.0", draft=True),
            release("v3.0.0", prerelease=True),
            release("bitcoin-v30.2"),
        ]

        entries = versioned_site.select_release_entries(
            releases, tag_resolver=lambda tag: f"sha-{tag}"
        )

        self.assertEqual(
            [entry["id"] for entry in entries],
            ["v1.0.0", "v0.1.2-testnet4", "v0.1.0-testnet4"],
        )
        self.assertEqual(entries[0]["source_sha"], "sha-v1.0.0")
        self.assertEqual(entries[0]["source_checkout_ref"], "sha-v1.0.0")

    def test_build_plan_adds_development_after_releases(self) -> None:
        plan = versioned_site.build_plan(
            [release("v1.0.0")],
            development_ref="topic/ref",
            development_checkout_ref="refs/pull/12/merge",
            publisher_sha="2" * 40,
            tag_resolver=lambda _tag: "1" * 40,
            development_resolver=lambda _ref: "3" * 40,
        )

        self.assertEqual(plan["latest"], "v1.0.0")
        self.assertEqual([entry["id"] for entry in plan["builds"]], ["v1.0.0", "main"])
        self.assertEqual(plan["development"]["source_ref"], "topic/ref")
        self.assertEqual(
            plan["development"]["source_checkout_ref"], "refs/pull/12/merge"
        )
        self.assertIn("33333333", plan["development"]["label"])

    def test_duplicate_release_tag_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            versioned_site.VersionedSiteError, "duplicate published release tag"
        ):
            versioned_site.select_release_entries(
                [release("v1.0.0"), release("v1.0.0")],
                tag_resolver=lambda _tag: "1" * 40,
            )


class VersionAssemblyTest(unittest.TestCase):
    def _write_artifact(
        self,
        artifacts_root: Path,
        entry: dict[str, str],
        pages: tuple[str, ...],
        *,
        project_version: str | None = None,
        build_meta_project_version: str | None = None,
    ) -> None:
        artifact = artifacts_root / f"rpc-docs-version-{entry['id']}"
        site_dir = artifact / "site"
        data_dir = artifact / "data"
        assets_dir = site_dir / "assets"
        (site_dir / "search").mkdir(parents=True)
        data_dir.mkdir(parents=True)

        for page in pages:
            page_path = site_dir / page
            page_path.parent.mkdir(parents=True, exist_ok=True)
            page_path.write_text(f"<html>{entry['id']} {page}</html>\n", encoding="utf-8")
        (site_dir / "search" / "search_index.json").write_text(
            "{}\n", encoding="utf-8"
        )
        publication = site_builder.validate_publication(
            entry["id"], entry["label"], entry["kind"], entry["path"]
        )
        site_builder.write_publication_context(assets_dir, publication)

        if project_version is None:
            project_version = entry["id"] if entry["kind"] == "release" else "v1.0.0"
        if build_meta_project_version is None:
            build_meta_project_version = project_version
        (data_dir / "rpc-docs.json").write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "project": "qbit",
                    "project_version": project_version,
                    "methods": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (data_dir / "rpc-docs-build-meta.json").write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "project": "qbit",
                    "project_version": build_meta_project_version,
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def test_assembles_versions_main_and_latest_root_copy(self) -> None:
        latest = plan_entry("v1.0.0", "release", "1" * 40)
        older = plan_entry("v0.1.2-testnet4", "release", "2" * 40)
        development = plan_entry("main", "development", "3" * 40)
        plan = {
            "schema_version": "1",
            "publisher_sha": "4" * 40,
            "latest": latest["id"],
            "development": development,
            "releases": [latest, older],
            "builds": [latest, older, development],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            self._write_artifact(
                artifacts, latest, ("index.html", "methods/common.html")
            )
            self._write_artifact(artifacts, older, ("index.html",))
            self._write_artifact(
                artifacts,
                development,
                ("index.html", "methods/common.html", "methods/new.html"),
            )
            plan_path = versioned_site.write_json(root / "plan.json", plan)

            output = versioned_site.assemble_site(
                plan_path, artifacts, root / "pages"
            )

            self.assertTrue((output / "index.html").is_file())
            self.assertTrue((output / "v1.0.0" / "index.html").is_file())
            self.assertTrue(
                (output / "v0.1.2-testnet4" / "index.html").is_file()
            )
            self.assertTrue((output / "main" / "index.html").is_file())
            self.assertTrue((output / ".nojekyll").is_file())

            versions = json.loads(
                (output / "versions.json").read_text(encoding="utf-8")
            )
            self.assertEqual(versions["latest"], "v1.0.0")
            self.assertEqual(
                versions["versions"][1]["pages"], ["index.html"]
            )
            self.assertIn(
                "methods/new.html", versions["development"]["pages"]
            )

            root_context = json.loads(
                (output / "assets" / "rpcdocs-version.json").read_text(
                    encoding="utf-8"
                )
            )
            release_context = json.loads(
                (
                    output
                    / "v1.0.0"
                    / "assets"
                    / "rpcdocs-version.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(root_context["pages_root"], "../")
            self.assertEqual(root_context["current"]["path"], "")
            self.assertEqual(release_context["pages_root"], "../../")

    def test_missing_artifact_blocks_assembly(self) -> None:
        latest = plan_entry("v1.0.0", "release")
        development = plan_entry("main", "development")
        plan = {
            "schema_version": "1",
            "publisher_sha": "4" * 40,
            "latest": latest["id"],
            "development": development,
            "releases": [latest],
            "builds": [latest, development],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            self._write_artifact(artifacts, latest, ("index.html",))
            plan_path = versioned_site.write_json(root / "plan.json", plan)

            with self.assertRaisesRegex(
                versioned_site.VersionedSiteError,
                "missing=.*rpc-docs-version-main",
            ):
                versioned_site.assemble_site(
                    plan_path, artifacts, root / "pages"
                )

    def test_release_project_version_may_omit_tag_v_prefix(self) -> None:
        latest = plan_entry("v1.0.0", "release")
        development = plan_entry("main", "development")
        plan = {
            "schema_version": "1",
            "publisher_sha": "4" * 40,
            "latest": latest["id"],
            "development": development,
            "releases": [latest],
            "builds": [latest, development],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            self._write_artifact(
                artifacts,
                latest,
                ("index.html",),
                project_version="1.0.0",
            )
            self._write_artifact(artifacts, development, ("index.html",))
            plan_path = versioned_site.write_json(root / "plan.json", plan)

            output = versioned_site.assemble_site(plan_path, artifacts, root / "pages")

            self.assertTrue((output / "v1.0.0" / "index.html").is_file())

    def test_release_build_metadata_version_mismatch_blocks_assembly(self) -> None:
        latest = plan_entry("v1.0.0", "release")
        development = plan_entry("main", "development")
        plan = {
            "schema_version": "1",
            "publisher_sha": "4" * 40,
            "latest": latest["id"],
            "development": development,
            "releases": [latest],
            "builds": [latest, development],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            self._write_artifact(
                artifacts,
                latest,
                ("index.html",),
                build_meta_project_version="0.9.0",
            )
            self._write_artifact(artifacts, development, ("index.html",))
            plan_path = versioned_site.write_json(root / "plan.json", plan)

            with self.assertRaisesRegex(
                versioned_site.VersionedSiteError,
                "build metadata reports project_version '0.9.0'",
            ):
                versioned_site.assemble_site(plan_path, artifacts, root / "pages")


if __name__ == "__main__":
    unittest.main()
