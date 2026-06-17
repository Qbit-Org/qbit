# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Build the qbit RPC docs site source tree."""

from __future__ import annotations

import argparse
from pathlib import Path

import site_builder


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Path to the current manifest JSON")
    parser.add_argument("--baseline", required=True, help="Path to the baseline manifest JSON")
    parser.add_argument("--overlay", required=True, help="Path to the overlay annotations YAML")
    parser.add_argument("--out", required=True, help="Output directory for the generated site")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out)

    manifest = site_builder.load_manifest(args.manifest)
    baseline = site_builder.load_manifest(args.baseline)
    baseline_build_meta = site_builder.load_optional_build_meta_for_manifest(
        args.baseline
    )
    overlay = site_builder.load_overlay(
        args.overlay, set(site_builder.manifest_method_index(manifest))
    )

    site_model = site_builder.build_site_model(
        manifest,
        baseline,
        overlay,
        baseline_build_meta=baseline_build_meta,
    )
    site_model_path = site_builder.write_site_model(site_model, out_dir)
    docs_dir = site_builder.render_markdown_site(site_model, out_dir)
    assets_dir = site_builder.copy_site_assets(out_dir)
    config_path = site_builder.write_mkdocs_config(site_model, out_dir)
    site_builder.build_mkdocs_site(config_path)

    print(f"Wrote site model to {site_model_path}")
    print(f"Wrote generated Markdown to {docs_dir}")
    print(f"Copied site assets to {assets_dir}")
    print(f"Built MkDocs site in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
