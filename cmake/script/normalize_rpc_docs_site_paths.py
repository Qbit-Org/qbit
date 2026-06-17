# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Rewrite root-relative site asset paths to file-relative paths."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys


ATTR_PATTERN = re.compile(r'(?P<prefix>\b(?:href|src)=["\'])/(?P<path>[^"\']*)')
CSS_URL_PATTERN = re.compile(
    r'url\((?P<quote>["\']?)/(?P<path>[^)"\']*)(?P=quote)\)'
)


def _relative_target(file_path: Path, site_root: Path, target: str) -> str:
    relative_root = Path(os.path.relpath(site_root, file_path.parent))
    if not target:
        return relative_root.as_posix()
    target_path = Path(target)
    resolved = target_path if relative_root == Path(".") else relative_root / target_path
    return resolved.as_posix()


def _rewrite_file(file_path: Path, site_root: Path) -> None:
    original = file_path.read_text(encoding="utf-8")
    rewritten = original

    def replace_attr(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{_relative_target(file_path, site_root, match.group('path'))}"

    def replace_css_url(match: re.Match[str]) -> str:
        quote = match.group("quote")
        target = _relative_target(file_path, site_root, match.group("path"))
        return f"url({quote}{target}{quote})"

    rewritten = ATTR_PATTERN.sub(replace_attr, rewritten)
    rewritten = CSS_URL_PATTERN.sub(replace_css_url, rewritten)

    if rewritten != original:
        file_path.write_text(rewritten, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_rpc_docs_site_paths.py <site_dir>", file=sys.stderr)
        return 1

    site_root = Path(sys.argv[1]).resolve()
    for suffix in ("*.html", "*.css"):
        for path in site_root.rglob(suffix):
            _rewrite_file(path, site_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
