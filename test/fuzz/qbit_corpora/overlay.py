#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Validate the committed qbit seed corpora and overlay them onto a fuzz corpus directory.

    test/fuzz/qbit_corpora/overlay.py <qa-assets>/fuzz_corpora

Each seed is copied to <corpus>/<target>/qbit-<name>. Existing files are never
replaced. Files matching qbit-<name> left by an earlier overlay are removed
first, so a reused corpus checkout replays exactly the committed seeds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REQUIRED_TARGETS = (
    "asert_chain_transition",
    "asert_edge_cases",
    "asert_math",
    "auxpow",
    "p2mr_script",
    "pqc",
)
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_SCHEMA_VERSION = 1
LIMITS = {
    "max_seeds_per_target": 16,
    "max_seed_bytes": 8 * 1024,
    "max_target_bytes": 64 * 1024,
    "max_total_bytes": 384 * 1024,
}
SEED_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]*")
OVERLAY_PREFIX = "qbit-"
OVERLAY_NAME_PATTERN = re.compile(OVERLAY_PREFIX + SEED_NAME_PATTERN.pattern)
CORPORA_DIR = Path(__file__).resolve().parent


class OverlayError(Exception):
    pass


def load_seeds(corpora_dir: Path = CORPORA_DIR) -> dict[str, list[tuple[str, bytes]]]:
    """Return {target: [(name, bytes)]} after checking files against the manifest and limits."""
    try:
        manifest = json.loads((corpora_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise OverlayError(f"Cannot read {corpora_dir / MANIFEST_NAME}: {e}") from e
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise OverlayError(f"{MANIFEST_NAME}: unsupported schema_version, expected {MANIFEST_SCHEMA_VERSION}")
    if manifest.get("limits") != LIMITS:
        raise OverlayError(f"{MANIFEST_NAME}: limits differ from the enforced limits {LIMITS}")
    targets = manifest.get("targets")
    if not isinstance(targets, dict) or tuple(sorted(targets)) != REQUIRED_TARGETS:
        raise OverlayError(f"{MANIFEST_NAME}: targets must be exactly {', '.join(REQUIRED_TARGETS)}")

    seeds: dict[str, list[tuple[str, bytes]]] = {}
    total_bytes = 0
    for target in REQUIRED_TARGETS:
        entries = targets[target]
        if not isinstance(entries, list) or not 1 <= len(entries) <= LIMITS["max_seeds_per_target"]:
            raise OverlayError(f"{target}: expected 1 to {LIMITS['max_seeds_per_target']} manifest entries")
        target_dir = corpora_dir / target
        if not target_dir.is_dir():
            raise OverlayError(f"{target_dir}: seed directory is missing")

        names = []
        for entry in entries:
            name = entry.get("file") if isinstance(entry, dict) else None
            if not isinstance(name, str) or not SEED_NAME_PATTERN.fullmatch(name):
                raise OverlayError(f"{target}: invalid manifest entry {entry!r}")
            names.append(name)
        on_disk = sorted(p.name for p in target_dir.iterdir())
        if len(set(names)) != len(names) or sorted(names) != on_disk:
            raise OverlayError(f"{target}: seed files {on_disk} do not match manifest entries {sorted(names)}")

        target_bytes = 0
        seeds[target] = []
        for entry, name in zip(entries, names):
            path = target_dir / name
            if path.is_symlink() or not path.is_file():
                raise OverlayError(f"{path}: seed must be a regular file")
            data = path.read_bytes()
            if not 1 <= len(data) <= LIMITS["max_seed_bytes"]:
                raise OverlayError(f"{path}: {len(data)} bytes outside [1, {LIMITS['max_seed_bytes']}]")
            if entry.get("size") != len(data) or entry.get("sha256") != hashlib.sha256(data).hexdigest():
                raise OverlayError(f"{path}: size or sha256 does not match {MANIFEST_NAME}")
            target_bytes += len(data)
            seeds[target].append((name, data))
        if target_bytes > LIMITS["max_target_bytes"]:
            raise OverlayError(f"{target}: {target_bytes} bytes exceeds {LIMITS['max_target_bytes']}")
        total_bytes += target_bytes
    if total_bytes > LIMITS["max_total_bytes"]:
        raise OverlayError(f"total seed size {total_bytes} bytes exceeds {LIMITS['max_total_bytes']}")
    return seeds


def overlay(seeds: dict[str, list[tuple[str, bytes]]], corpus_dir: Path) -> None:
    if not corpus_dir.is_dir():
        raise OverlayError(f"{corpus_dir}: corpus directory does not exist")
    for target, files in seeds.items():
        dest = corpus_dir / target
        if dest.exists() and not dest.is_dir():
            raise OverlayError(f"{dest}: exists and is not a directory")
        dest.mkdir(exist_ok=True)
        for stale in dest.iterdir():
            if OVERLAY_NAME_PATTERN.fullmatch(stale.name) and stale.is_file() and not stale.is_symlink():
                stale.unlink()
        kept = sum(1 for p in dest.iterdir() if p.is_file())
        for name, data in files:
            out = dest / (OVERLAY_PREFIX + name)
            try:
                with open(out, "xb") as f:
                    f.write(data)
            except FileExistsError as e:
                raise OverlayError(f"{out}: already exists and is not a replaceable overlay seed") from e
        print(f"{target}: overlaid {len(files)} qbit seed files, kept {kept} existing input files")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus_dir", type=Path, help="Directory with one subdirectory per fuzz target.")
    args = parser.parse_args()
    try:
        overlay(load_seeds(), args.corpus_dir)
    except OverlayError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
