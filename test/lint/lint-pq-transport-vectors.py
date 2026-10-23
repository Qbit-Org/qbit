#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Check that src/test/data/pq_transport_vectors.json matches the Python reference recipe."""

import subprocess
import sys
from pathlib import Path


def main():
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True, encoding="utf8").strip())
    generator = root / "contrib" / "devtools" / "generate-pq-transport-vectors.py"
    sys.exit(subprocess.run([sys.executable, str(generator), "--check"], cwd=root).returncode)


if __name__ == "__main__":
    main()
