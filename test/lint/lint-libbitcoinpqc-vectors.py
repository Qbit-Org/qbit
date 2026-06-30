#!/usr/bin/env python3
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
#
# Verify bounded30 SPHINCS+ wiring in src/libbitcoinpqc/sphincsplus.
#
# The current upstream tag does not carry the NIST KAT generator payload. When
# those sources are absent, fall back to static bounded30 guard checks instead
# of treating that absence as a lint failure.

import subprocess
import sys
from pathlib import Path

# Keep this minimal for CI runtime while still validating KAT-vector plumbing.
VECTORS_TO_CHECK = (
    ("sphincs-sha2-128s-simple", "ref"),
)
KAT_GENERATOR_FILES = (
    "PQCgenKAT_sign.c",
    "rng.c",
    "rng.h",
)


def kat_generator_state(sphincs_dir: Path, implementation: str) -> str | None:
    impl_dir = sphincs_dir / implementation
    if not impl_dir.is_dir():
        print(f"Missing SPHINCS+ implementation directory: {impl_dir}", flush=True)
        return None

    existing = [name for name in KAT_GENERATOR_FILES if (impl_dir / name).is_file()]
    if len(existing) == len(KAT_GENERATOR_FILES):
        return "present"
    if not existing:
        return "absent"

    missing = [name for name in KAT_GENERATOR_FILES if name not in existing]
    print(
        f"{impl_dir} has a partially present KAT generator payload.",
        flush=True,
    )
    print(f"  present: {', '.join(existing)}", flush=True)
    print(f"  missing: {', '.join(missing)}", flush=True)
    return None


def run_vector_check(sphincs_dir: Path, instance: str, implementation: str) -> bool:
    vectors_py = sphincs_dir / "vectors.py"
    if not vectors_py.is_file():
        print(f"Missing vectors.py at expected path: {vectors_py}", flush=True)
        return False

    cmd = [sys.executable, "vectors.py", instance, implementation]
    print(f"Running {' '.join(cmd)} in {sphincs_dir}", flush=True)
    return subprocess.run(cmd, cwd=sphincs_dir).returncode == 0


def require_contains(path: Path, needles: tuple[str, ...]) -> bool:
    text = path.read_text(encoding="utf8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        print(f"{path} is missing active bounded30 vector guard text:")
        for needle in missing:
            print(f"  {needle}")
        return False
    return True


def main() -> None:
    root = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True, encoding="utf8"
        ).strip()
    )
    sphincs_dir = root / "src" / "libbitcoinpqc" / "sphincsplus"

    ok = True
    for instance, implementation in VECTORS_TO_CHECK:
        state = kat_generator_state(sphincs_dir, implementation)
        if state == "present":
            ok &= run_vector_check(sphincs_dir, instance, implementation)
        elif state == "absent":
            print(
                "Skipping SPHINCS+ vector regeneration because the upstream "
                f"tag does not include KAT generator sources for {implementation}.",
                flush=True,
            )
        else:
            ok = False

    ok &= require_contains(
        root / "src" / "libbitcoinpqc" / "CMakeLists.txt",
        (
            "PARAMS=sphincs-sha2-128s-bounded30",
            "SPX_PRODUCTION_BUILD=1",
        ),
    )
    ok &= require_contains(
        root / "src" / "test" / "pqc_tests.cpp",
        (
            "pqc_bounded30_known_answer_vector",
            "6a1406d1631522bb8cf7abfdcd7cdca8f075c261234c5a49f2768882e20aead0",
        ),
    )

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
