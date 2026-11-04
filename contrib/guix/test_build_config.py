# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression checks for Guix release build configuration."""

from __future__ import annotations

import io
import os
import re
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SH = REPO_ROOT / "contrib" / "guix" / "libexec" / "build.sh"

DISTNAME = "qbit-1.0.1"
SOURCE_DATE_EPOCH = "1767225600"
BIN_NAMES = ("qbit", "qbit-cli", "qbit-qt", "qbit-tx", "qbit-util", "qbit-wallet", "qbitd")
LIBEXEC_NAMES = ("test_qbit",)

# Stand-ins for the tools that build.sh runs between configuring and
# packaging. Unstripped binaries carry the "UNSTRIPPED" marker; the fake
# dsymutil refuses any other input, as a stripped binary has no debug map.
FAKE_CMAKE = r"""#!/usr/bin/env bash
set -e -o pipefail
case "$1" in
    -S)
        mkdir -p build/bin build/libexec
        echo 'execute_process(COMMAND llvm-strip -u -r "${file}")' > build/cmake_install.cmake
        cp "$FAKE_SPLIT_DEBUG" build/split-debug.sh
        ;;
    --build)
        case " $* " in
            *" deploy "*)
                case "$FAKE_HOST" in
                    *mingw*) echo installer > build/qbit-win64-setup.exe ;;
                    *darwin*)
                        mkdir -p build/dist/qbit-qt.app/Contents/MacOS
                        echo "STRIPPED qbit-qt" > build/dist/qbit-qt.app/Contents/MacOS/qbit-qt
                        echo "deploy zip" > build/dist/qbit-qt.zip
                        ;;
                esac
                ;;
            *" check-security "*|*" check-symbols "*) ;;
            *)
                for name in $FAKE_BIN_NAMES; do echo "UNSTRIPPED $name" > "build/bin/$name"; done
                for name in $FAKE_LIBEXEC_NAMES; do echo "UNSTRIPPED $name" > "build/libexec/$name"; done
                chmod 755 build/bin/* build/libexec/*
                ;;
        esac
        ;;
    --install)
        strip=0
        shift 2
        while [ $# -gt 0 ]; do
            case "$1" in
                --strip) strip=1 ;;
                --prefix) prefix="$2"; shift ;;
            esac
            shift
        done
        mkdir -p "$prefix/bin" "$prefix/libexec" "$prefix/share/man/man1"
        for f in build/bin/* build/libexec/*; do
            dest="$prefix/$(basename "$(dirname "$f")")/$(basename "$f")"
            if [ "$strip" = 1 ]; then echo "STRIPPED $(basename "$f")" > "$dest"; else cp "$f" "$dest"; fi
            chmod 755 "$dest"
        done
        for name in $FAKE_BIN_NAMES; do echo "man $name" > "$prefix/share/man/man1/$name.1"; done
        ;;
    *)
        echo "fake cmake: unexpected arguments: $*" >&2
        exit 1
        ;;
esac
"""

FAKE_SPLIT_DEBUG = r"""#!/bin/sh
set -e
{ printf 'DEBUG '; cat "$1"; } > "$3"
echo "STRIPPED $(basename "$1")" > "$2"
"""

FAKE_DSYMUTIL = r"""#!/usr/bin/env bash
set -e
echo "$*" >> "$FAKE_DSYMUTIL_LOG"
while [ $# -gt 0 ]; do
    case "$1" in
        --num-threads) shift ;;
        -o) out="$2"; shift ;;
        *) input="$1" ;;
    esac
    shift
done
grep -q '^UNSTRIPPED ' "$input" || { echo "fake dsymutil: no debug map in $input" >&2; exit 1; }
mkdir -p "$out/Contents/Resources/DWARF"
echo "plist $(basename "$input")" > "$out/Contents/Info.plist"
{ printf 'DWARF '; cat "$input"; } > "$out/Contents/Resources/DWARF/$(basename "$input")"
"""

FAKE_ZIP = r"""#!/usr/bin/env python3
import os
import sys
import zipfile
with zipfile.ZipFile(sys.argv[-1], "w") as archive:
    for name in sys.stdin.read().splitlines():
        if os.path.isdir(name):
            archive.writestr(zipfile.ZipInfo(name + "/", (2026, 1, 1, 0, 0, 0)), b"")
        else:
            with open(name, "rb") as file:
                archive.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), file.read())
"""


def packaging_section(script: str) -> str:
    """Return the part of build.sh that installs and packages a configured tree."""
    match = re.search(r'^mkdir -p "\$DISTSRC"$.*?^\)  # \$DISTSRC$', script, re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError("build.sh packaging section markers not found")
    return match.group(0)


def tar_option_exports(script: str) -> str:
    match = re.search(r"^export TAR_OPTIONS=.*$", script, re.MULTILINE)
    if not match:
        raise AssertionError("build.sh TAR_OPTIONS export not found")
    # Some distribution builds of GNU tar 1.35 abort on quoted values in
    # TAR_OPTIONS; the unquoted value is equivalent, as it has no spaces.
    return match.group(0).replace("'@${SOURCE_DATE_EPOCH}'", "@${SOURCE_DATE_EPOCH}")


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf8")
    path.chmod(0o755)


def make_source_archive(path: Path) -> None:
    files = {
        "README.md": "qbit readme\n",
        "doc/build/README_windows.txt": "windows readme\n",
        "share/examples/qbit.conf": "# qbit.conf\n",
        "share/rpcauth/rpcauth.py": "# rpcauth\n",
        "contrib/macdeploy/detached-sig-create.sh": "#!/bin/sh\n",
        "contrib/windeploy/detached-sig-create.sh": "#!/bin/sh\n",
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, content in sorted(files.items()):
            data = content.encode("utf8")
            info = tarfile.TarInfo(f"{DISTNAME}/{name}")
            info.size = len(data)
            info.mode = 0o755 if name.endswith(".sh") else 0o644
            archive.addfile(info, io.BytesIO(data))


def run_packaging(script: str, host: str, workdir: Path) -> Path:
    """Run the packaging section of a build.sh text for HOST with fake tools.

    Returns the output directory holding the produced release archives.
    """
    fakebin = workdir / "fakebin"
    fakebin.mkdir()
    write_executable(fakebin / "cmake", FAKE_CMAKE)
    write_executable(fakebin / "dsymutil", FAKE_DSYMUTIL)
    write_executable(fakebin / "zip", FAKE_ZIP)
    write_executable(workdir / "split-debug.sh", FAKE_SPLIT_DEBUG)
    make_source_archive(workdir / f"{DISTNAME}.tar.gz")

    driver = workdir / "driver.sh"
    driver.write_text(
        "\n".join(
            [
                "export LC_ALL=C",
                "set -e -o pipefail",
                "export TZ=UTC",
                "umask 0022",
                f"DISTNAME={DISTNAME}",
                f"HOST={host}",
                f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
                "JOBS=2",
                f'DISTSRC="{workdir}/distsrc"',
                f'OUTDIR="{workdir}/output"',
                f'BASEPREFIX="{workdir}/depends"',
                f'GIT_ARCHIVE="{workdir}/{DISTNAME}.tar.gz"',
                'CONFIGFLAGS="-DREDUCE_EXPORTS=ON"',
                tar_option_exports(script),
                packaging_section(script),
                "",
            ]
        ),
        encoding="utf8",
    )
    env = dict(os.environ)
    env.update(
        {
            "PATH": f"{fakebin}{os.pathsep}{env.get('PATH', '')}",
            "FAKE_HOST": host,
            "FAKE_BIN_NAMES": " ".join(BIN_NAMES),
            "FAKE_LIBEXEC_NAMES": " ".join(LIBEXEC_NAMES),
            "FAKE_SPLIT_DEBUG": str(workdir / "split-debug.sh"),
            "FAKE_DSYMUTIL_LOG": str(workdir / "dsymutil.log"),
        }
    )
    result = subprocess.run(
        ["bash", str(driver)], cwd=workdir, env=env, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise AssertionError(
            f"build.sh packaging failed for {host}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return workdir / "output"


def tar_contents(path: Path) -> dict[str, bytes | None]:
    """Map each member of a tarball to its content, or None for directories."""
    contents: dict[str, bytes | None] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            fileobj = archive.extractfile(member) if member.isfile() else None
            contents[member.name] = fileobj.read() if fileobj else None
    return contents


class GuixBuildConfigTest(unittest.TestCase):
    def test_release_builds_default_mainnet_guard_off(self) -> None:
        script = BUILD_SH.read_text(encoding="utf8")

        self.assertNotRegex(script, re.compile(r'qbit-\*-testnet', re.MULTILINE))
        self.assertIn(
            '-DQBIT_TESTNET_ONLY_RELEASE=$QBIT_TESTNET_ONLY_RELEASE',
            script,
        )
        self.assertIn(
            'QBIT_TESTNET_ONLY_RELEASE="${QBIT_TESTNET_ONLY_RELEASE:-OFF}"',
            script,
        )

    def test_release_builds_disable_pqc_runtime_controls(self) -> None:
        script = BUILD_SH.read_text(encoding="utf8")

        self.assertIn(
            '-DSPX_ENABLE_TEST_BENCH_ENV_KNOBS=OFF',
            script,
        )


class GuixPackagingTest(unittest.TestCase):
    def package(self, host: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return run_packaging(BUILD_SH.read_text(encoding="utf8"), host, Path(tmp.name))

    def test_darwin_ships_dsym_bundles_beside_stripped_release(self) -> None:
        executables = [f"bin/{name}" for name in BIN_NAMES] + [
            f"libexec/{name}" for name in LIBEXEC_NAMES
        ]
        for host in ("x86_64-apple-darwin", "arm64-apple-darwin"):
            with self.subTest(host=host):
                outdir = self.package(host)

                self.assertEqual(
                    sorted(path.name for path in outdir.iterdir()),
                    sorted(
                        f"{DISTNAME}-{host}-{suffix}"
                        for suffix in (
                            "codesigning.tar.gz",
                            "debug.tar.gz",
                            "unsigned.tar.gz",
                            "unsigned.zip",
                        )
                    ),
                )

                release = tar_contents(outdir / f"{DISTNAME}-{host}-unsigned.tar.gz")
                codesigning = tar_contents(outdir / f"{DISTNAME}-{host}-codesigning.tar.gz")
                for name, content in [*release.items(), *codesigning.items()]:
                    self.assertNotIn(".dSYM", name)
                    self.assertFalse(content and b"UNSTRIPPED" in content, name)
                for executable in executables:
                    member = f"{DISTNAME}/{executable}"
                    self.assertEqual(release[member], f"STRIPPED {Path(executable).name}\n".encode())
                    self.assertIn(f"./{member}", codesigning)

                debug = tar_contents(outdir / f"{DISTNAME}-{host}-debug.tar.gz")
                expected_debug: dict[str, bytes | None] = {
                    DISTNAME: None,
                    f"{DISTNAME}/bin": None,
                    f"{DISTNAME}/libexec": None,
                }
                for executable in executables:
                    name = Path(executable).name
                    bundle = f"{DISTNAME}/{executable}.dSYM"
                    expected_debug.update(
                        {
                            bundle: None,
                            f"{bundle}/Contents": None,
                            f"{bundle}/Contents/Info.plist": f"plist {name}\n".encode(),
                            f"{bundle}/Contents/Resources": None,
                            f"{bundle}/Contents/Resources/DWARF": None,
                            f"{bundle}/Contents/Resources/DWARF/{name}": (
                                f"DWARF UNSTRIPPED {name}\n".encode()
                            ),
                        }
                    )
                self.assertEqual(debug, expected_debug)

                invocations = (outdir.parent / "dsymutil.log").read_text(encoding="utf8").splitlines()
                self.assertEqual(len(invocations), len(executables))
                for invocation in invocations:
                    self.assertTrue(invocation.startswith("--num-threads 1 -o "), invocation)

    def test_linux_debug_tarball_keeps_split_debug_files(self) -> None:
        host = "x86_64-linux-gnu"
        outdir = self.package(host)

        self.assertEqual(
            sorted(path.name for path in outdir.iterdir()),
            [f"{DISTNAME}-{host}-debug.tar.gz", f"{DISTNAME}-{host}.tar.gz"],
        )
        release = tar_contents(outdir / f"{DISTNAME}-{host}.tar.gz")
        debug = tar_contents(outdir / f"{DISTNAME}-{host}-debug.tar.gz")
        self.assertEqual(release[f"{DISTNAME}/bin/qbitd"], b"STRIPPED qbitd\n")
        self.assertFalse(any(name.endswith(".dbg") for name in release))
        self.assertEqual(debug[f"{DISTNAME}/bin/qbitd.dbg"], b"DEBUG UNSTRIPPED qbitd\n")
        self.assertTrue(all(name.endswith(".dbg") for name in debug))

    def test_windows_debug_zip_keeps_split_debug_files(self) -> None:
        outdir = self.package("x86_64-w64-mingw32")

        self.assertEqual(
            sorted(path.name for path in outdir.iterdir()),
            sorted(
                f"{DISTNAME}-win64-{suffix}"
                for suffix in ("codesigning.tar.gz", "debug.zip", "setup-unsigned.exe", "unsigned.zip")
            ),
        )
        with zipfile.ZipFile(outdir / f"{DISTNAME}-win64-unsigned.zip") as release:
            self.assertEqual(release.read(f"{DISTNAME}/bin/qbitd"), b"STRIPPED qbitd\n")
            self.assertFalse(any(name.endswith(".dbg") for name in release.namelist()))
        with zipfile.ZipFile(outdir / f"{DISTNAME}-win64-debug.zip") as debug:
            self.assertEqual(debug.read(f"{DISTNAME}/bin/qbitd.dbg"), b"DEBUG UNSTRIPPED qbitd\n")
            self.assertTrue(all(name.endswith(".dbg") for name in debug.namelist()))
        codesigning = tar_contents(outdir / f"{DISTNAME}-win64-codesigning.tar.gz")
        self.assertFalse(any(name.endswith(".dbg") for name in codesigning))


if __name__ == "__main__":
    unittest.main()
