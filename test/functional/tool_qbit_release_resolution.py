#!/usr/bin/env python3
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the previous-release metadata (qbit_release_resolution).

Checks, without downloading anything or starting a node, that a qbit client
version resolves to the right tag, download URL, archive, archive root, hash and
binary names on every host qbit publishes for, that the Bitcoin Core mappings
are unchanged, and that a qbit release gets Core-era options by its Core base
and qbit-only options only when it supports them.
"""
import argparse
import contextlib
import importlib
import io
import os
from pathlib import Path
import sys
from unittest import mock

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import MIN_BITCOIN_CORE_VERSION, QBIT_RELEASES, TestNode, release_info
from test_framework.util import assert_equal, assert_raises_message

# The non-debug archive lines of https://github.com/Qbit-Org/qbit/releases/download/v1.0.0/SHA256SUMS,
# copied verbatim. get_previous_releases.py must register exactly these hashes.
QBIT_V1_0_0_SHA256SUMS = """
a0242e5941eec64070f386e80c848220e2ec2292984a9b2ab1fd93f57436b31d  qbit-1.0.0-aarch64-linux-gnu.tar.gz
5607d03b68d804934ae5918f7b8bdf4c6e0da3507e809bc05b97146de13156d7  qbit-1.0.0-arm-linux-gnueabihf.tar.gz
a98310136b57f49471bb19b7bbba1ccf3801da9a1d64202cf7dcf6756db0b3a1  qbit-1.0.0-arm64-apple-darwin-unsigned.tar.gz
3580f170ada2bc4230ff9b6c0000c8d23d1195c0ff9a178f99add1285f8f819b  qbit-1.0.0-arm64-apple-darwin-unsigned.zip
acfc5098de60029e359fffda6438f29822e12a0ed5504b1a5940409c627f0384  qbit-1.0.0-powerpc64-linux-gnu.tar.gz
02455e62c33c0fac5ad65c3d8c8aa0c05be191cf7ad915a9d6dd4892c6b74cc4  qbit-1.0.0-riscv64-linux-gnu.tar.gz
93ca27facf73f736c1e1b152ad19f11eba0f075b800053bd07de9068fbe885b4  qbit-1.0.0-win64-unsigned.zip
e49b48469432e6f8bef26416b1660fc2a64809e0415f3b80cd6cb7b3f2109a2a  qbit-1.0.0-x86_64-apple-darwin-unsigned.tar.gz
6f9de70a569df992218db792366cfb0b4d368a162ad53dccca03250d40517727  qbit-1.0.0-x86_64-apple-darwin-unsigned.zip
ae121af03263b55d530e3f3e8719a71362d0950cba82f54a2bc2d6c437a029b5  qbit-1.0.0-x86_64-linux-gnu.tar.gz
"""

# Host triple -> the v1.0.0 archive holding bin/qbitd. macOS and Windows only have
# unsigned archives; the macOS "-unsigned.zip" is the GUI app bundle alone.
QBIT_V1_0_0_ARCHIVES = {
    "x86_64-linux-gnu": "qbit-1.0.0-x86_64-linux-gnu.tar.gz",
    "aarch64-linux-gnu": "qbit-1.0.0-aarch64-linux-gnu.tar.gz",
    "arm-linux-gnueabihf": "qbit-1.0.0-arm-linux-gnueabihf.tar.gz",
    "riscv64-linux-gnu": "qbit-1.0.0-riscv64-linux-gnu.tar.gz",
    "powerpc64-linux-gnu": "qbit-1.0.0-powerpc64-linux-gnu.tar.gz",
    "x86_64-apple-darwin": "qbit-1.0.0-x86_64-apple-darwin-unsigned.tar.gz",
    "arm64-apple-darwin": "qbit-1.0.0-arm64-apple-darwin-unsigned.tar.gz",
    "win64": "qbit-1.0.0-win64-unsigned.zip",
}


def core_client_version(tag):
    """Bitcoin Core client version for a release tag, e.g. v0.20.1 -> 200100, v24.0.1 -> 240001."""
    parts = [int(p) for p in tag[1:].split(".")]
    if parts[0] == 0:
        return parts[1] * 10000 + parts[2] * 100
    return parts[0] * 10000 + parts[1] * 100 + (parts[2] if len(parts) > 2 else 0)


class QbitReleaseResolutionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0  # No node/datadir needed

    def setup_network(self):
        pass

    def run_test(self):
        sys.path.insert(0, os.path.join(self.config["environment"]["SRCDIR"], "test"))
        self.releases = importlib.import_module("get_previous_releases")
        self.exeext = self.config["environment"]["EXEEXT"]

        self.test_qbit_downloads()
        self.test_default_tags()
        self.test_qbit_release_info()
        self.test_core_mappings_unchanged()
        self.test_node_options()

    def test_qbit_downloads(self):
        self.log.info("qbit v1.0.0 resolves to its GitHub archive and SHA256SUMS hash on every host")
        sums = {name: digest for digest, name in (line.split() for line in QBIT_V1_0_0_SHA256SUMS.split("\n") if line)}
        assert_equal(set(self.releases.QBIT_RELEASES["v1.0.0"]["archives"]), set(QBIT_V1_0_0_ARCHIVES))
        for host, archive in QBIT_V1_0_0_ARCHIVES.items():
            download = self.releases.resolve_download("v1.0.0", host)
            assert_equal(download.archive, archive)
            assert_equal(download.url, f"https://github.com/Qbit-Org/qbit/releases/download/v1.0.0/{archive}")
            assert_equal(download.archive_root, "qbit-1.0.0")
            assert_equal(download.sha256, sums[archive])
            assert_equal(download.archive.endswith(".zip"), host == "win64")
            assert_equal(download.adhoc_sign, host == "arm64-apple-darwin")
        # No archive for a host qbit does not publish, rather than a guessed name.
        assert_equal(self.releases.resolve_download("v1.0.0", "powerpc64le-linux-gnu"), None)

        self.log.info("Every qbit tag is both downloadable and known to the framework")
        framework_tags = {r.tag for r in QBIT_RELEASES.values()}
        assert_equal(framework_tags, set(self.releases.QBIT_RELEASES))
        # A qbit tag must not shadow a Bitcoin Core one.
        core_tags = {v["tag"] for v in self.releases.SHA256_SUMS.values()}
        assert_equal(framework_tags & core_tags, set())

    def test_default_tags(self):
        self.log.info("The default tags leave out qbit releases without an archive for the host")
        core_tags = {v["tag"] for v in self.releases.SHA256_SUMS.values()}
        assert_equal(self.releases.default_tags("x86_64-linux-gnu"), sorted(core_tags | {"v1.0.0"}))
        # powerpc64le is a host set_host() recognizes, but v1.0.0 has no archive for it.
        assert_equal(self.releases.default_tags("powerpc64le-linux-gnu"), sorted(core_tags))

        self.log.info("Without tags nothing unavailable is fetched; an explicit unavailable tag is still an error")
        target_dir = Path(self.options.tmpdir) / "previous_releases"
        for tag in core_tags:
            (target_dir / tag).mkdir(parents=True)  # cached, so nothing is downloaded

        def main(tags):
            args = argparse.Namespace(target_dir=str(target_dir), remove_dir=False, tags=tags)
            out, err = io.StringIO(), io.StringIO()
            # set_host() runs depends/config.guess relative to the source directory.
            with mock.patch.dict(os.environ, {"HOST": "powerpc64le-unknown-linux-gnu"}), \
                 self.releases.pushd(self.config["environment"]["SRCDIR"]), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                return self.releases.main(args), out.getvalue(), err.getvalue()
        ret, out, err = main([])
        assert_equal((ret, err), (0, ""))
        assert "Skipping v1.0.0: no qbit v1.0.0 archive for host powerpc64le-linux-gnu" in out, out
        ret, out, err = main(["v1.0.0"])
        assert_equal((ret, err), (1, "No qbit v1.0.0 archive for host powerpc64le-linux-gnu\n"))
        assert not (target_dir / "v1.0.0").exists()

    def test_qbit_release_info(self):
        self.log.info("Client version 10000 is qbit v1.0.0, based on Core v30.2")
        release = release_info(10000)
        assert_equal(release.family, "qbit")
        assert_equal(release.client_version, 10000)
        assert_equal(release.tag, "v1.0.0")
        assert_equal(release.core_compat_version, 300200)
        assert_equal(release.binary_prefix, "qbit")
        assert_equal(release.supports_v2_pq, False)

        bin_dir = os.path.join(self.options.previous_releases_path, release.tag, "bin")
        binaries = self.get_binaries(bin_dir, release.binary_prefix)
        assert_equal(binaries.node_argv()[0], os.path.join(bin_dir, "qbitd" + self.exeext))
        assert_equal(binaries.rpc_argv()[0], os.path.join(bin_dir, "qbit-cli" + self.exeext))

        self.log.info("An unknown or too-low qbit version is rejected, not read as a Core version")
        for version in (10001, 10100, 20000, 100, 1, 139999):
            assert_raises_message(ValueError, f"client version {version} is not a known qbit release", release_info, version)
        assert_equal(release_info(MIN_BITCOIN_CORE_VERSION).family, "bitcoin")

    def test_core_mappings_unchanged(self):
        self.log.info("Bitcoin Core versions keep their tags, URLs, hashes and binary names")
        for digest, entry in self.releases.SHA256_SUMS.items():
            tag, archive = entry["tag"], entry["archive"]
            version = core_client_version(tag)
            release = release_info(version)
            assert_equal(release.family, "bitcoin")
            assert_equal(release.tag, tag)
            assert_equal(release.core_compat_version, version)
            assert_equal(release.binary_prefix, "bitcoin")
            assert_equal(release.supports_v2_pq, False)

            host = archive.removeprefix(f"bitcoin-{tag[1:]}-").removesuffix(".tar.gz").removesuffix(".zip")
            if host == "osx64":
                host = "x86_64-apple-darwin"
            download = self.releases.resolve_download(tag, host)
            assert_equal(download.archive, archive)
            assert_equal(download.url, f"https://bitcoincore.org/bin/bitcoin-core-{tag[1:]}/{archive}")
            assert_equal(download.archive_root, f"bitcoin-{tag[1:]}")
            assert_equal(download.sha256, digest)

        # Release candidates, unregistered hashes and arm64 macOS self-signing.
        download = self.releases.resolve_download("v0.20.0rc2", "x86_64-linux-gnu")
        assert_equal(download.url, "https://bitcoincore.org/bin/bitcoin-core-0.20.0/test.rc2/bitcoin-0.20.0rc2-x86_64-linux-gnu.tar.gz")
        assert_equal(download.sha256, None)
        assert_equal(self.releases.resolve_download("v0.21.0", "arm64-apple-darwin").archive, "bitcoin-0.21.0-osx64.tar.gz")
        assert_equal(self.releases.resolve_download("v24.0.1", "arm64-apple-darwin").adhoc_sign, True)
        assert_equal(self.releases.resolve_download("v28.2", "arm64-apple-darwin").adhoc_sign, False)
        assert_equal(self.releases.resolve_download("v24.0.1", "x86_64-apple-darwin").adhoc_sign, False)

        bin_dir = os.path.join(self.options.previous_releases_path, "v28.2", "bin")
        binaries = self.get_binaries(bin_dir, release_info(280200).binary_prefix)
        assert_equal(binaries.node_argv()[0], os.path.join(bin_dir, "bitcoind" + self.exeext))
        assert_equal(binaries.rpc_argv()[0], os.path.join(bin_dir, "bitcoin-cli" + self.exeext))

    def make_node(self, version):
        release = None if version is None else release_info(version)
        bin_dir = None if release is None else os.path.join(self.options.previous_releases_path, release.tag, "bin")
        return TestNode(
            0,
            Path(self.options.tmpdir) / f"node_{version}",
            chain=self.chain,
            rpchost=None,
            timewait=self.rpc_timeout,
            timeout_factor=self.options.timeout_factor,
            binaries=self.get_binaries(bin_dir, "bitcoin" if release is None else release.binary_prefix),
            coverage_dir=None,
            cwd=self.options.tmpdir,
            version=version,
            v2transport=True,
        )

    def test_node_options(self):
        self.log.info("A v1.0.0 node gets -v2transport and the logging options through its Core base")
        node = self.make_node(10000)
        for arg in ("-v2transport=1", "-logthreadnames", "-logsourcelocations", "-loglevel=trace", "-nologratelimit", "-conf=qbit.conf"):
            assert arg in node.args, arg
        assert node.version_is_at_least(300200)
        assert not node.version_is_at_least(300201)

        self.log.info("qbit-only options go to qbit releases that have them and to the build under test")
        assert node.qbit_version_is_at_least(10000)
        assert not node.qbit_version_is_at_least(10001)
        assert_equal(node.supports_p2mronly, True)
        assert_equal(node.supports_v2_pq, False)

        core = self.make_node(250000)
        assert "-v2transport=1" not in core.args
        assert not core.qbit_version_is_at_least(10000)
        assert_equal(core.supports_p2mronly, False)
        assert_equal(core.supports_v2_pq, False)

        current = self.make_node(None)
        assert "-v2transport=1" in current.args
        assert current.version_is_at_least(10**9)
        assert current.qbit_version_is_at_least(10**9)
        assert_equal(current.supports_p2mronly, True)
        assert_equal(current.supports_v2_pq, True)


if __name__ == '__main__':
    QbitReleaseResolutionTest(__file__).main()
