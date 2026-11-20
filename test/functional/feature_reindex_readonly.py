#!/usr/bin/env python3
# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -reindex from a read-only blockstore
- Start a node, generate blocks, then restart with -reindex after setting blk files to read-only
"""

from contextlib import ExitStack
import errno
import os
import platform
import shutil
import stat
import subprocess
from test_framework.test_framework import BitcoinTestFramework, SkipTest


class BlockstoreReindexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-fastprune"]]

    def reindex_readonly(self):
        self.log.debug("Generate block big enough to start second block file")
        fastprune_blockfile_size = 0x10000
        opreturn = "6a"
        nulldata = fastprune_blockfile_size * "ff"
        self.generateblock(self.nodes[0], output=f"raw({opreturn}{nulldata})", transactions=[])
        block_count = self.nodes[0].getblockcount()
        self.stop_node(0)

        assert (self.nodes[0].chain_path / "blocks" / "blk00000.dat").exists()
        assert (self.nodes[0].chain_path / "blocks" / "blk00001.dat").exists()

        self.log.debug("Make the first block file read-only")
        filename = self.nodes[0].chain_path / "blocks" / "blk00000.dat"
        with ExitStack() as cleanup:
            mode = filename.stat().st_mode
            filename.chmod(stat.S_IREAD)
            cleanup.callback(filename.chmod, mode)
            linux = platform.system() == "Linux"
            tool, enable, disable = ("chattr", "+i", "-i") if linux else ("chflags", "uchg", "nouchg")
            if shutil.which(tool):
                result = subprocess.run([tool, enable, filename], capture_output=True, text=True)
                if result.returncode == 0:
                    cleanup.callback(subprocess.check_call, [tool, disable, filename])
                    self.log.info(f"Made file immutable with {tool}")
                else:
                    self.log.info(f"{tool} failed: {result.stderr.strip()}")

            def writable():
                # The node inherits our credentials. Probe without truncating or modifying the file.
                try:
                    fd = os.open(filename, os.O_WRONLY)
                except OSError as e:
                    if e.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
                        return False
                    raise
                os.close(fd)
                return True

            if writable():
                if linux and os.geteuid() == 0 and shutil.which("mount") and shutil.which("umount"):
                    for options in ("bind", "remount,bind,ro"):
                        result = subprocess.run(["mount", "-o", options, filename, filename], capture_output=True, text=True)
                        if result.returncode:
                            raise SkipTest(f"Block file is writable and {options} mount failed: {result.stderr.strip()}")
                        if options == "bind":
                            cleanup.callback(subprocess.check_call, ["umount", filename])
                    self.log.info("Made block file read-only with a bind mount")
                    assert not writable(), "Block file is still writable after read-only remount"
                else:
                    raise SkipTest("Cannot make the block file read-only for the node")

            self.log.debug("Attempt to restart and reindex the node with the unwritable block file")
            with self.nodes[0].assert_debug_log(["Reindexing finished"], timeout=60):
                self.start_node(0, extra_args=['-reindex', '-fastprune'])
            assert block_count == self.nodes[0].getblockcount()

    def run_test(self):
        self.reindex_readonly()


if __name__ == '__main__':
    BlockstoreReindexTest(__file__).main()
