#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import subprocess

from test_framework.test_framework import BitcoinTestFramework

class BitcoinChainstateTest(BitcoinTestFramework):

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_chainstate()

    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""
        self.num_nodes = 1
        # Set prune to avoid disk space warning.
        self.extra_args = [["-prune=550"]]

    def add_block(self, datadir, input, expected_stderr):
        proc = subprocess.Popen(
            self.get_binaries().chainstate_argv() + [datadir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        timeout = 30 * self.options.timeout_factor
        try:
            stdout, stderr = proc.communicate(input=input + "\n", timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise AssertionError(
                f"qbit-chainstate timed out after {timeout}s.\n"
                f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
        self.log.debug("STDOUT: {0}".format(stdout.strip("\n")))
        self.log.info("STDERR: {0}".format(stderr.strip("\n")))

        if expected_stderr not in stderr:
            raise AssertionError(f"Expected stderr output {expected_stderr} does not partially match stderr:\n{stderr}")

    def run_test(self):
        node = self.nodes[0]
        datadir = node.cli.datadir
        block_one = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
        block_one_prev_hash = bytes.fromhex(block_one[8:72])[::-1].hex()
        chain_genesis_hash = node.getblockhash(0)
        node.stop_node()

        self.log.info(f"Testing qbit-chainstate {self.get_binaries().chainstate_argv()} with datadir: {datadir}")
        if chain_genesis_hash == block_one_prev_hash:
            first_submit_expected_stderr = "Block has not yet been rejected"
            second_submit_expected_stderr = "duplicate"
        else:
            first_submit_expected_stderr = "We don't have the previous block the checked one is built on"
            second_submit_expected_stderr = first_submit_expected_stderr

        self.add_block(datadir, block_one, first_submit_expected_stderr)
        self.add_block(datadir, block_one, second_submit_expected_stderr)
        self.add_block(datadir, "00", "Block decode failed")
        self.add_block(datadir, "", "Empty line found")

if __name__ == "__main__":
    BitcoinChainstateTest(__file__).main()
