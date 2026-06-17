#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test signet miner tool"""

import json
import os.path
import shlex
import subprocess
import sys
from io import BytesIO
from pathlib import Path

from test_framework.blocktools import DIFF_1_N_BITS, SIGNET_HEADER
from test_framework.key import ECKey
from test_framework.messages import CTransaction, CTxInWitness
from test_framework.psbt import PSBT, PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_IN_NON_WITNESS_UTXO
from test_framework.script_util import CScript, key_to_p2pkh_script, key_to_p2wpkh_script
from test_framework.script import SIGHASH_ALL, SegwitV0SignatureHash
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
CHALLENGE_PRIVATE_KEY = (42).to_bytes(32, 'big')
SIGNET_TEST_TIME = 2_000_000_000
# Fixed P2MR signet addresses keep the mined templates stable without depending
# on wallet key generation.
FIXTURE_REWARD_ADDRESSES = {
    "single_sig_generate": "tq1zqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsg03xv5",
    "single_sig_manual": "tq1zqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq9ekpeu",
    "op_true_generate": "tq1zqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsqt0m07",
    "op_16_generate": "tq1zqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszq38p9te",
    "push_hash_generate": "tq1zq5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5zs54clam",
    "push_hash_manual": "tq1zqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqerlcgn",
}

def get_segwit_commitment(node):
    coinbase = node.getblock(node.getbestblockhash(), 2)['tx'][0]
    commitment = coinbase['vout'][1]['scriptPubKey']['hex']
    assert_equal(commitment[0:12], '6a24aa21a9ed')
    return commitment

def get_signet_commitment(segwit_commitment):
    for el in CScript.fromhex(segwit_commitment):
        if isinstance(el, bytes) and el[0:4] == SIGNET_HEADER:
            return el[4:].hex()
    return None

class SignetMinerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.mocktime = SIGNET_TEST_TIME

        # generate and specify signet challenge (simple p2wpkh script)
        privkey = ECKey()
        privkey.set(CHALLENGE_PRIVATE_KEY, True)
        pubkey = privkey.get_pubkey().get_bytes()
        challenge = key_to_p2wpkh_script(pubkey)

        self.extra_args = [
            [f'-signetchallenge={challenge.hex()}', f'-mocktime={self.mocktime}'],
            ["-signetchallenge=51", f'-mocktime={self.mocktime}'], # OP_TRUE
            ["-signetchallenge=60", f'-mocktime={self.mocktime}'], # OP_16
            ["-signetchallenge=202cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", f'-mocktime={self.mocktime}'], # sha256("hello")
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        self.skip_if_no_bitcoin_util()

    def setup_network(self):
        self.setup_nodes()
        # Nodes with different signet networks are not connected

    def get_mineable_time(self, node):
        return max(self.mocktime, node.getblockheader(node.getbestblockhash())["time"] + 1)

    def fixture_grind_cmd(self):
        base_dir = Path(self.config["environment"]["SRCDIR"])
        helper_path = base_dir / "test" / "functional" / "data" / "signet" / "fixture_grind.py"
        return shlex.join([sys.executable, str(helper_path)])

    def sign_single_sig_challenge_psbt(self, b64_psbt):
        psbt = PSBT.from_base64(b64_psbt)
        prev_tx = CTransaction()
        prev_tx.deserialize(BytesIO(psbt.i[0].map[PSBT_IN_NON_WITNESS_UTXO]))

        privkey = ECKey()
        privkey.set(CHALLENGE_PRIVATE_KEY, True)
        pubkey = privkey.get_pubkey().get_bytes()
        script_code = key_to_p2pkh_script(pubkey)

        tx = CTransaction(psbt.tx)
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[0].scriptWitness.stack = [pubkey]
        sighash = SegwitV0SignatureHash(script_code, tx, 0, SIGHASH_ALL, prev_tx.vout[0].nValue)
        der_sig = privkey.sign_ecdsa(sighash, rfc6979=True)
        tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, der_sig + bytes([SIGHASH_ALL]))

        psbt.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS] = tx.wit.vtxinwit[0].serialize()
        return psbt.to_base64()

    # generate block with signet miner tool
    def mine_block(self, node, *, reward_address):
        n_blocks = node.getblockcount()
        base_dir = self.config["environment"]["SRCDIR"]
        signet_miner_path = os.path.join(base_dir, "contrib", "signet", "miner")
        rpc_argv = node.binaries.rpc_argv() + [f"-datadir={node.cli.datadir}"]
        block_time = self.get_mineable_time(node)
        subprocess.run([
                sys.executable,
                signet_miner_path,
                f'--cli={shlex.join(rpc_argv)}',
                'generate',
                f'--address={reward_address}',
                f'--grind-cmd={self.fixture_grind_cmd()}',
                f'--nbits={DIFF_1_N_BITS:08x}',
                f'--set-block-time={block_time}',
                '--poolnum=99',
            ], check=True, stderr=subprocess.STDOUT)
        assert_equal(node.getblockcount(), n_blocks + 1)

    # generate block using the signet miner tool genpsbt and solvepsbt commands
    def mine_block_manual(self, node, *, sign, reward_address):
        n_blocks = node.getblockcount()
        base_dir = self.config["environment"]["SRCDIR"]
        signet_miner_path = os.path.join(base_dir, "contrib", "signet", "miner")
        rpc_argv = node.binaries.rpc_argv() + [f"-datadir={node.cli.datadir}"]
        base_cmd = [
            sys.executable,
            signet_miner_path,
            f'--cli={shlex.join(rpc_argv)}',
        ]

        template = node.getblocktemplate(dict(rules=["signet","segwit"]))
        assert_equal(template["curtime"], self.get_mineable_time(node))
        genpsbt = subprocess.run(base_cmd + [
                'genpsbt',
                f'--address={reward_address}',
                '--poolnum=98',
            ], check=True, input=json.dumps(template).encode('utf8'), capture_output=True)
        psbt = genpsbt.stdout.decode('utf8').strip()
        if sign:
            self.log.debug("Sign the PSBT")
            psbt = self.sign_single_sig_challenge_psbt(psbt)
        solvepsbt = subprocess.run(base_cmd + [
                'solvepsbt',
                f'--grind-cmd={self.fixture_grind_cmd()}',
            ], check=True, input=psbt.encode('utf8'), capture_output=True)
        node.submitblock(solvepsbt.stdout.decode('utf8').strip())
        assert_equal(node.getblockcount(), n_blocks + 1)

    def run_test(self):
        self.log.info("Signet node with single signature challenge")
        node = self.nodes[0]
        self.mine_block_manual(node, sign=True, reward_address=FIXTURE_REWARD_ADDRESSES["single_sig_generate"])
        # MUST include signet commitment
        assert get_signet_commitment(get_segwit_commitment(node))

        self.log.info("Mine manually using genpsbt and solvepsbt")
        self.mine_block_manual(node, sign=True, reward_address=FIXTURE_REWARD_ADDRESSES["single_sig_manual"])
        assert get_signet_commitment(get_segwit_commitment(node))

        node = self.nodes[1]
        self.log.info("Signet node with trivial challenge (OP_TRUE)")
        self.mine_block(node, reward_address=FIXTURE_REWARD_ADDRESSES["op_true_generate"])
        # MAY omit signet commitment (BIP 325). Do so for better compatibility
        # with signet unaware mining software and hardware.
        assert get_signet_commitment(get_segwit_commitment(node)) is None

        node = self.nodes[2]
        self.log.info("Signet node with trivial challenge (OP_16)")
        self.mine_block(node, reward_address=FIXTURE_REWARD_ADDRESSES["op_16_generate"])
        assert get_signet_commitment(get_segwit_commitment(node)) is None

        node = self.nodes[3]
        self.log.info("Signet node with trivial challenge (push sha256 hash)")
        self.mine_block(node, reward_address=FIXTURE_REWARD_ADDRESSES["push_hash_generate"])
        assert get_signet_commitment(get_segwit_commitment(node)) is None

        self.log.info("Manual mining with a trivial challenge doesn't require a PSBT")
        self.mine_block_manual(node, sign=False, reward_address=FIXTURE_REWARD_ADDRESSES["push_hash_manual"])
        assert get_signet_commitment(get_segwit_commitment(node)) is None


if __name__ == "__main__":
    SignetMinerTest(__file__).main()
