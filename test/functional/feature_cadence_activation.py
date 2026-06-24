#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test regtest-only cadence activation-height override."""

from test_framework.auxpow import make_valid_auxpow_from_template
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    hash256,
    ser_uint256_vector,
    ser_vector,
    uint256_from_compact,
    uint256_from_str,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import getnewdestination


CADENCE_ACTIVATION_HEIGHT = 120
BLOCK_VERSION_TOP_BITS = 0x20000000
BLOCK_VERSION_CHAIN_ID_SHIFT = 13
BLOCK_VERSION_RESERVED_SHIFT = 9
BLOCK_VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_SIGNAL_MASK = 0xFF
QBIT_AUXPOW_CHAIN_ID = 31430
MERGED_MINING_HEADER = bytes.fromhex("fabe6d6d")


def make_version(*, chain_id=0, auxpow=False, reserved=0, version_bits=0, top_bits=BLOCK_VERSION_TOP_BITS):
    return (
        top_bits
        | ((chain_id & 0xFFFF) << BLOCK_VERSION_CHAIN_ID_SHIFT)
        | ((reserved & 0x0F) << BLOCK_VERSION_RESERVED_SHIFT)
        | (BLOCK_VERSION_AUXPOW if auxpow else 0)
        | (version_bits & BLOCK_VERSION_SIGNAL_MASK)
    )


def make_parent_header(*, merkle_root, ntime, nbits):
    parent = CBlockHeader()
    parent.nVersion = 1
    parent.hashPrevBlock = 0
    parent.hashMerkleRoot = merkle_root
    parent.nTime = ntime
    parent.nBits = nbits
    parent.nNonce = 0

    target = uint256_from_compact(parent.nBits)
    while uint256_from_str(hash256(parent.serialize())) > target:
        parent.nNonce += 1

    return parent


def serialize_auxpow_payload(block):
    aux_block_hash = hash256(block._serialize_header())
    commitment = (
        MERGED_MINING_HEADER
        + aux_block_hash[::-1]
        + (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )

    parent_coinbase = CTransaction()
    parent_coinbase.version = 1
    parent_coinbase.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), CScript([commitment]), 0)]
    parent_coinbase.vout = [CTxOut(0, CScript([OP_TRUE]))]
    parent_coinbase.nLockTime = 0

    parent_block = make_parent_header(
        merkle_root=parent_coinbase.txid_int,
        ntime=block.nTime,
        nbits=block.nBits,
    )

    return (
        parent_coinbase.serialize_without_witness()
        + ser_uint256_vector([])
        + (0).to_bytes(4, "little", signed=True)
        + ser_uint256_vector([])
        + (0).to_bytes(4, "little", signed=True)
        + parent_block.serialize()
    )


def serialize_auxpow_block(block):
    return (
        block._serialize_header()
        + serialize_auxpow_payload(block)
        + ser_vector(block.vtx, "serialize_with_witness")
    ).hex()


class FeatureCadenceActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=cadence@{CADENCE_ACTIVATION_HEIGHT}"]]

    def create_candidate_block(self, *, version):
        node = self.nodes[0]
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(
            hashprev=int(tmpl["previousblockhash"], 16),
            coinbase=create_coinbase(tmpl["height"]),
            ntime=tmpl["curtime"] + 1,
            version=version,
            tmpl=tmpl,
        )
        block.solve()
        return block

    def proposal_and_submit(self, *, block_hex, expected):
        node = self.nodes[0]
        proposal_result = node.getblocktemplate(
            template_request={
                "data": block_hex,
                "mode": "proposal",
                "rules": ["segwit"],
            }
        )
        assert_equal(proposal_result, expected)
        assert_equal(node.submitblock(block_hex), expected)

    def run_test(self):
        node = self.nodes[0]
        _, _, payout_address = getnewdestination("bech32")
        target_height = CADENCE_ACTIVATION_HEIGHT - 2
        current_height = node.getblockcount()
        if current_height < target_height:
            self.generate(node, target_height - current_height)
        assert_equal(node.getblockcount(), target_height)

        signal_bits = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)["version"] & BLOCK_VERSION_SIGNAL_MASK

        self.log.info("Pre-activation: createauxblock fails fast")
        assert_raises_rpc_error(
            -1,
            f"cadence is inactive at height {CADENCE_ACTIVATION_HEIGHT - 1}",
            node.createauxblock,
            payout_address,
        )

        self.log.info("Pre-activation: AuxPoW headers are rejected")
        pre_tip = node.getbestblockhash()
        pre_auxpow = self.create_candidate_block(
            version=make_version(chain_id=QBIT_AUXPOW_CHAIN_ID, auxpow=True, version_bits=signal_bits)
        )
        self.proposal_and_submit(
            block_hex=serialize_auxpow_block(pre_auxpow),
            expected="bad-cadence-inactive",
        )
        assert_equal(node.getbestblockhash(), pre_tip)
        assert_equal(node.getblockcount(), CADENCE_ACTIVATION_HEIGHT - 2)

        self.log.info("Pre-activation: reserved bits are still accepted")
        pre_reserved = self.create_candidate_block(
            version=make_version(chain_id=0, reserved=0b0110, version_bits=signal_bits)
        )
        self.proposal_and_submit(
            block_hex=pre_reserved.serialize().hex(),
            expected=None,
        )
        assert_equal(node.getbestblockhash(), pre_reserved.hash_hex)
        assert_equal(node.getblockcount(), CADENCE_ACTIVATION_HEIGHT - 1)

        self.log.info("Activation boundary: createauxblock returns submittable AuxPoW work")
        aux_template = node.createauxblock(payout_address)
        assert_equal(aux_template["height"], CADENCE_ACTIVATION_HEIGHT)
        assert_equal(aux_template["chainid"], QBIT_AUXPOW_CHAIN_ID)
        assert_equal(aux_template["previousblockhash"], node.getbestblockhash())
        assert_equal(node.submitauxblock(aux_template["hash"], make_valid_auxpow_from_template(aux_template).to_hex()), None)
        assert_equal(node.getblockcount(), CADENCE_ACTIVATION_HEIGHT)

        self.log.info("Post-activation: reserved bits are rejected")
        post_tip = node.getbestblockhash()
        post_reserved = self.create_candidate_block(
            version=make_version(chain_id=0, reserved=0b0110, version_bits=signal_bits)
        )
        self.proposal_and_submit(
            block_hex=post_reserved.serialize().hex(),
            expected=f"bad-version-reserved(0x{post_reserved.nVersion:08x})",
        )
        assert_equal(node.getbestblockhash(), post_tip)
        assert_equal(node.getblockcount(), CADENCE_ACTIVATION_HEIGHT)


if __name__ == "__main__":
    FeatureCadenceActivationTest(__file__).main()
