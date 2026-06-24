#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test consensus header rejects for canonical version-field validation."""

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

BLOCK_VERSION_TOP_BITS = 0x20000000
BLOCK_VERSION_CHAIN_ID_SHIFT = 13
BLOCK_VERSION_RESERVED_SHIFT = 9
BLOCK_VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_SIGNAL_MASK = 0xFF
BLOCK_VERSION_CHAIN_ID_MASK = 0x1FFFE000
BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK = BLOCK_VERSION_CHAIN_ID_MASK
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
    parent_coinbase.vin = [CTxIn(COutPoint(0, 0xffffffff), CScript([commitment]), 0)]
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


class MiningVersionFieldTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

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

    def proposal_and_submit_decode_failure(self, *, block_hex):
        node = self.nodes[0]
        assert_raises_rpc_error(
            -22,
            "Block decode failed",
            node.getblocktemplate,
            {
                "data": block_hex,
                "mode": "proposal",
                "rules": ["segwit"],
            },
        )
        assert_raises_rpc_error(-22, "Block decode failed", node.submitblock, block_hex)

    def run_test(self):
        node = self.nodes[0]
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        signal_bits = tmpl["version"] & BLOCK_VERSION_SIGNAL_MASK
        assert_equal(tmpl["version"] & BLOCK_VERSION_CHAIN_ID_MASK, 0)
        assert_equal(tmpl["versionrollingmask"], f"{BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK:08x}")

        self.log.info("Disable version rolling for non-BIP9 -blockversion overrides")
        self.restart_node(0, extra_args=["-blockversion=4"])
        node = self.nodes[0]
        override_tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(override_tmpl["version"], 4)
        assert_equal(override_tmpl["versionrollingmask"], "00000000")
        self.restart_node(0)
        node = self.nodes[0]

        self.log.info("Reject versions with non-BIP9 top bits")
        bad_top_bits = 0x40000000 | signal_bits
        bad_top_bits_block = self.create_candidate_block(version=bad_top_bits)
        self.proposal_and_submit(
            block_hex=bad_top_bits_block.serialize().hex(),
            expected=f"bad-version-topbits(0x{bad_top_bits:08x})",
        )

        self.log.info("Reject zero-top-bit versions that still set cadence layout bits")
        for bad_zero_top in (BLOCK_VERSION_AUXPOW, 0b0011 << BLOCK_VERSION_RESERVED_SHIFT):
            bad_zero_top_block = self.create_candidate_block(version=bad_zero_top | signal_bits)
            self.proposal_and_submit(
                block_hex=bad_zero_top_block.serialize().hex(),
                expected=f"bad-version-topbits(0x{bad_zero_top_block.nVersion:08x})",
            )

        self.log.info("Accept zero-top-bit versions that stay within the legacy low-bit range")
        legacy_signal_only = max(4, signal_bits)
        legacy_signal_only_block = self.create_candidate_block(version=legacy_signal_only)
        self.proposal_and_submit(
            block_hex=legacy_signal_only_block.serialize().hex(),
            expected=None,
        )

        self.log.info("Accept permissionless version rolling across qbit chain-id bits")
        for chain_id in (1, 0xffff):
            rolled_version_block = self.create_candidate_block(
                version=make_version(chain_id=chain_id, auxpow=False, version_bits=signal_bits)
            )
            self.proposal_and_submit(
                block_hex=rolled_version_block.serialize().hex(),
                expected=None,
            )

        self.log.info("Reject versions with reserved bits set")
        bad_reserved = make_version(chain_id=0, reserved=0b0110, version_bits=signal_bits)
        bad_reserved_block = self.create_candidate_block(version=bad_reserved)
        self.proposal_and_submit(
            block_hex=bad_reserved_block.serialize().hex(),
            expected=f"bad-version-reserved(0x{bad_reserved:08x})",
        )

        self.log.info("Reject auxpow versions with mismatched chain id")
        bad_chainid = make_version(chain_id=QBIT_AUXPOW_CHAIN_ID + 1, auxpow=True, version_bits=signal_bits)
        bad_chainid_block = self.create_candidate_block(version=bad_chainid)
        self.proposal_and_submit(
            block_hex=serialize_auxpow_block(bad_chainid_block),
            expected="bad-auxpow-chainid",
        )

        self.log.info("Reject auxpow versions without auxpow payload at decode time")
        bad_auxpow_payload = make_version(chain_id=QBIT_AUXPOW_CHAIN_ID, auxpow=True, version_bits=signal_bits)
        bad_auxpow_block = self.create_candidate_block(version=bad_auxpow_payload)
        self.proposal_and_submit_decode_failure(
            block_hex=bad_auxpow_block.serialize().hex(),
        )


if __name__ == "__main__":
    MiningVersionFieldTest(__file__).main()
