#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for building AuxPoW payloads in functional tests."""

import copy

from test_framework.blocktools import (
    add_witness_commitment,
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
    ser_uint256,
    ser_uint256_vector,
    ser_vector,
    uint256_from_compact,
    uint256_from_str,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
)

BLOCK_VERSION_TOP_BITS = 0x20000000
BLOCK_VERSION_CHAIN_ID_SHIFT = 13
BLOCK_VERSION_RESERVED_SHIFT = 9
BLOCK_VERSION_AUXPOW = 1 << 8
BLOCK_VERSION_SIGNAL_MASK = 0xFF
QBIT_AUXPOW_CHAIN_ID = 31430
MERGED_MINING_HEADER = bytes.fromhex("fabe6d6d")

LCG_MULTIPLIER = 1103515245
LCG_INCREMENT = 12345
UINT32_MASK = 0xFFFFFFFF


def make_version(*, chain_id=0, auxpow=False, reserved=0, version_bits=0, top_bits=BLOCK_VERSION_TOP_BITS):
    return (
        top_bits
        | ((chain_id & 0xFFFF) << BLOCK_VERSION_CHAIN_ID_SHIFT)
        | ((reserved & 0x0F) << BLOCK_VERSION_RESERVED_SHIFT)
        | (BLOCK_VERSION_AUXPOW if auxpow else 0)
        | (version_bits & BLOCK_VERSION_SIGNAL_MASK)
    )


def _advance_slot_lcg(value):
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & UINT32_MASK


def get_expected_index(*, nonce, chain_id, merkle_height):
    rand = _advance_slot_lcg(nonce)
    rand = (rand + chain_id) & UINT32_MASK
    rand = _advance_slot_lcg(rand)
    if merkle_height >= 32:
        return rand
    return rand & ((1 << merkle_height) - 1)


def check_merkle_branch(*, leaf, branch, index):
    merkle_hash = leaf
    for sibling in branch:
        if index & 1:
            merkle_hash = uint256_from_str(hash256(ser_uint256(sibling) + ser_uint256(merkle_hash)))
        else:
            merkle_hash = uint256_from_str(hash256(ser_uint256(merkle_hash) + ser_uint256(sibling)))
        index >>= 1
    return merkle_hash


def auxpow_commitment_root(root, *, commitment_order="display"):
    if commitment_order == "display":
        return ser_uint256(root)[::-1]
    if commitment_order == "internal":
        return ser_uint256(root)
    raise AssertionError(f"unknown AuxPoW commitment order {commitment_order!r}")


def make_parent_header(*, merkle_root, ntime, nbits, solve=True):
    parent = CBlockHeader()
    parent.nVersion = 1
    parent.hashPrevBlock = 0
    parent.hashMerkleRoot = merkle_root
    parent.nTime = ntime
    parent.nBits = nbits
    parent.nNonce = 0

    if solve:
        target = uint256_from_compact(parent.nBits)
        while uint256_from_str(hash256(parent.serialize())) > target:
            parent.nNonce += 1

    return parent


class AuxPowPayload:
    def __init__(
        self,
        *,
        coinbase_tx,
        coinbase_merkle_branch,
        coinbase_branch_index,
        chain_merkle_branch,
        chain_index,
        parent_block,
    ):
        self.coinbase_tx = coinbase_tx
        self.coinbase_merkle_branch = coinbase_merkle_branch
        self.coinbase_branch_index = coinbase_branch_index
        self.chain_merkle_branch = chain_merkle_branch
        self.chain_index = chain_index
        self.parent_block = parent_block

    def copy(self):
        return copy.deepcopy(self)

    def serialize(self):
        return (
            self.coinbase_tx.serialize_without_witness()
            + ser_uint256_vector(self.coinbase_merkle_branch)
            + self.coinbase_branch_index.to_bytes(4, "little", signed=True)
            + ser_uint256_vector(self.chain_merkle_branch)
            + self.chain_index.to_bytes(4, "little", signed=True)
            + self.parent_block.serialize()
        )

    def serialize_legacy(self, *, legacy_hash_block=None):
        if legacy_hash_block is None:
            legacy_hash_block = self.parent_block.hash_int
        return (
            self.coinbase_tx.serialize_without_witness()
            + ser_uint256(legacy_hash_block)
            + ser_uint256_vector(self.coinbase_merkle_branch)
            + self.coinbase_branch_index.to_bytes(4, "little", signed=True)
            + ser_uint256_vector(self.chain_merkle_branch)
            + self.chain_index.to_bytes(4, "little", signed=True)
            + self.parent_block.serialize()
        )

    def to_hex(self):
        return self.serialize().hex()

    def to_legacy_hex(self, *, legacy_hash_block=None):
        return self.serialize_legacy(legacy_hash_block=legacy_hash_block).hex()

    def update_parent_merkle_root(self):
        self.parent_block.hashMerkleRoot = check_merkle_branch(
            leaf=self.coinbase_tx.txid_int,
            branch=self.coinbase_merkle_branch,
            index=self.coinbase_branch_index,
        )

    def solve_parent_pow(self):
        target = uint256_from_compact(self.parent_block.nBits)
        self.parent_block.nNonce = 0
        while uint256_from_str(hash256(self.parent_block.serialize())) > target:
            self.parent_block.nNonce += 1

    def invalidate_parent_pow(self):
        target = uint256_from_compact(self.parent_block.nBits)
        while uint256_from_str(hash256(self.parent_block.serialize())) <= target:
            self.parent_block.nNonce += 1


def make_valid_auxpow(
    *,
    aux_hash,
    target_bits,
    chain_id=QBIT_AUXPOW_CHAIN_ID,
    parent_time=0,
    nonce=0,
    chain_merkle_branch=None,
    coinbase_merkle_branch=None,
    solve_parent=True,
    commitment_order="display",
):
    chain_merkle_branch = [] if chain_merkle_branch is None else list(chain_merkle_branch)
    coinbase_merkle_branch = [] if coinbase_merkle_branch is None else list(coinbase_merkle_branch)
    chain_index = get_expected_index(nonce=nonce, chain_id=chain_id, merkle_height=len(chain_merkle_branch))
    chain_root = check_merkle_branch(leaf=aux_hash, branch=chain_merkle_branch, index=chain_index)
    commitment = (
        MERGED_MINING_HEADER
        + auxpow_commitment_root(chain_root, commitment_order=commitment_order)
        + (1 << len(chain_merkle_branch)).to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )

    parent_coinbase = CTransaction()
    parent_coinbase.version = 1
    parent_coinbase.vin = [CTxIn(COutPoint(0, 0xFFFFFFFF), CScript([commitment]), 0)]
    parent_coinbase.vout = [CTxOut(0, CScript([OP_TRUE]))]
    parent_coinbase.nLockTime = 0

    parent_merkle_root = check_merkle_branch(
        leaf=parent_coinbase.txid_int,
        branch=coinbase_merkle_branch,
        index=0,
    )
    parent_block = make_parent_header(
        merkle_root=parent_merkle_root,
        ntime=parent_time,
        nbits=target_bits,
        solve=solve_parent,
    )

    return AuxPowPayload(
        coinbase_tx=parent_coinbase,
        coinbase_merkle_branch=coinbase_merkle_branch,
        coinbase_branch_index=0,
        chain_merkle_branch=chain_merkle_branch,
        chain_index=chain_index,
        parent_block=parent_block,
    )


def make_valid_auxpow_from_template(template, *, parent_time=0, nonce=0, commitment_order=None):
    return make_valid_auxpow(
        aux_hash=int(template["hash"], 16),
        target_bits=int(template["bits"], 16),
        chain_id=template["chainid"],
        parent_time=parent_time,
        nonce=nonce,
        commitment_order=commitment_order or template.get("commitmentorder", "display"),
    )


def make_valid_auxpow_from_block(block, *, chain_id=QBIT_AUXPOW_CHAIN_ID, parent_time=0, nonce=0, commitment_order="display"):
    return make_valid_auxpow(
        aux_hash=uint256_from_str(hash256(block._serialize_header())),
        target_bits=block.nBits,
        chain_id=chain_id,
        parent_time=parent_time or block.nTime,
        nonce=nonce,
        commitment_order=commitment_order,
    )


def serialize_auxpow_payload(auxpow):
    return auxpow.serialize()


def serialize_auxpow_block(block, auxpow):
    return (
        block._serialize_header()
        + serialize_auxpow_payload(auxpow)
        + ser_vector(block.vtx, "serialize_with_witness")
    ).hex()


def reconstruct_createauxblock(*, aux_template, gbt_template, payout_script_pubkey):
    coinbase = create_coinbase(aux_template["height"], script_pubkey=payout_script_pubkey)
    coinbase.vout[0].nValue = aux_template["coinbasevalue"]
    block = create_block(
        hashprev=int(aux_template["previousblockhash"], 16),
        coinbase=coinbase,
        ntime=gbt_template["curtime"],
        version=make_version(
            chain_id=aux_template["chainid"],
            auxpow=True,
            version_bits=gbt_template["version"] & BLOCK_VERSION_SIGNAL_MASK,
        ),
        tmpl={
            "previousblockhash": aux_template["previousblockhash"],
            "bits": aux_template["bits"],
            "height": aux_template["height"],
            "curtime": gbt_template["curtime"],
        },
        txlist=[tx["data"] for tx in gbt_template["transactions"]],
    )
    add_witness_commitment(block)
    return block
