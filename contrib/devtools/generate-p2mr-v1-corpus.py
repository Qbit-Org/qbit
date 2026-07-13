#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Generate the non-signature qbit P2MR v1 conformance corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PROFILE = "qbit-p2mr-v1"
PROFILE_VERSION = 1
SCHEMA_VERSION = 1
LEAF_VERSION = 0xC0
CONTROL_BYTE = LEAF_VERSION | 1
BECH32M_CONST = 0x2BC830A3
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("CompactSize cannot encode a negative value")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + payload)


def leaf_preimage(script: bytes, tag: str, version: int = LEAF_VERSION) -> bytes:
    del tag
    return bytes([version]) + compact_size(len(script)) + script


def leaf_hash(script: bytes, tag: str = "P2MRLeaf", version: int = LEAF_VERSION) -> bytes:
    return tagged_hash(tag, leaf_preimage(script, tag, version))


def branch_step(left: bytes, right: bytes) -> tuple[bytes, bytes]:
    preimage = min(left, right) + max(left, right)
    return preimage, tagged_hash("P2MRBranch", preimage)


def script_pubkey(root: bytes) -> bytes:
    if len(root) != 32:
        raise ValueError("P2MR root must be 32 bytes")
    return b"\x52\x20" + root


def bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value >> from_bits:
            raise ValueError("input value exceeds source bit width")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if bits:
        result.append((accumulator << (to_bits - bits)) & max_value)
    return result


def witness_address(hrp: str, program: bytes) -> str:
    data = [2] + convert_bits(program, 8, 5)
    values = hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0] * 6) ^ BECH32M_CONST
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in data + checksum)


def expected(accepted: bool, stage: str, error: str) -> dict[str, Any]:
    return {"accepted": accepted, "stage": stage, "error": error}


def build_valid_vector(
    vector_id: str,
    script_hex: str,
    siblings_hex: list[str],
    notes: str | None = None,
) -> dict[str, Any]:
    script = bytes.fromhex(script_hex)
    hashed_leaf = leaf_hash(script)
    current = hashed_leaf
    branch_preimages: list[str] = []
    siblings = [bytes.fromhex(sibling) for sibling in siblings_hex]
    for sibling in siblings:
        preimage, current = branch_step(current, sibling)
        branch_preimages.append(preimage.hex())
    value: dict[str, Any] = {
        "id": vector_id,
        "name": vector_id,
        "expected": expected(True, "script-complete", "SCRIPT_ERR_OK"),
        "leaf_script": script_hex,
        "leaf_version": LEAF_VERSION,
        "leaf_preimage": leaf_preimage(script, "P2MRLeaf").hex(),
        "leaf_hash": hashed_leaf.hex(),
        "siblings": siblings_hex,
        "branch_preimages": branch_preimages,
        "control_block": (bytes([CONTROL_BYTE]) + b"".join(siblings)).hex(),
        "merkle_root": current.hex(),
        "scriptPubKey": script_pubkey(current).hex(),
        "mainnet_address": witness_address("qb", current),
        "regtest_address": witness_address("qbrt", current),
    }
    if notes is not None:
        value["notes"] = notes
    return value


def build_commitment_corpus() -> dict[str, Any]:
    op_false_hash = leaf_hash(b"\x00").hex()
    op_true_hash = leaf_hash(b"\x51").hex()
    valid = [
        build_valid_vector("single_leaf_op_true", "51", []),
        build_valid_vector(
            "two_leaf_op_true_with_op_false_sibling",
            "51",
            [op_false_hash],
        ),
        build_valid_vector(
            "two_leaf_spent_hash_sorts_after_sibling",
            "5161",
            [op_true_hash],
            "The spent leaf hash is lexicographically greater than its sibling, so the branch preimage must be sibling || spent.",
        ),
        build_valid_vector(
            "three_leaf_two_level_spend_middle_leaf",
            "5161",
            [
                "817b726bbe1b4cb416f82d1e4f3ce1656e762c9d6f19e9f7d1344868f0035fe8",
                "dda3b0355ee1622abb9fdd5d5abc3d6d4300fbd2e1f4fa4d291d0dee90bd423d",
            ],
            "Tree shape is A || (B || C); control path is C then A, bottom-up.",
        ),
    ]
    by_id = {vector["id"]: vector for vector in valid}
    single_root = by_id["single_leaf_op_true"]["merkle_root"]
    two_root = by_id["two_leaf_op_true_with_op_false_sibling"]["merkle_root"]
    sorted_after = by_id["two_leaf_spent_hash_sorts_after_sibling"]
    wrong_leaf_preimage = bytes([LEAF_VERSION, 2, 0x51])
    wrong_leaf_hash = tagged_hash("P2MRLeaf", wrong_leaf_preimage).hex()
    spent = bytes.fromhex(sorted_after["leaf_hash"])
    sibling = bytes.fromhex(sorted_after["siblings"][0])
    wrong_branch_preimage = spent + sibling
    wrong_branch_root = tagged_hash("P2MRBranch", wrong_branch_preimage).hex()

    def invalid(
        vector_id: str,
        base: str,
        stage: str,
        error: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        base_vector = by_id[base]
        return {
            "id": vector_id,
            "name": vector_id,
            "expected": expected(False, stage, error),
            "base": base,
            "leaf_script": base_vector["leaf_script"],
            "leaf_version": base_vector["leaf_version"],
            **fields,
            "expected_error": error,
        }

    invalid_vectors = [
        invalid(
            "missing_bit0_control_marker",
            "single_leaf_op_true",
            "control-marker",
            "SCRIPT_ERR_P2MR_CONTROL_BIT0",
            {"control_block": "c0", "merkle_root": single_root},
        ),
        invalid(
            "malformed_control_block_size",
            "single_leaf_op_true",
            "control-size",
            "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE",
            {"control_block": "c100", "merkle_root": single_root},
        ),
        invalid(
            "wrong_leaf_version",
            "single_leaf_op_true",
            "commitment",
            "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
            {"leaf_version": 0xC2, "control_block": "c3", "merkle_root": single_root},
        ),
        invalid(
            "wrong_compactsize_script_length_encoding",
            "single_leaf_op_true",
            "commitment",
            "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
            {
                "wrong_leaf_preimage": wrong_leaf_preimage.hex(),
                "wrong_leaf_hash": wrong_leaf_hash,
                "control_block": "c1",
                "merkle_root": wrong_leaf_hash,
            },
        ),
        invalid(
            "mutated_sibling",
            "two_leaf_op_true_with_op_false_sibling",
            "commitment",
            "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
            {
                "control_block": "c1fb" + op_false_hash[2:],
                "merkle_root": two_root,
            },
        ),
        invalid(
            "unsorted_branch_preimage_when_spent_hash_sorts_after_sibling",
            "two_leaf_spent_hash_sorts_after_sibling",
            "commitment",
            "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
            {
                "wrong_branch_preimage": wrong_branch_preimage.hex(),
                "wrong_merkle_root": wrong_branch_root,
                "control_block": sorted_after["control_block"],
                "merkle_root": wrong_branch_root,
            },
        ),
        invalid(
            "wrong_address_root_commitment",
            "single_leaf_op_true",
            "commitment",
            "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
            {"control_block": "c1", "merkle_root": "42" * 32},
        ),
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "generator": {
            "id": "standalone-python",
            "version": 1,
            "uses_qbit_consensus_helpers": False,
        },
        "valid": valid,
        "invalid": invalid_vectors,
    }


def build_cross_profile_corpus() -> dict[str, Any]:
    script = b"\x00"
    tapleaf_root = leaf_hash(script, "TapLeaf")
    p2mr_root = leaf_hash(script)
    common = {
        "leaf_version": "c0",
        "leaf_script": "00",
        "control_block": "c1",
        "tapleaf_root": tapleaf_root.hex(),
        "p2mr_leaf_root": p2mr_root.hex(),
        "witness": ["00", "c1"],
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "comparison_profile": {
            "name": "BIP-360",
            "version": "0.12.0",
            "commit": "6740c533e8dce4e912f17ee85a6f627644e1b783",
            "normative": False,
        },
        "vectors": [
            {
                "id": "pinned-bip-root-rejected-by-qbit",
                "name": "Pinned BIP-360 root is not a qbit P2MR v1 commitment",
                "comparison_scope": "full-pinned-profile",
                **common,
                "scriptPubKey": script_pubkey(tapleaf_root).hex(),
                "expected": {
                    "pinned_bip_360": expected(True, "depth-zero-shortcut", "SCRIPT_ERR_OK"),
                    "qbit_p2mr_v1": expected(
                        False,
                        "commitment",
                        "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH",
                    ),
                },
            },
            {
                "id": "qbit-root-executes-depth-zero-script",
                "name": "qbit P2MR v1 executes a matching depth-zero OP_0 leaf",
                "comparison_scope": "isolated-depth-zero-rule-with-qbit-tags",
                **common,
                "scriptPubKey": script_pubkey(p2mr_root).hex(),
                "expected": {
                    "bip_style_depth_zero_with_qbit_tags": expected(
                        True,
                        "depth-zero-shortcut",
                        "SCRIPT_ERR_OK",
                    ),
                    "qbit_p2mr_v1": expected(
                        False,
                        "script-execution",
                        "SCRIPT_ERR_EVAL_FALSE",
                    ),
                },
            },
        ],
    }


def boundary_case(
    case_id: str,
    category: str,
    scenario: str,
    parameters: dict[str, Any],
    consensus: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "category": category,
        "scenario": scenario,
        "parameters": parameters,
        "consensus": consensus,
        "policy": policy if policy is not None else consensus.copy(),
    }


def build_boundary_corpus() -> dict[str, Any]:
    ok = expected(True, "script-complete", "SCRIPT_ERR_OK")
    fixture = {
        "fixture_file": "src/test/data/p2mr_pqc_witness_vectors.json",
        "fixture_id": "single_key_default_sighash",
    }
    cases = [
        boundary_case("witness-empty", "witness-control", "witness-shape", {"kind": "empty"}, expected(False, "witness", "SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY")),
        boundary_case("witness-one-element", "witness-control", "witness-shape", {"kind": "one-element"}, expected(False, "witness", "SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY")),
        boundary_case("witness-annex-underflow", "witness-control", "witness-shape", {"kind": "annex-underflow"}, expected(False, "witness", "SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY")),
        boundary_case("control-minimum", "witness-control", "control-path", {"nodes": 0, "mutation": "none"}, ok),
        boundary_case("control-depth-128", "witness-control", "control-path", {"nodes": 128, "mutation": "none"}, ok),
        boundary_case("control-depth-129", "witness-control", "control-path", {"nodes": 129, "mutation": "none"}, expected(False, "control-size", "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE")),
        boundary_case("control-nonmultiple-length", "witness-control", "control-path", {"nodes": 0, "mutation": "append-byte"}, expected(False, "control-size", "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE")),
        boundary_case("control-marker-zero", "witness-control", "control-path", {"nodes": 0, "mutation": "clear-marker"}, expected(False, "control-marker", "SCRIPT_ERR_P2MR_CONTROL_BIT0")),
        boundary_case("control-mutated-path-node", "witness-control", "control-path", {"nodes": 1, "mutation": "path-node"}, expected(False, "commitment", "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH")),
        boundary_case("control-direct-root-mismatch", "witness-control", "control-path", {"nodes": 0, "mutation": "program-root"}, expected(False, "commitment", "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH")),
        boundary_case("leaf-c0-true", "leaf-version", "leaf-version", {"control_byte": 193, "script": "true"}, ok),
        boundary_case("leaf-c0-false", "leaf-version", "leaf-version", {"control_byte": 193, "script": "false"}, expected(False, "script", "SCRIPT_ERR_EVAL_FALSE")),
        boundary_case("leaf-production-reserved", "leaf-version", "leaf-version", {"control_byte": 195, "script": "false"}, expected(True, "upgrade-success", "SCRIPT_ERR_OK"), expected(False, "policy", "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")),
        boundary_case("leaf-staged-signature-system", "leaf-version", "leaf-version", {"control_byte": 225, "script": "false"}, expected(True, "upgrade-success", "SCRIPT_ERR_OK"), expected(False, "policy", "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")),
        boundary_case("leaf-experimental", "leaf-version", "leaf-version", {"control_byte": 241, "script": "false"}, expected(True, "upgrade-success", "SCRIPT_ERR_OK"), expected(False, "policy", "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")),
        boundary_case("leaf-extension-fe", "leaf-version", "leaf-version", {"control_byte": 255, "script": "false"}, expected(True, "upgrade-success", "SCRIPT_ERR_OK"), expected(False, "policy", "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")),
        boundary_case("leaf-odd-control-mask", "leaf-version", "leaf-version", {"control_byte": 195, "script": "true"}, expected(True, "upgrade-success", "SCRIPT_ERR_OK"), expected(False, "policy", "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")),
        boundary_case("opcode-checksigpqc-valid", "opcode", "opcode", {"kind": "checksigpqc-valid", **fixture, "artifact": "transaction-checksigpqc"}, ok),
        boundary_case("opcode-checksigpqc-empty-signature", "opcode", "opcode", {"kind": "checksigpqc-empty"}, expected(False, "script", "SCRIPT_ERR_VERIFY")),
        boundary_case("opcode-checksigpqc-bad-size", "opcode", "opcode", {"kind": "checksigpqc-bad-size"}, expected(False, "script", "SCRIPT_ERR_P2MR_SIG_SIZE")),
        boundary_case("opcode-checksigpqc-bad-key", "opcode", "opcode", {"kind": "checksigpqc-bad-key"}, expected(False, "script", "SCRIPT_ERR_PUBKEYTYPE")),
        boundary_case("opcode-checksigpqc-invalid-signature", "opcode", "opcode", {"kind": "checksigpqc-invalid", **fixture, "artifact": "transaction-checksigpqc", "mutation": "flip-first-signature-byte"}, expected(False, "script", "SCRIPT_ERR_P2MR_SIG")),
        boundary_case("opcode-checksigpqc-underflow", "opcode", "opcode", {"kind": "checksigpqc-underflow"}, expected(False, "script", "SCRIPT_ERR_INVALID_STACK_OPERATION")),
        boundary_case("opcode-checksigadd-pqc", "opcode", "opcode", {"kind": "checksigadd-valid", **fixture, "artifact": "checkSigAdd"}, ok),
        boundary_case("opcode-checksigadd-pqc-underflow", "opcode", "opcode", {"kind": "checksigadd-underflow"}, expected(False, "script", "SCRIPT_ERR_INVALID_STACK_OPERATION")),
        boundary_case("opcode-legacy-checksig", "opcode", "opcode", {"kind": "legacy-checksig"}, expected(False, "script", "SCRIPT_ERR_P2MR_CHECKSIG")),
        boundary_case("opcode-legacy-checkmultisig", "opcode", "opcode", {"kind": "legacy-checkmultisig"}, expected(False, "script", "SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG")),
        boundary_case("opcode-ctv-valid", "opcode", "opcode", {"kind": "ctv-fixed", "control_block": "c1", "template_hash": "6597328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28ac", "leaf_script": "206597328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28acbb", "script_pubkey": "52207efd262261fb0e7917e65f9ba628fa12549527ec1649173648e6e637cfd017ac"}, ok),
        boundary_case("opcode-ctv-mismatch", "opcode", "opcode", {"kind": "ctv-fixed", "control_block": "c1", "template_hash": "6497328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28ac", "leaf_script": "206497328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28acbb", "script_pubkey": "522093e9c5f8a9170f35989d4c55ec190d356e79743ac59d3428fedde4ddfe79b2e1"}, expected(False, "script", "SCRIPT_ERR_TEMPLATE_MISMATCH")),
        boundary_case("opcode-checkdatasigpqc", "opcode", "opcode", {"kind": "checkdatasigpqc-valid", **fixture, "artifact": "dataSig"}, ok),
        boundary_case("opcode-checkdatasigpqc-invalid-signature", "opcode", "opcode", {"kind": "checkdatasigpqc-invalid", **fixture, "artifact": "dataSig", "mutation": "flip-first-signature-byte"}, expected(False, "script", "SCRIPT_ERR_P2MR_SIG")),
        boundary_case("opcode-checkdatasigpqc-wrong-domain", "opcode", "opcode", {"kind": "checkdatasigpqc-wrong-domain", **fixture, "artifact": "dataSig", "mutation": "raw-message-signature"}, expected(False, "script", "SCRIPT_ERR_P2MR_SIG")),
        boundary_case("opcode-checkdatasigpqc-underflow", "opcode", "opcode", {"kind": "checkdatasigpqc-underflow"}, expected(False, "script", "SCRIPT_ERR_INVALID_STACK_OPERATION")),
        boundary_case("opcode-checkdatasigaddpqc", "opcode", "opcode", {"kind": "checkdatasigaddpqc-valid", **fixture, "artifact": "dataSigAdd"}, ok),
        boundary_case("opcode-checkdatasigaddpqc-wrong-message", "opcode", "opcode", {"kind": "checkdatasigaddpqc-wrong-message", **fixture, "artifact": "dataSigAdd"}, expected(False, "script", "SCRIPT_ERR_P2MR_SIG")),
        boundary_case("opcode-checkdatasigaddpqc-wrong-pubkey", "opcode", "opcode", {"kind": "checkdatasigaddpqc-wrong-pubkey", **fixture, "artifact": "dataSigAdd"}, expected(False, "script", "SCRIPT_ERR_P2MR_SIG")),
        boundary_case("opcode-checkdatasigaddpqc-underflow", "opcode", "opcode", {"kind": "checkdatasigaddpqc-underflow"}, expected(False, "script", "SCRIPT_ERR_INVALID_STACK_OPERATION")),
        boundary_case("opcode-nonactivated-op-success", "opcode", "opcode", {"kind": "op-success"}, expected(True, "op-success", "SCRIPT_ERR_OK"), expected(False, "policy", "SCRIPT_ERR_DISCOURAGE_OP_SUCCESS")),
        boundary_case("opcode-permanently-disabled", "opcode", "opcode", {"kind": "disabled"}, expected(False, "script", "SCRIPT_ERR_BAD_OPCODE")),
        boundary_case("resource-stack-items-1000", "resource", "resource", {"kind": "stack-items", "value": 1000}, ok),
        boundary_case("resource-stack-items-1001", "resource", "resource", {"kind": "stack-items", "value": 1001}, expected(False, "initial-stack", "SCRIPT_ERR_STACK_SIZE")),
        boundary_case("resource-item-bytes-16384", "resource", "resource", {"kind": "item-bytes", "value": 16384}, ok),
        boundary_case("resource-item-bytes-16385", "resource", "resource", {"kind": "item-bytes", "value": 16385}, expected(False, "initial-stack", "SCRIPT_ERR_PUSH_SIZE")),
        boundary_case("resource-total-bytes-131072", "resource", "resource", {"kind": "total-bytes", "value": 131072}, ok),
        boundary_case("resource-total-bytes-131073", "resource", "resource", {"kind": "total-bytes", "value": 131073}, expected(False, "initial-stack", "SCRIPT_ERR_PUSH_SIZE")),
        boundary_case("resource-validation-weight-one", "resource", "resource", {"kind": "validation-weight", "nonempty_checks": 1, **fixture, "artifact": "transaction-checksigpqc"}, ok),
        boundary_case("resource-validation-weight-multiple", "resource", "resource", {"kind": "validation-weight", "nonempty_checks": 2, **fixture, "artifact": "dataSigAdd"}, ok),
        boundary_case("resource-validation-weight-exceeded", "resource", "resource", {"kind": "validation-weight-exceeded", "nonempty_checks": 2}, expected(False, "validation-weight", "SCRIPT_ERR_P2MR_VALIDATION_WEIGHT")),
        boundary_case("resource-empty-signatures-no-charge", "resource", "resource", {"kind": "empty-signatures", "nonempty_checks": 0}, ok),
        boundary_case("resource-clean-stack", "resource", "resource", {"kind": "clean-stack", "value": 2}, expected(False, "script-complete", "SCRIPT_ERR_CLEANSTACK")),
        boundary_case("resource-false-final-stack", "resource", "resource", {"kind": "false-final", "value": 0}, expected(False, "script-complete", "SCRIPT_ERR_EVAL_FALSE")),
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "limits": {
            "control_path_max_nodes": 128,
            "initial_stack_max_items": 1000,
            "initial_stack_item_max_bytes": 16_384,
            "initial_stack_total_max_bytes": 128 * 1024,
            "validation_weight_per_nonempty_pqc_check": 3_683,
        },
        "cases": cases,
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    write_json(args.output_dir / "p2mr_vectors.json", build_commitment_corpus())
    write_json(
        args.output_dir / "p2mr_cross_profile_vectors.json",
        build_cross_profile_corpus(),
    )
    write_json(
        args.output_dir / "p2mr_script_boundary_vectors.json",
        build_boundary_corpus(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
