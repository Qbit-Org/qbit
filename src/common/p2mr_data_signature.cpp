// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/p2mr_data_signature.h>

#include <script/interpreter.h>
#include <script/p2mr.h>

#include <optional>
#include <span>

namespace common {

P2MRDataSignatureVerification VerifyP2MRDataSignatureProof(const P2MRDataSignatureProof& proof)
{
    P2MRDataSignatureVerification result;

    if (!proof.pubkey.IsValid()) {
        result.error = "pubkey is invalid";
        return result;
    }

    const std::optional<CPQCPubKey> leaf_pubkey{p2mr::MatchPK(proof.leaf_script)};
    if (!leaf_pubkey || *leaf_pubkey != proof.pubkey) {
        result.error = "leaf_script is not a single-key P2MR pubkey leaf for pubkey";
        return result;
    }

    if (proof.leaf_version != P2MR_LEAF_VERSION_V1) {
        result.error = "unsupported P2MR leaf version";
        return result;
    }

    if (proof.control_block.size() < P2MR_CONTROL_BASE_SIZE || proof.control_block.size() > P2MR_CONTROL_MAX_SIZE ||
        ((proof.control_block.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
        result.error = "Invalid P2MR control block size";
        return result;
    }

    if ((proof.control_block.front() & 1) == 0) {
        result.error = "P2MR control byte bit 0 must be set";
        return result;
    }

    if ((proof.control_block.front() & TAPROOT_LEAF_MASK) != proof.leaf_version) {
        result.error = "leaf_version does not match control_block";
        return result;
    }

    const std::vector<unsigned char> leaf_script_bytes{proof.leaf_script.begin(), proof.leaf_script.end()};
    const uint256 leaf_hash{ComputeP2MRLeafHash(proof.leaf_version, leaf_script_bytes)};
    const uint256 merkle_root{ComputeP2MRMerkleRoot(proof.control_block, leaf_hash)};
    result.p2mr_merkle_root = merkle_root;
    if (merkle_root != proof.output.GetMerkleRoot()) {
        result.error = "leaf_script/control_block do not match address";
        return result;
    }

    const uint256 datasig_hash{ComputeQbitDataSigPQCHash(std::span<const unsigned char>{proof.message_hash.begin(), proof.message_hash.end()})};
    result.datasig_hash = datasig_hash;
    if (datasig_hash != proof.datasig_hash) {
        result.error = "datasig_hash does not match message_hash";
        return result;
    }

    if (!proof.pubkey.Verify(datasig_hash, proof.signature)) {
        result.error = "signature does not verify";
        return result;
    }

    result.valid = true;
    return result;
}

} // namespace common
