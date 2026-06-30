// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_COMMON_P2MR_DATA_SIGNATURE_H
#define QBIT_COMMON_P2MR_DATA_SIGNATURE_H

#include <addresstype.h>
#include <crypto/pqc.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace common {

static constexpr const char* P2MR_DATA_SIGNATURE_PROOF_MODE{"p2mr-pubkey"};
static constexpr const char* P2MR_DATA_SIGNATURE_DOMAIN{"QbitDataSigPQC"};
static constexpr const char* P2MR_DATA_SIGNATURE_ALGORITHM{"SLH-DSA-SHA2-128s-bounded30"};

struct P2MRDataSignatureProof {
    WitnessV2P2MR output;
    uint256 message_hash;
    uint256 datasig_hash;
    CPQCPubKey pubkey;
    std::vector<unsigned char> signature;
    CScript leaf_script;
    std::vector<unsigned char> control_block;
    uint8_t leaf_version;
};

struct P2MRDataSignatureVerification {
    bool valid{false};
    std::string error;
    uint256 datasig_hash;
    uint256 p2mr_merkle_root;
};

P2MRDataSignatureVerification VerifyP2MRDataSignatureProof(const P2MRDataSignatureProof& proof);

} // namespace common

#endif // QBIT_COMMON_P2MR_DATA_SIGNATURE_H
