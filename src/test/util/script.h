// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_TEST_UTIL_SCRIPT_H
#define QBIT_TEST_UTIL_SCRIPT_H

#include <crypto/sha256.h>
#include <script/interpreter.h>
#include <script/script.h>

static const std::vector<uint8_t> WITNESS_STACK_ELEM_OP_TRUE{uint8_t{OP_TRUE}};
static const CScript P2WSH_OP_TRUE{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           CSHA256().Write(WITNESS_STACK_ELEM_OP_TRUE.data(), WITNESS_STACK_ELEM_OP_TRUE.size()).Finalize(hash.begin());
           return hash;
       }())};

static const std::vector<uint8_t> EMPTY{};
static const CScript P2WSH_EMPTY{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           CSHA256().Write(EMPTY.data(), EMPTY.size()).Finalize(hash.begin());
           return hash;
       }())};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TRUE_STACK{{static_cast<uint8_t>(OP_TRUE)}, {}};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TWO_STACK{{static_cast<uint8_t>(OP_2)}, {}};

inline const std::vector<uint8_t>& P2MROpTrueControl()
{
    static const std::vector<uint8_t> control{static_cast<uint8_t>(P2MR_LEAF_VERSION_V1 | 1)};
    return control;
}

inline const CScript& P2MROpTrueScript()
{
    static const CScript script{
        CScript{}
        << OP_2
        << ToByteVector([] {
               const uint256 leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, WITNESS_STACK_ELEM_OP_TRUE)};
               return ComputeP2MRMerkleRoot(P2MROpTrueControl(), leaf_hash);
           }())};
    return script;
}

inline const std::vector<std::vector<uint8_t>>& P2MROpTrueStack()
{
    static const std::vector<std::vector<uint8_t>> stack{
        WITNESS_STACK_ELEM_OP_TRUE,
        P2MROpTrueControl(),
    };
    return stack;
}

/** Flags that are not forbidden by an assert in script validation */
bool IsValidFlagCombination(unsigned flags);

#endif // QBIT_TEST_UTIL_SCRIPT_H
