// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_P2MR_SIZING_H
#define QBIT_SCRIPT_P2MR_SIZING_H

#include <crypto/pqc.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>

#include <cstddef>

static constexpr size_t P2MR_V1_WITNESS_STACK_ITEMS{3}; // signature, leaf script, control block
static constexpr size_t P2MR_V1_MAX_SIGNATURE_ITEM_SIZE{PQC_SIG_SIZE + 1};
static constexpr size_t P2MR_V1_PK_LEAF_SCRIPT_SIZE{1 + CPQCPubKey::SIZE + 1};
static constexpr size_t P2MR_V1_MAX_STANDARD_SIGNATURES{
    MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES / P2MR_V1_MAX_SIGNATURE_ITEM_SIZE};

static_assert(P2MR_V1_MAX_SIGNATURE_ITEM_SIZE <= MAX_P2MR_V1_STACK_ITEM_SIZE);
static_assert(P2MR_VALIDATION_WEIGHT_PER_SIGOP_V2 == PQC_SIG_SIZE + GetSizeOfCompactSize(PQC_SIG_SIZE));
static_assert(P2MR_VALIDATION_WEIGHT_PER_SIGOP_LEGACY > P2MR_VALIDATION_WEIGHT_PER_SIGOP_V2);
static_assert(P2MR_V1_MAX_STANDARD_SIGNATURES == 35);

constexpr size_t GetP2MRControlBlockSize(size_t merkle_depth)
{
    return P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE * merkle_depth;
}

constexpr size_t GetP2MRV1SpendSize(size_t leaf_script_size, size_t control_block_size)
{
    return 32 + 4 + 1 + 4 +
           GetSizeOfCompactSize(P2MR_V1_WITNESS_STACK_ITEMS) +
           GetSizeOfCompactSize(P2MR_V1_MAX_SIGNATURE_ITEM_SIZE) + P2MR_V1_MAX_SIGNATURE_ITEM_SIZE +
           GetSizeOfCompactSize(leaf_script_size) + leaf_script_size +
           GetSizeOfCompactSize(control_block_size) + control_block_size;
}

static constexpr size_t P2MR_V1_SINGLE_KEY_SPEND_SIZE{
    GetP2MRV1SpendSize(P2MR_V1_PK_LEAF_SCRIPT_SIZE, GetP2MRControlBlockSize(/*merkle_depth=*/0))};

#endif // QBIT_SCRIPT_P2MR_SIZING_H
