// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_AUXPOW_H
#define QBIT_AUXPOW_H

#include <consensus/params.h>
#include <primitives/pureheader.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

class CBlockHeader;

namespace auxpow {
static constexpr size_t MAX_CHAIN_MERKLE_BRANCH_LENGTH{30};
static constexpr size_t LEGACY_COMMITMENT_START_LIMIT{20};

struct ValidationError {
    std::string reject_reason;
    std::string debug_message;
};

enum class CommitmentValidation {
    EITHER,
    INTERNAL,
    DISPLAY,
};

inline CommitmentValidation CommitmentValidationForHeight(const Consensus::Params& consensus, const int height)
{
    return consensus.AuxpowDisplayCommitmentActiveAtHeight(height) ? CommitmentValidation::DISPLAY : CommitmentValidation::INTERNAL;
}

uint256 CheckMerkleBranch(const uint256& leaf, std::span<const uint256> branch, uint32_t index);
int32_t GetExpectedIndex(uint32_t nonce, int32_t chain_id, size_t merkle_height);
std::optional<ValidationError> Validate(const CBlockHeader& block, const Consensus::Params& consensus, bool check_pow = true, CommitmentValidation commitment_validation = CommitmentValidation::EITHER);
} // namespace auxpow

class CAuxPow
{
public:
    CTransactionRef coinbase_tx;
    std::vector<uint256> coinbase_merkle_branch;
    int32_t coinbase_branch_index{0};
    std::vector<uint256> chain_merkle_branch;
    int32_t chain_index{0};
    // The parent header is intentionally pure header data, not CBlockHeader.
    // Only CBlockHeader serializes a nested CAuxPow payload, so recursive
    // AuxPoW is unrepresentable here; parent nVersion bits are parent-chain
    // data, while qbit consensus is enforced through the aux block chain id,
    // the parent hash meeting the qbit target, and the coinbase commitment.
    CPureBlockHeader parent_block;

    CAuxPow() = default;

    template <typename Stream>
    CAuxPow(deserialize_type, Stream& s)
    {
        Unserialize(s);
    }

    SERIALIZE_METHODS(CAuxPow, obj)
    {
        READWRITE(TX_NO_WITNESS(obj.coinbase_tx),
                  obj.coinbase_merkle_branch,
                  obj.coinbase_branch_index,
                  obj.chain_merkle_branch,
                  obj.chain_index,
                  obj.parent_block);
    }

    uint256 GetParentBlockHash() const
    {
        return parent_block.GetHash();
    }

    std::optional<auxpow::ValidationError> Validate(const uint256& aux_block_hash, const Consensus::Params& consensus, uint32_t target_bits, uint16_t expected_chain_id, bool check_pow, auxpow::CommitmentValidation commitment_validation) const;
};

#endif // QBIT_AUXPOW_H
