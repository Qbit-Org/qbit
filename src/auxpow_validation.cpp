// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>

#include <crypto/common.h>
#include <pow.h>
#include <primitives/block.h>
#include <tinyformat.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

namespace {
static constexpr std::array<unsigned char, 4> MERGED_MINING_HEADER{0xfa, 0xbe, 0x6d, 0x6d};

std::optional<auxpow::ValidationError> Invalid(std::string_view reject_reason, std::string debug_message) { return auxpow::ValidationError{std::string{reject_reason}, std::move(debug_message)}; }

template <typename Iterator>
bool HasRoom(Iterator first, Iterator last, size_t size)
{
    return static_cast<size_t>(std::distance(first, last)) >= size;
}
} // namespace

std::optional<auxpow::ValidationError> CAuxPow::Validate(const uint256& aux_block_hash, const Consensus::Params& consensus, const uint32_t target_bits, const uint16_t expected_chain_id, const bool check_pow, const auxpow::CommitmentValidation commitment_validation) const
{
    if (!coinbase_tx || !coinbase_tx->IsCoinBase()) {
        return Invalid("bad-auxpow-coinbase", "auxpow payload coinbase transaction missing or invalid");
    }
    if (coinbase_branch_index < 0) {
        return Invalid("bad-auxpow-coinbase-index", "auxpow coinbase merkle branch index is negative");
    }
    if (coinbase_branch_index != 0) {
        return Invalid("bad-auxpow-coinbase-index", strprintf("auxpow coinbase merkle branch index=%d expected=0", coinbase_branch_index));
    }
    if (chain_index < 0) {
        return Invalid("bad-auxpow-chain-index", "auxpow chain merkle branch index is negative");
    }
    if (chain_merkle_branch.size() > auxpow::MAX_CHAIN_MERKLE_BRANCH_LENGTH) {
        return Invalid("bad-auxpow-chain-branch-size",
                       strprintf("auxpow chain merkle branch height=%u exceeds limit=%u",
                                 chain_merkle_branch.size(),
                                 auxpow::MAX_CHAIN_MERKLE_BRANCH_LENGTH));
    }
    if (coinbase_merkle_branch.size() >= std::numeric_limits<uint32_t>::digits) {
        return Invalid("bad-auxpow-coinbase-branch-size", "auxpow coinbase merkle branch height overflows index range");
    }
    if ((static_cast<uint32_t>(coinbase_branch_index) >> coinbase_merkle_branch.size()) != 0) return Invalid("bad-auxpow-coinbase-index", "auxpow coinbase merkle branch index exceeds tree width");
    if ((static_cast<uint32_t>(chain_index) >> chain_merkle_branch.size()) != 0) {
        return Invalid("bad-auxpow-chain-index", "auxpow chain merkle branch index exceeds tree width");
    }

    const uint256 coinbase_root = auxpow::CheckMerkleBranch(coinbase_tx->GetHash().ToUint256(), coinbase_merkle_branch, static_cast<uint32_t>(coinbase_branch_index));
    if (coinbase_root != parent_block.hashMerkleRoot) {
        return Invalid("bad-auxpow-coinbase-branch", "auxpow coinbase merkle branch does not match parent block merkle root");
    }

    if (check_pow && !CheckProofOfWork(GetParentBlockHash(), target_bits, consensus)) {
        return Invalid("bad-auxpow-parent-hash", "auxpow parent header does not satisfy the qbit target");
    }

    const uint256 chain_root = auxpow::CheckMerkleBranch(aux_block_hash, chain_merkle_branch, static_cast<uint32_t>(chain_index));
    const auto& script_sig = coinbase_tx->vin[0].scriptSig;
    std::vector<unsigned char> internal_commitment{chain_root.begin(), chain_root.end()};
    std::vector<unsigned char> display_commitment{internal_commitment};
    std::reverse(display_commitment.begin(), display_commitment.end());

    const std::vector<const std::vector<unsigned char>*> commitments = [&] {
        switch (commitment_validation) {
        case auxpow::CommitmentValidation::INTERNAL:
            return std::vector<const std::vector<unsigned char>*>{&internal_commitment};
        case auxpow::CommitmentValidation::DISPLAY:
            return std::vector<const std::vector<unsigned char>*>{&display_commitment};
        case auxpow::CommitmentValidation::EITHER:
            if (internal_commitment == display_commitment) {
                return std::vector<const std::vector<unsigned char>*>{&display_commitment};
            }
            return std::vector<const std::vector<unsigned char>*>{&display_commitment, &internal_commitment};
        }
        assert(false);
        return std::vector<const std::vector<unsigned char>*>{};
    }();

    std::optional<auxpow::ValidationError> commitment_error;
    for (const auto* chain_root_commitment : commitments) {
        const auto root_it = std::search(script_sig.begin(), script_sig.end(), chain_root_commitment->begin(), chain_root_commitment->end());
        if (root_it == script_sig.end()) {
            continue;
        }

        const auto header_it = std::search(script_sig.begin(), script_sig.end(), MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end());
        if (header_it != script_sig.end()) {
            const auto second_header_it = std::search(std::next(header_it), script_sig.end(), MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end());
            if (second_header_it != script_sig.end()) {
                commitment_error = Invalid("bad-auxpow-commitment", "auxpow parent coinbase contains multiple merged mining headers");
                continue;
            }
            if (std::next(header_it, MERGED_MINING_HEADER.size()) != root_it) {
                commitment_error = Invalid("bad-auxpow-commitment", "auxpow merged mining header must be immediately followed by the committed chain merkle root");
                continue;
            }
        } else if (static_cast<size_t>(std::distance(script_sig.begin(), root_it)) > auxpow::LEGACY_COMMITMENT_START_LIMIT) {
            commitment_error = Invalid("bad-auxpow-commitment", "auxpow chain merkle root appears too deep in the parent coinbase scriptSig");
            continue;
        }

        const auto footer_it = std::next(root_it, chain_root_commitment->size());
        if (!HasRoom(footer_it, script_sig.end(), sizeof(uint32_t) * 2)) {
            commitment_error = Invalid("bad-auxpow-commitment", "auxpow commitment is missing merkle size or nonce footer");
            continue;
        }

        const uint32_t merkle_size = ReadLE32(&*footer_it);
        const uint32_t nonce = ReadLE32(&*std::next(footer_it, sizeof(uint32_t)));
        const uint32_t expected_size = 1U << chain_merkle_branch.size();
        if (merkle_size != expected_size) {
            commitment_error = Invalid("bad-auxpow-merkle-size", strprintf("auxpow merkle size=%u expected=%u", merkle_size, expected_size));
            continue;
        }

        const int32_t expected_index = auxpow::GetExpectedIndex(nonce, expected_chain_id, chain_merkle_branch.size());
        if (chain_index != expected_index) {
            commitment_error = Invalid("bad-auxpow-chain-index",
                                       strprintf("auxpow chain index=%d expected=%d for chainid=%u nonce=%u",
                                                 chain_index,
                                                 expected_index,
                                                 static_cast<unsigned int>(expected_chain_id),
                                                 nonce));
            continue;
        }

        return std::nullopt;
    }

    if (commitment_error) {
        return commitment_error;
    }
    return Invalid("bad-auxpow-commitment", "auxpow chain merkle root missing from parent coinbase scriptSig");
}

namespace auxpow {
std::optional<ValidationError> Validate(const CBlockHeader& block, const Consensus::Params& consensus, const bool check_pow, const CommitmentValidation commitment_validation)
{
    if (!block.SignalsAuxpow()) {
        if (block.HasAuxpow()) {
            return Invalid("bad-auxpow-unexpected-payload", "permissionless block includes an unexpected auxpow payload");
        }
        if (check_pow && !CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
            return Invalid("high-hash", "proof of work failed");
        }
        return std::nullopt;
    }

    const uint16_t expected_chain_id = static_cast<uint16_t>(consensus.nAuxpowChainId);
    if (block.GetChainId() != expected_chain_id) {
        return Invalid("bad-auxpow-chainid",
                       strprintf("rejected auxpow chainid=%u expected=%u",
                                 static_cast<unsigned int>(block.GetChainId()),
                                 static_cast<unsigned int>(expected_chain_id)));
    }

    if (!block.HasAuxpow()) {
        return Invalid("bad-auxpow-missing-payload", "auxpow version is missing the auxpow payload");
    }

    return block.auxpow->Validate(block.GetHash(), consensus, block.nBits, expected_chain_id, check_pow, commitment_validation);
}
} // namespace auxpow
