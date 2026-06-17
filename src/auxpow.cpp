// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>

#include <hash.h>

#include <cstdint>
#include <limits>

namespace auxpow {
namespace {
constexpr uint64_t LCG_MULTIPLIER{1103515245ULL};
constexpr uint64_t LCG_INCREMENT{12345ULL};
constexpr uint64_t UINT32_MASK{std::numeric_limits<uint32_t>::max()};

uint32_t AdvanceSlotLcg(const uint32_t value) noexcept
{
    return static_cast<uint32_t>((static_cast<uint64_t>(value) * LCG_MULTIPLIER + LCG_INCREMENT) & UINT32_MASK);
}
} // namespace

uint256 CheckMerkleBranch(const uint256& leaf, std::span<const uint256> branch, uint32_t index)
{
    uint256 hash{leaf};
    for (const uint256& sibling : branch) {
        hash = (index & 1) != 0 ?
            Hash(sibling, hash) :
            Hash(hash, sibling);
        index >>= 1;
    }
    return hash;
}

int32_t GetExpectedIndex(const uint32_t nonce, const int32_t chain_id, const size_t merkle_height)
{
    uint32_t rand{AdvanceSlotLcg(nonce)};
    rand = static_cast<uint32_t>((static_cast<uint64_t>(rand) + static_cast<uint32_t>(chain_id)) & UINT32_MASK);
    rand = AdvanceSlotLcg(rand);

    if (merkle_height >= std::numeric_limits<uint32_t>::digits) return static_cast<int32_t>(rand);
    return static_cast<int32_t>(rand & ((uint32_t{1} << merkle_height) - 1));
}
} // namespace auxpow
