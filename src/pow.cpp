// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/common.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

#include <array>
#include <cstdlib>
#include <limits>

namespace {
constexpr size_t WIDE_TARGET_WIDTH{9};
constexpr uint64_t WIDE_TARGET_BITS{WIDE_TARGET_WIDTH * 32};
using WideTarget = std::array<uint32_t, WIDE_TARGET_WIDTH>;

arith_uint256 CalculateRetargetedTarget(const arith_uint256& old_target, int64_t actual_timespan, int64_t target_timespan, const arith_uint256& pow_limit)
{
    Assume(actual_timespan >= 0);
    Assume(target_timespan > 0);

    const arith_uint256 actual{static_cast<uint64_t>(actual_timespan)};
    const arith_uint256 target{static_cast<uint64_t>(target_timespan)};
    if (actual == 0) return 0;
    const arith_uint256 quotient{old_target / target};
    const arith_uint256 remainder{old_target - (quotient * target)};

    // If the quotient term alone reaches the cap, we can clamp immediately.
    if (quotient > pow_limit / actual) return pow_limit;
    arith_uint256 retarget{quotient * actual};

    // floor((q * T + r) * A / T) = q * A + floor(r * A / T)
    const arith_uint256 remainder_term{(remainder * actual) / target};
    if (retarget > pow_limit - remainder_term) return pow_limit;
    retarget += remainder_term;
    return retarget;
}

bool WideTargetAnySet(const WideTarget& value) { return value != WideTarget{}; }

WideTarget ShiftRightWideTarget(const WideTarget& value, uint64_t shift)
{
    WideTarget result{};
    if (shift >= WIDE_TARGET_BITS) return result;

    const size_t k = static_cast<size_t>(shift / 32);
    const uint32_t r = static_cast<uint32_t>(shift % 32);
    for (size_t i = 0; i < WIDE_TARGET_WIDTH; ++i) {
        uint64_t n{0};
        if (i + k < WIDE_TARGET_WIDTH) {
            n = static_cast<uint64_t>(value[i + k]) >> r;
            if (r != 0 && i + k + 1 < WIDE_TARGET_WIDTH) {
                n |= static_cast<uint64_t>(value[i + k + 1]) << (32 - r);
            }
        }
        result[i] = static_cast<uint32_t>(n);
    }
    return result;
}

WideTarget ShiftLeftWideTarget(const WideTarget& value, uint64_t shift)
{
    WideTarget result{};
    if (shift >= WIDE_TARGET_BITS) return result;

    const size_t k = static_cast<size_t>(shift / 32);
    const uint32_t r = static_cast<uint32_t>(shift % 32);
    for (size_t i = 0; i < WIDE_TARGET_WIDTH; ++i) {
        uint64_t n{0};
        if (i >= k) {
            n = static_cast<uint64_t>(value[i - k]) << r;
            if (r != 0 && i > k) {
                n |= static_cast<uint64_t>(value[i - k - 1]) >> (32 - r);
            }
        }
        result[i] = static_cast<uint32_t>(n);
    }
    return result;
}

bool LeftShiftWideTargetOverflows(const WideTarget& original, const WideTarget& shifted, uint64_t shift)
{
    if (shift >= WIDE_TARGET_BITS) return WideTargetAnySet(original);
    return ShiftRightWideTarget(shifted, shift) != original;
}

WideTarget MultiplyToWideTarget(const arith_uint256& value, uint32_t factor)
{
    WideTarget result{};
    const uint256 compact = ArithToUint256(value);
    uint64_t carry{0};
    for (size_t i = 0; i < 8; ++i) {
        const uint64_t n = carry + static_cast<uint64_t>(ReadLE32(compact.begin() + i * 4)) * factor;
        result[i] = static_cast<uint32_t>(n);
        carry = n >> 32;
    }
    result[8] = static_cast<uint32_t>(carry);
    return result;
}

arith_uint256 WideTargetToArith(const WideTarget& value)
{
    uint256 compact{};
    for (size_t i = 0; i < 8; ++i) {
        WriteLE32(compact.begin() + i * 4, value[i]);
    }
    return UintToArith256(compact);
}

bool IsCadenceActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params) noexcept
{
    const int next_height = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    return params.CadenceActiveAtHeight(next_height);
}

unsigned int CalculateNextWorkRequiredLegacy(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4) {
        nActualTimespan = params.nPowTargetTimespan / 4;
    }
    if (nActualTimespan > params.nPowTargetTimespan * 4) {
        nActualTimespan = params.nPowTargetTimespan * 4;
    }

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        const int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew = CalculateRetargetedTarget(bnNew, nActualTimespan, params.nPowTargetTimespan, bnPowLimit);
    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredLegacy(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    const bool cadence_active = IsCadenceActiveAfter(pindexLast, params);

    // Only change once per difficulty adjustment interval.
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            const bool next_block_is_auxpow = cadence_active &&
                                              (pblock != nullptr ? IsAuxpowVersion(pblock->nVersion)
                                                                 : IsAuxpowVersion(pindexLast->nVersion));
            const int64_t target_spacing = cadence_active ? GetCadenceTargetSpacing(params, next_block_is_auxpow)
                                                          : params.nPowTargetSpacing;
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2x its active spacing,
            // then it MUST be a min-difficulty block.
            if (pblock != nullptr &&
                pblock->GetBlockTime() > pindexLast->GetBlockTime() + target_spacing * 2) {
                return nProofOfWorkLimit;
            }
            // Return the last non-special-min-difficulty-rules-block.
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit) {
                pindex = pindex->pprev;
            }
            return pindex->nBits;
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks.
    const int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequiredLegacy(pindexLast, pindexFirst->GetBlockTime(), params);
}

bool IsAuxpowBlock(const CBlockIndex* pindex) noexcept
{
    return pindex != nullptr && IsAuxpowVersion(pindex->nVersion);
}

bool IsAuxpowBlock(const CBlockHeader* pblock) noexcept
{
    return pblock != nullptr && IsAuxpowVersion(pblock->nVersion);
}

bool GetNextBlockIsAuxpow(const CBlockIndex* pindexLast, const CBlockHeader* pblock) noexcept
{
    if (pblock != nullptr) return IsAuxpowBlock(pblock);

    // Callers normally provide the incoming header. Fall back to the parent
    // type for legacy/fuzz call sites that only need a deterministic answer.
    return IsAuxpowBlock(pindexLast);
}

uint32_t GetASERTAnchorBits(const Consensus::Params& params, const bool auxpow) noexcept
{
    const auto& anchor = params.asertAnchorParams;
    if (auxpow && anchor.nBitsAuxPow != 0) return anchor.nBitsAuxPow;
    if (!auxpow && anchor.nBitsLegacy != 0) return anchor.nBitsLegacy;
    return anchor.nBits;
}

const CBlockIndex* GetPreviousSameTypeBlock(const CBlockIndex* pindexLast,
                                            const bool next_block_is_auxpow,
                                            const Consensus::Params& params) noexcept
{
    const auto& anchor = params.asertAnchorParams;
    const CBlockIndex* pindexPrev = pindexLast;
    while (pindexPrev != nullptr && IsAuxpowBlock(pindexPrev) != next_block_is_auxpow) {
        if (pindexPrev->nHeight <= anchor.nHeight) return nullptr;
        pindexPrev = pindexPrev->pprev;
    }
    return pindexPrev;
}

ASERTHeaderState GetASERTHeaderState(const CBlockIndex& pindex) noexcept
{
    return ASERTHeaderState{pindex.nHeight, pindex.GetBlockTime(), pindex.nAuxPow};
}

int64_t GetASERTHeightDiff(const ASERTHeaderState& pindexPrev,
                           const bool auxpow,
                           const Consensus::Params& params) noexcept
{
    const auto& anchor = params.asertAnchorParams;
    assert(pindexPrev.nHeight >= anchor.nHeight);

    // nAuxPow is cumulative from genesis, so subtract the anchor's cumulative
    // count before converting it into same-track height since the anchor.
    assert(pindexPrev.nAuxPow >= anchor.nAuxPow);
    const uint64_t nAuxPowDiff = pindexPrev.nAuxPow - anchor.nAuxPow;
    assert(nAuxPowDiff <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
    const int64_t nAuxPowDiffSigned = static_cast<int64_t>(nAuxPowDiff);

    if (auxpow) return nAuxPowDiffSigned;
    return pindexPrev.nHeight - anchor.nHeight - nAuxPowDiffSigned;
}

uint32_t GetNextASERTWorkRequired(const CBlockIndex* pindexPrev,
                                  const Consensus::Params& params) noexcept
{
    const auto& anchor = params.asertAnchorParams;
    assert(anchor.nBits > 0);
    assert(params.nASERTHalfLife > 0);

    if (pindexPrev->nHeight < anchor.nHeight) {
        return anchor.nBits;
    }

    const arith_uint256 refTarget = arith_uint256().SetCompact(anchor.nBits);
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchor.nBlockTime;
    const int64_t nHeightDiff = pindexPrev->nHeight - anchor.nHeight;

    return CalculateASERT(refTarget,
                          params.nPowTargetSpacing,
                          nTimeDiff,
                          nHeightDiff,
                          UintToArith256(params.powLimit),
                          params.nASERTHalfLife)
        .GetCompact();
}

uint32_t GetNextASERTWorkRequired(const CBlockIndex* pindexPrev,
                                  const bool next_block_is_auxpow,
                                  const Consensus::Params& params) noexcept
{
    if (pindexPrev == nullptr) {
        return ::GetNextASERTWorkRequired(std::nullopt, next_block_is_auxpow, params);
    }
    return ::GetNextASERTWorkRequired(GetASERTHeaderState(*pindexPrev), next_block_is_auxpow, params);
}
} // namespace

uint32_t GetNextASERTWorkRequired(const std::optional<ASERTHeaderState>& pindexPrev,
                                  const bool next_block_is_auxpow,
                                  const Consensus::Params& params) noexcept
{
    const auto& anchor = params.asertAnchorParams;
    const uint32_t anchor_bits = GetASERTAnchorBits(params, next_block_is_auxpow);
    const int64_t target_spacing = GetCadenceTargetSpacing(params, next_block_is_auxpow);

    assert(anchor_bits > 0);
    assert(target_spacing > 0);
    assert(params.nASERTHalfLife > 0);

    if (!pindexPrev || pindexPrev->nHeight < anchor.nHeight) {
        return anchor_bits;
    }

    const arith_uint256 refTarget = arith_uint256().SetCompact(anchor_bits);
    const int64_t nTimeDiff = pindexPrev->nTime - anchor.nBlockTime;
    const int64_t nHeightDiff = GetASERTHeightDiff(*pindexPrev, next_block_is_auxpow, params);

    return CalculateASERT(refTarget,
                          target_spacing,
                          nTimeDiff,
                          nHeightDiff,
                          UintToArith256(params.powLimit),
                          params.nASERTHalfLife)
        .GetCompact();
}

int64_t GetCadenceTargetSpacing(const Consensus::Params& params, const bool auxpow) noexcept
{
    if (auxpow && params.nPowTargetSpacingAuxPow > 0) return params.nPowTargetSpacingAuxPow;
    if (!auxpow && params.nPowTargetSpacingLegacy > 0) return params.nPowTargetSpacingLegacy;
    return params.nPowTargetSpacing;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    const bool cadence_active = IsCadenceActiveAfter(pindexLast, params);
    const bool next_block_is_auxpow = cadence_active && GetNextBlockIsAuxpow(pindexLast, pblock);
    const int64_t target_spacing = cadence_active ? GetCadenceTargetSpacing(params, next_block_is_auxpow)
                                                  : params.nPowTargetSpacing;
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    if (params.fPowUseASERT &&
        pblock != nullptr &&
        params.fPowAllowMinDifficultyBlocks &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + target_spacing * 2) {
        return nProofOfWorkLimit;
    }

    if (!params.fPowUseASERT) {
        return GetNextWorkRequiredLegacy(pindexLast, pblock, params);
    }

    if (!cadence_active) {
        return GetNextASERTWorkRequired(pindexLast, params);
    }

    const CBlockIndex* pindexPrevSameType = GetPreviousSameTypeBlock(pindexLast, next_block_is_auxpow, params);
    return GetNextASERTWorkRequired(pindexPrevSameType, next_block_is_auxpow, params);
}

arith_uint256 CalculateASERT(const arith_uint256& refTarget,
                             int64_t nPowTargetSpacing,
                             int64_t nTimeDiff,
                             int64_t nHeightDiff,
                             const arith_uint256& powLimit,
                             int64_t nHalfLife) noexcept
{
    assert(refTarget > 0 && refTarget <= powLimit);
    assert(nHeightDiff >= 0);
    assert(nHalfLife > 0);
    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));

    static_assert(int64_t(-1) >> 1 == int64_t(-1), "ASERT algorithm needs arithmetic shift support");

    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * nHeightDiff) * 65536) / nHalfLife;
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);
    const WideTarget initial_target = MultiplyToWideTarget(refTarget, factor);
    WideTarget shifted_target = initial_target;

    shifts -= 16;
    bool overflow{false};
    if (shifts <= 0) {
        shifted_target = ShiftRightWideTarget(shifted_target, static_cast<uint64_t>(-shifts));
    } else {
        shifted_target = ShiftLeftWideTarget(shifted_target, static_cast<uint64_t>(shifts));
        overflow = LeftShiftWideTargetOverflows(initial_target, shifted_target, static_cast<uint64_t>(shifts));
    }

    arith_uint256 nextTarget = overflow || shifted_target[8] != 0 ? powLimit : WideTargetToArith(shifted_target);
    if (nextTarget == 0) {
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }
    return nextTarget;
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params,
                                   int64_t height,
                                   uint32_t old_nbits,
                                   uint32_t new_nbits,
                                   std::optional<int64_t> old_block_time,
                                   std::optional<int64_t> new_block_time)
{
    if (params.fPowNoRetargeting) return true;

    if (params.fPowUseASERT) {
        const bool cadence_active = params.CadenceActiveAtHeight(static_cast<int>(height));
        const auto old_target = DeriveTarget(old_nbits, params.powLimit);
        const auto new_target = DeriveTarget(new_nbits, params.powLimit);
        if (!old_target || !new_target) return false;

        if (!cadence_active && old_block_time && new_block_time && height > 0) {
            const int64_t prev_height = height - 1;
            const uint32_t pow_limit_nbits = UintToArith256(params.powLimit).GetCompact();

            if (params.fPowAllowMinDifficultyBlocks &&
                *new_block_time > *old_block_time + params.nPowTargetSpacing * 2) {
                return new_nbits == pow_limit_nbits;
            }

            const auto& anchor = params.asertAnchorParams;
            uint32_t expected_nbits{anchor.nBits};
            if (prev_height >= anchor.nHeight) {
                const arith_uint256 ref_target = arith_uint256().SetCompact(anchor.nBits);
                const int64_t n_time_diff = *old_block_time - anchor.nBlockTime;
                const int64_t n_height_diff = prev_height - anchor.nHeight;
                expected_nbits = CalculateASERT(ref_target,
                                                params.nPowTargetSpacing,
                                                n_time_diff,
                                                n_height_diff,
                                                UintToArith256(params.powLimit),
                                                params.nASERTHalfLife)
                                     .GetCompact();
            }
            return new_nbits == expected_nbits;
        }

        if (cadence_active) {
            // Cadence ASERT is lane-local and cannot be validated from this
            // adjacent-header interface. Callers with continuous header context
            // must validate the exact same-lane transition themselves.
            return true;
        }

        const uint32_t pow_limit_nbits = UintToArith256(params.powLimit).GetCompact();
        if (params.fPowAllowMinDifficultyBlocks && old_nbits == pow_limit_nbits) {
            // Testnet-style min-difficulty recovery can legitimately jump
            // from powLimit back to the ASERT track in one step.
            return true;
        }

        // Do not allow more than 2x hardening in a single header step.
        return *new_target >= (*old_target >> 1);
    }
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target = CalculateRetargetedTarget(largest_difficulty_target, largest_timespan, params.nPowTargetTimespan, pow_limit);

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target = CalculateRetargetedTarget(smallest_difficulty_target, smallest_timespan, params.nPowTargetTimespan, pow_limit);

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
