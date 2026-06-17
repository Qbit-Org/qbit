// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_POW_H
#define QBIT_POW_H

#include <consensus/params.h>

#include <cstdint>
#include <optional>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

struct ASERTHeaderState {
    int64_t nHeight{0};
    int64_t nTime{0};
    uint64_t nAuxPow{0};
};

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
int64_t GetCadenceTargetSpacing(const Consensus::Params& params, bool auxpow) noexcept;
arith_uint256 CalculateASERT(const arith_uint256& refTarget,
                             int64_t nPowTargetSpacing,
                             int64_t nTimeDiff,
                             int64_t nHeightDiff,
                             const arith_uint256& powLimit,
                             int64_t nHalfLife) noexcept;
uint32_t GetNextASERTWorkRequired(const std::optional<ASERTHeaderState>& pindexPrev,
                                  bool next_block_is_auxpow,
                                  const Consensus::Params&) noexcept;

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * On non-cadence ASERT networks this checks the exact transition when callers
 * provide adjacent header times. On cadence-active ASERT networks it only
 * validates compact targets; exact dual-lane ASERT validation requires
 * same-lane history that this adjacent-header interface cannot represent.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params,
                                   int64_t height,
                                   uint32_t old_nbits,
                                   uint32_t new_nbits,
                                   std::optional<int64_t> old_block_time = std::nullopt,
                                   std::optional<int64_t> new_block_time = std::nullopt);

#endif // QBIT_POW_H
