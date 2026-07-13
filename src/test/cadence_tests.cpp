// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <deque>
#include <limits>
#include <numeric>

BOOST_FIXTURE_TEST_SUITE(cadence_tests, BasicTestingSetup)

namespace {
Consensus::Params GetConsensusParams(const ArgsManager& args, const ChainType chain = ChainType::MAIN)
{
    return CreateChainParams(args, chain)->GetConsensus();
}

uint32_t LegacyAnchorBits(const Consensus::Params& consensus)
{
    return consensus.asertAnchorParams.nBitsLegacy != 0 ? consensus.asertAnchorParams.nBitsLegacy
                                                        : consensus.asertAnchorParams.nBits;
}

uint32_t AuxPowAnchorBits(const Consensus::Params& consensus)
{
    return consensus.asertAnchorParams.nBitsAuxPow != 0 ? consensus.asertAnchorParams.nBitsAuxPow
                                                        : consensus.asertAnchorParams.nBits;
}

int64_t LegacyTargetSpacing(const Consensus::Params& consensus)
{
    return consensus.nPowTargetSpacingLegacy > 0 ? consensus.nPowTargetSpacingLegacy
                                                 : consensus.nPowTargetSpacing;
}

int64_t AuxPowTargetSpacing(const Consensus::Params& consensus)
{
    return consensus.nPowTargetSpacingAuxPow > 0 ? consensus.nPowTargetSpacingAuxPow
                                                 : consensus.nPowTargetSpacing;
}

uint32_t PowLimitBits(const Consensus::Params& consensus)
{
    return UintToArith256(consensus.powLimit).GetCompact();
}

uint32_t ExpectedSingleTrackBits(const Consensus::Params& consensus, const CBlockIndex& prev)
{
    const arith_uint256 ref_target = arith_uint256().SetCompact(consensus.asertAnchorParams.nBits);
    return CalculateASERT(ref_target,
                          consensus.nPowTargetSpacing,
                          prev.GetBlockTime() - consensus.asertAnchorParams.nBlockTime,
                          prev.nHeight - consensus.asertAnchorParams.nHeight,
                          UintToArith256(consensus.powLimit),
                          consensus.nASERTHalfLife)
        .GetCompact();
}

int32_t PermissionlessVersion()
{
    return MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
}

int32_t MergedVersion(const Consensus::Params& consensus)
{
    return MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
}

CBlockIndex& AppendBlock(std::deque<CBlockIndex>& chain, const int32_t version, const uint32_t time, const uint32_t bits)
{
    chain.emplace_back();
    CBlockIndex& index = chain.back();
    index.nVersion = version;
    index.nTime = time;
    index.nBits = bits;

    if (chain.size() > 1) {
        index.pprev = &chain[chain.size() - 2];
        index.nHeight = index.pprev->nHeight + 1;
        index.nAuxPow = index.pprev->nAuxPow;
        index.BuildSkip();
    }
    index.BuildCadenceLaneLinks();

    if (IsAuxpowVersion(version)) {
        ++index.nAuxPow;
    }

    return index;
}

CBlockIndex& AppendChild(std::deque<CBlockIndex>& storage,
                         CBlockIndex* parent,
                         const int32_t version,
                         const uint32_t time,
                         const uint32_t bits)
{
    storage.emplace_back();
    CBlockIndex& index = storage.back();
    index.pprev = parent;
    index.nHeight = parent == nullptr ? 0 : parent->nHeight + 1;
    index.nVersion = version;
    index.nTime = time;
    index.nBits = bits;
    index.nAuxPow = (parent == nullptr ? 0 : parent->nAuxPow) + (IsAuxpowVersion(version) ? 1 : 0);
    index.BuildSkip();
    index.BuildCadenceLaneLinks();
    return index;
}

const CBlockIndex* LinearPreviousBlockForLane(const CBlockIndex* pindex,
                                              const bool auxpow,
                                              const int anchor_height)
{
    while (pindex != nullptr && pindex->SignalsAuxpow() != auxpow) {
        if (pindex->nHeight <= anchor_height) return nullptr;
        pindex = pindex->pprev;
    }
    return pindex;
}

CBlockHeader MakeNextHeader(const int32_t version, const uint32_t time)
{
    CBlockHeader header{};
    header.nVersion = version;
    header.nTime = time;
    return header;
}

uint32_t ExpectedCadenceBits(const Consensus::Params& consensus, const CBlockIndex& prev_same_type, const bool auxpow)
{
    const arith_uint256 ref_target = arith_uint256().SetCompact(auxpow ? AuxPowAnchorBits(consensus) : LegacyAnchorBits(consensus));
    const int64_t target_spacing = auxpow ? AuxPowTargetSpacing(consensus) : LegacyTargetSpacing(consensus);
    const auto& anchor = consensus.asertAnchorParams;
    BOOST_REQUIRE(prev_same_type.nAuxPow >= anchor.nAuxPow);
    const uint64_t auxpow_diff_unsigned = prev_same_type.nAuxPow - anchor.nAuxPow;
    BOOST_REQUIRE(auxpow_diff_unsigned <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
    const int64_t auxpow_diff = static_cast<int64_t>(auxpow_diff_unsigned);
    const int64_t height_diff = auxpow
        ? auxpow_diff
        : prev_same_type.nHeight - anchor.nHeight - auxpow_diff;

    return CalculateASERT(ref_target,
                          target_spacing,
                          prev_same_type.GetBlockTime() - anchor.nBlockTime,
                          height_diff,
                          UintToArith256(consensus.powLimit),
                          consensus.nASERTHalfLife)
        .GetCompact();
}
} // namespace

BOOST_AUTO_TEST_CASE(cadence_type_specific_anchor_targets)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);

    CBlockIndex genesis;
    genesis.nVersion = permissionless_version;
    genesis.nHeight = consensus.asertAnchorParams.nHeight;
    genesis.nTime = consensus.asertAnchorParams.nBlockTime;
    genesis.nBits = LegacyAnchorBits(consensus);

    const CBlockHeader next_permissionless = MakeNextHeader(permissionless_version, genesis.nTime + LegacyTargetSpacing(consensus));
    const CBlockHeader next_merged = MakeNextHeader(merged_version, genesis.nTime + AuxPowTargetSpacing(consensus));

    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next_permissionless, consensus), LegacyAnchorBits(consensus));
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next_merged, consensus), AuxPowAnchorBits(consensus));
}

BOOST_AUTO_TEST_CASE(cadence_dual_track_independence)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> stable_chain;
    AppendBlock(stable_chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(stable_chain, merged_version, anchor_time + 60, merged_bits);
    const CBlockIndex* stable_tip = &AppendBlock(stable_chain, permissionless_version, anchor_time + 120, legacy_bits);

    const CBlockHeader next_merged_stable = MakeNextHeader(merged_version, anchor_time + 180);
    const CBlockHeader next_permissionless_stable = MakeNextHeader(permissionless_version, anchor_time + 180);

    std::deque<CBlockIndex> fast_permissionless_chain;
    AppendBlock(fast_permissionless_chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(fast_permissionless_chain, merged_version, anchor_time + 60, merged_bits);
    AppendBlock(fast_permissionless_chain, permissionless_version, anchor_time + 90, legacy_bits);
    const CBlockIndex* fast_tip = &AppendBlock(fast_permissionless_chain, permissionless_version, anchor_time + 120, legacy_bits);

    const CBlockHeader next_merged_fast = MakeNextHeader(merged_version, anchor_time + 180);
    const CBlockHeader next_permissionless_fast = MakeNextHeader(permissionless_version, anchor_time + 180);

    BOOST_CHECK_EQUAL(GetNextWorkRequired(stable_tip, &next_merged_stable, consensus),
                      GetNextWorkRequired(fast_tip, &next_merged_fast, consensus));

    const auto stable_target = DeriveTarget(GetNextWorkRequired(stable_tip, &next_permissionless_stable, consensus), consensus.powLimit);
    const auto fast_target = DeriveTarget(GetNextWorkRequired(fast_tip, &next_permissionless_fast, consensus), consensus.powLimit);
    BOOST_REQUIRE(stable_target.has_value());
    BOOST_REQUIRE(fast_target.has_value());
    BOOST_CHECK(*fast_target < *stable_target);
}

BOOST_AUTO_TEST_CASE(cadence_same_type_predecessor_lookup)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    const CBlockIndex* merged_1 = &AppendBlock(chain, merged_version, anchor_time + 60, merged_bits);
    AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, anchor_time + 240, legacy_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, anchor_time + 300);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), ExpectedCadenceBits(consensus, *merged_1, /*auxpow=*/true));
}

BOOST_AUTO_TEST_CASE(cadence_lane_links_match_linear_reference_on_forks_and_anchors)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> common;
    CBlockIndex* genesis = &AppendChild(common, nullptr, permissionless_version, anchor_time, legacy_bits);
    CBlockIndex* first_auxpow = &AppendChild(common, genesis, merged_version, anchor_time + 60, merged_bits);
    CBlockIndex* fork = &AppendChild(common, first_auxpow, permissionless_version, anchor_time + 120, legacy_bits);

    std::deque<CBlockIndex> permissionless_branch;
    CBlockIndex* permissionless_tip = fork;
    for (int i = 1; i <= 1000; ++i) {
        permissionless_tip = &AppendChild(permissionless_branch,
                                          permissionless_tip,
                                          permissionless_version,
                                          anchor_time + 120 + i * 60,
                                          legacy_bits);
    }

    std::deque<CBlockIndex> auxpow_branch;
    CBlockIndex* auxpow_tip = fork;
    for (int i = 1; i <= 1000; ++i) {
        auxpow_tip = &AppendChild(auxpow_branch,
                                  auxpow_tip,
                                  merged_version,
                                  anchor_time + 120 + i * 60,
                                  merged_bits);
    }

    for (const CBlockIndex* tip : {permissionless_tip, auxpow_tip}) {
        for (const bool auxpow : {false, true}) {
            const CBlockIndex* linear = LinearPreviousBlockForLane(tip, auxpow, /*anchor_height=*/0);
            BOOST_CHECK(tip->GetPreviousBlockForLane(auxpow, /*min_height=*/0) == linear);

            const CBlockHeader next = MakeNextHeader(auxpow ? merged_version : permissionless_version, tip->nTime + 1);
            const uint32_t expected_bits = linear != nullptr ? ExpectedCadenceBits(consensus, *linear, auxpow) : (auxpow ? merged_bits : legacy_bits);
            BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next, consensus), expected_bits);
        }
    }

    BOOST_CHECK(permissionless_tip->GetPreviousBlockForLane(/*auxpow=*/true, fork->nHeight) == nullptr);
    BOOST_CHECK(permissionless_tip->GetPreviousBlockForLane(/*auxpow=*/true, first_auxpow->nHeight) == first_auxpow);
    BOOST_CHECK(auxpow_tip->GetPreviousBlockForLane(/*auxpow=*/false, fork->nHeight) == fork);

    CChain active_chain;
    active_chain.SetTip(*permissionless_tip);
    BOOST_CHECK(active_chain.Tip()->GetPreviousBlockForLane(/*auxpow=*/true, /*min_height=*/0) == first_auxpow);
    active_chain.SetTip(*auxpow_tip);
    BOOST_CHECK(active_chain.Tip()->GetPreviousBlockForLane(/*auxpow=*/false, /*min_height=*/0) == fork);
}

BOOST_AUTO_TEST_CASE(cadence_pre_activation_uses_single_track_asert_history)
{
    auto consensus = GetConsensusParams(*m_node.args);
    consensus.nCadenceActivationHeight = 100;

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    const CBlockIndex* merged_1 = &AppendBlock(chain, merged_version, anchor_time + 60, merged_bits);
    AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);
    const CBlockIndex* tip = &chain.back();

    const CBlockHeader next_merged = MakeNextHeader(merged_version, anchor_time + 180);
    const uint32_t single_track_bits = ExpectedSingleTrackBits(consensus, *tip);
    const uint32_t cadence_bits = ExpectedCadenceBits(consensus, *merged_1, /*auxpow=*/true);

    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), single_track_bits);
    BOOST_CHECK_NE(single_track_bits, cadence_bits);
}

BOOST_AUTO_TEST_CASE(cadence_consecutive_same_type_sequences)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> permissionless_chain;
    AppendBlock(permissionless_chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(permissionless_chain, permissionless_version, anchor_time + 60, legacy_bits);
    const CBlockIndex* permissionless_tip = &AppendBlock(permissionless_chain, permissionless_version, anchor_time + 120, legacy_bits);

    const CBlockHeader next_permissionless = MakeNextHeader(permissionless_version, anchor_time + 180);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(permissionless_tip, &next_permissionless, consensus),
                      ExpectedCadenceBits(consensus, *permissionless_tip, /*auxpow=*/false));

    std::deque<CBlockIndex> merged_chain;
    AppendBlock(merged_chain, permissionless_version, anchor_time, legacy_bits);
    const CBlockIndex* merged_1 = &AppendBlock(merged_chain, merged_version, anchor_time + 120, merged_bits);
    const CBlockIndex* merged_2 = &AppendBlock(merged_chain, merged_version, anchor_time + 240, merged_bits);
    const CBlockIndex* merged_tip = &AppendBlock(merged_chain, merged_version, anchor_time + 360, merged_bits);

    BOOST_CHECK_EQUAL(merged_1->nAuxPow, 1);
    BOOST_CHECK_EQUAL(merged_2->nAuxPow, 2);
    BOOST_CHECK_EQUAL(merged_tip->nAuxPow, 3);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, anchor_time + 480);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(merged_tip, &next_merged, consensus),
                      ExpectedCadenceBits(consensus, *merged_tip, /*auxpow=*/true));
}

BOOST_AUTO_TEST_CASE(cadence_sparse_track_uses_anchor_edge)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, anchor_time + 240, legacy_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, anchor_time + 300);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), AuxPowAnchorBits(consensus));
}

BOOST_AUTO_TEST_CASE(cadence_starved_auxpow_lane_resumes_from_lane_local_history)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;
    const uint32_t starvation_seconds = 24 * 60 * 60;
    const uint32_t resumption_time = anchor_time + starvation_seconds;
    const uint32_t permissionless_spacing = static_cast<uint32_t>(LegacyTargetSpacing(consensus));
    BOOST_REQUIRE(permissionless_spacing > 0);

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    const CBlockIndex* tip{nullptr};
    for (uint32_t block_time = anchor_time + permissionless_spacing;
         block_time < resumption_time;
         block_time += permissionless_spacing) {
        tip = &AppendBlock(chain, permissionless_version, block_time, legacy_bits);
    }
    tip = &AppendBlock(chain, permissionless_version, resumption_time, legacy_bits);
    BOOST_CHECK_GT(tip->nHeight, 100);

    const CBlockHeader seed_merged = MakeNextHeader(merged_version, resumption_time);
    const uint32_t seed_bits = GetNextWorkRequired(tip, &seed_merged, consensus);
    BOOST_CHECK_EQUAL(seed_bits, merged_bits);

    const CBlockIndex* merged_seed = &AppendBlock(chain, merged_version, resumption_time, seed_bits);
    const CBlockHeader next_merged = MakeNextHeader(merged_version, resumption_time + 1);
    const uint32_t post_seed_bits = GetNextWorkRequired(merged_seed, &next_merged, consensus);
    BOOST_CHECK_EQUAL(post_seed_bits, ExpectedCadenceBits(consensus, *merged_seed, /*auxpow=*/true));

    const auto seed_target = DeriveTarget(seed_bits, consensus.powLimit);
    const auto post_seed_target = DeriveTarget(post_seed_bits, consensus.powLimit);
    BOOST_REQUIRE(seed_target.has_value());
    BOOST_REQUIRE(post_seed_target.has_value());
    BOOST_CHECK(*post_seed_target > *seed_target * 1000);
    BOOST_CHECK(*post_seed_target < UintToArith256(consensus.powLimit));
}

BOOST_AUTO_TEST_CASE(cadence_height_diff_subtracts_anchor_auxpow_count)
{
    auto consensus = GetConsensusParams(*m_node.args);
    consensus.nASERTHalfLife = 60;
    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsAuxPow = 0x1c00ffff;

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t base_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, base_time, legacy_bits);
    AppendBlock(chain, merged_version, base_time + 60, merged_bits);
    const CBlockIndex* anchor = &AppendBlock(chain, permissionless_version, base_time + 120, legacy_bits);
    AppendBlock(chain, permissionless_version, base_time + 180, legacy_bits);
    const CBlockIndex* merged_after_anchor = &AppendBlock(chain, merged_version, base_time + 240, merged_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, base_time + 300, legacy_bits);

    consensus.asertAnchorParams.nHeight = anchor->nHeight;
    consensus.asertAnchorParams.nAuxPow = anchor->nAuxPow;
    consensus.asertAnchorParams.nBlockTime = anchor->GetBlockTime();

    BOOST_CHECK_EQUAL(anchor->nAuxPow, 1);
    BOOST_CHECK_EQUAL(merged_after_anchor->nAuxPow - anchor->nAuxPow, 1);
    BOOST_CHECK_EQUAL(tip->nHeight - anchor->nHeight - (tip->nAuxPow - anchor->nAuxPow), 2);

    const CBlockHeader next_permissionless = MakeNextHeader(permissionless_version, tip->GetBlockTime() + 60);
    const uint32_t expected_permissionless = ExpectedCadenceBits(consensus, *tip, /*auxpow=*/false);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_permissionless, consensus), expected_permissionless);

    const uint32_t legacy_wrong_bits = CalculateASERT(arith_uint256().SetCompact(LegacyAnchorBits(consensus)),
                                                      LegacyTargetSpacing(consensus),
                                                      tip->GetBlockTime() - consensus.asertAnchorParams.nBlockTime,
                                                      tip->nHeight - consensus.asertAnchorParams.nHeight - tip->nAuxPow,
                                                      UintToArith256(consensus.powLimit),
                                                      consensus.nASERTHalfLife)
                                           .GetCompact();
    BOOST_CHECK_NE(expected_permissionless, legacy_wrong_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, tip->GetBlockTime() + 60);
    const uint32_t expected_merged = ExpectedCadenceBits(consensus, *merged_after_anchor, /*auxpow=*/true);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), expected_merged);

    const uint32_t auxpow_wrong_bits = CalculateASERT(arith_uint256().SetCompact(AuxPowAnchorBits(consensus)),
                                                      AuxPowTargetSpacing(consensus),
                                                      merged_after_anchor->GetBlockTime() - consensus.asertAnchorParams.nBlockTime,
                                                      merged_after_anchor->nAuxPow,
                                                      UintToArith256(consensus.powLimit),
                                                      consensus.nASERTHalfLife)
                                           .GetCompact();
    BOOST_CHECK_NE(expected_merged, auxpow_wrong_bits);
}

BOOST_AUTO_TEST_CASE(cadence_anchor_auxpow_count_accepts_large_64bit_values)
{
    auto consensus = GetConsensusParams(*m_node.args);
    consensus.nASERTHalfLife = 60;
    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsAuxPow = 0x1c00ffff;

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t base_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, base_time, legacy_bits);
    AppendBlock(chain, merged_version, base_time + 60, merged_bits);
    CBlockIndex* anchor = &AppendBlock(chain, permissionless_version, base_time + 120, legacy_bits);
    AppendBlock(chain, permissionless_version, base_time + 180, legacy_bits);
    CBlockIndex* merged_after_anchor = &AppendBlock(chain, merged_version, base_time + 240, merged_bits);
    CBlockIndex* tip = &AppendBlock(chain, permissionless_version, base_time + 300, legacy_bits);

    const uint64_t auxpow_offset{uint64_t{1} << 33};
    anchor->nAuxPow += auxpow_offset;
    merged_after_anchor->nAuxPow += auxpow_offset;
    tip->nAuxPow += auxpow_offset;

    consensus.asertAnchorParams.nHeight = anchor->nHeight;
    consensus.asertAnchorParams.nAuxPow = anchor->nAuxPow;
    consensus.asertAnchorParams.nBlockTime = anchor->GetBlockTime();

    const CBlockHeader next_permissionless = MakeNextHeader(permissionless_version, tip->GetBlockTime() + 60);
    const uint32_t expected_permissionless = CalculateASERT(arith_uint256().SetCompact(LegacyAnchorBits(consensus)),
                                                            LegacyTargetSpacing(consensus),
                                                            tip->GetBlockTime() - consensus.asertAnchorParams.nBlockTime,
                                                            /*nHeightDiff=*/2,
                                                            UintToArith256(consensus.powLimit),
                                                            consensus.nASERTHalfLife)
                                                 .GetCompact();
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_permissionless, consensus), expected_permissionless);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, tip->GetBlockTime() + 60);
    const uint32_t expected_merged = CalculateASERT(arith_uint256().SetCompact(AuxPowAnchorBits(consensus)),
                                                    AuxPowTargetSpacing(consensus),
                                                    merged_after_anchor->GetBlockTime() - consensus.asertAnchorParams.nBlockTime,
                                                    /*nHeightDiff=*/1,
                                                    UintToArith256(consensus.powLimit),
                                                    consensus.nASERTHalfLife)
                                         .GetCompact();
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), expected_merged);
}

BOOST_AUTO_TEST_CASE(cadence_min_difficulty_uses_track_timeout)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::TESTNET);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    const CBlockIndex* merged_tip = &AppendBlock(chain, merged_version, anchor_time + 60, merged_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, tip->GetBlockTime() + (consensus.nPowTargetSpacing * 2) + 1);
    BOOST_REQUIRE(next_merged.GetBlockTime() < tip->GetBlockTime() + (AuxPowTargetSpacing(consensus) * 2));
    BOOST_CHECK_NE(GetNextWorkRequired(tip, &next_merged, consensus), PowLimitBits(consensus));
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus),
                      ExpectedCadenceBits(consensus, *merged_tip, /*auxpow=*/true));
}

BOOST_AUTO_TEST_CASE(cadence_asert_min_difficulty_exceeds_track_timeout)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::TESTNET);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(chain, merged_version, anchor_time + 60, merged_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, tip->GetBlockTime() + (AuxPowTargetSpacing(consensus) * 2) + 1);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), PowLimitBits(consensus));
}

BOOST_AUTO_TEST_CASE(cadence_pre_activation_uses_base_timeout)
{
    auto consensus = GetConsensusParams(*m_node.args, ChainType::TESTNET);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);
    consensus.nCadenceActivationHeight = 100;

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(chain, merged_version, anchor_time + 60, merged_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, tip->GetBlockTime() + (consensus.nPowTargetSpacing * 2) + 1);
    BOOST_REQUIRE(next_merged.GetBlockTime() < tip->GetBlockTime() + (AuxPowTargetSpacing(consensus) * 2));
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), PowLimitBits(consensus));

    consensus.nCadenceActivationHeight = 0;
    BOOST_CHECK_NE(GetNextWorkRequired(tip, &next_merged, consensus), PowLimitBits(consensus));
}

BOOST_AUTO_TEST_CASE(cadence_min_difficulty_sparse_track_ignores_anchor_timeout)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::TESTNET);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    AppendBlock(chain, permissionless_version, anchor_time + 120, legacy_bits);
    const CBlockIndex* tip = &AppendBlock(chain, permissionless_version, anchor_time + 240, legacy_bits);

    const CBlockHeader next_merged = MakeNextHeader(merged_version, anchor_time + (AuxPowTargetSpacing(consensus) * 2) + 1);
    BOOST_REQUIRE(next_merged.GetBlockTime() > anchor_time + (AuxPowTargetSpacing(consensus) * 2));
    BOOST_REQUIRE(next_merged.GetBlockTime() <= tip->GetBlockTime() + (AuxPowTargetSpacing(consensus) * 2));
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), AuxPowAnchorBits(consensus));
}

BOOST_AUTO_TEST_CASE(cadence_target_ratio_schedule_stays_on_target)
{
    const auto consensus = GetConsensusParams(*m_node.args);
    const uint32_t legacy_bits = LegacyAnchorBits(consensus);
    const uint32_t merged_bits = AuxPowAnchorBits(consensus);
    const int32_t permissionless_version = PermissionlessVersion();
    const int32_t merged_version = MergedVersion(consensus);
    const uint32_t anchor_time = consensus.asertAnchorParams.nBlockTime;
    const int64_t legacy_spacing = LegacyTargetSpacing(consensus);
    const int64_t merged_spacing = AuxPowTargetSpacing(consensus);
    const uint64_t cadence_period = std::lcm(static_cast<uint64_t>(legacy_spacing),
                                             static_cast<uint64_t>(merged_spacing));
    const int permissionless_per_period = static_cast<int>(cadence_period / static_cast<uint64_t>(legacy_spacing));
    const int merged_per_period = static_cast<int>(cadence_period / static_cast<uint64_t>(merged_spacing));
    const int permissionless_target = permissionless_per_period * 2;
    const int merged_target = merged_per_period * 2;

    std::deque<CBlockIndex> chain;
    AppendBlock(chain, permissionless_version, anchor_time, legacy_bits);
    int merged_count = 0;
    for (int permissionless_count = 1; permissionless_count <= permissionless_target; ++permissionless_count) {
        const uint32_t permissionless_time = anchor_time + static_cast<uint32_t>(permissionless_count * legacy_spacing);
        while (merged_count < merged_target &&
               anchor_time + static_cast<uint32_t>((merged_count + 1) * merged_spacing) < permissionless_time) {
            ++merged_count;
            AppendBlock(chain,
                        merged_version,
                        anchor_time + static_cast<uint32_t>(merged_count * merged_spacing),
                        merged_bits);
        }
        AppendBlock(chain, permissionless_version, permissionless_time, legacy_bits);
    }
    while (merged_count < merged_target) {
        ++merged_count;
        AppendBlock(chain,
                    merged_version,
                    anchor_time + static_cast<uint32_t>(merged_count * merged_spacing),
                    merged_bits);
    }

    const CBlockIndex* tip = &chain.back();
    const CBlockHeader next_permissionless = MakeNextHeader(
        permissionless_version,
        anchor_time + static_cast<uint32_t>((permissionless_target + 1) * legacy_spacing));
    const CBlockHeader next_merged = MakeNextHeader(
        merged_version,
        anchor_time + static_cast<uint32_t>((merged_target + 1) * merged_spacing));

    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_permissionless, consensus), legacy_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(tip, &next_merged, consensus), merged_bits);
}

BOOST_AUTO_TEST_SUITE_END()
