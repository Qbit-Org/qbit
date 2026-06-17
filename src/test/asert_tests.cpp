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

#include <algorithm>
#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(asert_tests, BasicTestingSetup)

static Consensus::Params GetConsensusParams(const ArgsManager& args, ChainType chain)
{
    return CreateChainParams(args, chain)->GetConsensus();
}

static uint32_t LegacyAnchorBits(const Consensus::Params& consensus)
{
    return consensus.asertAnchorParams.nBitsLegacy != 0 ? consensus.asertAnchorParams.nBitsLegacy
                                                        : consensus.asertAnchorParams.nBits;
}

static int64_t LegacyTargetSpacing(const Consensus::Params& consensus)
{
    return consensus.nPowTargetSpacingLegacy > 0 ? consensus.nPowTargetSpacingLegacy
                                                 : consensus.nPowTargetSpacing;
}

BOOST_AUTO_TEST_CASE(asert_genesis_anchor_target)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(consensus.asertAnchorParams.nBits);

    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              0,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(next, ref_target);
}

BOOST_AUTO_TEST_CASE(asert_one_block_on_target)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              consensus.nPowTargetSpacing,
                                              1,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(next, ref_target);
}

BOOST_AUTO_TEST_CASE(asert_fast_and_slow_blocks)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const int64_t height_diff = 120;
    const int64_t ideal_time = consensus.nPowTargetSpacing * height_diff;

    const arith_uint256 faster = CalculateASERT(ref_target,
                                                consensus.nPowTargetSpacing,
                                                ideal_time - (10 * consensus.nPowTargetSpacing),
                                                height_diff,
                                                pow_limit,
                                                consensus.nASERTHalfLife);
    const arith_uint256 slower = CalculateASERT(ref_target,
                                                consensus.nPowTargetSpacing,
                                                ideal_time + (10 * consensus.nPowTargetSpacing),
                                                height_diff,
                                                pow_limit,
                                                consensus.nASERTHalfLife);

    BOOST_CHECK(faster < ref_target);
    BOOST_CHECK(slower > ref_target);
}

BOOST_AUTO_TEST_CASE(asert_halflife_property)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const arith_uint256 up = CalculateASERT(ref_target,
                                            consensus.nPowTargetSpacing,
                                            consensus.nASERTHalfLife,
                                            0,
                                            pow_limit,
                                            consensus.nASERTHalfLife);
    const arith_uint256 down = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              -consensus.nASERTHalfLife,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);

    BOOST_CHECK_EQUAL(up, ref_target * 2);
    BOOST_CHECK_EQUAL(down, ref_target >> 1);
}

BOOST_AUTO_TEST_CASE(asert_bounds_clamp)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);

    const arith_uint256 at_max = CalculateASERT(pow_limit,
                                                consensus.nPowTargetSpacing,
                                                100 * consensus.nASERTHalfLife,
                                                0,
                                                pow_limit,
                                                consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(at_max, pow_limit);

    const arith_uint256 at_min = CalculateASERT(arith_uint256(1),
                                                consensus.nPowTargetSpacing,
                                                -100 * consensus.nASERTHalfLife,
                                                0,
                                                pow_limit,
                                                consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(at_min, arith_uint256(1));
}

BOOST_AUTO_TEST_CASE(asert_deterministic)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const int64_t n_time_diff = (consensus.nPowTargetSpacing * 144) + 42;
    const int64_t n_height_diff = 144;

    const arith_uint256 one = CalculateASERT(ref_target,
                                             consensus.nPowTargetSpacing,
                                             n_time_diff,
                                             n_height_diff,
                                             pow_limit,
                                             consensus.nASERTHalfLife);
    const arith_uint256 two = CalculateASERT(ref_target,
                                             consensus.nPowTargetSpacing,
                                             n_time_diff,
                                             n_height_diff,
                                             pow_limit,
                                             consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(one, two);
}

BOOST_AUTO_TEST_CASE(asert_compact_roundtrip)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              (consensus.nPowTargetSpacing * 77) + (consensus.nASERTHalfLife / 2),
                                              77,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK(next != ref_target);

    bool negative{false};
    bool overflow{false};
    arith_uint256 roundtrip;
    roundtrip.SetCompact(next.GetCompact(), &negative, &overflow);
    BOOST_CHECK(!negative);
    BOOST_CHECK(!overflow);
    BOOST_CHECK(roundtrip >= arith_uint256(1));
    BOOST_CHECK(roundtrip <= pow_limit);
}

BOOST_AUTO_TEST_CASE(asert_symmetric_response)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const int64_t skew = consensus.nASERTHalfLife / 3;
    const arith_uint256 faster = CalculateASERT(ref_target,
                                                consensus.nPowTargetSpacing,
                                                -skew,
                                                0,
                                                pow_limit,
                                                consensus.nASERTHalfLife);
    const arith_uint256 slower = CalculateASERT(ref_target,
                                                consensus.nPowTargetSpacing,
                                                skew,
                                                0,
                                                pow_limit,
                                                consensus.nASERTHalfLife);

    const double up = slower.getdouble() / ref_target.getdouble();
    const double down = ref_target.getdouble() / faster.getdouble();
    BOOST_CHECK_CLOSE(up, down, 1.0);
}

BOOST_AUTO_TEST_CASE(asert_large_time_gap)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              24 * 60 * 60,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK(next >= ref_target);
    BOOST_CHECK(next <= pow_limit);
}

BOOST_AUTO_TEST_CASE(asert_extreme_positive_delta_2pow32_clamps_to_pow_limit)
{
    // Review gate: explicit overflow coverage at +2^32 deltas.
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);
    constexpr int64_t kTwoPow32 = int64_t{1} << 32;
    constexpr int64_t kTwoPow32MinusOne = kTwoPow32 - 1;

    const int64_t n_height_diff = 1000;
    const int64_t ideal_time = consensus.nPowTargetSpacing * n_height_diff;

    const arith_uint256 at_plus_2pow32 = CalculateASERT(ref_target,
                                                        consensus.nPowTargetSpacing,
                                                        ideal_time + kTwoPow32,
                                                        n_height_diff,
                                                        pow_limit,
                                                        consensus.nASERTHalfLife);
    const arith_uint256 at_plus_2pow32_minus_one = CalculateASERT(ref_target,
                                                                  consensus.nPowTargetSpacing,
                                                                  ideal_time + kTwoPow32MinusOne,
                                                                  n_height_diff,
                                                                  pow_limit,
                                                                  consensus.nASERTHalfLife);

    BOOST_CHECK_EQUAL(at_plus_2pow32, pow_limit);
    BOOST_CHECK_EQUAL(at_plus_2pow32_minus_one, pow_limit);
}

BOOST_AUTO_TEST_CASE(asert_extreme_negative_delta_2pow32_clamps_to_min_target)
{
    // Review gate: explicit underflow coverage at -2^32 deltas.
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);
    constexpr int64_t kTwoPow32 = int64_t{1} << 32;
    constexpr int64_t kTwoPow32MinusOne = kTwoPow32 - 1;

    const int64_t n_height_diff = 1000;
    const int64_t ideal_time = consensus.nPowTargetSpacing * n_height_diff;

    const arith_uint256 at_minus_2pow32 = CalculateASERT(ref_target,
                                                         consensus.nPowTargetSpacing,
                                                         ideal_time - kTwoPow32,
                                                         n_height_diff,
                                                         pow_limit,
                                                         consensus.nASERTHalfLife);
    const arith_uint256 at_minus_2pow32_plus_one = CalculateASERT(ref_target,
                                                                  consensus.nPowTargetSpacing,
                                                                  ideal_time - kTwoPow32MinusOne,
                                                                  n_height_diff,
                                                                  pow_limit,
                                                                  consensus.nASERTHalfLife);

    BOOST_CHECK_EQUAL(at_minus_2pow32, arith_uint256(1));
    BOOST_CHECK_EQUAL(at_minus_2pow32_plus_one, arith_uint256(1));
}
BOOST_AUTO_TEST_CASE(asert_rapid_blocks)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const int64_t blocks = 100;
    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              blocks,
                                              blocks,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK(next >= arith_uint256(1));
    BOOST_CHECK(next < ref_target);
}

BOOST_AUTO_TEST_CASE(asert_minimum_target)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);

    const arith_uint256 next = CalculateASERT(arith_uint256(1),
                                              consensus.nPowTargetSpacing,
                                              -100 * consensus.nASERTHalfLife,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(next, arith_uint256(1));
}

BOOST_AUTO_TEST_CASE(asert_maximum_target)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);

    const arith_uint256 next = CalculateASERT(pow_limit,
                                              consensus.nPowTargetSpacing,
                                              100 * consensus.nASERTHalfLife,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(next, pow_limit);
}

BOOST_AUTO_TEST_CASE(asert_steady_state_convergence)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    for (int64_t height = 1; height <= 10000; ++height) {
        const arith_uint256 next = CalculateASERT(ref_target,
                                                  consensus.nPowTargetSpacing,
                                                  height * consensus.nPowTargetSpacing,
                                                  height,
                                                  pow_limit,
                                                  consensus.nASERTHalfLife);
        BOOST_CHECK_EQUAL(next, ref_target);
    }
}

BOOST_AUTO_TEST_CASE(asert_pre_anchor_uses_anchor_bits)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const uint32_t anchor_bits = LegacyAnchorBits(consensus);
    const int64_t target_spacing = LegacyTargetSpacing(consensus);
    CBlockIndex pindex_last;
    pindex_last.nHeight = consensus.asertAnchorParams.nHeight - 1;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime - target_spacing;
    pindex_last.nBits = anchor_bits;

    CBlockHeader next_block{};
    next_block.nTime = pindex_last.nTime + target_spacing;

    const uint32_t next_bits = GetNextWorkRequired(&pindex_last, &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, anchor_bits);
}

BOOST_AUTO_TEST_CASE(asert_out_of_order_timestamp_hardens_target)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const uint32_t anchor_bits = LegacyAnchorBits(consensus);
    const int64_t target_spacing = LegacyTargetSpacing(consensus);

    CBlockIndex pindex_on_schedule;
    pindex_on_schedule.nHeight = consensus.asertAnchorParams.nHeight + 1000;
    pindex_on_schedule.nTime = consensus.asertAnchorParams.nBlockTime + (1000 * target_spacing);
    pindex_on_schedule.nBits = anchor_bits;

    CBlockHeader next_on_schedule{};
    next_on_schedule.nTime = pindex_on_schedule.nTime + target_spacing;
    const auto on_schedule_target = DeriveTarget(GetNextWorkRequired(&pindex_on_schedule, &next_on_schedule, consensus), consensus.powLimit);
    BOOST_REQUIRE(on_schedule_target.has_value());

    CBlockIndex pindex_out_of_order;
    pindex_out_of_order.nHeight = pindex_on_schedule.nHeight;
    pindex_out_of_order.nTime = pindex_on_schedule.nTime;
    pindex_out_of_order.nBits = pindex_on_schedule.nBits;
    pindex_out_of_order.nTime -= 90;
    CBlockHeader next_out_of_order{};
    next_out_of_order.nTime = pindex_out_of_order.nTime + target_spacing;
    const auto out_of_order_target = DeriveTarget(GetNextWorkRequired(&pindex_out_of_order, &next_out_of_order, consensus), consensus.powLimit);
    BOOST_REQUIRE(out_of_order_target.has_value());
    BOOST_CHECK(*out_of_order_target >= arith_uint256(1));
    BOOST_CHECK(*out_of_order_target <= pow_limit);
    BOOST_CHECK(*out_of_order_target < *on_schedule_target);
}
BOOST_AUTO_TEST_CASE(asert_hashrate_drop_recovery)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const int64_t blocks = consensus.nASERTHalfLife / consensus.nPowTargetSpacing;
    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              blocks * consensus.nPowTargetSpacing * 2,
                                              blocks,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    const double ratio = next.getdouble() / ref_target.getdouble();
    BOOST_CHECK(ratio > 1.9);
    BOOST_CHECK(ratio < 2.1);
}

BOOST_AUTO_TEST_CASE(asert_hashrate_spike_recovery)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    const int64_t blocks = (2 * consensus.nASERTHalfLife) / consensus.nPowTargetSpacing;
    const arith_uint256 next = CalculateASERT(ref_target,
                                              consensus.nPowTargetSpacing,
                                              blocks * (consensus.nPowTargetSpacing / 2),
                                              blocks,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    const double ratio = next.getdouble() / ref_target.getdouble();
    BOOST_CHECK(ratio > 0.45);
    BOOST_CHECK(ratio < 0.55);
}

BOOST_AUTO_TEST_CASE(asert_oscillation_resistance)
{
    const auto consensus = GetConsensusParams(*m_node.args, ChainType::MAIN);
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(0x1c00ffff);

    int64_t elapsed = 0;
    arith_uint256 min_target = pow_limit;
    arith_uint256 max_target = arith_uint256(1);
    for (int64_t height = 1; height <= 240; ++height) {
        elapsed += (height % 2 == 0) ? (consensus.nPowTargetSpacing / 2) : (consensus.nPowTargetSpacing * 3 / 2);
        const arith_uint256 next = CalculateASERT(ref_target,
                                                  consensus.nPowTargetSpacing,
                                                  elapsed,
                                                  height,
                                                  pow_limit,
                                                  consensus.nASERTHalfLife);
        min_target = std::min(min_target, next);
        max_target = std::max(max_target, next);
    }

    BOOST_CHECK(max_target < (ref_target << 2));
    BOOST_CHECK(min_target > (ref_target >> 2));
}

BOOST_AUTO_TEST_CASE(asert_testnet_min_difficulty)
{
    auto consensus = GetConsensusParams(*m_node.args, ChainType::TESTNET);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);
    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;
    const int64_t target_spacing = LegacyTargetSpacing(consensus);

    CBlockIndex pindex_last;
    pindex_last.nHeight = consensus.asertAnchorParams.nHeight + 10;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime + 10 * target_spacing;
    pindex_last.nBits = LegacyAnchorBits(consensus);

    CBlockHeader on_time_block{};
    on_time_block.nTime = pindex_last.nTime + target_spacing;
    const uint32_t asert_bits = GetNextWorkRequired(&pindex_last, &on_time_block, consensus);
    BOOST_CHECK_NE(asert_bits, UintToArith256(consensus.powLimit).GetCompact());

    CBlockHeader min_diff_block{};
    min_diff_block.nTime = pindex_last.nTime + (target_spacing * 3);

    const uint32_t next_bits = GetNextWorkRequired(&pindex_last, &min_diff_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, UintToArith256(consensus.powLimit).GetCompact());
    BOOST_CHECK_NE(next_bits, asert_bits);
}

BOOST_AUTO_TEST_CASE(asert_regtest_flag)
{
    ArgsManager default_args;
    const auto regtest_default = CreateChainParams(default_args, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK(!regtest_default.fPowUseASERT);
    BOOST_CHECK(regtest_default.fPowNoRetargeting);

    ArgsManager asert_args;
    asert_args.ForceSetArg("-asert", "1");
    const auto regtest_asert = CreateChainParams(asert_args, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK(regtest_asert.fPowUseASERT);
    BOOST_CHECK(!regtest_asert.fPowNoRetargeting);
    const int64_t target_spacing = LegacyTargetSpacing(regtest_asert);
    const uint32_t anchor_bits = LegacyAnchorBits(regtest_asert);

    CBlockIndex pindex_last;
    pindex_last.nHeight = regtest_asert.asertAnchorParams.nHeight + 100;
    pindex_last.nTime = regtest_asert.asertAnchorParams.nBlockTime + (100 * target_spacing) - regtest_asert.nASERTHalfLife;
    pindex_last.nBits = anchor_bits;

    CBlockHeader next_block{};
    next_block.nTime = pindex_last.nTime + target_spacing;

    const uint32_t bits_default = GetNextWorkRequired(&pindex_last, &next_block, regtest_default);
    const uint32_t bits_asert = GetNextWorkRequired(&pindex_last, &next_block, regtest_asert);
    BOOST_CHECK_EQUAL(bits_default, pindex_last.nBits);
    BOOST_CHECK(bits_asert < pindex_last.nBits);

    ArgsManager legacy_args;
    legacy_args.ForceSetArg("-legacyretarget", "1");
    const auto regtest_legacy = CreateChainParams(legacy_args, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK(!regtest_legacy.fPowUseASERT);
    BOOST_CHECK(!regtest_legacy.fPowNoRetargeting);

    ArgsManager invalid_args;
    invalid_args.ForceSetArg("-asert", "1");
    invalid_args.ForceSetArg("-legacyretarget", "1");
    BOOST_CHECK_THROW(CreateChainParams(invalid_args, ChainType::REGTEST), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(asert_bchn_reference_vectors)
{
    // Cross-validate against BCHN's calculate_asert_test vectors:
    // src/test/pow_tests.cpp in bitcoin-cash-node/bitcoin-cash-node.
    //
    // BCHN's helper path accounts for the parent of the reference block and
    // an internal +1 height step. We adapt each vector for this direct
    // CalculateASERT(...) call by applying:
    //   time_diff   = parent_time_diff + vector.time_diff
    //   height_diff = vector.height_diff + 1
    // Use BCH's reference powLimit for these vectors to preserve the expected
    // compact encodings from BCHN's upstream test cases.
    const arith_uint256 pow_limit = UintToArith256(uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"});
    const uint32_t pow_limit_nbits = pow_limit.GetCompact();

    const int64_t target_spacing = 600;
    const int64_t half_life = 2 * 24 * 60 * 60;
    const int64_t parent_time_diff = 600;

    struct BchnVector {
        arith_uint256 ref_target;
        int64_t time_diff;
        int64_t height_diff;
        arith_uint256 expected_target;
        uint32_t expected_nbits;
    };

    const auto single_300_target_u = uint256::FromHex("00000000ffb1ffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const auto funny_ref_target_u = uint256::FromHex("000000008000000000000000000fffffffffffffffffffffffffffffffffffff");
    BOOST_REQUIRE(single_300_target_u.has_value());
    BOOST_REQUIRE(funny_ref_target_u.has_value());
    const arith_uint256 single_300_target = UintToArith256(*single_300_target_u);
    const arith_uint256 funny_ref_target = UintToArith256(*funny_ref_target_u);

    const std::vector<BchnVector> vectors{
        {pow_limit, 0, 2 * 144, pow_limit >> 1, 0x1c7fffff},
        {pow_limit, 0, 4 * 144, pow_limit >> 2, 0x1c3fffff},
        {pow_limit >> 1, 0, 2 * 144, pow_limit >> 2, 0x1c3fffff},
        {pow_limit >> 2, 0, 2 * 144, pow_limit >> 3, 0x1c1fffff},
        {pow_limit >> 3, 0, 2 * 144, pow_limit >> 4, 0x1c0fffff},
        {pow_limit, 0, 2 * (256 - 34) * 144, 3, 0x01030000},
        {pow_limit, 0, 2 * (256 - 34) * 144 + 119, 3, 0x01030000},
        {pow_limit, 0, 2 * (256 - 34) * 144 + 120, 2, 0x01020000},
        {pow_limit, 0, 2 * (256 - 33) * 144 - 1, 2, 0x01020000},
        {pow_limit, 0, 2 * (256 - 33) * 144, 1, 0x01010000},
        {pow_limit, 0, 2 * (256 - 32) * 144, 1, 0x01010000},
        {arith_uint256(1), 0, 2 * (256 - 32) * 144, 1, 0x01010000},
        {pow_limit, 2 * (512 - 32) * 144, 0, pow_limit, pow_limit_nbits},
        {arith_uint256(1), (512 - 64) * 144 * 600, 0, pow_limit, pow_limit_nbits},
        {pow_limit, 300, 1, single_300_target, 0x1d00ffb1},
        {funny_ref_target, 600 * 2 * 33 * 144, 0, pow_limit, pow_limit_nbits},
        {arith_uint256(1), 600 * 2 * 256 * 144, 0, pow_limit, pow_limit_nbits},
        {arith_uint256(1), 600 * 2 * 224 * 144 - 1, 0, arith_uint256(0xffff8) << 204, pow_limit_nbits},
    };

    for (const auto& v : vectors) {
        const arith_uint256 next = CalculateASERT(v.ref_target,
                                                  target_spacing,
                                                  parent_time_diff + v.time_diff,
                                                  v.height_diff + 1,
                                                  pow_limit,
                                                  half_life);
        BOOST_CHECK_EQUAL(next, v.expected_target);
        BOOST_CHECK_EQUAL(next.GetCompact(), v.expected_nbits);
    }
}

BOOST_AUTO_TEST_SUITE_END()
