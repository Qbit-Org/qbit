// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chain.h>
#include <node/confirmation_target.h>
#include <pow.h>
#include <primitives/pureheader.h>
#include <rpc/mining.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <memory>
#include <string>
#include <vector>

using node::ConfirmationCalculator;
using node::ConfirmationResult;

namespace {
const Consensus::Params& MainConsensus()
{
    static const Consensus::Params params = [] {
        ArgsManager args;
        return CreateChainParams(args, ChainType::MAIN)->GetConsensus();
    }();
    return params;
}

int64_t DefaultBlockTime()
{
    return MainConsensus().nPowTargetSpacing;
}

int64_t DefaultLegacySpacing()
{
    return MainConsensus().nPowTargetSpacingLegacy > 0
        ? MainConsensus().nPowTargetSpacingLegacy
        : DefaultBlockTime();
}

int64_t DefaultAuxPowSpacing()
{
    return MainConsensus().nPowTargetSpacingAuxPow > 0
        ? MainConsensus().nPowTargetSpacingAuxPow
        : DefaultBlockTime();
}

double DefaultCadenceMergedFraction()
{
    return ConfirmationCalculator::CadenceMergedFraction(
        DefaultLegacySpacing(),
        DefaultAuxPowSpacing(),
        DefaultBlockTime());
}

struct TestBlockIndex {
    uint256 hash{uint256::ZERO};
    CBlockIndex index;
};

struct HashrateTestChain {
    CChain chain;
    std::vector<std::unique_ptr<TestBlockIndex>> blocks;

    void AddBlock(const bool auxpow, const uint32_t time, const uint32_t bits = 0x207fffff)
    {
        constexpr uint16_t auxpow_chain_id{31430};
        auto block = std::make_unique<TestBlockIndex>();
        block->index.nVersion = MakeVersion(/*chain_id=*/auxpow ? auxpow_chain_id : 0, auxpow, /*version_bits=*/0);
        block->index.nTime = time;
        block->index.nBits = bits;
        block->index.nHeight = static_cast<int>(blocks.size());
        block->index.pprev = blocks.empty() ? nullptr : &blocks.back()->index;
        block->index.nAuxPow = (block->index.pprev ? block->index.pprev->nAuxPow : 0) + (auxpow ? 1 : 0);
        block->index.nChainWork = (block->index.pprev ? block->index.pprev->nChainWork : arith_uint256{}) + GetBlockProof(block->index);
        block->index.phashBlock = &block->hash;
        block->index.BuildSkip();
        block->index.BuildCadenceLaneLinks();
        blocks.push_back(std::move(block));
        chain.SetTip(blocks.back()->index);
    }

    const CBlockIndex& Block(const size_t height) const
    {
        return blocks.at(height)->index;
    }

    double Work(const size_t height) const
    {
        return GetBlockProof(Block(height)).getdouble();
    }
};

double ExpectedSecurityPerConf(
    double merge_mining_pct,
    double btc_hashrate = 7e20,
    double qbit_hashrate = 1e12,
    int64_t block_time = DefaultBlockTime(),
    int64_t legacy_spacing = DefaultLegacySpacing(),
    int64_t auxpow_spacing = DefaultAuxPowSpacing())
{
    const double cadence_merged_fraction = ConfirmationCalculator::CadenceMergedFraction(
        legacy_spacing,
        auxpow_spacing,
        block_time);
    const double native_fraction = btc_hashrate > 0.0 ? qbit_hashrate / btc_hashrate : 0.0;
    return cadence_merged_fraction * merge_mining_pct +
        (1.0 - cadence_merged_fraction) * native_fraction;
}

double ExpectedObservedSecurityPerConf(
    double btc_hashrate,
    double permissionless_hashrate,
    double auxpow_hashrate,
    int64_t block_time = DefaultBlockTime())
{
    return (static_cast<double>(block_time) / 600.0) *
        ((permissionless_hashrate + auxpow_hashrate) / btc_hashrate);
}

int ExpectedRequiredConfirmations(int btc_target, double security_per_conf, double orphan_rate = 0.0)
{
    return static_cast<int>(std::ceil(static_cast<double>(btc_target) / security_per_conf * (1.0 / (1.0 - orphan_rate))));
}

/** Helper: compute result for a given security level with common defaults. */
ConfirmationResult Calc(
    const std::string& level,
    double merge_mining_pct,
    double orphan_rate = 0.0,
    double btc_hashrate = 7e20,
    double permissionless_hashrate = 1e12,
    int64_t value_satoshis = 100000000,
    int64_t block_time = DefaultBlockTime(),
    int64_t legacy_spacing = DefaultLegacySpacing(),
    int64_t auxpow_spacing = DefaultAuxPowSpacing())
{
    return ConfirmationCalculator::Calculate(
        value_satoshis, level, /*use_observed_hashrate=*/false, merge_mining_pct, btc_hashrate,
        permissionless_hashrate, /*auxpow_hashrate=*/0.0, orphan_rate,
        block_time, legacy_spacing, auxpow_spacing);
}

ConfirmationResult CalcObserved(
    const std::string& level,
    double btc_hashrate,
    double permissionless_hashrate,
    double auxpow_hashrate,
    double orphan_rate = 0.0,
    int64_t block_time = DefaultBlockTime())
{
    return ConfirmationCalculator::Calculate(
        /*value_satoshis=*/100000000, level, /*use_observed_hashrate=*/true,
        /*merge_mining_pct=*/0.0, btc_hashrate, permissionless_hashrate, auxpow_hashrate,
        orphan_rate, block_time, DefaultLegacySpacing(), DefaultAuxPowSpacing());
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(confirmation_target_tests, BasicTestingSetup)

// ── BtcTargetForLevel ────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(level_low)
{
    BOOST_CHECK_EQUAL(ConfirmationCalculator::BtcTargetForLevel("low"), 1);
}

BOOST_AUTO_TEST_CASE(level_medium)
{
    BOOST_CHECK_EQUAL(ConfirmationCalculator::BtcTargetForLevel("medium"), 3);
}

BOOST_AUTO_TEST_CASE(level_high)
{
    BOOST_CHECK_EQUAL(ConfirmationCalculator::BtcTargetForLevel("high"), 6);
}

BOOST_AUTO_TEST_CASE(level_maximum)
{
    BOOST_CHECK_EQUAL(ConfirmationCalculator::BtcTargetForLevel("maximum"), 60);
}

BOOST_AUTO_TEST_CASE(level_unknown)
{
    BOOST_CHECK_EQUAL(ConfirmationCalculator::BtcTargetForLevel("unknown"), -1);
    BOOST_CHECK_EQUAL(ConfirmationCalculator::BtcTargetForLevel(""), -1);
}

BOOST_AUTO_TEST_CASE(calculate_unknown_level_falls_back_to_maximum)
{
    const auto result = Calc("unknown", 0.5);
    const double expected_security = ExpectedSecurityPerConf(0.5);
    BOOST_CHECK_EQUAL(result.security_level, "maximum");
    BOOST_CHECK_EQUAL(result.btc_target_confirmations, ConfirmationCalculator::BTC_CONFS_MAXIMUM);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_MAXIMUM, expected_security));
}

// ── Derived-cadence reference examples ───────────────────────────

BOOST_AUTO_TEST_CASE(derived_cadence_50pct_merge_mining)
{
    const auto result = Calc("high", 0.5);
    const double expected_security = ExpectedSecurityPerConf(0.5);
    const int expected_required = ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected_security);

    BOOST_CHECK_EQUAL(result.required_confirmations, expected_required);
    BOOST_CHECK_CLOSE(result.equivalent_btc_confirmations,
                      static_cast<double>(expected_required) * expected_security, 1e-6);
    BOOST_CHECK_CLOSE(result.security_per_confirmation, expected_security, 1e-6);
}

BOOST_AUTO_TEST_CASE(derived_cadence_5pct_merge_mining)
{
    const auto result = Calc("high", 0.05);
    const double expected_security = ExpectedSecurityPerConf(0.05);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected_security));
}

BOOST_AUTO_TEST_CASE(derived_cadence_1pct_merge_mining)
{
    const auto result_medium = Calc("medium", 0.01);
    const double expected_security = ExpectedSecurityPerConf(0.01);
    BOOST_CHECK_EQUAL(result_medium.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_MEDIUM, expected_security));
    BOOST_CHECK(result_medium.required_confirmations > 100);

    const auto result_low = Calc("low", 0.01);
    BOOST_CHECK_EQUAL(result_low.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_LOW, expected_security));
    BOOST_CHECK(result_low.required_confirmations > 100);
}

// ── Security levels produce increasing confirmations ─────────────

BOOST_AUTO_TEST_CASE(security_levels_monotonic)
{
    const auto low = Calc("low", 0.3);
    const auto med = Calc("medium", 0.3);
    const auto high = Calc("high", 0.3);
    const auto max = Calc("maximum", 0.3);

    BOOST_CHECK(low.required_confirmations < med.required_confirmations);
    BOOST_CHECK(med.required_confirmations < high.required_confirmations);
    BOOST_CHECK(high.required_confirmations < max.required_confirmations);
}

// ── Merge mining percentage effects ──────────────────────────────

BOOST_AUTO_TEST_CASE(more_merge_mining_fewer_confs)
{
    const auto low_mm = Calc("high", 0.05);
    const auto mid_mm = Calc("high", 0.25);
    const auto high_mm = Calc("high", 0.50);

    BOOST_CHECK(high_mm.required_confirmations < mid_mm.required_confirmations);
    BOOST_CHECK(mid_mm.required_confirmations < low_mm.required_confirmations);
}

BOOST_AUTO_TEST_CASE(merge_mining_100pct)
{
    const auto result = Calc("high", 1.0);
    const double expected_security = ExpectedSecurityPerConf(1.0);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected_security));
    BOOST_CHECK_CLOSE(result.security_per_confirmation, expected_security, 1e-4);
}

// ── Orphan rate effects ──────────────────────────────────────────

BOOST_AUTO_TEST_CASE(orphan_rate_increases_confs)
{
    const auto clean = Calc("high", 0.5, 0.0);
    const auto moderate = Calc("high", 0.5, 0.05);
    const auto high = Calc("high", 0.5, 0.10);

    BOOST_CHECK(clean.required_confirmations <= moderate.required_confirmations);
    BOOST_CHECK(moderate.required_confirmations <= high.required_confirmations);
}

BOOST_AUTO_TEST_CASE(orphan_rate_8pct)
{
    const auto result = Calc("high", 0.5, 0.08);
    const double expected_security = ExpectedSecurityPerConf(0.5);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected_security, 0.08));
    BOOST_CHECK_CLOSE(result.orphan_rate_penalty, 1.0 / 0.92, 1e-6);
}

BOOST_AUTO_TEST_CASE(orphan_rate_clamped_at_99pct)
{
    // Orphan rate is clamped to 0.99 to prevent division by zero.
    const auto result = Calc("low", 0.5, 1.0);
    BOOST_CHECK(result.required_confirmations > 0);
    BOOST_CHECK_CLOSE(result.orphan_rate, 0.99, 1e-6);
    BOOST_CHECK_CLOSE(result.orphan_rate_penalty, 100.0, 1e-6);
}

// ── Zero merge mining (launch scenario) ──────────────────────────

BOOST_AUTO_TEST_CASE(zero_merge_mining_uses_native_hashrate)
{
    const auto result = Calc("high", 0.0, 0.0, 7e20, 1e12);
    BOOST_CHECK_EQUAL(result.required_confirmations, 100000);
    // equivalent_btc must reflect the clamped count, not the target.
    BOOST_CHECK(result.equivalent_btc_confirmations < 6.0);
}

BOOST_AUTO_TEST_CASE(zero_merge_mining_zero_native)
{
    // Both merge mining and native hashrate are zero.
    // Falls back to block-time-ratio scaling: ceil(6 * 10) = 60
    const auto result = Calc("high", 0.0, 0.0, 7e20, 0.0);
    BOOST_CHECK_EQUAL(result.required_confirmations, 60);
}

BOOST_AUTO_TEST_CASE(zero_merge_mining_zero_native_applies_orphan_penalty_to_equivalent_btc)
{
    const auto result = Calc("high", 0.0, 0.08, 7e20, 0.0);
    const double block_time_ratio = 600.0 / static_cast<double>(result.block_time_seconds);
    const double expected = static_cast<double>(result.required_confirmations) / block_time_ratio / result.orphan_rate_penalty;
    BOOST_CHECK_CLOSE(result.equivalent_btc_confirmations, expected, 1e-6);
}

BOOST_AUTO_TEST_CASE(zero_merge_mining_zero_native_respects_block_time_ratio)
{
    // At 120s qbit blocks: ratio = 600 / 120 = 5, so high (6 BTC conf target)
    // falls back to ceil(6 * 5) = 30 confirmations.
    const auto result = Calc("high", 0.0, 0.0, 7e20, 0.0, 100000000, 120);
    BOOST_CHECK_EQUAL(result.required_confirmations, 30);
}

BOOST_AUTO_TEST_CASE(merged_mining_with_zero_native_uses_merged_term_only)
{
    const auto result = Calc("high", 0.5, 0.0, 7e20, 0.0);
    const double expected_security = DefaultCadenceMergedFraction() * 0.5;
    BOOST_CHECK_CLOSE(result.security_per_confirmation, expected_security, 1e-12);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected_security));
}

BOOST_AUTO_TEST_CASE(permissionless_hashrate_excludes_auxpow_work)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/0);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/60);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/120);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/180);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/240);

    const double proof = GetBlockProof(*test_chain.chain.Tip()).getdouble();
    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/4, /*height=*/-1, test_chain.chain),
                      proof * 4.0 / 240.0,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/4, /*height=*/-1, test_chain.chain),
                      proof * 2.0 / 240.0,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/4, /*height=*/-1, test_chain.chain),
                      proof * 2.0 / 240.0,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/4, /*height=*/-1, test_chain.chain),
                      EstimatePermissionlessNetworkHashPS(/*lookup=*/4, /*height=*/-1, test_chain.chain) +
                          EstimateAuxpowNetworkHashPS(/*lookup=*/4, /*height=*/-1, test_chain.chain),
                      1e-12);
}

BOOST_AUTO_TEST_CASE(hashrate_lane_windows_use_active_chain_time_and_exact_lookup_blocks)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/100, /*bits=*/0x207fffff); // ancestor, not counted for lookup=3
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/150, /*bits=*/0x207fffff); // active-chain time endpoint only
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/200, /*bits=*/0x1f7fffff);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/250, /*bits=*/0x1e7fffff);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/400, /*bits=*/0x1f00ffff);

    BOOST_CHECK(test_chain.Block(2).SignalsAuxpow());
    BOOST_CHECK(!test_chain.Block(2).IsPermissionless());
    BOOST_CHECK(!test_chain.Block(3).SignalsAuxpow());
    BOOST_CHECK(test_chain.Block(3).IsPermissionless());

    const double span = 250.0; // max/min over heights 1..4, not only same-lane blocks.
    const double auxpow_work = test_chain.Work(2) + test_chain.Work(4);
    const double permissionless_work = test_chain.Work(3);
    const double total_work = auxpow_work + permissionless_work;

    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      total_work / span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      permissionless_work / span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      auxpow_work / span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      EstimatePermissionlessNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain) +
                          EstimateAuxpowNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      1e-12);
}

BOOST_AUTO_TEST_CASE(auxpow_only_hashrate_window_has_zero_permissionless_work)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/0);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/1);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/2);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/3);

    BOOST_CHECK(EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain) > 0.0);
    BOOST_CHECK_EQUAL(EstimatePermissionlessNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain), 0.0);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      1e-12);
}

BOOST_AUTO_TEST_CASE(permissionless_only_hashrate_window_has_zero_auxpow_work)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/0);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/1);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/2);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/3);

    BOOST_CHECK(EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain) > 0.0);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      1e-12);
    BOOST_CHECK_EQUAL(EstimateAuxpowNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain), 0.0);
}

BOOST_AUTO_TEST_CASE(hashrate_boundary_height_historical_and_truncated_lookups)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/100, /*bits=*/0x207fffff);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/130, /*bits=*/0x1f7fffff);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/190, /*bits=*/0x1e7fffff);

    BOOST_CHECK_EQUAL(EstimateNetworkHashPS(/*lookup=*/120, /*height=*/0, test_chain.chain), 0.0);
    BOOST_CHECK_EQUAL(EstimatePermissionlessNetworkHashPS(/*lookup=*/120, /*height=*/0, test_chain.chain), 0.0);
    BOOST_CHECK_EQUAL(EstimateAuxpowNetworkHashPS(/*lookup=*/120, /*height=*/0, test_chain.chain), 0.0);

    const double height_one_span = 30.0;
    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/120, /*height=*/1, test_chain.chain),
                      test_chain.Work(1) / height_one_span,
                      1e-12);
    BOOST_CHECK_EQUAL(EstimatePermissionlessNetworkHashPS(/*lookup=*/120, /*height=*/1, test_chain.chain), 0.0);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/120, /*height=*/1, test_chain.chain),
                      test_chain.Work(1) / height_one_span,
                      1e-12);

    const double tip_one_block_span = 60.0;
    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/1, /*height=*/2, test_chain.chain),
                      test_chain.Work(2) / tip_one_block_span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/1, /*height=*/2, test_chain.chain),
                      test_chain.Work(2) / tip_one_block_span,
                      1e-12);
    BOOST_CHECK_EQUAL(EstimateAuxpowNetworkHashPS(/*lookup=*/1, /*height=*/2, test_chain.chain), 0.0);

    const double truncated_span = 90.0;
    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/100, /*height=*/2, test_chain.chain),
                      (test_chain.Work(1) + test_chain.Work(2)) / truncated_span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/100, /*height=*/2, test_chain.chain),
                      test_chain.Work(2) / truncated_span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/100, /*height=*/2, test_chain.chain),
                      test_chain.Work(1) / truncated_span,
                      1e-12);
}

BOOST_AUTO_TEST_CASE(hashrate_asert_minus_one_uses_one_block_window)
{
    BOOST_REQUIRE(Params().GetConsensus().fPowUseASERT);

    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/100);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/160);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/220);

    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/-1, /*height=*/-1, test_chain.chain),
                      EstimateNetworkHashPS(/*lookup=*/1, /*height=*/-1, test_chain.chain),
                      1e-12);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/-1, /*height=*/-1, test_chain.chain),
                      EstimatePermissionlessNetworkHashPS(/*lookup=*/1, /*height=*/-1, test_chain.chain),
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/-1, /*height=*/-1, test_chain.chain),
                      EstimateAuxpowNetworkHashPS(/*lookup=*/1, /*height=*/-1, test_chain.chain),
                      1e-12);
}

BOOST_AUTO_TEST_CASE(hashrate_identical_timestamps_return_zero_elapsed_estimate)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/42);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/42);

    BOOST_CHECK_EQUAL(EstimateNetworkHashPS(/*lookup=*/1, /*height=*/-1, test_chain.chain), 0.0);
    BOOST_CHECK_EQUAL(EstimatePermissionlessNetworkHashPS(/*lookup=*/1, /*height=*/-1, test_chain.chain), 0.0);
    BOOST_CHECK_EQUAL(EstimateAuxpowNetworkHashPS(/*lookup=*/1, /*height=*/-1, test_chain.chain), 0.0);
}

BOOST_AUTO_TEST_CASE(hashrate_non_monotonic_timestamps_use_min_max_elapsed_window)
{
    HashrateTestChain test_chain;
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/100);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/200);
    test_chain.AddBlock(/*auxpow=*/true, /*time=*/150);
    test_chain.AddBlock(/*auxpow=*/false, /*time=*/175);

    const double span = 100.0; // max/min over heights 0..3.
    const double permissionless_work = test_chain.Work(1) + test_chain.Work(3);
    const double auxpow_work = test_chain.Work(2);

    BOOST_CHECK_CLOSE(EstimateNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      (permissionless_work + auxpow_work) / span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimatePermissionlessNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      permissionless_work / span,
                      1e-12);
    BOOST_CHECK_CLOSE(EstimateAuxpowNetworkHashPS(/*lookup=*/3, /*height=*/-1, test_chain.chain),
                      auxpow_work / span,
                      1e-12);
}

// ── Clamping and edge cases ──────────────────────────────────────

BOOST_AUTO_TEST_CASE(min_confirmations_floor)
{
    // Even with enormous merge mining, should never go below 1.
    const auto result = Calc("low", 1.0, 0.0, 7e20, 7e20);
    BOOST_CHECK(result.required_confirmations >= 1);
}

BOOST_AUTO_TEST_CASE(max_confirmations_cap)
{
    const auto result = Calc("maximum", 0.001);
    const double expected_security = ExpectedSecurityPerConf(0.001);
    BOOST_CHECK_EQUAL(result.required_confirmations, 100000);
    BOOST_CHECK_CLOSE(result.equivalent_btc_confirmations,
                      static_cast<double>(ConfirmationCalculator::MAX_CONFIRMATIONS) * expected_security, 1.0);
    BOOST_CHECK(result.equivalent_btc_confirmations < 60.0);
}

BOOST_AUTO_TEST_CASE(no_int_overflow_on_tiny_security)
{
    // With extremely small security_per_conf, raw >> INT_MAX.
    // Must not trigger undefined behaviour from double-to-int cast.
    // security_per_conf ≈ 5e-22, raw ≈ 1.2e22 — well above INT_MAX.
    const auto result = Calc("high", 0.0, 0.0, 7e20, 1e-1);
    BOOST_CHECK_EQUAL(result.required_confirmations, 100000);
    BOOST_CHECK(result.equivalent_btc_confirmations < 6.0);
}

BOOST_AUTO_TEST_CASE(negative_orphan_rate_clamped)
{
    const auto result = Calc("medium", 0.5, -0.5);
    BOOST_CHECK_CLOSE(result.orphan_rate, 0.0, 1e-12);
    BOOST_CHECK_CLOSE(result.orphan_rate_penalty, 1.0, 1e-12);
}

BOOST_AUTO_TEST_CASE(merge_mining_pct_clamped_above_1)
{
    const auto result = Calc("medium", 1.5);
    BOOST_CHECK_CLOSE(result.merge_mining_pct, 1.0, 1e-12);
}

BOOST_AUTO_TEST_CASE(merge_mining_pct_clamped_below_0)
{
    const auto result = Calc("medium", -0.5);
    BOOST_CHECK_CLOSE(result.merge_mining_pct, 0.0, 1e-12);
}

BOOST_AUTO_TEST_CASE(negative_btc_hashrate_uses_default)
{
    const auto result = Calc("medium", 0.5, 0.0, -1.0);
    BOOST_CHECK_CLOSE(result.btc_hashrate, ConfirmationCalculator::DEFAULT_BTC_HASHRATE, 1e-6);
}

BOOST_AUTO_TEST_CASE(zero_btc_hashrate_uses_default)
{
    const auto result = Calc("medium", 0.5, 0.0, 0.0);
    BOOST_CHECK_CLOSE(result.btc_hashrate, ConfirmationCalculator::DEFAULT_BTC_HASHRATE, 1e-6);
}

// ── Result fields ────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(required_minutes_calculation)
{
    const auto result = Calc("high", 0.5, 0.0, 7e20, 1e12, 100000000, 60);
    BOOST_CHECK_CLOSE(result.required_minutes, static_cast<double>(result.required_confirmations), 1e-6);
}

BOOST_AUTO_TEST_CASE(value_qbt_conversion)
{
    const auto result = Calc("medium", 0.5, 0.0, 7e20, 1e12, 250000000);
    BOOST_CHECK_CLOSE(result.value_qbt, 2.5, 1e-6);
}

BOOST_AUTO_TEST_CASE(model_fields_populated)
{
    const auto result = Calc("high", 0.5, 0.03, 7e20, 1e12, 100000000, 60);
    BOOST_CHECK_EQUAL(result.btc_target_confirmations, 6);
    BOOST_CHECK_EQUAL(result.block_time_seconds, 60);
    BOOST_CHECK_CLOSE(result.merge_mining_pct, 0.5, 1e-12);
    BOOST_CHECK_CLOSE(result.btc_hashrate, 7e20, 1e-6);
    BOOST_CHECK_CLOSE(result.cadence_merged_fraction, DefaultCadenceMergedFraction(), 1e-12);
    BOOST_CHECK_EQUAL(result.security_level, "high");
    BOOST_CHECK_CLOSE(result.permissionless_hashrate, 1e12, 1e-6);
    BOOST_CHECK_EQUAL(result.auxpow_hashrate, 0.0);
    BOOST_CHECK_CLOSE(result.total_observed_hashrate, 1e12, 1e-6);
    BOOST_CHECK_CLOSE(result.orphan_rate, 0.03, 1e-12);
}

BOOST_AUTO_TEST_CASE(different_block_time)
{
    // With 120s block time, same confs but required_minutes doubles.
    const auto r60 = Calc("high", 0.5, 0.0, 7e20, 1e12, 100000000, 60);
    const auto r120 = Calc("high", 0.5, 0.0, 7e20, 1e12, 100000000, 120);
    BOOST_CHECK_EQUAL(r60.required_confirmations, r120.required_confirmations);
    BOOST_CHECK_CLOSE(r120.required_minutes, r60.required_minutes * 2.0, 1e-6);
}

// ── Consistency: equivalent_btc_confirmations ────────────────────

BOOST_AUTO_TEST_CASE(equivalent_btc_confs_reflect_ceiling)
{
    for (const auto& level : {"low", "medium", "high", "maximum"}) {
        const auto result = Calc(level, 0.5);
        BOOST_CHECK(result.equivalent_btc_confirmations >= static_cast<double>(result.btc_target_confirmations));
        BOOST_CHECK(result.equivalent_btc_confirmations <
                    static_cast<double>(result.btc_target_confirmations) + result.security_per_confirmation);
    }
}

// ── Determinism ──────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(deterministic_same_inputs)
{
    const auto a = Calc("high", 0.3, 0.05);
    const auto b = Calc("high", 0.3, 0.05);
    BOOST_CHECK_EQUAL(a.required_confirmations, b.required_confirmations);
    BOOST_CHECK_CLOSE(a.required_minutes, b.required_minutes, 1e-12);
    BOOST_CHECK_CLOSE(a.security_per_confirmation, b.security_per_confirmation, 1e-12);
}

// ── Security per confirmation formula ────────────────────────────

BOOST_AUTO_TEST_CASE(security_per_conf_formula)
{
    const auto result = Calc("medium", 0.3, 0.0, 7e20, 1e15);
    const double expected = ExpectedSecurityPerConf(0.3, 7e20, 1e15);
    BOOST_CHECK_CLOSE(result.security_per_confirmation, expected, 1e-4);
}

BOOST_AUTO_TEST_CASE(observed_hashrate_security_per_conf_formula)
{
    const auto result = CalcObserved("high", /*btc_hashrate=*/1000.0,
                                    /*permissionless_hashrate=*/100.0,
                                    /*auxpow_hashrate=*/200.0,
                                    /*orphan_rate=*/0.0,
                                    /*block_time=*/60);
    const double expected = ExpectedObservedSecurityPerConf(1000.0, 100.0, 200.0, 60);
    BOOST_CHECK_CLOSE(result.security_per_confirmation, expected, 1e-12);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected));
}

BOOST_AUTO_TEST_CASE(observed_hashrate_does_not_apply_cadence_multiplier)
{
    const auto result = CalcObserved("high", /*btc_hashrate=*/1000.0,
                                    /*permissionless_hashrate=*/0.0,
                                    /*auxpow_hashrate=*/300.0,
                                    /*orphan_rate=*/0.0,
                                    /*block_time=*/60);
    const double expected = ExpectedObservedSecurityPerConf(1000.0, 0.0, 300.0, 60);
    const double cadence_weighted = DefaultCadenceMergedFraction() * (300.0 / 1000.0);
    BOOST_CHECK_CLOSE(result.security_per_confirmation, expected, 1e-12);
    BOOST_CHECK(result.security_per_confirmation < cadence_weighted);
}

BOOST_AUTO_TEST_CASE(significant_native_hashrate)
{
    const auto result = Calc("high", 0.0, 0.0, 1e18, 1e17);
    const double expected_security = ExpectedSecurityPerConf(0.0, 1e18, 1e17);
    BOOST_CHECK_EQUAL(result.required_confirmations,
                      ExpectedRequiredConfirmations(ConfirmationCalculator::BTC_CONFS_HIGH, expected_security));
}

BOOST_AUTO_TEST_SUITE_END()
