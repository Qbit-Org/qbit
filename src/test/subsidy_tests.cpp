// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <util/chaintype.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <utility>

namespace {
constexpr CAmount INITIAL_SUBSIDY{210 * COIN};
constexpr int MAIN_SUBSIDY_STEP_INTERVAL{43'200};
constexpr int REGTEST_SUBSIDY_STEP_INTERVAL{150};
constexpr int SUBSIDY_STEPDOWN_NUMERATOR{598};
constexpr int SUBSIDY_STEPDOWN_DENOMINATOR{625};
constexpr int LAST_NONZERO_REWARD_STEP{479};
constexpr int FIRST_ZERO_REWARD_STEP{480};

CAmount SubsidyAtStep(int step_count)
{
    CAmount subsidy{INITIAL_SUBSIDY};
    for (int step{0}; step < step_count && subsidy > 0; ++step) {
        subsidy = (subsidy * SUBSIDY_STEPDOWN_NUMERATOR) / SUBSIDY_STEPDOWN_DENOMINATOR;
    }
    return subsidy;
}

CAmount ComputeTotalEmission(const Consensus::Params& consensus_params)
{
    CAmount total{0};
    for (int step{0}; step <= FIRST_ZERO_REWARD_STEP; ++step) {
        const CAmount subsidy{GetBlockSubsidy(step * consensus_params.nSubsidyStepInterval, consensus_params)};
        if (subsidy == 0) break;
        total += subsidy * consensus_params.nSubsidyStepInterval;
    }
    return total;
}

void CheckStepdownParams(const Consensus::Params& consensus_params, int expected_step_interval)
{
    BOOST_CHECK_EQUAL(consensus_params.nSubsidyInitial, INITIAL_SUBSIDY);
    BOOST_CHECK_EQUAL(consensus_params.nSubsidyStepInterval, expected_step_interval);
    BOOST_CHECK_EQUAL(consensus_params.nSubsidyStepdownNumerator, SUBSIDY_STEPDOWN_NUMERATOR);
    BOOST_CHECK_EQUAL(consensus_params.nSubsidyStepdownDenominator, SUBSIDY_STEPDOWN_DENOMINATOR);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(subsidy_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(subsidy_genesis_full_reward)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.nSubsidyInitial, INITIAL_SUBSIDY);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensus), INITIAL_SUBSIDY);

    const std::array<int, 9> early_heights{0, 1, 2, 3, 10, 100, 1'000, 10'000, consensus.nSubsidyStepInterval - 1};
    for (const int height : early_heights) {
        BOOST_CHECK_EQUAL(GetBlockSubsidy(height, consensus), INITIAL_SUBSIDY);
    }
}

BOOST_AUTO_TEST_CASE(subsidy_uses_consensus_initial_reward)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus = main_params->GetConsensus();
    consensus.nSubsidyInitial = 42 * COIN;

    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensus), consensus.nSubsidyInitial);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensus.nSubsidyStepInterval - 1, consensus), consensus.nSubsidyInitial);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensus.nSubsidyStepInterval, consensus),
                      (consensus.nSubsidyInitial * consensus.nSubsidyStepdownNumerator) / consensus.nSubsidyStepdownDenominator);
}

BOOST_AUTO_TEST_CASE(subsidy_stepdown_does_not_overflow_money_range_initial_reward)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus = main_params->GetConsensus();
    consensus.nSubsidyInitial = MAX_MONEY;

    const CAmount expected_stepdown{
        (MAX_MONEY / consensus.nSubsidyStepdownDenominator) * consensus.nSubsidyStepdownNumerator
        + ((MAX_MONEY % consensus.nSubsidyStepdownDenominator) * consensus.nSubsidyStepdownNumerator) / consensus.nSubsidyStepdownDenominator};
    const CAmount subsidy{GetBlockSubsidy(consensus.nSubsidyStepInterval, consensus)};

    BOOST_CHECK(MoneyRange(subsidy));
    BOOST_CHECK_EQUAL(subsidy, expected_stepdown);
    BOOST_CHECK_LT(subsidy, MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(subsidy_step_boundaries)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();
    const int interval = consensus.nSubsidyStepInterval;
    BOOST_REQUIRE(interval > 0);

    for (int step{1}; step <= 12; ++step) {
        const int boundary_height{step * interval};
        const CAmount expected_before{SubsidyAtStep(step - 1)};
        const CAmount expected_at{SubsidyAtStep(step)};

        BOOST_CHECK_EQUAL(GetBlockSubsidy(boundary_height - 1, consensus), expected_before);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(boundary_height, consensus), expected_at);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(boundary_height + 1, consensus), expected_at);
    }
}

BOOST_AUTO_TEST_CASE(subsidy_representative_rewards)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();

    const std::array<std::pair<int, CAmount>, 14> rewards{{
        {0, 21'000'000'000},
        {1, 20'092'800'000},
        {2, 19'224'791'040},
        {3, 18'394'280'067},
        {12, 12'361'560'375},
        {53, 2'021'813'653},
        {68, 1'042'458'135},
        {105, 203'442'540},
        {157, 20'471'147},
        {209, 2'059'874},
        {261, 207'262},
        {313, 20'844},
        {479, 1},
        {480, 0},
    }};

    for (const auto& [step, expected_subsidy] : rewards) {
        BOOST_CHECK_EQUAL(GetBlockSubsidy(step * consensus.nSubsidyStepInterval, consensus), expected_subsidy);
    }
}

BOOST_AUTO_TEST_CASE(subsidy_zero_after_step_480)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();
    const int interval = consensus.nSubsidyStepInterval;
    BOOST_REQUIRE(interval > 0);

    BOOST_CHECK_EQUAL(GetBlockSubsidy(LAST_NONZERO_REWARD_STEP * interval, consensus), 1);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(FIRST_ZERO_REWARD_STEP * interval - 1, consensus), 1);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(FIRST_ZERO_REWARD_STEP * interval, consensus), 0);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(FIRST_ZERO_REWARD_STEP * interval + 1, consensus), 0);
    BOOST_CHECK_EQUAL(FIRST_ZERO_REWARD_STEP * interval, 20'736'000);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(-1, consensus), 0);
}

BOOST_AUTO_TEST_CASE(subsidy_network_step_params)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto testnet_params = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto testnet4_params = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const auto signet_params = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto regtest_params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    CheckStepdownParams(main_params->GetConsensus(), MAIN_SUBSIDY_STEP_INTERVAL);
    CheckStepdownParams(testnet_params->GetConsensus(), MAIN_SUBSIDY_STEP_INTERVAL);
    CheckStepdownParams(testnet4_params->GetConsensus(), MAIN_SUBSIDY_STEP_INTERVAL);
    CheckStepdownParams(signet_params->GetConsensus(), MAIN_SUBSIDY_STEP_INTERVAL);
    CheckStepdownParams(regtest_params->GetConsensus(), REGTEST_SUBSIDY_STEP_INTERVAL);
}

BOOST_AUTO_TEST_CASE(subsidy_regtest_step_boundaries)
{
    const auto regtest_params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const auto& consensus = regtest_params->GetConsensus();
    const int interval = consensus.nSubsidyStepInterval;
    BOOST_REQUIRE_EQUAL(interval, REGTEST_SUBSIDY_STEP_INTERVAL);

    for (int step{1}; step <= 3; ++step) {
        const int boundary_height{step * interval};
        const CAmount expected_before{SubsidyAtStep(step - 1)};
        const CAmount expected_at{SubsidyAtStep(step)};

        BOOST_CHECK_EQUAL(GetBlockSubsidy(boundary_height - 1, consensus), expected_before);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(boundary_height, consensus), expected_at);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(boundary_height + 1, consensus), expected_at);
    }
}

BOOST_AUTO_TEST_CASE(subsidy_total_emission)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();

    const CAmount total_emission{ComputeTotalEmission(consensus)};
    BOOST_CHECK_EQUAL(total_emission, CAmount{20'999'999'761'876'800});
    BOOST_CHECK_EQUAL(MAX_MONEY - total_emission, CAmount{238'123'200});
    BOOST_CHECK_LT(total_emission, MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(subsidy_max_reward_bound)
{
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = main_params->GetConsensus();
    const int interval = consensus.nSubsidyStepInterval;
    BOOST_REQUIRE(interval > 0);

    CAmount previous_subsidy{INITIAL_SUBSIDY};
    for (int step{0}; step <= FIRST_ZERO_REWARD_STEP + 2; ++step) {
        const int height{step * interval};
        const CAmount subsidy_at_height{GetBlockSubsidy(height, consensus)};
        const CAmount subsidy_after_height{GetBlockSubsidy(height + 1, consensus)};
        BOOST_CHECK(subsidy_at_height <= INITIAL_SUBSIDY);
        BOOST_CHECK(subsidy_at_height >= 0);
        BOOST_CHECK(subsidy_after_height <= INITIAL_SUBSIDY);
        BOOST_CHECK(subsidy_after_height >= 0);
        BOOST_CHECK(subsidy_at_height <= previous_subsidy);
        previous_subsidy = subsidy_at_height;
    }
}

BOOST_AUTO_TEST_SUITE_END()
