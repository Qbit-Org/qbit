// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <node/kernel_notifications.h>
#include <validation.h>
#include <validationinterface.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

BOOST_AUTO_TEST_SUITE(chainstate_write_tests)

BOOST_FIXTURE_TEST_CASE(chainstate_write_interval, TestingSetup)
{
    struct TestSubscriber final : CValidationInterface {
        bool m_did_flush{false};
        void ChainStateFlushed(ChainstateRole, const CBlockLocator&) override
        {
            m_did_flush = true;
        }
    };

    const auto sub{std::make_shared<TestSubscriber>()};
    m_node.validation_signals->RegisterSharedValidationInterface(sub);
    auto& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    BlockValidationState state_dummy{};

    // The first periodic flush sets m_next_write and does not flush
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    // The periodic flush interval is between 50 and 70 minutes (inclusive)
    SetMockTime(GetTime<std::chrono::minutes>() + 49min);
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(!sub->m_did_flush);

    SetMockTime(GetTime<std::chrono::minutes>() + 70min);
    chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(sub->m_did_flush);
}

BOOST_FIXTURE_TEST_CASE(chainstate_witness_compaction_error_path, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& notifications{*Assert(m_node.notifications)};
    notifications.m_shutdown_on_fatal_error = false;

    chainman.m_blockman.SetPendingWitnessCompactionForTest(
        std::make_pair(fs::path{"blk00001.dat.wpruned"}, fs::path{"blk00001.dat"}));
    WITH_LOCK(::cs_main, chainman.m_blockman.RequestWitnessPruningCheck());

    chainman.m_blockman.ForceWitnessCompactionFailureForTest(true);
    BlockValidationState state{};
    BOOST_CHECK(!chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS));
    chainman.m_blockman.ForceWitnessCompactionFailureForTest(false);
    chainman.m_blockman.SetPendingWitnessCompactionForTest(std::nullopt);

    BOOST_CHECK(state.IsError());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "Witness compaction handoff failed. Will retry on restart.");
}

BOOST_FIXTURE_TEST_CASE(chainstate_witness_compaction_cleanup_failure_path, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& notifications{*Assert(m_node.notifications)};
    notifications.m_shutdown_on_fatal_error = false;

    const fs::path blocks_dir{m_node.args->GetBlocksDirPath()};
    fs::create_directories(blocks_dir);
    const fs::path temp_path{blocks_dir / "blk00001.dat.wpruned"};
    const fs::path original_path{blocks_dir / "blk00001.dat"};
    const fs::path backup_path{blocks_dir / "blk00001.dat.wfull"};
    {
        std::ofstream out{fs::PathToString(original_path), std::ios::binary};
        out << "replacement";
    }
    fs::create_directories(backup_path);
    {
        std::ofstream out{fs::PathToString(backup_path / "sentinel"), std::ios::binary};
        out << "x";
    }

    chainman.m_blockman.SetPendingWitnessCompactionForTest(std::make_pair(temp_path, original_path), /*installed=*/true);
    WITH_LOCK(::cs_main, chainman.m_blockman.RequestWitnessPruningCheck());

    BlockValidationState state{};
    BOOST_CHECK(!chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS));
    chainman.m_blockman.SetPendingWitnessCompactionForTest(std::nullopt);

    BOOST_CHECK(state.IsError());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "Witness compaction handoff failed. Will retry on restart.");
}

BOOST_AUTO_TEST_SUITE_END()
