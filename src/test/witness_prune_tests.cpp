// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <stdexcept>

using node::BlockManager;
using node::KernelNotifications;

BOOST_FIXTURE_TEST_SUITE(witness_prune_tests, BasicTestingSetup)

static BlockManager::Options MakeBlockmanOptions(const CChainParams& chainparams,
                                                 KernelNotifications& notifications,
                                                 const ArgsManager& args)
{
    return BlockManager::Options{
        .chainparams = chainparams,
        .blocks_dir = args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
}

static BlockManager::Options MakeWitnessPruneBlockmanOptions(const CChainParams& chainparams,
                                                             KernelNotifications& notifications,
                                                             const ArgsManager& args)
{
    auto opts{MakeBlockmanOptions(chainparams, notifications, args)};
    opts.prune_witnesses = true;
    return opts;
}

static CBlock MakePowValidBlock(const CChainParams& chainparams, uint32_t time_delta, const uint256& prev_hash = uint256{})
{
    CBlock block{chainparams.GenesisBlock()};
    block.hashPrevBlock = prev_hash;
    block.nTime += time_delta;
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())) {
        ++block.nNonce;
    }
    return block;
}

static CBlockIndex& AddBlockIndex(BlockManager& blockman,
                                  const CBlock& block,
                                  const FlatFilePos& pos,
                                  int height,
                                  bool witness_pruned = false) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    auto [it, inserted] = blockman.m_block_index.try_emplace(block.GetHash());
    BOOST_REQUIRE(inserted);

    CBlockIndex& index{it->second};
    index.phashBlock = &it->first;
    index.nHeight = height;
    index.nFile = pos.nFile;
    index.nDataPos = pos.nPos;
    index.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    if (witness_pruned) index.nStatus |= BLOCK_OPT_WITNESS_PRUNED;
    index.nTx = 1;
    index.m_chain_tx_count = 1;
    return index;
}

static fs::path WitnessTempPath(const BlockManager& blockman, int file_number)
{
    const fs::path original_path{blockman.GetBlockPosFilename(FlatFilePos{file_number, 0})};
    return fs::PathFromString(fs::PathToString(original_path) + ".wpruned");
}

static fs::path WitnessBackupPath(const BlockManager& blockman, int file_number)
{
    const fs::path original_path{blockman.GetBlockPosFilename(FlatFilePos{file_number, 0})};
    return fs::PathFromString(fs::PathToString(original_path) + ".wfull");
}

static std::string ReadFileBytes(const fs::path& path)
{
    std::ifstream in{fs::PathToString(path), std::ios::binary};
    if (!in.good()) {
        throw std::runtime_error{"failed to read test file bytes"};
    }
    return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

BOOST_AUTO_TEST_CASE(witness_prune_mode_config)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};

    {
        auto default_opts{MakeBlockmanOptions(*params, notifications, m_args)};
        BlockManager default_blockman{*Assert(m_node.shutdown_signal), default_opts};
        BOOST_CHECK(!default_blockman.IsWitnessPruneMode());
    }
    {
        auto prune_opts{MakeBlockmanOptions(*params, notifications, m_args)};
        prune_opts.prune_witnesses = true;
        BlockManager prune_blockman{*Assert(m_node.shutdown_signal), prune_opts};
        BOOST_CHECK(prune_blockman.IsWitnessPruneMode());
    }
    {
        auto disabled_opts{MakeBlockmanOptions(*params, notifications, m_args)};
        disabled_opts.witness_pruning_enabled = false;
        BlockManager disabled_blockman{*Assert(m_node.shutdown_signal), disabled_opts};
        BOOST_CHECK(!disabled_blockman.IsWitnessPruneMode());
    }
}

BOOST_AUTO_TEST_CASE(witness_prune_status_helpers)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    CBlockIndex index;
    WITH_LOCK(::cs_main, {
        index.nStatus = BLOCK_HAVE_DATA;
        BOOST_CHECK(blockman.HasWitnessData(index));
        BOOST_CHECK(!blockman.IsWitnessPruned(index));

        index.nStatus |= BLOCK_OPT_WITNESS_PRUNED;
        BOOST_CHECK(blockman.IsWitnessPruned(index));
        BOOST_CHECK(!blockman.HasWitnessData(index));
    });
}

BOOST_AUTO_TEST_CASE(witness_prune_check_flag_roundtrip)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    WITH_LOCK(::cs_main, {
        BOOST_CHECK(!blockman.WitnessPruningCheckRequested());
        blockman.RequestWitnessPruningCheck();
        BOOST_CHECK(blockman.WitnessPruningCheckRequested());
        blockman.ClearWitnessPruningCheck();
        BOOST_CHECK(!blockman.WitnessPruningCheckRequested());
    });
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_removes_orphan_temp_file)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    fs::create_directories(opts.blocks_dir);
    const fs::path orphan_temp{opts.blocks_dir / "blk99999.dat.wpruned"};
    {
        std::ofstream out{fs::PathToString(orphan_temp), std::ios::binary};
        out << "temp";
    }
    BOOST_CHECK(fs::exists(orphan_temp));

    WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions());
    BOOST_CHECK(!fs::exists(orphan_temp));
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_ignores_non_data_index_entries)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/9)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, {
        CBlockIndex& index{AddBlockIndex(blockman, block, pos, /*height=*/1)};
        index.nStatus &= ~BLOCK_HAVE_DATA;
    });

    const fs::path temp_path{WitnessTempPath(blockman, pos.nFile)};
    {
        std::ofstream out{fs::PathToString(temp_path), std::ios::binary};
        out << "temp";
    }
    BOOST_CHECK(fs::exists(temp_path));

    WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions());
    BOOST_CHECK(!fs::exists(temp_path));
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_renames_committed_temp_file)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    fs::create_directories(opts.blocks_dir);
    const fs::path original_path{opts.blocks_dir / "blk00001.dat"};
    const fs::path temp_path{opts.blocks_dir / "blk00001.dat.wpruned"};

    {
        std::ofstream out{fs::PathToString(original_path), std::ios::binary};
        out << "original";
    }
    {
        std::ofstream out{fs::PathToString(temp_path), std::ios::binary};
        out << "replacement";
    }

    WITH_LOCK(::cs_main, {
        CBlockIndex& index{blockman.m_block_index.try_emplace(uint256::ONE).first->second};
        index.nFile = 1;
        index.nStatus = BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        blockman.RecoverPendingWitnessCompactions();
    });

    BOOST_CHECK(fs::exists(original_path));
    BOOST_CHECK(!fs::exists(temp_path));

    std::ifstream in{fs::PathToString(original_path), std::ios::binary};
    std::string content;
    in >> content;
    BOOST_CHECK_EQUAL(content, "replacement");
}

BOOST_AUTO_TEST_CASE(recovered_block_roundtrip_and_cleanup)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/11)};
    BOOST_CHECK(blockman.WriteRecoveredBlock(block));
    BOOST_CHECK(blockman.HaveRecoveredBlock(block.GetHash()));

    CBlock recovered;
    BOOST_CHECK(blockman.ReadRecoveredBlock(recovered, block.GetHash()));

    DataStream original_stream{};
    original_stream << TX_WITH_WITNESS(block);
    DataStream recovered_stream{};
    recovered_stream << TX_WITH_WITNESS(recovered);
    BOOST_CHECK_EQUAL_COLLECTIONS(original_stream.begin(), original_stream.end(),
                                  recovered_stream.begin(), recovered_stream.end());

    blockman.CleanupRecoveredBlocks();
    BOOST_CHECK(!blockman.HaveRecoveredBlock(block.GetHash()));
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_rolls_back_precommit_install)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/10)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    CBlockIndex* index_ptr{nullptr};
    unsigned int original_data_pos{0};
    WITH_LOCK(::cs_main, {
        CBlockIndex& index{AddBlockIndex(blockman, block, pos, /*height=*/1)};
        index_ptr = &index;
        original_data_pos = index.nDataPos;
    });

    const fs::path original_path{blockman.GetBlockPosFilename(FlatFilePos{pos.nFile, 0})};
    const fs::path backup_path{WitnessBackupPath(blockman, pos.nFile)};
    const std::string original_bytes{ReadFileBytes(original_path)};

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(blockman.InstallWitnessCompactionForTest());
    BOOST_CHECK(fs::exists(backup_path));

    WITH_LOCK(::cs_main, {
        index_ptr->nStatus &= ~BLOCK_OPT_WITNESS_PRUNED;
        index_ptr->nDataPos = original_data_pos;
    });

    WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions());
    BOOST_CHECK(!fs::exists(backup_path));
    BOOST_CHECK_EQUAL(ReadFileBytes(original_path), original_bytes);
    WITH_LOCK(::cs_main, {
        BOOST_CHECK(!(index_ptr->nStatus & BLOCK_OPT_WITNESS_PRUNED));
    });
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_finalizes_postcommit_cleanup)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/11)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));

    const fs::path original_path{blockman.GetBlockPosFilename(FlatFilePos{pos.nFile, 0})};
    const fs::path backup_path{WitnessBackupPath(blockman, pos.nFile)};

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(blockman.InstallWitnessCompactionForTest());
    BOOST_CHECK(fs::exists(backup_path));
    const std::string stripped_bytes{ReadFileBytes(original_path)};

    WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions());
    BOOST_CHECK(!fs::exists(backup_path));
    BOOST_CHECK_EQUAL(ReadFileBytes(original_path), stripped_bytes);
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_missing_fileinfo_is_retryable)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(!blockman.HasPendingWitnessCompactionForTest());

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/1)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(blockman.HasPendingWitnessCompactionForTest());
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_zero_size_file_advances_watermark)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/2)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));

    const unsigned int actual_size{blockman.GetBlockFileInfo(0)->nSize};
    blockman.GetBlockFileInfo(0)->nSize = 0;

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(!blockman.HasPendingWitnessCompactionForTest());

    blockman.GetBlockFileInfo(0)->nSize = actual_size;
    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(!blockman.HasPendingWitnessCompactionForTest());
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_empty_file_scan_keeps_candidate_eligible)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/3)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(!blockman.HasPendingWitnessCompactionForTest());

    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));
    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(blockman.HasPendingWitnessCompactionForTest());
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_temp_cleanup_and_open_failure)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/4)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));

    const fs::path temp_path{WitnessTempPath(blockman, pos.nFile)};
    fs::create_directories(temp_path);
    {
        std::ofstream out{fs::PathToString(temp_path / "sentinel"), std::ios::binary};
        out << "x";
    }

    BOOST_CHECK(!blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(fs::is_directory(temp_path));
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_read_failure_cleans_temp_file)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/5)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, {
        CBlockIndex& index{AddBlockIndex(blockman, block, pos, /*height=*/1)};
        ++index.nDataPos;
    });

    const fs::path temp_path{WitnessTempPath(blockman, pos.nFile)};
    BOOST_CHECK(!blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(!fs::exists(temp_path));
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_write_failure_paths)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};

    const auto exercise_failure = [&](auto inject_failure) {
        auto opts{MakeWitnessPruneBlockmanOptions(*params, notifications, m_args)};
        BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

        const CBlock block{MakePowValidBlock(*params, /*time_delta=*/6)};
        const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
        WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));

        inject_failure(blockman);
        const fs::path temp_path{WitnessTempPath(blockman, pos.nFile)};
        BOOST_CHECK(!blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
        BOOST_CHECK(!fs::exists(temp_path));
        BOOST_CHECK(!blockman.HasPendingWitnessCompactionForTest());
        blockman.ClearWitnessCompactionPrepareFailureForTest();
    };

    exercise_failure([](BlockManager& blockman) { blockman.InjectWitnessCompactionWriteFailureForTest(); });
    exercise_failure([](BlockManager& blockman) { blockman.InjectWitnessCompactionCommitFailureForTest(); });
    exercise_failure([](BlockManager& blockman) { blockman.InjectWitnessCompactionCloseFailureForTest(); });
}

BOOST_AUTO_TEST_CASE(witness_prune_prepare_skips_without_explicit_prune_mode)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/6)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1));

    BOOST_CHECK(blockman.PrepareWitnessCompactionForTest(opts.witness_prune_depth + 1));
    BOOST_CHECK(!blockman.HasPendingWitnessCompactionForTest());
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_ignores_invalid_temp_filename)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    fs::create_directories(opts.blocks_dir);
    const fs::path invalid_temp{opts.blocks_dir / "blk12x45.dat.wpruned"};
    {
        std::ofstream out{fs::PathToString(invalid_temp), std::ios::binary};
        out << "temp";
    }

    WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions());
    BOOST_CHECK(fs::exists(invalid_temp));
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_mixed_file_removes_temp_file)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/7)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1, /*witness_pruned=*/false));

    const fs::path original_path{blockman.GetBlockPosFilename(FlatFilePos{pos.nFile, 0})};
    const fs::path temp_path{WitnessTempPath(blockman, pos.nFile)};
    const auto original_size{fs::file_size(original_path)};
    {
        std::ofstream out{fs::PathToString(temp_path), std::ios::binary};
        out << "replacement";
    }

    WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions());
    BOOST_CHECK(!fs::exists(temp_path));
    BOOST_CHECK_EQUAL(fs::file_size(original_path), original_size);
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_rename_failure_throws)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    const CBlock block{MakePowValidBlock(*params, /*time_delta=*/8)};
    const FlatFilePos pos{blockman.WriteBlock(block, /*nHeight=*/1)};
    WITH_LOCK(::cs_main, AddBlockIndex(blockman, block, pos, /*height=*/1, /*witness_pruned=*/true));

    const fs::path original_path{blockman.GetBlockPosFilename(FlatFilePos{pos.nFile, 0})};
    const fs::path temp_path{WitnessTempPath(blockman, pos.nFile)};
    fs::remove(original_path);
    fs::create_directories(original_path);
    {
        std::ofstream out{fs::PathToString(original_path / "sentinel"), std::ios::binary};
        out << "x";
    }
    {
        std::ofstream out{fs::PathToString(temp_path), std::ios::binary};
        out << "replacement";
    }

    const auto recover = [&] { WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions()); };
    BOOST_CHECK_EXCEPTION(
        recover(),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()}.find("Failed to recover witness-compacted block file") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(witness_prune_recovery_stale_temp_removal_failure_throws)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    auto opts{MakeBlockmanOptions(*params, notifications, m_args)};
    BlockManager blockman{*Assert(m_node.shutdown_signal), opts};

    fs::create_directories(opts.blocks_dir);
    const fs::path stale_temp{opts.blocks_dir / "blk00002.dat.wpruned"};
    {
        std::ofstream out{fs::PathToString(stale_temp), std::ios::binary};
        out << "temp";
    }

    const auto old_perms{fs::status(opts.blocks_dir).permissions()};
    fs::permissions(opts.blocks_dir, fs::perms::owner_read | fs::perms::owner_exec, fs::perm_options::replace);

    const fs::path probe_path{opts.blocks_dir / "remove_probe.tmp"};
    {
        std::ofstream out{fs::PathToString(probe_path), std::ios::binary};
        out << "probe";
    }
    std::error_code probe_ec;
    const bool probe_removed{fs::remove(probe_path, probe_ec)};
    if (probe_removed || !probe_ec) {
        fs::permissions(opts.blocks_dir, old_perms, fs::perm_options::replace);
        BOOST_TEST_MESSAGE("Skipping stale temp removal failure path: filesystem permissions permit removal");
        return;
    }

    const auto recover = [&] { WITH_LOCK(::cs_main, blockman.RecoverPendingWitnessCompactions()); };
    BOOST_CHECK_EXCEPTION(
        recover(),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()}.find("Failed to remove stale witness compaction temp file") != std::string::npos;
        });

    fs::permissions(opts.blocks_dir, old_perms, fs::perm_options::replace);
}

BOOST_AUTO_TEST_SUITE_END()
