// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <kernel/disconnected_transactions.h>
#include <node/chainstatemanager_args.h>
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/result.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <tinyformat.h>
#include <util/fs.h>

#include <fstream>
#include <optional>
#include <vector>

#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

namespace {
class BlockCheckedStateCatcher final : public CValidationInterface
{
public:
    explicit BlockCheckedStateCatcher(uint256 hash) : m_hash{std::move(hash)} {}

    std::optional<BlockValidationState> m_state;

private:
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
    {
        if (block->GetHash() == m_hash) {
            m_state = state;
        }
    }

    const uint256 m_hash;
};
} // namespace

static bool HasAssumeutxoData()
{
    return !Params().GetAvailableSnapshotHeights().empty();
}

static CBlockIndex& InsertTestBlockIndex(ChainstateManager& chainman, const uint256& hash, CBlockIndex* prev, int height, uint32_t n_bits, const arith_uint256& chain_work) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    auto [it, inserted] = chainman.m_blockman.m_block_index.try_emplace(hash);
    BOOST_REQUIRE(inserted);

    CBlockIndex& index = it->second;
    index.phashBlock = &it->first;
    index.pprev = prev;
    index.nHeight = height;
    index.nBits = n_bits;
    index.nChainWork = chain_work;
    index.nTx = 1;
    index.m_chain_tx_count = prev ? prev->m_chain_tx_count + 1 : 1;
    index.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    index.BuildSkip();
    return index;
}

//! Basic tests for ChainstateManager.
//!
//! First create a legacy (IBD) chainstate, then create a snapshot chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;
    std::vector<Chainstate*> chainstates;

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);

    BOOST_CHECK(!manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    auto all = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all.begin(), all.end(), chainstates.begin(), chainstates.end());

    auto& active_chain = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain, &c1.m_chain);

    // Mine 10 more blocks on top of the COINBASE_MATURITY blocks from TestChain100Setup.
    mineBlocks(10);
    const int expected_height = COINBASE_MATURITY + 10;
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), expected_height);
    auto active_tip = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    auto exp_tip = c1.m_chain.Tip();
    BOOST_CHECK_EQUAL(active_tip, exp_tip);

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a snapshot-based chainstate.
    //
    const uint256 snapshot_blockhash = active_tip->GetBlockHash();
    Chainstate& c2 = WITH_LOCK(::cs_main, return manager.ActivateExistingSnapshot(snapshot_blockhash));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);
    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        c2.CoinsTip().SetBestBlock(active_tip->GetBlockHash());
        c2.setBlockIndexCandidates.insert(manager.m_blockman.LookupBlockIndex(active_tip->GetBlockHash()));
        c2.LoadChainTip();
    }
    BlockValidationState _;
    BOOST_CHECK(c2.ActivateBestChain(_, nullptr));

    BOOST_CHECK_EQUAL(manager.SnapshotBlockhash().value(), snapshot_blockhash);
    BOOST_CHECK(manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    BOOST_CHECK_EQUAL(&c2, &manager.ActiveChainstate());
    BOOST_CHECK(&c1 != &manager.ActiveChainstate());
    auto all2 = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all2.begin(), all2.end(), chainstates.begin(), chainstates.end());

    auto& active_chain2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain2, &c2.m_chain);

    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), expected_height);
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), expected_height + 1);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return c1.m_chain.Height()), expected_height);

    auto active_tip2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    BOOST_CHECK_EQUAL(active_tip, active_tip2->pprev);
    BOOST_CHECK_EQUAL(active_tip, c1.m_chain.Tip());
    BOOST_CHECK_EQUAL(active_tip2, c2.m_chain.Tip());

    // Let scheduler events finish running to avoid accessing memory that is going to be unloaded
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

//! Test rebalancing the caches associated with each chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebalance_caches, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;

    size_t max_cache = 10000;
    manager.m_total_coinsdb_cache = max_cache;
    manager.m_total_coinstip_cache = max_cache;

    std::vector<Chainstate*> chainstates;

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);
    {
        LOCK(::cs_main);
        c1.InitCoinsCache(1 << 23);
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, max_cache);
    BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, max_cache);

    // Create a snapshot-based chainstate.
    //
    CBlockIndex* snapshot_base{WITH_LOCK(manager.GetMutex(), return manager.ActiveChain()[manager.ActiveChain().Height() / 2])};
    Chainstate& c2 = WITH_LOCK(cs_main, return manager.ActivateExistingSnapshot(*snapshot_base->phashBlock));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);

    // Reset IBD state so IsInitialBlockDownload() returns true and causes
    // MaybeRebalancesCaches() to prioritize the snapshot chainstate, giving it
    // more cache space than the snapshot chainstate. Calling ResetIbd() is
    // necessary because m_cached_finished_ibd is already latched to true before
    // the test starts due to the test setup. After ResetIbd() is called.
    // IsInitialBlockDownload will return true because at this point the active
    // chainstate has a null chain tip.
    static_cast<TestChainstateManager&>(manager).ResetIbd();

    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_CLOSE(double(c1.m_coinstip_cache_size_bytes), max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(double(c1.m_coinsdb_cache_size_bytes), max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(double(c2.m_coinstip_cache_size_bytes), max_cache * 0.95, 1);
    BOOST_CHECK_CLOSE(double(c2.m_coinsdb_cache_size_bytes), max_cache * 0.95, 1);
}

BOOST_FIXTURE_TEST_CASE(needs_witness_for_validation_gate, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& test_chainman{static_cast<TestChainstateManager&>(chainman)};

    WITH_LOCK(::cs_main, {
        const uint32_t n_bits{chainman.ActiveChain()[0]->nBits};
        CBlockIndex proof_index;
        proof_index.nBits = n_bits;
        const arith_uint256 proof{GetBlockProof(proof_index)};
        BOOST_REQUIRE(proof != 0);

        auto& mutable_opts = const_cast<ChainstateManager::Options&>(chainman.m_options);
        mutable_opts.minimum_chain_work = proof;

        auto& base = InsertTestBlockIndex(chainman, uint256{1}, nullptr, 0, n_bits, proof);
        auto& candidate = InsertTestBlockIndex(chainman, uint256{2}, &base, 1, n_bits, proof * 2);
        auto& assumed = InsertTestBlockIndex(chainman, uint256{3}, &candidate, 2, n_bits, proof * 3);

        mutable_opts.assumed_valid_block = uint256::ZERO;
        chainman.m_best_header = &assumed;
        BOOST_CHECK(chainman.NeedsWitnessForValidation(candidate));

        mutable_opts.assumed_valid_block = assumed.GetBlockHash();
        BOOST_CHECK(!chainman.NeedsWitnessForValidation(candidate));
        BOOST_CHECK(!test_chainman.CanSkipScriptChecksForTest(candidate, /*witness_unavailable=*/false));

        auto& best = InsertTestBlockIndex(chainman, uint256{4}, &assumed, 3, n_bits, assumed.nChainWork + proof * 2);
        chainman.m_best_header = &best;
        BOOST_CHECK(!chainman.NeedsWitnessForValidation(candidate));
        BOOST_CHECK(!test_chainman.CanSkipScriptChecksForTest(candidate, /*witness_unavailable=*/false));

        const int64_t burial_seconds{60 * 60 * 24 * 7 * 2};
        const int64_t burial_blocks{burial_seconds / chainman.GetConsensus().nPowTargetSpacing + 1};
        auto& buried = InsertTestBlockIndex(chainman, uint256{6}, &best, 4, n_bits, best.nChainWork + proof * burial_blocks);
        chainman.m_best_header = &buried;
        BOOST_CHECK(test_chainman.CanSkipScriptChecksForTest(candidate, /*witness_unavailable=*/false));

        auto& alternate = InsertTestBlockIndex(chainman, uint256{5}, &base, 1, n_bits, proof * 2);
        BOOST_CHECK(chainman.NeedsWitnessForValidation(alternate));
    });
}

BOOST_FIXTURE_TEST_CASE(assumevalid_covers_witness_pruned_history_gate, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};

    WITH_LOCK(::cs_main, {
        const uint32_t n_bits{chainman.ActiveChain()[0]->nBits};
        CBlockIndex proof_index;
        proof_index.nBits = n_bits;
        const arith_uint256 proof{GetBlockProof(proof_index)};
        BOOST_REQUIRE(proof != 0);

        auto& mutable_opts = const_cast<ChainstateManager::Options&>(chainman.m_options);
        mutable_opts.minimum_chain_work = proof;

        auto& base = InsertTestBlockIndex(chainman, uint256{10}, nullptr, 0, n_bits, proof);
        auto& highest_pruned = InsertTestBlockIndex(chainman, uint256{11}, &base, 1, n_bits, proof * 2);
        auto& assumed = InsertTestBlockIndex(chainman, uint256{12}, &highest_pruned, 2, n_bits, proof * 3);
        auto& best = InsertTestBlockIndex(chainman, uint256{13}, &assumed, 3, n_bits, proof * 4);
        highest_pruned.nStatus |= BLOCK_OPT_WITNESS_PRUNED;
        chainman.m_best_header = &best;

        mutable_opts.assumed_valid_block = uint256::ZERO;
        BOOST_CHECK(!chainman.CheckAssumeValidCoversWitnessPrunedHistory());

        mutable_opts.assumed_valid_block = uint256{14};
        BOOST_CHECK(!chainman.CheckAssumeValidCoversWitnessPrunedHistory());

        auto& alternate = InsertTestBlockIndex(chainman, uint256{15}, &base, 1, n_bits, proof * 2);
        mutable_opts.assumed_valid_block = alternate.GetBlockHash();
        BOOST_CHECK(!chainman.CheckAssumeValidCoversWitnessPrunedHistory());

        mutable_opts.assumed_valid_block = base.GetBlockHash();
        BOOST_CHECK(!chainman.CheckAssumeValidCoversWitnessPrunedHistory());

        mutable_opts.assumed_valid_block = highest_pruned.GetBlockHash();
        BOOST_CHECK(chainman.CheckAssumeValidCoversWitnessPrunedHistory());

        mutable_opts.assumed_valid_block = assumed.GetBlockHash();
        BOOST_CHECK(chainman.CheckAssumeValidCoversWitnessPrunedHistory());

        mutable_opts.minimum_chain_work = best.nChainWork + proof;
        BOOST_CHECK(!chainman.CheckAssumeValidCoversWitnessPrunedHistory());
    });
}

struct PreSegwitValidationSetup : TestingSetup {
    PreSegwitValidationSetup()
        : TestingSetup{ChainType::REGTEST, {.extra_args = {"-testactivationheight=segwit@200"}}}
    {
    }
};

BOOST_FIXTURE_TEST_CASE(needs_witness_for_validation_pre_segwit, PreSegwitValidationSetup)
{
    auto& chainman{*Assert(m_node.chainman)};

    WITH_LOCK(::cs_main, {
        const uint32_t n_bits{chainman.ActiveChain()[0]->nBits};
        CBlockIndex proof_index;
        proof_index.nBits = n_bits;
        const arith_uint256 proof{GetBlockProof(proof_index)};
        BOOST_REQUIRE(proof != 0);

        auto& candidate = InsertTestBlockIndex(chainman, uint256{42}, nullptr, 1, n_bits, proof);
        BOOST_CHECK(!chainman.NeedsWitnessForValidation(candidate));
    });
}

BOOST_FIXTURE_TEST_CASE(activatebestchainstep_schedules_recovery_for_witness_pruned_candidate_needing_witness, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    BlockValidationState state{};
    bool reset_most_work{false};
    CBlockIndex* active_tip{nullptr};
    CBlockIndex* candidate_ptr{nullptr};

    {
        LOCK2(::cs_main, *chainstate.MempoolMutex());
        active_tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(active_tip != nullptr);

        auto [it, inserted] = chainman.m_blockman.m_block_index.try_emplace(uint256{77});
        BOOST_REQUIRE(inserted);

        CBlockIndex& candidate{it->second};
        candidate_ptr = &candidate;
        candidate.phashBlock = &it->first;
        candidate.pprev = active_tip;
        candidate.nHeight = active_tip->nHeight + 1;
        candidate.nBits = active_tip->nBits;
        candidate.nChainWork = active_tip->nChainWork + GetBlockProof(*active_tip);
        candidate.nTx = 1;
        candidate.m_chain_tx_count = active_tip->m_chain_tx_count + 1;
        candidate.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        candidate.BuildSkip();

        BOOST_REQUIRE(candidate_ptr != nullptr);
        BOOST_CHECK(chainman.NeedsWitnessForValidation(*candidate_ptr));
        BOOST_CHECK(chainstate.ActivateBestChainStepForTest(state, candidate_ptr, reset_most_work));
        BOOST_REQUIRE(chainman.PendingWitnessRecovery() != nullptr);
        BOOST_CHECK_EQUAL(chainman.PendingWitnessRecovery()->GetBlockHash(), candidate_ptr->GetBlockHash());
    }
    BOOST_CHECK(reset_most_work);
    BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), active_tip);
}

BOOST_FIXTURE_TEST_CASE(activatebestchain_does_not_schedule_recovery_for_candidate_with_missing_ancestor, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* active_tip{nullptr};
    CBlockIndex* candidate_ptr{nullptr};

    {
        LOCK(::cs_main);
        active_tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(active_tip != nullptr);

        const arith_uint256 proof{GetBlockProof(*active_tip)};
        BOOST_REQUIRE(proof != 0);

        auto& missing_ancestor = InsertTestBlockIndex(
            chainman,
            uint256{78},
            active_tip,
            active_tip->nHeight + 1,
            active_tip->nBits,
            active_tip->nChainWork + proof);
        missing_ancestor.nStatus = BLOCK_VALID_SCRIPTS;

        auto& candidate = InsertTestBlockIndex(
            chainman,
            uint256{79},
            &missing_ancestor,
            missing_ancestor.nHeight + 1,
            active_tip->nBits,
            missing_ancestor.nChainWork + proof);
        candidate.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        candidate_ptr = &candidate;
        chainstate.setBlockIndexCandidates.insert(candidate_ptr);

        BOOST_REQUIRE(chainman.NeedsWitnessForValidation(candidate));
    }

    BlockValidationState state{};
    BOOST_CHECK(chainstate.ActivateBestChain(state));

    WITH_LOCK(::cs_main, {
        BOOST_CHECK_EQUAL(chainman.PendingWitnessRecovery(), nullptr);
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), active_tip);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_ptr), 0U);
    });
}

BOOST_FIXTURE_TEST_CASE(activatebestchain_replaces_stale_pending_witness_recovery, TestingSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* active_tip{nullptr};
    CBlockIndex* candidate_ptr{nullptr};

    {
        LOCK(::cs_main);
        active_tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(active_tip != nullptr);

        const arith_uint256 proof{GetBlockProof(*active_tip)};
        BOOST_REQUIRE(proof != 0);

        auto& stale = InsertTestBlockIndex(
            chainman,
            uint256{80},
            active_tip,
            active_tip->nHeight + 1,
            active_tip->nBits,
            active_tip->nChainWork + proof);
        stale.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        BOOST_REQUIRE(chainman.ScheduleWitnessRecovery(stale));

        auto& candidate = InsertTestBlockIndex(
            chainman,
            uint256{81},
            active_tip,
            active_tip->nHeight + 1,
            active_tip->nBits,
            active_tip->nChainWork + proof * 2);
        candidate.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        candidate_ptr = &candidate;
        chainstate.setBlockIndexCandidates.insert(candidate_ptr);

        BOOST_REQUIRE(chainman.NeedsWitnessForValidation(candidate));
        BOOST_REQUIRE_NE(chainman.PendingWitnessRecovery(), nullptr);
        BOOST_CHECK_EQUAL(chainman.PendingWitnessRecovery()->GetBlockHash(), stale.GetBlockHash());
    }

    BlockValidationState state{};
    BOOST_CHECK(chainstate.ActivateBestChain(state));

    WITH_LOCK(::cs_main, {
        BOOST_REQUIRE_NE(chainman.PendingWitnessRecovery(), nullptr);
        BOOST_CHECK_EQUAL(chainman.PendingWitnessRecovery()->GetBlockHash(), candidate_ptr->GetBlockHash());
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), active_tip);
    });
}

BOOST_FIXTURE_TEST_CASE(recovered_witness_retry, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const CBlock candidate_block{CreateBlock({}, P2MROpTrueScript(), chainstate)};
    const uint256 candidate_hash{candidate_block.GetHash()};
    const fs::path recovered_path{
        m_args.GetBlocksDirPath() / "recovered-witness" / fs::PathFromString(candidate_hash.ToString() + ".dat")
    };
    CBlockIndex* active_tip{nullptr};

    {
        LOCK(::cs_main);
        active_tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(active_tip != nullptr);

        const arith_uint256 proof{GetBlockProof(*active_tip)};
        BOOST_REQUIRE(proof != 0);

        auto& candidate = InsertTestBlockIndex(
            chainman,
            candidate_hash,
            active_tip,
            active_tip->nHeight + 1,
            candidate_block.nBits,
            active_tip->nChainWork + proof);
        candidate.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        chainman.m_best_header = &candidate;
        chainstate.setBlockIndexCandidates.insert(&candidate);

        BOOST_REQUIRE(chainman.NeedsWitnessForValidation(candidate));
        BOOST_REQUIRE(chainman.m_blockman.WriteRecoveredBlock(candidate_block));
        BOOST_REQUIRE(chainman.m_blockman.HaveRecoveredBlock(candidate_hash));
    }

    {
        std::ofstream recovered_file{fs::PathToString(recovered_path), std::ios::binary | std::ios::trunc};
        BOOST_REQUIRE(recovered_file.is_open());
        recovered_file << "corrupt";
        recovered_file.close();
    }

    BlockValidationState state{};
    BOOST_CHECK(chainstate.ActivateBestChain(state));
    BOOST_CHECK(state.IsValid());

    WITH_LOCK(::cs_main, {
        BOOST_REQUIRE_NE(chainman.PendingWitnessRecovery(), nullptr);
        BOOST_CHECK_EQUAL(chainman.PendingWitnessRecovery()->GetBlockHash(), candidate_hash);
        BOOST_CHECK(!chainman.m_blockman.HaveRecoveredBlock(candidate_hash));
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), active_tip);
    });
}

BOOST_FIXTURE_TEST_CASE(activatebestchain_recovery_error, TestChain100Setup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const CMutableTransaction funding_tx{
        CreateValidMempoolTransaction(
            m_coinbase_txns[0], 0, /*input_height=*/1, coinbaseKey, P2MROpTrueScript(),
            /*output_amount=*/1 * COIN, /*submit=*/false)
    };
    (void)CreateAndProcessBlock({funding_tx}, P2MROpTrueScript());
    const int funding_height{WITH_LOCK(::cs_main, return chainstate.m_chain.Height())};

    const CMutableTransaction witness_tx{
        CreateValidMempoolTransaction(
            MakeTransactionRef(funding_tx), 0, funding_height, coinbaseKey, P2MROpTrueScript(),
            /*output_amount=*/COIN / 2, /*submit=*/false)
    };
    const CBlock candidate_block{CreateBlock({witness_tx}, P2MROpTrueScript(), chainstate)};
    CBlock recovered_block{candidate_block};
    BOOST_REQUIRE_EQUAL(candidate_block.vtx.size(), 2U);
    CMutableTransaction mutated_witness_tx{*candidate_block.vtx[1]};
    BOOST_REQUIRE(!mutated_witness_tx.vin.empty());
    BOOST_REQUIRE(!mutated_witness_tx.vin[0].scriptWitness.stack.empty());
    BOOST_REQUIRE(!mutated_witness_tx.vin[0].scriptWitness.stack[0].empty());
    mutated_witness_tx.vin[0].scriptWitness.stack[0][0] ^= 1;
    recovered_block.vtx[1] = MakeTransactionRef(mutated_witness_tx);

    const uint256 candidate_hash{candidate_block.GetHash()};
    CBlockIndex* active_tip{nullptr};
    CBlockIndex* candidate_ptr{nullptr};
    BlockCheckedStateCatcher catcher{candidate_hash};
    m_node.validation_signals->RegisterValidationInterface(&catcher);

    {
        LOCK(::cs_main);
        active_tip = chainman.ActiveChain().Tip();
        BOOST_REQUIRE(active_tip != nullptr);

        const arith_uint256 proof{GetBlockProof(*active_tip)};
        BOOST_REQUIRE(proof != 0);

        auto& candidate = InsertTestBlockIndex(
            chainman,
            candidate_hash,
            active_tip,
            active_tip->nHeight + 1,
            candidate_block.nBits,
            active_tip->nChainWork + proof);
        candidate.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS_PRUNED;
        candidate_ptr = &candidate;
        chainstate.setBlockIndexCandidates.insert(candidate_ptr);
        BOOST_REQUIRE(chainman.NeedsWitnessForValidation(candidate));
        BOOST_REQUIRE(chainman.m_blockman.WriteRecoveredBlock(recovered_block));
        BOOST_REQUIRE(chainman.m_blockman.HaveRecoveredBlock(candidate_hash));
    }

    BlockValidationState state{};
    bool reset_most_work{false};
    {
        LOCK2(::cs_main, *chainstate.MempoolMutex());
        BOOST_REQUIRE(candidate_ptr != nullptr);
        BOOST_CHECK(chainstate.ActivateBestChainStepForTest(state, candidate_ptr, reset_most_work));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(reset_most_work);
        BOOST_CHECK(!chainman.m_blockman.HaveRecoveredBlock(candidate_hash));
        BOOST_CHECK_EQUAL(chainstate.m_chain.Tip(), active_tip);
    }

    BOOST_REQUIRE(catcher.m_state.has_value());
    BOOST_CHECK(catcher.m_state->IsError());
    BOOST_CHECK_EQUAL(catcher.m_state->GetRejectReason(), "recovered-witness-validation-failed");

    m_node.validation_signals->UnregisterValidationInterface(&catcher);
}

struct SnapshotTestSetup : TestChain100Setup {
    // Run with coinsdb on the filesystem to support, e.g., moving invalidated
    // chainstate dirs to "*_invalid".
    //
    // Note that this means the tests run considerably slower than in-memory DB
    // tests, but we can't otherwise test this functionality since it relies on
    // destructive filesystem operations.
    SnapshotTestSetup() : TestChain100Setup{
                              {},
                              {
                                  .coins_db_in_memory = false,
                                  .block_tree_db_in_memory = false,
                              },
                          }
    {
    }

    std::tuple<Chainstate*, Chainstate*> SetupSnapshot()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_CHECK(!chainman.IsSnapshotActive());

        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.IsSnapshotValidated());
            BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));
        }

        size_t initial_size;
        size_t initial_total_coins{100};

        // Make some initial assertions about the contents of the chainstate.
        {
            LOCK(::cs_main);
            CCoinsViewCache& ibd_coinscache = chainman.ActiveChainstate().CoinsTip();
            initial_size = ibd_coinscache.GetCacheSize();
            size_t total_coins{0};

            for (CTransactionRef& txn : m_coinbase_txns) {
                COutPoint op{txn->GetHash(), 0};
                BOOST_CHECK(ibd_coinscache.HaveCoin(op));
                total_coins++;
            }

            BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
            BOOST_CHECK_EQUAL(initial_size, initial_total_coins);
        }

        Chainstate& validation_chainstate = chainman.ActiveChainstate();

        // Snapshot should refuse to load at this height.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK(!chainman.SnapshotBlockhash());

        // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
        // be found.
        constexpr int snapshot_height = 110;
        mineBlocks(10);
        initial_size += 10;
        initial_total_coins += 10;

        // Should not load malleated snapshots
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // A UTXO is missing but count is correct
                metadata.m_coins_count -= 1;

                Txid txid;
                auto_infile >> txid;
                // coins size
                (void)ReadCompactSize(auto_infile);
                // vout index
                (void)ReadCompactSize(auto_infile);
                Coin coin;
                auto_infile >> coin;
        }));

        BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));

        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is larger than coins in file
                metadata.m_coins_count += 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is smaller than coins in file
                metadata.m_coins_count -= 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ZERO;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ONE;
        }));

        BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(fs::exists(*node::FindSnapshotChainstateDir(chainman.m_options.datadir)));

        // Ensure our active chain is the snapshot chainstate.
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash->IsNull());
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            *chainman.SnapshotBlockhash());

        Chainstate& snapshot_chainstate = chainman.ActiveChainstate();

        {
            LOCK(::cs_main);

            fs::path found = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);

            // Note: WriteSnapshotBaseBlockhash() is implicitly tested above.
            BOOST_CHECK_EQUAL(
                *node::ReadSnapshotBaseBlockhash(found),
                *chainman.SnapshotBlockhash());
        }

        const auto& au_data = ::Params().AssumeutxoForHeight(snapshot_height);
        const CBlockIndex* tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

        BOOST_CHECK_EQUAL(tip->m_chain_tx_count, au_data->m_chain_tx_count);

        // To be checked against later when we try loading a subsequent snapshot.
        uint256 loaded_snapshot_blockhash{*chainman.SnapshotBlockhash()};

        // Make some assertions about the both chainstates. These checks ensure the
        // legacy chainstate hasn't changed and that the newly created chainstate
        // reflects the expected content.
        {
            LOCK(::cs_main);
            int chains_tested{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();

                // Both caches will be empty initially.
                BOOST_CHECK_EQUAL((unsigned int)0, coinscache.GetCacheSize());

                size_t total_coins{0};

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    BOOST_CHECK(coinscache.HaveCoin(op));
                    total_coins++;
                }

                BOOST_CHECK_EQUAL(initial_size , coinscache.GetCacheSize());
                BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
                chains_tested++;
            }

            BOOST_CHECK_EQUAL(chains_tested, 2);
        }

        // Mine some new blocks on top of the activated snapshot chainstate.
        constexpr size_t new_coins{100};
        mineBlocks(new_coins);  // Defined in TestChain100Setup.

        {
            LOCK(::cs_main);
            size_t coins_in_active{0};
            size_t coins_in_background{0};
            size_t coins_missing_from_background{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();
                bool is_background = chainstate != &chainman.ActiveChainstate();

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    if (coinscache.HaveCoin(op)) {
                        (is_background ? coins_in_background : coins_in_active)++;
                    } else if (is_background) {
                        coins_missing_from_background++;
                    }
                }
            }

            BOOST_CHECK_EQUAL(coins_in_active, initial_total_coins + new_coins);
            BOOST_CHECK_EQUAL(coins_in_background, initial_total_coins);
            BOOST_CHECK_EQUAL(coins_missing_from_background, new_coins);
        }

        // Snapshot should refuse to load after one has already loaded.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));

        // Snapshot blockhash should be unchanged.
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            loaded_snapshot_blockhash);
        return std::make_tuple(&validation_chainstate, &snapshot_chainstate);
    }

    // Simulate a restart of the node by flushing all state to disk, clearing the
    // existing ChainstateManager, and unloading the block index.
    //
    // @returns a reference to the "restarted" ChainstateManager
    ChainstateManager& SimulateNodeRestart()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_TEST_MESSAGE("Simulating node restart");
        {
            for (Chainstate* cs : chainman.GetAll()) {
                LOCK(::cs_main);
                cs->ForceFlushStateToDisk();
            }
            // Process all callbacks referring to the old manager before wiping it.
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            LOCK(::cs_main);
            chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .witness_pruning_enabled = chainman_opts.chainparams.IsWitnessPruningEnabled(),
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            // For robustness, ensure the old manager is destroyed before creating a
            // new one.
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(*Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    }
};

//! Test basic snapshot activation.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_activate_snapshot, SnapshotTestSetup)
{
    if (!HasAssumeutxoData()) {
        BOOST_TEST_MESSAGE("Skipping snapshot activation test: no assumeutxo data configured");
        return;
    }
    this->SetupSnapshot();
}

//! Test LoadBlockIndex behavior when multiple chainstates are in use.
//!
//! - First, verify that setBlockIndexCandidates is as expected when using a single,
//!   fully-validating chainstate.
//!
//! - Then mark a region of the chain as missing data and introduce a second chainstate
//!   that will tolerate assumed-valid blocks. Run LoadBlockIndex() and ensure that the first
//!   chainstate only contains fully validated blocks and the other chainstate contains all blocks,
//!   except those marked assume-valid, because those entries don't HAVE_DATA.
//!
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, TestChain100Setup)
{
    if (!HasAssumeutxoData()) {
        BOOST_TEST_MESSAGE("Skipping loadblockindex snapshot test: no assumeutxo data configured");
        return;
    }

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& cs1 = chainman.ActiveChainstate();

    int num_indexes{0};
    // Blocks in range [assumed_valid_start_idx, last_assumed_valid_idx) will be
    // marked as assumed-valid and not having data.
    const int expected_assumed_valid{20};
    const int last_assumed_valid_idx{111};
    const int assumed_valid_start_idx = last_assumed_valid_idx - expected_assumed_valid;

    // Mine to height 120, past the hardcoded regtest assumeutxo snapshot at
    // height 110
    mineBlocks(20);

    CBlockIndex* validated_tip{nullptr};
    CBlockIndex* assumed_base{nullptr};
    CBlockIndex* assumed_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);

    auto reload_all_block_indexes = [&]() {
        // For completeness, we also reset the block sequence counters to
        // ensure that no state which affects the ranking of tip-candidates is
        // retained (even though this isn't strictly necessary).
        WITH_LOCK(::cs_main, return chainman.ResetBlockSequenceCounters());
        for (Chainstate* cs : chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ClearBlockIndexCandidates();
            BOOST_CHECK(cs->setBlockIndexCandidates.empty());
        }

        WITH_LOCK(::cs_main, chainman.LoadBlockIndex());
    };

    // Ensure that without any assumed-valid BlockIndex entries, only the current tip is
    // considered as a candidate.
    reload_all_block_indexes();
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);

    // Reset some region of the chain's nStatus, removing the HAVE_DATA flag.
    for (int i = 0; i <= cs1.m_chain.Height(); ++i) {
        LOCK(::cs_main);
        auto index = cs1.m_chain[i];

        // Blocks with heights in range [91, 110] are marked as missing data.
        if (i < last_assumed_valid_idx && i >= assumed_valid_start_idx) {
            index->nStatus = BlockStatus::BLOCK_VALID_TREE;
            index->nTx = 0;
            index->m_chain_tx_count = 0;
        }

        ++num_indexes;

        // Note the last fully-validated block as the expected validated tip.
        if (i == (assumed_valid_start_idx - 1)) {
            validated_tip = index;
        }
        // Note the last assumed valid block as the snapshot base
        if (i == last_assumed_valid_idx - 1) {
            assumed_base = index;
        }
    }

    // Note: cs2's tip is not set when ActivateExistingSnapshot is called.
    Chainstate& cs2 = WITH_LOCK(::cs_main,
        return chainman.ActivateExistingSnapshot(*assumed_base->phashBlock));

    // Set tip of the fully validated chain to be the validated tip
    cs1.m_chain.SetTip(*validated_tip);

    // Set tip of the assume-valid-based chain to the assume-valid block
    cs2.m_chain.SetTip(*assumed_base);

    // Sanity check test variables.
    BOOST_CHECK_EQUAL(num_indexes, 121); // 121 total blocks, including genesis
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);  // original chain has height 120
    BOOST_CHECK_EQUAL(validated_tip->nHeight, 90); // current cs1 chain has height 90
    BOOST_CHECK_EQUAL(assumed_base->nHeight, 110); // current cs2 chain has height 110

    // Regenerate cs1.setBlockIndexCandidates and cs2.setBlockIndexCandidate and
    // check contents below.
    reload_all_block_indexes();

    // The fully validated chain should only have the current validated tip and
    // the assumed valid base as candidates, blocks 90 and 110. Specifically:
    //
    // - It does not have blocks 0-89 because they contain less work than the
    //   chain tip.
    //
    // - It has block 90 because it has data and equal work to the chain tip,
    //   (since it is the chain tip).
    //
    // - It does not have blocks 91-109 because they do not contain data.
    //
    // - It has block 110 even though it does not have data, because
    //   LoadBlockIndex has a special case to always add the snapshot block as a
    //   candidate. The special case is only actually intended to apply to the
    //   snapshot chainstate cs2, not the background chainstate cs1, but it is
    //   written broadly and applies to both.
    //
    // - It does not have any blocks after height 110 because cs1 is a background
    //   chainstate, and only blocks where are ancestors of the snapshot block
    //   are added as candidates for the background chainstate.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 2);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_base), 1);

    // The assumed-valid tolerant chain has the assumed valid base as a
    // candidate, but otherwise has none of the assumed-valid (which do not
    // HAVE_DATA) blocks as candidates.
    //
    // Specifically:
    // - All blocks below height 110 are not candidates, because cs2 chain tip
    //   has height 110 and they have less work than it does.
    //
    // - Block 110 is a candidate even though it does not have data, because it
    //   is the snapshot block, which is assumed valid.
    //
    // - Blocks 111-120 are added because they have data.

    // Check that block 90 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(validated_tip), 0);
    // Check that block 109 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base->pprev), 0);
    // Check that block 110 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base), 1);
    // Check that block 120 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_tip), 1);
    // Check that 11 blocks total are present.
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.size(), num_indexes - last_assumed_valid_idx + 1);
}

//! Ensure that snapshot chainstates initialize properly when found on disk.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_init, SnapshotTestSetup)
{
    if (!HasAssumeutxoData()) {
        BOOST_TEST_MESSAGE("Skipping snapshot init test: no assumeutxo data configured");
        return;
    }

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& bg_chainstate = chainman.ActiveChainstate();

    this->SetupSnapshot();

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 2);

    // "Rewind" the background chainstate so that its tip is not at the
    // base block of the snapshot - this is so after simulating a node restart,
    // it will initialize instead of attempting to complete validation.
    //
    // Note that this is not a realistic use of DisconnectTip().
    DisconnectedBlockTransactions unused_pool{MAX_DISCONNECTED_TX_POOL_BYTES};
    BlockValidationState unused_state;
    {
        LOCK2(::cs_main, bg_chainstate.MempoolMutex());
        BOOST_CHECK(bg_chainstate.DisconnectTip(unused_state, &unused_pool));
        unused_pool.clear();  // to avoid queuedTx assertion errors on teardown
    }
    BOOST_CHECK_EQUAL(bg_chainstate.m_chain.Height(), 109);

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates.
    this->LoadVerifyActivateChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 2);
        BOOST_CHECK(chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the initialized snapshot chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);

        // Background chainstate should be unaware of new blocks on the snapshot
        // chainstate.
        for (Chainstate* cs : chainman_restarted.GetAll()) {
            if (cs != &chainman_restarted.ActiveChainstate()) {
                BOOST_CHECK_EQUAL(cs->m_chain.Height(), 109);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion, SnapshotTestSetup)
{
    if (!HasAssumeutxoData()) {
        BOOST_TEST_MESSAGE("Skipping snapshot completion test: no assumeutxo data configured");
        return;
    }

    this->SetupSnapshot();

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& active_cs = chainman.ActiveChainstate();
    auto tip_cache_before_complete = active_cs.m_coinstip_cache_size_bytes;
    auto db_cache_before_complete = active_cs.m_coinsdb_cache_size_bytes;

    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SUCCESS);

    WITH_LOCK(::cs_main, BOOST_CHECK(chainman.IsSnapshotValidated()));
    BOOST_CHECK(chainman.IsSnapshotActive());

    // Cache should have been rebalanced and reallocated to the "only" remaining
    // chainstate.
    BOOST_CHECK(active_cs.m_coinstip_cache_size_bytes > tip_cache_before_complete);
    BOOST_CHECK(active_cs.m_coinsdb_cache_size_bytes > db_cache_before_complete);

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &active_cs);

    // Trying completion again should return false.
    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SKIPPED);

    // The invalid snapshot path should not have been used.
    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should still exist.
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should now *not* exist.
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    const Chainstate& active_cs2 = chainman_restarted.ActiveChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK(active_cs2.m_coinstip_cache_size_bytes > tip_cache_before_complete);
        BOOST_CHECK(active_cs2.m_coinsdb_cache_size_bytes > db_cache_before_complete);

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion_hash_mismatch, SnapshotTestSetup)
{
    if (!HasAssumeutxoData()) {
        BOOST_TEST_MESSAGE("Skipping snapshot hash mismatch test: no assumeutxo data configured");
        return;
    }

    auto chainstates = this->SetupSnapshot();
    Chainstate& validation_chainstate = *std::get<0>(chainstates);
    ChainstateManager& chainman = *Assert(m_node.chainman);
    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    // Test tampering with the IBD UTXO set with an extra coin to ensure it causes
    // snapshot completion to fail.
    CCoinsViewCache& ibd_coins = WITH_LOCK(::cs_main,
        return validation_chainstate.CoinsTip());
    Coin badcoin;
    badcoin.out.nValue = m_rng.rand32();
    badcoin.nHeight = 1;
    badcoin.out.scriptPubKey.assign(m_rng.randbits(6), 0);
    Txid txid = Txid::FromUint256(m_rng.rand256());
    ibd_coins.AddCoin(COutPoint(txid, 0), std::move(badcoin), false);

    fs::path snapshot_chainstate_dir = gArgs.GetDataDirNet() / "chainstate_snapshot";
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    {
        ASSERT_DEBUG_LOG("failed to validate the -assumeutxo snapshot state");
        res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
        BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::HASH_MISMATCH);
    }

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &validation_chainstate);
    BOOST_CHECK_EQUAL(&chainman.ActiveChainstate(), &validation_chainstate);

    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(fs::exists(snapshot_invalid_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully loads only the fully-validated
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(fs::exists(snapshot_invalid_dir));
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

/** Helper function to parse args into args_man and return the result of applying them to opts */
template <typename Options>
util::Result<Options> SetOptsFromArgs(ArgsManager& args_man, Options opts,
                                      const std::vector<const char*>& args)
{
    const auto argv{Cat({"ignore"}, args)};
    std::string error{};
    if (!args_man.ParseParameters(argv.size(), argv.data(), error)) {
        return util::Error{Untranslated("ParseParameters failed with error: " + error)};
    }
    const auto result{node::ApplyArgsManOptions(args_man, opts)};
    if (!result) return util::Error{util::ErrorString(result)};
    return opts;
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_args, BasicTestingSetup)
{
    //! Try to apply the provided args to a ChainstateManager::Options
    auto get_opts = [&](const std::vector<const char*>& args) {
        static kernel::Notifications notifications{};
        static const ChainstateManager::Options options{
            .chainparams = ::Params(),
            .datadir = {},
            .notifications = notifications};
        return SetOptsFromArgs(*this->m_node.args, options, args);
    };
    //! Like get_opts, but requires the provided args to be valid and unwraps the result
    auto get_valid_opts = [&](const std::vector<const char*>& args) {
        const auto result{get_opts(args)};
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        return *result;
    };

    // test -assumevalid
    BOOST_CHECK(!get_valid_opts({}).assumed_valid_block);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid="}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-noassumevalid"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0x12"}).assumed_valid_block, uint256{0x12});

    std::string assume_valid{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-assumevalid=" + assume_valid).c_str()}).assumed_valid_block, uint256::FromHex(assume_valid));

    BOOST_CHECK(!get_opts({"-assumevalid=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-assumevalid=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    // test -minimumchainwork
    BOOST_CHECK(!get_valid_opts({}).minimum_chain_work);
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-nominimumchainwork"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0x1234"}).minimum_chain_work, arith_uint256{0x1234});

    std::string minimum_chainwork{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-minimumchainwork=" + minimum_chainwork).c_str()}).minimum_chain_work, UintToArith256(uint256::FromHex(minimum_chainwork).value()));

    BOOST_CHECK(!get_opts({"-minimumchainwork=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-minimumchainwork=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars
}

BOOST_AUTO_TEST_SUITE_END()
