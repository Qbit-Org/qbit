// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <node/miner.h>
#include <pow.h>
#include <random.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <thread>

using node::BlockAssembler;

namespace validation_block_tests {
struct MinerTestingSetup : public TestingSetup {
    MinerTestingSetup()
        : TestingSetup{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}} {}

    std::shared_ptr<CBlock> Block(const uint256& prev_hash);
    std::shared_ptr<const CBlock> GoodBlock(const uint256& prev_hash);
    std::shared_ptr<const CBlock> BadBlock(const uint256& prev_hash);
    std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock);
    void BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks);
};
} // namespace validation_block_tests

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, MinerTestingSetup)

struct TestSubscriber final : public CValidationInterface {
    uint256 m_expected_tip;

    explicit TestSubscriber(uint256 tip) : m_expected_tip(tip) {}

    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, pindexNew->GetBlockHash());
    }

    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->hashPrevBlock);
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->pprev->GetBlockHash());

        m_expected_tip = block->GetHash();
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->GetHash());
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->GetBlockHash());

        m_expected_tip = block->hashPrevBlock;
    }
};

std::shared_ptr<CBlock> MinerTestingSetup::Block(const uint256& prev_hash)
{
    static int i = 0;
    static uint64_t time = Params().GenesisBlock().nTime;

    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << i++ << OP_TRUE;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    auto pblock = std::make_shared<CBlock>(ptemplate->block);
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = ++time;

    // Make the coinbase transaction with two outputs:
    // One zero-value one that has a unique pubkey to make sure that blocks at the same height can have a different hash
    // Another one that has the coinbase reward in a P2WSH with OP_TRUE as witness program to make it easy to spend
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vout.resize(2);
    txCoinbase.vout[1].scriptPubKey = P2WSH_OP_TRUE;
    txCoinbase.vout[1].nValue = txCoinbase.vout[0].nValue;
    txCoinbase.vout[0].nValue = 0;
    txCoinbase.vin[0].scriptWitness.SetNull();
    // Always pad with OP_0 at the end to avoid bad-cb-length error
    const int prev_height{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(prev_hash)->nHeight)};
    txCoinbase.vin[0].scriptSig = CScript{} << prev_height + 1 << OP_0;
    txCoinbase.nLockTime = static_cast<uint32_t>(prev_height);
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    return pblock;
}

std::shared_ptr<CBlock> MinerTestingSetup::FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    const CBlockIndex* prev_block{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(pblock->hashPrevBlock))};
    m_node.chainman->GenerateCoinbaseCommitment(*pblock, prev_block);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
        ++(pblock->nNonce);
    }

    // submit block header, so that miner can get the block height from the
    // global state and the node has the topology of the chain
    BlockValidationState ignored;
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlockHeaders({{pblock->GetBlockHeader()}}, true, ignored));

    return pblock;
}

static CTransactionRef WitnessTx(const uint64_t prevout_tag, std::vector<std::vector<unsigned char>> witness_stack)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{static_cast<uint8_t>(prevout_tag)}), 0}, CScript{}, /*nSequence=*/0);
    tx.vout.emplace_back(/*nValue=*/0, CScript{} << OP_TRUE);
    tx.vin[0].scriptWitness.stack = std::move(witness_stack);
    return MakeTransactionRef(std::move(tx));
}

static std::shared_ptr<const CBlock> StripWitnesses(const CBlock& block)
{
    auto stripped_block{std::make_shared<CBlock>(block)};
    for (auto& tx : stripped_block->vtx) {
        CMutableTransaction mutable_tx{*tx};
        for (auto& txin : mutable_tx.vin) txin.scriptWitness.SetNull();
        tx = MakeTransactionRef(std::move(mutable_tx));
    }
    return stripped_block;
}

static BlockValidationState AcceptBlockForTest(ChainstateManager& chainman, const std::shared_ptr<const CBlock>& block, bool requested_stripped)
{
    BlockValidationState state;
    bool new_block{false};
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.AcceptBlock(block, state, /*ppindex=*/nullptr, /*fRequested=*/true, /*dbp=*/nullptr, &new_block, /*min_pow_checked=*/true, requested_stripped));
    }
    BOOST_CHECK(state.IsInvalid());
    return state;
}

// construct a valid block
std::shared_ptr<const CBlock> MinerTestingSetup::GoodBlock(const uint256& prev_hash)
{
    return FinalizeBlock(Block(prev_hash));
}

// construct an invalid block (but with a valid header)
std::shared_ptr<const CBlock> MinerTestingSetup::BadBlock(const uint256& prev_hash)
{
    auto pblock = Block(prev_hash);

    CMutableTransaction coinbase_spend;
    coinbase_spend.vin.emplace_back(COutPoint(pblock->vtx[0]->GetHash(), 0), CScript(), 0);
    coinbase_spend.vout.push_back(pblock->vtx[0]->vout[0]);

    CTransactionRef tx = MakeTransactionRef(coinbase_spend);
    pblock->vtx.push_back(tx);

    auto ret = FinalizeBlock(pblock);
    return ret;
}

// NOLINTNEXTLINE(misc-no-recursion)
void MinerTestingSetup::BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks)
{
    if (height <= 0 || blocks.size() >= max_size) return;

    bool gen_invalid = m_rng.randrange(100U) < invalid_rate;
    bool gen_fork = m_rng.randrange(100U) < branch_rate;

    const std::shared_ptr<const CBlock> pblock = gen_invalid ? BadBlock(root) : GoodBlock(root);
    blocks.push_back(pblock);
    if (!gen_invalid) {
        BuildChain(pblock->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }

    if (gen_fork) {
        blocks.push_back(GoodBlock(root));
        BuildChain(blocks.back()->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_signals_ordering)
{
    // build a large-ish chain that's likely to have some forks
    std::vector<std::shared_ptr<const CBlock>> blocks;
    while (blocks.size() < 50) {
        blocks.clear();
        BuildChain(Params().GenesisBlock().GetHash(), 100, 15, 10, 500, blocks);
    }

    bool ignored;
    // Connect the genesis block and drain any outstanding events
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // subscribe to events (this subscriber will validate event ordering)
    const CBlockIndex* initial_tip = nullptr;
    {
        LOCK(cs_main);
        initial_tip = m_node.chainman->ActiveChain().Tip();
    }
    auto sub = std::make_shared<TestSubscriber>(initial_tip->GetBlockHash());
    m_node.validation_signals->RegisterSharedValidationInterface(sub);

    // create a bunch of threads that repeatedly process a block generated above at random
    // this will create parallelism and randomness inside validation - the ValidationInterface
    // will subscribe to events generated during block validation and assert on ordering invariance
    std::vector<std::thread> threads;
    threads.reserve(10);
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&]() {
            bool ignored;
            FastRandomContext insecure;
            for (int i = 0; i < 1000; i++) {
                const auto& block = blocks[insecure.randrange(blocks.size() - 1)];
                Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
            }

            // to make sure that eventually we process the full chain - do it here
            for (const auto& block : blocks) {
                if (block->vtx.size() == 1) {
                    bool processed = Assert(m_node.chainman)->ProcessNewBlock(block, true, true, &ignored);
                    assert(processed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    m_node.validation_signals->UnregisterSharedValidationInterface(sub);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(sub->m_expected_tip, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(processnewblock_rejects_stripped_segwit_blocks_even_when_requested_stripped)
{
    bool ignored{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));

    const uint256 prev_hash{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash())};
    const auto full_block{GoodBlock(prev_hash)};

    BOOST_REQUIRE(GetWitnessCommitmentIndex(*full_block) != NO_WITNESS_COMMITMENT);
    BOOST_CHECK(HasAnyWitnessData(*full_block));
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(full_block, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored, /*requested_stripped=*/false));

    WITH_LOCK(::cs_main, {
        const CBlockIndex* pindex{m_node.chainman->m_blockman.LookupBlockIndex(full_block->GetHash())};
        BOOST_REQUIRE(pindex != nullptr);
        BOOST_CHECK((pindex->nStatus & BLOCK_OPT_WITNESS_PRUNED) == 0);
    });

    auto stripped_block{std::make_shared<CBlock>(*GoodBlock(full_block->GetHash()))};
    for (auto& tx : stripped_block->vtx) {
        CMutableTransaction mutable_tx{*tx};
        for (auto& txin : mutable_tx.vin) txin.scriptWitness.SetNull();
        tx = MakeTransactionRef(std::move(mutable_tx));
    }
    BOOST_CHECK(!HasAnyWitnessData(*stripped_block));
    BOOST_CHECK(!Assert(m_node.chainman)->ProcessNewBlock(stripped_block, /*force_processing=*/true, /*min_pow_checked=*/true, &ignored, /*requested_stripped=*/true));
}

BOOST_AUTO_TEST_CASE(acceptblock_rejects_requested_stripped_block_hiding_overweight_witness)
{
    bool ignored{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));

    const uint256 prev_hash{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash())};

    auto full_block{Block(prev_hash)};
    full_block->vtx.push_back(WitnessTx(/*prevout_tag=*/1, {{std::vector<unsigned char>(MAX_BLOCK_WEIGHT, 0x42)}}));
    full_block = FinalizeBlock(full_block);
    BOOST_REQUIRE(GetWitnessCommitmentIndex(*full_block) != NO_WITNESS_COMMITMENT);
    BOOST_REQUIRE(HasAnyWitnessData(*full_block));
    BOOST_CHECK_GT(GetBlockWeight(*full_block), MAX_BLOCK_WEIGHT);

    const BlockValidationState full_state{
        AcceptBlockForTest(*Assert(m_node.chainman), full_block, /*requested_stripped=*/false)};
    BOOST_CHECK_EQUAL(full_state.GetRejectReason(), "bad-blk-weight");

    auto stripped_source{Block(prev_hash)};
    stripped_source->vtx.push_back(WitnessTx(/*prevout_tag=*/2, {{std::vector<unsigned char>(MAX_BLOCK_WEIGHT, 0x24)}}));
    stripped_source = FinalizeBlock(stripped_source);
    BOOST_CHECK_GT(GetBlockWeight(*stripped_source), MAX_BLOCK_WEIGHT);

    const auto stripped_block{StripWitnesses(*stripped_source)};
    BOOST_CHECK_EQUAL(stripped_source->GetHash(), stripped_block->GetHash());
    BOOST_CHECK(!HasAnyWitnessData(*stripped_block));
    BOOST_CHECK_LE(GetBlockWeight(*stripped_block), MAX_BLOCK_WEIGHT);

    BlockValidationState check_state;
    BOOST_CHECK(CheckBlock(*stripped_block, check_state, Params().GetConsensus()));

    // Keep `allow_stripped` behind `RequiresWitnessForPeerBlock()`: omitted
    // post-segwit witness bytes can hide both total block weight and witness
    // commitment failures in `ContextualCheckBlock()` / `CheckWitnessMalleation()`.
    const BlockValidationState stripped_state{
        AcceptBlockForTest(*Assert(m_node.chainman), stripped_block, /*requested_stripped=*/true)};
    BOOST_CHECK_EQUAL(stripped_state.GetRejectReason(), "bad-blk-missing-witness");
}

BOOST_AUTO_TEST_CASE(acceptblock_rejects_requested_stripped_block_hiding_invalid_witness_commitment)
{
    bool ignored{false};
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), true, true, &ignored));

    const uint256 prev_hash{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash())};

    auto full_block{std::make_shared<CBlock>(*GoodBlock(prev_hash))};
    full_block->fChecked = false;
    full_block->m_checked_merkle_root = false;
    full_block->m_checked_witness_commitment = false;
    BOOST_REQUIRE(GetWitnessCommitmentIndex(*full_block) != NO_WITNESS_COMMITMENT);
    BOOST_REQUIRE(HasAnyWitnessData(*full_block));

    CMutableTransaction mutated_coinbase{*full_block->vtx[0]};
    BOOST_REQUIRE_EQUAL(mutated_coinbase.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(mutated_coinbase.vin[0].scriptWitness.stack.size(), 1U);
    BOOST_REQUIRE_EQUAL(mutated_coinbase.vin[0].scriptWitness.stack[0].size(), 32U);
    mutated_coinbase.vin[0].scriptWitness.stack[0][0] ^= 1;
    full_block->vtx[0] = MakeTransactionRef(std::move(mutated_coinbase));
    BOOST_CHECK_EQUAL(full_block->hashMerkleRoot, BlockMerkleRoot(*full_block));
    const int commitpos{GetWitnessCommitmentIndex(*full_block)};
    BOOST_REQUIRE(commitpos != NO_WITNESS_COMMITMENT);
    uint256 mutated_commitment{BlockWitnessMerkleRoot(*full_block, nullptr)};
    CHash256().Write(mutated_commitment).Write(full_block->vtx[0]->vin[0].scriptWitness.stack[0]).Finalize(mutated_commitment);
    BOOST_CHECK(memcmp(mutated_commitment.begin(), &full_block->vtx[0]->vout[commitpos].scriptPubKey[6], 32) != 0);
    BOOST_CHECK(IsBlockMutated(*full_block, /*check_witness_root=*/true));
    full_block->fChecked = false;
    full_block->m_checked_merkle_root = false;
    full_block->m_checked_witness_commitment = false;

    const BlockValidationState full_state{
        AcceptBlockForTest(*Assert(m_node.chainman), full_block, /*requested_stripped=*/false)};
    BOOST_CHECK_EQUAL(full_state.GetRejectReason(), "bad-witness-merkle-match");

    auto stripped_source{std::make_shared<CBlock>(*GoodBlock(prev_hash))};
    stripped_source->fChecked = false;
    stripped_source->m_checked_merkle_root = false;
    stripped_source->m_checked_witness_commitment = false;
    CMutableTransaction stripped_source_coinbase{*stripped_source->vtx[0]};
    BOOST_REQUIRE_EQUAL(stripped_source_coinbase.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(stripped_source_coinbase.vin[0].scriptWitness.stack.size(), 1U);
    BOOST_REQUIRE_EQUAL(stripped_source_coinbase.vin[0].scriptWitness.stack[0].size(), 32U);
    stripped_source_coinbase.vin[0].scriptWitness.stack[0][0] ^= 1;
    stripped_source->vtx[0] = MakeTransactionRef(std::move(stripped_source_coinbase));

    const auto stripped_block{StripWitnesses(*stripped_source)};
    BOOST_CHECK_EQUAL(stripped_source->GetHash(), stripped_block->GetHash());
    BOOST_CHECK(!HasAnyWitnessData(*stripped_block));

    BlockValidationState check_state;
    BOOST_CHECK(CheckBlock(*stripped_block, check_state, Params().GetConsensus()));

    const BlockValidationState stripped_state{
        AcceptBlockForTest(*Assert(m_node.chainman), stripped_block, /*requested_stripped=*/true)};
    BOOST_CHECK_EQUAL(stripped_state.GetRejectReason(), "bad-blk-missing-witness");
}

/**
 * Test that mempool updates happen atomically with reorgs.
 *
 * This prevents RPC clients, among others, from retrieving immediately-out-of-date mempool data
 * during large reorgs.
 *
 * The test verifies this by creating a chain of `num_txs` blocks, matures their coinbases, and then
 * submits txns spending from their coinbase to the mempool. A fork chain is then processed,
 * invalidating the txns and evicting them from the mempool.
 *
 * We verify that the mempool updates atomically by polling it continuously
 * from another thread during the reorg and checking that its size only changes
 * once. The size changing exactly once indicates that the polling thread's
 * view of the mempool is either consistent with the chain state before reorg,
 * or consistent with the chain state after the reorg, and not just consistent
 * with some intermediate state during the reorg.
 */
BOOST_AUTO_TEST_CASE(mempool_locks_reorg)
{
    bool ignored;
    auto ProcessBlock = [&](std::shared_ptr<const CBlock> block) -> bool {
        return Assert(m_node.chainman)->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&ignored);
    };

    // Process all mined blocks
    BOOST_REQUIRE(ProcessBlock(std::make_shared<CBlock>(Params().GenesisBlock())));
    auto last_mined = GoodBlock(Params().GenesisBlock().GetHash());
    BOOST_REQUIRE(ProcessBlock(last_mined));

    // Run the test multiple times
    for (int test_runs = 3; test_runs > 0; --test_runs) {
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // Later on split from here
        const uint256 split_hash{last_mined->hashPrevBlock};

        // Create a bunch of transactions to spend the miner rewards of the
        // most recent blocks
        std::vector<CTransactionRef> txs;
        for (int num_txs = 22; num_txs > 0; --num_txs) {
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint{last_mined->vtx[0]->GetHash(), 1}, CScript{});
            mtx.vin[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
            mtx.vout.push_back(last_mined->vtx[0]->vout[1]);
            mtx.vout[0].nValue -= 1000;
            txs.push_back(MakeTransactionRef(mtx));

            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mature the inputs of the txs
        for (int j = COINBASE_MATURITY; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            BOOST_REQUIRE(ProcessBlock(last_mined));
        }

        // Mine a reorg (and hold it back) before adding the txs to the mempool
        const uint256 tip_init{last_mined->GetHash()};

        std::vector<std::shared_ptr<const CBlock>> reorg;
        last_mined = GoodBlock(split_hash);
        reorg.push_back(last_mined);
        for (size_t j = COINBASE_MATURITY + txs.size() + 1; j > 0; --j) {
            last_mined = GoodBlock(last_mined->GetHash());
            reorg.push_back(last_mined);
        }

        // Add the txs to the tx pool
        {
            LOCK(cs_main);
            for (const auto& tx : txs) {
                const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx);
                BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            }
        }

        // Check that all txs are in the pool
        {
            BOOST_CHECK_EQUAL(m_node.mempool->size(), txs.size());
        }

        // Run a thread that simulates an RPC caller that is polling while
        // validation is doing a reorg
        std::thread rpc_thread{[&]() {
            // This thread is checking that the mempool either contains all of
            // the transactions invalidated by the reorg, or none of them, and
            // not some intermediate amount.
            while (true) {
                LOCK(m_node.mempool->cs);
                if (m_node.mempool->size() == 0) {
                    // We are done with the reorg
                    break;
                }
                // Internally, we might be in the middle of the reorg, but
                // externally the reorg to the most-proof-of-work chain should
                // be atomic. So the caller assumes that the returned mempool
                // is consistent. That is, it has all txs that were there
                // before the reorg.
                assert(m_node.mempool->size() == txs.size());
                continue;
            }
            LOCK(cs_main);
            // We are done with the reorg, so the tip must have changed
            assert(tip_init != m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }};

        // Submit the reorg in this thread to invalidate and remove the txs from the tx pool
        for (const auto& b : reorg) {
            ProcessBlock(b);
        }
        // Check that the reorg was eventually successful
        BOOST_CHECK_EQUAL(last_mined->GetHash(), WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

        // We can join the other thread, which returns when the reorg was successful
        rpc_thread.join();
    }
}

BOOST_AUTO_TEST_CASE(witness_commitment_index)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    CScript pubKey;
    pubKey << 1 << OP_TRUE;
    BlockAssembler::Options options;
    options.coinbase_output_script = pubKey;
    auto ptemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    CBlock pblock = ptemplate->block;

    CTxOut witness;
    witness.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
    witness.scriptPubKey[0] = OP_RETURN;
    witness.scriptPubKey[1] = 0x24;
    witness.scriptPubKey[2] = 0xaa;
    witness.scriptPubKey[3] = 0x21;
    witness.scriptPubKey[4] = 0xa9;
    witness.scriptPubKey[5] = 0xed;

    // A witness larger than the minimum size is still valid
    CTxOut min_plus_one = witness;
    min_plus_one.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT + 1);

    CTxOut invalid = witness;
    invalid.scriptPubKey[0] = OP_VERIFY;

    CMutableTransaction txCoinbase(*pblock.vtx[0]);
    txCoinbase.vout.resize(4);
    txCoinbase.vout[0] = witness;
    txCoinbase.vout[1] = witness;
    txCoinbase.vout[2] = min_plus_one;
    txCoinbase.vout[3] = invalid;
    pblock.vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    BOOST_CHECK_EQUAL(GetWitnessCommitmentIndex(pblock), 2);
}
BOOST_AUTO_TEST_SUITE_END()
