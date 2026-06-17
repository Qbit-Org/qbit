// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <interfaces/mining.h>
#include <node/kernel_notifications.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <test/util/random.h>
#include <test/util/transaction_utils.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <versionbits.h>
#include <pow.h>

#include <test/util/setup_common.h>

#include <memory>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;

namespace miner_tests {
struct MinerTestingSetup : public TestingSetup {
    // These tests construct many non-P2MR synthetic outputs to exercise block
    // assembly edge cases; keep regtest p2mr-only policy disabled here.
    MinerTestingSetup()
        : TestingSetup{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}}
    {
    }

    void TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool TestSequenceLocks(const CTransaction& tx, CTxMemPool& tx_mempool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CCoinsViewMemPool view_mempool{&m_node.chainman->ActiveChainstate().CoinsTip(), tx_mempool};
        CBlockIndex* tip{m_node.chainman->ActiveChain().Tip()};
        const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(tip, view_mempool, tx)};
        return lock_points.has_value() && CheckSequenceLocksAtTip(tip, *lock_points);
    }
    CTxMemPool& MakeMempool()
    {
        // Delete the previous mempool to ensure with valgrind that the old
        // pointer is not accessed, when the new one should be accessed
        // instead.
        m_node.mempool.reset();
        bilingual_str error;
        m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(m_node), error);
        Assert(error.empty());
        return *m_node.mempool;
    }
    std::unique_ptr<Mining> MakeMining()
    {
        return interfaces::MakeMining(m_node);
    }
};
} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);

constexpr int NUM_PREPARATION_BLOCKS{10};

static std::unique_ptr<CBlockIndex> CreateBlockIndex(int nHeight, CBlockIndex* active_chain_tip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto index{std::make_unique<CBlockIndex>()};
    index->nHeight = nHeight;
    index->pprev = active_chain_tip;
    return index;
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void MinerTestingSetup::TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    CTxMemPool& tx_mempool{MakeMempool()};
    auto mining{MakeMining()};
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    const CAmount COINBASE_VALUE{txFirst[0]->vout.at(0).nValue};
    // Keep waitNext() focused on fee/tip-trigger behavior rather than the
    // testnet/regtest min-difficulty timeout path.
    SetMockTime(Assert(m_node.chainman)->ActiveChain().Tip()->GetBlockTime());

    LOCK(tx_mempool.cs);
    BOOST_CHECK(tx_mempool.size() == 0);

    // Block template should only have a coinbase when there's nothing in the mempool
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);

    // waitNext() may still refresh the template for non-fee reasons (e.g. time),
    // but must not add transactions when mempool is empty.
    auto maybe_updated_template = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 1});
    if (maybe_updated_template) {
        block_template = std::move(maybe_updated_template);
    }
    BOOST_REQUIRE_EQUAL(block_template->getBlock().vtx.size(), 1U);

    // Unless fee_threshold is 0
    block_template = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 0});
    BOOST_REQUIRE(block_template);

    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = COINBASE_VALUE - 1000;
    // This tx has a low fee: 1000 satoshis
    Txid hashParentTx = tx.GetHash(); // save this txid for later use
    const auto parent_tx{entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    AddToMempool(tx_mempool, parent_tx);

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = COINBASE_VALUE - 10000;
    Txid hashMediumFeeTx = tx.GetHash();
    const auto medium_fee_tx{entry.Fee(10000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx)};
    AddToMempool(tx_mempool, medium_fee_tx);

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = COINBASE_VALUE - 1000 - 50000; // 50k satoshi fee
    Txid hashHighFeeTx = tx.GetHash();
    const auto high_fee_tx{entry.Fee(50000).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx)};
    AddToMempool(tx_mempool, high_fee_tx);

    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 4U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashHighFeeTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashMediumFeeTx);

    // Test the inclusion of package feerates in the block template and ensure they are sequential.
    const auto block_package_feerates = BlockAssembler{m_node.chainman->ActiveChainstate(), &tx_mempool, options}.CreateNewBlock()->m_package_feerates;
    BOOST_CHECK(block_package_feerates.size() == 2);

    // parent_tx and high_fee_tx are added to the block as a package.
    const auto combined_txs_fee = parent_tx.GetFee() + high_fee_tx.GetFee();
    const auto combined_txs_size = parent_tx.GetTxSize() + high_fee_tx.GetTxSize();
    FeeFrac package_feefrac{combined_txs_fee, combined_txs_size};
    // The package should be added first.
    BOOST_CHECK(block_package_feerates[0] == package_feefrac);

    // The medium_fee_tx should be added next.
    FeeFrac medium_tx_feefrac{medium_fee_tx.GetFee(), medium_fee_tx.GetTxSize()};
    BOOST_CHECK(block_package_feerates[1] == medium_tx_feefrac);

    // Test that a package below the block min tx fee doesn't get included
    tx.vin[0].prevout.hash = hashHighFeeTx;
    tx.vout[0].nValue = COINBASE_VALUE - 1000 - 50000; // 0 fee
    Txid hashFreeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).FromTx(tx));
    size_t freeTxSize = ::GetSerializeSize(TX_WITH_WITNESS(tx));

    // Calculate a fee on child transaction that will put the package just
    // below the block min tx fee (assuming 1 child tx of the same size).
    CAmount feeToUse = blockMinFeeRate.GetFee(2*freeTxSize) - 1;

    tx.vin[0].prevout.hash = hashFreeTx;
    tx.vout[0].nValue = COINBASE_VALUE - 1000 - 50000 - feeToUse;
    Txid hashLowFeeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(feeToUse).FromTx(tx));

    // A refreshed template is acceptable here as long as transaction selection
    // stays unchanged with the low-fee package present.
    maybe_updated_template = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 1});
    if (maybe_updated_template) {
        block_template = std::move(maybe_updated_template);
    }

    block = block_template->getBlock();
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i=0; i<block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeTx);
        BOOST_CHECK(block.vtx[i]->GetHash() != hashLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with a higher fee transaction
    tx_mempool.removeRecursive(CTransaction(tx), MemPoolRemovalReason::REPLACED);
    tx.vout[0].nValue -= 2; // Now we should be just over the min relay fee
    hashLowFeeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(feeToUse + 2).FromTx(tx));

    // waitNext() should return if fees for the new template are at least 1 sat up
    // (timeout=0 avoids blocking with fixed mock time).
    block_template = block_template->waitNext({.timeout = MillisecondsDouble{0}, .fee_threshold = 1});
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 6U);
    BOOST_CHECK(block.vtx[4]->GetHash() == hashFreeTx);
    BOOST_CHECK(block.vtx[5]->GetHash() == hashLowFeeTx);

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout.resize(2);
    tx.vout[0].nValue = COINBASE_VALUE - 100000000;
    tx.vout[1].nValue = 100000000; // 1BTC output
    // Increase size to avoid rounding errors: when the feerate is extremely small (i.e. 1sat/kvB), evaluating the fee
    // at smaller sizes gives us rounded values that are equal to each other, which means we incorrectly include
    // hashFreeTx2 + hashLowFeeTx2. Keep padding below script stack limits on WSF=1 chains.
    BulkTransaction(tx, WITNESS_SCALE_FACTOR * 900);
    Txid hashFreeTx2 = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout.hash = hashFreeTx2;
    tx.vout.resize(1);
    // BulkTransaction() increased tx size; derive fee from the child size.
    feeToUse = blockMinFeeRate.GetFee(::GetSerializeSize(TX_WITH_WITNESS(tx)));
    tx.vout[0].nValue = COINBASE_VALUE - 100000000 - feeToUse;
    Txid hashLowFeeTx2 = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();

    // Verify that this tx isn't selected.
    for (size_t i=0; i<block.vtx.size(); ++i) {
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeTx2);
        BOOST_CHECK(block.vtx[i]->GetHash() != hashLowFeeTx2);
    }

    // Add a higher-fee sibling to exercise package updates under qbit policy.
    tx.vin[0].prevout.n = 1;
    const CAmount package_boost_fee{1000000}; // Higher fee required with WSF=1.
    tx.vout[0].nValue = 100000000 - package_boost_fee;
    const Txid hashSiblingTx2 = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(package_boost_fee).FromTx(tx));
    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();

    bool has_sibling{false};
    bool has_low_fee_child{false};
    for (const auto& txref : block.vtx) {
        const Txid txid{txref->GetHash()};
        if (txid == hashSiblingTx2) has_sibling = true;
        if (txid == hashLowFeeTx2) has_low_fee_child = true;
    }
    BOOST_CHECK(has_sibling);
    BOOST_CHECK(has_low_fee_child);
}

void MinerTestingSetup::TestBasicMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst, int baseheight)
{
    Txid hash;
    CMutableTransaction tx;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.nHeight = 11;
    std::vector<std::unique_ptr<CBlockIndex>> boundary_chain;
    std::vector<std::unique_ptr<uint256>> boundary_hashes;

    const CAmount BLOCKSUBSIDY = GetBlockSubsidy(baseheight + 1, Assert(m_node.chainman)->GetParams().GetConsensus());
    const CAmount LOWFEE = CENT / 10;
    const CAmount HIGHFEE = COIN;
    const CAmount HIGHERFEE = 4 * COIN;

    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // Just to make sure we can still make simple blocks
        auto block_template{mining->createNewBlock(options)};
        BOOST_REQUIRE(block_template);
        CBlock block{block_template->getBlock()};

        // block sigops > limit: use an explicit sigops cost above the cap.
        tx.vin.resize(1);
        // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
        tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout.resize(1);
        tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
        const Txid high_sigops_txid{tx.GetHash()};
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).SigOpsCost(MAX_BLOCK_SIGOPS_COST + 1).FromTx(tx));

        auto block_template_high_sigops{mining->createNewBlock(options)};
        BOOST_REQUIRE(block_template_high_sigops);
        CBlock high_sigops_block{block_template_high_sigops->getBlock()};
        for (const auto& included_tx : high_sigops_block.vtx) {
            BOOST_CHECK(included_tx->GetHash() != high_sigops_txid);
        }
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
        // If we set a valid # of sigops in the CTxMemPoolEntry, template creation passes.
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).SigOpsCost(80).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // block size > limit
        tx.vin[0].scriptSig = CScript();
        // 18 * (520char + DROP) + OP_1 = 9433 bytes
        std::vector<unsigned char> vchData(520);
        for (unsigned int i = 0; i < 18; ++i) {
            tx.vin[0].scriptSig << vchData << OP_DROP;
        }
        tx.vin[0].scriptSig << OP_1;
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vout[0].nValue = BLOCKSUBSIDY;
        for (unsigned int i = 0; i < 128; ++i) {
            tx.vout[0].nValue -= LOWFEE;
            hash = tx.GetHash();
            bool spendsCoinbase = i == 0; // only first tx spends coinbase
            AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
            tx.vin[0].prevout.hash = hash;
        }
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // orphan in tx_mempool, template creation fails
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // child with higher feerate than parent
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vin[0].prevout.hash = txFirst[1]->GetHash();
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin.resize(2);
        tx.vin[1].scriptSig = CScript() << OP_1;
        tx.vin[1].prevout.hash = txFirst[0]->GetHash();
        tx.vin[1].prevout.n = 0;
        tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE; // First txn output + fresh coinbase - new txn fee
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHERFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_REQUIRE(mining->createNewBlock(options));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // coinbase in tx_mempool, template creation fails
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
        tx.vout[0].nValue = 0;
        hash = tx.GetHash();
        // give it a fee so it'll get mined
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        // Should throw bad-cb-multiple
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options), std::runtime_error, HasReason("bad-cb-multiple"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // double spend txn pair in tx_mempool, template creation fails
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
        tx.vout[0].scriptPubKey = CScript() << OP_1;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vout[0].scriptPubKey = CScript() << OP_2;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(HIGHFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options), std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    }

    {
        CTxMemPool& tx_mempool{MakeMempool()};
        LOCK(tx_mempool.cs);

        // Subsidy step-boundary smoke test.
        const int nHeight = m_node.chainman->ActiveChain().Height();
        const auto& consensus{Assert(m_node.chainman)->GetParams().GetConsensus()};
        const int step_interval{consensus.nSubsidyStepInterval};
        BOOST_REQUIRE(step_interval > 0);
        const int64_t next_step_height{(static_cast<int64_t>(nHeight) / step_interval + 1) * step_interval};
        const int before_step_height{static_cast<int>(next_step_height - 1)};
        const int at_step_height{static_cast<int>(next_step_height)};

        const auto extend_tip_to = [&](int target_height) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            while (m_node.chainman->ActiveChain().Tip()->nHeight < target_height) {
                CBlockIndex* prev = m_node.chainman->ActiveChain().Tip();
                auto next{std::make_unique<CBlockIndex>()};
                auto hash{std::make_unique<uint256>(m_rng.rand256())};
                next->phashBlock = hash.get();
                next->pprev = prev;
                next->nHeight = prev->nHeight + 1;
                next->nVersion = prev->nVersion;
                next->nBits = prev->nBits;
                next->nTime = prev->nTime + 1;
                next->nTimeMax = (prev->nTimeMax > next->nTime) ? prev->nTimeMax : next->nTime;
                next->BuildSkip();
                m_node.chainman->ActiveChain().SetTip(*next);
                m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
                (void)Assert(m_node.notifications)->blockTip(SynchronizationState::POST_INIT, *next, /*verification_progress=*/1.0);
                boundary_hashes.push_back(std::move(hash));
                boundary_chain.push_back(std::move(next));
            }
        };

        extend_tip_to(before_step_height - 1);
        auto before_step_template{mining->createNewBlock(options)};
        BOOST_REQUIRE(before_step_template);
        BOOST_CHECK_EQUAL(before_step_template->getBlock().vtx[0]->vout[0].nValue, GetBlockSubsidy(before_step_height, consensus));

        extend_tip_to(at_step_height - 1);
        auto at_step_template{mining->createNewBlock(options)};
        BOOST_REQUIRE(at_step_template);
        BOOST_CHECK_EQUAL(at_step_template->getBlock().vtx[0]->vout[0].nValue, GetBlockSubsidy(at_step_height, consensus));
        BOOST_CHECK_LT(GetBlockSubsidy(at_step_height, consensus), GetBlockSubsidy(before_step_height, consensus));

        // invalid p2sh txn in tx_mempool, template creation fails
        tx.vin[0].prevout.hash = txFirst[0]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
        CScript script = CScript() << OP_0;
        tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptHash(script));
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
        tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        AddToMempool(tx_mempool, entry.Fee(LOWFEE).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
        BOOST_CHECK_EXCEPTION(mining->createNewBlock(options), std::runtime_error, HasReason("block-script-verify-flag-failed"));

        // Unwind the dummy blocks and release owned objects.
        while (m_node.chainman->ActiveChain().Tip()->nHeight > nHeight) {
            m_node.chainman->ActiveChain().SetTip(*Assert(m_node.chainman->ActiveChain().Tip()->pprev));
            m_node.chainman->ActiveChainstate().CoinsTip().SetBestBlock(m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        (void)Assert(m_node.notifications)->blockTip(SynchronizationState::POST_INIT, *m_node.chainman->ActiveChain().Tip(), /*verification_progress=*/1.0);
        boundary_chain.clear();
        boundary_hashes.clear();
    }

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    // non-final txs in mempool
    SetMockTime(m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
    const int flags{LOCKTIME_VERIFY_SEQUENCE};
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.version = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = m_node.chainman->ActiveChain().Tip()->nHeight - baseheight + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 2, active_chain_tip))); // Sequence locks pass on 2nd block
    }

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()+1-m_node.chainman->ActiveChain()[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd block
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    const int SEQUENCE_LOCK_TIME = 512; // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i)
        m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i)->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
    {
        CBlockIndex* active_chain_tip = m_node.chainman->ActiveChain().Tip();
        BOOST_CHECK(SequenceLocks(CTransaction(tx), flags, prevheights, *CreateBlockIndex(active_chain_tip->nHeight + 1, active_chain_tip)));
    }

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime -= SEQUENCE_LOCK_TIME; // undo tricked MTP
    }

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    hash = tx.GetHash();
    AddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast())); // Locktime passes on 2nd block

    // ensure tx is final for a specific case where there is no locktime and block height is zero
    tx.nLockTime = 0;
    BOOST_CHECK(IsFinalTx(CTransaction(tx), /*nBlockHeight=*/0, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast()));

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = m_node.chainman->ActiveChain().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    AddToMempool(tx_mempool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(CTransaction(tx), m_node.chainman->ActiveChain().Tip()->nHeight + 2, m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = m_node.chainman->ActiveChain().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTxAtTip(*Assert(m_node.chainman->ActiveChain().Tip()), CTransaction{tx})); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(CTransaction{tx}, tx_mempool)); // Sequence locks fail

    // CreateNewBlock should stay valid and exclude non-final transactions from the template.
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);

    // None of the absolute height/time locked txs should be included because
    // CreateNewBlock checks IsFinalTx.
    CBlock block{block_template->getBlock()};
    BOOST_CHECK_EQUAL(block.vtx.size(), 1U);
    // If we advance height by 1 and MTP by SEQUENCE_LOCK_TIME, both absolute
    // locked transactions should become mineable.
    std::vector<CBlockIndex*> shifted_mtp_ancestors;
    shifted_mtp_ancestors.reserve(CBlockIndex::nMedianTimeSpan);
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        CBlockIndex* ancestor{Assert(m_node.chainman->ActiveChain().Tip()->GetAncestor(m_node.chainman->ActiveChain().Tip()->nHeight - i))};
        ancestor->nTime += SEQUENCE_LOCK_TIME; // Trick the MedianTimePast
        shifted_mtp_ancestors.push_back(ancestor);
    }
    CBlockIndex* active_chain_tip{m_node.chainman->ActiveChain().Tip()};
    const int original_tip_height{active_chain_tip->nHeight};
    active_chain_tip->nHeight++;
    SetMockTime(active_chain_tip->GetMedianTimePast() + 1);

    block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    block = block_template->getBlock();
    BOOST_CHECK_EQUAL(block.vtx.size(), 3U);

    // Restore temporary chain modifications so later tests in this case do not depend on side effects.
    for (CBlockIndex* ancestor : shifted_mtp_ancestors) {
        ancestor->nTime -= SEQUENCE_LOCK_TIME;
    }
    active_chain_tip->nHeight = original_tip_height;
}

void MinerTestingSetup::TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    const CAmount COINBASE_VALUE{txFirst[0]->vout.at(0).nValue};

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);

    TestMemPoolEntryHelper entry;

    // Test that a tx below min fee but prioritised is included
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = COINBASE_VALUE; // 0 fee
    Txid hashFreePrioritisedTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreePrioritisedTx, 5 * COIN);

    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout[0].nValue = COINBASE_VALUE - 1000;
    // This tx has a low fee: 1000 satoshis
    Txid hashParentTx = tx.GetHash(); // save this txid for later use
    AddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout[0].nValue = COINBASE_VALUE - 10000;
    Txid hashMediumFeeTx = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(10000).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashMediumFeeTx, -5 * COIN);

    // This tx also has a low fee, but is prioritised
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = COINBASE_VALUE - 1000 - 1000; // 1000 satoshi fee
    Txid hashPrioritsedChild = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(1000).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashPrioritsedChild, 2 * COIN);

    // Test that transaction selection properly updates ancestor fee calculations as prioritised
    // parents get included in a block. Create a transaction with two prioritised ancestors, each
    // included by itself: FreeParent <- FreeChild <- FreeGrandchild.
    // When FreeParent is added, a modified entry will be created for FreeChild + FreeGrandchild
    // FreeParent's prioritisation should not be included in that entry.
    // When FreeChild is included, FreeChild's prioritisation should also not be included.
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.vout[0].nValue = COINBASE_VALUE; // 0 fee
    Txid hashFreeParent = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreeParent, 10 * COIN);

    tx.vin[0].prevout.hash = hashFreeParent;
    tx.vout[0].nValue = COINBASE_VALUE; // 0 fee
    Txid hashFreeChild = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(false).FromTx(tx));
    tx_mempool.PrioritiseTransaction(hashFreeChild, 1 * COIN);

    tx.vin[0].prevout.hash = hashFreeChild;
    tx.vout[0].nValue = COINBASE_VALUE; // 0 fee
    Txid hashFreeGrandchild = tx.GetHash();
    AddToMempool(tx_mempool, entry.Fee(0).SpendsCoinbase(false).FromTx(tx));

    auto block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 6U);
    BOOST_CHECK(block.vtx[1]->GetHash() == hashFreeParent);
    BOOST_CHECK(block.vtx[2]->GetHash() == hashFreePrioritisedTx);
    BOOST_CHECK(block.vtx[3]->GetHash() == hashParentTx);
    BOOST_CHECK(block.vtx[4]->GetHash() == hashPrioritsedChild);
    BOOST_CHECK(block.vtx[5]->GetHash() == hashFreeChild);
    for (size_t i=0; i<block.vtx.size(); ++i) {
        // The FreeParent and FreeChild's prioritisations should not impact the child.
        BOOST_CHECK(block.vtx[i]->GetHash() != hashFreeGrandchild);
        // De-prioritised transaction should not be included.
        BOOST_CHECK(block.vtx[i]->GetHash() != hashMediumFeeTx);
    }
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    // Note that by default, these tests run with size accounting enabled.
    CScript scriptPubKey = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    // Create and check a simple template
    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    {
        CBlock block{block_template->getBlock()};
        {
            std::string reason;
            std::string debug;
            BOOST_REQUIRE(!mining->checkBlock(block, {.check_pow = false}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "bad-txnmrklroot");
            BOOST_REQUIRE_EQUAL(debug, "hashMerkleRoot mismatch");
        }

        block.hashMerkleRoot = BlockMerkleRoot(block);

        {
            std::string reason;
            std::string debug;
            BOOST_REQUIRE(mining->checkBlock(block, {.check_pow = false}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "");
            BOOST_REQUIRE_EQUAL(debug, "");
        }

        {
            // A block template does not have proof-of-work, but it might pass
            // verification by coincidence. Grind the nonce if needed:
            while (CheckProofOfWork(block.GetHash(), block.nBits, Assert(m_node.chainman)->GetParams().GetConsensus())) {
                block.nNonce++;
            }

            std::string reason;
            std::string debug;
            BOOST_REQUIRE(!mining->checkBlock(block, {.check_pow = true}, reason, debug));
            BOOST_REQUIRE_EQUAL(reason, "high-hash");
            BOOST_REQUIRE_EQUAL(debug, "proof of work failed");
        }
    }

    // We can't make transactions until we have inputs. Mine a few real blocks,
    // then extend the chain with synthetic indices so coinbase outputs are
    // mature under COINBASE_MATURITY=1000.
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    std::vector<std::unique_ptr<CBlockIndex>> synthetic_chain;
    std::vector<std::unique_ptr<uint256>> synthetic_hashes;
    CBlockIndex* real_tip_after_mining{nullptr};
    for (int i = 0; i < NUM_PREPARATION_BLOCKS; ++i) {
        const int current_height{mining->getTip()->height};

        block_template = mining->createNewBlock(options);
        BOOST_REQUIRE(block_template);

        CBlock block{block_template->getBlock()};
        CMutableTransaction txCoinbase(*block.vtx[0]);
        {
            LOCK(cs_main);
            block.nVersion = VERSIONBITS_TOP_BITS;
            block.nTime = Assert(m_node.chainman)->ActiveChain().Tip()->GetMedianTimePast()+1;
            txCoinbase.version = 1;
            txCoinbase.vin[0].scriptSig = CScript{} << (current_height + 1) << i;
            // Keep the witness commitment output (if present) so RegenerateCommitments can update it.
            txCoinbase.vout[0].scriptPubKey = CScript();
            block.vtx[0] = MakeTransactionRef(txCoinbase);
            node::RegenerateCommitments(block, *Assert(m_node.chainman));
            if (txFirst.empty()) {
                baseheight = current_height;
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(block.vtx[0]);
            }
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        for (block.nNonce = 0; !CheckProofOfWork(block.GetHash(), block.nBits, Assert(m_node.chainman)->GetParams().GetConsensus()); ++block.nNonce) {}

        const std::shared_ptr<const CBlock> shared_pblock{std::make_shared<const CBlock>(block)};
        const bool processed{Assert(m_node.chainman)->ProcessNewBlock(shared_pblock, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr)};
        if (!processed) {
            std::string reason;
            std::string debug;
            const bool valid{mining->checkBlock(block, {.check_pow = false}, reason, debug)};
            BOOST_TEST_MESSAGE("checkBlock(valid=" + std::string(valid ? "true" : "false") + ") reason=" + reason + " debug=" + debug);
        }
        BOOST_REQUIRE(processed);
        {
            LOCK(cs_main);
            // The above calls don't guarantee the tip is actually updated, so
            // we explicitly check this.
            auto maybe_new_tip{Assert(m_node.chainman)->ActiveChain().Tip()};
            BOOST_REQUIRE_EQUAL(maybe_new_tip->GetBlockHash(), block.GetHash());
        }
    }
    {
        LOCK(cs_main);
        real_tip_after_mining = Assert(m_node.chainman)->ActiveChain().Tip();
        const int maturity_target{baseheight + COINBASE_MATURITY + 4};
        while (Assert(m_node.chainman)->ActiveChain().Tip()->nHeight < maturity_target) {
            CBlockIndex* prev{Assert(m_node.chainman)->ActiveChain().Tip()};
            auto next{std::make_unique<CBlockIndex>()};
            auto hash{std::make_unique<uint256>(m_rng.rand256())};
            next->phashBlock = hash.get();
            next->pprev = prev;
            next->nHeight = prev->nHeight + 1;
            next->nVersion = prev->nVersion;
            next->nBits = prev->nBits;
            next->nTime = prev->nTime + 1;
            next->nTimeMax = (prev->nTimeMax > next->nTime) ? prev->nTimeMax : next->nTime;
            next->BuildSkip();
            Assert(m_node.chainman)->ActiveChain().SetTip(*next);
            Assert(m_node.chainman)->ActiveChainstate().CoinsTip().SetBestBlock(next->GetBlockHash());
            (void)Assert(m_node.notifications)->blockTip(SynchronizationState::POST_INIT, *next, /*verification_progress=*/1.0);
            synthetic_hashes.push_back(std::move(hash));
            synthetic_chain.push_back(std::move(next));
        }
    }

    LOCK(cs_main);

    TestBasicMining(scriptPubKey, txFirst, baseheight);

    SetMockTime(0);

    TestPackageSelection(scriptPubKey, txFirst);

    SetMockTime(0);

    TestPrioritisedMining(scriptPubKey, txFirst);

    Assert(real_tip_after_mining);
    Assert(m_node.chainman)->ActiveChain().SetTip(*real_tip_after_mining);
    Assert(m_node.chainman)->ActiveChainstate().CoinsTip().SetBestBlock(real_tip_after_mining->GetBlockHash());
    (void)Assert(m_node.notifications)->blockTip(SynchronizationState::POST_INIT, *real_tip_after_mining, /*verification_progress=*/1.0);
}

BOOST_AUTO_TEST_SUITE_END()
