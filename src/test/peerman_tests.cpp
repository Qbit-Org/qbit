// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <net.h>
#include <chainparams.h>
#include <node/miner.h>
#include <net_processing.h>
#include <pow.h>
#include <protocol.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <deque>

BOOST_FIXTURE_TEST_SUITE(peerman_tests, RegTestingSetup)

/** Window, in blocks, for connecting to NODE_NETWORK_LIMITED peers */
static constexpr int64_t NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS = 144;

static void mineBlock(const node::NodeContext& node, std::chrono::seconds block_time)
{
    auto curr_time = GetTime<std::chrono::seconds>();
    SetMockTime(block_time); // update time so the block is created with it
    CBlock block = node::BlockAssembler{node.chainman->ActiveChainstate(), nullptr, {}}.CreateNewBlock()->block;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, node.chainman->GetConsensus())) ++block.nNonce;
    block.fChecked = true; // little speedup
    SetMockTime(curr_time); // process block at current time
    Assert(node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    node.validation_signals->SyncWithValidationInterfaceQueue(); // drain events queue
}

static void MineToHeight(const node::NodeContext& node, int target_height)
{
    while (WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Height()) < target_height) {
        const CBlockIndex* tip{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
        assert(tip != nullptr);
        mineBlock(node, std::chrono::seconds{tip->GetBlockTime() + 1});
    }
}

static CBlockHeader MakeHeader(const CBlockHeader& prev_header, const CBlockIndex& prev_index, const Consensus::Params& consensus)
{
    CBlockHeader header;
    header.nVersion = prev_header.nVersion;
    header.hashPrevBlock = prev_header.GetHash();
    header.hashMerkleRoot = prev_header.hashMerkleRoot;
    header.nTime = prev_header.nTime + consensus.nPowTargetSpacing;
    header.nBits = GetNextWorkRequired(&prev_index, &header, consensus);
    header.nNonce = 0;
    while (!CheckProofOfWork(header.GetHash(), header.nBits, consensus)) ++header.nNonce;
    return header;
}

static std::vector<CBlockHeader> BuildHeaders(const CBlockIndex& base_index, const Consensus::Params& consensus, size_t count)
{
    std::vector<CBlockHeader> headers;
    headers.reserve(count);
    std::deque<CBlockIndex> index_chain;
    std::deque<uint256> hashes;
    CBlockHeader prev_header{base_index.GetBlockHeader()};
    const CBlockIndex* prev_index{&base_index};
    for (size_t i = 0; i < count; ++i) {
        headers.push_back(MakeHeader(prev_header, *prev_index, consensus));

        index_chain.emplace_back(headers.back());
        hashes.push_back(headers.back().GetHash());
        CBlockIndex& current_index{index_chain.back()};
        current_index.phashBlock = &hashes.back();
        current_index.pprev = const_cast<CBlockIndex*>(prev_index);
        current_index.nHeight = prev_index->nHeight + 1;
        current_index.BuildSkip();
        current_index.BuildCadenceLaneLinks();

        prev_header = headers.back();
        prev_index = &current_index;
    }
    return headers;
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
    index.BuildCadenceLaneLinks();
    return index;
}

// Verifying when network-limited peer connections are desirable based on the node's proximity to the tip
BOOST_AUTO_TEST_CASE(connections_desirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    auto consensus = m_node.chainman->GetParams().GetConsensus();

    // Check we start connecting to full nodes
    ServiceFlags peer_flags{NODE_WITNESS | NODE_NETWORK_LIMITED};
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // Make peerman aware of the initial best block and verify we accept limited peers when we start close to the tip time.
    auto tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    uint64_t tip_block_time = tip->GetBlockTime();
    int tip_block_height = tip->nHeight;
    peerman->SetBestBlock(tip_block_height, std::chrono::seconds{tip_block_time});

    SetMockTime(tip_block_time + 1); // Set node time to tip time
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Check we don't disallow limited peers connections when we are behind but still recoverable (below the connection safety window)
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS - 1)});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Check we disallow limited peers connections when we are further than the limited peers safety window
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * 2});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // By now, we tested that the connections desirable services flags change based on the node's time proximity to the tip.
    // Now, perform the same tests for when the node receives a block.
    m_node.validation_signals->RegisterValidationInterface(peerman.get());

    // First, verify a block in the past doesn't enable limited peers connections
    // At this point, our time is (NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1) * 10 minutes ahead the tip's time.
    mineBlock(m_node, /*block_time=*/std::chrono::seconds{tip_block_time + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));

    // Verify a block close to the tip enables limited peers connections
    mineBlock(m_node, /*block_time=*/GetTime<std::chrono::seconds>());
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS));

    // Lastly, verify the stale tip checks can disallow limited peers connections after not receiving blocks for a prolonged period.
    SetMockTime(GetTime<std::chrono::seconds>() + std::chrono::seconds{consensus.nPowTargetSpacing * NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS + 1});
    BOOST_CHECK(peerman->GetDesirableServiceFlags(peer_flags) == ServiceFlags(NODE_NETWORK | NODE_WITNESS));
}

BOOST_AUTO_TEST_CASE(undesirable_service_flags)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});

    BOOST_CHECK(peerman->HasUndesirableServiceFlags(NODE_WITNESS_PRUNED));
    BOOST_CHECK(peerman->HasUndesirableServiceFlags(ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED)));
    BOOST_CHECK(!peerman->HasUndesirableServiceFlags(ServiceFlags(NODE_NETWORK | NODE_WITNESS)));
}

BOOST_AUTO_TEST_CASE(undesirable_service_flags_relax_after_witness_pruning_without_pending_recovery)
{
    std::unique_ptr<PeerManager> peerman = PeerManager::make(*m_node.connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});

    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.m_have_witness_pruned = true);
    BOOST_CHECK(!peerman->HasUndesirableServiceFlags(ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED)));

    const uint256 recovery_hash{uint256::ONE};
    CBlockIndex recovery_index;
    recovery_index.phashBlock = &recovery_hash;
    WITH_LOCK(::cs_main, m_node.chainman->ScheduleWitnessRecovery(recovery_index));
    BOOST_CHECK(peerman->HasUndesirableServiceFlags(ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED)));
}

BOOST_AUTO_TEST_CASE(headers_direct_fetch_skips_historical_block_requiring_witness_from_witness_pruned_peer)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());

    auto* peer = new CNode{/*id=*/0,
                           /*sock=*/nullptr,
                           CAddress{},
                           /*nKeyedNetGroupIn=*/0,
                           /*nLocalHostNonceIn=*/0,
                           CAddress{},
                           /*addrNameIn=*/"",
                           ConnectionType::INBOUND,
                           /*inbound_onion=*/false};
    connman->Handshake(*peer, /*successfully_connected=*/true,
                       /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED),
                       /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                       /*version=*/PROTOCOL_VERSION,
                       /*relay_txs=*/true);
    connman->AddTestNode(*peer);

    MineToHeight(m_node, COINBASE_MATURITY);
    const CBlockIndex* active_tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(active_tip != nullptr);
    BOOST_REQUIRE_EQUAL(active_tip->nHeight, COINBASE_MATURITY);
    const auto headers{BuildHeaders(*active_tip, m_node.chainman->GetConsensus(), COINBASE_MATURITY + 3)};

    SetMockTime(std::chrono::seconds{headers.back().nTime + 1});
    BlockValidationState state;
    const CBlockIndex* peer_tip{nullptr};
    BOOST_REQUIRE_MESSAGE(
        m_node.chainman->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &peer_tip),
        state.ToString());
    BOOST_REQUIRE(peer_tip != nullptr);

    auto& mutable_opts = const_cast<ChainstateManager::Options&>(m_node.chainman->m_options);
    mutable_opts.assumed_valid_block = uint256::ZERO;
    peerman->SetBestKnownBlockForTest(peer->GetId(), *peer_tip);

    const CBlockIndex* historical{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(headers.front().GetHash()))};
    BOOST_REQUIRE(historical != nullptr);
    BOOST_CHECK(WITH_LOCK(::cs_main, return m_node.chainman->NeedsWitnessForValidation(*historical)));
    BOOST_CHECK(WITH_LOCK(::cs_main, return historical->IsValid(BLOCK_VALID_TREE)));

    SetMockTime(std::chrono::seconds{active_tip->GetBlockTime() + 1});
    peerman->HeadersDirectFetchBlocksForTest(*peer, *historical);

    CNodeStateStats stats;
    BOOST_REQUIRE(peerman->GetNodeStateStats(peer->GetId(), stats));
    BOOST_CHECK(stats.vHeightInFlight.empty());
    BOOST_CHECK(!peerman->RequestedStrippedForTest(peer->GetId(), headers.front().GetHash()).has_value());

    peerman->FinalizeNode(*peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(headers_direct_fetch_skips_historical_block_from_witness_pruned_peer_even_when_assumevalid_covers_it)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto connman = std::make_unique<ConnmanTestMsg>(0x2442, 0x2442, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());

    auto* peer = new CNode{/*id=*/1,
                           /*sock=*/nullptr,
                           CAddress{},
                           /*nKeyedNetGroupIn=*/1,
                           /*nLocalHostNonceIn=*/1,
                           CAddress{},
                           /*addrNameIn=*/"",
                           ConnectionType::INBOUND,
                           /*inbound_onion=*/false};
    connman->Handshake(*peer, /*successfully_connected=*/true,
                       /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_WITNESS_PRUNED),
                       /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                       /*version=*/PROTOCOL_VERSION,
                       /*relay_txs=*/true);
    connman->AddTestNode(*peer);

    MineToHeight(m_node, COINBASE_MATURITY);
    const CBlockIndex* active_tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip())};
    BOOST_REQUIRE(active_tip != nullptr);
    BOOST_REQUIRE_EQUAL(active_tip->nHeight, COINBASE_MATURITY);
    const auto headers{BuildHeaders(*active_tip, m_node.chainman->GetConsensus(), COINBASE_MATURITY + 3)};

    SetMockTime(std::chrono::seconds{headers.back().nTime + 1});
    BlockValidationState state;
    const CBlockIndex* peer_tip{nullptr};
    BOOST_REQUIRE_MESSAGE(
        m_node.chainman->ProcessNewBlockHeaders(headers, /*min_pow_checked=*/true, state, &peer_tip),
        state.ToString());
    BOOST_REQUIRE(peer_tip != nullptr);

    auto& mutable_opts = const_cast<ChainstateManager::Options&>(m_node.chainman->m_options);
    mutable_opts.assumed_valid_block = headers.back().GetHash();
    peerman->SetBestKnownBlockForTest(peer->GetId(), *peer_tip);

    const CBlockIndex* historical{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(headers.front().GetHash()))};
    BOOST_REQUIRE(historical != nullptr);
    BOOST_CHECK(!WITH_LOCK(::cs_main, return m_node.chainman->NeedsWitnessForValidation(*historical)));
    BOOST_CHECK(WITH_LOCK(::cs_main, return m_node.chainman->RequiresWitnessForPeerBlock(*historical)));
    BOOST_CHECK(WITH_LOCK(::cs_main, return historical->IsValid(BLOCK_VALID_TREE)));

    SetMockTime(std::chrono::seconds{active_tip->GetBlockTime() + 1});
    peerman->HeadersDirectFetchBlocksForTest(*peer, *historical);

    CNodeStateStats stats;
    BOOST_REQUIRE(peerman->GetNodeStateStats(peer->GetId(), stats));
    BOOST_CHECK(stats.vHeightInFlight.empty());
    BOOST_CHECK(!peerman->RequestedStrippedForTest(peer->GetId(), headers.front().GetHash()).has_value());

    peerman->FinalizeNode(*peer);
    connman->ClearTestNodes();
}

BOOST_FIXTURE_TEST_CASE(recovery_block_source_updates_to_latest_peer_after_retry, TestChain100Setup)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto connman = std::make_unique<ConnmanTestMsg>(0x3670, 0x3670, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());

    auto* peer1 = new CNode{/*id=*/2,
                            /*sock=*/nullptr,
                            CAddress{},
                            /*nKeyedNetGroupIn=*/2,
                            /*nLocalHostNonceIn=*/2,
                            CAddress{},
                            /*addrNameIn=*/"",
                            ConnectionType::INBOUND,
                            /*inbound_onion=*/false};
    connman->Handshake(*peer1, /*successfully_connected=*/true,
                       /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                       /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                       /*version=*/PROTOCOL_VERSION,
                       /*relay_txs=*/true);
    connman->AddTestNode(*peer1);

    auto* peer2 = new CNode{/*id=*/3,
                            /*sock=*/nullptr,
                            CAddress{},
                            /*nKeyedNetGroupIn=*/3,
                            /*nLocalHostNonceIn=*/3,
                            CAddress{},
                            /*addrNameIn=*/"",
                            ConnectionType::INBOUND,
                            /*inbound_onion=*/false};
    connman->Handshake(*peer2, /*successfully_connected=*/true,
                       /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                       /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                       /*version=*/PROTOCOL_VERSION,
                       /*relay_txs=*/true);
    connman->AddTestNode(*peer2);

    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const CBlock candidate_block{CreateBlock({}, P2MROpTrueScript(), chainstate)};
    const uint256 candidate_hash{candidate_block.GetHash()};
    CBlockIndex* recovery_index{nullptr};

    {
        LOCK(::cs_main);
        CBlockIndex* active_tip = chainman.ActiveChain().Tip();
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
        recovery_index = &candidate;

        BOOST_REQUIRE(chainman.ScheduleWitnessRecovery(*recovery_index));
    }

    BOOST_REQUIRE(recovery_index != nullptr);
    BOOST_REQUIRE(peerman->RequestWitnessRecoveryForTest(peer1->GetId(), *recovery_index));
    std::atomic<bool> interrupt_dummy{false};
    const std::chrono::microseconds time_received_dummy{0};
    const auto msg_block_1{NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(candidate_block))};
    DataStream msg_block_stream_1{msg_block_1.data};
    peerman->ProcessMessage(*peer1, NetMsgType::BLOCK, msg_block_stream_1, time_received_dummy, interrupt_dummy);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_CHECK(chainman.m_blockman.HaveRecoveredBlock(candidate_hash));
    const auto source1{peerman->BlockSourcePeerForTest(candidate_hash)};
    BOOST_REQUIRE(source1.has_value());
    BOOST_CHECK_EQUAL(*source1, peer1->GetId());

    BOOST_REQUIRE(chainman.m_blockman.RemoveRecoveredBlock(candidate_hash));
    BOOST_REQUIRE_NE(WITH_LOCK(::cs_main, return chainman.PendingWitnessRecovery()), nullptr);

    BOOST_REQUIRE(peerman->RequestWitnessRecoveryForTest(peer2->GetId(), *recovery_index));
    const auto msg_block_2{NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(candidate_block))};
    DataStream msg_block_stream_2{msg_block_2.data};
    peerman->ProcessMessage(*peer2, NetMsgType::BLOCK, msg_block_stream_2, time_received_dummy, interrupt_dummy);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_CHECK(chainman.m_blockman.HaveRecoveredBlock(candidate_hash));
    const auto source2{peerman->BlockSourcePeerForTest(candidate_hash)};
    BOOST_REQUIRE(source2.has_value());
    BOOST_CHECK_EQUAL(*source2, peer2->GetId());

    peerman->FinalizeNode(*peer1);
    peerman->FinalizeNode(*peer2);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_SUITE_END()
