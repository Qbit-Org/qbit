// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <net.h>
#include <auxpow.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <node/miner.h>
#include <net_processing.h>
#include <pow.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <deque>
#include <utility>

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

/** Parent coinbase padding that makes an AuxPoW header about 1.9 MB, so two fit in one headers message. */
static constexpr size_t LARGE_AUXPOW_PADDING{1'900'000};

/** A valid AuxPoW payload for header whose parent coinbase carries an extra output of padding bytes. */
static std::shared_ptr<const CAuxPow> MakePaddedAuxpow(const CBlockHeader& header, const Consensus::Params& consensus, size_t padding)
{
    // Merged mining header, the aux block hash in display order, merkle size 1 and nonce 0.
    std::vector<unsigned char> commitment{0xfa, 0xbe, 0x6d, 0x6d};
    const uint256 hash{header.GetHash()};
    commitment.insert(commitment.end(), hash.begin(), hash.end());
    std::reverse(commitment.end() - uint256::size(), commitment.end());
    commitment.insert(commitment.end(), {1, 0, 0, 0, 0, 0, 0, 0});

    CMutableTransaction coinbase;
    coinbase.version = 1;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << commitment;
    coinbase.vout.resize(2);
    coinbase.vout[0].scriptPubKey = CScript{} << OP_TRUE;
    coinbase.vout[1].scriptPubKey.resize(padding);

    auto auxpow{std::make_shared<CAuxPow>()};
    auxpow->coinbase_tx = MakeTransactionRef(std::move(coinbase));
    auxpow->parent_block.nVersion = 1;
    auxpow->parent_block.hashMerkleRoot = auxpow->coinbase_tx->GetHash().ToUint256();
    auxpow->parent_block.nTime = header.nTime;
    auxpow->parent_block.nBits = header.nBits;
    while (!CheckProofOfWork(auxpow->parent_block.GetHash(), header.nBits, consensus)) ++auxpow->parent_block.nNonce;
    return auxpow;
}

/** Give an AuxPoW header a payload that makes its headers message entry entry_size bytes. */
static void SetHeadersEntrySize(CBlockHeader& header, const Consensus::Params& consensus, size_t entry_size)
{
    header.auxpow = MakePaddedAuxpow(header, consensus, entry_size);
    header.auxpow = MakePaddedAuxpow(header, consensus, 2 * entry_size - HeadersMessageEntrySize(header));
    BOOST_REQUIRE_EQUAL(HeadersMessageEntrySize(header), entry_size);
}

/** Mine a block onto the active tip whose AuxPoW header is padded by padding bytes. */
static void MineAuxpowBlock(const node::NodeContext& node, size_t padding)
{
    auto& chainman{*Assert(node.chainman)};
    const auto& consensus{chainman.GetConsensus()};
    CBlock block{node::BlockAssembler{chainman.ActiveChainstate(), nullptr, {}}.CreateNewBlock()->block};
    block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, block.GetVersionBits());
    chainman.GenerateCoinbaseCommitment(block, WITH_LOCK(::cs_main, return chainman.ActiveTip()));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.auxpow = MakePaddedAuxpow(block, consensus, padding);
    BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash()), block.GetHash());
}

/** Headers building on base that are not in the block index: num_large AuxPoW headers padded by
 *  LARGE_AUXPOW_PADDING bytes, then num_small ordinary headers. */
static std::vector<CBlockHeader> BuildAuxpowHeaders(const CBlockIndex& base, const Consensus::Params& consensus, size_t num_large, size_t num_small)
{
    std::vector<CBlockHeader> headers;
    CBlockHeader prev{base.GetBlockHeader()};
    for (size_t i{0}; i < num_large + num_small; ++i) {
        const bool large{i < num_large};
        CBlockHeader header;
        header.nVersion = MakeVersion(large ? static_cast<uint16_t>(consensus.nAuxpowChainId) : 0, /*auxpow=*/large, /*version_bits=*/0);
        header.hashPrevBlock = prev.GetHash();
        header.hashMerkleRoot = uint256::ONE;
        header.nTime = prev.nTime + consensus.nPowTargetSpacing;
        header.nBits = base.nBits; // regtest does not retarget
        if (large) {
            header.auxpow = MakePaddedAuxpow(header, consensus, LARGE_AUXPOW_PADDING);
        } else {
            while (!CheckProofOfWork(header.GetHash(), header.nBits, consensus)) ++header.nNonce;
        }
        headers.push_back(header);
        prev = header;
    }
    return headers;
}

static CNode& AddHeadersTestPeer(ConnmanTestMsg& connman, NodeId id) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    auto* peer = new CNode{id,
                           /*sock=*/nullptr,
                           CAddress{},
                           /*nKeyedNetGroupIn=*/static_cast<uint64_t>(id),
                           /*nLocalHostNonceIn=*/static_cast<uint64_t>(id),
                           CAddress{},
                           /*addrNameIn=*/"",
                           ConnectionType::INBOUND,
                           /*inbound_onion=*/false};
    connman.Handshake(*peer, /*successfully_connected=*/true,
                      /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                      /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                      /*version=*/PROTOCOL_VERSION,
                      /*relay_txs=*/true);
    connman.AddTestNode(*peer);
    connman.FlushSendBuffer(*peer);
    return *peer;
}

/** Process a message from peer, as if it had arrived over the network. */
template <typename... Args>
static void ReceiveFromPeer(PeerManager& peerman, CNode& peer, const std::string& msg_type, Args&&... args) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    const CSerializedNetMsg msg{NetMsg::Make(msg_type, std::forward<Args>(args)...)};
    DataStream stream{msg.data};
    const std::atomic<bool> interrupt{false};
    peerman.ProcessMessage(peer, msg_type, stream, /*time_received=*/std::chrono::microseconds{0}, interrupt);
}

static void ReceiveHeadersFromPeer(PeerManager& peerman, CNode& peer, const std::vector<CBlockHeader>& headers) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    // Like a sender, use CBlocks for the 0x00 transaction count after each header.
    const std::vector<CBlock> blocks(headers.begin(), headers.end());
    ReceiveFromPeer(peerman, peer, NetMsgType::HEADERS, TX_WITH_WITNESS(blocks));
}

/** Parse a headers message payload the way PeerManager does. */
static std::vector<CBlockHeader> ParseHeadersMessage(std::span<const unsigned char> payload)
{
    DataStream stream{payload};
    std::vector<CBlockHeader> headers(ReadCompactSize(stream));
    for (CBlockHeader& header : headers) {
        stream >> header;
        BOOST_CHECK_EQUAL(ReadCompactSize(stream), 0U);
    }
    BOOST_CHECK(stream.empty());
    return headers;
}

/** Records the messages sent to peers while in scope. */
class SentMessages
{
public:
    explicit SentMessages(ArgsManager& args) : m_args{args}, m_capture_orig{CaptureMessage}
    {
        m_args.ForceSetArg("-capturemessages", "1");
        CaptureMessage = [this](const CAddress&, const std::string& msg_type, std::span<const unsigned char> data, bool is_incoming) {
            if (!is_incoming) m_messages.emplace_back(msg_type, std::vector<unsigned char>(data.begin(), data.end()));
        };
    }

    ~SentMessages()
    {
        CaptureMessage = m_capture_orig;
        m_args.ForceSetArg("-capturemessages", "0");
    }

    /** Remove and return the payloads of the msg_type messages sent so far. */
    std::vector<std::vector<unsigned char>> Take(const std::string& msg_type)
    {
        std::vector<std::vector<unsigned char>> payloads;
        std::erase_if(m_messages, [&](auto& message) {
            if (message.first != msg_type) return false;
            payloads.push_back(std::move(message.second));
            return true;
        });
        return payloads;
    }

private:
    ArgsManager& m_args;
    const decltype(CaptureMessage) m_capture_orig;
    std::vector<std::pair<std::string, std::vector<unsigned char>>> m_messages;
};

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

BOOST_AUTO_TEST_CASE(headers_message_count_or_size_decides_whether_to_ask_for_more)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto connman = std::make_unique<ConnmanTestMsg>(0x2586, 0x2586, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    const auto& consensus{m_node.chainman->GetConsensus()};
    SentMessages sent{*m_node.args};
    const auto asks_for_more{[&](const std::vector<CBlockHeader>& headers) {
        ReceiveHeadersFromPeer(*peerman, peer, headers);
        connman->FlushSendBuffer(peer);
        BOOST_CHECK(!peer.fDisconnect);
        return !sent.Take(NetMsgType::GETHEADERS).empty();
    }};

    // A message of MAX_HEADERS_RESULTS headers may not hold all of them, as
    // before; one header fewer does. Ordinary headers stay far below the size
    // threshold, so for them the count alone decides.
    const CBlockIndex* genesis{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Genesis())};
    const auto headers{BuildAuxpowHeaders(*genesis, consensus, /*num_large=*/0, /*num_small=*/MAX_HEADERS_RESULTS)};
    BOOST_CHECK_LT(HeadersMessageSize(headers), THRESHOLD_HEADERS_MESSAGE_SIZE);
    BOOST_CHECK(!asks_for_more({headers.begin(), headers.end() - 1}));
    BOOST_CHECK(asks_for_more(headers));

    // With fewer headers, a message of THRESHOLD_HEADERS_MESSAGE_SIZE bytes
    // may have been cut short by size; one byte less may not.
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return m_node.chainman->m_best_header)};
    BOOST_REQUIRE_EQUAL(tip->GetBlockHash(), headers.back().GetHash());
    auto large{BuildAuxpowHeaders(*tip, consensus, /*num_large=*/2, /*num_small=*/0)};
    const size_t first_entry{1'000'000};
    SetHeadersEntrySize(large[0], consensus, first_entry);
    SetHeadersEntrySize(large[1], consensus, THRESHOLD_HEADERS_MESSAGE_SIZE - 1 - GetSizeOfCompactSize(2) - first_entry);
    BOOST_REQUIRE_EQUAL(HeadersMessageSize(large), THRESHOLD_HEADERS_MESSAGE_SIZE - 1);
    BOOST_CHECK(!asks_for_more(large));
    SetHeadersEntrySize(large[1], consensus, THRESHOLD_HEADERS_MESSAGE_SIZE - GetSizeOfCompactSize(2) - first_entry);
    BOOST_REQUIRE_EQUAL(HeadersMessageSize(large), THRESHOLD_HEADERS_MESSAGE_SIZE);
    BOOST_CHECK(asks_for_more(large));

    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(getheaders_reply_with_small_headers_is_unchanged)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto connman = std::make_unique<ConnmanTestMsg>(0x2580, 0x2580, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    MineToHeight(m_node, MAX_HEADERS_RESULTS + 1);
    std::vector<CBlock> expected;
    uint256 genesis_hash, last_expected_hash;
    {
        LOCK(::cs_main);
        const CChain& chain{m_node.chainman->ActiveChain()};
        for (int height{1}; height <= static_cast<int>(MAX_HEADERS_RESULTS); ++height) expected.emplace_back(chain[height]->GetBlockHeader());
        genesis_hash = chain.Genesis()->GetBlockHash();
        last_expected_hash = chain[MAX_HEADERS_RESULTS]->GetBlockHash();
    }

    SentMessages sent{*m_node.args};
    ReceiveFromPeer(*peerman, peer, NetMsgType::GETHEADERS, CBlockLocator{{genesis_hash}}, uint256{});
    auto replies{sent.Take(NetMsgType::HEADERS)};
    BOOST_REQUIRE_EQUAL(replies.size(), 1U);
    // One message of MAX_HEADERS_RESULTS headers, byte for byte what the
    // count-only sender produced.
    BOOST_CHECK(replies[0] == NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(expected)).data);
    BOOST_CHECK(MayHaveMoreHeaders(ParseHeadersMessage(replies[0])));

    ReceiveFromPeer(*peerman, peer, NetMsgType::GETHEADERS, CBlockLocator{{last_expected_hash}}, uint256{});
    replies = sent.Take(NetMsgType::HEADERS);
    BOOST_REQUIRE_EQUAL(replies.size(), 1U);
    const auto last{ParseHeadersMessage(replies[0])};
    BOOST_REQUIRE_EQUAL(last.size(), 1U);
    BOOST_CHECK(!MayHaveMoreHeaders(last));

    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(getheaders_replies_with_large_auxpow_headers_stay_within_receive_limit)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto connman = std::make_unique<ConnmanTestMsg>(0x2581, 0x2581, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    MineToHeight(m_node, 3);
    for (int i{0}; i < 5; ++i) MineAuxpowBlock(m_node, LARGE_AUXPOW_PADDING);
    for (int i{0}; i < 3; ++i) MineAuxpowBlock(m_node, /*padding=*/0);
    std::vector<CBlockHeader> chain_headers;
    {
        LOCK(::cs_main);
        const CChain& chain{m_node.chainman->ActiveChain()};
        for (const CBlockIndex* pindex{chain[1]}; pindex; pindex = chain.Next(pindex)) chain_headers.push_back(pindex->GetBlockHeader());
    }
    // The whole range would not fit in one message.
    size_t chain_bytes{0};
    for (const CBlockHeader& header : chain_headers) chain_bytes += HeadersMessageEntrySize(header);
    BOOST_REQUIRE_GT(chain_bytes, MAX_PROTOCOL_MESSAGE_LENGTH);

    // Request headers like a syncing peer until a reply looks final.
    SentMessages sent{*m_node.args};
    std::vector<CBlockHeader> received;
    std::vector<size_t> reply_sizes;
    uint256 last_hash{Params().GenesisBlock().GetHash()};
    while (true) {
        BOOST_REQUIRE_LT(reply_sizes.size(), chain_headers.size());
        ReceiveFromPeer(*peerman, peer, NetMsgType::GETHEADERS, CBlockLocator{{last_hash}}, uint256{});
        connman->FlushSendBuffer(peer);
        const auto replies{sent.Take(NetMsgType::HEADERS)};
        BOOST_REQUIRE_EQUAL(replies.size(), 1U);
        BOOST_CHECK_LE(replies[0].size(), MAX_PROTOCOL_MESSAGE_LENGTH);
        const auto headers{ParseHeadersMessage(replies[0])};
        BOOST_REQUIRE(!headers.empty());
        BOOST_CHECK_EQUAL(headers.front().hashPrevBlock, last_hash);
        received.insert(received.end(), headers.begin(), headers.end());
        reply_sizes.push_back(headers.size());
        last_hash = headers.back().GetHash();
        if (!MayHaveMoreHeaders(headers)) break;
        // A reply cut short by size still reaches the size threshold.
        BOOST_CHECK_GE(replies[0].size(), THRESHOLD_HEADERS_MESSAGE_SIZE);
    }

    // [3 small, 2 large], [2 large], [1 large, 3 small], each ending at the
    // receive limit until the last, which reaches the tip.
    BOOST_CHECK(reply_sizes == (std::vector<size_t>{5, 2, 4}));
    BOOST_REQUIRE_EQUAL(received.size(), chain_headers.size());
    for (size_t i{0}; i < received.size(); ++i) {
        BOOST_CHECK_EQUAL(received[i].GetHash(), chain_headers[i].GetHash());
        BOOST_CHECK_EQUAL(GetSerializeSize(received[i]), GetSerializeSize(chain_headers[i]));
    }

    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(getheaders_reply_with_oversized_index_auxpow_stays_within_receive_limit)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto connman = std::make_unique<ConnmanTestMsg>(0x2585, 0x2585, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    auto& chainman{*m_node.chainman};
    const auto& consensus{chainman.GetConsensus()};
    MineToHeight(m_node, 2);
    CBlock block{node::BlockAssembler{chainman.ActiveChainstate(), nullptr, {}}.CreateNewBlock()->block};
    block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, block.GetVersionBits());
    chainman.GenerateCoinbaseCommitment(block, WITH_LOCK(::cs_main, return chainman.ActiveTip()));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // AuxPoW is not part of the block hash, so the header can first arrive
    // alone in a headers message with a payload no block could carry, and the
    // block index keeps that payload when the block arrives with its own.
    const size_t oversized_entry{MAX_PROTOCOL_MESSAGE_LENGTH - GetSizeOfCompactSize(1) - 4};
    CBlockHeader header{block.GetBlockHeader()};
    SetHeadersEntrySize(header, consensus, oversized_entry);
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders({{header}}, /*min_pow_checked=*/true, state), state.ToString());
    block.auxpow = MakePaddedAuxpow(block, consensus, /*padding=*/0);
    BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block), /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE_EQUAL(HeadersMessageEntrySize(WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHeader())), oversized_entry);
    for (int i{0}; i < 2; ++i) MineAuxpowBlock(m_node, /*padding=*/0);

    // That header goes alone, with nothing after it pushing the message past
    // the receive limit, and the rest follows on request.
    SentMessages sent{*m_node.args};
    ReceiveFromPeer(*peerman, peer, NetMsgType::GETHEADERS, CBlockLocator{{block.hashPrevBlock}}, uint256{});
    connman->FlushSendBuffer(peer);
    auto replies{sent.Take(NetMsgType::HEADERS)};
    BOOST_REQUIRE_EQUAL(replies.size(), 1U);
    BOOST_CHECK_LE(replies[0].size(), MAX_PROTOCOL_MESSAGE_LENGTH);
    const auto first{ParseHeadersMessage(replies[0])};
    BOOST_REQUIRE_EQUAL(first.size(), 1U);
    BOOST_CHECK_EQUAL(first[0].GetHash(), block.GetHash());
    BOOST_CHECK(MayHaveMoreHeaders(first));

    ReceiveFromPeer(*peerman, peer, NetMsgType::GETHEADERS, CBlockLocator{{block.GetHash()}}, uint256{});
    replies = sent.Take(NetMsgType::HEADERS);
    BOOST_REQUIRE_EQUAL(replies.size(), 1U);
    const auto rest{ParseHeadersMessage(replies[0])};
    BOOST_CHECK_EQUAL(rest.size(), 2U);
    BOOST_CHECK(!MayHaveMoreHeaders(rest));

    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(headers_sync_requests_more_after_byte_limited_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto connman = std::make_unique<ConnmanTestMsg>(0x2582, 0x2582, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    const CBlockIndex* genesis{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Genesis())};
    const auto headers{BuildAuxpowHeaders(*genesis, m_node.chainman->GetConsensus(), /*num_large=*/5, /*num_small=*/3)};
    const auto messages{SplitIntoHeadersMessages(headers)};
    BOOST_REQUIRE_EQUAL(messages.size(), 3U);

    SentMessages sent{*m_node.args};
    for (size_t i{0}; i < messages.size(); ++i) {
        ReceiveHeadersFromPeer(*peerman, peer, messages[i]);
        connman->FlushSendBuffer(peer);
        BOOST_CHECK(!peer.fDisconnect);
        BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return m_node.chainman->m_best_header->GetBlockHash()), messages[i].back().GetHash());
        const auto requests{sent.Take(NetMsgType::GETHEADERS)};
        if (i + 1 < messages.size()) {
            // A byte-limited message far short of MAX_HEADERS_RESULTS headers
            // is not the peer's tip: ask for the headers after it.
            BOOST_CHECK_LT(messages[i].size(), MAX_HEADERS_RESULTS);
            BOOST_REQUIRE_EQUAL(requests.size(), 1U);
            DataStream request{requests[0]};
            CBlockLocator locator;
            request >> locator;
            BOOST_CHECK_EQUAL(locator.vHave.front(), messages[i].back().GetHash());
        } else {
            BOOST_CHECK(requests.empty());
        }
    }

    // A v1.0.0 sender fills a message up to MAX_HEADERS_RESULTS headers
    // regardless of size. If its last message happens to exceed the size
    // threshold, we ask once more and accept the empty reply as final.
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return m_node.chainman->m_best_header)};
    const auto more_headers{BuildAuxpowHeaders(*tip, m_node.chainman->GetConsensus(), /*num_large=*/2, /*num_small=*/0)};
    BOOST_REQUIRE(MayHaveMoreHeaders(more_headers));
    ReceiveHeadersFromPeer(*peerman, peer, more_headers);
    connman->FlushSendBuffer(peer);
    BOOST_CHECK_EQUAL(sent.Take(NetMsgType::GETHEADERS).size(), 1U);
    ReceiveHeadersFromPeer(*peerman, peer, {});
    BOOST_CHECK(sent.Take(NetMsgType::GETHEADERS).empty());
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return m_node.chainman->m_best_header->GetBlockHash()), more_headers.back().GetHash());

    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(low_work_headers_sync_continues_through_byte_limited_messages)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto connman = std::make_unique<ConnmanTestMsg>(0x2583, 0x2583, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    const CBlockIndex* genesis{WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Genesis())};
    const auto headers{BuildAuxpowHeaders(*genesis, m_node.chainman->GetConsensus(), /*num_large=*/5, /*num_small=*/3)};
    const auto messages{SplitIntoHeadersMessages(headers)};
    BOOST_REQUIRE_EQUAL(messages.size(), 3U);

    // Require exactly the work of the whole chain, so that only its last
    // header completes each phase of the low-work headers sync.
    arith_uint256 chain_work{genesis->nChainWork};
    for (const CBlockHeader& header : headers) chain_work += GetBlockProof(CBlockIndex{header});
    const_cast<ChainstateManager::Options&>(m_node.chainman->m_options).minimum_chain_work = chain_work;

    SentMessages sent{*m_node.args};
    const auto next_request_start{[&]() {
        connman->FlushSendBuffer(peer);
        const auto requests{sent.Take(NetMsgType::GETHEADERS)};
        BOOST_REQUIRE_EQUAL(requests.size(), 1U);
        DataStream request{requests[0]};
        CBlockLocator locator;
        request >> locator;
        return locator.vHave.front();
    }};

    // PRESYNC follows the byte-limited messages, then restarts from the
    // chain start once the chain has enough work.
    for (size_t i{0}; i < messages.size(); ++i) {
        ReceiveHeadersFromPeer(*peerman, peer, messages[i]);
        BOOST_CHECK_EQUAL(next_request_start(), i + 1 < messages.size() ? messages[i].back().GetHash() : genesis->GetBlockHash());
        BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return m_node.chainman->m_best_header), genesis);
    }

    // REDOWNLOAD follows them again and then accepts every header.
    for (size_t i{0}; i + 1 < messages.size(); ++i) {
        ReceiveHeadersFromPeer(*peerman, peer, messages[i]);
        BOOST_CHECK_EQUAL(next_request_start(), messages[i].back().GetHash());
        BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return m_node.chainman->m_best_header), genesis);
    }
    ReceiveHeadersFromPeer(*peerman, peer, messages.back());
    connman->FlushSendBuffer(peer);
    BOOST_CHECK(sent.Take(NetMsgType::GETHEADERS).empty());
    BOOST_CHECK(!peer.fDisconnect);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return m_node.chainman->m_best_header->GetBlockHash()), headers.back().GetHash());

    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(headers_announcement_too_large_for_one_message_reverts_to_inv)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);
    auto& chainman{static_cast<TestChainstateManager&>(*m_node.chainman)};
    chainman.JumpOutOfIbd();
    auto connman = std::make_unique<ConnmanTestMsg>(0x2584, 0x2584, *m_node.addrman, *m_node.netgroupman, Params());
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr, chainman, *m_node.mempool, *m_node.warnings, {});
    connman->SetMsgProc(peerman.get());
    m_node.validation_signals->RegisterValidationInterface(peerman.get());
    CNode& peer{AddHeadersTestPeer(*connman, /*id=*/0)};

    // The peer wants headers announcements and has our tip.
    ReceiveFromPeer(*peerman, peer, NetMsgType::SENDHEADERS);
    ReceiveFromPeer(*peerman, peer, NetMsgType::GETHEADERS, CBlockLocator{{WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash())}}, uint256{});
    connman->FlushSendBuffer(peer);

    SentMessages sent{*m_node.args};
    // Small headers are announced in a headers message, as before.
    for (int i{0}; i < 2; ++i) MineAuxpowBlock(m_node, /*padding=*/0);
    peerman->SendMessages(&peer);
    connman->FlushSendBuffer(peer);
    const auto announcements{sent.Take(NetMsgType::HEADERS)};
    BOOST_REQUIRE_EQUAL(announcements.size(), 1U);
    BOOST_CHECK_EQUAL(ParseHeadersMessage(announcements[0]).size(), 2U);

    // Three large AuxPoW headers do not fit in one message: announce the tip
    // with an inv instead, so the peer fetches the headers with getheaders.
    for (int i{0}; i < 3; ++i) MineAuxpowBlock(m_node, LARGE_AUXPOW_PADDING);
    peerman->SendMessages(&peer);
    connman->FlushSendBuffer(peer);
    const uint256 tip_hash{WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash())};
    std::vector<CInv> invs;
    for (const auto& payload : sent.Take(NetMsgType::INV)) {
        DataStream stream{payload};
        std::vector<CInv> payload_invs;
        stream >> payload_invs;
        invs.insert(invs.end(), payload_invs.begin(), payload_invs.end());
    }
    BOOST_CHECK(std::ranges::any_of(invs, [&](const CInv& inv) { return inv.IsMsgBlk() && inv.hash == tip_hash; }));
    BOOST_CHECK(sent.Take(NetMsgType::HEADERS).empty());

    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    m_node.validation_signals->UnregisterValidationInterface(peerman.get());
    peerman->FinalizeNode(peer);
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_SUITE_END()
