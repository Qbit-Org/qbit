#include <clock.h>
#include <fec.h>
#include <mainnet_block_headers.h>
#include <peer_manager.h>
#include <protocol.h>
#include <relay_engine.h>
#include <scheduler.h>
#include <udp_transport.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__GLIBC__)
#include <malloc.h>
#if __GLIBC_PREREQ(2, 33)
#define PHOTON_TEST_HAVE_MALLINFO2 1
#endif
#endif

namespace {

using photon::BlockChunkPayload;
using photon::BlockHeaderPayload;
using photon::InboundPeerInfo;
using photon::MessageType;
using photon::MockClock;
using photon::Packet;
using photon::ParentCheck;
using photon::PeerConfig;
using photon::PeerManager;
using photon::PeerRelayStats;
using photon::RelayEngine;
using photon::RelayEngineConfig;
using photon::RelayStats;
using photon::SubmitOutcome;

constexpr std::uint64_t kRemoteSessionId = 7001;

void Require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::array<std::uint8_t, 32> Key(std::uint8_t seed)
{
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(seed + i);
    }
    return key;
}

std::vector<std::uint8_t> RandomBytes(std::size_t size, std::uint64_t seed)
{
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<std::uint8_t> out(size);
    for (std::uint8_t& byte : out) {
        byte = static_cast<std::uint8_t>(dist(rng));
    }
    return out;
}

// A serialized block: an 80-byte header followed by transaction bytes. The relay reads only the
// header, so random bytes serve as both.
std::vector<std::uint8_t> MakeBlock(std::size_t size, std::uint64_t seed)
{
    Require(size > 80, "test block must hold a header and a transaction count");
    return RandomBytes(size, seed);
}

std::string HashOf(const std::vector<std::uint8_t>& block)
{
    const auto summary = photon::ReadBlockHeaderSummary(block);
    Require(summary.has_value(), "test block header should be readable");
    return summary->hash_hex;
}

// The identifier earlier versions announce a block under (its hash's leading 64 bits). Receivers
// still accept it, so most tests below use it.
std::uint64_t PrefixOf(const std::vector<std::uint8_t>& block)
{
    return photon::HashPrefixFromHex(HashOf(block));
}

// The identifier this version announces a block under (its hash's low-order 64 bits).
std::uint64_t BlockIdOf(const std::vector<std::uint8_t>& block)
{
    return photon::BlockIdFromHex(HashOf(block));
}

PeerConfig MakePeer(std::uint16_t port, const std::array<std::uint8_t, 32>& key)
{
    PeerConfig peer{};
    peer.name = "peer";
    peer.host = "127.0.0.1";
    peer.port = port;
    peer.hmac_key = key;
    return peer;
}

class RecordingSink final : public photon::PacketSink {
public:
    struct Sent {
        Packet packet{};
        sockaddr_storage addr{};
        socklen_t addr_len{0};
    };

    bool SendPacket(const Packet& packet,
                    const sockaddr_storage& addr,
                    socklen_t addr_len,
                    std::string*) override
    {
        sent.push_back(Sent{packet, addr, addr_len});
        return true;
    }

    std::vector<Sent> sent{};
};

class CapturingSubmitter final : public photon::BlockSubmitter {
public:
    ParentCheck CheckParent(const std::string& block_hash_hex, const std::string& prev_hash_hex, std::uint32_t max_depth) override
    {
        if (check_hook) {
            check_hook();
        }
        ++check_calls;
        last_block_hash = block_hash_hex;
        last_prev_hash = prev_hash_hex;
        last_max_depth = max_depth;
        if (!parent_results.empty()) {
            const ParentCheck result = parent_results.front();
            parent_results.pop_front();
            return result;
        }
        return parent_result;
    }

    SubmitOutcome SubmitBlock(std::span<const std::uint8_t> block_data) override
    {
        ++submit_calls;
        last_block.assign(block_data.begin(), block_data.end());
        return submit_hook ? submit_hook(block_data) : submit_result;
    }

    ParentCheck parent_result{ParentCheck::kNearTip};
    // Answers for the next parent checks, before parent_result applies.
    std::deque<ParentCheck> parent_results{};
    SubmitOutcome submit_result{SubmitOutcome::kAccepted};
    std::function<void()> check_hook{};
    std::function<SubmitOutcome(std::span<const std::uint8_t>)> submit_hook{};
    std::size_t check_calls{0};
    std::size_t submit_calls{0};
    std::string last_block_hash{};
    std::string last_prev_hash{};
    std::uint32_t last_max_depth{0};
    std::vector<std::uint8_t> last_block{};
};

struct TestBlock {
    std::vector<std::uint8_t> bytes{};
    std::uint64_t prefix{0};
    photon::fec::EncodedBlock encoded{};
};

TestBlock EncodeTestBlock(std::size_t size, std::uint64_t seed, std::uint16_t data_chunks = 2)
{
    TestBlock block;
    block.bytes = MakeBlock(size, seed);
    block.prefix = PrefixOf(block.bytes);
    photon::fec::Encoder encoder(photon::fec::Parameters::FromDataChunkCount(data_chunks));
    block.encoded = encoder.Encode(block.bytes);
    return block;
}

bool ResolveLoopback(const std::string& host,
                     std::uint16_t port,
                     sockaddr_storage* out_addr,
                     socklen_t* out_len,
                     std::string* error)
{
    return photon::UdpTransport::ResolveEndpoint(host, port, out_addr, out_len, error);
}

sockaddr_storage ResolveAddrOrThrow(std::uint16_t port, socklen_t& out_len)
{
    sockaddr_storage addr{};
    std::string error;
    const bool ok = photon::UdpTransport::ResolveEndpoint("127.0.0.1", port, &addr, &out_len, &error);
    Require(ok, "failed to resolve test peer address");
    return addr;
}

void ActivatePeer(PeerManager& manager,
                  RecordingSink& sink,
                  const std::array<std::uint8_t, 32>& key,
                  std::uint16_t port)
{
    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(port, addr_len);

    Packet synack = photon::MakePacket(MessageType::kSynAck, 7);
    photon::SynPayload syn{};
    syn.session_id = kRemoteSessionId;
    syn.peer_id = 8001;
    photon::EncodeSynPayload(syn, synack.payload);
    photon::AttachPacketMac(synack, key);

    const bool accepted = manager.HandleInbound(synack, addr, addr_len);
    Require(accepted, "expected signed SynAck to activate peer");
    Require(manager.ActivePeerCount() == 1, "peer should be active after handshake");
}

BlockChunkPayload BuildChunkPayload(const photon::fec::Chunk& chunk, std::uint64_t hash_prefix)
{
    BlockChunkPayload payload{};
    payload.block_hash_prefix = hash_prefix;
    payload.coding_group_id = chunk.coding_group_id;
    payload.chunk_id = chunk.chunk_id;
    payload.flags = 0;
    payload.data_len = static_cast<std::uint16_t>(photon::kFecChunkSize);
    payload.chunk_data = chunk.bytes;
    return payload;
}

BlockHeaderPayload BuildHeaderPayload(const photon::fec::EncodedBlock& encoded,
                                      std::uint64_t hash_prefix,
                                      std::size_t original_size)
{
    BlockHeaderPayload header{};
    header.block_hash_prefix = hash_prefix;
    header.original_size = static_cast<std::uint64_t>(original_size);
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;
    return header;
}

std::size_t CountSent(const std::vector<RecordingSink::Sent>& sent, MessageType type)
{
    std::size_t count = 0;
    for (const auto& item : sent) {
        if (item.packet.msg_type == type) {
            ++count;
        }
    }
    return count;
}

void TestOutboundEncodeSchedulePump()
{
    MockClock clock{};
    RecordingSink sink;
    CapturingSubmitter submitter;
    (void)submitter;

    const auto key = Key(1);
    constexpr std::uint16_t kPort = 42001;

    PeerManager manager({MakePeer(kPort, key)}, clock, ResolveLoopback);
    ActivatePeer(manager, sink, key, kPort);
    sink.sent.clear();

    RelayEngine engine(clock);
    const std::string hash_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const std::vector<std::uint8_t> block = RandomBytes(5000, 0xA11CE);

    engine.OnNewBlock(hash_hex, block);
    engine.PumpOutbound(sink, manager);

    Require(CountSent(sink.sent, MessageType::kBlockHeader) == 3, "expected 3 redundant block headers");
    Require(CountSent(sink.sent, MessageType::kBlockChunk) > 0, "expected outbound block chunks");
}

void TestOutboundPreemption()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(11);
    constexpr std::uint16_t kPort = 42002;

    PeerManager manager({MakePeer(kPort, key)}, clock, ResolveLoopback);
    ActivatePeer(manager, sink, key, kPort);
    sink.sent.clear();

    RelayEngine engine(clock, RelayEngineConfig{.fec_overhead_ratio = 1.2, .max_outbound_chunks_per_tick = 8, .seen_blocks_capacity = 16});

    const std::string old_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string new_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const std::vector<std::uint8_t> old_block = RandomBytes(100000, 0x1111);
    const std::vector<std::uint8_t> new_block = RandomBytes(100000, 0x2222);

    engine.OnNewBlock(old_hash, old_block);
    engine.PumpOutbound(sink, manager);

    sink.sent.clear();
    engine.OnNewBlock(new_hash, new_block);
    engine.PumpOutbound(sink, manager);

    bool saw_new_prefix = false;
    for (const auto& item : sink.sent) {
        if (item.packet.msg_type == MessageType::kBlockHeader) {
            BlockHeaderPayload header{};
            Require(photon::DecodeBlockHeaderPayload(item.packet.payload, header), "header decode failed");
            saw_new_prefix = header.block_hash_prefix == photon::BlockIdFromHex(new_hash);
            break;
        }
    }

    Require(saw_new_prefix, "expected preempted outbound stream to switch to new hash prefix");
}

void TestInboundReconstructionAllChunks()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(20);
    const std::vector<std::uint8_t> block = MakeBlock(5000, 0x3333);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);
    BlockHeaderPayload header{};
    header.block_hash_prefix = kPrefix;
    header.original_size = static_cast<std::uint64_t>(block.size());
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;
    engine.OnBlockHeader(header, submitter);

    for (std::uint16_t id = 0; id < encoded.params.data_chunks; ++id) {
        const auto& chunk = encoded.chunks[id];
        engine.OnBlockChunk(BuildChunkPayload(chunk, kPrefix), submitter);
    }

    Require(submitter.submit_calls == 1, "expected one successful submit");
    Require(submitter.last_block == block, "reconstructed block mismatch");
    Require(submitter.check_calls == 1, "expected one parent check before the submit");
}

void TestInboundDedupKnownPrefix()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const std::string hash_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const std::uint64_t prefix = photon::BlockIdFromHex(hash_hex);

    const std::vector<std::uint8_t> block = RandomBytes(4000, 0x4444);
    engine.OnNewBlock(hash_hex, block);

    BlockChunkPayload chunk{};
    chunk.block_hash_prefix = prefix;
    chunk.coding_group_id = 0;
    chunk.chunk_id = 0;
    chunk.data_len = static_cast<std::uint16_t>(photon::kFecChunkSize);
    chunk.chunk_data.fill(0);

    const RelayStats before = engine.stats();
    engine.OnBlockChunk(chunk, submitter);

    Require(engine.stats().blocks_already_known == before.blocks_already_known + 1,
            "known-prefix chunk should increment dedup counter");
    Require(submitter.submit_calls == 0, "known-prefix chunk must not submit");
}

void TestInboundWithLossStillRecovers()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(20);
    const std::vector<std::uint8_t> block = MakeBlock(5000, 0x5555);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);
    BlockHeaderPayload header{};
    header.block_hash_prefix = kPrefix;
    header.original_size = static_cast<std::uint64_t>(block.size());
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;
    engine.OnBlockHeader(header, submitter);

    for (std::uint16_t id = 1; id < encoded.params.data_chunks; ++id) {
        engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[id], kPrefix), submitter);
    }
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[encoded.params.data_chunks], kPrefix), submitter);

    Require(submitter.submit_calls == 1, "expected loss scenario to recover with parity");
    Require(submitter.last_block == block, "loss-recovered block mismatch");
}

void TestBlockHeaderFlowCreatesDecoder()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0xABCDE);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    Require(submitter.submit_calls == 0, "chunk before header should not submit");

    BlockHeaderPayload header{};
    header.block_hash_prefix = kPrefix;
    header.original_size = static_cast<std::uint64_t>(block.size());
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;
    engine.OnBlockHeader(header, submitter);

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);

    Require(submitter.submit_calls == 1, "header + buffered chunk flow should submit once complete");
    Require(submitter.last_block == block, "header flow reconstructed block mismatch");
}

void TestDuplicateHeaderDoesNotResetProgress()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0x7E1A7);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);

    BlockHeaderPayload header{};
    header.block_hash_prefix = kPrefix;
    header.original_size = static_cast<std::uint64_t>(block.size());
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;

    engine.OnBlockHeader(header, submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);

    // Duplicate header should not clear already-ingested decoder state.
    engine.OnBlockHeader(header, submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);

    Require(submitter.submit_calls == 1, "duplicate header should not prevent completion");
    Require(submitter.last_block == block, "duplicate header flow reconstructed block mismatch");
}

void TestSamePrefixConflictingPeerDoesNotPoisonHonestRelay()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0x40E57);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);
    const InboundPeerInfo honest_peer{
        .slot_index = 0,
        .remote_session_id = 7001,
        .remote_peer_id = 8001,
    };
    const InboundPeerInfo malicious_peer{
        .slot_index = 1,
        .remote_session_id = 7002,
        .remote_peer_id = 8002,
    };

    BlockHeaderPayload malicious_header = BuildHeaderPayload(encoded, kPrefix, block.size());
    malicious_header.data_chunks = 3;
    malicious_header.coding_group_count = 1;

    engine.OnBlockHeader(malicious_peer, malicious_header, submitter);
    engine.OnBlockHeader(honest_peer, BuildHeaderPayload(encoded, kPrefix, block.size()), submitter);
    engine.OnBlockChunk(honest_peer, BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    engine.OnBlockChunk(honest_peer, BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);

    Require(submitter.submit_calls == 1, "conflicting peer header should not suppress honest relay");
    Require(submitter.last_block == block, "honest peer relay reconstructed block mismatch");
    Require(engine.stats().submit_successes == 1, "honest peer relay should submit successfully");
}

void TestOversizedInboundHeaderRejected()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_original_size = 8;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    BlockHeaderPayload header{};
    header.block_hash_prefix = 0x1010101010101010ULL;
    header.original_size = config.max_inbound_original_size + 1;
    header.data_chunks = 2;
    header.coding_group_count = 1;

    engine.OnBlockHeader(header, submitter);

    Require(engine.stats().inbound_rejected == 1, "oversized header should be rejected");
    Require(submitter.submit_calls == 0, "oversized header must not submit");
}

void TestZeroSizeInboundHeaderRejected()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    BlockHeaderPayload header{};
    header.block_hash_prefix = 0x2020202020202020ULL;
    header.original_size = 0;
    header.data_chunks = 2;
    header.coding_group_count = 1;

    engine.OnBlockHeader(header, submitter);

    const RelayStats stats = engine.stats();
    Require(stats.inbound_rejected == 1, "zero-size header should be rejected");
    Require(stats.submit_successes == 0, "zero-size header must not count as submitted");
    Require(stats.blocks_received_in == 0, "zero-size header must not count as a received block");
    Require(submitter.submit_calls == 0, "zero-size header must not submit");
}

void TestCm256HeaderAcceptedWithinDecoderBudget()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    BlockHeaderPayload header{};
    header.block_hash_prefix = 0x2020202020202021ULL;
    header.original_size = 2'000'000;
    header.data_chunks = photon::fec::CM256_MAX_DATA_CHUNKS;
    header.coding_group_count = 63;

    engine.OnBlockHeader(header, submitter);

    Require(engine.stats().inbound_rejected == 0, "CM256 header should fit decoder budget");
    Require(submitter.submit_calls == 0, "incomplete accepted CM256 header must not submit");
}

void TestPostHeaderChunkFailureErasesDecoder()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0xBAD);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);
    engine.OnBlockHeader(BuildHeaderPayload(encoded, kPrefix, block.size()), submitter);

    BlockChunkPayload invalid = BuildChunkPayload(encoded.chunks[0], kPrefix);
    invalid.coding_group_id = encoded.coding_group_count;
    engine.OnBlockChunk(invalid, submitter);

    Require(engine.stats().inbound_rejected == 1, "invalid post-header chunk should be rejected");

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);
    Require(submitter.submit_calls == 0, "invalid post-header chunk should erase decoder state");
}

void TestMismatchedCodingGroupCountRejected()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(20);
    const std::vector<std::uint8_t> block = RandomBytes(5000, 0x5150);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    BlockHeaderPayload header = BuildHeaderPayload(encoded, 0x3030303030303030ULL, block.size());
    ++header.coding_group_count;

    engine.OnBlockHeader(header, submitter);

    Require(engine.stats().inbound_rejected == 1, "mismatched coding group count should be rejected");
    Require(submitter.submit_calls == 0, "group-count rejection must not submit");
}

void TestDefaultFecHeaderAcceptedWithinDecoderBudget()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const photon::fec::Parameters params = photon::fec::Parameters::FromOverheadRatio(1.2);
    BlockHeaderPayload header{};
    header.block_hash_prefix = 0x4040404040404040ULL;
    header.original_size = 2'000'000;
    header.data_chunks = params.data_chunks;
    header.coding_group_count = 8;

    engine.OnBlockHeader(header, submitter);

    Require(engine.stats().inbound_rejected == 0, "default FEC header should fit decoder budget");
    Require(submitter.submit_calls == 0, "incomplete accepted header must not submit");
}

void TestInboundEntryLimitEvictsOldestPrefix()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_entries = 2;
    config.max_inbound_buffered_chunks_per_entry = 4;
    config.max_inbound_buffered_bytes = 4 * photon::fec::FEC_CHUNK_SIZE;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const TestBlock evicted = EncodeTestBlock(100, 0x11);
    const TestBlock second = EncodeTestBlock(100, 0x12);
    const TestBlock kept = EncodeTestBlock(100, 0x13);

    engine.OnBlockChunk(BuildChunkPayload(evicted.encoded.chunks[0], evicted.prefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(BuildChunkPayload(second.encoded.chunks[0], second.prefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(BuildChunkPayload(kept.encoded.chunks[0], kept.prefix), submitter);

    Require(engine.stats().inbound_evictions == 1, "entry cap should evict one incomplete relay");

    engine.OnBlockHeader(BuildHeaderPayload(evicted.encoded, evicted.prefix, evicted.bytes.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(evicted.encoded.chunks[1], evicted.prefix), submitter);
    Require(submitter.submit_calls == 0, "oldest evicted prefix should have lost its buffered chunk");

    engine.OnBlockHeader(BuildHeaderPayload(kept.encoded, kept.prefix, kept.bytes.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(kept.encoded.chunks[1], kept.prefix), submitter);
    Require(submitter.submit_calls == 1, "newer prefix should still reconstruct inside entry cap");
    Require(submitter.last_block == kept.bytes, "entry-cap reconstruction mismatch");
}

void TestInboundAgeLimitEvictsIncompleteRelay()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_age = std::chrono::milliseconds{10};
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;
    RecordingSink sink;
    PeerManager manager(std::vector<PeerConfig>{}, clock, ResolveLoopback);

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0xA6E);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{11});
    engine.PumpOutbound(sink, manager);

    Require(engine.stats().inbound_evictions == 1, "age cap should evict stale incomplete relay");

    engine.OnBlockHeader(BuildHeaderPayload(encoded, kPrefix, block.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);
    Require(submitter.submit_calls == 0, "age-evicted prefix should have lost its buffered chunk");
}

void TestInboundAgeLimitUsesLastActivity()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_age = std::chrono::milliseconds{10};
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;
    RecordingSink sink;
    PeerManager manager(std::vector<PeerConfig>{}, clock, ResolveLoopback);

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0x510);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{8});
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{8});
    engine.PumpOutbound(sink, manager);

    Require(engine.stats().inbound_evictions == 0, "recently active relay should not be evicted");

    engine.OnBlockHeader(BuildHeaderPayload(encoded, kPrefix, block.size()), submitter);
    Require(submitter.submit_calls == 1, "active slow relay should reconstruct after delayed header");
    Require(submitter.last_block == block, "last-activity reconstruction mismatch");
}

void TestInboundPreHeaderBufferedByteLimit()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_buffered_chunks_per_entry = 4;
    config.max_inbound_buffered_bytes = photon::fec::FEC_CHUNK_SIZE;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0xB17E);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);

    Require(engine.stats().inbound_rejected == 1, "global buffered-byte cap should reject second pre-header chunk");

    engine.OnBlockHeader(BuildHeaderPayload(encoded, kPrefix, block.size()), submitter);
    Require(submitter.submit_calls == 0, "dropped pre-header chunk must not be available after header");

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);
    Require(submitter.submit_calls == 1, "post-header chunk should complete reconstruction");
    Require(submitter.last_block == block, "byte-limit reconstruction mismatch");
}

void TestRejectedNewPrefixChunkDoesNotEvictExistingRelay()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_entries = 2;
    config.max_inbound_buffered_chunks_per_entry = 1;
    config.max_inbound_buffered_bytes = photon::fec::FEC_CHUNK_SIZE;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0x4EE9);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kDecoderPrefix = PrefixOf(block);
    constexpr std::uint64_t kBufferedPrefix = 0xBBBB000000000002ULL;
    constexpr std::uint64_t kRejectedPrefix = 0xCCCC000000000003ULL;

    engine.OnBlockHeader(BuildHeaderPayload(encoded, kDecoderPrefix, block.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kDecoderPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kBufferedPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kRejectedPrefix), submitter);
    Require(engine.stats().inbound_rejected == 1, "new prefix chunk should be rejected at buffer cap");
    Require(engine.stats().inbound_evictions == 0, "rejected new prefix must not evict existing relay");

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kDecoderPrefix), submitter);
    Require(submitter.submit_calls == 1, "existing decoder should survive rejected new prefix");
    Require(submitter.last_block == block, "surviving decoder reconstruction mismatch");
}

void TestInboundLimitsAllowValidReconstruction()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_original_size = 1024;
    config.max_inbound_entries = 4;
    config.max_inbound_buffered_chunks_per_entry = 2;
    config.max_inbound_buffered_bytes = 2 * photon::fec::FEC_CHUNK_SIZE;
    config.max_inbound_age = std::chrono::seconds{30};
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = MakeBlock(100, 0x0C);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    const std::uint64_t kPrefix = PrefixOf(block);

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kPrefix), submitter);
    engine.OnBlockHeader(BuildHeaderPayload(encoded, kPrefix, block.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kPrefix), submitter);

    Require(submitter.submit_calls == 1, "valid reconstruction should succeed inside inbound limits");
    Require(submitter.last_block == block, "limited reconstruction mismatch");
}

void TestStatsAccumulation()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(33);
    constexpr std::uint16_t kPort = 42003;

    PeerManager manager({MakePeer(kPort, key)}, clock, ResolveLoopback);
    ActivatePeer(manager, sink, key, kPort);
    sink.sent.clear();

    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const std::string hash_hex = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const std::vector<std::uint8_t> block = RandomBytes(6000, 0x6666);

    engine.OnNewBlock(hash_hex, block);
    engine.PumpOutbound(sink, manager);

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> inbound_block = MakeBlock(100, 0x41);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(inbound_block);

    const std::uint64_t kInboundPrefix = PrefixOf(inbound_block);
    BlockHeaderPayload header{};
    header.block_hash_prefix = kInboundPrefix;
    header.original_size = static_cast<std::uint64_t>(inbound_block.size());
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;
    engine.OnBlockHeader(header, submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kInboundPrefix), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kInboundPrefix), submitter);

    const RelayStats stats = engine.stats();
    Require(stats.blocks_relayed_out == 1, "blocks_relayed_out should increment");
    Require(stats.chunks_sent > 0, "chunks_sent should increment");
    Require(stats.blocks_received_in == 1, "blocks_received_in should increment");
    Require(stats.submit_successes == 1, "submit_successes should increment");
}

// Sends the header and then the data chunks of every coding group, which completes the decode.
void DeliverBlock(RelayEngine& engine,
                  const InboundPeerInfo& peer,
                  const TestBlock& block,
                  CapturingSubmitter& submitter,
                  std::optional<std::uint64_t> announced_prefix = std::nullopt)
{
    const std::uint64_t prefix = announced_prefix.value_or(block.prefix);
    engine.OnBlockHeader(peer, BuildHeaderPayload(block.encoded, prefix, block.bytes.size()), submitter);
    for (const auto& chunk : block.encoded.chunks) {
        if (chunk.chunk_id < block.encoded.params.data_chunks) {
            engine.OnBlockChunk(peer, BuildChunkPayload(chunk, prefix), submitter);
        }
    }
}

std::optional<PeerRelayStats> FindPeerStats(const RelayEngine& engine, std::size_t slot_index)
{
    for (const PeerRelayStats& stats : engine.PeerStatsSnapshot()) {
        if (stats.slot_index == slot_index) {
            return stats;
        }
    }
    return std::nullopt;
}

// Counters for a slot; all zero for a slot that has no inbound state.
PeerRelayStats PeerStats(const RelayEngine& engine, std::size_t slot_index)
{
    return FindPeerStats(engine, slot_index).value_or(PeerRelayStats{.slot_index = slot_index});
}

const InboundPeerInfo kPeer0{.slot_index = 0, .remote_session_id = 7001, .remote_peer_id = 8001};
const InboundPeerInfo kPeer1{.slot_index = 1, .remote_session_id = 7002, .remote_peer_id = 8002};
const InboundPeerInfo kPeer2{.slot_index = 2, .remote_session_id = 7003, .remote_peer_id = 8003};

void TestMismatchedIdentifierNotSubmitted()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const TestBlock block = EncodeTestBlock(500, 0xD1);
    DeliverBlock(engine, kPeer0, block, submitter, block.prefix ^ 0x1ULL);

    Require(submitter.check_calls == 0, "a block that is not the announced one must not reach the node");
    Require(submitter.submit_calls == 0, "a block that is not the announced one must not be submitted");
    Require(engine.stats().blocks_mismatched == 1, "identifier mismatch should be counted");
    Require(engine.stats().submit_failures == 0, "a dropped block is not a submission");
    Require(engine.stats().inbound_entries == 0, "dropped block state should be released");
    const auto peer = PeerStats(engine, 0);
    Require(peer.faults == 1 && peer.fault_score == 1, "mismatch should count against the peer");
}

void TestTooShortBlockNotSubmitted()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    // 80 bytes cannot hold a header and a transaction count.
    const std::vector<std::uint8_t> payload = RandomBytes(80, 0xD2);
    photon::fec::Encoder encoder(photon::fec::Parameters::FromDataChunkCount(2));
    TestBlock block;
    block.bytes = payload;
    block.prefix = 0x1122334455667788ULL;
    block.encoded = encoder.Encode(payload);
    DeliverBlock(engine, kPeer0, block, submitter);

    Require(submitter.submit_calls == 0, "a payload without a block header must not be submitted");
    Require(engine.stats().blocks_mismatched == 1, "unreadable header should be counted");
}

void TestParentCheckReceivesBlockParent()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    TestBlock block = EncodeTestBlock(300, 0xD3);
    // hashPrevBlock (bytes 4..36, little-endian) = 0x01..0x20, printed in display order.
    for (std::size_t i = 0; i < 32; ++i) {
        block.bytes[4 + i] = static_cast<std::uint8_t>(i + 1);
    }
    block.prefix = PrefixOf(block.bytes);
    photon::fec::Encoder encoder(photon::fec::Parameters::FromDataChunkCount(2));
    block.encoded = encoder.Encode(block.bytes);

    DeliverBlock(engine, kPeer0, block, submitter);

    Require(submitter.check_calls == 1, "parent should be checked once per finished block");
    Require(submitter.last_block_hash == photon::ReadBlockHeaderSummary(block.bytes)->hash_hex, "block hash should be passed");
    Require(submitter.last_prev_hash == "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201",
            "parent hash should be passed in display order");
    Require(submitter.last_max_depth == RelayEngineConfig{}.max_parent_depth, "configured depth should be passed");
    Require(submitter.submit_calls == 1, "block near the tip should be submitted");
}

void TestBlockWithParentAwayFromTipNotSubmitted()
{
    for (const ParentCheck result : {ParentCheck::kTooFar, ParentCheck::kUnknown}) {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = result;

        DeliverBlock(engine, kPeer0, EncodeTestBlock(500, 0xD4), submitter);

        Require(submitter.check_calls == 1, "parent should be checked");
        Require(submitter.submit_calls == 0, "block whose parent is not near the tip must not be submitted");
        const bool too_far = result == ParentCheck::kTooFar;
        Require(engine.stats().blocks_parent_rejected == (too_far ? 1U : 0U) &&
                    engine.stats().blocks_parent_unknown == (too_far ? 0U : 1U),
                "too-far and unknown parents should be counted separately");
        const auto peer = PeerStats(engine, 0);
        // A parent the node does not know yet may still be on its way to it, so a first such block
        // does not count against the peer.
        const std::uint32_t expected = too_far ? 1 : 0;
        Require(peer.faults == expected && peer.fault_score == expected,
                "only a parent too far from the tip should count against the peer here");
    }
}

void TestUnavailableParentCheckDropsWithoutPenalty()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kUnavailable;

    for (std::uint64_t i = 0; i < 20; ++i) {
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xE000 + i), submitter);
    }

    Require(submitter.submit_calls == 0, "blocks must not be submitted when the parent check fails");
    Require(engine.stats().block_checks_unavailable == 20, "failed checks should be counted");
    Require(engine.stats().blocks_parent_rejected == 0, "failed checks are not parent rejections");
    Require(engine.stats().peer_suspensions == 0, "failed checks must not suspend the peer");
    const auto peer = PeerStats(engine, 0);
    Require(peer.fault_score == 0 && !peer.suspended, "failed checks must not count against the peer");
}

void TestSubmitOutcomesCountedSeparately()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const std::vector<SubmitOutcome> outcomes{
        SubmitOutcome::kAccepted,
        SubmitOutcome::kDuplicate,
        SubmitOutcome::kDuplicate,
        SubmitOutcome::kInconclusive,
        SubmitOutcome::kRejected,
        SubmitOutcome::kKnownInvalid,
        SubmitOutcome::kTimeout,
        SubmitOutcome::kTimeout,
        SubmitOutcome::kTimeout,
        SubmitOutcome::kError,
    };
    std::uint64_t seed = 0xF000;
    for (const SubmitOutcome outcome : outcomes) {
        submitter.submit_result = outcome;
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, ++seed), submitter);
    }

    const RelayStats stats = engine.stats();
    Require(stats.submit_successes == 1 && stats.blocks_received_in == 1, "accepted count");
    Require(stats.submit_duplicates == 2, "duplicate count");
    Require(stats.submit_inconclusive == 1, "inconclusive count");
    Require(stats.submit_rejected == 2, "rejected count, including blocks already marked invalid");
    Require(stats.submit_timeouts == 3, "timeout count");
    Require(stats.submit_errors == 1, "error count");
    Require(stats.submit_failures == 9, "submit_failures should keep counting every non-accepted submission");
    const auto peer = PeerStats(engine, 0);
    Require(peer.blocks_received_in == 1 && peer.faults == 3, "per-peer counts");
    Require(peer.fault_score == 3, "only inconclusive and rejected blocks count against the peer");
}

void TestNeutralOutcomesNeverSuspendPeer()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    std::uint64_t seed = 0xF100;
    for (const SubmitOutcome outcome : {SubmitOutcome::kDuplicate, SubmitOutcome::kTimeout, SubmitOutcome::kError}) {
        submitter.submit_result = outcome;
        for (int i = 0; i < 12; ++i) {
            DeliverBlock(engine, kPeer0, EncodeTestBlock(200, ++seed), submitter);
        }
    }

    Require(submitter.submit_calls == 36, "every block should have been submitted");
    Require(engine.stats().peer_suspensions == 0, "duplicates, timeouts and errors must not suspend a peer");
    const auto peer = PeerStats(engine, 0);
    Require(peer.fault_score == 0, "neutral outcomes must not add to the fault score");
}

void TestRepeatedRejectedBlocksSuspendPeer()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.submit_result = SubmitOutcome::kRejected;
    const std::uint32_t threshold = RelayEngineConfig{}.peer_fault_threshold;

    std::uint64_t seed = 0xF200;
    for (std::uint32_t i = 0; i + 1 < threshold; ++i) {
        DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);
    }
    Require(engine.stats().peer_suspensions == 0, "peer must not be suspended below the threshold");
    DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);
    Require(engine.stats().peer_suspensions == 1, "peer should be suspended at the threshold");
    Require(submitter.submit_calls == threshold, "every block up to the threshold was submitted");

    // While suspended, the peer's blocks are refused before any decoding.
    const RelayStats before = engine.stats();
    DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);
    Require(submitter.submit_calls == threshold, "suspended peer's block must not be submitted");
    Require(engine.stats().inbound_rejected > before.inbound_rejected, "suspended peer's packets should be refused");
    Require(engine.stats().inbound_entries == 0, "suspended peer must not hold inbound state");
    auto peer = PeerStats(engine, 1);
    Require(peer.suspended && peer.suspensions == 1, "per-peer suspension state");

    // Another peer is unaffected.
    submitter.submit_result = SubmitOutcome::kAccepted;
    DeliverBlock(engine, kPeer0, EncodeTestBlock(200, ++seed), submitter);
    Require(submitter.submit_calls == threshold + 1, "other peer's block should still be submitted");

    // After the initial pause the peer is heard again; a second suspension lasts twice as long.
    clock.Advance(RelayEngineConfig{}.peer_suspend_initial + std::chrono::milliseconds{1});
    submitter.submit_result = SubmitOutcome::kRejected;
    for (std::uint32_t i = 0; i < threshold; ++i) {
        DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);
    }
    Require(engine.stats().peer_suspensions == 2, "peer should be suspended again");
    clock.Advance(RelayEngineConfig{}.peer_suspend_initial + std::chrono::milliseconds{1});
    peer = PeerStats(engine, 1);
    Require(peer.suspended, "second suspension should outlast the initial pause");
    clock.Advance(RelayEngineConfig{}.peer_suspend_initial);
    peer = PeerStats(engine, 1);
    Require(!peer.suspended, "second suspension should end after twice the initial pause");
}

void TestAcceptedBlockLowersFaultScoreWithoutResetting()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    const RelayEngineConfig defaults{};

    std::uint64_t seed = 0xF300;
    submitter.submit_result = SubmitOutcome::kRejected;
    for (std::uint32_t i = 0; i + 1 < defaults.peer_fault_threshold; ++i) {
        DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);
    }
    submitter.submit_result = SubmitOutcome::kAccepted;
    DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);

    auto peer = PeerStats(engine, 1);
    Require(peer.fault_score == defaults.peer_fault_threshold - 1 - defaults.peer_fault_success_credit,
            "an accepted block should lower the score by the fixed credit");

    // Interleaving accepted blocks cannot keep a peer below the threshold indefinitely.
    submitter.submit_result = SubmitOutcome::kRejected;
    for (std::uint32_t i = 0; i < defaults.peer_fault_success_credit + 1; ++i) {
        DeliverBlock(engine, kPeer1, EncodeTestBlock(200, ++seed), submitter);
    }
    Require(engine.stats().peer_suspensions == 1, "peer should reach the threshold despite the accepted block");
}

void TestFaultScoreDecaysOverTime()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.submit_result = SubmitOutcome::kInconclusive;
    const RelayEngineConfig defaults{};

    std::uint64_t seed = 0xF400;
    for (int i = 0; i < 6; ++i) {
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, ++seed), submitter);
    }
    clock.Advance(defaults.peer_fault_decay_interval * 4);
    auto peer = PeerStats(engine, 0);
    Require(peer.fault_score == 2, "score should decay by one per interval");

    // An occasional failed block, as in honest stale races, never accumulates to a suspension.
    for (int i = 0; i < 100; ++i) {
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, ++seed), submitter);
        clock.Advance(defaults.peer_fault_decay_interval);
    }
    Require(engine.stats().peer_suspensions == 0, "one failed block per decay interval must not suspend a peer");
}

void TestPeerFloodDoesNotEvictOtherPeersBlock()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    // Peer 0 relays a block with the default parameters: three headers, then the first half of
    // the chunks.
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock honest = EncodeTestBlock(600'000, 0xF500, params.data_chunks);
    const BlockHeaderPayload honest_header = BuildHeaderPayload(honest.encoded, honest.prefix, honest.bytes.size());
    for (int i = 0; i < 3; ++i) {
        engine.OnBlockHeader(kPeer0, honest_header, submitter);
    }
    const std::size_t half = honest.encoded.chunks.size() / 2;
    for (std::size_t i = 0; i < half; ++i) {
        engine.OnBlockChunk(kPeer0, BuildChunkPayload(honest.encoded.chunks[i], honest.prefix), submitter);
    }

    // Peer 1 announces 128 maximum-size blocks with fresh identifiers.
    clock.Advance(std::chrono::milliseconds{5});
    for (std::uint64_t k = 0; k < 128; ++k) {
        BlockHeaderPayload flood{};
        flood.block_hash_prefix = 0x1000 + k;
        flood.original_size = 2'000'000;
        flood.data_chunks = params.data_chunks;
        flood.coding_group_count = static_cast<std::uint16_t>(
            (2'000'000 + params.data_chunks * photon::fec::FEC_CHUNK_SIZE - 1) / (params.data_chunks * photon::fec::FEC_CHUNK_SIZE));
        engine.OnBlockHeader(kPeer1, flood, submitter);
    }

    for (std::size_t i = half; i < honest.encoded.chunks.size(); ++i) {
        engine.OnBlockChunk(kPeer0, BuildChunkPayload(honest.encoded.chunks[i], honest.prefix), submitter);
    }

    Require(submitter.submit_calls == 1, "peer 0's block should be submitted despite peer 1's headers");
    Require(submitter.last_block == honest.bytes, "peer 0's block should be reconstructed intact");

    const auto peer0 = PeerStats(engine, 0);
    const auto peer1 = PeerStats(engine, 1);
    Require(peer0.inbound_evictions == 0, "peer 0 must lose nothing to peer 1");
    Require(peer1.inbound_evictions > 0, "peer 1's own blocks should be displaced");
    const RelayEngineConfig defaults{};
    Require(peer1.inbound_entries <= defaults.max_inbound_entries_per_peer, "peer 1 should stay within its entry quota");
    Require(peer1.inbound_decoder_bytes <= defaults.max_inbound_decoder_bytes_per_peer,
            "peer 1 should stay within its decoder quota");
}

void TestPerPeerEntryQuotaBoundary()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_entries_per_peer = 2;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const TestBlock other = EncodeTestBlock(100, 0xF601);
    const TestBlock first = EncodeTestBlock(100, 0xF602);
    const TestBlock second = EncodeTestBlock(100, 0xF603);
    const TestBlock third = EncodeTestBlock(100, 0xF604);

    engine.OnBlockChunk(kPeer1, BuildChunkPayload(other.encoded.chunks[0], other.prefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(first.encoded.chunks[0], first.prefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(second.encoded.chunks[0], second.prefix), submitter);
    Require(engine.stats().inbound_evictions == 0, "two entries fit the per-peer quota");

    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(third.encoded.chunks[0], third.prefix), submitter);
    Require(engine.stats().inbound_evictions == 1, "third entry should displace one of the peer's own");
    Require(PeerStats(engine, 0).inbound_evictions == 1, "the eviction belongs to peer 0");
    Require(PeerStats(engine, 1).inbound_evictions == 0, "peer 1's older entry must be kept");

    // Peer 1's entry is intact; peer 0's oldest one was the one dropped.
    engine.OnBlockHeader(kPeer1, BuildHeaderPayload(other.encoded, other.prefix, other.bytes.size()), submitter);
    engine.OnBlockChunk(kPeer1, BuildChunkPayload(other.encoded.chunks[1], other.prefix), submitter);
    Require(submitter.submit_calls == 1 && submitter.last_block == other.bytes, "peer 1's block should complete");
    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(first.encoded, first.prefix, first.bytes.size()), submitter);
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(first.encoded.chunks[1], first.prefix), submitter);
    Require(submitter.submit_calls == 1, "peer 0's oldest entry should have been evicted");
    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(third.encoded, third.prefix, third.bytes.size()), submitter);
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(third.encoded.chunks[1], third.prefix), submitter);
    Require(submitter.submit_calls == 2 && submitter.last_block == third.bytes, "peer 0's newest entry should complete");
}

void TestPerPeerDecoderQuotaBoundary()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const std::size_t size = 600'000;
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, size);
    const auto group_count = static_cast<std::uint16_t>(
        (size + params.data_chunks * photon::fec::FEC_CHUNK_SIZE - 1) / (params.data_chunks * photon::fec::FEC_CHUNK_SIZE));
    auto header = [&](std::uint64_t prefix) {
        BlockHeaderPayload h{};
        h.block_hash_prefix = prefix;
        h.original_size = size;
        h.data_chunks = params.data_chunks;
        h.coding_group_count = group_count;
        return h;
    };

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_decoder_bytes_per_peer = 2 * charge;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer0, header(1), submitter);
    engine.OnBlockHeader(kPeer0, header(2), submitter);
    Require(engine.stats().inbound_evictions == 0 && engine.stats().inbound_rejected == 0, "two decoders fit exactly");
    Require(PeerStats(engine, 0).inbound_decoder_bytes == 2 * charge, "decoder bytes should be charged per entry");

    engine.OnBlockHeader(kPeer1, header(3), submitter);
    Require(engine.stats().inbound_evictions == 0, "another peer has its own quota");

    engine.OnBlockHeader(kPeer0, header(4), submitter);
    Require(engine.stats().inbound_evictions == 1, "third decoder should displace the peer's own oldest");
    Require(PeerStats(engine, 0).inbound_decoder_bytes == 2 * charge, "peer 0 should stay at its quota");
    Require(PeerStats(engine, 1).inbound_decoder_bytes == charge, "peer 1's decoder must be kept");

    // A single block larger than the peer quota is refused outright.
    RelayEngineConfig small{};
    small.max_inbound_decoder_bytes_per_peer = charge - 1;
    RelayEngine small_engine(clock, small);
    small_engine.OnBlockHeader(kPeer0, header(5), submitter);
    Require(small_engine.stats().inbound_rejected == 1 && small_engine.stats().inbound_entries == 0,
            "a decoder above the peer quota should be refused and leave no state");
}

void TestGlobalLimitSparesOtherPeersRecentProgress()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_entries = 2;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const TestBlock block0 = EncodeTestBlock(5000, 0xF701, 20); // needs 20 chunks
    const TestBlock block1 = EncodeTestBlock(100, 0xF702);
    const TestBlock block2 = EncodeTestBlock(100, 0xF703);
    auto chunk0 = [&](std::size_t i) { return BuildChunkPayload(block0.encoded.chunks[i], block0.prefix); };

    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(block0.encoded, block0.prefix, block0.bytes.size()), submitter);
    engine.OnBlockChunk(kPeer0, chunk0(0), submitter);
    engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block1.encoded, block1.prefix, block1.bytes.size()), submitter);

    // Both entries are fresh: peer 2 cannot displace either of them.
    engine.OnBlockHeader(kPeer2, BuildHeaderPayload(block2.encoded, block2.prefix, block2.bytes.size()), submitter);
    Require(engine.stats().inbound_evictions == 0, "entries with recent progress must not be displaced");
    Require(PeerStats(engine, 2).inbound_rejected == 1, "the new entry should be refused instead");

    // Peer 0 keeps making progress with new chunks; peer 1 only repeats itself, which is not progress.
    clock.Advance(config.inbound_progress_grace);
    engine.OnBlockChunk(kPeer0, chunk0(1), submitter);
    engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block1.encoded, block1.prefix, block1.bytes.size()), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    const TestBlock block3 = EncodeTestBlock(100, 0xF704);
    engine.OnBlockHeader(kPeer2, BuildHeaderPayload(block3.encoded, block3.prefix, block3.bytes.size()), submitter);
    Require(PeerStats(engine, 1).inbound_evictions == 1, "the idle entry should be displaced");
    Require(PeerStats(engine, 0).inbound_evictions == 0, "the active entry must be kept");

    for (std::size_t i = 2; i < block0.encoded.params.data_chunks; ++i) {
        engine.OnBlockChunk(kPeer0, chunk0(i), submitter);
    }
    engine.OnBlockChunk(kPeer2, BuildChunkPayload(block3.encoded.chunks[0], block3.prefix), submitter);
    engine.OnBlockChunk(kPeer2, BuildChunkPayload(block3.encoded.chunks[1], block3.prefix), submitter);
    Require(submitter.submit_calls == 2, "both remaining blocks should complete");
}

void TestRepeatedChunksDoNotKeepBlockAlive()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_age = std::chrono::seconds{30};
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const TestBlock block = EncodeTestBlock(5000, 0xF710, 20);
    engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size()), submitter);
    engine.OnBlockChunk(kPeer1, BuildChunkPayload(block.encoded.chunks[0], block.prefix), submitter);
    for (int i = 0; i < 3; ++i) {
        clock.Advance(std::chrono::seconds{9});
        engine.OnBlockChunk(kPeer1, BuildChunkPayload(block.encoded.chunks[0], block.prefix), submitter);
        engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size()), submitter);
    }

    // 31 s after its last new chunk (but 4 s after the last repeat), any inbound activity ages it out.
    clock.Advance(std::chrono::seconds{4});
    const TestBlock other = EncodeTestBlock(100, 0xF711);
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(other.encoded.chunks[0], other.prefix), submitter);
    Require(PeerStats(engine, 1).inbound_evictions == 1, "a block that only repeats itself should age out");
    Require(PeerStats(engine, 1).inbound_entries == 0, "its state should be released");
}

void TestCombinedLimitsEvictNothingWhenRefused()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, 600'000);
    const auto group_count = static_cast<std::uint16_t>(
        (600'000 + params.data_chunks * photon::fec::FEC_CHUNK_SIZE - 1) / (params.data_chunks * photon::fec::FEC_CHUNK_SIZE));

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_entries_per_peer = 2;
    config.max_inbound_decoder_bytes = charge;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    // Peer 1's active block fills the decoder total; peer 0 holds its full entry quota without decoders.
    BlockHeaderPayload busy{};
    busy.block_hash_prefix = 0xB0;
    busy.original_size = 600'000;
    busy.data_chunks = params.data_chunks;
    busy.coding_group_count = group_count;
    engine.OnBlockHeader(kPeer1, busy, submitter);
    const TestBlock pending1 = EncodeTestBlock(100, 0xF720);
    const TestBlock pending2 = EncodeTestBlock(100, 0xF721);
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(pending1.encoded.chunks[0], pending1.prefix), submitter);
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(pending2.encoded.chunks[0], pending2.prefix), submitter);
    Require(engine.stats().inbound_entries == 3, "setup should fit");

    // Peer 0's new header would need an entry and decoder memory; the memory cannot be found, so
    // none of its own entries is given up for it.
    BlockHeaderPayload wanted = busy;
    wanted.block_hash_prefix = 0xB1;
    engine.OnBlockHeader(kPeer0, wanted, submitter);
    Require(engine.stats().inbound_evictions == 0, "nothing should be evicted for a refused block");
    Require(PeerStats(engine, 0).inbound_entries == 2, "peer 0 should keep its entries");
}

void TestRefusedHeaderRemainingChunksIgnored()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const auto params = photon::fec::Parameters::FromDataChunkCount(28);
    const std::vector<std::uint8_t> big = MakeBlock(2'000'000, 0xF730);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(big);
    const std::uint64_t prefix = PrefixOf(big);

    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(encoded, prefix, big.size()), submitter);
    Require(engine.stats().inbound_rejected == 1, "the header should be refused");
    for (std::size_t i = 0; i < 200; ++i) {
        engine.OnBlockChunk(kPeer0, BuildChunkPayload(encoded.chunks[i], prefix), submitter);
    }
    Require(engine.stats().inbound_rejected == 1, "its chunks should not be counted as further refusals");
    Require(engine.stats().inbound_entries == 0, "its chunks should not be buffered");
}

// Sends a block's chunks with indices in [from, to), each once.
void SendChunks(RelayEngine& engine, const InboundPeerInfo& peer, const TestBlock& block, std::size_t from, std::size_t to,
                CapturingSubmitter& submitter)
{
    for (std::size_t i = from; i < std::min(to, block.encoded.chunks.size()); ++i) {
        engine.OnBlockChunk(peer, BuildChunkPayload(block.encoded.chunks[i], block.prefix), submitter);
    }
}

// Sends the data chunks of a block from index `from` on, as DeliverBlock does.
void SendDataChunks(RelayEngine& engine, const InboundPeerInfo& peer, const TestBlock& block, std::size_t from,
                    CapturingSubmitter& submitter)
{
    for (std::size_t i = from; i < block.encoded.chunks.size(); ++i) {
        if (block.encoded.chunks[i].chunk_id < block.encoded.params.data_chunks) {
            engine.OnBlockChunk(peer, BuildChunkPayload(block.encoded.chunks[i], block.prefix), submitter);
        }
    }
}

BlockHeaderPayload HeaderOf(const TestBlock& block)
{
    return BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size());
}

// A block's chunks in the order a sender sends them.
std::vector<photon::fec::Chunk> SendOrder(const TestBlock& block)
{
    std::vector<photon::fec::EncodedBlock> groups{block.encoded};
    photon::ChunkScheduler scheduler(std::move(groups));
    std::vector<photon::fec::Chunk> order;
    while (const auto next = scheduler.Next()) {
        order.push_back(next->chunk);
    }
    Require(order.size() == block.encoded.chunks.size(), "a sender should send every chunk once");
    return order;
}

void SendInOrder(RelayEngine& engine, const InboundPeerInfo& peer, const TestBlock& block,
                 const std::vector<photon::fec::Chunk>& order, std::size_t from, std::size_t to,
                 CapturingSubmitter& submitter)
{
    for (std::size_t i = from; i < std::min(to, order.size()); ++i) {
        engine.OnBlockChunk(peer, BuildChunkPayload(order[i], block.prefix), submitter);
    }
}

// How many of a block's chunks can be lost with every coding group still complete.
std::size_t ParityChunks(const TestBlock& block)
{
    const auto& params = block.encoded.params;
    return static_cast<std::size_t>(block.encoded.coding_group_count) * (params.total_chunks - params.data_chunks);
}

void TestCapacityRefusedBlockCompletesInSenderOrder()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF780, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(600'000, 0xF781, params.data_chunks);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, wanted.bytes.size());

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_decoder_bytes = charge; // one such decoder in total
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    // Peer 1's block, still receiving chunks, holds all the decoder memory.
    engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
    SendChunks(engine, kPeer1, busy, 0, 1, submitter);

    // Peer 0 sends what a sender sends: its three header copies, then each chunk once, in the
    // sender's order. Until room is free, the block waits: refused once, not the peer's fault,
    // and nothing displaced for it. It keeps 64 chunks and loses the rest, fewer than its parity.
    for (int i = 0; i < 3; ++i) {
        engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    }
    const auto order = SendOrder(wanted);
    const std::size_t before_room = config.max_inbound_buffered_chunks_per_entry + ParityChunks(wanted) - 40;
    SendInOrder(engine, kPeer0, wanted, order, 0, before_room, submitter);
    const PeerRelayStats waiting = PeerStats(engine, 0);
    Require(waiting.inbound_rejected == 1, "the block should be counted as refused once");
    Require(waiting.faults == 0, "a lack of room should not count against the peer");
    Require(waiting.inbound_entries == 1 && waiting.inbound_decoder_bytes == 0, "the block should wait without a decoder");
    Require(engine.stats().inbound_evictions == 0, "nothing should be displaced for a waiting block");
    Require(submitter.submit_calls == 0, "nothing should be submitted yet");

    // Peer 1's block completes and frees the room; the rest of peer 0's chunks complete its block.
    SendDataChunks(engine, kPeer1, busy, 1, submitter);
    Require(submitter.submit_calls == 1 && submitter.last_block == busy.bytes, "peer 1's block should complete");
    SendInOrder(engine, kPeer0, wanted, order, before_room, order.size(), submitter);
    Require(submitter.submit_calls == 2 && submitter.last_block == wanted.bytes,
            "the waiting block should complete from the chunks sent after room was freed");
    Require(PeerStats(engine, 0).faults == 0 && PeerStats(engine, 0).inbound_rejected == 1,
            "the waiting block should not be counted against the peer or refused again");
    Require(engine.stats().inbound_evictions == 0, "nothing should have been displaced");
}

void TestCapacityRefusedHeaderCanBeRetried()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF782, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(5000, 0xF783, 20);

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_decoder_bytes = photon::fec::Decoder::MemoryBytes(params, busy.bytes.size());
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
    SendChunks(engine, kPeer1, busy, 0, 1, submitter);

    // Peer 0's header is refused for lack of room, and all of its chunks are kept meanwhile.
    for (int i = 0; i < 3; ++i) {
        engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    }
    SendDataChunks(engine, kPeer0, wanted, 0, submitter);
    Require(submitter.submit_calls == 0 && PeerStats(engine, 0).inbound_decoder_bytes == 0, "the block should wait");

    // Once peer 1's block has completed, a header copy that arrives late (delayed on the way)
    // starts the block from the kept chunks.
    SendDataChunks(engine, kPeer1, busy, 1, submitter);
    Require(submitter.submit_calls == 1, "peer 1's block should complete");
    engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    Require(submitter.submit_calls == 2 && submitter.last_block == wanted.bytes,
            "a later header copy should complete the block from its kept chunks");
    Require(PeerStats(engine, 0).inbound_rejected == 1 && PeerStats(engine, 0).faults == 0,
            "the waiting block should be counted as refused once and not against the peer");
}

void TestWaitingBlockEndsOnceItCannotComplete()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF78D, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(600'000, 0xF78E, params.data_chunks);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, wanted.bytes.size());
    const auto order = SendOrder(wanted);

    // Chunks are lost once the block's own buffer, or the shared pre-header buffer, is full.
    for (const bool shared_buffer : {false, true}) {
        MockClock clock{};
        RelayEngineConfig config{};
        config.max_inbound_decoder_bytes = charge;
        if (shared_buffer) {
            config.max_inbound_buffered_bytes = 8 * photon::fec::FEC_CHUNK_SIZE;
        }
        const std::size_t kept = shared_buffer ? 8 : config.max_inbound_buffered_chunks_per_entry;
        RelayEngine engine(clock, config);
        CapturingSubmitter submitter;
        const std::string which = shared_buffer ? " (shared buffer)" : " (own buffer)";

        engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
        SendChunks(engine, kPeer1, busy, 0, 1, submitter);
        for (int i = 0; i < 3; ++i) {
            engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
        }

        // As many chunks lost as the block has parity chunks: it may still complete.
        SendInOrder(engine, kPeer0, wanted, order, 0, kept + ParityChunks(wanted), submitter);
        Require(PeerStats(engine, 0).inbound_entries == 1, "the block should still wait" + which);

        // One more, and some coding group cannot be completed: the block ends, without counting
        // against the peer or as a further refusal, and holds nothing.
        SendInOrder(engine, kPeer0, wanted, order, kept + ParityChunks(wanted), kept + ParityChunks(wanted) + 1, submitter);
        Require(PeerStats(engine, 0).inbound_entries == 0, "a block that cannot complete should end" + which);
        Require(PeerStats(engine, 0).inbound_rejected == 1 && PeerStats(engine, 0).faults == 0,
                "the ended block should be counted once and not against the peer" + which);

        // Room frees, but the rest of its chunks are ignored and no decoder is built for it.
        SendDataChunks(engine, kPeer1, busy, 1, submitter);
        Require(submitter.submit_calls == 1, "peer 1's block should complete" + which);
        SendInOrder(engine, kPeer0, wanted, order, kept + ParityChunks(wanted) + 1, order.size(), submitter);
        Require(submitter.submit_calls == 1 && engine.stats().inbound_entries == 0 && engine.stats().inbound_decoder_bytes == 0,
                "the rest of the ended block should be ignored" + which);
    }
}

void TestHeaderAfterChunksWaitsWithThem()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF78F, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(600'000, 0xF790, params.data_chunks);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, wanted.bytes.size());
    const auto order = SendOrder(wanted);

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_entries_per_peer = 1;
    config.max_inbound_decoder_bytes = charge;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
    SendChunks(engine, kPeer1, busy, 0, 1, submitter);

    // Peer 0's first chunks overtake its headers; the block then waits in the entry they made,
    // although peer 0 has no other entry free.
    SendInOrder(engine, kPeer0, wanted, order, 0, 10, submitter);
    for (int i = 0; i < 3; ++i) {
        engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    }
    Require(PeerStats(engine, 0).inbound_entries == 1 && PeerStats(engine, 0).inbound_decoder_bytes == 0,
            "the block should wait in the entry its chunks made");
    Require(PeerStats(engine, 0).inbound_rejected == 1, "the block should be counted as refused once");
    SendInOrder(engine, kPeer0, wanted, order, 10, 100, submitter);

    SendDataChunks(engine, kPeer1, busy, 1, submitter);
    Require(submitter.submit_calls == 1, "peer 1's block should complete");
    SendInOrder(engine, kPeer0, wanted, order, 100, order.size(), submitter);
    Require(submitter.submit_calls == 2 && submitter.last_block == wanted.bytes,
            "the block should complete with the chunks that came before its header");
    Require(PeerStats(engine, 0).faults == 0 && engine.stats().inbound_evictions == 0, "nothing should be held against anyone");
}

void TestStartingWaitingBlockIsNotProgress()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF791, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(600'000, 0xF792, params.data_chunks);
    const TestBlock later = EncodeTestBlock(600'000, 0xF793, params.data_chunks);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, wanted.bytes.size());

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_decoder_bytes = charge;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
    SendChunks(engine, kPeer1, busy, 0, 1, submitter);
    engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    SendChunks(engine, kPeer0, wanted, 0, 10, submitter);

    // Long after peer 0's last new chunk, room frees and a repeated header copy starts its block.
    clock.Advance(config.inbound_progress_grace + std::chrono::milliseconds{1});
    SendDataChunks(engine, kPeer1, busy, 1, submitter);
    Require(submitter.submit_calls == 1, "peer 1's block should complete");
    engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    Require(PeerStats(engine, 0).inbound_decoder_bytes == charge, "the repeated header copy should start the block");

    // That start is not progress: the block is still idle, so another peer's new block may displace it.
    engine.OnBlockHeader(kPeer2, HeaderOf(later), submitter);
    Require(PeerStats(engine, 0).inbound_evictions == 1, "the idle started block should be displaced");
    Require(PeerStats(engine, 2).inbound_decoder_bytes == charge, "the new block should get the room");
}

void TestWaitingBlockTakesNothingFromOtherBlocks()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF784, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(600'000, 0xF785, params.data_chunks);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, wanted.bytes.size());

    {
        // Peer 0 has no free entry: the header is refused like any other, and its chunks displace
        // none of peer 0's blocks.
        MockClock clock{};
        RelayEngineConfig config{};
        config.max_inbound_entries_per_peer = 2;
        config.max_inbound_decoder_bytes = charge;
        RelayEngine engine(clock, config);
        CapturingSubmitter submitter;

        engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
        const TestBlock pending1 = EncodeTestBlock(100, 0xF786);
        const TestBlock pending2 = EncodeTestBlock(100, 0xF787);
        SendChunks(engine, kPeer0, pending1, 0, 1, submitter);
        SendChunks(engine, kPeer0, pending2, 0, 1, submitter);

        for (int i = 0; i < 3; ++i) {
            engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
        }
        SendChunks(engine, kPeer0, wanted, 0, 100, submitter);
        Require(engine.stats().inbound_evictions == 0, "nothing should be evicted for a refused block");
        Require(PeerStats(engine, 0).inbound_entries == 2, "peer 0 should keep its own blocks");
        Require(PeerStats(engine, 0).inbound_rejected == 1, "the refused block's other packets should be ignored");
        Require(engine.stats().inbound_entries == 3, "the refused block should hold no entry");
    }

    {
        // A waiting block looks for room again after a block is released, but takes only room that
        // is free: it does not displace another peer's block, even one idle long enough that a
        // new header would.
        MockClock clock{};
        RelayEngineConfig config{};
        config.max_inbound_entries_per_peer = 1;
        config.max_inbound_decoder_bytes = charge;
        RelayEngine engine(clock, config);
        CapturingSubmitter submitter;

        engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
        SendChunks(engine, kPeer1, busy, 0, 1, submitter);
        engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
        Require(PeerStats(engine, 0).inbound_entries == 1 && PeerStats(engine, 0).inbound_decoder_bytes == 0,
                "the block should wait");

        clock.Advance(config.inbound_progress_grace + std::chrono::milliseconds{1});
        // Peer 2's second pre-header block displaces its first: a release that frees no decoder memory.
        const TestBlock other1 = EncodeTestBlock(100, 0xF788);
        const TestBlock other2 = EncodeTestBlock(100, 0xF789);
        SendChunks(engine, kPeer2, other1, 0, 1, submitter);
        SendChunks(engine, kPeer2, other2, 0, 1, submitter);
        Require(PeerStats(engine, 2).inbound_evictions == 1, "peer 2 should have released a block");

        SendChunks(engine, kPeer0, wanted, 0, 10, submitter);
        Require(PeerStats(engine, 1).inbound_evictions == 0, "peer 1's idle block must not be displaced for a waiting block");
        Require(PeerStats(engine, 0).inbound_decoder_bytes == 0, "the block should still wait");

        // Peer 1's block completes; peer 0's next chunk starts the waiting block, and the rest complete it.
        SendDataChunks(engine, kPeer1, busy, 1, submitter);
        Require(submitter.submit_calls == 1, "peer 1's block should complete");
        SendChunks(engine, kPeer0, wanted, 10, 11, submitter);
        Require(PeerStats(engine, 0).inbound_decoder_bytes == charge, "the first chunk after the release should start the block");
        SendChunks(engine, kPeer0, wanted, 11, wanted.encoded.chunks.size(), submitter);
        Require(submitter.submit_calls == 2 && submitter.last_block == wanted.bytes, "the waiting block should complete");
        Require(engine.stats().inbound_evictions == 1, "only peer 2's own block should have been displaced");
    }
}

void TestNeverFittingDecoderFinishesBlock()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock block = EncodeTestBlock(600'000, 0xF78A, params.data_chunks);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, block.bytes.size());

    for (const bool per_peer : {true, false}) {
        MockClock clock{};
        RelayEngineConfig config{};
        (per_peer ? config.max_inbound_decoder_bytes_per_peer : config.max_inbound_decoder_bytes) = charge - 1;
        RelayEngine engine(clock, config);
        CapturingSubmitter submitter;

        // A decoder above the peer's or the total cap can never be built: the block ends there,
        // without counting against the peer, and the rest of it from that peer is ignored.
        const std::string cap = per_peer ? "per-peer" : "total";
        for (int i = 0; i < 3; ++i) {
            engine.OnBlockHeader(kPeer0, HeaderOf(block), submitter);
        }
        Require(engine.stats().inbound_entries == 0, "a header above the " + cap + " cap should not be kept");
        SendDataChunks(engine, kPeer0, block, 0, submitter);
        Require(PeerStats(engine, 0).inbound_rejected == 1, "a block above the " + cap + " cap should be refused once");
        Require(PeerStats(engine, 0).faults == 0, "a block above the " + cap + " cap should not count against the peer");
        Require(engine.stats().inbound_entries == 0, "a block above the " + cap + " cap should leave no state");
        Require(submitter.submit_calls == 0, "a block above the " + cap + " cap should not be submitted");
    }
}

void TestWaitingBlockChunkMustFitItsHeader()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const TestBlock busy = EncodeTestBlock(600'000, 0xF78B, params.data_chunks);
    const TestBlock wanted = EncodeTestBlock(5000, 0xF78C, 20); // one coding group

    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_decoder_bytes = photon::fec::Decoder::MemoryBytes(params, busy.bytes.size());
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer1, HeaderOf(busy), submitter);
    engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    Require(PeerStats(engine, 0).inbound_entries == 1, "the block should wait");

    // The header is known, so a chunk outside it counts against the peer and ends the block.
    BlockChunkPayload outside = BuildChunkPayload(wanted.encoded.chunks[0], wanted.prefix);
    outside.coding_group_id = 1;
    engine.OnBlockChunk(kPeer0, outside, submitter);
    Require(PeerStats(engine, 0).faults == 1, "a chunk outside the kept header should count against the peer");
    Require(PeerStats(engine, 0).inbound_entries == 0, "the block should be dropped");

    // Its remaining chunks are ignored, even once there is room.
    SendDataChunks(engine, kPeer1, busy, 0, submitter);
    SendDataChunks(engine, kPeer0, wanted, 0, submitter);
    engine.OnBlockHeader(kPeer0, HeaderOf(wanted), submitter);
    Require(submitter.submit_calls == 1, "only peer 1's block should be submitted");
    Require(PeerStats(engine, 0).inbound_rejected == 2, "only the header and the chunk outside it should be refused");
}

void TestFaultRefusedHeaderStaysHandled()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const TestBlock block = EncodeTestBlock(5000, 0xF790, 20);
    BlockHeaderPayload malformed = BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size());
    ++malformed.coding_group_count;
    engine.OnBlockHeader(kPeer0, malformed, submitter);
    Require(PeerStats(engine, 0).inbound_rejected == 1 && PeerStats(engine, 0).faults == 1,
            "the malformed header should be refused and count against the peer");

    // The rest of that block from the same peer is ignored, a well-formed header copy included.
    DeliverBlock(engine, kPeer0, block, submitter);
    Require(submitter.submit_calls == 0, "the block should not be started from the same peer");
    Require(engine.stats().inbound_entries == 0, "its chunks should not be buffered");
    Require(PeerStats(engine, 0).inbound_rejected == 1 && PeerStats(engine, 0).faults == 1,
            "its later packets should be ignored, not refused or counted again");

    // Another peer's copy is still used.
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.submit_calls == 1 && submitter.last_block == block.bytes, "another peer's copy should be used");
}

void TestNodeAnsweredBlockStillRelayedOut()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.submit_result = SubmitOutcome::kDuplicate;

    const TestBlock block = EncodeTestBlock(300, 0xF740);
    DeliverBlock(engine, kPeer0, block, submitter);
    Require(engine.stats().submit_duplicates == 1, "the node already had the block");

    // The local node announcing the block afterwards still sends it on to the other relays.
    engine.OnNewBlock(photon::ReadBlockHeaderSummary(block.bytes)->hash_hex, block.bytes);
    Require(engine.stats().blocks_relayed_out == 1, "a block the node already had should still be relayed out");
}

void TestUnavailableCheckNotRepeatedForCopies()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kUnavailable;

    const TestBlock block = EncodeTestBlock(300, 0xF750);
    for (const InboundPeerInfo& peer : {kPeer0, kPeer1, kPeer2}) {
        DeliverBlock(engine, peer, block, submitter);
    }
    Require(submitter.check_calls == 1, "the node should be asked once per block, not once per copy");
}

void TestOversizedDecoderChargeRejected()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    // A maximum-size block split into many small Wirehair groups costs far more decoder memory
    // than its payload; it is refused before any decoder is built.
    BlockHeaderPayload header{};
    header.block_hash_prefix = 0x7777;
    header.original_size = 2'000'000;
    header.data_chunks = 28;
    header.coding_group_count = static_cast<std::uint16_t>((2'000'000 + 28 * photon::fec::FEC_CHUNK_SIZE - 1) / (28 * photon::fec::FEC_CHUNK_SIZE));
    Require(photon::fec::Decoder::MemoryBytes(photon::fec::Parameters::FromDataChunkCount(28), 2'000'000) >
                RelayEngineConfig{}.max_inbound_decoder_bytes_per_entry,
            "test parameters should exceed the per-block charge limit");

    engine.OnBlockHeader(kPeer0, header, submitter);
    Require(engine.stats().inbound_rejected == 1, "over-limit decoder should be refused");
    Require(engine.stats().inbound_entries == 0 && engine.stats().inbound_decoder_bytes == 0, "no state should remain");
}

void TestBlockAlreadyKnownNotSubmittedOrPenalized()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kAlreadyKnown;

    const TestBlock block = EncodeTestBlock(300, 0xA100);
    DeliverBlock(engine, kPeer0, block, submitter);
    Require(submitter.check_calls == 1 && submitter.submit_calls == 0, "a block the node has must not be submitted");
    Require(engine.stats().blocks_already_known >= 1, "it should count as known");
    Require(PeerStats(engine, 0).fault_score == 0, "it must not count against the peer");

    // Another peer's copy is recognised without asking the node again.
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.check_calls == 1, "a block known to the node should not be checked again");
}

void TestNodeBehindDropsWithoutPenalty()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kNodeBehind;

    for (std::uint64_t i = 0; i < 20; ++i) {
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xA200 + i), submitter);
    }
    Require(submitter.submit_calls == 0, "blocks the node cannot connect yet are not submitted");
    Require(engine.stats().blocks_node_behind == 20, "they should be counted separately");
    Require(engine.stats().blocks_parent_rejected == 0, "they are not parent rejections");
    Require(engine.stats().peer_suspensions == 0 && PeerStats(engine, 0).fault_score == 0,
            "a lagging local node must not count against the peer");
}

void TestInconclusiveBlockCountedOnceAcrossPeers()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.submit_result = SubmitOutcome::kInconclusive;

    const TestBlock block = EncodeTestBlock(300, 0xA300);
    const BlockHeaderPayload header = BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size());
    for (const InboundPeerInfo& peer : {kPeer1, kPeer2}) {
        engine.OnBlockHeader(peer, header, submitter);
        engine.OnBlockChunk(peer, BuildChunkPayload(block.encoded.chunks[0], block.prefix), submitter);
    }
    DeliverBlock(engine, kPeer0, block, submitter);
    for (const InboundPeerInfo& peer : {kPeer1, kPeer2}) {
        engine.OnBlockChunk(peer, BuildChunkPayload(block.encoded.chunks[1], block.prefix), submitter);
    }

    Require(submitter.submit_calls == 1, "the node should receive the block once");
    Require(PeerStats(engine, 0).fault_score == 1, "the first peer's copy counts once");
    Require(PeerStats(engine, 1).fault_score == 0 && PeerStats(engine, 2).fault_score == 0,
            "other peers relaying the same block are not counted");
    Require(engine.stats().inbound_entries == 0, "other copies should be released");
}

void TestInvalidChunkAfterHeaderCountsAgainstPeer()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    const std::uint32_t threshold = RelayEngineConfig{}.peer_fault_threshold;

    for (std::uint32_t i = 0; i < threshold; ++i) {
        const TestBlock block = EncodeTestBlock(200, 0xA400 + i);
        engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size()), submitter);
        BlockChunkPayload invalid = BuildChunkPayload(block.encoded.chunks[0], block.prefix);
        invalid.coding_group_id = block.encoded.coding_group_count;
        engine.OnBlockChunk(kPeer1, invalid, submitter);
    }

    Require(engine.stats().peer_suspensions == 1, "repeated undecodable blocks should pause the peer");
    Require(engine.stats().inbound_entries == 0 && engine.stats().inbound_decoder_bytes == 0, "their state should be released");
}

void TestRemainingChunksOfHandledBlockIgnored()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kTooFar;

    const TestBlock block = EncodeTestBlock(300, 0xA500);
    DeliverBlock(engine, kPeer0, block, submitter);
    Require(engine.stats().blocks_parent_rejected == 1, "block should be dropped");

    const RelayStats before = engine.stats();
    for (std::size_t i = block.encoded.params.data_chunks; i < block.encoded.chunks.size(); ++i) {
        engine.OnBlockChunk(kPeer0, BuildChunkPayload(block.encoded.chunks[i], block.prefix), submitter);
    }
    Require(engine.stats().inbound_entries == 0, "remaining chunks must not start a new incomplete block");
    Require(engine.stats().inbound_rejected == before.inbound_rejected, "remaining chunks are not refusals");
    Require(submitter.check_calls == 1, "the block should be handled once");

    // The verdict is about the block, so another peer's copy is not checked again for a while...
    submitter.parent_result = ParentCheck::kNearTip;
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.check_calls == 1 && submitter.submit_calls == 0, "another peer's copy should not be re-checked at once");
    Require(PeerStats(engine, 1).fault_score == 0, "and does not count against that peer");

    // ...but is processed again once that has expired.
    clock.Advance(std::chrono::seconds{11});
    DeliverBlock(engine, kPeer2, block, submitter);
    Require(submitter.submit_calls == 1, "a later copy should be processed");
}

void TestFailedReservationEvictsNothing()
{
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const std::size_t group_bytes = static_cast<std::size_t>(params.data_chunks) * photon::fec::FEC_CHUNK_SIZE;
    auto header = [&](std::uint64_t prefix, std::size_t size) {
        BlockHeaderPayload h{};
        h.block_hash_prefix = prefix;
        h.original_size = size;
        h.data_chunks = params.data_chunks;
        h.coding_group_count = static_cast<std::uint16_t>((size + group_bytes - 1) / group_bytes);
        return h;
    };
    const std::size_t small = photon::fec::Decoder::MemoryBytes(params, 100'000);
    const std::size_t large = photon::fec::Decoder::MemoryBytes(params, 600'000);

    MockClock clock{};
    RelayEngineConfig config{};
    // Peer 0 must give up its small block to fit its own limit, but even then the total limit
    // cannot fit the large block while peer 1's block keeps making progress.
    config.max_inbound_decoder_bytes_per_peer = small + large - 1;
    config.max_inbound_decoder_bytes = 2 * large - 1;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer1, header(1, 600'000), submitter);
    engine.OnBlockHeader(kPeer0, header(2, 100'000), submitter);
    Require(engine.stats().inbound_entries == 2 && engine.stats().inbound_rejected == 0, "setup should fit");

    engine.OnBlockHeader(kPeer0, header(3, 600'000), submitter);
    Require(engine.stats().inbound_rejected == 1, "the large block should be refused");
    Require(engine.stats().inbound_evictions == 0, "nothing should be evicted for a block that is refused anyway");
    Require(PeerStats(engine, 0).inbound_decoder_bytes == small, "peer 0 should keep its small block");
}

void TestRejectedCopyDoesNotBlockOtherPeersCopy()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const TestBlock honest = EncodeTestBlock(2000, 0xF800);
    // Another peer's copy carries the same header (so the same identifier) with a different body.
    TestBlock bad;
    bad.bytes.assign(honest.bytes.begin(), honest.bytes.begin() + 80);
    const std::vector<std::uint8_t> junk = RandomBytes(120, 0xF801);
    bad.bytes.insert(bad.bytes.end(), junk.begin(), junk.end());
    bad.prefix = PrefixOf(bad.bytes);
    Require(bad.prefix == honest.prefix, "both copies share the header");
    photon::fec::Encoder encoder(photon::fec::Parameters::FromDataChunkCount(2));
    bad.encoded = encoder.Encode(bad.bytes);

    submitter.submit_hook = [&](std::span<const std::uint8_t> data) {
        return std::equal(data.begin(), data.end(), honest.bytes.begin(), honest.bytes.end()) ? SubmitOutcome::kAccepted
                                                                                             : SubmitOutcome::kRejected;
    };

    DeliverBlock(engine, kPeer1, bad, submitter);
    Require(engine.stats().submit_rejected == 1, "the bad copy should be rejected by the node");
    DeliverBlock(engine, kPeer0, honest, submitter);
    Require(submitter.submit_calls == 2 && engine.stats().submit_successes == 1, "the honest copy must still be submitted");
    Require(PeerStats(engine, 1).fault_score == 1 && PeerStats(engine, 0).fault_score == 0, "only the bad copy's sender is counted");
}

void TestSettleUsesTimeAfterNodeCalls()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kAlreadyKnown;
    // The node takes longer to answer than the settle lifetime.
    submitter.check_hook = [&clock] { clock.Advance(std::chrono::seconds{11}); };

    const TestBlock block = EncodeTestBlock(300, 0xF810);
    DeliverBlock(engine, kPeer0, block, submitter);
    submitter.check_hook = {};
    clock.Advance(std::chrono::seconds{1});
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.check_calls == 1, "a copy right after a slow check should not be checked again");
}

void TestUnknownParentEndsOnlyThatCopy()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kUnknown;

    const TestBlock block = EncodeTestBlock(300, 0xF820);
    DeliverBlock(engine, kPeer0, block, submitter);
    // The node may learn the parent a moment later; another peer's copy is checked again.
    submitter.parent_result = ParentCheck::kNearTip;
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.check_calls == 2 && submitter.submit_calls == 1, "another peer's copy should be checked and submitted");
}

void TestRepeatedPreHeaderChunksNotBuffered()
{
    MockClock clock{};
    RelayEngineConfig config{};
    config.max_inbound_buffered_bytes = 2 * photon::fec::FEC_CHUNK_SIZE;
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    const TestBlock block = EncodeTestBlock(300, 0xF830);
    for (int i = 0; i < 5; ++i) {
        engine.OnBlockChunk(kPeer0, BuildChunkPayload(block.encoded.chunks[0], block.prefix), submitter);
    }
    engine.OnBlockChunk(kPeer0, BuildChunkPayload(block.encoded.chunks[1], block.prefix), submitter);
    Require(engine.stats().inbound_rejected == 0, "repeats should not take buffer space");
    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size()), submitter);
    Require(submitter.submit_calls == 1 && submitter.last_block == block.bytes, "the buffered chunks should complete the block");
}

void TestMalformedHeadersCountAgainstPeer()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    const RelayEngineConfig defaults{};

    for (std::uint64_t i = 0; i < defaults.peer_fault_threshold; ++i) {
        BlockHeaderPayload header{};
        header.block_hash_prefix = 0xC000 + i;
        header.original_size = 1000;
        header.data_chunks = 1; // no sender produces this
        header.coding_group_count = 1;
        engine.OnBlockHeader(kPeer1, header, submitter);
    }
    Require(engine.stats().peer_suspensions == 1, "malformed headers should pause the peer");

    // Headers refused during the pause are not remembered as handled.
    const TestBlock block = EncodeTestBlock(300, 0xF840);
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.submit_calls == 0, "a paused peer's block is refused");
    clock.Advance(defaults.peer_suspend_initial + std::chrono::milliseconds{1});
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.submit_calls == 1, "the same block is accepted after the pause");
}

void TestBufferedChunksCheckedBeforeEviction()
{
    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    MockClock clock{};
    RelayEngineConfig config{};
    const TestBlock kept = EncodeTestBlock(300, 0xF850);
    const TestBlock bad = EncodeTestBlock(300, 0xF851);
    config.max_inbound_decoder_bytes_per_peer = photon::fec::Decoder::MemoryBytes(params, kept.bytes.size());
    RelayEngine engine(clock, config);
    CapturingSubmitter submitter;

    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(kept.encoded, kept.prefix, kept.bytes.size()), submitter);
    BlockChunkPayload stray = BuildChunkPayload(bad.encoded.chunks[0], bad.prefix);
    stray.coding_group_id = 7; // the announced block has one group
    engine.OnBlockChunk(kPeer0, stray, submitter);
    engine.OnBlockHeader(kPeer0, BuildHeaderPayload(bad.encoded, bad.prefix, bad.bytes.size()), submitter);

    Require(engine.stats().inbound_evictions == 0, "nothing should be evicted for a block that cannot be decoded");
    Require(PeerStats(engine, 0).inbound_decoder_bytes == config.max_inbound_decoder_bytes_per_peer, "the other block should be kept");
    Require(PeerStats(engine, 0).faults == 1, "the bad block should count against the peer");
}

void TestKnownInvalidBlockSettledForAllCopies()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.submit_result = SubmitOutcome::kKnownInvalid;

    const TestBlock block = EncodeTestBlock(300, 0xF860);
    DeliverBlock(engine, kPeer0, block, submitter);
    DeliverBlock(engine, kPeer1, block, submitter);
    Require(submitter.submit_calls == 1, "a block the node holds as invalid should be submitted once");
    Require(engine.stats().submit_rejected == 1 && engine.stats().submit_failures == 1, "it counts as rejected once");
    Require(PeerStats(engine, 0).faults == 1, "and against the first sender");
    Require(PeerStats(engine, 1).faults == 0, "but not against later senders");
}

void TestHandledBlockTimedAfterNodeCalls()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.submit_result = SubmitOutcome::kRejected;
    // The node takes longer to answer than the time remaining chunks are ignored for.
    submitter.submit_hook = [&clock](std::span<const std::uint8_t>) {
        clock.Advance(std::chrono::seconds{11});
        return SubmitOutcome::kRejected;
    };

    const TestBlock block = EncodeTestBlock(300, 0xF870);
    DeliverBlock(engine, kPeer0, block, submitter);
    // The sender's remaining chunks, read after the node calls return, are still ignored.
    for (std::size_t i = block.encoded.params.data_chunks; i < 20; ++i) {
        engine.OnBlockChunk(kPeer0, BuildChunkPayload(block.encoded.chunks[i], block.prefix), submitter);
    }
    Require(engine.stats().inbound_entries == 0, "remaining chunks must not start a new incomplete block");
}

std::string Hex64(std::uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

// A block built from a real mainnet header and a made-up body; the relay reads only the header.
std::vector<std::uint8_t> MainnetBlock(std::size_t index)
{
    const std::string_view hex = photon::test::kMainnetHeaders.at(index).hex;
    Require(hex.size() == 160, "fixture header should be 80 bytes");
    std::vector<std::uint8_t> block;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        block.push_back(static_cast<std::uint8_t>(std::stoul(std::string(hex.substr(i, 2)), nullptr, 16)));
    }
    const std::vector<std::uint8_t> body = RandomBytes(300, 0x5EED0000 + index);
    block.insert(block.end(), body.begin(), body.end());
    return block;
}

// Pumps the engine's current outbound block until all of its packets are sent.
void PumpAll(RelayEngine& engine, RecordingSink& sink, PeerManager& manager)
{
    for (int i = 0; i < 1000 && engine.HasOutbound(); ++i) {
        engine.PumpOutbound(sink, manager);
    }
    Require(!engine.HasOutbound(), "outbound block should be fully sent");
}

// Feeds every block packet in `sent` to `receiver` as if received from `from`.
void DeliverPackets(const std::vector<RecordingSink::Sent>& sent,
                    RelayEngine& receiver,
                    const InboundPeerInfo& from,
                    CapturingSubmitter& submitter)
{
    for (const auto& item : sent) {
        if (item.packet.msg_type == MessageType::kBlockHeader) {
            BlockHeaderPayload header{};
            Require(photon::DecodeBlockHeaderPayload(item.packet.payload, header), "header decode failed");
            receiver.OnBlockHeader(from, header, submitter);
        } else if (item.packet.msg_type == MessageType::kBlockChunk) {
            BlockChunkPayload chunk{};
            Require(photon::DecodeBlockChunkPayload(item.packet.payload, chunk), "chunk decode failed");
            receiver.OnBlockChunk(from, chunk, submitter);
        }
    }
}

std::optional<std::uint64_t> AnnouncedIdentifier(const std::vector<RecordingSink::Sent>& sent)
{
    for (const auto& item : sent) {
        if (item.packet.msg_type == MessageType::kBlockHeader) {
            BlockHeaderPayload header{};
            Require(photon::DecodeBlockHeaderPayload(item.packet.payload, header), "header decode failed");
            return header.block_hash_prefix;
        }
    }
    return std::nullopt;
}

void TestBlocksSharingLeadingHashBitsAllRelayed()
{
    MockClock clock{};
    RecordingSink sink;
    const auto key = Key(61);
    constexpr std::uint16_t kPort = 42021;
    PeerManager manager({MakePeer(kPort, key)}, clock, ResolveLoopback);
    ActivatePeer(manager, sink, key, kPort);

    RelayEngine engine(clock);
    std::mt19937_64 rng(0x1EAD);
    for (std::uint64_t i = 0; i < 20; ++i) {
        // Like native-lane block hashes: the same leading 64 bits, different low-order bits.
        const std::string hash = Hex64(1) + Hex64(rng()) + Hex64(rng()) + Hex64(rng());
        sink.sent.clear();
        engine.OnNewBlock(hash, RandomBytes(3000, 0xC100 + i));
        PumpAll(engine, sink, manager);

        const auto announced = AnnouncedIdentifier(sink.sent);
        Require(announced.has_value(), "block " + std::to_string(i) + " should be announced");
        Require(*announced == photon::BlockIdFromHex(hash), "block should be announced under its hash's low-order bits");
        for (const auto& item : sink.sent) {
            if (item.packet.msg_type == MessageType::kBlockChunk) {
                BlockChunkPayload chunk{};
                Require(photon::DecodeBlockChunkPayload(item.packet.payload, chunk), "chunk decode failed");
                Require(chunk.block_hash_prefix == *announced, "chunks should carry the announced identifier");
            }
        }
    }
    Require(engine.stats().blocks_relayed_out == 20, "every block should be relayed out");
    Require(engine.stats().blocks_already_known == 0, "no block should be taken for an earlier one");
}

void TestBlockIdentifierForms()
{
    const std::string hash = "00000000000000010123456789abcdef0011223344556677fedcba9876543210";
    Require(photon::BlockIdFromHex(hash) == 0xfedcba9876543210ULL, "identifier is the last 16 hex digits");
    Require(photon::HashPrefixFromHex(hash) == 0x1ULL, "earlier form is the first 16 hex digits");
    std::string upper = hash;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](char ch) { return static_cast<char>(std::toupper(ch)); });
    Require(photon::BlockIdFromHex(upper) == 0xfedcba9876543210ULL, "upper-case hex is accepted");
    Require(photon::BlockIdFromHex(hash.substr(0, 63)) == 0, "a short hash has no identifier");
    Require(photon::BlockIdFromHex(hash + "0") == 0, "a long hash has no identifier");
    Require(photon::BlockIdFromHex("x" + hash.substr(1)) == 0, "a hash with a non-hex digit has no identifier");
    Require(photon::BlockIdFromHex("") == 0, "an empty hash has no identifier");

    // The identifier is the low 64 bits of the hash as a number: the first 8 bytes of the header's
    // double SHA-256, read little-endian.
    const std::vector<std::uint8_t> block = MakeBlock(200, 0xB000);
    const std::string block_hash = HashOf(block);
    std::uint64_t low = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        const std::size_t pos = 62 - 2 * i; // byte i of the hash, in display-order hex
        low |= static_cast<std::uint64_t>(std::stoul(block_hash.substr(pos, 2), nullptr, 16)) << (8 * i);
    }
    Require(BlockIdOf(block) == low, "identifier should be the hash's low-order 64 bits");
}

void TestEarlierFormIdentifierAcceptedWithoutFault()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    // Header first.
    const TestBlock block = EncodeTestBlock(500, 0xB101);
    Require(block.prefix != BlockIdOf(block.bytes), "the two forms should differ for this block");
    DeliverBlock(engine, kPeer0, block, submitter, block.prefix);
    Require(submitter.submit_calls == 1 && submitter.last_block == block.bytes, "earlier-form block should be submitted");

    // Chunks before the header.
    const TestBlock other = EncodeTestBlock(500, 0xB102);
    engine.OnBlockChunk(kPeer1, BuildChunkPayload(other.encoded.chunks[0], other.prefix), submitter);
    engine.OnBlockHeader(kPeer1, BuildHeaderPayload(other.encoded, other.prefix, other.bytes.size()), submitter);
    engine.OnBlockChunk(kPeer1, BuildChunkPayload(other.encoded.chunks[1], other.prefix), submitter);
    Require(submitter.submit_calls == 2 && submitter.last_block == other.bytes, "earlier-form chunks should be used");

    Require(engine.stats().submit_successes == 2 && engine.stats().blocks_mismatched == 0, "both blocks should be accepted");
    Require(PeerStats(engine, 0).faults == 0 && PeerStats(engine, 1).faults == 0, "earlier-form blocks must not count against peers");
}

void TestBlockIdentifierAccepted()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const TestBlock block = EncodeTestBlock(500, 0xB111);
    DeliverBlock(engine, kPeer0, block, submitter, BlockIdOf(block.bytes));
    Require(submitter.submit_calls == 1 && submitter.last_block == block.bytes, "block should be submitted");
    Require(engine.stats().submit_successes == 1 && engine.stats().blocks_mismatched == 0, "block should be accepted");
    Require(PeerStats(engine, 0).faults == 0, "block must not count against the peer");

    // A mismatch is still caught in this form.
    const TestBlock other = EncodeTestBlock(500, 0xB112);
    DeliverBlock(engine, kPeer1, other, submitter, BlockIdOf(other.bytes) ^ 0x1ULL);
    Require(submitter.submit_calls == 1 && engine.stats().blocks_mismatched == 1, "mismatched identifier should be dropped");
    Require(PeerStats(engine, 1).faults == 1, "mismatch should count against the peer");

    // The local node announcing the accepted block does not send it back out.
    engine.OnNewBlock(HashOf(block.bytes), block.bytes);
    Require(engine.stats().blocks_relayed_out == 0, "an accepted block should not be relayed out again");
}

void TestBlockAnnouncedUnderBothFormsUsedOnce()
{
    // Earlier form first: a copy under this version's form is recognised before it is decoded.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        const TestBlock block = EncodeTestBlock(500, 0xB121);
        DeliverBlock(engine, kPeer0, block, submitter, block.prefix);
        const RelayStats before = engine.stats();
        DeliverBlock(engine, kPeer1, block, submitter, BlockIdOf(block.bytes));
        Require(submitter.submit_calls == 1 && submitter.check_calls == 1, "the block should reach the node once");
        Require(engine.stats().chunks_received == before.chunks_received, "the second copy should not be decoded");
        engine.OnNewBlock(HashOf(block.bytes), block.bytes);
        Require(engine.stats().blocks_relayed_out == 0, "the block should not be relayed out again");
    }
    // This version's form first: a copy under the earlier form is recognised once reconstructed.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        const TestBlock block = EncodeTestBlock(500, 0xB122);
        DeliverBlock(engine, kPeer0, block, submitter, BlockIdOf(block.bytes));
        DeliverBlock(engine, kPeer1, block, submitter, block.prefix);
        Require(submitter.submit_calls == 1 && submitter.check_calls == 1, "the block should reach the node once");
        Require(PeerStats(engine, 1).faults == 0, "the later copy must not count against its sender");
        Require(engine.stats().inbound_entries == 0, "no state should remain");
    }
    // Both in flight at once.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        const TestBlock block = EncodeTestBlock(500, 0xB123);
        engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block.encoded, block.prefix, block.bytes.size()), submitter);
        engine.OnBlockChunk(kPeer1, BuildChunkPayload(block.encoded.chunks[0], block.prefix), submitter);
        DeliverBlock(engine, kPeer0, block, submitter, BlockIdOf(block.bytes));
        engine.OnBlockChunk(kPeer1, BuildChunkPayload(block.encoded.chunks[1], block.prefix), submitter);
        Require(submitter.submit_calls == 1 && submitter.check_calls == 1, "the block should reach the node once");
        Require(PeerStats(engine, 1).faults == 0, "the other copy must not count against its sender");
        Require(engine.stats().inbound_entries == 0, "no state should remain");
    }
    // An answer that settles the block (here: the node already had it) covers the other form too.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.submit_result = SubmitOutcome::kDuplicate;
        const TestBlock block = EncodeTestBlock(500, 0xB124);
        DeliverBlock(engine, kPeer0, block, submitter, BlockIdOf(block.bytes));
        DeliverBlock(engine, kPeer1, block, submitter, block.prefix);
        Require(submitter.submit_calls == 1 && submitter.check_calls == 1, "a settled block should not reach the node again");
        // Under this version's form, a copy of a settled block is not even decoded.
        const RelayStats before = engine.stats();
        DeliverBlock(engine, kPeer2, block, submitter, BlockIdOf(block.bytes));
        Require(engine.stats().chunks_received == before.chunks_received, "a settled block's copy should not be decoded");
    }
}

void TestMainnetHashSequenceRelayedWithoutSuppression()
{
    const auto& headers = photon::test::kMainnetHeaders;
    std::set<std::uint64_t> native_prefixes;
    std::size_t native_blocks = 0;
    for (std::size_t i = 0; i < headers.size(); ++i) {
        if (!headers[i].auxpow) {
            ++native_blocks;
            native_prefixes.insert(PrefixOf(MainnetBlock(i)));
        }
    }
    Require(native_blocks >= 40 && native_prefixes.size() <= 3, "the fixture's native-lane hashes should share their leading bits");

    MockClock clock{};
    RecordingSink sink;
    const auto key = Key(71);
    constexpr std::uint16_t kPort = 42031;
    PeerManager manager({MakePeer(kPort, key)}, clock, ResolveLoopback);
    ActivatePeer(manager, sink, key, kPort);

    RelayEngine sender(clock);
    RelayEngine receiver(clock);
    CapturingSubmitter submitter;
    for (std::size_t i = 0; i < headers.size(); ++i) {
        const std::vector<std::uint8_t> block = MainnetBlock(i);
        const std::string hash = HashOf(block);
        sink.sent.clear();
        sender.OnNewBlock(hash, block);
        PumpAll(sender, sink, manager);
        DeliverPackets(sink.sent, receiver, kPeer0, submitter);
        Require(submitter.submit_calls == i + 1 && submitter.last_block == block,
                "mainnet block " + std::to_string(i) + " should reach the receiving node");
        // The receiving node then announces the block; the receiver does not send it back out.
        receiver.OnNewBlock(hash, block);
        clock.Advance(std::chrono::seconds{1});
    }

    Require(sender.stats().blocks_relayed_out == headers.size(), "every block should be relayed out");
    Require(sender.stats().blocks_already_known == 0, "no block should be taken for an earlier one");
    Require(receiver.stats().submit_successes == headers.size(), "every block should be accepted");
    Require(receiver.stats().blocks_relayed_out == 0, "relayed blocks should not be sent back out");
    Require(PeerStats(receiver, 0).faults == 0, "no block should count against the sender");
}

// A receiver that, like earlier versions, uses the announced identifier only as a key: no check
// against the block, a seen set of announced identifiers, and the earlier form for blocks its own
// node announces.
class IdentifierKeyedReceiver {
public:
    void OnHeader(const BlockHeaderPayload& header)
    {
        if (Seen(header.block_hash_prefix) || m_decoders.count(header.block_hash_prefix) != 0) {
            return;
        }
        m_decoders.emplace(header.block_hash_prefix,
                           photon::fec::Decoder(photon::fec::Parameters::FromDataChunkCount(header.data_chunks),
                                                static_cast<std::size_t>(header.original_size)));
    }

    void OnChunk(const BlockChunkPayload& chunk)
    {
        const auto it = m_decoders.find(chunk.block_hash_prefix);
        if (Seen(chunk.block_hash_prefix) || it == m_decoders.end()) {
            return;
        }
        Require(it->second.AddChunk(chunk.coding_group_id, chunk.chunk_id, chunk.chunk_data), "chunk should fit its block");
        if (!it->second.IsComplete()) {
            return;
        }
        const auto block = it->second.Reconstruct();
        Require(block.has_value(), "block should reconstruct");
        delivered.push_back(*block);
        Remember(chunk.block_hash_prefix);
        m_decoders.erase(it);
    }

    // The local node announces a block; returns the identifier it is relayed out under, if any.
    std::optional<std::uint64_t> OnNodeBlock(const std::string& hash_hex)
    {
        const std::uint64_t id = photon::HashPrefixFromHex(hash_hex);
        if (Seen(id)) {
            return std::nullopt;
        }
        Remember(id);
        return id;
    }

    std::vector<std::vector<std::uint8_t>> delivered{};

private:
    bool Seen(std::uint64_t id) const { return m_seen.count(id) != 0; }

    void Remember(std::uint64_t id)
    {
        if (!m_seen.insert(id).second) {
            return;
        }
        m_order.push_back(id);
        if (m_order.size() > 16) {
            m_seen.erase(m_order.front());
            m_order.pop_front();
        }
    }

    std::map<std::uint64_t, photon::fec::Decoder> m_decoders{};
    std::deque<std::uint64_t> m_order{};
    std::unordered_set<std::uint64_t> m_seen{};
};

void TestIdentifierKeyedReceiverGetsEveryBlock()
{
    MockClock clock{};
    RecordingSink sink;
    const auto key = Key(81);
    constexpr std::uint16_t kPort = 42041;
    PeerManager manager({MakePeer(kPort, key)}, clock, ResolveLoopback);
    ActivatePeer(manager, sink, key, kPort);

    RelayEngine sender(clock);
    CapturingSubmitter submitter;
    IdentifierKeyedReceiver earlier;
    const auto& headers = photon::test::kMainnetHeaders;
    std::size_t sent_back = 0;
    for (std::size_t i = 0; i < headers.size(); ++i) {
        const std::vector<std::uint8_t> block = MainnetBlock(i);
        const std::string hash = HashOf(block);
        sink.sent.clear();
        sender.OnNewBlock(hash, block);
        PumpAll(sender, sink, manager);
        for (const auto& item : sink.sent) {
            if (item.packet.msg_type == MessageType::kBlockHeader) {
                BlockHeaderPayload header{};
                Require(photon::DecodeBlockHeaderPayload(item.packet.payload, header), "header decode failed");
                earlier.OnHeader(header);
            } else if (item.packet.msg_type == MessageType::kBlockChunk) {
                BlockChunkPayload chunk{};
                Require(photon::DecodeBlockChunkPayload(item.packet.payload, chunk), "chunk decode failed");
                earlier.OnChunk(chunk);
            }
        }
        Require(earlier.delivered.size() == i + 1 && earlier.delivered.back() == block,
                "mainnet block " + std::to_string(i) + " should reach the identifier-keyed receiver intact");

        // Its node announces the block, and it may send it on under the earlier form; this
        // relay recognises that copy as a block it already sent, without asking its node.
        if (const auto id = earlier.OnNodeBlock(hash)) {
            ++sent_back;
            TestBlock copy;
            copy.bytes = block;
            copy.prefix = *id;
            copy.encoded = photon::fec::Encoder(photon::fec::Parameters::FromDataChunkCount(2)).Encode(block);
            DeliverBlock(sender, kPeer0, copy, submitter);
        }
        clock.Advance(std::chrono::seconds{1});
    }

    Require(sent_back > 0, "the receiver should send some blocks back under the earlier form");
    Require(submitter.check_calls == 0 && submitter.submit_calls == 0, "copies of the relay's own blocks must not reach its node");
    Require(PeerStats(sender, 0).faults == 0, "copies sent back must not count against the receiver");
    Require(sender.stats().blocks_relayed_out == headers.size(), "each block should be relayed out once");
}

void TestParentKnownOnlyAsHeaderSubmitted()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kParentNotConnected;

    // The node stores the block without connecting it yet: not the peer's fault, however often.
    submitter.submit_result = SubmitOutcome::kInconclusive;
    for (std::uint64_t i = 0; i < 20; ++i) {
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB300 + i), submitter);
    }
    Require(submitter.submit_calls == 20, "blocks whose parent the node knows as a header should be submitted");
    Require(engine.stats().blocks_parent_pending == 20 && engine.stats().submit_inconclusive == 20, "they should be counted");
    Require(engine.stats().blocks_node_behind == 0 && engine.stats().blocks_parent_rejected == 0, "they are not dropped");
    Require(PeerStats(engine, 0).faults == 0 && engine.stats().peer_suspensions == 0, "they must not count against the peer");

    // The node may connect it at once, after the parent.
    submitter.submit_result = SubmitOutcome::kAccepted;
    DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB320), submitter);
    Require(engine.stats().submit_successes == 1, "block should be accepted");

    // A rejection still counts.
    submitter.submit_result = SubmitOutcome::kRejected;
    DeliverBlock(engine, kPeer1, EncodeTestBlock(200, 0xB321), submitter);
    Require(PeerStats(engine, 1).faults == 1, "a rejected block should count against its sender");

    // A node far behind still drops the block, without counting it against the peer.
    submitter.parent_result = ParentCheck::kNodeBehind;
    DeliverBlock(engine, kPeer2, EncodeTestBlock(200, 0xB322), submitter);
    Require(submitter.submit_calls == 22 && engine.stats().blocks_node_behind == 1, "a node far behind should not be sent the block");
    Require(PeerStats(engine, 2).faults == 0, "a node far behind is not the peer's fault");
}

void TestUnknownParentAllowedOncePerInterval()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;
    submitter.parent_result = ParentCheck::kUnknown;
    const RelayEngineConfig defaults{};

    DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB400), submitter);
    Require(PeerStats(engine, 0).faults == 0, "a peer's first unknown-parent block should be let off");
    DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB401), submitter);
    Require(PeerStats(engine, 0).faults == 1, "a second one within the interval should count");
    DeliverBlock(engine, kPeer1, EncodeTestBlock(200, 0xB402), submitter);
    Require(PeerStats(engine, 1).faults == 0, "each peer has its own allowance");

    // A full interval after the last one let off, one is let off again.
    clock.Advance(defaults.peer_fault_decay_interval);
    DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB403), submitter);
    Require(PeerStats(engine, 0).faults == 1, "the allowance should renew after the interval");

    // A stream of them pauses the peer, like other unusable blocks.
    for (std::uint32_t i = 0; i < defaults.peer_fault_threshold; ++i) {
        DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB410 + i), submitter);
    }
    Require(PeerStats(engine, 0).suspended && engine.stats().peer_suspensions == 1, "the peer should be paused");
    Require(submitter.submit_calls == 0, "blocks with an unknown parent must not be submitted");
    Require(engine.stats().blocks_parent_unknown == 4 + defaults.peer_fault_threshold, "they should be counted");
    Require(engine.stats().blocks_parent_rejected == 0, "they are not parent rejections");
}

void TestUnknownParentRaceStaysNeutral()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    // A peer relays a block before qbitd has its parent.
    const TestBlock child = EncodeTestBlock(300, 0xB420);
    submitter.parent_result = ParentCheck::kUnknown;
    DeliverBlock(engine, kPeer0, child, submitter, BlockIdOf(child.bytes));
    Require(submitter.submit_calls == 0 && engine.stats().blocks_parent_unknown == 1, "the block should be dropped");

    // The parent, then the block, reach qbitd over P2P, and qbitd announces them; the relay sends
    // both on.
    const std::vector<std::uint8_t> parent = MakeBlock(300, 0xB421);
    engine.OnNewBlock(HashOf(parent), parent);
    engine.OnNewBlock(HashOf(child.bytes), child.bytes);
    Require(engine.stats().blocks_relayed_out == 2, "both blocks should be relayed out");

    // The peer's next block is used.
    clock.Advance(std::chrono::seconds{20});
    submitter.parent_result = ParentCheck::kNearTip;
    const TestBlock next = EncodeTestBlock(300, 0xB422);
    DeliverBlock(engine, kPeer0, next, submitter, BlockIdOf(next.bytes));
    Require(submitter.submit_calls == 1 && engine.stats().submit_successes == 1, "the next block should be accepted");

    // The same race a few minutes later is let off again.
    clock.Advance(std::chrono::minutes{5});
    submitter.parent_result = ParentCheck::kUnknown;
    DeliverBlock(engine, kPeer0, EncodeTestBlock(300, 0xB423), submitter);
    const auto peer = PeerStats(engine, 0);
    Require(peer.faults == 0 && peer.fault_score == 0, "occasional races must not count against the peer");
}

void TestUnansweredBlockTriedOnceMore()
{
    const auto node_announces_block = [](RelayEngine& engine, std::uint64_t seed) {
        const std::vector<std::uint8_t> other = MakeBlock(300, seed);
        engine.OnNewBlock(HashOf(other), other);
    };

    // The parent check gets no answer; the block is tried again once the node announces a block.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        const TestBlock block = EncodeTestBlock(500, 0xB501);
        DeliverBlock(engine, kPeer0, block, submitter, BlockIdOf(block.bytes));
        Require(submitter.check_calls == 1 && submitter.submit_calls == 0, "block should not be submitted yet");

        // Other copies are not checked again meanwhile; under this version's form they are not
        // even decoded.
        const RelayStats before = engine.stats();
        DeliverBlock(engine, kPeer1, block, submitter, BlockIdOf(block.bytes));
        Require(engine.stats().chunks_received == before.chunks_received, "a held block's copy should not be decoded");
        DeliverBlock(engine, kPeer2, block, submitter, block.prefix);
        Require(submitter.check_calls == 1, "copies should not be checked while the block is held");

        // No retry while the node has given no answer since.
        clock.Advance(std::chrono::seconds{30});
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 1, "a node that has not answered should not be called again");

        submitter.parent_result = ParentCheck::kNearTip;
        node_announces_block(engine, 0xB502);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 2 && submitter.submit_calls == 1 && submitter.last_block == block.bytes,
                "held block should be checked and submitted again");
        Require(engine.stats().node_retries == 1 && engine.stats().submit_successes == 1, "retry should be counted");
        Require(PeerStats(engine, 0).blocks_received_in == 1, "the accepted block should be credited to its sender");

        node_announces_block(engine, 0xB503);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 2 && engine.stats().node_retries == 1, "a block should be retried once");
    }
    // The retry gets no answer either: the block is dropped.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        DeliverBlock(engine, kPeer0, EncodeTestBlock(500, 0xB511), submitter);
        node_announces_block(engine, 0xB512);
        engine.RetryHeldBlock(submitter);
        node_announces_block(engine, 0xB513);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 2 && submitter.submit_calls == 0, "a block should be retried once only");
        Require(engine.stats().block_checks_unavailable == 2 && PeerStats(engine, 0).faults == 0, "neither attempt counts against the peer");
        Require(engine.stats().node_retries == 1 && engine.stats().held_blocks_dropped == 0, "one retry, nothing dropped unretried");
    }
    // submitblock gets no answer; the retry finds the node has the block and does not send it again.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.submit_result = SubmitOutcome::kTimeout;
        DeliverBlock(engine, kPeer0, EncodeTestBlock(500, 0xB521), submitter);
        Require(submitter.submit_calls == 1 && engine.stats().submit_timeouts == 1, "submission should time out");
        submitter.parent_result = ParentCheck::kAlreadyKnown;
        node_announces_block(engine, 0xB522);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 2 && submitter.submit_calls == 1, "the node's copy should be found before resubmitting");
        Require(engine.stats().node_retries == 1, "retry should be counted");
    }
    // Another block's answered check also shows the node answers again.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        const TestBlock held = EncodeTestBlock(500, 0xB531);
        DeliverBlock(engine, kPeer0, held, submitter);
        submitter.parent_result = ParentCheck::kNearTip;
        DeliverBlock(engine, kPeer1, EncodeTestBlock(500, 0xB532), submitter);
        engine.RetryHeldBlock(submitter);
        Require(submitter.submit_calls == 2 && submitter.last_block == held.bytes, "held block should follow the answered one");
    }
    // The node announcing the held block itself: no further node calls.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        const TestBlock block = EncodeTestBlock(500, 0xB541);
        DeliverBlock(engine, kPeer0, block, submitter);
        engine.OnNewBlock(HashOf(block.bytes), block.bytes);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 1 && submitter.submit_calls == 0, "a block the node announced needs no retry");
        Require(engine.stats().node_retries == 0, "no retry is counted without a call to the node");
    }
    // A held block is dropped after its lifetime, and when its sender is paused.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        const TestBlock expired = EncodeTestBlock(500, 0xB551);
        DeliverBlock(engine, kPeer0, expired, submitter);
        clock.Advance(RelayEngineConfig{}.held_block_lifetime + std::chrono::milliseconds{1});
        node_announces_block(engine, 0xB552);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 1, "an expired held block should not be retried");
        Require(engine.stats().held_blocks_dropped == 1, "the expired block should be counted");
        // Like any block the node did not answer for, its late copies are not checked at once.
        DeliverBlock(engine, kPeer2, expired, submitter, BlockIdOf(expired.bytes));
        Require(submitter.check_calls == 1, "a late copy of an expired held block should not be checked at once");

        const TestBlock paused = EncodeTestBlock(500, 0xB553);
        DeliverBlock(engine, kPeer1, paused, submitter);
        submitter.parent_result = ParentCheck::kTooFar;
        for (std::uint32_t i = 0; i < RelayEngineConfig{}.peer_fault_threshold; ++i) {
            DeliverBlock(engine, kPeer1, EncodeTestBlock(200, 0xB560 + i), submitter);
        }
        Require(PeerStats(engine, 1).suspended, "peer should be paused");
        const std::size_t checks = submitter.check_calls;
        node_announces_block(engine, 0xB554);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == checks, "a paused peer's held block should not be retried");
        Require(engine.stats().held_blocks_dropped == 2, "the paused peer's block should be counted");
        // Another peer's copy of it is still tried: the node never saw it.
        submitter.parent_result = ParentCheck::kNearTip;
        DeliverBlock(engine, kPeer2, paused, submitter, BlockIdOf(paused.bytes));
        Require(submitter.check_calls == checks + 1 && submitter.last_block == paused.bytes,
                "another peer's copy of a paused peer's held block should be used");
    }
    // A block whose parent is the held block: the held block is tried first once qbitd answers.
    {
        const auto child_of = [](const TestBlock& parent, std::uint64_t seed) {
            TestBlock child = EncodeTestBlock(300, seed);
            const std::string parent_hash = HashOf(parent.bytes);
            for (std::size_t i = 0; i < 32; ++i) {
                child.bytes[4 + i] = static_cast<std::uint8_t>(std::stoul(parent_hash.substr((31 - i) * 2, 2), nullptr, 16));
            }
            child.prefix = PrefixOf(child.bytes);
            child.encoded = photon::fec::Encoder(photon::fec::Parameters::FromDataChunkCount(2)).Encode(child.bytes);
            Require(photon::ReadBlockHeaderSummary(child.bytes)->prev_hash_hex == parent_hash, "child should build on its parent");
            return child;
        };

        // The node answers again, but does not know the new block's parent, the held block: the
        // held block is tried first, then the new block is checked again, and both are submitted.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB581);
            DeliverBlock(engine, kPeer0, held, submitter);
            const TestBlock child = child_of(held, 0xB582);
            std::vector<std::vector<std::uint8_t>> submitted;
            submitter.submit_hook = [&submitted](std::span<const std::uint8_t> data) {
                submitted.emplace_back(data.begin(), data.end());
                return SubmitOutcome::kAccepted;
            };
            submitter.parent_results = {ParentCheck::kUnknown, ParentCheck::kNearTip, ParentCheck::kNearTip};
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(submitter.check_calls == 4 && submitted.size() == 2 && submitted[0] == held.bytes && submitted[1] == child.bytes,
                    "the held parent should be submitted before its child");
            Require(engine.stats().node_retries == 1 && engine.stats().submit_successes == 2, "both should be accepted");
            Require(engine.stats().blocks_parent_unknown == 0, "the child's parent is found on the second check");
            engine.RetryHeldBlock(submitter);
            Require(submitter.check_calls == 4, "the parent should not be tried again");
        }
        // qbitd still does not answer: the held block is not tried again at that point, and it is
        // kept rather than replaced by its child.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB583);
            DeliverBlock(engine, kPeer0, held, submitter);
            const TestBlock child = child_of(held, 0xB584);
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(submitter.check_calls == 2 && engine.stats().node_retries == 0, "a node that does not answer should not be called again");
            Require(engine.stats().held_blocks_dropped == 0, "the parent should stay held");
            DeliverBlock(engine, kPeer2, child, submitter, BlockIdOf(child.bytes));
            Require(submitter.check_calls == 2, "the dropped child's copies should not be checked at once");
            submitter.parent_result = ParentCheck::kNearTip;
            node_announces_block(engine, 0xB585);
            engine.RetryHeldBlock(submitter);
            Require(submitter.submit_calls == 1 && submitter.last_block == held.bytes, "the parent should be retried");
            Require(PeerStats(engine, 0).faults == 0 && PeerStats(engine, 1).faults == 0, "neither counts against its sender");
        }
        // The held parent's retry is answered, but qbitd still cannot use it (its own parent is
        // unknown): the child's unknown parent does not count against its sender either.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB5E0);
            DeliverBlock(engine, kPeer0, held, submitter);
            submitter.parent_result = ParentCheck::kUnknown;
            DeliverBlock(engine, kPeer1, EncodeTestBlock(300, 0xB5E1), submitter); // uses the allowance
            const TestBlock child = child_of(held, 0xB5E2);
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(submitter.check_calls == 5 && engine.stats().node_retries == 1, "parent retried, child checked twice");
            Require(PeerStats(engine, 0).faults == 0 && PeerStats(engine, 1).faults == 0, "neither counts against its sender");
        }
        // The held parent's retry is answered but the child's second check is not: the child is held.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB5B0);
            DeliverBlock(engine, kPeer0, held, submitter);
            const TestBlock child = child_of(held, 0xB5B1);
            submitter.parent_results = {ParentCheck::kUnknown, ParentCheck::kNearTip, ParentCheck::kUnavailable};
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(submitter.check_calls == 4 && submitter.submit_calls == 1 && submitter.last_block == held.bytes,
                    "the parent should be submitted");
            Require(engine.stats().held_blocks_dropped == 0, "nothing should be dropped");
            submitter.parent_result = ParentCheck::kNearTip;
            node_announces_block(engine, 0xB5B2);
            engine.RetryHeldBlock(submitter);
            Require(submitter.submit_calls == 2 && submitter.last_block == child.bytes, "the child should be held and retried");
        }
        // The held parent's retry pauses the parent's sender, a different peer: the child is still used.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kTooFar;
            for (std::uint32_t i = 0; i + 1 < RelayEngineConfig{}.peer_fault_threshold; ++i) {
                DeliverBlock(engine, kPeer0, EncodeTestBlock(200, 0xB5C0 + i), submitter);
            }
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB5D0);
            DeliverBlock(engine, kPeer0, held, submitter);
            const TestBlock child = child_of(held, 0xB5D1);
            submitter.parent_results = {ParentCheck::kUnknown, ParentCheck::kNearTip, ParentCheck::kParentNotConnected};
            submitter.submit_hook = [&held](std::span<const std::uint8_t> data) {
                return std::equal(data.begin(), data.end(), held.bytes.begin(), held.bytes.end()) ? SubmitOutcome::kRejected
                                                                                                 : SubmitOutcome::kInconclusive;
            };
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(PeerStats(engine, 0).suspended && !PeerStats(engine, 1).suspended, "only the parent's sender should be paused");
            Require(submitter.submit_calls == 2 && submitter.last_block == child.bytes, "the child should still be submitted");
            Require(PeerStats(engine, 1).faults == 0, "the child should not count against its sender");
        }
        // The held parent's retry gets no answer: the child is not checked again but held, and its
        // unknown parent does not count against its sender, even after the sender's allowance is used.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB586);
            DeliverBlock(engine, kPeer0, held, submitter);
            submitter.parent_result = ParentCheck::kUnknown;
            DeliverBlock(engine, kPeer1, EncodeTestBlock(300, 0xB587), submitter); // uses the allowance
            const TestBlock child = child_of(held, 0xB588);
            submitter.parent_results = {ParentCheck::kUnknown, ParentCheck::kUnavailable};
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(engine.stats().node_retries == 1 && submitter.submit_calls == 0, "the parent should be tried once");
            Require(submitter.check_calls == 4, "the child should not be checked again while qbitd does not answer");
            // The child is held instead, and its retry finding its parent unknown is not counted.
            submitter.parent_result = ParentCheck::kUnknown;
            node_announces_block(engine, 0xB589);
            engine.RetryHeldBlock(submitter);
            Require(submitter.check_calls == 5 && engine.stats().node_retries == 2, "the child should be retried");
            Require(PeerStats(engine, 1).faults == 0, "the child should not count against its sender");
        }
        // The held parent is rejected and that pauses the sender of both: the child is dropped.
        {
            MockClock clock{};
            RelayEngine engine(clock);
            CapturingSubmitter submitter;
            submitter.parent_result = ParentCheck::kTooFar;
            for (std::uint32_t i = 0; i + 1 < RelayEngineConfig{}.peer_fault_threshold; ++i) {
                DeliverBlock(engine, kPeer1, EncodeTestBlock(200, 0xB590 + i), submitter);
            }
            submitter.parent_result = ParentCheck::kUnavailable;
            const TestBlock held = EncodeTestBlock(500, 0xB5A0);
            DeliverBlock(engine, kPeer1, held, submitter);
            const TestBlock child = child_of(held, 0xB5A1);
            submitter.parent_results = {ParentCheck::kUnknown, ParentCheck::kNearTip};
            submitter.submit_result = SubmitOutcome::kRejected;
            DeliverBlock(engine, kPeer1, child, submitter);
            Require(PeerStats(engine, 1).suspended, "the rejected parent should pause its sender");
            Require(submitter.submit_calls == 1 && submitter.last_block == held.bytes, "the paused sender's child should not be submitted");
            submitter.parent_result = ParentCheck::kNearTip;
            node_announces_block(engine, 0xB5A2);
            engine.RetryHeldBlock(submitter);
            Require(submitter.submit_calls == 1, "nor held for later");
        }
    }
    // A copy in progress when the block is held: the rest of its chunks are ignored, even after a
    // retry that leaves other copies free to be tried.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        const TestBlock block = EncodeTestBlock(500, 0xB591);
        const std::uint64_t id = BlockIdOf(block.bytes);
        engine.OnBlockHeader(kPeer1, BuildHeaderPayload(block.encoded, id, block.bytes.size()), submitter);
        engine.OnBlockChunk(kPeer1, BuildChunkPayload(block.encoded.chunks[0], id), submitter);
        submitter.parent_result = ParentCheck::kUnavailable;
        DeliverBlock(engine, kPeer0, block, submitter, id);
        Require(engine.stats().inbound_entries == 0, "the copy in progress should be dropped when the block is held");
        // Other copies start while the block is held, one with its header, one with a chunk.
        const InboundPeerInfo peer3{.slot_index = 3, .remote_session_id = 7004, .remote_peer_id = 8004};
        engine.OnBlockHeader(kPeer2, BuildHeaderPayload(block.encoded, id, block.bytes.size()), submitter);
        engine.OnBlockChunk(peer3, BuildChunkPayload(block.encoded.chunks[0], id), submitter);

        submitter.parent_result = ParentCheck::kNearTip;
        submitter.submit_result = SubmitOutcome::kRejected;
        node_announces_block(engine, 0xB592);
        engine.RetryHeldBlock(submitter);
        Require(engine.stats().submit_rejected == 1, "the retried copy should be rejected");
        for (const InboundPeerInfo& peer : {kPeer1, kPeer2, peer3}) {
            engine.OnBlockChunk(peer, BuildChunkPayload(block.encoded.chunks[1], id), submitter);
        }
        Require(engine.stats().inbound_entries == 0, "the ignored copies' remaining chunks must not start new blocks");
    }
    // A newer block replaces the held one.
    {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        const TestBlock replaced = EncodeTestBlock(500, 0xB571);
        DeliverBlock(engine, kPeer0, replaced, submitter);
        const TestBlock newer = EncodeTestBlock(500, 0xB572);
        DeliverBlock(engine, kPeer1, newer, submitter);
        Require(engine.stats().held_blocks_dropped == 1, "the replaced block should be counted");
        // Late copies of the replaced block are not sent to the node again right away; under this
        // version's form they are not even decoded.
        DeliverBlock(engine, kPeer2, replaced, submitter);
        const RelayStats before = engine.stats();
        DeliverBlock(engine, kPeer2, replaced, submitter, BlockIdOf(replaced.bytes));
        Require(engine.stats().chunks_received == before.chunks_received, "a replaced block's copy should not be decoded");
        Require(submitter.check_calls == 2, "a replaced block's copy should not be checked again at once");
        submitter.parent_result = ParentCheck::kNearTip;
        node_announces_block(engine, 0xB573);
        engine.RetryHeldBlock(submitter);
        Require(submitter.submit_calls == 1 && submitter.last_block == newer.bytes, "the newer block should be retried");
    }
}

// What a retry finds may reflect how long the node took to answer: those outcomes do not count
// against the sender, while verdicts on the block itself still do.
void TestHeldBlockRetryOutcomes()
{
    struct Case {
        ParentCheck parent;
        SubmitOutcome submit;
        std::uint64_t faults;
    };
    const std::vector<Case> cases{
        {ParentCheck::kTooFar, SubmitOutcome::kAccepted, 0},
        {ParentCheck::kUnknown, SubmitOutcome::kAccepted, 0},
        {ParentCheck::kNearTip, SubmitOutcome::kInconclusive, 0},
        {ParentCheck::kNearTip, SubmitOutcome::kRejected, 1},
        {ParentCheck::kNearTip, SubmitOutcome::kKnownInvalid, 1},
    };
    std::uint64_t seed = 0xB600;
    for (const Case& test_case : cases) {
        MockClock clock{};
        RelayEngine engine(clock);
        CapturingSubmitter submitter;
        submitter.parent_result = ParentCheck::kUnavailable;
        const TestBlock block = EncodeTestBlock(500, ++seed);
        DeliverBlock(engine, kPeer0, block, submitter);

        submitter.parent_result = test_case.parent;
        submitter.submit_result = test_case.submit;
        const std::vector<std::uint8_t> other = MakeBlock(300, ++seed);
        engine.OnNewBlock(HashOf(other), other);
        engine.RetryHeldBlock(submitter);
        Require(submitter.check_calls == 2 && engine.stats().node_retries == 1, "the held block should be retried");
        Require(PeerStats(engine, 0).faults == test_case.faults,
                std::string("retry outcome ") + photon::ParentCheckName(test_case.parent) + "/" +
                    photon::SubmitOutcomeName(test_case.submit) + " charged wrongly");

        // A retry with an unknown parent does not use up the peer's allowance.
        if (test_case.parent == ParentCheck::kUnknown) {
            DeliverBlock(engine, kPeer0, EncodeTestBlock(500, ++seed), submitter);
            Require(PeerStats(engine, 0).faults == 0, "the peer's allowance should be left for its next block");
        }

        // An outcome that concerns only this copy leaves other peers' copies to be tried.
        if (test_case.submit == SubmitOutcome::kRejected) {
            submitter.submit_result = SubmitOutcome::kAccepted;
            DeliverBlock(engine, kPeer1, block, submitter, BlockIdOf(block.bytes));
            Require(submitter.submit_calls == 2 && engine.stats().submit_successes == 1, "another peer's copy should be used");
        }
    }
}

#if defined(PHOTON_TEST_HAVE_MALLINFO2)
std::size_t HeapInUse()
{
    const struct mallinfo2 info = mallinfo2();
    return info.uordblks + info.hblkhd;
}

std::size_t HeapGrowthSince(std::size_t base)
{
    const std::size_t now = HeapInUse();
    return now > base ? now - base : 0;
}

// mallinfo2 sees only glibc's allocator; under a sanitizer or a preloaded allocator it reports
// nothing useful, so measurements are skipped there.
bool HeapMeasurable()
{
    constexpr std::size_t kProbeBytes = 1024 * 1024;
    const std::size_t base = HeapInUse();
    void* volatile probe = std::malloc(kProbeBytes);
    const bool visible = probe != nullptr && HeapInUse() >= base + kProbeBytes;
    std::free(probe);
    return visible;
}

// Largest block size for which a decoder with `data_chunks` fits within `charge_limit`.
std::size_t LargestChargeableSize(std::uint16_t data_chunks, std::size_t charge_limit, std::size_t size_limit)
{
    const auto params = photon::fec::Parameters::FromDataChunkCount(data_chunks);
    const std::size_t group_bytes = static_cast<std::size_t>(data_chunks) * photon::fec::FEC_CHUNK_SIZE;
    std::size_t best = 0;
    for (std::size_t groups = 1; groups * group_bytes - group_bytes < size_limit; ++groups) {
        const std::size_t size = std::min(groups * group_bytes, size_limit);
        if (photon::fec::Decoder::MemoryBytes(params, size) > charge_limit) {
            break;
        }
        best = size;
    }
    return best;
}
#endif

void TestDefaultBlockDecoderFitsEntryLimit()
{
#if defined(PHOTON_TEST_HAVE_MALLINFO2)
    if (!HeapMeasurable()) {
        std::cout << "  (allocator not visible to mallinfo2; skipped)\n";
        return;
    }
    const RelayEngineConfig defaults{};
    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const std::vector<std::uint8_t> block = MakeBlock(defaults.max_inbound_original_size, 0xF800);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);
    const std::size_t charge = photon::fec::Decoder::MemoryBytes(params, block.size());

    // Measure the real decoder: parity chunks first (the most state held), then data chunks.
    const std::size_t base = HeapInUse();
    std::size_t peak = 0;
    {
        photon::fec::Decoder decoder(params, block.size());
        peak = HeapGrowthSince(base);
        for (int pass = 0; pass < 2 && !decoder.IsComplete(); ++pass) {
            for (const auto& chunk : encoded.chunks) {
                if ((pass == 0) != (chunk.chunk_id >= params.data_chunks)) {
                    continue;
                }
                (void)decoder.AddChunk(chunk);
                peak = std::max(peak, HeapGrowthSince(base));
                if (decoder.IsComplete()) {
                    break;
                }
            }
        }
        Require(decoder.IsComplete(), "default-parameter block should decode");
    }

    std::cout << "  default 2,000,000-byte block: decoder peak " << peak << " B, charged " << charge
              << " B, per-block limit " << defaults.max_inbound_decoder_bytes_per_entry << " B, margin over charge "
              << (defaults.max_inbound_decoder_bytes_per_entry - std::min(charge, defaults.max_inbound_decoder_bytes_per_entry))
              << " B\n";
    Require(peak <= charge, "measured decoder memory must not exceed the charge");
    Require(charge <= defaults.max_inbound_decoder_bytes_per_entry, "default block must fit the per-block limit");
    Require(defaults.max_inbound_decoder_bytes_per_entry - charge >= 128 * 1024, "per-block limit should leave a margin");
#else
    std::cout << "  (heap measurement needs glibc 2.33 or later; skipped)\n";
#endif
}

void TestWorstCaseInboundDecodersStayWithinBound()
{
#if defined(PHOTON_TEST_HAVE_MALLINFO2)
    if (!HeapMeasurable()) {
        std::cout << "  (allocator not visible to mallinfo2; skipped)\n";
        return;
    }
    MockClock clock{};
    const RelayEngineConfig defaults{};
    CapturingSubmitter submitter;

    // Parameter mix that costs the most decoder memory per block, each at the largest size the
    // per-block limit admits.
    const std::vector<std::uint16_t> worst_data_chunks{2, 27, 28, 40, 64, 128, 212, 254};

    const std::size_t base = HeapInUse();
    std::size_t peak = 0;
    std::size_t charged_peak = 0;
    {
        RelayEngine engine(clock, defaults);
        std::uint64_t prefix = 0x9000;
        for (std::size_t slot = 0; slot < 24; ++slot) {
            const InboundPeerInfo peer{.slot_index = slot, .remote_session_id = 100 + slot, .remote_peer_id = 200 + slot};
            for (const std::uint16_t data_chunks : worst_data_chunks) {
                const std::size_t size = LargestChargeableSize(
                    data_chunks, defaults.max_inbound_decoder_bytes_per_entry, defaults.max_inbound_original_size);
                Require(size > 0, "every parameter set should admit some block");
                const std::size_t group_bytes = static_cast<std::size_t>(data_chunks) * photon::fec::FEC_CHUNK_SIZE;
                BlockHeaderPayload header{};
                header.block_hash_prefix = ++prefix;
                header.original_size = size;
                header.data_chunks = data_chunks;
                header.coding_group_count = static_cast<std::uint16_t>((size + group_bytes - 1) / group_bytes);
                engine.OnBlockHeader(peer, header, submitter);
                peak = std::max(peak, HeapGrowthSince(base));
                charged_peak = std::max<std::size_t>(charged_peak, engine.stats().inbound_decoder_bytes);
                const PeerRelayStats peer_stats = PeerStats(engine, slot);
                Require(peer_stats.inbound_decoder_bytes <= defaults.max_inbound_decoder_bytes_per_peer,
                        "per-peer decoder charge must stay within its limit");
            }
        }
        Require(engine.stats().inbound_entries <= defaults.max_inbound_entries, "entry limit must hold");
    }

    // Engine bookkeeping (map nodes, per-peer state) is small next to the decoders.
    constexpr std::size_t kBookkeepingAllowance = 1024 * 1024;
    std::cout << "  worst-case inbound decoders: heap peak " << peak << " B, charged peak " << charged_peak
              << " B, documented bound " << defaults.max_inbound_decoder_bytes << " B\n";
    Require(charged_peak <= defaults.max_inbound_decoder_bytes, "charged decoder memory must stay within the total limit");
    Require(peak <= charged_peak + kBookkeepingAllowance, "measured memory must stay within the charge");
    Require(peak <= defaults.max_inbound_decoder_bytes + kBookkeepingAllowance, "measured memory must stay within the documented bound");
#else
    std::cout << "  (heap measurement needs glibc 2.33 or later; skipped)\n";
#endif
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"outbound_encode_schedule_pump", TestOutboundEncodeSchedulePump},
        {"outbound_preemption", TestOutboundPreemption},
        {"inbound_reconstruction_all_chunks", TestInboundReconstructionAllChunks},
        {"inbound_dedup_known_prefix", TestInboundDedupKnownPrefix},
        {"inbound_with_loss_recovers", TestInboundWithLossStillRecovers},
        {"blockheader_flow_creates_decoder", TestBlockHeaderFlowCreatesDecoder},
        {"duplicate_header_preserves_progress", TestDuplicateHeaderDoesNotResetProgress},
        {"same_prefix_conflicting_peer_does_not_poison_honest_relay", TestSamePrefixConflictingPeerDoesNotPoisonHonestRelay},
        {"oversized_inbound_header_rejected", TestOversizedInboundHeaderRejected},
        {"zero_size_inbound_header_rejected", TestZeroSizeInboundHeaderRejected},
        {"cm256_header_accepted_within_decoder_budget", TestCm256HeaderAcceptedWithinDecoderBudget},
        {"post_header_chunk_failure_erases_decoder", TestPostHeaderChunkFailureErasesDecoder},
        {"mismatched_coding_group_count_rejected", TestMismatchedCodingGroupCountRejected},
        {"default_fec_header_accepted_within_decoder_budget", TestDefaultFecHeaderAcceptedWithinDecoderBudget},
        {"inbound_entry_limit_evicts_oldest_prefix", TestInboundEntryLimitEvictsOldestPrefix},
        {"inbound_age_limit_evicts_incomplete_relay", TestInboundAgeLimitEvictsIncompleteRelay},
        {"inbound_age_limit_uses_last_activity", TestInboundAgeLimitUsesLastActivity},
        {"inbound_preheader_buffered_byte_limit", TestInboundPreHeaderBufferedByteLimit},
        {"rejected_new_prefix_chunk_does_not_evict_existing_relay", TestRejectedNewPrefixChunkDoesNotEvictExistingRelay},
        {"inbound_limits_allow_valid_reconstruction", TestInboundLimitsAllowValidReconstruction},
        {"stats_accumulation", TestStatsAccumulation},
        {"mismatched_identifier_not_submitted", TestMismatchedIdentifierNotSubmitted},
        {"too_short_block_not_submitted", TestTooShortBlockNotSubmitted},
        {"parent_check_receives_block_parent", TestParentCheckReceivesBlockParent},
        {"block_with_parent_away_from_tip_not_submitted", TestBlockWithParentAwayFromTipNotSubmitted},
        {"unavailable_parent_check_drops_without_penalty", TestUnavailableParentCheckDropsWithoutPenalty},
        {"submit_outcomes_counted_separately", TestSubmitOutcomesCountedSeparately},
        {"neutral_outcomes_never_suspend_peer", TestNeutralOutcomesNeverSuspendPeer},
        {"repeated_rejected_blocks_suspend_peer", TestRepeatedRejectedBlocksSuspendPeer},
        {"accepted_block_lowers_fault_score_without_resetting", TestAcceptedBlockLowersFaultScoreWithoutResetting},
        {"fault_score_decays_over_time", TestFaultScoreDecaysOverTime},
        {"peer_flood_does_not_evict_other_peers_block", TestPeerFloodDoesNotEvictOtherPeersBlock},
        {"per_peer_entry_quota_boundary", TestPerPeerEntryQuotaBoundary},
        {"per_peer_decoder_quota_boundary", TestPerPeerDecoderQuotaBoundary},
        {"global_limit_spares_other_peers_recent_progress", TestGlobalLimitSparesOtherPeersRecentProgress},
        {"oversized_decoder_charge_rejected", TestOversizedDecoderChargeRejected},
        {"default_block_decoder_fits_entry_limit", TestDefaultBlockDecoderFitsEntryLimit},
        {"worst_case_inbound_decoders_stay_within_bound", TestWorstCaseInboundDecodersStayWithinBound},
        {"block_already_known_not_submitted_or_penalized", TestBlockAlreadyKnownNotSubmittedOrPenalized},
        {"node_behind_drops_without_penalty", TestNodeBehindDropsWithoutPenalty},
        {"inconclusive_block_counted_once_across_peers", TestInconclusiveBlockCountedOnceAcrossPeers},
        {"invalid_chunk_after_header_counts_against_peer", TestInvalidChunkAfterHeaderCountsAgainstPeer},
        {"remaining_chunks_of_handled_block_ignored", TestRemainingChunksOfHandledBlockIgnored},
        {"failed_reservation_evicts_nothing", TestFailedReservationEvictsNothing},
        {"repeated_chunks_do_not_keep_block_alive", TestRepeatedChunksDoNotKeepBlockAlive},
        {"combined_limits_evict_nothing_when_refused", TestCombinedLimitsEvictNothingWhenRefused},
        {"refused_header_remaining_chunks_ignored", TestRefusedHeaderRemainingChunksIgnored},
        {"capacity_refused_block_completes_in_sender_order", TestCapacityRefusedBlockCompletesInSenderOrder},
        {"capacity_refused_header_can_be_retried", TestCapacityRefusedHeaderCanBeRetried},
        {"waiting_block_ends_once_it_cannot_complete", TestWaitingBlockEndsOnceItCannotComplete},
        {"header_after_chunks_waits_with_them", TestHeaderAfterChunksWaitsWithThem},
        {"starting_waiting_block_is_not_progress", TestStartingWaitingBlockIsNotProgress},
        {"waiting_block_takes_nothing_from_other_blocks", TestWaitingBlockTakesNothingFromOtherBlocks},
        {"never_fitting_decoder_finishes_block", TestNeverFittingDecoderFinishesBlock},
        {"waiting_block_chunk_must_fit_its_header", TestWaitingBlockChunkMustFitItsHeader},
        {"fault_refused_header_stays_handled", TestFaultRefusedHeaderStaysHandled},
        {"node_answered_block_still_relayed_out", TestNodeAnsweredBlockStillRelayedOut},
        {"unavailable_check_not_repeated_for_copies", TestUnavailableCheckNotRepeatedForCopies},
        {"rejected_copy_does_not_block_other_peers_copy", TestRejectedCopyDoesNotBlockOtherPeersCopy},
        {"settle_uses_time_after_node_calls", TestSettleUsesTimeAfterNodeCalls},
        {"unknown_parent_ends_only_that_copy", TestUnknownParentEndsOnlyThatCopy},
        {"repeated_preheader_chunks_not_buffered", TestRepeatedPreHeaderChunksNotBuffered},
        {"malformed_headers_count_against_peer", TestMalformedHeadersCountAgainstPeer},
        {"buffered_chunks_checked_before_eviction", TestBufferedChunksCheckedBeforeEviction},
        {"known_invalid_block_settled_for_all_copies", TestKnownInvalidBlockSettledForAllCopies},
        {"handled_block_timed_after_node_calls", TestHandledBlockTimedAfterNodeCalls},
        {"block_identifier_forms", TestBlockIdentifierForms},
        {"blocks_sharing_leading_hash_bits_all_relayed", TestBlocksSharingLeadingHashBitsAllRelayed},
        {"earlier_form_identifier_accepted_without_fault", TestEarlierFormIdentifierAcceptedWithoutFault},
        {"block_identifier_accepted", TestBlockIdentifierAccepted},
        {"block_announced_under_both_forms_used_once", TestBlockAnnouncedUnderBothFormsUsedOnce},
        {"mainnet_hash_sequence_relayed_without_suppression", TestMainnetHashSequenceRelayedWithoutSuppression},
        {"identifier_keyed_receiver_gets_every_block", TestIdentifierKeyedReceiverGetsEveryBlock},
        {"parent_known_only_as_header_submitted", TestParentKnownOnlyAsHeaderSubmitted},
        {"unknown_parent_allowed_once_per_interval", TestUnknownParentAllowedOncePerInterval},
        {"unknown_parent_race_stays_neutral", TestUnknownParentRaceStaysNeutral},
        {"held_block_retry_outcomes", TestHeldBlockRetryOutcomes},
        {"unanswered_block_tried_once_more", TestUnansweredBlockTriedOnceMore},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        try {
            fn();
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception& e) {
            ++failures;
            std::cout << "[FAIL] " << name << ": " << e.what() << '\n';
        }
    }

    return failures;
}

} // namespace

int main()
{
    return RunAllTests() == 0 ? 0 : 1;
}
