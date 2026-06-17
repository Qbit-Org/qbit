#include <clock.h>
#include <fec.h>
#include <peer_manager.h>
#include <protocol.h>
#include <relay_engine.h>
#include <udp_transport.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using photon::BlockChunkPayload;
using photon::BlockHeaderPayload;
using photon::InboundPeerInfo;
using photon::MessageType;
using photon::MockClock;
using photon::Packet;
using photon::PeerConfig;
using photon::PeerManager;
using photon::RelayEngine;
using photon::RelayEngineConfig;
using photon::RelayStats;

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
    bool SubmitBlock(std::span<const std::uint8_t> block_data) override
    {
        ++submit_calls;
        last_block.assign(block_data.begin(), block_data.end());
        return submit_result;
    }

    bool submit_result{true};
    std::size_t submit_calls{0};
    std::vector<std::uint8_t> last_block{};
};

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
            saw_new_prefix = header.block_hash_prefix == photon::HashPrefixFromHex(new_hash);
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
    const std::vector<std::uint8_t> block = RandomBytes(5000, 0x3333);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x1234567890ABCDEFULL;
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
}

void TestInboundDedupKnownPrefix()
{
    MockClock clock{};
    RelayEngine engine(clock);
    CapturingSubmitter submitter;

    const std::string hash_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const std::uint64_t prefix = photon::HashPrefixFromHex(hash_hex);

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
    const std::vector<std::uint8_t> block = RandomBytes(5000, 0x5555);
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x9988776655443322ULL;
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
    const std::vector<std::uint8_t> block = {'a', 'b', 'c', 'd', 'e'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x0F0E0D0C0B0A0908ULL;

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
    const std::vector<std::uint8_t> block = {'r', 'e', 'l', 'a', 'y'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x0A0B0C0D0E0F0102ULL;

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
    const std::vector<std::uint8_t> block = {'h', 'o', 'n', 'e', 's', 't'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x0BADC0FFEE123456ULL;
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
    const std::vector<std::uint8_t> block = {'b', 'a', 'd'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x2525252525252525ULL;
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

    const auto params = photon::fec::Parameters::FromDataChunkCount(2);
    const std::vector<std::uint8_t> block = {'l', 'i', 'm', 'i', 't'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kEvictedPrefix = 0x0000000000000001ULL;
    constexpr std::uint64_t kSecondPrefix = 0x0000000000000002ULL;
    constexpr std::uint64_t kKeptPrefix = 0x0000000000000003ULL;

    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kEvictedPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kSecondPrefix), submitter);
    clock.Advance(std::chrono::milliseconds{1});
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[0], kKeptPrefix), submitter);

    Require(engine.stats().inbound_evictions == 1, "entry cap should evict one incomplete relay");

    engine.OnBlockHeader(BuildHeaderPayload(encoded, kEvictedPrefix, block.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kEvictedPrefix), submitter);
    Require(submitter.submit_calls == 0, "oldest evicted prefix should have lost its buffered chunk");

    engine.OnBlockHeader(BuildHeaderPayload(encoded, kKeptPrefix, block.size()), submitter);
    engine.OnBlockChunk(BuildChunkPayload(encoded.chunks[1], kKeptPrefix), submitter);
    Require(submitter.submit_calls == 1, "newer prefix should still reconstruct inside entry cap");
    Require(submitter.last_block == block, "entry-cap reconstruction mismatch");
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
    const std::vector<std::uint8_t> block = {'a', 'g', 'e'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x0BADF00D0BADF00DULL;

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
    const std::vector<std::uint8_t> block = {'s', 'l', 'o', 'w'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x5151515151515151ULL;

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
    const std::vector<std::uint8_t> block = {'b', 'y', 't', 'e'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0x1234000012340000ULL;

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
    const std::vector<std::uint8_t> block = {'k', 'e', 'e', 'p'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kDecoderPrefix = 0xAAAA000000000001ULL;
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
    const std::vector<std::uint8_t> block = {'o', 'k'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    constexpr std::uint64_t kPrefix = 0xABCD0000ABCD0000ULL;

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
    const std::vector<std::uint8_t> inbound_block = {'h', 'i'};
    photon::fec::Encoder encoder(params);
    const photon::fec::EncodedBlock encoded = encoder.Encode(inbound_block);

    constexpr std::uint64_t kInboundPrefix = 0xABCDEF1234567890ULL;
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
