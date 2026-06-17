#include <relay_engine.h>

#include <logging.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <limits>
#include <vector>

namespace photon {
namespace {

constexpr std::size_t kHeaderRedundancy = 3;
constexpr std::size_t kDefaultMaxInboundOriginalSize = 2'000'000;
constexpr std::size_t kDefaultMaxInboundEntries = 128;
constexpr std::size_t kDefaultMaxInboundBufferedChunksPerEntry = 64;
constexpr std::size_t kDefaultMaxInboundBufferedBytes = 1024 * fec::FEC_CHUNK_SIZE;
constexpr std::size_t kDefaultMaxInboundDecoderBytesPerEntry = 3 * 1024 * 1024;
constexpr std::chrono::milliseconds kDefaultMaxInboundAge{std::chrono::minutes{2}};

template <typename T>
constexpr T DivCeil(T numerator, T denominator)
{
    return (numerator + denominator - 1) / denominator;
}

std::size_t SaturatingMultiply(std::size_t left, std::size_t right)
{
    if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left) {
        return std::numeric_limits<std::size_t>::max();
    }
    return left * right;
}

std::size_t DecoderBudgetBytes(const fec::Parameters& params, std::size_t group_count, std::size_t group_payload_bytes)
{
    if (params.data_chunks <= fec::CM256_MAX_DATA_CHUNKS) {
        return SaturatingMultiply(
            SaturatingMultiply(group_count, static_cast<std::size_t>(params.data_chunks)),
            fec::FEC_CHUNK_SIZE);
    }
    return SaturatingMultiply(group_count, group_payload_bytes);
}

void HashCombine(std::size_t& seed, std::size_t value)
{
    seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

bool HexNibble(char ch, std::uint8_t& nibble)
{
    if (ch >= '0' && ch <= '9') {
        nibble = static_cast<std::uint8_t>(ch - '0');
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        nibble = static_cast<std::uint8_t>(ch - 'a' + 10);
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        nibble = static_cast<std::uint8_t>(ch - 'A' + 10);
        return true;
    }
    return false;
}

} // namespace

std::uint64_t HashPrefixFromHex(const std::string& hash_hex)
{
    if (hash_hex.size() < 16) {
        return 0;
    }

    std::uint64_t prefix = 0;
    for (std::size_t i = 0; i < 16; ++i) {
        std::uint8_t nibble = 0;
        if (!HexNibble(hash_hex[i], nibble)) {
            return 0;
        }
        prefix = (prefix << 4) | static_cast<std::uint64_t>(nibble);
    }

    return prefix;
}

RelayEngine::OutboundRelay::OutboundRelay(std::uint64_t prefix,
                                          fec::Parameters parameters,
                                          std::size_t size,
                                          std::uint16_t group_count,
                                          ChunkScheduler schedule)
    : hash_prefix(prefix)
    , params(parameters)
    , original_size(size)
    , coding_group_count(group_count)
    , scheduler(std::move(schedule))
{
}

std::size_t RelayEngine::InboundRelayKeyHash::operator()(const InboundRelayKey& key) const
{
    std::size_t seed = std::hash<std::uint64_t>{}(key.hash_prefix);
    HashCombine(seed, std::hash<std::size_t>{}(key.slot_index));
    HashCombine(seed, std::hash<std::uint64_t>{}(key.remote_session_id));
    HashCombine(seed, std::hash<std::uint64_t>{}(key.remote_peer_id));
    return seed;
}

RelayEngine::InboundRelayKey RelayEngine::MakeInboundRelayKey(const InboundPeerInfo& inbound_peer,
                                                              std::uint64_t hash_prefix)
{
    return InboundRelayKey{
        .hash_prefix = hash_prefix,
        .slot_index = inbound_peer.slot_index,
        .remote_session_id = inbound_peer.remote_session_id,
        .remote_peer_id = inbound_peer.remote_peer_id,
    };
}

bool RelayEngine::InboundRelayKeyLess(const InboundRelayKey& left, const InboundRelayKey& right)
{
    if (left.hash_prefix != right.hash_prefix) {
        return left.hash_prefix < right.hash_prefix;
    }
    if (left.slot_index != right.slot_index) {
        return left.slot_index < right.slot_index;
    }
    if (left.remote_session_id != right.remote_session_id) {
        return left.remote_session_id < right.remote_session_id;
    }
    return left.remote_peer_id < right.remote_peer_id;
}

RelayEngine::RelayEngine(const Clock& clock, RelayEngineConfig config)
    : m_clock(clock)
    , m_config(config)
{
    if (m_config.max_outbound_chunks_per_tick == 0) {
        m_config.max_outbound_chunks_per_tick = 64;
    }
    if (m_config.max_inbound_original_size == 0) {
        m_config.max_inbound_original_size = kDefaultMaxInboundOriginalSize;
    }
    if (m_config.max_inbound_entries == 0) {
        m_config.max_inbound_entries = kDefaultMaxInboundEntries;
    }
    if (m_config.max_inbound_buffered_chunks_per_entry == 0) {
        m_config.max_inbound_buffered_chunks_per_entry = kDefaultMaxInboundBufferedChunksPerEntry;
    }
    if (m_config.max_inbound_buffered_bytes == 0) {
        m_config.max_inbound_buffered_bytes = kDefaultMaxInboundBufferedBytes;
    }
    if (m_config.max_inbound_decoder_bytes_per_entry == 0) {
        m_config.max_inbound_decoder_bytes_per_entry = kDefaultMaxInboundDecoderBytesPerEntry;
    }
    if (m_config.max_inbound_age <= std::chrono::milliseconds::zero()) {
        m_config.max_inbound_age = kDefaultMaxInboundAge;
    }
}

void RelayEngine::OnNewBlock(const std::string& hash_hex, std::span<const std::uint8_t> block_data)
{
    const std::uint64_t hash_prefix = HashPrefixFromHex(hash_hex);
    if (IsKnown(hash_prefix)) {
        ++m_stats.blocks_already_known;
        return;
    }

    try {
        const fec::Parameters params = fec::Parameters::FromOverheadRatio(m_config.fec_overhead_ratio);
        fec::Encoder encoder(params);
        fec::EncodedBlock encoded = encoder.Encode(block_data);

        const fec::Parameters encoded_params = encoded.params;
        const std::size_t original_size = encoded.original_size;
        const std::uint16_t coding_group_count = encoded.coding_group_count;

        std::vector<fec::EncodedBlock> grouped;
        grouped.reserve(1);
        grouped.push_back(std::move(encoded));

        ChunkScheduler scheduler(std::move(grouped));
        m_outbound.emplace(hash_prefix,
                           encoded_params,
                           original_size,
                           coding_group_count,
                           std::move(scheduler));

        RememberSeen(hash_prefix);
        EraseInboundForPrefix(hash_prefix);
        ++m_stats.blocks_relayed_out;
    } catch (const std::exception& e) {
        LOG_WARN("relay OnNewBlock encode failure: " + std::string(e.what()));
    }
}

void RelayEngine::OnBlockHeader(const BlockHeaderPayload& payload, BlockSubmitter& submitter)
{
    OnBlockHeader(InboundPeerInfo{}, payload, submitter);
}

void RelayEngine::OnBlockHeader(const InboundPeerInfo& inbound_peer,
                                const BlockHeaderPayload& payload,
                                BlockSubmitter& submitter)
{
    const auto now = m_clock.Now();
    EvictExpiredInbound(now);

    if (IsKnown(payload.block_hash_prefix)) {
        ++m_stats.blocks_already_known;
        return;
    }
    if (payload.data_chunks < 2 || payload.data_chunks >= fec::FEC_TOTAL_CHUNKS) {
        return;
    }
    if (payload.original_size == 0) {
        ++m_stats.inbound_rejected;
        return;
    }
    if (payload.original_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return;
    }
    if (payload.original_size > static_cast<std::uint64_t>(m_config.max_inbound_original_size)) {
        ++m_stats.inbound_rejected;
        return;
    }

    fec::Parameters params{};
    try {
        params = fec::Parameters::FromDataChunkCount(payload.data_chunks);
    } catch (const std::exception&) {
        return;
    }

    const std::size_t original_size = static_cast<std::size_t>(payload.original_size);
    const std::size_t group_payload_bytes = static_cast<std::size_t>(params.data_chunks) * fec::FEC_CHUNK_SIZE;
    const std::size_t expected_group_count = original_size == 0 ? 0 : DivCeil(original_size, group_payload_bytes);
    if (expected_group_count > std::numeric_limits<std::uint16_t>::max() ||
        payload.coding_group_count != static_cast<std::uint16_t>(expected_group_count)) {
        ++m_stats.inbound_rejected;
        return;
    }

    const std::size_t decoder_bytes = DecoderBudgetBytes(params, expected_group_count, group_payload_bytes);
    if (decoder_bytes > m_config.max_inbound_decoder_bytes_per_entry) {
        ++m_stats.inbound_rejected;
        return;
    }

    const InboundRelayKey key = MakeInboundRelayKey(inbound_peer, payload.block_hash_prefix);
    InboundRelay* relay = GetOrCreateInbound(key, now);
    if (relay == nullptr) {
        ++m_stats.inbound_rejected;
        return;
    }

    if (relay->decoder.has_value()) {
        // Sender transmits redundant headers. Ignore duplicates after initialization
        // so already ingested chunks are not discarded by decoder re-creation.
        return;
    }
    relay->params = params;

    try {
        relay->decoder.emplace(params, static_cast<std::size_t>(payload.original_size));
    } catch (const std::exception&) {
        relay->decoder.reset();
        ++m_stats.inbound_rejected;
        EraseInbound(key);
        return;
    }

    for (const fec::Chunk& chunk : relay->buffered_chunks) {
        if (!relay->decoder->AddChunk(chunk)) {
            ++m_stats.inbound_rejected;
            EraseInbound(key);
            return;
        }
    }
    ClearBufferedChunks(*relay);

    TryFinalizeInbound(key, *relay, submitter);
}

void RelayEngine::OnBlockChunk(const BlockChunkPayload& payload, BlockSubmitter& submitter)
{
    OnBlockChunk(InboundPeerInfo{}, payload, submitter);
}

void RelayEngine::OnBlockChunk(const InboundPeerInfo& inbound_peer,
                               const BlockChunkPayload& payload,
                               BlockSubmitter& submitter)
{
    const auto now = m_clock.Now();
    EvictExpiredInbound(now);

    if (IsKnown(payload.block_hash_prefix)) {
        ++m_stats.blocks_already_known;
        return;
    }

    const InboundRelayKey key = MakeInboundRelayKey(inbound_peer, payload.block_hash_prefix);
    if (m_inbound.find(key) == m_inbound.end() && !HasGlobalInboundBufferCapacity()) {
        ++m_stats.inbound_rejected;
        return;
    }

    InboundRelay* relay = GetOrCreateInbound(key, now);
    if (relay == nullptr) {
        ++m_stats.inbound_rejected;
        return;
    }

    const bool relay_remains = FeedChunk(key, *relay, payload);
    ++m_stats.chunks_received;
    if (!relay_remains) {
        return;
    }

    TryFinalizeInbound(key, *relay, submitter);
}

void RelayEngine::PumpOutbound(PacketSink& sink, PeerManager& peer_manager)
{
    const auto now = m_clock.Now();
    EvictExpiredInbound(now);

    if (!m_outbound.has_value()) {
        return;
    }

    const std::vector<ActivePeerInfo> active_peers = peer_manager.GetActivePeers();
    if (active_peers.empty()) {
        return;
    }

    if (!m_outbound->header_sent) {
        BlockHeaderPayload header{};
        header.block_hash_prefix = m_outbound->hash_prefix;
        header.original_size = static_cast<std::uint64_t>(m_outbound->original_size);
        header.data_chunks = m_outbound->params.data_chunks;
        header.coding_group_count = m_outbound->coding_group_count;

        std::array<std::uint8_t, kPayloadSize> payload{};
        EncodeBlockHeaderPayload(header, payload);

        for (std::size_t repeat = 0; repeat < kHeaderRedundancy; ++repeat) {
            for (const ActivePeerInfo& peer : active_peers) {
                Packet packet = MakePacket(MessageType::kBlockHeader, peer_manager.ConsumeCounter(peer.slot_index));
                packet.payload = payload;
                AttachPacketMac(packet, peer.hmac_key, peer.local_session_id);

                std::string error;
                (void)sink.SendPacket(packet, peer.addr, peer.addr_len, &error);
            }
        }

        m_outbound->header_sent = true;
    }

    std::size_t sent_chunks = 0;
    while (sent_chunks < m_config.max_outbound_chunks_per_tick) {
        const auto next = m_outbound->scheduler.Next();
        if (!next.has_value()) {
            m_outbound.reset();
            break;
        }

        BlockChunkPayload chunk_payload{};
        chunk_payload.block_hash_prefix = m_outbound->hash_prefix;
        chunk_payload.coding_group_id = next->chunk.coding_group_id;
        chunk_payload.chunk_id = next->chunk.chunk_id;
        chunk_payload.flags = 0;
        chunk_payload.data_len = static_cast<std::uint16_t>(fec::FEC_CHUNK_SIZE);
        chunk_payload.chunk_data = next->chunk.bytes;

        std::array<std::uint8_t, kPayloadSize> payload{};
        EncodeBlockChunkPayload(chunk_payload, payload);

        for (const ActivePeerInfo& peer : active_peers) {
            Packet packet = MakePacket(MessageType::kBlockChunk, peer_manager.ConsumeCounter(peer.slot_index));
            packet.payload = payload;
            AttachPacketMac(packet, peer.hmac_key, peer.local_session_id);

            std::string error;
            if (sink.SendPacket(packet, peer.addr, peer.addr_len, &error)) {
                ++m_stats.chunks_sent;
            }
        }

        ++sent_chunks;
    }
}

void RelayEngine::RememberSeen(std::uint64_t hash_prefix)
{
    if (m_config.seen_blocks_capacity == 0) {
        return;
    }

    if (m_seen_set.count(hash_prefix) != 0) {
        const auto it = std::find(m_seen_order.begin(), m_seen_order.end(), hash_prefix);
        if (it != m_seen_order.end()) {
            m_seen_order.erase(it);
        }
        m_seen_order.push_back(hash_prefix);
        return;
    }

    while (m_seen_order.size() >= m_config.seen_blocks_capacity) {
        const std::uint64_t oldest = m_seen_order.front();
        m_seen_order.pop_front();
        m_seen_set.erase(oldest);
    }

    m_seen_order.push_back(hash_prefix);
    m_seen_set.insert(hash_prefix);
}

bool RelayEngine::IsKnown(std::uint64_t hash_prefix) const
{
    return m_seen_set.count(hash_prefix) != 0;
}

bool RelayEngine::HasGlobalInboundBufferCapacity() const
{
    return m_config.max_inbound_buffered_bytes >= fec::FEC_CHUNK_SIZE &&
           m_inbound_buffered_bytes <= m_config.max_inbound_buffered_bytes - fec::FEC_CHUNK_SIZE;
}

RelayEngine::InboundRelay* RelayEngine::GetOrCreateInbound(const InboundRelayKey& key, Clock::TimePoint now)
{
    auto it = m_inbound.find(key);
    if (it != m_inbound.end()) {
        it->second.last_updated = now;
        return &it->second;
    }

    while (m_inbound.size() >= m_config.max_inbound_entries) {
        if (!EvictOldestInbound()) {
            return nullptr;
        }
    }

    auto [inserted_it, inserted] = m_inbound.emplace(key, InboundRelay{});
    (void)inserted;
    inserted_it->second.first_seen = now;
    inserted_it->second.last_updated = now;
    return &inserted_it->second;
}

void RelayEngine::EvictExpiredInbound(Clock::TimePoint now)
{
    for (auto it = m_inbound.begin(); it != m_inbound.end();) {
        if (now - it->second.last_updated <= m_config.max_inbound_age) {
            ++it;
            continue;
        }

        ClearBufferedChunks(it->second);
        it = m_inbound.erase(it);
        ++m_stats.inbound_evictions;
    }
}

bool RelayEngine::EvictOldestInbound()
{
    if (m_inbound.empty()) {
        return false;
    }

    auto oldest = m_inbound.begin();
    for (auto it = m_inbound.begin(); it != m_inbound.end(); ++it) {
        if (it->second.first_seen < oldest->second.first_seen) {
            oldest = it;
            continue;
        }
        if (it->second.first_seen == oldest->second.first_seen && InboundRelayKeyLess(it->first, oldest->first)) {
            oldest = it;
        }
    }

    ClearBufferedChunks(oldest->second);
    m_inbound.erase(oldest);
    ++m_stats.inbound_evictions;
    return true;
}

void RelayEngine::EraseInbound(const InboundRelayKey& key)
{
    auto it = m_inbound.find(key);
    if (it == m_inbound.end()) {
        return;
    }

    ClearBufferedChunks(it->second);
    m_inbound.erase(it);
}

void RelayEngine::EraseInboundForPrefix(std::uint64_t hash_prefix)
{
    for (auto it = m_inbound.begin(); it != m_inbound.end();) {
        if (it->first.hash_prefix != hash_prefix) {
            ++it;
            continue;
        }

        ClearBufferedChunks(it->second);
        it = m_inbound.erase(it);
    }
}

void RelayEngine::ClearBufferedChunks(InboundRelay& relay)
{
    if (relay.buffered_bytes <= m_inbound_buffered_bytes) {
        m_inbound_buffered_bytes -= relay.buffered_bytes;
    } else {
        m_inbound_buffered_bytes = 0;
    }
    relay.buffered_bytes = 0;
    std::vector<fec::Chunk> empty;
    relay.buffered_chunks.swap(empty);
}

void RelayEngine::TryFinalizeInbound(const InboundRelayKey& key, InboundRelay& relay, BlockSubmitter& submitter)
{
    if (!relay.decoder.has_value() || !relay.decoder->IsComplete()) {
        return;
    }

    const auto reconstructed = relay.decoder->Reconstruct();
    if (!reconstructed.has_value()) {
        ++m_stats.submit_failures;
        EraseInbound(key);
        return;
    }

    if (submitter.SubmitBlock(*reconstructed)) {
        ++m_stats.submit_successes;
        ++m_stats.blocks_received_in;
        RememberSeen(key.hash_prefix);
        EraseInboundForPrefix(key.hash_prefix);
        return;
    } else {
        ++m_stats.submit_failures;
    }

    EraseInbound(key);
}

bool RelayEngine::FeedChunk(const InboundRelayKey& key, InboundRelay& relay, const BlockChunkPayload& payload)
{
    fec::Chunk chunk{};
    chunk.coding_group_id = payload.coding_group_id;
    chunk.chunk_id = payload.chunk_id;
    chunk.bytes = payload.chunk_data;

    if (!relay.decoder.has_value()) {
        if (relay.buffered_chunks.size() >= m_config.max_inbound_buffered_chunks_per_entry) {
            ++m_stats.inbound_rejected;
            return true;
        }
        if (!HasGlobalInboundBufferCapacity()) {
            ++m_stats.inbound_rejected;
            return true;
        }

        relay.buffered_chunks.push_back(std::move(chunk));
        relay.buffered_bytes += fec::FEC_CHUNK_SIZE;
        m_inbound_buffered_bytes += fec::FEC_CHUNK_SIZE;
        return true;
    }

    if (!relay.decoder->AddChunk(chunk)) {
        ++m_stats.inbound_rejected;
        EraseInbound(key);
        return false;
    }
    return true;
}

} // namespace photon
