#include <relay_engine.h>

#include <logging.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <limits>
#include <vector>

namespace photon {
namespace {

constexpr std::size_t kHeaderRedundancy = 3;
constexpr std::size_t kDefaultMaxInboundOriginalSize = 2'000'000;
constexpr std::size_t kDefaultMaxInboundEntries = 128;
constexpr std::size_t kDefaultMaxInboundEntriesPerPeer = 4;
constexpr std::size_t kDefaultMaxInboundBufferedChunksPerEntry = 64;
constexpr std::size_t kDefaultMaxInboundBufferedBytes = 1024 * fec::FEC_CHUNK_SIZE;
constexpr std::size_t kDefaultMaxInboundDecoderBytesPerEntry = 5 * 1024 * 1024;
constexpr std::size_t kDefaultMaxInboundDecoderBytesPerPeer = 10 * 1024 * 1024;
constexpr std::size_t kDefaultMaxInboundDecoderBytes = 64 * 1024 * 1024;
constexpr std::chrono::milliseconds kDefaultMaxInboundAge{std::chrono::minutes{2}};
constexpr std::chrono::milliseconds kDefaultInboundProgressGrace{std::chrono::seconds{10}};
constexpr std::uint32_t kDefaultPeerFaultThreshold = 8;
constexpr std::chrono::milliseconds kDefaultPeerFaultDecayInterval{std::chrono::seconds{60}};
constexpr std::chrono::milliseconds kDefaultPeerSuspendInitial{std::chrono::seconds{60}};
constexpr std::chrono::milliseconds kDefaultPeerSuspendMax{std::chrono::minutes{30}};

// Serialized block header: version (4), previous block hash (32), merkle root (32), time, bits, nonce.
constexpr std::size_t kBlockHeaderSize = 80;
constexpr std::size_t kPrevBlockHashOffset = 4;
constexpr std::size_t kBlockHashSize = 32;

template <typename T>
constexpr T DivCeil(T numerator, T denominator)
{
    return (numerator + denominator - 1) / denominator;
}

std::string ReversedHex(std::span<const std::uint8_t> bytes)
{
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        out.push_back(kHex[(*it >> 4) & 0x0F]);
        out.push_back(kHex[*it & 0x0F]);
    }
    return out;
}

bool Sha256(std::span<const std::uint8_t> data, std::array<std::uint8_t, kBlockHashSize>& out)
{
    unsigned int size = 0;
    return EVP_Digest(data.data(), data.size(), out.data(), &size, EVP_sha256(), nullptr) == 1 &&
           size == out.size();
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

std::optional<BlockHeaderSummary> ReadBlockHeaderSummary(std::span<const std::uint8_t> block_data)
{
    // A block holds at least its header and a transaction count.
    if (block_data.size() <= kBlockHeaderSize) {
        return std::nullopt;
    }

    const auto header = block_data.first(kBlockHeaderSize);
    std::array<std::uint8_t, kBlockHashSize> first{};
    std::array<std::uint8_t, kBlockHashSize> hash{};
    if (!Sha256(header, first) || !Sha256(first, hash)) {
        return std::nullopt;
    }

    return BlockHeaderSummary{
        .hash_hex = ReversedHex(hash),
        .prev_hash_hex = ReversedHex(header.subspan(kPrevBlockHashOffset, kBlockHashSize)),
    };
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
    if (m_config.max_inbound_entries_per_peer == 0) {
        m_config.max_inbound_entries_per_peer = kDefaultMaxInboundEntriesPerPeer;
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
    if (m_config.max_inbound_decoder_bytes_per_peer == 0) {
        m_config.max_inbound_decoder_bytes_per_peer = kDefaultMaxInboundDecoderBytesPerPeer;
    }
    if (m_config.max_inbound_decoder_bytes == 0) {
        m_config.max_inbound_decoder_bytes = kDefaultMaxInboundDecoderBytes;
    }
    if (m_config.max_inbound_age <= std::chrono::milliseconds::zero()) {
        m_config.max_inbound_age = kDefaultMaxInboundAge;
    }
    if (m_config.inbound_progress_grace <= std::chrono::milliseconds::zero()) {
        m_config.inbound_progress_grace = kDefaultInboundProgressGrace;
    }
    if (m_config.peer_fault_threshold == 0) {
        m_config.peer_fault_threshold = kDefaultPeerFaultThreshold;
    }
    if (m_config.peer_fault_decay_interval <= std::chrono::milliseconds::zero()) {
        m_config.peer_fault_decay_interval = kDefaultPeerFaultDecayInterval;
    }
    if (m_config.peer_suspend_initial <= std::chrono::milliseconds::zero()) {
        m_config.peer_suspend_initial = kDefaultPeerSuspendInitial;
    }
    if (m_config.peer_suspend_max < m_config.peer_suspend_initial) {
        m_config.peer_suspend_max = std::max(m_config.peer_suspend_initial, kDefaultPeerSuspendMax);
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
    const std::size_t slot = inbound_peer.slot_index;

    if (IsKnown(payload.block_hash_prefix)) {
        ++m_stats.blocks_already_known;
        return;
    }
    if (payload.data_chunks < 2 || payload.data_chunks >= fec::FEC_TOTAL_CHUNKS) {
        return;
    }
    if (payload.original_size == 0) {
        RejectInbound(slot);
        return;
    }
    if (payload.original_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return;
    }
    if (payload.original_size > static_cast<std::uint64_t>(m_config.max_inbound_original_size)) {
        RejectInbound(slot);
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
        RejectInbound(slot);
        return;
    }

    const std::size_t decoder_bytes = fec::Decoder::MemoryBytes(params, original_size);
    if (decoder_bytes > m_config.max_inbound_decoder_bytes_per_entry) {
        RejectInbound(slot);
        return;
    }
    if (IsSuspended(slot, now)) {
        RejectInbound(slot);
        return;
    }

    const InboundRelayKey key = MakeInboundRelayKey(inbound_peer, payload.block_hash_prefix);
    InboundRelay* relay = GetOrCreateInbound(key, now);
    if (relay == nullptr) {
        RejectInbound(slot);
        return;
    }

    if (relay->decoder.has_value()) {
        // Sender transmits redundant headers. Ignore duplicates after initialization
        // so already ingested chunks are not discarded by decoder re-creation.
        return;
    }

    if (!ReserveDecoderBytes(key, *relay, decoder_bytes, now)) {
        RejectInbound(slot);
        EraseInbound(key);
        return;
    }
    relay->params = params;

    try {
        relay->decoder.emplace(params, original_size);
    } catch (const std::exception&) {
        relay->decoder.reset();
        RejectInbound(slot);
        EraseInbound(key);
        return;
    }

    for (const fec::Chunk& chunk : relay->buffered_chunks) {
        if (!relay->decoder->AddChunk(chunk)) {
            RejectInbound(slot);
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
    if (m_inbound.find(key) == m_inbound.end() &&
        (IsSuspended(key.slot_index, now) || !HasGlobalInboundBufferCapacity())) {
        RejectInbound(key.slot_index);
        return;
    }

    InboundRelay* relay = GetOrCreateInbound(key, now);
    if (relay == nullptr) {
        RejectInbound(key.slot_index);
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

std::vector<PeerRelayStats> RelayEngine::PeerStatsSnapshot() const
{
    const auto now = m_clock.Now();
    std::vector<PeerRelayStats> out;
    out.reserve(m_peers.size());
    for (const auto& [slot_index, peer] : m_peers) {
        PeerInbound current = peer;
        DecayFaults(current, now);

        PeerRelayStats stats = peer.stats;
        stats.slot_index = slot_index;
        stats.fault_score = current.fault_score;
        stats.suspended = now < peer.suspended_until;
        stats.inbound_entries = peer.entries;
        stats.inbound_decoder_bytes = peer.decoder_bytes;
        out.push_back(stats);
    }
    return out;
}

RelayEngine::PeerInbound& RelayEngine::Peer(std::size_t slot_index)
{
    PeerInbound& peer = m_peers[slot_index];
    peer.stats.slot_index = slot_index;
    return peer;
}

void RelayEngine::RejectInbound(std::size_t slot_index)
{
    ++m_stats.inbound_rejected;
    ++Peer(slot_index).stats.inbound_rejected;
}

bool RelayEngine::IsSuspended(std::size_t slot_index, Clock::TimePoint now)
{
    const auto it = m_peers.find(slot_index);
    return it != m_peers.end() && now < it->second.suspended_until;
}

void RelayEngine::DecayFaults(PeerInbound& peer, Clock::TimePoint now) const
{
    if (peer.fault_score == 0) {
        peer.fault_decay_from = now;
        return;
    }
    if (now <= peer.fault_decay_from) {
        return;
    }

    const auto steps = (now - peer.fault_decay_from) / m_config.peer_fault_decay_interval;
    if (steps <= 0) {
        return;
    }
    if (static_cast<std::uint64_t>(steps) >= peer.fault_score) {
        peer.fault_score = 0;
        peer.fault_decay_from = now;
        return;
    }
    peer.fault_score -= static_cast<std::uint32_t>(steps);
    peer.fault_decay_from += steps * m_config.peer_fault_decay_interval;
}

void RelayEngine::RecordFault(std::size_t slot_index, Clock::TimePoint now)
{
    PeerInbound& peer = Peer(slot_index);
    DecayFaults(peer, now);
    ++peer.fault_score;
    if (peer.fault_score >= m_config.peer_fault_threshold) {
        SuspendPeer(slot_index, now);
    }
}

void RelayEngine::RecordAccepted(std::size_t slot_index, Clock::TimePoint now)
{
    PeerInbound& peer = Peer(slot_index);
    DecayFaults(peer, now);
    peer.fault_score -= std::min(peer.fault_score, m_config.peer_fault_success_credit);
    ++peer.stats.blocks_received_in;
}

void RelayEngine::SuspendPeer(std::size_t slot_index, Clock::TimePoint now)
{
    PeerInbound& peer = Peer(slot_index);

    // Start over from the initial pause once a full maximum pause has passed without another one.
    if (peer.ever_suspended && now - peer.suspended_until >= m_config.peer_suspend_max) {
        peer.suspension_level = 0;
    }

    std::chrono::milliseconds pause = m_config.peer_suspend_initial;
    for (std::uint32_t i = 0; i < peer.suspension_level && pause < m_config.peer_suspend_max; ++i) {
        pause *= 2;
    }
    pause = std::min(pause, m_config.peer_suspend_max);

    peer.suspended_until = now + pause;
    peer.ever_suspended = true;
    peer.suspension_level = std::min<std::uint32_t>(peer.suspension_level + 1, 32);
    peer.fault_score = 0;
    peer.fault_decay_from = now;
    ++peer.stats.suspensions;
    ++m_stats.peer_suspensions;

    LOG_WARN("relay refusing inbound blocks from peer slot " + std::to_string(slot_index) + " for "
             + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(pause).count())
             + "s after repeated blocks that could not be used");

    EraseInboundForSlot(slot_index);
}

RelayEngine::InboundRelay* RelayEngine::GetOrCreateInbound(const InboundRelayKey& key, Clock::TimePoint now)
{
    auto it = m_inbound.find(key);
    if (it != m_inbound.end()) {
        it->second.last_updated = now;
        return &it->second;
    }

    PeerInbound& peer = Peer(key.slot_index);
    while (peer.entries >= m_config.max_inbound_entries_per_peer) {
        if (!EvictOwnOldest(key.slot_index, nullptr, /*decoder_only=*/false)) {
            return nullptr;
        }
    }
    while (m_inbound.size() >= m_config.max_inbound_entries) {
        if (!EvictForGlobalLimit(key.slot_index, nullptr, /*decoder_only=*/false, now)) {
            return nullptr;
        }
    }

    auto [inserted_it, inserted] = m_inbound.emplace(key, InboundRelay{});
    (void)inserted;
    inserted_it->second.first_seen = now;
    inserted_it->second.last_updated = now;
    ++peer.entries;
    m_stats.inbound_entries = m_inbound.size();
    return &inserted_it->second;
}

bool RelayEngine::ReserveDecoderBytes(const InboundRelayKey& key,
                                      InboundRelay& relay,
                                      std::size_t bytes,
                                      Clock::TimePoint now)
{
    PeerInbound& peer = Peer(key.slot_index);
    while (peer.decoder_bytes + bytes > m_config.max_inbound_decoder_bytes_per_peer) {
        if (!EvictOwnOldest(key.slot_index, &key, /*decoder_only=*/true)) {
            return false;
        }
    }
    while (m_inbound_decoder_bytes + bytes > m_config.max_inbound_decoder_bytes) {
        if (!EvictForGlobalLimit(key.slot_index, &key, /*decoder_only=*/true, now)) {
            return false;
        }
    }

    relay.decoder_bytes = bytes;
    peer.decoder_bytes += bytes;
    m_inbound_decoder_bytes += bytes;
    m_stats.inbound_decoder_bytes = m_inbound_decoder_bytes;
    return true;
}

bool RelayEngine::EvictOwnOldest(std::size_t slot_index, const InboundRelayKey* keep, bool decoder_only)
{
    auto victim = m_inbound.end();
    for (auto it = m_inbound.begin(); it != m_inbound.end(); ++it) {
        if (it->first.slot_index != slot_index || (keep != nullptr && it->first == *keep) ||
            (decoder_only && it->second.decoder_bytes == 0)) {
            continue;
        }
        if (victim == m_inbound.end() || it->second.first_seen < victim->second.first_seen ||
            (it->second.first_seen == victim->second.first_seen && InboundRelayKeyLess(it->first, victim->first))) {
            victim = it;
        }
    }

    if (victim == m_inbound.end()) {
        return false;
    }
    EraseInboundAt(victim, /*evicted=*/true);
    return true;
}

bool RelayEngine::EvictForGlobalLimit(std::size_t slot_index,
                                      const InboundRelayKey* keep,
                                      bool decoder_only,
                                      Clock::TimePoint now)
{
    // The requesting peer gives up its own oldest block first.
    if (EvictOwnOldest(slot_index, keep, decoder_only)) {
        return true;
    }

    // Otherwise only another peer's block that has stopped making progress may be displaced.
    auto victim = m_inbound.end();
    for (auto it = m_inbound.begin(); it != m_inbound.end(); ++it) {
        if (it->first.slot_index == slot_index || now - it->second.last_updated <= m_config.inbound_progress_grace ||
            (decoder_only && it->second.decoder_bytes == 0)) {
            continue;
        }
        if (victim == m_inbound.end() || it->second.last_updated < victim->second.last_updated ||
            (it->second.last_updated == victim->second.last_updated && InboundRelayKeyLess(it->first, victim->first))) {
            victim = it;
        }
    }

    if (victim == m_inbound.end()) {
        return false;
    }
    EraseInboundAt(victim, /*evicted=*/true);
    return true;
}

void RelayEngine::EvictExpiredInbound(Clock::TimePoint now)
{
    for (auto it = m_inbound.begin(); it != m_inbound.end();) {
        if (now - it->second.last_updated <= m_config.max_inbound_age) {
            ++it;
            continue;
        }

        it = EraseInboundAt(it, /*evicted=*/true);
    }
}

RelayEngine::InboundMap::iterator RelayEngine::EraseInboundAt(InboundMap::iterator it, bool evicted)
{
    InboundRelay& relay = it->second;
    ClearBufferedChunks(relay);

    PeerInbound& peer = Peer(it->first.slot_index);
    peer.decoder_bytes -= std::min(peer.decoder_bytes, relay.decoder_bytes);
    m_inbound_decoder_bytes -= std::min(m_inbound_decoder_bytes, relay.decoder_bytes);
    relay.decoder_bytes = 0;
    if (peer.entries > 0) {
        --peer.entries;
    }
    if (evicted) {
        ++m_stats.inbound_evictions;
        ++peer.stats.inbound_evictions;
    }

    auto next = m_inbound.erase(it);
    m_stats.inbound_entries = m_inbound.size();
    m_stats.inbound_decoder_bytes = m_inbound_decoder_bytes;
    return next;
}

void RelayEngine::EraseInbound(const InboundRelayKey& key)
{
    auto it = m_inbound.find(key);
    if (it == m_inbound.end()) {
        return;
    }

    EraseInboundAt(it, /*evicted=*/false);
}

void RelayEngine::EraseInboundForPrefix(std::uint64_t hash_prefix)
{
    for (auto it = m_inbound.begin(); it != m_inbound.end();) {
        if (it->first.hash_prefix != hash_prefix) {
            ++it;
            continue;
        }

        it = EraseInboundAt(it, /*evicted=*/false);
    }
}

void RelayEngine::EraseInboundForSlot(std::size_t slot_index)
{
    for (auto it = m_inbound.begin(); it != m_inbound.end();) {
        if (it->first.slot_index != slot_index) {
            ++it;
            continue;
        }

        it = EraseInboundAt(it, /*evicted=*/false);
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

    const auto now = m_clock.Now();
    const std::size_t slot = key.slot_index;
    const auto reconstructed = relay.decoder->Reconstruct();

    // The decoder is no longer needed whatever happens next; release it before calling the node.
    EraseInbound(key);

    if (!reconstructed.has_value()) {
        ++m_stats.submit_failures;
        ++Peer(slot).stats.submit_failures;
        RecordFault(slot, now);
        return;
    }

    // The reconstructed block must be the block that was announced.
    const auto summary = ReadBlockHeaderSummary(*reconstructed);
    if (!summary.has_value() || HashPrefixFromHex(summary->hash_hex) != key.hash_prefix) {
        ++m_stats.blocks_mismatched;
        ++Peer(slot).stats.blocks_dropped;
        RecordFault(slot, now);
        return;
    }

    // It must also build on the node's best chain, at or close to its tip.
    const ParentCheck parent = submitter.CheckParent(summary->prev_hash_hex, m_config.max_parent_depth);
    if (parent == ParentCheck::kUnavailable) {
        // Nothing is known about the block, and the peer is not at fault.
        ++m_stats.block_checks_unavailable;
        return;
    }
    if (parent != ParentCheck::kNearTip) {
        ++m_stats.blocks_parent_rejected;
        ++Peer(slot).stats.blocks_dropped;
        RecordFault(slot, now);
        return;
    }

    const SubmitOutcome outcome = submitter.SubmitBlock(*reconstructed);
    if (outcome == SubmitOutcome::kAccepted) {
        ++m_stats.submit_successes;
        ++m_stats.blocks_received_in;
        RecordAccepted(slot, now);
        RememberSeen(key.hash_prefix);
        EraseInboundForPrefix(key.hash_prefix);
        return;
    }

    ++m_stats.submit_failures;
    ++Peer(slot).stats.submit_failures;
    switch (outcome) {
    case SubmitOutcome::kDuplicate:
        ++m_stats.submit_duplicates;
        break;
    case SubmitOutcome::kInconclusive:
        ++m_stats.submit_inconclusive;
        RecordFault(slot, now);
        break;
    case SubmitOutcome::kRejected:
        ++m_stats.submit_rejected;
        RecordFault(slot, now);
        break;
    case SubmitOutcome::kTimeout:
        ++m_stats.submit_timeouts;
        break;
    case SubmitOutcome::kError:
        ++m_stats.submit_errors;
        break;
    case SubmitOutcome::kAccepted:
        break;
    }
}

bool RelayEngine::FeedChunk(const InboundRelayKey& key, InboundRelay& relay, const BlockChunkPayload& payload)
{
    fec::Chunk chunk{};
    chunk.coding_group_id = payload.coding_group_id;
    chunk.chunk_id = payload.chunk_id;
    chunk.bytes = payload.chunk_data;

    if (!relay.decoder.has_value()) {
        if (relay.buffered_chunks.size() >= m_config.max_inbound_buffered_chunks_per_entry) {
            RejectInbound(key.slot_index);
            return true;
        }
        if (!HasGlobalInboundBufferCapacity()) {
            RejectInbound(key.slot_index);
            return true;
        }

        relay.buffered_chunks.push_back(std::move(chunk));
        relay.buffered_bytes += fec::FEC_CHUNK_SIZE;
        m_inbound_buffered_bytes += fec::FEC_CHUNK_SIZE;
        return true;
    }

    if (!relay.decoder->AddChunk(chunk)) {
        RejectInbound(key.slot_index);
        EraseInbound(key);
        return false;
    }
    return true;
}

} // namespace photon
