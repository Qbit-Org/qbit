#include <relay_engine.h>

#include <logging.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <limits>
#include <type_traits>
#include <vector>

namespace photon {
namespace {

constexpr std::size_t kHeaderRedundancy = 3;
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

// The 16 hex digits of `hash_hex` from `offset` as a number, or 0 if any is not a hex digit.
std::uint64_t HexDigitsValue(const std::string& hash_hex, std::size_t offset)
{
    std::uint64_t value = 0;
    for (std::size_t i = offset; i < offset + 16; ++i) {
        std::uint8_t nibble = 0;
        if (!HexNibble(hash_hex[i], nibble)) {
            return 0;
        }
        value = (value << 4) | static_cast<std::uint64_t>(nibble);
    }
    return value;
}

} // namespace

std::uint64_t BlockIdFromHex(const std::string& hash_hex)
{
    if (hash_hex.size() != 2 * kBlockHashSize) {
        return 0;
    }
    const bool all_hex = std::all_of(hash_hex.begin(), hash_hex.end(), [](char ch) {
        std::uint8_t nibble = 0;
        return HexNibble(ch, nibble);
    });
    return all_hex ? HexDigitsValue(hash_hex, hash_hex.size() - 16) : 0;
}

std::uint64_t HashPrefixFromHex(const std::string& hash_hex)
{
    if (hash_hex.size() < 16) {
        return 0;
    }
    return HexDigitsValue(hash_hex, 0);
}

namespace {

// Whether `announced` identifies the block with hash `hash_hex`: in the form this version announces,
// or in the form earlier versions announced.
bool IdentifiesBlock(std::uint64_t announced, const std::string& hash_hex)
{
    return announced == BlockIdFromHex(hash_hex) || announced == HashPrefixFromHex(hash_hex);
}

} // namespace

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
    // Zero or negative settings fall back to the defaults.
    const RelayEngineConfig defaults{};
    const auto use_default_if_zero = [](auto& value, const auto& fallback) {
        if (value <= std::remove_reference_t<decltype(value)>{}) {
            value = fallback;
        }
    };
    use_default_if_zero(m_config.max_outbound_chunks_per_tick, defaults.max_outbound_chunks_per_tick);
    use_default_if_zero(m_config.max_inbound_original_size, defaults.max_inbound_original_size);
    use_default_if_zero(m_config.max_inbound_entries, defaults.max_inbound_entries);
    use_default_if_zero(m_config.max_inbound_entries_per_peer, defaults.max_inbound_entries_per_peer);
    use_default_if_zero(m_config.max_inbound_buffered_chunks_per_entry, defaults.max_inbound_buffered_chunks_per_entry);
    use_default_if_zero(m_config.max_inbound_buffered_bytes, defaults.max_inbound_buffered_bytes);
    use_default_if_zero(m_config.max_inbound_decoder_bytes_per_entry, defaults.max_inbound_decoder_bytes_per_entry);
    use_default_if_zero(m_config.max_inbound_decoder_bytes_per_peer, defaults.max_inbound_decoder_bytes_per_peer);
    use_default_if_zero(m_config.max_inbound_decoder_bytes, defaults.max_inbound_decoder_bytes);
    use_default_if_zero(m_config.max_inbound_age, defaults.max_inbound_age);
    use_default_if_zero(m_config.inbound_progress_grace, defaults.inbound_progress_grace);
    use_default_if_zero(m_config.peer_fault_threshold, defaults.peer_fault_threshold);
    use_default_if_zero(m_config.peer_fault_decay_interval, defaults.peer_fault_decay_interval);
    use_default_if_zero(m_config.peer_suspend_initial, defaults.peer_suspend_initial);
    use_default_if_zero(m_config.held_block_lifetime, defaults.held_block_lifetime);
    if (m_config.peer_suspend_max < m_config.peer_suspend_initial) {
        m_config.peer_suspend_max = std::max(m_config.peer_suspend_initial, defaults.peer_suspend_max);
    }
}

void RelayEngine::OnNewBlock(const std::string& hash_hex, std::span<const std::uint8_t> block_data)
{
    // qbitd announced a block, so it is answering.
    ++m_node_answers;

    const std::uint64_t block_id = BlockIdFromHex(hash_hex);
    if (IsKnown(block_id)) {
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
        m_outbound.emplace(block_id,
                           encoded_params,
                           original_size,
                           coding_group_count,
                           std::move(scheduler));

        RememberSeen(block_id);
        EraseInboundForPrefix(block_id);
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
    const InboundRelayKey key = MakeInboundRelayKey(inbound_peer, payload.block_hash_prefix);

    if (IsKnown(payload.block_hash_prefix) || IsHandled(key)) {
        ++m_stats.blocks_already_known;
        return;
    }

    auto existing = m_inbound.find(key);
    if (existing != m_inbound.end() && existing->second.decoder.has_value()) {
        // Sender transmits redundant headers. Ignore duplicates after initialization
        // so already ingested chunks are not discarded by decoder re-creation.
        return;
    }

    if (IsSuspended(slot, now)) {
        RejectInbound(slot);
        EraseInbound(key);
        return;
    }

    // A refused header also ends this block for this peer: its remaining chunks are ignored
    // rather than buffered for a decoder that will not come. A header that no honest sender
    // produces also counts against the peer.
    const auto refuse = [&](bool fault) {
        RejectInbound(slot);
        EraseInbound(key);
        MarkFinished(key, now);
        if (fault) {
            RecordFault(slot, now);
        }
    };

    if (payload.data_chunks < 2 || payload.data_chunks >= fec::FEC_TOTAL_CHUNKS || payload.original_size == 0 ||
        payload.original_size > static_cast<std::uint64_t>(m_config.max_inbound_original_size)) {
        refuse(/*fault=*/true);
        return;
    }

    fec::Parameters params{};
    try {
        params = fec::Parameters::FromDataChunkCount(payload.data_chunks);
    } catch (const std::exception&) {
        refuse(/*fault=*/true);
        return;
    }

    const std::size_t original_size = static_cast<std::size_t>(payload.original_size);
    const std::size_t group_payload_bytes = static_cast<std::size_t>(params.data_chunks) * fec::FEC_CHUNK_SIZE;
    const std::size_t expected_group_count = DivCeil(original_size, group_payload_bytes);
    if (expected_group_count > std::numeric_limits<std::uint16_t>::max() ||
        payload.coding_group_count != static_cast<std::uint16_t>(expected_group_count)) {
        refuse(/*fault=*/true);
        return;
    }

    const std::size_t decoder_bytes = fec::Decoder::MemoryBytes(params, original_size);
    if (decoder_bytes > m_config.max_inbound_decoder_bytes_per_entry) {
        refuse(/*fault=*/true);
        return;
    }

    // Chunks that arrived before the header must fit it, checked before anything is evicted.
    if (existing != m_inbound.end()) {
        for (const fec::Chunk& chunk : existing->second.buffered_chunks) {
            if (chunk.coding_group_id >= expected_group_count || chunk.chunk_id >= fec::FEC_TOTAL_CHUNKS) {
                refuse(/*fault=*/true);
                return;
            }
        }
    }

    if (!MakeRoom(key, /*new_entry=*/existing == m_inbound.end(), decoder_bytes, now)) {
        refuse(/*fault=*/false);
        return;
    }
    existing = m_inbound.find(key);
    InboundRelay& relay = existing != m_inbound.end() ? existing->second : CreateInbound(key, now);

    try {
        relay.decoder.emplace(params, original_size);
    } catch (const std::exception&) {
        relay.decoder.reset();
        refuse(/*fault=*/false);
        return;
    }
    relay.params = params;
    relay.last_updated = now;
    ChargeDecoder(key, relay, decoder_bytes);

    for (const fec::Chunk& chunk : relay.buffered_chunks) {
        if (!relay.decoder->AddChunk(chunk)) {
            refuse(/*fault=*/true);
            return;
        }
    }
    ClearBufferedChunks(relay);

    TryFinalizeInbound(key, relay, submitter);
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

    const InboundRelayKey key = MakeInboundRelayKey(inbound_peer, payload.block_hash_prefix);
    if (IsKnown(payload.block_hash_prefix) || IsHandled(key)) {
        ++m_stats.blocks_already_known;
        return;
    }

    auto it = m_inbound.find(key);
    if (it == m_inbound.end()) {
        if (IsSuspended(key.slot_index, now) || !HasGlobalInboundBufferCapacity() ||
            !MakeRoom(key, /*new_entry=*/true, /*decoder_bytes=*/0, now)) {
            RejectInbound(key.slot_index);
            return;
        }
        CreateInbound(key, now);
        it = m_inbound.find(key);
    }
    InboundRelay& relay = it->second;

    const bool relay_remains = FeedChunk(key, relay, payload);
    ++m_stats.chunks_received;
    if (!relay_remains) {
        return;
    }

    TryFinalizeInbound(key, relay, submitter);
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

void RelayEngine::RememberSeen(std::uint64_t block_id)
{
    if (m_config.seen_blocks_capacity == 0) {
        return;
    }

    if (m_seen_set.count(block_id) != 0) {
        const auto it = std::find(m_seen_order.begin(), m_seen_order.end(), block_id);
        if (it != m_seen_order.end()) {
            m_seen_order.erase(it);
        }
        m_seen_order.push_back(block_id);
        return;
    }

    while (m_seen_order.size() >= m_config.seen_blocks_capacity) {
        const std::uint64_t oldest = m_seen_order.front();
        m_seen_order.pop_front();
        m_seen_set.erase(oldest);
    }

    m_seen_order.push_back(block_id);
    m_seen_set.insert(block_id);
}

bool RelayEngine::IsKnown(std::uint64_t block_id) const
{
    return m_seen_set.count(block_id) != 0;
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
    ++peer.stats.faults;
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
    if (peer.stats.suspensions > 0 && now - peer.suspended_until >= m_config.peer_suspend_max) {
        peer.suspension_level = 0;
    }

    std::chrono::milliseconds pause = m_config.peer_suspend_initial;
    for (std::uint32_t i = 0; i < peer.suspension_level && pause < m_config.peer_suspend_max; ++i) {
        pause *= 2;
    }
    pause = std::min(pause, m_config.peer_suspend_max);

    peer.suspended_until = now + pause;
    peer.suspension_level = std::min<std::uint32_t>(peer.suspension_level + 1, 32);
    peer.fault_score = 0;
    peer.fault_decay_from = now;
    ++peer.stats.suspensions;
    ++m_stats.peer_suspensions;

    LOG_WARN("relay refusing inbound blocks from peer slot " + std::to_string(slot_index) + " for "
             + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(pause).count())
             + "s after repeated blocks that could not be used");

    EraseInboundForSlot(slot_index);
    if (m_held.has_value() && m_held->key.slot_index == slot_index) {
        DropHeldBlock(now, "dropped while waiting for qbitd: sender paused");
    }
}

bool RelayEngine::MakeRoom(const InboundRelayKey& key, bool new_entry, std::size_t decoder_bytes, Clock::TimePoint now)
{
    const PeerInbound& peer = Peer(key.slot_index);
    const auto excess = [](std::size_t used, std::size_t adding, std::size_t limit) {
        return used + adding > limit ? used + adding - limit : std::size_t{0};
    };
    const std::size_t adding_entries = new_entry ? 1 : 0;
    std::size_t own_entries = excess(peer.entries, adding_entries, m_config.max_inbound_entries_per_peer);
    std::size_t total_entries = excess(m_inbound.size(), adding_entries, m_config.max_inbound_entries);
    std::size_t own_bytes = excess(peer.decoder_bytes, decoder_bytes, m_config.max_inbound_decoder_bytes_per_peer);
    std::size_t total_bytes = excess(m_inbound_decoder_bytes, decoder_bytes, m_config.max_inbound_decoder_bytes);
    const auto satisfied = [&] { return own_entries == 0 && total_entries == 0 && own_bytes == 0 && total_bytes == 0; };
    if (satisfied()) {
        return true;
    }

    // The requesting peer gives up its own oldest blocks first; beyond that, only another peer's
    // block that has made no progress for the grace period may be displaced. Nothing is freed
    // unless every limit can be met.
    std::vector<InboundMap::iterator> own;
    std::vector<InboundMap::iterator> idle_others;
    for (auto it = m_inbound.begin(); it != m_inbound.end(); ++it) {
        if (it->first == key) {
            continue;
        }
        if (it->first.slot_index == key.slot_index) {
            own.push_back(it);
        } else if (now - it->second.last_updated > m_config.inbound_progress_grace) {
            idle_others.push_back(it);
        }
    }
    std::sort(own.begin(), own.end(), [](const auto& left, const auto& right) {
        if (left->second.first_seen != right->second.first_seen) {
            return left->second.first_seen < right->second.first_seen;
        }
        return InboundRelayKeyLess(left->first, right->first);
    });
    std::sort(idle_others.begin(), idle_others.end(), [](const auto& left, const auto& right) {
        if (left->second.last_updated != right->second.last_updated) {
            return left->second.last_updated < right->second.last_updated;
        }
        return InboundRelayKeyLess(left->first, right->first);
    });

    const auto reduce = [](std::size_t& remaining, std::size_t amount) { remaining -= std::min(remaining, amount); };
    std::vector<InboundMap::iterator> victims;
    for (const auto& it : own) {
        if (satisfied()) {
            break;
        }
        const std::size_t bytes = it->second.decoder_bytes;
        if (own_entries == 0 && total_entries == 0 && bytes == 0) {
            continue; // would not help the remaining byte limits
        }
        victims.push_back(it);
        reduce(own_entries, 1);
        reduce(total_entries, 1);
        reduce(own_bytes, bytes);
        reduce(total_bytes, bytes);
    }
    if (own_entries > 0 || own_bytes > 0) {
        return false;
    }
    for (const auto& it : idle_others) {
        if (total_entries == 0 && total_bytes == 0) {
            break;
        }
        const std::size_t bytes = it->second.decoder_bytes;
        if (total_entries == 0 && bytes == 0) {
            continue;
        }
        victims.push_back(it);
        reduce(total_entries, 1);
        reduce(total_bytes, bytes);
    }
    if (!satisfied()) {
        return false;
    }

    for (const auto& victim : victims) {
        EraseInboundAt(victim, /*evicted=*/true);
    }
    return true;
}

RelayEngine::InboundRelay& RelayEngine::CreateInbound(const InboundRelayKey& key, Clock::TimePoint now)
{
    auto [it, inserted] = m_inbound.emplace(key, InboundRelay{});
    if (inserted) {
        it->second.first_seen = now;
        it->second.last_updated = now;
        ++Peer(key.slot_index).entries;
        UpdateUsageStats();
    }
    return it->second;
}

void RelayEngine::ChargeDecoder(const InboundRelayKey& key, InboundRelay& relay, std::size_t bytes)
{
    relay.decoder_bytes = bytes;
    Peer(key.slot_index).decoder_bytes += bytes;
    m_inbound_decoder_bytes += bytes;
    UpdateUsageStats();
}

void RelayEngine::MarkFinished(const InboundRelayKey& key, Clock::TimePoint now)
{
    m_finished.Insert(key, now);
}

void RelayEngine::SettleInbound(std::uint64_t block_id, Clock::TimePoint now)
{
    EraseInboundForPrefix(block_id);
    m_settled.Insert(block_id, now);
}

bool RelayEngine::IsHandled(const InboundRelayKey& key) const
{
    return m_settled.Contains(key.hash_prefix) || IsHeld(key.hash_prefix) || m_finished.Contains(key);
}

void RelayEngine::LogUnusedBlock(Clock::TimePoint now, std::size_t slot_index, const std::string& block, const char* reason)
{
    // One limit per reason, so a frequent reason does not hide a rarer one.
    auto& limiter = m_unused_block_logs.try_emplace(reason, std::chrono::seconds{60}).first->second;
    if (const auto message = limiter.Record(
            now, "relay inbound block " + block + " from peer slot " + std::to_string(slot_index) + " not used: " + reason)) {
        LOG_WARN(*message);
    }
}

void RelayEngine::UpdateUsageStats()
{
    m_stats.inbound_entries = m_inbound.size();
    m_stats.inbound_decoder_bytes = m_inbound_decoder_bytes;
}

void RelayEngine::EvictExpiredInbound(Clock::TimePoint now)
{
    m_finished.Prune(now);
    m_settled.Prune(now);
    ExpireHeldBlock(now);

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
    UpdateUsageStats();
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

    const std::size_t slot = key.slot_index;
    auto reconstructed = relay.decoder->Reconstruct();

    // The decoder is no longer needed whatever happens next; release it before calling the node.
    // Whatever the outcome, the rest of this block's chunks from this peer are then ignored, timed
    // from when the node calls return (no packets are handled while they run).
    const auto finished_at = m_clock.Now();
    EraseInbound(key);
    struct FinishOnReturn {
        RelayEngine& engine;
        const InboundRelayKey& key;
        ~FinishOnReturn() { engine.MarkFinished(key, engine.m_clock.Now()); }
    } finish_on_return{*this, key};

    if (!reconstructed.has_value()) {
        ++m_stats.submit_failures;
        LogUnusedBlock(finished_at, slot, "(undecodable)", "decode failed");
        RecordFault(slot, finished_at);
        return;
    }

    // The reconstructed block must be the block that was announced, under either form of its
    // identifier. Only its 80-byte header is bound to the identifier; the rest is judged by the node.
    const auto summary = ReadBlockHeaderSummary(*reconstructed);
    if (!summary.has_value() || !IdentifiesBlock(key.hash_prefix, summary->hash_hex)) {
        ++m_stats.blocks_mismatched;
        LogUnusedBlock(finished_at, slot, summary.has_value() ? summary->hash_hex : "(no header)", "does not match its announced identifier");
        RecordFault(slot, finished_at);
        return;
    }

    CheckAndSubmit(key, std::move(*reconstructed), *summary, submitter, /*retry=*/false);
}

void RelayEngine::CheckAndSubmit(const InboundRelayKey& key,
                                 std::vector<std::uint8_t> block_data,
                                 const BlockHeaderSummary& summary,
                                 BlockSubmitter& submitter,
                                 bool retry)
{
    const std::size_t slot = key.slot_index;
    const auto& block = summary.hash_hex;

    // What is known about a block is keyed by the identifier taken from its hash, so a copy
    // announced under the other form is recognised here, once it is reconstructed.
    const std::uint64_t block_id = BlockIdFromHex(block);
    if (IsKnown(block_id) || m_settled.Contains(block_id) || IsHeld(block_id)) {
        ++m_stats.blocks_already_known;
        return;
    }
    if (retry) {
        ++m_stats.node_retries;
    }

    // It must also build on the node's best chain, at or close to its tip. Answers that depend
    // only on the header, or on the node not answering, hold for every copy of the block and
    // settle it; answers that may depend on this copy's body, or that the node may outgrow
    // within seconds, end only this peer's copy.
    const ParentCheck parent = submitter.CheckParent(block, summary.prev_hash_hex, m_config.max_parent_depth);
    const auto checked_at = m_clock.Now();
    if (parent != ParentCheck::kUnavailable) {
        ++m_node_answers;
    }
    bool parent_pending = false;
    switch (parent) {
    case ParentCheck::kNearTip:
        break;
    case ParentCheck::kParentNotConnected:
        // The node has the parent's header and connects this block right after the parent.
        ++m_stats.blocks_parent_pending;
        parent_pending = true;
        break;
    case ParentCheck::kAlreadyKnown:
        ++m_stats.blocks_already_known;
        SettleInbound(block_id, checked_at);
        return;
    case ParentCheck::kUnavailable:
        // Nothing is known about the block, and the peer is not at fault. This copy is held for one
        // more try once the node answers again, and other copies are not checked meanwhile.
        ++m_stats.block_checks_unavailable;
        if (retry) {
            LogUnusedBlock(checked_at, slot, block, "qbitd did not answer the parent check");
            SettleInbound(block_id, checked_at);
        } else {
            LogUnusedBlock(checked_at, slot, block, "qbitd did not answer the parent check (will try once more)");
            HoldBlock(key, block_id, summary, std::move(block_data), checked_at);
        }
        return;
    case ParentCheck::kNodeBehind:
        // The local node is far behind this block's chain; not the peer's fault.
        ++m_stats.blocks_node_behind;
        return;
    case ParentCheck::kTooFar:
        ++m_stats.blocks_parent_rejected;
        LogUnusedBlock(checked_at, slot, block, "too far from the best block");
        SettleInbound(block_id, checked_at);
        // A held block may have fallen behind while the node was not answering.
        if (!retry) {
            RecordFault(slot, checked_at);
        }
        return;
    case ParentCheck::kUnknown: {
        // The node may not have the parent yet (it may still be on its way over P2P), so one such
        // block per peer per decay interval is not the peer's fault; more than that is. Neither a
        // held block's retry, which may come late, nor a child of the held block is counted.
        ++m_stats.blocks_parent_unknown;
        LogUnusedBlock(checked_at, slot, block, "parent unknown to qbitd");
        PeerInbound& peer = Peer(slot);
        const bool parent_held = m_held.has_value() && m_held->summary.hash_hex == summary.prev_hash_hex;
        if (!retry && !parent_held) {
            if (peer.unknown_parent_allowed_at.has_value() &&
                checked_at - *peer.unknown_parent_allowed_at < m_config.peer_fault_decay_interval) {
                RecordFault(slot, checked_at);
            } else {
                peer.unknown_parent_allowed_at = checked_at;
            }
        }
        return;
    }
    }

    const SubmitOutcome outcome = submitter.SubmitBlock(block_data);
    const auto submitted_at = m_clock.Now();
    if (outcome != SubmitOutcome::kTimeout) {
        ++m_node_answers;
    }
    if (outcome == SubmitOutcome::kAccepted) {
        ++m_stats.submit_successes;
        ++m_stats.blocks_received_in;
        RecordAccepted(slot, submitted_at);
        RememberSeen(block_id);
        EraseInboundForPrefix(block_id);
        return;
    }

    ++m_stats.submit_failures;
    switch (outcome) {
    case SubmitOutcome::kDuplicate:
        // The node already holds this block, so other copies add nothing.
        ++m_stats.submit_duplicates;
        SettleInbound(block_id, submitted_at);
        break;
    case SubmitOutcome::kInconclusive:
        // Stored by the node (so this copy's body was sound): other copies add nothing. It counts
        // against the peer unless the node had yet to connect its parent, or the block was held
        // while the node was not answering (another block may have taken its place meanwhile).
        ++m_stats.submit_inconclusive;
        SettleInbound(block_id, submitted_at);
        if (!parent_pending && !retry) {
            RecordFault(slot, submitted_at);
        }
        break;
    case SubmitOutcome::kRejected:
        // May be this copy's body only: another peer's copy is still tried.
        ++m_stats.submit_rejected;
        LogUnusedBlock(submitted_at, slot, block, "rejected by qbitd");
        RecordFault(slot, submitted_at);
        break;
    case SubmitOutcome::kKnownInvalid:
        // Decided by the block hash alone: no copy of it will do.
        ++m_stats.submit_rejected;
        LogUnusedBlock(submitted_at, slot, block, "already marked invalid by qbitd");
        SettleInbound(block_id, submitted_at);
        RecordFault(slot, submitted_at);
        break;
    case SubmitOutcome::kTimeout:
        // The node may still store the block; the retry checks for that first.
        ++m_stats.submit_timeouts;
        if (retry) {
            LogUnusedBlock(submitted_at, slot, block, "no answer from qbitd to submitblock");
            SettleInbound(block_id, submitted_at);
        } else {
            LogUnusedBlock(submitted_at, slot, block, "no answer from qbitd to submitblock (will try once more)");
            HoldBlock(key, block_id, summary, std::move(block_data), submitted_at);
        }
        break;
    case SubmitOutcome::kError:
        ++m_stats.submit_errors;
        LogUnusedBlock(submitted_at, slot, block, "qbitd returned an error for submitblock");
        SettleInbound(block_id, submitted_at);
        break;
    case SubmitOutcome::kAccepted:
        break;
    }
}

void RelayEngine::HoldBlock(const InboundRelayKey& key,
                            std::uint64_t block_id,
                            const BlockHeaderSummary& summary,
                            std::vector<std::uint8_t> block_data,
                            Clock::TimePoint now)
{
    // One block at a time, at most max_inbound_original_size bytes. A newer block replaces an
    // older one, which is the likelier of the two to have reached the node another way.
    if (m_held.has_value()) {
        DropHeldBlock(now, "dropped while waiting for qbitd: replaced by a newer block");
    }
    // Other copies in progress are dropped now, and the rest of their chunks ignored; later copies
    // are ignored while this one is held.
    for (auto it = m_inbound.begin(); it != m_inbound.end();) {
        if (it->first.hash_prefix != block_id) {
            ++it;
            continue;
        }
        MarkFinished(it->first, now);
        it = EraseInboundAt(it, /*evicted=*/false);
    }
    m_held = HeldBlock{
        .key = key,
        .block_id = block_id,
        .summary = summary,
        .block = std::move(block_data),
        .held_at = now,
        .node_answers = m_node_answers,
    };
}

void RelayEngine::DropHeldBlock(Clock::TimePoint now, const char* reason)
{
    ++m_stats.held_blocks_dropped;
    LogUnusedBlock(now, m_held->key.slot_index, m_held->summary.hash_hex, reason);
    // As for any block the node did not answer for, other copies are not sent to it for a while.
    m_settled.Insert(m_held->block_id, now);
    m_held.reset();
}

void RelayEngine::ExpireHeldBlock(Clock::TimePoint now)
{
    if (m_held.has_value() && now - m_held->held_at > m_config.held_block_lifetime) {
        DropHeldBlock(now, "dropped while waiting for qbitd: qbitd did not answer in time");
    }
}

bool RelayEngine::IsHeld(std::uint64_t block_id) const
{
    return m_held.has_value() && m_held->block_id == block_id;
}

void RelayEngine::RetryHeldBlock(BlockSubmitter& submitter)
{
    ExpireHeldBlock(m_clock.Now());
    // Calling a node that is still not answering would only stall the relay again.
    if (!m_held.has_value() || m_held->node_answers == m_node_answers) {
        return;
    }

    HeldBlock held = std::move(*m_held);
    m_held.reset();
    CheckAndSubmit(held.key, std::move(held.block), held.summary, submitter, /*retry=*/true);
}

bool RelayEngine::FeedChunk(const InboundRelayKey& key, InboundRelay& relay, const BlockChunkPayload& payload)
{
    const auto now = m_clock.Now();
    fec::Chunk chunk{};
    chunk.coding_group_id = payload.coding_group_id;
    chunk.chunk_id = payload.chunk_id;
    chunk.bytes = payload.chunk_data;

    if (!relay.decoder.has_value()) {
        if (relay.buffered_chunks.size() >= m_config.max_inbound_buffered_chunks_per_entry) {
            RejectInbound(key.slot_index);
            return true;
        }
        const bool repeated = std::any_of(relay.buffered_chunks.begin(), relay.buffered_chunks.end(), [&chunk](const fec::Chunk& held) {
            return held.coding_group_id == chunk.coding_group_id && held.chunk_id == chunk.chunk_id;
        });
        if (repeated) {
            // Not progress, and nothing new to keep.
            return true;
        }
        if (!HasGlobalInboundBufferCapacity()) {
            RejectInbound(key.slot_index);
            return true;
        }

        relay.buffered_chunks.push_back(std::move(chunk));
        relay.buffered_bytes += fec::FEC_CHUNK_SIZE;
        m_inbound_buffered_bytes += fec::FEC_CHUNK_SIZE;
        relay.last_updated = now;
        return true;
    }

    const std::size_t received_before = relay.decoder->ReceivedChunkCount();
    if (!relay.decoder->AddChunk(chunk)) {
        // A chunk that does not fit the announced block: drop the block and count it against the peer.
        RejectInbound(key.slot_index);
        EraseInbound(key);
        MarkFinished(key, now);
        RecordFault(key.slot_index, now);
        return false;
    }
    // Only new chunks count as progress; repeats do not keep a block alive.
    if (relay.decoder->ReceivedChunkCount() != received_before) {
        relay.last_updated = now;
    }
    return true;
}

} // namespace photon
