#ifndef QBIT_PHOTON_SRC_RELAY_ENGINE_H
#define QBIT_PHOTON_SRC_RELAY_ENGINE_H

#include <clock.h>
#include <fec.h>
#include <peer_manager.h>
#include <protocol.h>
#include <scheduler.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace photon {

struct RelayEngineConfig {
    double fec_overhead_ratio{1.2};
    std::size_t max_outbound_chunks_per_tick{64};
    std::size_t seen_blocks_capacity{16};
    std::size_t max_inbound_original_size{2'000'000};
    std::size_t max_inbound_entries{128};
    std::size_t max_inbound_buffered_chunks_per_entry{64};
    std::size_t max_inbound_buffered_bytes{1024 * fec::FEC_CHUNK_SIZE};
    std::size_t max_inbound_decoder_bytes_per_entry{3 * 1024 * 1024};
    std::chrono::milliseconds max_inbound_age{std::chrono::minutes{2}};
};

struct RelayStats {
    std::uint64_t blocks_relayed_out{0};
    std::uint64_t blocks_received_in{0};
    std::uint64_t blocks_already_known{0};
    std::uint64_t chunks_sent{0};
    std::uint64_t chunks_received{0};
    std::uint64_t submit_successes{0};
    std::uint64_t submit_failures{0};
    std::uint64_t inbound_rejected{0};
    std::uint64_t inbound_evictions{0};
};

class BlockSubmitter {
public:
    virtual ~BlockSubmitter() = default;
    virtual bool SubmitBlock(std::span<const std::uint8_t> block_data) = 0;
};

[[nodiscard]] std::uint64_t HashPrefixFromHex(const std::string& hash_hex);

class RelayEngine {
public:
    explicit RelayEngine(const Clock& clock, RelayEngineConfig config = {});

    void OnNewBlock(const std::string& hash_hex, std::span<const std::uint8_t> block_data);
    void OnBlockHeader(const BlockHeaderPayload& payload, BlockSubmitter& submitter);
    void OnBlockHeader(const InboundPeerInfo& inbound_peer,
                       const BlockHeaderPayload& payload,
                       BlockSubmitter& submitter);
    void OnBlockChunk(const BlockChunkPayload& payload, BlockSubmitter& submitter);
    void OnBlockChunk(const InboundPeerInfo& inbound_peer,
                      const BlockChunkPayload& payload,
                      BlockSubmitter& submitter);
    void PumpOutbound(PacketSink& sink, PeerManager& peer_manager);

    [[nodiscard]] const RelayStats& stats() const
    {
        return m_stats;
    }

    [[nodiscard]] bool HasOutbound() const
    {
        return m_outbound.has_value();
    }

private:
    struct OutboundRelay {
        OutboundRelay(std::uint64_t prefix,
                      fec::Parameters parameters,
                      std::size_t size,
                      std::uint16_t group_count,
                      ChunkScheduler schedule);

        std::uint64_t hash_prefix{0};
        fec::Parameters params{};
        std::size_t original_size{0};
        std::uint16_t coding_group_count{0};
        ChunkScheduler scheduler;
        bool header_sent{false};
    };

    struct InboundRelay {
        std::optional<fec::Parameters> params{};
        std::optional<fec::Decoder> decoder{};
        std::vector<fec::Chunk> buffered_chunks{};
        Clock::TimePoint first_seen{};
        Clock::TimePoint last_updated{};
        std::size_t buffered_bytes{0};
    };

    struct InboundRelayKey {
        std::uint64_t hash_prefix{0};
        std::size_t slot_index{0};
        std::uint64_t remote_session_id{0};
        std::uint64_t remote_peer_id{0};

        [[nodiscard]] bool operator==(const InboundRelayKey&) const = default;
    };

    struct InboundRelayKeyHash {
        [[nodiscard]] std::size_t operator()(const InboundRelayKey& key) const;
    };

    [[nodiscard]] static InboundRelayKey MakeInboundRelayKey(const InboundPeerInfo& inbound_peer,
                                                             std::uint64_t hash_prefix);
    [[nodiscard]] static bool InboundRelayKeyLess(const InboundRelayKey& left, const InboundRelayKey& right);

    void RememberSeen(std::uint64_t hash_prefix);
    [[nodiscard]] bool IsKnown(std::uint64_t hash_prefix) const;
    [[nodiscard]] bool HasGlobalInboundBufferCapacity() const;
    [[nodiscard]] InboundRelay* GetOrCreateInbound(const InboundRelayKey& key, Clock::TimePoint now);
    void EvictExpiredInbound(Clock::TimePoint now);
    [[nodiscard]] bool EvictOldestInbound();
    void EraseInbound(const InboundRelayKey& key);
    void EraseInboundForPrefix(std::uint64_t hash_prefix);
    void ClearBufferedChunks(InboundRelay& relay);
    void TryFinalizeInbound(const InboundRelayKey& key, InboundRelay& relay, BlockSubmitter& submitter);
    [[nodiscard]] bool FeedChunk(const InboundRelayKey& key, InboundRelay& relay, const BlockChunkPayload& payload);

    const Clock& m_clock;
    RelayEngineConfig m_config{};
    RelayStats m_stats{};

    std::optional<OutboundRelay> m_outbound{};
    std::unordered_map<InboundRelayKey, InboundRelay, InboundRelayKeyHash> m_inbound{};
    std::size_t m_inbound_buffered_bytes{0};

    std::deque<std::uint64_t> m_seen_order{};
    std::unordered_set<std::uint64_t> m_seen_set{};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_RELAY_ENGINE_H
