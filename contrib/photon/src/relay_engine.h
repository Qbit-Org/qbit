#ifndef QBIT_PHOTON_SRC_RELAY_ENGINE_H
#define QBIT_PHOTON_SRC_RELAY_ENGINE_H

#include <clock.h>
#include <fec.h>
#include <log_rate_limiter.h>
#include <peer_manager.h>
#include <protocol.h>
#include <rpc_client.h>
#include <scheduler.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
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
    // Incomplete inbound blocks, in total and per peer slot.
    std::size_t max_inbound_entries{128};
    std::size_t max_inbound_entries_per_peer{4};
    std::size_t max_inbound_buffered_chunks_per_entry{64};
    std::size_t max_inbound_buffered_bytes{1024 * fec::FEC_CHUNK_SIZE};
    // Decoder memory as charged by fec::Decoder::MemoryBytes(): per block, per peer slot, in total.
    std::size_t max_inbound_decoder_bytes_per_entry{5 * 1024 * 1024};
    std::size_t max_inbound_decoder_bytes_per_peer{10 * 1024 * 1024};
    std::size_t max_inbound_decoder_bytes{64 * 1024 * 1024};
    std::chrono::milliseconds max_inbound_age{std::chrono::minutes{2}};
    // An incomplete block that received a packet within this window is never displaced by
    // another peer's block.
    std::chrono::milliseconds inbound_progress_grace{std::chrono::seconds{10}};
    // A reconstructed block is submitted only if its parent is within this many blocks of the
    // node's best block (see RpcClient::CheckParent).
    std::uint32_t max_parent_depth{6};
    // Per peer slot: each failed block adds one point, each accepted block removes
    // peer_fault_success_credit points, and one point decays every peer_fault_decay_interval.
    // Reaching peer_fault_threshold refuses the slot's inbound blocks for peer_suspend_initial,
    // doubling on each repeat up to peer_suspend_max.
    std::uint32_t peer_fault_threshold{8};
    std::uint32_t peer_fault_success_credit{2};
    std::chrono::milliseconds peer_fault_decay_interval{std::chrono::seconds{60}};
    std::chrono::milliseconds peer_suspend_initial{std::chrono::seconds{60}};
    std::chrono::milliseconds peer_suspend_max{std::chrono::minutes{30}};
};

struct RelayStats {
    std::uint64_t blocks_relayed_out{0};
    std::uint64_t blocks_received_in{0};
    std::uint64_t blocks_already_known{0};
    std::uint64_t chunks_sent{0};
    std::uint64_t chunks_received{0};
    std::uint64_t submit_successes{0};
    // Blocks handed to qbitd that it did not accept (the outcomes below), plus reconstructed
    // blocks that failed to decode.
    std::uint64_t submit_failures{0};
    std::uint64_t submit_duplicates{0};
    std::uint64_t submit_inconclusive{0};
    std::uint64_t submit_rejected{0};
    std::uint64_t submit_timeouts{0};
    std::uint64_t submit_errors{0};
    // Reconstructed blocks dropped before submission.
    std::uint64_t blocks_mismatched{0};
    std::uint64_t blocks_parent_rejected{0};
    std::uint64_t block_checks_unavailable{0};
    std::uint64_t blocks_node_behind{0};
    std::uint64_t inbound_rejected{0};
    std::uint64_t inbound_evictions{0};
    std::uint64_t peer_suspensions{0};
    // Current usage.
    std::uint64_t inbound_entries{0};
    std::uint64_t inbound_decoder_bytes{0};
};

struct PeerRelayStats {
    std::size_t slot_index{0};
    std::uint64_t blocks_received_in{0};
    std::uint64_t submit_failures{0};
    std::uint64_t blocks_dropped{0};
    std::uint64_t inbound_rejected{0};
    std::uint64_t inbound_evictions{0};
    std::uint64_t suspensions{0};
    std::uint32_t fault_score{0};
    bool suspended{false};
    std::uint64_t inbound_entries{0};
    std::uint64_t inbound_decoder_bytes{0};
};

class BlockSubmitter {
public:
    virtual ~BlockSubmitter() = default;
    virtual ParentCheck CheckParent(const std::string& block_hash_hex,
                                    const std::string& prev_hash_hex,
                                    std::uint32_t max_depth) = 0;
    virtual SubmitOutcome SubmitBlock(std::span<const std::uint8_t> block_data) = 0;
};

/// Identity of a serialized block, read from its 80-byte header.
struct BlockHeaderSummary {
    std::string hash_hex{};      ///< Display order, as the node prints it.
    std::string prev_hash_hex{}; ///< Display order.
};

/// Reads the header of a serialized block. Returns nullopt when the data is too short to be a block.
[[nodiscard]] std::optional<BlockHeaderSummary> ReadBlockHeaderSummary(std::span<const std::uint8_t> block_data);

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

    /// Per-slot counters for every slot that has sent inbound block traffic, ordered by slot.
    [[nodiscard]] std::vector<PeerRelayStats> PeerStatsSnapshot() const;

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
        std::size_t decoder_bytes{0};
    };

    struct InboundRelayKey {
        std::uint64_t hash_prefix{0};
        std::size_t slot_index{0};
        std::uint64_t remote_session_id{0};
        std::uint64_t remote_peer_id{0};

        [[nodiscard]] bool operator==(const InboundRelayKey&) const = default;
    };

    struct PeerInbound {
        std::size_t entries{0};
        std::size_t decoder_bytes{0};
        std::uint32_t fault_score{0};
        Clock::TimePoint fault_decay_from{};
        Clock::TimePoint suspended_until{};
        std::uint32_t suspension_level{0};
        PeerRelayStats stats{};
    };

    struct InboundRelayKeyHash {
        [[nodiscard]] std::size_t operator()(const InboundRelayKey& key) const;
    };

    [[nodiscard]] static InboundRelayKey MakeInboundRelayKey(const InboundPeerInfo& inbound_peer,
                                                             std::uint64_t hash_prefix);
    [[nodiscard]] static bool InboundRelayKeyLess(const InboundRelayKey& left, const InboundRelayKey& right);

    using InboundMap = std::unordered_map<InboundRelayKey, InboundRelay, InboundRelayKeyHash>;

    void RememberSeen(std::uint64_t hash_prefix);
    [[nodiscard]] bool IsKnown(std::uint64_t hash_prefix) const;
    [[nodiscard]] bool HasGlobalInboundBufferCapacity() const;
    [[nodiscard]] PeerInbound& Peer(std::size_t slot_index);
    void RejectInbound(std::size_t slot_index);
    [[nodiscard]] bool IsSuspended(std::size_t slot_index, Clock::TimePoint now);
    void DecayFaults(PeerInbound& peer, Clock::TimePoint now) const;
    void RecordFault(std::size_t slot_index, Clock::TimePoint now);
    void RecordAccepted(std::size_t slot_index, Clock::TimePoint now);
    void SuspendPeer(std::size_t slot_index, Clock::TimePoint now);
    [[nodiscard]] bool MakeRoom(const InboundRelayKey& key, bool new_entry, std::size_t decoder_bytes, Clock::TimePoint now);
    InboundRelay& CreateInbound(const InboundRelayKey& key, Clock::TimePoint now);
    void ChargeDecoder(const InboundRelayKey& key, InboundRelay& relay, std::size_t bytes);
    void MarkFinished(const InboundRelayKey& key, Clock::TimePoint now);
    [[nodiscard]] bool IsFinished(const InboundRelayKey& key, Clock::TimePoint now);
    void SettleInbound(std::uint64_t hash_prefix, Clock::TimePoint now);
    [[nodiscard]] bool IsSettled(std::uint64_t hash_prefix, Clock::TimePoint now);
    void LogUnusedBlock(Clock::TimePoint now, std::size_t slot_index, const std::string& block, const char* reason);
    void UpdateUsageStats();
    void EvictExpiredInbound(Clock::TimePoint now);
    InboundMap::iterator EraseInboundAt(InboundMap::iterator it, bool evicted);
    void EraseInbound(const InboundRelayKey& key);
    void EraseInboundForPrefix(std::uint64_t hash_prefix);
    void EraseInboundForSlot(std::size_t slot_index);
    void ClearBufferedChunks(InboundRelay& relay);
    void TryFinalizeInbound(const InboundRelayKey& key, InboundRelay& relay, BlockSubmitter& submitter);
    [[nodiscard]] bool FeedChunk(const InboundRelayKey& key, InboundRelay& relay, const BlockChunkPayload& payload);

    const Clock& m_clock;
    RelayEngineConfig m_config{};
    RelayStats m_stats{};

    std::optional<OutboundRelay> m_outbound{};
    InboundMap m_inbound{};
    std::size_t m_inbound_buffered_bytes{0};
    std::size_t m_inbound_decoder_bytes{0};
    std::map<std::size_t, PeerInbound> m_peers{};
    // One peer's blocks already handled or refused, so that the sender's remaining chunks do not
    // start a new incomplete block.
    std::deque<std::pair<InboundRelayKey, Clock::TimePoint>> m_finished_order{};
    std::unordered_set<InboundRelayKey, InboundRelayKeyHash> m_finished{};
    // Blocks the node has already answered for (other than accepting them), so that other peers'
    // copies are not decoded and sent to the node again. Unlike the seen set, this does not stop
    // the relay from sending the block on when its own node announces it.
    std::deque<std::pair<std::uint64_t, Clock::TimePoint>> m_settled_order{};
    std::unordered_set<std::uint64_t> m_settled{};
    LogRateLimiter m_unused_block_logs{std::chrono::seconds{60}};

    std::deque<std::uint64_t> m_seen_order{};
    std::unordered_set<std::uint64_t> m_seen_set{};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_RELAY_ENGINE_H
