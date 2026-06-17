#ifndef QBIT_PHOTON_SRC_PEER_MANAGER_H
#define QBIT_PHOTON_SRC_PEER_MANAGER_H

#include <clock.h>
#include <config.h>
#include <protocol.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include <sys/socket.h>

namespace photon {

enum class PeerState {
    kDisconnected = 0,
    kConnecting,
    kActive,
    kStale,
};

// Exact bounded history. Retired identities age out one at a time after this
// limit, avoiding Bloom false positives and whole-filter reset windows.
inline constexpr std::size_t kRetiredRemoteIdentityHistoryLimit = 1024;

struct RetiredRemoteIdentity {
    std::uint64_t session_id{0};
    std::uint64_t peer_id{0};
};

struct PeerStats {
    std::uint64_t syn_sent{0};
    std::uint64_t syn_received{0};
    std::uint64_t synack_sent{0};
    std::uint64_t synack_received{0};
    std::uint64_t keepalive_sent{0};
    std::uint64_t keepalive_received{0};
    std::uint64_t pong_received{0};
    std::uint64_t disconnect_received{0};
    std::uint64_t packets_sent{0};
    std::uint64_t packets_received{0};
    std::uint64_t mac_failures{0};
    std::uint64_t replay_rejects{0};
    std::uint64_t session_replacements{0};
    std::uint64_t session_replacement_rejects{0};
    std::uint64_t resolve_failures{0};
};

struct PeerStateCounts {
    std::size_t disconnected{0};
    std::size_t connecting{0};
    std::size_t active{0};
    std::size_t stale{0};
};

struct PeerManagerStats {
    PeerStateCounts states{};
    PeerStats totals{};
};

struct PeerSlot {
    PeerConfig config{};
    PeerState state{PeerState::kDisconnected};
    PeerStats stats{};

    sockaddr_storage resolved_addr{};
    socklen_t resolved_addr_len{0};
    bool has_resolved_addr{false};

    std::uint32_t next_counter{1};
    std::uint64_t local_session_id{0};
    bool has_last_inbound_counter{false};
    std::uint32_t last_inbound_counter{0};
    bool require_next_inbound_counter_after_reset{false};
    bool has_remote_identity{false};
    std::uint64_t remote_session_id{0};
    std::uint64_t remote_peer_id{0};
    std::deque<RetiredRemoteIdentity> retired_remote_identities{};
    std::chrono::milliseconds reconnect_backoff{std::chrono::seconds(1)};

    Clock::TimePoint state_since{};
    Clock::TimePoint last_packet_received{};
    Clock::TimePoint last_syn_sent{};
    Clock::TimePoint last_keepalive_sent{};
    Clock::TimePoint next_connect_attempt{};
};

struct PeerManagerConfig {
    std::chrono::milliseconds connect_timeout{std::chrono::seconds(5)};
    std::chrono::milliseconds keepalive_interval{std::chrono::seconds(5)};
    std::chrono::milliseconds stale_timeout{std::chrono::seconds(15)};
    std::chrono::milliseconds initial_backoff{std::chrono::seconds(1)};
    std::chrono::milliseconds max_backoff{std::chrono::seconds(60)};
};

struct ActivePeerInfo {
    std::size_t slot_index{0};
    sockaddr_storage addr{};
    socklen_t addr_len{0};
    std::array<std::uint8_t, 32> hmac_key{};
    std::uint64_t local_session_id{0};
};

struct InboundPeerInfo {
    std::size_t slot_index{0};
    std::uint64_t remote_session_id{0};
    std::uint64_t remote_peer_id{0};
};

class PacketSink {
public:
    virtual ~PacketSink() = default;
    virtual bool SendPacket(const Packet& packet,
                            const sockaddr_storage& addr,
                            socklen_t addr_len,
                            std::string* error) = 0;
};

class PeerManager {
public:
    using ResolveEndpointFn = std::function<bool(const std::string& host,
                                                 std::uint16_t port,
                                                 sockaddr_storage* out_addr,
                                                 socklen_t* out_len,
                                                 std::string* error)>;

    PeerManager(std::vector<PeerConfig> peers,
                const Clock& clock,
                ResolveEndpointFn resolve_endpoint,
                PeerManagerConfig config = {});

    void Tick(PacketSink& sink);
    [[nodiscard]] bool HandleInbound(const Packet& packet, const sockaddr_storage& addr, socklen_t addr_len);
    [[nodiscard]] bool HandleInbound(const Packet& packet,
                                     const sockaddr_storage& addr,
                                     socklen_t addr_len,
                                     InboundPeerInfo* inbound_peer);
    [[nodiscard]] bool HandleInbound(const Packet& packet,
                                     const sockaddr_storage& addr,
                                     socklen_t addr_len,
                                     PacketSink& sink);
    [[nodiscard]] bool HandleInbound(const Packet& packet,
                                     const sockaddr_storage& addr,
                                     socklen_t addr_len,
                                     PacketSink& sink,
                                     InboundPeerInfo* inbound_peer);
    [[nodiscard]] std::vector<ActivePeerInfo> GetActivePeers() const;
    [[nodiscard]] std::size_t ActivePeerCount() const;
    [[nodiscard]] PeerManagerStats StatsSnapshot() const;
    [[nodiscard]] std::uint32_t ConsumeCounter(std::size_t slot_index);
    void SendDisconnectAll(PacketSink& sink);

    [[nodiscard]] const std::vector<PeerSlot>& slots() const
    {
        return m_slots;
    }

private:
    [[nodiscard]] bool HandleInbound(const Packet& packet,
                                     const sockaddr_storage& addr,
                                     socklen_t addr_len,
                                     PacketSink* sink,
                                     InboundPeerInfo* inbound_peer);
    [[nodiscard]] bool ResolvePeer(PeerSlot& slot);
    void EnsureLocalSession(PeerSlot& slot);
    [[nodiscard]] bool SendSignedControlMessage(PacketSink& sink,
                                                std::size_t slot_index,
                                                PeerSlot& slot,
                                                MessageType type,
                                                const std::array<std::uint8_t, kPayloadSize>& payload);
    [[nodiscard]] bool SendSynAck(PacketSink& sink, std::size_t slot_index, PeerSlot& slot);
    [[nodiscard]] std::size_t FindSlotByAddr(const sockaddr_storage& addr, socklen_t addr_len) const;
    [[nodiscard]] bool AcceptInboundReplayState(PeerSlot& slot, const Packet& packet);
    [[nodiscard]] bool IsRetiredRemoteIdentity(const PeerSlot& slot, const SynPayload& syn) const;
    void RetireRemoteIdentity(PeerSlot& slot);
    void ReplaceRemoteSession(PeerSlot& slot,
                              const SynPayload& syn,
                              std::uint32_t counter,
                              bool require_next_non_handshake);
    void TransitionToDisconnected(PeerSlot& slot, Clock::TimePoint now, bool increase_backoff);
    void TransitionToStale(PeerSlot& slot, Clock::TimePoint now);
    void TransitionToActive(PeerSlot& slot, Clock::TimePoint now);

    std::vector<PeerSlot> m_slots{};
    const Clock& m_clock;
    ResolveEndpointFn m_resolve_endpoint{};
    PeerManagerConfig m_config{};
    std::uint64_t m_local_peer_id{0};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_PEER_MANAGER_H
