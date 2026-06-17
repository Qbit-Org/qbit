#include <peer_manager.h>

#include <logging.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <string>

#include <netinet/in.h>
#include <openssl/rand.h>

namespace photon {
namespace {

bool ExtractIpv4Endpoint(const sockaddr_storage& addr,
                         socklen_t addr_len,
                         in_addr* out_addr,
                         in_port_t* out_port)
{
    if (out_addr == nullptr || out_port == nullptr) {
        return false;
    }

    if (addr.ss_family == AF_INET) {
        if (addr_len < static_cast<socklen_t>(sizeof(sockaddr_in))) {
            return false;
        }
        const auto* addr_in = reinterpret_cast<const sockaddr_in*>(&addr);
        *out_addr = addr_in->sin_addr;
        *out_port = addr_in->sin_port;
        return true;
    }

    if (addr.ss_family == AF_INET6) {
        if (addr_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
            return false;
        }

        const auto* addr_in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (!IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
            return false;
        }

        std::memcpy(&out_addr->s_addr, &addr_in6->sin6_addr.s6_addr[12], sizeof(out_addr->s_addr));
        *out_port = addr_in6->sin6_port;
        return true;
    }

    return false;
}

bool SockaddrEquals(const sockaddr_storage& left,
                    socklen_t left_len,
                    const sockaddr_storage& right,
                    socklen_t right_len)
{
    if (left.ss_family != right.ss_family) {
        in_addr left_v4{};
        in_addr right_v4{};
        in_port_t left_port = 0;
        in_port_t right_port = 0;
        if (ExtractIpv4Endpoint(left, left_len, &left_v4, &left_port)
            && ExtractIpv4Endpoint(right, right_len, &right_v4, &right_port)) {
            return left_port == right_port && left_v4.s_addr == right_v4.s_addr;
        }
        return false;
    }

    if (left.ss_family == AF_INET) {
        if (left_len < static_cast<socklen_t>(sizeof(sockaddr_in))
            || right_len < static_cast<socklen_t>(sizeof(sockaddr_in))) {
            return false;
        }

        const auto* left_in = reinterpret_cast<const sockaddr_in*>(&left);
        const auto* right_in = reinterpret_cast<const sockaddr_in*>(&right);
        return left_in->sin_port == right_in->sin_port
            && left_in->sin_addr.s_addr == right_in->sin_addr.s_addr;
    }

    if (left.ss_family == AF_INET6) {
        if (left_len < static_cast<socklen_t>(sizeof(sockaddr_in6))
            || right_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
            return false;
        }

        const auto* left_in6 = reinterpret_cast<const sockaddr_in6*>(&left);
        const auto* right_in6 = reinterpret_cast<const sockaddr_in6*>(&right);
        return left_in6->sin6_port == right_in6->sin6_port
            && left_in6->sin6_scope_id == right_in6->sin6_scope_id
            && std::memcmp(&left_in6->sin6_addr, &right_in6->sin6_addr, sizeof(in6_addr)) == 0;
    }

    return false;
}

std::uint32_t NextInboundCounter(std::uint32_t counter)
{
    if (counter == std::numeric_limits<std::uint32_t>::max()) {
        return 1;
    }
    return counter + 1;
}

constexpr std::uint64_t kMaxAcceptedInboundWrapGap = 1024;

bool IsForwardInboundCounter(std::uint32_t previous, std::uint32_t current)
{
    if (current == previous) {
        return false;
    }
    if (current > previous) {
        return true;
    }

    const auto wrap_gap = (static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) - previous)
        + current;
    // Preserve a small post-wrap acceptance window so UDP loss around the
    // 32-bit boundary does not stall the peer, while stale low counters far
    // from wrap still fail replay checks.
    return wrap_gap <= kMaxAcceptedInboundWrapGap;
}

std::chrono::milliseconds DoubleBackoff(std::chrono::milliseconds current, std::chrono::milliseconds maximum)
{
    if (current >= maximum) {
        return maximum;
    }

    const auto doubled = current * 2;
    return doubled > maximum ? maximum : doubled;
}

std::uint64_t Mix64(std::uint64_t value)
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

std::uint64_t GenerateNonZeroIdentity()
{
    std::uint64_t value = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) == 1 && value != 0) {
            return value;
        }
    }

    static std::atomic<std::uint64_t> fallback_counter{1};
    const auto counter = fallback_counter.fetch_add(1, std::memory_order_relaxed);
    const auto steady_now = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const auto system_now = static_cast<std::uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    const auto address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&value));
    value = Mix64(steady_now ^ (system_now << 1U) ^ (counter * 0x9e3779b97f4a7c15ULL) ^ address);
    if (value == 0) {
        value = counter;
    }
    if (value == 0) {
        value = 1;
    }
    return value;
}

bool HasNonZeroSynIdentity(const SynPayload& syn)
{
    return syn.session_id != 0 && syn.peer_id != 0;
}

bool SameRemoteIdentity(const PeerSlot& slot, const SynPayload& syn)
{
    return slot.has_remote_identity
        && syn.session_id == slot.remote_session_id
        && syn.peer_id == slot.remote_peer_id;
}

std::string PeerLogName(const PeerSlot& slot)
{
    if (!slot.config.name.empty()) {
        return slot.config.name;
    }
    return slot.config.host + ":" + std::to_string(slot.config.port);
}

const char* PeerStateName(PeerState state)
{
    switch (state) {
    case PeerState::kDisconnected:
        return "disconnected";
    case PeerState::kConnecting:
        return "connecting";
    case PeerState::kActive:
        return "active";
    case PeerState::kStale:
        return "stale";
    }
    return "unknown";
}

} // namespace

PeerManager::PeerManager(std::vector<PeerConfig> peers,
                         const Clock& clock,
                         ResolveEndpointFn resolve_endpoint,
                         PeerManagerConfig config)
    : m_clock(clock)
    , m_resolve_endpoint(std::move(resolve_endpoint))
    , m_config(config)
    , m_local_peer_id(GenerateNonZeroIdentity())
{
    if (m_config.initial_backoff <= std::chrono::milliseconds::zero()) {
        m_config.initial_backoff = std::chrono::seconds(1);
    }
    if (m_config.max_backoff < m_config.initial_backoff) {
        m_config.max_backoff = m_config.initial_backoff;
    }

    const auto now = m_clock.Now();
    m_slots.reserve(peers.size());

    for (PeerConfig& peer : peers) {
        PeerSlot slot{};
        slot.config = std::move(peer);
        slot.state = PeerState::kDisconnected;
        slot.reconnect_backoff = m_config.initial_backoff;
        slot.state_since = now;
        slot.last_packet_received = now;
        slot.last_syn_sent = now;
        slot.last_keepalive_sent = now;
        slot.next_connect_attempt = now;
        m_slots.push_back(std::move(slot));
    }
}

void PeerManager::Tick(PacketSink& sink)
{
    const auto now = m_clock.Now();
    std::array<std::uint8_t, kPayloadSize> empty_payload{};

    for (std::size_t i = 0; i < m_slots.size(); ++i) {
        PeerSlot& slot = m_slots[i];

        switch (slot.state) {
        case PeerState::kDisconnected: {
            if (now < slot.next_connect_attempt) {
                break;
            }

            if (!ResolvePeer(slot)) {
                ++slot.stats.resolve_failures;
                TransitionToDisconnected(slot, now, true);
                break;
            }

            EnsureLocalSession(slot);

            SynPayload syn{};
            syn.session_id = slot.local_session_id;
            syn.peer_id = m_local_peer_id;
            std::array<std::uint8_t, kPayloadSize> syn_payload{};
            EncodeSynPayload(syn, syn_payload);

            if (!SendSignedControlMessage(sink, i, slot, MessageType::kSyn, syn_payload)) {
                TransitionToDisconnected(slot, now, true);
                break;
            }

            ++slot.stats.syn_sent;
            slot.state = PeerState::kConnecting;
            slot.state_since = now;
            slot.last_syn_sent = now;
            break;
        }
        case PeerState::kConnecting: {
            if (now - slot.state_since >= m_config.connect_timeout) {
                TransitionToDisconnected(slot, now, true);
            }
            break;
        }
        case PeerState::kActive: {
            if (now - slot.last_packet_received >= m_config.stale_timeout) {
                TransitionToStale(slot, now);
                break;
            }

            if (now - slot.last_keepalive_sent >= m_config.keepalive_interval) {
                if (SendSignedControlMessage(sink, i, slot, MessageType::kKeepalive, empty_payload)) {
                    ++slot.stats.keepalive_sent;
                    slot.last_keepalive_sent = now;
                }
            }
            break;
        }
        case PeerState::kStale: {
            if (now - slot.state_since >= m_config.connect_timeout) {
                TransitionToDisconnected(slot, now, true);
                break;
            }

            if (now - slot.last_keepalive_sent >= m_config.keepalive_interval) {
                if (SendSignedControlMessage(sink, i, slot, MessageType::kKeepalive, empty_payload)) {
                    ++slot.stats.keepalive_sent;
                    slot.last_keepalive_sent = now;
                }
            }
            break;
        }
        }
    }
}

bool PeerManager::HandleInbound(const Packet& packet, const sockaddr_storage& addr, socklen_t addr_len)
{
    return HandleInbound(packet, addr, addr_len, static_cast<PacketSink*>(nullptr), nullptr);
}

bool PeerManager::HandleInbound(const Packet& packet,
                                const sockaddr_storage& addr,
                                socklen_t addr_len,
                                InboundPeerInfo* inbound_peer)
{
    return HandleInbound(packet, addr, addr_len, static_cast<PacketSink*>(nullptr), inbound_peer);
}

bool PeerManager::HandleInbound(const Packet& packet,
                                const sockaddr_storage& addr,
                                socklen_t addr_len,
                                PacketSink& sink)
{
    return HandleInbound(packet, addr, addr_len, &sink, nullptr);
}

bool PeerManager::HandleInbound(const Packet& packet,
                                const sockaddr_storage& addr,
                                socklen_t addr_len,
                                PacketSink& sink,
                                InboundPeerInfo* inbound_peer)
{
    return HandleInbound(packet, addr, addr_len, &sink, inbound_peer);
}

bool PeerManager::HandleInbound(const Packet& packet,
                                const sockaddr_storage& addr,
                                socklen_t addr_len,
                                PacketSink* sink,
                                InboundPeerInfo* inbound_peer)
{
    if (inbound_peer != nullptr) {
        *inbound_peer = {};
    }

    std::size_t slot_index = FindSlotByAddr(addr, addr_len);
    if (slot_index == m_slots.size()) {
        for (std::size_t i = 0; i < m_slots.size(); ++i) {
            PeerSlot& candidate = m_slots[i];
            if (candidate.has_resolved_addr) {
                continue;
            }
            if (!ResolvePeer(candidate)) {
                continue;
            }
            if (SockaddrEquals(candidate.resolved_addr, candidate.resolved_addr_len, addr, addr_len)) {
                slot_index = i;
                break;
            }
        }
    }

    if (slot_index == m_slots.size()) {
        return false;
    }

    PeerSlot& slot = m_slots[slot_index];
    if (packet.msg_type == MessageType::kSyn && slot.local_session_id == 0) {
        EnsureLocalSession(slot);
    } else if (IsHandshakeMessage(packet.msg_type) && slot.local_session_id == 0) {
        return false;
    }

    const auto bytes = SerializePacket(packet);
    if (IsHandshakeMessage(packet.msg_type)) {
        if (!VerifyPacketMac(bytes, slot.config.hmac_key)) {
            ++slot.stats.mac_failures;
            return false;
        }
    } else {
        if ((slot.state != PeerState::kActive && slot.state != PeerState::kStale)
            || !slot.has_remote_identity || slot.remote_session_id == 0) {
            return false;
        }
        if (!VerifyPacketMac(bytes, slot.config.hmac_key, slot.remote_session_id)) {
            ++slot.stats.mac_failures;
            return false;
        }
    }

    if (!AcceptInboundReplayState(slot, packet)) {
        return false;
    }

    const auto now = m_clock.Now();
    slot.last_packet_received = now;
    ++slot.stats.packets_received;

    switch (packet.msg_type) {
    case MessageType::kSyn:
        ++slot.stats.syn_received;
        TransitionToActive(slot, now);
        if (sink != nullptr) {
            (void)SendSynAck(*sink, slot_index, slot);
        }
        break;
    case MessageType::kSynAck:
        ++slot.stats.synack_received;
        TransitionToActive(slot, now);
        break;
    case MessageType::kKeepalive:
        ++slot.stats.keepalive_received;
        TransitionToActive(slot, now);
        break;
    case MessageType::kPong:
        ++slot.stats.pong_received;
        TransitionToActive(slot, now);
        break;
    case MessageType::kDisconnect:
        ++slot.stats.disconnect_received;
        slot.reconnect_backoff = m_config.initial_backoff;
        TransitionToDisconnected(slot, now, false);
        break;
    case MessageType::kBlockHeader:
    case MessageType::kBlockChunk:
    case MessageType::kPing:
        if (slot.state == PeerState::kConnecting || slot.state == PeerState::kStale) {
            TransitionToActive(slot, now);
        }
        break;
    }

    if (inbound_peer != nullptr && slot.has_remote_identity) {
        inbound_peer->slot_index = slot_index;
        inbound_peer->remote_session_id = slot.remote_session_id;
        inbound_peer->remote_peer_id = slot.remote_peer_id;
    }

    return true;
}

std::vector<ActivePeerInfo> PeerManager::GetActivePeers() const
{
    std::vector<ActivePeerInfo> active;
    active.reserve(m_slots.size());

    for (std::size_t i = 0; i < m_slots.size(); ++i) {
        const PeerSlot& slot = m_slots[i];
        if (slot.state != PeerState::kActive || !slot.has_resolved_addr || slot.local_session_id == 0) {
            continue;
        }

        ActivePeerInfo info{};
        info.slot_index = i;
        info.addr = slot.resolved_addr;
        info.addr_len = slot.resolved_addr_len;
        info.hmac_key = slot.config.hmac_key;
        info.local_session_id = slot.local_session_id;
        active.push_back(info);
    }

    return active;
}

std::size_t PeerManager::ActivePeerCount() const
{
    std::size_t count = 0;
    for (const PeerSlot& slot : m_slots) {
        if (slot.state == PeerState::kActive) {
            ++count;
        }
    }
    return count;
}

PeerManagerStats PeerManager::StatsSnapshot() const
{
    PeerManagerStats snapshot{};

    for (const PeerSlot& slot : m_slots) {
        switch (slot.state) {
        case PeerState::kDisconnected:
            ++snapshot.states.disconnected;
            break;
        case PeerState::kConnecting:
            ++snapshot.states.connecting;
            break;
        case PeerState::kActive:
            ++snapshot.states.active;
            break;
        case PeerState::kStale:
            ++snapshot.states.stale;
            break;
        }

        snapshot.totals.syn_sent += slot.stats.syn_sent;
        snapshot.totals.syn_received += slot.stats.syn_received;
        snapshot.totals.synack_sent += slot.stats.synack_sent;
        snapshot.totals.synack_received += slot.stats.synack_received;
        snapshot.totals.keepalive_sent += slot.stats.keepalive_sent;
        snapshot.totals.keepalive_received += slot.stats.keepalive_received;
        snapshot.totals.pong_received += slot.stats.pong_received;
        snapshot.totals.disconnect_received += slot.stats.disconnect_received;
        snapshot.totals.packets_sent += slot.stats.packets_sent;
        snapshot.totals.packets_received += slot.stats.packets_received;
        snapshot.totals.mac_failures += slot.stats.mac_failures;
        snapshot.totals.replay_rejects += slot.stats.replay_rejects;
        snapshot.totals.session_replacements += slot.stats.session_replacements;
        snapshot.totals.session_replacement_rejects += slot.stats.session_replacement_rejects;
        snapshot.totals.resolve_failures += slot.stats.resolve_failures;
    }

    return snapshot;
}

std::uint32_t PeerManager::ConsumeCounter(std::size_t slot_index)
{
    if (slot_index >= m_slots.size()) {
        return 0;
    }

    PeerSlot& slot = m_slots[slot_index];
    const std::uint32_t current = slot.next_counter;
    ++slot.next_counter;
    if (slot.next_counter == 0) {
        slot.next_counter = 1;
    }
    return current;
}

void PeerManager::SendDisconnectAll(PacketSink& sink)
{
    const auto now = m_clock.Now();
    std::array<std::uint8_t, kPayloadSize> payload{};

    for (std::size_t i = 0; i < m_slots.size(); ++i) {
        PeerSlot& slot = m_slots[i];
        if (!slot.has_resolved_addr || slot.state == PeerState::kDisconnected) {
            continue;
        }

        (void)SendSignedControlMessage(sink, i, slot, MessageType::kDisconnect, payload);
        slot.reconnect_backoff = m_config.initial_backoff;
        TransitionToDisconnected(slot, now, false);
    }
}

bool PeerManager::ResolvePeer(PeerSlot& slot)
{
    if (!m_resolve_endpoint) {
        return false;
    }

    sockaddr_storage resolved{};
    socklen_t resolved_len = 0;
    std::string error;
    if (!m_resolve_endpoint(slot.config.host, slot.config.port, &resolved, &resolved_len, &error)) {
        return false;
    }

    slot.resolved_addr = resolved;
    slot.resolved_addr_len = resolved_len;
    slot.has_resolved_addr = true;
    return true;
}

void PeerManager::EnsureLocalSession(PeerSlot& slot)
{
    if (slot.local_session_id == 0) {
        slot.local_session_id = GenerateNonZeroIdentity();
    }
}

bool PeerManager::SendSignedControlMessage(PacketSink& sink,
                                           std::size_t slot_index,
                                           PeerSlot& slot,
                                           MessageType type,
                                           const std::array<std::uint8_t, kPayloadSize>& payload)
{
    if (!slot.has_resolved_addr) {
        return false;
    }

    Packet packet = MakePacket(type, ConsumeCounter(slot_index));
    packet.payload = payload;
    if (IsHandshakeMessage(type)) {
        AttachPacketMac(packet, slot.config.hmac_key);
    } else {
        if (slot.local_session_id == 0) {
            return false;
        }
        AttachPacketMac(packet, slot.config.hmac_key, slot.local_session_id);
    }

    std::string error;
    const bool ok = sink.SendPacket(packet, slot.resolved_addr, slot.resolved_addr_len, &error);
    if (ok) {
        ++slot.stats.packets_sent;
    }
    return ok;
}

bool PeerManager::SendSynAck(PacketSink& sink, std::size_t slot_index, PeerSlot& slot)
{
    EnsureLocalSession(slot);

    SynPayload syn{};
    syn.session_id = slot.local_session_id;
    syn.peer_id = m_local_peer_id;

    std::array<std::uint8_t, kPayloadSize> payload{};
    EncodeSynPayload(syn, payload);

    if (!SendSignedControlMessage(sink, slot_index, slot, MessageType::kSynAck, payload)) {
        return false;
    }

    ++slot.stats.synack_sent;
    return true;
}

std::size_t PeerManager::FindSlotByAddr(const sockaddr_storage& addr, socklen_t addr_len) const
{
    for (std::size_t i = 0; i < m_slots.size(); ++i) {
        const PeerSlot& slot = m_slots[i];
        if (!slot.has_resolved_addr) {
            continue;
        }

        if (SockaddrEquals(slot.resolved_addr, slot.resolved_addr_len, addr, addr_len)) {
            return i;
        }
    }

    return m_slots.size();
}

bool PeerManager::AcceptInboundReplayState(PeerSlot& slot, const Packet& packet)
{
    if (packet.counter == 0) {
        ++slot.stats.replay_rejects;
        return false;
    }

    SynPayload syn{};
    bool has_syn_payload = false;
    if (packet.msg_type == MessageType::kSyn || packet.msg_type == MessageType::kSynAck) {
        if (!DecodeSynPayload(packet.payload, syn)) {
            return false;
        }
        if (!HasNonZeroSynIdentity(syn)) {
            return false;
        }
        has_syn_payload = true;
        if (IsRetiredRemoteIdentity(slot, syn)) {
            ++slot.stats.session_replacement_rejects;
            LOG_WARN("peer " + PeerLogName(slot)
                     + " rejected handshake for retired remote session_id=" + std::to_string(syn.session_id)
                     + " peer_id=" + std::to_string(syn.peer_id));
            return false;
        }
        if (slot.has_remote_identity && !SameRemoteIdentity(slot, syn)) {
            if (packet.msg_type == MessageType::kSyn || slot.state == PeerState::kConnecting) {
                ReplaceRemoteSession(slot, syn, packet.counter, true);
                return true;
            }

            ++slot.stats.session_replacement_rejects;
            LOG_WARN("peer " + PeerLogName(slot)
                     + " rejected changed "
                     + (packet.msg_type == MessageType::kSynAck ? std::string{"SynAck"} : std::string{"handshake"})
                     + " remote_session_id=" + std::to_string(syn.session_id)
                     + " remote_peer_id=" + std::to_string(syn.peer_id)
                     + " current_state=" + PeerStateName(slot.state));
            return false;
        }
    }

    bool clear_next_counter_requirement = false;
    bool is_next_inbound_counter = false;
    if (slot.has_last_inbound_counter) {
        is_next_inbound_counter = packet.counter == NextInboundCounter(slot.last_inbound_counter);
        if (!IsForwardInboundCounter(slot.last_inbound_counter, packet.counter)) {
            ++slot.stats.replay_rejects;
            return false;
        }
    }

    // Non-handshake packets are session-bound by MAC context. After accepting
    // a counter-reset session, also require the first such packet to continue
    // the new counter baseline, then return to monotonic acceptance for UDP loss.
    if (!has_syn_payload && slot.require_next_inbound_counter_after_reset && slot.has_last_inbound_counter) {
        if (!is_next_inbound_counter) {
            ++slot.stats.replay_rejects;
            return false;
        }
        clear_next_counter_requirement = true;
    }

    if (has_syn_payload && !slot.has_remote_identity) {
        ReplaceRemoteSession(slot, syn, packet.counter, false);
    }

    slot.last_inbound_counter = packet.counter;
    slot.has_last_inbound_counter = true;
    if (clear_next_counter_requirement) {
        slot.require_next_inbound_counter_after_reset = false;
    }
    return true;
}

bool PeerManager::IsRetiredRemoteIdentity(const PeerSlot& slot, const SynPayload& syn) const
{
    for (const RetiredRemoteIdentity& retired : slot.retired_remote_identities) {
        if (retired.session_id == syn.session_id && retired.peer_id == syn.peer_id) {
            return true;
        }
    }
    return false;
}

void PeerManager::RetireRemoteIdentity(PeerSlot& slot)
{
    if (!slot.has_remote_identity || slot.remote_session_id == 0 || slot.remote_peer_id == 0) {
        return;
    }

    const RetiredRemoteIdentity retired{slot.remote_session_id, slot.remote_peer_id};
    const auto already_retired = std::any_of(
        slot.retired_remote_identities.begin(),
        slot.retired_remote_identities.end(),
        [&](const RetiredRemoteIdentity& entry) {
            return entry.session_id == retired.session_id && entry.peer_id == retired.peer_id;
        });
    if (already_retired) {
        return;
    }

    if (slot.retired_remote_identities.size() >= kRetiredRemoteIdentityHistoryLimit) {
        slot.retired_remote_identities.pop_front();
    }
    slot.retired_remote_identities.push_back(retired);
}

void PeerManager::ReplaceRemoteSession(PeerSlot& slot,
                                       const SynPayload& syn,
                                       std::uint32_t counter,
                                       bool require_next_non_handshake)
{
    const bool replacing = slot.has_remote_identity && !SameRemoteIdentity(slot, syn);
    const std::uint64_t old_session_id = slot.remote_session_id;
    const std::uint64_t old_peer_id = slot.remote_peer_id;

    if (replacing) {
        RetireRemoteIdentity(slot);
        ++slot.stats.session_replacements;
        LOG_INFO("peer " + PeerLogName(slot)
                 + " replaced remote session old_session_id=" + std::to_string(old_session_id)
                 + " old_peer_id=" + std::to_string(old_peer_id)
                 + " new_session_id=" + std::to_string(syn.session_id)
                 + " new_peer_id=" + std::to_string(syn.peer_id)
                 + " state=" + PeerStateName(slot.state));
    }

    slot.remote_session_id = syn.session_id;
    slot.remote_peer_id = syn.peer_id;
    slot.has_remote_identity = true;
    slot.last_inbound_counter = counter;
    slot.has_last_inbound_counter = true;
    slot.require_next_inbound_counter_after_reset = require_next_non_handshake;
}

void PeerManager::TransitionToDisconnected(PeerSlot& slot, Clock::TimePoint now, bool increase_backoff)
{
    const PeerState previous = slot.state;
    const auto wait = slot.reconnect_backoff;
    slot.state = PeerState::kDisconnected;
    slot.state_since = now;
    slot.next_connect_attempt = now + wait;
    if (previous != slot.state) {
        LOG_INFO("peer " + PeerLogName(slot)
                 + " state " + PeerStateName(previous)
                 + " -> " + PeerStateName(slot.state));
    }

    if (increase_backoff) {
        slot.reconnect_backoff = DoubleBackoff(slot.reconnect_backoff, m_config.max_backoff);
    }
}

void PeerManager::TransitionToStale(PeerSlot& slot, Clock::TimePoint now)
{
    const PeerState previous = slot.state;
    slot.state = PeerState::kStale;
    slot.state_since = now;
    if (previous != slot.state) {
        LOG_INFO("peer " + PeerLogName(slot)
                 + " state " + PeerStateName(previous)
                 + " -> " + PeerStateName(slot.state));
    }
}

void PeerManager::TransitionToActive(PeerSlot& slot, Clock::TimePoint now)
{
    const PeerState previous = slot.state;
    slot.state = PeerState::kActive;
    slot.state_since = now;
    slot.last_packet_received = now;
    slot.reconnect_backoff = m_config.initial_backoff;
    if (previous != slot.state) {
        LOG_INFO("peer " + PeerLogName(slot)
                 + " state " + PeerStateName(previous)
                 + " -> " + PeerStateName(slot.state));
    }
}

} // namespace photon
