#include <clock.h>
#include <peer_manager.h>
#include <protocol.h>
#include <udp_transport.h>

#include <netinet/in.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using photon::MessageType;
using photon::MockClock;
using photon::Packet;
using photon::PeerConfig;
using photon::PeerManager;
using photon::PeerState;
using photon::PeerSlot;
using photon::SynPayload;
using photon::kRetiredRemoteIdentityHistoryLimit;

constexpr std::uint64_t kDefaultRemoteSessionId = 1001;
constexpr std::uint64_t kDefaultRemotePeerId = 2001;

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

PeerConfig MakePeer(const std::string& name,
                    const std::string& host,
                    std::uint16_t port,
                    const std::array<std::uint8_t, 32>& key)
{
    PeerConfig peer{};
    peer.name = name;
    peer.host = host;
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

bool ResolveLoopback(const std::string& host,
                     std::uint16_t port,
                     sockaddr_storage* out_addr,
                     socklen_t* out_len,
                     std::string* error)
{
    return photon::UdpTransport::ResolveEndpoint(host, port, out_addr, out_len, error);
}

bool ResolveNever(const std::string&,
                  std::uint16_t,
                  sockaddr_storage*,
                  socklen_t*,
                  std::string*)
{
    return false;
}

Packet SignedSynAck(const std::array<std::uint8_t, 32>& key,
                    std::uint32_t counter = 7,
                    std::uint64_t session_id = kDefaultRemoteSessionId,
                    std::uint64_t peer_id = kDefaultRemotePeerId)
{
    Packet packet = photon::MakePacket(MessageType::kSynAck, counter);
    SynPayload syn{};
    syn.session_id = session_id;
    syn.peer_id = peer_id;
    photon::EncodeSynPayload(syn, packet.payload);
    photon::AttachPacketMac(packet, key);
    return packet;
}

Packet SignedSyn(const std::array<std::uint8_t, 32>& key,
                 std::uint32_t counter,
                 std::uint64_t session_id = kDefaultRemoteSessionId,
                 std::uint64_t peer_id = kDefaultRemotePeerId)
{
    Packet packet = photon::MakePacket(MessageType::kSyn, counter);
    SynPayload syn{};
    syn.session_id = session_id;
    syn.peer_id = peer_id;
    photon::EncodeSynPayload(syn, packet.payload);
    photon::AttachPacketMac(packet, key);
    return packet;
}

SynPayload DecodeSynPayloadOrThrow(const Packet& packet)
{
    SynPayload syn{};
    Require(photon::DecodeSynPayload(packet.payload, syn), "failed to decode Syn payload");
    return syn;
}

Packet SignedControl(MessageType type,
                     const std::array<std::uint8_t, 32>& key,
                     std::uint32_t counter,
                     std::uint64_t session_id = kDefaultRemoteSessionId)
{
    Packet packet = photon::MakePacket(type, counter);
    photon::AttachPacketMac(packet, key, session_id);
    return packet;
}

sockaddr_storage ResolveAddrOrThrow(std::uint16_t port, socklen_t& out_len)
{
    sockaddr_storage addr{};
    std::string error;
    const bool ok = photon::UdpTransport::ResolveEndpoint("127.0.0.1", port, &addr, &out_len, &error);
    Require(ok, "failed to resolve loopback address for test peer");
    return addr;
}

sockaddr_storage MakeIpv4MappedIpv6Loopback(std::uint16_t port, socklen_t& out_len)
{
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(port);
    addr6.sin6_addr.s6_addr[10] = 0xFF;
    addr6.sin6_addr.s6_addr[11] = 0xFF;
    addr6.sin6_addr.s6_addr[12] = 127;
    addr6.sin6_addr.s6_addr[15] = 1;

    sockaddr_storage storage{};
    std::memcpy(&storage, &addr6, sizeof(addr6));
    out_len = sizeof(addr6);
    return storage;
}

sockaddr_storage MakeIpv6Loopback(std::uint16_t port, socklen_t& out_len)
{
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(port);
    addr6.sin6_addr = in6addr_loopback;

    sockaddr_storage storage{};
    std::memcpy(&storage, &addr6, sizeof(addr6));
    out_len = sizeof(addr6);
    return storage;
}

std::uint16_t SentPort(const RecordingSink::Sent& sent)
{
    if (sent.addr.ss_family == AF_INET) {
        const auto* addr = reinterpret_cast<const sockaddr_in*>(&sent.addr);
        return ntohs(addr->sin_port);
    }
    if (sent.addr.ss_family == AF_INET6) {
        const auto* addr = reinterpret_cast<const sockaddr_in6*>(&sent.addr);
        return ntohs(addr->sin6_port);
    }
    throw std::runtime_error("unsupported sockaddr family in sent packet");
}

PeerSlot HandshakeOnePeer(PeerManager& manager,
                          RecordingSink& sink,
                          const std::array<std::uint8_t, 32>& key,
                          std::uint16_t peer_port)
{
    manager.Tick(sink);
    Require(!sink.sent.empty(), "expected Syn packet");
    Require(sink.sent.front().packet.msg_type == MessageType::kSyn, "first packet should be Syn");
    SynPayload outbound_syn{};
    Require(photon::DecodeSynPayload(sink.sent.front().packet.payload, outbound_syn),
            "outbound Syn should carry a valid payload");
    Require(outbound_syn.session_id != 0, "outbound Syn should carry a nonzero session id");

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(peer_port, addr_len);
    const bool handled = manager.HandleInbound(SignedSynAck(key), addr, addr_len);
    Require(handled, "expected signed SynAck to be accepted");

    const auto& slots = manager.slots();
    Require(slots.size() == 1, "expected one slot");
    return slots[0];
}

void AssertReplayedPacketDoesNotRefreshStaleOrDisconnectedPeer(MessageType type,
                                                               const std::string& packet_name,
                                                               std::uint8_t key_seed,
                                                               std::uint16_t peer_port)
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(key_seed);
    PeerManager manager({MakePeer("p1", "127.0.0.1", peer_port, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, peer_port);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(peer_port, addr_len);
    const Packet packet = SignedControl(type, key, 8);

    clock.Advance(std::chrono::seconds(1));
    Require(manager.HandleInbound(packet, addr, addr_len), "first " + packet_name + " should be accepted");
    Require(manager.slots()[0].stats.packets_received == 2,
            packet_name + " should increment packets received once");
    Require(manager.slots()[0].last_inbound_counter == 8,
            packet_name + " should establish the inbound counter baseline");
    const auto accepted_last_packet_received = manager.slots()[0].last_packet_received;

    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kStale, packet_name + " replay test peer should become stale");

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(packet, addr, addr_len),
            "replayed " + packet_name + " should be rejected while stale");
    Require(manager.slots()[0].state == PeerState::kStale,
            "replayed " + packet_name + " should not reactivate stale peer");
    Require(manager.slots()[0].stats.packets_received == 2,
            "replayed " + packet_name + " should not increment packets received");
    Require(manager.slots()[0].last_packet_received == accepted_last_packet_received,
            "replayed " + packet_name + " should not refresh stale receive time");
    Require(manager.slots()[0].last_inbound_counter == 8,
            "replayed " + packet_name + " should not advance inbound counter");

    clock.Advance(std::chrono::seconds(5));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            packet_name + " replay test peer should disconnect after staleness");
    const auto disconnected_last_packet_received = manager.slots()[0].last_packet_received;
    const auto next_connect_attempt = manager.slots()[0].next_connect_attempt;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(packet, addr, addr_len),
            "replayed " + packet_name + " should be rejected while disconnected");
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            "replayed " + packet_name + " should not reactivate disconnected peer");
    Require(manager.slots()[0].stats.packets_received == 2,
            "disconnected replayed " + packet_name + " should not increment packets received");
    Require(manager.slots()[0].last_packet_received == disconnected_last_packet_received,
            "disconnected replayed " + packet_name + " should not refresh receive time");
    Require(manager.slots()[0].next_connect_attempt == next_connect_attempt,
            "disconnected replayed " + packet_name + " should not reschedule reconnect");
    Require(manager.slots()[0].last_inbound_counter == 8,
            "disconnected replayed " + packet_name + " should not advance inbound counter");
}

void TestHandshakeHappyPath()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(10);
    PeerManager manager({MakePeer("p1", "127.0.0.1", 41001, key)}, clock, ResolveLoopback);

    const PeerSlot slot = HandshakeOnePeer(manager, sink, key, 41001);
    Require(slot.state == PeerState::kActive, "peer should become active after SynAck");
    Require(slot.stats.syn_sent == 1, "syn_sent should increment");
    Require(slot.stats.synack_received == 1, "synack_received should increment");
}

void TestOutgoingSynUsesNonZeroIdentity()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(11);
    constexpr std::uint16_t kPort = 41028;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);
    Require(sink.sent.size() == 1, "expected initial Syn packet");
    Require(sink.sent.back().packet.msg_type == MessageType::kSyn, "initial packet should be Syn");
    const SynPayload initial_syn = DecodeSynPayloadOrThrow(sink.sent.back().packet);
    Require(initial_syn.session_id != 0, "outgoing Syn should encode a nonzero session id");
    Require(initial_syn.peer_id != 0, "outgoing Syn should encode a nonzero peer id");

    clock.Advance(std::chrono::seconds(6));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            "connect timeout should disconnect before retry");
    clock.Advance(std::chrono::seconds(1));
    manager.Tick(sink);
    Require(sink.sent.size() == 2, "expected reconnect Syn packet");
    Require(sink.sent.back().packet.msg_type == MessageType::kSyn, "reconnect packet should be Syn");
    const SynPayload reconnect_syn = DecodeSynPayloadOrThrow(sink.sent.back().packet);
    Require(reconnect_syn.session_id != 0, "reconnect Syn should encode a nonzero session id");
    Require(reconnect_syn.peer_id == initial_syn.peer_id,
            "same process should reuse stable local peer id across reconnects");
}

void TestDefaultRestartedPeerSessionRebindsAfterReconnect()
{
    MockClock clock{};
    RecordingSink old_process_sink;
    RecordingSink restarted_process_sink;
    RecordingSink observer_sink;

    const auto key = Key(12);
    constexpr std::uint16_t kProcessPort = 41029;
    constexpr std::uint16_t kObserverPort = 41030;
    PeerManager observer({MakePeer("process", "127.0.0.1", kProcessPort, key)}, clock, ResolveLoopback);
    PeerManager process({MakePeer("observer", "127.0.0.1", kObserverPort, key)}, clock, ResolveLoopback);

    process.Tick(old_process_sink);
    Require(old_process_sink.sent.size() == 1, "expected first process Syn packet");
    const Packet first_syn = old_process_sink.sent.back().packet;
    const SynPayload first_identity = DecodeSynPayloadOrThrow(first_syn);
    Require(first_identity.session_id != 0, "first process Syn should have nonzero session id");
    Require(first_identity.peer_id != 0, "first process Syn should have nonzero peer id");

    observer.Tick(observer_sink);
    Require(observer.slots()[0].state == PeerState::kConnecting,
            "observer should establish a local session before accepting inbound Syn");

    socklen_t process_addr_len = 0;
    const sockaddr_storage process_addr = ResolveAddrOrThrow(kProcessPort, process_addr_len);
    Require(observer.HandleInbound(first_syn, process_addr, process_addr_len),
            "observer should accept first process Syn");
    Require(observer.HandleInbound(SignedControl(MessageType::kKeepalive, key, 50, first_identity.session_id),
                                   process_addr,
                                   process_addr_len),
            "observer should record high inbound counter from first process");
    Require(observer.slots()[0].state == PeerState::kActive, "observer should mark first process active");
    Require(observer.slots()[0].last_inbound_counter == 50, "observer should store high first-process counter");

    clock.Advance(std::chrono::seconds(16));
    observer.Tick(observer_sink);
    Require(observer.slots()[0].state == PeerState::kStale, "observer should become stale before reconnect");

    clock.Advance(std::chrono::seconds(6));
    observer.Tick(observer_sink);
    Require(observer.slots()[0].state == PeerState::kDisconnected, "observer should disconnect stale process");

    clock.Advance(std::chrono::seconds(1));
    observer.Tick(observer_sink);
    Require(observer.slots()[0].state == PeerState::kConnecting, "observer should reconnect to process");

    PeerManager restarted_process({MakePeer("observer", "127.0.0.1", kObserverPort, key)},
                                  clock,
                                  ResolveLoopback);
    restarted_process.Tick(restarted_process_sink);
    Require(restarted_process_sink.sent.size() == 1, "expected restarted process Syn packet");
    const Packet restarted_syn = restarted_process_sink.sent.back().packet;
    const SynPayload restarted_identity = DecodeSynPayloadOrThrow(restarted_syn);
    Require(restarted_identity.session_id != 0, "restarted process Syn should have nonzero session id");
    Require(restarted_identity.peer_id != 0, "restarted process Syn should have nonzero peer id");
    Require(observer.HandleInbound(restarted_syn, process_addr, process_addr_len),
            "observer should accept restarted process Syn with reset counter");
    Require(observer.slots()[0].state == PeerState::kActive, "restarted process should reactivate observer");
    Require(observer.slots()[0].last_inbound_counter == 1,
            "restarted process should reset observer inbound counter baseline");
    Require(observer.slots()[0].remote_session_id == restarted_identity.session_id,
            "observer should bind restarted process session id");
    Require(observer.slots()[0].remote_peer_id == restarted_identity.peer_id,
            "observer should bind restarted process peer id");
}

void TestInboundSynInitializesLocalSessionAndSendsSynAck()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(13);
    constexpr std::uint16_t kPort = 41031;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSyn(key, 1, 7001, 8001), addr, addr_len, sink),
            "inbound Syn should initialize local session and be accepted");
    Require(manager.slots()[0].state == PeerState::kActive, "inbound Syn should activate peer");
    Require(manager.slots()[0].local_session_id != 0, "inbound Syn should initialize local session");
    Require(manager.slots()[0].remote_session_id == 7001, "inbound Syn should bind remote session");
    Require(manager.slots()[0].remote_peer_id == 8001, "inbound Syn should bind remote peer id");
    Require(manager.slots()[0].stats.syn_received == 1, "syn_received should increment");
    Require(manager.slots()[0].stats.synack_sent == 1, "SynAck response should be counted");
    Require(sink.sent.size() == 1, "inbound Syn should send one SynAck response");
    Require(sink.sent.back().packet.msg_type == MessageType::kSynAck, "response should be SynAck");

    const SynPayload response_identity = DecodeSynPayloadOrThrow(sink.sent.back().packet);
    Require(response_identity.session_id == manager.slots()[0].local_session_id,
            "SynAck should advertise local session id");
    Require(response_identity.peer_id != 0, "SynAck should advertise local peer id");
}

void TestRestartedPeerSynReplacesActiveSessionAndSendsSynAck()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(14);
    constexpr std::uint16_t kPort = 41032;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, 50, 5001, 6001), addr, addr_len),
            "initial SynAck should be accepted");
    Require(manager.slots()[0].state == PeerState::kActive, "peer should start active");
    const auto active_last_packet_received = manager.slots()[0].last_packet_received;
    const std::size_t sent_before_restart_syn = sink.sent.size();

    Require(manager.HandleInbound(SignedSyn(key, 1, 5002, 6002), addr, addr_len, sink),
            "fresh restarted Syn should replace active remote session");
    Require(manager.slots()[0].state == PeerState::kActive, "restarted Syn should keep peer active");
    Require(manager.slots()[0].remote_session_id == 5002, "remote session should be replaced");
    Require(manager.slots()[0].remote_peer_id == 6002, "remote peer id should be replaced");
    Require(manager.slots()[0].last_inbound_counter == 1, "restart Syn should reset inbound counter baseline");
    Require(manager.slots()[0].stats.session_replacements == 1, "session replacement should be counted");
    Require(manager.slots()[0].stats.syn_received == 1, "restart Syn should increment syn_received");
    Require(manager.slots()[0].stats.synack_sent == 1, "restart Syn should trigger SynAck");
    Require(sink.sent.size() == sent_before_restart_syn + 1, "restart Syn should send one SynAck");
    Require(sink.sent.back().packet.msg_type == MessageType::kSynAck, "restart response should be SynAck");
    Require(manager.slots()[0].last_packet_received == active_last_packet_received,
            "mock clock did not advance during replacement");

    Require(!manager.HandleInbound(SignedSyn(key, 51, 5001, 6001), addr, addr_len),
            "retired old-session Syn should not rebind after replacement");
    Require(!manager.HandleInbound(SignedSynAck(key, 52, 5001, 6001), addr, addr_len),
            "retired old-session SynAck should not rebind after replacement");
    Require(!manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 53, 5001), addr, addr_len),
            "old-session Keepalive should fail new session MAC context");
    Require(manager.slots()[0].remote_session_id == 5002, "old session packets should not replace session");
    Require(manager.slots()[0].remote_peer_id == 6002, "old session packets should not replace peer id");
    Require(manager.slots()[0].last_inbound_counter == 1, "old session packets should not advance counter");
    Require(manager.slots()[0].stats.session_replacement_rejects == 2,
            "retired handshakes should be counted as replacement rejects");

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 2, 5002), addr, addr_len),
            "new session Keepalive should continue from restarted Syn baseline");
    Require(!manager.slots()[0].require_next_inbound_counter_after_reset,
            "first new-session non-handshake packet should clear reset guard");
    Require(manager.slots()[0].last_inbound_counter == 2, "new session Keepalive should advance counter");
}

void TestRetiredRemoteSessionsUseBoundedExactHistory()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(17);
    constexpr std::uint16_t kPort = 41035;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, 50, 5301, 6301), addr, addr_len),
            "initial SynAck should be accepted");

    const Packet oldest_restarted_syn = SignedSyn(key, 1, 5302, 6302);
    Require(manager.HandleInbound(oldest_restarted_syn, addr, addr_len, sink),
            "first restarted Syn should replace active remote session");

    std::uint64_t latest_restarted_session_id = 5302;
    std::uint64_t latest_restarted_peer_id = 6302;
    Packet recent_retired_syn{};
    for (std::size_t i = 0; i <= kRetiredRemoteIdentityHistoryLimit; ++i) {
        if (i == kRetiredRemoteIdentityHistoryLimit) {
            recent_retired_syn = SignedSyn(key, 1, latest_restarted_session_id, latest_restarted_peer_id);
        }

        const std::uint64_t session_id = 5303 + static_cast<std::uint64_t>(i);
        const std::uint64_t peer_id = session_id + 1000;
        Require(manager.HandleInbound(SignedSyn(key, 1, session_id, peer_id), addr, addr_len, sink),
                "later restarted Syn should replace active remote session");
        latest_restarted_session_id = session_id;
        latest_restarted_peer_id = peer_id;
    }

    Require(manager.slots()[0].state == PeerState::kActive, "peer should remain active after restarts");
    Require(manager.slots()[0].remote_session_id == latest_restarted_session_id,
            "latest session should remain bound");
    Require(manager.slots()[0].remote_peer_id == latest_restarted_peer_id,
            "latest peer id should remain bound");
    Require(manager.slots()[0].stats.session_replacements == kRetiredRemoteIdentityHistoryLimit + 2,
            "each restarted Syn should count as a session replacement");
    Require(manager.slots()[0].retired_remote_identities.size() == kRetiredRemoteIdentityHistoryLimit,
            "retired identity history should stay bounded");

    Require(!manager.HandleInbound(recent_retired_syn, addr, addr_len, sink),
            "recent retired Syn should stay rejected after history rotation");
    Require(manager.slots()[0].remote_session_id == latest_restarted_session_id,
            "recent retired Syn should not rebind remote session");
    Require(manager.slots()[0].remote_peer_id == latest_restarted_peer_id,
            "recent retired Syn should not rebind remote peer id");
    Require(manager.slots()[0].stats.session_replacement_rejects == 1,
            "recent retired Syn should count as a replacement reject");

    Require(manager.HandleInbound(oldest_restarted_syn, addr, addr_len, sink),
            "oldest retired Syn should age out one entry at a time after the history limit");
    Require(manager.slots()[0].remote_session_id == 5302,
            "aged-out oldest Syn should rebind once it leaves bounded history");
    Require(manager.slots()[0].remote_peer_id == 6302,
            "aged-out oldest Syn should restore its peer id once it leaves bounded history");

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 2, 5302), addr, addr_len),
            "current session should remain usable after bounded-history age-out");
    Require(manager.slots()[0].last_inbound_counter == 2,
            "current session Keepalive should advance the inbound baseline");
}

void TestRestartedPeerSynReplacesStaleSessionBeforeDisconnect()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(15);
    constexpr std::uint16_t kPort = 41033;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, 50, 5101, 6101), addr, addr_len),
            "initial SynAck should be accepted");
    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kStale, "peer should become stale before restart Syn");

    Require(manager.HandleInbound(SignedSyn(key, 1, 5102, 6102), addr, addr_len, sink),
            "fresh restarted Syn should replace stale remote session");
    Require(manager.slots()[0].state == PeerState::kActive, "restart Syn should reactivate stale peer");
    Require(manager.slots()[0].remote_session_id == 5102, "stale remote session should be replaced");
    Require(manager.slots()[0].remote_peer_id == 6102, "stale remote peer id should be replaced");
    Require(manager.slots()[0].stats.session_replacements == 1, "stale replacement should be counted");
    Require(manager.slots()[0].stats.synack_sent == 1, "stale restart Syn should trigger SynAck");
}

void TestRestartedPeerSynReplacesDisconnectedSessionBeforeRetry()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(16);
    constexpr std::uint16_t kPort = 41034;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, 50, 5201, 6201), addr, addr_len),
            "initial SynAck should be accepted");
    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    clock.Advance(std::chrono::seconds(6));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            "peer should disconnect before next retry window");

    Require(manager.HandleInbound(SignedSyn(key, 1, 5202, 6202), addr, addr_len, sink),
            "fresh restarted Syn should replace disconnected remote session");
    Require(manager.slots()[0].state == PeerState::kActive, "restart Syn should reactivate disconnected peer");
    Require(manager.slots()[0].remote_session_id == 5202, "disconnected remote session should be replaced");
    Require(manager.slots()[0].remote_peer_id == 6202, "disconnected remote peer id should be replaced");
    Require(manager.slots()[0].stats.session_replacements == 1,
            "disconnected replacement should be counted");
}

void TestKeepaliveSentOnTimer()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(20);
    PeerManager manager({MakePeer("p1", "127.0.0.1", 41002, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, 41002);

    clock.Advance(std::chrono::seconds(5));
    manager.Tick(sink);

    Require(sink.sent.size() >= 2, "expected keepalive send after timer");
    Require(sink.sent.back().packet.msg_type == MessageType::kKeepalive, "last packet should be keepalive");
}

void TestStaleDetectionOnMissedKeepalive()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(30);
    PeerManager manager({MakePeer("p1", "127.0.0.1", 41003, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, 41003);

    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kStale, "peer should transition to stale");

    clock.Advance(std::chrono::seconds(6));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected, "stale peer should transition to disconnected");
    Require(manager.slots()[0].reconnect_backoff == std::chrono::seconds(2), "backoff should double to 2 seconds");
}

void TestMacVerificationFailure()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(40);
    PeerManager manager({MakePeer("p1", "127.0.0.1", 41004, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(41004, addr_len);

    Packet bad_synack = SignedSynAck(Key(90));
    const bool handled = manager.HandleInbound(bad_synack, addr, addr_len);

    Require(!handled, "invalid mac should be rejected");
    Require(manager.slots()[0].stats.mac_failures == 1, "mac failure counter should increment");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should remain connecting");
}

void TestBackoffDoublingCapped()
{
    MockClock clock{};
    RecordingSink sink;

    PeerManager manager({MakePeer("p1", "127.0.0.1", 41005, Key(50))}, clock, ResolveNever);

    std::chrono::milliseconds wait = std::chrono::seconds(1);
    const std::vector<std::chrono::milliseconds> expected_backoff = {
        std::chrono::seconds(2),
        std::chrono::seconds(4),
        std::chrono::seconds(8),
        std::chrono::seconds(16),
        std::chrono::seconds(32),
        std::chrono::seconds(60),
        std::chrono::seconds(60),
    };

    for (const auto backoff : expected_backoff) {
        manager.Tick(sink);
        Require(manager.slots()[0].reconnect_backoff == backoff, "unexpected reconnect backoff value");
        clock.Advance(wait);
        wait = std::min(wait * 2, std::chrono::milliseconds{std::chrono::seconds(60)});
    }
}

void TestConnectTimeoutTriggersReconnectAttempt()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(55);
    PeerManager manager({MakePeer("p1", "127.0.0.1", 41012, key)}, clock, ResolveLoopback);

    manager.Tick(sink);
    Require(sink.sent.size() == 1, "expected initial Syn send");
    Require(sink.sent.back().packet.msg_type == MessageType::kSyn, "first send should be Syn");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should enter connecting state");

    clock.Advance(std::chrono::seconds(5));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected, "connect timeout should disconnect peer");
    Require(manager.slots()[0].reconnect_backoff == std::chrono::seconds(2), "backoff should double after timeout");

    clock.Advance(std::chrono::seconds(1));
    manager.Tick(sink);
    Require(sink.sent.size() == 2, "expected reconnect Syn after timeout backoff");
    Require(sink.sent.back().packet.msg_type == MessageType::kSyn, "reconnect attempt should send Syn");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should re-enter connecting state");
    Require(manager.slots()[0].stats.syn_sent == 2, "syn_sent should count reconnect attempt");
}

void TestNoUsablePeersAvailableBacksOffCleanly()
{
    MockClock clock{};
    RecordingSink sink;

    PeerManager manager({MakePeer("p1", "unresolved.invalid", 41013, Key(56))}, clock, ResolveNever);

    manager.Tick(sink);
    Require(sink.sent.empty(), "resolve failure should not send packets");
    Require(manager.ActivePeerCount() == 0, "no peers should become active when resolution fails");
    Require(manager.slots()[0].state == PeerState::kDisconnected, "peer should remain disconnected");
    Require(manager.slots()[0].stats.resolve_failures == 1, "first resolve failure should be counted");
    Require(manager.slots()[0].reconnect_backoff == std::chrono::seconds(2), "backoff should double after first resolve failure");

    clock.Advance(std::chrono::seconds(1));
    manager.Tick(sink);
    Require(sink.sent.empty(), "repeated resolve failures should not send packets");
    Require(manager.slots()[0].stats.resolve_failures == 2, "second resolve failure should be counted");
    Require(manager.slots()[0].reconnect_backoff == std::chrono::seconds(4), "backoff should keep doubling on repeated resolve failure");
}

void TestReconnectReResolvesPeerAddress()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(57);
    constexpr std::uint16_t kFirstPort = 41014;
    constexpr std::uint16_t kSecondPort = 41015;
    std::size_t resolve_calls = 0;

    PeerManager::ResolveEndpointFn resolve_rotating =
        [&resolve_calls](const std::string&,
                         std::uint16_t,
                         sockaddr_storage* out_addr,
                         socklen_t* out_len,
                         std::string* error) {
            ++resolve_calls;
            const std::uint16_t port = resolve_calls == 1 ? kFirstPort : kSecondPort;
            return ResolveLoopback("127.0.0.1", port, out_addr, out_len, error);
        };

    PeerManager manager({MakePeer("p1", "rotating.example", kFirstPort, key)}, clock, resolve_rotating);

    manager.Tick(sink);
    Require(sink.sent.size() == 1, "expected initial Syn send");
    Require(SentPort(sink.sent[0]) == kFirstPort, "first resolve should target initial address");

    clock.Advance(std::chrono::seconds(5));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected, "connect timeout should disconnect peer");

    clock.Advance(std::chrono::seconds(1));
    manager.Tick(sink);
    Require(sink.sent.size() == 2, "expected reconnect Syn after timeout");
    Require(SentPort(sink.sent[1]) == kSecondPort, "reconnect should re-resolve to updated address");
    Require(resolve_calls >= 2, "resolver should be invoked again for reconnect");
}

void TestMultipleIndependentPeers()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key_a = Key(60);
    const auto key_b = Key(80);

    PeerManager manager(
        {
            MakePeer("pa", "127.0.0.1", 41006, key_a),
            MakePeer("pb", "127.0.0.1", 41007, key_b),
        },
        clock,
        ResolveLoopback);

    manager.Tick(sink);
    Require(sink.sent.size() == 2, "expected Syn for each peer");

    socklen_t addr_len = 0;
    const sockaddr_storage addr_a = ResolveAddrOrThrow(41006, addr_len);
    const bool handled_a = manager.HandleInbound(SignedSynAck(key_a, 101), addr_a, addr_len);
    Require(handled_a, "peer A synack should be accepted");

    const auto& slots = manager.slots();
    Require(slots.size() == 2, "expected two slots");
    Require(slots[0].state == PeerState::kActive, "peer A should be active");
    Require(slots[1].state == PeerState::kConnecting, "peer B should remain connecting");
}

void TestDisconnectPacketHandling()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(100);
    PeerManager manager({MakePeer("p1", "127.0.0.1", 41008, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, 41008);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(41008, addr_len);
    const bool handled = manager.HandleInbound(SignedControl(MessageType::kDisconnect, key, 55), addr, addr_len);

    Require(handled, "disconnect should be accepted");
    Require(manager.slots()[0].state == PeerState::kDisconnected, "peer should transition to disconnected");
    Require(manager.slots()[0].stats.disconnect_received == 1, "disconnect counter should increment");
}

void TestInboundZeroCounterRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(101);
    constexpr std::uint16_t kPort = 41016;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);
    const bool handled = manager.HandleInbound(SignedSynAck(key, 0), addr, addr_len);

    Require(!handled, "zero inbound counter should be rejected");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should remain connecting");
    Require(manager.slots()[0].stats.packets_received == 0, "zero counter should not increment packets received");
    Require(manager.slots()[0].stats.synack_received == 0, "zero counter should not increment synack counter");
    Require(!manager.slots()[0].has_last_inbound_counter, "zero counter should not initialize inbound counter state");
    Require(!manager.slots()[0].has_remote_identity, "zero counter should not bind remote identity");
}

void TestInboundZeroSessionRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(103);
    constexpr std::uint16_t kPort = 41028;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);
    const bool handled = manager.HandleInbound(SignedSynAck(key, 7, 0, kDefaultRemotePeerId), addr, addr_len);

    Require(!handled, "zero session SynAck should be rejected");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should remain connecting");
    Require(manager.slots()[0].stats.packets_received == 0, "zero session should not increment packets received");
    Require(manager.slots()[0].stats.synack_received == 0, "zero session should not increment synack counter");
    Require(!manager.slots()[0].has_remote_identity, "zero session should not bind remote identity");
}

void TestReplayedSynAckRejectedBeforeStats()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(102);
    constexpr std::uint16_t kPort = 41017;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);
    const Packet synack = SignedSynAck(key, 7, 1001, 2001);

    Require(manager.HandleInbound(synack, addr, addr_len), "first SynAck should be accepted");
    const auto last_packet_received = manager.slots()[0].last_packet_received;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(synack, addr, addr_len), "replayed SynAck should be rejected");
    Require(manager.slots()[0].state == PeerState::kActive, "peer should remain active after rejected replay");
    Require(manager.slots()[0].stats.packets_received == 1, "replayed SynAck should not increment packets received");
    Require(manager.slots()[0].stats.synack_received == 1, "replayed SynAck should not increment synack counter");
    Require(manager.slots()[0].last_packet_received == last_packet_received,
            "replayed SynAck should not refresh last packet time");
    Require(manager.slots()[0].last_inbound_counter == 7, "replayed SynAck should not advance inbound counter");
}

void TestReplayedKeepaliveDoesNotRefreshStaleOrDisconnectedPeer()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(103);
    constexpr std::uint16_t kPort = 41018;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, kPort);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);
    const Packet keepalive = SignedControl(MessageType::kKeepalive, key, 8);

    clock.Advance(std::chrono::seconds(1));
    Require(manager.HandleInbound(keepalive, addr, addr_len), "first keepalive should be accepted");
    Require(manager.slots()[0].stats.keepalive_received == 1, "keepalive counter should increment once");

    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kStale, "peer should become stale");
    const auto stale_last_packet_received = manager.slots()[0].last_packet_received;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(keepalive, addr, addr_len), "replayed keepalive should be rejected while stale");
    Require(manager.slots()[0].state == PeerState::kStale, "replayed keepalive should not reactivate stale peer");
    Require(manager.slots()[0].stats.packets_received == 2, "replayed keepalive should not increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1, "replayed keepalive should not increment keepalive counter");
    Require(manager.slots()[0].last_packet_received == stale_last_packet_received,
            "replayed keepalive should not refresh stale receive time");

    clock.Advance(std::chrono::seconds(5));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected, "stale peer should disconnect");
    const auto disconnected_last_packet_received = manager.slots()[0].last_packet_received;
    const auto next_connect_attempt = manager.slots()[0].next_connect_attempt;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(keepalive, addr, addr_len), "replayed keepalive should be rejected while disconnected");
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            "replayed keepalive should not reactivate disconnected peer");
    Require(manager.slots()[0].stats.packets_received == 2, "disconnected replay should not increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1, "disconnected replay should not increment keepalive counter");
    Require(manager.slots()[0].last_packet_received == disconnected_last_packet_received,
            "disconnected replay should not refresh receive time");
    Require(manager.slots()[0].next_connect_attempt == next_connect_attempt,
            "disconnected replay should not reschedule reconnect");
}

void TestReplayedPongDoesNotRefreshStaleOrDisconnectedPeer()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(111);
    constexpr std::uint16_t kPort = 41027;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, kPort);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);
    const Packet pong = SignedControl(MessageType::kPong, key, 8);

    clock.Advance(std::chrono::seconds(1));
    Require(manager.HandleInbound(pong, addr, addr_len), "first pong should be accepted");
    Require(manager.slots()[0].stats.pong_received == 1, "pong counter should increment once");

    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kStale, "peer should become stale");
    const auto stale_last_packet_received = manager.slots()[0].last_packet_received;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(pong, addr, addr_len), "replayed pong should be rejected while stale");
    Require(manager.slots()[0].state == PeerState::kStale, "replayed pong should not reactivate stale peer");
    Require(manager.slots()[0].stats.packets_received == 2, "replayed pong should not increment packets received");
    Require(manager.slots()[0].stats.pong_received == 1, "replayed pong should not increment pong counter");
    Require(manager.slots()[0].last_packet_received == stale_last_packet_received,
            "replayed pong should not refresh stale receive time");
    Require(manager.slots()[0].last_inbound_counter == 8, "replayed pong should not advance inbound counter");

    clock.Advance(std::chrono::seconds(5));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected, "stale peer should disconnect");
    const auto disconnected_last_packet_received = manager.slots()[0].last_packet_received;
    const auto next_connect_attempt = manager.slots()[0].next_connect_attempt;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(pong, addr, addr_len), "replayed pong should be rejected while disconnected");
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            "replayed pong should not reactivate disconnected peer");
    Require(manager.slots()[0].stats.packets_received == 2, "disconnected replay should not increment packets received");
    Require(manager.slots()[0].stats.pong_received == 1, "disconnected replay should not increment pong counter");
    Require(manager.slots()[0].last_packet_received == disconnected_last_packet_received,
            "disconnected replay should not refresh receive time");
    Require(manager.slots()[0].next_connect_attempt == next_connect_attempt,
            "disconnected replay should not reschedule reconnect");
    Require(manager.slots()[0].last_inbound_counter == 8,
            "disconnected replay should not advance inbound counter");
}

void TestReplayedDisconnectRejectedAfterHandled()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(104);
    constexpr std::uint16_t kPort = 41019;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, kPort);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);
    const Packet disconnect = SignedControl(MessageType::kDisconnect, key, 8);

    Require(manager.HandleInbound(disconnect, addr, addr_len), "first disconnect should be accepted");
    Require(manager.slots()[0].state == PeerState::kDisconnected, "peer should disconnect");
    const auto next_connect_attempt = manager.slots()[0].next_connect_attempt;

    clock.Advance(std::chrono::seconds(1));
    Require(!manager.HandleInbound(disconnect, addr, addr_len), "replayed disconnect should be rejected");
    Require(manager.slots()[0].state == PeerState::kDisconnected,
            "replayed disconnect should leave peer disconnected");
    Require(manager.slots()[0].stats.packets_received == 2, "replayed disconnect should not increment packets received");
    Require(manager.slots()[0].stats.disconnect_received == 1,
            "replayed disconnect should not increment disconnect counter");
    Require(manager.slots()[0].next_connect_attempt == next_connect_attempt,
            "replayed disconnect should not reschedule reconnect");
}

void TestReplayedPingDoesNotRefreshStaleOrDisconnectedPeer()
{
    AssertReplayedPacketDoesNotRefreshStaleOrDisconnectedPeer(
        MessageType::kPing, "ping", 105, 41020);
}

void TestReplayedBlockChunkDoesNotRefreshStaleOrDisconnectedPeer()
{
    AssertReplayedPacketDoesNotRefreshStaleOrDisconnectedPeer(
        MessageType::kBlockChunk, "block chunk", 106, 41021);
}

void TestLowerInboundCounterRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(107);
    constexpr std::uint16_t kPort = 41022;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    (void)HandshakeOnePeer(manager, sink, key, kPort);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 10), addr, addr_len),
            "higher counter keepalive should be accepted");
    Require(!manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 9), addr, addr_len),
            "lower inbound counter should be rejected");
    Require(manager.slots()[0].state == PeerState::kActive, "lower counter should not change peer state");
    Require(manager.slots()[0].stats.packets_received == 2, "lower counter should not increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1, "lower counter should not increment keepalive counter");
    Require(manager.slots()[0].last_inbound_counter == 10, "lower counter should not replace last inbound counter");
}

void TestInboundCounterWrapAccepted()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(110);
    constexpr std::uint16_t kPort = 41024;
    constexpr std::uint32_t kMaxCounter = std::numeric_limits<std::uint32_t>::max();
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, kMaxCounter), addr, addr_len),
            "max inbound counter SynAck should be accepted");
    Require(manager.slots()[0].last_inbound_counter == kMaxCounter,
            "max inbound counter should be recorded");

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 1), addr, addr_len),
            "wrapped inbound counter should be accepted");
    Require(manager.slots()[0].stats.packets_received == 2, "wrapped counter should increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1, "wrapped counter should increment keepalive counter");
    Require(manager.slots()[0].last_inbound_counter == 1, "wrapped counter should become inbound baseline");

    Require(!manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 1), addr, addr_len),
            "replayed wrapped counter should be rejected");
    Require(manager.slots()[0].stats.packets_received == 2,
            "replayed wrapped counter should not increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1,
            "replayed wrapped counter should not increment keepalive counter");
}

void TestInboundCounterWrapGapAccepted()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(111);
    constexpr std::uint16_t kPort = 41023;
    constexpr std::uint32_t kMaxCounter = std::numeric_limits<std::uint32_t>::max();
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, kMaxCounter), addr, addr_len),
            "max inbound counter SynAck should be accepted");
    Require(manager.slots()[0].last_inbound_counter == kMaxCounter,
            "max inbound counter should be recorded before wrap gap");

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 2), addr, addr_len),
            "post-wrap keepalive should tolerate a lost wrap-point packet");
    Require(manager.slots()[0].stats.packets_received == 2,
            "post-wrap gap should still increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1,
            "post-wrap gap should still increment keepalive counter");
    Require(manager.slots()[0].last_inbound_counter == 2,
            "post-wrap gap should advance the inbound counter");

    Require(!manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 1), addr, addr_len),
            "stale wrapped counter should still be rejected after gap acceptance");
    Require(manager.slots()[0].stats.packets_received == 2,
            "stale wrapped counter should not increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1,
            "stale wrapped counter should not increment keepalive counter");
    Require(manager.slots()[0].last_inbound_counter == 2,
            "stale wrapped counter should not replace the inbound baseline");
}

void TestStaleLowInboundCounterFarFromWrapRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(112);
    constexpr std::uint16_t kPort = 41026;
    constexpr std::uint32_t kHighCounter = 3'000'000'000u;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, kHighCounter), addr, addr_len),
            "high inbound counter SynAck should be accepted");
    Require(manager.slots()[0].state == PeerState::kActive, "peer should become active after high counter SynAck");

    Require(!manager.HandleInbound(SignedControl(MessageType::kDisconnect, key, 1), addr, addr_len),
            "stale low disconnect should be rejected far from wrap");
    Require(manager.slots()[0].state == PeerState::kActive,
            "stale low disconnect should not change peer state");
    Require(manager.slots()[0].stats.packets_received == 1,
            "stale low disconnect should not increment packets received");
    Require(manager.slots()[0].stats.disconnect_received == 0,
            "stale low disconnect should not increment disconnect counter");
    Require(manager.slots()[0].last_inbound_counter == kHighCounter,
            "stale low disconnect should not replace last inbound counter");

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, kHighCounter + 1), addr, addr_len),
            "higher monotonic counter should still be accepted");
    Require(manager.slots()[0].stats.packets_received == 2,
            "higher monotonic counter should still increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1,
            "higher monotonic counter should increment keepalive counter");
    Require(manager.slots()[0].last_inbound_counter == kHighCounter + 1,
            "higher monotonic counter should advance the inbound baseline");
}

void TestConflictingSynAckSessionRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(108);
    constexpr std::uint16_t kPort = 41025;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, 7, 3001, 4001), addr, addr_len),
            "initial SynAck should bind remote identity");
    Require(manager.slots()[0].has_remote_identity, "remote identity should be bound");
    Require(manager.slots()[0].remote_session_id == 3001, "remote session id should be recorded");
    Require(manager.slots()[0].remote_peer_id == 4001, "remote peer id should be recorded");

    Require(!manager.HandleInbound(SignedSynAck(key, 8, 3002, 4001), addr, addr_len),
            "conflicting SynAck session id should be rejected");
    Require(!manager.HandleInbound(SignedSynAck(key, 9, 3001, 4002), addr, addr_len),
            "conflicting SynAck peer id should be rejected");
    Require(manager.slots()[0].state == PeerState::kActive, "conflicting SynAck should not change peer state");
    Require(manager.slots()[0].stats.packets_received == 1, "conflicting SynAck should not increment packets received");
    Require(manager.slots()[0].stats.synack_received == 1, "conflicting SynAck should not increment synack counter");
    Require(manager.slots()[0].last_inbound_counter == 7, "conflicting SynAck should not advance inbound counter");
    Require(manager.slots()[0].remote_session_id == 3001, "conflicting SynAck should not replace session id");
    Require(manager.slots()[0].remote_peer_id == 4001, "conflicting SynAck should not replace peer id");
}

void TestReconnectAcceptsNewSynAckSessionWithResetCounter()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(109);
    constexpr std::uint16_t kPort = 41026;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);

    socklen_t addr_len = 0;
    const sockaddr_storage addr = ResolveAddrOrThrow(kPort, addr_len);

    Require(manager.HandleInbound(SignedSynAck(key, 50, 5001, 6001), addr, addr_len),
            "initial SynAck should be accepted");
    Require(manager.slots()[0].state == PeerState::kActive, "peer should become active");
    Require(manager.slots()[0].last_inbound_counter == 50, "initial counter should be recorded");

    clock.Advance(std::chrono::seconds(16));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kStale, "peer should become stale before reconnect");

    clock.Advance(std::chrono::seconds(6));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kDisconnected, "stale peer should disconnect");

    clock.Advance(std::chrono::seconds(1));
    manager.Tick(sink);
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should send a reconnect Syn");

    Require(manager.HandleInbound(SignedSynAck(key, 1, 5002, 6002), addr, addr_len),
            "new reconnect SynAck session should be accepted with reset counter");
    Require(manager.slots()[0].state == PeerState::kActive, "new session should reactivate peer");
    Require(manager.slots()[0].stats.packets_received == 2, "new session should count as second received packet");
    Require(manager.slots()[0].stats.synack_received == 2, "new session should count as second SynAck");
    Require(manager.slots()[0].last_inbound_counter == 1, "new session should reset inbound counter baseline");
    Require(manager.slots()[0].remote_session_id == 5002, "new session id should replace old session id");
    Require(manager.slots()[0].remote_peer_id == 6002, "new peer id should replace old peer id");
    const auto new_session_last_packet_received = manager.slots()[0].last_packet_received;

    Require(!manager.HandleInbound(SignedSyn(key, 51, 5001, 6001), addr, addr_len),
            "stale old session Syn should not rebind new session identity");
    Require(!manager.HandleInbound(SignedSynAck(key, 52, 5001, 6001), addr, addr_len),
            "stale old session SynAck should be rejected after reconnect");
    Require(!manager.HandleInbound(SignedControl(MessageType::kDisconnect, key, 53, 5001), addr, addr_len),
            "stale old session Disconnect should not force-disconnect new session");
    Require(!manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 54, 5001), addr, addr_len),
            "stale old session Keepalive should not advance new session counter");
    Require(!manager.HandleInbound(SignedControl(MessageType::kPong, key, 55, 5001), addr, addr_len),
            "stale old session Pong should not refresh new session liveness");
    Require(!manager.HandleInbound(SignedControl(MessageType::kBlockHeader, key, 56, 5001), addr, addr_len),
            "stale old session BlockHeader should not reach relay handling");
    Require(!manager.HandleInbound(SignedControl(MessageType::kBlockChunk, key, 57, 5001), addr, addr_len),
            "stale old session BlockChunk should not reach relay handling");
    Require(!manager.HandleInbound(SignedControl(MessageType::kPing, key, 58, 5001), addr, addr_len),
            "stale old session Ping should not refresh new session liveness");
    Require(manager.slots()[0].state == PeerState::kActive, "stale old session packets should not change peer state");
    Require(manager.slots()[0].stats.packets_received == 2, "stale old session packets should not increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 0,
            "stale old session Keepalive should not increment keepalive counter");
    Require(manager.slots()[0].stats.pong_received == 0, "stale old session Pong should not increment pong counter");
    Require(manager.slots()[0].stats.disconnect_received == 0,
            "stale old session Disconnect should not increment disconnect counter");
    Require(manager.slots()[0].last_inbound_counter == 1,
            "stale old session packets should not advance inbound counter");
    Require(manager.slots()[0].last_packet_received == new_session_last_packet_received,
            "stale old session packets should not refresh new session liveness");
    Require(manager.slots()[0].remote_session_id == 5002, "stale old session packets should not replace session id");
    Require(manager.slots()[0].remote_peer_id == 6002, "stale old session packets should not replace peer id");

    Require(manager.HandleInbound(SignedControl(MessageType::kKeepalive, key, 2, 5002), addr, addr_len),
            "new session Keepalive should continue from reset counter");
    Require(manager.slots()[0].stats.packets_received == 3, "new session Keepalive should increment packets received");
    Require(manager.slots()[0].stats.keepalive_received == 1,
            "new session Keepalive should increment keepalive counter");
    Require(manager.slots()[0].last_inbound_counter == 2,
            "new session Keepalive should advance inbound counter");

    Require(!manager.HandleInbound(SignedControl(MessageType::kDisconnect, key, 59, 5001), addr, addr_len),
            "stale old session Disconnect should be rejected after reset guard clears");
    Require(!manager.HandleInbound(SignedControl(MessageType::kBlockChunk, key, 60, 5001), addr, addr_len),
            "stale old session BlockChunk should be rejected after reset guard clears");
    Require(manager.slots()[0].state == PeerState::kActive,
            "post-guard stale old session packets should not change peer state");
    Require(manager.slots()[0].stats.packets_received == 3,
            "post-guard stale old session packets should not increment packets received");
    Require(manager.slots()[0].stats.disconnect_received == 0,
            "post-guard stale old session Disconnect should not increment disconnect counter");
    Require(manager.slots()[0].last_inbound_counter == 2,
            "post-guard stale old session packets should not advance inbound counter");

    Require(manager.HandleInbound(SignedControl(MessageType::kBlockHeader, key, 4, 5002), addr, addr_len),
            "new session should allow monotonic non-handshake counter gaps after reset guard clears");
    Require(manager.slots()[0].stats.packets_received == 4,
            "post-guard non-handshake packet should increment packets received");
    Require(manager.slots()[0].last_inbound_counter == 4,
            "post-guard non-handshake packet should advance inbound counter");
}

void TestCrossFamilyMappedIpv6InboundAccepted()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(110);
    constexpr std::uint16_t kPort = 41009;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);
    Require(!sink.sent.empty(), "expected Syn packet before inbound handling");

    socklen_t addr_len = 0;
    const sockaddr_storage addr = MakeIpv4MappedIpv6Loopback(kPort, addr_len);
    const bool handled = manager.HandleInbound(SignedSynAck(key, 201), addr, addr_len);

    Require(handled, "expected IPv4-mapped IPv6 inbound packet to match IPv4 peer");
    Require(manager.slots()[0].state == PeerState::kActive, "peer should become active");
    Require(manager.slots()[0].stats.synack_received == 1, "synack counter should increment");
}

void TestCrossFamilyNonMappedIpv6InboundRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(120);
    constexpr std::uint16_t kPort = 41010;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);
    Require(!sink.sent.empty(), "expected Syn packet before inbound handling");

    socklen_t addr_len = 0;
    const sockaddr_storage addr = MakeIpv6Loopback(kPort, addr_len);
    const bool handled = manager.HandleInbound(SignedSynAck(key, 202), addr, addr_len);

    Require(!handled, "non-mapped IPv6 inbound packet should not match IPv4 peer");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should remain connecting");
    Require(manager.slots()[0].stats.synack_received == 0, "synack counter should stay unchanged");
}

void TestCrossFamilyMappedIpv6ShortLengthRejected()
{
    MockClock clock{};
    RecordingSink sink;

    const auto key = Key(130);
    constexpr std::uint16_t kPort = 41011;
    PeerManager manager({MakePeer("p1", "127.0.0.1", kPort, key)}, clock, ResolveLoopback);

    manager.Tick(sink);
    Require(!sink.sent.empty(), "expected Syn packet before inbound handling");

    socklen_t addr_len = 0;
    const sockaddr_storage addr = MakeIpv4MappedIpv6Loopback(kPort, addr_len);
    const bool handled = manager.HandleInbound(
        SignedSynAck(key, 203), addr, static_cast<socklen_t>(sizeof(sockaddr_in6) - 1));

    Require(!handled, "short IPv6 sockaddr length should not match");
    Require(manager.slots()[0].state == PeerState::kConnecting, "peer should remain connecting");
    Require(manager.slots()[0].stats.synack_received == 0, "synack counter should stay unchanged");
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"handshake_happy_path", TestHandshakeHappyPath},
        {"outgoing_syn_uses_nonzero_identity", TestOutgoingSynUsesNonZeroIdentity},
        {"default_restarted_peer_session_rebinds_after_reconnect",
         TestDefaultRestartedPeerSessionRebindsAfterReconnect},
        {"inbound_syn_initializes_local_session_and_sends_synack",
         TestInboundSynInitializesLocalSessionAndSendsSynAck},
        {"restarted_peer_syn_replaces_active_session_and_sends_synack",
         TestRestartedPeerSynReplacesActiveSessionAndSendsSynAck},
        {"retired_remote_sessions_use_bounded_exact_history",
         TestRetiredRemoteSessionsUseBoundedExactHistory},
        {"restarted_peer_syn_replaces_stale_session_before_disconnect",
         TestRestartedPeerSynReplacesStaleSessionBeforeDisconnect},
        {"restarted_peer_syn_replaces_disconnected_session_before_retry",
         TestRestartedPeerSynReplacesDisconnectedSessionBeforeRetry},
        {"keepalive_sent_on_timer", TestKeepaliveSentOnTimer},
        {"stale_detection_missed_keepalive", TestStaleDetectionOnMissedKeepalive},
        {"mac_verification_failure", TestMacVerificationFailure},
        {"backoff_doubling_capped", TestBackoffDoublingCapped},
        {"connect_timeout_triggers_reconnect_attempt", TestConnectTimeoutTriggersReconnectAttempt},
        {"no_usable_peers_available_backs_off_cleanly", TestNoUsablePeersAvailableBacksOffCleanly},
        {"reconnect_re_resolves_peer_address", TestReconnectReResolvesPeerAddress},
        {"multiple_independent_peers", TestMultipleIndependentPeers},
        {"disconnect_packet_handling", TestDisconnectPacketHandling},
        {"inbound_zero_counter_rejected", TestInboundZeroCounterRejected},
        {"inbound_zero_session_rejected", TestInboundZeroSessionRejected},
        {"replayed_synack_rejected_before_stats", TestReplayedSynAckRejectedBeforeStats},
        {"replayed_keepalive_does_not_refresh_stale_or_disconnected_peer",
         TestReplayedKeepaliveDoesNotRefreshStaleOrDisconnectedPeer},
        {"replayed_pong_does_not_refresh_stale_or_disconnected_peer",
         TestReplayedPongDoesNotRefreshStaleOrDisconnectedPeer},
        {"replayed_disconnect_rejected_after_handled", TestReplayedDisconnectRejectedAfterHandled},
        {"replayed_ping_does_not_refresh_stale_or_disconnected_peer",
         TestReplayedPingDoesNotRefreshStaleOrDisconnectedPeer},
        {"replayed_block_chunk_does_not_refresh_stale_or_disconnected_peer",
         TestReplayedBlockChunkDoesNotRefreshStaleOrDisconnectedPeer},
        {"lower_inbound_counter_rejected", TestLowerInboundCounterRejected},
        {"inbound_counter_wrap_accepted", TestInboundCounterWrapAccepted},
        {"inbound_counter_wrap_gap_accepted", TestInboundCounterWrapGapAccepted},
        {"stale_low_inbound_counter_far_from_wrap_rejected", TestStaleLowInboundCounterFarFromWrapRejected},
        {"conflicting_synack_session_rejected", TestConflictingSynAckSessionRejected},
        {"reconnect_accepts_new_synack_session_with_reset_counter",
         TestReconnectAcceptsNewSynAckSessionWithResetCounter},
        {"cross_family_mapped_ipv6_inbound_accepted", TestCrossFamilyMappedIpv6InboundAccepted},
        {"cross_family_non_mapped_ipv6_inbound_rejected", TestCrossFamilyNonMappedIpv6InboundRejected},
        {"cross_family_mapped_ipv6_short_length_rejected", TestCrossFamilyMappedIpv6ShortLengthRejected},
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
