// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bip324.h>
#include <bip324_pq.h>
#include <compat/compat.h>
#include <crypto/mlkem.h>
#include <key.h>
#include <logging.h>
#include <net.h>
#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/sock.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using namespace std::literals;

namespace {

//! Messages are never processed: the tests drive the connection manager directly.
class NoMessages final : public NetEventsInterface
{
public:
    //! Nodes deleted, and of those, the ones deleted unfinalized or still holding hybrid secrets.
    int m_deleted{0};
    int m_deleted_unfinalized{0};
    int m_deleted_with_secrets{0};

    void InitializeNode(const CNode&, ServiceFlags) override {}
    //! CConnman calls this right before it deletes the node.
    void FinalizeNode(const CNode& node) override
    {
        ++m_deleted;
        if (!node.m_pq_finalized) ++m_deleted_unfinalized;
        const auto* transport{dynamic_cast<const V2Transport*>(node.m_transport.get())};
        if (transport && transport->HoldsHybridSecretsForTesting()) ++m_deleted_with_secrets;
    }
    bool HasAllDesirableServiceFlags(ServiceFlags) const override { return true; }
    bool HasUndesirableServiceFlags(ServiceFlags) const override { return false; }
    bool ProcessMessages(CNode*, std::atomic<bool>&) override EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) { return false; }
    bool SendMessages(CNode*) override EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) { return false; }
};

//! A DynSock whose Recv() or Send() can fail as if the peer reset the connection.
class FailingSock : public DynSock
{
public:
    using DynSock::DynSock;

    std::atomic<bool> m_fail_recv{false};
    std::atomic<bool> m_fail_send{false};

    ssize_t Recv(void* buf, size_t len, int flags) const override
    {
        return m_fail_recv ? Fail() : DynSock::Recv(buf, len, flags);
    }
    ssize_t Send(const void* buf, size_t len, int flags) const override
    {
        return m_fail_send ? Fail() : DynSock::Send(buf, len, flags);
    }

private:
    FailingSock& operator=(Sock&&) override
    {
        assert(false && "Move of Sock into FailingSock not allowed.");
        return *this;
    }

    static ssize_t Fail()
    {
#ifdef WIN32
        WSASetLastError(WSAECONNRESET);
#else
        errno = ECONNRESET;
#endif
        return -1;
    }
};

//! One connection under test: a CNode on a FailingSock, whose pipes are the peer's side.
struct Link {
    std::shared_ptr<DynSock::Pipes> pipes;
    std::shared_ptr<FailingSock> sock;
    CNode* node;
};

//! The far side of a v2 connection, built by hand: it sends no garbage and any version contents.
class RawPeer
{
    BIP324Cipher m_cipher;
    const bool m_initiator;

public:
    explicit RawPeer(bool initiator) : m_cipher{GenerateRandomKey(), MakeByteSpan(GetRandHash())}, m_initiator{initiator} {}

    std::vector<uint8_t> Key() const
    {
        const EllSwiftPubKey& key{m_cipher.GetOurPubKey()};
        const auto bytes{MakeUCharSpan(std::span{key.data(), key.size()})};
        return {bytes.begin(), bytes.end()};
    }

    void Initialize(std::span<const uint8_t> their_key)
    {
        BOOST_REQUIRE_EQUAL(their_key.size(), EllSwiftPubKey::size());
        m_cipher.Initialize(EllSwiftPubKey{MakeByteSpan(their_key)}, m_initiator);
    }

    //! Our garbage terminator, then a version packet with contents (empty garbage as AAD).
    std::vector<uint8_t> TerminatorAndVersion(std::span<const std::byte> contents, bool damage_tag = false)
    {
        std::vector<uint8_t> out(BIP324Cipher::GARBAGE_TERMINATOR_LEN + BIP324Cipher::EXPANSION + contents.size());
        std::ranges::copy(MakeUCharSpan(m_cipher.GetSendGarbageTerminator()), out.begin());
        m_cipher.Encrypt(contents, /*aad=*/{}, /*ignore=*/false, MakeWritableByteSpan(out).subspan(BIP324Cipher::GARBAGE_TERMINATOR_LEN));
        if (damage_tag) out.back() ^= 0x01;
        return out;
    }
};

/** A record CompactSize(1 + payload size) || header || payload. */
std::vector<std::byte> MakeRecord(uint8_t header, size_t payload_size)
{
    DataStream stream;
    WriteCompactSize(stream, 1 + payload_size);
    stream << header;
    stream.write(std::vector<std::byte>(payload_size, std::byte{0x42}));
    return {stream.begin(), stream.end()};
}

/** The level a line is logged at, as #184's logging table sets it. */
enum class LineLevel { NET_DEBUG, INFO, WARNING };

/**
 * Matches a log line that ends with one of texts, logged at level. The logger prints a level
 * prefix right before the message: "[net] " for a net debug line, "[warning] " for a warning,
 * nothing for an info line. The test setup turns on -logsourcelocations, so without a prefix the
 * bracket right before the message is the function signature.
 */
std::function<bool(const std::string*)> AtLevel(std::vector<std::string> texts, LineLevel level)
{
    BOOST_REQUIRE(LogInstance().m_log_sourcelocations);
    return [texts, level](const std::string* line) {
        if (line == nullptr) return true;
        return std::ranges::any_of(texts, [&](const std::string& text) {
            if (!line->ends_with(text + "\n")) return false;
            const std::string_view head{std::string_view{*line}.substr(0, line->size() - text.size() - 1)};
            const size_t open{head.rfind('[')};
            if (open == std::string_view::npos || !head.ends_with("] ")) return false;
            const std::string_view bracket{head.substr(open)};
            switch (level) {
            case LineLevel::NET_DEBUG: return bracket == "[net] ";
            case LineLevel::WARNING: return bracket == "[warning] ";
            case LineLevel::INFO: return bracket.find('(') != std::string_view::npos;
            }
            return false;
        });
    };
}

/** Expect a log line that is exactly text, logged at level. */
DebugLogHelper ExpectLine(std::string text, LineLevel level) { return DebugLogHelper{text, AtLevel({text}, level)}; }

/** The backends every failure line names. */
std::string Backends()
{
    const auto backends{mlkem::GetBackendNames()};
    return strprintf(" arith=%s keccak=%s", backends.arith, backends.keccak);
}

/** Counts the log lines that contain text while alive. */
class LogLineCounter
{
    const std::string m_text;
    std::list<std::function<void(const std::string&)>>::iterator m_callback;

public:
    std::atomic<int> m_count{0};

    explicit LogLineCounter(std::string text) : m_text{std::move(text)}
    {
        m_callback = LogInstance().PushBackCallback([this](const std::string& line) {
            if (line.find(m_text) != std::string::npos) ++m_count;
        });
    }
    ~LogLineCounter() { LogInstance().DeleteCallback(m_callback); }
};

/** Sets a global while alive, and puts the old value back on every path: a failed BOOST_REQUIRE
 *  throws past the end of the test, and later suites in the same process must not see it. */
template <typename T>
class GlobalOverride
{
    T& m_global;
    T m_previous;

public:
    GlobalOverride(T& global, T value) : m_global{global}, m_previous{std::exchange(global, std::move(value))} {}
    ~GlobalOverride() { m_global = std::move(m_previous); }
    GlobalOverride(const GlobalOverride&) = delete;
    GlobalOverride& operator=(const GlobalOverride&) = delete;
};

/** A CreateSock that hands out sockets with contents, or ZeroSocks without. */
GlobalOverride<decltype(CreateSock)> MockCreateSock(std::string contents = {})
{
    if (contents.empty()) return {CreateSock, [](int, int, int) -> std::unique_ptr<Sock> { return std::make_unique<ZeroSock>(); }};
    return {CreateSock, [contents](int, int, int) -> std::unique_ptr<Sock> { return std::make_unique<StaticContentsSock>(contents); }};
}

/** Clears the SOCKS5 interrupt while alive, and sets it again on every path if it was set. Every
 *  CConnman::Interrupt() sets it, such as an earlier test's at teardown. */
class Socks5InterruptCleared
{
    const bool m_was_set{g_socks5_interrupt};

public:
    Socks5InterruptCleared() { g_socks5_interrupt.reset(); }
    ~Socks5InterruptCleared()
    {
        if (m_was_set) g_socks5_interrupt();
    }
    Socks5InterruptCleared(const Socks5InterruptCleared&) = delete;
    Socks5InterruptCleared& operator=(const Socks5InterruptCleared&) = delete;
};

/** Our outbound node's peer: a responder. */
V2Transport Responder(V2PQOptions pq = {.mode = PQMode::NEGOTIATE}) { return {/*nodeid=*/1000, /*initiating=*/false, pq}; }
/** Our inbound node's peer: an initiator. */
V2Transport Initiator(V2PQOptions pq = {.mode = PQMode::NEGOTIATE}) { return {/*nodeid=*/1000, /*initiating=*/true, pq}; }

/** 64 bytes an initiator could send as its key: any 64 bytes are a valid ElligatorSwift key. */
std::vector<uint8_t> InitiatorKey() { return FastRandomContext{}.randbytes<uint8_t>(EllSwiftPubKey::size()); }

struct PQNetSetup : public RegTestingSetup {
    NoMessages m_events;
    ConnmanTestMsg m_connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    NodeId m_next_id{0};

    PQNetSetup()
    {
        static_assert(PQ_FAILURE_THRESHOLD == 3);
        InitConnman();
        m_connman.SetPeerConnectTimeout(60s);
        SetMockTime(GetTime<std::chrono::seconds>());
        MockableSteadyClock::SetMockTime(STEADY_START);
    }

    ~PQNetSetup()
    {
        m_connman.Stop();
        SetMockTime(0s);
        MockableSteadyClock::ClearMockTime();
    }

    //! Where the mocked steady clock, which drives load shedding, starts.
    static constexpr std::chrono::seconds STEADY_START{3600};

    /** Init() with room for inbound peers, v2 accepted, the given load shedding threshold, and
     *  the given hybrid transport configuration: on by default. */
    void InitConnman(uint64_t shed_threshold = DEFAULT_PQ_SHED_THRESHOLD_PER_S,
                     PQTransportConfig pq = {.v2_enabled = true, .pq_requested = true})
    {
        CConnman::Options options;
        options.m_max_automatic_connections = DEFAULT_MAX_PEER_CONNECTIONS;
        options.m_local_services = NODE_P2P_V2;
        options.pq_shed_threshold_per_s = shed_threshold;
        options.m_pq = pq;
        m_connman.Init(options);
        m_connman.SetMsgProc(&m_events);
    }

    /** An inbound connection through the accept path, with the transport options it gives. */
    Link Accept(const CService& addr = LookupNumeric("10.9.0.1", 50000))
    {
        auto pipes{std::make_shared<DynSock::Pipes>()};
        m_connman.CreateNodeFromAcceptedSocketPublic(std::make_unique<FailingSock>(pipes, std::make_shared<DynSock::Queue>()),
                                                     LookupNumeric("127.0.0.1", 18444), addr);
        CNode* node{m_connman.TestNodes().back()};
        auto sock{std::static_pointer_cast<FailingSock>(WITH_LOCK(node->m_sock_mutex, return node->m_sock))};
        BOOST_REQUIRE(node->IsInboundConn());
        return {pipes, sock, node};
    }

    /** A connection the connection manager holds, as ConnectNode() or the accept path would add it. */
    Link Add(ConnectionType conn_type, PQMode mode = PQMode::NEGOTIATE, std::optional<PQEndpointKey> endpoint = std::nullopt,
             const CService& addr = LookupNumeric("1.2.3.4", 8333))
    {
        auto pipes{std::make_shared<DynSock::Pipes>()};
        auto sock{std::make_shared<FailingSock>(pipes, std::make_shared<DynSock::Queue>())};
        CNode* node{new CNode{m_next_id++, sock, CAddress{addr, NODE_NONE}, /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                              CAddress{}, /*addrNameIn=*/"", conn_type, /*inbound_onion=*/false,
                              CNodeOptions{.use_v2transport = true, .pq = {.mode = mode}, .pq_endpoint = std::move(endpoint)}}};
        node->AddRef(); // the reference m_nodes holds
        m_connman.AddTestNode(*node);
        return {pipes, sock, node};
    }

    /** Two socket handler passes over links: each node sends what it has queued, receives once,
     *  then sends what that queued. */
    void Pass(const std::vector<Link>& links)
    {
        Sock::EventsPerSock events;
        std::vector<CNode*> nodes;
        for (const Link& link : links) {
            events.emplace(link.sock, Sock::Events{Sock::RECV | Sock::SEND}).first->second.occurred = Sock::RECV | Sock::SEND;
            nodes.push_back(link.node);
        }
        m_connman.SocketHandlerConnectedPublic(nodes, events);
        m_connman.SocketHandlerConnectedPublic(nodes, events);
    }
    void Pass(const Link& link) { Pass(std::vector{link}); }

    /** Everything the node sent so far. */
    static std::vector<uint8_t> Sent(const Link& link)
    {
        std::vector<uint8_t> out;
        uint8_t buf[4096];
        ssize_t read;
        while ((read = link.pipes->send.GetBytes(buf, sizeof(buf))) > 0) out.insert(out.end(), buf, buf + read);
        return out;
    }

    /** The node's key, at the start of what it sent; the rest is dropped. */
    static std::vector<uint8_t> NodeKey(const Link& link)
    {
        std::vector<uint8_t> sent{Sent(link)};
        BOOST_REQUIRE(sent.size() >= EllSwiftPubKey::size());
        sent.resize(EllSwiftPubKey::size());
        return sent;
    }

    static void Receive(const Link& link, std::span<const uint8_t> bytes) { link.pipes->recv.PushBytes(bytes.data(), bytes.size()); }

    /** What peer has to send. */
    static std::vector<uint8_t> PeerBytes(Transport& peer)
    {
        std::vector<uint8_t> out;
        while (true) {
            const auto [bytes, more, msg_type] = peer.GetBytesToSend(/*have_next_message=*/false);
            if (bytes.empty()) return out;
            out.insert(out.end(), bytes.begin(), bytes.end());
            peer.MarkBytesSent(bytes.size());
        }
    }

    /** Queue what peer has to send for the node. */
    static void PeerToNode(const Link& link, Transport& peer) { Receive(link, PeerBytes(peer)); }

    /** Feed peer what the node sent; false if peer failed. */
    static bool NodeToPeer(const Link& link, Transport& peer)
    {
        const std::vector<uint8_t> sent{Sent(link)};
        std::span<const uint8_t> bytes{sent};
        while (!bytes.empty()) {
            if (!peer.ReceivedBytes(bytes)) return false;
            if (peer.ReceivedMessageComplete()) {
                bool reject{false};
                peer.GetReceivedMessage({}, reject);
            }
        }
        return true;
    }

    /** Run socket handler passes, moving bytes both ways. A peer that fails gets nothing more, but
     *  what it queued before still reaches the node. */
    void Exchange(const Link& link, Transport& peer)
    {
        bool peer_failed{false};
        for (int round{0}; round < 10; ++round) {
            PeerToNode(link, peer);
            Pass(link);
            if (peer_failed) {
                Sent(link);
            } else {
                peer_failed = !NodeToPeer(link, peer);
            }
        }
    }

    /** Remove the disconnected nodes; those with a reference left stay in the disconnected pool. */
    void Disconnect() { m_connman.DisconnectNodesPublic(); }

    PQTransportStats Stats() const { return m_connman.GetPQTransportStats(); }

    /** How a test connection ends. */
    enum class End { MALFORMED, CONFIRMATION, PEER_EOF, PEER_RESET, TIMEOUT, LOCAL, SEND_ERROR, LEGACY, SUCCESS };

    /** One outbound connection to endpoint that ends as end; the connection manager finalizes it. */
    void Connect(const PQEndpointKey& endpoint, End end)
    {
        Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, endpoint)};
        switch (end) {
        case End::MALFORMED: { // an offer of the wrong length
            Pass(link);
            RawPeer peer{/*initiator=*/false};
            peer.Initialize(NodeKey(link));
            Receive(link, peer.Key());
            Receive(link, peer.TerminatorAndVersion(MakeRecord(PQ_MLKEM1024, 100)));
            Pass(link);
            break;
        }
        case End::CONFIRMATION: {
            V2Transport peer{Responder({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true})};
            Exchange(link, peer);
            break;
        }
        case End::LEGACY:
        case End::SUCCESS: {
            // Not `cond ? a : b`: MSVC requires a copy constructor for a conditional of
            // prvalues, and V2Transport has none.
            V2Transport peer{[&] { if (end == End::LEGACY) return Responder({}); return Responder(); }()};
            Exchange(link, peer);
            BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().confirmed == (end == End::SUCCESS));
            link.node->RequestDisconnect();
            break;
        }
        case End::PEER_EOF:
        case End::PEER_RESET:
        case End::TIMEOUT:
        case End::LOCAL:
        case End::SEND_ERROR: { // we switch, and the connection closes before the peer's confirmation
            V2Transport peer{Responder()};
            Pass(link);
            BOOST_REQUIRE(NodeToPeer(link, peer));
            PeerToNode(link, peer);
            if (end == End::SEND_ERROR) link.sock->m_fail_send = true;
            Pass(link);
            BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().switched);
            if (end == End::PEER_EOF) link.pipes->recv.Eof();
            if (end == End::PEER_RESET) link.sock->m_fail_recv = true;
            if (end == End::TIMEOUT) SetMockTime(GetTime<std::chrono::seconds>() + 61s);
            if (end == End::LOCAL) link.node->RequestDisconnect();
            Pass(link);
            break;
        }
        }
        BOOST_REQUIRE(link.node->fDisconnect);
        Disconnect();
    }

    std::optional<PQStreakStats> Streak(const PQEndpointKey& endpoint) const
    {
        for (const PQStreakStats& streak : Stats().failure_streaks) {
            if (streak.endpoint == endpoint) return streak;
        }
        return std::nullopt;
    }

    std::optional<PQFallbackStats> Fallback(const PQEndpointKey& endpoint) const
    {
        for (const PQFallbackStats& fallback : Stats().fallback_set) {
            if (fallback.endpoint == endpoint) return fallback;
        }
        return std::nullopt;
    }
};

/** A distinct outbound endpoint per index. */
PQEndpointKey TestEndpoint(uint8_t subnet, int index)
{
    return LookupNumeric(strprintf("10.%d.%d.%d", subnet, index / 250, 1 + index % 250), 8333);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(net_pq_tests, PQNetSetup)

BOOST_AUTO_TEST_CASE(pq_endpoint_identity)
{
    // Name-proxy destinations: lowercase ASCII, one trailing root dot removed, the port kept.
    BOOST_CHECK(MakePQNameEndpoint("Example.COM.", 8444) == (PQNameEndpoint{"example.com", 8444}));
    BOOST_CHECK(MakePQNameEndpoint("example.com", 8444) == MakePQNameEndpoint("EXAMPLE.com.", 8444));
    BOOST_CHECK(MakePQNameEndpoint("example.com..", 8444) == (PQNameEndpoint{"example.com.", 8444}));
    BOOST_CHECK(MakePQNameEndpoint("example.com", 8444) != MakePQNameEndpoint("example.com", 8445));
    BOOST_CHECK(MakePQNameEndpoint("example.com", 8444) != MakePQNameEndpoint("example.org", 8444));
    BOOST_CHECK(MakePQNameEndpoint("\xC3\x84" "B.example", 1) == (PQNameEndpoint{"\xC3\x84" "b.example", 1})); // ASCII only

    // Resolved destinations keep the address and the port.
    const CService ipv4{LookupNumeric("1.2.3.4", 8333)};
    const PQEndpointKey a{ipv4};
    BOOST_CHECK(a != PQEndpointKey{LookupNumeric("1.2.3.4", 8334)});
    BOOST_CHECK(a != PQEndpointKey{LookupNumeric("2001:db8::1", 8333)});
    BOOST_CHECK(a == PQEndpointKey{LookupNumeric("::ffff:1.2.3.4", 8333)}); // the same IPv4 address
    // Private addresses share a network class, NET_UNROUTABLE, but stay distinct endpoints.
    BOOST_CHECK(PQEndpointKey{LookupNumeric("10.0.0.1", 8333)} != PQEndpointKey{LookupNumeric("10.0.0.2", 8333)});
    // A name never aliases an address, even one that spells the same.
    BOOST_CHECK(a != PQEndpointKey{MakePQNameEndpoint("1.2.3.4", 8333)});

    // A map keyed by endpoint orders them strictly.
    std::map<PQEndpointKey, int> keys;
    for (const PQEndpointKey& key : {a, PQEndpointKey{LookupNumeric("1.2.3.4", 8334)}, PQEndpointKey{MakePQNameEndpoint("A.example", 1)},
                                     PQEndpointKey{MakePQNameEndpoint("a.example.", 1)}, PQEndpointKey{MakePQNameEndpoint("b.example", 1)}}) {
        ++keys[key];
    }
    BOOST_CHECK_EQUAL(keys.size(), 4U);

    // A node without a captured endpoint uses its address and port.
    Link plain{Add(ConnectionType::OUTBOUND_FULL_RELAY)};
    BOOST_CHECK(plain.node->m_pq_endpoint == a);
    Link named{Add(ConnectionType::MANUAL, PQMode::NEGOTIATE, MakePQNameEndpoint("Seed.Example.", 18444), CService{})};
    BOOST_CHECK(named.node->m_pq_endpoint == PQEndpointKey{(PQNameEndpoint{"seed.example", 18444})});

    // Outbound construction captures the resolved destination and port.
    {
        const auto create_sock{MockCreateSock()};
        const std::unique_ptr<CNode> outbound{m_connman.ConnectNodeOnly("5.6.7.8:18555", ConnectionType::MANUAL, /*use_v2transport=*/true)};
        BOOST_REQUIRE(outbound);
        BOOST_CHECK(outbound->m_pq_endpoint == PQEndpointKey{LookupNumeric("5.6.7.8", 18555)});
        const std::unique_ptr<CNode> ipv6{m_connman.ConnectNodeOnly("[2a01:4f8::2]:18555", ConnectionType::MANUAL, /*use_v2transport=*/true)};
        BOOST_REQUIRE(ipv6);
        BOOST_CHECK(ipv6->m_pq_endpoint == PQEndpointKey{LookupNumeric("2a01:4f8::2", 18555)});
    }

    // Inbound uses the actual remote address and source port.
    m_connman.CreateNodeFromAcceptedSocketPublic(std::make_unique<ZeroSock>(), LookupNumeric("127.0.0.1", 18444), LookupNumeric("9.8.7.6", 51234));
    const std::vector<CNode*> nodes{m_connman.TestNodes()};
    BOOST_REQUIRE(!nodes.empty());
    BOOST_CHECK(nodes.back()->IsInboundConn());
    BOOST_CHECK(nodes.back()->m_pq_endpoint == PQEndpointKey{LookupNumeric("9.8.7.6", 51234)});
}

BOOST_AUTO_TEST_CASE(proxy_settings_restorer)
{
    // The guard puts back exactly what was set before it, nested or not.
    BOOST_REQUIRE(!HaveNameProxy());
    Proxy proxy;
    BOOST_REQUIRE(!GetProxy(NET_IPV4, proxy));
    {
        ProxySettingsRestorerForTesting outer;
        BOOST_REQUIRE(SetNameProxy(Proxy{LookupNumeric("127.0.0.1", 9050)}));
        {
            ProxySettingsRestorerForTesting inner;
            BOOST_REQUIRE(SetNameProxy(Proxy{LookupNumeric("127.0.0.2", 9050)}));
            BOOST_REQUIRE(SetProxy(NET_IPV4, Proxy{LookupNumeric("127.0.0.3", 9050)}));
        }
        BOOST_REQUIRE(GetNameProxy(proxy));
        BOOST_CHECK(proxy.proxy == LookupNumeric("127.0.0.1", 9050));
        BOOST_CHECK(!GetProxy(NET_IPV4, proxy));
    }
    BOOST_CHECK(!HaveNameProxy());
    BOOST_CHECK(!GetProxy(NET_IPV4, proxy));
}

BOOST_AUTO_TEST_CASE(pq_name_proxy_endpoint)
{
    // Through a name proxy, a destination by name is never resolved locally: ConnectNode() asks
    // the proxy for it, and the endpoint key is the normalized SOCKS destination and the
    // effective port, never the proxy's own address.
    const CService proxy{LookupNumeric("127.0.0.9", 9050)};
    {
        const Socks5InterruptCleared socks5_interrupt;
        ProxySettingsRestorerForTesting restore_proxies;
        BOOST_REQUIRE(SetNameProxy(Proxy{proxy}));
        // The proxy accepts without authentication, then reports the connection made.
        const auto create_sock{MockCreateSock(std::string{"\x05\x00" "\x05\x00\x00\x01" "\x00\x00\x00\x00" "\x00\x00", 12})};
        for (const auto& [dest, key] : {std::pair{"Seed.Example.COM.:18555", PQNameEndpoint{"seed.example.com", 18555}},
                                        std::pair{"seed.example.com", PQNameEndpoint{"seed.example.com", Params().GetDefaultPort()}},
                                        std::pair{"other.example:18555", PQNameEndpoint{"other.example", 18555}}}) {
            const std::unique_ptr<CNode> node{m_connman.ConnectNodeOnly(dest, ConnectionType::MANUAL, /*use_v2transport=*/true)};
            BOOST_REQUIRE(node);
            BOOST_CHECK(node->m_pq_endpoint == PQEndpointKey{key});
            BOOST_CHECK(node->m_pq_endpoint != PQEndpointKey{proxy});
        }
    }
    // No later test sees the name proxy.
    BOOST_CHECK(!HaveNameProxy());
}

BOOST_AUTO_TEST_CASE(pq_observation_once)
{
    // A hybrid handshake: switched once, however often it is observed.
    Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY)};
    link.node->AddRef(); // keep the node through DisconnectNodes()
    V2Transport peer{Responder()};
    Exchange(link, peer);
    BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().confirmed);
    BOOST_CHECK(link.node->m_transport->GetInfo().transport_pq_status == PQStatus::HYBRID);
    for (int i{0}; i < 3; ++i) m_connman.ObservePQPublic(*link.node, /*finalizing=*/false);
    BOOST_CHECK_EQUAL(Stats().outbound.switched, 1U);

    // A switch whose confirmation fails, seen after receive, at disconnect and in cleanup.
    Link failing{Add(ConnectionType::OUTBOUND_FULL_RELAY)};
    failing.node->AddRef();
    V2Transport bad_peer{Responder({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true})};
    Exchange(failing, bad_peer);
    BOOST_REQUIRE(failing.node->fDisconnect);
    m_connman.ObservePQPublic(*failing.node, /*finalizing=*/false);
    PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.outbound.switched, 2U);
    BOOST_CHECK_EQUAL(stats.outbound.first_packet_failed, 1U);
    BOOST_CHECK_EQUAL(stats.outbound_failures.entries.size(), 1U);

    // Racing observers, as from the socket handler and cleanup, still count each event once.
    std::vector<std::thread> threads;
    for (int i{0}; i < 4; ++i) {
        threads.emplace_back([&, i] { m_connman.ObservePQPublic(*failing.node, /*finalizing=*/i % 2 == 0); });
    }
    for (auto& thread : threads) thread.join();
    Disconnect();
    for (const Link& l : {link, failing}) {
        m_connman.ObservePQPublic(*l.node, /*finalizing=*/false);
        m_connman.ObservePQPublic(*l.node, /*finalizing=*/true);
        BOOST_CHECK(l.node->m_pq_finalized);
    }
    stats = Stats();
    BOOST_CHECK_EQUAL(stats.outbound.switched, 2U);
    BOOST_CHECK_EQUAL(stats.outbound.first_packet_failed, 1U);
    BOOST_CHECK_EQUAL(stats.outbound.closed_after_switch, 0U); // our own close after the failure
    BOOST_CHECK_EQUAL(stats.outbound_failures.entries.size(), 1U);
    BOOST_CHECK_EQUAL(stats.outbound_failures.last_sequence, 1U);
    BOOST_CHECK_EQUAL(stats.inbound.switched + stats.inbound.first_packet_failed, 0U);
    BOOST_CHECK(stats.inbound_failures.entries.empty());
    for (const Link& l : {link, failing}) l.node->Release();
    Disconnect();

    // Instance identity: random per connection manager, counted from its creation.
    ConnmanTestMsg other{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    BOOST_CHECK(other.GetPQTransportStats().instance_id != stats.instance_id);
    BOOST_CHECK(stats.since <= Now<NodeSeconds>());
    BOOST_CHECK_EQUAL(other.GetPQTransportStats().outbound.switched, 0U);
}

BOOST_AUTO_TEST_CASE(pq_ring_bounds)
{
    // One outbound failure: the responder offers no features.
    Link outbound{Add(ConnectionType::MANUAL)};
    V2Transport legacy{Responder({})};
    Exchange(outbound, legacy);
    BOOST_CHECK_EQUAL(Stats().outbound.legacy_peer, 1U);

    // 300 inbound failures: each offer is abandoned when the peer closes.
    std::vector<Link> inbound;
    for (int i{0}; i < 300; ++i) {
        inbound.push_back(Add(ConnectionType::INBOUND, PQMode::NEGOTIATE, std::nullopt, LookupNumeric("10.0.0.1", 40000 + i)));
        Receive(inbound.back(), InitiatorKey());
    }
    Pass(inbound);
    for (const Link& link : inbound) {
        BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().offer == PQOfferState::SENT);
        link.pipes->recv.Eof();
    }
    Pass(inbound);
    Disconnect();

    const PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.inbound.abandoned, 300U);
    BOOST_CHECK_EQUAL(stats.inbound_failures.entries.size(), PQ_FAILURE_RING_SIZE);
    BOOST_CHECK_EQUAL(stats.inbound_failures.dropped, 44U);
    BOOST_CHECK_EQUAL(stats.inbound_failures.last_sequence, 300U);
    for (size_t i{0}; i < stats.inbound_failures.entries.size(); ++i) {
        const PQFailureEntry& entry{stats.inbound_failures.entries[i]};
        BOOST_CHECK_EQUAL(entry.sequence, 45 + i);
        BOOST_CHECK(entry.inbound);
        BOOST_CHECK(entry.outcome == PQOutcome::ABANDONED);
        BOOST_CHECK_EQUAL(entry.reason, "eof");
    }
    BOOST_CHECK(stats.inbound_failures.entries.back().endpoint == PQEndpointKey{LookupNumeric("10.0.0.1", 40299)});

    // The outbound entry survives, with its own sequence.
    BOOST_REQUIRE_EQUAL(stats.outbound_failures.entries.size(), 1U);
    const PQFailureEntry& entry{stats.outbound_failures.entries.front()};
    BOOST_CHECK_EQUAL(entry.sequence, 1U);
    BOOST_CHECK_EQUAL(stats.outbound_failures.last_sequence, 1U);
    BOOST_CHECK_EQUAL(stats.outbound_failures.dropped, 0U);
    BOOST_CHECK(entry.outcome == PQOutcome::LEGACY_PEER);
    BOOST_CHECK_EQUAL(entry.reason, "no_features");
    BOOST_CHECK(!entry.inbound);
    BOOST_CHECK(entry.connection_type == ConnectionType::MANUAL);
    BOOST_CHECK_EQUAL(entry.peer_id, outbound.node->GetId());
    BOOST_CHECK(entry.endpoint == PQEndpointKey{LookupNumeric("1.2.3.4", 8333)});
    BOOST_CHECK(entry.time == Now<NodeSeconds>());
}

BOOST_AUTO_TEST_CASE(pq_switched_then_failed)
{
    for (const bool inbound : {false, true}) {
        Link link{Add(inbound ? ConnectionType::INBOUND : ConnectionType::OUTBOUND_FULL_RELAY)};
        // Not `cond ? a : b`: MSVC requires a copy constructor for a conditional of
        // prvalues, and V2Transport has none.
        V2Transport peer{[&] { if (inbound) return Initiator({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true}); return Responder({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true}); }()};
        Exchange(link, peer);
        const PQHandshake::Snapshot snapshot{link.node->m_transport->GetPQSnapshot()};
        BOOST_CHECK(snapshot.switched);
        BOOST_CHECK(snapshot.failure == PQFailure::CONFIRM_LENGTH || snapshot.failure == PQFailure::CONFIRM_TAG);
        BOOST_CHECK(link.node->fDisconnect);
        Disconnect();
        const PQTransportStats stats{Stats()};
        const PQCounts& counts{inbound ? stats.inbound : stats.outbound};
        BOOST_CHECK_EQUAL(counts.switched, 1U);
        BOOST_CHECK_EQUAL(counts.first_packet_failed, 1U);
        BOOST_CHECK_EQUAL(counts.closed_after_switch + counts.abandoned + counts.malformed_record, 0U);
        const PQFailureRing& ring{inbound ? stats.inbound_failures : stats.outbound_failures};
        BOOST_REQUIRE_EQUAL(ring.entries.size(), 1U);
        BOOST_CHECK(ring.entries.front().outcome == PQOutcome::FIRST_PACKET_FAILED);
        BOOST_CHECK(ring.entries.front().reason == "length" || ring.entries.front().reason == "tag");
    }
}

BOOST_AUTO_TEST_CASE(pq_abandoned)
{
    // An offer is queued, and the connection closes before an authenticated version arrives.
    struct Case {
        std::string reason;
        std::function<void(PQNetSetup&, const Link&, RawPeer&)> close;
    };
    const std::vector<Case> cases{
        {"eof", [](PQNetSetup&, const Link& link, RawPeer&) { link.pipes->recv.Eof(); }},
        {"reset", [](PQNetSetup&, const Link& link, RawPeer&) { link.sock->m_fail_recv = true; }},
        {"timeout", [](PQNetSetup&, const Link&, RawPeer&) { SetMockTime(GetTime<std::chrono::seconds>() + 61s); }},
        {"local", [](PQNetSetup& setup, const Link& link, RawPeer&) { BOOST_CHECK(setup.m_connman.DisconnectNode(link.node->GetId())); }},
        // The peer's version packet doesn't authenticate.
        {"version_tag", [](PQNetSetup&, const Link& link, RawPeer& peer) {
             Receive(link, peer.TerminatorAndVersion({}, /*damage_tag=*/true));
         }},
        // The peer's version packet is longer than any packet may be.
        {"version_length", [](PQNetSetup&, const Link& link, RawPeer& peer) {
             const auto packet{peer.TerminatorAndVersion(std::vector<std::byte>(MAX_PROTOCOL_MESSAGE_LENGTH + 14))};
             Receive(link, std::span{packet}.first(BIP324Cipher::GARBAGE_TERMINATOR_LEN + BIP324Cipher::LENGTH_LEN));
         }},
        // No garbage terminator in the longest garbage allowed.
        {"garbage_terminator", [](PQNetSetup&, const Link& link, RawPeer&) {
             Receive(link, std::vector<uint8_t>(V2Transport::MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN, 0));
         }},
    };
    for (const Case& test : cases) {
        BOOST_TEST_MESSAGE("abandoned: " + test.reason);
        // The peer sends its key, so the node offers, and then not the version it is asked for.
        Link link{Add(ConnectionType::INBOUND, PQMode::NEGOTIATE, std::nullopt, LookupNumeric("10.0.0.2", 50000))};
        RawPeer peer{/*initiator=*/true};
        Receive(link, peer.Key());
        Pass(link);
        BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().offer == PQOfferState::SENT);
        peer.Initialize(NodeKey(link));
        test.close(*this, link, peer);
        for (int i{0}; i < 4; ++i) Pass(link);
        BOOST_CHECK(link.node->fDisconnect);
        const auto line{ExpectLine(strprintf("v2 pq: abandoned reason=%s role=responder conn_type=inbound peer=%d", test.reason, link.node->GetId()),
                                   LineLevel::NET_DEBUG)};
        Disconnect();
    }
    // A failed send of the queued offer.
    {
        Link link{Add(ConnectionType::INBOUND)};
        Receive(link, InitiatorKey());
        link.sock->m_fail_send = true;
        Pass(link); // receives the key and queues the offer
        Pass(link); // the send fails
        BOOST_CHECK(link.node->GetCloseCause() == NodeCloseCause::SEND_ERROR);
        Disconnect();
    }

    const PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.inbound.abandoned, cases.size() + 1);
    BOOST_CHECK_EQUAL(stats.inbound.switched, 0U);
    BOOST_REQUIRE_EQUAL(stats.inbound_failures.entries.size(), cases.size() + 1);
    for (size_t i{0}; i < cases.size(); ++i) BOOST_CHECK_EQUAL(stats.inbound_failures.entries[i].reason, cases[i].reason);
    BOOST_CHECK_EQUAL(stats.inbound_failures.entries.back().reason, "send_error");
    BOOST_CHECK(stats.inbound_failures.entries.front().endpoint == PQEndpointKey{LookupNumeric("10.0.0.2", 50000)});
    BOOST_CHECK(stats.outbound_failures.entries.empty());

    // An offer the peer answered is not abandoned, however the connection ends.
    Link answered{Add(ConnectionType::INBOUND)};
    V2Transport peer{Initiator({})};
    Exchange(answered, peer);
    BOOST_CHECK(answered.node->m_transport->GetPQSnapshot().legacy == PQLegacyReason::NO_FEATURES);
    answered.pipes->recv.Eof();
    Pass(answered);
    Disconnect();
    BOOST_CHECK_EQUAL(Stats().inbound.abandoned, cases.size() + 1);
    BOOST_CHECK_EQUAL(Stats().inbound.legacy_peer, 1U);
}

BOOST_AUTO_TEST_CASE(pq_outbound_never_abandoned)
{
    // Only responders offer, so an outbound connection that closes before the peer's version is
    // never abandoned, whoever closes it: the outbound count stays 0 and its ring stays empty.
    for (const bool peer_closes : {true, false}) {
        Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, TestEndpoint(10, peer_closes ? 1 : 2))};
        Pass(link);
        Receive(link, InitiatorKey()); // any 64 bytes are a valid key, here the responder's
        Pass(link);
        BOOST_REQUIRE(!link.node->m_transport->GetPQSnapshot().version_received);
        if (peer_closes) {
            link.pipes->recv.Eof();
        } else {
            link.node->RequestDisconnect();
        }
        Pass(link);
        BOOST_REQUIRE(link.node->fDisconnect);
        Disconnect();
    }
    const PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.outbound.abandoned, 0U);
    BOOST_CHECK(stats.outbound_failures.entries.empty());
}

BOOST_AUTO_TEST_CASE(pq_closed_after_switch)
{
    // We switched, and the peer closed or stopped responding before its confirmation arrived.
    // Each connection goes to its own endpoint, so none enters the fallback set.
    uint16_t port{8000};
    for (const std::string cause : {"eof", "reset", "timeout", "local", "send_error"}) {
        Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, LookupNumeric("1.2.3.4", ++port))};
        V2Transport peer{Responder()};
        Pass(link); // our key and garbage
        BOOST_REQUIRE(NodeToPeer(link, peer));
        PeerToNode(link, peer); // the peer's key, garbage, terminator and offer
        if (cause == "send_error") link.sock->m_fail_send = true;
        Pass(link);
        BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().switched);
        if (cause == "eof") link.pipes->recv.Eof();
        if (cause == "reset") link.sock->m_fail_recv = true;
        if (cause == "timeout") SetMockTime(GetTime<std::chrono::seconds>() + 61s);
        if (cause == "local") link.node->RequestDisconnect();
        Pass(link);
        Pass(link);
        BOOST_REQUIRE(link.node->fDisconnect);
        const bool counted{cause == "eof" || cause == "reset" || cause == "timeout"};
        // Count the lines rather than require one, so that a missing line fails the check instead
        // of throwing from a destructor.
        const std::string text{strprintf("v2 pq: closed_after_switch cause=%s role=initiator conn_type=outbound-full-relay peer=%d%s",
                                         cause, link.node->GetId(), Backends())};
        const auto expected{AtLevel({text}, LineLevel::INFO)};
        int lines{0}, expected_lines{0};
        const uint64_t before{Stats().outbound.closed_after_switch};
        {
            DebugLogHelper watch{"v2 pq: closed_after_switch", [&](const std::string* line) {
                                     if (line) {
                                         ++lines;
                                         if (expected(line)) ++expected_lines;
                                     }
                                     return false;
                                 }};
            Disconnect();
        }
        BOOST_CHECK_EQUAL(lines, counted ? 1 : 0);
        BOOST_CHECK_EQUAL(expected_lines, counted ? 1 : 0);
        BOOST_CHECK_EQUAL(Stats().outbound.closed_after_switch, before + (counted ? 1 : 0));
    }
    const PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.outbound.switched, 5U);
    BOOST_CHECK_EQUAL(stats.outbound.closed_after_switch, 3U);
    BOOST_REQUIRE_EQUAL(stats.outbound_failures.entries.size(), 3U);
    BOOST_CHECK_EQUAL(stats.outbound_failures.entries[2].reason, "timeout");

    // An inbound switch closed by the peer is not counted: closed_after_switch is outbound only.
    Link inbound{Add(ConnectionType::INBOUND)};
    V2Transport peer{Initiator()};
    PeerToNode(inbound, peer);
    Pass(inbound);
    BOOST_REQUIRE(NodeToPeer(inbound, peer));
    const std::vector<uint8_t> accept{PeerBytes(peer)}; // and the confirmation, held back
    Receive(inbound, std::span{accept}.first(accept.size() - PQ_CONFIRMATION_BYTES));
    Pass(inbound);
    BOOST_REQUIRE(inbound.node->m_transport->GetPQSnapshot().switched);
    BOOST_REQUIRE(!inbound.node->m_transport->GetPQSnapshot().confirmed);
    inbound.pipes->recv.Eof();
    Pass(inbound);
    Disconnect();
    BOOST_CHECK_EQUAL(Stats().inbound.switched, 1U);
    BOOST_CHECK_EQUAL(Stats().inbound.closed_after_switch + Stats().inbound.abandoned, 0U);

    // After a confirmed handshake, a peer close or a timeout is an ordinary close: nothing is
    // counted, the ring gets no entry, and nothing is logged.
    int lines{0};
    {
        DebugLogHelper watch{"v2 pq: closed_after_switch", [&](const std::string* line) {
                                 if (line) ++lines;
                                 return false;
                             }};
        for (const NodeCloseCause cause : {NodeCloseCause::PEER_EOF, NodeCloseCause::PEER_RESET, NodeCloseCause::TIMEOUT}) {
            Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, LookupNumeric("1.2.3.6", 8333))};
            V2Transport responder{Responder()};
            Exchange(link, responder);
            BOOST_REQUIRE(link.node->m_transport->GetPQSnapshot().confirmed);
            if (cause == NodeCloseCause::PEER_EOF) link.pipes->recv.Eof();
            if (cause == NodeCloseCause::PEER_RESET) link.sock->m_fail_recv = true;
            if (cause == NodeCloseCause::TIMEOUT) SetMockTime(GetTime<std::chrono::seconds>() + 61s);
            Pass(link);
            BOOST_REQUIRE(link.node->GetCloseCause() == cause);
            Disconnect();
        }
    }
    BOOST_CHECK_EQUAL(lines, 0);
    BOOST_CHECK_EQUAL(Stats().outbound.switched, stats.outbound.switched + 3);
    BOOST_CHECK_EQUAL(Stats().outbound.closed_after_switch, stats.outbound.closed_after_switch);
    BOOST_CHECK_EQUAL(Stats().outbound_failures.last_sequence, stats.outbound_failures.last_sequence);
}

BOOST_AUTO_TEST_CASE(pq_log_lines)
{
    // Outbound failures are info lines; inbound lines and outbound successes are net debug lines.
    const auto line{[](std::string_view text, const Link& link, bool failure) {
        return ExpectLine(strprintf("v2 pq: %s conn_type=%s peer=%d%s", text, link.node->ConnectionTypeAsString(), link.node->GetId(),
                                    failure ? Backends() : ""),
                          failure && !link.node->IsInboundConn() ? LineLevel::INFO : LineLevel::NET_DEBUG);
    }};

    // Outbound: a hybrid handshake, a legacy peer, malformed records, a parse error.
    {
        Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY)};
        V2Transport peer{Responder()};
        const auto expect{line("switched role=initiator", link, false)};
        Exchange(link, peer);
    }
    {
        Link link{Add(ConnectionType::BLOCK_RELAY)};
        V2Transport peer{Responder({})};
        const auto expect{line("legacy_peer reason=no_features role=initiator", link, false)};
        Exchange(link, peer);
    }
    const auto raw_responder{[&](const Link& link, std::span<const std::byte> contents) {
        Pass(link);
        RawPeer peer{/*initiator=*/false};
        peer.Initialize(NodeKey(link));
        Receive(link, peer.Key());
        Receive(link, peer.TerminatorAndVersion(contents));
        Pass(link);
    }};
    {
        Link link{Add(ConnectionType::MANUAL)};
        const auto expect{line("legacy_peer reason=parse_error role=initiator", link, false)};
        raw_responder(link, std::vector{std::byte{0x05}, std::byte{0x01}});
    }
    {
        Link link{Add(ConnectionType::MANUAL)};
        const auto expect{line("malformed_record reason=ek_length role=initiator", link, true)};
        raw_responder(link, MakeRecord(PQ_MLKEM1024, 100));
        BOOST_CHECK(link.node->fDisconnect);
        // A closing connection reports pending until it is removed.
        BOOST_CHECK(link.node->m_transport->GetInfo().transport_pq_status == PQStatus::PENDING);
    }
    // With mismatched keys, the confirmation's length decrypts to a random value, rarely to 0.
    const auto confirm_failed{[](const Link& link, std::string_view role) {
        std::vector<std::string> texts;
        for (const std::string_view reason : {"length", "tag"}) {
            texts.push_back(strprintf("v2 pq: first_packet_failed reason=%s role=%s conn_type=%s peer=%d%s", reason, role,
                                      link.node->ConnectionTypeAsString(), link.node->GetId(), Backends()));
        }
        return DebugLogHelper{"v2 pq: first_packet_failed reason=", AtLevel(texts, role == "initiator" ? LineLevel::INFO : LineLevel::NET_DEBUG)};
    }};
    {
        Link link{Add(ConnectionType::FEELER)};
        const auto expect{confirm_failed(link, "initiator")};
        V2Transport peer{Responder({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true})};
        Exchange(link, peer);
    }
    {
        // A local fault before we committed: the connection continues as plain v2, status off.
        Link link{Add(ConnectionType::ADDR_FETCH)};
        const auto expect{line("internal_error reason=encaps role=initiator", link, true)};
        V2Transport peer{Responder()};
        mlkem::InjectResultForTesting inject{mlkem::Operation::ENCAPS, mlkem::upstream::ERR_FAIL};
        Exchange(link, peer);
        BOOST_CHECK(!link.node->fDisconnect);
        BOOST_CHECK(link.node->m_transport->GetInfo().transport_pq_status == PQStatus::OFF);
    }

    // Inbound: the same outcomes, at debug level from their own call sites.
    {
        Link link{Add(ConnectionType::INBOUND)};
        V2Transport peer{Initiator()};
        const auto expect{line("switched role=responder", link, false)};
        Exchange(link, peer);
        BOOST_CHECK(link.node->m_transport->GetPQSnapshot().confirmed);
    }
    {
        Link link{Add(ConnectionType::INBOUND)};
        V2Transport peer{Initiator({})};
        const auto expect{line("legacy_peer reason=no_features role=responder", link, false)};
        Exchange(link, peer);
    }
    const auto raw_initiator{[&](const Link& link, std::span<const std::byte> contents) {
        RawPeer peer{/*initiator=*/true};
        Receive(link, peer.Key());
        Pass(link);
        peer.Initialize(NodeKey(link));
        Receive(link, peer.TerminatorAndVersion(contents));
        Pass(link);
    }};
    {
        Link link{Add(ConnectionType::INBOUND)};
        const auto expect{line("legacy_peer reason=parse_error role=responder", link, false)};
        raw_initiator(link, std::vector{std::byte{0x05}, std::byte{0x01}});
    }
    {
        Link link{Add(ConnectionType::INBOUND)};
        const auto expect{line("malformed_record reason=ct_length role=responder", link, true)};
        raw_initiator(link, MakeRecord(PQ_MLKEM1024, 100));
    }
    {
        Link link{Add(ConnectionType::INBOUND)};
        const auto expect{confirm_failed(link, "responder")};
        V2Transport peer{Initiator({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true})};
        Exchange(link, peer);
    }
    {
        Link link{Add(ConnectionType::INBOUND)};
        const auto expect{line("internal_error reason=keygen role=responder", link, true)};
        mlkem::InjectResultForTesting inject{mlkem::Operation::KEYGEN, mlkem::upstream::ERR_FAIL};
        Receive(link, InitiatorKey());
        Pass(link);
        // No offer, so the connection continues as plain v2, status off.
        BOOST_CHECK(!link.node->fDisconnect);
        BOOST_CHECK(link.node->m_transport->GetInfo().transport_pq_status == PQStatus::OFF);
    }
    {
        Link link{Add(ConnectionType::INBOUND)};
        const auto expect{line("internal_error reason=decaps role=responder", link, true)};
        V2Transport peer{Initiator()};
        mlkem::InjectResultForTesting inject{mlkem::Operation::DECAPS, mlkem::upstream::ERR_FAIL};
        Exchange(link, peer);
        // The initiator has committed, so this local fault closes, and reports pending until the
        // connection is removed. Counting reads the failure, never the status.
        BOOST_CHECK(link.node->fDisconnect);
        BOOST_CHECK(link.node->m_transport->GetInfo().transport_pq_status == PQStatus::PENDING);
    }

    // -logips adds the peer's address.
    {
        Link link{Add(ConnectionType::MANUAL)};
        V2Transport peer{Responder()};
        const GlobalOverride log_ips{fLogIPs, true};
        const auto expect{ExpectLine(strprintf("v2 pq: switched role=initiator conn_type=manual peer=%d peeraddr=1.2.3.4:8333", link.node->GetId()),
                                     LineLevel::NET_DEBUG)};
        Exchange(link, peer);
    }
    Disconnect();

    const PQTransportStats stats{Stats()};
    for (const PQCounts& counts : {stats.inbound, stats.outbound}) {
        BOOST_CHECK_EQUAL(counts.legacy_peer, 2U);
        BOOST_CHECK_EQUAL(counts.malformed_record, 1U);
        BOOST_CHECK_EQUAL(counts.first_packet_failed, 1U);
    }
    BOOST_CHECK_EQUAL(stats.outbound.switched, 3U); // hybrid, corrupted, -logips
    BOOST_CHECK_EQUAL(stats.outbound.internal_error, 1U);
    BOOST_CHECK_EQUAL(stats.inbound.switched, 2U); // hybrid, corrupted
    BOOST_CHECK_EQUAL(stats.inbound.internal_error, 2U);
}

BOOST_AUTO_TEST_CASE(pq_cipher_state_closes)
{
    // An inconsistent cipher state is a local fault that closes the connection in either role,
    // an initiator that hasn't committed yet included. It counts once, as internal_error with
    // reason cipher_state: an inbound offer that was queued is not also abandoned.
    // DiscardHybridSecretForTesting() induces it; the failing check is an Assume, so only
    // release builds can exercise it.
    if constexpr (!G_FUZZING_BUILD && !G_ABORT_ON_FAILED_ASSUME) {
        const PQEndpointKey endpoint{LookupNumeric("1.2.3.5", 8333)};
        for (int i{0}; i < 3; ++i) {
            // Outbound: the keys are initialized, and the responder's offer arrives after the discard.
            Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, endpoint)};
            auto& transport{dynamic_cast<V2Transport&>(*link.node->m_transport)};
            V2Transport peer{Responder()};
            Pass(link);
            BOOST_REQUIRE(NodeToPeer(link, peer));
            const std::vector<uint8_t> bytes{PeerBytes(peer)};
            Receive(link, std::span{bytes}.first(EllSwiftPubKey::size()));
            Pass(link);
            BOOST_REQUIRE(transport.HoldsHybridSecretsForTesting());
            transport.DiscardHybridSecretForTesting();
            const std::string text{strprintf("v2 pq: internal_error reason=cipher_state role=initiator conn_type=outbound-full-relay peer=%d%s",
                                             link.node->GetId(), Backends())};
            DebugLogHelper expect{text, AtLevel({text}, LineLevel::INFO)};
            Receive(link, std::span{bytes}.subspan(EllSwiftPubKey::size()));
            Pass(link);
            BOOST_CHECK(link.node->fDisconnect);
            BOOST_CHECK(transport.GetPQSnapshot().failure == PQFailure::CIPHER_STATE_INTERNAL);
            BOOST_CHECK(transport.GetInfo().transport_pq_status == PQStatus::PENDING);
            Disconnect();
        }
        {
            // Inbound: the offer is queued, and the initiator's accept arrives after the discard.
            Link link{Add(ConnectionType::INBOUND)};
            auto& transport{dynamic_cast<V2Transport&>(*link.node->m_transport)};
            V2Transport peer{Initiator()};
            PeerToNode(link, peer);
            Pass(link);
            BOOST_REQUIRE(transport.GetPQSnapshot().offer == PQOfferState::SENT);
            BOOST_REQUIRE(NodeToPeer(link, peer));
            transport.DiscardHybridSecretForTesting();
            const std::string text{strprintf("v2 pq: internal_error reason=cipher_state role=responder conn_type=inbound peer=%d%s",
                                             link.node->GetId(), Backends())};
            DebugLogHelper expect{text, AtLevel({text}, LineLevel::NET_DEBUG)};
            PeerToNode(link, peer);
            Pass(link);
            BOOST_CHECK(link.node->fDisconnect);
            BOOST_CHECK(transport.GetPQSnapshot().failure == PQFailure::CIPHER_STATE_INTERNAL);
            Disconnect();
        }
        const PQTransportStats stats{Stats()};
        BOOST_CHECK_EQUAL(stats.outbound.internal_error, 3U);
        BOOST_CHECK_EQUAL(stats.inbound.internal_error, 1U);
        BOOST_CHECK_EQUAL(stats.inbound.abandoned + stats.outbound.closed_after_switch + stats.outbound.switched, 0U);
        BOOST_REQUIRE_EQUAL(stats.inbound_failures.entries.size(), 1U);
        BOOST_CHECK_EQUAL(stats.inbound_failures.entries.front().reason, "cipher_state");
        BOOST_REQUIRE_EQUAL(stats.outbound_failures.entries.size(), 3U);
        for (const PQFailureEntry& entry : stats.outbound_failures.entries) {
            BOOST_CHECK(entry.outcome == PQOutcome::INTERNAL_ERROR);
            BOOST_CHECK_EQUAL(entry.reason, "cipher_state");
        }
        // A local fault never counts toward the fallback.
        BOOST_CHECK(!Streak(endpoint));
        BOOST_CHECK(!m_connman.IsPQFallback(endpoint, Now<NodeSeconds>()));
        BOOST_CHECK_EQUAL(stats.outbound.fallback, 0U);
    }
}

BOOST_AUTO_TEST_CASE(pq_finalization_wipes)
{
    // Every way a connection can close while hybrid secrets are pending: an inbound offer's
    // decapsulation key and either role's retained ECDH secret. Finalization wipes them before
    // the disconnected pool releases the node, not only when the node is deleted.
    enum class Close { PEER_EOF, PEER_RESET, TIMEOUT, LOCAL, SEND_ERROR, NETWORK_OFF, TRANSPORT };
    for (const bool inbound : {true, false}) {
        for (const Close close : {Close::PEER_EOF, Close::PEER_RESET, Close::TIMEOUT, Close::LOCAL, Close::SEND_ERROR,
                                  Close::NETWORK_OFF, Close::TRANSPORT}) {
            Link link{Add(inbound ? ConnectionType::INBOUND : ConnectionType::OUTBOUND_FULL_RELAY)};
            link.node->AddRef(); // keep the node in the disconnected pool
            const auto& transport{dynamic_cast<const V2Transport&>(*link.node->m_transport)};
            if (!inbound) Pass(link); // our key and garbage
            // The peer's key: an inbound node queues its offer, an outbound one its terminator.
            Receive(link, InitiatorKey());
            if (close == Close::SEND_ERROR) link.sock->m_fail_send = true;
            Pass(link);
            BOOST_CHECK_EQUAL(transport.GetPQSnapshot().offer == PQOfferState::SENT, inbound);
            if (close != Close::SEND_ERROR) BOOST_REQUIRE(transport.HoldsHybridSecretsForTesting());
            switch (close) {
            case Close::PEER_EOF: link.pipes->recv.Eof(); break;
            case Close::PEER_RESET: link.sock->m_fail_recv = true; break;
            case Close::TIMEOUT: SetMockTime(GetTime<std::chrono::seconds>() + 61s); break;
            case Close::LOCAL: link.node->RequestDisconnect(); break;
            case Close::SEND_ERROR: break;
            case Close::NETWORK_OFF: m_connman.SetNetworkActive(false); break;
            case Close::TRANSPORT: // garbage without a terminator; the transport wipes as it fails
                Receive(link, std::vector<uint8_t>(V2Transport::MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN, 0));
                break;
            }
            Pass(link);
            // A peer or socket close leaves the secrets to finalization.
            if (close != Close::TRANSPORT && close != Close::NETWORK_OFF) {
                BOOST_REQUIRE(link.node->fDisconnect);
                BOOST_CHECK(transport.HoldsHybridSecretsForTesting());
            }
            const uint64_t abandoned{Stats().inbound.abandoned};
            Disconnect();
            m_connman.SetNetworkActive(true);
            BOOST_CHECK(link.node->m_pq_finalized);
            BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
            // With the network off, every close is ours: nothing is recorded.
            BOOST_CHECK_EQUAL(Stats().inbound.abandoned, abandoned + (inbound && close != Close::NETWORK_OFF ? 1 : 0));
            link.node->Release();
            Disconnect();
        }
    }

    // The wipe is effective: a peer's accept that arrives later can no longer switch the keys.
    // The transport then fails an Assume, so only release builds can exercise it.
    if constexpr (!G_FUZZING_BUILD && !G_ABORT_ON_FAILED_ASSUME) {
        Link link{Add(ConnectionType::INBOUND)};
        link.node->AddRef();
        V2Transport peer{Initiator()};
        PeerToNode(link, peer);
        Pass(link);
        BOOST_REQUIRE(NodeToPeer(link, peer)); // the peer now holds its accept for us
        link.node->RequestDisconnect();
        Disconnect();
        const std::vector<uint8_t> bytes{PeerBytes(peer)};
        std::span<const uint8_t> span{bytes};
        BOOST_CHECK(!link.node->m_transport->ReceivedBytes(span));
        const PQHandshake::Snapshot snapshot{link.node->m_transport->GetPQSnapshot()};
        BOOST_CHECK(snapshot.version_received);
        BOOST_CHECK(!snapshot.switched);
        BOOST_CHECK(snapshot.failure == PQFailure::CIPHER_STATE_INTERNAL);
        // Nothing is counted after finalization.
        m_connman.ObservePQPublic(*link.node, /*finalizing=*/false);
        BOOST_CHECK_EQUAL(Stats().inbound.internal_error, 0U);
        link.node->Release();
        Disconnect();
    }
}

BOOST_AUTO_TEST_CASE(pq_shutdown_finalizes)
{
    // Shutdown deletes the connections it still holds itself, without DisconnectNodes(). It
    // finalizes them first: no node is deleted holding hybrid secrets, but a shutdown close is
    // our own decision, so nothing is recorded, as with the network off.
    Link inbound{Add(ConnectionType::INBOUND)}; // its offer is pending: decapsulation key and ECDH secret
    Receive(inbound, InitiatorKey());
    Pass(inbound);
    BOOST_REQUIRE(inbound.node->m_transport->GetPQSnapshot().offer == PQOfferState::SENT);
    Link outbound{Add(ConnectionType::OUTBOUND_FULL_RELAY)}; // awaiting the version: the ECDH secret
    Pass(outbound);
    Receive(outbound, InitiatorKey());
    Pass(outbound);
    Link hybrid{Add(ConnectionType::MANUAL)};
    V2Transport peer{Responder()};
    Exchange(hybrid, peer);
    BOOST_REQUIRE(hybrid.node->m_transport->GetPQSnapshot().confirmed);
    for (const Link& link : {inbound, outbound}) {
        BOOST_REQUIRE(dynamic_cast<const V2Transport&>(*link.node->m_transport).HoldsHybridSecretsForTesting());
    }
    const PQTransportStats before{Stats()};
    const int deleted{m_events.m_deleted};
    m_connman.Stop();
    BOOST_CHECK_EQUAL(m_events.m_deleted - deleted, 3);
    BOOST_CHECK_EQUAL(m_events.m_deleted_with_secrets, 0);
    BOOST_CHECK_EQUAL(m_events.m_deleted_unfinalized, 0);
    // No outcome: the pending offer isn't abandoned, and no ring entry is added.
    const PQTransportStats after{Stats()};
    BOOST_CHECK_EQUAL(after.inbound.abandoned, before.inbound.abandoned);
    BOOST_CHECK_EQUAL(after.inbound.switched, before.inbound.switched);
    BOOST_CHECK_EQUAL(after.outbound.switched, before.outbound.switched);
    BOOST_CHECK_EQUAL(after.inbound_failures.last_sequence, before.inbound_failures.last_sequence);
    BOOST_CHECK_EQUAL(after.outbound_failures.last_sequence, before.outbound_failures.last_sequence);
}

BOOST_AUTO_TEST_CASE(pq_fallback_threshold)
{
    using enum End;
    struct Case {
        End end;
        std::string cause;
        std::vector<std::string> reasons;
    };
    int index{0};
    for (const Case& test : {Case{MALFORMED, "malformed_record", {"ek_length"}}, Case{CONFIRMATION, "first_packet_failed", {"length", "tag"}},
                             Case{PEER_EOF, "closed_after_switch", {"eof"}}, Case{PEER_RESET, "closed_after_switch", {"reset"}},
                             Case{TIMEOUT, "closed_after_switch", {"timeout"}}}) {
        BOOST_TEST_MESSAGE("counted failure: " + test.cause + " " + test.reasons.front());
        const PQEndpointKey endpoint{TestEndpoint(3, index++)};
        Connect(endpoint, test.end);
        Connect(endpoint, test.end);
        // Our own closes, send errors and legacy outcomes are neutral: they neither advance nor
        // reset the streak.
        Connect(endpoint, LOCAL);
        Connect(endpoint, SEND_ERROR);
        Connect(endpoint, LEGACY);
        BOOST_CHECK(!m_connman.IsPQFallback(endpoint, Now<NodeSeconds>()));
        const auto streak{Streak(endpoint)};
        BOOST_REQUIRE(streak);
        BOOST_CHECK_EQUAL(streak->streak, 2U);
        BOOST_CHECK_EQUAL(PQOutcomeString(streak->cause), test.cause);
        BOOST_CHECK(std::ranges::count(test.reasons, streak->reason) == 1);
        BOOST_CHECK(streak->next_window == 3600s);

        // The third enters the fallback set once, with one warning.
        const uint64_t fallbacks{Stats().outbound.fallback};
        const NodeSeconds failure_time{Now<NodeSeconds>() + (test.end == TIMEOUT ? 61s : 0s)};
        {
            const std::string until{FormatISO8601DateTime(TicksSinceEpoch<std::chrono::seconds>(failure_time + 3600s))};
            const std::string text{strprintf("v2 pq: fallback cause=%s until=%s role=initiator conn_type=outbound-full-relay peer=%d%s",
                                             test.cause, until, m_next_id, Backends())};
            DebugLogHelper expect{text, AtLevel({text}, LineLevel::WARNING)};
            Connect(endpoint, test.end);
        }
        BOOST_CHECK(m_connman.IsPQFallback(endpoint, Now<NodeSeconds>()));
        PQTransportStats stats{Stats()};
        BOOST_CHECK_EQUAL(stats.outbound.fallback, fallbacks + 1);
        const auto fallback{Fallback(endpoint)};
        BOOST_REQUIRE(fallback);
        BOOST_CHECK_EQUAL(PQOutcomeString(fallback->cause), test.cause);
        BOOST_CHECK_EQUAL(fallback->streak, 3U);
        BOOST_CHECK(fallback->entered == failure_time);
        BOOST_CHECK(fallback->expires == failure_time + 3600s);
        BOOST_CHECK(!Streak(endpoint));
        const PQFailureEntry& entry{stats.outbound_failures.entries.back()};
        BOOST_CHECK(entry.outcome == PQOutcome::FALLBACK);
        BOOST_CHECK_EQUAL(entry.reason, test.cause);
        BOOST_CHECK(entry.endpoint == endpoint);
        BOOST_CHECK(!entry.inbound);

        // A failure from a connection that was already running doesn't enter again.
        Connect(endpoint, test.end);
        stats = Stats();
        BOOST_CHECK_EQUAL(stats.outbound.fallback, fallbacks + 1);
        BOOST_CHECK(Fallback(endpoint)->expires == failure_time + 3600s);
    }

    // Inbound failures never count: inbound connections never fall back.
    const CService inbound_addr{LookupNumeric("10.3.1.1", 50000)};
    for (int i{0}; i < 3; ++i) {
        Link link{Add(ConnectionType::INBOUND, PQMode::NEGOTIATE, std::nullopt, inbound_addr)};
        RawPeer peer{/*initiator=*/true};
        Receive(link, peer.Key());
        Pass(link);
        peer.Initialize(NodeKey(link));
        Receive(link, peer.TerminatorAndVersion(MakeRecord(PQ_MLKEM1024, 100)));
        Pass(link);
        BOOST_REQUIRE(link.node->fDisconnect);
        Disconnect();
    }
    BOOST_CHECK_EQUAL(Stats().inbound.malformed_record, 3U);
    BOOST_CHECK(!Streak(inbound_addr));
    BOOST_CHECK(!m_connman.IsPQFallback(inbound_addr, Now<NodeSeconds>()));
}

BOOST_AUTO_TEST_CASE(pq_fallback_windows)
{
    const PQEndpointKey endpoint{LookupNumeric("5.6.7.8", 18555)};
    const auto create_sock{MockCreateSock()};
    // A new outbound connection to the endpoint, as the connection logic opens one.
    const auto new_status{[&] {
        const std::unique_ptr<CNode> node{m_connman.ConnectNodeOnly("5.6.7.8:18555", ConnectionType::OUTBOUND_FULL_RELAY, /*use_v2transport=*/true)};
        BOOST_REQUIRE(node);
        return node->m_transport->GetInfo().transport_pq_status;
    }};
    BOOST_CHECK(new_status() == PQStatus::PENDING);
    // A session that is running when the endpoint enters the fallback set.
    Link running{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, endpoint)};

    for (const std::chrono::seconds window : {3600s, 14400s, 86400s, 86400s}) {
        Connect(endpoint, End::MALFORMED);
        Connect(endpoint, End::MALFORMED);
        BOOST_REQUIRE(Streak(endpoint));
        BOOST_CHECK(Streak(endpoint)->next_window == window);
        const NodeSeconds start{Now<NodeSeconds>()};
        const uint64_t fallbacks{Stats().outbound.fallback};
        Connect(endpoint, End::MALFORMED);
        BOOST_CHECK_EQUAL(Stats().outbound.fallback, fallbacks + 1);
        BOOST_REQUIRE(Fallback(endpoint));
        BOOST_CHECK(Fallback(endpoint)->expires == start + window);
        BOOST_CHECK(new_status() == PQStatus::FALLBACK);

        // A failure during the window neither extends it nor enters again.
        SetMockTime(TicksSinceEpoch<std::chrono::seconds>(start + window - 1s));
        Connect(endpoint, End::MALFORMED);
        BOOST_CHECK(m_connman.IsPQFallback(endpoint, Now<NodeSeconds>()));
        BOOST_CHECK(Fallback(endpoint)->expires == start + window);
        BOOST_CHECK_EQUAL(Stats().outbound.fallback, fallbacks + 1);

        // At expiry the window ends, and the streak restarts at 0.
        SetMockTime(TicksSinceEpoch<std::chrono::seconds>(start + window));
        BOOST_CHECK(!Fallback(endpoint));
        BOOST_CHECK(!m_connman.IsPQFallback(endpoint, Now<NodeSeconds>()));
        BOOST_CHECK(!Streak(endpoint));
        BOOST_CHECK(new_status() == PQStatus::PENDING);
    }
    // Existing sessions never renegotiate.
    BOOST_CHECK(running.node->m_transport->GetInfo().transport_pq_status == PQStatus::PENDING);
}

BOOST_AUTO_TEST_CASE(pq_success_protection)
{
    const PQEndpointKey endpoint{TestEndpoint(4, 0)};
    // A connection that will fail late: we switch now, and the peer's bad confirmation waits.
    Link late{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::NEGOTIATE, endpoint)};
    V2Transport bad_peer{Responder({.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true})};
    Pass(late);
    BOOST_REQUIRE(NodeToPeer(late, bad_peer));
    PeerToNode(late, bad_peer);
    Pass(late);
    BOOST_REQUIRE(late.node->m_transport->GetPQSnapshot().switched);
    BOOST_CHECK(!NodeToPeer(late, bad_peer)); // the peer switched to other keys, and fails ours
    const std::vector<uint8_t> late_confirmation{PeerBytes(bad_peer)};

    // An earlier failure, then a success: the history goes, and the endpoint is protected.
    Connect(endpoint, End::MALFORMED);
    BOOST_CHECK(Streak(endpoint));
    Connect(endpoint, End::SUCCESS);
    BOOST_CHECK(!Streak(endpoint));

    // The late failure arrives after the success, and can't undo it.
    Receive(late, late_confirmation);
    Pass(late);
    BOOST_REQUIRE(late.node->m_transport->GetPQSnapshot().failure != PQFailure::NONE);
    Disconnect();
    BOOST_CHECK(!Streak(endpoint));

    // More than PQ_MAX_ENDPOINT_HISTORY other endpoints churn the history.
    for (int i{1}; i <= int{PQ_MAX_ENDPOINT_HISTORY} + 1; ++i) Connect(TestEndpoint(4, i), End::MALFORMED);
    BOOST_CHECK_EQUAL(Stats().failure_streaks.size(), PQ_MAX_ENDPOINT_HISTORY);

    // The protected endpoint never falls back; its failures are still counted.
    for (const End end : {End::MALFORMED, End::CONFIRMATION, End::PEER_EOF, End::MALFORMED}) Connect(endpoint, end);
    BOOST_CHECK(!m_connman.IsPQFallback(endpoint, Now<NodeSeconds>()));
    BOOST_CHECK(!Streak(endpoint));
    BOOST_CHECK(!Fallback(endpoint));
    const PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.outbound.fallback, 0U);
    BOOST_CHECK_EQUAL(stats.outbound.first_packet_failed, 2U);
    BOOST_CHECK_EQUAL(stats.outbound.closed_after_switch, 1U);
}

BOOST_AUTO_TEST_CASE(pq_history_eviction)
{
    // 1,001 endpoints fail once each, all at the same time, inserted in descending key order so
    // that insertion order and map order disagree.
    const int newest{int{PQ_MAX_ENDPOINT_HISTORY}};
    for (int i{newest}; i >= 0; --i) Connect(TestEndpoint(6, i), End::MALFORMED);
    PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.failure_streaks.size(), PQ_MAX_ENDPOINT_HISTORY);
    // The first insertion, which has the largest key, is the one evicted.
    BOOST_CHECK(!Streak(TestEndpoint(6, newest)));
    BOOST_CHECK(Streak(TestEndpoint(6, 0)));
    BOOST_CHECK(Streak(TestEndpoint(6, 1)));
    BOOST_CHECK(Streak(TestEndpoint(6, newest - 1)));
    // The rings keep their own bound and counts.
    BOOST_CHECK_EQUAL(stats.outbound.malformed_record, PQ_MAX_ENDPOINT_HISTORY + 1);
    BOOST_CHECK_EQUAL(stats.outbound_failures.last_sequence, PQ_MAX_ENDPOINT_HISTORY + 1);
    BOOST_CHECK_EQUAL(stats.outbound_failures.entries.size(), PQ_FAILURE_RING_SIZE);
    BOOST_CHECK_EQUAL(stats.outbound_failures.dropped, PQ_MAX_ENDPOINT_HISTORY + 1 - PQ_FAILURE_RING_SIZE);

    // Eviction follows insertion, not the latest failure or the key: the oldest remaining
    // insertion fails again, later than every other, and is still the next to go.
    SetMockTime(GetTime<std::chrono::seconds>() + 1s);
    Connect(TestEndpoint(6, newest - 1), End::MALFORMED);
    BOOST_CHECK_EQUAL(Streak(TestEndpoint(6, newest - 1))->streak, 2U);
    Connect(TestEndpoint(6, newest + 1), End::MALFORMED);
    BOOST_CHECK(!Streak(TestEndpoint(6, newest - 1)));
    BOOST_CHECK(Streak(TestEndpoint(6, newest - 2)));
    BOOST_CHECK(Streak(TestEndpoint(6, 0)));
    BOOST_CHECK(Streak(TestEndpoint(6, newest + 1)));
    BOOST_CHECK_EQUAL(Stats().failure_streaks.size(), PQ_MAX_ENDPOINT_HISTORY);
}

namespace {
/** The warning names the backends that ran, and -mlkemportable as the remedy while native code runs. */
std::string LocalFaultLine()
{
    const auto backends{mlkem::GetBackendNames()};
    const bool native{backends.arith != "portable" || backends.keccak != "portable"};
    return strprintf("v2 pq: local_fault arith=%s keccak=%s: hybrid handshakes failed with 8 distinct endpoints and none succeeded "
                     "since startup, so this node's own ML-KEM code may be at fault.%s",
                     backends.arith, backends.keccak,
                     native ? " Restart with -mlkemportable to use the portable implementation." : "");
}
} // namespace

BOOST_AUTO_TEST_CASE(pq_local_fault_warning)
{
    // Whatever backends this machine runs.
    LogLineCounter warnings{"v2 pq: local_fault"};
    for (int i{0}; i < 7; ++i) Connect(TestEndpoint(7, i), End::MALFORMED);
    BOOST_CHECK_EQUAL(warnings.m_count, 0);
    {
        const std::string text{LocalFaultLine()};
        DebugLogHelper expect{text, AtLevel({text}, LineLevel::WARNING)};
        Connect(TestEndpoint(7, 7), End::MALFORMED);
    }
    BOOST_CHECK_EQUAL(warnings.m_count, 1);
    BOOST_CHECK_EQUAL(m_connman.PQLocalFaultEndpoints(), PQ_LOCAL_FAULT_THRESHOLD);
    // It warns once, and behavior doesn't change.
    for (int i{0}; i < 12; ++i) Connect(TestEndpoint(7, i), End::MALFORMED);
    BOOST_CHECK_EQUAL(warnings.m_count, 1);
    BOOST_CHECK(m_connman.IsPQFallback(TestEndpoint(7, 0), Now<NodeSeconds>()) == false);
    BOOST_CHECK_EQUAL(Streak(TestEndpoint(7, 0))->streak, 2U);
    // The set of failing endpoints stops growing at the threshold: it is never evicted, so the
    // cap is its only bound.
    BOOST_CHECK_EQUAL(m_connman.PQLocalFaultEndpoints(), PQ_LOCAL_FAULT_THRESHOLD);
}

BOOST_AUTO_TEST_CASE(pq_local_fault_warning_portable)
{
    mlkem::ForcePortableForTesting portable;
    BOOST_CHECK_EQUAL(mlkem::GetBackendNames().arith, "portable");
    const std::string text{LocalFaultLine()};
    BOOST_CHECK(text.find("arith=portable keccak=portable:") != std::string::npos);
    // Portable code already runs: no remedy to name.
    BOOST_CHECK(text.find("-mlkemportable") == std::string::npos);
    LogLineCounter warnings{"v2 pq: local_fault"};
    {
        DebugLogHelper expect{text, AtLevel({text}, LineLevel::WARNING)};
        for (int i{0}; i < 8; ++i) Connect(TestEndpoint(7, i), End::MALFORMED);
    }
    BOOST_CHECK_EQUAL(warnings.m_count, 1);
}

BOOST_AUTO_TEST_CASE(pq_local_fault_after_success)
{
    // One success since startup rules out a local fault.
    LogLineCounter warnings{"v2 pq: local_fault"};
    Connect(TestEndpoint(8, 0), End::SUCCESS);
    for (int i{1}; i <= 12; ++i) Connect(TestEndpoint(8, i), End::MALFORMED);
    BOOST_CHECK_EQUAL(warnings.m_count, 0);
}

BOOST_AUTO_TEST_CASE(pq_inbound_success_does_not_protect)
{
    // Only outbound successes enter the success set, which is never evicted. An inbound peer's
    // key is its address and source port, so letting inbound successes in would let a peer that
    // reconnects grow the set without bound, and silence the local-fault warning.
    const CService addr{LookupNumeric("10.7.0.1", 8333)};
    Link inbound{Add(ConnectionType::INBOUND, PQMode::NEGOTIATE, std::nullopt, addr)};
    V2Transport peer{Initiator()};
    Exchange(inbound, peer);
    BOOST_REQUIRE(inbound.node->m_transport->GetPQSnapshot().confirmed);
    inbound.node->RequestDisconnect();
    Disconnect();
    LogLineCounter warnings{"v2 pq: local_fault"};
    // An outbound failure to the same address and port still starts a streak...
    Connect(addr, End::MALFORMED);
    BOOST_CHECK(Streak(addr));
    // ...and with no outbound success, eight failing endpoints still warn.
    for (int i{1}; i < 8; ++i) Connect(TestEndpoint(9, i), End::MALFORMED);
    BOOST_CHECK_EQUAL(warnings.m_count, 1);
}

BOOST_AUTO_TEST_CASE(pq_fallback_connection)
{
    // A fallback connection to a peer that sends a malformed offer: plain v2, with the offer
    // neither parsed nor validated.
    Link link{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::FALLBACK)};
    Pass(link);
    RawPeer raw{/*initiator=*/false};
    raw.Initialize(NodeKey(link));
    Receive(link, raw.Key());
    Receive(link, raw.TerminatorAndVersion(MakeRecord(PQ_MLKEM1024, 100)));
    Pass(link);
    BOOST_CHECK(!link.node->fDisconnect);
    Transport::Info info{link.node->m_transport->GetInfo()};
    BOOST_CHECK(info.transport_type == TransportProtocolType::V2);
    BOOST_CHECK(info.transport_pq_status == PQStatus::FALLBACK);
    BOOST_CHECK(!info.transport_pq);

    // Toward an upgraded responder, which offers: our version stays empty, and the peer sees a
    // legacy initiator.
    Link upgraded{Add(ConnectionType::OUTBOUND_FULL_RELAY, PQMode::FALLBACK)};
    V2Transport peer{Responder()};
    Exchange(upgraded, peer);
    BOOST_CHECK(!upgraded.node->fDisconnect);
    info = upgraded.node->m_transport->GetInfo();
    BOOST_CHECK(info.transport_type == TransportProtocolType::V2);
    BOOST_CHECK(info.transport_pq_status == PQStatus::FALLBACK);
    BOOST_CHECK(peer.GetInfo().transport_pq_status == PQStatus::LEGACY_PEER);

    // Nothing is counted for either.
    link.node->RequestDisconnect();
    upgraded.node->RequestDisconnect();
    Disconnect();
    const PQTransportStats stats{Stats()};
    BOOST_CHECK_EQUAL(stats.outbound.switched + stats.outbound.legacy_peer + stats.outbound.malformed_record, 0U);
    BOOST_CHECK(stats.outbound_failures.entries.empty());
}

BOOST_AUTO_TEST_CASE(pq_load_shedding)
{
    BOOST_CHECK_EQUAL(Stats().load_shedding.threshold_per_s, DEFAULT_PQ_SHED_THRESHOLD_PER_S);
    // A low threshold, as unit tests and the flood lab set it.
    InitConnman(/*shed_threshold=*/10);
    BOOST_CHECK_EQUAL(Stats().load_shedding.threshold_per_s, 10U);
    LogLineCounter started{"v2 pq: load_shedding started"};
    LogLineCounter stopped{"v2 pq: load_shedding stopped"};

    // One attempted offer: an inbound connection whose 64-byte key arrived.
    const auto attempt{[&] {
        Link link{Accept()};
        Receive(link, InitiatorKey());
        Pass(link);
        return link.node->m_transport->GetPQSnapshot().offer == PQOfferState::SENT;
    }};
    // The steady clock drives the seconds; the wall clock only dates the start.
    const NodeSeconds start{Now<NodeSeconds>()};
    const auto at{[&](std::chrono::seconds offset) {
        SetMockTime(TicksSinceEpoch<std::chrono::seconds>(start + offset));
        MockableSteadyClock::SetMockTime(STEADY_START + offset);
    }};

    // Up to the threshold in one second, responders offer.
    for (int i{0}; i < 10; ++i) BOOST_CHECK(attempt());
    BOOST_CHECK(!Stats().load_shedding.active);
    BOOST_CHECK_EQUAL(started.m_count, 0);

    // More than the threshold within the second starts shedding, with one line.
    {
        const std::string text{"v2 pq: load_shedding started threshold_per_s=10"};
        DebugLogHelper expect{text, AtLevel({text}, LineLevel::INFO)};
        BOOST_CHECK(!attempt());
    }
    // A shed responder sends empty contents, which is exactly plain v2: the peer sees a legacy
    // responder, and the connection's status is off.
    Link shed{Accept()};
    V2Transport peer{Initiator()};
    Exchange(shed, peer);
    BOOST_CHECK(!shed.node->fDisconnect);
    BOOST_CHECK(shed.node->m_transport->GetInfo().transport_type == TransportProtocolType::V2);
    BOOST_CHECK(shed.node->m_transport->GetInfo().transport_pq_status == PQStatus::OFF);
    BOOST_CHECK(peer.GetInfo().transport_pq_status == PQStatus::LEGACY_PEER);
    BOOST_CHECK(shed.node->m_transport->GetPQSnapshot().legacy == PQLegacyReason::NONE);
    PQTransportStats stats{Stats()};
    BOOST_CHECK(stats.load_shedding.active);
    BOOST_CHECK(stats.load_shedding.since == start);
    BOOST_CHECK_EQUAL(stats.inbound.shed, 2U);
    BOOST_CHECK_EQUAL(started.m_count, 1);

    // Outbound connections are never affected.
    Link outbound{Add(ConnectionType::OUTBOUND_FULL_RELAY)};
    V2Transport responder{Responder()};
    Exchange(outbound, responder);
    BOOST_CHECK(outbound.node->m_transport->GetInfo().transport_pq_status == PQStatus::HYBRID);

    // Nine quiet seconds (fewer than half the threshold), then a second at half: not quiet, so
    // shedding goes on and the run starts over.
    for (int second{1}; second <= 10; ++second) {
        at(std::chrono::seconds{second});
        for (int i{0}; i < (second == 10 ? 5 : 4); ++i) BOOST_CHECK(!attempt());
    }
    // Ten quiet seconds: offers resume in the eleventh, with one line.
    for (int second{11}; second <= 20; ++second) {
        at(std::chrono::seconds{second});
        for (int i{0}; i < 4; ++i) BOOST_CHECK(!attempt());
    }
    BOOST_CHECK(Stats().load_shedding.active);
    at(21s);
    {
        const std::string text{"v2 pq: load_shedding stopped"};
        DebugLogHelper expect{text, AtLevel({text}, LineLevel::INFO)};
        BOOST_CHECK(attempt());
    }
    stats = Stats();
    BOOST_CHECK(!stats.load_shedding.active);
    BOOST_CHECK(stats.load_shedding.since == NodeSeconds{});
    BOOST_CHECK_EQUAL(stats.inbound.shed, 2U + 9 * 4 + 5 + 10 * 4);
    // Shed offers add no ring entries: a flood can't wash out the evidence.
    BOOST_CHECK(stats.inbound_failures.entries.empty());

    // A second flood, which then stops entirely: the socket handler ends shedding on time even
    // though no offer is attempted.
    for (int i{0}; i < 11; ++i) attempt();
    BOOST_CHECK(Stats().load_shedding.active);
    BOOST_CHECK(Stats().load_shedding.since == start + 21s);
    at(31s);
    m_connman.UpdatePQSheddingPublic();
    BOOST_CHECK(Stats().load_shedding.active);
    at(32s);
    m_connman.UpdatePQSheddingPublic();
    m_connman.UpdatePQSheddingPublic();
    BOOST_CHECK(!Stats().load_shedding.active);
    BOOST_CHECK_EQUAL(started.m_count, 2);
    BOOST_CHECK_EQUAL(stopped.m_count, 2);
}

BOOST_AUTO_TEST_CASE(pq_load_shedding_off)
{
    // With the switch off, inbound transports never ask the gate: nothing is counted or shed.
    InitConnman(/*shed_threshold=*/1, {.v2_enabled = true, .pq_requested = false});
    for (int i{0}; i < 5; ++i) {
        Link link{Accept()};
        Receive(link, InitiatorKey());
        Pass(link);
        BOOST_CHECK(link.node->m_transport->GetInfo().transport_pq_status == PQStatus::OFF);
    }
    BOOST_CHECK(!Stats().load_shedding.active);
    BOOST_CHECK_EQUAL(Stats().inbound.shed, 0U);
}

BOOST_AUTO_TEST_CASE(pq_shed_wipes_secrets)
{
    // A shed responder runs plain v2 for the rest of the connection, so it keeps no hybrid
    // secret: the retained ECDH secret and transcript go at once, not at finalization.
    InitConnman(/*shed_threshold=*/1);
    Link offered{Accept()};
    Receive(offered, InitiatorKey());
    Pass(offered);
    BOOST_REQUIRE(offered.node->m_transport->GetPQSnapshot().offer == PQOfferState::SENT);
    BOOST_CHECK(dynamic_cast<const V2Transport&>(*offered.node->m_transport).HoldsHybridSecretsForTesting());
    Link shed{Accept(LookupNumeric("10.9.0.2", 50001))};
    Receive(shed, InitiatorKey());
    Pass(shed);
    BOOST_REQUIRE(Stats().load_shedding.active);
    BOOST_REQUIRE(shed.node->m_transport->GetPQSnapshot().offer == PQOfferState::NONE);
    BOOST_REQUIRE(!shed.node->fDisconnect);
    // Check before the initiator's version arrives: processing it wipes whatever is still held,
    // which would hide a shed branch that didn't wipe.
    BOOST_REQUIRE(!shed.node->m_transport->GetPQSnapshot().version_received);
    BOOST_CHECK(!dynamic_cast<const V2Transport&>(*shed.node->m_transport).HoldsHybridSecretsForTesting());
}

BOOST_AUTO_TEST_CASE(pq_load_shedding_wall_clock_step)
{
    // Offers trickle in, one per second, far below the threshold, while the wall clock steps back
    // an hour (an NTP correction or a VM restore). The steady clock still tells the seconds apart,
    // so nothing is shed.
    InitConnman(/*shed_threshold=*/5);
    const auto attempt{[&] {
        Link link{Accept()};
        Receive(link, InitiatorKey());
        Pass(link);
        const bool offered{link.node->m_transport->GetPQSnapshot().offer == PQOfferState::SENT};
        link.node->RequestDisconnect();
        Disconnect();
        return offered;
    }};
    const NodeSeconds wall{Now<NodeSeconds>()};
    BOOST_CHECK(attempt());
    for (int i{1}; i <= 120; ++i) {
        SetMockTime(TicksSinceEpoch<std::chrono::seconds>(wall - 3600s + std::chrono::seconds{i}));
        MockableSteadyClock::SetMockTime(STEADY_START + std::chrono::seconds{i});
        m_connman.UpdatePQSheddingPublic();
        BOOST_CHECK(attempt());
    }
    BOOST_CHECK(!Stats().load_shedding.active);
    BOOST_CHECK_EQUAL(Stats().inbound.shed, 0U);

    // A flood within one steady second starts shedding, and a wall clock step forward doesn't
    // end it early: only ten quiet steady seconds do.
    MockableSteadyClock::SetMockTime(STEADY_START + 200s);
    for (int i{0}; i < 6; ++i) attempt();
    BOOST_CHECK(Stats().load_shedding.active);
    SetMockTime(TicksSinceEpoch<std::chrono::seconds>(wall + 3600s));
    m_connman.UpdatePQSheddingPublic();
    BOOST_CHECK(!attempt());
    BOOST_CHECK(Stats().load_shedding.active);
    MockableSteadyClock::SetMockTime(STEADY_START + 211s);
    m_connman.UpdatePQSheddingPublic();
    BOOST_CHECK(!Stats().load_shedding.active);
    BOOST_CHECK(attempt());
}

BOOST_AUTO_TEST_CASE(pq_load_shedding_socket_thread)
{
    // The socket handler thread ends shedding on time when the flood stops entirely, without a
    // further offer: the real thread function runs, as Start() runs it.
    InitConnman(/*shed_threshold=*/2);
    LogLineCounter stopped{"v2 pq: load_shedding stopped"};
    for (int i{0}; i < 3; ++i) {
        Link link{Accept()};
        Receive(link, InitiatorKey());
        Pass(link);
        link.node->RequestDisconnect();
    }
    Disconnect(); // so the thread has no sockets to serve
    BOOST_REQUIRE(Stats().load_shedding.active);
    MockableSteadyClock::SetMockTime(STEADY_START + PQ_SHED_QUIET_PERIOD + 1s);
    m_connman.StartSocketHandlerThread();
    const auto deadline{SteadyClock::now() + 10s};
    while (Stats().load_shedding.active && SteadyClock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    m_connman.StopSocketHandlerThread();
    BOOST_CHECK(!Stats().load_shedding.active);
    BOOST_CHECK_EQUAL(stopped.m_count, 1);
}

BOOST_AUTO_TEST_CASE(pq_config)
{
    // Init() takes the negotiation of new connections, inbound and outbound, from the
    // configuration: on only with both switches on.
    const auto create_sock_orig{CreateSock};
    CreateSock = [](int, int, int) -> std::unique_ptr<Sock> { return std::make_unique<ZeroSock>(); };
    for (const auto& [config, enabled] : std::vector<std::pair<PQTransportConfig, bool>>{
             {{.v2_enabled = false, .pq_requested = true}, false},
             {{.v2_enabled = true, .pq_requested = false}, false},
             {{.v2_enabled = true, .pq_requested = true}, true},
         }) {
        BOOST_CHECK_EQUAL(config.Enabled(), enabled);
        InitConnman(DEFAULT_PQ_SHED_THRESHOLD_PER_S, config);
        Link inbound{Accept()};
        V2Transport peer{Initiator()};
        Exchange(inbound, peer);
        const Transport::Info info{inbound.node->m_transport->GetInfo()};
        BOOST_CHECK_EQUAL(info.transport_pq, enabled);
        BOOST_CHECK(info.transport_pq_status == (enabled ? PQStatus::HYBRID : PQStatus::OFF));
        const std::unique_ptr<CNode> outbound{m_connman.ConnectNodeOnly("5.6.7.8:18555", ConnectionType::MANUAL, /*use_v2transport=*/true)};
        BOOST_REQUIRE(outbound);
        BOOST_CHECK(outbound->m_transport->GetInfo().transport_pq_status == (enabled ? PQStatus::PENDING : PQStatus::OFF));
    }

    // -test=pq_fail_first_packet corrupts this side's shared secret, so its check of the peer's key
    // confirmation fails (and it closes before its own confirmation is sent).
    InitConnman(DEFAULT_PQ_SHED_THRESHOLD_PER_S, {.v2_enabled = true, .pq_requested = true, .fail_first_packet = true});
    Link inbound{Accept()};
    V2Transport peer{Initiator()};
    Exchange(inbound, peer);
    const PQHandshake::Snapshot ours{inbound.node->m_transport->GetPQSnapshot()};
    BOOST_CHECK(ours.switched);
    BOOST_CHECK(!ours.confirmed);
    BOOST_CHECK(ours.failure == PQFailure::CONFIRM_LENGTH || ours.failure == PQFailure::CONFIRM_TAG);
    BOOST_CHECK(inbound.node->fDisconnect);
    BOOST_CHECK(peer.GetPQSnapshot().switched);
    CreateSock = create_sock_orig;
}

BOOST_AUTO_TEST_SUITE_END()
