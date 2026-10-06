// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/pq_transport_vectors.json.h>

#include <bip324_pq.h>
#include <chainparams.h>
#include <clientversion.h>
#include <common/args.h>
#include <compat/compat.h>
#include <crypto/common.h>
#include <crypto/mlkem.h>
#include <crypto/sha256.h>
#include <cstdint>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/protocol_version.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <deque>
#include <ios>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace std::literals;
using namespace util::hex_literals;
using util::ToString;

BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(connman_init_preserves_prestart_local_services)
{
    auto connman = std::make_unique<CConnman>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params());
    connman->AddLocalServices(ServiceFlags(NODE_WITNESS_PRUNED | NODE_ARCHIVE));

    CConnman::Options options;
    options.m_local_services = ServiceFlags(NODE_WITNESS | NODE_P2P_V2);
    connman->Init(options);

    const ServiceFlags services{connman->GetLocalServices()};
    BOOST_CHECK(services & NODE_WITNESS);
    BOOST_CHECK(services & NODE_P2P_V2);
    BOOST_CHECK(services & NODE_WITNESS_PRUNED);
    BOOST_CHECK(services & NODE_ARCHIVE);
}

BOOST_AUTO_TEST_CASE(connman_init_preserves_prestart_local_service_removals)
{
    auto connman = std::make_unique<CConnman>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params());
    connman->RemoveLocalServices(NODE_ARCHIVE);
    connman->AddLocalServices(NODE_WITNESS_PRUNED);

    CConnman::Options options;
    options.m_local_services = ServiceFlags(NODE_WITNESS | NODE_ARCHIVE);
    connman->Init(options);

    const ServiceFlags services{connman->GetLocalServices()};
    BOOST_CHECK(services & NODE_WITNESS);
    BOOST_CHECK(services & NODE_WITNESS_PRUNED);
    BOOST_CHECK(!(services & NODE_ARCHIVE));
}

BOOST_AUTO_TEST_CASE(seeds_service_flags_include_archive)
{
    BOOST_CHECK_EQUAL(SeedsServiceFlags(), ServiceFlags(NODE_NETWORK | NODE_WITNESS | NODE_ARCHIVE));
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    std::unique_ptr<CNode> pnode1 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode2 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode3 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode4 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

namespace {
//! A socket whose Send() and Recv() fail as if the peer reset the connection.
class ResetSock : public ZeroSock
{
public:
    ssize_t Send(const void*, size_t, int) const override { return Fail(); }
    ssize_t Recv(void*, size_t, int) const override { return Fail(); }

private:
    static ssize_t Fail()
    {
#ifdef WIN32
        WSASetLastError(WSAECONNRESET);
#else
        errno = ECONNRESET;
#endif
        return -1;
    }

    ResetSock& operator=(Sock&&) override
    {
        assert(false && "Move of Sock into ResetSock not allowed.");
        return *this;
    }
};

//! Message processing that only records each node's close cause when CConnman deletes it.
class CloseCauseRecorder final : public NetEventsInterface
{
public:
    std::map<NodeId, NodeCloseCause> m_finalized;

    void InitializeNode(const CNode&, ServiceFlags) override {}
    void FinalizeNode(const CNode& node) override { m_finalized.emplace(node.GetId(), node.GetCloseCause()); }
    bool HasAllDesirableServiceFlags(ServiceFlags) const override { return true; }
    bool HasUndesirableServiceFlags(ServiceFlags) const override { return false; }
    bool ProcessMessages(CNode*, std::atomic<bool>&) override EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) { return false; }
    bool SendMessages(CNode*) override EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) { return false; }
};
} // namespace

BOOST_AUTO_TEST_CASE(close_cause_first_wins)
{
    constexpr std::array causes{NodeCloseCause::PEER_EOF, NodeCloseCause::PEER_RESET, NodeCloseCause::SEND_ERROR,
                                NodeCloseCause::TIMEOUT, NodeCloseCause::LOCAL};
    NodeId id{0};
    const auto new_node{[&](std::shared_ptr<Sock> sock, ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY) {
        return new CNode{id++,
                         std::move(sock),
                         CAddress{LookupNumeric("1.2.3.4", 8333), NODE_NONE},
                         /*nKeyedNetGroupIn=*/0,
                         /*nLocalHostNonceIn=*/0,
                         CAddress{},
                         /*addrNameIn=*/"",
                         conn_type,
                         /*inbound_onion=*/false};
    }};

    // Each cause is recorded, and repeated cleanup keeps it.
    for (const auto cause : causes) {
        const std::unique_ptr<CNode> node{new_node(nullptr)};
        BOOST_CHECK(node->GetCloseCause() == NodeCloseCause::NONE);
        BOOST_CHECK(!node->fDisconnect);
        node->RequestDisconnect(cause);
        BOOST_CHECK(node->GetCloseCause() == cause);
        BOOST_CHECK(node->fDisconnect);
        for (const auto later : causes) {
            node->RequestDisconnect(later);
            node->CloseSocketDisconnect(later);
        }
        node->CloseSocketDisconnect();
        BOOST_CHECK(node->GetCloseCause() == cause);
    }

    // Racing writers, like the socket, message handler and RPC threads, all
    // see the same cause once their own call returns.
    for (int round{0}; round < 50; ++round) {
        const std::unique_ptr<CNode> node{new_node(nullptr)};
        std::atomic<bool> start{false};
        std::array<NodeCloseCause, causes.size()> seen{};
        std::vector<std::thread> threads;
        for (size_t i{0}; i < causes.size(); ++i) {
            threads.emplace_back([&, i] {
                while (!start) std::this_thread::yield();
                node->CloseSocketDisconnect(causes[i]);
                node->RequestDisconnect();
                seen[i] = node->GetCloseCause();
            });
        }
        start = true;
        for (auto& thread : threads) thread.join();
        const NodeCloseCause winner{node->GetCloseCause()};
        BOOST_CHECK(winner != NodeCloseCause::NONE);
        for (const auto cause : seen) BOOST_CHECK(cause == winner);
    }

    // Each disconnect site records its cause.
    CloseCauseRecorder events;
    ConnmanTestMsg connman{0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()};
    connman.SetMsgProc(&events);
    connman.SetPeerConnectTimeout(60s);
    const auto now{GetTime<std::chrono::seconds>()};
    SetMockTime(now);

    const std::shared_ptr<Sock> eof_sock{std::make_shared<StaticContentsSock>("")};
    const std::shared_ptr<Sock> reset_sock{std::make_shared<ResetSock>()};
    CNode* eof_node{new_node(eof_sock)};
    CNode* reset_node{new_node(reset_sock)};
    CNode* send_node{new_node(std::make_shared<ResetSock>())};
    CNode* timeout_node{new_node(std::make_shared<ZeroSock>())};
    CNode* local_node{new_node(std::make_shared<ZeroSock>())};
    CNode* unexplained_node{new_node(std::make_shared<ZeroSock>())};
    // Zeros never start with the network magic, so the transport rejects them.
    const std::shared_ptr<Sock> garbage_sock{std::make_shared<ZeroSock>()};
    CNode* garbage_node{new_node(garbage_sock)};
    CNode* network_off_node{new_node(std::make_shared<ZeroSock>())};
    const std::vector nodes{eof_node, reset_node, send_node, timeout_node, local_node, unexplained_node, garbage_node, network_off_node};
    for (CNode* node : nodes) {
        node->AddRef(); // the reference m_nodes holds, as in ConnectNode()
        node->AddRef(); // keeps the node alive through DisconnectNodes() below
        connman.AddTestNode(*node);
    }

    // Our own decision, as from the RPC thread.
    BOOST_CHECK(connman.DisconnectNode(local_node->GetId()));
    BOOST_CHECK(local_node->GetCloseCause() == NodeCloseCause::LOCAL);
    // A failed optimistic send, as from the message handler thread.
    connman.PushMessage(send_node, NetMsg::Make(NetMsgType::VERACK));
    BOOST_CHECK(send_node->GetCloseCause() == NodeCloseCause::SEND_ERROR);
    // Setting fDisconnect directly leaves the cause unknown.
    unexplained_node->fDisconnect = true;

    // One socket handler pass after the inactivity timeout, so the timeout
    // check runs for every node with an open socket after it was read.
    SetMockTime(now + 61s);
    Sock::EventsPerSock events_per_sock;
    for (const auto& sock : {eof_sock, reset_sock, garbage_sock}) {
        events_per_sock.emplace(sock, Sock::Events{Sock::RECV}).first->second.occurred = Sock::RECV;
    }
    connman.SocketHandlerConnectedPublic({eof_node, reset_node, send_node, timeout_node, local_node, garbage_node}, events_per_sock);
    BOOST_CHECK(eof_node->GetCloseCause() == NodeCloseCause::PEER_EOF);
    BOOST_CHECK(reset_node->GetCloseCause() == NodeCloseCause::PEER_RESET);
    BOOST_CHECK(send_node->GetCloseCause() == NodeCloseCause::SEND_ERROR);
    BOOST_CHECK(timeout_node->GetCloseCause() == NodeCloseCause::TIMEOUT);
    BOOST_CHECK(local_node->GetCloseCause() == NodeCloseCause::LOCAL);
    BOOST_CHECK(garbage_node->GetCloseCause() == NodeCloseCause::LOCAL);
    BOOST_CHECK(unexplained_node->GetCloseCause() == NodeCloseCause::NONE);
    BOOST_CHECK(network_off_node->GetCloseCause() == NodeCloseCause::NONE);

    // With the network off, DisconnectNodes() disconnects the remaining node
    // as LOCAL. Finalization counts the unexplained disconnect as LOCAL and
    // keeps every recorded cause.
    connman.SetNetworkActive(false);
    connman.DisconnectNodesPublic();
    connman.SetNetworkActive(true);
    BOOST_CHECK(connman.TestNodes().empty());
    BOOST_CHECK(eof_node->GetCloseCause() == NodeCloseCause::PEER_EOF);
    BOOST_CHECK(reset_node->GetCloseCause() == NodeCloseCause::PEER_RESET);
    BOOST_CHECK(send_node->GetCloseCause() == NodeCloseCause::SEND_ERROR);
    BOOST_CHECK(timeout_node->GetCloseCause() == NodeCloseCause::TIMEOUT);
    BOOST_CHECK(local_node->GetCloseCause() == NodeCloseCause::LOCAL);
    BOOST_CHECK(garbage_node->GetCloseCause() == NodeCloseCause::LOCAL);
    BOOST_CHECK(unexplained_node->GetCloseCause() == NodeCloseCause::LOCAL);
    BOOST_CHECK(network_off_node->GetCloseCause() == NodeCloseCause::LOCAL);

    for (CNode* node : nodes) node->Release();
    connman.DisconnectNodesPublic(); // deletes the released nodes

    // Eviction records LOCAL. Enough inbound candidates that some survive the
    // protections in SelectNodeToEvict(); outbound connections are never evicted.
    std::vector<CNode*> inbound_nodes;
    for (int i{0}; i < 40; ++i) {
        inbound_nodes.push_back(new_node(nullptr, ConnectionType::INBOUND));
    }
    CNode* shutdown_node{new_node(std::make_shared<ZeroSock>())};
    for (CNode* node : inbound_nodes) {
        node->AddRef();
        connman.AddTestNode(*node);
    }
    shutdown_node->AddRef();
    connman.AddTestNode(*shutdown_node);
    BOOST_CHECK(connman.AttemptToEvictConnectionPublic());
    std::vector<CNode*> evicted;
    std::copy_if(inbound_nodes.begin(), inbound_nodes.end(), std::back_inserter(evicted), [](const CNode* node) { return node->fDisconnect.load(); });
    BOOST_CHECK_EQUAL(evicted.size(), 1U);
    for (const CNode* node : evicted) BOOST_CHECK(node->GetCloseCause() == NodeCloseCause::LOCAL);

    // Shutdown deletes the remaining nodes and records LOCAL for any without a cause.
    const NodeId shutdown_id{shutdown_node->GetId()};
    connman.Stop();
    BOOST_CHECK(connman.TestNodes().empty());
    BOOST_CHECK(events.m_finalized.at(shutdown_id) == NodeCloseCause::LOCAL);
    for (const auto& [finalized_id, cause] : events.m_finalized) BOOST_CHECK(cause != NodeCloseCause::NONE);

    // The ping timeout records TIMEOUT, from the message handler thread.
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        auto& fixture_connman{static_cast<ConnmanTestMsg&>(*m_node.connman)};
        const std::unique_ptr<CNode> ping_node{new_node(nullptr, ConnectionType::INBOUND)};
        // The handshake ends by sending the first ping.
        fixture_connman.Handshake(*ping_node,
                                  /*successfully_connected=*/true,
                                  /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                                  /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                                  /*version=*/PROTOCOL_VERSION,
                                  /*relay_txs=*/true);
        BOOST_CHECK(!ping_node->fDisconnect);
        SetMockTime(GetTime<std::chrono::seconds>() + TIMEOUT_INTERVAL + 1s);
        m_node.peerman->SendMessages(ping_node.get());
        BOOST_CHECK(ping_node->GetCloseCause() == NodeCloseCause::TIMEOUT);
        m_node.peerman->FinalizeNode(*ping_node);
    }
    SetMockTime(0s);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    CNetAddr addr;

    // IPv4, INADDR_ANY
    addr = LookupHost("0.0.0.0", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "0.0.0.0");

    // IPv4, INADDR_NONE
    addr = LookupHost("255.255.255.255", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "255.255.255.255");

    // IPv4, casual
    addr = LookupHost("12.34.56.78", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "12.34.56.78");

    // IPv6, in6addr_any
    addr = LookupHost("::", false).value();
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "::");

    // IPv6, casual
    addr = LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    addr = LookupHost(scoped_addr, false).value();
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), scoped_addr);

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    // TORv3
    const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char* i2p_addr = "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of bytes.
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(
        !addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_tostring_canonical_ipv6)
{
    // Test that CNetAddr::ToString formats IPv6 addresses with zero compression as described in
    // RFC 5952 ("A Recommendation for IPv6 Address Text Representation").
    const std::map<std::string, std::string> canonical_representations_ipv6{
        {"0000:0000:0000:0000:0000:0000:0000:0000", "::"},
        {"000:0000:000:00:0:00:000:0000", "::"},
        {"000:000:000:000:000:000:000:000", "::"},
        {"00:00:00:00:00:00:00:00", "::"},
        {"0:0:0:0:0:0:0:0", "::"},
        {"0:0:0:0:0:0:0:1", "::1"},
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:0db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:0db8::0001", "2001:db8::1"},
        {"2001:0db8::0001:0000", "2001:db8::1:0"},
        {"2001:0db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0:0:0:0:2:1", "2001:db8::2:1"},
        {"2001:db8:0:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:DB8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:aaaa::1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0::1", "2001:db8::1"},
        {"2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:db8::0:1", "2001:db8::1"},
        {"2001:db8::0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:DB8::1", "2001:db8::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:0:1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:01", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:1", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
    };
    for (const auto& [input_address, expected_canonical_representation_output] : canonical_representations_ipv6) {
        const std::optional<CNetAddr> net_addr{LookupHost(input_address, false)};
        BOOST_REQUIRE(net_addr.value().IsIPv6());
        BOOST_CHECK_EQUAL(net_addr.value().ToStringAddr(), expected_canonical_representation_output);
    }
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V1_NETWORK};

    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr = LookupHost("1.2.3.4", false).value();
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    addr = LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", false).value();
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V2_NETWORK};

    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    addr = LookupHost("1.2.3.4", false).value();
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    addr = LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", false).value();
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << ser_params(addr);
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    DataStream s{};
    const auto ser_params{CAddress::V2_NETWORK};

    // Valid IPv4.
    s << "01"            // network type (IPv4)
         "04"            // address length
         "01020304"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << "01"        // network type (IPv4)
         "04"        // address length
         "0102"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << "01"            // network type (IPv4)
         "05"            // address length
         "01020304"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << "01"            // network type (IPv4)
         "fd0102"        // address length (513 as CompactSize)
         "01020304"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << "02"                                    // network type (IPv6)
         "10"                                    // address length
         "0102030405060708090a0b0c0d0e0f10"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << "02"                                    // network type (IPv6)
         "10"                                    // address length
         "fd6b88c08724ca978112ca1bbdcafac2"_hex; // address: 0xfd + sha256("bitcoin")[0:5] +
                                                 // sha256(name)[0:10]
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << "02"      // network type (IPv6)
         "04"      // address length
         "00"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << "02"                                    // network type (IPv6)
         "10"                                    // address length
         "00000000000000000000ffff01020304"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << "02"                                    // network type (IPv6)
         "10"                                    // address length
         "fd87d87eeb430102030405060708090a"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // TORv2, no longer supported.
    s << "03"                        // network type (TORv2)
         "0a"                        // address length
         "f1f2f3f4f5f6f7f8f9fa"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    s << "04"                               // network type (TORv3)
         "20"                               // address length
         "79bcc625184b05194975c28b66b66b04" // address
         "69f7f6556fb1ac3189a79b40dda32f1f"_hex;
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << "04"      // network type (TORv3)
         "00"      // address length
         "00"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << "05"                               // network type (I2P)
         "20"                               // address length
         "a2894dabaec08c0051a481a6dac88b64" // address
         "f98232ae42d4b6fd2fa81952dfe36a87"_hex;
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(),
                      "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << "05"      // network type (I2P)
         "03"      // address length
         "00"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << "06"                                    // network type (CJDNS)
         "10"                                    // address length
         "fc000001000200030004000500060007"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToStringAddr(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << "06"                                    // network type (CJDNS)
         "10"                                    // address length
         "aa000001000200030004000500060007"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << "06"      // network type (CJDNS)
         "01"      // address length
         "00"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << "aa"                  // network type (unknown)
         "fe00000002"          // address length (CompactSize's MAX_SIZE)
         "01020304050607"_hex; // address
    BOOST_CHECK_EXCEPTION(s >> ser_params(addr), std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << "aa"            // network type (unknown)
         "04"            // address length
         "01020304"_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << "aa"    // network type (unknown)
         "00"    // address length
         ""_hex; // address
    s >> ser_params(addr);
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(/*id=*/0,
                                                           /*sock=*/nullptr,
                                                           addr,
                                                           /*nKeyedNetGroupIn=*/0,
                                                           /*nLocalHostNonceIn=*/0,
                                                           CAddress{},
                                                           /*pszDest=*/std::string{},
                                                           ConnectionType::OUTBOUND_FULL_RELAY,
                                                           /*inbound_onion=*/false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    GetLocalAddrForPeer(*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port)
{
    // Test that GetLocalAddrForPeer() properly selects the address to self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the port.
    // 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{/*id=*/0,
                   /*sock=*/nullptr,
                   /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*addrBindIn=*/CService{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{/*id=*/0,
                  /*sock=*/nullptr,
                  /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  /*addrBindIn=*/CService{},
                  /*addrNameIn=*/std::string{},
                  /*conn_type_in=*/ConnectionType::INBOUND,
                  /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV4));
    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV6));
    BOOST_CHECK(g_reachable_nets.Contains(NET_ONION));
    BOOST_CHECK(g_reachable_nets.Contains(NET_I2P));
    BOOST_CHECK(g_reachable_nets.Contains(NET_CJDNS));

    g_reachable_nets.Remove(NET_IPV4);
    g_reachable_nets.Remove(NET_IPV6);
    g_reachable_nets.Remove(NET_ONION);
    g_reachable_nets.Remove(NET_I2P);
    g_reachable_nets.Remove(NET_CJDNS);

    BOOST_CHECK(!g_reachable_nets.Contains(NET_IPV4));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_IPV6));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_ONION));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_I2P));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_CJDNS));

    g_reachable_nets.Add(NET_IPV4);
    g_reachable_nets.Add(NET_IPV6);
    g_reachable_nets.Add(NET_ONION);
    g_reachable_nets.Add(NET_I2P);
    g_reachable_nets.Add(NET_CJDNS);

    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV4));
    BOOST_CHECK(g_reachable_nets.Contains(NET_IPV6));
    BOOST_CHECK(g_reachable_nets.Contains(NET_ONION));
    BOOST_CHECK(g_reachable_nets.Contains(NET_I2P));
    BOOST_CHECK(g_reachable_nets.Contains(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    // Should be reachable by default.
    BOOST_CHECK(g_reachable_nets.Contains(NET_UNROUTABLE));
    BOOST_CHECK(g_reachable_nets.Contains(NET_INTERNAL));

    g_reachable_nets.RemoveAll();

    BOOST_CHECK(!g_reachable_nets.Contains(NET_UNROUTABLE));
    BOOST_CHECK(!g_reachable_nets.Contains(NET_INTERNAL));

    g_reachable_nets.Add(NET_IPV4);
    g_reachable_nets.Add(NET_IPV6);
    g_reachable_nets.Add(NET_ONION);
    g_reachable_nets.Add(NET_I2P);
    g_reachable_nets.Add(NET_CJDNS);
    g_reachable_nets.Add(NET_UNROUTABLE);
    g_reachable_nets.Add(NET_INTERNAL);
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    g_reachable_nets.Add(NET_IPV4);
    BOOST_CHECK(g_reachable_nets.Contains(addr));

    g_reachable_nets.Remove(NET_IPV4);
    BOOST_CHECK(!g_reachable_nets.Contains(addr));

    g_reachable_nets.Add(NET_IPV4); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    g_reachable_nets.Add(NET_IPV4);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP connection,
    //   we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*addrBindIn=*/CService{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};

    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    const int64_t time{0};

    // Force ChainstateManager::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    auto& chainman = static_cast<TestChainstateManager&>(*m_node.chainman);
    chainman.JumpOutOfIbd();

    m_node.peerman->InitializeNode(peer, NODE_NETWORK);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    const auto msg_version =
        NetMsg::Make(NetMsgType::VERSION, PROTOCOL_VERSION, services, time, services, CAddress::V1_NETWORK(peer_us));
    DataStream msg_version_stream{msg_version.data};

    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERSION, msg_version_stream, time_received_dummy, interrupt_dummy);

    const auto msg_verack = NetMsg::Make(NetMsgType::VERACK);
    DataStream msg_verack_stream{msg_verack.data};

    // Will set peer.fSuccessfullyConnected to true (necessary in SendMessages()).
    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERACK, msg_verack_stream, time_received_dummy, interrupt_dummy);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage = [&sent, &expected](const CAddress& addr,
                                        const std::string& msg_type,
                                        std::span<const unsigned char> data,
                                        bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            DataStream s{data};
            std::vector<CAddress> addresses;

            s >> CAddress::V1_NETWORK(addresses);

            for (const auto& addr : addresses) {
                if (addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    m_node.peerman->SendMessages(&peer);

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainman.ResetIbd();
    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
}


BOOST_AUTO_TEST_CASE(advertise_local_address)
{
    auto CreatePeer = [](const CAddress& addr) {
        return std::make_unique<CNode>(/*id=*/0,
                                       /*sock=*/nullptr,
                                       addr,
                                       /*nKeyedNetGroupIn=*/0,
                                       /*nLocalHostNonceIn=*/0,
                                       CAddress{},
                                       /*pszDest=*/std::string{},
                                       ConnectionType::OUTBOUND_FULL_RELAY,
                                       /*inbound_onion=*/false);
    };
    g_reachable_nets.Add(NET_CJDNS);

    CAddress addr_ipv4{Lookup("1.2.3.4", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_ipv4.IsValid());
    BOOST_REQUIRE(addr_ipv4.IsIPv4());

    CAddress addr_ipv6{Lookup("1122:3344:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_ipv6.IsValid());
    BOOST_REQUIRE(addr_ipv6.IsIPv6());

    CAddress addr_ipv6_tunnel{Lookup("2002:3344:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_ipv6_tunnel.IsValid());
    BOOST_REQUIRE(addr_ipv6_tunnel.IsIPv6());
    BOOST_REQUIRE(addr_ipv6_tunnel.IsRFC3964());

    CAddress addr_teredo{Lookup("2001:0000:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    BOOST_REQUIRE(addr_teredo.IsValid());
    BOOST_REQUIRE(addr_teredo.IsIPv6());
    BOOST_REQUIRE(addr_teredo.IsRFC4380());

    CAddress addr_onion;
    BOOST_REQUIRE(addr_onion.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    BOOST_REQUIRE(addr_onion.IsValid());
    BOOST_REQUIRE(addr_onion.IsTor());

    CAddress addr_i2p;
    BOOST_REQUIRE(addr_i2p.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p"));
    BOOST_REQUIRE(addr_i2p.IsValid());
    BOOST_REQUIRE(addr_i2p.IsI2P());

    CService service_cjdns{Lookup("fc00:3344:5566:7788:9900:aabb:ccdd:eeff", 8333, false).value(), NODE_NONE};
    CAddress addr_cjdns{MaybeFlipIPv6toCJDNS(service_cjdns), NODE_NONE};
    BOOST_REQUIRE(addr_cjdns.IsValid());
    BOOST_REQUIRE(addr_cjdns.IsCJDNS());

    const auto peer_ipv4{CreatePeer(addr_ipv4)};
    const auto peer_ipv6{CreatePeer(addr_ipv6)};
    const auto peer_ipv6_tunnel{CreatePeer(addr_ipv6_tunnel)};
    const auto peer_teredo{CreatePeer(addr_teredo)};
    const auto peer_onion{CreatePeer(addr_onion)};
    const auto peer_i2p{CreatePeer(addr_i2p)};
    const auto peer_cjdns{CreatePeer(addr_cjdns)};

    // one local clearnet address - advertise to all but privacy peers
    AddLocal(addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv4) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6_tunnel) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_teredo) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_cjdns) == addr_ipv4);
    BOOST_CHECK(!GetLocalAddress(*peer_onion).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_i2p).IsValid());
    RemoveLocal(addr_ipv4);

    // local privacy addresses - don't advertise to clearnet peers
    AddLocal(addr_onion);
    AddLocal(addr_i2p);
    BOOST_CHECK(!GetLocalAddress(*peer_ipv4).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_ipv6).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_ipv6_tunnel).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_teredo).IsValid());
    BOOST_CHECK(!GetLocalAddress(*peer_cjdns).IsValid());
    BOOST_CHECK(GetLocalAddress(*peer_onion) == addr_onion);
    BOOST_CHECK(GetLocalAddress(*peer_i2p) == addr_i2p);
    RemoveLocal(addr_onion);
    RemoveLocal(addr_i2p);

    // local addresses from all networks
    AddLocal(addr_ipv4);
    AddLocal(addr_ipv6);
    AddLocal(addr_ipv6_tunnel);
    AddLocal(addr_teredo);
    AddLocal(addr_onion);
    AddLocal(addr_i2p);
    AddLocal(addr_cjdns);
    BOOST_CHECK(GetLocalAddress(*peer_ipv4) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6) == addr_ipv6);
    BOOST_CHECK(GetLocalAddress(*peer_ipv6_tunnel) == addr_ipv6);
    BOOST_CHECK(GetLocalAddress(*peer_teredo) == addr_ipv4);
    BOOST_CHECK(GetLocalAddress(*peer_onion) == addr_onion);
    BOOST_CHECK(GetLocalAddress(*peer_i2p) == addr_i2p);
    BOOST_CHECK(GetLocalAddress(*peer_cjdns) == addr_cjdns);
    RemoveLocal(addr_ipv4);
    RemoveLocal(addr_ipv6);
    RemoveLocal(addr_ipv6_tunnel);
    RemoveLocal(addr_teredo);
    RemoveLocal(addr_onion);
    RemoveLocal(addr_i2p);
    RemoveLocal(addr_cjdns);
}

namespace {

CKey GenerateRandomTestKey(FastRandomContext& rng) noexcept
{
    CKey key;
    uint256 key_data = rng.rand256();
    key.Set(key_data.begin(), key_data.end(), true);
    return key;
}

/** A class for scenario-based tests of V2Transport
 *
 * Each V2TransportTester encapsulates a V2Transport (the one being tested), and can be told to
 * interact with it. To do so, it also encapsulates a BIP324Cipher to act as the other side. A
 * second V2Transport is not used, as doing so would not permit scenarios that involve sending
 * invalid data, or ones using BIP324 features that are not implemented on the sending
 * side (like decoy packets).
 */
class V2TransportTester
{
    FastRandomContext& m_rng;
    V2Transport m_transport; //!< V2Transport being tested
    BIP324Cipher m_cipher; //!< Cipher to help with the other side
    bool m_test_initiator; //!< Whether m_transport is the initiator (true) or responder (false)
    PQHandshake m_peer_pq; //!< The other side's hybrid negotiation state

    std::vector<uint8_t> m_sent_garbage; //!< The garbage we've sent to m_transport.
    std::vector<uint8_t> m_recv_garbage; //!< The garbage we've received from m_transport.
    std::vector<uint8_t> m_to_send; //!< Bytes we have queued up to send to m_transport.
    std::vector<uint8_t> m_received; //!< Bytes we have received from m_transport.
    std::deque<CSerializedNetMsg> m_msg_to_send; //!< Messages to be sent *by* m_transport to us.
    bool m_sent_aad{false};

public:
    /** Construct a tester object. test_initiator: whether the tested transport is initiator. */
    explicit V2TransportTester(FastRandomContext& rng, bool test_initiator, V2PQOptions pq = {})
        : m_rng{rng},
          m_transport{0, test_initiator, pq},
          m_cipher{GenerateRandomTestKey(m_rng), MakeByteSpan(m_rng.rand256())},
          m_test_initiator(test_initiator),
          m_peer_pq{!test_initiator, PQMode::NEGOTIATE} {}

    /** Construct a tester object whose transport uses the given ML-KEM entropy and operations. */
    V2TransportTester(FastRandomContext& rng, bool test_initiator, V2PQOptions pq, PQRandomSource random, const PQKemOps& ops)
        : m_rng{rng},
          m_transport{0, test_initiator, GenerateRandomTestKey(rng), MakeByteSpan(rng.rand256()),
                      rng.randbytes<uint8_t>(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1)), pq, random, ops},
          m_cipher{GenerateRandomTestKey(m_rng), MakeByteSpan(m_rng.rand256())},
          m_test_initiator(test_initiator),
          m_peer_pq{!test_initiator, PQMode::NEGOTIATE} {}

    /** Data type returned by Interact:
     *
     * - std::nullopt: transport error occurred
     * - otherwise: a vector of
     *   - std::nullopt: invalid message received
     *   - otherwise: a CNetMessage retrieved
     */
    using InteractResult = std::optional<std::vector<std::optional<CNetMessage>>>;

    /** Send/receive scheduled/available bytes and messages.
     *
     * This is the only function that interacts with the transport being tested; everything else is
     * scheduling things done by Interact(), or processing things learned by it.
     */
    InteractResult Interact()
    {
        std::vector<std::optional<CNetMessage>> ret;
        while (true) {
            bool progress{false};
            // Send bytes from m_to_send to the transport.
            if (!m_to_send.empty()) {
                std::span<const uint8_t> to_send = std::span{m_to_send}.first(1 + m_rng.randrange(m_to_send.size()));
                size_t old_len = to_send.size();
                if (!m_transport.ReceivedBytes(to_send)) {
                    return std::nullopt; // transport error occurred
                }
                if (old_len != to_send.size()) {
                    progress = true;
                    m_to_send.erase(m_to_send.begin(), m_to_send.begin() + (old_len - to_send.size()));
                }
            }
            // Retrieve messages received by the transport.
            if (m_transport.ReceivedMessageComplete() && (!progress || m_rng.randbool())) {
                bool reject{false};
                auto msg = m_transport.GetReceivedMessage({}, reject);
                if (reject) {
                    ret.emplace_back(std::nullopt);
                } else {
                    ret.emplace_back(std::move(msg));
                }
                progress = true;
            }
            // Enqueue a message to be sent by the transport to us.
            if (!m_msg_to_send.empty() && (!progress || m_rng.randbool())) {
                if (m_transport.SetMessageToSend(m_msg_to_send.front())) {
                    m_msg_to_send.pop_front();
                    progress = true;
                }
            }
            // Receive bytes from the transport.
            const auto& [recv_bytes, _more, _msg_type] = m_transport.GetBytesToSend(!m_msg_to_send.empty());
            if (!recv_bytes.empty() && (!progress || m_rng.randbool())) {
                size_t to_receive = 1 + m_rng.randrange(recv_bytes.size());
                m_received.insert(m_received.end(), recv_bytes.begin(), recv_bytes.begin() + to_receive);
                progress = true;
                m_transport.MarkBytesSent(to_receive);
            }
            if (!progress) break;
        }
        return ret;
    }

    /** Expose the cipher. */
    BIP324Cipher& GetCipher() { return m_cipher; }

    /** Expose the transport being tested. */
    V2Transport& GetTransport() { return m_transport; }

    /** The bytes scheduled to be sent to the transport. */
    std::vector<uint8_t>& ToSend() { return m_to_send; }

    /** The bytes received from the transport and not processed yet. */
    std::vector<uint8_t>& Received() { return m_received; }

    /** Deliver scheduled bytes to the transport, all in one call or one byte per call. Returns false
     *  (leaving the rest scheduled) at the first transport error. */
    bool Deliver(bool byte_by_byte = false)
    {
        while (!m_to_send.empty()) {
            std::span<const uint8_t> to_send{m_to_send};
            if (byte_by_byte) to_send = to_send.first(1);
            const size_t old_len{to_send.size()};
            const bool ret{m_transport.ReceivedBytes(to_send)};
            m_to_send.erase(m_to_send.begin(), m_to_send.begin() + (old_len - to_send.size()));
            if (!ret) return false;
            BOOST_REQUIRE(to_send.empty() || m_transport.ReceivedMessageComplete());
            if (!to_send.empty()) return true;
        }
        return true;
    }

    /** Take every byte the transport has to send. */
    void Collect()
    {
        while (true) {
            const auto& [bytes, _more, _msg_type] = m_transport.GetBytesToSend(false);
            if (bytes.empty()) break;
            m_received.insert(m_received.end(), bytes.begin(), bytes.end());
            m_transport.MarkBytesSent(bytes.size());
        }
    }

    /** Schedule bytes to be sent to the transport. */
    void Send(std::span<const uint8_t> data)
    {
        m_to_send.insert(m_to_send.end(), data.begin(), data.end());
    }

    /** Send V1 version message header to the transport. */
    void SendV1Version(const MessageStartChars& magic)
    {
        CMessageHeader hdr(magic, "version", 126 + m_rng.randrange(11));
        DataStream ser{};
        ser << hdr;
        m_to_send.insert(m_to_send.end(), UCharCast(ser.data()), UCharCast(ser.data() + ser.size()));
    }

    /** Schedule bytes to be sent to the transport. */
    void Send(std::span<const std::byte> data) { Send(MakeUCharSpan(data)); }

    /** Schedule our ellswift key to be sent to the transport. */
    void SendKey() { Send(m_cipher.GetOurPubKey()); }

    /** Schedule specified garbage to be sent to the transport. */
    void SendGarbage(std::span<const uint8_t> garbage)
    {
        // Remember the specified garbage (so we can use it as AAD).
        m_sent_garbage.assign(garbage.begin(), garbage.end());
        // Schedule it for sending.
        Send(m_sent_garbage);
    }

    /** Schedule garbage (of specified length) to be sent to the transport. */
    void SendGarbage(size_t garbage_len)
    {
        // Generate random garbage and send it.
        SendGarbage(m_rng.randbytes<uint8_t>(garbage_len));
    }

    /** Schedule garbage (with valid random length) to be sent to the transport. */
    void SendGarbage()
    {
         SendGarbage(m_rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1));
    }

    /** Schedule a message to be sent to us by the transport. */
    void AddMessage(std::string m_type, std::vector<uint8_t> payload)
    {
        CSerializedNetMsg msg;
        msg.m_type = std::move(m_type);
        msg.data = std::move(payload);
        m_msg_to_send.push_back(std::move(msg));
    }

    /** Expect ellswift key to have been received from transport and process it.
     *
     * Many other V2TransportTester functions cannot be called until after ReceiveKey() has been
     * called, as no encryption keys are set up before that point.
     */
    void ReceiveKey(bool retain_for_hybrid = false)
    {
        // When processing a key, enough bytes need to have been received already.
        BOOST_REQUIRE(m_received.size() >= EllSwiftPubKey::size());
        // Initialize the cipher using it (acting as the opposite side of the tested transport).
        m_cipher.Initialize(MakeByteSpan(m_received).first(EllSwiftPubKey::size()), !m_test_initiator,
                            /*self_decrypt=*/false, retain_for_hybrid);
        // Strip the processed bytes off the front of the receive buffer.
        m_received.erase(m_received.begin(), m_received.begin() + EllSwiftPubKey::size());
    }

    /** Schedule an encrypted packet with specified content/aad/ignore to be sent to transport
     *  (only after ReceiveKey). */
    void SendPacket(std::span<const uint8_t> content, std::span<const uint8_t> aad = {}, bool ignore = false)
    {
        // Use cipher to construct ciphertext.
        std::vector<std::byte> ciphertext;
        ciphertext.resize(content.size() + BIP324Cipher::EXPANSION);
        m_cipher.Encrypt(
            /*contents=*/MakeByteSpan(content),
            /*aad=*/MakeByteSpan(aad),
            /*ignore=*/ignore,
            /*output=*/ciphertext);
        // Schedule it for sending.
        Send(ciphertext);
    }

    /** Schedule garbage terminator to be sent to the transport (only after ReceiveKey). */
    void SendGarbageTerm()
    {
        // Schedule the garbage terminator to be sent.
        Send(m_cipher.GetSendGarbageTerminator());
    }

    /** Schedule version packet to be sent to the transport (only after ReceiveKey). */
    void SendVersion(std::span<const uint8_t> version_data = {}, bool vers_ignore = false)
    {
        std::span<const std::uint8_t> aad;
        // Set AAD to garbage only for first packet.
        if (!m_sent_aad) aad = m_sent_garbage;
        SendPacket(/*content=*/version_data, /*aad=*/aad, /*ignore=*/vers_ignore);
        m_sent_aad = true;
    }

    /** Expect a packet to have been received from transport, process it, and return its contents
     *  (only after ReceiveKey). Decoys are skipped. Optional associated authenticated data (AAD) is
     *  expected in the first received packet, no matter if that is a decoy or not. */
    std::vector<uint8_t> ReceivePacket(std::span<const std::byte> aad = {})
    {
        std::vector<uint8_t> contents;
        // Loop as long as there are ignored packets that are to be skipped.
        while (true) {
            // When processing a packet, at least enough bytes for its length descriptor must be received.
            BOOST_REQUIRE(m_received.size() >= BIP324Cipher::LENGTH_LEN);
            // Decrypt the content length.
            size_t size = m_cipher.DecryptLength(MakeByteSpan(std::span{m_received}.first(BIP324Cipher::LENGTH_LEN)));
            // Check that the full packet is in the receive buffer.
            BOOST_REQUIRE(m_received.size() >= size + BIP324Cipher::EXPANSION);
            // Decrypt the packet contents.
            contents.resize(size);
            bool ignore{false};
            bool ret = m_cipher.Decrypt(
                /*input=*/MakeByteSpan(
                    std::span{m_received}.first(size + BIP324Cipher::EXPANSION).subspan(BIP324Cipher::LENGTH_LEN)),
                /*aad=*/aad,
                /*ignore=*/ignore,
                /*contents=*/MakeWritableByteSpan(contents));
            BOOST_CHECK(ret);
            // Don't expect AAD in further packets.
            aad = {};
            // Strip the processed packet's bytes off the front of the receive buffer.
            m_received.erase(m_received.begin(), m_received.begin() + size + BIP324Cipher::EXPANSION);
            // Stop if the ignore bit is not set on this packet.
            if (!ignore) break;
        }
        return contents;
    }

    /** Expect garbage and garbage terminator to have been received, and process them (only after
     *  ReceiveKey). */
    void ReceiveGarbage()
    {
        // Figure out the garbage length.
        size_t garblen;
        for (garblen = 0; garblen <= V2Transport::MAX_GARBAGE_LEN; ++garblen) {
            BOOST_REQUIRE(m_received.size() >= garblen + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
            auto term_span = MakeByteSpan(std::span{m_received}.subspan(garblen, BIP324Cipher::GARBAGE_TERMINATOR_LEN));
            if (std::ranges::equal(term_span, m_cipher.GetReceiveGarbageTerminator())) break;
        }
        // Copy the garbage to a buffer.
        m_recv_garbage.assign(m_received.begin(), m_received.begin() + garblen);
        // Strip garbage + garbage terminator off the front of the receive buffer.
        m_received.erase(m_received.begin(), m_received.begin() + garblen + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
    }

    /** Expect version packet to have been received, and process it (only after ReceiveKey). */
    void ReceiveVersion()
    {
        auto contents = ReceivePacket(/*aad=*/MakeByteSpan(m_recv_garbage));
        // Version packets from real BIP324 peers are expected to be empty, despite the fact that
        // this class supports *sending* non-empty version packets (to test that BIP324 peers
        // correctly ignore version packet contents).
        BOOST_CHECK(contents.empty());
    }

    /** Expect a version packet to have been received, process it and return its contents (only
     *  after ReceiveKey). */
    std::vector<uint8_t> ReceiveVersionContents()
    {
        return ReceivePacket(/*aad=*/MakeByteSpan(m_recv_garbage));
    }

    /** Expect a key confirmation: exactly one empty decoy packet (only after a switch). */
    void ReceiveConfirmation()
    {
        BOOST_REQUIRE(m_received.size() >= PQ_CONFIRMATION_BYTES);
        const auto packet{MakeByteSpan(std::span{m_received}.first(PQ_CONFIRMATION_BYTES))};
        BOOST_CHECK_EQUAL(m_cipher.DecryptLength(packet.first(BIP324Cipher::LENGTH_LEN)), 0U);
        bool ignore{false};
        BOOST_CHECK(m_cipher.Decrypt(packet.subspan(BIP324Cipher::LENGTH_LEN), /*aad=*/{}, ignore, /*contents=*/{}));
        BOOST_CHECK(ignore);
        m_received.erase(m_received.begin(), m_received.begin() + PQ_CONFIRMATION_BYTES);
    }

    /** Schedule our key confirmation, an empty decoy (only after a switch). */
    void SendConfirmation() { SendPacket(/*content=*/{}, /*aad=*/{}, /*ignore=*/true); }

    /** As a hybrid responder (after ReceiveKey(true) and SendGarbageTerm): schedule our version
     *  packet with an offer, followed by extra contents. */
    void SendOffer(std::span<const std::byte> extra = {})
    {
        PQHandshake::Record offer;
        BOOST_REQUIRE(m_peer_pq.MakeOffer(offer) == mlkem::Error::NONE);
        std::vector<std::byte> contents{offer.begin(), offer.end()};
        contents.insert(contents.end(), extra.begin(), extra.end());
        BOOST_REQUIRE(m_cipher.AddVersionContents(contents));
        SendVersion(MakeUCharSpan(contents));
    }

    /** As a hybrid responder: process the transport's version packet, which must carry a valid
     *  accept, and switch keys; invert_ss inverts byte 0 of our ML-KEM secret first. */
    void ReceiveAcceptAndSwitch(bool invert_ss = false)
    {
        const auto contents{ReceiveVersionContents()};
        BOOST_REQUIRE(m_cipher.AddVersionContents(MakeByteSpan(contents)));
        const auto parsed{PQHandshake::ParseContents(MakeByteSpan(contents))};
        BOOST_REQUIRE(parsed.kind == PQHandshake::ParseKind::OWN_RECORD);
        const auto ct{m_peer_pq.CheckRecordLength(parsed.payload)};
        BOOST_REQUIRE(ct);
        mlkem::SharedSecret ss;
        BOOST_REQUIRE(m_peer_pq.DecapsulateAccept(*ct, ss) == mlkem::Error::NONE);
        if (invert_ss) ss.Bytes()[0] ^= 0xff;
        BOOST_REQUIRE(m_cipher.SwitchToHybrid(std::as_bytes(ss.Bytes())));
    }

    /** As a hybrid initiator (after ReceiveKey(true) and SendGarbageTerm): process the transport's
     *  version packet, which must carry a valid offer, schedule our version packet with the accept
     *  under the ECDH keys, and switch keys. damage_ct flips a ciphertext bit after hashing it;
     *  invert_ss inverts byte 0 of our ML-KEM secret before switching. */
    void AcceptOfferAndSwitch(bool damage_ct = false, bool invert_ss = false)
    {
        const auto contents{ReceiveVersionContents()};
        BOOST_REQUIRE(m_cipher.AddVersionContents(MakeByteSpan(contents)));
        const auto parsed{PQHandshake::ParseContents(MakeByteSpan(contents))};
        BOOST_REQUIRE(parsed.kind == PQHandshake::ParseKind::OWN_RECORD);
        const auto ek{m_peer_pq.CheckRecordLength(parsed.payload)};
        BOOST_REQUIRE(ek);
        PQHandshake::Record accept;
        mlkem::SharedSecret ss;
        BOOST_REQUIRE(m_peer_pq.AcceptOffer(*ek, accept, ss) == mlkem::Error::NONE);
        BOOST_REQUIRE(m_cipher.AddVersionContents(accept));
        if (damage_ct) accept[4 + m_rng.randrange(mlkem::CIPHERTEXT_BYTES)] ^= std::byte(1 << m_rng.randrange(8));
        SendVersion(MakeUCharSpan(accept));
        if (invert_ss) ss.Bytes()[0] ^= 0xff;
        BOOST_REQUIRE(m_cipher.SwitchToHybrid(std::as_bytes(ss.Bytes())));
    }

    /** Expect application packet to have been received, with specified short id and payload.
     *  (only after ReceiveKey). */
    void ReceiveMessage(uint8_t short_id, std::span<const uint8_t> payload)
    {
        auto ret = ReceivePacket();
        BOOST_CHECK(ret.size() == payload.size() + 1);
        BOOST_CHECK(ret[0] == short_id);
        BOOST_CHECK(std::ranges::equal(std::span{ret}.subspan(1), payload));
    }

    /** Expect application packet to have been received, with specified 12-char message type and
     *  payload (only after ReceiveKey). */
    void ReceiveMessage(const std::string& m_type, std::span<const uint8_t> payload)
    {
        auto ret = ReceivePacket();
        BOOST_REQUIRE(ret.size() == payload.size() + 1 + CMessageHeader::MESSAGE_TYPE_SIZE);
        BOOST_CHECK(ret[0] == 0);
        for (unsigned i = 0; i < 12; ++i) {
            if (i < m_type.size()) {
                BOOST_CHECK(ret[1 + i] == m_type[i]);
            } else {
                BOOST_CHECK(ret[1 + i] == 0);
            }
        }
        BOOST_CHECK(std::ranges::equal(std::span{ret}.subspan(1 + CMessageHeader::MESSAGE_TYPE_SIZE), payload));
    }

    /** Schedule an encrypted packet with specified message type and payload to be sent to
     *  transport (only after ReceiveKey). */
    void SendMessage(std::string mtype, std::span<const uint8_t> payload)
    {
        // Construct contents consisting of 0x00 + 12-byte message type + payload.
        std::vector<uint8_t> contents(1 + CMessageHeader::MESSAGE_TYPE_SIZE + payload.size());
        std::copy(mtype.begin(), mtype.end(), reinterpret_cast<char*>(contents.data() + 1));
        std::copy(payload.begin(), payload.end(), contents.begin() + 1 + CMessageHeader::MESSAGE_TYPE_SIZE);
        // Send a packet with that as contents.
        SendPacket(contents);
    }

    /** Schedule an encrypted packet with specified short message id and payload to be sent to
     *  transport (only after ReceiveKey). */
    void SendMessage(uint8_t short_id, std::span<const uint8_t> payload)
    {
        // Construct contents consisting of short_id + payload.
        std::vector<uint8_t> contents(1 + payload.size());
        contents[0] = short_id;
        std::copy(payload.begin(), payload.end(), contents.begin() + 1);
        // Send a packet with that as contents.
        SendPacket(contents);
    }

    /** Test whether the transport's session ID matches the session ID we expect. */
    void CompareSessionIDs() const
    {
        auto info = m_transport.GetInfo();
        BOOST_CHECK(info.session_id);
        BOOST_CHECK(uint256(MakeUCharSpan(m_cipher.GetSessionID())) == *info.session_id);
    }

    /** Introduce a bit error in the data scheduled to be sent. */
    void Damage()
    {
        m_to_send[m_rng.randrange(m_to_send.size())] ^= (uint8_t{1} << m_rng.randrange(8));
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(v2transport_test)
{
    // A mostly normal scenario, testing a transport in initiator mode.
    for (int i = 0; i < 10; ++i) {
        V2TransportTester tester(m_rng, true);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.SendGarbage();
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        tester.SendVersion();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        auto msg_data_1 = m_rng.randbytes<uint8_t>(m_rng.randrange(100000));
        auto msg_data_2 = m_rng.randbytes<uint8_t>(m_rng.randrange(1000));
        tester.SendMessage(uint8_t(4), msg_data_1); // cmpctblock short id
        tester.SendMessage(0, {}); // Invalidly encoded message
        tester.SendMessage("tx", msg_data_2); // 12-character encoded message type
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 3);
        BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "cmpctblock" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(msg_data_1)));
        BOOST_CHECK(!(*ret)[1]);
        BOOST_CHECK((*ret)[2] && (*ret)[2]->m_type == "tx" && std::ranges::equal((*ret)[2]->m_recv, MakeByteSpan(msg_data_2)));

        // Then send a message with a bit error, expecting failure. It's possible this failure does
        // not occur immediately (when the length descriptor was modified), but it should come
        // eventually, and no messages can be delivered anymore.
        tester.SendMessage("bad", msg_data_1);
        tester.Damage();
        while (true) {
            ret = tester.Interact();
            if (!ret) break; // failure
            BOOST_CHECK(ret->size() == 0); // no message can be delivered
            // Send another message.
            auto msg_data_3 = m_rng.randbytes<uint8_t>(m_rng.randrange(10000));
            tester.SendMessage(uint8_t(12), msg_data_3); // getheaders short id
        }
    }

    // Normal scenario, with a transport in responder node.
    for (int i = 0; i < 10; ++i) {
        V2TransportTester tester(m_rng, false);
        tester.SendKey();
        tester.SendGarbage();
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        tester.SendVersion();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        auto msg_data_1 = m_rng.randbytes<uint8_t>(m_rng.randrange(100000));
        auto msg_data_2 = m_rng.randbytes<uint8_t>(m_rng.randrange(1000));
        tester.SendMessage(uint8_t(14), msg_data_1); // inv short id
        tester.SendMessage(uint8_t(19), msg_data_2); // pong short id
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 2);
        BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "inv" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(msg_data_1)));
        BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "pong" && std::ranges::equal((*ret)[1]->m_recv, MakeByteSpan(msg_data_2)));

        // Then send a too-large message.
        auto msg_data_3 = m_rng.randbytes<uint8_t>(4005000);
        tester.SendMessage(uint8_t(11), msg_data_3); // getdata short id
        ret = tester.Interact();
        BOOST_CHECK(!ret);
    }

    // Various valid but unusual scenarios. The last 50 have the hybrid negotiation on, with a legacy
    // peer.
    for (int i = 0; i < 100; ++i) {
        /** Whether the tested transport negotiates hybrid keys. */
        const bool pq{i >= 50};
        /** Whether an initiator or responder is being tested. */
        bool initiator = m_rng.randbool();
        /** Use either 0 bytes or the maximum possible (4095 bytes) garbage length. */
        size_t garb_len = m_rng.randbool() ? 0 : V2Transport::MAX_GARBAGE_LEN;
        /** How many decoy packets to send before the version packet. */
        unsigned num_ignore_version = m_rng.randrange(10);
        /** What data to send in the version packet (ignored by BIP324 peers, but reserved for future extensions). */
        auto ver_data = m_rng.randbytes<uint8_t>(m_rng.randbool() ? 0 : m_rng.randrange(1000));
        // A legacy peer's random contents never carry an own record.
        while (pq && PQHandshake::ParseContents(MakeByteSpan(ver_data)).kind == PQHandshake::ParseKind::OWN_RECORD) {
            ver_data = m_rng.randbytes<uint8_t>(m_rng.randrange(1000));
        }
        /** Whether to immediately send key and garbage out (required for responders, optional otherwise). */
        bool send_immediately = !initiator || m_rng.randbool();
        /** How many decoy packets to send before the first and second real message. */
        unsigned num_decoys_1 = m_rng.randrange(1000), num_decoys_2 = m_rng.randrange(1000);
        V2TransportTester tester(m_rng, initiator, {.mode = pq ? PQMode::NEGOTIATE : PQMode::OFF});
        if (send_immediately) {
            tester.SendKey();
            tester.SendGarbage(garb_len);
        }
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        if (!send_immediately) {
            tester.SendKey();
            tester.SendGarbage(garb_len);
        }
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        for (unsigned v = 0; v < num_ignore_version; ++v) {
            size_t ver_ign_data_len = m_rng.randbool() ? 0 : m_rng.randrange(1000);
            auto ver_ign_data = m_rng.randbytes<uint8_t>(ver_ign_data_len);
            tester.SendVersion(ver_ign_data, true);
        }
        tester.SendVersion(ver_data, false);
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        if (pq && !initiator) {
            // The tested responder offered; the legacy peer ignores the offer.
            const auto contents{tester.ReceiveVersionContents()};
            BOOST_CHECK(PQHandshake::ParseContents(MakeByteSpan(contents)).kind == PQHandshake::ParseKind::OWN_RECORD);
        } else {
            tester.ReceiveVersion();
        }
        tester.CompareSessionIDs();
        for (unsigned d = 0; d < num_decoys_1; ++d) {
            auto decoy_data = m_rng.randbytes<uint8_t>(m_rng.randrange(1000));
            tester.SendPacket(/*content=*/decoy_data, /*aad=*/{}, /*ignore=*/true);
        }
        auto msg_data_1 = m_rng.randbytes<uint8_t>(m_rng.randrange(4000000));
        tester.SendMessage(uint8_t(28), msg_data_1);
        for (unsigned d = 0; d < num_decoys_2; ++d) {
            auto decoy_data = m_rng.randbytes<uint8_t>(m_rng.randrange(1000));
            tester.SendPacket(/*content=*/decoy_data, /*aad=*/{}, /*ignore=*/true);
        }
        auto msg_data_2 = m_rng.randbytes<uint8_t>(m_rng.randrange(1000));
        tester.SendMessage(uint8_t(13), msg_data_2); // headers short id
        // Send invalidly-encoded message
        tester.SendMessage(std::string("blocktxn\x00\x00\x00a", CMessageHeader::MESSAGE_TYPE_SIZE), {});
        tester.SendMessage("foobar", {}); // test receiving unknown message type
        tester.AddMessage("barfoo", {}); // test sending unknown message type
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 4);
        BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "addrv2" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(msg_data_1)));
        BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "headers" && std::ranges::equal((*ret)[1]->m_recv, MakeByteSpan(msg_data_2)));
        BOOST_CHECK(!(*ret)[2]);
        BOOST_CHECK((*ret)[3] && (*ret)[3]->m_type == "foobar" && (*ret)[3]->m_recv.empty());
        tester.ReceiveMessage("barfoo", {});
        const auto info{tester.GetTransport().GetInfo()};
        BOOST_CHECK(!info.transport_pq);
        BOOST_CHECK(info.transport_pq_status == (pq ? PQStatus::LEGACY_PEER : PQStatus::OFF));
    }

    // Too long garbage (initiator).
    {
        V2TransportTester tester(m_rng, true);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.SendGarbage(V2Transport::MAX_GARBAGE_LEN + 1);
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        ret = tester.Interact();
        BOOST_CHECK(!ret);
    }

    // Too long garbage (responder).
    {
        V2TransportTester tester(m_rng, false);
        tester.SendKey();
        tester.SendGarbage(V2Transport::MAX_GARBAGE_LEN + 1);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveKey();
        tester.SendGarbageTerm();
        ret = tester.Interact();
        BOOST_CHECK(!ret);
    }

    // Send garbage that includes the first 15 garbage terminator bytes somewhere.
    {
        V2TransportTester tester(m_rng, true);
        auto ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.ReceiveKey();
        /** The number of random garbage bytes before the included first 15 bytes of terminator. */
        size_t len_before = m_rng.randrange(V2Transport::MAX_GARBAGE_LEN - 16 + 1);
        /** The number of random garbage bytes after it. */
        size_t len_after = m_rng.randrange(V2Transport::MAX_GARBAGE_LEN - 16 - len_before + 1);
        // Construct len_before + 16 + len_after random bytes.
        auto garbage = m_rng.randbytes<uint8_t>(len_before + 16 + len_after);
        // Replace the designed 16 bytes in the middle with the to-be-sent garbage terminator.
        auto garb_term = MakeUCharSpan(tester.GetCipher().GetSendGarbageTerminator());
        std::copy(garb_term.begin(), garb_term.begin() + 16, garbage.begin() + len_before);
        // Introduce a bit error in the last byte of that copied garbage terminator, making only
        // the first 15 of them match.
        garbage[len_before + 15] ^= (uint8_t(1) << m_rng.randrange(8));
        tester.SendGarbage(garbage);
        tester.SendGarbageTerm();
        tester.SendVersion();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveVersion();
        tester.CompareSessionIDs();
        auto msg_data_1 = m_rng.randbytes<uint8_t>(4000000); // test that receiving 4M payload works
        auto msg_data_2 = m_rng.randbytes<uint8_t>(4000000); // test that sending 4M payload works
        tester.SendMessage(uint8_t(m_rng.randrange(223) + 33), {}); // unknown short id
        tester.SendMessage(uint8_t(2), msg_data_1); // "block" short id
        tester.AddMessage("blocktxn", msg_data_2); // schedule blocktxn to be sent to us
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->size() == 2);
        BOOST_CHECK(!(*ret)[0]);
        BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "block" && std::ranges::equal((*ret)[1]->m_recv, MakeByteSpan(msg_data_1)));
        tester.ReceiveMessage(uint8_t(3), msg_data_2); // "blocktxn" short id
    }

    // Send correct network's V1 header
    {
        V2TransportTester tester(m_rng, false);
        tester.SendV1Version(Params().MessageStart());
        auto ret = tester.Interact();
        BOOST_CHECK(ret);
    }

    // Send wrong network's V1 header
    {
        V2TransportTester tester(m_rng, false);
        tester.SendV1Version(CChainParams::Main()->MessageStart());
        auto ret = tester.Interact();
        BOOST_CHECK(!ret);
    }
}

namespace {

/** Deterministic PQ entropy: the queued 32-byte values in order, then SHA256(seed || counter). */
struct TestPQEntropy {
    std::deque<std::array<uint8_t, 32>> queued;
    uint256 seed;
    uint64_t counter{0};

    explicit TestPQEntropy(const uint256& seed_in) : seed{seed_in} {}

    static void Fill(void* context, std::span<uint8_t, 32> out) noexcept
    {
        auto& self{*static_cast<TestPQEntropy*>(context)};
        if (!self.queued.empty()) {
            std::ranges::copy(self.queued.front(), out.begin());
            self.queued.pop_front();
            return;
        }
        uint8_t counter_le[8];
        WriteLE64(counter_le, self.counter++);
        CSHA256().Write(self.seed.begin(), self.seed.size()).Write(counter_le, sizeof(counter_le)).Finalize(out.data());
    }

    PQRandomSource Source() { return {.fill32 = &Fill, .context = this}; }

    void Queue(std::span<const uint8_t> bytes)
    {
        BOOST_REQUIRE(bytes.size() % 32 == 0);
        for (size_t i{0}; i < bytes.size(); i += 32) {
            std::array<uint8_t, 32> value;
            std::ranges::copy(bytes.subspan(i, 32), value.begin());
            queued.push_back(value);
        }
    }
};

/** How often each ML-KEM operation ran through COUNTING_KEM_OPS. */
struct KemCallCounts {
    int keygen{0}, check{0}, encaps{0}, decaps{0};
    int total() const { return keygen + check + encaps + decaps; }
};
KemCallCounts g_kem_calls;

const PQKemOps COUNTING_KEM_OPS{
    .keygen = [](std::span<const uint8_t, mlkem::KEYGEN_SEED_BYTES> seed, mlkem::PublicKey& ek, mlkem::DecapsulationKey& dk) noexcept {
        ++g_kem_calls.keygen;
        return mlkem::KeyGen(seed, ek, dk);
    },
    .check_public_key = [](std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES> ek) noexcept {
        ++g_kem_calls.check;
        return mlkem::CheckPublicKey(ek);
    },
    .encaps = [](std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES> ek, std::span<const uint8_t, mlkem::ENCAPS_COINS_BYTES> coins,
                 mlkem::Ciphertext& ct, mlkem::SharedSecret& ss) noexcept {
        ++g_kem_calls.encaps;
        return mlkem::Encaps(ek, coins, ct, ss);
    },
    .decaps = [](const mlkem::DecapsulationKey& dk, std::span<const uint8_t, mlkem::CIPHERTEXT_BYTES> ct, mlkem::SharedSecret& ss) noexcept {
        ++g_kem_calls.decaps;
        return mlkem::Decaps(dk, ct, ss);
    },
};

std::vector<std::byte> HexBytes(std::string_view hex)
{
    auto bytes{TryParseHex<std::byte>(hex)};
    BOOST_REQUIRE(bytes);
    return std::move(*bytes);
}

std::vector<std::byte> Concat(std::initializer_list<std::span<const std::byte>> parts)
{
    std::vector<std::byte> out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

/** A record CompactSize(1 + payload size) || header || payload. */
std::vector<std::byte> MakeRecord(uint8_t header, std::span<const std::byte> payload)
{
    DataStream stream;
    WriteCompactSize(stream, 1 + payload.size());
    stream << header;
    stream.write(payload);
    return {stream.begin(), stream.end()};
}

/** A valid encapsulation key, from a fixed seed. */
mlkem::PublicKey TestEncapsulationKey()
{
    std::array<uint8_t, mlkem::KEYGEN_SEED_BYTES> seed{};
    seed.fill(0x5a);
    mlkem::PublicKey ek;
    mlkem::DecapsulationKey dk;
    BOOST_REQUIRE(mlkem::KeyGen(seed, ek, dk) == mlkem::Error::NONE);
    return ek;
}

/** ek with its first coefficient set to q = 3329, which fails the modulus check. */
mlkem::PublicKey BadModulusKey(mlkem::PublicKey ek)
{
    ek[0] = 0x01;
    ek[1] = (ek[1] & 0xF0) | 0x0D;
    return ek;
}

void CheckParse(std::span<const std::byte> contents, PQHandshake::ParseKind kind, std::optional<std::pair<size_t, size_t>> payload = std::nullopt)
{
    const auto parsed{PQHandshake::ParseContents(contents)};
    BOOST_CHECK(parsed.kind == kind);
    if (payload) {
        BOOST_CHECK(parsed.payload.data() == contents.data() + payload->first);
        BOOST_CHECK_EQUAL(parsed.payload.size(), payload->second);
    } else {
        BOOST_CHECK(parsed.payload.empty());
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(pq_records_grammar)
{
    using enum PQHandshake::ParseKind;
    // Empty contents, as every BIP324 implementation sends today: no features.
    CheckParse({}, NO_RECORD);
    // Unknown and reserved headers, with and without payload, are ignored.
    CheckParse(HexBytes("0100"), NO_RECORD);
    CheckParse(HexBytes("0301aabb"), NO_RECORD);
    CheckParse(HexBytes("0100" "02f1aa" "01ff"), NO_RECORD);
    // An own record with an empty payload parses; its length is checked later, by the role.
    CheckParse(HexBytes("01f0"), OWN_RECORD, std::pair{2, 0});
    CheckParse(HexBytes("0201aa" "03f0bbcc"), OWN_RECORD, std::pair{5, 2});
    // len = 0, alone or after valid records.
    CheckParse(HexBytes("00"), INVALID_GRAMMAR);
    CheckParse(HexBytes("0201aa" "00"), INVALID_GRAMMAR);
    CheckParse(HexBytes("00" "01f0"), INVALID_GRAMMAR);
    // Truncated records and truncated CompactSize encodings.
    CheckParse(HexBytes("05f0aabb"), INVALID_GRAMMAR);
    CheckParse(HexBytes("02f0"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fd"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fd21"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fe010000"), INVALID_GRAMMAR);
    CheckParse(HexBytes("ff01000000000000"), INVALID_GRAMMAR);
    // Non-canonical CompactSize encodings of lengths that would otherwise fit.
    CheckParse(HexBytes("fd0200" "f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fe02000000" "f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("ff0200000000000000" "f0aa"), INVALID_GRAMMAR);
    // Oversized lengths: beyond the contents (one byte, and far), exactly MAX_SIZE (which
    // ReadCompactSize accepts), beyond MAX_SIZE (which it rejects), and beyond size_t on 32-bit
    // platforms. None is used to skip bytes before it is checked.
    static_assert(MAX_SIZE == 0x02000000);
    CheckParse(HexBytes("03f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fdfd00" "f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fe00000002" "f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("fe01000002" "f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("ffffffffffffffffff" "f0aa"), INVALID_GRAMMAR);
    CheckParse(HexBytes("ff0000000001000000" "f0aa"), INVALID_GRAMMAR);
    // Trailing corruption after valid records, including after a valid own record.
    CheckParse(HexBytes("0201aa" "07"), INVALID_GRAMMAR);
    CheckParse(HexBytes("02f0aa" "fd"), INVALID_GRAMMAR);
    CheckParse(HexBytes("02f0aa" "0301aa"), INVALID_GRAMMAR);
    // Canonical 3-byte CompactSize lengths parse.
    std::vector<std::byte> long_unknown{HexBytes("fdfd00" "01")};
    long_unknown.resize(long_unknown.size() + 0xfc);
    CheckParse(long_unknown, NO_RECORD);
}

BOOST_AUTO_TEST_CASE(pq_records_first_wins)
{
    using enum PQHandshake::ParseKind;
    const mlkem::PublicKey ek{TestEncapsulationKey()};
    const auto offer{PQHandshake::SerializeRecord(ek)};
    BOOST_CHECK_EQUAL(HexStr(std::span{offer}.first(4)), "fd2106f0");
    BOOST_CHECK(std::ranges::equal(std::span{offer}.subspan(4), std::as_bytes(std::span{ek})));
    const auto malformed{MakeRecord(PQ_MLKEM1024, HexBytes("aabb"))};
    const auto unknown{MakeRecord(0xf1, HexBytes("cc"))};

    // A valid first own record wins over a malformed duplicate, wherever unknown records are.
    CheckParse(offer, OWN_RECORD, std::pair{4, mlkem::PUBLIC_KEY_BYTES});
    CheckParse(Concat({offer, malformed}), OWN_RECORD, std::pair{4, mlkem::PUBLIC_KEY_BYTES});
    CheckParse(Concat({unknown, offer, unknown, malformed}), OWN_RECORD, std::pair{unknown.size() + 4, mlkem::PUBLIC_KEY_BYTES});
    // A malformed first own record wins over a valid second one; the role's length check then fails.
    CheckParse(Concat({malformed, offer}), OWN_RECORD, std::pair{2, 2});
    CheckParse(Concat({unknown, malformed, offer}), OWN_RECORD, std::pair{unknown.size() + 2, 2});
    // Any later framing corruption means no features, even after a valid own record.
    CheckParse(Concat({offer, HexBytes("00")}), INVALID_GRAMMAR);
    CheckParse(Concat({offer, unknown, HexBytes("05f0")}), INVALID_GRAMMAR);
    CheckParse(Concat({offer, HexBytes("fd0300f0aabb")}), INVALID_GRAMMAR);
    auto truncated{Concat({unknown, offer})};
    truncated.pop_back();
    CheckParse(truncated, INVALID_GRAMMAR);
}

BOOST_AUTO_TEST_CASE(pq_record_semantics)
{
    const mlkem::PublicKey ek{TestEncapsulationKey()};
    for (const size_t size : {size_t{0}, mlkem::PUBLIC_KEY_BYTES - 1, mlkem::PUBLIC_KEY_BYTES + 1}) {
        std::vector<std::byte> payload(size, std::byte{0x42});
        // The responder's offer, at the initiator.
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
        const auto contents{MakeRecord(PQ_MLKEM1024, payload)};
        const auto parsed{PQHandshake::ParseContents(contents)};
        BOOST_REQUIRE(parsed.kind == PQHandshake::ParseKind::OWN_RECORD);
        BOOST_CHECK(!initiator.CheckRecordLength(parsed.payload));
        BOOST_CHECK(initiator.GetSnapshot().failure == PQFailure::EK_LENGTH);
        BOOST_CHECK(initiator.GetSnapshot().offer == PQOfferState::NONE);
        // The initiator's accept, at the responder, which wipes its key.
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake::Record offer;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        BOOST_CHECK(!responder.CheckRecordLength(parsed.payload));
        BOOST_CHECK(responder.GetSnapshot().failure == PQFailure::CT_LENGTH);
        BOOST_CHECK(!responder.HasDecapsulationKey());
    }

    // A key of the right length that fails the modulus check.
    g_kem_calls = {};
    TestPQEntropy entropy{uint256::ONE};
    PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE, entropy.Source(), COUNTING_KEM_OPS};
    const auto contents{PQHandshake::SerializeRecord(BadModulusKey(ek))};
    const auto payload{initiator.CheckRecordLength(PQHandshake::ParseContents(contents).payload)};
    BOOST_REQUIRE(payload);
    PQHandshake::Record accept;
    accept.fill(std::byte{0x33});
    mlkem::SharedSecret ss;
    BOOST_CHECK(initiator.AcceptOffer(*payload, accept, ss) == mlkem::Error::INVALID_PUBLIC_KEY);
    BOOST_CHECK(initiator.GetSnapshot().failure == PQFailure::EK_MODULUS);
    BOOST_CHECK(initiator.GetSnapshot().offer == PQOfferState::RECEIVED);
    BOOST_CHECK(std::ranges::all_of(accept, [](std::byte b) { return b == std::byte{0x33}; }));
    BOOST_CHECK_EQUAL(g_kem_calls.check, 1);
    BOOST_CHECK_EQUAL(g_kem_calls.total(), 1);
    // No entropy was drawn for a rejected key.
    BOOST_CHECK_EQUAL(entropy.counter, 0U);
}

BOOST_AUTO_TEST_CASE(pq_records_max_contents)
{
    using enum PQHandshake::ParseKind;
    // The largest contents a v2 packet can carry (1 + 12 + 4,000,000 bytes), as minimal unknown
    // records. One pass, no copies, no exception.
    constexpr size_t MAX_CONTENTS{4'000'013};
    std::vector<std::byte> contents;
    contents.reserve(MAX_CONTENTS);
    while (contents.size() + 2 < MAX_CONTENTS) {
        contents.push_back(std::byte{0x01});
        contents.push_back(std::byte{0x01});
    }
    // Ending in a malformed record: no features.
    std::vector<std::byte> malformed{contents};
    malformed.push_back(std::byte{0x05});
    BOOST_REQUIRE_EQUAL(malformed.size(), MAX_CONTENTS);
    CheckParse(malformed, INVALID_GRAMMAR);
    // Ending in a valid unknown record: still no features.
    std::vector<std::byte> valid{contents.begin(), contents.end() - 2};
    for (const auto b : HexBytes("0201aa")) valid.push_back(b);
    BOOST_REQUIRE_EQUAL(valid.size(), MAX_CONTENTS);
    CheckParse(valid, NO_RECORD);
    // Ending in an own record: found at the very end.
    const auto offer{PQHandshake::SerializeRecord(TestEncapsulationKey())};
    std::vector<std::byte> own{HexBytes("0201aa")};
    while (own.size() + 2 + offer.size() <= MAX_CONTENTS) {
        own.push_back(std::byte{0x01});
        own.push_back(std::byte{0x01});
    }
    own.insert(own.end(), offer.begin(), offer.end());
    BOOST_REQUIRE_EQUAL(own.size(), MAX_CONTENTS);
    CheckParse(own, OWN_RECORD, std::pair{MAX_CONTENTS - mlkem::PUBLIC_KEY_BYTES, mlkem::PUBLIC_KEY_BYTES});
}

BOOST_AUTO_TEST_CASE(pq_handshake_negotiation)
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(json_tests::pq_transport_vectors));
    const UniValue& vector{doc["vectors"][0]};
    const auto keygen_seed{ParseHex(vector["mlkem_keygen_seed"].get_str())};
    const auto encaps_m{ParseHex(vector["mlkem_encaps_m"].get_str())};

    // With the vector's entropy, MakeOffer draws d then z and AcceptOffer draws m, so the offer,
    // the accept and both secrets are the vector's.
    {
        TestPQEntropy responder_entropy{uint256::ZERO}, initiator_entropy{uint256::ONE};
        responder_entropy.Queue(keygen_seed);
        initiator_entropy.Queue(encaps_m);
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE, responder_entropy.Source(), DefaultPQKemOps()};
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE, initiator_entropy.Source(), DefaultPQKemOps()};

        PQHandshake::Record offer;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        BOOST_CHECK_EQUAL(HexStr(offer), "fd2106f0" + vector["ek"].get_str());
        BOOST_CHECK(responder.HasDecapsulationKey());
        // SENT means queued, which only the caller knows.
        BOOST_CHECK(responder.GetSnapshot().offer == PQOfferState::NONE);
        responder.SetOfferSent();
        BOOST_CHECK(responder.GetSnapshot().offer == PQOfferState::SENT);
        BOOST_CHECK(responder_entropy.queued.empty());

        const auto ek{initiator.CheckRecordLength(PQHandshake::ParseContents(offer).payload)};
        BOOST_REQUIRE(ek);
        PQHandshake::Record accept;
        mlkem::SharedSecret ss_initiator;
        BOOST_REQUIRE(initiator.AcceptOffer(*ek, accept, ss_initiator) == mlkem::Error::NONE);
        BOOST_CHECK_EQUAL(HexStr(accept), "fd2106f0" + vector["ct"].get_str());
        BOOST_CHECK_EQUAL(HexStr(ss_initiator.Bytes()), vector["ss_mlkem"].get_str());
        BOOST_CHECK(initiator.GetSnapshot().offer == PQOfferState::RECEIVED);
        BOOST_CHECK(initiator.GetSnapshot().failure == PQFailure::NONE);

        const auto ct{responder.CheckRecordLength(PQHandshake::ParseContents(accept).payload)};
        BOOST_REQUIRE(ct);
        mlkem::SharedSecret ss_responder;
        BOOST_REQUIRE(responder.DecapsulateAccept(*ct, ss_responder) == mlkem::Error::NONE);
        BOOST_CHECK_EQUAL(HexStr(ss_responder.Bytes()), vector["ss_mlkem"].get_str());
        // The decapsulation key is single use.
        BOOST_CHECK(!responder.HasDecapsulationKey());
        BOOST_CHECK(responder.GetSnapshot().failure == PQFailure::NONE);
    }

    // Random production entropy: both sides agree, and every handshake has fresh keys.
    std::optional<std::vector<uint8_t>> previous;
    for (int i = 0; i < 2; ++i) {
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
        PQHandshake::Record offer, accept;
        mlkem::SharedSecret ss_initiator, ss_responder;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        BOOST_REQUIRE(initiator.AcceptOffer(*initiator.CheckRecordLength(PQHandshake::ParseContents(offer).payload), accept, ss_initiator) == mlkem::Error::NONE);
        BOOST_REQUIRE(responder.DecapsulateAccept(*responder.CheckRecordLength(PQHandshake::ParseContents(accept).payload), ss_responder) == mlkem::Error::NONE);
        BOOST_CHECK(std::ranges::equal(ss_initiator.Bytes(), ss_responder.Bytes()));
        std::vector<uint8_t> current(offer.size());
        std::ranges::copy(MakeUCharSpan(offer), current.begin());
        if (previous) BOOST_CHECK(*previous != current);
        previous = current;
    }

    // A corrupted ciphertext of the right length is not an error: it yields a different secret.
    {
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
        PQHandshake::Record offer, accept;
        mlkem::SharedSecret ss_initiator, ss_responder;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        BOOST_REQUIRE(initiator.AcceptOffer(*initiator.CheckRecordLength(PQHandshake::ParseContents(offer).payload), accept, ss_initiator) == mlkem::Error::NONE);
        accept[100] ^= std::byte{0x01};
        BOOST_REQUIRE(responder.DecapsulateAccept(*responder.CheckRecordLength(PQHandshake::ParseContents(accept).payload), ss_responder) == mlkem::Error::NONE);
        BOOST_CHECK(!std::ranges::equal(ss_initiator.Bytes(), ss_responder.Bytes()));
    }

    using mlkem::InjectResultForTesting;
    using mlkem::Operation;
    namespace upstream = mlkem::upstream;
    const auto all_bytes_are = [](std::span<const uint8_t> bytes, uint8_t value) {
        return std::ranges::all_of(bytes, [&](uint8_t b) { return b == value; });
    };

    // Key generation fails: no offer, no key, a recorded internal error.
    {
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake::Record offer;
        offer.fill(std::byte{0x33});
        {
            InjectResultForTesting inject{Operation::KEYGEN, upstream::ERR_FAIL};
            BOOST_CHECK(responder.MakeOffer(offer) == mlkem::Error::INTERNAL);
        }
        BOOST_CHECK(std::ranges::all_of(offer, [](std::byte b) { return b == std::byte{0x33}; }));
        BOOST_CHECK(!responder.HasDecapsulationKey());
        BOOST_CHECK(responder.GetSnapshot().offer == PQOfferState::NONE);
        BOOST_CHECK(responder.GetSnapshot().failure == PQFailure::KEYGEN_INTERNAL);
    }

    // The key check or encapsulation fails internally: no accept, the secret cleared.
    for (const auto& [op, failure] : {std::pair{Operation::CHECK_PUBLIC_KEY, PQFailure::CHECK_EK_INTERNAL},
                                      std::pair{Operation::ENCAPS, PQFailure::ENCAPS_INTERNAL}}) {
        for (const int result : {upstream::ERR_FAIL, upstream::ERR_OUT_OF_MEMORY}) {
            PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
            const mlkem::PublicKey ek{TestEncapsulationKey()};
            PQHandshake::Record accept;
            accept.fill(std::byte{0x33});
            mlkem::SharedSecret ss;
            std::ranges::fill(ss.Bytes(), 0x44);
            {
                InjectResultForTesting inject{op, result};
                BOOST_CHECK(initiator.AcceptOffer(ek, accept, ss) == mlkem::Error::INTERNAL);
            }
            BOOST_CHECK(std::ranges::all_of(accept, [](std::byte b) { return b == std::byte{0x33}; }));
            BOOST_CHECK(all_bytes_are(ss.Bytes(), 0));
            BOOST_CHECK(initiator.GetSnapshot().failure == failure);
        }
    }
    // An encapsulation that rejects the key after the check passed is a local fault too.
    {
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
        PQHandshake::Record accept;
        mlkem::SharedSecret ss;
        InjectResultForTesting inject{Operation::ENCAPS, upstream::ERR_INVALID_PK};
        BOOST_CHECK(initiator.AcceptOffer(TestEncapsulationKey(), accept, ss) == mlkem::Error::INTERNAL);
        BOOST_CHECK(initiator.GetSnapshot().failure == PQFailure::ENCAPS_INTERNAL);
    }

    // Decapsulation fails internally (including a failed key hash check): the secret cleared, the
    // key wiped.
    for (const int result : {upstream::ERR_FAIL, upstream::ERR_INVALID_SK}) {
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
        PQHandshake::Record offer, accept;
        mlkem::SharedSecret ss_initiator, ss_responder;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        BOOST_REQUIRE(initiator.AcceptOffer(*initiator.CheckRecordLength(PQHandshake::ParseContents(offer).payload), accept, ss_initiator) == mlkem::Error::NONE);
        std::ranges::fill(ss_responder.Bytes(), 0x44);
        {
            InjectResultForTesting inject{Operation::DECAPS, result};
            BOOST_CHECK(responder.DecapsulateAccept(*responder.CheckRecordLength(PQHandshake::ParseContents(accept).payload), ss_responder) == mlkem::Error::INTERNAL);
        }
        BOOST_CHECK(all_bytes_are(ss_responder.Bytes(), 0));
        BOOST_CHECK(!responder.HasDecapsulationKey());
        BOOST_CHECK(responder.GetSnapshot().failure == PQFailure::DECAPS_INTERNAL);
    }

    // ClearSecrets() and any recorded failure wipe the key; the first failure is kept.
    {
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake::Record offer;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        responder.ClearSecrets();
        BOOST_CHECK(!responder.HasDecapsulationKey());
        BOOST_CHECK(responder.GetSnapshot().failure == PQFailure::NONE);
    }
    {
        PQHandshake responder{/*initiating=*/false, PQMode::NEGOTIATE};
        PQHandshake::Record offer;
        BOOST_REQUIRE(responder.MakeOffer(offer) == mlkem::Error::NONE);
        responder.SetFailure(PQFailure::CONFIRM_TAG);
        BOOST_CHECK(!responder.HasDecapsulationKey());
        responder.SetFailure(PQFailure::CONFIRM_LENGTH);
        BOOST_CHECK(responder.GetSnapshot().failure == PQFailure::CONFIRM_TAG);
    }

    // The snapshot records progress.
    {
        PQHandshake initiator{/*initiating=*/true, PQMode::NEGOTIATE};
        BOOST_CHECK(!initiator.GetSnapshot().version_received);
        initiator.SetVersionReceived();
        initiator.SetSwitched();
        initiator.SetConfirmed();
        const auto snapshot{initiator.GetSnapshot()};
        BOOST_CHECK(snapshot.version_received && snapshot.switched && snapshot.confirmed);
        BOOST_CHECK(snapshot.failure == PQFailure::NONE);
    }
}

namespace {

constexpr V2PQOptions PQ_ON{.mode = PQMode::NEGOTIATE};

/** Drive a tester, as the hybrid peer, through the handshake with its transport: both sides
 *  switch, and the tester checks the transport's key confirmation. The tester's own confirmation
 *  is scheduled (not delivered) if send_confirmation. Returns the ECDH session id. */
uint256 HybridHandshake(V2TransportTester& tester, bool test_initiator, bool send_confirmation = true)
{
    uint256 ecdh_session_id;
    if (test_initiator) {
        // The transport initiates and holds its version packet; we (the responder) offer at once.
        auto ret{tester.Interact()};
        BOOST_REQUIRE(ret && ret->empty());
        tester.SendKey();
        tester.SendGarbage();
        tester.ReceiveKey(/*retain_for_hybrid=*/true);
        ecdh_session_id = uint256(MakeUCharSpan(tester.GetCipher().GetSessionID()));
        tester.SendGarbageTerm();
        tester.SendOffer();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveGarbage();
        tester.ReceiveAcceptAndSwitch();
    } else {
        // The transport responds with an offer; we (the initiator) accept it.
        tester.SendKey();
        tester.SendGarbage();
        auto ret{tester.Interact()};
        BOOST_REQUIRE(ret && ret->empty());
        tester.ReceiveKey(/*retain_for_hybrid=*/true);
        ecdh_session_id = uint256(MakeUCharSpan(tester.GetCipher().GetSessionID()));
        tester.SendGarbageTerm();
        tester.ReceiveGarbage();
        tester.AcceptOfferAndSwitch();
        ret = tester.Interact();
        BOOST_REQUIRE(ret && ret->empty());
    }
    tester.ReceiveConfirmation();
    if (send_confirmation) tester.SendConfirmation();
    return ecdh_session_id;
}

void CheckPQ(V2Transport& transport, PQStatus status, PQFailure failure = PQFailure::NONE)
{
    const auto info{transport.GetInfo()};
    BOOST_CHECK(info.transport_pq_status == status);
    BOOST_CHECK_EQUAL(info.transport_pq, status == PQStatus::HYBRID);
    BOOST_CHECK(transport.GetPQSnapshot().failure == failure);
}

/** Exchange count messages each way between two connected transports, fragmenting the bytes at
 *  random, and check that each arrives intact and in order. */
void ExchangeMessages(FastRandomContext& rng, V2Transport& initiator, V2Transport& responder, int count)
{
    const std::array<V2Transport*, 2> transports{&initiator, &responder};
    std::array<std::deque<CSerializedNetMsg>, 2> to_send;
    std::array<std::deque<CSerializedNetMsg>, 2> expected;
    std::array<std::vector<uint8_t>, 2> in_flight;
    for (int side = 0; side < 2; ++side) {
        for (int i = 0; i < count; ++i) {
            CSerializedNetMsg msg;
            msg.m_type = i == 0 ? "version" : "ping";
            msg.data = rng.randbytes<uint8_t>(rng.randrange(1000));
            expected[side].push_back(msg.Copy());
            to_send[side].push_back(std::move(msg));
        }
    }
    bool progress{true};
    while (progress) {
        progress = false;
        for (int side = 0; side < 2; ++side) {
            if (!to_send[side].empty() && transports[side]->SetMessageToSend(to_send[side].front())) {
                to_send[side].pop_front();
                progress = true;
            }
            const auto& [bytes, _more, _type] = transports[side]->GetBytesToSend(!to_send[side].empty());
            if (!bytes.empty()) {
                const size_t n{1 + rng.randrange(bytes.size())};
                in_flight[side].insert(in_flight[side].end(), bytes.begin(), bytes.begin() + n);
                transports[side]->MarkBytesSent(n);
                progress = true;
            }
            if (!in_flight[side].empty()) {
                std::span<const uint8_t> received{std::span{in_flight[side]}.first(1 + rng.randrange(in_flight[side].size()))};
                const size_t old_size{received.size()};
                BOOST_REQUIRE(transports[!side]->ReceivedBytes(received));
                in_flight[side].erase(in_flight[side].begin(), in_flight[side].begin() + (old_size - received.size()));
                if (received.size() != old_size) progress = true;
            }
            while (transports[!side]->ReceivedMessageComplete()) {
                bool reject{false};
                const CNetMessage msg{transports[!side]->GetReceivedMessage({}, reject)};
                BOOST_REQUIRE(!reject && !expected[side].empty());
                BOOST_CHECK_EQUAL(msg.m_type, expected[side].front().m_type);
                BOOST_CHECK(std::ranges::equal(MakeUCharSpan(msg.m_recv), expected[side].front().data));
                expected[side].pop_front();
                progress = true;
            }
        }
    }
    BOOST_CHECK(expected[0].empty() && expected[1].empty());
}

} // namespace

BOOST_AUTO_TEST_CASE(v2_pq_pair)
{
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, PQ_ON);
            auto& transport{tester.GetTransport()};
            // Pending from the start of the handshake.
            CheckPQ(transport, PQStatus::PENDING);
            BOOST_CHECK(!transport.GetPQSnapshot().version_received);
            const uint256 ecdh_session_id{HybridHandshake(tester, test_initiator, /*send_confirmation=*/false)};

            // Switched, not confirmed: pending, still detecting, and no session id. The switch
            // wiped the decapsulation key and the retained ECDH secret.
            auto info{transport.GetInfo()};
            BOOST_CHECK(info.transport_type == TransportProtocolType::DETECTING);
            BOOST_CHECK(!info.session_id);
            CheckPQ(transport, PQStatus::PENDING);
            auto snapshot{transport.GetPQSnapshot()};
            BOOST_CHECK(snapshot.version_received && snapshot.switched && !snapshot.confirmed);
            BOOST_CHECK(snapshot.offer == (test_initiator ? PQOfferState::RECEIVED : PQOfferState::SENT));
            BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());

            // The transport sends application messages without waiting for our confirmation.
            const auto msg_data_1{m_rng.randbytes<uint8_t>(m_rng.randrange(100000))};
            tester.AddMessage("barfoo", msg_data_1);
            auto ret{tester.Interact()};
            BOOST_REQUIRE(ret && ret->empty());
            tester.ReceiveMessage("barfoo", msg_data_1);

            // It delivers ours only after our confirmation.
            const auto msg_data_2{m_rng.randbytes<uint8_t>(m_rng.randrange(100000))};
            tester.SendConfirmation();
            tester.SendMessage(uint8_t(4), msg_data_2); // cmpctblock short id
            tester.SendMessage("tx", msg_data_1);
            ret = tester.Interact();
            BOOST_REQUIRE(ret && ret->size() == 2);
            BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "cmpctblock" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(msg_data_2)));
            BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "tx" && std::ranges::equal((*ret)[1]->m_recv, MakeByteSpan(msg_data_1)));

            // Hybrid: v2 with the hybrid session id, which both sides share.
            info = transport.GetInfo();
            BOOST_CHECK(info.transport_type == TransportProtocolType::V2);
            CheckPQ(transport, PQStatus::HYBRID);
            tester.CompareSessionIDs();
            BOOST_CHECK(info.session_id && *info.session_id != ecdh_session_id);
            snapshot = transport.GetPQSnapshot();
            BOOST_CHECK(snapshot.switched && snapshot.confirmed);
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_legacy_matrix)
{
    // The tested transport (on, off or in fallback) against a scripted peer (hybrid or legacy), in
    // both roles. A legacy peer sends its version packet and an application burst as soon as it
    // can, without waiting for ours.
    for (const bool test_initiator : {true, false}) {
        for (const PQMode local : {PQMode::OFF, PQMode::NEGOTIATE, PQMode::FALLBACK}) {
            // Inbound connections never fall back.
            if (local == PQMode::FALLBACK && !test_initiator) continue;
            for (const bool peer_hybrid : {false, true}) {
                BOOST_TEST_CONTEXT("test_initiator=" << test_initiator << " local=" << int(local) << " peer_hybrid=" << peer_hybrid)
                {
                    g_kem_calls = {};
                    TestPQEntropy entropy{m_rng.rand256()};
                    V2TransportTester tester(m_rng, test_initiator, {.mode = local}, entropy.Source(), COUNTING_KEM_OPS);
                    auto& transport{tester.GetTransport()};
                    const bool hybrid{local == PQMode::NEGOTIATE && peer_hybrid};
                    const bool offered{local == PQMode::NEGOTIATE && !test_initiator};
                    const auto burst_1{m_rng.randbytes<uint8_t>(m_rng.randrange(10000))};
                    const auto burst_2{m_rng.randbytes<uint8_t>(m_rng.randrange(1000))};
                    const auto send_burst = [&] {
                        tester.SendMessage(uint8_t(14), burst_1); // inv short id
                        tester.SendMessage("foobar", burst_2);
                    };
                    // Until the peer's version packet is processed, the negotiation is pending.
                    const PQStatus initial_status{local == PQMode::OFF ? PQStatus::OFF :
                                                  local == PQMode::FALLBACK ? PQStatus::FALLBACK : PQStatus::PENDING};
                    CheckPQ(transport, initial_status);

                    if (test_initiator) {
                        auto ret{tester.Interact()};
                        BOOST_REQUIRE(ret && ret->empty());
                    }
                    tester.SendKey();
                    tester.SendGarbage();
                    if (!test_initiator) {
                        auto ret{tester.Interact()};
                        BOOST_REQUIRE(ret && ret->empty());
                    }
                    tester.ReceiveKey(/*retain_for_hybrid=*/peer_hybrid);
                    tester.SendGarbageTerm();
                    // After the key exchange, before the peer's version packet: still pending, and
                    // only the negotiation holds secrets for the switch.
                    auto ret{tester.Interact()};
                    BOOST_REQUIRE(ret && ret->empty());
                    CheckPQ(transport, initial_status);
                    BOOST_CHECK(!transport.GetPQSnapshot().version_received);
                    BOOST_CHECK_EQUAL(transport.HoldsHybridSecretsForTesting(), local == PQMode::NEGOTIATE);
                    if (!peer_hybrid) {
                        tester.SendVersion();
                        send_burst();
                    } else if (test_initiator) {
                        // A hybrid responder offers at once.
                        tester.SendOffer();
                    }
                    ret = tester.Interact();
                    BOOST_REQUIRE(ret);
                    BOOST_CHECK_EQUAL(ret->size(), peer_hybrid ? 0U : 2U);
                    tester.ReceiveGarbage();
                    if (!peer_hybrid) {
                        // A legacy peer ignores an offer.
                        const auto contents{tester.ReceiveVersionContents()};
                        BOOST_CHECK(offered ? PQHandshake::ParseContents(MakeByteSpan(contents)).kind == PQHandshake::ParseKind::OWN_RECORD : contents.empty());
                    } else if (test_initiator) {
                        if (hybrid) {
                            tester.ReceiveAcceptAndSwitch();
                            tester.ReceiveConfirmation();
                            tester.SendConfirmation();
                        } else {
                            BOOST_CHECK(tester.ReceiveVersionContents().empty());
                            tester.GetCipher().DiscardHybridSecret();
                        }
                        send_burst();
                    } else {
                        // A hybrid initiator answers the responder's version packet.
                        if (hybrid) {
                            tester.AcceptOfferAndSwitch();
                            tester.SendConfirmation();
                        } else {
                            BOOST_CHECK(tester.ReceiveVersionContents().empty());
                            tester.GetCipher().DiscardHybridSecret();
                            tester.SendVersion();
                        }
                        send_burst();
                    }
                    if (peer_hybrid) {
                        ret = tester.Interact();
                        BOOST_REQUIRE(ret && ret->size() == 2);
                        if (hybrid && !test_initiator) tester.ReceiveConfirmation();
                    }
                    BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "inv" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(burst_1)));
                    BOOST_CHECK((*ret)[1] && (*ret)[1]->m_type == "foobar" && std::ranges::equal((*ret)[1]->m_recv, MakeByteSpan(burst_2)));

                    // The transport's messages arrive under the keys the peer expects.
                    tester.AddMessage("barfoo", burst_2);
                    ret = tester.Interact();
                    BOOST_REQUIRE(ret && ret->empty());
                    tester.ReceiveMessage("barfoo", burst_2);
                    BOOST_CHECK(tester.Received().empty());
                    tester.CompareSessionIDs();
                    const PQStatus status{local == PQMode::OFF ? PQStatus::OFF :
                                          local == PQMode::FALLBACK ? PQStatus::FALLBACK :
                                          hybrid ? PQStatus::HYBRID : PQStatus::LEGACY_PEER};
                    CheckPQ(transport, status);
                    // The switch and a legacy outcome both wiped what the switch needed.
                    BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());

                    // Off and fallback neither generate, parse nor validate anything; a responder
                    // never decapsulates without an accept.
                    BOOST_CHECK_EQUAL(g_kem_calls.keygen, offered ? 1 : 0);
                    BOOST_CHECK_EQUAL(g_kem_calls.check, hybrid && test_initiator ? 1 : 0);
                    BOOST_CHECK_EQUAL(g_kem_calls.encaps, hybrid && test_initiator ? 1 : 0);
                    BOOST_CHECK_EQUAL(g_kem_calls.decaps, hybrid && !test_initiator ? 1 : 0);
                }
            }
        }
    }

    // Two transports in every combination of modes.
    for (const PQMode initiator_mode : {PQMode::OFF, PQMode::NEGOTIATE, PQMode::FALLBACK}) {
        for (const PQMode responder_mode : {PQMode::OFF, PQMode::NEGOTIATE}) {
            BOOST_TEST_CONTEXT("initiator=" << int(initiator_mode) << " responder=" << int(responder_mode))
            {
                V2Transport initiator{0, /*initiating=*/true, {.mode = initiator_mode}};
                V2Transport responder{1, /*initiating=*/false, {.mode = responder_mode}};
                ExchangeMessages(m_rng, initiator, responder, 5);
                const auto initiator_info{initiator.GetInfo()}, responder_info{responder.GetInfo()};
                BOOST_CHECK(initiator_info.transport_type == TransportProtocolType::V2);
                BOOST_CHECK(initiator_info.session_id && initiator_info.session_id == responder_info.session_id);
                const bool hybrid{initiator_mode == PQMode::NEGOTIATE && responder_mode == PQMode::NEGOTIATE};
                const auto expected = [&](PQMode mode) {
                    if (mode == PQMode::OFF) return PQStatus::OFF;
                    if (mode == PQMode::FALLBACK) return PQStatus::FALLBACK;
                    return hybrid ? PQStatus::HYBRID : PQStatus::LEGACY_PEER;
                };
                CheckPQ(initiator, expected(initiator_mode));
                CheckPQ(responder, expected(responder_mode));
                BOOST_CHECK(!initiator.HoldsHybridSecretsForTesting());
                BOOST_CHECK(!responder.HoldsHybridSecretsForTesting());
            }
        }
    }

    // A responder never falls back: its FALLBACK is a caller bug (Assume), and it runs and reports
    // as off. Debug builds abort on the Assume instead.
    if constexpr (!G_FUZZING_BUILD && !G_ABORT_ON_FAILED_ASSUME) {
        V2Transport initiator{0, /*initiating=*/true, PQ_ON};
        V2Transport responder{1, /*initiating=*/false, {.mode = PQMode::FALLBACK}};
        ExchangeMessages(m_rng, initiator, responder, 2);
        CheckPQ(initiator, PQStatus::LEGACY_PEER);
        CheckPQ(responder, PQStatus::OFF);
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_v1_detection)
{
    // A responder with the negotiation on detects v1 peers and peers from another network as
    // before, without generating a key.
    g_kem_calls = {};
    {
        TestPQEntropy entropy{m_rng.rand256()};
        V2TransportTester tester(m_rng, false, PQ_ON, entropy.Source(), COUNTING_KEM_OPS);
        tester.SendV1Version(Params().MessageStart());
        BOOST_CHECK(tester.Interact());
        const auto info{tester.GetTransport().GetInfo()};
        BOOST_CHECK(info.transport_type == TransportProtocolType::V1);
        BOOST_CHECK(info.transport_pq_status == PQStatus::V1);
        BOOST_CHECK(!info.transport_pq);
    }
    {
        TestPQEntropy entropy{m_rng.rand256()};
        V2TransportTester tester(m_rng, false, PQ_ON, entropy.Source(), COUNTING_KEM_OPS);
        tester.SendV1Version(CChainParams::Main()->MessageStart());
        BOOST_CHECK(!tester.Interact());
    }
    BOOST_CHECK_EQUAL(g_kem_calls.total(), 0);

    // An initiator asks for the v1 retry exactly as before: after sending at least 24 bytes and
    // before receiving anything.
    for (const PQMode mode : {PQMode::OFF, PQMode::NEGOTIATE, PQMode::FALLBACK}) {
        V2TransportTester tester(m_rng, true, {.mode = mode});
        auto& transport{tester.GetTransport()};
        BOOST_CHECK(!transport.ShouldReconnectV1());
        BOOST_REQUIRE(tester.Interact());
        BOOST_CHECK(transport.ShouldReconnectV1());
        tester.SendKey();
        tester.ToSend().resize(1);
        BOOST_REQUIRE(tester.Deliver());
        BOOST_CHECK(!transport.ShouldReconnectV1());
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_send_hold)
{
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, PQ_ON);
            auto& transport{tester.GetTransport()};
            if (test_initiator) tester.Collect();
            tester.SendKey();
            tester.SendGarbage();
            BOOST_REQUIRE(tester.Deliver());

            // A responder's offer counts as sent once it is queued.
            BOOST_CHECK(transport.GetPQSnapshot().offer == (test_initiator ? PQOfferState::NONE : PQOfferState::SENT));

            // Holding: the terminator (initiator) or the key, garbage, terminator and offer
            // (responder) is queued. Send part of it, and look at all of it.
            auto [bytes, more, _type] = transport.GetBytesToSend(/*have_next_message=*/true);
            BOOST_CHECK(!more);
            BOOST_REQUIRE(bytes.size() > (test_initiator ? 0U : PQ_RECORD_BYTES));
            const std::vector<uint8_t> queued{bytes.begin(), bytes.end()};
            tester.Received().insert(tester.Received().end(), queued.begin(), queued.end());
            const size_t sent{test_initiator ? 1 + m_rng.randrange(queued.size() - 1) : queued.size() - 1 - m_rng.randrange(PQ_RECORD_BYTES)};
            transport.MarkBytesSent(sent);

            // No message is taken, and nothing more will be sendable.
            CSerializedNetMsg msg;
            msg.m_type = "ping";
            msg.data = m_rng.randbytes<uint8_t>(8);
            const auto data{msg.data};
            BOOST_CHECK(!transport.SetMessageToSend(msg));
            BOOST_CHECK(msg.m_type == "ping" && msg.data == data);
            for (const bool have_next : {false, true}) {
                const auto& [rest, rest_more, _rest_type] = transport.GetBytesToSend(have_next);
                BOOST_CHECK(!rest_more);
                BOOST_CHECK(std::ranges::equal(rest, std::span{queued}.subspan(sent)));
            }

            // The peer's version packet: the transport appends after the unsent bytes.
            tester.ReceiveKey(/*retain_for_hybrid=*/true);
            tester.SendGarbageTerm();
            if (test_initiator) {
                tester.SendOffer();
            } else {
                tester.ReceiveGarbage();
                tester.AcceptOfferAndSwitch();
            }
            BOOST_REQUIRE(tester.Deliver());
            const auto& [after, after_more, _after_type] = transport.GetBytesToSend(/*have_next_message=*/true);
            BOOST_CHECK(after_more);
            const size_t appended{(test_initiator ? BIP324Cipher::EXPANSION + PQ_RECORD_BYTES : 0) + PQ_CONFIRMATION_BYTES};
            BOOST_REQUIRE_EQUAL(after.size(), queued.size() - sent + appended);
            BOOST_CHECK(std::ranges::equal(after.first(queued.size() - sent), std::span{queued}.subspan(sent)));
            tester.Received().insert(tester.Received().end(), after.end() - appended, after.end());
            transport.MarkBytesSent(after.size());
            if (test_initiator) {
                tester.ReceiveGarbage();
                tester.ReceiveAcceptAndSwitch();
            }
            tester.ReceiveConfirmation();

            // Now the held message goes out under the hybrid keys.
            BOOST_CHECK(transport.SetMessageToSend(msg));
            tester.Collect();
            tester.ReceiveMessage(uint8_t(18), data); // ping short id
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_switch_boundary)
{
    for (const bool test_initiator : {true, false}) {
        for (const bool byte_by_byte : {false, true}) {
            BOOST_TEST_CONTEXT("test_initiator=" << test_initiator << " byte_by_byte=" << byte_by_byte)
            {
                V2TransportTester tester(m_rng, test_initiator, PQ_ON);
                auto& transport{tester.GetTransport()};
                const auto payload{m_rng.randbytes<uint8_t>(m_rng.randrange(1000))};
                if (test_initiator) {
                    // The offer (ECDH keys), then confirmation and message (hybrid keys).
                    tester.Collect();
                    tester.SendKey();
                    tester.SendGarbage();
                    tester.ReceiveKey(/*retain_for_hybrid=*/true);
                    tester.SendGarbageTerm();
                    tester.SendOffer();
                    BOOST_REQUIRE(tester.Deliver(byte_by_byte));
                    tester.Collect();
                    tester.ReceiveGarbage();
                    tester.ReceiveAcceptAndSwitch();
                    tester.ReceiveConfirmation();
                } else {
                    // The accept (ECDH keys), confirmation and message (hybrid keys), coalesced.
                    tester.SendKey();
                    tester.SendGarbage();
                    BOOST_REQUIRE(tester.Deliver(byte_by_byte));
                    tester.Collect();
                    tester.ReceiveKey(/*retain_for_hybrid=*/true);
                    tester.SendGarbageTerm();
                    tester.ReceiveGarbage();
                    tester.AcceptOfferAndSwitch();
                }
                tester.SendConfirmation();
                const size_t before_message{tester.ToSend().size()};
                tester.SendMessage(uint8_t(14), payload); // inv short id
                std::vector<uint8_t> message{tester.ToSend().begin() + before_message, tester.ToSend().end()};
                tester.ToSend().resize(before_message);

                // Up to the end of the confirmation: confirmed, and no message.
                BOOST_REQUIRE(tester.Deliver(byte_by_byte));
                BOOST_CHECK(!transport.ReceivedMessageComplete());
                CheckPQ(transport, PQStatus::HYBRID);
                if (!test_initiator) {
                    tester.Collect();
                    tester.ReceiveConfirmation();
                }

                // Then the message, under the hybrid keys.
                tester.Send(message);
                BOOST_REQUIRE(tester.Deliver(byte_by_byte));
                BOOST_REQUIRE(transport.ReceivedMessageComplete());
                bool reject{false};
                const CNetMessage msg{transport.GetReceivedMessage({}, reject)};
                BOOST_CHECK(!reject && msg.m_type == "inv" && std::ranges::equal(msg.m_recv, MakeByteSpan(payload)));
                BOOST_CHECK(!transport.ReceivedMessageComplete());
                tester.CompareSessionIDs();
            }
        }
    }

    // All at once: the accept, the confirmation and a message coalesced in one delivery.
    {
        V2TransportTester tester(m_rng, false, PQ_ON);
        auto& transport{tester.GetTransport()};
        const auto payload{m_rng.randbytes<uint8_t>(100)};
        tester.SendKey();
        tester.SendGarbage();
        BOOST_REQUIRE(tester.Deliver());
        tester.Collect();
        tester.ReceiveKey(/*retain_for_hybrid=*/true);
        tester.SendGarbageTerm();
        tester.ReceiveGarbage();
        tester.AcceptOfferAndSwitch();
        tester.SendConfirmation();
        tester.SendMessage(uint8_t(14), payload);
        BOOST_REQUIRE(tester.Deliver());
        BOOST_REQUIRE(transport.ReceivedMessageComplete());
        bool reject{false};
        const CNetMessage msg{transport.GetReceivedMessage({}, reject)};
        BOOST_CHECK(!reject && msg.m_type == "inv" && std::ranges::equal(msg.m_recv, MakeByteSpan(payload)));
        CheckPQ(transport, PQStatus::HYBRID);
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_confirmation_length)
{
    for (const bool test_initiator : {true, false}) {
        for (const size_t length : {size_t{1}, size_t{17}, size_t{4'000'014}}) {
            BOOST_TEST_CONTEXT("test_initiator=" << test_initiator << " length=" << length)
            {
                V2TransportTester tester(m_rng, test_initiator, PQ_ON);
                auto& transport{tester.GetTransport()};
                HybridHandshake(tester, test_initiator, /*send_confirmation=*/false);
                // An authenticated decoy with a nonzero length, of which only the length arrives.
                tester.SendPacket(std::vector<uint8_t>(length), /*aad=*/{}, /*ignore=*/true);
                tester.ToSend().resize(BIP324Cipher::LENGTH_LEN);
                BOOST_CHECK(!tester.Deliver(/*byte_by_byte=*/true));
                BOOST_CHECK(tester.ToSend().empty());
                CheckPQ(transport, PQStatus::PENDING, PQFailure::CONFIRM_LENGTH);
                BOOST_CHECK(!transport.ShouldReconnectV1());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_confirmation_tag)
{
    for (const bool test_initiator : {true, false}) {
        for (const bool damage_header : {false, true}) {
            BOOST_TEST_CONTEXT("test_initiator=" << test_initiator << " damage_header=" << damage_header)
            {
                V2TransportTester tester(m_rng, test_initiator, PQ_ON);
                auto& transport{tester.GetTransport()};
                HybridHandshake(tester, test_initiator, /*send_confirmation=*/false);
                tester.SendConfirmation();
                BOOST_REQUIRE_EQUAL(tester.ToSend().size(), PQ_CONFIRMATION_BYTES);
                tester.ToSend()[damage_header ? BIP324Cipher::LENGTH_LEN : PQ_CONFIRMATION_BYTES - 1] ^= 1 << m_rng.randrange(8);
                // Nothing fails before byte 20.
                std::vector<uint8_t> last{tester.ToSend().back()};
                tester.ToSend().pop_back();
                BOOST_REQUIRE(tester.Deliver(/*byte_by_byte=*/true));
                CheckPQ(transport, PQStatus::PENDING);
                tester.Send(last);
                BOOST_CHECK(!tester.Deliver());
                CheckPQ(transport, PQStatus::PENDING, PQFailure::CONFIRM_TAG);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_confirmation_not_decoy)
{
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, PQ_ON);
            auto& transport{tester.GetTransport()};
            HybridHandshake(tester, test_initiator, /*send_confirmation=*/false);
            // An authenticated empty packet without the ignore bit (an empty application message).
            tester.SendPacket(/*content=*/{}, /*aad=*/{}, /*ignore=*/false);
            BOOST_CHECK(!tester.Deliver(/*byte_by_byte=*/true));
            BOOST_CHECK(tester.ToSend().empty());
            BOOST_CHECK(!transport.ReceivedMessageComplete());
            CheckPQ(transport, PQStatus::PENDING, PQFailure::CONFIRM_NOT_DECOY);
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_corrupt_ct)
{
    // A ciphertext damaged in transit, of the right length: the responder switches to different
    // keys, and the first packet under them fails. No continuation with ECDH keys.
    {
        V2TransportTester tester(m_rng, false, PQ_ON);
        auto& transport{tester.GetTransport()};
        tester.SendKey();
        tester.SendGarbage();
        BOOST_REQUIRE(tester.Interact());
        tester.ReceiveKey(/*retain_for_hybrid=*/true);
        tester.SendGarbageTerm();
        tester.ReceiveGarbage();
        tester.AcceptOfferAndSwitch(/*damage_ct=*/true);
        tester.SendConfirmation();
        BOOST_CHECK(!tester.Interact());
        const auto snapshot{transport.GetPQSnapshot()};
        BOOST_CHECK(snapshot.switched && !snapshot.confirmed);
        BOOST_CHECK(snapshot.failure == PQFailure::CONFIRM_LENGTH || snapshot.failure == PQFailure::CONFIRM_TAG);
        BOOST_CHECK(transport.GetInfo().transport_pq_status == PQStatus::PENDING);
    }

    // The local fault injection: the transport inverts byte 0 of its ML-KEM secret. Each side
    // rejects the other's confirmation, and an initiator does not retry with v1.
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, {.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true});
            auto& transport{tester.GetTransport()};
            if (test_initiator) {
                BOOST_REQUIRE(tester.Interact());
                tester.SendKey();
                tester.SendGarbage();
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                tester.SendOffer();
                BOOST_REQUIRE(tester.Interact());
                tester.ReceiveGarbage();
                tester.ReceiveAcceptAndSwitch();
            } else {
                tester.SendKey();
                tester.SendGarbage();
                BOOST_REQUIRE(tester.Interact());
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                tester.ReceiveGarbage();
                tester.AcceptOfferAndSwitch();
                BOOST_REQUIRE(tester.Interact());
            }
            // The transport's confirmation does not verify under our honest keys.
            BOOST_REQUIRE_EQUAL(tester.Received().size(), PQ_CONFIRMATION_BYTES);
            const auto packet{MakeByteSpan(tester.Received())};
            bool ignore{false};
            BOOST_CHECK(tester.GetCipher().DecryptLength(packet.first(BIP324Cipher::LENGTH_LEN)) != 0 ||
                        !tester.GetCipher().Decrypt(packet.subspan(BIP324Cipher::LENGTH_LEN), {}, ignore, {}));
            tester.SendConfirmation();
            BOOST_CHECK(!tester.Interact());
            const auto snapshot{transport.GetPQSnapshot()};
            BOOST_CHECK(snapshot.switched && !snapshot.confirmed);
            BOOST_CHECK(snapshot.failure == PQFailure::CONFIRM_LENGTH || snapshot.failure == PQFailure::CONFIRM_TAG);
            BOOST_CHECK(!transport.ShouldReconnectV1());
        }
    }

    // The injected fault is exactly byte 0 of the ML-KEM secret inverted, EK and CT untouched: a
    // peer that inverts the same byte derives the transport's keys. pq_transport_vectors.json
    // models the same change in a negative vector.
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, {.mode = PQMode::NEGOTIATE, .corrupt_shared_secret = true});
            auto& transport{tester.GetTransport()};
            if (test_initiator) {
                BOOST_REQUIRE(tester.Interact());
                tester.SendKey();
                tester.SendGarbage();
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                tester.SendOffer();
                BOOST_REQUIRE(tester.Interact());
                tester.ReceiveGarbage();
                tester.ReceiveAcceptAndSwitch(/*invert_ss=*/true);
            } else {
                tester.SendKey();
                tester.SendGarbage();
                BOOST_REQUIRE(tester.Interact());
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                tester.ReceiveGarbage();
                tester.AcceptOfferAndSwitch(/*damage_ct=*/false, /*invert_ss=*/true);
                BOOST_REQUIRE(tester.Interact());
            }
            tester.ReceiveConfirmation();
            tester.SendConfirmation();
            BOOST_REQUIRE(tester.Interact());
            CheckPQ(transport, PQStatus::HYBRID);
            tester.CompareSessionIDs();
        }
    }
    UniValue doc;
    BOOST_REQUIRE(doc.read(json_tests::pq_transport_vectors));
    int modeled{0};
    for (const UniValue& neg : doc["negative_vectors"].getValues()) {
        const UniValue& vec{doc["vectors"][neg["vector"].getInt<size_t>()]};
        auto ss{ParseHex(vec["ss_mlkem"].get_str())};
        ss[0] ^= 0xff;
        const UniValue& contents{neg["transcript_contents"]};
        if (HexStr(ss) == neg["ss_mlkem"].get_str() && contents[0].get_str() == vec["contents_responder"].get_str() &&
            contents[1].get_str() == vec["contents_initiator"].get_str()) {
            ++modeled;
        }
    }
    BOOST_CHECK_EQUAL(modeled, 1);
}

BOOST_AUTO_TEST_CASE(v2_pq_internal_errors)
{
    using mlkem::InjectResultForTesting;
    using mlkem::Operation;
    namespace upstream = mlkem::upstream;

    // Failures before anything is committed: an empty version packet, and plain v2 continues.
    for (const auto& [op, failure] : {std::pair{Operation::KEYGEN, PQFailure::KEYGEN_INTERNAL},
                                      std::pair{Operation::CHECK_PUBLIC_KEY, PQFailure::CHECK_EK_INTERNAL},
                                      std::pair{Operation::ENCAPS, PQFailure::ENCAPS_INTERNAL}}) {
        const bool test_initiator{op != Operation::KEYGEN};
        BOOST_TEST_CONTEXT("failure=" << int(failure))
        {
            g_kem_calls = {};
            TestPQEntropy entropy{m_rng.rand256()};
            V2TransportTester tester(m_rng, test_initiator, PQ_ON, entropy.Source(), COUNTING_KEM_OPS);
            auto& transport{tester.GetTransport()};
            if (test_initiator) {
                BOOST_REQUIRE(tester.Interact());
                tester.SendKey();
                tester.SendGarbage();
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                tester.SendOffer();
                InjectResultForTesting inject{op, upstream::ERR_FAIL};
                BOOST_REQUIRE(tester.Interact());
            } else {
                tester.SendKey();
                tester.SendGarbage();
                {
                    InjectResultForTesting inject{op, upstream::ERR_FAIL};
                    BOOST_REQUIRE(tester.Interact());
                }
                // No offer was queued, and the retained secret is wiped at once, not only when the
                // initiator's version packet arrives.
                BOOST_CHECK(transport.GetPQSnapshot().offer == PQOfferState::NONE);
                BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
            }
            tester.ReceiveGarbage();
            BOOST_CHECK(tester.ReceiveVersionContents().empty());
            tester.GetCipher().DiscardHybridSecret();
            if (!test_initiator) {
                // An unsolicited own record (an accept to an offer never made) is ignored and
                // never decapsulated.
                tester.SendVersion(MakeUCharSpan(MakeRecord(PQ_MLKEM1024, MakeByteSpan(m_rng.randbytes<uint8_t>(mlkem::CIPHERTEXT_BYTES)))));
            }
            const auto payload{m_rng.randbytes<uint8_t>(100)};
            tester.SendMessage(uint8_t(14), payload);
            tester.AddMessage("barfoo", payload);
            const auto ret{tester.Interact()};
            BOOST_REQUIRE(ret && ret->size() == 1);
            BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "inv" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(payload)));
            tester.ReceiveMessage("barfoo", payload);
            tester.CompareSessionIDs();
            CheckPQ(transport, PQStatus::OFF, failure);
            BOOST_CHECK(!transport.GetPQSnapshot().switched);
            BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
            BOOST_CHECK_EQUAL(g_kem_calls.decaps, 0);
            BOOST_CHECK_EQUAL(g_kem_calls.keygen, test_initiator ? 0 : 1);
        }
    }

    // Decapsulation fails after the initiator committed to its accept: close at once, on the
    // version packet, without queuing a confirmation. There is no failed status, so the closing
    // connection reports pending.
    {
        V2TransportTester tester(m_rng, false, PQ_ON);
        auto& transport{tester.GetTransport()};
        tester.SendKey();
        tester.SendGarbage();
        BOOST_REQUIRE(tester.Interact());
        tester.ReceiveKey(/*retain_for_hybrid=*/true);
        tester.SendGarbageTerm();
        tester.ReceiveGarbage();
        tester.AcceptOfferAndSwitch();
        InjectResultForTesting inject{Operation::DECAPS, upstream::ERR_FAIL};
        BOOST_CHECK(!tester.Deliver());
        BOOST_CHECK(tester.ToSend().empty());
        BOOST_CHECK(std::get<0>(transport.GetBytesToSend(false)).empty());
        const auto snapshot{transport.GetPQSnapshot()};
        BOOST_CHECK(snapshot.version_received && !snapshot.switched);
        CheckPQ(transport, PQStatus::PENDING, PQFailure::DECAPS_INTERNAL);
        BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
    }

    // An inconsistent cipher state (a local bug, behind Assume) closes in both roles, also before
    // the initiator committed to anything. Debug builds abort on the Assume instead.
    if constexpr (!G_FUZZING_BUILD && !G_ABORT_ON_FAILED_ASSUME) {
        for (const bool test_initiator : {true, false}) {
            BOOST_TEST_CONTEXT("cipher_state test_initiator=" << test_initiator)
            {
                g_kem_calls = {};
                TestPQEntropy entropy{m_rng.rand256()};
                V2TransportTester tester(m_rng, test_initiator, PQ_ON, entropy.Source(), COUNTING_KEM_OPS);
                auto& transport{tester.GetTransport()};
                if (test_initiator) tester.Collect();
                tester.SendKey();
                tester.SendGarbage();
                BOOST_REQUIRE(tester.Deliver());
                tester.Collect();
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                transport.DiscardHybridSecretForTesting();
                if (test_initiator) {
                    tester.SendOffer();
                } else {
                    tester.ReceiveGarbage();
                    tester.AcceptOfferAndSwitch();
                }
                BOOST_CHECK(!tester.Deliver());
                // Nothing more is queued: no version packet from the initiator, no confirmation.
                BOOST_CHECK(std::get<0>(transport.GetBytesToSend(false)).empty());
                BOOST_CHECK(!transport.GetPQSnapshot().switched);
                CheckPQ(transport, PQStatus::PENDING, PQFailure::CIPHER_STATE_INTERNAL);
                BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
                BOOST_CHECK_EQUAL(g_kem_calls.check + g_kem_calls.encaps + g_kem_calls.decaps, 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_malformed_record)
{
    // The first own record of the peer's version packet has the wrong length, or (offer only) a
    // key that fails the modulus check: close with that failure, wipe both secrets, and queue
    // nothing, without any encapsulation or decapsulation.
    const auto valid_offer{PQHandshake::SerializeRecord(TestEncapsulationKey())};
    const auto bad_payload = [&](size_t size) { return MakeRecord(PQ_MLKEM1024, MakeByteSpan(m_rng.randbytes<uint8_t>(size))); };
    struct Case {
        std::string name;
        bool test_initiator;
        std::vector<std::byte> contents;
        PQFailure failure;
    };
    std::vector<Case> cases{
        {"ek 1567", true, bad_payload(mlkem::PUBLIC_KEY_BYTES - 1), PQFailure::EK_LENGTH},
        {"ek 1569", true, bad_payload(mlkem::PUBLIC_KEY_BYTES + 1), PQFailure::EK_LENGTH},
        {"ek modulus", true, MakeRecord(PQ_MLKEM1024, std::vector<std::byte>(mlkem::PUBLIC_KEY_BYTES, std::byte{0xff})), PQFailure::EK_MODULUS},
        {"malformed first, valid second", true, Concat({bad_payload(2), valid_offer}), PQFailure::EK_LENGTH},
    };
    for (const size_t size : {size_t{0}, mlkem::CIPHERTEXT_BYTES - 1, mlkem::CIPHERTEXT_BYTES + 1, size_t{3000}}) {
        cases.push_back({strprintf("ct %u", size), false, bad_payload(size), PQFailure::CT_LENGTH});
    }
    for (const auto& c : cases) {
        BOOST_TEST_CONTEXT(c.name)
        {
            g_kem_calls = {};
            TestPQEntropy entropy{m_rng.rand256()};
            V2TransportTester tester(m_rng, c.test_initiator, PQ_ON, entropy.Source(), COUNTING_KEM_OPS);
            auto& transport{tester.GetTransport()};
            if (c.test_initiator) tester.Collect();
            tester.SendKey();
            tester.SendGarbage();
            BOOST_REQUIRE(tester.Deliver());
            // Everything queued so far: the key, garbage and terminator, and a responder's offer.
            tester.Collect();
            BOOST_CHECK(transport.HoldsHybridSecretsForTesting());
            tester.ReceiveKey();
            tester.SendGarbageTerm();
            if (!c.test_initiator) {
                tester.ReceiveGarbage();
                BOOST_CHECK(PQHandshake::ParseContents(MakeByteSpan(tester.ReceiveVersionContents())).kind == PQHandshake::ParseKind::OWN_RECORD);
            }
            tester.SendVersion(MakeUCharSpan(c.contents));
            BOOST_CHECK(!tester.Deliver());
            BOOST_CHECK(std::get<0>(transport.GetBytesToSend(false)).empty());
            const auto snapshot{transport.GetPQSnapshot()};
            BOOST_CHECK(snapshot.version_received && !snapshot.switched);
            CheckPQ(transport, PQStatus::PENDING, c.failure);
            BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
            BOOST_CHECK_EQUAL(g_kem_calls.check, c.failure == PQFailure::EK_MODULUS ? 1 : 0);
            BOOST_CHECK_EQUAL(g_kem_calls.encaps + g_kem_calls.decaps, 0);
            BOOST_CHECK_EQUAL(g_kem_calls.keygen, c.test_initiator ? 0 : 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_close_wipes)
{
    // A close the transport detects before the peer's version packet authenticated (a missing
    // garbage terminator, or a version packet that is too long or fails its tag) wipes the
    // retained ECDH secret and a responder's decapsulation key at once.
    enum class Close { GARBAGE_TERMINATOR, VERSION_LENGTH, VERSION_TAG };
    for (const bool test_initiator : {true, false}) {
        for (const Close close : {Close::GARBAGE_TERMINATOR, Close::VERSION_LENGTH, Close::VERSION_TAG}) {
            BOOST_TEST_CONTEXT("test_initiator=" << test_initiator << " close=" << int(close))
            {
                V2TransportTester tester(m_rng, test_initiator, PQ_ON);
                auto& transport{tester.GetTransport()};
                if (test_initiator) tester.Collect();
                tester.SendKey();
                BOOST_REQUIRE(tester.Deliver());
                tester.Collect();
                tester.ReceiveKey();
                if (close == Close::GARBAGE_TERMINATOR) {
                    tester.SendGarbage(V2Transport::MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
                } else {
                    tester.SendGarbage();
                    tester.SendGarbageTerm();
                    const size_t version_start{tester.ToSend().size()};
                    if (close == Close::VERSION_LENGTH) {
                        // Only the length of a version packet one byte over the maximum arrives.
                        tester.SendVersion(std::vector<uint8_t>(4'000'014));
                        tester.ToSend().resize(version_start + BIP324Cipher::LENGTH_LEN);
                    } else {
                        tester.SendVersion();
                        tester.ToSend().back() ^= 1 << m_rng.randrange(8);
                    }
                }
                // Nothing fails before the last byte, and the secrets for the switch are held.
                const std::vector<uint8_t> last{tester.ToSend().back()};
                tester.ToSend().pop_back();
                BOOST_REQUIRE(tester.Deliver());
                BOOST_CHECK(transport.HoldsHybridSecretsForTesting());
                tester.Send(last);
                BOOST_CHECK(!tester.Deliver());
                BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());
                // No PQ failure: the close is the transport's, before the peer's version packet.
                const auto snapshot{transport.GetPQSnapshot()};
                BOOST_CHECK(!snapshot.version_received && !snapshot.switched);
                BOOST_CHECK(snapshot.offer == (test_initiator ? PQOfferState::NONE : PQOfferState::SENT));
                CheckPQ(transport, PQStatus::PENDING);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_version_wipes)
{
    // However a transport came to send its version packet without the negotiation, processing the
    // peer's version packet wipes anything still held for a switch. A test option retains the ECDH
    // secret and the transcript with the negotiation off, as a path that declined it after the key
    // exchange without wiping them would.
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, {.mode = PQMode::OFF, .retain_without_negotiation = true});
            auto& transport{tester.GetTransport()};
            if (test_initiator) tester.Collect();
            tester.SendKey();
            tester.SendGarbage();
            BOOST_REQUIRE(tester.Deliver());
            tester.Collect();
            tester.ReceiveKey();
            tester.SendGarbageTerm();
            BOOST_REQUIRE(tester.Deliver());
            // The transport sent its empty version packet, and still holds the retained secret.
            BOOST_CHECK(transport.HoldsHybridSecretsForTesting());
            tester.ReceiveGarbage();
            tester.ReceiveVersion();
            tester.SendVersion();
            BOOST_REQUIRE(tester.Deliver());
            BOOST_CHECK(!transport.HoldsHybridSecretsForTesting());

            // The connection continues as plain v2.
            const auto payload{m_rng.randbytes<uint8_t>(100)};
            tester.SendMessage("foobar", payload);
            tester.AddMessage("barfoo", payload);
            const auto ret{tester.Interact()};
            BOOST_REQUIRE(ret && ret->size() == 1);
            BOOST_CHECK((*ret)[0] && (*ret)[0]->m_type == "foobar" && std::ranges::equal((*ret)[0]->m_recv, MakeByteSpan(payload)));
            tester.ReceiveMessage("barfoo", payload);
            tester.CompareSessionIDs();
            CheckPQ(transport, PQStatus::OFF);
        }
    }
}

BOOST_AUTO_TEST_CASE(v2_pq_rekey)
{
    for (const bool test_initiator : {true, false}) {
        BOOST_TEST_CONTEXT("test_initiator=" << test_initiator)
        {
            V2TransportTester tester(m_rng, test_initiator, PQ_ON);
            auto& transport{tester.GetTransport()};
            // 222 decoys before our version packet: the transport's ECDH receive counter is at 223,
            // one packet before a rekey, when it switches.
            constexpr int DECOYS{BIP324Cipher::REKEY_INTERVAL - 2};
            if (test_initiator) {
                BOOST_REQUIRE(tester.Interact());
                tester.SendKey();
                tester.SendGarbage();
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                for (int i = 0; i < DECOYS; ++i) tester.SendVersion(m_rng.randbytes<uint8_t>(m_rng.randrange(10)), /*vers_ignore=*/true);
                tester.SendOffer();
                BOOST_REQUIRE(tester.Interact());
                tester.ReceiveGarbage();
                tester.ReceiveAcceptAndSwitch();
            } else {
                tester.SendKey();
                tester.SendGarbage();
                BOOST_REQUIRE(tester.Interact());
                tester.ReceiveKey(/*retain_for_hybrid=*/true);
                tester.SendGarbageTerm();
                tester.ReceiveGarbage();
                for (int i = 0; i < DECOYS; ++i) tester.SendVersion(m_rng.randbytes<uint8_t>(m_rng.randrange(10)), /*vers_ignore=*/true);
                tester.AcceptOfferAndSwitch();
                BOOST_REQUIRE(tester.Interact());
            }
            tester.ReceiveConfirmation();
            tester.SendConfirmation();

            // More than two rekey intervals of hybrid packets each way.
            constexpr int MESSAGES{2 * BIP324Cipher::REKEY_INTERVAL + 2};
            std::vector<std::vector<uint8_t>> payloads;
            for (int i = 0; i < MESSAGES; ++i) {
                payloads.push_back(m_rng.randbytes<uint8_t>(m_rng.randrange(100)));
                tester.SendMessage(uint8_t(14), payloads.back());
                tester.AddMessage("barfoo", payloads.back());
            }
            const auto ret{tester.Interact()};
            BOOST_REQUIRE(ret && ret->size() == MESSAGES);
            for (int i = 0; i < MESSAGES; ++i) {
                BOOST_CHECK((*ret)[i] && (*ret)[i]->m_type == "inv" && std::ranges::equal((*ret)[i]->m_recv, MakeByteSpan(payloads[i])));
                tester.ReceiveMessage("barfoo", payloads[i]);
            }
            CheckPQ(transport, PQStatus::HYBRID);
            tester.CompareSessionIDs();
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
