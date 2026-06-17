#include <app.h>
#include <clock.h>
#include <log_rate_limiter.h>
#include <protocol.h>
#include <test_harness.h>
#include <udp_transport.h>
#include <version.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t kRemoteSessionId = 9001;

class ArgvBuilder {
public:
    explicit ArgvBuilder(std::vector<std::string> args)
        : m_args(std::move(args))
    {
        m_argv.reserve(m_args.size());
        for (std::string& arg : m_args) {
            m_argv.push_back(arg.data());
        }
    }

    int argc() const
    {
        return static_cast<int>(m_argv.size());
    }

    char** argv()
    {
        return m_argv.data();
    }

private:
    std::vector<std::string> m_args{};
    std::vector<char*> m_argv{};
};

struct ListenerState {
    bool connect_result{true};
    std::optional<std::string> sequence_endpoint{};
    std::string connect_endpoint{};
    std::deque<std::optional<std::array<std::uint8_t, 32>>> next_hash_results{};
    std::size_t next_hash_calls{0};
};

class ScriptedListener final : public photon::app::Listener {
public:
    explicit ScriptedListener(std::shared_ptr<ListenerState> state)
        : m_state(std::move(state))
    {
    }

    void SetSequenceEndpoint(std::optional<std::string> endpoint) override
    {
        m_state->sequence_endpoint = std::move(endpoint);
    }

    bool Connect(const std::string& endpoint) override
    {
        m_state->connect_endpoint = endpoint;
        return m_state->connect_result;
    }

    std::optional<std::array<std::uint8_t, 32>> NextHash(std::chrono::milliseconds) override
    {
        ++m_state->next_hash_calls;
        if (m_state->next_hash_results.empty()) {
            return std::nullopt;
        }

        const auto value = m_state->next_hash_results.front();
        m_state->next_hash_results.pop_front();
        return value;
    }

private:
    std::shared_ptr<ListenerState> m_state;
};

struct RpcState {
    bool probe_result{true};
    std::size_t probe_calls{0};
    std::vector<std::string> getblock_hashes{};
    std::optional<std::vector<std::uint8_t>> getblock_result{std::vector<std::uint8_t>{0x01}};
    bool submit_result{true};
    std::size_t submit_calls{0};
    std::vector<std::uint8_t> last_submitted{};
};

class ScriptedRpc final : public photon::app::Rpc {
public:
    explicit ScriptedRpc(std::shared_ptr<RpcState> state)
        : m_state(std::move(state))
    {
    }

    bool Probe() override
    {
        ++m_state->probe_calls;
        return m_state->probe_result;
    }

    std::optional<std::vector<std::uint8_t>> GetBlock(const std::string& hash_hex) override
    {
        m_state->getblock_hashes.push_back(hash_hex);
        return m_state->getblock_result;
    }

    bool SubmitBlock(std::span<const std::uint8_t> block_data) override
    {
        ++m_state->submit_calls;
        m_state->last_submitted.assign(block_data.begin(), block_data.end());
        return m_state->submit_result;
    }

private:
    std::shared_ptr<RpcState> m_state;
};

struct TransportState {
    bool open_result{true};
    std::string bind_host{};
    std::uint16_t bind_port{0};
    std::deque<photon::RecvPacketResult> recv_results{};
    std::vector<photon::Packet> sent_packets{};
};

class ScriptedTransport final : public photon::app::Transport {
public:
    explicit ScriptedTransport(std::shared_ptr<TransportState> state)
        : m_state(std::move(state))
    {
    }

    bool OpenAndBind(const std::string& bind_host, std::uint16_t bind_port, std::string*) override
    {
        m_state->bind_host = bind_host;
        m_state->bind_port = bind_port;
        return m_state->open_result;
    }

    bool SendPacket(const photon::Packet& packet,
                    const sockaddr_storage&,
                    socklen_t,
                    std::string*) override
    {
        m_state->sent_packets.push_back(packet);
        return true;
    }

    photon::RecvPacketResult ReceivePacket() override
    {
        if (m_state->recv_results.empty()) {
            photon::RecvPacketResult result{};
            result.status = photon::RecvStatus::kWouldBlock;
            return result;
        }

        const photon::RecvPacketResult result = m_state->recv_results.front();
        m_state->recv_results.pop_front();
        return result;
    }

private:
    std::shared_ptr<TransportState> m_state;
};

photon::ConfigLoadResult MakeConfigResult()
{
    photon::ConfigLoadResult result{};
    result.ok = true;
    result.config.qbitd.zmq_hashblock = "tcp://127.0.0.1:28332";
    result.config.qbitd.zmq_sequence = "tcp://127.0.0.1:28333";
    result.config.qbitd.rpc_host = "127.0.0.1";
    result.config.qbitd.rpc_port = 8352;
    result.config.qbitd.rpc_cookiefile = "/tmp/photon-test.cookie";
    result.config.qbitd.rpc_timeout_ms = 100;
    result.config.local.bind_port = 8144;
    return result;
}

photon::ConfigLoadResult MakeConfigWithPeer(std::uint16_t peer_port, const std::array<std::uint8_t, 32>& key)
{
    photon::ConfigLoadResult result = MakeConfigResult();

    photon::PeerConfig peer{};
    peer.name = "peer-a";
    peer.host = "127.0.0.1";
    peer.port = peer_port;
    peer.hmac_key = key;

    result.config.peers.push_back(peer);
    return result;
}

bool ResolveAddr(std::uint16_t port, sockaddr_storage& addr, socklen_t& addr_len)
{
    std::string error;
    return photon::UdpTransport::ResolveEndpoint("127.0.0.1", port, &addr, &addr_len, &error);
}

photon::RecvPacketResult PacketResult(const photon::Packet& packet, const sockaddr_storage& addr, socklen_t addr_len)
{
    photon::RecvPacketResult result{};
    result.status = photon::RecvStatus::kPacket;
    result.packet = packet;
    result.peer = addr;
    result.peer_len = addr_len;
    return result;
}

bool SentMessage(const std::vector<photon::Packet>& sent_packets, photon::MessageType type)
{
    for (const photon::Packet& packet : sent_packets) {
        if (packet.msg_type == type) {
            return true;
        }
    }
    return false;
}

void TestHelpFlag()
{
    ArgvBuilder args({"qbit-photon", "--help"});
    std::ostringstream out;
    std::ostringstream err;

    photon::app::Deps deps{};
    deps.should_shutdown = [] { return true; };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 0);
    CHECK(out.str().find("Usage: qbit-photon") != std::string::npos);
    CHECK(err.str().empty());
}

void TestVersionFlag()
{
    ArgvBuilder args({"qbit-photon", "--version"});
    std::ostringstream out;
    std::ostringstream err;

    photon::app::Deps deps{};
    deps.should_shutdown = [] { return true; };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 0);
    CHECK(out.str().find(std::string("qbit-photon ") + QBIT_PHOTON_VERSION) != std::string::npos);
    CHECK(err.str().empty());
}

void TestArgumentValidation()
{
    {
        ArgvBuilder args({"qbit-photon", "--config"});
        std::ostringstream out;
        std::ostringstream err;

        photon::app::Deps deps{};
        deps.should_shutdown = [] { return true; };
        deps.install_signal_handlers = [] {};

        const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
        CHECK(rc == 1);
        CHECK(err.str().find("--config requires a path") != std::string::npos);
    }

    {
        ArgvBuilder args({"qbit-photon", "--unknown-flag"});
        std::ostringstream out;
        std::ostringstream err;

        photon::app::Deps deps{};
        deps.should_shutdown = [] { return true; };
        deps.install_signal_handlers = [] {};

        const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
        CHECK(rc == 1);
        CHECK(err.str().find("Unknown argument: --unknown-flag") != std::string::npos);
        CHECK(err.str().find("Usage: qbit-photon") != std::string::npos);
    }
}

void TestConfigLoadFailurePath()
{
    ArgvBuilder args({"qbit-photon"});
    std::ostringstream out;
    std::ostringstream err;

    photon::app::Deps deps{};
    deps.load_config = [](const std::string&) {
        photon::ConfigLoadResult result{};
        result.ok = false;
        result.error = "missing required field";
        return result;
    };
    deps.should_shutdown = [] { return true; };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 1);
    CHECK(err.str().find("Failed to load config: missing required field") != std::string::npos);
}

void TestZmqConnectFailurePath()
{
    ArgvBuilder args({"qbit-photon"});
    std::ostringstream out;
    std::ostringstream err;

    const auto listener_state = std::make_shared<ListenerState>();
    listener_state->connect_result = false;

    bool rpc_factory_called = false;

    photon::app::Deps deps{};
    deps.load_config = [](const std::string&) { return MakeConfigResult(); };
    deps.set_log_level = [](photon::logging::LogLevel) {};
    deps.make_listener = [listener_state] { return std::make_unique<ScriptedListener>(listener_state); };
    deps.make_rpc = [&rpc_factory_called](const photon::RpcClientOptions&) {
        rpc_factory_called = true;
        return std::unique_ptr<photon::app::Rpc>{};
    };
    deps.should_shutdown = [] { return true; };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 1);
    CHECK(listener_state->connect_endpoint == "tcp://127.0.0.1:28332");
    CHECK(listener_state->sequence_endpoint.has_value());
    CHECK(*listener_state->sequence_endpoint == "tcp://127.0.0.1:28333");
    CHECK(!rpc_factory_called);
}

void TestRpcProbeFailurePath()
{
    ArgvBuilder args({"qbit-photon"});
    std::ostringstream out;
    std::ostringstream err;

    const auto listener_state = std::make_shared<ListenerState>();
    const auto rpc_state = std::make_shared<RpcState>();
    rpc_state->probe_result = false;

    photon::app::Deps deps{};
    deps.load_config = [](const std::string&) { return MakeConfigResult(); };
    deps.set_log_level = [](photon::logging::LogLevel) {};
    deps.make_listener = [listener_state] { return std::make_unique<ScriptedListener>(listener_state); };
    deps.make_rpc = [rpc_state](const photon::RpcClientOptions&) { return std::make_unique<ScriptedRpc>(rpc_state); };
    deps.should_shutdown = [] { return true; };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 1);
    CHECK(rpc_state->probe_calls == 1);
    CHECK(rpc_state->getblock_hashes.empty());
}

void TestHashNotificationTriggersGetBlock()
{
    ArgvBuilder args({"qbit-photon"});
    std::ostringstream out;
    std::ostringstream err;

    std::array<std::uint8_t, 32> hash{};
    for (std::size_t i = 0; i < hash.size(); ++i) {
        hash[i] = static_cast<std::uint8_t>(i);
    }

    const auto listener_state = std::make_shared<ListenerState>();
    listener_state->next_hash_results.push_back(hash);

    const auto rpc_state = std::make_shared<RpcState>();
    rpc_state->probe_result = true;
    rpc_state->getblock_result = std::vector<std::uint8_t>{0xAA, 0xBB};

    const auto transport_state = std::make_shared<TransportState>();

    photon::app::Deps deps{};
    deps.load_config = [](const std::string&) { return MakeConfigResult(); };
    deps.set_log_level = [](photon::logging::LogLevel) {};
    deps.make_listener = [listener_state] { return std::make_unique<ScriptedListener>(listener_state); };
    deps.make_rpc = [rpc_state](const photon::RpcClientOptions&) { return std::make_unique<ScriptedRpc>(rpc_state); };
    deps.make_transport = [transport_state] { return std::make_unique<ScriptedTransport>(transport_state); };
    deps.should_shutdown = [rpc_state, spins = 0U]() mutable {
        ++spins;
        return !rpc_state->getblock_hashes.empty() || spins > 32;
    };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 0);
    CHECK(rpc_state->probe_calls == 1);
    CHECK(rpc_state->getblock_hashes.size() == 1);
    CHECK(rpc_state->getblock_hashes[0] == photon::app::HashToHex(hash));
    CHECK(transport_state->bind_port == 8144);
}

void TestHashNotificationSendsChunksToPeer()
{
    ArgvBuilder args({"qbit-photon"});
    std::ostringstream out;
    std::ostringstream err;

    const std::array<std::uint8_t, 32> peer_key{
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    };
    constexpr std::uint16_t kPeerPort = 39001;

    std::array<std::uint8_t, 32> hash{};
    for (std::size_t i = 0; i < hash.size(); ++i) {
        hash[i] = static_cast<std::uint8_t>(0xA0 + i);
    }

    const auto listener_state = std::make_shared<ListenerState>();
    listener_state->next_hash_results.push_back(hash);

    const auto rpc_state = std::make_shared<RpcState>();
    rpc_state->probe_result = true;
    rpc_state->getblock_result = std::vector<std::uint8_t>(4000, 0x42);

    const auto transport_state = std::make_shared<TransportState>();

    sockaddr_storage peer_addr{};
    socklen_t peer_addr_len = 0;
    CHECK(ResolveAddr(kPeerPort, peer_addr, peer_addr_len));

    photon::Packet synack = photon::MakePacket(photon::MessageType::kSynAck, 100);
    photon::SynPayload syn{};
    syn.session_id = kRemoteSessionId;
    syn.peer_id = 10001;
    photon::EncodeSynPayload(syn, synack.payload);
    photon::AttachPacketMac(synack, peer_key);
    transport_state->recv_results.push_back(PacketResult(synack, peer_addr, peer_addr_len));

    photon::app::Deps deps{};
    deps.load_config = [peer_key](const std::string&) { return MakeConfigWithPeer(kPeerPort, peer_key); };
    deps.set_log_level = [](photon::logging::LogLevel) {};
    deps.make_listener = [listener_state] { return std::make_unique<ScriptedListener>(listener_state); };
    deps.make_rpc = [rpc_state](const photon::RpcClientOptions&) { return std::make_unique<ScriptedRpc>(rpc_state); };
    deps.make_transport = [transport_state] { return std::make_unique<ScriptedTransport>(transport_state); };
    deps.should_shutdown = [transport_state, spins = 0U]() mutable {
        ++spins;
        return SentMessage(transport_state->sent_packets, photon::MessageType::kBlockChunk) || spins > 400;
    };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 0);
    CHECK(SentMessage(transport_state->sent_packets, photon::MessageType::kBlockHeader));
    CHECK(SentMessage(transport_state->sent_packets, photon::MessageType::kBlockChunk));
}

void TestInboundChunksTriggerSubmitBlock()
{
    ArgvBuilder args({"qbit-photon"});
    std::ostringstream out;
    std::ostringstream err;

    const std::array<std::uint8_t, 32> peer_key{
        9, 8, 7, 6, 5, 4, 3, 2,
        1, 0, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
    };
    constexpr std::uint16_t kPeerPort = 39002;
    constexpr std::uint64_t kHashPrefix = 0x1122334455667788ULL;

    const auto listener_state = std::make_shared<ListenerState>();
    const auto rpc_state = std::make_shared<RpcState>();
    rpc_state->probe_result = true;

    const auto transport_state = std::make_shared<TransportState>();

    sockaddr_storage peer_addr{};
    socklen_t peer_addr_len = 0;
    CHECK(ResolveAddr(kPeerPort, peer_addr, peer_addr_len));

    photon::Packet synack = photon::MakePacket(photon::MessageType::kSynAck, 1);
    photon::SynPayload syn{};
    syn.session_id = kRemoteSessionId;
    syn.peer_id = 10002;
    photon::EncodeSynPayload(syn, synack.payload);
    photon::AttachPacketMac(synack, peer_key);
    transport_state->recv_results.push_back(PacketResult(synack, peer_addr, peer_addr_len));

    photon::BlockHeaderPayload header{};
    header.block_hash_prefix = kHashPrefix;
    header.original_size = 5;
    header.data_chunks = 2;
    header.coding_group_count = 1;

    photon::Packet header_packet = photon::MakePacket(photon::MessageType::kBlockHeader, 2);
    photon::EncodeBlockHeaderPayload(header, header_packet.payload);
    photon::AttachPacketMac(header_packet, peer_key, kRemoteSessionId);
    transport_state->recv_results.push_back(PacketResult(header_packet, peer_addr, peer_addr_len));

    photon::BlockChunkPayload chunk0{};
    chunk0.block_hash_prefix = kHashPrefix;
    chunk0.coding_group_id = 0;
    chunk0.chunk_id = 0;
    chunk0.data_len = static_cast<std::uint16_t>(photon::kFecChunkSize);
    chunk0.chunk_data.fill(0);
    chunk0.chunk_data[0] = 'h';
    chunk0.chunk_data[1] = 'e';
    chunk0.chunk_data[2] = 'l';
    chunk0.chunk_data[3] = 'l';
    chunk0.chunk_data[4] = 'o';

    photon::Packet chunk0_packet = photon::MakePacket(photon::MessageType::kBlockChunk, 3);
    photon::EncodeBlockChunkPayload(chunk0, chunk0_packet.payload);
    photon::AttachPacketMac(chunk0_packet, peer_key, kRemoteSessionId);
    transport_state->recv_results.push_back(PacketResult(chunk0_packet, peer_addr, peer_addr_len));

    photon::BlockChunkPayload chunk1{};
    chunk1.block_hash_prefix = kHashPrefix;
    chunk1.coding_group_id = 0;
    chunk1.chunk_id = 1;
    chunk1.data_len = static_cast<std::uint16_t>(photon::kFecChunkSize);
    chunk1.chunk_data.fill(0);

    photon::Packet chunk1_packet = photon::MakePacket(photon::MessageType::kBlockChunk, 4);
    photon::EncodeBlockChunkPayload(chunk1, chunk1_packet.payload);
    photon::AttachPacketMac(chunk1_packet, peer_key, kRemoteSessionId);
    transport_state->recv_results.push_back(PacketResult(chunk1_packet, peer_addr, peer_addr_len));

    photon::app::Deps deps{};
    deps.load_config = [peer_key](const std::string&) { return MakeConfigWithPeer(kPeerPort, peer_key); };
    deps.set_log_level = [](photon::logging::LogLevel) {};
    deps.make_listener = [listener_state] { return std::make_unique<ScriptedListener>(listener_state); };
    deps.make_rpc = [rpc_state](const photon::RpcClientOptions&) { return std::make_unique<ScriptedRpc>(rpc_state); };
    deps.make_transport = [transport_state] { return std::make_unique<ScriptedTransport>(transport_state); };
    deps.should_shutdown = [rpc_state, spins = 0U]() mutable {
        ++spins;
        return rpc_state->submit_calls > 0 || spins > 400;
    };
    deps.install_signal_handlers = [] {};

    const int rc = photon::app::Run(args.argc(), args.argv(), out, err, std::move(deps));
    CHECK(rc == 0);
    CHECK(rpc_state->submit_calls == 1);

    const std::vector<std::uint8_t> expected{'h', 'e', 'l', 'l', 'o'};
    CHECK(rpc_state->last_submitted == expected);
}

void TestMalformedUdpParseErrorsAreRateLimited()
{
    photon::MockClock clock{};
    photon::LogRateLimiter limiter{std::chrono::seconds{60}};

    const auto first_log = limiter.Record(clock.Now(), "udp parse error: invalid packet size");
    CHECK(first_log.has_value());
    if (first_log.has_value()) {
        CHECK(first_log->find("invalid packet size") != std::string::npos);
        CHECK(first_log->find("suppressed") == std::string::npos);
    }

    for (std::size_t i = 0; i < 256; ++i) {
        const auto suppressed = limiter.Record(clock.Now(), "udp parse error: invalid packet size");
        CHECK(!suppressed.has_value());
    }

    CHECK(limiter.total() == 257);
    CHECK(limiter.suppressed() == 256);

    clock.Advance(std::chrono::seconds{60});
    const auto summary_log = limiter.Record(clock.Now(), "udp parse error: invalid packet size");
    CHECK(summary_log.has_value());
    if (summary_log.has_value()) {
        CHECK(summary_log->find("suppressed 256 similar messages") != std::string::npos);
        CHECK(summary_log->find("total=258") != std::string::npos);
    }

    CHECK(limiter.total() == 258);
    CHECK(limiter.suppressed() == 256);
}

} // namespace

int main()
{
    TestHelpFlag();
    TestVersionFlag();
    TestArgumentValidation();
    TestConfigLoadFailurePath();
    TestZmqConnectFailurePath();
    TestRpcProbeFailurePath();
    TestHashNotificationTriggersGetBlock();
    TestHashNotificationSendsChunksToPeer();
    TestInboundChunksTriggerSubmitBlock();
    TestMalformedUdpParseErrorsAreRateLimited();
    return photon::test::Finish();
}
