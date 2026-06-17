#include <app.h>

#include <clock.h>
#include <log_rate_limiter.h>
#include <logging.h>
#include <peer_manager.h>
#include <relay_engine.h>
#include <udp_transport.h>
#include <version.h>
#include <zmq_listener.h>

#include <atomic>
#include <csignal>
#include <memory>
#include <string>
#include <utility>

namespace photon::app {
namespace {

std::atomic<bool> g_shutdown{false};

void SignalHandler(int)
{
    g_shutdown.store(true, std::memory_order_relaxed);
}

std::string PeerStatsLogFields(const PeerManagerStats& stats)
{
    return " peers_active=" + std::to_string(stats.states.active)
        + " peers_stale=" + std::to_string(stats.states.stale)
        + " peers_connecting=" + std::to_string(stats.states.connecting)
        + " peers_disconnected=" + std::to_string(stats.states.disconnected)
        + " peer_syn_sent=" + std::to_string(stats.totals.syn_sent)
        + " peer_syn_recv=" + std::to_string(stats.totals.syn_received)
        + " peer_synack_sent=" + std::to_string(stats.totals.synack_sent)
        + " peer_synack_recv=" + std::to_string(stats.totals.synack_received)
        + " peer_keepalive_sent=" + std::to_string(stats.totals.keepalive_sent)
        + " peer_keepalive_recv=" + std::to_string(stats.totals.keepalive_received)
        + " peer_mac_failures=" + std::to_string(stats.totals.mac_failures)
        + " peer_replay_rejects=" + std::to_string(stats.totals.replay_rejects)
        + " peer_session_replacements=" + std::to_string(stats.totals.session_replacements)
        + " peer_session_replacement_rejects=" + std::to_string(stats.totals.session_replacement_rejects)
        + " peer_resolve_failures=" + std::to_string(stats.totals.resolve_failures);
}

void PrintUsage(std::ostream& out, const char* program)
{
    out << "Usage: " << program << " [--config <path>] [--help] [--version]\n";
}

class ZmqListenerAdapter final : public Listener {
public:
    void SetSequenceEndpoint(std::optional<std::string> endpoint) override
    {
        m_listener.SetSequenceEndpoint(std::move(endpoint));
    }

    bool Connect(const std::string& endpoint) override
    {
        return m_listener.Connect(endpoint);
    }

    std::optional<std::array<std::uint8_t, 32>> NextHash(std::chrono::milliseconds timeout) override
    {
        return m_listener.NextHash(timeout);
    }

private:
    ZmqListener m_listener{};
};

class RpcClientAdapter final : public Rpc {
public:
    explicit RpcClientAdapter(RpcClientOptions options)
        : m_rpc(std::move(options))
    {
    }

    bool Probe() override
    {
        return m_rpc.Probe();
    }

    std::optional<std::vector<std::uint8_t>> GetBlock(const std::string& hash_hex) override
    {
        return m_rpc.GetBlock(hash_hex);
    }

    bool SubmitBlock(std::span<const std::uint8_t> block_data) override
    {
        return m_rpc.SubmitBlock(block_data);
    }

private:
    RpcClient m_rpc;
};

class UdpTransportAdapter final : public Transport {
public:
    bool OpenAndBind(const std::string& bind_host, std::uint16_t bind_port, std::string* error) override
    {
        return m_transport.OpenAndBind(bind_host, bind_port, error);
    }

    bool SendPacket(const Packet& packet,
                    const sockaddr_storage& addr,
                    socklen_t addr_len,
                    std::string* error) override
    {
        return m_transport.SendPacket(packet, addr, addr_len, error);
    }

    RecvPacketResult ReceivePacket() override
    {
        return m_transport.ReceivePacket();
    }

private:
    UdpTransport m_transport{};
};

class TransportPacketSink final : public PacketSink {
public:
    explicit TransportPacketSink(Transport& transport)
        : m_transport(transport)
    {
    }

    bool SendPacket(const Packet& packet,
                    const sockaddr_storage& addr,
                    socklen_t addr_len,
                    std::string* error) override
    {
        return m_transport.SendPacket(packet, addr, addr_len, error);
    }

private:
    Transport& m_transport;
};

class RpcSubmitterAdapter final : public BlockSubmitter {
public:
    explicit RpcSubmitterAdapter(Rpc& rpc)
        : m_rpc(rpc)
    {
    }

    bool SubmitBlock(std::span<const std::uint8_t> block_data) override
    {
        return m_rpc.SubmitBlock(block_data);
    }

private:
    Rpc& m_rpc;
};

} // namespace

std::string HashToHex(const std::array<std::uint8_t, 32>& hash)
{
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out;
    out.reserve(hash.size() * 2);

    for (const std::uint8_t byte : hash) {
        out.push_back(kHex[(byte >> 4) & 0x0F]);
        out.push_back(kHex[byte & 0x0F]);
    }

    return out;
}

Deps MakeDefaultDeps()
{
    Deps deps{};
    deps.load_config = [](const std::string& path) { return LoadConfig(path); };
    deps.set_log_level = [](logging::LogLevel level) { logging::SetLogLevel(level); };
    deps.make_listener = [] { return std::make_unique<ZmqListenerAdapter>(); };
    deps.make_rpc = [](const RpcClientOptions& options) { return std::make_unique<RpcClientAdapter>(options); };
    deps.make_transport = [] { return std::make_unique<UdpTransportAdapter>(); };
    deps.should_shutdown = [] { return g_shutdown.load(std::memory_order_relaxed); };
    deps.install_signal_handlers = [] {
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        std::signal(SIGINT, SignalHandler);
        std::signal(SIGTERM, SignalHandler);
    };
    return deps;
}

int Run(int argc, char** argv, std::ostream& out, std::ostream& err, Deps deps)
{
    if (!deps.load_config) {
        deps.load_config = [](const std::string& path) { return LoadConfig(path); };
    }
    if (!deps.set_log_level) {
        deps.set_log_level = [](logging::LogLevel level) { logging::SetLogLevel(level); };
    }
    if (!deps.should_shutdown) {
        deps.should_shutdown = [] { return g_shutdown.load(std::memory_order_relaxed); };
    }
    if (!deps.install_signal_handlers) {
        deps.install_signal_handlers = [] {};
    }

    std::string config_path = "qbit-photon.conf";

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);

        if (arg == "--help") {
            PrintUsage(out, argv[0]);
            return 0;
        }

        if (arg == "--version") {
            out << "qbit-photon " << QBIT_PHOTON_VERSION << '\n';
            return 0;
        }

        if (arg == "--config") {
            if (i + 1 >= argc) {
                err << "--config requires a path\n";
                return 1;
            }

            config_path = argv[++i];
            continue;
        }

        err << "Unknown argument: " << arg << '\n';
        PrintUsage(err, argv[0]);
        return 1;
    }

    const ConfigLoadResult loaded = deps.load_config(config_path);
    if (!loaded.ok) {
        err << "Failed to load config: " << loaded.error << '\n';
        return 1;
    }

    deps.set_log_level(loaded.config.local.log_level);

    LOG_INFO("qbit-photon starting");
    LOG_INFO("configured bind_port=" + std::to_string(loaded.config.local.bind_port)
             + " peers=" + std::to_string(loaded.config.peers.size()));

    deps.install_signal_handlers();

    if (!deps.make_listener) {
        err << "internal error: listener factory not configured\n";
        return 1;
    }

    std::unique_ptr<Listener> listener = deps.make_listener();
    if (!listener) {
        err << "internal error: listener factory returned null\n";
        return 1;
    }

    listener->SetSequenceEndpoint(loaded.config.qbitd.zmq_sequence);
    if (!listener->Connect(loaded.config.qbitd.zmq_hashblock)) {
        LOG_ERROR("failed to connect ZMQ listener");
        return 1;
    }

    if (!deps.make_rpc) {
        err << "internal error: RPC factory not configured\n";
        return 1;
    }

    std::unique_ptr<Rpc> rpc = deps.make_rpc(RpcClientOptions{
        .host = loaded.config.qbitd.rpc_host,
        .port = loaded.config.qbitd.rpc_port,
        .cookie_file = loaded.config.qbitd.rpc_cookiefile,
        .timeout = std::chrono::milliseconds{loaded.config.qbitd.rpc_timeout_ms},
    });
    if (!rpc) {
        err << "internal error: RPC factory returned null\n";
        return 1;
    }

    if (!rpc->Probe()) {
        LOG_ERROR("RPC probe failed");
        return 1;
    }

    if (!deps.make_transport) {
        err << "internal error: transport factory not configured\n";
        return 1;
    }

    std::unique_ptr<Transport> transport = deps.make_transport();
    if (!transport) {
        err << "internal error: transport factory returned null\n";
        return 1;
    }

    std::string bind_error;
    if (!transport->OpenAndBind("", loaded.config.local.bind_port, &bind_error)) {
        LOG_ERROR("failed to bind UDP transport: " + bind_error);
        return 1;
    }

    SystemClock clock{};
    PeerManager peer_manager(
        loaded.config.peers,
        clock,
        [](const std::string& host,
           std::uint16_t port,
           sockaddr_storage* out_addr,
           socklen_t* out_len,
           std::string* error) {
            return UdpTransport::ResolveEndpoint(host, port, out_addr, out_len, error);
        });

    RelayEngine relay_engine(clock);
    TransportPacketSink sink(*transport);
    RpcSubmitterAdapter submitter(*rpc);

    LOG_INFO("startup complete; entering relay loop");

    auto next_stats_log = clock.Now() + std::chrono::seconds(60);
    LogRateLimiter udp_parse_error_logs{std::chrono::seconds{60}};

    peer_manager.Tick(sink);

    while (!deps.should_shutdown()) {
        for (std::size_t i = 0; i < 128; ++i) {
            const RecvPacketResult received = transport->ReceivePacket();
            if (received.status == RecvStatus::kWouldBlock) {
                break;
            }

            if (received.status == RecvStatus::kSocketError) {
                LOG_WARN("udp receive error: " + received.error);
                break;
            }

            if (received.status == RecvStatus::kParseError) {
                if (const auto log_message = udp_parse_error_logs.Record(clock.Now(), "udp parse error: " + received.error)) {
                    LOG_WARN(*log_message);
                }
                continue;
            }

            InboundPeerInfo inbound_peer{};
            if (!peer_manager.HandleInbound(received.packet, received.peer, received.peer_len, sink, &inbound_peer)) {
                continue;
            }

            if (received.packet.msg_type == MessageType::kBlockHeader) {
                BlockHeaderPayload header{};
                if (DecodeBlockHeaderPayload(received.packet.payload, header)) {
                    relay_engine.OnBlockHeader(inbound_peer, header, submitter);
                }
                continue;
            }

            if (received.packet.msg_type == MessageType::kBlockChunk) {
                BlockChunkPayload chunk{};
                if (DecodeBlockChunkPayload(received.packet.payload, chunk)) {
                    relay_engine.OnBlockChunk(inbound_peer, chunk, submitter);
                }
            }
        }

        relay_engine.PumpOutbound(sink, peer_manager);
        peer_manager.Tick(sink);

        const auto hash = listener->NextHash(std::chrono::milliseconds{10});
        if (hash.has_value()) {
            const std::string hash_hex = HashToHex(*hash);
            const auto block = rpc->GetBlock(hash_hex);
            if (!block.has_value()) {
                LOG_WARN("failed to fetch block for hash " + hash_hex);
            } else {
                relay_engine.OnNewBlock(hash_hex, *block);
            }
        }

        const auto now = clock.Now();
        if (now >= next_stats_log) {
            const RelayStats& stats = relay_engine.stats();
            const PeerManagerStats peer_stats = peer_manager.StatsSnapshot();
            LOG_INFO("stats"
                     + PeerStatsLogFields(peer_stats)
                     + " blocks_out=" + std::to_string(stats.blocks_relayed_out)
                     + " blocks_in=" + std::to_string(stats.blocks_received_in)
                     + " known=" + std::to_string(stats.blocks_already_known)
                     + " chunks_sent=" + std::to_string(stats.chunks_sent)
                     + " chunks_recv=" + std::to_string(stats.chunks_received)
                     + " submit_ok=" + std::to_string(stats.submit_successes)
                     + " submit_fail=" + std::to_string(stats.submit_failures)
                     + " inbound_rejected=" + std::to_string(stats.inbound_rejected)
                     + " inbound_evicted=" + std::to_string(stats.inbound_evictions)
                     + " udp_parse_errors=" + std::to_string(udp_parse_error_logs.total())
                     + " udp_parse_error_logs_suppressed=" + std::to_string(udp_parse_error_logs.suppressed()));
            next_stats_log = now + std::chrono::seconds(60);
        }
    }

    peer_manager.SendDisconnectAll(sink);

    const RelayStats& stats = relay_engine.stats();
    const PeerManagerStats peer_stats = peer_manager.StatsSnapshot();
    LOG_INFO("shutdown stats"
             + PeerStatsLogFields(peer_stats)
             + " blocks_out=" + std::to_string(stats.blocks_relayed_out)
             + " blocks_in=" + std::to_string(stats.blocks_received_in)
             + " known=" + std::to_string(stats.blocks_already_known)
             + " chunks_sent=" + std::to_string(stats.chunks_sent)
             + " chunks_recv=" + std::to_string(stats.chunks_received)
             + " submit_ok=" + std::to_string(stats.submit_successes)
             + " submit_fail=" + std::to_string(stats.submit_failures)
             + " inbound_rejected=" + std::to_string(stats.inbound_rejected)
             + " inbound_evicted=" + std::to_string(stats.inbound_evictions)
             + " udp_parse_errors=" + std::to_string(udp_parse_error_logs.total())
             + " udp_parse_error_logs_suppressed=" + std::to_string(udp_parse_error_logs.suppressed()));

    LOG_INFO("received shutdown signal, exiting");
    return 0;
}

} // namespace photon::app
