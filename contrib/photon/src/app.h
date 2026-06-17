#ifndef QBIT_PHOTON_SRC_APP_H
#define QBIT_PHOTON_SRC_APP_H

#include <config.h>
#include <rpc_client.h>
#include <udp_transport.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace photon::app {

class Listener {
public:
    virtual ~Listener() = default;

    virtual void SetSequenceEndpoint(std::optional<std::string> endpoint) = 0;
    virtual bool Connect(const std::string& endpoint) = 0;
    virtual std::optional<std::array<std::uint8_t, 32>> NextHash(std::chrono::milliseconds timeout) = 0;
};

class Rpc {
public:
    virtual ~Rpc() = default;

    virtual bool Probe() = 0;
    virtual std::optional<std::vector<std::uint8_t>> GetBlock(const std::string& hash_hex) = 0;
    virtual bool SubmitBlock(std::span<const std::uint8_t> block_data) = 0;
};

class Transport {
public:
    virtual ~Transport() = default;

    virtual bool OpenAndBind(const std::string& bind_host, std::uint16_t bind_port, std::string* error) = 0;
    virtual bool SendPacket(const Packet& packet,
                            const sockaddr_storage& addr,
                            socklen_t addr_len,
                            std::string* error) = 0;
    virtual RecvPacketResult ReceivePacket() = 0;
};

struct Deps {
    std::function<ConfigLoadResult(const std::string& path)> load_config{};
    std::function<void(logging::LogLevel)> set_log_level{};
    std::function<std::unique_ptr<Listener>()> make_listener{};
    std::function<std::unique_ptr<Rpc>(const RpcClientOptions&)> make_rpc{};
    std::function<std::unique_ptr<Transport>()> make_transport{};
    std::function<bool()> should_shutdown{};
    std::function<void()> install_signal_handlers{};
};

std::string HashToHex(const std::array<std::uint8_t, 32>& hash);
Deps MakeDefaultDeps();
int Run(int argc, char** argv, std::ostream& out, std::ostream& err, Deps deps);

} // namespace photon::app

#endif // QBIT_PHOTON_SRC_APP_H
