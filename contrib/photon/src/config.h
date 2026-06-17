#ifndef QBIT_PHOTON_SRC_CONFIG_H
#define QBIT_PHOTON_SRC_CONFIG_H

#include <logging.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace photon {

struct PeerConfig {
    std::string name{};
    std::string host{};
    std::uint16_t port{0};
    std::array<std::uint8_t, 32> hmac_key{};
};

struct LocalConfig {
    std::uint16_t bind_port{8144};
    logging::LogLevel log_level{logging::LogLevel::kInfo};
};

struct QbitdConfig {
    std::string zmq_hashblock{};
    std::optional<std::string> zmq_sequence{};
    std::string rpc_host{"127.0.0.1"};
    std::uint16_t rpc_port{8352};
    std::string rpc_cookiefile{};
    std::uint32_t rpc_timeout_ms{5000};
};

struct Config {
    LocalConfig local{};
    QbitdConfig qbitd{};
    std::vector<PeerConfig> peers{};
};

struct ConfigLoadResult {
    Config config{};
    std::string error{};
    bool ok{false};
};

ConfigLoadResult LoadConfig(const std::string& path);

} // namespace photon

#endif // QBIT_PHOTON_SRC_CONFIG_H
