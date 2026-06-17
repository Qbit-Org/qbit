#ifndef QBIT_PHOTON_SRC_RPC_CLIENT_H
#define QBIT_PHOTON_SRC_RPC_CLIENT_H

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace photon {

struct RpcClientOptions {
    std::string host{"127.0.0.1"};
    std::uint16_t port{8352};
    std::string cookie_file{};
    std::chrono::milliseconds timeout{std::chrono::milliseconds{5000}};
};

class RpcClient {
public:
    explicit RpcClient(RpcClientOptions options);

    bool Probe();
    std::optional<std::vector<std::uint8_t>> GetBlock(const std::string& hash_hex);
    bool SubmitBlock(std::span<const std::uint8_t> block_data);

private:
    struct HttpResponse {
        int status_code{0};
        std::string body{};
    };

    std::optional<HttpResponse> SendJsonRpc(const std::string& method, const std::string& params_json);
    std::optional<HttpResponse> SendHttpRequest(const std::string& request_body);
    bool LoadCookie();

    RpcClientOptions m_options;
    std::string m_cookie_auth;
    bool m_cookie_loaded{false};
    std::uint64_t m_request_id{0};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_RPC_CLIENT_H
