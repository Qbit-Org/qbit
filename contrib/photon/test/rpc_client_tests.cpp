#include <rpc_client.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

void Require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string Base64Encode(std::string_view input)
{
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 2 < input.size()) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16)
            | (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8)
            | static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2]));

        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
        out.push_back(kAlphabet[chunk & 0x3F]);
        i += 3;
    }

    const std::size_t tail = input.size() - i;
    if (tail == 1) {
        const std::uint32_t chunk = static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16;
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (tail == 2) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16)
            | (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8);
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}

std::filesystem::path WriteTempFile(const std::string& prefix, const std::string& content)
{
    const auto path = std::filesystem::temp_directory_path() /
        (prefix + "_" + std::to_string(::getpid()) + "_" + std::to_string(std::rand()) + ".tmp");

    std::ofstream out(path);
    out << content;
    out.close();

    return path;
}

void RemoveFile(const std::filesystem::path& path)
{
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

std::string HttpResponse(int status, std::string body)
{
    std::string reason = "OK";
    if (status == 401) {
        reason = "Unauthorized";
    }

    return "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n"
        + "Content-Type: application/json\r\n"
        + "Content-Length: " + std::to_string(body.size()) + "\r\n"
        + "Connection: close\r\n\r\n"
        + body;
}

std::optional<std::size_t> ParseContentLength(const std::string& headers)
{
    const std::string needle = "Content-Length:";
    auto pos = headers.find(needle);
    if (pos == std::string::npos) {
        return std::nullopt;
    }

    pos += needle.size();
    while (pos < headers.size() && (headers[pos] == ' ' || headers[pos] == '\t')) {
        ++pos;
    }

    std::size_t end = pos;
    while (end < headers.size() && std::isdigit(static_cast<unsigned char>(headers[end]))) {
        ++end;
    }

    if (end == pos) {
        return std::nullopt;
    }

    return static_cast<std::size_t>(std::stoul(headers.substr(pos, end - pos)));
}

std::string ReadHttpRequest(int fd)
{
    std::string request;
    char buffer[2048];

    std::size_t body_expected = 0;
    bool have_headers = false;

    while (true) {
        const ssize_t bytes = recv(fd, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            break;
        }

        request.append(buffer, static_cast<std::size_t>(bytes));

        if (!have_headers) {
            const auto header_end = request.find("\r\n\r\n");
            if (header_end == std::string::npos) {
                continue;
            }

            have_headers = true;
            const std::string headers = request.substr(0, header_end + 4);
            const auto content_length = ParseContentLength(headers);
            body_expected = content_length.value_or(0);

            const std::size_t body_have = request.size() - (header_end + 4);
            if (body_have >= body_expected) {
                break;
            }

            continue;
        }

        const auto header_end = request.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            continue;
        }

        const std::size_t body_have = request.size() - (header_end + 4);
        if (body_have >= body_expected) {
            break;
        }
    }

    return request;
}

bool SendAll(int fd, const std::string& response)
{
    std::size_t written = 0;

#if defined(MSG_NOSIGNAL)
    constexpr int kSendFlags = MSG_NOSIGNAL;
#else
    constexpr int kSendFlags = 0;
#endif

    while (written < response.size()) {
        const ssize_t bytes = send(fd, response.data() + written, response.size() - written, kSendFlags);
        if (bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (bytes == 0) {
            return false;
        }
        written += static_cast<std::size_t>(bytes);
    }

    return true;
}

std::string AuthorizationHeader(const std::string& request)
{
    const std::string needle = "Authorization:";
    const auto pos = request.find(needle);
    if (pos == std::string::npos) {
        return {};
    }

    const auto end = request.find("\r\n", pos);
    if (end == std::string::npos) {
        return {};
    }

    return request.substr(pos, end - pos);
}

struct ServerStep {
    std::string response{};
    int delay_ms{0};
    std::function<void(const std::string&)> on_request{};
};

class MockHttpServer {
public:
    explicit MockHttpServer(std::vector<ServerStep> steps)
        : m_steps(std::move(steps))
    {
        m_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_listen_fd < 0) {
            throw std::runtime_error("socket() failed");
        }

        int reuse = 1;
        setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (bind(m_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(m_listen_fd);
            throw std::runtime_error("bind() failed");
        }

        if (listen(m_listen_fd, 16) != 0) {
            close(m_listen_fd);
            throw std::runtime_error("listen() failed");
        }

        sockaddr_in bound{};
        socklen_t bound_len = sizeof(bound);
        if (getsockname(m_listen_fd, reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
            close(m_listen_fd);
            throw std::runtime_error("getsockname() failed");
        }

        m_port = ntohs(bound.sin_port);
        m_thread = std::thread([this] { this->Run(); });
    }

    ~MockHttpServer()
    {
        Stop();
    }

    std::uint16_t port() const
    {
        return m_port;
    }

    std::vector<std::string> requests() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_requests;
    }

    void Stop()
    {
        if (m_stopped.exchange(true)) {
            return;
        }

        if (m_listen_fd >= 0) {
            shutdown(m_listen_fd, SHUT_RDWR);
            close(m_listen_fd);
            m_listen_fd = -1;
        }

        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

private:
    void Run()
    {
        for (std::size_t i = 0; i < m_steps.size(); ++i) {
            if (m_stopped.load()) {
                return;
            }

            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            const int client_fd = accept(m_listen_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
            if (client_fd < 0) {
                return;
            }

#ifdef SO_NOSIGPIPE
            int set = 1;
            setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif

            std::string request = ReadHttpRequest(client_fd);

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_requests.push_back(request);
            }

            const ServerStep& step = m_steps[i];
            if (step.on_request) {
                step.on_request(request);
            }
            if (step.delay_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(step.delay_ms));
            }

            SendAll(client_fd, step.response);
            shutdown(client_fd, SHUT_RDWR);
            close(client_fd);
        }
    }

    std::vector<ServerStep> m_steps;
    mutable std::mutex m_mutex;
    std::vector<std::string> m_requests;
    std::atomic<bool> m_stopped{false};

    int m_listen_fd{-1};
    std::uint16_t m_port{0};
    std::thread m_thread{};
};

void TestCookieParsing()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_valid", "__cookie__:token123\n");

    MockHttpServer server({
        ServerStep{HttpResponse(200, R"({"result":{"chain":"regtest"},"error":null,"id":"x"})")},
    });

    photon::RpcClient client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = cookie_path.string(),
        .timeout = std::chrono::milliseconds{2000},
    });

    Require(client.Probe(), "probe should succeed with valid cookie");

    const auto requests = server.requests();
    Require(requests.size() == 1, "expected one request for valid cookie probe");

    const std::string expected_auth = "Authorization: Basic " + Base64Encode("__cookie__:token123");
    Require(AuthorizationHeader(requests[0]) == expected_auth, "authorization header mismatch for valid cookie");

    RemoveFile(cookie_path);

    photon::RpcClient missing_cookie_client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = "/tmp/does-not-exist-photon.cookie",
        .timeout = std::chrono::milliseconds{200},
    });
    Require(!missing_cookie_client.Probe(), "missing cookie should fail");

    const auto malformed_cookie_path = WriteTempFile("rpc_cookie_bad", "not_a_cookie_format\n");
    photon::RpcClient malformed_cookie_client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = malformed_cookie_path.string(),
        .timeout = std::chrono::milliseconds{200},
    });
    Require(!malformed_cookie_client.Probe(), "malformed cookie should fail");

    RemoveFile(malformed_cookie_path);
    server.Stop();
}

void TestGetBlockDecode()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_block", "__cookie__:blocktoken\n");

    MockHttpServer server({
        ServerStep{HttpResponse(200, R"({"result":"00ffab","error":null,"id":"x"})")},
    });

    photon::RpcClient client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = cookie_path.string(),
        .timeout = std::chrono::milliseconds{2000},
    });

    const auto block = client.GetBlock("001122");
    Require(block.has_value(), "GetBlock should return bytes");
    Require(block->size() == 3, "decoded byte size mismatch");
    Require((*block)[0] == 0x00 && (*block)[1] == 0xff && (*block)[2] == 0xab, "decoded bytes mismatch");

    RemoveFile(cookie_path);
    server.Stop();
}

void TestUnauthorizedReloadsCookie()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_reload", "__cookie__:oldtoken\n");

    MockHttpServer server({
        ServerStep{
            HttpResponse(401, R"({"result":null,"error":null,"id":"x"})"),
            0,
            [cookie_path](const std::string&) {
                std::ofstream out(cookie_path);
                out << "__cookie__:newtoken\n";
            },
        },
        ServerStep{HttpResponse(200, R"({"result":{"chain":"regtest"},"error":null,"id":"x"})")},
    });

    photon::RpcClient client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = cookie_path.string(),
        .timeout = std::chrono::milliseconds{2000},
    });

    Require(client.Probe(), "probe should succeed after 401 retry");

    const auto requests = server.requests();
    Require(requests.size() == 2, "expected exactly two requests for 401 retry flow");

    const std::string old_auth = "Authorization: Basic " + Base64Encode("__cookie__:oldtoken");
    const std::string new_auth = "Authorization: Basic " + Base64Encode("__cookie__:newtoken");

    Require(AuthorizationHeader(requests[0]) == old_auth, "first request should use old cookie");
    Require(AuthorizationHeader(requests[1]) == new_auth, "second request should use refreshed cookie");

    RemoveFile(cookie_path);
    server.Stop();
}

void TestTimeoutHandling()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_timeout", "__cookie__:slowtoken\n");

    MockHttpServer server({
        ServerStep{
            HttpResponse(200, R"({"result":{"chain":"regtest"},"error":null,"id":"x"})"),
            250,
            {},
        },
    });

    photon::RpcClient client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = cookie_path.string(),
        .timeout = std::chrono::milliseconds{50},
    });

    Require(!client.Probe(), "probe should timeout and fail");

    RemoveFile(cookie_path);
    server.Stop();
}

void TestSubmitBlockSuccess()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_submit", "__cookie__:submittoken\n");

    std::string captured_request;
    MockHttpServer server({
        ServerStep{
            HttpResponse(200, R"({"result":null,"error":null,"id":"x"})"),
            0,
            [&captured_request](const std::string& request) {
                captured_request = request;
            },
        },
    });

    photon::RpcClient client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = cookie_path.string(),
        .timeout = std::chrono::milliseconds{2000},
    });

    const std::vector<std::uint8_t> block_data{0xAA, 0xBB, 0xCC, 0xDD};
    Require(client.SubmitBlock(block_data), "SubmitBlock should succeed on null result + null error");
    Require(captured_request.find("\"method\":\"submitblock\"") != std::string::npos, "submitblock RPC method not present in request");
    Require(captured_request.find("aabbccdd") != std::string::npos, "submitblock payload hex not present in request");

    RemoveFile(cookie_path);
    server.Stop();
}

void TestConnectionClosedDuringRequestHandling()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_closed", "__cookie__:closetoken\n");

    MockHttpServer server({
        ServerStep{
            "",
            0,
            {},
        },
    });

    photon::RpcClient client(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = server.port(),
        .cookie_file = cookie_path.string(),
        .timeout = std::chrono::milliseconds{1000},
    });

    Require(!client.Probe(), "Probe should fail cleanly when peer closes connection before response");

    RemoveFile(cookie_path);
    server.Stop();
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"cookie_parsing", TestCookieParsing},
        {"getblock_decode", TestGetBlockDecode},
        {"unauthorized_cookie_reload", TestUnauthorizedReloadsCookie},
        {"timeout_handling", TestTimeoutHandling},
        {"submitblock_success", TestSubmitBlockSuccess},
        {"connection_closed_during_request", TestConnectionClosedDuringRequestHandling},
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
