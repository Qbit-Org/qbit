#include <clock.h>
#include <fec.h>
#include <protocol.h>
#include <relay_engine.h>
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
    // When set, the response is written in eight slices with this pause before each.
    int slice_delay_ms{0};
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

            if (step.slice_delay_ms > 0) {
                const std::size_t slice = (step.response.size() + 7) / 8;
                for (std::size_t offset = 0; offset < step.response.size(); offset += slice) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(step.slice_delay_ms));
                    SendAll(client_fd, step.response.substr(offset, slice));
                }
            } else {
                SendAll(client_fd, step.response);
            }
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
    Require(client.SubmitBlock(block_data) == photon::SubmitOutcome::kAccepted,
            "SubmitBlock should succeed on null result + null error");
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

photon::RpcClient MakeClient(std::uint16_t port, const std::filesystem::path& cookie_path, std::chrono::milliseconds timeout)
{
    return photon::RpcClient(photon::RpcClientOptions{
        .host = "127.0.0.1",
        .port = port,
        .cookie_file = cookie_path.string(),
        .timeout = timeout,
    });
}

std::string JsonResult(const std::string& result_json)
{
    return HttpResponse(200, R"({"result":)" + result_json + R"(,"error":null,"id":"x"})");
}

std::string JsonError(int code, const std::string& message)
{
    return HttpResponse(500, R"({"result":null,"error":{"code":)" + std::to_string(code) + R"(,"message":")" + message + R"("},"id":"x"})");
}

std::string HashHex(char digit)
{
    return std::string(64, digit);
}

// 64-digit chain work with `tail` as its low digits.
std::string ChainWork(const std::string& tail)
{
    return std::string(64 - tail.size(), '0') + tail;
}

std::string HeaderReply(const std::string& hash, int confirmations, int height, const std::string& chainwork)
{
    return JsonResult(R"({"hash":")" + hash + R"(","confirmations":)" + std::to_string(confirmations)
                      + R"(,"height":)" + std::to_string(height) + R"(,"version":536870912,"bits":"1d00ffff","chainwork":")"
                      + chainwork + R"(","nTx":1})");
}

std::string RequestMethod(const std::string& request)
{
    const std::string key = "\"method\":\"";
    const auto start = request.find(key);
    if (start == std::string::npos) {
        return {};
    }
    const auto end = request.find('"', start + key.size());
    return request.substr(start + key.size(), end - start - key.size());
}

void RequireMethods(const MockHttpServer& server, const std::vector<std::string>& expected)
{
    const auto requests = server.requests();
    Require(requests.size() == expected.size(),
            "expected " + std::to_string(expected.size()) + " RPC calls, saw " + std::to_string(requests.size()));
    for (std::size_t i = 0; i < expected.size(); ++i) {
        Require(RequestMethod(requests[i]) == expected[i], "unexpected RPC call " + RequestMethod(requests[i]));
    }
}

void TestSubmitBlockOutcomes()
{
    struct Case {
        std::string response;
        int delay_ms;
        photon::SubmitOutcome expected;
    };
    const std::vector<Case> cases{
        {JsonResult("null"), 0, photon::SubmitOutcome::kAccepted},
        {JsonResult(R"("duplicate")"), 0, photon::SubmitOutcome::kDuplicate},
        {JsonResult(R"("inconclusive")"), 0, photon::SubmitOutcome::kInconclusive},
        {JsonResult(R"("high-hash")"), 0, photon::SubmitOutcome::kRejected},
        {JsonError(-22, "Block decode failed"), 0, photon::SubmitOutcome::kRejected},
        {JsonError(-28, "Loading block index..."), 0, photon::SubmitOutcome::kError},
        {JsonError(-25, "system error"), 0, photon::SubmitOutcome::kError},
        {HttpResponse(200, "not json"), 0, photon::SubmitOutcome::kError},
        {JsonResult("null"), 250, photon::SubmitOutcome::kTimeout},
    };

    for (const Case& test_case : cases) {
        const auto cookie_path = WriteTempFile("rpc_cookie_outcome", "__cookie__:outcometoken\n");
        MockHttpServer server({ServerStep{test_case.response, test_case.delay_ms, {}}});
        photon::RpcClient client = MakeClient(server.port(), cookie_path, std::chrono::milliseconds{100});

        const std::vector<std::uint8_t> block_data{0x01, 0x02};
        const photon::SubmitOutcome outcome = client.SubmitBlock(block_data);
        Require(outcome == test_case.expected,
                std::string("submitblock outcome ") + photon::SubmitOutcomeName(outcome) + ", expected "
                    + photon::SubmitOutcomeName(test_case.expected));

        RemoveFile(cookie_path);
        server.Stop();
    }
}

struct ParentCase {
    std::vector<ServerStep> steps;
    photon::ParentCheck expected;
    std::vector<std::string> methods;
};

const std::string kBlockHash = std::string(64, 'd');

void RunParentCase(const std::string& name, const ParentCase& test_case, const std::string& prev, std::uint32_t depth = 6,
                   std::chrono::milliseconds timeout = std::chrono::milliseconds{2000},
                   const std::string& block = kBlockHash)
{
    const auto cookie_path = WriteTempFile("rpc_cookie_parent", "__cookie__:parenttoken\n");
    MockHttpServer server(test_case.steps);
    photon::RpcClient client = MakeClient(server.port(), cookie_path, timeout);

    const photon::ParentCheck result = client.CheckParent(block, prev, depth);
    server.Stop();
    RemoveFile(cookie_path);

    Require(result == test_case.expected, name + ": parent check returned " + photon::ParentCheckName(result)
                                              + ", expected " + photon::ParentCheckName(test_case.expected));
    RequireMethods(server, test_case.methods);
}

ServerStep BlockNotFound()
{
    return ServerStep{JsonError(-5, "Block not found")};
}

void TestCheckParentBestBlock()
{
    const std::string prev = HashHex('a');
    RunParentCase("best block",
                  {{ServerStep{JsonResult("\"" + prev + "\"")}}, photon::ParentCheck::kNearTip, {"getbestblockhash"}},
                  prev);
}

void TestCheckParentBlockAlreadyKnown()
{
    const std::string prev = HashHex('a');
    RunParentCase("block is the best block",
                  {{ServerStep{JsonResult("\"" + kBlockHash + "\"")}}, photon::ParentCheck::kAlreadyKnown, {"getbestblockhash"}},
                  prev);
    // A block the node already has near the tip is recognised before its parent is judged...
    RunParentCase("block on the best chain",
                  {{ServerStep{JsonResult("\"" + HashHex('b') + "\"")}, ServerStep{HeaderReply(kBlockHash, 3, 98, ChainWork("100"))}},
                   photon::ParentCheck::kAlreadyKnown,
                   {"getbestblockhash", "getblockheader"}},
                  prev);
    // ...but one deep in the best chain is as far from the tip as a block whose parent is.
    RunParentCase("block deep in the best chain",
                  {{ServerStep{JsonResult("\"" + HashHex('b') + "\"")}, ServerStep{HeaderReply(kBlockHash, 20, 80, ChainWork("100"))}},
                   photon::ParentCheck::kTooFar,
                   {"getbestblockhash", "getblockheader"}},
                  prev);
}

void TestCheckParentActiveChainDepth()
{
    const std::string prev = HashHex('a');
    const std::string best = HashHex('b');
    const std::vector<std::string> calls{"getbestblockhash", "getblockheader", "getblockheader"};
    // confirmations counts the best block itself: 7 confirmations is 6 blocks below it.
    RunParentCase("depth 6",
                  {{ServerStep{JsonResult("\"" + best + "\"")}, BlockNotFound(), ServerStep{HeaderReply(prev, 7, 94, ChainWork("100"))}},
                   photon::ParentCheck::kNearTip,
                   calls},
                  prev);
    RunParentCase("depth 7",
                  {{ServerStep{JsonResult("\"" + best + "\"")}, BlockNotFound(), ServerStep{HeaderReply(prev, 8, 93, ChainWork("100"))}},
                   photon::ParentCheck::kTooFar,
                   calls},
                  prev);
    RunParentCase("depth 0 limit",
                  {{ServerStep{JsonResult("\"" + best + "\"")}, BlockNotFound(), ServerStep{HeaderReply(prev, 2, 99, ChainWork("100"))}},
                   photon::ParentCheck::kTooFar,
                   calls},
                  prev, 0);
    // A block the node holds only off its best chain is still judged by its parent.
    RunParentCase("block known on another branch",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    ServerStep{HeaderReply(kBlockHash, -1, 95, ChainWork("100"))},
                    ServerStep{HeaderReply(prev, 7, 94, ChainWork("100"))}},
                   photon::ParentCheck::kNearTip,
                   calls},
                  prev);
}

void TestCheckParentUnknown()
{
    const std::string prev = HashHex('a');
    RunParentCase("unknown parent",
                  {{ServerStep{JsonResult("\"" + HashHex('b') + "\"")}, BlockNotFound(), BlockNotFound()},
                   photon::ParentCheck::kUnknown,
                   {"getbestblockhash", "getblockheader", "getblockheader"}},
                  prev);
}

void TestCheckParentCompetingBranchNearTip()
{
    const std::string prev = HashHex('a');
    const std::string best = HashHex('b');
    const std::string anchor = HashHex('c');
    const std::vector<std::string> all_calls{
        "getbestblockhash", "getblockheader", "getblockheader", "getblockheader", "getblockhash", "getblockheader"};

    // The best block's sibling: same height, side branch, chain work above the block six below the tip.
    std::string getblockhash_request;
    RunParentCase("sibling of the best block",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 100, ChainWork("1f4"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))},
                    ServerStep{JsonResult("\"" + anchor + "\""), 0, [&getblockhash_request](const std::string& r) { getblockhash_request = r; }},
                    ServerStep{HeaderReply(anchor, 7, 94, ChainWork("1ef"))}},
                   photon::ParentCheck::kNearTip,
                   all_calls},
                  prev);
    Require(getblockhash_request.find("\"params\":[94]") != std::string::npos, "anchor should be six blocks below the best block");

    // A competing branch tip six blocks down with exactly the anchor's chain work still qualifies.
    RunParentCase("competing branch at the depth limit",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 94, ChainWork("1ef"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))},
                    ServerStep{JsonResult("\"" + anchor + "\"")},
                    ServerStep{HeaderReply(anchor, 7, 94, ChainWork("1ef"))}},
                   photon::ParentCheck::kNearTip,
                   all_calls},
                  prev);

    // Same heights, but the branch carries less work than the best chain six blocks down.
    RunParentCase("low-work branch",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 99, ChainWork("1ee"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))},
                    ServerStep{JsonResult("\"" + anchor + "\"")},
                    ServerStep{HeaderReply(anchor, 7, 94, ChainWork("1ef"))}},
                   photon::ParentCheck::kTooFar,
                   all_calls},
                  prev);

    // A branch block far below the best block is refused before the chain-work lookup.
    RunParentCase("branch far below the tip",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 93, ChainWork("1e0"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))}},
                   photon::ParentCheck::kTooFar,
                   {"getbestblockhash", "getblockheader", "getblockheader", "getblockheader"}},
                  prev);
}

void TestCheckParentNodeBehind()
{
    const std::string prev = HashHex('a');
    const std::string best = HashHex('b');
    // The node knows the parent only as a header above its best block (it is still syncing).
    RunParentCase("parent above the best block",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 105, ChainWork("2f4"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))}},
                   photon::ParentCheck::kNodeBehind,
                   {"getbestblockhash", "getblockheader", "getblockheader", "getblockheader"}},
                  prev);
    // A branch with more work than the best block, even below it in height.
    RunParentCase("lower branch with more work",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 98, ChainWork("2f4"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))}},
                   photon::ParentCheck::kNodeBehind,
                   {"getbestblockhash", "getblockheader", "getblockheader", "getblockheader"}},
                  prev);
    // A longer branch with less work than the best chain is judged by its chain work instead.
    RunParentCase("longer low-work branch",
                  {{ServerStep{JsonResult("\"" + best + "\"")},
                    BlockNotFound(),
                    ServerStep{HeaderReply(prev, -1, 105, ChainWork("040"))},
                    ServerStep{HeaderReply(best, 1, 100, ChainWork("1f5"))},
                    ServerStep{JsonResult("\"" + HashHex('c') + "\"")},
                    ServerStep{HeaderReply(HashHex('c'), 7, 94, ChainWork("1ef"))}},
                   photon::ParentCheck::kTooFar,
                   {"getbestblockhash", "getblockheader", "getblockheader", "getblockheader", "getblockhash", "getblockheader"}},
                  prev);
}

void TestCheckParentUnavailable()
{
    const std::string prev = HashHex('a');
    const std::string best = HashHex('b');

    RunParentCase("no answer",
                  {{ServerStep{JsonResult("\"" + best + "\""), 300, {}}}, photon::ParentCheck::kUnavailable, {"getbestblockhash"}},
                  prev, 6, std::chrono::milliseconds{100});
    RunParentCase("node warming up",
                  {{ServerStep{JsonResult("\"" + best + "\"")}, ServerStep{JsonError(-28, "Loading block index...")}},
                   photon::ParentCheck::kUnavailable,
                   {"getbestblockhash", "getblockheader"}},
                  prev);
    RunParentCase("malformed header reply",
                  {{ServerStep{JsonResult("\"" + best + "\"")}, BlockNotFound(), ServerStep{HeaderReply(prev, 3, 98, "zz")}},
                   photon::ParentCheck::kUnavailable,
                   {"getbestblockhash", "getblockheader", "getblockheader"}},
                  prev);
    RunParentCase("malformed best block hash",
                  {{ServerStep{JsonResult("\"1234\"")}}, photon::ParentCheck::kUnavailable, {"getbestblockhash"}},
                  prev);
    RunParentCase("malformed input", {{}, photon::ParentCheck::kUnavailable, {}}, "not-a-hash");
    RunParentCase("malformed block hash", {{}, photon::ParentCheck::kUnavailable, {}}, prev, 6, std::chrono::milliseconds{2000}, "xyz");
}

void TestCheckParentSharesOneDeadline()
{
    const std::string prev = HashHex('a');
    const std::string best = HashHex('b');
    const auto cookie_path = WriteTempFile("rpc_cookie_deadline", "__cookie__:deadlinetoken\n");
    // The first reply arrives in time; the second would arrive after the check's single deadline,
    // so the check gives up at the deadline instead of waiting another full timeout.
    MockHttpServer server({ServerStep{JsonResult("\"" + best + "\""), 500, {}}, ServerStep{JsonError(-5, "Block not found"), 1500, {}}});
    photon::RpcClient client = MakeClient(server.port(), cookie_path, std::chrono::milliseconds{1000});

    const auto start = std::chrono::steady_clock::now();
    const photon::ParentCheck result = client.CheckParent(kBlockHash, prev, 6);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    server.Stop();
    RemoveFile(cookie_path);

    Require(result == photon::ParentCheck::kUnavailable, "check past its deadline should be unavailable");
    Require(elapsed < std::chrono::milliseconds{1400}, "check should end at its single deadline");
    RequireMethods(server, {"getbestblockhash", "getblockheader"});
}

void TestRpcDeadlineBoundsWholeCall()
{
    const auto cookie_path = WriteTempFile("rpc_cookie_trickle", "__cookie__:trickletoken\n");
    // Each slice of the reply arrives well within the socket timeout, but the whole reply does not
    // arrive within the call's deadline.
    MockHttpServer server({ServerStep{JsonResult(R"("ok")"), 0, {}, 100}});
    photon::RpcClient client = MakeClient(server.port(), cookie_path, std::chrono::milliseconds{300});

    const auto start = std::chrono::steady_clock::now();
    const photon::SubmitOutcome outcome = client.SubmitBlock(std::vector<std::uint8_t>{0x01});
    const auto elapsed = std::chrono::steady_clock::now() - start;
    server.Stop();
    RemoveFile(cookie_path);

    Require(outcome == photon::SubmitOutcome::kTimeout, "late reply should count as a timeout");
    Require(elapsed < std::chrono::milliseconds{650}, "call should end at its deadline");
}

class RpcBlockSubmitter final : public photon::BlockSubmitter {
public:
    explicit RpcBlockSubmitter(photon::RpcClient& client)
        : m_client(client)
    {
    }

    photon::ParentCheck CheckParent(const std::string& block_hash_hex,
                                    const std::string& prev_hash_hex,
                                    std::uint32_t max_depth) override
    {
        return m_client.CheckParent(block_hash_hex, prev_hash_hex, max_depth);
    }

    photon::SubmitOutcome SubmitBlock(std::span<const std::uint8_t> block_data) override
    {
        return m_client.SubmitBlock(block_data);
    }

private:
    photon::RpcClient& m_client;
};

// Relays one block whose parent is `prev_display_hex` through a RelayEngine backed by a real
// RpcClient talking to the scripted node.
photon::RelayStats RelayBlockThroughNode(const std::string& prev_display_hex,
                                         std::vector<ServerStep> steps,
                                         std::vector<std::uint8_t>& block,
                                         std::vector<std::string>& requests)
{
    block.assign(300, 0);
    for (std::size_t i = 0; i < block.size(); ++i) {
        block[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    for (std::size_t i = 0; i < 32; ++i) {
        const std::string byte_hex = prev_display_hex.substr((31 - i) * 2, 2);
        block[4 + i] = static_cast<std::uint8_t>(std::stoul(byte_hex, nullptr, 16));
    }
    const auto summary = photon::ReadBlockHeaderSummary(block);
    Require(summary.has_value() && summary->prev_hash_hex == prev_display_hex, "test block parent mismatch");
    const std::uint64_t prefix = photon::HashPrefixFromHex(summary->hash_hex);

    const auto cookie_path = WriteTempFile("rpc_cookie_relay", "__cookie__:relaytoken\n");
    MockHttpServer server(std::move(steps));
    photon::RpcClient client = MakeClient(server.port(), cookie_path, std::chrono::milliseconds{2000});
    RpcBlockSubmitter submitter(client);

    photon::MockClock clock{};
    photon::RelayEngine engine(clock);
    photon::fec::Encoder encoder(photon::fec::Parameters::FromDataChunkCount(2));
    const photon::fec::EncodedBlock encoded = encoder.Encode(block);

    photon::BlockHeaderPayload header{};
    header.block_hash_prefix = prefix;
    header.original_size = block.size();
    header.data_chunks = encoded.params.data_chunks;
    header.coding_group_count = encoded.coding_group_count;
    engine.OnBlockHeader(header, submitter);
    for (std::size_t i = 0; i < 2; ++i) {
        photon::BlockChunkPayload chunk{};
        chunk.block_hash_prefix = prefix;
        chunk.coding_group_id = encoded.chunks[i].coding_group_id;
        chunk.chunk_id = encoded.chunks[i].chunk_id;
        chunk.data_len = static_cast<std::uint16_t>(photon::fec::FEC_CHUNK_SIZE);
        chunk.chunk_data = encoded.chunks[i].bytes;
        engine.OnBlockChunk(chunk, submitter);
    }

    server.Stop();
    RemoveFile(cookie_path);
    requests = server.requests();
    return engine.stats();
}

void TestRelaySubmitsChildOfCompetingTip()
{
    const std::string sibling = HashHex('5');
    const std::string best = HashHex('6');
    const std::string anchor = HashHex('7');
    std::vector<std::uint8_t> block;
    std::vector<std::string> requests;
    const photon::RelayStats stats = RelayBlockThroughNode(
        sibling,
        {ServerStep{JsonResult("\"" + best + "\"")},
         ServerStep{JsonError(-5, "Block not found")},
         ServerStep{HeaderReply(sibling, -1, 100, ChainWork("1f4"))},
         ServerStep{HeaderReply(best, 1, 100, ChainWork("1f4"))},
         ServerStep{JsonResult("\"" + anchor + "\"")},
         ServerStep{HeaderReply(anchor, 7, 94, ChainWork("1ee"))},
         ServerStep{JsonResult("null")}},
        block,
        requests);

    Require(requests.size() == 7 && RequestMethod(requests.back()) == "submitblock", "block should reach submitblock");
    std::string block_hex;
    for (const std::uint8_t byte : block) {
        static constexpr char kHex[] = "0123456789abcdef";
        block_hex.push_back(kHex[byte >> 4]);
        block_hex.push_back(kHex[byte & 0x0F]);
    }
    Require(requests.back().find(block_hex) != std::string::npos, "submitted bytes should be the relayed block");
    Require(stats.submit_successes == 1, "block should be counted as accepted");
}

void TestRelayDropsBlockOnLowWorkBranch()
{
    const std::string branch = HashHex('5');
    const std::string best = HashHex('6');
    const std::string anchor = HashHex('7');
    std::vector<std::uint8_t> block;
    std::vector<std::string> requests;
    const photon::RelayStats stats = RelayBlockThroughNode(
        branch,
        {ServerStep{JsonResult("\"" + best + "\"")},
         ServerStep{JsonError(-5, "Block not found")},
         ServerStep{HeaderReply(branch, -1, 99, ChainWork("040"))},
         ServerStep{HeaderReply(best, 1, 100, ChainWork("1f4"))},
         ServerStep{JsonResult("\"" + anchor + "\"")},
         ServerStep{HeaderReply(anchor, 7, 94, ChainWork("1ee"))},
         ServerStep{JsonResult("null")}},
        block,
        requests);

    Require(requests.size() == 6, "block on a low-work branch must not reach submitblock");
    Require(stats.blocks_parent_rejected == 1 && stats.submit_successes == 0, "block should be counted as dropped");
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
        {"submitblock_outcomes", TestSubmitBlockOutcomes},
        {"check_parent_best_block", TestCheckParentBestBlock},
        {"check_parent_block_already_known", TestCheckParentBlockAlreadyKnown},
        {"check_parent_node_behind", TestCheckParentNodeBehind},
        {"rpc_deadline_bounds_whole_call", TestRpcDeadlineBoundsWholeCall},
        {"check_parent_active_chain_depth", TestCheckParentActiveChainDepth},
        {"check_parent_unknown", TestCheckParentUnknown},
        {"check_parent_competing_branch_near_tip", TestCheckParentCompetingBranchNearTip},
        {"check_parent_unavailable", TestCheckParentUnavailable},
        {"check_parent_shares_one_deadline", TestCheckParentSharesOneDeadline},
        {"relay_submits_child_of_competing_tip", TestRelaySubmitsChildOfCompetingTip},
        {"relay_drops_block_on_low_work_branch", TestRelayDropsBlockOnLowWorkBranch},
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
