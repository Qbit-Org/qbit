// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <i2p.h>
#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <sync.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/readwritefile.h>
#include <util/string.h>
#include <util/threadinterrupt.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef HAVE_SOCKADDR_UN
#include <sys/un.h>
#endif

using namespace std::chrono_literals;

/// Save the log level and the value of CreateSock and restore them when the test ends. Forget the
/// routers' rejections of the post-quantum leaseset type before and after.
class EnvTestingSetup : public BasicTestingSetup
{
public:
    explicit EnvTestingSetup(const ChainType chainType = ChainType::MAIN,
                             TestOpts opts = {})
        : BasicTestingSetup{chainType, opts},
          m_prev_log_level{LogInstance().LogLevel()},
          m_create_sock_orig{CreateSock}
    {
        LogInstance().SetLogLevel(BCLog::Level::Trace);
        i2p::sam::ResetRouterHybridStateForTest();
    }

    ~EnvTestingSetup()
    {
        i2p::sam::ResetRouterHybridStateForTest();
        CreateSock = m_create_sock_orig;
        LogInstance().SetLogLevel(m_prev_log_level);
    }

private:
    const BCLog::Level m_prev_log_level;
    const decltype(CreateSock) m_create_sock_orig;
};

namespace {
/** A valid I2P private key (destination and its keys), in I2P-style Base64. */
const std::string TEST_PRIV{"WnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqLE4SD-yjT48UNI7qiTUfIPiDitCoiTTz2cr4QGfw89rBQAEAAcAAOvuCIKTyv5f~1QgGq7XQl-IqBULTB5WzB3gw5yGPtd1p0AeoADrq1ccZggLPQ4ZLUsGK-HVw373rcTfvxrcuwenqVjiN4tbbYLWtP7xXGWj6fM6HyORhU63GphrjEePpMUHDHXd3o7pWGM-ieVVQSK~1MzF9P93pQWI3Do52EeNAayz4HbpPjNhVBzG1hUEFwznfPmUZBPuaOR4-uBm1NEWEuONlNOCctE4-U0Ukh94z-Qb55U5vXjR5G4apmBblr68t6Wm1TKlzpgFHzSqLryh3stWqrOKY1H0z9eZ2z1EkHFOpD5LyF6nf51e-lV7HLMl44TYzoEHK8RRVodtLcW9lacVdBpv~tOzlZERIiDziZODPETENZMz5oy9DQ7UUw=="};

/** The start of the warning about a router that rejects the post-quantum leaseset type. */
const std::string HYBRID_WARNING{"I2P: the router rejected leaseSetEncType=6,4"};

/** The full warning, for a rejection with `result`. */
std::string HybridWarning(const std::string& result)
{
    return strprintf("I2P: the router rejected leaseSetEncType=6,4 (RESULT=%s) and accepted 4,0, so this session has "
                     "no post-quantum leaseset. Java I2P older than 2.10.0 does this; upgrade the router to get it.",
                     result);
}

/** The reply of Java I2P 2.9.0, which lacks the post-quantum leaseset type, to a request for it. */
const std::string JAVA_I2P_2_9_0_REJECTION{"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Error creating I2PSocketManager: "
                                           "[SAM TCP Client(CLOSED)]: Failed to build tunnels - Disconnected from router "
                                           "while waiting for tunnels: Unsupported crypto type: 6\""};

/** Its MESSAGE=, as logged. */
const std::string JAVA_I2P_2_9_0_MESSAGE_LOGGED{"Error creating I2PSocketManager: SAM TCP Client(CLOSED): Failed to build tunnels - "
                                                "Disconnected from router while waiting for tunnels: Unsupported crypto type: 6"};

/** A rejection like a passing router error: it does not name the encryption type. */
const std::string TUNNEL_BUILD_FAILURE{"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Failed to build tunnels\""};

/** Part of the info line about a session that uses 4,0 after a rejection that does not name the encryption type. */
const std::string UNNAMED_REJECTION{"which does not name the encryption type"};

/** The full info line, for transient session `session_id` through `router`. */
std::string UnnamedRejectionInfo(const Proxy& router, const std::string& session_id, const std::string& result, const std::string& message)
{
    return strprintf("Transient SAM session %s uses leaseSetEncType=4,0 because %s rejected 6,4 with RESULT=%s MESSAGE=\"%s\", "
                     "which does not name the encryption type; the next session asks for 6,4 again",
                     session_id, router.ToString(), result, message);
}

/** Errors when creating a session runs out of time, depending on the step it was at. */
const std::vector<std::string> TIMEOUT_ERRORS{"Receive timeout", "Timed out during", "Timed out connecting to"};

void SetSockError(int err)
{
#ifdef WIN32
    WSASetLastError(err);
#else
    errno = err;
#endif
}

#ifdef WIN32
constexpr int SOCK_ERROR_IN_PROGRESS{WSAEWOULDBLOCK};
constexpr int SOCK_ERROR_RESET{WSAECONNRESET};
#else
constexpr int SOCK_ERROR_IN_PROGRESS{EINPROGRESS};
constexpr int SOCK_ERROR_RESET{ECONNRESET};
#endif

/**
 * Recording mock of SAM routers. Every socket from `NewSock()` is one connection. The router
 * it connects to, named like `Proxy::ToString()`, answers each request as its script says.
 * Every request is recorded.
 */
class MockSamRouters
{
public:
    enum class Action {
        REPLY,     //!< Reply with `line` after `delay`.
        STALL,     //!< Never reply.
        CLOSE,     //!< Close the connection.
        FAIL_SEND, //!< Fail sending the request, as if the connection was reset.
    };

    struct Response {
        Action action{Action::REPLY};
        std::string line{};
        std::chrono::milliseconds delay{0};
    };

    /** Answers `request` received on the router's connection number `conn` (0-based). */
    using Script = std::function<Response(size_t conn, const std::string& request)>;

    struct Router {
        Script script;
        /** Connections (by number) whose connect never completes. */
        std::set<size_t> pending_connects{};
        /** Called with the 1-based number of every wait for a pending connect. */
        std::function<void(size_t)> on_connect_wait{};
    };

    void AddRouter(const std::string& name, Router router) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_routers.insert_or_assign(name, RouterState{.router = std::move(router)});
    }

    std::unique_ptr<Sock> NewSock() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** The requests a router received, per connection. */
    std::vector<std::vector<std::string>> Requests(const std::string& name) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_routers.at(name).requests;
    }

    /**
     * The timeout of every reply a router's connections waited for, per connection. On a
     * connection, the n-th one is for the n-th request.
     */
    std::vector<std::vector<std::chrono::milliseconds>> RecvTimeouts(const std::string& name) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        auto recv_timeouts{m_routers.at(name).recv_timeouts};
        recv_timeouts.resize(m_routers.at(name).requests.size());
        return recv_timeouts;
    }

    /** The timeout of every wait for a pending connect to a router. */
    std::vector<std::chrono::milliseconds> ConnectWaits(const std::string& name) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_routers.at(name).connect_waits;
    }

    size_t OpenSocks() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_socks.size();
    }

    /** The most sockets open at the same time since the last `ResetMaxOpenSocks()`. */
    size_t MaxOpenSocks() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_max_open_socks;
    }

    void ResetMaxOpenSocks() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_max_open_socks = m_socks.size();
    }

private:
    class MockSamSock;

    struct RouterState {
        Router router;
        std::vector<std::vector<std::string>> requests{};
        std::vector<std::vector<std::chrono::milliseconds>> recv_timeouts{};
        std::vector<std::chrono::milliseconds> connect_waits{};
    };

    struct SockState {
        std::string router{};
        size_t conn{0};
        bool connect_pending{false};
        std::string partial_request{};
        std::string inbox{};
        std::chrono::steady_clock::time_point inbox_ready{};
        bool closed{false};
    };

    static bool Readable(const SockState& sock)
    {
        return sock.inbox.empty() ? sock.closed : std::chrono::steady_clock::now() >= sock.inbox_ready;
    }

    void Close(uint64_t id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_socks.erase(id);
    }

    int Connect(uint64_t id, const sockaddr* addr, socklen_t len) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::string name;
        if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
            CService service;
            if (service.SetSockAddr(addr, len)) name = service.ToStringAddrPort();
#ifdef HAVE_SOCKADDR_UN
        } else if (addr->sa_family == AF_UNIX) {
            name = ADDR_PREFIX_UNIX + std::string{reinterpret_cast<const sockaddr_un*>(addr)->sun_path};
#endif
        }
        LOCK(m_mutex);
        const auto router{m_routers.find(name)};
        if (router == m_routers.end()) {
            SetSockError(SOCK_ERROR_RESET);
            return SOCKET_ERROR;
        }
        SockState& sock{m_socks.at(id)};
        sock.router = name;
        sock.conn = router->second.requests.size();
        router->second.requests.emplace_back();
        if (router->second.router.pending_connects.contains(sock.conn)) {
            sock.connect_pending = true;
            SetSockError(SOCK_ERROR_IN_PROGRESS);
            return SOCKET_ERROR;
        }
        return 0;
    }

    ssize_t Send(uint64_t id, const void* data, size_t len) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        SockState& sock{m_socks.at(id)};
        RouterState& router{m_routers.at(sock.router)};
        sock.partial_request.append(static_cast<const char*>(data), len);
        for (auto end{sock.partial_request.find('\n')}; end != std::string::npos; end = sock.partial_request.find('\n')) {
            const std::string request{sock.partial_request.substr(0, end)};
            sock.partial_request.erase(0, end + 1);
            router.requests.at(sock.conn).push_back(request);
            const Response response{router.router.script(sock.conn, request)};
            switch (response.action) {
            case Action::REPLY:
                sock.inbox += response.line + "\n";
                sock.inbox_ready = std::chrono::steady_clock::now() + response.delay;
                break;
            case Action::STALL:
                break;
            case Action::CLOSE:
                sock.closed = true;
                break;
            case Action::FAIL_SEND:
                SetSockError(SOCK_ERROR_RESET);
                return -1;
            }
        }
        return len;
    }

    void RecordRecvTimeout(uint64_t id, std::chrono::milliseconds timeout) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        const SockState& sock{m_socks.at(id)};
        RouterState& router{m_routers.at(sock.router)};
        router.recv_timeouts.resize(router.requests.size());
        router.recv_timeouts.at(sock.conn).push_back(timeout);
    }

    ssize_t Recv(uint64_t id, void* buf, size_t len, int flags) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        SockState& sock{m_socks.at(id)};
        if (!Readable(sock)) {
            SetSockError(WSAEWOULDBLOCK);
            return -1;
        }
        const size_t n{std::min(len, sock.inbox.size())};
        std::copy_n(sock.inbox.begin(), n, static_cast<char*>(buf));
        if ((flags & MSG_PEEK) == 0) sock.inbox.erase(0, n);
        return n;
    }

    bool Wait(uint64_t id, std::chrono::milliseconds timeout, Sock::Event requested, Sock::Event* occurred) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::function<void(size_t)> on_connect_wait;
        size_t wait_number{0};
        std::chrono::steady_clock::duration sleep{std::min<std::chrono::steady_clock::duration>(timeout, 5ms)};
        {
            LOCK(m_mutex);
            const SockState& sock{m_socks.at(id)};
            if (sock.connect_pending) {
                RouterState& router{m_routers.at(sock.router)};
                router.connect_waits.push_back(timeout);
                on_connect_wait = router.router.on_connect_wait;
                wait_number = router.connect_waits.size();
            } else if ((requested & Sock::RECV) && Readable(sock)) {
                if (occurred) *occurred = Sock::RECV;
                return true;
            } else if (requested & Sock::SEND) {
                if (occurred) *occurred = Sock::SEND;
                return true;
            } else if (!sock.inbox.empty()) {
                sleep = std::min(sleep, sock.inbox_ready - std::chrono::steady_clock::now());
            }
        }
        if (on_connect_wait) on_connect_wait(wait_number);
        if (sleep > 0s) std::this_thread::sleep_for(sleep);
        LOCK(m_mutex);
        const SockState& sock{m_socks.at(id)};
        if (occurred) *occurred = !sock.connect_pending && (requested & Sock::RECV) && Readable(sock) ? Sock::RECV : 0;
        return true;
    }

    mutable Mutex m_mutex;
    std::map<std::string, RouterState> m_routers GUARDED_BY(m_mutex);
    std::map<uint64_t, SockState> m_socks GUARDED_BY(m_mutex);
    uint64_t m_next_sock_id GUARDED_BY(m_mutex){0};
    size_t m_max_open_socks GUARDED_BY(m_mutex){0};
};

class MockSamRouters::MockSamSock : public ZeroSock
{
public:
    MockSamSock(MockSamRouters& routers, uint64_t id) : m_routers{routers}, m_id{id} {}
    ~MockSamSock() override { m_routers.Close(m_id); }

    int Connect(const sockaddr* addr, socklen_t len) const override { return m_routers.Connect(m_id, addr, len); }
    ssize_t Send(const void* data, size_t len, int) const override { return m_routers.Send(m_id, data, len); }
    ssize_t Recv(void* buf, size_t len, int flags) const override { return m_routers.Recv(m_id, buf, len, flags); }
    bool Wait(std::chrono::milliseconds timeout, Event requested, Event* occurred = nullptr) const override
    {
        return m_routers.Wait(m_id, timeout, requested, occurred);
    }
    bool IsConnected(std::string&) const override { return true; }

    std::string RecvUntilTerminator(uint8_t terminator,
                                    std::chrono::milliseconds timeout,
                                    CThreadInterrupt& interrupt,
                                    size_t max_data) const override
    {
        m_routers.RecordRecvTimeout(m_id, timeout);
        return Sock::RecvUntilTerminator(terminator, timeout, interrupt, max_data);
    }

    MockSamSock& operator=(Sock&&) override
    {
        assert(false && "Move of Sock into MockSamSock not allowed.");
        return *this;
    }

private:
    MockSamRouters& m_routers;
    const uint64_t m_id;
};

std::unique_ptr<Sock> MockSamRouters::NewSock()
{
    LOCK(m_mutex);
    const uint64_t id{m_next_sock_id++};
    m_socks.emplace(id, SockState{});
    m_max_open_socks = std::max(m_max_open_socks, m_socks.size());
    return std::make_unique<MockSamSock>(*this, id);
}

using Response = MockSamRouters::Response;
using Action = MockSamRouters::Action;

/** The value of `key=` in a SAM request or reply, or "" if it has none. */
std::string Field(const std::string& line, const std::string& key)
{
    for (const auto& token : util::SplitString(line, ' ')) {
        if (token.starts_with(key + "=")) return token.substr(key.size() + 1);
    }
    return "";
}

/** The "SESSION CREATE" requests in `requests`, each with the number of its connection. */
std::vector<std::pair<size_t, std::string>> Creates(const std::vector<std::vector<std::string>>& requests, size_t first_conn = 0)
{
    std::vector<std::pair<size_t, std::string>> creates;
    for (size_t conn{first_conn}; conn < requests.size(); ++conn) {
        for (const auto& request : requests[conn]) {
            if (request.starts_with("SESSION CREATE")) creates.emplace_back(conn, request);
        }
    }
    return creates;
}

size_t CountRequests(const std::vector<std::vector<std::string>>& requests, const std::string& prefix)
{
    size_t count{0};
    for (const auto& conn : requests) {
        count += std::ranges::count_if(conn, [&](const auto& request) { return request.starts_with(prefix); });
    }
    return count;
}

Response CreateOk() { return {.line = "SESSION STATUS RESULT=OK DESTINATION=" + TEST_PRIV}; }

Response RejectHybrid(std::chrono::milliseconds delay = 0ms)
{
    return {.line = JAVA_I2P_2_9_0_REJECTION, .delay = delay};
}

/**
 * A router script. "SESSION CREATE" is answered by `create`, given the requested
 * i2cp.leaseSetEncType; other requests like a working router does, after `delay`.
 */
MockSamRouters::Script RouterScript(std::function<Response(const std::string& enc_types)> create,
                                    std::chrono::milliseconds delay = 0ms)
{
    return [create, delay](size_t, const std::string& request) -> Response {
        if (request.starts_with("HELLO")) return {.line = "HELLO REPLY RESULT=OK VERSION=3.1", .delay = delay};
        if (request.starts_with("DEST GENERATE")) return {.line = "DEST REPLY PRIV=" + TEST_PRIV, .delay = delay};
        if (request.starts_with("SESSION CREATE")) return create(Field(request, "i2cp.leaseSetEncType"));
        if (request.starts_with("STREAM ACCEPT")) return {.line = "STREAM STATUS RESULT=OK", .delay = delay};
        return {.action = Action::STALL};
    };
}

/** A router with the post-quantum leaseset type. */
MockSamRouters::Script Hybrid()
{
    return RouterScript([](const std::string&) { return CreateOk(); });
}

/**
 * A router without the post-quantum leaseset type, like Java I2P older than 2.10.0. It takes
 * `delay` to answer anything but an acceptable "SESSION CREATE".
 */
MockSamRouters::Script NoHybrid(std::chrono::milliseconds delay = 0ms)
{
    return RouterScript([delay](const std::string& enc_types) { return enc_types == "6,4" ? RejectHybrid(delay) : CreateOk(); }, delay);
}

Proxy TestRouter(uint16_t port) { return Proxy{LookupNumeric("127.0.0.1", port)}; }

/** Captures the log lines while alive. */
class LogCapture
{
public:
    LogCapture()
    {
        m_callback = LogInstance().PushBackCallback([this](const std::string& line) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
            LOCK(m_mutex);
            m_lines.push_back(line);
        });
    }
    ~LogCapture() { LogInstance().DeleteCallback(m_callback); }

    /** The number of lines that contain `needle`. */
    size_t Count(std::string_view needle) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return std::ranges::count_if(m_lines, [&](const auto& line) { return line.find(needle) != std::string::npos; });
    }

    /** The latest line that contains `needle`, or "" if there is none. */
    std::string Last(std::string_view needle) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        const auto it{std::ranges::find_if(m_lines | std::views::reverse, [&](const auto& line) { return line.find(needle) != std::string::npos; })};
        return it == (m_lines | std::views::reverse).end() ? "" : *it;
    }

private:
    mutable Mutex m_mutex;
    std::vector<std::string> m_lines GUARDED_BY(m_mutex);
    std::list<std::function<void(const std::string&)>>::iterator m_callback;
};

/** Whether the latest "Couldn't listen" error in `log` contains one of `errors`. */
bool ListenFailedWith(const LogCapture& log, const std::vector<std::string>& errors)
{
    const std::string line{log.Last("Couldn't listen")};
    return std::ranges::any_of(errors, [&](const auto& error) { return line.find(error) != std::string::npos; });
}

/** The "SESSION CREATE" requests in `creates` that ask for `enc_types`. */
size_t CountEncTypes(const std::vector<std::pair<size_t, std::string>>& creates, std::string_view enc_types)
{
    return std::ranges::count_if(creates, [&](const auto& c) { return Field(c.second, "i2cp.leaseSetEncType") == enc_types; });
}

/** Whether the session's next "SESSION CREATE" after connection `first_conn` asked for `enc_types`. */
bool FirstCreateAsks(const MockSamRouters& routers, const Proxy& router, size_t first_conn, std::string_view enc_types)
{
    const auto creates{Creates(routers.Requests(router.ToString()), first_conn)};
    return !creates.empty() && Field(creates[0].second, "i2cp.leaseSetEncType") == enc_types;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(i2p_tests, EnvTestingSetup)

BOOST_AUTO_TEST_CASE(unlimited_recv)
{
    CreateSock = [](int, int, int) {
        return std::make_unique<StaticContentsSock>(std::string(i2p::sam::MAX_MSG_SIZE + 1, 'a'));
    };

    CThreadInterrupt interrupt;
    const std::optional<CService> addr{Lookup("127.0.0.1", 9000, false)};
    const Proxy sam_proxy(addr.value(), /*tor_stream_isolation=*/false);
    i2p::sam::Session session(gArgs.GetDataDirNet() / "test_i2p_private_key", sam_proxy, &interrupt);

    {
        ASSERT_DEBUG_LOG("Creating persistent SAM session");
        ASSERT_DEBUG_LOG("too many bytes without a terminator");

        i2p::Connection conn;
        bool proxy_error;
        BOOST_REQUIRE(!session.Connect(CService{}, conn, proxy_error));
    }
}

BOOST_AUTO_TEST_CASE(listen_ok_accept_fail)
{
    size_t num_sockets{0};
    CreateSock = [&num_sockets](int, int, int) {
        // clang-format off
        ++num_sockets;
        // First socket is the control socket for creating the session.
        if (num_sockets == 1) {
            return std::make_unique<StaticContentsSock>(
                // reply to HELLO
                "HELLO REPLY RESULT=OK VERSION=3.1\n"
                // reply to DEST GENERATE
                "DEST REPLY PUB=WnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqLE4SD-yjT48UNI7qiTUfIPiDitCoiTTz2cr4QGfw89rBQAEAAcAAA== PRIV=WnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqLE4SD-yjT48UNI7qiTUfIPiDitCoiTTz2cr4QGfw89rBQAEAAcAAOvuCIKTyv5f~1QgGq7XQl-IqBULTB5WzB3gw5yGPtd1p0AeoADrq1ccZggLPQ4ZLUsGK-HVw373rcTfvxrcuwenqVjiN4tbbYLWtP7xXGWj6fM6HyORhU63GphrjEePpMUHDHXd3o7pWGM-ieVVQSK~1MzF9P93pQWI3Do52EeNAayz4HbpPjNhVBzG1hUEFwznfPmUZBPuaOR4-uBm1NEWEuONlNOCctE4-U0Ukh94z-Qb55U5vXjR5G4apmBblr68t6Wm1TKlzpgFHzSqLryh3stWqrOKY1H0z9eZ2z1EkHFOpD5LyF6nf51e-lV7HLMl44TYzoEHK8RRVodtLcW9lacVdBpv~tOzlZERIiDziZODPETENZMz5oy9DQ7UUw==\n"
                // reply to SESSION CREATE
                "SESSION STATUS RESULT=OK\n"
                // dummy to avoid reporting EOF on the socket
                "a"
            );
        }
        // Subsequent sockets are for recreating the session or for listening and accepting incoming connections.
        if (num_sockets % 2 == 0) {
            // Replies to Listen() and Accept()
            return std::make_unique<StaticContentsSock>(
                // reply to HELLO
                "HELLO REPLY RESULT=OK VERSION=3.1\n"
                // reply to STREAM ACCEPT
                "STREAM STATUS RESULT=OK\n"
                // continued reply to STREAM ACCEPT, violating the protocol described at
                // https://geti2p.net/en/docs/api/samv3#Accept%20Response
                // should be base64, something like
                // "IchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLiHIVetPG2g6F26s0CkqhQ5k1z1YKA2zwIWSbzUV18YuIchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLiHIVetPG2g6F26s0CkqhQ5k1z1YKA2zwIWSbzUV18YuIchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLiHIVetPG2g6F26s0CkqhQ5k1z1YKA2zwIWSbzUV18YuIchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLlSreVaCuCS5sdb-8ToWULWP7kt~lRPDeUNxQMq3cRSBBQAEAAcAAA==\n"
                "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Session was closed\"\n"
            );
        } else {
            // Another control socket, but without creating a destination (it is cached in the session).
            return std::make_unique<StaticContentsSock>(
                // reply to HELLO
                "HELLO REPLY RESULT=OK VERSION=3.1\n"
                // reply to SESSION CREATE
                "SESSION STATUS RESULT=OK\n"
                // dummy to avoid reporting EOF on the socket
                "a"
            );
        }
        // clang-format on
    };

    CThreadInterrupt interrupt;
    const CService addr{in6_addr(IN6ADDR_LOOPBACK_INIT), /*port=*/7656};
    const Proxy sam_proxy(addr, /*tor_stream_isolation=*/false);
    i2p::sam::Session session(gArgs.GetDataDirNet() / "test_i2p_private_key",
                              sam_proxy,
                              &interrupt);

    i2p::Connection conn;
    for (size_t i = 0; i < 5; ++i) {
        ASSERT_DEBUG_LOG("Creating persistent SAM session");
        ASSERT_DEBUG_LOG("Persistent SAM session" /* ... created */);
        ASSERT_DEBUG_LOG("Error accepting");
        ASSERT_DEBUG_LOG("Destroying SAM session");
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_REQUIRE(!session.Accept(conn));
    }
}

BOOST_AUTO_TEST_CASE(damaged_private_key)
{
    CreateSock = [](int, int, int) {
        return std::make_unique<StaticContentsSock>("HELLO REPLY RESULT=OK VERSION=3.1\n"
                                                    "SESSION STATUS RESULT=OK DESTINATION=\n");
    };

    const auto i2p_private_key_file = m_args.GetDataDirNet() / "test_i2p_private_key_damaged";

    for (const auto& [file_contents, expected_error] : std::vector<std::tuple<std::string, std::string>>{
             {"", "The private key is too short (0 < 387)"},

             {"abcd", "The private key is too short (4 < 387)"},

             {std::string(386, '\0'), "The private key is too short (386 < 387)"},

             {std::string(385, '\0') + '\0' + '\1',
              "Certificate length (1) designates that the private key should be 388 bytes, but it is only "
              "387 bytes"},

             {std::string(385, '\0') + '\0' + '\5' + "abcd",
              "Certificate length (5) designates that the private key should be 392 bytes, but it is only "
              "391 bytes"}}) {
        BOOST_REQUIRE(WriteBinaryFile(i2p_private_key_file, file_contents));

        CThreadInterrupt interrupt;
        const CService addr{in6_addr(IN6ADDR_LOOPBACK_INIT), /*port=*/7656};
        const Proxy sam_proxy{addr, /*tor_stream_isolation=*/false};
        i2p::sam::Session session(i2p_private_key_file, sam_proxy, &interrupt);

        {
            ASSERT_DEBUG_LOG("Creating persistent SAM session");
            ASSERT_DEBUG_LOG(expected_error);

            i2p::Connection conn;
            bool proxy_error;
            BOOST_CHECK(!session.Connect(CService{}, conn, proxy_error));
        }
    }
}

BOOST_AUTO_TEST_CASE(hybrid_create_success)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    LogCapture log;

    for (const bool transient : {false, true}) {
        const Proxy router{TestRouter(transient ? 17002 : 17001)};
        routers.AddRouter(router.ToString(), {.script = Hybrid()});
        CThreadInterrupt interrupt;
        auto session{transient ? std::make_unique<i2p::sam::Session>(router, &interrupt) :
                                 std::make_unique<i2p::sam::Session>(m_args.GetDataDirNet() / "i2p_key_success", router, &interrupt)};

        i2p::Connection conn;
        BOOST_REQUIRE(session->Listen(conn));

        // One connection created the session, the next one listens with it.
        const auto requests{routers.Requests(router.ToString())};
        BOOST_REQUIRE_EQUAL(requests.size(), 2U);
        const auto creates{Creates(requests)};
        BOOST_REQUIRE_EQUAL(creates.size(), 1U);
        BOOST_CHECK_EQUAL(creates[0].first, 0U);
        BOOST_CHECK_EQUAL(Field(creates[0].second, "i2cp.leaseSetEncType"), "6,4");
        BOOST_CHECK_EQUAL(Field(creates[0].second, "DESTINATION"), transient ? "TRANSIENT" : TEST_PRIV);
        BOOST_CHECK_EQUAL(requests[1].back(), strprintf("STREAM ACCEPT ID=%s SILENT=false", Field(creates[0].second, "ID")));
    }
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 0U);
}

BOOST_AUTO_TEST_CASE(hybrid_rejection_retry)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };

    for (const bool transient : {false, true}) {
        const Proxy router{TestRouter(transient ? 17012 : 17011)};
        routers.AddRouter(router.ToString(), {.script = NoHybrid()});
        CThreadInterrupt interrupt;
        auto session{transient ? std::make_unique<i2p::sam::Session>(router, &interrupt) :
                                 std::make_unique<i2p::sam::Session>(m_args.GetDataDirNet() / "i2p_key_retry", router, &interrupt)};

        LogCapture log;
        routers.ResetMaxOpenSocks();
        i2p::Connection conn;
        BOOST_REQUIRE(session->Listen(conn));
        BOOST_CHECK_EQUAL(log.Count("with leaseSetEncType=6,4: RESULT=I2P_ERROR MESSAGE=\"" + JAVA_I2P_2_9_0_MESSAGE_LOGGED + "\", retrying with 4,0"), 1U);
        BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 1U);
        BOOST_CHECK_EQUAL(log.Count(HybridWarning("I2P_ERROR")), 1U);
        BOOST_CHECK_EQUAL(log.Count(UNNAMED_REJECTION), 0U);

        // Rejected, retried, then listening.
        const auto requests{routers.Requests(router.ToString())};
        BOOST_REQUIRE_EQUAL(requests.size(), 3U);
        const auto creates{Creates(requests)};
        BOOST_REQUIRE_EQUAL(creates.size(), 2U);
        BOOST_CHECK_EQUAL(Field(creates[0].second, "i2cp.leaseSetEncType"), "6,4");
        BOOST_CHECK_EQUAL(Field(creates[1].second, "i2cp.leaseSetEncType"), "4,0");
        // The retry uses a fresh connection, HELLO and session id.
        BOOST_CHECK_EQUAL(creates[0].first, 0U);
        BOOST_CHECK_EQUAL(creates[1].first, 1U);
        BOOST_CHECK(requests[1].front().starts_with("HELLO"));
        BOOST_CHECK(Field(creates[0].second, "ID") != Field(creates[1].second, "ID"));
        // The rejected connection is closed before the retry: at most the control socket and
        // the listening one were open at the same time.
        BOOST_CHECK_EQUAL(routers.MaxOpenSocks(), 2U);
        // The persistent destination is generated once and kept for the retry.
        BOOST_CHECK_EQUAL(CountRequests(requests, "DEST GENERATE"), transient ? 0U : 1U);
        BOOST_CHECK_EQUAL(Field(creates[1].second, "DESTINATION"), transient ? "TRANSIENT" : TEST_PRIV);
        BOOST_CHECK_EQUAL(Field(creates[0].second, "DESTINATION"), Field(creates[1].second, "DESTINATION"));
        // The session uses the id of the retried one.
        BOOST_CHECK_EQUAL(requests[2].back(), strprintf("STREAM ACCEPT ID=%s SILENT=false", Field(creates[1].second, "ID")));
    }

    // The warning names the RESULT only if it is one of the SAM protocol's. Whatever the RESULT,
    // the MESSAGE names the encryption type.
    uint16_t port{17013};
    for (const auto& [result, shown] : std::vector<std::pair<std::string, std::string>>{
             {"CANT_REACH_PEER", "CANT_REACH_PEER"},
             {"TIMEOUT", "TIMEOUT"},
             {"NOT_A_SAM_RESULT", "other"},
             {"I2P_ERROR\x07", "other"}}) {
        const Proxy router{TestRouter(port++)};
        routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string& enc_types) {
                                                  return enc_types == "6,4" ? Response{.line = "SESSION STATUS RESULT=" + result + " MESSAGE=\"Unsupported crypto type: 6\""} : CreateOk();
                                              })});
        LogCapture log;
        CThreadInterrupt interrupt;
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK_EQUAL(log.Count(HybridWarning(shown)), 1U);
    }
}

BOOST_AUTO_TEST_CASE(hybrid_rejection_cached)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    const Proxy router{TestRouter(17021)};
    bool accept_legacy{true};
    routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string& enc_types) {
                                              return enc_types == "6,4" || !accept_legacy ? RejectHybrid() : CreateOk();
                                          })});
    // Two sessions in a row in which the router rejects 6,4 like Java I2P 2.9.0, naming the
    // encryption type, and accepts 4,0.
    for (unsigned i{0}; i < i2p::sam::SAM_HYBRID_FALLBACKS_TO_REMEMBER; ++i) {
        const size_t first_conn{routers.Requests(router.ToString()).size()};
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK(FirstCreateAsks(routers, router, first_conn, "6,4"));
    }
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 1U);
    BOOST_CHECK_EQUAL(log.Count("until qbit restarts"), 1U);

    // Later sessions through the same router start with 4,0 and never retry, even when the router
    // rejects 4,0 as well.
    for (const bool legacy_ok : {true, false}) {
        accept_legacy = legacy_ok;
        const size_t first_conn{routers.Requests(router.ToString()).size()};
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_CHECK_EQUAL(session.Listen(conn), legacy_ok);
        const auto creates{Creates(routers.Requests(router.ToString()), first_conn)};
        BOOST_REQUIRE_EQUAL(creates.size(), 1U);
        BOOST_CHECK_EQUAL(Field(creates[0].second, "i2cp.leaseSetEncType"), "4,0");
    }
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 1U);

    // A different router is unaffected.
    std::vector<Proxy> other_routers{TestRouter(17022)};
#ifdef HAVE_SOCKADDR_UN
    other_routers.emplace_back("unix:/tmp/qbit-i2p-tests-sam.sock");
#endif
    for (const auto& other : other_routers) {
        routers.AddRouter(other.ToString(), {.script = Hybrid()});
        i2p::sam::Session session{other, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        const auto creates{Creates(routers.Requests(other.ToString()))};
        BOOST_REQUIRE_EQUAL(creates.size(), 1U);
        BOOST_CHECK_EQUAL(Field(creates[0].second, "i2cp.leaseSetEncType"), "6,4");
    }

    // Sessions created at the same time through one router share one record and warn once. In
    // any order, at least two of them see the router reject 6,4 before it is remembered.
    const Proxy busy_router{TestRouter(17023)};
    routers.AddRouter(busy_router.ToString(), {.script = NoHybrid(/*delay=*/50ms)});
    {
        LogCapture busy_log;
        constexpr int num_sessions{4};
        std::atomic<int> listening{0};
        std::vector<std::thread> threads;
        for (int i{0}; i < num_sessions; ++i) {
            threads.emplace_back([&] {
                i2p::sam::Session session{busy_router, &interrupt};
                i2p::Connection conn;
                if (session.Listen(conn)) ++listening;
            });
        }
        for (auto& thread : threads) thread.join();
        BOOST_CHECK_EQUAL(listening, num_sessions);
        BOOST_CHECK_EQUAL(busy_log.Count(HYBRID_WARNING), 1U);
        BOOST_CHECK_EQUAL(busy_log.Count("until qbit restarts"), 1U);
        BOOST_CHECK_EQUAL(CountEncTypes(Creates(routers.Requests(busy_router.ToString())), "4,0"), size_t{num_sessions});

        const size_t first_conn{routers.Requests(busy_router.ToString()).size()};
        i2p::sam::Session session{busy_router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK(FirstCreateAsks(routers, busy_router, first_conn, "4,0"));
    }
}

BOOST_AUTO_TEST_CASE(hybrid_two_strikes)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    const Proxy router{TestRouter(17081)};
    // The router's answer to 6,4: a rejection, or acceptance if none.
    std::optional<std::string> rejection;
    routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string& enc_types) {
                                              return enc_types == "6,4" && rejection ? Response{.line = *rejection} : CreateOk();
                                          })});
    // Creates a session and returns the leaseset types its first "SESSION CREATE" asked for.
    const auto session_starts_with = [&](std::optional<std::string> reply_to_hybrid) {
        rejection = std::move(reply_to_hybrid);
        const size_t first_conn{routers.Requests(router.ToString()).size()};
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        const auto creates{Creates(routers.Requests(router.ToString()), first_conn)};
        BOOST_REQUIRE(!creates.empty());
        return Field(creates[0].second, "i2cp.leaseSetEncType");
    };

    // A rejection, then a session that gets 6,4: one rejection does not turn 6,4 off.
    BOOST_CHECK_EQUAL(session_starts_with(JAVA_I2P_2_9_0_REJECTION), "6,4");
    BOOST_CHECK_EQUAL(log.Count(HybridWarning("I2P_ERROR")), 1U);
    BOOST_CHECK_EQUAL(session_starts_with(std::nullopt), "6,4");

    // That success started the count anew, so this rejection is only the first in a row.
    BOOST_CHECK_EQUAL(session_starts_with(JAVA_I2P_2_9_0_REJECTION), "6,4");
    BOOST_CHECK_EQUAL(log.Count("until qbit restarts"), 0U);
    // A rejection that does not name the encryption type neither counts nor starts the count anew.
    BOOST_CHECK_EQUAL(session_starts_with(TUNNEL_BUILD_FAILURE), "6,4");
    BOOST_CHECK_EQUAL(log.Count("until qbit restarts"), 0U);
    BOOST_CHECK_EQUAL(log.Count(UNNAMED_REJECTION), 1U);
    // So this is the second in a row: from now on, sessions start with 4,0.
    BOOST_CHECK_EQUAL(session_starts_with(JAVA_I2P_2_9_0_REJECTION), "6,4");
    BOOST_CHECK_EQUAL(log.Count("until qbit restarts"), 1U);
    BOOST_CHECK_EQUAL(session_starts_with(JAVA_I2P_2_9_0_REJECTION), "4,0");
    BOOST_CHECK_EQUAL(session_starts_with(std::nullopt), "4,0");

    // Warned once per router, at the first rejection.
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 1U);
}

BOOST_AUTO_TEST_CASE(hybrid_unnamed_rejection)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;

    // Rejections of 6,4 that do not name the encryption type, and their RESULT= and MESSAGE= as
    // the info line shows them.
    struct Unnamed {
        std::string reply;
        std::string result;
        std::string message;
    };
    uint16_t port{17101};
    for (const auto& c : std::vector<Unnamed>{
             {TUNNEL_BUILD_FAILURE, "I2P_ERROR", "Failed to build tunnels"},
             {"SESSION STATUS RESULT=TIMEOUT", "TIMEOUT", ""},
             {"SESSION STATUS RESULT=CANT_REACH_PEER", "CANT_REACH_PEER", ""},
             {"SESSION STATUS RESULT=I2P_ERROR", "I2P_ERROR", ""},
             // Router text is sanitized and capped.
             {"SESSION STATUS RESULT=NOT_A_SAM_RESULT MESSAGE=\"Tunnel\x07 build failed " + std::string(300, 'x') + "\"",
              "other", "Tunnel build failed " + std::string(179, 'x')},
         }) {
        BOOST_TEST_MESSAGE(c.reply);
        const Proxy router{TestRouter(port++)};
        routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string& enc_types) {
                                                  return enc_types == "6,4" ? Response{.line = c.reply} : CreateOk();
                                              })});
        LogCapture log;

        // Each session is retried with 4,0 and created. After three in a row, the next session
        // still asks for 6,4.
        for (size_t i{1}; i <= 4; ++i) {
            const size_t first_conn{routers.Requests(router.ToString()).size()};
            i2p::sam::Session session{router, &interrupt};
            i2p::Connection conn;
            BOOST_REQUIRE(session.Listen(conn));
            const auto creates{Creates(routers.Requests(router.ToString()), first_conn)};
            BOOST_REQUIRE_EQUAL(creates.size(), 2U);
            BOOST_CHECK_EQUAL(Field(creates[0].second, "i2cp.leaseSetEncType"), "6,4");
            BOOST_CHECK_EQUAL(Field(creates[1].second, "i2cp.leaseSetEncType"), "4,0");
            // One info line per session.
            BOOST_CHECK_EQUAL(log.Count(UNNAMED_REJECTION), i);
            BOOST_CHECK_EQUAL(log.Count(UnnamedRejectionInfo(router, Field(creates[1].second, "ID"), c.result, c.message)), 1U);
        }
        // Not counted, and no warning.
        BOOST_CHECK_EQUAL(log.Count("until qbit restarts"), 0U);
        BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 0U);
    }
}

BOOST_AUTO_TEST_CASE(hybrid_rejection_names_enc_type)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;

    uint16_t port{17121};
    for (const auto& [reply, named] : std::vector<std::pair<std::string, bool>>{
             {JAVA_I2P_2_9_0_REJECTION, true},
             // Each phrase, in any case.
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Unsupported CRYPTO TYPE 6\"", true},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Encryption Type 6 is not supported\"", true},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"bad enc TYPE: 6\"", true},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"unknown EncType 6\"", true},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=unsupported_encType", true},
             // Matched before MESSAGE= is capped for the log.
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"" + std::string(300, 'x') + " crypto type 6\"", true},
             // Only "type" or "crypto".
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Unsupported type: 6\"", false},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"crypto failure\"", false},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"crypto: unsupported type 6\"", false},
             // Not in MESSAGE=: an unquoted one ends at the first space.
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=Unsupported crypto type: 6", false},
             {"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Failed\" enctype=6", false},
         }) {
        BOOST_TEST_MESSAGE(reply);
        const Proxy router{TestRouter(port++)};
        routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string& enc_types) {
                                                  return enc_types == "6,4" ? Response{.line = reply} : CreateOk();
                                              })});
        LogCapture log;
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK_EQUAL(CountEncTypes(Creates(routers.Requests(router.ToString())), "4,0"), 1U);
        // Only a rejection that names the encryption type counts and warns.
        BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), named ? 1U : 0U);
        BOOST_CHECK_EQUAL(log.Count(UNNAMED_REJECTION), named ? 0U : 1U);
    }
}

BOOST_AUTO_TEST_CASE(hybrid_remembered_routers_bounded)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;

    const auto fallback_session = [&](const Proxy& router) {
        const size_t first_conn{routers.Requests(router.ToString()).size()};
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        const auto creates{Creates(routers.Requests(router.ToString()), first_conn)};
        BOOST_REQUIRE(!creates.empty());
        return Field(creates[0].second, "i2cp.leaseSetEncType");
    };

    // The oldest router does not sort first, so forgetting the first one would not pass.
    const Proxy oldest{TestRouter(17299)};
    routers.AddRouter(oldest.ToString(), {.script = NoHybrid()});
    for (unsigned i{0}; i < i2p::sam::SAM_HYBRID_FALLBACKS_TO_REMEMBER; ++i) {
        BOOST_CHECK_EQUAL(fallback_session(oldest), "6,4");
    }
    BOOST_CHECK_EQUAL(fallback_session(oldest), "4,0");

    // As many newer routers as can be remembered: the oldest one is forgotten.
    std::vector<Proxy> newer;
    for (size_t i{0}; i < i2p::sam::SAM_MAX_REMEMBERED_ROUTERS; ++i) {
        newer.push_back(TestRouter(17200 + i));
        routers.AddRouter(newer.back().ToString(), {.script = NoHybrid()});
        BOOST_CHECK_EQUAL(fallback_session(newer.back()), "6,4");
    }
    // The newer ones are remembered: a second rejection in a row turns 6,4 off.
    BOOST_CHECK_EQUAL(fallback_session(newer.front()), "6,4");
    BOOST_CHECK_EQUAL(fallback_session(newer.front()), "4,0");
    BOOST_CHECK_EQUAL(fallback_session(oldest), "6,4");
}

BOOST_AUTO_TEST_CASE(hybrid_unrelated_rejection)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    uint16_t port{17031};
    for (const std::string result : {"DUPLICATED_ID", "DUPLICATED_DEST", "INVALID_ID", "INVALID_KEY"}) {
        const Proxy router{TestRouter(port++)};
        bool accept{false};
        routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string&) {
                                                  return accept ? CreateOk() : Response{.line = "SESSION STATUS RESULT=" + result};
                                              })});
        {
            i2p::sam::Session session{router, &interrupt};
            i2p::Connection conn;
            BOOST_CHECK(!session.Listen(conn));
            BOOST_CHECK(ListenFailedWith(log, {"Unexpected reply to \"SESSION CREATE ...\": \"SESSION STATUS RESULT=" + result + "\""}));
        }
        // No retry.
        const auto requests{routers.Requests(router.ToString())};
        BOOST_CHECK_EQUAL(requests.size(), 1U);
        BOOST_CHECK_EQUAL(Creates(requests).size(), 1U);

        // Nothing remembered: the next session through this router asks for 6,4 again.
        accept = true;
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK(FirstCreateAsks(routers, router, requests.size(), "6,4"));
    }
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 0U);
}

BOOST_AUTO_TEST_CASE(hybrid_retry_also_fails)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    const Proxy router{TestRouter(17041)};
    bool accept{false};
    // MESSAGE is router text: logged sanitized and capped. It names the encryption type, so only
    // the failed retry keeps the rejections from counting.
    const std::string named_message{"Bad\x07 crypto type " + std::string(300, 'x')};
    std::string message;
    routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string&) {
                                              return accept ? CreateOk() : Response{.line = "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"" + message + "\""};
                                          })});
    // Two failed retries in a row, after rejections that name the encryption type, are not
    // remembered. A failed retry after one that does not name it logs no info line either.
    for (const std::string& m : {named_message, named_message, std::string{"Failed to build tunnels"}}) {
        message = m;
        const size_t first_conn{routers.Requests(router.ToString()).size()};
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_CHECK(!session.Listen(conn));
        BOOST_CHECK(ListenFailedWith(log, {"Unexpected reply to \"SESSION CREATE ...\""}));
        const auto creates{Creates(routers.Requests(router.ToString()), first_conn)};
        BOOST_REQUIRE_EQUAL(creates.size(), 2U);
        BOOST_CHECK_EQUAL(Field(creates[0].second, "i2cp.leaseSetEncType"), "6,4");
        BOOST_CHECK_EQUAL(Field(creates[1].second, "i2cp.leaseSetEncType"), "4,0");
        BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);
    }
    BOOST_CHECK_EQUAL(log.Count("RESULT=I2P_ERROR MESSAGE=\"Bad crypto type " + std::string(183, 'x') + "\", retrying with 4,0"), 2U);
    BOOST_CHECK_EQUAL(log.Count("RESULT=I2P_ERROR MESSAGE=\"Failed to build tunnels\", retrying with 4,0"), 1U);
    BOOST_CHECK_EQUAL(log.Count(UNNAMED_REJECTION), 0U);

    // Nothing remembered: the next session through this router asks for 6,4 again.
    accept = true;
    const size_t first_conn{routers.Requests(router.ToString()).size()};
    i2p::sam::Session session{router, &interrupt};
    i2p::Connection conn;
    BOOST_REQUIRE(session.Listen(conn));
    BOOST_CHECK(FirstCreateAsks(routers, router, first_conn, "6,4"));
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 0U);
}

BOOST_AUTO_TEST_CASE(hybrid_no_retry_on_transport_failure)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    struct Failure {
        std::string name;
        Response response;
        std::vector<std::string> errors;
        std::chrono::milliseconds create_timeout{i2p::sam::SAM_CREATE_TIMEOUT};
    };
    const std::vector<Failure> failures{
        {"send failure", {.action = Action::FAIL_SEND}, {"send():"}},
        {"EOF", {.action = Action::CLOSE}, {"Connection unexpectedly closed by peer"}},
        {"malformed reply, empty RESULT", {.line = "SESSION STATUS RESULT="}, {"Unexpected reply"}},
        {"malformed reply, not SESSION STATUS", {.line = "STREAM STATUS RESULT=I2P_ERROR"}, {"Unexpected reply"}},
        {"missing RESULT", {.line = "SESSION STATUS MESSAGE=\"no result\""}, {"Missing RESULT="}},
        {"RESULT without a value", {.line = "SESSION STATUS RESULT"}, {"Missing RESULT="}},
        // The router got the request, but its reply is lost.
        {"lost success reply", {.action = Action::STALL}, TIMEOUT_ERRORS, 1s},
    };

    uint16_t port{17051};
    for (const auto& failure : failures) {
        BOOST_TEST_MESSAGE(failure.name);
        const Proxy router{TestRouter(port++)};
        bool accept{false};
        routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string&) {
                                                  return accept ? CreateOk() : failure.response;
                                              })});
        {
            i2p::sam::Session session{router, &interrupt, failure.create_timeout};
            i2p::Connection conn;
            BOOST_CHECK(!session.Listen(conn));
            BOOST_CHECK(ListenFailedWith(log, failure.errors));
        }
        // No retry: no second connection. (Only an exhausted deadline can keep the request
        // from being sent.)
        const auto requests{routers.Requests(router.ToString())};
        BOOST_CHECK_EQUAL(requests.size(), 1U);
        BOOST_CHECK_LE(Creates(requests).size(), 1U);
        BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);

        // Nothing remembered: the next session through this router asks for 6,4 again.
        accept = true;
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK(FirstCreateAsks(routers, router, requests.size(), "6,4"));
    }
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 0U);
}

// Shutdown must interrupt connecting to the SAM proxy within 100 ms.
static_assert(MAX_CONNECT_POLL_INTERVAL <= 100ms);

BOOST_AUTO_TEST_CASE(hybrid_retry_deadline_and_interrupt)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    LogCapture log;

    // Signal the interrupt during the retry: while it connects, or on a request.
    struct Interruption {
        std::string name;
        /** "connect", or the start of the request. */
        std::string on;
        std::string error;
        /** The requests of the retry that the router gets. */
        size_t retry_requests;
    };
    uint16_t port{17061};
    for (const auto& c : std::vector<Interruption>{
             {"interrupt during reconnect", "connect", "Interrupted while connecting to", 0},
             {"interrupt during HELLO", "HELLO", "Receive interrupted", 1},
             {"interrupt during CREATE", "SESSION CREATE", "Receive interrupted", 2},
         }) {
        BOOST_TEST_MESSAGE(c.name);
        const Proxy router{TestRouter(port++)};
        CThreadInterrupt interrupt;
        bool accept{false};
        routers.AddRouter(router.ToString(),
                          {.script = [&](size_t conn, const std::string& request) -> Response {
                               if (accept) return Hybrid()(conn, request);
                               if (conn == 1 && request.starts_with(c.on)) {
                                   interrupt();
                                   return {.action = Action::STALL};
                               }
                               return NoHybrid()(conn, request);
                           },
                           .pending_connects = c.on == "connect" ? std::set<size_t>{1} : std::set<size_t>{},
                           .on_connect_wait = [&](size_t wait) {
                               if (wait == 2) interrupt();
                           }});

        // The deadline is far: only the interrupt can end this.
        i2p::sam::Session session{router, &interrupt};
        i2p::Connection conn;
        const auto start{std::chrono::steady_clock::now()};
        BOOST_CHECK(!session.Listen(conn));
        BOOST_CHECK(ListenFailedWith(log, {c.error}));
        BOOST_CHECK(std::chrono::steady_clock::now() - start < i2p::sam::SAM_CREATE_TIMEOUT / 3);

        const auto requests{routers.Requests(router.ToString())};
        BOOST_REQUIRE_EQUAL(requests.size(), 2U);
        BOOST_CHECK_EQUAL(requests[1].size(), c.retry_requests);
        BOOST_CHECK(std::ranges::all_of(routers.ConnectWaits(router.ToString()), [](auto w) { return w <= MAX_CONNECT_POLL_INTERVAL; }));
        // Sockets released.
        BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);

        // No half-published session: the next use creates the session anew.
        interrupt.reset();
        accept = true;
        BOOST_REQUIRE(session.Listen(conn));
        const auto next_creates{Creates(routers.Requests(router.ToString()), requests.size())};
        BOOST_REQUIRE_EQUAL(next_creates.size(), 1U);
        BOOST_CHECK_EQUAL(routers.Requests(router.ToString()).back().back(),
                          strprintf("STREAM ACCEPT ID=%s SILENT=false", Field(next_creates[0].second, "ID")));
    }

    {
        BOOST_TEST_MESSAGE("deadline exhausted across steps");
        // Each answer of the first attempt is quicker than the deadline, the retry's HELLO is
        // answered only long after it. Only one deadline over all the steps ends the retry in time.
        constexpr auto create_timeout{1000ms};
        constexpr auto delay{400ms};
        const Proxy router{TestRouter(port++)};
        CThreadInterrupt interrupt;
        bool accept{false};
        routers.AddRouter(router.ToString(),
                          {.script = [&](size_t conn, const std::string& request) -> Response {
                              if (accept) return Hybrid()(conn, request);
                              if (conn == 0) return NoHybrid(delay)(conn, request);
                              return {.line = "HELLO REPLY RESULT=OK VERSION=3.1", .delay = 20s};
                          }});

        i2p::sam::Session session{router, &interrupt, create_timeout};
        i2p::Connection conn;
        const auto start{std::chrono::steady_clock::now()};
        BOOST_CHECK(!session.Listen(conn));
        const auto elapsed{std::chrono::steady_clock::now() - start};
        BOOST_CHECK(ListenFailedWith(log, TIMEOUT_ERRORS));
        // The first attempt's two answers took that long, and the retry's HELLO was not waited for.
        BOOST_CHECK(elapsed >= 2 * delay);
        BOOST_CHECK(elapsed < 15s);

        const auto requests{routers.Requests(router.ToString())};
        BOOST_CHECK_EQUAL(CountEncTypes(Creates(requests), "4,0"), 0U);
        // Every wait for an answer ends by the deadline: the retry's waits got what was left
        // after the first attempt's two answers. Deadlines are rounded up to milliseconds.
        const auto recv_timeouts{routers.RecvTimeouts(router.ToString())};
        for (size_t c{0}; c < recv_timeouts.size(); ++c) {
            for (const auto timeout : recv_timeouts[c]) {
                BOOST_CHECK(timeout <= (c == 0 ? create_timeout : create_timeout - 2 * delay) + 1ms);
            }
        }
        BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);

        // No half-published session: the next use creates the session anew.
        accept = true;
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK_EQUAL(Creates(routers.Requests(router.ToString()), requests.size()).size(), 1U);
    }

    {
        BOOST_TEST_MESSAGE("deadline exhausted while connecting");
        constexpr auto create_timeout{300ms};
        const Proxy router{TestRouter(port++)};
        CThreadInterrupt interrupt;
        routers.AddRouter(router.ToString(), {.script = Hybrid(), .pending_connects = {0}});

        i2p::sam::Session session{router, &interrupt, create_timeout};
        i2p::Connection conn;
        const auto start{std::chrono::steady_clock::now()};
        BOOST_CHECK(!session.Listen(conn));
        const auto elapsed{std::chrono::steady_clock::now() - start};
        BOOST_CHECK(ListenFailedWith(log, {"Timed out connecting to"}));
        BOOST_CHECK(elapsed >= create_timeout);
        BOOST_CHECK(elapsed < 15s);
        BOOST_CHECK(std::ranges::all_of(routers.ConnectWaits(router.ToString()), [](auto w) { return w <= MAX_CONNECT_POLL_INTERVAL; }));
        BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);

        // No half-published session: the next use creates the session anew.
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_CHECK_EQUAL(Creates(routers.Requests(router.ToString())).size(), 1U);
    }
    BOOST_CHECK_EQUAL(log.Count(HYBRID_WARNING), 0U);
}

BOOST_AUTO_TEST_CASE(hybrid_deadline_covers_dest_generate)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    // A persistent session without a key generates one first. The router answers that only
    // long after the deadline.
    constexpr auto create_timeout{500ms};
    const Proxy router{TestRouter(17091)};
    bool accept{false};
    routers.AddRouter(router.ToString(), {.script = [&](size_t conn, const std::string& request) -> Response {
                                              if (!accept && request.starts_with("DEST GENERATE")) {
                                                  return {.line = "DEST REPLY PRIV=" + TEST_PRIV, .delay = 20s};
                                              }
                                              return Hybrid()(conn, request);
                                          }});
    const fs::path key_file{m_args.GetDataDirNet() / "i2p_key_dest_generate"};
    i2p::sam::Session session{key_file, router, &interrupt, create_timeout};
    i2p::Connection conn;
    const auto start{std::chrono::steady_clock::now()};
    BOOST_CHECK(!session.Listen(conn));
    BOOST_CHECK(std::chrono::steady_clock::now() - start < 15s);
    BOOST_CHECK(ListenFailedWith(log, TIMEOUT_ERRORS));

    const auto requests{routers.Requests(router.ToString())};
    BOOST_REQUIRE_EQUAL(requests.size(), 1U);
    BOOST_REQUIRE_EQUAL(requests[0].size(), 2U);
    BOOST_CHECK(requests[0][1].starts_with("DEST GENERATE"));
    BOOST_CHECK_EQUAL(Creates(requests).size(), 0U);
    // The wait for the new key ends by the deadline, not after the usual 3 minutes.
    const auto recv_timeouts{routers.RecvTimeouts(router.ToString())};
    BOOST_REQUIRE_EQUAL(recv_timeouts[0].size(), 2U);
    BOOST_CHECK(recv_timeouts[0][1] <= create_timeout + 1ms);
    BOOST_CHECK(!fs::exists(key_file));
    BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);

    accept = true;
    BOOST_REQUIRE(session.Listen(conn));
    BOOST_CHECK(fs::exists(key_file));
}

BOOST_AUTO_TEST_CASE(hybrid_connect_capped_by_timeout)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    // Connecting to the router never completes. -timeout ends it long before the creation
    // deadline. (Should it not, the interrupt ends it eventually, with another error.)
    const Proxy router{TestRouter(17092)};
    routers.AddRouter(router.ToString(), {.script = Hybrid(),
                                          .pending_connects = {0},
                                          .on_connect_wait = [&](size_t wait) {
                                              if (wait == 3000) interrupt();
                                          }});
    const int connect_timeout_orig{nConnectTimeout};
    nConnectTimeout = 200;
    i2p::sam::Session session{router, &interrupt};
    i2p::Connection conn;
    BOOST_CHECK(!session.Listen(conn));
    nConnectTimeout = connect_timeout_orig;
    BOOST_CHECK(ListenFailedWith(log, {"Cannot connect to"}));
    BOOST_CHECK(std::ranges::all_of(routers.ConnectWaits(router.ToString()), [](auto w) { return w <= MAX_CONNECT_POLL_INTERVAL; }));
    BOOST_CHECK_EQUAL(routers.OpenSocks(), 0U);
}

BOOST_AUTO_TEST_CASE(hybrid_private_key_never_logged)
{
    MockSamRouters routers;
    CreateSock = [&routers](int, int, int) { return routers.NewSock(); };
    CThreadInterrupt interrupt;
    LogCapture log;

    // How the router answers "SESSION CREATE".
    std::function<Response(const std::string&)> create;
    const Proxy router{TestRouter(17093)};
    routers.AddRouter(router.ToString(), {.script = RouterScript([&](const std::string& enc_types) { return create(enc_types); })});

    const fs::path key_file{m_args.GetDataDirNet() / "i2p_key_never_logged"};
    for (const auto& [name, answer] : std::vector<std::pair<std::string, std::function<Response(const std::string&)>>>{
             {"retried", [](const std::string& enc_types) { return enc_types == "6,4" ? RejectHybrid() : CreateOk(); }},
             {"retried, not named", [](const std::string& enc_types) { return enc_types == "6,4" ? Response{.line = TUNNEL_BUILD_FAILURE} : CreateOk(); }},
             {"retry rejected", [](const std::string&) { return RejectHybrid(); }},
             {"missing RESULT", [](const std::string&) { return Response{.line = "SESSION STATUS MESSAGE=\"no result\""}; }},
             {"unrelated rejection", [](const std::string&) { return Response{.line = "SESSION STATUS RESULT=DUPLICATED_DEST"}; }},
         }) {
        BOOST_TEST_MESSAGE(name);
        create = answer;
        i2p::sam::Session session{key_file, router, &interrupt};
        i2p::Connection conn;
        (void)session.Listen(conn);
    }

    // Every "SESSION CREATE" carried the key, and the errors were logged without it.
    const auto creates{Creates(routers.Requests(router.ToString()))};
    BOOST_REQUIRE_EQUAL(creates.size(), 8U);
    BOOST_CHECK(std::ranges::all_of(creates, [](const auto& c) { return Field(c.second, "DESTINATION") == TEST_PRIV; }));
    BOOST_CHECK_GE(log.Count("SESSION CREATE ..."), 3U);
    // In I2P's Base64 alphabet and the standard one.
    std::string standard_b64{TEST_PRIV};
    std::ranges::replace(standard_b64, '-', '+');
    std::ranges::replace(standard_b64, '~', '/');
    BOOST_CHECK_EQUAL(log.Count(TEST_PRIV), 0U);
    BOOST_CHECK_EQUAL(log.Count(standard_b64), 0U);
    BOOST_CHECK_EQUAL(log.Count(TEST_PRIV.substr(400, 64)), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
