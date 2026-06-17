#include <zmq_listener.h>

#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <zmq.h>

namespace {

void Require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::uint16_t PickFreePort()
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("failed to create socket for free-port probe");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        throw std::runtime_error("failed to bind free-port probe socket");
    }

    sockaddr_in bound{};
    socklen_t bound_len = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
        close(fd);
        throw std::runtime_error("failed to read bound port for free-port probe");
    }

    close(fd);
    return ntohs(bound.sin_port);
}

class ScopedPublisher {
public:
    explicit ScopedPublisher(std::string endpoint)
        : m_endpoint(std::move(endpoint))
    {
        m_context = zmq_ctx_new();
        if (m_context == nullptr) {
            throw std::runtime_error("zmq_ctx_new failed for publisher");
        }

        m_socket = zmq_socket(m_context, ZMQ_PUB);
        if (m_socket == nullptr) {
            zmq_ctx_term(m_context);
            throw std::runtime_error("zmq_socket(ZMQ_PUB) failed");
        }

        const int linger = 0;
        zmq_setsockopt(m_socket, ZMQ_LINGER, &linger, sizeof(linger));

        if (zmq_bind(m_socket, m_endpoint.c_str()) != 0) {
            zmq_close(m_socket);
            zmq_ctx_term(m_context);
            throw std::runtime_error("zmq_bind failed for publisher endpoint " + m_endpoint);
        }
    }

    ~ScopedPublisher()
    {
        if (m_socket != nullptr) {
            zmq_close(m_socket);
            m_socket = nullptr;
        }

        if (m_context != nullptr) {
            zmq_ctx_term(m_context);
            m_context = nullptr;
        }
    }

    void Send(const std::string& topic, const std::vector<std::uint8_t>& payload) const
    {
        const int topic_rc = zmq_send(m_socket, topic.data(), topic.size(), ZMQ_SNDMORE);
        if (topic_rc < 0) {
            throw std::runtime_error("failed to send ZMQ topic");
        }

        const int payload_rc = zmq_send(m_socket, payload.data(), payload.size(), 0);
        if (payload_rc < 0) {
            throw std::runtime_error("failed to send ZMQ payload");
        }
    }

private:
    std::string m_endpoint{};
    void* m_context{nullptr};
    void* m_socket{nullptr};
};

std::string MakeEndpoint()
{
    return "tcp://127.0.0.1:" + std::to_string(PickFreePort());
}

std::vector<std::uint8_t> ToVector(const std::array<std::uint8_t, 32>& bytes)
{
    return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

void NoopSignalHandler(int) {}

class ScopedSignalHandler {
public:
    explicit ScopedSignalHandler(int signum)
        : m_signum(signum)
    {
        struct sigaction sa {};
        sa.sa_handler = NoopSignalHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        if (sigaction(m_signum, &sa, &m_old_action) != 0) {
            throw std::runtime_error("failed to install signal handler");
        }
        m_installed = true;
    }

    ~ScopedSignalHandler()
    {
        if (m_installed) {
            sigaction(m_signum, &m_old_action, nullptr);
        }
    }

private:
    int m_signum{0};
    struct sigaction m_old_action {};
    bool m_installed{false};
};

void TestReceivesHashblock()
{
    const std::string endpoint = MakeEndpoint();
    ScopedPublisher publisher(endpoint);

    photon::ZmqListener listener;
    Require(listener.Connect(endpoint), "listener failed to connect to hashblock endpoint");

    // Give SUB/PUB handshake time to avoid slow-joiner message loss.
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    std::array<std::uint8_t, 32> expected_hash{};
    for (std::size_t i = 0; i < expected_hash.size(); ++i) {
        expected_hash[i] = static_cast<std::uint8_t>(i);
    }

    publisher.Send("hashblock", ToVector(expected_hash));

    const auto received = listener.NextHash(std::chrono::milliseconds{2000});
    Require(received.has_value(), "expected hashblock notification");
    Require(*received == expected_hash, "received hash did not match expected payload");
}

void TestMalformedPayloadIsRejected()
{
    const std::string endpoint = MakeEndpoint();
    ScopedPublisher publisher(endpoint);

    photon::ZmqListener listener;
    Require(listener.Connect(endpoint), "listener failed to connect to hashblock endpoint");
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    publisher.Send("hashblock", std::vector<std::uint8_t>(8, 0xFF));

    const auto received = listener.NextHash(std::chrono::milliseconds{2000});
    Require(!received.has_value(), "short hashblock payload must be rejected");
}

void TestReconnectAfterTimeout()
{
    const std::string endpoint = MakeEndpoint();
    ScopedPublisher publisher(endpoint);

    photon::ZmqListener listener;
    Require(listener.Connect(endpoint), "listener failed to connect to hashblock endpoint");

    const auto timeout_result = listener.NextHash(std::chrono::milliseconds{10});
    Require(!timeout_result.has_value(), "expected timeout with no publisher messages");

    std::array<std::uint8_t, 32> expected_hash{};
    for (std::size_t i = 0; i < expected_hash.size(); ++i) {
        expected_hash[i] = static_cast<std::uint8_t>(0x80 + i);
    }

    std::optional<std::array<std::uint8_t, 32>> received;
    for (int attempt = 0; attempt < 5 && !received.has_value(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{150});
        publisher.Send("hashblock", ToVector(expected_hash));
        received = listener.NextHash(std::chrono::milliseconds{500});
    }

    Require(received.has_value(), "listener did not recover after reconnect-on-timeout");
    Require(*received == expected_hash, "recovered listener returned unexpected hash");
}

void TestEintrPollDoesNotReconnect()
{
    const std::string endpoint = MakeEndpoint();
    ScopedPublisher publisher(endpoint);

    photon::ZmqListener listener;
    Require(listener.Connect(endpoint), "listener failed to connect to hashblock endpoint");
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    ScopedSignalHandler signal_handler(SIGUSR1);
    const pthread_t main_thread = pthread_self();

    std::array<std::uint8_t, 32> expected_hash{};
    for (std::size_t i = 0; i < expected_hash.size(); ++i) {
        expected_hash[i] = static_cast<std::uint8_t>(0x40 + i);
    }

    std::thread interrupter([&publisher, expected_hash, main_thread] {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        pthread_kill(main_thread, SIGUSR1);
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
        publisher.Send("hashblock", ToVector(expected_hash));
    });

    const auto interrupted = listener.NextHash(std::chrono::milliseconds{2000});
    Require(!interrupted.has_value(), "expected poll to be interrupted by SIGUSR1");

    const auto received = listener.NextHash(std::chrono::milliseconds{1000});
    interrupter.join();
    Require(received.has_value(), "expected listener to keep subscription after EINTR");
    Require(*received == expected_hash, "received hash after EINTR did not match expected payload");
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"receives_hashblock", TestReceivesHashblock},
        {"malformed_payload_is_rejected", TestMalformedPayloadIsRejected},
        {"reconnect_after_timeout", TestReconnectAfterTimeout},
        {"eintr_poll_does_not_reconnect", TestEintrPollDoesNotReconnect},
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
