#ifndef QBIT_PHOTON_SRC_ZMQ_LISTENER_H
#define QBIT_PHOTON_SRC_ZMQ_LISTENER_H

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace photon {

class ZmqListener {
public:
    ZmqListener();
    ~ZmqListener();

    ZmqListener(const ZmqListener&) = delete;
    ZmqListener& operator=(const ZmqListener&) = delete;

    void SetSequenceEndpoint(std::optional<std::string> endpoint);
    bool Connect(const std::string& endpoint);

    std::optional<std::array<std::uint8_t, 32>> NextHash(std::chrono::milliseconds timeout);

private:
    bool Reconnect();
    bool CreateSocket();
    void CloseSocket();

    void* m_context{nullptr};
    void* m_socket{nullptr};
    std::string m_hashblock_endpoint{};
    std::optional<std::string> m_sequence_endpoint{};
    bool m_connected{false};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_ZMQ_LISTENER_H
