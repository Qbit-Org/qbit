#ifndef QBIT_PHOTON_SRC_UDP_TRANSPORT_H
#define QBIT_PHOTON_SRC_UDP_TRANSPORT_H

#include <protocol.h>

#include <optional>
#include <span>
#include <string>

#include <sys/socket.h>

namespace photon {

enum class RecvStatus {
    kPacket = 0,
    kWouldBlock,
    kSocketError,
    kParseError,
};

struct RecvPacketResult {
    RecvStatus status{RecvStatus::kWouldBlock};
    Packet packet{};
    sockaddr_storage peer{};
    socklen_t peer_len{0};
    ParseError parse_error{ParseError::kNone};
    std::string error{};
};

class UdpTransport {
public:
    UdpTransport() = default;
    ~UdpTransport();

    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;
    UdpTransport(UdpTransport&& other) noexcept;
    UdpTransport& operator=(UdpTransport&& other) noexcept;

    [[nodiscard]] bool OpenAndBind(const std::string& bind_host, std::uint16_t bind_port, std::string* error);
    void Close();
    [[nodiscard]] bool IsOpen() const { return socket_fd_ >= 0; }
    [[nodiscard]] int fd() const { return socket_fd_; }

    [[nodiscard]] std::optional<std::uint16_t> BoundPort(std::string* error = nullptr) const;

    [[nodiscard]] static bool ResolveEndpoint(const std::string& host,
                                              std::uint16_t port,
                                              sockaddr_storage* out_addr,
                                              socklen_t* out_len,
                                              std::string* error);

    [[nodiscard]] bool SendPacket(const Packet& packet,
                                  const sockaddr_storage& addr,
                                  socklen_t addr_len,
                                  std::string* error = nullptr) const;

    [[nodiscard]] bool SendRaw(std::span<const std::uint8_t> bytes,
                               const sockaddr_storage& addr,
                               socklen_t addr_len,
                               std::string* error = nullptr) const;

    [[nodiscard]] RecvPacketResult ReceivePacket() const;

private:
    int socket_fd_{-1};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_UDP_TRANSPORT_H
