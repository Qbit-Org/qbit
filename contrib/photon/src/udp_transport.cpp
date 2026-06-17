#include <udp_transport.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace photon {
namespace {

constexpr int kInvalidFd = -1;

std::string IntToString(int value);
std::string ErrnoMessage(const char* context, int err);

void SetError(std::string* error, const std::string& value)
{
    if (error != nullptr) {
        *error = value;
    }
}

bool SetNonBlocking(int fd, std::string* error)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        SetError(error, ErrnoMessage("fcntl(F_GETFL)", errno));
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        SetError(error, ErrnoMessage("fcntl(F_SETFL)", errno));
        return false;
    }
    return true;
}

std::string ToPortString(std::uint16_t port)
{
    char buffer[5];
    int idx = static_cast<int>(sizeof(buffer));
    std::uint16_t remaining = port;
    do {
        --idx;
        buffer[idx] = static_cast<char>('0' + (remaining % 10U));
        remaining = static_cast<std::uint16_t>(remaining / 10U);
    } while (remaining > 0U);

    return std::string(buffer + idx, buffer + sizeof(buffer));
}

std::string IntToString(int value)
{
    bool negative = false;
    unsigned int magnitude = 0;
    if (value < 0) {
        negative = true;
        magnitude = static_cast<unsigned int>(-(value + 1)) + 1U;
    } else {
        magnitude = static_cast<unsigned int>(value);
    }

    char buffer[12];
    int idx = static_cast<int>(sizeof(buffer));
    do {
        --idx;
        buffer[idx] = static_cast<char>('0' + (magnitude % 10U));
        magnitude /= 10U;
    } while (magnitude > 0U);

    if (negative) {
        --idx;
        buffer[idx] = '-';
    }

    return std::string(buffer + idx, buffer + sizeof(buffer));
}

std::string ErrnoMessage(const char* context, int err)
{
    return std::string(context) + " failed (errno=" + IntToString(err) + ")";
}

bool IsWouldBlockError(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK;
}

} // namespace

UdpTransport::~UdpTransport()
{
    Close();
}

UdpTransport::UdpTransport(UdpTransport&& other) noexcept
{
    socket_fd_ = other.socket_fd_;
    other.socket_fd_ = kInvalidFd;
}

UdpTransport& UdpTransport::operator=(UdpTransport&& other) noexcept
{
    if (this == &other) {
        return *this;
    }

    Close();
    socket_fd_ = other.socket_fd_;
    other.socket_fd_ = kInvalidFd;
    return *this;
}

bool UdpTransport::OpenAndBind(const std::string& bind_host, std::uint16_t bind_port, std::string* error)
{
    Close();

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* resolved = nullptr;
    const std::string port = ToPortString(bind_port);
    const char* node = bind_host.empty() ? nullptr : bind_host.c_str();
    if (getaddrinfo(node, port.c_str(), &hints, &resolved) != 0) {
        SetError(error, "getaddrinfo failed for bind endpoint");
        return false;
    }

    bool success = false;
    const auto try_bind = [&](int family_filter) {
        for (const addrinfo* cursor = resolved; cursor != nullptr; cursor = cursor->ai_next) {
            if (family_filter != AF_UNSPEC && cursor->ai_family != family_filter) {
                continue;
            }

            const int fd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);
            if (fd < 0) {
                continue;
            }

            const int reuse_addr = 1;
            (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
#ifdef IPV6_V6ONLY
            if (cursor->ai_family == AF_INET6) {
                const int v6_only = 0;
                (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only));
            }
#endif

            std::string local_error;
            if (!SetNonBlocking(fd, &local_error)) {
                close(fd);
                continue;
            }

            if (bind(fd, cursor->ai_addr, cursor->ai_addrlen) == 0) {
                socket_fd_ = fd;
                return true;
            }

            close(fd);
        }

        return false;
    };

    if (bind_host.empty()) {
        success = try_bind(AF_INET) || try_bind(AF_INET6);
    } else {
        success = try_bind(AF_UNSPEC);
    }

    freeaddrinfo(resolved);

    if (!success) {
        SetError(error, "unable to bind UDP socket to " + bind_host + ":" + port);
        return false;
    }

    return true;
}

void UdpTransport::Close()
{
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = kInvalidFd;
    }
}

std::optional<std::uint16_t> UdpTransport::BoundPort(std::string* error) const
{
    if (!IsOpen()) {
        SetError(error, "socket is not open");
        return std::nullopt;
    }

    sockaddr_storage storage {};
    socklen_t addr_len = sizeof(storage);
    if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&storage), &addr_len) < 0) {
        SetError(error, ErrnoMessage("getsockname", errno));
        return std::nullopt;
    }

    if (storage.ss_family == AF_INET) {
        const auto* addr = reinterpret_cast<const sockaddr_in*>(&storage);
        return ntohs(addr->sin_port);
    }
    if (storage.ss_family == AF_INET6) {
        const auto* addr = reinterpret_cast<const sockaddr_in6*>(&storage);
        return ntohs(addr->sin6_port);
    }

    SetError(error, "unsupported socket family from getsockname");
    return std::nullopt;
}

bool UdpTransport::ResolveEndpoint(const std::string& host,
                                   std::uint16_t port,
                                   sockaddr_storage* out_addr,
                                   socklen_t* out_len,
                                   std::string* error)
{
    if (out_addr == nullptr || out_len == nullptr) {
        SetError(error, "ResolveEndpoint requires output pointers");
        return false;
    }

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo* resolved = nullptr;
    const std::string port_str = ToPortString(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &resolved) != 0) {
        SetError(error, "getaddrinfo failed for remote endpoint");
        return false;
    }

    const addrinfo* first = resolved;
    if (first == nullptr || first->ai_addrlen > static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        freeaddrinfo(resolved);
        SetError(error, "no usable address resolved");
        return false;
    }

    std::memset(out_addr, 0, sizeof(*out_addr));
    std::memcpy(out_addr, first->ai_addr, static_cast<std::size_t>(first->ai_addrlen));
    *out_len = first->ai_addrlen;
    freeaddrinfo(resolved);
    return true;
}

bool UdpTransport::SendRaw(std::span<const std::uint8_t> bytes,
                           const sockaddr_storage& addr,
                           socklen_t addr_len,
                           std::string* error) const
{
    if (!IsOpen()) {
        SetError(error, "socket is not open");
        return false;
    }

    const ssize_t sent = sendto(socket_fd_,
                                bytes.data(),
                                bytes.size(),
                                0,
                                reinterpret_cast<const sockaddr*>(&addr),
                                addr_len);
    if (sent < 0) {
        SetError(error, ErrnoMessage("sendto", errno));
        return false;
    }
    if (sent != static_cast<ssize_t>(bytes.size())) {
        SetError(error, "sendto wrote partial datagram");
        return false;
    }

    return true;
}

bool UdpTransport::SendPacket(const Packet& packet,
                              const sockaddr_storage& addr,
                              socklen_t addr_len,
                              std::string* error) const
{
    const auto bytes = SerializePacket(packet);
    return SendRaw(bytes, addr, addr_len, error);
}

RecvPacketResult UdpTransport::ReceivePacket() const
{
    RecvPacketResult result{};
    if (!IsOpen()) {
        result.status = RecvStatus::kSocketError;
        result.error = "socket is not open";
        return result;
    }

    std::array<std::uint8_t, 2048> buffer{};
    sockaddr_storage peer {};
    socklen_t peer_len = sizeof(peer);
    const ssize_t received = recvfrom(socket_fd_,
                                      buffer.data(),
                                      buffer.size(),
                                      0,
                                      reinterpret_cast<sockaddr*>(&peer),
                                      &peer_len);
    if (received < 0) {
        const int err = errno;
        if (IsWouldBlockError(err)) {
            result.status = RecvStatus::kWouldBlock;
            return result;
        }

        result.status = RecvStatus::kSocketError;
        result.error = ErrnoMessage("recvfrom", err);
        return result;
    }

    result.peer = peer;
    result.peer_len = peer_len;

    if (received != static_cast<ssize_t>(kPacketSize)) {
        result.status = RecvStatus::kParseError;
        result.parse_error = ParseError::kInvalidPacketSize;
        result.error = ParseErrorString(result.parse_error);
        return result;
    }

    const auto parse = ParsePacket(std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(received)));
    if (!parse.ok()) {
        result.status = RecvStatus::kParseError;
        result.parse_error = parse.error;
        result.error = ParseErrorString(parse.error);
        return result;
    }

    result.status = RecvStatus::kPacket;
    result.packet = parse.packet;
    return result;
}

} // namespace photon
