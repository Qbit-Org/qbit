#include <udp_transport.h>

#include <test_harness.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace photon {

RecvPacketResult WaitForPacket(const UdpTransport& transport, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        RecvPacketResult result = transport.ReceivePacket();
        if (result.status == RecvStatus::kWouldBlock) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        return result;
    }

    return RecvPacketResult{};
}

void TestSendReceiveRoundTrip()
{
    UdpTransport receiver;
    UdpTransport sender;
    std::string error;

    CHECK(receiver.OpenAndBind("127.0.0.1", 0, &error));
    CHECK(sender.OpenAndBind("127.0.0.1", 0, &error));

    const auto receiver_port = receiver.BoundPort(&error);
    CHECK(receiver_port.has_value());
    if (!receiver_port.has_value()) {
        return;
    }

    sockaddr_storage destination {};
    socklen_t destination_len = 0;
    CHECK(UdpTransport::ResolveEndpoint("127.0.0.1", *receiver_port, &destination, &destination_len, &error));

    Packet packet = MakePacket(MessageType::kBlockHeader, 7001);
    packet.payload[0] = 0xAA;
    packet.payload[1] = 0xBB;
    CHECK(sender.SendPacket(packet, destination, destination_len, &error));

    const RecvPacketResult received = WaitForPacket(receiver, std::chrono::milliseconds(1000));
    CHECK(received.status == RecvStatus::kPacket);
    if (received.status != RecvStatus::kPacket) {
        return;
    }

    CHECK(received.packet.counter == packet.counter);
    CHECK(received.packet.msg_type == packet.msg_type);
    CHECK(received.packet.payload[0] == packet.payload[0]);
    CHECK(received.packet.payload[1] == packet.payload[1]);
}

void TestInvalidDatagramSizeRejected()
{
    UdpTransport receiver;
    UdpTransport sender;
    std::string error;

    CHECK(receiver.OpenAndBind("127.0.0.1", 0, &error));
    CHECK(sender.OpenAndBind("127.0.0.1", 0, &error));

    const auto receiver_port = receiver.BoundPort(&error);
    CHECK(receiver_port.has_value());
    if (!receiver_port.has_value()) {
        return;
    }

    sockaddr_storage destination {};
    socklen_t destination_len = 0;
    CHECK(UdpTransport::ResolveEndpoint("127.0.0.1", *receiver_port, &destination, &destination_len, &error));

    const std::array<std::uint8_t, 10> short_datagram{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    CHECK(sender.SendRaw(short_datagram, destination, destination_len, &error));

    const RecvPacketResult received = WaitForPacket(receiver, std::chrono::milliseconds(1000));
    CHECK(received.status == RecvStatus::kParseError);
    CHECK(received.parse_error == ParseError::kInvalidPacketSize);
}

void TestOversizedDatagramRejectedAtBoundary()
{
    UdpTransport receiver;
    UdpTransport sender;
    std::string error;

    CHECK(receiver.OpenAndBind("127.0.0.1", 0, &error));
    CHECK(sender.OpenAndBind("127.0.0.1", 0, &error));

    const auto receiver_port = receiver.BoundPort(&error);
    CHECK(receiver_port.has_value());
    if (!receiver_port.has_value()) {
        return;
    }

    sockaddr_storage destination {};
    socklen_t destination_len = 0;
    CHECK(UdpTransport::ResolveEndpoint("127.0.0.1", *receiver_port, &destination, &destination_len, &error));

    // One byte above the protocol packet size also crosses the IPv6-min-MTU envelope.
    std::array<std::uint8_t, kPacketSize + 1> oversized_datagram{};
    oversized_datagram.fill(0xAB);
    CHECK(sender.SendRaw(oversized_datagram, destination, destination_len, &error));

    const RecvPacketResult received = WaitForPacket(receiver, std::chrono::milliseconds(1000));
    CHECK(received.status == RecvStatus::kParseError);
    CHECK(received.parse_error == ParseError::kInvalidPacketSize);
}

void TestOpenAndBindEmptyHostSupportsIpv4LoopbackTraffic()
{
    UdpTransport listener;
    UdpTransport sender;
    std::string error;

    CHECK(listener.OpenAndBind("", 0, &error));
    CHECK(sender.OpenAndBind("127.0.0.1", 0, &error));

    const auto listener_port = listener.BoundPort(&error);
    CHECK(listener_port.has_value());
    if (!listener_port.has_value()) {
        return;
    }

    sockaddr_storage destination {};
    socklen_t destination_len = 0;
    CHECK(UdpTransport::ResolveEndpoint("127.0.0.1", *listener_port, &destination, &destination_len, &error));

    Packet packet = MakePacket(MessageType::kPing, 7002);
    packet.payload[0] = 0xCC;
    packet.payload[1] = 0xDD;
    CHECK(sender.SendPacket(packet, destination, destination_len, &error));

    const RecvPacketResult received = WaitForPacket(listener, std::chrono::milliseconds(1000));
    CHECK(received.status == RecvStatus::kPacket);
    if (received.status != RecvStatus::kPacket) {
        return;
    }

    CHECK(received.packet.counter == packet.counter);
    CHECK(received.packet.msg_type == packet.msg_type);
    CHECK(received.packet.payload[0] == packet.payload[0]);
    CHECK(received.packet.payload[1] == packet.payload[1]);
}

} // namespace photon

int main()
{
    photon::TestSendReceiveRoundTrip();
    photon::TestInvalidDatagramSizeRejected();
    photon::TestOversizedDatagramRejectedAtBoundary();
    photon::TestOpenAndBindEmptyHostSupportsIpv4LoopbackTraffic();
    return photon::test::Finish();
}
