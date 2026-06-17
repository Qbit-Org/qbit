#ifndef QBIT_PHOTON_SRC_PROTOCOL_H
#define QBIT_PHOTON_SRC_PROTOCOL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace photon {

inline constexpr std::size_t kIpv6MinMtu = 1280;
inline constexpr std::size_t kIpv6HeaderSize = 40;
inline constexpr std::size_t kUdpHeaderSize = 8;
inline constexpr std::size_t kNetworkHeaderSize = kIpv6HeaderSize + kUdpHeaderSize;

inline constexpr std::size_t kPacketSize = 1232;
inline constexpr std::size_t kMacSize = 16;
inline constexpr std::size_t kPayloadSize = 1208;
inline constexpr std::size_t kMacOffset = 4;
inline constexpr std::size_t kCounterOffset = 20;
inline constexpr std::size_t kPayloadOffset = 24;
inline constexpr std::size_t kMacSignedBytes = 4 + (kPacketSize - kCounterOffset);

inline constexpr std::uint16_t kProtocolMagic = 0x5142;
inline constexpr std::uint8_t kProtocolVersion = 1;

inline constexpr std::size_t kFecChunkSize = 1194;
inline constexpr std::uint8_t kMaxChunkId = 254;

enum class MessageType : std::uint8_t {
    kSyn = 0x00,
    kSynAck = 0x01,
    kKeepalive = 0x02,
    kDisconnect = 0x03,
    kBlockHeader = 0x10,
    kBlockChunk = 0x11,
    kPing = 0x20,
    kPong = 0x21,
};

enum class ParseError {
    kNone = 0,
    kInvalidPacketSize,
    kInvalidMagic,
    kUnsupportedVersion,
    kUnknownMessageType,
    kInvalidReservedBits,
    kInvalidVersionRange,
    kInvalidChunkId,
    kInvalidChunkLength,
};

const char* ParseErrorString(ParseError error);

struct Packet {
    std::uint16_t magic{kProtocolMagic};
    std::uint8_t version{kProtocolVersion};
    MessageType msg_type{MessageType::kKeepalive};
    std::array<std::uint8_t, kMacSize> mac{};
    std::uint32_t counter{0};
    std::array<std::uint8_t, kPayloadSize> payload{};
};

struct PacketParseResult {
    ParseError error{ParseError::kNone};
    Packet packet{};

    [[nodiscard]] bool ok() const { return error == ParseError::kNone; }
};

struct SynPayload {
    std::uint8_t version_min{kProtocolVersion};
    std::uint8_t version_cur{kProtocolVersion};
    std::uint16_t reserved{0};
    std::uint64_t session_id{0};
    std::uint64_t feature_flags{0};
    std::uint64_t peer_id{0};
};

struct BlockChunkPayload {
    std::uint64_t block_hash_prefix{0};
    std::uint16_t coding_group_id{0};
    std::uint8_t chunk_id{0};
    std::uint8_t flags{0};
    std::uint16_t data_len{0};
    std::array<std::uint8_t, kFecChunkSize> chunk_data{};
};

struct BlockHeaderPayload {
    std::uint64_t block_hash_prefix{0};
    std::uint64_t original_size{0};
    std::uint16_t data_chunks{0};
    std::uint16_t coding_group_count{0};
};

[[nodiscard]] bool IsKnownMessageType(std::uint8_t raw_type);
[[nodiscard]] bool IsHandshakeMessage(MessageType msg_type);
[[nodiscard]] Packet MakePacket(MessageType msg_type, std::uint32_t counter);

[[nodiscard]] std::array<std::uint8_t, kPacketSize> SerializePacket(const Packet& packet);
[[nodiscard]] PacketParseResult ParsePacket(std::span<const std::uint8_t> bytes);

void EncodeSynPayload(const SynPayload& payload, std::array<std::uint8_t, kPayloadSize>& out_payload);
[[nodiscard]] bool DecodeSynPayload(std::span<const std::uint8_t> payload, SynPayload& out_payload);

void EncodeBlockHeaderPayload(const BlockHeaderPayload& payload, std::array<std::uint8_t, kPayloadSize>& out_payload);
[[nodiscard]] bool DecodeBlockHeaderPayload(std::span<const std::uint8_t> payload, BlockHeaderPayload& out_payload);

void EncodeBlockChunkPayload(const BlockChunkPayload& payload, std::array<std::uint8_t, kPayloadSize>& out_payload);
[[nodiscard]] bool DecodeBlockChunkPayload(std::span<const std::uint8_t> payload, BlockChunkPayload& out_payload);

[[nodiscard]] bool ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                                    std::span<const std::uint8_t> key,
                                    std::array<std::uint8_t, kMacSize>& out_mac);
[[nodiscard]] bool ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                                    std::span<const std::uint8_t> key,
                                    std::uint64_t session_id,
                                    std::array<std::uint8_t, kMacSize>& out_mac);
[[nodiscard]] std::array<std::uint8_t, kMacSize> ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                                                                  std::span<const std::uint8_t> key);
[[nodiscard]] std::array<std::uint8_t, kMacSize> ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                                                                  std::span<const std::uint8_t> key,
                                                                  std::uint64_t session_id);
[[nodiscard]] bool VerifyPacketMac(std::span<const std::uint8_t> packet_bytes, std::span<const std::uint8_t> key);
[[nodiscard]] bool VerifyPacketMac(std::span<const std::uint8_t> packet_bytes,
                                   std::span<const std::uint8_t> key,
                                   std::uint64_t session_id);
void AttachPacketMac(Packet& packet, std::span<const std::uint8_t> key);
void AttachPacketMac(Packet& packet, std::span<const std::uint8_t> key, std::uint64_t session_id);

} // namespace photon

#endif // QBIT_PHOTON_SRC_PROTOCOL_H
