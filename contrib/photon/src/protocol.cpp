#include <protocol.h>

#include <algorithm>
#include <limits>

#include <openssl/crypto.h>
#include <openssl/hmac.h>

namespace photon {
namespace {

#pragma pack(push, 1)
struct WirePacketLayout {
    std::uint16_t magic;
    std::uint8_t version;
    std::uint8_t msg_type;
    std::array<std::uint8_t, kMacSize> mac;
    std::uint32_t counter;
    std::array<std::uint8_t, kPayloadSize> payload;
};
#pragma pack(pop)

std::uint16_t LoadLE16(const std::uint8_t* ptr)
{
    const std::uint16_t lo = ptr[0];
    const std::uint16_t hi = static_cast<std::uint16_t>(static_cast<std::uint16_t>(ptr[1]) << 8);
    return static_cast<std::uint16_t>(lo | hi);
}

std::uint32_t LoadLE32(const std::uint8_t* ptr)
{
    return static_cast<std::uint32_t>(ptr[0]) |
           (static_cast<std::uint32_t>(ptr[1]) << 8) |
           (static_cast<std::uint32_t>(ptr[2]) << 16) |
           (static_cast<std::uint32_t>(ptr[3]) << 24);
}

std::uint64_t LoadLE64(const std::uint8_t* ptr)
{
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<std::uint64_t>(ptr[i]) << (i * 8);
    }
    return value;
}

void StoreLE16(std::uint8_t* ptr, std::uint16_t value)
{
    ptr[0] = static_cast<std::uint8_t>(value & 0xffU);
    ptr[1] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
}

void StoreLE32(std::uint8_t* ptr, std::uint32_t value)
{
    ptr[0] = static_cast<std::uint8_t>(value & 0xffU);
    ptr[1] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
    ptr[2] = static_cast<std::uint8_t>((value >> 16) & 0xffU);
    ptr[3] = static_cast<std::uint8_t>((value >> 24) & 0xffU);
}

void StoreLE64(std::uint8_t* ptr, std::uint64_t value)
{
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        ptr[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffU);
    }
}

bool IsAllZero(std::span<const std::uint8_t> data)
{
    return std::all_of(data.begin(), data.end(), [](std::uint8_t b) { return b == 0; });
}

ParseError ValidatePayload(const Packet& packet)
{
    switch (packet.msg_type) {
    case MessageType::kSyn:
    case MessageType::kSynAck: {
        SynPayload syn{};
        if (!DecodeSynPayload(packet.payload, syn)) {
            return ParseError::kInvalidReservedBits;
        }
        if (syn.version_cur < syn.version_min) {
            return ParseError::kInvalidVersionRange;
        }
        return ParseError::kNone;
    }
    case MessageType::kKeepalive:
    case MessageType::kDisconnect:
        if (!IsAllZero(packet.payload)) {
            return ParseError::kInvalidReservedBits;
        }
        return ParseError::kNone;
    case MessageType::kPing:
    case MessageType::kPong:
        return ParseError::kNone;
    case MessageType::kBlockChunk: {
        BlockChunkPayload chunk{};
        if (!DecodeBlockChunkPayload(packet.payload, chunk)) {
            return ParseError::kInvalidChunkLength;
        }
        if (chunk.flags != 0) {
            return ParseError::kInvalidReservedBits;
        }
        if (chunk.chunk_id > kMaxChunkId) {
            return ParseError::kInvalidChunkId;
        }
        if (chunk.data_len > kFecChunkSize) {
            return ParseError::kInvalidChunkLength;
        }
        return ParseError::kNone;
    }
    case MessageType::kBlockHeader: {
        BlockHeaderPayload header{};
        if (!DecodeBlockHeaderPayload(packet.payload, header)) {
            return ParseError::kInvalidReservedBits;
        }
        return ParseError::kNone;
    }
    }
    return ParseError::kUnknownMessageType;
}

} // namespace

static_assert(kPacketSize == 1232);
static_assert(kPacketSize + kNetworkHeaderSize <= kIpv6MinMtu);
static_assert(kPayloadSize == 1208);
static_assert(kFecChunkSize == 1194);
static_assert(kPayloadOffset + kPayloadSize == kPacketSize);
static_assert(sizeof(WirePacketLayout) == kPacketSize);
static_assert(sizeof(WirePacketLayout) + kNetworkHeaderSize <= kIpv6MinMtu);

const char* ParseErrorString(ParseError error)
{
    switch (error) {
    case ParseError::kNone:
        return "ok";
    case ParseError::kInvalidPacketSize:
        return "invalid packet size";
    case ParseError::kInvalidMagic:
        return "invalid packet magic";
    case ParseError::kUnsupportedVersion:
        return "unsupported protocol version";
    case ParseError::kUnknownMessageType:
        return "unknown message type";
    case ParseError::kInvalidReservedBits:
        return "reserved bits must be zero";
    case ParseError::kInvalidVersionRange:
        return "invalid version range";
    case ParseError::kInvalidChunkId:
        return "invalid chunk id";
    case ParseError::kInvalidChunkLength:
        return "invalid chunk data length";
    }
    return "unknown parse error";
}

bool IsKnownMessageType(std::uint8_t raw_type)
{
    switch (static_cast<MessageType>(raw_type)) {
    case MessageType::kSyn:
    case MessageType::kSynAck:
    case MessageType::kKeepalive:
    case MessageType::kDisconnect:
    case MessageType::kBlockHeader:
    case MessageType::kBlockChunk:
    case MessageType::kPing:
    case MessageType::kPong:
        return true;
    }
    return false;
}

bool IsHandshakeMessage(MessageType msg_type)
{
    return msg_type == MessageType::kSyn || msg_type == MessageType::kSynAck;
}

Packet MakePacket(MessageType msg_type, std::uint32_t counter)
{
    Packet packet{};
    packet.msg_type = msg_type;
    packet.counter = counter;
    return packet;
}

std::array<std::uint8_t, kPacketSize> SerializePacket(const Packet& packet)
{
    std::array<std::uint8_t, kPacketSize> out{};

    StoreLE16(out.data(), packet.magic);
    out[2] = packet.version;
    out[3] = static_cast<std::uint8_t>(packet.msg_type);
    std::copy(packet.mac.begin(), packet.mac.end(), out.begin() + static_cast<std::ptrdiff_t>(kMacOffset));
    StoreLE32(out.data() + static_cast<std::ptrdiff_t>(kCounterOffset), packet.counter);
    std::copy(packet.payload.begin(), packet.payload.end(), out.begin() + static_cast<std::ptrdiff_t>(kPayloadOffset));

    return out;
}

PacketParseResult ParsePacket(std::span<const std::uint8_t> bytes)
{
    PacketParseResult result{};

    if (bytes.size() != kPacketSize) {
        result.error = ParseError::kInvalidPacketSize;
        return result;
    }

    Packet packet{};
    packet.magic = LoadLE16(bytes.data());
    if (packet.magic != kProtocolMagic) {
        result.error = ParseError::kInvalidMagic;
        return result;
    }

    packet.version = bytes[2];
    if (packet.version != kProtocolVersion) {
        result.error = ParseError::kUnsupportedVersion;
        return result;
    }

    const std::uint8_t raw_type = bytes[3];
    if (!IsKnownMessageType(raw_type)) {
        result.error = ParseError::kUnknownMessageType;
        return result;
    }
    packet.msg_type = static_cast<MessageType>(raw_type);

    std::copy_n(bytes.data() + static_cast<std::ptrdiff_t>(kMacOffset), kMacSize, packet.mac.begin());
    packet.counter = LoadLE32(bytes.data() + static_cast<std::ptrdiff_t>(kCounterOffset));
    std::copy_n(bytes.data() + static_cast<std::ptrdiff_t>(kPayloadOffset), kPayloadSize, packet.payload.begin());

    const ParseError payload_error = ValidatePayload(packet);
    if (payload_error != ParseError::kNone) {
        result.error = payload_error;
        return result;
    }

    result.packet = packet;
    return result;
}

void EncodeSynPayload(const SynPayload& payload, std::array<std::uint8_t, kPayloadSize>& out_payload)
{
    out_payload.fill(0);
    out_payload[0] = payload.version_min;
    out_payload[1] = payload.version_cur;
    StoreLE16(out_payload.data() + 2, payload.reserved);
    StoreLE64(out_payload.data() + 4, payload.session_id);
    StoreLE64(out_payload.data() + 12, payload.feature_flags);
    StoreLE64(out_payload.data() + 20, payload.peer_id);
}

bool DecodeSynPayload(std::span<const std::uint8_t> payload, SynPayload& out_payload)
{
    if (payload.size() != kPayloadSize) {
        return false;
    }

    out_payload.version_min = payload[0];
    out_payload.version_cur = payload[1];
    out_payload.reserved = LoadLE16(payload.data() + 2);
    out_payload.session_id = LoadLE64(payload.data() + 4);
    out_payload.feature_flags = LoadLE64(payload.data() + 12);
    out_payload.peer_id = LoadLE64(payload.data() + 20);

    if (out_payload.reserved != 0) {
        return false;
    }

    return IsAllZero(payload.subspan(28));
}

void EncodeBlockHeaderPayload(const BlockHeaderPayload& payload, std::array<std::uint8_t, kPayloadSize>& out_payload)
{
    out_payload.fill(0);
    StoreLE64(out_payload.data(), payload.block_hash_prefix);
    StoreLE64(out_payload.data() + 8, payload.original_size);
    StoreLE16(out_payload.data() + 16, payload.data_chunks);
    StoreLE16(out_payload.data() + 18, payload.coding_group_count);
}

bool DecodeBlockHeaderPayload(std::span<const std::uint8_t> payload, BlockHeaderPayload& out_payload)
{
    if (payload.size() != kPayloadSize) {
        return false;
    }

    out_payload.block_hash_prefix = LoadLE64(payload.data());
    out_payload.original_size = LoadLE64(payload.data() + 8);
    out_payload.data_chunks = LoadLE16(payload.data() + 16);
    out_payload.coding_group_count = LoadLE16(payload.data() + 18);

    return IsAllZero(payload.subspan(20));
}

void EncodeBlockChunkPayload(const BlockChunkPayload& payload, std::array<std::uint8_t, kPayloadSize>& out_payload)
{
    out_payload.fill(0);
    StoreLE64(out_payload.data(), payload.block_hash_prefix);
    StoreLE16(out_payload.data() + 8, payload.coding_group_id);
    out_payload[10] = payload.chunk_id;
    out_payload[11] = payload.flags;
    StoreLE16(out_payload.data() + 12, payload.data_len);
    std::copy(payload.chunk_data.begin(), payload.chunk_data.end(), out_payload.begin() + 14);
}

bool DecodeBlockChunkPayload(std::span<const std::uint8_t> payload, BlockChunkPayload& out_payload)
{
    if (payload.size() != kPayloadSize) {
        return false;
    }

    out_payload.block_hash_prefix = LoadLE64(payload.data());
    out_payload.coding_group_id = LoadLE16(payload.data() + 8);
    out_payload.chunk_id = payload[10];
    out_payload.flags = payload[11];
    out_payload.data_len = LoadLE16(payload.data() + 12);
    std::copy_n(payload.data() + 14, kFecChunkSize, out_payload.chunk_data.begin());

    return true;
}

static bool ComputePacketMacWithContext(std::span<const std::uint8_t> packet_bytes,
                                        std::span<const std::uint8_t> key,
                                        std::span<const std::uint8_t> session_context,
                                        std::array<std::uint8_t, kMacSize>& out_mac)
{
    out_mac.fill(0);
    if (packet_bytes.size() != kPacketSize) {
        return false;
    }
    if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return false;
    }

    if (session_context.size() > sizeof(std::uint64_t)) {
        return false;
    }

    std::array<std::uint8_t, sizeof(std::uint64_t) + kMacSignedBytes> signed_data{};
    std::size_t signed_data_size = 0;
    std::copy(session_context.begin(), session_context.end(), signed_data.begin());
    signed_data_size += session_context.size();
    std::copy_n(packet_bytes.data(), 4, signed_data.begin() + static_cast<std::ptrdiff_t>(signed_data_size));
    signed_data_size += 4;
    std::copy_n(packet_bytes.data() + static_cast<std::ptrdiff_t>(kCounterOffset),
                kPacketSize - kCounterOffset,
                signed_data.begin() + static_cast<std::ptrdiff_t>(signed_data_size));
    signed_data_size += kPacketSize - kCounterOffset;

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    const auto* key_ptr = key.empty() ? reinterpret_cast<const unsigned char*>("") : key.data();
    if (HMAC(EVP_sha256(),
             key_ptr,
             static_cast<int>(key.size()),
             signed_data.data(),
             signed_data_size,
             digest.data(),
             &digest_len) == nullptr) {
        return false;
    }
    if (digest_len < kMacSize) {
        return false;
    }

    std::copy_n(digest.begin(), kMacSize, out_mac.begin());
    return true;
}

bool ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                      std::span<const std::uint8_t> key,
                      std::array<std::uint8_t, kMacSize>& out_mac)
{
    return ComputePacketMacWithContext(packet_bytes, key, {}, out_mac);
}

bool ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                      std::span<const std::uint8_t> key,
                      std::uint64_t session_id,
                      std::array<std::uint8_t, kMacSize>& out_mac)
{
    std::array<std::uint8_t, sizeof(session_id)> session_context{};
    StoreLE64(session_context.data(), session_id);
    return ComputePacketMacWithContext(packet_bytes, key, session_context, out_mac);
}

std::array<std::uint8_t, kMacSize> ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                                                    std::span<const std::uint8_t> key)
{
    std::array<std::uint8_t, kMacSize> mac{};
    (void)ComputePacketMac(packet_bytes, key, mac);
    return mac;
}

std::array<std::uint8_t, kMacSize> ComputePacketMac(std::span<const std::uint8_t> packet_bytes,
                                                    std::span<const std::uint8_t> key,
                                                    std::uint64_t session_id)
{
    std::array<std::uint8_t, kMacSize> mac{};
    (void)ComputePacketMac(packet_bytes, key, session_id, mac);
    return mac;
}

bool VerifyPacketMac(std::span<const std::uint8_t> packet_bytes, std::span<const std::uint8_t> key)
{
    if (packet_bytes.size() != kPacketSize) {
        return false;
    }

    std::array<std::uint8_t, kMacSize> expected{};
    if (!ComputePacketMac(packet_bytes, key, expected)) {
        return false;
    }
    return CRYPTO_memcmp(expected.data(), packet_bytes.data() + static_cast<std::ptrdiff_t>(kMacOffset), kMacSize) == 0;
}

bool VerifyPacketMac(std::span<const std::uint8_t> packet_bytes,
                     std::span<const std::uint8_t> key,
                     std::uint64_t session_id)
{
    if (packet_bytes.size() != kPacketSize) {
        return false;
    }

    std::array<std::uint8_t, kMacSize> expected{};
    if (!ComputePacketMac(packet_bytes, key, session_id, expected)) {
        return false;
    }
    return CRYPTO_memcmp(expected.data(), packet_bytes.data() + static_cast<std::ptrdiff_t>(kMacOffset), kMacSize) == 0;
}

void AttachPacketMac(Packet& packet, std::span<const std::uint8_t> key)
{
    const auto bytes = SerializePacket(packet);
    packet.mac = ComputePacketMac(bytes, key);
}

void AttachPacketMac(Packet& packet, std::span<const std::uint8_t> key, std::uint64_t session_id)
{
    const auto bytes = SerializePacket(packet);
    packet.mac = ComputePacketMac(bytes, key, session_id);
}

} // namespace photon
