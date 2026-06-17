#include <protocol.h>

#include <test_harness.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace photon {

void TestConstants()
{
    CHECK(kPacketSize == 1232);
    CHECK(kPayloadSize == 1208);
    CHECK(kFecChunkSize == 1194);
    CHECK(kPacketSize + kNetworkHeaderSize <= kIpv6MinMtu);
}

void TestRoundTripSerialization()
{
    Packet packet = MakePacket(MessageType::kPing, 41);
    for (std::size_t i = 0; i < packet.payload.size(); ++i) {
        packet.payload[i] = static_cast<std::uint8_t>(i % 251);
    }

    const auto bytes = SerializePacket(packet);
    const auto parsed = ParsePacket(bytes);
    CHECK(parsed.ok());
    if (!parsed.ok()) {
        return;
    }

    CHECK(parsed.packet.magic == packet.magic);
    CHECK(parsed.packet.version == packet.version);
    CHECK(parsed.packet.msg_type == packet.msg_type);
    CHECK(parsed.packet.counter == packet.counter);
    CHECK(parsed.packet.payload == packet.payload);
}

void TestMacVerification()
{
    Packet packet = MakePacket(MessageType::kBlockHeader, 99);
    packet.payload[0] = 0x42;
    packet.payload[17] = 0x11;
    const std::array<std::uint8_t, 8> key{1, 2, 3, 4, 5, 6, 7, 8};

    AttachPacketMac(packet, key);
    auto bytes = SerializePacket(packet);
    CHECK(VerifyPacketMac(bytes, key));

    bytes[100] ^= 0x01;
    CHECK(!VerifyPacketMac(bytes, key));

    const std::array<std::uint8_t, 8> wrong_key{9, 9, 9, 9, 9, 9, 9, 9};
    CHECK(!VerifyPacketMac(SerializePacket(packet), wrong_key));
}

void TestMacFailureIsFailClosed()
{
    Packet packet = MakePacket(MessageType::kBlockHeader, 1234);
    packet.mac.fill(0);
    const auto bytes = SerializePacket(packet);

    const std::array<std::uint8_t, 1> tiny_key{0x01};
    const std::span<const std::uint8_t> oversized_key(
        tiny_key.data(),
        static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1U);

    CHECK(!VerifyPacketMac(bytes, oversized_key));
}

void TestPacketValidationFailures()
{
    Packet packet = MakePacket(MessageType::kBlockHeader, 5);
    auto bytes = SerializePacket(packet);

    bytes[3] = 0xff;
    CHECK(ParsePacket(bytes).error == ParseError::kUnknownMessageType);

    bytes = SerializePacket(packet);
    bytes[2] = kProtocolVersion + 1;
    CHECK(ParsePacket(bytes).error == ParseError::kUnsupportedVersion);

    bytes = SerializePacket(packet);
    bytes[0] = 0;
    bytes[1] = 0;
    CHECK(ParsePacket(bytes).error == ParseError::kInvalidMagic);

    const std::vector<std::uint8_t> short_bytes(kPacketSize - 1, 0);
    CHECK(ParsePacket(short_bytes).error == ParseError::kInvalidPacketSize);
}

void TestKeepaliveReservedPayload()
{
    Packet packet = MakePacket(MessageType::kKeepalive, 7);
    packet.payload[10] = 1;
    CHECK(ParsePacket(SerializePacket(packet)).error == ParseError::kInvalidReservedBits);

    packet.payload.fill(0);
    CHECK(ParsePacket(SerializePacket(packet)).ok());
}

void TestBlockChunkValidation()
{
    BlockChunkPayload chunk{};
    chunk.block_hash_prefix = 0x8877665544332211ULL;
    chunk.coding_group_id = 3;
    chunk.chunk_id = 42;
    chunk.flags = 0;
    chunk.data_len = static_cast<std::uint16_t>(kFecChunkSize);
    for (std::size_t i = 0; i < chunk.chunk_data.size(); ++i) {
        chunk.chunk_data[i] = static_cast<std::uint8_t>(i % 241);
    }

    Packet packet = MakePacket(MessageType::kBlockChunk, 12);
    EncodeBlockChunkPayload(chunk, packet.payload);

    auto parsed = ParsePacket(SerializePacket(packet));
    CHECK(parsed.ok());
    if (parsed.ok()) {
        BlockChunkPayload decoded{};
        CHECK(DecodeBlockChunkPayload(parsed.packet.payload, decoded));
        CHECK(decoded.block_hash_prefix == chunk.block_hash_prefix);
        CHECK(decoded.coding_group_id == chunk.coding_group_id);
        CHECK(decoded.chunk_id == chunk.chunk_id);
        CHECK(decoded.flags == chunk.flags);
        CHECK(decoded.data_len == chunk.data_len);
        CHECK(decoded.chunk_data == chunk.chunk_data);
    }

    chunk.flags = 1;
    EncodeBlockChunkPayload(chunk, packet.payload);
    CHECK(ParsePacket(SerializePacket(packet)).error == ParseError::kInvalidReservedBits);

    chunk.flags = 0;
    chunk.chunk_id = 255;
    EncodeBlockChunkPayload(chunk, packet.payload);
    CHECK(ParsePacket(SerializePacket(packet)).error == ParseError::kInvalidChunkId);

    chunk.chunk_id = 17;
    chunk.data_len = static_cast<std::uint16_t>(kFecChunkSize + 1);
    EncodeBlockChunkPayload(chunk, packet.payload);
    CHECK(ParsePacket(SerializePacket(packet)).error == ParseError::kInvalidChunkLength);
}

void TestBlockHeaderPayloadEncoding()
{
    BlockHeaderPayload header{};
    header.block_hash_prefix = 0x0102030405060708ULL;
    header.original_size = 1'000'000;
    header.data_chunks = 212;
    header.coding_group_count = 9;

    Packet packet = MakePacket(MessageType::kBlockHeader, 77);
    EncodeBlockHeaderPayload(header, packet.payload);

    const auto parsed = ParsePacket(SerializePacket(packet));
    CHECK(parsed.ok());
    if (!parsed.ok()) {
        return;
    }

    BlockHeaderPayload decoded{};
    CHECK(DecodeBlockHeaderPayload(parsed.packet.payload, decoded));
    CHECK(decoded.block_hash_prefix == header.block_hash_prefix);
    CHECK(decoded.original_size == header.original_size);
    CHECK(decoded.data_chunks == header.data_chunks);
    CHECK(decoded.coding_group_count == header.coding_group_count);

    auto bad = packet.payload;
    bad[24] = 0x01;
    CHECK(!DecodeBlockHeaderPayload(bad, decoded));
}

void TestSynValidation()
{
    SynPayload syn{};
    syn.version_min = 1;
    syn.version_cur = 1;
    syn.session_id = 100;
    syn.feature_flags = 0x04;
    syn.peer_id = 0x99887766;

    Packet packet = MakePacket(MessageType::kSyn, 123);
    EncodeSynPayload(syn, packet.payload);
    CHECK(ParsePacket(SerializePacket(packet)).ok());

    syn.reserved = 1;
    EncodeSynPayload(syn, packet.payload);
    CHECK(ParsePacket(SerializePacket(packet)).error == ParseError::kInvalidReservedBits);

    syn.reserved = 0;
    syn.version_min = 2;
    syn.version_cur = 1;
    EncodeSynPayload(syn, packet.payload);
    CHECK(ParsePacket(SerializePacket(packet)).error == ParseError::kInvalidVersionRange);

    std::array<std::uint8_t, kPayloadSize> raw_payload{};
    EncodeSynPayload(SynPayload{}, raw_payload);
    raw_payload[32] = 1;
    SynPayload decoded{};
    CHECK(!DecodeSynPayload(raw_payload, decoded));
}

void TestSessionBoundMac()
{
    const std::array<std::uint8_t, 32> key{
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    };

    Packet packet = MakePacket(MessageType::kKeepalive, 44);
    AttachPacketMac(packet, key, 1001);
    const auto bytes = SerializePacket(packet);

    CHECK(VerifyPacketMac(bytes, key, 1001));
    CHECK(!VerifyPacketMac(bytes, key, 1002));
    CHECK(!VerifyPacketMac(bytes, key));
}

} // namespace photon

int main()
{
    photon::TestConstants();
    photon::TestRoundTripSerialization();
    photon::TestMacVerification();
    photon::TestMacFailureIsFailClosed();
    photon::TestPacketValidationFailures();
    photon::TestKeepaliveReservedPayload();
    photon::TestBlockChunkValidation();
    photon::TestBlockHeaderPayloadEncoding();
    photon::TestSynValidation();
    photon::TestSessionBoundMac();
    return photon::test::Finish();
}
