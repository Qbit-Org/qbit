#include <protocol.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> bytes(data, size);
    const auto parsed = photon::ParsePacket(bytes);

    if (size == photon::kPacketSize) {
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = data[i];
        }
        (void)photon::VerifyPacketMac(bytes, key);

        if (parsed.ok() && parsed.packet.msg_type == photon::MessageType::kBlockChunk) {
            photon::BlockChunkPayload chunk{};
            (void)photon::DecodeBlockChunkPayload(parsed.packet.payload, chunk);
        }
    }

    return 0;
}

#ifndef PHOTON_WITH_LIBFUZZER
int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: photon_fuzz_protocol <input-file> [more-files...]\n";
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        std::ifstream in(argv[i], std::ios::binary);
        if (!in.is_open()) {
            std::cerr << "failed to open: " << argv[i] << '\n';
            return 1;
        }

        const std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)),
                                             std::istreambuf_iterator<char>());
        if (data.empty()) {
            continue;
        }
        (void)LLVMFuzzerTestOneInput(data.data(), data.size());
    }

    return 0;
}
#endif
