#ifndef QBIT_PHOTON_SRC_FEC_H
#define QBIT_PHOTON_SRC_FEC_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace photon::fec {

constexpr std::size_t FEC_CHUNK_SIZE = 1194;
constexpr std::uint16_t FEC_TOTAL_CHUNKS = 255;
constexpr std::uint16_t CM256_MAX_DATA_CHUNKS = 27;

struct Parameters {
    double overhead_ratio{1.2};
    std::uint16_t data_chunks{213};
    std::uint16_t total_chunks{FEC_TOTAL_CHUNKS};
    std::uint16_t parity_chunks{42};

    static Parameters FromOverheadRatio(double overhead_ratio);
    static Parameters FromDataChunkCount(std::uint16_t data_chunks);
};

struct Chunk {
    std::uint16_t coding_group_id{0};
    std::uint8_t chunk_id{0};
    std::array<std::uint8_t, FEC_CHUNK_SIZE> bytes{};
};

struct EncodedBlock {
    Parameters params{};
    std::size_t original_size{0};
    std::uint16_t coding_group_count{0};
    std::vector<Chunk> chunks{};
};

class Encoder {
public:
    explicit Encoder(Parameters params);

    EncodedBlock Encode(std::span<const std::uint8_t> block) const;

private:
    Parameters m_params;
};

class Decoder {
public:
    Decoder(Parameters params, std::size_t original_size);
    ~Decoder();

    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;
    Decoder(Decoder&&) noexcept;
    Decoder& operator=(Decoder&&) noexcept;

    bool AddChunk(const Chunk& chunk);
    bool AddChunk(std::uint16_t coding_group_id, std::uint8_t chunk_id, std::span<const std::uint8_t> bytes);
    [[nodiscard]] bool IsComplete() const;
    std::optional<std::vector<std::uint8_t>> Reconstruct() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace photon::fec

#endif // QBIT_PHOTON_SRC_FEC_H
