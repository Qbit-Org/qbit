#include <fec.h>

#include <vendor/cm256.h>
#include <vendor/wirehair/wirehair.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace photon::fec {
namespace {

template <typename T>
constexpr T DivCeil(T numerator, T denominator)
{
    return (numerator + denominator - 1) / denominator;
}

void ValidateParameters(const Parameters& params)
{
    if (params.total_chunks != FEC_TOTAL_CHUNKS) {
        throw std::invalid_argument("total_chunks must be 255");
    }
    if (params.data_chunks < 2 || params.data_chunks >= params.total_chunks) {
        throw std::invalid_argument("data_chunks must be in [2, 254]");
    }
    if (params.parity_chunks != params.total_chunks - params.data_chunks) {
        throw std::invalid_argument("parity_chunks must equal total_chunks - data_chunks");
    }
}

struct WirehairCodecDeleter {
    void operator()(WirehairCodec_t* codec) const
    {
        if (codec != nullptr) {
            wirehair_free(codec);
        }
    }
};

using WirehairCodecPtr = std::unique_ptr<WirehairCodec_t, WirehairCodecDeleter>;

void EnsureCodecInit()
{
    static const bool initialized = [] {
        if (cm256_init() != 0) {
            throw std::runtime_error("cm256_init failed");
        }
        if (wirehair_init() != Wirehair_Success) {
            throw std::runtime_error("wirehair_init failed");
        }
        return true;
    }();

    (void)initialized;
}

std::vector<std::uint8_t> BuildGroupPayload(
    std::span<const std::uint8_t> block,
    std::size_t group_index,
    std::size_t group_payload_bytes)
{
    std::vector<std::uint8_t> payload(group_payload_bytes, 0U);

    const std::size_t group_offset = group_index * group_payload_bytes;
    if (group_offset >= block.size()) {
        return payload;
    }

    const std::size_t bytes_to_copy = std::min(group_payload_bytes, block.size() - group_offset);
    std::memcpy(payload.data(), block.data() + group_offset, bytes_to_copy);
    return payload;
}

void AppendCm256Chunks(
    std::uint16_t group_id,
    std::uint16_t data_chunks,
    std::span<const std::uint8_t> group_payload,
    std::vector<Chunk>& out_chunks)
{
    if (data_chunks > CM256_MAX_DATA_CHUNKS) {
        throw std::runtime_error("cm256 mode requires data_chunks <= 27");
    }

    std::array<cm256_block, CM256_MAX_DATA_CHUNKS> originals{};
    for (std::uint16_t i = 0; i < data_chunks; ++i) {
        originals[i].Block = const_cast<std::uint8_t*>(group_payload.data() + (i * FEC_CHUNK_SIZE));
        originals[i].Index = static_cast<unsigned char>(i);
    }

    cm256_encoder_params params{
        static_cast<int>(data_chunks),
        static_cast<int>(FEC_TOTAL_CHUNKS - data_chunks),
        static_cast<int>(FEC_CHUNK_SIZE),
    };

    for (std::uint16_t chunk_id = 0; chunk_id < FEC_TOTAL_CHUNKS; ++chunk_id) {
        Chunk chunk;
        chunk.coding_group_id = group_id;
        chunk.chunk_id = static_cast<std::uint8_t>(chunk_id);

        if (chunk_id < data_chunks) {
            std::memcpy(
                chunk.bytes.data(),
                group_payload.data() + (chunk_id * FEC_CHUNK_SIZE),
                FEC_CHUNK_SIZE);
        } else {
            cm256_encode_block(params, originals.data(), static_cast<int>(chunk_id), chunk.bytes.data());
        }

        out_chunks.push_back(std::move(chunk));
    }
}

void AppendWirehairChunks(
    std::uint16_t group_id,
    std::span<const std::uint8_t> group_payload,
    std::vector<Chunk>& out_chunks)
{
    WirehairCodecPtr codec(
        wirehair_encoder_create(
            nullptr,
            group_payload.data(),
            static_cast<std::uint64_t>(group_payload.size()),
            static_cast<std::uint32_t>(FEC_CHUNK_SIZE)));

    if (!codec) {
        throw std::runtime_error("wirehair_encoder_create failed");
    }

    for (std::uint16_t chunk_id = 0; chunk_id < FEC_TOTAL_CHUNKS; ++chunk_id) {
        Chunk chunk;
        chunk.coding_group_id = group_id;
        chunk.chunk_id = static_cast<std::uint8_t>(chunk_id);

        std::uint32_t written_bytes = 0;
        const WirehairResult result = wirehair_encode(
            codec.get(),
            chunk_id,
            chunk.bytes.data(),
            static_cast<std::uint32_t>(FEC_CHUNK_SIZE),
            &written_bytes);

        if (result != Wirehair_Success) {
            throw std::runtime_error("wirehair_encode failed");
        }

        if (written_bytes < FEC_CHUNK_SIZE) {
            std::memset(chunk.bytes.data() + written_bytes, 0, FEC_CHUNK_SIZE - written_bytes);
        }

        out_chunks.push_back(std::move(chunk));
    }
}

} // namespace

Parameters Parameters::FromDataChunkCount(std::uint16_t data_chunks)
{
    Parameters params{};
    params.data_chunks = data_chunks;
    params.total_chunks = FEC_TOTAL_CHUNKS;
    params.parity_chunks = FEC_TOTAL_CHUNKS - data_chunks;
    params.overhead_ratio = static_cast<double>(params.total_chunks) / static_cast<double>(params.data_chunks);
    ValidateParameters(params);
    return params;
}

Parameters Parameters::FromOverheadRatio(double overhead_ratio)
{
    if (!std::isfinite(overhead_ratio) || overhead_ratio <= 1.0) {
        throw std::invalid_argument("overhead_ratio must be finite and > 1.0");
    }

    const double exact_data_chunks = static_cast<double>(FEC_TOTAL_CHUNKS) / overhead_ratio;
    const auto rounded_data_chunks = static_cast<std::uint16_t>(std::floor(exact_data_chunks));
    const auto clamped_data_chunks = std::clamp<std::uint16_t>(
        rounded_data_chunks,
        2,
        static_cast<std::uint16_t>(FEC_TOTAL_CHUNKS - 1));

    return FromDataChunkCount(clamped_data_chunks);
}

Encoder::Encoder(Parameters params)
    : m_params(params)
{
    ValidateParameters(m_params);
    EnsureCodecInit();
}

EncodedBlock Encoder::Encode(std::span<const std::uint8_t> block) const
{
    EncodedBlock encoded{};
    encoded.params = m_params;
    encoded.original_size = block.size();

    if (block.empty()) {
        return encoded;
    }

    const std::size_t group_payload_bytes =
        static_cast<std::size_t>(m_params.data_chunks) * FEC_CHUNK_SIZE;
    const std::size_t group_count = DivCeil(block.size(), group_payload_bytes);

    if (group_count > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("too many coding groups for uint16 coding_group_id");
    }

    encoded.coding_group_count = static_cast<std::uint16_t>(group_count);
    encoded.chunks.reserve(group_count * FEC_TOTAL_CHUNKS);

    for (std::size_t group_index = 0; group_index < group_count; ++group_index) {
        std::vector<std::uint8_t> payload = BuildGroupPayload(block, group_index, group_payload_bytes);

        if (m_params.data_chunks <= CM256_MAX_DATA_CHUNKS) {
            AppendCm256Chunks(
                static_cast<std::uint16_t>(group_index),
                m_params.data_chunks,
                payload,
                encoded.chunks);
        } else {
            AppendWirehairChunks(
                static_cast<std::uint16_t>(group_index),
                payload,
                encoded.chunks);
        }
    }

    return encoded;
}

class Decoder::Impl {
public:
    Impl(Parameters params, std::size_t original_size)
        : m_params(params)
        , m_original_size(original_size)
        , m_group_payload_bytes(static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE)
    {
        ValidateParameters(m_params);
        EnsureCodecInit();

        if (m_original_size == 0) {
            return;
        }

        const std::size_t group_count = DivCeil(m_original_size, m_group_payload_bytes);
        if (group_count > std::numeric_limits<std::uint16_t>::max()) {
            throw std::runtime_error("too many coding groups for uint16 coding_group_id");
        }

        m_group_count = static_cast<std::uint16_t>(group_count);
        m_groups.resize(m_group_count);

        const bool use_cm256 = m_params.data_chunks <= CM256_MAX_DATA_CHUNKS;

        for (GroupState& group : m_groups) {
            group.use_cm256 = use_cm256;
            group.seen.fill(false);

            if (!group.use_cm256) {
                group.codec.reset(
                    wirehair_decoder_create(
                        nullptr,
                        static_cast<std::uint64_t>(m_group_payload_bytes),
                        static_cast<std::uint32_t>(FEC_CHUNK_SIZE)));

                if (!group.codec) {
                    throw std::runtime_error("wirehair_decoder_create failed");
                }
            } else {
                group.chunk_data.reserve(m_params.data_chunks);
                group.chunk_ids.reserve(m_params.data_chunks);
            }
        }
    }

    bool AddChunk(
        std::uint16_t coding_group_id,
        std::uint8_t chunk_id,
        std::span<const std::uint8_t> bytes)
    {
        if (bytes.size() != FEC_CHUNK_SIZE) {
            return false;
        }

        if (coding_group_id >= m_group_count || chunk_id >= FEC_TOTAL_CHUNKS) {
            return false;
        }

        GroupState& group = m_groups[coding_group_id];

        if (group.complete) {
            return true;
        }

        if (group.seen[chunk_id]) {
            return true;
        }

        group.seen[chunk_id] = true;

        if (group.use_cm256) {
            group.chunk_data.emplace_back();
            std::memcpy(group.chunk_data.back().data(), bytes.data(), FEC_CHUNK_SIZE);
            group.chunk_ids.push_back(chunk_id);

            if (group.chunk_ids.size() >= m_params.data_chunks) {
                if (!TryCompleteCm256Group(group)) {
                    return false;
                }
            }

            return true;
        }

        if (!group.codec) {
            return false;
        }

        const WirehairResult result =
            wirehair_decode(group.codec.get(), chunk_id, bytes.data(), static_cast<std::uint32_t>(FEC_CHUNK_SIZE));

        if (result == Wirehair_Success) {
            group.complete = true;
            return true;
        }

        return result == Wirehair_NeedMore;
    }

    [[nodiscard]] bool IsComplete() const
    {
        return AllGroupsComplete();
    }

    std::optional<std::vector<std::uint8_t>> Reconstruct() const
    {
        if (!AllGroupsComplete()) {
            return std::nullopt;
        }

        std::vector<std::uint8_t> output(m_original_size, 0U);
        if (m_original_size == 0) {
            return output;
        }

        std::vector<std::uint8_t> recovered_group(m_group_payload_bytes, 0U);

        for (std::size_t group_index = 0; group_index < m_group_count; ++group_index) {
            const GroupState& group = m_groups[group_index];
            const std::uint8_t* source_ptr = nullptr;

            if (group.use_cm256) {
                if (group.decoded_bytes.size() != m_group_payload_bytes) {
                    return std::nullopt;
                }
                source_ptr = group.decoded_bytes.data();
            } else {
                if (!group.codec) {
                    return std::nullopt;
                }

                const WirehairResult result = wirehair_recover(
                    group.codec.get(),
                    recovered_group.data(),
                    static_cast<std::uint64_t>(m_group_payload_bytes));
                if (result != Wirehair_Success) {
                    return std::nullopt;
                }
                source_ptr = recovered_group.data();
            }

            const std::size_t output_offset = group_index * m_group_payload_bytes;
            const std::size_t bytes_to_copy = std::min(m_group_payload_bytes, m_original_size - output_offset);
            std::memcpy(output.data() + output_offset, source_ptr, bytes_to_copy);
        }

        return output;
    }

private:
    struct GroupState {
        std::array<bool, FEC_TOTAL_CHUNKS> seen{};
        std::vector<std::array<std::uint8_t, FEC_CHUNK_SIZE>> chunk_data{};
        std::vector<std::uint8_t> chunk_ids{};
        std::vector<std::uint8_t> decoded_bytes{};
        bool complete{false};
        bool use_cm256{false};
        WirehairCodecPtr codec{};
    };

    bool TryCompleteCm256Group(GroupState& group) const
    {
        if (group.complete) {
            return true;
        }

        const std::size_t required_chunks = m_params.data_chunks;
        if (group.chunk_ids.size() < required_chunks) {
            return true;
        }

        const cm256_encoder_params params{
            static_cast<int>(m_params.data_chunks),
            static_cast<int>(m_params.parity_chunks),
            static_cast<int>(FEC_CHUNK_SIZE),
        };

        const std::size_t window_count = group.chunk_ids.size() - required_chunks + 1;
        for (std::size_t window_start = 0; window_start < window_count; ++window_start) {
            std::array<cm256_block, CM256_MAX_DATA_CHUNKS> decode_blocks{};
            std::array<std::array<std::uint8_t, FEC_CHUNK_SIZE>, CM256_MAX_DATA_CHUNKS> decode_storage{};

            for (std::size_t i = 0; i < required_chunks; ++i) {
                const std::size_t source_index = window_start + i;
                decode_storage[i] = group.chunk_data[source_index];
                decode_blocks[i].Block = decode_storage[i].data();
                decode_blocks[i].Index = group.chunk_ids[source_index];
            }

            if (cm256_decode(params, decode_blocks.data()) != 0) {
                continue;
            }

            std::sort(
                decode_blocks.begin(),
                decode_blocks.begin() + static_cast<std::ptrdiff_t>(required_chunks),
                [](const cm256_block& left, const cm256_block& right) {
                    return left.Index < right.Index;
                });

            for (std::size_t i = 0; i < required_chunks; ++i) {
                if (decode_blocks[i].Index != i) {
                    return false;
                }
            }

            group.decoded_bytes.resize(m_group_payload_bytes);
            for (std::size_t i = 0; i < required_chunks; ++i) {
                std::memcpy(
                    group.decoded_bytes.data() + (i * FEC_CHUNK_SIZE),
                    decode_blocks[i].Block,
                    FEC_CHUNK_SIZE);
            }

            std::vector<std::array<std::uint8_t, FEC_CHUNK_SIZE>> empty_chunk_data;
            std::vector<std::uint8_t> empty_chunk_ids;
            group.chunk_data.swap(empty_chunk_data);
            group.chunk_ids.swap(empty_chunk_ids);
            group.complete = true;
            return true;
        }

        return false;
    }

    [[nodiscard]] bool AllGroupsComplete() const
    {
        for (const GroupState& group : m_groups) {
            if (!group.complete) {
                return false;
            }
        }
        return true;
    }

    Parameters m_params;
    std::size_t m_original_size{0};
    std::size_t m_group_payload_bytes{0};
    std::uint16_t m_group_count{0};
    std::vector<GroupState> m_groups{};
};

Decoder::Decoder(Parameters params, std::size_t original_size)
    : m_impl(std::make_unique<Impl>(params, original_size))
{
}

Decoder::~Decoder() = default;

Decoder::Decoder(Decoder&&) noexcept = default;

Decoder& Decoder::operator=(Decoder&&) noexcept = default;

bool Decoder::AddChunk(const Chunk& chunk)
{
    return AddChunk(
        chunk.coding_group_id,
        chunk.chunk_id,
        std::span<const std::uint8_t>(chunk.bytes.data(), chunk.bytes.size()));
}

bool Decoder::AddChunk(
    std::uint16_t coding_group_id,
    std::uint8_t chunk_id,
    std::span<const std::uint8_t> bytes)
{
    return m_impl->AddChunk(coding_group_id, chunk_id, bytes);
}

bool Decoder::IsComplete() const
{
    return m_impl->IsComplete();
}

std::optional<std::vector<std::uint8_t>> Decoder::Reconstruct() const
{
    return m_impl->Reconstruct();
}

} // namespace photon::fec
