#include <fec.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <limits>
#include <unordered_set>
#include <vector>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace {

using photon::fec::Chunk;
using photon::fec::Decoder;
using photon::fec::EncodedBlock;
using photon::fec::Encoder;
using photon::fec::FEC_CHUNK_SIZE;
using photon::fec::FEC_TOTAL_CHUNKS;
using photon::fec::Parameters;

void Require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<std::uint8_t> RandomBytes(std::size_t size, std::uint64_t seed)
{
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<std::uint8_t> out(size);
    for (std::uint8_t& byte : out) {
        byte = static_cast<std::uint8_t>(dist(rng));
    }
    return out;
}

std::array<const Chunk*, FEC_TOTAL_CHUNKS> BuildGroupIndex(const EncodedBlock& encoded, std::uint16_t group_id)
{
    std::array<const Chunk*, FEC_TOTAL_CHUNKS> by_id{};
    by_id.fill(nullptr);

    for (const Chunk& chunk : encoded.chunks) {
        if (chunk.coding_group_id != group_id) {
            continue;
        }
        by_id[chunk.chunk_id] = &chunk;
    }

    return by_id;
}

void AssertRoundTrip(const Parameters& params, const std::vector<std::uint8_t>& block)
{
    Encoder encoder(params);
    EncodedBlock encoded = encoder.Encode(block);

    Require(encoded.original_size == block.size(), "original size mismatch in EncodedBlock");
    Require(!encoded.chunks.empty(), "expected encoded chunks");

    Decoder decoder(params, block.size());
    for (const Chunk& chunk : encoded.chunks) {
        Require(decoder.AddChunk(chunk), "AddChunk failed while replaying encoded stream");
    }

    Require(decoder.IsComplete(), "decoder did not complete");

    const auto recovered = decoder.Reconstruct();
    Require(recovered.has_value(), "decoder did not reconstruct");
    Require(*recovered == block, "decoded block mismatch");
}

void TestParameterMapping()
{
    const auto p12 = Parameters::FromOverheadRatio(1.2);
    const auto p135 = Parameters::FromOverheadRatio(1.35);
    const auto p15 = Parameters::FromOverheadRatio(1.5);

    Require(p12.data_chunks == 212 && p12.parity_chunks == 43, "1.2 ratio mapping mismatch");
    Require(p135.data_chunks == 188 && p135.parity_chunks == 67, "1.35 ratio mapping mismatch");
    Require(p15.data_chunks == 170 && p15.parity_chunks == 85, "1.5 ratio mapping mismatch");
}

void TestRoundTripCm256Mode()
{
    const auto params = Parameters::FromDataChunkCount(20);
    const auto block = RandomBytes((20 * FEC_CHUNK_SIZE) - 77, 0xA11CE);
    AssertRoundTrip(params, block);
}

void TestRoundTripWirehair2MB()
{
    const auto params = Parameters::FromOverheadRatio(1.2);
    const auto block = RandomBytes(2'000'000, 0xB10C);
    AssertRoundTrip(params, block);
}

void TestDeterministicThresholds()
{
    for (const double ratio : {1.2, 1.35, 1.5}) {
        const auto params = Parameters::FromOverheadRatio(ratio);
        const auto block = RandomBytes(
            static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE,
            static_cast<std::uint64_t>(ratio * 10'000));

        Encoder encoder(params);
        const EncodedBlock encoded = encoder.Encode(block);
        Require(encoded.coding_group_count == 1, "expected one coding group");

        const auto by_id = BuildGroupIndex(encoded, 0);
        for (std::size_t i = 0; i < FEC_TOTAL_CHUNKS; ++i) {
            Require(by_id[i] != nullptr, "missing chunk in encoded group");
        }

        Decoder should_decode(params, block.size());
        for (std::uint16_t data_id = 1; data_id < params.data_chunks; ++data_id) {
            Require(should_decode.AddChunk(*by_id[data_id]), "failed to add data chunk in decode case");
        }
        Require(should_decode.AddChunk(*by_id[params.data_chunks]), "failed to add parity chunk in decode case");
        Require(should_decode.AddChunk(*by_id[params.data_chunks + 1]), "failed to add parity chunk in decode case");
        Require(should_decode.IsComplete(), "decoder did not complete at N-K-1 loss");

        const auto decoded = should_decode.Reconstruct();
        Require(decoded.has_value(), "decoder reconstruction missing at N-K-1 loss");
        Require(*decoded == block, "decoder output mismatch at N-K-1 loss");

        Decoder should_fail(params, block.size());
        for (std::uint16_t data_id = 1; data_id < params.data_chunks; ++data_id) {
            Require(should_fail.AddChunk(*by_id[data_id]), "failed to add data chunk in failure case");
        }
        Require(!should_fail.IsComplete(), "decoder completed at N-K+1 loss");
        Require(!should_fail.Reconstruct().has_value(), "decoder reconstructed at N-K+1 loss");
    }
}

void TestProbabilisticNearLimit()
{
    constexpr int kTrials = 100;

    for (const double ratio : {1.2, 1.35, 1.5}) {
        const auto params = Parameters::FromOverheadRatio(ratio);
        const auto block = RandomBytes(
            static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE,
            static_cast<std::uint64_t>(ratio * 100'000));

        Encoder encoder(params);
        const EncodedBlock encoded = encoder.Encode(block);
        const auto by_id = BuildGroupIndex(encoded, 0);

        std::vector<std::uint16_t> ids(FEC_TOTAL_CHUNKS);
        std::iota(ids.begin(), ids.end(), 0);

        std::mt19937 rng(static_cast<std::uint32_t>(ratio * 1000));
        int successes = 0;

        for (int trial = 0; trial < kTrials; ++trial) {
            std::shuffle(ids.begin(), ids.end(), rng);

            std::unordered_set<std::uint16_t> dropped;
            dropped.reserve(params.parity_chunks);
            for (std::uint16_t i = 0; i < params.parity_chunks; ++i) {
                dropped.insert(ids[i]);
            }

            std::vector<std::uint16_t> kept;
            kept.reserve(params.data_chunks);
            for (const std::uint16_t id : ids) {
                if (dropped.count(id) == 0) {
                    kept.push_back(id);
                }
            }
            std::shuffle(kept.begin(), kept.end(), rng);

            Decoder decoder(params, block.size());
            bool add_ok = true;
            for (const std::uint16_t id : kept) {
                add_ok = decoder.AddChunk(*by_id[id]);
                if (!add_ok) {
                    break;
                }
            }

            if (!add_ok || !decoder.IsComplete()) {
                continue;
            }

            const auto recovered = decoder.Reconstruct();
            if (recovered.has_value() && *recovered == block) {
                ++successes;
            }
        }

        const double success_rate = static_cast<double>(successes) / static_cast<double>(kTrials);
        if (success_rate < 0.95) {
            std::ostringstream oss;
            oss << "near-limit success rate below 95% for ratio " << ratio
                << ": got " << success_rate;
            throw std::runtime_error(oss.str());
        }
    }
}

void TestPacketLossMatrix()
{
    const auto params = Parameters::FromOverheadRatio(1.2);
    const auto block = RandomBytes(
        static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE,
        0xFACEB00C);

    Encoder encoder(params);
    const EncodedBlock encoded = encoder.Encode(block);
    Require(encoded.coding_group_count == 1, "expected one coding group for packet-loss matrix");
    const auto by_id = BuildGroupIndex(encoded, 0);

    struct LossCase {
        std::string label;
        std::uint16_t dropped_chunks;
        bool expect_success;
    };

    const std::vector<LossCase> cases = {
        {"clean_0pct_loss", 0, true},
        {"loss_10pct", 26, true},
        {"loss_30pct", 77, false},
        {"loss_50pct", 128, false},
    };

    std::vector<std::uint16_t> ids(FEC_TOTAL_CHUNKS);
    std::iota(ids.begin(), ids.end(), 0);

    for (const LossCase& test_case : cases) {
        std::mt19937 rng(static_cast<std::uint32_t>(0x600D + test_case.dropped_chunks));
        std::shuffle(ids.begin(), ids.end(), rng);

        std::unordered_set<std::uint16_t> dropped;
        dropped.reserve(test_case.dropped_chunks);
        for (std::uint16_t i = 0; i < test_case.dropped_chunks; ++i) {
            dropped.insert(ids[i]);
        }

        std::vector<std::uint16_t> kept;
        kept.reserve(FEC_TOTAL_CHUNKS - test_case.dropped_chunks);
        for (const std::uint16_t id : ids) {
            if (dropped.count(id) == 0) {
                kept.push_back(id);
            }
        }
        std::shuffle(kept.begin(), kept.end(), rng);

        Decoder decoder(params, block.size());
        bool add_ok = true;
        for (const std::uint16_t id : kept) {
            add_ok = decoder.AddChunk(*by_id[id]);
            if (!add_ok) {
                break;
            }
        }

        bool recovered = false;
        if (add_ok && decoder.IsComplete()) {
            const auto reconstructed = decoder.Reconstruct();
            recovered = reconstructed.has_value() && *reconstructed == block;
        }

        if (test_case.expect_success) {
            Require(recovered, test_case.label + " expected successful reconstruction");
        } else {
            Require(!recovered, test_case.label + " expected reconstruction failure");
        }
    }
}

void TestCorruptedPacketHandling()
{
    const auto params = Parameters::FromOverheadRatio(1.2);
    const auto block = RandomBytes(
        static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE,
        0xBADF00D);

    Encoder encoder(params);
    const EncodedBlock encoded = encoder.Encode(block);
    Require(encoded.coding_group_count == 1, "expected one coding group for corruption test");
    const auto by_id = BuildGroupIndex(encoded, 0);

    Decoder decoder(params, block.size());
    for (std::uint16_t id = 0; id < params.data_chunks; ++id) {
        Chunk candidate = *by_id[id];
        if (id == 0) {
            candidate.bytes[0] ^= 0x80;
        }
        Require(decoder.AddChunk(candidate), "AddChunk failed in corruption test");
    }

    const auto reconstructed = decoder.Reconstruct();
    Require(!reconstructed.has_value() || *reconstructed != block, "corrupted chunk should not reconstruct original block");
}

void TestOutOfOrderDelivery()
{
    const auto params = Parameters::FromOverheadRatio(1.2);
    const auto block = RandomBytes(
        static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE,
        0x12345678);

    Encoder encoder(params);
    const EncodedBlock encoded = encoder.Encode(block);
    Require(encoded.coding_group_count == 1, "expected one coding group for out-of-order test");
    const auto by_id = BuildGroupIndex(encoded, 0);

    std::vector<std::uint16_t> shuffled_ids(FEC_TOTAL_CHUNKS);
    std::iota(shuffled_ids.begin(), shuffled_ids.end(), 0);
    std::mt19937 rng(0xC001D00D);
    std::shuffle(shuffled_ids.begin(), shuffled_ids.end(), rng);

    Decoder decoder(params, block.size());
    for (const std::uint16_t id : shuffled_ids) {
        Require(decoder.AddChunk(*by_id[id]), "AddChunk failed for out-of-order stream");
    }

    Require(decoder.IsComplete(), "decoder did not complete for out-of-order stream");
    const auto reconstructed = decoder.Reconstruct();
    Require(reconstructed.has_value(), "decoder did not reconstruct for out-of-order stream");
    Require(*reconstructed == block, "out-of-order reconstruction mismatch");
}

void TestDuplicateAndValidation()
{
    const auto params = Parameters::FromOverheadRatio(1.2);
    const auto block = RandomBytes(static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE, 0xD00D);

    Encoder encoder(params);
    const EncodedBlock encoded = encoder.Encode(block);
    const auto by_id = BuildGroupIndex(encoded, 0);

    Decoder decoder(params, block.size());
    Require(decoder.AddChunk(*by_id[0]), "failed to add first chunk");
    Require(decoder.AddChunk(*by_id[0]), "duplicate add should be accepted and ignored");

    std::array<std::uint8_t, 8> tiny{};
    Require(!decoder.AddChunk(0, 1, tiny), "short chunk payload should be rejected");
    Require(!decoder.AddChunk(99, 1, by_id[1]->bytes), "invalid group id should be rejected");
}

#if defined(__GLIBC__)
std::size_t HeapGrowthSince(std::size_t base)
{
    const struct mallinfo2 info = mallinfo2();
    const std::size_t now = info.uordblks + info.hblkhd;
    return now > base ? now - base : 0;
}

std::size_t HeapInUse()
{
    const struct mallinfo2 info = mallinfo2();
    return info.uordblks + info.hblkhd;
}

// Peak heap held by a decoder for `block`, from construction until it completes. Parity chunks
// are fed first so the decoder holds the most state before it can finish.
std::size_t MeasureDecoderPeak(const Parameters& params, const std::vector<std::uint8_t>& block)
{
    Encoder encoder(params);
    const EncodedBlock encoded = encoder.Encode(block);

    const std::size_t base = HeapInUse();
    std::size_t peak = 0;
    {
        Decoder decoder(params, block.size());
        peak = HeapGrowthSince(base);
        for (int pass = 0; pass < 2 && !decoder.IsComplete(); ++pass) {
            for (const Chunk& chunk : encoded.chunks) {
                if ((pass == 0) != (chunk.chunk_id >= params.data_chunks)) {
                    continue;
                }
                (void)decoder.AddChunk(chunk);
                peak = std::max(peak, HeapGrowthSince(base));
                if (decoder.IsComplete()) {
                    break;
                }
            }
        }
        Require(decoder.IsComplete(), "decoder should complete with every chunk");
    }
    return peak;
}
#endif

void TestDecoderMemoryChargeCoversHeap()
{
#if defined(__GLIBC__)
    // One coding group for every data chunk count: the charge must cover what the codec allocates,
    // without being so loose that the relay limits stop meaning anything.
    for (std::uint16_t data_chunks = 2; data_chunks < FEC_TOTAL_CHUNKS; ++data_chunks) {
        const Parameters params = Parameters::FromDataChunkCount(data_chunks);
        const std::vector<std::uint8_t> block = RandomBytes(static_cast<std::size_t>(data_chunks) * FEC_CHUNK_SIZE, 0xC0DE + data_chunks);
        const std::size_t peak = MeasureDecoderPeak(params, block);
        const std::size_t charge = Decoder::MemoryBytes(params, block.size());
        Require(peak <= charge, "charge below measured heap for data_chunks=" + std::to_string(data_chunks)
                                    + " (" + std::to_string(charge) + " < " + std::to_string(peak) + ")");
        // CM256 completes a group inside one AddChunk call, briefly holding the received and the
        // decoded payload together; sampling between calls cannot see that, so allow for it.
        const std::size_t slack = data_chunks <= photon::fec::CM256_MAX_DATA_CHUNKS ? peak : peak / 4;
        Require(charge <= peak + slack + 4096, "charge far above measured heap for data_chunks=" + std::to_string(data_chunks));
    }

    // Multi-group blocks up to the relay's 2,000,000-byte limit.
    for (const std::uint16_t data_chunks : {2, 27, 28, 64, 212, 254}) {
        const Parameters params = Parameters::FromDataChunkCount(data_chunks);
        const std::size_t size = data_chunks <= photon::fec::CM256_MAX_DATA_CHUNKS ? 200'000 : 2'000'000;
        const std::vector<std::uint8_t> block = RandomBytes(size, 0xBEEF + data_chunks);
        const std::size_t peak = MeasureDecoderPeak(params, block);
        const std::size_t charge = Decoder::MemoryBytes(params, block.size());
        std::cout << "  data_chunks=" << data_chunks << " size=" << size << " heap_peak=" << peak << " charge=" << charge << '\n';
        Require(peak <= charge, "charge below measured heap for multi-group data_chunks=" + std::to_string(data_chunks));
    }
#else
    std::cout << "  (heap measurement needs glibc; skipped)\n";
#endif
}

void TestDecoderMemoryChargeRejectsInvalidArguments()
{
    Parameters invalid{};
    invalid.data_chunks = 1;
    invalid.parity_chunks = 254;
    Require(Decoder::MemoryBytes(invalid, 1000) == std::numeric_limits<std::size_t>::max(), "invalid parameters should not be chargeable");
    Require(Decoder::MemoryBytes(Parameters::FromDataChunkCount(2), std::numeric_limits<std::size_t>::max()) ==
                std::numeric_limits<std::size_t>::max(),
            "too many coding groups should not be chargeable");
    Require(Decoder::MemoryBytes(Parameters::FromDataChunkCount(212), 0) < 1024, "an empty decoder holds almost nothing");
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"parameter_mapping", TestParameterMapping},
        {"roundtrip_cm256", TestRoundTripCm256Mode},
        {"roundtrip_wirehair_2mb", TestRoundTripWirehair2MB},
        {"deterministic_thresholds", TestDeterministicThresholds},
        {"probabilistic_near_limit", TestProbabilisticNearLimit},
        {"packet_loss_matrix", TestPacketLossMatrix},
        {"corrupted_packet_handling", TestCorruptedPacketHandling},
        {"out_of_order_delivery", TestOutOfOrderDelivery},
        {"duplicate_and_validation", TestDuplicateAndValidation},
        {"decoder_memory_charge_covers_heap", TestDecoderMemoryChargeCoversHeap},
        {"decoder_memory_charge_rejects_invalid_arguments", TestDecoderMemoryChargeRejectsInvalidArguments},
    };

    int failures = 0;
    for (const auto& [name, test_fn] : tests) {
        try {
            test_fn();
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception& e) {
            ++failures;
            std::cout << "[FAIL] " << name << ": " << e.what() << '\n';
        }
    }

    return failures;
}

} // namespace

int main()
{
    return RunAllTests() == 0 ? 0 : 1;
}
