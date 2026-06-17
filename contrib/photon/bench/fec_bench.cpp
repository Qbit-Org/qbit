#include <fec.h>

#include <charconv>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

int ParseIterations(const char* arg)
{
    int value = 0;
    const std::string_view str(arg);
    const auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    if (ec != std::errc{} || ptr != str.data() + str.size() || value <= 0) {
        throw std::invalid_argument("iterations must be a positive integer");
    }
    return value;
}

std::vector<std::uint8_t> RandomBytes(std::size_t size, std::uint64_t seed)
{
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<std::uint8_t> data(size);
    for (std::uint8_t& byte : data) {
        byte = static_cast<std::uint8_t>(dist(rng));
    }
    return data;
}

double PercentileMs(std::vector<double> samples, double percentile)
{
    if (samples.empty()) {
        return 0.0;
    }

    std::sort(samples.begin(), samples.end());
    const double pos = (percentile / 100.0) * static_cast<double>(samples.size() - 1);
    const std::size_t lower = static_cast<std::size_t>(pos);
    const std::size_t upper = std::min(lower + 1, samples.size() - 1);
    const double frac = pos - static_cast<double>(lower);
    return samples[lower] + (samples[upper] - samples[lower]) * frac;
}

} // namespace

int main(int argc, char** argv)
{
    int iterations = 50;
    if (argc > 1) {
        iterations = ParseIterations(argv[1]);
    }

    const auto params = photon::fec::Parameters::FromOverheadRatio(1.2);
    const auto block = RandomBytes(2'000'000, 0xFEEDFACE);
    photon::fec::Encoder encoder(params);

    std::vector<double> encode_ms;
    std::vector<double> decode_ms;
    std::vector<double> total_ms;
    encode_ms.reserve(iterations);
    decode_ms.reserve(iterations);
    total_ms.reserve(iterations);

    for (int i = 0; i < iterations; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        const photon::fec::EncodedBlock encoded = encoder.Encode(block);
        const auto t1 = std::chrono::steady_clock::now();

        photon::fec::Decoder decoder(params, block.size());
        for (const photon::fec::Chunk& chunk : encoded.chunks) {
            if (!decoder.AddChunk(chunk)) {
                std::cerr << "AddChunk failed in iteration " << i << '\n';
                return 1;
            }
        }

        const auto recovered = decoder.Reconstruct();
        if (!recovered.has_value() || *recovered != block) {
            std::cerr << "decode mismatch in iteration " << i << '\n';
            return 1;
        }

        const auto t2 = std::chrono::steady_clock::now();

        const std::chrono::duration<double, std::milli> enc = t1 - t0;
        const std::chrono::duration<double, std::milli> dec = t2 - t1;
        const std::chrono::duration<double, std::milli> ttl = t2 - t0;

        encode_ms.push_back(enc.count());
        decode_ms.push_back(dec.count());
        total_ms.push_back(ttl.count());
    }

    const double enc_p50 = PercentileMs(encode_ms, 50.0);
    const double enc_p95 = PercentileMs(encode_ms, 95.0);
    const double dec_p50 = PercentileMs(decode_ms, 50.0);
    const double dec_p95 = PercentileMs(decode_ms, 95.0);
    const double ttl_p50 = PercentileMs(total_ms, 50.0);
    const double ttl_p95 = PercentileMs(total_ms, 95.0);

    std::cout << "qbit-photon FEC benchmark (2 MB block, iterations=" << iterations << ")\n";
    std::cout << "encode p50=" << enc_p50 << "ms p95=" << enc_p95 << "ms\n";
    std::cout << "decode p50=" << dec_p50 << "ms p95=" << dec_p95 << "ms\n";
    std::cout << "total  p50=" << ttl_p50 << "ms p95=" << ttl_p95 << "ms\n";

    return 0;
}
