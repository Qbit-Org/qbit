#include <fec.h>
#include <scheduler.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using photon::ChunkScheduler;
using photon::ScheduledChunk;
using photon::fec::Decoder;
using photon::fec::EncodedBlock;
using photon::fec::Encoder;
using photon::fec::FEC_CHUNK_SIZE;
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

std::vector<ScheduledChunk> DrainScheduler(ChunkScheduler& scheduler)
{
    std::vector<ScheduledChunk> out;
    out.reserve(scheduler.total_chunks());

    while (true) {
        const auto next = scheduler.Next();
        if (!next.has_value()) {
            break;
        }

        out.push_back(*next);
    }

    return out;
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

bool DecodeAfterBurstLoss(
    const std::vector<ScheduledChunk>& scheduled,
    const Parameters& params,
    const std::vector<std::uint8_t>& original,
    std::size_t burst_start,
    std::size_t burst_len)
{
    Decoder decoder(params, original.size());

    const std::size_t burst_end = burst_start + burst_len;
    for (std::size_t i = 0; i < scheduled.size(); ++i) {
        if (i >= burst_start && i < burst_end) {
            continue;
        }

        if (!decoder.AddChunk(scheduled[i].chunk)) {
            return false;
        }
    }

    if (!decoder.IsComplete()) {
        return false;
    }

    const auto reconstructed = decoder.Reconstruct();
    return reconstructed.has_value() && *reconstructed == original;
}

struct SchedulerFixture {
    Parameters params{};
    std::vector<std::uint8_t> block{};
    EncodedBlock encoded{};
    std::vector<ScheduledChunk> scheduled{};
};

SchedulerFixture BuildFixture(std::uint64_t seed)
{
    SchedulerFixture fixture{};
    fixture.params = Parameters::FromOverheadRatio(1.2);

    const std::size_t group_payload_bytes = static_cast<std::size_t>(fixture.params.data_chunks) * FEC_CHUNK_SIZE;
    fixture.block = RandomBytes(group_payload_bytes * 8, seed);

    Encoder encoder(fixture.params);
    fixture.encoded = encoder.Encode(fixture.block);

    ChunkScheduler scheduler({fixture.encoded});
    fixture.scheduled = DrainScheduler(scheduler);

    return fixture;
}

void TestRoundTripAndChunkCount()
{
    const SchedulerFixture fixture = BuildFixture(0xC0FFEE);

    Require(fixture.encoded.coding_group_count == 8, "expected eight coding groups for 2MB fixture");
    Require(fixture.scheduled.size() == fixture.encoded.chunks.size(), "scheduled chunk count mismatch");

    Decoder decoder(fixture.params, fixture.block.size());
    for (const ScheduledChunk& scheduled : fixture.scheduled) {
        Require(decoder.AddChunk(scheduled.chunk), "AddChunk failed during scheduled replay");
    }

    Require(decoder.IsComplete(), "decoder did not complete");
    const auto reconstructed = decoder.Reconstruct();
    Require(reconstructed.has_value(), "reconstruct missing value");
    Require(*reconstructed == fixture.block, "round-trip mismatch");
}

void TestDeterministicBurstRecovery()
{
    const SchedulerFixture fixture = BuildFixture(0x1234);
    const std::size_t burst = fixture.params.parity_chunks;

    const std::size_t middle = (fixture.scheduled.size() / 2) - (burst / 2);
    const std::size_t tail = fixture.scheduled.size() - burst;

    Require(DecodeAfterBurstLoss(fixture.scheduled, fixture.params, fixture.block, 0, burst), "failed burst recovery at start");
    Require(DecodeAfterBurstLoss(fixture.scheduled, fixture.params, fixture.block, middle, burst), "failed burst recovery at middle");
    Require(DecodeAfterBurstLoss(fixture.scheduled, fixture.params, fixture.block, tail, burst), "failed burst recovery at end");
}

void TestProbabilisticBurstRecovery()
{
    constexpr int kTrials = 200;
    const SchedulerFixture fixture = BuildFixture(0xBEEF);

    const std::size_t burst = fixture.params.parity_chunks;
    std::mt19937 rng(0xDEADBEEF);
    std::uniform_int_distribution<std::size_t> dist(0, fixture.scheduled.size() - burst);

    int successes = 0;
    for (int trial = 0; trial < kTrials; ++trial) {
        const std::size_t start = dist(rng);
        if (DecodeAfterBurstLoss(fixture.scheduled, fixture.params, fixture.block, start, burst)) {
            ++successes;
        }
    }

    const double success_rate = static_cast<double>(successes) / static_cast<double>(kTrials);
    Require(success_rate >= 0.99, "random 43-chunk burst success rate below 99%");
}

void TestNextLatencyP95()
{
    const SchedulerFixture fixture = BuildFixture(0xF00D);

    ChunkScheduler scheduler({fixture.encoded});
    std::size_t consumed = 0;

    constexpr std::size_t kSamples = 10'000;
    std::vector<double> latencies_ms;
    latencies_ms.reserve(kSamples);

    for (std::size_t i = 0; i < kSamples; ++i) {
        if (consumed >= scheduler.total_chunks()) {
            scheduler = ChunkScheduler({fixture.encoded});
            consumed = 0;
        }

        const auto t0 = std::chrono::steady_clock::now();
        const auto next = scheduler.Next();
        const auto t1 = std::chrono::steady_clock::now();

        Require(next.has_value(), "Next() unexpectedly returned nullopt");
        ++consumed;

        const std::chrono::duration<double, std::milli> elapsed = t1 - t0;
        latencies_ms.push_back(elapsed.count());
    }

    const double p95 = PercentileMs(latencies_ms, 95.0);
    Require(p95 < 5.0, "Next() latency p95 exceeded 5ms");
}

void TestEncodeScheduleRegression()
{
    constexpr int kIterations = 20;

    const Parameters params = Parameters::FromOverheadRatio(1.2);
    const std::size_t group_payload_bytes = static_cast<std::size_t>(params.data_chunks) * FEC_CHUNK_SIZE;
    const std::size_t block_size = group_payload_bytes * 8;

    Encoder encoder(params);

    std::vector<double> encode_ms;
    std::vector<double> encode_and_schedule_ms;
    encode_ms.reserve(kIterations);
    encode_and_schedule_ms.reserve(kIterations);

    for (int i = 0; i < kIterations; ++i) {
        const std::vector<std::uint8_t> block = RandomBytes(block_size, static_cast<std::uint64_t>(0x9000 + i));

        const auto t0 = std::chrono::steady_clock::now();
        const EncodedBlock encoded = encoder.Encode(block);
        const auto t1 = std::chrono::steady_clock::now();

        ChunkScheduler scheduler({encoded});
        while (scheduler.Next().has_value()) {
        }

        const auto t2 = std::chrono::steady_clock::now();

        const std::chrono::duration<double, std::milli> encode_elapsed = t1 - t0;
        const std::chrono::duration<double, std::milli> combined_elapsed = t2 - t0;

        encode_ms.push_back(encode_elapsed.count());
        encode_and_schedule_ms.push_back(combined_elapsed.count());
    }

    const double encode_p95 = PercentileMs(encode_ms, 95.0);
    const double combined_p95 = PercentileMs(encode_and_schedule_ms, 95.0);

    Require(combined_p95 <= (encode_p95 * 1.10), "encode+scheduler p95 exceeded 110% of encode-only p95");
}

int RunAllTests()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests = {
        {"roundtrip_and_chunk_count", TestRoundTripAndChunkCount},
        {"deterministic_burst_recovery", TestDeterministicBurstRecovery},
        {"probabilistic_burst_recovery", TestProbabilisticBurstRecovery},
        {"next_latency_p95", TestNextLatencyP95},
        {"encode_schedule_regression", TestEncodeScheduleRegression},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        try {
            fn();
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
