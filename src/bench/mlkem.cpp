// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bench/bench.h>
#include <crypto/mlkem.h>
#include <tinyformat.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>

using namespace mlkem;

namespace {

enum class Backend { DETECTED, PORTABLE };

/**
 * Run `body` on the detected backend, or with portable C forced, and name the
 * benchmark after the backend that runs. Auto-detection is restored afterwards.
 */
template <typename Body>
void WithBackend(benchmark::Bench& bench, const char* operation, Backend backend, Body body)
{
    std::optional<ForcePortableForTesting> portable;
    if (backend == Backend::PORTABLE) portable.emplace();
    const BackendNames names{GetBackendNames()};
    bench.name(strprintf("%s using the '%s/%s' ML-KEM-1024 backend", operation, names.arith, names.keccak));
    body();
}

std::array<uint8_t, KEYGEN_SEED_BYTES> Seed()
{
    std::array<uint8_t, KEYGEN_SEED_BYTES> seed;
    for (size_t i{0}; i < seed.size(); ++i) seed[i] = uint8_t(i * 7 + 1);
    return seed;
}

void KeyGenBench(benchmark::Bench& bench, Backend backend)
{
    WithBackend(bench, "MLKEMKeyGen", backend, [&] {
        auto seed{Seed()};
        PublicKey ek;
        DecapsulationKey dk;
        bench.batch(1).unit("keygen").run([&] {
            ++seed[0];
            const Error error{KeyGen(seed, ek, dk)};
            assert(error == Error::NONE);
        });
    });
}

void EncapsBench(benchmark::Bench& bench, Backend backend)
{
    WithBackend(bench, "MLKEMEncaps", backend, [&] {
        PublicKey ek;
        DecapsulationKey dk;
        const Error keygen{KeyGen(Seed(), ek, dk)};
        assert(keygen == Error::NONE);
        std::array<uint8_t, ENCAPS_COINS_BYTES> coins{};
        Ciphertext ct;
        SharedSecret ss;
        bench.batch(1).unit("encaps").run([&] {
            ++coins[0];
            const Error error{Encaps(ek, coins, ct, ss)};
            assert(error == Error::NONE);
        });
    });
}

void DecapsBench(benchmark::Bench& bench, Backend backend)
{
    WithBackend(bench, "MLKEMDecaps", backend, [&] {
        PublicKey ek;
        DecapsulationKey dk;
        const Error keygen{KeyGen(Seed(), ek, dk)};
        assert(keygen == Error::NONE);
        const std::array<uint8_t, ENCAPS_COINS_BYTES> coins{};
        Ciphertext ct;
        SharedSecret sent;
        const Error encaps{Encaps(ek, coins, ct, sent)};
        assert(encaps == Error::NONE);
        SharedSecret received;
        bench.batch(1).unit("decaps").run([&] {
            const Error error{Decaps(dk, ct, received)};
            assert(error == Error::NONE);
        });
    });
}

} // namespace

static void MLKEM_KEYGEN_DETECTED(benchmark::Bench& bench) { KeyGenBench(bench, Backend::DETECTED); }
static void MLKEM_KEYGEN_PORTABLE(benchmark::Bench& bench) { KeyGenBench(bench, Backend::PORTABLE); }
static void MLKEM_ENCAPS_DETECTED(benchmark::Bench& bench) { EncapsBench(bench, Backend::DETECTED); }
static void MLKEM_ENCAPS_PORTABLE(benchmark::Bench& bench) { EncapsBench(bench, Backend::PORTABLE); }
static void MLKEM_DECAPS_DETECTED(benchmark::Bench& bench) { DecapsBench(bench, Backend::DETECTED); }
static void MLKEM_DECAPS_PORTABLE(benchmark::Bench& bench) { DecapsBench(bench, Backend::PORTABLE); }

BENCHMARK(MLKEM_KEYGEN_DETECTED, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEM_KEYGEN_PORTABLE, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEM_ENCAPS_DETECTED, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEM_ENCAPS_PORTABLE, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEM_DECAPS_DETECTED, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEM_DECAPS_PORTABLE, benchmark::PriorityLevel::HIGH);
