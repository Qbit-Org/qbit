// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_CRYPTO_MLKEM_H
#define QBIT_CRYPTO_MLKEM_H

#include <support/cleanse.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

/**
 * ML-KEM-1024 (FIPS 203), backed by the vendored mlkem-native library.
 *
 * Native code runs where it is built and the CPU allows it: x86_64 with AVX2,
 * SSSE3, SSE4.1, POPCNT and BMI2 (and the OS saving AVX state), and AArch64 on
 * macOS. Everything else runs portable C, AArch64 ELF (Linux, BSD) included,
 * whose builds leave the assembly out to keep their BTI and PAC marking. See
 * doc/subtrees/mlkem-native.md. The library is built into bitcoin_node only.
 *
 * Fixed-size spans make wrong-sized calls impossible; callers check network
 * lengths before constructing them. Entropy is the caller's job: key
 * generation takes two independent 32-byte draws, encapsulation one.
 */
namespace mlkem {
inline constexpr size_t PUBLIC_KEY_BYTES = 1568;
inline constexpr size_t SECRET_KEY_BYTES = 3168;
inline constexpr size_t CIPHERTEXT_BYTES = 1568;
inline constexpr size_t SHARED_SECRET_BYTES = 32;
inline constexpr size_t KEYGEN_SEED_BYTES = 64;
inline constexpr size_t ENCAPS_COINS_BYTES = 32;

/** Fixed-size secret bytes, wiped with memory_cleanse on destruction, Clear() and move-from. */
template <size_t N>
class Secret
{
    std::array<uint8_t, N> m_bytes{};

public:
    Secret() noexcept = default;
    ~Secret() { Clear(); }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& other) noexcept : m_bytes{other.m_bytes} { other.Clear(); }
    Secret& operator=(Secret&& other) noexcept
    {
        if (this != &other) {
            m_bytes = other.m_bytes;
            other.Clear();
        }
        return *this;
    }
    std::span<uint8_t, N> Bytes() noexcept { return m_bytes; }
    std::span<const uint8_t, N> Bytes() const noexcept { return m_bytes; }
    void Clear() noexcept { memory_cleanse(m_bytes.data(), m_bytes.size()); }
};

using PublicKey = std::array<uint8_t, PUBLIC_KEY_BYTES>;
using Ciphertext = std::array<uint8_t, CIPHERTEXT_BYTES>;
using DecapsulationKey = Secret<SECRET_KEY_BYTES>;
using SharedSecret = Secret<SHARED_SECRET_BYTES>;

enum class Error : uint8_t { NONE = 0, INVALID_PUBLIC_KEY = 1, INVALID_SECRET_KEY = 2, INTERNAL = 3 };

/**
 * Deterministic key generation (FIPS 203 ML-KEM.KeyGen_internal) from
 * seed64 = d || z. On failure, ek and dk are cleared.
 */
[[nodiscard]] Error KeyGen(std::span<const uint8_t, KEYGEN_SEED_BYTES> seed64, PublicKey& ek, DecapsulationKey& dk) noexcept;

/** The FIPS 203 section 7.2 modulus check: INVALID_PUBLIC_KEY if a coefficient is not below q. */
[[nodiscard]] Error CheckPublicKey(std::span<const uint8_t, PUBLIC_KEY_BYTES> ek) noexcept;

/**
 * Deterministic encapsulation (FIPS 203 ML-KEM.Encaps_internal), including the
 * modulus check of ek. On failure, ct and ss are cleared.
 */
[[nodiscard]] Error Encaps(std::span<const uint8_t, PUBLIC_KEY_BYTES> ek, std::span<const uint8_t, ENCAPS_COINS_BYTES> coins32,
                           Ciphertext& ct, SharedSecret& ss) noexcept;

/**
 * Decapsulation (FIPS 203 ML-KEM.Decaps), including the section 7.3 hash
 * check of dk (INVALID_SECRET_KEY). A corrupted ciphertext of the right
 * length is not an error: it yields the implicit-rejection secret, which
 * differs from the encapsulated one. On failure, ss is cleared.
 */
[[nodiscard]] Error Decaps(const DecapsulationKey& dk, std::span<const uint8_t, CIPHERTEXT_BYTES> ct,
                           SharedSecret& ss) noexcept;

struct BackendNames {
    std::string_view arith;  //!< "x86_64-avx2", "aarch64-neon" or "portable"
    std::string_view keccak; //!< "x86_64-avx2", "aarch64" or "portable"
};

/**
 * Detect CPU features and set the portable override. Call once at startup,
 * before networking starts. Operations work without it, with auto-detection.
 */
void InitializeRuntime(bool force_portable) noexcept;

/** The implementation that runs now: native only if compiled in, supported by the CPU and not overridden. */
BackendNames GetBackendNames() noexcept;

/**
 * Forces portable C while alive, then restores the previous override (RAII).
 * Each operation reads the override once, at entry, so one that is already
 * running finishes on the backend it started with. Test code only.
 */
class ForcePortableForTesting
{
    bool m_previous;

public:
    ForcePortableForTesting() noexcept;
    ~ForcePortableForTesting();
    ForcePortableForTesting(const ForcePortableForTesting&) = delete;
    ForcePortableForTesting& operator=(const ForcePortableForTesting&) = delete;
};

/** mlkem-native's error codes (mlkem/mlkem_native.h), for InjectResultForTesting. */
namespace upstream {
inline constexpr int ERR_FAIL{-1};
inline constexpr int ERR_OUT_OF_MEMORY{-2};
inline constexpr int ERR_RNG_FAIL{-3};
inline constexpr int ERR_INVALID_PK{-4};
inline constexpr int ERR_INVALID_SK{-5};
inline constexpr int ERR_PCT_FAIL{-6};
} // namespace upstream

enum class Operation : uint8_t { KEYGEN, CHECK_PUBLIC_KEY, ENCAPS, DECAPS };

/**
 * Test-only (RAII): while alive, `op` behaves as if mlkem-native had returned
 * `upstream_result` (non-zero) after writing its outputs. This drives the
 * wrapper's error mapping and output clearing, and lets callers test their
 * handling of internal errors. Single-threaded test code only.
 */
class InjectResultForTesting
{
    Operation m_op;
    int m_previous;

public:
    InjectResultForTesting(Operation op, int upstream_result) noexcept;
    ~InjectResultForTesting();
    InjectResultForTesting(const InjectResultForTesting&) = delete;
    InjectResultForTesting& operator=(const InjectResultForTesting&) = delete;
};
} // namespace mlkem

#endif // QBIT_CRYPTO_MLKEM_H
