// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <crypto/mlkem.h>

#include <compat/cpu_features.h>
#include <crypto/mlkem_shim.h>
#include <support/cleanse.h>

#include <mlkem/mlkem_native.h>

#include <array>
#include <atomic>

static_assert(MLKEM1024_PUBLICKEYBYTES == mlkem::PUBLIC_KEY_BYTES);
static_assert(MLKEM1024_SECRETKEYBYTES == mlkem::SECRET_KEY_BYTES);
static_assert(MLKEM1024_CIPHERTEXTBYTES == mlkem::CIPHERTEXT_BYTES);
static_assert(MLKEM1024_BYTES == mlkem::SHARED_SECRET_BYTES);
static_assert(2 * MLKEM1024_SYMBYTES == mlkem::KEYGEN_SEED_BYTES);
static_assert(MLKEM1024_SYMBYTES == mlkem::ENCAPS_COINS_BYTES);
static_assert(MLK_ERR_FAIL == mlkem::upstream::ERR_FAIL);
static_assert(MLK_ERR_OUT_OF_MEMORY == mlkem::upstream::ERR_OUT_OF_MEMORY);
static_assert(MLK_ERR_RNG_FAIL == mlkem::upstream::ERR_RNG_FAIL);
static_assert(MLK_ERR_INVALID_PK == mlkem::upstream::ERR_INVALID_PK);
static_assert(MLK_ERR_INVALID_SK == mlkem::upstream::ERR_INVALID_SK);
static_assert(MLK_ERR_PCT_FAIL == mlkem::upstream::ERR_PCT_FAIL);

namespace {

constexpr std::string_view PORTABLE{"portable"};

//! When set, every operation that starts afterwards runs portable C only.
std::atomic_bool g_force_portable{false};

/**
 * g_force_portable as the operation running on this thread read it at entry.
 * The capability hooks read only this copy, so a change on another thread
 * mid-operation cannot mix backends: the x86_64 backend keeps its own
 * coefficient order, and a mixed operation would give a wrong result.
 */
thread_local bool t_force_portable{false};

//! Whether the CPU and OS can run the x86_64 backend. Written once, by DetectCapabilities().
std::atomic_bool g_cpu_x86_native{false};

//! Results injected by InjectResultForTesting, indexed by Operation; 0 means none.
std::array<std::atomic_int, 4> g_injected_results{};

/**
 * Detect CPU features on the first call. Every entry point calls this before
 * entering the library, so no CPUID or XGETBV runs inside an operation, and
 * the capability hooks read only the cached result.
 */
void DetectCapabilities() noexcept
{
    static const bool detected{[] {
        g_cpu_x86_native.store(cpu_features::HasMlkemX86Native(), std::memory_order_relaxed);
        return true;
    }()};
    (void)detected;
}

/** Call at every entry point, before the library runs: fixes the backend for this operation. */
void BeginOperation() noexcept
{
    DetectCapabilities();
    t_force_portable = g_force_portable.load(std::memory_order_relaxed);
}

int Injected(mlkem::Operation op, int result) noexcept
{
    const int injected{g_injected_results[static_cast<size_t>(op)].load(std::memory_order_relaxed)};
    return injected != 0 ? injected : result;
}

mlkem::Error MapResult(mlkem::Operation op, int result) noexcept
{
    if (result == 0) return mlkem::Error::NONE;
    if (result == MLK_ERR_INVALID_PK && (op == mlkem::Operation::CHECK_PUBLIC_KEY || op == mlkem::Operation::ENCAPS)) {
        return mlkem::Error::INVALID_PUBLIC_KEY;
    }
    if (result == MLK_ERR_INVALID_SK && op == mlkem::Operation::DECAPS) return mlkem::Error::INVALID_SECRET_KEY;
    // Anything else, including codes this configuration never produces, is an internal failure.
    return mlkem::Error::INTERNAL;
}

/** The backend that runs for a compiled-in backend name, given the capability hooks' current answers. */
std::string_view ActiveBackend(std::string_view compiled) noexcept
{
    if (compiled == "x86_64-avx2") return qbit_mlkem_has_avx2() ? compiled : PORTABLE;
    if (compiled == "aarch64-neon" || compiled == "aarch64") return qbit_mlkem_has_neon() ? compiled : PORTABLE;
    return PORTABLE;
}

} // namespace

extern "C" void qbit_mlkem_zeroize(void* ptr, size_t len)
{
    memory_cleanse(ptr, len);
}

extern "C" int qbit_mlkem_has_avx2(void)
{
    return !t_force_portable && g_cpu_x86_native.load(std::memory_order_relaxed) ? 1 : 0;
}

extern "C" int qbit_mlkem_has_neon(void)
{
#if defined(__aarch64__) || defined(_M_ARM64)
    // NEON is mandatory on AArch64.
    return !t_force_portable ? 1 : 0;
#else
    return 0;
#endif
}

namespace mlkem {

Error KeyGen(std::span<const uint8_t, KEYGEN_SEED_BYTES> seed64, PublicKey& ek, DecapsulationKey& dk) noexcept
{
    BeginOperation();
    const int result{Injected(Operation::KEYGEN, qbit_mlkem1024_keypair_derand(ek.data(), dk.Bytes().data(), seed64.data()))};
    const Error error{MapResult(Operation::KEYGEN, result)};
    if (error != Error::NONE) {
        dk.Clear();
        memory_cleanse(ek.data(), ek.size());
    }
    return error;
}

Error CheckPublicKey(std::span<const uint8_t, PUBLIC_KEY_BYTES> ek) noexcept
{
    BeginOperation();
    return MapResult(Operation::CHECK_PUBLIC_KEY, Injected(Operation::CHECK_PUBLIC_KEY, qbit_mlkem1024_check_pk(ek.data())));
}

Error Encaps(std::span<const uint8_t, PUBLIC_KEY_BYTES> ek, std::span<const uint8_t, ENCAPS_COINS_BYTES> coins32,
             Ciphertext& ct, SharedSecret& ss) noexcept
{
    BeginOperation();
    const int result{Injected(Operation::ENCAPS, qbit_mlkem1024_enc_derand(ct.data(), ss.Bytes().data(), ek.data(), coins32.data()))};
    const Error error{MapResult(Operation::ENCAPS, result)};
    if (error != Error::NONE) {
        ss.Clear();
        memory_cleanse(ct.data(), ct.size());
    }
    return error;
}

Error Decaps(const DecapsulationKey& dk, std::span<const uint8_t, CIPHERTEXT_BYTES> ct, SharedSecret& ss) noexcept
{
    BeginOperation();
    const int result{Injected(Operation::DECAPS, qbit_mlkem1024_dec(ss.Bytes().data(), ct.data(), dk.Bytes().data()))};
    const Error error{MapResult(Operation::DECAPS, result)};
    if (error != Error::NONE) ss.Clear();
    return error;
}

void InitializeRuntime(bool force_portable) noexcept
{
    DetectCapabilities();
    g_force_portable.store(force_portable);
}

BackendNames GetBackendNames() noexcept
{
    BeginOperation();
    return {
        .arith = ActiveBackend(qbit_mlkem_compiled_arith_backend()),
        .keccak = ActiveBackend(qbit_mlkem_compiled_keccak_backend()),
    };
}

ForcePortableForTesting::ForcePortableForTesting() noexcept
    : m_previous{g_force_portable.exchange(true)}
{
}

ForcePortableForTesting::~ForcePortableForTesting()
{
    g_force_portable.store(m_previous);
}

InjectResultForTesting::InjectResultForTesting(Operation op, int upstream_result) noexcept
    : m_op{op}, m_previous{g_injected_results[static_cast<size_t>(op)].exchange(upstream_result)}
{
}

InjectResultForTesting::~InjectResultForTesting()
{
    g_injected_results[static_cast<size_t>(m_op)].store(m_previous);
}

} // namespace mlkem
