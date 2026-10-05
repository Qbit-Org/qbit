// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <test/data/mlkem1024_vectors.json.h>

#include <crypto/mlkem.h>
#include <crypto/mlkem_shim.h>
#include <crypto/sha256.h>
#include <crypto/sha3.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define MLKEM_TESTS_MSAN 1
#endif
#endif

#include <univalue.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <new>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace mlkem {
static std::ostream& operator<<(std::ostream& os, Error error)
{
    switch (error) {
    case Error::NONE: return os << "NONE";
    case Error::INVALID_PUBLIC_KEY: return os << "INVALID_PUBLIC_KEY";
    case Error::INVALID_SECRET_KEY: return os << "INVALID_SECRET_KEY";
    case Error::INTERNAL: return os << "INTERNAL";
    }
    return os << "Error(" << int(error) << ")";
}
} // namespace mlkem

using namespace mlkem;

namespace {

constexpr int MLKEM_K{4};
constexpr int MLKEM_N{256};
constexpr uint16_t MLKEM_Q{3329};

UniValue ReadVectors()
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::mlkem1024_vectors));
    return vectors;
}

template <size_t N>
std::array<uint8_t, N> FromHex(const UniValue& value)
{
    const std::vector<uint8_t> bytes{ParseHex(value.get_str())};
    BOOST_REQUIRE_EQUAL(bytes.size(), N);
    std::array<uint8_t, N> out;
    std::ranges::copy(bytes, out.begin());
    return out;
}

DecapsulationKey DecapsulationKeyFromHex(const UniValue& value)
{
    DecapsulationKey dk;
    std::ranges::copy(FromHex<SECRET_KEY_BYTES>(value), dk.Bytes().begin());
    return dk;
}

bool AllBytesAre(std::span<const uint8_t> bytes, uint8_t value)
{
    return std::ranges::all_of(bytes, [&](uint8_t b) { return b == value; });
}

/** Run `check` with the active backend, then again with portable C forced. */
void ForEachBackend(const std::function<void()>& check)
{
    {
        BOOST_TEST_CONTEXT("backend " << GetBackendNames().arith << "/" << GetBackendNames().keccak) { check(); }
    }
    ForcePortableForTesting portable;
    BOOST_REQUIRE_EQUAL(GetBackendNames().arith, "portable");
    BOOST_TEST_CONTEXT("backend portable (forced)") { check(); }
}

/**
 * SHAKE256 truncated to 32 bytes, built on qbit's own Keccak-f[1600]: an
 * independent reference for ML-KEM's J, which derives the implicit-rejection
 * secret J(z || c).
 */
std::array<uint8_t, 32> Shake256To32(std::span<const uint8_t> input)
{
    constexpr size_t RATE{136};
    uint64_t state[25]{};
    const auto xor_byte{[&](size_t pos, uint8_t byte) { state[pos / 8] ^= uint64_t{byte} << (8 * (pos % 8)); }};
    while (input.size() >= RATE) {
        for (size_t i{0}; i < RATE; ++i) xor_byte(i, input[i]);
        KeccakF(state);
        input = input.subspan(RATE);
    }
    for (size_t i{0}; i < input.size(); ++i) xor_byte(i, input[i]);
    xor_byte(input.size(), 0x1f);
    xor_byte(RATE - 1, 0x80);
    KeccakF(state);
    std::array<uint8_t, 32> out;
    for (size_t i{0}; i < out.size(); ++i) out[i] = uint8_t(state[i / 8] >> (8 * (i % 8)));
    return out;
}

/** The implicit-rejection secret for ciphertext `ct` under `dk`: J(z || ct), z being dk's last 32 bytes. */
std::array<uint8_t, 32> RejectionSecret(const DecapsulationKey& dk, std::span<const uint8_t> ct)
{
    std::vector<uint8_t> input(dk.Bytes().end() - 32, dk.Bytes().end());
    input.insert(input.end(), ct.begin(), ct.end());
    return Shake256To32(input);
}

/** Overwrite coefficient `index` of polynomial `poly` in an encapsulation key (FIPS 203 ByteEncode_12). */
void SetCoefficient(PublicKey& ek, int poly, int index, uint16_t value)
{
    uint8_t* group{ek.data() + 384 * poly + 3 * (index / 2)};
    if (index % 2 == 0) {
        group[0] = uint8_t(value);
        group[1] = uint8_t((group[1] & 0xf0) | (value >> 8));
    } else {
        group[1] = uint8_t((group[1] & 0x0f) | ((value & 0x0f) << 4));
        group[2] = uint8_t(value >> 4);
    }
}

/**
 * The 1040 invalid ML-KEM-1024 encapsulation keys of C2SP CCTV
 * ML-KEM/modulus/ML-KEM-1024.txt, in file order, rebuilt from the key they
 * share, as CCTV's modulus.go generates them.
 */
std::vector<PublicKey> CctvModulusKeys(const PublicKey& base)
{
    std::vector<PublicKey> keys;
    const auto add{[&](int poly, int index, uint16_t value) {
        keys.push_back(base);
        SetCoefficient(keys.back(), poly, index, value);
    }};
    for (int i{0}; i < MLKEM_K; ++i) {
        add(i, 0, MLKEM_Q);
        add(i, 255, MLKEM_Q);
        add(i, 0, (1 << 12) - 1);
        add(i, 255, (1 << 12) - 1);
    }
    int i{0}, j{0};
    uint16_t x{MLKEM_Q};
    bool done_values{false}, done_positions{false};
    while (true) {
        add(i, j, x);
        if (++x == (1 << 12)) {
            x = MLKEM_Q;
            done_values = true;
        }
        if (++j == MLKEM_N) {
            j = 0;
            ++i;
        }
        if (i == MLKEM_K) {
            i = 0;
            done_positions = true;
        }
        if (done_values && done_positions) break;
    }
    return keys;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mlkem_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(acvp_keygen_1024)
{
    const UniValue vectors{ReadVectors()};
    const UniValue& cases{vectors["acvp"]["keyGen"]};
    BOOST_REQUIRE(!cases.empty());
    for (const UniValue& tc : cases.getValues()) {
        BOOST_TEST_CONTEXT("ACVP keyGen tcId " << tc["tcId"].getInt<int>())
        {
            std::array<uint8_t, KEYGEN_SEED_BYTES> seed;
            const auto d{FromHex<32>(tc["d"])};
            const auto z{FromHex<32>(tc["z"])};
            std::ranges::copy(d, seed.begin());
            std::ranges::copy(z, seed.begin() + 32);
            const auto expected_ek{FromHex<PUBLIC_KEY_BYTES>(tc["ek"])};
            const auto expected_dk{FromHex<SECRET_KEY_BYTES>(tc["dk"])};
            ForEachBackend([&] {
                PublicKey ek;
                DecapsulationKey dk;
                BOOST_REQUIRE_EQUAL(KeyGen(seed, ek, dk), Error::NONE);
                BOOST_CHECK(ek == expected_ek);
                BOOST_CHECK(std::ranges::equal(dk.Bytes(), expected_dk));
            });
        }
    }
}

BOOST_AUTO_TEST_CASE(acvp_encap_decap_1024)
{
    const UniValue vectors{ReadVectors()};
    const UniValue& acvp{vectors["acvp"]};

    BOOST_REQUIRE(!acvp["encapsulation"].empty());
    for (const UniValue& tc : acvp["encapsulation"].getValues()) {
        BOOST_TEST_CONTEXT("ACVP encapsulation tcId " << tc["tcId"].getInt<int>())
        {
            const auto ek{FromHex<PUBLIC_KEY_BYTES>(tc["ek"])};
            const auto coins{FromHex<ENCAPS_COINS_BYTES>(tc["m"])};
            const auto expected_ct{FromHex<CIPHERTEXT_BYTES>(tc["c"])};
            const auto expected_ss{FromHex<SHARED_SECRET_BYTES>(tc["k"])};
            ForEachBackend([&] {
                Ciphertext ct;
                SharedSecret ss;
                BOOST_REQUIRE_EQUAL(Encaps(ek, coins, ct, ss), Error::NONE);
                BOOST_CHECK(ct == expected_ct);
                BOOST_CHECK(std::ranges::equal(ss.Bytes(), expected_ss));
            });
        }
    }

    // Both "valid decapsulation" and "modified ciphertext" cases decapsulate
    // successfully; the latter yield the implicit-rejection secret.
    BOOST_REQUIRE(!acvp["decapsulation"].empty());
    for (const UniValue& tc : acvp["decapsulation"].getValues()) {
        BOOST_TEST_CONTEXT("ACVP decapsulation tcId " << tc["tcId"].getInt<int>() << " (" << tc["reason"].get_str() << ")")
        {
            const DecapsulationKey dk{DecapsulationKeyFromHex(tc["dk"])};
            const auto ct{FromHex<CIPHERTEXT_BYTES>(tc["c"])};
            const auto expected_ss{FromHex<SHARED_SECRET_BYTES>(tc["k"])};
            ForEachBackend([&] {
                SharedSecret ss;
                BOOST_REQUIRE_EQUAL(Decaps(dk, ct, ss), Error::NONE);
                BOOST_CHECK(std::ranges::equal(ss.Bytes(), expected_ss));
            });
        }
    }

    BOOST_REQUIRE(!acvp["encapsulationKeyCheck"].empty());
    for (const UniValue& tc : acvp["encapsulationKeyCheck"].getValues()) {
        BOOST_TEST_CONTEXT("ACVP encapsulationKeyCheck tcId " << tc["tcId"].getInt<int>() << " (" << tc["reason"].get_str() << ")")
        {
            const auto ek{FromHex<PUBLIC_KEY_BYTES>(tc["ek"])};
            const Error expected{tc["testPassed"].get_bool() ? Error::NONE : Error::INVALID_PUBLIC_KEY};
            ForEachBackend([&] {
                BOOST_CHECK_EQUAL(CheckPublicKey(ek), expected);
                const std::array<uint8_t, ENCAPS_COINS_BYTES> coins{};
                Ciphertext ct;
                SharedSecret ss;
                BOOST_CHECK_EQUAL(Encaps(ek, coins, ct, ss), expected);
            });
        }
    }

    BOOST_REQUIRE(!acvp["decapsulationKeyCheck"].empty());
    for (const UniValue& tc : acvp["decapsulationKeyCheck"].getValues()) {
        BOOST_TEST_CONTEXT("ACVP decapsulationKeyCheck tcId " << tc["tcId"].getInt<int>() << " (" << tc["reason"].get_str() << ")")
        {
            const DecapsulationKey dk{DecapsulationKeyFromHex(tc["dk"])};
            const Error expected{tc["testPassed"].get_bool() ? Error::NONE : Error::INVALID_SECRET_KEY};
            ForEachBackend([&] {
                const Ciphertext ct{};
                SharedSecret ss;
                BOOST_CHECK_EQUAL(Decaps(dk, ct, ss), expected);
            });
        }
    }
}

BOOST_AUTO_TEST_CASE(public_key_modulus)
{
    const UniValue vectors{ReadVectors()};
    const UniValue& cctv{vectors["cctv_modulus"]};
    const PublicKey base{FromHex<PUBLIC_KEY_BYTES>(cctv["base_ek"])};
    const std::array<uint8_t, ENCAPS_COINS_BYTES> coins{};

    // The rebuilt keys are exactly CCTV's file.
    const std::vector<PublicKey> invalid_keys{CctvModulusKeys(base)};
    BOOST_REQUIRE_EQUAL(invalid_keys.size(), size_t(cctv["count"].getInt<int>()));
    CSHA256 file_hash;
    for (const PublicKey& ek : invalid_keys) {
        const std::string line{HexStr(ek) + "\n"};
        file_hash.Write(reinterpret_cast<const unsigned char*>(line.data()), line.size());
    }
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    file_hash.Finalize(digest.data());
    BOOST_REQUIRE_EQUAL(HexStr(digest), cctv["sha256_of_txt"].get_str());

    ForEachBackend([&] {
        Ciphertext ct;
        SharedSecret ss;
        BOOST_CHECK_EQUAL(CheckPublicKey(base), Error::NONE);
        BOOST_CHECK_EQUAL(Encaps(base, coins, ct, ss), Error::NONE);

        for (size_t n{0}; n < invalid_keys.size(); ++n) {
            BOOST_TEST_CONTEXT("CCTV modulus key " << n)
            {
                BOOST_CHECK_EQUAL(CheckPublicKey(invalid_keys[n]), Error::INVALID_PUBLIC_KEY);
                ct.fill(0xa5);
                std::ranges::fill(ss.Bytes(), 0xa5);
                BOOST_CHECK_EQUAL(Encaps(invalid_keys[n], coins, ct, ss), Error::INVALID_PUBLIC_KEY);
                BOOST_CHECK(AllBytesAre(ct, 0));
                BOOST_CHECK(AllBytesAre(ss.Bytes(), 0));
            }
        }

        // The boundary: q - 1 = 3328 is the largest valid coefficient, q = 3329 the smallest invalid one.
        for (int poly{0}; poly < MLKEM_K; ++poly) {
            for (const int index : {0, 1, 128, 255}) {
                BOOST_TEST_CONTEXT("coefficient " << index << " of polynomial " << poly)
                {
                    PublicKey ek{base};
                    SetCoefficient(ek, poly, index, MLKEM_Q - 1);
                    BOOST_CHECK_EQUAL(CheckPublicKey(ek), Error::NONE);
                    BOOST_CHECK_EQUAL(Encaps(ek, coins, ct, ss), Error::NONE);
                    SetCoefficient(ek, poly, index, MLKEM_Q);
                    BOOST_CHECK_EQUAL(CheckPublicKey(ek), Error::INVALID_PUBLIC_KEY);
                    BOOST_CHECK_EQUAL(Encaps(ek, coins, ct, ss), Error::INVALID_PUBLIC_KEY);
                }
            }
        }
    });
}

BOOST_AUTO_TEST_CASE(implicit_rejection)
{
    // The reference: ACVP's modified-ciphertext cases equal J(z || c).
    const UniValue vectors{ReadVectors()};
    int modified_cases{0};
    for (const UniValue& tc : vectors["acvp"]["decapsulation"].getValues()) {
        if (tc["reason"].get_str() != "modified ciphertext") continue;
        const DecapsulationKey dk{DecapsulationKeyFromHex(tc["dk"])};
        const auto ct{FromHex<CIPHERTEXT_BYTES>(tc["c"])};
        BOOST_CHECK(RejectionSecret(dk, ct) == FromHex<SHARED_SECRET_BYTES>(tc["k"]));
        ++modified_cases;
    }
    BOOST_REQUIRE_GT(modified_cases, 0);

    std::array<uint8_t, KEYGEN_SEED_BYTES> seed;
    for (size_t i{0}; i < seed.size(); ++i) seed[i] = uint8_t(i);
    std::array<uint8_t, ENCAPS_COINS_BYTES> coins;
    coins.fill(0x42);

    ForEachBackend([&] {
        PublicKey ek;
        DecapsulationKey dk;
        BOOST_REQUIRE_EQUAL(KeyGen(seed, ek, dk), Error::NONE);
        Ciphertext ct;
        SharedSecret sent;
        BOOST_REQUIRE_EQUAL(Encaps(ek, coins, ct, sent), Error::NONE);
        SharedSecret received;
        BOOST_REQUIRE_EQUAL(Decaps(dk, ct, received), Error::NONE);
        BOOST_CHECK(std::ranges::equal(sent.Bytes(), received.Bytes()));

        for (const auto& [byte, bit] : std::vector<std::pair<size_t, int>>{{0, 0}, {784, 3}, {1407, 7}, {CIPHERTEXT_BYTES - 1, 7}}) {
            BOOST_TEST_CONTEXT("flipped bit " << bit << " of ciphertext byte " << byte)
            {
                Ciphertext corrupted{ct};
                corrupted[byte] ^= uint8_t(1 << bit);
                SharedSecret rejected;
                BOOST_REQUIRE_EQUAL(Decaps(dk, corrupted, rejected), Error::NONE);
                BOOST_CHECK(!std::ranges::equal(rejected.Bytes(), sent.Bytes()));
                BOOST_CHECK(std::ranges::equal(rejected.Bytes(), RejectionSecret(dk, corrupted)));
            }
        }
    });
}

BOOST_AUTO_TEST_CASE(wrapper_lifetimes_and_errors)
{
    const UniValue vectors{ReadVectors()};
    std::array<uint8_t, KEYGEN_SEED_BYTES> seed;
    seed.fill(0x07);
    const std::array<uint8_t, ENCAPS_COINS_BYTES> coins{};
    PublicKey ek;
    DecapsulationKey dk;
    BOOST_REQUIRE_EQUAL(KeyGen(seed, ek, dk), Error::NONE);

    // An invalid decapsulation key (failed hash check) is its own error, and clears the secret.
    for (const UniValue& tc : vectors["acvp"]["decapsulationKeyCheck"].getValues()) {
        if (tc["testPassed"].get_bool()) continue;
        const DecapsulationKey bad_dk{DecapsulationKeyFromHex(tc["dk"])};
        SharedSecret ss;
        std::ranges::fill(ss.Bytes(), 0x5a);
        BOOST_CHECK_EQUAL(Decaps(bad_dk, Ciphertext{}, ss), Error::INVALID_SECRET_KEY);
        BOOST_CHECK(AllBytesAre(ss.Bytes(), 0));
    }

    // Injected library results: anything but the documented invalid-key codes
    // is INTERNAL, and every failure clears the outputs the library wrote.
    {
        InjectResultForTesting inject{Operation::KEYGEN, upstream::ERR_FAIL};
        PublicKey ek2;
        DecapsulationKey dk2;
        BOOST_CHECK_EQUAL(KeyGen(seed, ek2, dk2), Error::INTERNAL);
        BOOST_CHECK(AllBytesAre(ek2, 0));
        BOOST_CHECK(AllBytesAre(dk2.Bytes(), 0));
    }
    {
        InjectResultForTesting inject{Operation::KEYGEN, upstream::ERR_INVALID_PK};
        PublicKey ek2;
        DecapsulationKey dk2;
        BOOST_CHECK_EQUAL(KeyGen(seed, ek2, dk2), Error::INTERNAL);
        BOOST_CHECK(AllBytesAre(dk2.Bytes(), 0));
    }
    for (const auto& [result, expected] : std::vector<std::pair<int, Error>>{
             {upstream::ERR_INVALID_PK, Error::INVALID_PUBLIC_KEY},
             {upstream::ERR_INVALID_SK, Error::INTERNAL},
             {upstream::ERR_OUT_OF_MEMORY, Error::INTERNAL}}) {
        BOOST_TEST_CONTEXT("upstream result " << result)
        {
            {
                InjectResultForTesting inject{Operation::CHECK_PUBLIC_KEY, result};
                BOOST_CHECK_EQUAL(CheckPublicKey(ek), expected);
            }
            InjectResultForTesting inject{Operation::ENCAPS, result};
            Ciphertext ct;
            SharedSecret ss;
            BOOST_CHECK_EQUAL(Encaps(ek, coins, ct, ss), expected);
            BOOST_CHECK(AllBytesAre(ct, 0));
            BOOST_CHECK(AllBytesAre(ss.Bytes(), 0));
        }
    }
    for (const auto& [result, expected] : std::vector<std::pair<int, Error>>{
             {upstream::ERR_INVALID_SK, Error::INVALID_SECRET_KEY},
             {upstream::ERR_INVALID_PK, Error::INTERNAL},
             {upstream::ERR_RNG_FAIL, Error::INTERNAL},
             {upstream::ERR_PCT_FAIL, Error::INTERNAL}}) {
        BOOST_TEST_CONTEXT("upstream result " << result)
        {
            InjectResultForTesting inject{Operation::DECAPS, result};
            SharedSecret ss;
            BOOST_CHECK_EQUAL(Decaps(dk, Ciphertext{}, ss), expected);
            BOOST_CHECK(AllBytesAre(ss.Bytes(), 0));
        }
    }
    {
        // Guards nest and restore what they replaced.
        InjectResultForTesting outer{Operation::ENCAPS, upstream::ERR_FAIL};
        {
            InjectResultForTesting inner{Operation::ENCAPS, upstream::ERR_INVALID_PK};
            Ciphertext ct;
            SharedSecret ss;
            BOOST_CHECK_EQUAL(Encaps(ek, coins, ct, ss), Error::INVALID_PUBLIC_KEY);
        }
        Ciphertext ct;
        SharedSecret ss;
        BOOST_CHECK_EQUAL(Encaps(ek, coins, ct, ss), Error::INTERNAL);
    }
    // Without injection every operation succeeds again.
    Ciphertext ct;
    SharedSecret ss;
    BOOST_CHECK_EQUAL(CheckPublicKey(ek), Error::NONE);
    BOOST_REQUIRE_EQUAL(Encaps(ek, coins, ct, ss), Error::NONE);

    // Moves transfer the secret and clear the source; Clear() wipes.
    DecapsulationKey moved_dk{std::move(dk)};
    BOOST_CHECK(AllBytesAre(dk.Bytes(), 0)); // NOLINT(bugprone-use-after-move)
    SharedSecret decapsulated;
    BOOST_REQUIRE_EQUAL(Decaps(moved_dk, ct, decapsulated), Error::NONE);
    BOOST_CHECK(std::ranges::equal(decapsulated.Bytes(), ss.Bytes()));

    SharedSecret assigned;
    assigned = std::move(decapsulated);
    BOOST_CHECK(std::ranges::equal(assigned.Bytes(), ss.Bytes()));
    BOOST_CHECK(AllBytesAre(decapsulated.Bytes(), 0)); // NOLINT(bugprone-use-after-move)
    SharedSecret& alias{assigned};
    assigned = std::move(alias);
    BOOST_CHECK(std::ranges::equal(assigned.Bytes(), ss.Bytes()));
    assigned.Clear();
    BOOST_CHECK(AllBytesAre(assigned.Bytes(), 0));

    // Destruction wipes the bytes.
    alignas(SharedSecret) unsigned char storage[sizeof(SharedSecret)];
    SharedSecret* secret{new (storage) SharedSecret};
    std::ranges::fill(secret->Bytes(), 0xc3);
    secret->~SharedSecret();
#ifdef MLKEM_TESTS_MSAN
    // MemorySanitizer marks a destroyed object's storage uninitialized; read
    // the bytes the destructor left behind anyway.
    __msan_unpoison(storage, sizeof(storage));
#endif
    BOOST_CHECK(AllBytesAre(storage, 0));
}

BOOST_AUTO_TEST_CASE(backend_selection)
{
    const std::string_view compiled_arith{qbit_mlkem_compiled_arith_backend()};
    const std::string_view compiled_keccak{qbit_mlkem_compiled_keccak_backend()};
    const BackendNames active{GetBackendNames()};
    BOOST_TEST_MESSAGE("compiled " << compiled_arith << "/" << compiled_keccak << ", active " << active.arith << "/" << active.keccak);

    // The configure step's decision reaches the compiled library.
#if ENABLE_MLKEM_NATIVE && (defined(__x86_64__) || defined(_M_X64))
    BOOST_CHECK_MESSAGE(compiled_arith == "x86_64-avx2" && compiled_keccak == "x86_64-avx2",
                        "FAIL: configure chose native x86_64, but the library was compiled with " << compiled_arith << "/" << compiled_keccak
                        << ". Cause: cmake/mlkem-native.cmake and src/crypto/mlkem_config.h disagree. Fix: compare the probes in mlkem_native_detect_arch with the header's conditions.");
#ifdef HAVE_BUILTIN_CPU_SUPPORTS
    // On a host with every extension the x86_64 assembly executes, native code
    // must be what runs; without any one of them (BMI2 or POPCNT masked in a
    // virtual machine, say), portable C must.
    __builtin_cpu_init();
    const bool x86_native{__builtin_cpu_supports("avx2") && __builtin_cpu_supports("ssse3") && __builtin_cpu_supports("sse4.1") &&
                          __builtin_cpu_supports("popcnt") && __builtin_cpu_supports("bmi2")};
    const std::string_view expected{x86_native ? "x86_64-avx2" : "portable"};
    BOOST_CHECK_MESSAGE(active.arith == expected && active.keccak == expected,
                        "FAIL: active backend " << active.arith << "/" << active.keccak << ", expected " << expected
                        << ". Cause: cached detection (cpu_features::HasMlkemX86Native) or the capability hook disagrees with the CPU. Fix: check cpu_features_tests and qbit_mlkem_has_avx2.");
#endif
#elif defined(__aarch64__) && defined(__APPLE__) && ENABLE_MLKEM_NATIVE
    BOOST_CHECK_EQUAL(compiled_arith, "aarch64-neon");
    BOOST_CHECK_EQUAL(compiled_keccak, "aarch64");
    BOOST_CHECK_EQUAL(active.arith, "aarch64-neon");
    BOOST_CHECK_EQUAL(active.keccak, "aarch64");
#else
    // WITH_MLKEM_NATIVE=OFF, MemorySanitizer, or a target without a native
    // backend, AArch64 ELF included: its assembly lacks BTI landing pads.
    BOOST_CHECK_MESSAGE(!ENABLE_MLKEM_NATIVE, "native build for a target without a qbit backend");
    BOOST_CHECK_EQUAL(compiled_arith, "portable");
    BOOST_CHECK_EQUAL(compiled_keccak, "portable");
    BOOST_CHECK_EQUAL(active.arith, "portable");
    BOOST_CHECK_EQUAL(active.keccak, "portable");
#endif

    // The portable guard forces portable C, nests, and restores what it replaced.
    {
        ForcePortableForTesting outer;
        BOOST_CHECK_EQUAL(GetBackendNames().arith, "portable");
        BOOST_CHECK_EQUAL(GetBackendNames().keccak, "portable");
        {
            ForcePortableForTesting inner;
            BOOST_CHECK_EQUAL(GetBackendNames().arith, "portable");
        }
        BOOST_CHECK_EQUAL(GetBackendNames().arith, "portable");
        BOOST_CHECK_EQUAL(GetBackendNames().keccak, "portable");
    }
    BOOST_CHECK_EQUAL(GetBackendNames().arith, active.arith);
    BOOST_CHECK_EQUAL(GetBackendNames().keccak, active.keccak);

    // The startup override.
    InitializeRuntime(/*force_portable=*/true);
    BOOST_CHECK_EQUAL(GetBackendNames().arith, "portable");
    BOOST_CHECK_EQUAL(GetBackendNames().keccak, "portable");
    InitializeRuntime(/*force_portable=*/false);
    BOOST_CHECK_EQUAL(GetBackendNames().arith, active.arith);
    BOOST_CHECK_EQUAL(GetBackendNames().keccak, active.keccak);
}

BOOST_AUTO_TEST_CASE(override_changed_by_another_thread)
{
    const BackendNames before{GetBackendNames()};
    // The outputs with nothing changing the override; every backend gives them.
    std::array<uint8_t, KEYGEN_SEED_BYTES> seed;
    for (size_t i{0}; i < seed.size(); ++i) seed[i] = uint8_t(i * 7 + 1);
    std::array<uint8_t, ENCAPS_COINS_BYTES> coins;
    for (size_t i{0}; i < coins.size(); ++i) coins[i] = uint8_t(i * 3 + 2);
    PublicKey expected_ek;
    DecapsulationKey expected_dk;
    Ciphertext expected_ct;
    SharedSecret expected_ss;
    BOOST_REQUIRE_EQUAL(KeyGen(seed, expected_ek, expected_dk), Error::NONE);
    BOOST_REQUIRE_EQUAL(Encaps(expected_ek, coins, expected_ct, expected_ss), Error::NONE);

    // Another thread flips the override as fast as it can while this one runs
    // operations. Each operation must finish on the backend it started with:
    // on x86_64, one that mixed backends would give wrong outputs.
    std::atomic_bool stop{false};
    std::atomic<uint64_t> flips{0};
    std::thread flipper{[&] {
        while (!stop.load(std::memory_order_relaxed)) {
            ForcePortableForTesting portable;
            flips.fetch_add(1, std::memory_order_relaxed);
        }
    }};
    while (flips.load(std::memory_order_relaxed) == 0) std::this_thread::yield();
    int wrong{0};
    int portable_seen{0};
    constexpr int ROUNDS{50};
    for (int round{0}; round < ROUNDS; ++round) {
        PublicKey ek;
        DecapsulationKey dk;
        Ciphertext ct;
        SharedSecret ss;
        SharedSecret decapsulated;
        const bool ok{KeyGen(seed, ek, dk) == Error::NONE && Encaps(ek, coins, ct, ss) == Error::NONE &&
                      Decaps(dk, ct, decapsulated) == Error::NONE};
        if (!ok || ek != expected_ek || !std::ranges::equal(dk.Bytes(), expected_dk.Bytes()) || ct != expected_ct ||
            !std::ranges::equal(ss.Bytes(), expected_ss.Bytes()) || !std::ranges::equal(decapsulated.Bytes(), expected_ss.Bytes())) {
            ++wrong;
        }
        if (GetBackendNames().arith == "portable") ++portable_seen;
    }
    stop.store(true, std::memory_order_relaxed);
    flipper.join();
    BOOST_TEST_MESSAGE(flips.load() << " flips; portable active at " << portable_seen << " of " << ROUNDS << " checks");
    BOOST_CHECK_MESSAGE(wrong == 0, "FAIL: " << wrong << " of " << ROUNDS << " rounds gave wrong outputs while another thread changed the override. "
                                    << "Cause: an operation mixed backends. Fix: the capability hooks in src/crypto/mlkem.cpp must read the copy taken at entry.");
    BOOST_CHECK_EQUAL(GetBackendNames().arith, before.arith);
}

BOOST_AUTO_TEST_SUITE_END()
