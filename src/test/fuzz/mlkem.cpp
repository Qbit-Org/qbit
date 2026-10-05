// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <crypto/mlkem.h>
#include <crypto/sha3.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

using namespace mlkem;

namespace {

void Initialize()
{
    // MLKEM_FORCE_PORTABLE=1 runs every operation on portable C.
    const char* force_portable{std::getenv("MLKEM_FORCE_PORTABLE")};
    InitializeRuntime(force_portable != nullptr && std::string_view{force_portable} == "1");
}

template <size_t N>
std::array<uint8_t, N> ConsumeArray(FuzzedDataProvider& provider)
{
    std::array<uint8_t, N> out{};
    const std::vector<uint8_t> bytes{provider.ConsumeBytes<uint8_t>(N)};
    std::ranges::copy(bytes, out.begin());
    return out;
}

/**
 * Inputs of both targets, in this order (bytes missing at the end of the input
 * are zero): the key generation seed d || z, the encapsulation coins, an
 * arbitrary encapsulation key, an arbitrary ciphertext and an arbitrary
 * decapsulation key; then, from the back, whether to flip one bit of the
 * honest ciphertext, and which.
 */
struct Inputs {
    std::array<uint8_t, KEYGEN_SEED_BYTES> seed;
    std::array<uint8_t, ENCAPS_COINS_BYTES> coins;
    PublicKey ek;
    Ciphertext ct;
    DecapsulationKey dk;
    bool flip;
    size_t flip_bit;
};

Inputs ConsumeInputs(FuzzedDataProvider& provider)
{
    Inputs in{
        .seed = ConsumeArray<KEYGEN_SEED_BYTES>(provider),
        .coins = ConsumeArray<ENCAPS_COINS_BYTES>(provider),
        .ek = ConsumeArray<PUBLIC_KEY_BYTES>(provider),
        .ct = ConsumeArray<CIPHERTEXT_BYTES>(provider),
        .dk = {},
        .flip = false,
        .flip_bit = 0,
    };
    std::ranges::copy(ConsumeArray<SECRET_KEY_BYTES>(provider), in.dk.Bytes().begin());
    in.flip = provider.ConsumeBool();
    in.flip_bit = provider.ConsumeIntegralInRange<size_t>(0, CIPHERTEXT_BYTES * 8 - 1);
    return in;
}

/** FIPS 203 section 7.2 modulus check, written independently of the library. */
bool PublicKeyInRange(const PublicKey& ek)
{
    for (size_t i{0}; i < 384 * 4; i += 3) {
        const unsigned low{ek[i] | ((ek[i + 1] & 0x0fU) << 8)};
        const unsigned high{(ek[i + 1] >> 4) | (unsigned{ek[i + 2]} << 4)};
        if (low >= 3329 || high >= 3329) return false;
    }
    return true;
}

/** FIPS 203 section 7.3 hash check, H(ek) stored in dk, using qbit's own SHA3-256. */
bool SecretKeyHashMatches(const DecapsulationKey& dk)
{
    const std::span<const uint8_t> bytes{dk.Bytes()};
    std::array<uint8_t, SHA3_256::OUTPUT_SIZE> hash;
    SHA3_256().Write(bytes.subspan(384 * 4, PUBLIC_KEY_BYTES)).Finalize(hash);
    return std::ranges::equal(hash, bytes.subspan(384 * 4 + PUBLIC_KEY_BYTES, hash.size()));
}

bool AllZero(std::span<const uint8_t> bytes)
{
    return std::ranges::all_of(bytes, [](uint8_t b) { return b == 0; });
}

void FlipBit(Ciphertext& ct, size_t bit)
{
    ct[bit / 8] ^= uint8_t(1U << (bit % 8));
}

/** Every observable result of one pass over the inputs. */
std::vector<uint8_t> RunAll(const Inputs& in)
{
    std::vector<uint8_t> out;
    const auto add_error{[&](Error error) { out.push_back(uint8_t(error)); }};
    const auto add_bytes{[&](std::span<const uint8_t> bytes) { out.insert(out.end(), bytes.begin(), bytes.end()); }};

    PublicKey ek;
    DecapsulationKey dk;
    add_error(KeyGen(in.seed, ek, dk));
    add_bytes(ek);
    add_bytes(dk.Bytes());
    Ciphertext ct;
    SharedSecret ss;
    add_error(Encaps(ek, in.coins, ct, ss));
    add_bytes(ct);
    add_bytes(ss.Bytes());
    {
        SharedSecret received;
        add_error(Decaps(dk, ct, received));
        add_bytes(received.Bytes());
    }
    if (in.flip) {
        Ciphertext corrupted{ct};
        FlipBit(corrupted, in.flip_bit);
        SharedSecret received;
        add_error(Decaps(dk, corrupted, received));
        add_bytes(received.Bytes());
    }

    add_error(CheckPublicKey(in.ek));
    {
        Ciphertext ct2;
        SharedSecret ss2;
        add_error(Encaps(in.ek, in.coins, ct2, ss2));
        add_bytes(ct2);
        add_bytes(ss2.Bytes());
    }
    {
        SharedSecret received;
        add_error(Decaps(dk, in.ct, received));
        add_bytes(received.Bytes());
    }
    {
        SharedSecret received;
        add_error(Decaps(in.dk, in.ct, received));
        add_bytes(received.Bytes());
    }
    return out;
}

} // namespace

FUZZ_TARGET(mlkem, .init = Initialize)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const Inputs in{ConsumeInputs(provider)};

    // Honest round trips agree.
    PublicKey ek;
    DecapsulationKey dk;
    assert(KeyGen(in.seed, ek, dk) == Error::NONE);
    assert(CheckPublicKey(ek) == Error::NONE);
    Ciphertext ct;
    SharedSecret sent;
    assert(Encaps(ek, in.coins, ct, sent) == Error::NONE);
    SharedSecret received;
    assert(Decaps(dk, ct, received) == Error::NONE);
    assert(std::ranges::equal(received.Bytes(), sent.Bytes()));

    // An arbitrary encapsulation key is accepted exactly when it passes the
    // modulus check, and a rejected one leaves no output behind.
    const Error check{CheckPublicKey(in.ek)};
    assert(check == (PublicKeyInRange(in.ek) ? Error::NONE : Error::INVALID_PUBLIC_KEY));
    {
        Ciphertext ct2;
        ct2.fill(0xa5);
        SharedSecret ss2;
        std::ranges::fill(ss2.Bytes(), 0xa5);
        assert(Encaps(in.ek, in.coins, ct2, ss2) == check);
        if (check != Error::NONE) assert(AllZero(ct2) && AllZero(ss2.Bytes()));
    }

    // Decapsulating a ciphertext of the right length always yields a secret
    // (implicit rejection). That is never proof the ciphertext was valid: any
    // other ciphertext yields a different secret.
    {
        SharedSecret other;
        assert(Decaps(dk, in.ct, other) == Error::NONE);
        if (in.ct != ct) assert(!std::ranges::equal(other.Bytes(), sent.Bytes()));
    }
    if (in.flip) {
        Ciphertext corrupted{ct};
        FlipBit(corrupted, in.flip_bit);
        SharedSecret rejected;
        assert(Decaps(dk, corrupted, rejected) == Error::NONE);
        assert(!std::ranges::equal(rejected.Bytes(), sent.Bytes()));
    }

    // An arbitrary decapsulation key is rejected exactly when its hash check
    // fails, and a rejected one leaves no secret behind.
    {
        SharedSecret ss;
        std::ranges::fill(ss.Bytes(), 0xa5);
        const Error error{Decaps(in.dk, in.ct, ss)};
        assert(error == (SecretKeyHashMatches(in.dk) ? Error::NONE : Error::INVALID_SECRET_KEY));
        if (error != Error::NONE) assert(AllZero(ss.Bytes()));
    }
}

FUZZ_TARGET(mlkem_backend_diff, .init = Initialize)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const Inputs in{ConsumeInputs(provider)};

    // The detected backend and portable C agree on every status and output.
    const BackendNames detected{GetBackendNames()};
    const std::vector<uint8_t> native_results{RunAll(in)};
    {
        ForcePortableForTesting portable;
        assert(GetBackendNames().arith == "portable" && GetBackendNames().keccak == "portable");
        assert(RunAll(in) == native_results);
    }
    // The override is restored.
    assert(GetBackendNames().arith == detected.arith && GetBackendNames().keccak == detected.keccak);
}
