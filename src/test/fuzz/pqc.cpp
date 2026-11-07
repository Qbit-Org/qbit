// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqc.h>
#include <hash.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cassert>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {
enum class InputMode {
    LEGACY,
    FIXTURE,
    GENERATION,
    UNSUPPORTED_VERSION,
};

struct TaggedInput {
    InputMode mode;
    std::span<const uint8_t> data;
};

/**
 * Tagged inputs start with "QBFX", a target tag byte and a format version byte
 * (see test/fuzz/qbit_corpora/README.md). Version 1 is followed by a selector
 * byte: a low nibble of 0xF (1/16 of selector values) runs the legacy
 * generation body on the remaining bytes, every other value runs the fixture
 * body. Inputs without the tag keep the legacy layout byte for byte.
 */
TaggedInput ParseTaggedInput(std::span<const uint8_t> buffer, uint8_t target_tag)
{
    static constexpr std::array<uint8_t, 4> MAGIC{'Q', 'B', 'F', 'X'};
    static constexpr uint8_t FORMAT_VERSION_1{0x01};
    if (buffer.size() < MAGIC.size() + 2 || !std::equal(MAGIC.begin(), MAGIC.end(), buffer.begin()) ||
        buffer[MAGIC.size()] != target_tag) {
        return {InputMode::LEGACY, buffer};
    }
    // Unknown versions are ignored rather than reinterpreted as another layout.
    if (buffer[MAGIC.size() + 1] != FORMAT_VERSION_1) return {InputMode::UNSUPPORTED_VERSION, {}};
    const std::span<const uint8_t> body{buffer.subspan(MAGIC.size() + 2)};
    if (body.empty()) return {InputMode::FIXTURE, body};
    const bool generation{(body[0] & 0x0F) == 0x0F};
    return {generation ? InputMode::GENERATION : InputMode::FIXTURE, body.subspan(1)};
}

struct PQCFixture {
    CPQCPubKey pubkey;
    std::array<uint256, 2> hashes;
    std::array<std::vector<unsigned char>, 2> sigs;
};

/**
 * Two keys, each with two real signatures. Built on first use so that legacy
 * and generation inputs never pay for, or get coverage from, fixture signing.
 */
const std::array<PQCFixture, 2>& GetPQCFixtures()
{
    static const auto fixtures = [] {
        std::array<PQCFixture, 2> out;
        for (size_t key_index = 0; key_index < out.size(); ++key_index) {
            std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE> random_data{};
            for (size_t i = 0; i < random_data.size(); ++i) {
                random_data[i] = static_cast<unsigned char>(0xA5 ^ (key_index * 0x3B) ^ (i * 0x1D));
            }
            std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_bytes{};
            std::array<unsigned char, PQC_SECKEY_SIZE> seckey_bytes{};
            const int keygen_ret{slh_dsa_keygen(pubkey_bytes.data(), seckey_bytes.data(), random_data.data(), random_data.size())};
            assert(keygen_ret == 0);

            CPQCKey key;
            key.Set(seckey_bytes.data(), seckey_bytes.data() + seckey_bytes.size());
            assert(key.IsValid());
            out[key_index].pubkey = key.GetPubKey();
            assert(out[key_index].pubkey.IsValid());

            for (size_t msg_index = 0; msg_index < out[key_index].hashes.size(); ++msg_index) {
                const std::vector<unsigned char> message{'q', 'b', 'f', 'x', static_cast<unsigned char>(key_index), static_cast<unsigned char>(msg_index)};
                out[key_index].hashes[msg_index] = Hash(message);
                uint32_t counter{static_cast<uint32_t>(msg_index)};
                const bool signed_ok{key.Sign(out[key_index].hashes[msg_index], out[key_index].sigs[msg_index], counter)};
                assert(signed_ok);
                assert(out[key_index].pubkey.Verify(out[key_index].hashes[msg_index], out[key_index].sigs[msg_index]));
            }
        }
        assert(!(out[0].pubkey == out[1].pubkey));
        return out;
    }();
    return fixtures;
}

void FixturePQCInput(FuzzedDataProvider& fuzzed_data_provider)
{
    const auto& fixtures{GetPQCFixtures()};
    const size_t key_index{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, fixtures.size() - 1)};
    const size_t msg_index{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 1)};
    const PQCFixture& fixture{fixtures[key_index]};
    const uint256& hash{fixture.hashes[msg_index]};
    const std::vector<unsigned char>& sig{fixture.sigs[msg_index]};
    assert(fixture.pubkey.Verify(hash, sig));

    std::vector<unsigned char> sig_mut{sig};
    std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_mut{};
    std::copy(fixture.pubkey.begin(), fixture.pubkey.end(), pubkey_mut.begin());
    uint256 hash_mut{hash};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 4) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (sig_mut.empty()) return;
                const size_t pos{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, sig_mut.size() - 1)};
                sig_mut[pos] ^= static_cast<unsigned char>(1U << fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 7));
            },
            [&] {
                if (sig_mut.empty()) return;
                const size_t pos{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, sig_mut.size() - 1)};
                sig_mut[pos] = fuzzed_data_provider.ConsumeIntegral<unsigned char>();
            },
            [&] {
                sig_mut.resize(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, PQC_SIG_SIZE + 1));
            },
            [&] {
                const size_t pos{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, pubkey_mut.size() - 1)};
                pubkey_mut[pos] ^= static_cast<unsigned char>(1U << fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 7));
            },
            [&] {
                hash_mut = fixture.hashes[1 - msg_index];
            },
            [&] {
                hash_mut = Hash(ConsumeRandomLengthByteVector(fuzzed_data_provider));
            },
            [&] {
                const CPQCPubKey& other{fixtures[1 - key_index].pubkey};
                std::copy(other.begin(), other.end(), pubkey_mut.begin());
            });
    }

    // Only an input that differs from the signed fixture may be rejected.
    const bool changed{sig_mut != sig || hash_mut != hash ||
                       !std::equal(pubkey_mut.begin(), pubkey_mut.end(), fixture.pubkey.begin())};
    const CPQCPubKey pubkey{pubkey_mut};
    assert(pubkey.Verify(hash_mut, sig_mut) == !changed);
}

void LegacyPQCInput(FuzzedDataProvider& fuzzed_data_provider)
{
    const auto consume_key = [&] {
        std::vector<unsigned char> random_data{fuzzed_data_provider.ConsumeBytes<unsigned char>(PQC_KEYGEN_RANDOM_DATA_SIZE)};
        random_data.resize(PQC_KEYGEN_RANDOM_DATA_SIZE);

        std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_bytes{};
        std::array<unsigned char, PQC_SECKEY_SIZE> seckey_bytes{};
        if (slh_dsa_keygen(pubkey_bytes.data(), seckey_bytes.data(), random_data.data(), random_data.size()) != 0) {
            return CPQCKey{};
        }

        CPQCKey key;
        key.Set(seckey_bytes.data(), seckey_bytes.data() + seckey_bytes.size());
        return key;
    };

    {
        const std::vector<unsigned char> pubkey_bytes{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
        const std::vector<unsigned char> sig{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
        const uint256 hash{Hash(ConsumeRandomLengthByteVector(fuzzed_data_provider))};

        const CPQCPubKey pubkey{std::span<const unsigned char>{pubkey_bytes.data(), pubkey_bytes.size()}};
        assert(!pubkey.Verify(hash, sig));
    }

    {
        CPQCKey key{consume_key()};
        assert(key.IsValid());

        const CPQCPubKey pubkey{key.GetPubKey()};
        assert(pubkey.IsValid());

        const uint256 hash{Hash(ConsumeRandomLengthByteVector(fuzzed_data_provider))};
        std::vector<unsigned char> sig;
        uint32_t counter{fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, PQC_MAX_SIGNATURES - 1)};

        assert(key.Sign(hash, sig, counter));
        assert(sig.size() == PQC_SIG_SIZE);
        assert(pubkey.Verify(hash, sig));

        std::vector<unsigned char> mutated_sig{sig};
        const size_t pos{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mutated_sig.size() - 1)};
        const unsigned char bit{static_cast<unsigned char>(1U << fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 7))};
        mutated_sig[pos] ^= bit;
        assert(!pubkey.Verify(hash, mutated_sig));
    }

    {
        CPQCKey key{consume_key()};
        assert(key.IsValid());

        const CPQCPubKey pubkey{key.GetPubKey()};
        assert(pubkey.IsValid());

        const uint256 hash{Hash(ConsumeRandomLengthByteVector(fuzzed_data_provider))};
        std::vector<unsigned char> sig;
        uint32_t counter{fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, PQC_MAX_SIGNATURES - 1)};

        assert(key.Sign(hash, sig, counter));
        assert(pubkey.Verify(hash, sig));
    }

    {
        std::vector<unsigned char> imported_secret;
        if (fuzzed_data_provider.ConsumeBool()) {
            imported_secret = fuzzed_data_provider.ConsumeBytes<unsigned char>(PQC_SECKEY_SIZE);
            imported_secret.resize(PQC_SECKEY_SIZE);
        } else {
            const size_t size{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, PQC_SECKEY_SIZE * 2)};
            imported_secret = fuzzed_data_provider.ConsumeBytes<unsigned char>(size);
            imported_secret.resize(size);
        }

        if (fuzzed_data_provider.ConsumeBool()) {
            std::vector<unsigned char> random_data{fuzzed_data_provider.ConsumeBytes<unsigned char>(PQC_KEYGEN_RANDOM_DATA_SIZE)};
            random_data.resize(PQC_KEYGEN_RANDOM_DATA_SIZE);

            std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_bytes{};
            imported_secret.assign(PQC_SECKEY_SIZE, 0);
            if (slh_dsa_keygen(pubkey_bytes.data(), imported_secret.data(), random_data.data(), random_data.size()) == 0 &&
                fuzzed_data_provider.ConsumeBool()) {
                const size_t pos{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, imported_secret.size() - 1)};
                const unsigned char bit{static_cast<unsigned char>(1U << fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 7))};
                imported_secret[pos] ^= bit;
            }
        }

        const unsigned char* begin{imported_secret.empty() ? nullptr : imported_secret.data()};
        const unsigned char* end{imported_secret.empty() ? nullptr : imported_secret.data() + imported_secret.size()};

        CPQCKey key;
        key.Set(begin, end);

        const bool internally_consistent{
            imported_secret.size() == PQC_SECKEY_SIZE &&
            slh_dsa_secret_key_validate(imported_secret.data(), imported_secret.size()) == 0};
        const bool valid{key.IsValid()};
        assert(valid == internally_consistent);
        assert((key.size() == PQC_SECKEY_SIZE) == valid);
        assert((key.data() != nullptr) == valid);

        const CPQCPubKey pubkey{key.GetPubKey()};
        assert(pubkey.IsValid() == valid);

        const uint256 hash{Hash(ConsumeRandomLengthByteVector(fuzzed_data_provider))};
        std::vector<unsigned char> sig;
        const uint32_t counter_before{
            fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, PQC_MAX_SIGNATURES)};
        uint32_t counter{counter_before};
        const bool signed_ok{key.Sign(hash, sig, counter)};

        if (!key.IsValid() || counter_before >= PQC_MAX_SIGNATURES) {
            assert(!signed_ok);
        }
        if (signed_ok) {
            assert(sig.size() == PQC_SIG_SIZE);
            assert(counter == counter_before + 1);
            assert(pubkey.Verify(hash, sig));
        } else {
            assert(counter == counter_before);
            assert(sig.empty());
        }
    }
}
} // namespace

FUZZ_TARGET(pqc)
{
    const TaggedInput input{ParseTaggedInput(buffer, 'P')};
    FuzzedDataProvider fuzzed_data_provider{input.data.data(), input.data.size()};
    switch (input.mode) {
    case InputMode::LEGACY:
    case InputMode::GENERATION:
        LegacyPQCInput(fuzzed_data_provider);
        return;
    case InputMode::FIXTURE:
        FixturePQCInput(fuzzed_data_provider);
        return;
    case InputMode::UNSUPPORTED_VERSION:
        return;
    }
}
