// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqc.h>
#include <hash.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

FUZZ_TARGET(pqc)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
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
