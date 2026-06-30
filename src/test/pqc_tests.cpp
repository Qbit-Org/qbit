// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <crypto/hex_base.h>
#include <crypto/pqc.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <libbitcoinpqc/bitcoinpqc.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>
#ifdef ENABLE_WALLET
#include <wallet/pqc_usage.h>
#endif

#include <algorithm>
#include <array>
#include <numeric>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pqc_tests, BasicTestingSetup)

#ifdef ENABLE_WALLET
using wallet::BuildSigningPQCUsageReport;
using wallet::FormatPQCUsageWarnings;
using wallet::GetPQCSignatureLimitState;
using wallet::PQCSignatureLimitState;
using wallet::PQCUsageRecorder;
#endif

namespace {

class PQCKeyOnlySigningProvider final : public SigningProvider
{
public:
    explicit PQCKeyOnlySigningProvider(const CPQCKey& key) : m_pubkey(key.GetPubKey()), m_key(key) {}

    bool GetPQCKey(const CPQCPubKey& pubkey, CPQCKey& key) const override
    {
        if (pubkey != m_pubkey) return false;
        key = m_key;
        return true;
    }

private:
    CPQCPubKey m_pubkey;
    CPQCKey m_key;
};

[[nodiscard]] uint256 TestHash(const char* tag)
{
    return Hash(std::string{tag});
}

[[nodiscard]] std::vector<unsigned char> CopySpan(std::span<const unsigned char> in)
{
    return {in.begin(), in.end()};
}

[[nodiscard]] std::string Sha256Hex(std::span<const unsigned char> in)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest{};
    CSHA256().Write(in.data(), in.size()).Finalize(digest.data());
    return HexStr(std::span<const unsigned char>{digest.data(), digest.size()});
}

void CheckInvalidPQCKey(const CPQCKey& key, const char* tag)
{
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), 0);
    BOOST_CHECK(key.data() == nullptr);

    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(!pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), 0);

    std::vector<unsigned char> sig{0x42};
    uint32_t counter{7};
    BOOST_CHECK(!key.Sign(TestHash(tag), sig, counter));
    BOOST_CHECK_EQUAL(counter, 7);
    BOOST_REQUIRE_EQUAL(sig.size(), 1U);
    BOOST_CHECK_EQUAL(sig.front(), 0x42);
}

#ifdef ENABLE_WALLET
[[nodiscard]] bool ContainsWarningSubstring(const std::vector<bilingual_str>& warnings, const std::string& needle)
{
    return std::any_of(warnings.begin(), warnings.end(), [&](const bilingual_str& warning) {
        return warning.original.find(needle) != std::string::npos;
    });
}
#endif

} // namespace

BOOST_AUTO_TEST_CASE(pqc_bounded30_profile_constants)
{
    BOOST_CHECK_EQUAL(PQC_PUBKEY_SIZE, SLH_DSA_SHA2_128S_BOUNDED30_PUBLIC_KEY_SIZE);
    BOOST_CHECK_EQUAL(PQC_SECKEY_SIZE, SLH_DSA_SHA2_128S_BOUNDED30_SECRET_KEY_SIZE);
    BOOST_CHECK_EQUAL(PQC_SIG_SIZE, SLH_DSA_SHA2_128S_BOUNDED30_SIGNATURE_SIZE);
    BOOST_CHECK_EQUAL(PQC_PUBKEY_SIZE, 32U);
    BOOST_CHECK_EQUAL(PQC_SECKEY_SIZE, 64U);
    BOOST_CHECK_EQUAL(PQC_SIG_SIZE, 3680U);
    BOOST_CHECK_EQUAL(PQC_MAX_SIGNATURES, 1U << 30);

    BOOST_CHECK_EQUAL(bitcoin_pqc_public_key_size(), PQC_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(bitcoin_pqc_secret_key_size(), PQC_SECKEY_SIZE);
    BOOST_CHECK_EQUAL(bitcoin_pqc_signature_size(), PQC_SIG_SIZE);
}

BOOST_AUTO_TEST_CASE(pqc_bounded30_known_answer_vector)
{
    std::array<unsigned char, 128> seed{};
    std::iota(seed.begin(), seed.end(), 0);

    std::array<unsigned char, 32> msg{};
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<unsigned char>(0xa0 + i);
    }

    const std::vector<unsigned char> expected_pk{ParseHex(
        "a1dab3577c94a2f33e80e41e593da88e"
        "36040b763fd6d077df412faa033062a3")};
    const std::vector<unsigned char> expected_sk{ParseHex(
        "d6264497cc4b4d2a5dbfdf72c4dafe26"
        "51f6d6d51f4f166bbe0b223cf902afa0"
        "a1dab3577c94a2f33e80e41e593da88e"
        "36040b763fd6d077df412faa033062a3")};
    constexpr std::string_view expected_sig_sha256{
        "6a1406d1631522bb8cf7abfdcd7cdca8f075c261234c5a49f2768882e20aead0"};

    std::array<unsigned char, PQC_PUBKEY_SIZE> pk{};
    std::array<unsigned char, PQC_SECKEY_SIZE> sk{};
    std::array<unsigned char, PQC_SIG_SIZE> sig{};
    size_t siglen{0};

    BOOST_CHECK_EQUAL(slh_dsa_keygen(pk.data(), sk.data(), seed.data(), seed.size()), 0);
    const std::vector<unsigned char> actual_pk{pk.begin(), pk.end()};
    const std::vector<unsigned char> actual_sk{sk.begin(), sk.end()};
    BOOST_CHECK(actual_pk == expected_pk);
    BOOST_CHECK(actual_sk == expected_sk);

    BOOST_CHECK_EQUAL(slh_dsa_sign(sig.data(), &siglen, msg.data(), msg.size(), sk.data()), 0);
    BOOST_CHECK_EQUAL(siglen, PQC_SIG_SIZE);
    BOOST_CHECK_EQUAL(Sha256Hex(sig), expected_sig_sha256);
    BOOST_CHECK_EQUAL(slh_dsa_verify(sig.data(), siglen, msg.data(), msg.size(), pk.data()), 0);

    uint256 hash;
    std::copy(msg.begin(), msg.end(), hash.begin());
    const CPQCPubKey pubkey{pk};
    BOOST_CHECK(pubkey.Verify(hash, sig));

    std::array<unsigned char, 32> wrong_msg{msg};
    wrong_msg[0] ^= 0x01;
    BOOST_CHECK_EQUAL(slh_dsa_verify(sig.data(), siglen, wrong_msg.data(), wrong_msg.size(), pk.data()), -1);

    std::vector<unsigned char> mutated_sig{sig.begin(), sig.end()};
    mutated_sig[0] ^= 0x01;
    BOOST_CHECK(!pubkey.Verify(hash, mutated_sig));
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pk.data(), pk.size(), msg.data(), msg.size(), mutated_sig.data(), mutated_sig.size()),
                      BITCOIN_PQC_ERROR_BAD_SIGNATURE);
}

BOOST_AUTO_TEST_CASE(pqc_keygen)
{
    CPQCKey key;
    BOOST_CHECK(!key.IsValid());
    key.MakeNewKey();
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), PQC_SECKEY_SIZE);

    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), PQC_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pqc_keygen_random_data_minimum)
{
    std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey{};
    std::array<unsigned char, PQC_SECKEY_SIZE> seckey{};
    std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE> random_data{};
    std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE - 1> short_random_data{};

    random_data.fill(0x42);
    short_random_data.fill(0x42);

    BOOST_CHECK_EQUAL(slh_dsa_keygen(pubkey.data(), seckey.data(), random_data.data(), random_data.size()), 0);
    BOOST_CHECK_NE(slh_dsa_keygen(pubkey.data(), seckey.data(), short_random_data.data(), short_random_data.size()), 0);
}

BOOST_AUTO_TEST_CASE(pqc_sign_verify_roundtrip)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const uint256 hash = TestHash("pqc_sign_verify_roundtrip");

    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key.Sign(hash, sig, counter));
    BOOST_CHECK(pubkey.Verify(hash, sig));
    BOOST_CHECK_EQUAL(counter, 1);
}

BOOST_AUTO_TEST_CASE(pqc_signature_size)
{
    CPQCKey key;
    key.MakeNewKey();
    const uint256 hash = TestHash("pqc_signature_size");

    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key.Sign(hash, sig, counter));
    BOOST_CHECK_EQUAL(sig.size(), PQC_SIG_SIZE);
}

BOOST_AUTO_TEST_CASE(pqc_pubkey_size)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> pubkey_bytes = CopySpan(std::span{pubkey.begin(), pubkey.end()});

    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), PQC_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(pubkey_bytes.size(), PQC_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(pqc_invalid_sig_rejected)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const uint256 hash = TestHash("pqc_invalid_sig_rejected");

    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key.Sign(hash, sig, counter));
    BOOST_REQUIRE(!sig.empty());
    sig[0] ^= 0x01;

    BOOST_CHECK(!pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(pqc_wrong_key_rejected)
{
    CPQCKey key1;
    CPQCKey key2;
    key1.MakeNewKey();
    key2.MakeNewKey();

    const uint256 hash = TestHash("pqc_wrong_key_rejected");
    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key1.Sign(hash, sig, counter));

    BOOST_CHECK(!key2.GetPubKey().Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(pqc_truncated_sig_rejected)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const uint256 hash = TestHash("pqc_truncated_sig_rejected");

    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key.Sign(hash, sig, counter));
    BOOST_REQUIRE(sig.size() > 1);
    sig.pop_back();

    BOOST_CHECK(!pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(pqc_c_api_verify_fail_closed)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const uint256 hash = TestHash("pqc_c_api_verify_fail_closed");

    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key.Sign(hash, sig, counter));
    BOOST_REQUIRE_EQUAL(sig.size(), PQC_SIG_SIZE);

    const unsigned char* pubkey_data = pubkey.data();
    const unsigned char* msg_data = hash.begin();
    const unsigned char* sig_data = sig.data();

    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, msg_data, hash.size(), sig_data, sig.size()),
                      BITCOIN_PQC_OK);

    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(nullptr, PQC_PUBKEY_SIZE, msg_data, hash.size(), sig_data, sig.size()),
                      BITCOIN_PQC_ERROR_BAD_ARG);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, nullptr, hash.size(), sig_data, sig.size()),
                      BITCOIN_PQC_ERROR_BAD_ARG);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, msg_data, hash.size(), nullptr, sig.size()),
                      BITCOIN_PQC_ERROR_BAD_ARG);

    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, 0, msg_data, hash.size(), sig_data, sig.size()),
                      BITCOIN_PQC_ERROR_BAD_KEY);
    const std::vector<unsigned char> truncated_pubkey(PQC_PUBKEY_SIZE - 1, 0x42);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(truncated_pubkey.data(), truncated_pubkey.size(), msg_data, hash.size(), sig_data, sig.size()),
                      BITCOIN_PQC_ERROR_BAD_KEY);
    const std::vector<unsigned char> oversized_pubkey(PQC_PUBKEY_SIZE + 1, 0x42);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(oversized_pubkey.data(), oversized_pubkey.size(), msg_data, hash.size(), sig_data, sig.size()),
                      BITCOIN_PQC_ERROR_BAD_KEY);

    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, msg_data, hash.size(), sig_data, 0),
                      BITCOIN_PQC_ERROR_BAD_SIGNATURE);
    const std::vector<unsigned char> truncated_sig(sig.begin(), sig.end() - 1);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, msg_data, hash.size(), truncated_sig.data(), truncated_sig.size()),
                      BITCOIN_PQC_ERROR_BAD_SIGNATURE);
    std::vector<unsigned char> oversized_sig{sig};
    oversized_sig.push_back(0x42);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, msg_data, hash.size(), oversized_sig.data(), oversized_sig.size()),
                      BITCOIN_PQC_ERROR_BAD_SIGNATURE);

    std::vector<unsigned char> malformed_sig(PQC_SIG_SIZE, 0x00);
    BOOST_CHECK_EQUAL(bitcoin_pqc_verify(pubkey_data, PQC_PUBKEY_SIZE, msg_data, hash.size(), malformed_sig.data(), malformed_sig.size()),
                      BITCOIN_PQC_ERROR_BAD_SIGNATURE);
}

BOOST_AUTO_TEST_CASE(pqc_low_wots_cap_sign_failure_cleans_output)
{
    std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE> seed{};
    std::array<unsigned char, PQC_PUBKEY_SIZE> pk{};
    std::array<unsigned char, PQC_SECKEY_SIZE> sk{};
    std::array<unsigned char, PQC_SIG_SIZE> sig{};
    std::array<unsigned char, 32> msg{};

    std::iota(seed.begin(), seed.end(), 0);
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<unsigned char>(0xb0 + i);
    }

    BOOST_REQUIRE_EQUAL(slh_dsa_keygen(pk.data(), sk.data(), seed.data(), seed.size()), 0);

    sig.fill(0xa5);
    size_t siglen{sig.size()};
    bitcoin_pqc_sign_stats_t stats{};
    const int ret = slh_dsa_sign_with_stats(sig.data(), &siglen, msg.data(), msg.size(), sk.data(), &stats);

    if (stats.wotsc_max_attempts != 1) {
        BOOST_TEST_MESSAGE("skipping low WOTS+C cap buffer-cleansing assertion; configure with -DBITCOINPQC_WOTSC_MAX_COUNTER=0");
        return;
    }

    BOOST_CHECK_NE(ret, 0);
    BOOST_CHECK_EQUAL(siglen, 0U);
    BOOST_CHECK_EQUAL(stats.cap_exceeded & BITCOIN_PQC_SIGN_LIMIT_WOTSC, BITCOIN_PQC_SIGN_LIMIT_WOTSC);
    BOOST_CHECK(std::all_of(sig.begin(), sig.end(), [](unsigned char byte) { return byte == 0; }));
}

BOOST_AUTO_TEST_CASE(pqc_wrong_message_rejected)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    const uint256 hash1 = TestHash("pqc_wrong_message_rejected_1");
    const uint256 hash2 = TestHash("pqc_wrong_message_rejected_2");
    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(key.Sign(hash1, sig, counter));

    BOOST_CHECK(!pubkey.Verify(hash2, sig));
}

BOOST_AUTO_TEST_CASE(pqc_counter_enforcement)
{
    CPQCKey key;
    key.MakeNewKey();
    const uint256 hash = TestHash("pqc_counter_enforcement");
    std::vector<unsigned char> sig;

    uint32_t counter = PQC_MAX_SIGNATURES - 1;
    BOOST_CHECK(key.Sign(hash, sig, counter));
    BOOST_CHECK_EQUAL(counter, PQC_MAX_SIGNATURES);

    const std::vector<unsigned char> sig_before = sig;
    BOOST_CHECK(!key.Sign(hash, sig, counter));
    BOOST_CHECK_EQUAL(counter, PQC_MAX_SIGNATURES);
    BOOST_CHECK(sig == sig_before);
}

BOOST_AUTO_TEST_CASE(pqc_deterministic_signing)
{
    CPQCKey key;
    key.MakeNewKey();
    const uint256 hash = TestHash("pqc_deterministic_signing");

    std::vector<unsigned char> sig1;
    std::vector<unsigned char> sig2;
    uint32_t counter1{0};
    uint32_t counter2{0};
    BOOST_CHECK(key.Sign(hash, sig1, counter1));
    BOOST_CHECK(key.Sign(hash, sig2, counter2));

    BOOST_CHECK(sig1 == sig2);
    BOOST_CHECK_EQUAL(counter1, 1);
    BOOST_CHECK_EQUAL(counter2, 1);
}

BOOST_AUTO_TEST_CASE(pqc_signing_provider_counter_updates)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);
    provider.pqc_sig_counters.emplace(pubkey, 0);

    int callback_calls = 0;
    uint32_t last_expected_counter = 0;
    uint32_t last_persisted_counter = 0;
    provider.pqc_counter_writer = [&](const CPQCPubKey& seen_pubkey, uint32_t expected_counter, uint32_t sig_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        ++callback_calls;
        last_expected_counter = expected_counter;
        last_persisted_counter = sig_counter;
        if (provider.pqc_sig_counters[pubkey] != expected_counter) return false;
        return true;
    };

    std::vector<unsigned char> sig1;
    std::vector<unsigned char> sig2;
    const uint256 hash1 = TestHash("pqc_signing_provider_counter_updates_1");
    const uint256 hash2 = TestHash("pqc_signing_provider_counter_updates_2");

    BOOST_CHECK(provider.SignPQC(pubkey, hash1, sig1));
    BOOST_CHECK_EQUAL(last_expected_counter, 0);
    BOOST_CHECK_EQUAL(last_persisted_counter, 1);
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters[pubkey], 1);
    BOOST_CHECK(provider.SignPQC(pubkey, hash2, sig2));
    BOOST_CHECK_EQUAL(last_expected_counter, 1);
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters[pubkey], 2);
    BOOST_CHECK_EQUAL(last_persisted_counter, 2);
    BOOST_CHECK_EQUAL(callback_calls, 2);
}

BOOST_AUTO_TEST_CASE(pqc_signing_provider_reserves_authoritative_counter)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    uint32_t authoritative_counter{0};
    auto reserve_next = [&](const CPQCPubKey& seen_pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        BOOST_CHECK_EQUAL(count, 1U);
        if (authoritative_counter > PQC_MAX_SIGNATURES - count) return false;
        previous_counter = authoritative_counter;
        reserved_counter = authoritative_counter + count;
        authoritative_counter = reserved_counter;
        return true;
    };

    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
    auto observe = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        observed_ranges.emplace_back(previous_counter, reserved_counter);
    };

    FlatSigningProvider first;
    first.pqc_keys.emplace(pubkey, key);
    first.pqc_sig_counters.emplace(pubkey, 0);
    first.pqc_counter_reserver = reserve_next;
    first.pqc_counter_observer = observe;

    FlatSigningProvider second;
    second.pqc_keys.emplace(pubkey, key);
    second.pqc_sig_counters.emplace(pubkey, 0);
    second.pqc_counter_reserver = reserve_next;
    second.pqc_counter_observer = observe;

    std::vector<unsigned char> sig1;
    std::vector<unsigned char> sig2;
    BOOST_CHECK(first.SignPQC(pubkey, TestHash("pqc_signing_provider_reserves_authoritative_counter_1"), sig1));
    BOOST_CHECK(second.SignPQC(pubkey, TestHash("pqc_signing_provider_reserves_authoritative_counter_2"), sig2));

    BOOST_CHECK_EQUAL(authoritative_counter, 2U);
    BOOST_CHECK_EQUAL(first.pqc_sig_counters[pubkey], 1U);
    BOOST_CHECK_EQUAL(second.pqc_sig_counters[pubkey], 2U);
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), 2U);
    BOOST_CHECK(observed_ranges[0] == std::make_pair(0U, 1U));
    BOOST_CHECK(observed_ranges[1] == std::make_pair(1U, 2U));
}

BOOST_AUTO_TEST_CASE(pqc_signing_provider_reports_committed_reservation_on_sign_failure)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    uint32_t authoritative_counter{0};

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);
    provider.pqc_sig_counters.emplace(pubkey, 0);
    provider.pqc_counter_reserver = [&](const CPQCPubKey& seen_pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        BOOST_CHECK_EQUAL(count, 1U);
        previous_counter = authoritative_counter;
        reserved_counter = authoritative_counter + count;
        authoritative_counter = reserved_counter;
        return true;
    };

    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
    provider.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        observed_ranges.emplace_back(previous_counter, reserved_counter);
    };
    provider.pqc_raw_signer = [&](const CPQCKey&, const uint256&, std::vector<unsigned char>& sig, uint32_t&) {
        sig.assign(PQC_SIG_SIZE, 0x42);
        return false;
    };

    std::vector<unsigned char> sig;
    BOOST_CHECK(!provider.SignPQC(pubkey, TestHash("pqc_signing_provider_reports_committed_reservation_on_sign_failure"), sig));
    BOOST_CHECK(sig.empty());
    BOOST_CHECK_EQUAL(authoritative_counter, 1U);
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters[pubkey], 1U);
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), 1U);
    BOOST_CHECK(observed_ranges[0] == std::make_pair(0U, 1U));
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(pqc_usage_level_boundaries)
{
    BOOST_CHECK(GetPQCSignatureLimitState((1U << 28) - 1) == PQCSignatureLimitState::NORMAL);
    BOOST_CHECK(GetPQCSignatureLimitState(1U << 28) == PQCSignatureLimitState::WARNING);
    BOOST_CHECK(GetPQCSignatureLimitState((PQC_MAX_SIGNATURES - (1U << 24)) - 1) == PQCSignatureLimitState::WARNING);
    BOOST_CHECK(GetPQCSignatureLimitState(PQC_MAX_SIGNATURES - (1U << 24)) == PQCSignatureLimitState::CRITICAL);
    BOOST_CHECK(GetPQCSignatureLimitState(PQC_MAX_SIGNATURES - 1) == PQCSignatureLimitState::CRITICAL);
    BOOST_CHECK(GetPQCSignatureLimitState(PQC_MAX_SIGNATURES) == PQCSignatureLimitState::EXHAUSTED);
}

BOOST_AUTO_TEST_CASE(pqc_usage_report_transition_and_reminder_logic)
{
    CPQCKey warning_key;
    warning_key.MakeNewKey();
    const CPQCPubKey warning_pubkey = warning_key.GetPubKey();

    CPQCKey reminder_key;
    reminder_key.MakeNewKey();
    const CPQCPubKey reminder_pubkey = reminder_key.GetPubKey();

    CPQCKey critical_key;
    critical_key.MakeNewKey();
    const CPQCPubKey critical_pubkey = critical_key.GetPubKey();

    PQCUsageRecorder recorder;
    recorder.Observe(warning_pubkey, (1U << 28) - 1, 1U << 28);
    recorder.Observe(reminder_pubkey, 1U << 28, (1U << 28) + (1U << 24) + 17);
    recorder.Observe(critical_pubkey, PQC_MAX_SIGNATURES - (1U << 24), PQC_MAX_SIGNATURES - (1U << 24) + (1U << 20) + 9);

    const auto report = BuildSigningPQCUsageReport(recorder);
    const auto warnings = FormatPQCUsageWarnings(report.warnings);

    BOOST_REQUIRE_EQUAL(report.key_states.size(), 3U);
    BOOST_REQUIRE(report.overall_state.has_value());
    BOOST_CHECK(*report.overall_state == PQCSignatureLimitState::CRITICAL);
    BOOST_REQUIRE_EQUAL(warnings.size(), 3U);
    BOOST_CHECK(ContainsWarningSubstring(warnings, "entered warning usage range"));
    BOOST_CHECK(ContainsWarningSubstring(warnings, "remains in warning usage range"));
    BOOST_CHECK(ContainsWarningSubstring(warnings, "remains in critical usage range"));
}

BOOST_AUTO_TEST_CASE(pqc_usage_report_collapse_and_single_warning_per_key)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    PQCUsageRecorder recorder;
    recorder.Observe(pubkey, (1U << 28) - 2, (1U << 28) - 1);
    recorder.Observe(pubkey, (1U << 28) - 1, 1U << 28);
    recorder.Observe(pubkey, 1U << 28, (1U << 28) + 5);

    const auto advances = recorder.GetAdvances();
    BOOST_REQUIRE_EQUAL(advances.size(), 1U);
    BOOST_CHECK_EQUAL(advances[0].previous_count, (1U << 28) - 2);
    BOOST_CHECK_EQUAL(advances[0].new_count, (1U << 28) + 5);

    const auto report = BuildSigningPQCUsageReport(recorder);
    const auto warnings = FormatPQCUsageWarnings(report.warnings);
    BOOST_REQUIRE_EQUAL(report.key_states.size(), 1U);
    BOOST_REQUIRE_EQUAL(warnings.size(), 1U);
    BOOST_CHECK(report.key_states[0].limit_state == PQCSignatureLimitState::WARNING);
    BOOST_CHECK(warnings[0].original.find("entered warning usage range") != std::string::npos);
}
#endif

BOOST_AUTO_TEST_CASE(pqc_signing_provider_counter_enforced)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);
    provider.pqc_sig_counters.emplace(pubkey, PQC_MAX_SIGNATURES);

    bool callback_called = false;
    provider.pqc_counter_writer = [&](const CPQCPubKey&, uint32_t, uint32_t) {
        callback_called = true;
        return true;
    };

    std::vector<unsigned char> sig;
    BOOST_CHECK(!provider.SignPQC(pubkey, TestHash("pqc_signing_provider_counter_enforced"), sig));
    BOOST_CHECK(!callback_called);
}

BOOST_AUTO_TEST_CASE(pqc_signing_provider_requires_override_for_counter_safety)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    PQCKeyOnlySigningProvider provider{key};
    std::vector<unsigned char> sig;

    BOOST_CHECK(!provider.SignPQC(pubkey, TestHash("pqc_signing_provider_requires_override_for_counter_safety"), sig));
    BOOST_CHECK(sig.empty());
}

BOOST_AUTO_TEST_CASE(pqc_signing_provider_merge_uses_max_counter)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    FlatSigningProvider lower;
    lower.pqc_sig_counters.emplace(pubkey, 7);
    FlatSigningProvider higher;
    higher.pqc_sig_counters.emplace(pubkey, 12);

    lower.Merge(std::move(higher));
    BOOST_CHECK_EQUAL(lower.pqc_sig_counters[pubkey], 12);

    FlatSigningProvider still_higher;
    still_higher.pqc_sig_counters.emplace(pubkey, 20);
    FlatSigningProvider lower_update;
    lower_update.pqc_sig_counters.emplace(pubkey, 4);

    still_higher.Merge(std::move(lower_update));
    BOOST_CHECK_EQUAL(still_higher.pqc_sig_counters[pubkey], 20);
}

BOOST_AUTO_TEST_CASE(pqc_pubkey_getid)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CKeyID id1 = pubkey.GetID();
    const CKeyID id2 = pubkey.GetID();

    BOOST_CHECK(id1 == id2);
    BOOST_CHECK(id1 == CKeyID(Hash160(std::span<const unsigned char>{pubkey.data(), pubkey.size()})));
}

BOOST_AUTO_TEST_CASE(pqc_key_copy)
{
    CPQCKey key;
    key.MakeNewKey();
    CPQCKey copy{key};
    BOOST_CHECK(copy.IsValid());
    BOOST_CHECK(copy == key);

    const uint256 hash = TestHash("pqc_key_copy");
    std::vector<unsigned char> sig1;
    std::vector<unsigned char> sig2;
    uint32_t counter1{0};
    uint32_t counter2{0};
    BOOST_CHECK(key.Sign(hash, sig1, counter1));
    BOOST_CHECK(copy.Sign(hash, sig2, counter2));
    BOOST_CHECK(sig1 == sig2);
}

BOOST_AUTO_TEST_CASE(pqc_derivation_adopts_trusted_keygen_output)
{
    std::array<unsigned char, 64> master_seed{};
    std::iota(master_seed.begin(), master_seed.end(), 0x42);

    CPQCKey derived;
    BOOST_REQUIRE(DerivePQCKey(std::span<const unsigned char>{master_seed.data(), master_seed.size()},
                               /*account=*/0, /*change=*/0, /*index=*/0, derived));
    BOOST_REQUIRE(derived.IsValid());
    BOOST_CHECK_EQUAL(derived.size(), PQC_SECKEY_SIZE);

    const CPQCPubKey pubkey = derived.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), PQC_PUBKEY_SIZE);

    const uint256 hash = TestHash("pqc_derivation_adopts_trusted_keygen_output");
    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_REQUIRE(derived.Sign(hash, sig, counter));
    BOOST_CHECK(pubkey.Verify(hash, sig));
    BOOST_CHECK_EQUAL(counter, 1);

    const std::vector<unsigned char> derived_secret{derived.data(), derived.data() + derived.size()};
    CPQCKey imported;
    imported.Set(derived_secret.data(), derived_secret.data() + derived_secret.size());
    BOOST_REQUIRE(imported.IsValid());
    BOOST_CHECK(imported == derived);
    BOOST_CHECK(imported.GetPubKey() == pubkey);
}

BOOST_AUTO_TEST_CASE(pqc_set_roundtrip_and_reject_invalid_lengths)
{
    CPQCKey original;
    original.MakeNewKey();
    BOOST_REQUIRE(original.IsValid());

    const std::vector<unsigned char> seckey_bytes{original.data(), original.data() + original.size()};
    BOOST_REQUIRE_EQUAL(seckey_bytes.size(), PQC_SECKEY_SIZE);

    CPQCKey restored;
    restored.Set(seckey_bytes.data(), seckey_bytes.data() + seckey_bytes.size());
    BOOST_REQUIRE(restored.IsValid());
    BOOST_CHECK(restored == original);

    const uint256 hash = TestHash("pqc_set_roundtrip_and_reject_invalid_lengths");
    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_REQUIRE(restored.Sign(hash, sig, counter));
    BOOST_CHECK(original.GetPubKey().Verify(hash, sig));

    CPQCKey short_input;
    short_input.Set(seckey_bytes.data(), seckey_bytes.data() + seckey_bytes.size() - 1);
    CheckInvalidPQCKey(short_input, "pqc_set_short_input");

    std::vector<unsigned char> oversized_bytes{seckey_bytes};
    oversized_bytes.push_back(0x42);
    CPQCKey oversized_input;
    oversized_input.MakeNewKey();
    BOOST_REQUIRE(oversized_input.IsValid());
    oversized_input.Set(oversized_bytes.data(), oversized_bytes.data() + oversized_bytes.size());
    CheckInvalidPQCKey(oversized_input, "pqc_set_oversized_input");

    CPQCKey empty_input;
    empty_input.Set(seckey_bytes.data(), seckey_bytes.data());
    CheckInvalidPQCKey(empty_input, "pqc_set_empty_input");

    CPQCKey null_input;
    null_input.Set(nullptr, nullptr);
    CheckInvalidPQCKey(null_input, "pqc_set_null_input");
}

BOOST_AUTO_TEST_CASE(pqc_set_rejects_inconsistent_exact_size_secrets)
{
    CPQCKey original;
    original.MakeNewKey();
    BOOST_REQUIRE(original.IsValid());

    const std::vector<unsigned char> valid_secret{original.data(), original.data() + original.size()};
    BOOST_REQUIRE_EQUAL(valid_secret.size(), PQC_SECKEY_SIZE);
    BOOST_REQUIRE_EQUAL(slh_dsa_secret_key_validate(valid_secret.data(), valid_secret.size()), 0);

    CPQCKey valid_import;
    valid_import.Set(valid_secret.data(), valid_secret.data() + valid_secret.size());
    BOOST_REQUIRE(valid_import.IsValid());
    BOOST_CHECK(valid_import == original);

    std::array<unsigned char, PQC_SECKEY_SIZE> zero_secret{};
    BOOST_REQUIRE_NE(slh_dsa_secret_key_validate(zero_secret.data(), zero_secret.size()), 0);
    CPQCKey zero_import;
    zero_import.MakeNewKey();
    BOOST_REQUIRE(zero_import.IsValid());
    zero_import.Set(zero_secret.data(), zero_secret.data() + zero_secret.size());
    CheckInvalidPQCKey(zero_import, "pqc_set_zero_secret");

    std::array<unsigned char, PQC_SECKEY_SIZE> arbitrary_secret{};
    std::iota(arbitrary_secret.begin(), arbitrary_secret.end(), 1);
    BOOST_REQUIRE_NE(slh_dsa_secret_key_validate(arbitrary_secret.data(), arbitrary_secret.size()), 0);
    CPQCKey arbitrary_import;
    arbitrary_import.Set(arbitrary_secret.data(), arbitrary_secret.data() + arbitrary_secret.size());
    CheckInvalidPQCKey(arbitrary_import, "pqc_set_arbitrary_secret");

    const auto check_mutated_secret = [&](size_t pos, const char* tag) {
        std::vector<unsigned char> mutated_secret{valid_secret};
        mutated_secret[pos] ^= 0x01;
        BOOST_REQUIRE_NE(slh_dsa_secret_key_validate(mutated_secret.data(), mutated_secret.size()), 0);

        CPQCKey imported;
        imported.MakeNewKey();
        BOOST_REQUIRE(imported.IsValid());
        imported.Set(mutated_secret.data(), mutated_secret.data() + mutated_secret.size());
        CheckInvalidPQCKey(imported, tag);
    };

    check_mutated_secret(/*pos=*/0, "pqc_set_mutated_sk_seed");
    check_mutated_secret(/*pos=*/PQC_SECKEY_SIZE - PQC_PUBKEY_SIZE, "pqc_set_mutated_pub_seed");
    check_mutated_secret(/*pos=*/PQC_SECKEY_SIZE - 1, "pqc_set_mutated_root");
}

BOOST_AUTO_TEST_CASE(pqc_trusted_wallet_restore_checks_persisted_pubkey_boundary)
{
    CPQCKey original;
    original.MakeNewKey();
    BOOST_REQUIRE(original.IsValid());
    const CPQCPubKey pubkey = original.GetPubKey();
    const std::vector<unsigned char> secret{original.data(), original.data() + original.size()};

    CPQCKey restored;
    restored.SetFromTrustedWalletRecord(std::span<const unsigned char>{secret.data(), secret.size()}, pubkey);
    BOOST_REQUIRE(restored.IsValid());
    BOOST_CHECK(restored == original);
    BOOST_CHECK(restored.GetPubKey() == pubkey);

    CPQCKey other;
    other.MakeNewKey();
    BOOST_REQUIRE(other.IsValid());
    CPQCKey mismatched_pubkey;
    mismatched_pubkey.SetFromTrustedWalletRecord(std::span<const unsigned char>{secret.data(), secret.size()}, other.GetPubKey());
    CheckInvalidPQCKey(mismatched_pubkey, "pqc_trusted_wallet_restore_mismatched_pubkey");

    CPQCKey invalid_pubkey;
    invalid_pubkey.SetFromTrustedWalletRecord(std::span<const unsigned char>{secret.data(), secret.size()}, CPQCPubKey{});
    CheckInvalidPQCKey(invalid_pubkey, "pqc_trusted_wallet_restore_invalid_pubkey");

    std::vector<unsigned char> mutated_seed_secret{secret};
    mutated_seed_secret.front() ^= 0x01;
    BOOST_REQUIRE_NE(slh_dsa_secret_key_validate(mutated_seed_secret.data(), mutated_seed_secret.size()), 0);

    CPQCKey trusted_record;
    trusted_record.SetFromTrustedWalletRecord(std::span<const unsigned char>{mutated_seed_secret.data(), mutated_seed_secret.size()}, pubkey);
    BOOST_REQUIRE(trusted_record.IsValid());
    BOOST_CHECK(trusted_record.GetPubKey() == pubkey);

    std::vector<unsigned char> sig;
    uint32_t counter{7};
    BOOST_CHECK(!trusted_record.Sign(TestHash("pqc_trusted_wallet_restore_mutated_seed"), sig, counter));
    BOOST_CHECK_EQUAL(counter, 7);
}

BOOST_AUTO_TEST_CASE(pqc_assignment_from_invalid_clears_state)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());

    const CPQCPubKey original_pubkey = key.GetPubKey();
    BOOST_REQUIRE(original_pubkey.IsValid());

    const CPQCKey invalid_source;
    key = invalid_source;

    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), 0);
    BOOST_CHECK(key.data() == nullptr);

    const uint256 hash = TestHash("pqc_assignment_from_invalid_clears_state");
    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(!key.Sign(hash, sig, counter));

    const CPQCPubKey cleared_pubkey = key.GetPubKey();
    BOOST_CHECK(!cleared_pubkey.IsValid());
    BOOST_CHECK_EQUAL(cleared_pubkey.size(), 0);
    BOOST_CHECK(cleared_pubkey.begin() == cleared_pubkey.end());

    BOOST_CHECK(original_pubkey.IsValid());
}

BOOST_AUTO_TEST_CASE(pqc_invalid_pubkey_construction_getid_and_ordering)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey valid_pubkey = key.GetPubKey();
    BOOST_REQUIRE(valid_pubkey.IsValid());
    BOOST_REQUIRE_EQUAL(valid_pubkey.size(), CPQCPubKey::SIZE);

    std::vector<unsigned char> short_bytes{valid_pubkey.begin(), valid_pubkey.begin() + (CPQCPubKey::SIZE - 1)};

    std::vector<unsigned char> long_bytes{valid_pubkey.begin(), valid_pubkey.end()};
    long_bytes.push_back(0x42);

    CPQCPubKey invalid_default;
    const CPQCPubKey invalid_short{std::span<const unsigned char>{short_bytes.data(), short_bytes.size()}};
    const CPQCPubKey invalid_long{std::span<const unsigned char>{long_bytes.data(), long_bytes.size()}};

    BOOST_CHECK(!invalid_short.IsValid());
    BOOST_CHECK(!invalid_long.IsValid());
    BOOST_CHECK_EQUAL(invalid_short.size(), 0);
    BOOST_CHECK_EQUAL(invalid_long.size(), 0);
    BOOST_CHECK(invalid_short.GetID() == CKeyID{});
    BOOST_CHECK(invalid_long.GetID() == CKeyID{});

    BOOST_CHECK(invalid_default == invalid_short);
    BOOST_CHECK(invalid_short == invalid_long);
    BOOST_CHECK(!(invalid_short < invalid_default));
    BOOST_CHECK(!(invalid_default < invalid_short));

    BOOST_CHECK(invalid_short < valid_pubkey);
    BOOST_CHECK(!(valid_pubkey < invalid_short));
}

BOOST_AUTO_TEST_CASE(pqc_invalid_key)
{
    CPQCKey key;
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK_EQUAL(key.size(), 0);

    std::vector<unsigned char> sig;
    uint32_t counter{0};
    BOOST_CHECK(!key.Sign(TestHash("pqc_invalid_key"), sig, counter));

    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(!pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), 0);
    BOOST_CHECK(pubkey.begin() == pubkey.end());
}

BOOST_AUTO_TEST_CASE(pqc_pubkey_serialization)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    DataStream stream{};
    stream << pubkey;

    CPQCPubKey deserialized;
    stream >> deserialized;
    BOOST_CHECK(deserialized.IsValid());
    BOOST_CHECK(deserialized == pubkey);
}

BOOST_AUTO_TEST_CASE(pqc_invalid_pubkey_serialization_roundtrip)
{
    CPQCPubKey invalid;
    BOOST_CHECK(!invalid.IsValid());
    BOOST_CHECK_EQUAL(invalid.size(), 0);

    DataStream stream{};
    stream << invalid;

    CPQCPubKey deserialized;
    stream >> deserialized;
    BOOST_CHECK(!deserialized.IsValid());
    BOOST_CHECK_EQUAL(deserialized.size(), 0);
    BOOST_CHECK(deserialized.begin() == deserialized.end());
}

BOOST_AUTO_TEST_SUITE_END()
