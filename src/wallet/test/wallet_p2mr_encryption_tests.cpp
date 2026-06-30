// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_encryption_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRKeysAreEncryptedAtRest)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetPQCKeys().empty());
    }

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsLocked());

    {
        LOCK(wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetPQCKeys().empty());
    }

    int pqc_plain_records{0};
    int pqc_crypted_records{0};
    int pqc_authenticated_crypted_records{0};
    for (const auto& [serialized_key, serialized_value] : GetMockableDatabase(*wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::WALLETDESCRIPTORPQCKEY) {
            ++pqc_plain_records;
        } else if (record_type == DBKeys::WALLETDESCRIPTORPQCCKEY) {
            ++pqc_crypted_records;

            DataStream value_stream{serialized_value};
            std::vector<unsigned char> crypted_secret;
            uint32_t sig_counter{0};
            uint256 auth_tag;
            value_stream >> crypted_secret;
            BOOST_REQUIRE(!value_stream.eof());
            value_stream >> sig_counter;
            BOOST_REQUIRE(!value_stream.eof());
            value_stream >> auth_tag;
            BOOST_CHECK(value_stream.eof());
            ++pqc_authenticated_crypted_records;
        }
    }

    BOOST_CHECK_EQUAL(pqc_plain_records, 0);
    BOOST_CHECK_GT(pqc_crypted_records, 0);
    BOOST_CHECK_EQUAL(pqc_authenticated_crypted_records, pqc_crypted_records);

}

BOOST_AUTO_TEST_CASE(P2MREncryptedPQCAuthTagRejectsCiphertextTamper)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsLocked());

    MockableData records = GetMockableDatabase(*wallet).m_records;

    bool mutated_pqc_record{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> crypted_secret;
        uint32_t sig_counter{0};
        uint256 auth_tag;
        value_stream >> crypted_secret;
        BOOST_REQUIRE(!crypted_secret.empty());
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> auth_tag;
        BOOST_REQUIRE(value_stream.eof());

        crypted_secret.front() ^= 0x01;

        DataStream new_value;
        new_value << crypted_secret;
        new_value << sig_counter;
        new_value << auth_tag;
        serialized_value = SerializeData{new_value.begin(), new_value.end()};
        mutated_pqc_record = true;
        break;
    }
    BOOST_REQUIRE(mutated_pqc_record);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);

    bool unlocked{false};
    bool threw{false};
    try {
        unlocked = loaded_wallet->Unlock(passphrase);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    BOOST_CHECK(threw || !unlocked);
}

BOOST_AUTO_TEST_CASE(P2MRLegacyEncryptedPQCRecordsUpgradeOnUnlock)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsLocked());

    MockableData records = GetMockableDatabase(*wallet).m_records;

    int stripped_pqc_records{0};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> crypted_secret;
        uint32_t sig_counter{0};
        uint256 auth_tag;
        value_stream >> crypted_secret;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> auth_tag;
        BOOST_REQUIRE(value_stream.eof());

        DataStream legacy_value;
        legacy_value << crypted_secret;
        legacy_value << sig_counter;
        serialized_value = SerializeData{legacy_value.begin(), legacy_value.end()};
        ++stripped_pqc_records;
    }
    BOOST_REQUIRE_GT(stripped_pqc_records, 0);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE(loaded_wallet->Unlock(passphrase));

    int upgraded_pqc_records{0};
    for (const auto& [serialized_key, serialized_value] : GetMockableDatabase(*loaded_wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> crypted_secret;
        uint32_t sig_counter{0};
        uint256 auth_tag;
        value_stream >> crypted_secret;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> auth_tag;
        BOOST_CHECK(value_stream.eof());
        ++upgraded_pqc_records;
    }
    BOOST_CHECK_EQUAL(upgraded_pqc_records, stripped_pqc_records);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
