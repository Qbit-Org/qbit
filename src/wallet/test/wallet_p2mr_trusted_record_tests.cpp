// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_trusted_record_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRWalletLoadRejectsTrustedRecordPubkeyTailMismatch)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

    bool mutated_pqc_record{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCKEY) continue;

        uint256 desc_id;
        CPQCPubKey pubkey;
        key_stream >> desc_id;
        key_stream >> pubkey;
        BOOST_REQUIRE(pubkey.IsValid());

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> secret;
        uint256 stored_hash;
        uint32_t sig_counter{0};
        value_stream >> secret;
        value_stream >> stored_hash;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE_EQUAL(secret.size(), CPQCKey::SIZE);

        secret.back() ^= 0x01;
        std::vector<unsigned char> to_hash;
        to_hash.reserve(pubkey.size() + secret.size() + sizeof(sig_counter));
        to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
        to_hash.insert(to_hash.end(), secret.begin(), secret.end());
        std::array<unsigned char, sizeof(sig_counter)> counter_bytes{};
        WriteLE32(counter_bytes.data(), sig_counter);
        to_hash.insert(to_hash.end(), counter_bytes.begin(), counter_bytes.end());

        DataStream new_value;
        new_value << secret;
        new_value << Hash(to_hash);
        new_value << sig_counter;
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
    BOOST_CHECK(!loaded_wallet);
    BOOST_CHECK(error.original.find("Wallet corrupted") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(P2MRWalletLoadDefersTrustedRecordBodyTamperToValidation)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

    CPQCPubKey mutated_pubkey;
    bool mutated_pqc_record{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCKEY) continue;

        uint256 desc_id;
        CPQCPubKey pubkey;
        key_stream >> desc_id;
        key_stream >> pubkey;
        BOOST_REQUIRE(pubkey.IsValid());

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> secret;
        uint256 stored_hash;
        uint32_t sig_counter{0};
        value_stream >> secret;
        value_stream >> stored_hash;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE_EQUAL(secret.size(), CPQCKey::SIZE);

        secret.front() ^= 0x01;
        std::vector<unsigned char> to_hash;
        to_hash.reserve(pubkey.size() + secret.size() + sizeof(sig_counter));
        to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
        to_hash.insert(to_hash.end(), secret.begin(), secret.end());
        std::array<unsigned char, sizeof(sig_counter)> counter_bytes{};
        WriteLE32(counter_bytes.data(), sig_counter);
        to_hash.insert(to_hash.end(), counter_bytes.begin(), counter_bytes.end());

        DataStream new_value;
        new_value << secret;
        new_value << Hash(to_hash);
        new_value << sig_counter;
        serialized_value = SerializeData{new_value.begin(), new_value.end()};
        mutated_pubkey = pubkey;
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

    PQCKeyValidationInfo info{loaded_wallet->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::PENDING);
    BOOST_CHECK_GT(info.pending_records, 0U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(info.encryption_recommended);
    BOOST_CHECK(!loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(mutated_pubkey));
    }

    CWallet::PlaintextPQCKeyValidationStepResult step_result{CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS};
    const size_t max_steps{info.pending_records};
    for (size_t i{0}; i < max_steps && step_result != CWallet::PlaintextPQCKeyValidationStepResult::FAILED; ++i) {
        step_result = loaded_wallet->RunPlaintextPQCKeyValidationStep();
    }
    BOOST_REQUIRE(step_result == CWallet::PlaintextPQCKeyValidationStepResult::FAILED);

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::FAILED);
    BOOST_CHECK_GT(info.failed_records, 0U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(!info.encryption_recommended);
    BOOST_CHECK(!loaded_wallet->IsPQCKeyValidationReadyForPrivateKeyUse());
    BOOST_CHECK(!loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(mutated_pubkey));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
