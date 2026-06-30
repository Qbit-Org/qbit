// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_plaintext_validation_ready_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRPlaintextPQCRecordsRequireValidationBeforePrivateUse)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

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
    BOOST_CHECK_EQUAL(info.failed_records, 0U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(info.encryption_recommended);
    BOOST_CHECK(!loaded_wallet->IsPQCKeyValidationReadyForPrivateKeyUse());
    BOOST_CHECK(!loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        const auto pqc_keys{p2mr_spk_man->GetPQCKeys()};
        BOOST_REQUIRE(!pqc_keys.empty());
        const auto pending_key{p2mr_spk_man->GetNextPendingPlaintextPQCKey()};
        BOOST_REQUIRE(pending_key);
        BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(pending_key->first));
    }

    while (true) {
        const auto step_result{loaded_wallet->RunPlaintextPQCKeyValidationStep()};
        if (step_result == CWallet::PlaintextPQCKeyValidationStepResult::COMPLETE) break;
        BOOST_REQUIRE(step_result == CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS);
    }

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.pending_records, 0U);
    BOOST_CHECK_EQUAL(info.failed_records, 0U);
    BOOST_CHECK_GT(info.validated_records, 0U);
    BOOST_CHECK(!info.signing_blocked);
    BOOST_CHECK(info.encryption_recommended);
    BOOST_CHECK(loaded_wallet->IsPQCKeyValidationReadyForPrivateKeyUse());

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetPQCKeys().empty());
    }

    BOOST_REQUIRE(loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));
    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::NOT_REQUIRED);
    BOOST_CHECK_EQUAL(info.plaintext_records, 0U);
    BOOST_CHECK(!info.encryption_recommended);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
