// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_plaintext_validation_failure_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRPlaintextPQCValidationContinuesAfterFailure)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);
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
    BOOST_REQUIRE_GT(info.pending_records, 2U);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(loaded_wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);
    const auto failed_pending_key{p2mr_spk_man->GetNextPendingPlaintextPQCKey()};
    BOOST_REQUIRE(failed_pending_key);
    BOOST_REQUIRE(p2mr_spk_man->FailPendingPlaintextPQCKeyValidation(failed_pending_key->first));

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_REQUIRE_EQUAL(info.failed_records, 1U);
    BOOST_REQUIRE_GT(info.pending_records, 1U);

    const auto step_result{loaded_wallet->RunPlaintextPQCKeyValidationStep()};
    BOOST_CHECK(step_result == CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS);

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK_EQUAL(info.failed_records, 1U);
    BOOST_CHECK_GT(info.pending_records, 0U);
    BOOST_CHECK(info.signing_blocked);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
