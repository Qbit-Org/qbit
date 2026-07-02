// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_plaintext_validation_completion_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(PendingPlaintextPQCValidationCompletesWithOtherCryptedPQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    DescriptorScriptPubKeyMan spk_man{wallet, SINGLE_ADDRESS_KEYPOOL_SIZE};

    CPQCKey plaintext_key;
    plaintext_key.MakeNewKey();
    BOOST_REQUIRE(plaintext_key.IsValid());
    const CPQCPubKey plaintext_pubkey{plaintext_key.GetPubKey()};
    const CKeyingMaterial plaintext_secret{plaintext_key.data(), plaintext_key.data() + plaintext_key.size()};

    CPQCKey crypted_key;
    crypted_key.MakeNewKey();
    BOOST_REQUIRE(crypted_key.IsValid());
    const CPQCPubKey crypted_pubkey{crypted_key.GetPubKey()};
    BOOST_REQUIRE(!(plaintext_pubkey == crypted_pubkey));

    BOOST_REQUIRE(spk_man.AddPendingPlaintextPQCKey(plaintext_pubkey, plaintext_secret, /*sig_counter=*/7));
    BOOST_REQUIRE(spk_man.AddCryptedPQCKey(crypted_pubkey, {0x00}, /*sig_counter=*/3));
    BOOST_CHECK_EQUAL(spk_man.GetPQCKeys().size(), 2U);

    PQCKeyValidationInfo info{spk_man.GetPQCKeyValidationInfo()};
    BOOST_CHECK_EQUAL(info.pending_records, 1U);
    BOOST_CHECK(info.signing_blocked);

    BOOST_REQUIRE(spk_man.CompletePendingPlaintextPQCKeyValidation(plaintext_pubkey, plaintext_key, /*sig_counter=*/7));

    info = spk_man.GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.pending_records, 0U);
    BOOST_CHECK_EQUAL(info.failed_records, 0U);
    BOOST_CHECK_EQUAL(info.validated_records, 1U);
    BOOST_CHECK(!info.signing_blocked);

    const auto pqc_keys{spk_man.GetPQCKeys()};
    BOOST_CHECK_EQUAL(pqc_keys.size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
