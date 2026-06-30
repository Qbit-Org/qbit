// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_descriptor_cache_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(CachedP2MRDescriptorsPersistPQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.m_keypool_size = 1;
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    const std::string desc_str{
        "mr(pk(pqc(qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe/87h/1h/0h/0/*)))"};

    FlatSigningProvider provider;
    std::string error;
    auto parsed_descs = Parse(desc_str, provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!parsed_descs.empty(), error);

    DescriptorCache cache;
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts;
    BOOST_REQUIRE(parsed_descs.at(0)->Expand(/*pos=*/0, provider, scripts, out_keys, &cache));
    BOOST_REQUIRE_EQUAL(out_keys.pqc_keys.size(), 1U);

    WalletDescriptor w_desc(std::move(parsed_descs.at(0)), /*creation_time=*/1, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    w_desc.cache = std::move(cache);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        p2mr_spk_man = &Assert(wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false)).value().get();
    }

    BOOST_REQUIRE(p2mr_spk_man);
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(p2mr_spk_man->GetWalletDescriptor().range_end, 1);
    }
    BOOST_CHECK_EQUAL(p2mr_spk_man->GetPQCKeys().size(), 1U);
}

BOOST_FIXTURE_TEST_CASE(GetSigningProviderSkipsUndecryptablePQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const std::string desc_str{
        "mr(pk(pqc(qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe/87h/1h/0h/0/0)))"};

    DescriptorScriptPubKeyMan* p2mr_spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(p2mr_spk_man);

    CPubKey descriptor_pubkey;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
        descriptor_pubkey = out_keys.pubkeys.begin()->second;
    }

    const SecureString passphrase{"test-passphrase"};
    // This test only needs the descriptor under test to be encrypted. Avoid
    // unrelated replacement descriptor setup, which is expensive under MSan.
    wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    CPQCKey bogus_pqc_key;
    bogus_pqc_key.MakeNewKey();
    BOOST_REQUIRE(p2mr_spk_man->AddCryptedPQCKey(bogus_pqc_key.GetPubKey(), {0x00}));

    auto provider = p2mr_spk_man->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_CHECK_EQUAL(provider->pqc_keys.count(bogus_pqc_key.GetPubKey()), 0U);
    for (const auto& [_, key] : provider->pqc_keys) {
        BOOST_CHECK(key.IsValid());
    }
}

BOOST_FIXTURE_TEST_CASE(GetSigningProviderSkipsUndecryptableECDSAKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const std::string desc_str{
        "mr(pk(pqc(qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe/87h/1h/0h/0/0)))"};

    DescriptorScriptPubKeyMan* p2mr_spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(p2mr_spk_man);

    CPubKey descriptor_pubkey;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
        descriptor_pubkey = out_keys.pubkeys.begin()->second;
    }

    const SecureString passphrase{"test-passphrase"};
    // This test only needs the descriptor under test to be encrypted. Avoid
    // unrelated replacement descriptor setup, which is expensive under MSan.
    wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    const CKey bogus_key = GenerateRandomKey();
    BOOST_REQUIRE(p2mr_spk_man->AddCryptedKey(bogus_key.GetPubKey().GetID(), bogus_key.GetPubKey(), {0x00}));

    auto provider = p2mr_spk_man->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_CHECK_EQUAL(provider->keys.count(descriptor_pubkey.GetID()), 1U);
    BOOST_CHECK_EQUAL(provider->keys.count(bogus_key.GetPubKey().GetID()), 0U);
    for (const auto& [_, key] : provider->keys) {
        BOOST_CHECK(key.IsValid());
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
