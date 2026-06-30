// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_descriptor_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(DescriptorTopUpWithDBThrowsWhenP2MRPersistenceNeedsLockedKey)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const SecureString passphrase{"test-passphrase"};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        wallet.m_keypool_size = SINGLE_ADDRESS_KEYPOOL_SIZE;
    }
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase, /*run_pending_initial_keypool_top_up=*/false));
    DescriptorScriptPubKeyMan* spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        CExtKey master_key;
        master_key.SetSeed(GenerateRandomKey());
        WalletBatch batch{wallet.GetDatabase()};
        spk_man = &wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::P2MR, /*internal=*/false);
    }
    BOOST_REQUIRE(spk_man);
    BOOST_CHECK_EQUAL(spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_REQUIRE(wallet.Lock());
    BOOST_REQUIRE(wallet.IsLocked());

    auto top_up_res{spk_man->TopUpWithInternalHintResult(/*internal_hint=*/false, SINGLE_ADDRESS_KEYPOOL_SIZE + 1)};
    BOOST_CHECK(!top_up_res);
    BOOST_CHECK_EQUAL(util::ErrorString(top_up_res).original, "wallet encryption key is unavailable for P2MR private-key persistence");
}

BOOST_AUTO_TEST_CASE(DescriptorTopUpWithDBAllowsLockedPublicP2MRWithoutPrivatePersistence)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
    }
    BOOST_REQUIRE(wallet.EncryptWallet(SecureString{"test-passphrase"}));
    BOOST_REQUIRE(wallet.IsLocked());

    const std::string desc_str{"mr(pk(" + HexStr(std::vector<unsigned char>(CPQCPubKey::SIZE, 0x11)) + "))"};
    FlatSigningProvider keys;
    std::string error;
    auto descs{Parse(desc_str, keys, error, /*require_checksum=*/false)};
    BOOST_REQUIRE_MESSAGE(descs.size() == 1U, error);
    WalletDescriptor desc{std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0};
    TestDescriptorScriptPubKeyMan spk_man{wallet, desc, SINGLE_ADDRESS_KEYPOOL_SIZE};
    WalletBatch batch{wallet.GetDatabase()};

    bool top_up{false};
    BOOST_CHECK_NO_THROW(top_up = spk_man.TopUpWithDB(batch, SINGLE_ADDRESS_KEYPOOL_SIZE, /*internal_hint=*/false));
    BOOST_CHECK(top_up);
    BOOST_CHECK_EQUAL(spk_man.GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
}

BOOST_AUTO_TEST_CASE(TopUpKeyPoolResultContinuesAfterDescriptorFailure)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const SecureString passphrase{"test-passphrase"};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        wallet.m_keypool_size = SINGLE_ADDRESS_KEYPOOL_SIZE;
    }
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase, /*run_pending_initial_keypool_top_up=*/false));

    DescriptorScriptPubKeyMan* failing_spk_man{nullptr};
    DescriptorScriptPubKeyMan* continued_spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        CExtKey master_key;
        master_key.SetSeed(GenerateRandomKey());
        WalletBatch batch{wallet.GetDatabase()};
        failing_spk_man = &wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::P2MR, /*internal=*/false);
        continued_spk_man = &wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::BECH32, /*internal=*/true);
    }
    BOOST_REQUIRE(failing_spk_man);
    BOOST_REQUIRE(continued_spk_man);
    BOOST_CHECK_EQUAL(failing_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_CHECK_EQUAL(continued_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_REQUIRE(wallet.Lock());

    auto top_up_res{wallet.TopUpKeyPoolResult(SINGLE_ADDRESS_KEYPOOL_SIZE + 1)};
    BOOST_CHECK(!top_up_res);
    const std::string message{util::ErrorString(top_up_res).original};
    BOOST_CHECK(message.find("active external p2mr descriptor keypool") != std::string::npos);
    BOOST_CHECK(message.find("wallet encryption key is unavailable for P2MR private-key persistence") != std::string::npos);
    BOOST_CHECK_EQUAL(failing_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_CHECK_EQUAL(continued_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE + 1);
}

BOOST_AUTO_TEST_CASE(DescriptorTopUpWithDBKeepsExternalBatchMemoryOnPersistenceFailure)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey master_key;
    master_key.SetSeed(GenerateRandomKey());
    TestDescriptorScriptPubKeyMan spk_man{wallet, SINGLE_ADDRESS_KEYPOOL_SIZE};
    WalletBatch setup_batch{wallet.GetDatabase()};
    BOOST_REQUIRE(spk_man.SetupDescriptorGeneration(setup_batch, master_key, OutputType::P2MR, /*internal=*/false));

    auto& database = GetMockableDatabase(wallet);
    const auto previous_spks{spk_man.GetScriptPubKeys().size()};
    const unsigned int target_size{spk_man.GetKeyPoolSize() + 1};
    database.ResetCounts();
    database.m_write_fail_after = 1;
    WalletBatch top_up_batch{wallet.GetDatabase()};

    BOOST_CHECK_THROW(
        spk_man.TopUpWithDB(top_up_batch, target_size, /*internal_hint=*/false),
        std::runtime_error);
    BOOST_CHECK_GT(database.m_write_count, 1);
    BOOST_CHECK_EQUAL(spk_man.GetScriptPubKeys().size(), previous_spks + 1);
}

BOOST_AUTO_TEST_CASE(P2MRCanGenerateMultipleAddresses)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);
    BOOST_CHECK(p2mr_spk_man->IsHDEnabled());
    BOOST_CHECK(p2mr_spk_man->CanGetAddresses(/*internal=*/false));

    std::set<CTxDestination> addrs;
    for (int i = 0; i < 4; ++i) {
        auto addr = wallet->GetNewDestination(OutputType::P2MR, "");
        BOOST_REQUIRE(addr);
        addrs.insert(*addr);
    }
    BOOST_CHECK_EQUAL(addrs.size(), 4U);
    BOOST_CHECK(p2mr_spk_man->CanGetAddresses(/*internal=*/false));

}

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningRetriesLaterLeavesAfterRuntimeFailure)
{
    CPQCKey first_key;
    CPQCKey second_key;
    first_key.MakeNewKey();
    second_key.MakeNewKey();

    CPQCPubKey first_pubkey{first_key.GetPubKey()};
    CPQCPubKey second_pubkey{second_key.GetPubKey()};
    CScript first_leaf{p2mr::BuildPKScript(first_pubkey)};
    CScript second_leaf{p2mr::BuildPKScript(second_pubkey)};

    if (ToBytes(second_leaf) < ToBytes(first_leaf)) {
        std::swap(first_key, second_key);
        std::swap(first_pubkey, second_pubkey);
        std::swap(first_leaf, second_leaf);
    }

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, ToBytes(first_leaf), P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, ToBytes(second_leaf), P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    const P2MRSpendData spenddata{builder.GetP2MRSpendData()};
    const auto failing_leaf_it{spenddata.scripts.find({ToBytes(first_leaf), P2MR_LEAF_VERSION_V1})};
    BOOST_REQUIRE(failing_leaf_it != spenddata.scripts.end());
    BOOST_REQUIRE(!failing_leaf_it->second.empty());
    const std::vector<unsigned char> failing_control_block{*failing_leaf_it->second.begin()};

    RuntimeFailPQCSigningProvider signing_provider;
    AddPQCSigningKeyForTest(signing_provider.provider, first_key);
    AddPQCSigningKeyForTest(signing_provider.provider, second_key);
    signing_provider.provider.mr_trees.emplace(output, builder);
    signing_provider.failing_pubkeys.insert(first_pubkey);

    const uint256 message_hash{uint256::ONE};
    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        signing_provider, output, message_hash, std::nullopt, std::nullopt, std::nullopt)};

    BOOST_REQUIRE(proof);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[first_pubkey], 1);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[second_pubkey], 1);
    BOOST_CHECK(proof->pubkey == second_pubkey);
    BOOST_CHECK(proof->leaf_script == second_leaf);
    BOOST_CHECK_EQUAL(proof->signature.size(), PQC_SIG_SIZE);
    BOOST_CHECK(second_pubkey.Verify(proof->datasig_hash, proof->signature));

    const util::Result<DataPQCSignatureProof> explicit_failing_leaf{SignP2MRDataHash(
        signing_provider,
        output,
        message_hash,
        std::nullopt,
        std::optional<CScript>{first_leaf},
        std::optional<std::vector<unsigned char>>{failing_control_block})};
    BOOST_CHECK(!explicit_failing_leaf);
    BOOST_CHECK_EQUAL(util::ErrorString(explicit_failing_leaf).original, "PQC data-hash signing failed");
}

BOOST_FIXTURE_TEST_CASE(NonRangedP2MRDescriptorDoesNotDeriveUnrelatedPQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CPQCKey p2mr_key;
    p2mr_key.MakeNewKey();
    const CPQCPubKey p2mr_pubkey = p2mr_key.GetPubKey();

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("mr(pk(" + HexStr(std::span{p2mr_pubkey.data(), p2mr_pubkey.size()}) + "))", provider, error, /* require_checksum=*/ false);
    BOOST_REQUIRE_EQUAL(descs.size(), 1U);

    const CKey unrelated_key = GenerateRandomKey();
    provider.keys.emplace(unrelated_key.GetPubKey().GetID(), unrelated_key);

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    auto spkm = wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false);
    BOOST_REQUIRE(spkm);

    BOOST_CHECK(spkm->get().GetPQCKeys().empty());

    int pqc_plain_records{0};
    for (const auto& [serialized_key, _] : GetMockableDatabase(wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::WALLETDESCRIPTORPQCKEY) {
            ++pqc_plain_records;
        }
    }
    BOOST_CHECK_EQUAL(pqc_plain_records, 0);
}

BOOST_FIXTURE_TEST_CASE(NonRangedP2MRDescriptorDoesNotUseUnrelatedSeedKey, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey account_extkey = DecodeExtKey("qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe");
    BOOST_REQUIRE(account_extkey.key.IsValid());
    for (const uint32_t child : {87U | 0x80000000U, 1U | 0x80000000U, 0U | 0x80000000U}) {
        CExtKey derived;
        BOOST_REQUIRE(account_extkey.Derive(derived, child));
        account_extkey = derived;
    }
    const std::string account_xprv = EncodeExtKey(account_extkey);
    const std::string account_xpub = EncodeExtPubKey(account_extkey.Neuter());
    const std::string suffix{"/0/0"};

    FlatSigningProvider cache_provider;
    std::string cache_error;
    auto cache_descs = Parse("mr(pk(pqc(" + account_xprv + suffix + ")))", cache_provider, cache_error, /* require_checksum=*/ false);
    BOOST_REQUIRE_EQUAL(cache_descs.size(), 1U);

    DescriptorCache cache;
    std::vector<CScript> cache_scripts;
    FlatSigningProvider cache_out_keys;
    BOOST_REQUIRE(cache_descs.at(0)->Expand(/*pos=*/0, cache_provider, cache_scripts, cache_out_keys, &cache));

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("mr(pk(pqc(" + account_xpub + suffix + ")))", provider, error, /* require_checksum=*/ false);
    BOOST_REQUIRE_EQUAL(descs.size(), 1U);

    const CKey unrelated_key = GenerateRandomKey();
    provider.keys.emplace(unrelated_key.GetPubKey().GetID(), unrelated_key);

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    w_desc.cache = cache;
    auto spkm = wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false);
    BOOST_REQUIRE(spkm);

    BOOST_CHECK(spkm->get().GetPQCKeys().empty());

    int pqc_plain_records{0};
    for (const auto& [serialized_key, _] : GetMockableDatabase(wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::WALLETDESCRIPTORPQCKEY) {
            ++pqc_plain_records;
        }
    }
    BOOST_CHECK_EQUAL(pqc_plain_records, 0);
}

BOOST_FIXTURE_TEST_CASE(NonRangedInternalP2MRDescriptorUsesMatchingPQCKey, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey account_extkey = DecodeExtKey("qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe");
    BOOST_REQUIRE(account_extkey.key.IsValid());
    for (const uint32_t child : {87U | 0x80000000U, 1U | 0x80000000U, 0U | 0x80000000U}) {
        CExtKey derived;
        BOOST_REQUIRE(account_extkey.Derive(derived, child));
        account_extkey = derived;
    }
    CExtKey leaf_extkey = account_extkey;
    for (const uint32_t child : {0U, 0U}) {
        CExtKey derived;
        BOOST_REQUIRE(leaf_extkey.Derive(derived, child));
        leaf_extkey = derived;
    }

    const std::string account_xprv = EncodeExtKey(account_extkey);
    const std::string account_xpub = EncodeExtPubKey(account_extkey.Neuter());
    const std::string suffix{"/0/0"};

    FlatSigningProvider cache_provider;
    std::string cache_error;
    auto cache_descs = Parse("mr(pk(pqc(" + account_xprv + suffix + ")))", cache_provider, cache_error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!cache_descs.empty(), cache_error);

    DescriptorCache cache;
    std::vector<CScript> scripts;
    FlatSigningProvider cache_out_keys;
    BOOST_REQUIRE(cache_descs.at(0)->Expand(/*pos=*/0, cache_provider, scripts, cache_out_keys, &cache));
    BOOST_REQUIRE_EQUAL(cache_out_keys.p2mr_pubkeys.size(), 1U);
    const CPQCPubKey expected_p2mr_pubkey = cache_out_keys.p2mr_pubkeys.begin()->second;

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("mr(pk(pqc(" + account_xpub + suffix + ")))", provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);
    provider.keys.emplace(leaf_extkey.key.GetPubKey().GetID(), leaf_extkey.key);

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    w_desc.cache = std::move(cache);
    auto spkm = wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/true);
    BOOST_REQUIRE(spkm);

    const auto pqc_keys = spkm->get().GetPQCKeys();
    BOOST_REQUIRE_EQUAL(pqc_keys.size(), 1U);
    BOOST_CHECK(pqc_keys.at(0) == expected_p2mr_pubkey);
}

BOOST_FIXTURE_TEST_CASE(InternalRangedP2MRDescriptorGetSigningProviderUsesMatchingPQCKey, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey account_extkey = DecodeExtKey("qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe");
    BOOST_REQUIRE(account_extkey.key.IsValid());
    for (const uint32_t child : {87U | 0x80000000U, 1U | 0x80000000U, 0U | 0x80000000U}) {
        CExtKey derived;
        BOOST_REQUIRE(account_extkey.Derive(derived, child));
        account_extkey = derived;
    }

    const std::string internal_range_desc{"mr(pk(pqc(" + EncodeExtPubKey(account_extkey.Neuter()) + "/1/*)))"};

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse(internal_range_desc, provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);

    FlatSigningProvider private_provider;
    private_provider.keys.emplace(account_extkey.key.GetPubKey().GetID(), account_extkey.key);

    std::vector<CScript> scripts;
    FlatSigningProvider cache_out_keys;
    DescriptorCache cache;
    BOOST_REQUIRE(descs.at(0)->Expand(/*pos=*/0, private_provider, scripts, cache_out_keys, &cache));
    BOOST_REQUIRE_EQUAL(cache_out_keys.p2mr_pubkeys.size(), 1U);

    CExtKey internal_leaf_extkey = account_extkey;
    CExtKey derived;
    BOOST_REQUIRE(internal_leaf_extkey.Derive(derived, /*nChild=*/1));
    internal_leaf_extkey = derived;
    BOOST_REQUIRE(internal_leaf_extkey.Derive(derived, /*nChild=*/0));
    internal_leaf_extkey = derived;

    CPQCKey expected_internal_p2mr_key;
    BOOST_REQUIRE(DerivePQCKey(internal_leaf_extkey.key, /*account=*/0, /*change=*/1, /*index=*/0, expected_internal_p2mr_key));
    const auto key_exp_pos = cache_out_keys.p2mr_pubkeys.begin()->first;
    cache.CacheDerivedP2MRPubKey(key_exp_pos, /*der_index=*/0, expected_internal_p2mr_key.GetPubKey());

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
    w_desc.cache = std::move(cache);

    DescriptorScriptPubKeyMan* spkm{nullptr};
    {
        LOCK(wallet.cs_wallet);
        spkm = &Assert(wallet.AddWalletDescriptor(w_desc, private_provider, "", /*internal=*/true)).value().get();
    }
    BOOST_REQUIRE(spkm);

    CPubKey descriptor_pubkey;
    {
        LOCK(spkm->cs_desc_man);
        const WalletDescriptor& wallet_descriptor = spkm->GetWalletDescriptor();
        std::vector<CScript> cached_scripts;
        FlatSigningProvider cached_out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, cached_scripts, cached_out_keys));
        BOOST_REQUIRE_EQUAL(cached_out_keys.pubkeys.size(), 1U);
        descriptor_pubkey = cached_out_keys.pubkeys.begin()->second;
    }

    auto signing_provider = spkm->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(signing_provider);

    CPQCKey got_internal_p2mr_key;
    BOOST_REQUIRE(signing_provider->GetPQCKey(expected_internal_p2mr_key.GetPubKey(), got_internal_p2mr_key));
    BOOST_CHECK(got_internal_p2mr_key.GetPubKey() == expected_internal_p2mr_key.GetPubKey());
}

BOOST_AUTO_TEST_CASE(ChangeTypeFallbackUsesP2MROnP2MROnlyChain)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, CHANGE_FALLBACK_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);

        auto* bech32m_internal = wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true);
        BOOST_REQUIRE(bech32m_internal);
        wallet->DeactivateScriptPubKeyMan(bech32m_internal->GetID(), OutputType::BECH32M, /*internal=*/true);

        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        wallet->m_default_address_type = OutputType::BECH32;

        const CRecipient recipient{
            WitnessV0ScriptHash(CScript{} << OP_TRUE),
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };
        const OutputType change_type = wallet->TransactionChangeType(std::nullopt, {recipient});
        BOOST_CHECK_EQUAL(change_type, OutputType::P2MR);
    }

}

BOOST_AUTO_TEST_CASE(ChangeTypeFallbackUsesDefaultP2MRWhenAvailable)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, CHANGE_FALLBACK_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);

        auto* bech32m_internal = wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true);
        BOOST_REQUIRE(bech32m_internal);
        wallet->DeactivateScriptPubKeyMan(bech32m_internal->GetID(), OutputType::BECH32M, /*internal=*/true);

        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        wallet->m_default_address_type = OutputType::P2MR;

        const CRecipient recipient{
            WitnessV0ScriptHash(CScript{} << OP_TRUE),
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };
        const OutputType change_type = wallet->TransactionChangeType(std::nullopt, {recipient});
        BOOST_CHECK_EQUAL(change_type, OutputType::P2MR);
    }

}

BOOST_AUTO_TEST_CASE(ChangeTypeRecipientMatchUsesP2MROnP2MROnlyChain)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, CHANGE_FALLBACK_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);

        auto* bech32m_internal = wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true);
        BOOST_REQUIRE(bech32m_internal);
        wallet->DeactivateScriptPubKeyMan(bech32m_internal->GetID(), OutputType::BECH32M, /*internal=*/true);

        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));

        const CRecipient p2mr_recipient{
            WitnessV2P2MR{},
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };
        const CRecipient wpkh_recipient{
            WitnessV0KeyHash(GenerateRandomKey().GetPubKey()),
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };

        const OutputType change_type = wallet->TransactionChangeType(std::nullopt, {p2mr_recipient, wpkh_recipient});
        BOOST_CHECK_EQUAL(change_type, OutputType::P2MR);
    }

}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
