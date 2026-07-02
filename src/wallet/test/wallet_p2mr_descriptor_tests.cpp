// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/p2mr_datapqchash_vectors.json.h>
#include <wallet/pqc_usage.h>
#include <wallet/test/wallet_p2mr_test_util.h>

#include <span>

namespace wallet {
using namespace wallet_p2mr_test;

std::string HashToHex(const uint256& hash)
{
    return HexStr(std::span<const unsigned char>{hash.begin(), hash.end()});
}

UniValue LoadPinnedDataPQCVector()
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(json_tests::p2mr_datapqchash_vectors));
    BOOST_REQUIRE(doc.isObject());
    BOOST_CHECK_EQUAL(doc["schema_version"].getInt<int>(), 1);
    const UniValue& vectors{doc["vectors"]};
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE_EQUAL(vectors.size(), 1U);
    return vectors[0];
}

template <typename ByteRange>
bool ByteRangeLess(const ByteRange& left, const ByteRange& right)
{
    for (size_t i{0}; i < left.size() && i < right.size(); ++i) {
        if (left[i] != right[i]) return left[i] < right[i];
    }
    return left.size() < right.size();
}

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

    if (ByteRangeLess(ToBytes(second_leaf), ToBytes(first_leaf))) {
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

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningMatchesPinnedProofFixture)
{
    const UniValue vector{LoadPinnedDataPQCVector()};

    const std::vector<unsigned char> secret_key_bytes{ParseHex(vector["secret_key"].get_str())};
    const std::vector<unsigned char> pubkey_bytes{ParseHex(vector["pubkey"].get_str())};
    CPQCKey key;
    key.Set(secret_key_bytes.data(), secret_key_bytes.data() + secret_key_bytes.size());
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey{pubkey_bytes};
    BOOST_REQUIRE(pubkey.IsValid());
    BOOST_CHECK(key.GetPubKey() == pubkey);

    const std::vector<unsigned char> leaf_script_bytes{ParseHex(vector["leaf_script"].get_str())};
    const CScript leaf_script{leaf_script_bytes.begin(), leaf_script_bytes.end()};
    BOOST_REQUIRE(leaf_script == p2mr::BuildPKScript(pubkey));

    const std::vector<unsigned char> sibling_leaf_script_bytes{ParseHex(vector["tree"]["sibling_leaf_script"].get_str())};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, leaf_script_bytes, P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, sibling_leaf_script_bytes, P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};
    BOOST_CHECK_EQUAL(HashToHex(output.GetMerkleRoot()), vector["p2mr_merkle_root"].get_str());

    FlatSigningProvider provider;
    AddPQCSigningKeyForTest(provider, key);
    provider.mr_trees.emplace(output, builder);

    const std::vector<unsigned char> message_hash_bytes{ParseHex(vector["message_hash"].get_str())};
    BOOST_REQUIRE_EQUAL(message_hash_bytes.size(), uint256::size());
    const uint256 message_hash{std::span<const unsigned char>{message_hash_bytes.data(), message_hash_bytes.size()}};
    const std::vector<unsigned char> control_block{ParseHex(vector["control_block"].get_str())};

    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        provider,
        output,
        message_hash,
        std::optional<CPQCPubKey>{pubkey},
        std::optional<CScript>{leaf_script},
        std::optional<std::vector<unsigned char>>{control_block})};

    BOOST_REQUIRE(proof);
    BOOST_CHECK(proof->output == output);
    BOOST_CHECK(proof->message_hash == message_hash);
    BOOST_CHECK_EQUAL(HashToHex(proof->datasig_hash), vector["datasig_hash"].get_str());
    BOOST_CHECK(proof->pubkey == pubkey);
    BOOST_CHECK(proof->leaf_script == leaf_script);
    BOOST_CHECK(proof->control_block == control_block);
    BOOST_CHECK_EQUAL(proof->leaf_version, P2MR_LEAF_VERSION_V1);
    BOOST_CHECK_EQUAL(HexStr(proof->signature), vector["signature"].get_str());
}

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningReportsCommittedFailedLeafReservation)
{
    CPQCKey first_key;
    CPQCKey second_key;
    first_key.MakeNewKey();
    second_key.MakeNewKey();

    CPQCPubKey first_pubkey{first_key.GetPubKey()};
    CPQCPubKey second_pubkey{second_key.GetPubKey()};
    CScript first_leaf{p2mr::BuildPKScript(first_pubkey)};
    CScript second_leaf{p2mr::BuildPKScript(second_pubkey)};

    if (ByteRangeLess(ToBytes(second_leaf), ToBytes(first_leaf))) {
        std::swap(first_key, second_key);
        std::swap(first_pubkey, second_pubkey);
        std::swap(first_leaf, second_leaf);
    }

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, ToBytes(first_leaf), P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, ToBytes(second_leaf), P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    AddPQCSigningKeyForTest(provider, first_key);
    AddPQCSigningKeyForTest(provider, second_key);
    provider.mr_trees.emplace(output, builder);

    std::map<CPQCPubKey, uint32_t> authoritative_counters{{first_pubkey, 0}, {second_pubkey, 0}};
    provider.pqc_counter_reserver = [&](const CPQCPubKey& pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        BOOST_CHECK_EQUAL(count, 1U);
        auto counter_it{authoritative_counters.find(pubkey)};
        BOOST_REQUIRE(counter_it != authoritative_counters.end());
        previous_counter = counter_it->second;
        reserved_counter = previous_counter + count;
        counter_it->second = reserved_counter;
        return true;
    };

    PQCUsageRecorder recorder;
    provider.pqc_counter_observer = recorder.GetObserver();
    provider.pqc_raw_signer = [&](const CPQCKey& key, const uint256& hash, std::vector<unsigned char>& sig, uint32_t& counter) {
        if (key.GetPubKey() == first_pubkey) {
            sig.clear();
            return false;
        }
        return key.Sign(hash, sig, counter);
    };

    const uint256 message_hash{uint256::ONE};
    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        provider, output, message_hash, std::nullopt, std::nullopt, std::nullopt)};

    BOOST_REQUIRE(proof);
    BOOST_CHECK(proof->pubkey == second_pubkey);
    BOOST_CHECK_EQUAL(authoritative_counters.at(first_pubkey), 1U);
    BOOST_CHECK_EQUAL(authoritative_counters.at(second_pubkey), 1U);
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters.at(first_pubkey), 1U);
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters.at(second_pubkey), 1U);

    const PQCUsageReport report{BuildSigningPQCUsageReport(recorder)};
    BOOST_REQUIRE_EQUAL(report.key_states.size(), 2U);
    std::set<CPQCPubKey> reported_pubkeys;
    for (const PQCUsageSnapshot& snapshot : report.key_states) {
        BOOST_CHECK_EQUAL(snapshot.signature_count, 1U);
        reported_pubkeys.insert(snapshot.pubkey);
    }
    BOOST_CHECK(reported_pubkeys.contains(first_pubkey));
    BOOST_CHECK(reported_pubkeys.contains(second_pubkey));
}

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningReportsFinalSlotFailureAsExhausted)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey{key.GetPubKey()};
    const CScript leaf{p2mr::BuildPKScript(pubkey)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ToBytes(leaf), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    AddPQCSigningKeyForTest(provider, key);
    provider.pqc_sig_counters[pubkey] = PQC_MAX_SIGNATURES - 1;
    provider.mr_trees.emplace(output, builder);

    uint32_t authoritative_counter{PQC_MAX_SIGNATURES - 1};
    provider.pqc_counter_reserver = [&](const CPQCPubKey& reserved_pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        BOOST_CHECK(reserved_pubkey == pubkey);
        BOOST_CHECK_EQUAL(count, 1U);
        previous_counter = authoritative_counter;
        reserved_counter = previous_counter + count;
        authoritative_counter = reserved_counter;
        return true;
    };

    PQCUsageRecorder recorder;
    provider.pqc_counter_observer = recorder.GetObserver();
    provider.pqc_raw_signer = [&](const CPQCKey& raw_key, const uint256&, std::vector<unsigned char>& sig, uint32_t&) {
        BOOST_CHECK(raw_key.GetPubKey() == pubkey);
        sig.clear();
        return false;
    };

    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        provider, output, uint256::ONE, std::nullopt, std::nullopt, std::nullopt)};

    BOOST_CHECK(!proof);
    BOOST_CHECK_EQUAL(util::ErrorString(proof).original, "PQC signature budget is exhausted for the selected P2MR pubkey leaf");
    BOOST_CHECK_EQUAL(authoritative_counter, PQC_MAX_SIGNATURES);
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters.at(pubkey), PQC_MAX_SIGNATURES);

    const PQCUsageReport report{BuildSigningPQCUsageReport(recorder)};
    BOOST_REQUIRE(report.overall_state.has_value());
    BOOST_CHECK(*report.overall_state == PQCSignatureLimitState::EXHAUSTED);
    BOOST_REQUIRE_EQUAL(report.key_states.size(), 1U);
    const PQCUsageSnapshot& snapshot{report.key_states.front()};
    BOOST_CHECK(snapshot.pubkey == pubkey);
    BOOST_CHECK_EQUAL(snapshot.signature_count, PQC_MAX_SIGNATURES);
    BOOST_CHECK_EQUAL(snapshot.signatures_remaining, 0U);
    BOOST_CHECK(snapshot.limit_state == PQCSignatureLimitState::EXHAUSTED);
}

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningDistinguishesExhaustedPQCKey)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey{key.GetPubKey()};
    const CScript leaf{p2mr::BuildPKScript(pubkey)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ToBytes(leaf), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    AddPQCSigningKeyForTest(provider, key);
    provider.pqc_sig_counters[pubkey] = PQC_MAX_SIGNATURES;
    provider.mr_trees.emplace(output, builder);

    PQCUsageRecorder recorder;
    provider.pqc_counter_observer = recorder.GetObserver();

    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        provider, output, uint256::ONE, std::nullopt, std::nullopt, std::nullopt)};

    BOOST_CHECK(!proof);
    BOOST_CHECK_EQUAL(util::ErrorString(proof).original, "PQC signature budget is exhausted for the selected P2MR pubkey leaf");
    BOOST_CHECK(recorder.Empty());
}

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningPrefersMissingKeyOverMixedExhaustion)
{
    CPQCKey exhausted_key;
    CPQCKey missing_key;
    exhausted_key.MakeNewKey();
    missing_key.MakeNewKey();

    const CPQCPubKey exhausted_pubkey{exhausted_key.GetPubKey()};
    const CPQCPubKey missing_pubkey{missing_key.GetPubKey()};
    const CScript exhausted_leaf{p2mr::BuildPKScript(exhausted_pubkey)};
    const CScript missing_leaf{p2mr::BuildPKScript(missing_pubkey)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, ToBytes(exhausted_leaf), P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, ToBytes(missing_leaf), P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    AddPQCSigningKeyForTest(provider, exhausted_key);
    provider.pqc_sig_counters[exhausted_pubkey] = PQC_MAX_SIGNATURES;
    provider.mr_trees.emplace(output, builder);

    PQCUsageRecorder recorder;
    provider.pqc_counter_observer = recorder.GetObserver();

    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        provider, output, uint256::ONE, std::nullopt, std::nullopt, std::nullopt)};

    BOOST_CHECK(!proof);
    BOOST_CHECK_EQUAL(util::ErrorString(proof).original, "Private key is not available for the selected P2MR pubkey leaf");
    BOOST_CHECK(recorder.Empty());
}

BOOST_AUTO_TEST_CASE(P2MRWalletDataHashSigningReportsNearLimitExhaustion)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    CScript p2mr_script;
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        p2mr_script = scripts.at(0);
    }

    std::vector<std::vector<unsigned char>> solutions;
    BOOST_REQUIRE_EQUAL(Solver(p2mr_script, solutions), TxoutType::WITNESS_V2_P2MR);
    const WitnessV2P2MR output{std::span<const unsigned char>{solutions.at(0)}};
    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};

    auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);
    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);

    PQCUsageRecorder recorder;
    const util::Result<DataPQCSignatureProof> proof{wallet->SignDataPQCHash(
        output, uint256::ONE, std::nullopt, std::nullopt, std::nullopt, recorder.GetObserver())};
    BOOST_REQUIRE_MESSAGE(proof, util::ErrorString(proof).original);
    BOOST_CHECK(proof->pubkey == pubkeys.pqc_pubkey);
    BOOST_CHECK_EQUAL(proof->signature.size(), PQC_SIG_SIZE);

    const PQCUsageReport report{BuildSigningPQCUsageReport(recorder)};
    BOOST_REQUIRE(report.overall_state.has_value());
    BOOST_CHECK(*report.overall_state == PQCSignatureLimitState::EXHAUSTED);
    BOOST_REQUIRE_EQUAL(report.key_states.size(), 1U);
    const PQCUsageSnapshot& snapshot{report.key_states.front()};
    BOOST_CHECK(snapshot.pubkey == pubkeys.pqc_pubkey);
    BOOST_CHECK_EQUAL(snapshot.signature_count, PQC_MAX_SIGNATURES);
    BOOST_CHECK_EQUAL(snapshot.signature_limit, PQC_MAX_SIGNATURES);
    BOOST_CHECK_EQUAL(snapshot.signatures_remaining, 0U);
    BOOST_CHECK(snapshot.limit_state == PQCSignatureLimitState::EXHAUSTED);

    const std::vector<bilingual_str> warnings{FormatPQCUsageWarnings(report.warnings)};
    BOOST_REQUIRE_EQUAL(warnings.size(), 1U);
    BOOST_CHECK(warnings.front().original.find("reached the signature limit") != std::string::npos);
    BOOST_CHECK(warnings.front().original.find("0 remaining") != std::string::npos);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES);

    PQCUsageRecorder exhausted_recorder;
    const util::Result<DataPQCSignatureProof> exhausted_proof{wallet->SignDataPQCHash(
        output, uint256::ONE, std::nullopt, std::nullopt, std::nullopt, exhausted_recorder.GetObserver())};
    BOOST_CHECK(!exhausted_proof);
    BOOST_CHECK_EQUAL(util::ErrorString(exhausted_proof).original, "PQC signature budget is exhausted for the selected P2MR pubkey leaf");
    BOOST_CHECK(exhausted_recorder.Empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES);
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
