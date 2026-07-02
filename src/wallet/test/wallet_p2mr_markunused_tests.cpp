// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_markunused_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(MarkUnusedAddressesP2MRDoesNotFullTopUpAboveLowWatermark, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{32};
    constexpr int32_t used_index{3};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    DatabaseOptions create_options;
    create_options.require_create = true;
    create_options.create_flags = WALLET_FLAG_DESCRIPTORS;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "mark_unused_above_watermark_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_REQUIRE(external_spk_man->IsRangedP2MRDescriptor());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(external_spk_man->GetP2MRReceiveKeyPoolLowWatermark(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    int32_t initial_range_end;
    {
        LOCK(external_spk_man->cs_desc_man);
        initial_range_end = external_spk_man->GetWalletDescriptor().range_end;
    }
    const CScript used_script = GetCachedScriptPubKey(*external_spk_man, used_index);

    const auto marked = external_spk_man->MarkUnusedAddresses(used_script, {
        .internal_hint = false,
    });
    BOOST_CHECK_EQUAL(marked.size(), static_cast<size_t>(used_index + 1));
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), static_cast<unsigned int>(keypool_size - used_index - 1));
    {
        LOCK(external_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = external_spk_man->GetWalletDescriptor();
        BOOST_CHECK_EQUAL(wallet_descriptor.next_index, used_index + 1);
        BOOST_CHECK_EQUAL(wallet_descriptor.range_end, initial_range_end);
        BOOST_CHECK(!wallet_descriptor.deferred_create_keypool_top_up.value_or(true));
    }

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));

    DatabaseOptions load_options;
    load_options.require_existing = true;
    auto loaded_wallet = LoadWallet(context, "mark_unused_above_watermark_test", std::nullopt, load_options, status, error, warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    {
        LOCK(loaded_wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_CHECK(!loaded_wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(external_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = external_spk_man->GetWalletDescriptor();
        BOOST_CHECK_EQUAL(wallet_descriptor.next_index, used_index + 1);
        BOOST_CHECK(!wallet_descriptor.deferred_create_keypool_top_up.value_or(true));
    }

    BOOST_CHECK(RemoveWallet(context, loaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(loaded_wallet));
}

BOOST_FIXTURE_TEST_CASE(MarkUnusedAddressesP2MRDoesNotTopUpGeneratedScriptAboveLowWatermark, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{32};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());

    const CScript generated_script = GetCachedScriptPubKey(*external_spk_man, 0);
    BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size - 1);

    int32_t range_end_after_generation;
    {
        LOCK(external_spk_man->cs_desc_man);
        range_end_after_generation = external_spk_man->GetWalletDescriptor().range_end;
    }

    const auto marked = external_spk_man->MarkUnusedAddresses(generated_script, {
        .internal_hint = false,
    });
    BOOST_CHECK(marked.empty());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size - 1);
    {
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, range_end_after_generation);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(MarkUnusedAddressesP2MRBoundsNormalLowWatermarkRefill, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);

    const unsigned int low_watermark{external_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    BOOST_REQUIRE_EQUAL(low_watermark, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    const int32_t used_index = keypool_size - low_watermark - 1;
    const CScript used_script = GetCachedScriptPubKey(*external_spk_man, used_index);

    const auto marked = external_spk_man->MarkUnusedAddresses(used_script, {
        .internal_hint = false,
    });
    BOOST_CHECK_EQUAL(marked.size(), static_cast<size_t>(used_index + 1));
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), low_watermark + DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_LT(external_spk_man->GetKeyPoolSize(), static_cast<unsigned int>(keypool_size));
    {
        LOCK(external_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = external_spk_man->GetWalletDescriptor();
        BOOST_CHECK_EQUAL(wallet_descriptor.next_index, used_index + 1);
        BOOST_CHECK_EQUAL(wallet_descriptor.range_end, keypool_size + DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(MarkUnusedAddressesP2MRPreservesRecoveryLookahead, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);

    const unsigned int low_watermark{external_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    BOOST_REQUIRE_EQUAL(low_watermark, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    const int32_t used_index = keypool_size - low_watermark - 1;
    const CScript used_script = GetCachedScriptPubKey(*external_spk_man, used_index);

    const auto marked = external_spk_man->MarkUnusedAddresses(used_script, {
        .internal_hint = false,
        .preserve_full_keypool_lookahead = true,
    });
    BOOST_CHECK_EQUAL(marked.size(), static_cast<size_t>(used_index + 1));
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    {
        LOCK(external_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = external_spk_man->GetWalletDescriptor();
        BOOST_CHECK_EQUAL(wallet_descriptor.next_index, used_index + 1);
        BOOST_CHECK_EQUAL(wallet_descriptor.range_end, wallet_descriptor.next_index + keypool_size);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(MarkUnusedAddressesP2MRLockedWalletDoesNotFailEarly, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{20};
    constexpr int32_t used_index{4};
    const SecureString passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    DatabaseOptions create_options;
    create_options.require_create = true;
    create_options.create_flags = WALLET_FLAG_DESCRIPTORS;
    create_options.create_passphrase = passphrase;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "locked_mark_unused_low_watermark_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_REQUIRE(wallet->Lock());

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    const CScript used_script = GetCachedScriptPubKey(*external_spk_man, used_index);

    {
        DebugLogHelper log_helper("P2MR keypool low-watermark refill deferred for locked wallet", [](const std::string* line) {
            return line && line->find("remaining=15") != std::string::npos;
        });
        const auto marked = external_spk_man->MarkUnusedAddresses(used_script, {
            .internal_hint = false,
        });
        BOOST_CHECK_EQUAL(marked.size(), static_cast<size_t>(used_index + 1));
    }
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size - used_index - 1);
    {
        LOCK(external_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = external_spk_man->GetWalletDescriptor();
        BOOST_CHECK_EQUAL(wallet_descriptor.next_index, used_index + 1);
        BOOST_CHECK_EQUAL(wallet_descriptor.range_end, keypool_size);
    }

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(MarkUnusedAddressesNonP2MRStillFullTopUp)
{
    constexpr int64_t keypool_size{32};
    constexpr int32_t used_index{3};
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.m_keypool_size = keypool_size;
        wallet.SetupDescriptorScriptPubKeyMans(BECH32_ONLY_OUTPUT_TYPES);
    }

    auto* spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
    BOOST_REQUIRE(spk_man);
    BOOST_CHECK_EQUAL(spk_man->GetKeyPoolSize(), keypool_size);
    const CScript used_script = GetCachedScriptPubKey(*spk_man, used_index);

    const auto marked = spk_man->MarkUnusedAddresses(used_script, {
        .internal_hint = false,
    });
    BOOST_CHECK_EQUAL(marked.size(), static_cast<size_t>(used_index + 1));
    BOOST_CHECK_EQUAL(spk_man->GetKeyPoolSize(), keypool_size);
    {
        LOCK(spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = spk_man->GetWalletDescriptor();
        BOOST_CHECK_EQUAL(wallet_descriptor.next_index, used_index + 1);
        BOOST_CHECK_EQUAL(wallet_descriptor.range_end, used_index + 1 + keypool_size);
    }
}

BOOST_FIXTURE_TEST_CASE(KeypoolTopUpReportsLockedInternalP2MRDescriptorFailure, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    const SecureString passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    DatabaseOptions create_options;
    create_options.require_create = true;
    create_options.create_flags = WALLET_FLAG_DESCRIPTORS;
    create_options.create_passphrase = passphrase;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "locked_internal_refill_error_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_CHECK(wallet->IsLocked());

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    BOOST_REQUIRE(wallet->Unlock(passphrase, /*run_pending_initial_keypool_top_up=*/false));
    auto external_top_up{external_spk_man->TopUpWithInternalHintResult(/*internal_hint=*/false, keypool_size)};
    BOOST_REQUIRE_MESSAGE(external_top_up.has_value(), util::ErrorString(external_top_up).original);
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_REQUIRE(wallet->Lock());

    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_GE(wallet->GetKeyPoolSize(), static_cast<unsigned int>(keypool_size));
    }
    auto top_up_res{wallet->TopUpKeyPoolResult(keypool_size)};
    BOOST_CHECK(!top_up_res);
    const std::string message{util::ErrorString(top_up_res).original};
    BOOST_CHECK(message.find("active internal p2mr descriptor keypool") != std::string::npos);
    BOOST_CHECK(message.find("target=64") != std::string::npos);
    BOOST_CHECK(message.find("remaining=16") != std::string::npos);
    BOOST_CHECK(message.find("wallet encryption key is unavailable for P2MR private-key persistence") != std::string::npos);

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
