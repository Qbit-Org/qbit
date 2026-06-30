// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_deferred_keypool_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(CreateWalletWarmsP2MRKeypoolThenDefersFullTopUp, RegtestDefaultWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    auto addr = wallet->GetNewDestination(OutputType::P2MR, "");
    BOOST_REQUIRE(addr);
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL - 1);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(CreateWalletSchedulerRefillsDeferredP2MRKeypoolAcrossBatches, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));
    DeferredCreateKeyPoolTopUpBatchStepOverride batch_step_override{1};

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "scheduled_refill_test", std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    auto& scheduler = *Assert(m_node.scheduler);
    scheduler.MockForward(std::chrono::seconds{29});
    WaitForScheduler(scheduler);
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    for (int i = 0; i < 10 && wallet->HasPendingInitialKeyPoolTopUp(); ++i) {
        scheduler.MockForward(std::chrono::seconds{1});
        WaitForScheduler(scheduler);
    }

    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    }

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadWalletSchedulerRefillsDeferredP2MRKeypoolAcrossBatches, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));
    DeferredCreateKeyPoolTopUpBatchStepOverride batch_step_override{1};

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions create_options;
    create_options.require_create = true;
    create_options.create_flags = WALLET_FLAG_DESCRIPTORS;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "scheduled_reload_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));

    DatabaseOptions load_options;
    load_options.require_existing = true;
    auto loaded_wallet = LoadWallet(context, "scheduled_reload_test", std::nullopt, load_options, status, error, warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(loaded_wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(loaded_wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(loaded_wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    auto& scheduler = *Assert(m_node.scheduler);
    scheduler.MockForward(std::chrono::seconds{29});
    WaitForScheduler(scheduler);
    BOOST_CHECK(loaded_wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(loaded_wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    for (int i = 0; i < 10 && loaded_wallet->HasPendingInitialKeyPoolTopUp(); ++i) {
        scheduler.MockForward(std::chrono::seconds{1});
        WaitForScheduler(scheduler);
    }

    BOOST_CHECK(!loaded_wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(loaded_wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    }

    BOOST_CHECK(RemoveWallet(context, loaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(loaded_wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadWalletDoesNotRestoreDeferredP2MRTopUpAfterRefillAndAddressUse, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
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
    auto wallet = CreateWallet(context, "refilled_reload_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    auto addr = wallet->GetNewDestination(OutputType::P2MR, "");
    BOOST_REQUIRE(addr);
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size - 1);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));

    DatabaseOptions load_options;
    load_options.require_existing = true;
    auto loaded_wallet = LoadWallet(context, "refilled_reload_test", std::nullopt, load_options, status, error, warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    {
        LOCK(loaded_wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(!loaded_wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_REQUIRE(loaded_wallet->GetNewDestination(OutputType::P2MR, ""));
    BOOST_CHECK(!loaded_wallet->HasPendingInitialKeyPoolTopUp());

    BOOST_CHECK(RemoveWallet(context, loaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(loaded_wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadWalletKeepsDeferredP2MRTopUpPendingAfterMarkUnusedAddresses, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
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
    auto wallet = CreateWallet(context, "mark_unused_reload_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    const CScript warm_pool_tail = GetCachedScriptPubKey(*external_spk_man, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL - 1);
    const auto marked = external_spk_man->MarkUnusedAddresses(warm_pool_tail);
    BOOST_CHECK_EQUAL(marked.size(), static_cast<size_t>(DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL));
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), 0U);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    {
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));

    DatabaseOptions load_options;
    load_options.require_existing = true;
    auto loaded_wallet = LoadWallet(context, "mark_unused_reload_test", std::nullopt, load_options, status, error, warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    {
        LOCK(loaded_wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(loaded_wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), 0U);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    {
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    BOOST_CHECK(loaded_wallet->RunPendingInitialKeyPoolTopUpStep() == CWallet::PendingInitialKeyPoolTopUpStepResult::PENDING);
    BOOST_CHECK(loaded_wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL * 2);
    {
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL * 2);
    }

    BOOST_CHECK(RemoveWallet(context, loaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(loaded_wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadWalletUnlockRefillsDeferredP2MRKeypoolForEncryptedWallets, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    const SecureString passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions create_options;
    create_options.require_create = true;
    create_options.create_flags = WALLET_FLAG_DESCRIPTORS;
    create_options.create_passphrase = passphrase;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "encrypted_reload_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));

    DatabaseOptions load_options;
    load_options.require_existing = true;
    auto loaded_wallet = LoadWallet(context, "encrypted_reload_test", std::nullopt, load_options, status, error, warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_CHECK(loaded_wallet->IsLocked());

    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(loaded_wallet->cs_wallet);
        external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    BOOST_CHECK(loaded_wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(loaded_wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    for (unsigned int i = 0; i < DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL; ++i) {
        BOOST_REQUIRE(loaded_wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    auto exhausted_addr = loaded_wallet->GetNewDestination(OutputType::P2MR, "");
    BOOST_CHECK(!exhausted_addr);
    BOOST_CHECK_EQUAL(util::ErrorString(exhausted_addr).original, "Error: Keypool ran out, please call keypoolrefill first");
    BOOST_CHECK(loaded_wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), 0U);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    BOOST_REQUIRE(loaded_wallet->Unlock(passphrase));
    BOOST_CHECK(!loaded_wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(loaded_wallet->cs_wallet);
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    }

    BOOST_CHECK(RemoveWallet(context, loaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(loaded_wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
