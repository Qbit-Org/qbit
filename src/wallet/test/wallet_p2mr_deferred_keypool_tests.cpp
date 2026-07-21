// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>
#include <wallet/sqlite.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_deferred_keypool_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(DescriptorTopUpPublishesCacheOnlyAfterCallerTransactionCommit)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);

    CExtKey committed_master_key;
    committed_master_key.SetSeed(GenerateRandomKey());
    TestDescriptorScriptPubKeyMan committed_spk_man{*wallet, SINGLE_ADDRESS_KEYPOOL_SIZE};
    CScript committed_script;
    {
        WalletBatch commit_batch{wallet->GetDatabase()};
        BOOST_REQUIRE(commit_batch.TxnBegin());
        BOOST_REQUIRE(committed_spk_man.SetupDescriptorGeneration(commit_batch, committed_master_key, OutputType::BECH32, /*internal=*/false));
        committed_script = GetCachedScriptPubKey(committed_spk_man, 0);

        {
            LOCK(wallet->cs_wallet);
            BOOST_CHECK(!wallet->IsMine(committed_script));
            BOOST_CHECK(!wallet->GetSolvingProvider(committed_script));
        }

        BOOST_REQUIRE(commit_batch.TxnCommit());
    }

    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->IsMine(committed_script));
        BOOST_CHECK(wallet->GetSolvingProvider(committed_script));
    }

    CExtKey aborted_master_key;
    aborted_master_key.SetSeed(GenerateRandomKey());
    TestDescriptorScriptPubKeyMan aborted_spk_man{*wallet, SINGLE_ADDRESS_KEYPOOL_SIZE};
    CScript aborted_script;
    {
        WalletBatch abort_batch{wallet->GetDatabase()};
        BOOST_REQUIRE(abort_batch.TxnBegin());
        BOOST_REQUIRE(aborted_spk_man.SetupDescriptorGeneration(abort_batch, aborted_master_key, OutputType::BECH32, /*internal=*/false));
        aborted_script = GetCachedScriptPubKey(aborted_spk_man, 0);

        BOOST_REQUIRE(abort_batch.TxnAbort());
    }
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->IsMine(aborted_script));
        BOOST_CHECK(!wallet->GetSolvingProvider(aborted_script));
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(DeferredTopUpNotifiesAfterCommitWithoutWalletLockInversion, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(60))
{
    constexpr int64_t keypool_size{DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL + 1};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());

    auto& database{dynamic_cast<SQLiteDatabase&>(wallet->GetDatabase())};
    int notification_count{0};
    bool callback_can_get_addresses{false};
    std::atomic_bool writer_succeeded{false};
    std::promise<void> wallet_lock_acquired;
    auto wallet_lock_acquired_future{wallet_lock_acquired.get_future()};
    std::thread writer;

    auto connection = external_spk_man->NotifyCanGetAddressesChanged.connect([&] {
        ++notification_count;
        BOOST_CHECK(LockStackEmpty());
        BOOST_CHECK(!database.HasActiveTxn());

        writer = std::thread([&] {
            LOCK(wallet->cs_wallet);
            wallet_lock_acquired.set_value();
            WalletBatch batch{wallet->GetDatabase()};
            writer_succeeded = batch.WriteOrderPosNext(1);
        });
        wallet_lock_acquired_future.wait();
        callback_can_get_addresses = wallet->CanGetAddresses();
    });

    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUpStep() == CWallet::PendingInitialKeyPoolTopUpStepResult::COMPLETE);
    BOOST_REQUIRE(writer.joinable());
    writer.join();

    BOOST_CHECK_EQUAL(notification_count, 1);
    BOOST_CHECK(callback_can_get_addresses);
    BOOST_CHECK(writer_succeeded);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(WalletInterfaceUnlockSerializesDeferredTopUpCachePublicationWithReaders, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(60))
{
    constexpr int64_t keypool_size{DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL + 1};
    const SecureString passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));
    DeferredCreateKeyPoolTopUpBatchStepOverride batch_step_override{1};

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    options.create_passphrase = passphrase;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "interface_unlock_cache_publication_test", std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->IsLocked());
    BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());

    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    BOOST_REQUIRE(external_spk_man);
    const CScript warm_script{GetCachedScriptPubKey(*external_spk_man, 0)};
    auto& database{dynamic_cast<SQLiteDatabase&>(wallet->GetDatabase())};

    std::promise<void> publication_ready;
    std::promise<void> release_publication;
    auto release_publication_future{release_publication.get_future()};
    std::atomic_bool pause_next_publication{true};
    std::atomic_bool publication_lock_stack_empty{false};
    std::atomic_bool publication_transaction_inactive{false};
    wallet->m_before_script_pub_key_cache_publish = [&] {
        if (!pause_next_publication.exchange(false)) return;
        publication_lock_stack_empty = LockStackEmpty();
        publication_transaction_inactive = !database.HasActiveTxn();
        publication_ready.set_value();
        release_publication_future.wait();
    };

    std::promise<void> publication_complete;
    auto publication_complete_future{publication_complete.get_future()};
    std::atomic_bool signal_publication_complete{true};
    auto connection = external_spk_man->NotifyCanGetAddressesChanged.connect([&] {
        if (signal_publication_complete.exchange(false)) publication_complete.set_value();
    });

    auto wallet_interface{interfaces::MakeWallet(context, wallet)};
    BOOST_REQUIRE(wallet_interface);
    BOOST_REQUIRE(wallet_interface->unlock(passphrase));
    publication_ready.get_future().wait();
    BOOST_CHECK(publication_lock_stack_empty);
    BOOST_CHECK(publication_transaction_inactive);

    // Descriptor state and its transaction are complete, but the new script
    // remains invisible until the publication batch acquires cs_wallet.
    const CScript new_script{GetCachedScriptPubKey(*external_spk_man, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL)};
    std::promise<void> reader_locked;
    std::promise<void> run_reader_checks;
    auto run_reader_checks_future{run_reader_checks.get_future()};
    std::promise<void> reader_checked;
    std::promise<void> release_reader;
    auto release_reader_future{release_reader.get_future()};
    std::atomic_bool reader_observed_warm_script{true};
    std::atomic_bool reader_observed_unpublished_script{false};
    std::thread reader{[&] {
        LOCK(wallet->cs_wallet);
        reader_locked.set_value();
        run_reader_checks_future.wait();
        bool observed_warm_script{true};
        for (int i = 0; i < 1000; ++i) {
            observed_warm_script &= wallet->IsMine(warm_script);
            observed_warm_script &= !!wallet->GetSolvingProvider(warm_script);
        }
        reader_observed_warm_script = observed_warm_script;
        reader_observed_unpublished_script = wallet->IsMine(new_script) || !!wallet->GetSolvingProvider(new_script);
        reader_checked.set_value();
        release_reader_future.wait();
    }};

    reader_locked.get_future().wait();
    release_publication.set_value();
    run_reader_checks.set_value();
    reader_checked.get_future().wait();
    BOOST_CHECK(reader_observed_warm_script);
    BOOST_CHECK(!reader_observed_unpublished_script);

    // The publisher has been released, but must still be blocked by the
    // foreground reader's cs_wallet ownership.
    BOOST_CHECK(publication_complete_future.wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout);
    release_reader.set_value();
    reader.join();
    publication_complete_future.wait();

    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->IsMine(new_script));
        BOOST_CHECK(wallet->GetSolvingProvider(new_script));
    }

    WaitForScheduler(*Assert(m_node.scheduler));
    wallet->m_before_script_pub_key_cache_publish = {};
    wallet_interface.reset();
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

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

BOOST_FIXTURE_TEST_CASE(WalletInterfaceUnlockSchedulesDeferredP2MRKeypoolTopUp, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    const SecureString passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));
    DeferredCreateKeyPoolTopUpBatchStepOverride batch_step_override{1};

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    options.create_passphrase = passphrase;

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, "interface_unlock_refill_test", std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->IsLocked());
    BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());

    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    auto* internal_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true)));
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    auto& scheduler{*Assert(m_node.scheduler)};
    std::promise<void> scheduler_blocked;
    std::promise<void> release_scheduler;
    auto release_scheduler_future{release_scheduler.get_future()};
    scheduler.scheduleFromNow([&] {
        scheduler_blocked.set_value();
        release_scheduler_future.wait();
    }, std::chrono::milliseconds{0});
    scheduler_blocked.get_future().wait();

    auto wallet_interface{interfaces::MakeWallet(context, wallet)};
    BOOST_REQUIRE(wallet_interface);
    BOOST_REQUIRE(wallet_interface->unlock(passphrase));
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->m_deferred_create_keypool_top_up_scheduled);
    }

    // Repeated scheduling while the first worker is pending must not queue a
    // second worker.
    MaybeSchedulePendingInitialKeyPoolTopUp(context, wallet);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->m_deferred_create_keypool_top_up_scheduled);
        BOOST_CHECK(wallet->m_deferred_create_keypool_top_up_reschedule_requested);
    }

    // Relocking before the worker runs must pause it and make a later unlock
    // able to schedule a fresh worker.
    BOOST_REQUIRE(wallet_interface->lock());
    release_scheduler.set_value();
    WaitForScheduler(scheduler);
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->m_deferred_create_keypool_top_up_scheduled);
        BOOST_CHECK(!wallet->m_deferred_create_keypool_top_up_reschedule_requested);
    }

    // Exercise the unlock race after a locked worker finishes its step but
    // before it updates the scheduling flags.
    std::promise<void> scheduler_blocked_again;
    std::promise<void> release_scheduler_again;
    auto release_scheduler_again_future{release_scheduler_again.get_future()};
    scheduler.scheduleFromNow([&] {
        scheduler_blocked_again.set_value();
        release_scheduler_again_future.wait();
    }, std::chrono::milliseconds{0});
    scheduler_blocked_again.get_future().wait();

    std::promise<void> step_finished;
    std::promise<void> release_step;
    auto release_step_future{release_step.get_future()};
    std::atomic_bool pause_next_step{true};
    context.deferred_keypool_top_up_step_finished_fn = [&] {
        if (!pause_next_step.exchange(false)) return;
        step_finished.set_value();
        release_step_future.wait();
    };

    BOOST_REQUIRE(wallet_interface->unlock(passphrase));
    BOOST_REQUIRE(wallet_interface->lock());
    release_scheduler_again.set_value();
    step_finished.get_future().wait();

    BOOST_REQUIRE(wallet_interface->unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->m_deferred_create_keypool_top_up_scheduled);
        BOOST_CHECK(wallet->m_deferred_create_keypool_top_up_reschedule_requested);
    }
    release_step.set_value();

    for (int i = 0; i < 10 && wallet->HasPendingInitialKeyPoolTopUp(); ++i) {
        WaitForScheduler(scheduler);
    }

    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->m_deferred_create_keypool_top_up_scheduled);
        BOOST_CHECK(!wallet->m_deferred_create_keypool_top_up_reschedule_requested);
    }

    wallet_interface.reset();
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
