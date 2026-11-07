// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <wallet/sqlite.h>

#include <thread>

// These cases take a few seconds in a release build and, in the CI MSan job,
// 10-45 times as long, up to about a minute, which is close to the release
// time limits. Sanitizer builds get twice those limits.
#if defined(__has_feature)
#if __has_feature(memory_sanitizer) || __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer) || \
    __has_feature(thread_sanitizer)
#define WALLET_P2MR_DEFERRED_KEYPOOL_TESTS_SANITIZER
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_HWADDRESS__) || defined(__SANITIZE_THREAD__)
#define WALLET_P2MR_DEFERRED_KEYPOOL_TESTS_SANITIZER
#endif

namespace wallet {
using namespace wallet_p2mr_test;

RPCHelpMan walletpassphrase();

namespace {
//! Per-case time limit: `seconds` in a release build, twice that under a sanitizer.
constexpr unsigned TimeLimit(unsigned seconds)
{
#ifdef WALLET_P2MR_DEFERRED_KEYPOOL_TESTS_SANITIZER
    return 2 * seconds;
#else
    return seconds;
#endif
}

void CallWalletPassphrase(WalletContext& context, const std::string& wallet_name, const std::string& passphrase, int64_t timeout)
{
    JSONRPCRequest request;
    request.context = &context;
    request.URI = "/wallet/" + wallet_name;
    request.params = UniValue{UniValue::VARR};
    request.params.push_back(passphrase);
    request.params.push_back(timeout);
    walletpassphrase().HandleRequest(request);
}

//! Holds the scheduler thread so that a test can see what an RPC did before
//! any background step runs.
class SchedulerBlocker
{
public:
    explicit SchedulerBlocker(CScheduler& scheduler)
    {
        scheduler.scheduleFromNow([this, release = m_release.get_future().share()] {
            m_blocked.set_value();
            release.wait();
        }, std::chrono::milliseconds{0});
        m_blocked.get_future().wait();
    }
    ~SchedulerBlocker() { Release(); }
    void Release()
    {
        if (m_released) return;
        m_released = true;
        m_release.set_value();
    }

private:
    std::promise<void> m_blocked;
    std::promise<void> m_release;
    bool m_released{false};
};
} // namespace

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

BOOST_FIXTURE_TEST_CASE(DeferredTopUpNotifiesAfterCommitWithoutWalletLockInversion, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(60)))
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

BOOST_FIXTURE_TEST_CASE(WalletInterfaceUnlockSerializesDeferredTopUpCachePublicationWithReaders, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(60)))
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
    std::set<CScript> unpublished_scripts;
    wallet->m_before_script_pub_key_cache_publish = [&](const std::set<CScript>& spks, ScriptPubKeyMan* spk_man) {
        if (spk_man != external_spk_man) return;
        if (!pause_next_publication.exchange(false)) return;
        unpublished_scripts = spks;
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

    // Descriptor state and its transaction are complete, so the new script
    // remains visible while publication into the wallet cache is pending.
    BOOST_REQUIRE_EQUAL(unpublished_scripts.size(), 1U);
    const CScript new_script{*unpublished_scripts.begin()};
    std::promise<void> reader_locked;
    std::promise<void> run_reader_checks;
    auto run_reader_checks_future{run_reader_checks.get_future()};
    std::promise<void> reader_checked;
    std::promise<void> release_reader;
    auto release_reader_future{release_reader.get_future()};
    std::atomic_bool reader_observed_warm_script{true};
    std::atomic_bool reader_observed_committed_script{false};
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
        reader_observed_committed_script = wallet->IsMine(new_script) && !!wallet->GetSolvingProvider(new_script);
        reader_checked.set_value();
        release_reader_future.wait();
    }};

    reader_locked.get_future().wait();
    release_publication.set_value();
    run_reader_checks.set_value();
    reader_checked.get_future().wait();
    BOOST_CHECK(reader_observed_warm_script);
    BOOST_CHECK(reader_observed_committed_script);

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

BOOST_FIXTURE_TEST_CASE(StartWalletsSchedulesDeferredP2MRKeypoolTopUpForStartupWallets, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    const SecureString passphrase{"test-passphrase"};
    m_node.args->ForceSetArg("-keypool", util::ToString(keypool_size));
    DeferredCreateKeyPoolTopUpBatchStepOverride batch_step_override{1};

    // Use the loader's context, which outlives the periodic tasks that
    // StartWallets() registers on the scheduler.
    WalletContext& context{*Assert(m_wallet_loader->context())};
    BOOST_REQUIRE(!context.scheduler);

    const auto check_keypool_size = [](CWallet& wallet, unsigned int expected) {
        LOCK(wallet.cs_wallet);
        for (const bool internal : {false, true}) {
            auto* spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet.GetScriptPubKeyMan(OutputType::P2MR, internal));
            BOOST_REQUIRE(spk_man);
            BOOST_CHECK_EQUAL(spk_man->GetKeyPoolSize(), expected);
        }
    };

    // Without a scheduler no top-up is queued, as when the node stops before
    // the deferred top-up has run.
    const std::vector<std::pair<std::string, SecureString>> startup_wallets{
        {"startup_plain", ""},
        {"startup_encrypted", passphrase},
        {"startup_unloaded", ""},
    };
    common::SettingsValue wallet_setting{common::SettingsValue::VARR};
    for (const auto& [name, wallet_passphrase] : startup_wallets) {
        DatabaseOptions create_options;
        create_options.require_create = true;
        create_options.create_flags = WALLET_FLAG_DESCRIPTORS;
        create_options.create_passphrase = wallet_passphrase;

        DatabaseStatus status;
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        auto wallet = CreateWallet(context, name, std::nullopt, create_options, status, error, warnings);
        BOOST_REQUIRE(wallet);
        BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
        BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());
        BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
        WaitForDeleteWallet(std::move(wallet));
        wallet_setting.push_back(name);
    }
    m_node.chain->overwriteRwSetting("wallet", std::move(wallet_setting), interfaces::SettingsAction::SKIP_WRITE);

    // Node startup loads the wallets with LoadWallets() and only then gives
    // them the scheduler in StartWallets().
    BOOST_REQUIRE(m_wallet_loader->load());
    auto plain_wallet{GetWallet(context, "startup_plain")};
    auto encrypted_wallet{GetWallet(context, "startup_encrypted")};
    auto unloaded_wallet{GetWallet(context, "startup_unloaded")};
    BOOST_REQUIRE(plain_wallet);
    BOOST_REQUIRE(encrypted_wallet);
    BOOST_REQUIRE(unloaded_wallet);
    BOOST_REQUIRE(encrypted_wallet->IsLocked());
    for (CWallet* wallet : {plain_wallet.get(), encrypted_wallet.get(), unloaded_wallet.get()}) {
        BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
        check_keypool_size(*wallet, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    auto& scheduler = *Assert(m_node.scheduler);
    m_wallet_loader->start(scheduler);
    BOOST_CHECK(WITH_LOCK(plain_wallet->cs_wallet, return plain_wallet->m_deferred_create_keypool_top_up_scheduled));
    // A locked wallet queues nothing and still finishes at its first unlock.
    BOOST_CHECK(!WITH_LOCK(encrypted_wallet->cs_wallet, return encrypted_wallet->m_deferred_create_keypool_top_up_scheduled));

    // A wallet unloaded while its top-up is queued must not be topped up.
    BOOST_CHECK(RemoveWallet(context, unloaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(unloaded_wallet));

    // Stay well inside the 30 second delay that loadwallet also uses.
    scheduler.MockForward(std::chrono::seconds{25});
    WaitForScheduler(scheduler);
    BOOST_CHECK(plain_wallet->HasPendingInitialKeyPoolTopUp());
    check_keypool_size(*plain_wallet, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    scheduler.MockForward(std::chrono::seconds{5});
    WaitForScheduler(scheduler);
    for (int i = 0; i < 10 && plain_wallet->HasPendingInitialKeyPoolTopUp(); ++i) {
        scheduler.MockForward(std::chrono::seconds{1});
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK(!plain_wallet->HasPendingInitialKeyPoolTopUp());
    check_keypool_size(*plain_wallet, keypool_size);

    BOOST_CHECK(encrypted_wallet->IsLocked());
    BOOST_CHECK(encrypted_wallet->HasPendingInitialKeyPoolTopUp());
    check_keypool_size(*encrypted_wallet, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_REQUIRE(encrypted_wallet->Unlock(passphrase));
    BOOST_CHECK(!encrypted_wallet->HasPendingInitialKeyPoolTopUp());
    check_keypool_size(*encrypted_wallet, keypool_size);

    DatabaseOptions load_options;
    load_options.require_existing = true;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto reloaded_wallet = LoadWallet(context, "startup_unloaded", std::nullopt, load_options, status, error, warnings);
    BOOST_REQUIRE(reloaded_wallet);
    BOOST_CHECK(reloaded_wallet->HasPendingInitialKeyPoolTopUp());
    check_keypool_size(*reloaded_wallet, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK(RemoveWallet(context, reloaded_wallet, std::nullopt));
    WaitForDeleteWallet(std::move(reloaded_wallet));

    plain_wallet.reset();
    encrypted_wallet.reset();
    m_wallet_loader->stop();
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

BOOST_FIXTURE_TEST_CASE(WalletPassphraseSchedulesDeferredP2MRKeypoolTopUp, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(120)))
{
    constexpr int64_t keypool_size{64};
    const std::string wallet_name{"walletpassphrase_deferred_test"};
    const std::string passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    options.create_passphrase = SecureString{passphrase};

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, wallet_name, std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->IsLocked());
    BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());

    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    auto* internal_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true)));
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    auto& scheduler{*Assert(m_node.scheduler)};
    SchedulerBlocker blocker{scheduler};
    CallWalletPassphrase(context, wallet_name, passphrase, /*timeout=*/1000);

    // The RPC returns unlocked without deriving the deferred keys itself.
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->m_deferred_create_keypool_top_up_scheduled);
        BOOST_CHECK_GT(wallet->nRelockTime, 0);
    }

    blocker.Release();
    for (int i = 0; i < 20 && wallet->HasPendingInitialKeyPoolTopUp(); ++i) {
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK(!WITH_LOCK(wallet->cs_wallet, return wallet->m_deferred_create_keypool_top_up_scheduled));

    BOOST_REQUIRE(wallet->Lock());
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(WalletLockWaitsForBackgroundKeyPoolTopUpStep, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(120)))
{
    constexpr int64_t keypool_size{64};
    const std::string wallet_name{"walletlock_background_step_test"};
    const std::string passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    options.create_passphrase = SecureString{passphrase};

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, wallet_name, std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());

    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    auto* internal_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true)));
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    // Pause the first background step after one of its top-ups, while it
    // holds no wallet lock, and record whether Lock() returns meanwhile.
    std::promise<void> in_step;
    std::promise<void> lock_returned;
    std::shared_future<void> lock_returned_future{lock_returned.get_future().share()};
    std::atomic_bool first_notification{true};
    std::atomic_bool lock_returned_during_step{false};
    boost::signals2::scoped_connection connection{external_spk_man->NotifyCanGetAddressesChanged.connect([&] {
        if (!first_notification.exchange(false)) return;
        in_step.set_value();
        lock_returned_during_step = lock_returned_future.wait_for(std::chrono::milliseconds{500}) == std::future_status::ready;
    })};

    CallWalletPassphrase(context, wallet_name, passphrase, /*timeout=*/1000);
    in_step.get_future().wait();
    std::thread lock_thread{[&] {
        wallet->Lock();
        lock_returned.set_value();
    }};
    lock_thread.join();
    BOOST_CHECK(!lock_returned_during_step);
    BOOST_CHECK(wallet->IsLocked());

    // The step finished before the lock, and no later step derives keys.
    auto& scheduler{*Assert(m_node.scheduler)};
    for (int i = 0; i < 5; ++i) {
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), 2 * DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), 2 * DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK(!WITH_LOCK(wallet->cs_wallet, return wallet->m_deferred_create_keypool_top_up_scheduled));

    connection.disconnect();
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(WalletPassphraseSchedulesP2MRKeypoolRefill, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(120)))
{
    // Large enough that the receive refill takes two background steps, and no
    // larger: under MSan each address drawn while locked takes about a second
    // and each key derived about half that, and with -keypool=64 this case ran
    // past its time limit.
    constexpr int64_t keypool_size{2 * DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL + 4};
    const std::string wallet_name{"walletpassphrase_refill_test"};
    const std::string passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    options.create_passphrase = SecureString{passphrase};

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, wallet_name, std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);

    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    auto* internal_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true)));
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);

    // Finish the create-time top-up, then, while the wallet is locked and the
    // pools cannot refill, drain the receive pool to its low watermark and
    // the change pool partway. A refill paused by a relock leaves a pool
    // between the two.
    BOOST_REQUIRE(wallet->Unlock(SecureString{passphrase}));
    BOOST_REQUIRE(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_REQUIRE(wallet->Lock());
    const unsigned int low_watermark{external_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    const unsigned int partial_size{keypool_size - 4};
    BOOST_REQUIRE_LT(low_watermark, partial_size);
    while (external_spk_man->GetKeyPoolSize() > low_watermark) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    while (internal_spk_man->GetKeyPoolSize() > partial_size) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR));
    }
    BOOST_REQUIRE(external_spk_man->NeedsP2MRReceiveKeyPoolRefill());
    BOOST_REQUIRE(!internal_spk_man->NeedsP2MRReceiveKeyPoolRefill());
    // The first receive refill step stops short of -keypool.
    BOOST_REQUIRE_LT(external_spk_man->GetP2MRReceiveKeyPoolRefillStepTarget(), keypool_size);

    auto& scheduler{*Assert(m_node.scheduler)};
    SchedulerBlocker blocker{scheduler};
    CallWalletPassphrase(context, wallet_name, passphrase, /*timeout=*/1000);

    // Both refills to -keypool are queued rather than derived inline.
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), low_watermark);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), partial_size);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->m_p2mr_receive_keypool_refill_scheduled);
        BOOST_CHECK(wallet->m_p2mr_change_keypool_refill_scheduled);
    }

    blocker.Release();
    for (int i = 0; i < 20 && (!external_spk_man->P2MRReceiveKeyPoolFull() || !internal_spk_man->P2MRReceiveKeyPoolFull()); ++i) {
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->m_p2mr_receive_keypool_refill_scheduled);
        BOOST_CHECK(!wallet->m_p2mr_change_keypool_refill_scheduled);
    }

    BOOST_REQUIRE(wallet->Lock());
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(WalletPassphraseTopsUpNonP2MRKeypoolInline, RegtestUnrestrictedWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(120)))
{
    constexpr int64_t keypool_size{20};
    const std::string wallet_name{"walletpassphrase_non_p2mr_test"};
    const std::string passphrase{"test-passphrase"};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    options.create_passphrase = SecureString{passphrase};

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CreateWallet(context, wallet_name, std::nullopt, options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->IsLocked());

    // A hardened descriptor can only derive keys while the wallet is unlocked.
    BOOST_REQUIRE(wallet->Unlock(SecureString{passphrase}));
    DescriptorScriptPubKeyMan* hardened_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        CExtKey master_key;
        master_key.SetSeed(GenerateRandomKey());
        FlatSigningProvider provider;
        std::string parse_error;
        auto descriptors{Parse("wpkh(" + EncodeExtKey(master_key) + "/0h/*h)", provider, parse_error, /*require_checksum=*/false)};
        BOOST_REQUIRE_MESSAGE(descriptors.size() == 1, parse_error);
        WalletDescriptor w_desc{std::move(descriptors.front()), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0};
        auto spk_man{wallet->AddWalletDescriptor(w_desc, provider, "", /*internal=*/false)};
        BOOST_REQUIRE_MESSAGE(spk_man, util::ErrorString(spk_man).original);
        hardened_spk_man = &spk_man->get();
        wallet->AddActiveScriptPubKeyMan(hardened_spk_man->GetID(), OutputType::BECH32, /*internal=*/false);
    }
    BOOST_REQUIRE_EQUAL(hardened_spk_man->GetKeyPoolSize(), keypool_size);
    auto* p2mr_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    BOOST_REQUIRE(p2mr_spk_man);
    BOOST_REQUIRE_EQUAL(p2mr_spk_man->GetKeyPoolSize(), keypool_size);

    // Drain both pools while locked.
    BOOST_REQUIRE(wallet->Lock());
    while (hardened_spk_man->GetKeyPoolSize() > 0) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::BECH32, ""));
    }
    BOOST_REQUIRE(!wallet->GetNewDestination(OutputType::BECH32, ""));
    const unsigned int low_watermark{p2mr_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    while (p2mr_spk_man->GetKeyPoolSize() > low_watermark) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    BOOST_REQUIRE(p2mr_spk_man->NeedsP2MRReceiveKeyPoolRefill());

    auto& scheduler{*Assert(m_node.scheduler)};
    SchedulerBlocker blocker{scheduler};
    CallWalletPassphrase(context, wallet_name, passphrase, /*timeout=*/1000);

    // The non-P2MR pool is full when the RPC returns; the P2MR one is queued.
    BOOST_CHECK_EQUAL(hardened_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(p2mr_spk_man->GetKeyPoolSize(), low_watermark);
    BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return wallet->m_p2mr_receive_keypool_refill_scheduled));

    blocker.Release();
    for (int i = 0; i < 20 && !p2mr_spk_man->P2MRReceiveKeyPoolFull(); ++i) {
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK_EQUAL(p2mr_spk_man->GetKeyPoolSize(), keypool_size);

    BOOST_REQUIRE(wallet->Lock());
    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(BackgroundKeyPoolTopUpCommitFailurePausesWithoutAborting, RegtestP2MROnlyWalletTestingSetup, * boost::unit_test::timeout(TimeLimit(120)))
{
    constexpr int64_t keypool_size{64};
    // Service the queue on this thread: an exception that escapes a step
    // then fails the check below instead of terminating the test binary.
    CScheduler scheduler;
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = &scheduler;
    const auto run_scheduler = [&] {
        scheduler.StopWhenDrained();
        BOOST_CHECK_NO_THROW(scheduler.serviceQueue());
    };

    auto wallet{std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase())};
    {
        LOCK(wallet->cs_wallet);
        wallet->m_keypool_size = keypool_size;
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans(/*use_create_keypool_warmup=*/true);
    }
    auto* external_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)));
    auto* internal_spk_man = WITH_LOCK(wallet->cs_wallet, return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true)));
    BOOST_REQUIRE(external_spk_man);
    BOOST_REQUIRE(internal_spk_man);
    BOOST_REQUIRE(wallet->HasPendingInitialKeyPoolTopUp());
    auto& database{GetMockableDatabase(*wallet)};

    // Deferred create-time top-up: the failed step pauses the top-up, keeps
    // it pending and lets a later attempt schedule it again.
    database.ResetCounts();
    database.m_txn_commit_pass = false;
    MaybeSchedulePendingInitialKeyPoolTopUp(context, wallet);
    BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return wallet->m_deferred_create_keypool_top_up_scheduled));
    run_scheduler();
    BOOST_CHECK_EQUAL(database.m_txn_commit_count, 1);
    BOOST_CHECK_EQUAL(database.m_txn_abort_count, 1);
    BOOST_CHECK(wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    BOOST_CHECK(!WITH_LOCK(wallet->cs_wallet, return wallet->m_deferred_create_keypool_top_up_scheduled));

    database.m_txn_commit_pass = true;
    MaybeSchedulePendingInitialKeyPoolTopUp(context, wallet);
    run_scheduler();
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    // Low-watermark refill: the same failure clears the scheduled flag, so
    // the next address request can schedule a new refill.
    const unsigned int low_watermark{external_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    while (external_spk_man->GetKeyPoolSize() > low_watermark) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    BOOST_REQUIRE(external_spk_man->NeedsP2MRReceiveKeyPoolRefill());
    database.ResetCounts();
    database.m_txn_commit_pass = false;
    MaybeScheduleP2MRKeyPoolRefill(context, wallet, OutputType::P2MR, /*internal=*/false);
    BOOST_CHECK(WITH_LOCK(wallet->cs_wallet, return wallet->m_p2mr_receive_keypool_refill_scheduled));
    run_scheduler();
    BOOST_CHECK_EQUAL(database.m_txn_commit_count, 1);
    BOOST_CHECK_EQUAL(database.m_txn_abort_count, 1);
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), low_watermark);
    BOOST_CHECK(!WITH_LOCK(wallet->cs_wallet, return wallet->m_p2mr_receive_keypool_refill_scheduled));

    database.m_txn_commit_pass = true;
    MaybeScheduleP2MRKeyPoolRefill(context, wallet, OutputType::P2MR, /*internal=*/false);
    run_scheduler();
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK(!WITH_LOCK(wallet->cs_wallet, return wallet->m_p2mr_receive_keypool_refill_scheduled));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
