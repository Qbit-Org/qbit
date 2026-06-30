// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_change_keypool_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(P2MRGetNewChangeAddressDoesNotTopUpAboveLowWatermark, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    int32_t initial_range_end;
    {
        LOCK(internal_spk_man->cs_desc_man);
        initial_range_end = internal_spk_man->GetWalletDescriptor().range_end;
    }

    for (int i = 0; i < 4; ++i) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR));
        BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), static_cast<unsigned int>(keypool_size - i - 1));
        LOCK(internal_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(internal_spk_man->GetWalletDescriptor().range_end, initial_range_end);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2MRGetNewChangeAddressBoundsLowWatermarkRefill, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    const unsigned int low_watermark{internal_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    BOOST_REQUIRE_EQUAL(low_watermark, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    for (int64_t i = 0; i < keypool_size - int64_t{low_watermark}; ++i) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR));
    }
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark);

    int32_t range_end_at_watermark;
    {
        LOCK(internal_spk_man->cs_desc_man);
        range_end_at_watermark = internal_spk_man->GetWalletDescriptor().range_end;
    }

    BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR));
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark + DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL - 1);
    BOOST_CHECK_LT(internal_spk_man->GetKeyPoolSize(), static_cast<unsigned int>(keypool_size));
    {
        LOCK(internal_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(internal_spk_man->GetWalletDescriptor().range_end, range_end_at_watermark + DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(InternalP2MRInlineRefillLogsTransactionFailure)
{
    constexpr int64_t keypool_size{20};
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.m_keypool_size = keypool_size;
        wallet.SetupDescriptorScriptPubKeyMans(P2MR_ONLY_OUTPUT_TYPES);
    }

    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet.GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    const unsigned int low_watermark{internal_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    BOOST_REQUIRE_EQUAL(low_watermark, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    for (int64_t i = 0; i < keypool_size - int64_t{low_watermark}; ++i) {
        BOOST_REQUIRE(wallet.GetNewChangeDestination(OutputType::P2MR));
    }
    BOOST_REQUIRE_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark);

    auto& database = GetMockableDatabase(wallet);
    database.ResetCounts();
    database.m_txn_begin_pass = false;
    {
        DebugLogHelper log_helper("P2MR change keypool inline low-watermark refill failed", [](const std::string* line) {
            return line && line->find("Error starting descriptors keypool top-up database transaction") != std::string::npos;
        });
        auto dest{wallet.GetNewChangeDestination(OutputType::P2MR)};
        BOOST_REQUIRE_MESSAGE(dest.has_value(), util::ErrorString(dest).original);
    }

    BOOST_CHECK_EQUAL(database.m_txn_begin_count, 1);
    BOOST_CHECK_EQUAL(database.m_txn_abort_count, 0);
    BOOST_CHECK_EQUAL(database.m_txn_commit_count, 0);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark - 1);
}

BOOST_FIXTURE_TEST_CASE(P2MRGetRawChangeAddressSchedulesLowWatermarkRefill, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{64};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    const unsigned int low_watermark{internal_spk_man->GetP2MRReceiveKeyPoolLowWatermark()};
    BOOST_REQUIRE_EQUAL(low_watermark, DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
    for (int64_t i = 0; i < keypool_size - int64_t{low_watermark}; ++i) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR, /*allow_internal_p2mr_refill=*/false));
    }
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark);

    int32_t range_end_at_watermark;
    {
        LOCK(internal_spk_man->cs_desc_man);
        range_end_at_watermark = internal_spk_man->GetWalletDescriptor().range_end;
    }

    BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR, /*allow_internal_p2mr_refill=*/false));
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark - 1);
    {
        LOCK(internal_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(internal_spk_man->GetWalletDescriptor().range_end, range_end_at_watermark);
    }

    MaybeScheduleP2MRKeyPoolRefill(context, wallet, OutputType::P2MR, /*internal=*/true);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), low_watermark - 1);
    {
        LOCK(internal_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(internal_spk_man->GetWalletDescriptor().range_end, range_end_at_watermark);
    }

    auto& scheduler = *Assert(m_node.scheduler);
    for (int i = 0; i < 10 && internal_spk_man->GetKeyPoolSize() < keypool_size; ++i) {
        scheduler.MockForward(std::chrono::seconds{1});
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2MRGetRawChangeAddressFallbackTopUpAtExhaustionWithoutInlineRefill, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{17};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK(wallet->RunPendingInitialKeyPoolTopUp());

    for (int64_t i = 0; i < keypool_size; ++i) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR, /*allow_internal_p2mr_refill=*/false));
    }
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), 0U);

    int32_t exhausted_range_end;
    {
        LOCK(internal_spk_man->cs_desc_man);
        exhausted_range_end = internal_spk_man->GetWalletDescriptor().range_end;
    }
    BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR, /*allow_internal_p2mr_refill=*/false));
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), 0U);
    {
        LOCK(internal_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(internal_spk_man->GetWalletDescriptor().range_end, exhausted_range_end + 1);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(LockedEncryptedP2MRWalletUsesCachedChangeKeysBelowLowWatermark, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{20};
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
    auto wallet = CreateWallet(context, "locked_cached_change_low_watermark_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_CHECK(wallet->IsLocked());
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    BOOST_CHECK(!wallet->HasPendingInitialKeyPoolTopUp());
    BOOST_REQUIRE(wallet->Lock());

    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(internal_spk_man);
    BOOST_CHECK_EQUAL(internal_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(internal_spk_man->GetP2MRReceiveKeyPoolLowWatermark(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    for (int i = 0; i < 5; ++i) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR));
    }
    BOOST_CHECK_LT(internal_spk_man->GetKeyPoolSize(), internal_spk_man->GetP2MRReceiveKeyPoolLowWatermark());
    for (int i = 0; i < 15; ++i) {
        BOOST_REQUIRE(wallet->GetNewChangeDestination(OutputType::P2MR));
    }
    auto exhausted_addr = wallet->GetNewChangeDestination(OutputType::P2MR);
    BOOST_CHECK(!exhausted_addr);
    BOOST_CHECK_EQUAL(util::ErrorString(exhausted_addr).original, "Error: Keypool ran out, please call keypoolrefill first");

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(LockedP2MRLowWatermarkRefillStepReportsFailure, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{20};
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
    auto wallet = CreateWallet(context, "locked_refill_step_failure_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_REQUIRE(wallet->IsLocked());

    BOOST_CHECK(wallet->RunP2MRKeyPoolRefillStep(/*internal=*/false) == CWallet::P2MRKeyPoolRefillStepResult::FAILED);

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
