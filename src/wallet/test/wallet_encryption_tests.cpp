// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <interfaces/chain.h>
#include <outputtype.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_p2mr_test_util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

namespace wallet {
namespace {

// Allows for sanitizer overhead and concurrent CI tests. Only a stuck thread
// waits this long.
constexpr auto STUCK_THREAD_TIMEOUT{std::chrono::minutes{5}};

//! A stuck thread holds wallet locks, and the future of a std::async call
//! waits for that thread when destroyed, so a failing test cannot unwind past
//! it. Say which thread is stuck and end the test process.
template <typename Future>
void WaitOrExit(Future& future, const char* waiting_for)
{
    if (future.wait_for(STUCK_THREAD_TIMEOUT) == std::future_status::ready) return;
    std::cerr << "Timed out waiting for " << waiting_for << ": the wallet threads are deadlocked" << std::endl;
    std::_Exit(EXIT_FAILURE);
}

//! Parks the first thread that passes until the test releases it.
class ParkingPoint
{
public:
    void Pass()
    {
        if (!m_armed.exchange(false)) return;
        m_reached.set_value();
        m_released.get_future().wait();
    }
    void WaitUntilReached(const char* waiting_for)
    {
        auto reached{m_reached.get_future()};
        WaitOrExit(reached, waiting_for);
    }
    void Release()
    {
        if (!m_release_done.exchange(true)) m_released.set_value();
    }

private:
    std::atomic<bool> m_armed{true};
    std::atomic<bool> m_release_done{false};
    std::promise<void> m_reached;
    std::promise<void> m_released;
};

//! Destroying a std::async future waits for its thread, so release a parked
//! thread when a failing test unwinds past this point.
class ReleaseOnExit
{
public:
    explicit ReleaseOnExit(ParkingPoint& point) : m_point{point} {}
    ~ReleaseOnExit() { m_point.Release(); }

private:
    ParkingPoint& m_point;
};

std::shared_ptr<CWallet> LoadP2MRWalletForKeyPoolTest(WalletContext& context, ArgsManager& args, interfaces::Chain& chain)
{
    args.ForceSetArg("-keypool", "32");
    context.args = &args;
    context.chain = &chain;
    return TestLoadWallet(context);
}

DescriptorScriptPubKeyMan* GetP2MRChangeManager(CWallet& wallet)
{
    LOCK(wallet.cs_wallet);
    return dynamic_cast<DescriptorScriptPubKeyMan*>(wallet.GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
}

//! Counts records of one type in a real database.
size_t CountDatabaseRecords(CWallet& wallet, const std::string& record_type)
{
    auto batch{wallet.GetDatabase().MakeBatch()};
    DataStream prefix;
    prefix << record_type;
    auto cursor{batch->GetNewPrefixCursor(prefix)};
    size_t count{0};
    DataStream key, value;
    while (cursor->Next(key, value) == DatabaseCursor::Status::MORE) {
        ++count;
        key.clear();
        value.clear();
    }
    return count;
}

std::unique_ptr<CWallet> CreateUnencryptedWallet(interfaces::Chain& chain)
{
    return CreateDescriptorWallet(chain, GetSupportedOutputTypes(), /*keypool_size=*/1);
}

size_t CountMasterKeyRecords(CWallet& wallet)
{
    size_t count{0};
    for (const auto& [serialized_key, _] : GetMockableDatabase(wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::MASTER_KEY) ++count;
    }
    return count;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_encryption_tests, WalletTestingSetup)

// An EncryptWallet caller derives its encryption key without holding the
// wallet locks. A competing caller that encrypts the wallet in that window
// must make the first caller fail cleanly and leave the competitor's
// encryption untouched.
BOOST_AUTO_TEST_CASE(ConcurrentEncryptWalletLoserFailsCleanly)
{
    auto wallet{CreateUnencryptedWallet(*m_node.chain)};
    const SecureString loser_passphrase{"loser"};
    const SecureString winner_passphrase{"winner"};

    std::promise<void> loser_key_derived;
    std::promise<void> release_loser;
    auto release_future{release_loser.get_future()};
    bool loser_released{false};
    const auto release = [&] {
        if (!std::exchange(loser_released, true)) release_loser.set_value();
    };
    std::atomic<bool> hold_next{true};
    wallet->m_before_encrypt_wallet_locks = [&] {
        if (!hold_next.exchange(false)) return;
        loser_key_derived.set_value();
        release_future.wait();
    };
    auto loser{std::async(std::launch::async, [&] { return wallet->EncryptWallet(loser_passphrase); })};
    // Destroying the future waits for the parked caller, so release it when a
    // failed assertion unwinds past this point.
    struct ReleaseOnExit {
        decltype(release)& fn;
        ~ReleaseOnExit() { fn(); }
    } const release_on_exit{release};
    loser_key_derived.get_future().wait();

    // The parked caller holds no wallet lock, so this encryption runs to
    // completion before it resumes.
    BOOST_REQUIRE(wallet->EncryptWallet(winner_passphrase));
    release();
    BOOST_CHECK(!loser.get());
    wallet->m_before_encrypt_wallet_locks = {};

    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK_EQUAL(wallet->mapMasterKeys.size(), 1U);
    BOOST_CHECK_EQUAL(CountMasterKeyRecords(*wallet), 1U);
    BOOST_CHECK(!wallet->Unlock(loser_passphrase));
    BOOST_CHECK(wallet->Unlock(winner_passphrase));
}

// When the database transaction cannot begin, the new master key must not
// stay in memory: the wallet remains unencrypted and usable, and a later
// attempt encrypts it normally.
BOOST_AUTO_TEST_CASE(EncryptWalletFailedTxnBeginLeavesWalletUnencrypted)
{
    auto wallet{CreateUnencryptedWallet(*m_node.chain)};
    MockableDatabase& database{GetMockableDatabase(*wallet)};
    const SecureString passphrase{"passphrase"};

    database.m_txn_begin_pass = false;
    BOOST_CHECK(!wallet->EncryptWallet(passphrase));
    database.m_txn_begin_pass = true;
    BOOST_CHECK(!wallet->IsCrypted());
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK(wallet->mapMasterKeys.empty());
    BOOST_CHECK_EQUAL(CountMasterKeyRecords(*wallet), 0U);

    BOOST_CHECK(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK_EQUAL(wallet->mapMasterKeys.size(), 1U);
    BOOST_CHECK_EQUAL(CountMasterKeyRecords(*wallet), 1U);
    BOOST_CHECK(wallet->Unlock(passphrase));
}

// A master key that cannot be written is the first write of the encryption
// transaction. The attempt must be rolled back with nothing kept in memory,
// rather than committing keys whose master key never reached the database.
BOOST_AUTO_TEST_CASE(EncryptWalletFailedMasterKeyWriteLeavesWalletUnencrypted)
{
    auto wallet{CreateUnencryptedWallet(*m_node.chain)};
    MockableDatabase& database{GetMockableDatabase(*wallet)};
    const SecureString passphrase{"passphrase"};
    const MockableData records_before{database.m_records};

    database.ResetCounts();
    database.m_write_fail_after = 0;
    BOOST_CHECK(!wallet->EncryptWallet(passphrase));
    database.m_write_fail_after = -1;
    BOOST_CHECK_EQUAL(database.m_txn_abort_count, 1);
    BOOST_CHECK(!wallet->IsCrypted());
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK(wallet->mapMasterKeys.empty());
    BOOST_CHECK(database.m_records == records_before);

    BOOST_CHECK(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK_EQUAL(CountMasterKeyRecords(*wallet), 1U);
    BOOST_CHECK(wallet->Unlock(passphrase));
}

// A background top-up runs without cs_wallet, as RunP2MRKeyPoolRefillStep and
// RunPendingInitialKeyPoolTopUpStep do. Force it to reach its locks while
// EncryptWallet has its database transaction open: EncryptWallet must not wait
// for a descriptor lock held by a top-up that is waiting for the transaction.
BOOST_FIXTURE_TEST_CASE(EncryptWalletAndBackgroundTopUpBothFinish, RegtestP2MROnlyWalletTestingSetup)
{
    WalletContext context;
    auto wallet{LoadP2MRWalletForKeyPoolTest(context, m_args, *m_node.chain)};
    auto* change{GetP2MRChangeManager(*wallet)};
    BOOST_REQUIRE(change);
    const unsigned int target{change->GetKeyPoolSize() + 4};
    BOOST_REQUIRE(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY) > 0);

    ParkingPoint top_up_prepared;
    ParkingPoint encrypt_txn_open;
    change->m_after_prepare_top_up = [&] { top_up_prepared.Pass(); };
    wallet->m_after_encrypt_wallet_txn_begin = [&] { encrypt_txn_open.Pass(); };

    // MSVC's std::future needs an assignable result type, which util::Result
    // is not, so the thread returns whether the top-up succeeded.
    auto top_up{std::async(std::launch::async, [&] { return change->TopUpWithInternalHintResult(/*internal_hint=*/true, target).has_value(); })};
    const ReleaseOnExit release_top_up{top_up_prepared};
    top_up_prepared.WaitUntilReached("the top-up to take its snapshot");
    auto encrypt{std::async(std::launch::async, [&] { return wallet->EncryptWallet("passphrase"); })};
    const ReleaseOnExit release_encrypt{encrypt_txn_open};
    encrypt_txn_open.WaitUntilReached("EncryptWallet to begin its transaction");

    // The top-up cannot complete while EncryptWallet owns the database writer.
    // Give it time to run into whichever lock it waits on.
    top_up_prepared.Release();
    BOOST_CHECK(top_up.wait_for(std::chrono::milliseconds{300}) == std::future_status::timeout);

    encrypt_txn_open.Release();
    WaitOrExit(encrypt, "EncryptWallet");
    WaitOrExit(top_up, "the top-up");
    change->m_after_prepare_top_up = {};
    wallet->m_after_encrypt_wallet_txn_begin = {};

    BOOST_CHECK(encrypt.get());
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());
    // The encryption committed first, so the top-up's snapshot is out of date.
    BOOST_CHECK(!top_up.get());
    BOOST_CHECK_EQUAL(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY), 0U);

    TestUnloadWallet(std::move(wallet));
}

// A top-up whose snapshot predates the whole encryption must drop that
// snapshot instead of persisting plaintext PQC private keys into the encrypted
// wallet, and the wallet must reload and top up normally afterwards.
BOOST_FIXTURE_TEST_CASE(StaleTopUpSnapshotDoesNotWritePlaintextKeys, RegtestP2MROnlyWalletTestingSetup)
{
    const SecureString passphrase{"passphrase"};
    WalletContext context;
    auto wallet{LoadP2MRWalletForKeyPoolTest(context, m_args, *m_node.chain)};
    auto* change{GetP2MRChangeManager(*wallet)};
    BOOST_REQUIRE(change);
    const uint256 change_id{change->GetID()};
    const unsigned int keypool_size{change->GetKeyPoolSize()};
    const unsigned int target{keypool_size + 4};
    BOOST_REQUIRE(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY) > 0);

    ParkingPoint top_up_prepared;
    change->m_after_prepare_top_up = [&] { top_up_prepared.Pass(); };
    auto top_up{std::async(std::launch::async, [&] { return change->TopUpWithInternalHintResult(/*internal_hint=*/true, target).has_value(); })};
    const ReleaseOnExit release_top_up{top_up_prepared};
    top_up_prepared.WaitUntilReached("the top-up to take its snapshot");

    // The parked top-up holds no lock, so this encryption runs to completion.
    BOOST_CHECK(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK_EQUAL(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY), 0U);

    top_up_prepared.Release();
    WaitOrExit(top_up, "the top-up");
    change->m_after_prepare_top_up = {};
    BOOST_CHECK(!top_up.get());
    BOOST_CHECK_EQUAL(change->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY), 0U);

    TestUnloadWallet(std::move(wallet));
    wallet = TestLoadWallet(context);
    BOOST_REQUIRE(wallet);
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK_EQUAL(wallet->GetPQCKeyValidationInfo().plaintext_records, 0U);
    BOOST_CHECK_EQUAL(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY), 0U);

    // With a snapshot of the encrypted wallet, the same top-up writes crypted keys.
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    auto* reloaded_change{dynamic_cast<DescriptorScriptPubKeyMan*>(WITH_LOCK(wallet->cs_wallet, return wallet->GetScriptPubKeyMan(change_id)))};
    BOOST_REQUIRE(reloaded_change);
    const size_t crypted_records{CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCCKEY)};
    BOOST_CHECK(reloaded_change->TopUpWithInternalHintResult(/*internal_hint=*/true, target));
    BOOST_CHECK_EQUAL(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCCKEY), crypted_records + 4);
    BOOST_CHECK_EQUAL(CountDatabaseRecords(*wallet, DBKeys::WALLETDESCRIPTORPQCKEY), 0U);

    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
