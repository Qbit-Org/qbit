// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <interfaces/chain.h>
#include <outputtype.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <test/util/logging.h>
#include <univalue.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_p2mr_test_util.h>
#include <wallet/sqlite.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace wallet {
// These RPCs are not declared in a header.
RPCHelpMan backupwallet();
RPCHelpMan encryptwallet();

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

//! Loads a P2MR wallet from a real database that does not overwrite deleted
//! records. Release builds use SQLite without SQLITE_SECURE_DELETE, so this
//! matches them whatever SQLite the test is linked with.
std::shared_ptr<CWallet> LoadWalletWithoutSecureDelete(WalletContext& context, ArgsManager& args, interfaces::Chain& chain, const std::string& name)
{
    args.ForceSetArg("-keypool", "8");
    context.args = &args;
    context.chain = &chain;
    DatabaseOptions options;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    DatabaseStatus status;
    bilingual_str error;
    auto database{MakeWalletDatabase(name, options, status, error)};
    BOOST_REQUIRE(database);
    // SQLITE_OK is 0.
    BOOST_REQUIRE_EQUAL(SQliteExecHandler{}.Exec(dynamic_cast<SQLiteDatabase&>(*database), "PRAGMA secure_delete = OFF"), 0);
    return TestLoadWallet(std::move(database), context, options.create_flags);
}

//! The private keys of the wallet's plaintext key records.
std::vector<std::vector<unsigned char>> GetPlaintextSecrets(CWallet& wallet)
{
    std::vector<std::vector<unsigned char>> secrets;
    auto batch{wallet.GetDatabase().MakeBatch()};
    for (const std::string& record_type : {DBKeys::WALLETDESCRIPTORKEY, DBKeys::WALLETDESCRIPTORPQCKEY}) {
        DataStream prefix;
        prefix << record_type;
        auto cursor{batch->GetNewPrefixCursor(prefix)};
        DataStream key, value;
        while (cursor->Next(key, value) == DatabaseCursor::Status::MORE) {
            std::string type;
            uint256 desc_id;
            key >> type >> desc_id;
            if (type == DBKeys::WALLETDESCRIPTORKEY) {
                CPubKey pubkey;
                CPrivKey privkey;
                key >> pubkey;
                value >> privkey;
                CKey secret;
                BOOST_REQUIRE(secret.Load(privkey, pubkey, /*fSkipCheck=*/true));
                secrets.emplace_back(UCharCast(secret.begin()), UCharCast(secret.end()));
            } else {
                std::vector<unsigned char> secret;
                value >> secret;
                BOOST_REQUIRE_EQUAL(secret.size(), CPQCKey::SIZE);
                secrets.push_back(std::move(secret));
            }
        }
    }
    return secrets;
}

//! Counts the secrets that appear in any of the files, read as raw bytes.
size_t CountSecretsInFiles(const std::vector<fs::path>& files, const std::vector<std::vector<unsigned char>>& secrets)
{
    std::set<size_t> found;
    for (const fs::path& file : files) {
        std::ifstream stream{file, std::ios::binary};
        const std::vector<unsigned char> contents{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
        for (size_t i{0}; i < secrets.size(); ++i) {
            if (std::search(contents.begin(), contents.end(), secrets[i].begin(), secrets[i].end()) != contents.end()) found.insert(i);
        }
    }
    return found.size();
}

bool HasPostEncryptionRewrite(CWallet& wallet)
{
    return WalletBatch(wallet.GetDatabase()).HasPostEncryptionRewrite();
}

//! Keeps a statement reading the database, which makes a VACUUM fail.
class UnfinishedRead
{
public:
    void Start(WalletDatabase& database)
    {
        m_batch = database.MakeBatch();
        m_cursor = m_batch->GetNewCursor();
        DataStream key, value;
        BOOST_REQUIRE(m_cursor->Next(key, value) == DatabaseCursor::Status::MORE);
    }
    void Finish()
    {
        m_cursor.reset();
        m_batch.reset();
    }

private:
    std::unique_ptr<DatabaseBatch> m_batch;
    std::unique_ptr<DatabaseCursor> m_cursor;
};

//! Calls an RPC with one string argument on the wallet with the empty name.
UniValue CallWalletRPC(WalletContext& context, const RPCHelpMan& rpc, const std::string& argument)
{
    JSONRPCRequest request;
    request.context = &context;
    request.URI = "/wallet/";
    request.params = UniValue{UniValue::VARR};
    request.params.push_back(argument);
    return rpc.HandleRequest(request);
}

//! The message of the RPC error that the call throws, or an empty string.
std::string GetRPCError(const std::function<void()>& call)
{
    try {
        call();
    } catch (const UniValue& error) {
        return error.find_value("message").get_str();
    }
    return "";
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

// A process that stops after the encryption commit and before the rewrite
// leaves the deleted plaintext keys in the wallet's files. Copy the files at
// that point, as a stop would leave them, and check that loading the copy
// removes the keys.
BOOST_FIXTURE_TEST_CASE(EncryptWalletStoppedBeforeRewriteIsRewrittenOnLoad, RegtestP2MROnlyWalletTestingSetup)
{
    WalletContext context;
    auto wallet{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "")};
    BOOST_REQUIRE(wallet);
    const auto secrets{GetPlaintextSecrets(*wallet)};
    BOOST_REQUIRE(!secrets.empty());

    const fs::path stopped_dir{fs::PathFromString(wallet->GetDatabase().Filename()).parent_path() / "stopped"};
    std::vector<fs::path> stopped_files;
    wallet->m_after_encrypt_wallet_commit = [&] {
        fs::create_directories(stopped_dir);
        for (const fs::path& file : wallet->GetDatabase().Files()) {
            if (!fs::exists(file)) continue;
            stopped_files.push_back(stopped_dir / file.filename());
            fs::copy_file(file, stopped_files.back(), fs::copy_options::none);
        }
    };
    BOOST_REQUIRE(wallet->EncryptWallet("passphrase"));
    wallet->m_after_encrypt_wallet_commit = {};
    BOOST_CHECK(HasPostEncryptionRewrite(*wallet));
    BOOST_CHECK_EQUAL(CountSecretsInFiles(wallet->GetDatabase().Files(), secrets), 0U);
    TestUnloadWallet(std::move(wallet));

    // Without a rewrite, the stopped wallet's files still hold the keys.
    BOOST_REQUIRE(CountSecretsInFiles(stopped_files, secrets) > 0);
    auto stopped{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "stopped")};
    BOOST_REQUIRE(stopped);
    BOOST_CHECK(stopped->IsCrypted());
    BOOST_CHECK(HasPostEncryptionRewrite(*stopped));
    BOOST_CHECK_EQUAL(CountSecretsInFiles(stopped->GetDatabase().Files(), secrets), 0U);
    TestUnloadWallet(std::move(stopped));
    BOOST_CHECK_EQUAL(CountSecretsInFiles(stopped_files, secrets), 0U);
}

// VACUUM fails while a transaction is open. The rewrite must wait for a
// transaction that another batch has open rather than fail.
BOOST_FIXTURE_TEST_CASE(EncryptWalletRewriteWaitsForOpenTransaction, RegtestP2MROnlyWalletTestingSetup)
{
    WalletContext context;
    auto wallet{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "")};
    BOOST_REQUIRE(wallet);
    const auto secrets{GetPlaintextSecrets(*wallet)};
    BOOST_REQUIRE(!secrets.empty());

    std::promise<void> txn_begun;
    std::future<bool> writer;
    wallet->m_after_encrypt_wallet_commit = [&] {
        writer = std::async(std::launch::async, [&] {
            auto batch{wallet->GetDatabase().MakeBatch()};
            const bool begun{batch->TxnBegin()};
            txn_begun.set_value();
            if (!begun) return false;
            // Keep the transaction open while EncryptWallet starts its rewrite.
            std::this_thread::sleep_for(std::chrono::milliseconds{300});
            return batch->Write(std::string{"testrecord"}, uint8_t{1}) && batch->TxnCommit();
        });
        auto begun{txn_begun.get_future()};
        WaitOrExit(begun, "the writer to begin its transaction");
    };
    BOOST_REQUIRE(wallet->EncryptWallet("passphrase"));
    wallet->m_after_encrypt_wallet_commit = {};
    WaitOrExit(writer, "the writer");
    BOOST_CHECK(writer.get());

    BOOST_CHECK(HasPostEncryptionRewrite(*wallet));
    BOOST_CHECK_EQUAL(CountSecretsInFiles(wallet->GetDatabase().Files(), secrets), 0U);
    TestUnloadWallet(std::move(wallet));
}

// A rewrite that fails, here because a statement still has a read transaction
// open, must leave the record absent. The next load must rewrite the file.
BOOST_FIXTURE_TEST_CASE(EncryptWalletFailedRewriteIsRetriedOnLoad, RegtestP2MROnlyWalletTestingSetup)
{
    WalletContext context;
    auto wallet{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "")};
    BOOST_REQUIRE(wallet);
    const auto secrets{GetPlaintextSecrets(*wallet)};
    BOOST_REQUIRE(!secrets.empty());

    UnfinishedRead read;
    wallet->m_after_encrypt_wallet_commit = [&] { read.Start(wallet->GetDatabase()); };
    BOOST_REQUIRE(wallet->EncryptWallet("passphrase"));
    wallet->m_after_encrypt_wallet_commit = {};
    read.Finish();
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(!HasPostEncryptionRewrite(*wallet));
    TestUnloadWallet(std::move(wallet));

    wallet = LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "");
    BOOST_REQUIRE(wallet);
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(HasPostEncryptionRewrite(*wallet));
    BOOST_CHECK_EQUAL(CountSecretsInFiles(wallet->GetDatabase().Files(), secrets), 0U);
    TestUnloadWallet(std::move(wallet));
}

// A backup copies the file's free pages. After a failed rewrite it must run the
// rewrite first, or be refused while the rewrite still fails. Either way it must
// not copy the deleted plaintext keys.
BOOST_FIXTURE_TEST_CASE(BackupAfterFailedRewriteDoesNotCopyPlaintextKeys, RegtestP2MROnlyWalletTestingSetup)
{
    WalletContext context;
    auto wallet{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "")};
    BOOST_REQUIRE(wallet);
    const auto secrets{GetPlaintextSecrets(*wallet)};
    BOOST_REQUIRE(!secrets.empty());
    AddWallet(context, wallet);

    UnfinishedRead read;
    wallet->m_after_encrypt_wallet_commit = [&] { read.Start(wallet->GetDatabase()); };
    const std::string result{CallWalletRPC(context, encryptwallet(), "passphrase").get_str()};
    wallet->m_after_encrypt_wallet_commit = {};
    BOOST_CHECK(result.find("Warning: the wallet file could not be rewritten") != std::string::npos);
    BOOST_CHECK(!HasPostEncryptionRewrite(*wallet));
    BOOST_REQUIRE(CountSecretsInFiles(wallet->GetDatabase().Files(), secrets) > 0);

    // While the rewrite still fails, the backup is refused.
    const fs::path restored_dir{fs::PathFromString(wallet->GetDatabase().Filename()).parent_path() / "restored"};
    fs::create_directories(restored_dir);
    const fs::path backup{restored_dir / "wallet.dat"};
    const std::string error{GetRPCError([&] { CallWalletRPC(context, backupwallet(), fs::PathToString(backup)); })};
    BOOST_CHECK(error.find("Backup refused") != std::string::npos);
    BOOST_CHECK(!fs::exists(backup));
    BOOST_CHECK(!HasPostEncryptionRewrite(*wallet));

    // Once it can succeed, the backup runs it first.
    read.Finish();
    CallWalletRPC(context, backupwallet(), fs::PathToString(backup));
    BOOST_CHECK(HasPostEncryptionRewrite(*wallet));
    BOOST_CHECK_EQUAL(CountSecretsInFiles(wallet->GetDatabase().Files(), secrets), 0U);
    BOOST_REQUIRE(fs::exists(backup));
    BOOST_CHECK_EQUAL(CountSecretsInFiles({backup}, secrets), 0U);
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
    TestUnloadWallet(std::move(wallet));

    // The backup is an encrypted wallet that needs no further rewrite.
    bool rewrote{false};
    {
        DebugLogHelper log_helper{"Rewrote the wallet file", [&](const std::string* line) {
            if (line) rewrote = true;
            return false;
        }};
        auto restored{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "restored")};
        BOOST_REQUIRE(restored);
        BOOST_CHECK(restored->IsCrypted());
        BOOST_CHECK(restored->Unlock("passphrase"));
        TestUnloadWallet(std::move(restored));
    }
    BOOST_CHECK(!rewrote);
}

// With no rewrite pending, a backup does not rewrite the file, and encryptwallet
// has nothing to warn about.
BOOST_FIXTURE_TEST_CASE(BackupWithoutPendingRewriteDoesNotRewrite, RegtestP2MROnlyWalletTestingSetup)
{
    WalletContext context;
    auto wallet{LoadWalletWithoutSecureDelete(context, m_args, *m_node.chain, "")};
    BOOST_REQUIRE(wallet);
    const auto secrets{GetPlaintextSecrets(*wallet)};
    BOOST_REQUIRE(!secrets.empty());
    AddWallet(context, wallet);
    const fs::path wallet_dir{fs::PathFromString(wallet->GetDatabase().Filename()).parent_path()};

    bool rewrote{false};
    const auto note_rewrite{[&](const std::string* line) {
        if (line) rewrote = true;
        return false;
    }};
    const fs::path unencrypted_backup{wallet_dir / "unencrypted.bak"};
    {
        DebugLogHelper log_helper{"Rewrote the wallet file", note_rewrite};
        BOOST_CHECK(wallet->BackupWallet(fs::PathToString(unencrypted_backup)));
    }
    BOOST_CHECK(!rewrote);
    BOOST_CHECK(!HasPostEncryptionRewrite(*wallet));
    // The keys of an unencrypted wallet are live records, so its backup has them all.
    BOOST_CHECK_EQUAL(CountSecretsInFiles({unencrypted_backup}, secrets), secrets.size());

    const std::string result{CallWalletRPC(context, encryptwallet(), "passphrase").get_str()};
    BOOST_CHECK(result.find("Warning") == std::string::npos);
    BOOST_CHECK(HasPostEncryptionRewrite(*wallet));

    const fs::path encrypted_backup{wallet_dir / "encrypted.bak"};
    {
        DebugLogHelper log_helper{"Rewrote the wallet file", note_rewrite};
        CallWalletRPC(context, backupwallet(), fs::PathToString(encrypted_backup));
    }
    BOOST_CHECK(!rewrote);
    BOOST_CHECK_EQUAL(CountSecretsInFiles({encrypted_backup}, secrets), 0U);

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
