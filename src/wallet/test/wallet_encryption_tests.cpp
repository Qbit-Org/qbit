// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <interfaces/chain.h>
#include <outputtype.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstddef>
#include <future>
#include <memory>
#include <string>

namespace wallet {
namespace {

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
    std::atomic<bool> hold_next{true};
    wallet->m_before_encrypt_wallet_locks = [&] {
        if (!hold_next.exchange(false)) return;
        loser_key_derived.set_value();
        release_future.wait();
    };
    auto loser{std::async(std::launch::async, [&] { return wallet->EncryptWallet(loser_passphrase); })};
    loser_key_derived.get_future().wait();

    // The parked caller holds no wallet lock, so this encryption runs to
    // completion before it resumes.
    BOOST_REQUIRE(wallet->EncryptWallet(winner_passphrase));
    release_loser.set_value();
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

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
