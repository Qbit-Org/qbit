// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <clientversion.h>
#include <streams.h>
#include <uint256.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(walletdb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(walletdb_readkeyvalue)
{
    /**
     * When ReadKeyValue() reads from either a "key" or "wkey" it first reads the DataStream into a
     * CPrivKey or CWalletKey respectively and then reads a hash of the pubkey and privkey into a uint256.
     * Wallets from 0.8 or before do not store the pubkey/privkey hash, trying to read the hash from old
     * wallets throws an exception, for backwards compatibility this read is wrapped in a try block to
     * silently fail. The test here makes sure the type of exception thrown from DataStream::read()
     * matches the type we expect, otherwise we need to update the "key"/"wkey" exception type caught.
     */
    DataStream ssValue{};
    uint256 dummy;
    BOOST_CHECK_THROW(ssValue >> dummy, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(walletdb_writecryptedpqckey_overwrite)
{
    auto database = std::make_unique<MockableDatabase>();
    WalletBatch batch(*database);

    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> secret(key.data(), key.data() + key.size());
    const uint256 descriptor_id{};

    BOOST_CHECK(batch.WriteCryptedDescriptorPQCKey(descriptor_id, pubkey, secret, /*sig_counter=*/0));
    BOOST_CHECK(batch.WriteCryptedDescriptorPQCKey(descriptor_id, pubkey, secret, /*sig_counter=*/1));
}

BOOST_AUTO_TEST_CASE(walletdb_transaction_listener_commit_phases)
{
    auto database = std::make_unique<MockableDatabase>();
    WalletBatch batch(*database);
    std::vector<std::string> events;
    const auto listener = [&](std::string name) {
        return DbTxnListener{
            .on_commit_prepare = [&, name] { events.push_back("prepare_" + name); },
            .on_commit_success = [&, name] { events.push_back("success_" + name); },
            .on_commit_failure = [&, name] { events.push_back("failure_" + name); },
            .on_commit = [&, name] { events.push_back("commit_" + name); },
            .on_abort = [&, name] { events.push_back("abort_" + name); },
        };
    };

    BOOST_REQUIRE(batch.TxnBegin());
    batch.RegisterTxnListener(listener("one"));
    batch.RegisterTxnListener(listener("two"));
    BOOST_REQUIRE(batch.TxnCommit());
    const std::vector<std::string> expected_success{
        "prepare_one", "prepare_two", "success_one", "success_two", "commit_one", "commit_two"};
    BOOST_CHECK(events == expected_success);

    events.clear();
    database->m_txn_commit_pass = false;
    BOOST_REQUIRE(batch.TxnBegin());
    batch.RegisterTxnListener(listener("one"));
    batch.RegisterTxnListener(listener("two"));
    BOOST_CHECK(!batch.TxnCommit());
    const std::vector<std::string> expected_failure{
        "prepare_one", "prepare_two", "failure_one", "failure_two"};
    BOOST_CHECK(events == expected_failure);
    BOOST_REQUIRE(batch.TxnAbort());
    const std::vector<std::string> expected_abort{
        "prepare_one", "prepare_two", "failure_one", "failure_two", "abort_two", "abort_one"};
    BOOST_CHECK(events == expected_abort);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
