// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <outputtype.h>
#include <wallet/context.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override {}
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "trx(tqpbZguYqtPCTm5UaopQ7izSVprMFpwXrV6gzuv6Ev9LNN68CavjtUrSbS7j3DQsfmmtW5Tn7nAvVTYBVHVHfF44KzRxTSaKGGn1jWa9cfEd7Vt/86'/1'/0'/0/*)#8gn5y6af";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::UNKNOWN_DESCRIPTOR);
    }

    // Test 2
    // Now write a valid descriptor with an invalid ID.
    // As the software produces another ID for the descriptor, the loading process must be aborted.
    database = CreateMockableWalletDatabase();

    // Verify the error
    bool found = false;
    DebugLogHelper logHelper("The descriptor ID calculated by the wallet differs from the one in DB", [&](const std::string* s) {
        found = true;
        return false;
    });

    {
        // Write valid descriptor with invalid ID
        WalletBatch batch(*database);
        std::string desc = "wpkh([d34db33f/84h/0h/0h]qpubUraEiRJcm6MqZkZFFduhzNveZDc7cHM8euBmem2Zm8sZQKCfzyozjo6383AJEVBL5qQENot99bfa2kxP6JWqT5cEyVRUpRS76UtgPhJWtD8/0/*)#6su5nfpr";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256::ONE, wallet_descriptor));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::CORRUPT);
        BOOST_CHECK(found); // The error must be logged
    }
}

// A wallet encrypted by v1.0.0 has no POST_ENCRYPTION_REWRITE record. Its
// first load must rewrite the file and write the record, and later loads must
// not rewrite it again. A failed rewrite must not fail the load, and the next
// load must retry it.
BOOST_FIXTURE_TEST_CASE(wallet_load_rewrites_encrypted_wallet_once, TestingSetup)
{
    m_args.ForceSetArg("-keypool", "1");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    DataStream record_key;
    record_key << DBKeys::POST_ENCRYPTION_REWRITE;
    const SerializeData record{record_key.begin(), record_key.end()};
    MockableData records;
    {
        auto wallet{CreateDescriptorWallet(*m_node.chain, GetSupportedOutputTypes(), /*keypool_size=*/1)};
        BOOST_REQUIRE(wallet->EncryptWallet("passphrase"));
        records = GetMockableDatabase(*wallet).m_records;
    }
    BOOST_REQUIRE_EQUAL(records.erase(record), 1U);

    // Loads the records, then keeps the records the load left behind.
    const auto load{[&](bool rewrite_pass) {
        auto database{std::make_unique<MockableDatabase>(records)};
        MockableDatabase& mock{*database};
        mock.m_rewrite_pass = rewrite_pass;
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        auto wallet{CWallet::Create(context, "", std::move(database), WALLET_FLAG_DESCRIPTORS, error, warnings)};
        BOOST_REQUIRE(wallet);
        BOOST_CHECK(wallet->IsCrypted());
        const int rewrites{mock.m_rewrite_count};
        // Only a failed rewrite is reported to the user.
        const bool warned{std::any_of(warnings.begin(), warnings.end(), [](const bilingual_str& warning) {
            return warning.original.find("could not be rewritten after encryption") != std::string::npos;
        })};
        BOOST_CHECK_EQUAL(warned, rewrites > 0 && !rewrite_pass);
        records = mock.m_records;
        TestUnloadWallet(std::move(wallet));
        return rewrites;
    }};

    BOOST_CHECK_EQUAL(load(/*rewrite_pass=*/true), 1);
    BOOST_CHECK(records.contains(record));
    BOOST_CHECK_EQUAL(load(/*rewrite_pass=*/true), 0);
    BOOST_CHECK(records.contains(record));

    records.erase(record);
    BOOST_CHECK_EQUAL(load(/*rewrite_pass=*/false), 1);
    BOOST_CHECK(!records.contains(record));
    BOOST_CHECK_EQUAL(load(/*rewrite_pass=*/true), 1);
    BOOST_CHECK(records.contains(record));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
