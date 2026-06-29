// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <atomic>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <array>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <addresstype.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <crypto/pqc.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <scheduler.h>
#include <script/p2mr.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/walletdb.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <chrono>

namespace wallet {

extern std::atomic<int> g_deferred_create_keypool_top_up_steps_per_batch;

// Ensure that fee levels defined in the wallet are at least as high
// as the default levels for node policy.
static_assert(DEFAULT_TRANSACTION_MINFEE >= DEFAULT_MIN_RELAY_TX_FEE, "wallet minimum fee is smaller than default relay fee");
static_assert(WALLET_INCREMENTAL_RELAY_FEE >= DEFAULT_INCREMENTAL_RELAY_FEE, "wallet incremental fee is smaller than default incremental relay fee");

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_tests, WalletTestingSetup)

constexpr std::array<OutputType, 1> P2MR_ONLY_OUTPUT_TYPES{OutputType::P2MR};
constexpr std::array<OutputType, 1> BECH32_ONLY_OUTPUT_TYPES{OutputType::BECH32};
constexpr std::array<OutputType, 3> CHANGE_FALLBACK_OUTPUT_TYPES{OutputType::BECH32M, OutputType::BECH32, OutputType::P2MR};
constexpr int64_t SINGLE_ADDRESS_KEYPOOL_SIZE{1};
constexpr int64_t FOUR_ADDRESS_KEYPOOL_SIZE{4};

struct RegtestP2MROnlyWalletTestingSetup : public WalletTestingSetup {
    RegtestP2MROnlyWalletTestingSetup()
        : WalletTestingSetup(ChainType::REGTEST, {.extra_args = {"-p2mronly=1"}}) {}
};

struct RegtestDefaultWalletTestingSetup : public WalletTestingSetup {
    RegtestDefaultWalletTestingSetup()
        : WalletTestingSetup(ChainType::REGTEST) {}
};

struct RegtestUnrestrictedWalletTestingSetup : public WalletTestingSetup {
    RegtestUnrestrictedWalletTestingSetup()
        : WalletTestingSetup(ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}) {}
};

namespace {
struct DeferredCreateKeyPoolTopUpBatchStepOverride {
    explicit DeferredCreateKeyPoolTopUpBatchStepOverride(int step_count)
        : m_previous_step_count(g_deferred_create_keypool_top_up_steps_per_batch.exchange(step_count))
    {
    }

    ~DeferredCreateKeyPoolTopUpBatchStepOverride()
    {
        g_deferred_create_keypool_top_up_steps_per_batch.store(m_previous_step_count);
    }

    const int m_previous_step_count;
};

void WaitForScheduler(CScheduler& scheduler)
{
    std::promise<void> promise;
    scheduler.scheduleFromNow([&promise] { promise.set_value(); }, std::chrono::milliseconds{1});
    promise.get_future().wait();
}

class TestDescriptorScriptPubKeyMan : public DescriptorScriptPubKeyMan
{
public:
    using DescriptorScriptPubKeyMan::DescriptorScriptPubKeyMan;
    using DescriptorScriptPubKeyMan::TopUpWithDB;
};

struct CachedP2MRPubKeys {
    CPubKey descriptor_pubkey;
    CPQCPubKey pqc_pubkey;
};

CachedP2MRPubKeys GetCachedP2MRPubKeys(DescriptorScriptPubKeyMan& spk_man, int32_t pos)
{
    LOCK(spk_man.cs_desc_man);
    const WalletDescriptor wallet_descriptor = spk_man.GetWalletDescriptor();
    std::vector<CScript> scripts;
    FlatSigningProvider out_keys;
    BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
    BOOST_REQUIRE_EQUAL(out_keys.p2mr_pubkeys.size(), 1U);
    return {
        .descriptor_pubkey = out_keys.pubkeys.begin()->second,
        .pqc_pubkey = out_keys.p2mr_pubkeys.begin()->second,
    };
}

CScript GetCachedScriptPubKey(DescriptorScriptPubKeyMan& spk_man, int32_t index)
{
    LOCK(spk_man.cs_desc_man);
    const WalletDescriptor wallet_descriptor = spk_man.GetWalletDescriptor();
    std::vector<CScript> scripts;
    FlatSigningProvider out_keys;
    Assert(wallet_descriptor.descriptor->ExpandFromCache(index, wallet_descriptor.cache, scripts, out_keys));
    assert(scripts.size() == 1);
    return scripts.at(0);
}

uint32_t GetProviderPQCCounter(DescriptorScriptPubKeyMan& spk_man, const CPubKey& descriptor_pubkey, const CPQCPubKey& pqc_pubkey)
{
    const auto provider{spk_man.GetSigningProvider(descriptor_pubkey)};
    BOOST_REQUIRE(provider);
    const auto counter_it{provider->pqc_sig_counters.find(pqc_pubkey)};
    BOOST_REQUIRE(counter_it != provider->pqc_sig_counters.end());
    return counter_it->second;
}

std::string FormatInputErrors(const std::map<int, bilingual_str>& input_errors)
{
    std::string message;
    for (const auto& [input_index, error] : input_errors) {
        if (!message.empty()) message += "; ";
        message += strprintf("input %d: %s", input_index, error.original);
    }
    return message;
}

std::vector<unsigned char> ToBytes(const CScript& script)
{
    return {script.begin(), script.end()};
}

void AddPQCSigningKeyForTest(FlatSigningProvider& provider, const CPQCKey& key)
{
    const CPQCPubKey pubkey{key.GetPubKey()};
    provider.pqc_keys.emplace(pubkey, key);
    provider.pqc_sig_counters.emplace(pubkey, 0);
}

class RuntimeFailPQCSigningProvider final : public SigningProvider
{
public:
    FlatSigningProvider provider;
    std::set<CPQCPubKey> failing_pubkeys;
    mutable std::map<CPQCPubKey, int> sign_attempts;

    bool CanSignPQC(const CPQCPubKey& pubkey) const override
    {
        return provider.CanSignPQC(pubkey);
    }

    bool SignPQC(const CPQCPubKey& pubkey, const uint256& hash, std::vector<unsigned char>& sig) const override
    {
        ++sign_attempts[pubkey];
        if (failing_pubkeys.count(pubkey) != 0) {
            sig.clear();
            return false;
        }
        return provider.SignPQC(pubkey, hash, sig);
    }

    bool GetP2MRSpendData(const WitnessV2P2MR& output, P2MRSpendData& spenddata) const override
    {
        return provider.GetP2MRSpendData(output, spenddata);
    }

    bool GetP2MRBuilder(const WitnessV2P2MR& output, TaprootBuilder& builder) const override
    {
        return provider.GetP2MRBuilder(output, builder);
    }
};

CScript P2MRMultiAScript(int threshold, const std::vector<CPQCPubKey>& pubkeys)
{
    CScript script;
    for (size_t i{0}; i < pubkeys.size(); ++i) {
        script << std::vector<unsigned char>(pubkeys.at(i).begin(), pubkeys.at(i).end()) << (i == 0 ? OP_CHECKSIGPQC : OP_CHECKSIGADD);
    }
    script << threshold << OP_NUMEQUAL;
    return script;
}

struct P2MRSigningWorkload {
    std::unique_ptr<CWallet> wallet;
    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    std::vector<CachedP2MRPubKeys> pubkeys;
    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
};

P2MRSigningWorkload MakeDistinctKeyP2MRSigningWorkload(interfaces::Chain& chain, size_t input_count)
{
    auto wallet = CreateDescriptorWallet(chain, P2MR_ONLY_OUTPUT_TYPES, input_count);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(input_count); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }

    std::vector<CachedP2MRPubKeys> pubkeys;
    for (int32_t pos{0}; pos < static_cast<int32_t>(input_count); ++pos) {
        pubkeys.push_back(GetCachedP2MRPubKeys(*p2mr_spk_man, pos));
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < input_count; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(input_count) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    return {
        .wallet = std::move(wallet),
        .p2mr_spk_man = p2mr_spk_man,
        .pubkeys = std::move(pubkeys),
        .spend_tx = std::move(spend_tx),
        .coins = std::move(coins),
    };
}
} // namespace

BOOST_AUTO_TEST_CASE(DefaultAddressTypeRequiresP2MRSPKM)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto seeded_wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    CKey key = GenerateRandomKey();
    BOOST_REQUIRE(CreateDescriptor(*seeded_wallet, "wpkh(" + EncodeSecret(key) + ")", true));

    auto wallet = TestLoadWallet(DuplicateMockDatabase(seeded_wallet->GetDatabase()), context, WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::BECH32);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(DefaultAddressTypeUsesP2MROnMainnet)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::P2MR);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(DefaultAddressTypeUsesP2MROnRegtestP2MROnly, RegtestP2MROnlyWalletTestingSetup)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::P2MR);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(WalletOutputAvailabilityRequiresAllowedTypeAndManager, RegtestP2MROnlyWalletTestingSetup)
{
    CWallet bare_wallet{m_node.chain.get(), "", CreateMockableWalletDatabase()};
    BOOST_CHECK(bare_wallet.GetActiveScriptPubKeyMans().empty());
    BOOST_CHECK(!HasWalletOutputTypeManager(bare_wallet, OutputType::P2MR, /*internal=*/false));
    BOOST_CHECK(!IsAvailableWalletOutputType(bare_wallet, OutputType::P2MR, /*internal=*/false));

    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK(HasWalletOutputTypeManager(*wallet, OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK(IsAvailableWalletOutputType(*wallet, OutputType::P2MR, /*internal=*/false));
        BOOST_CHECK(!HasWalletOutputTypeManager(*wallet, OutputType::LEGACY, /*internal=*/false));
        BOOST_CHECK(!IsAvailableWalletOutputType(*wallet, OutputType::LEGACY, /*internal=*/false));
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(FreshWalletOnlyCreatesP2MRManagers)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false));
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(FreshRegtestWalletDefaultsToP2MROnlyManagers, RegtestDefaultWalletTestingSetup)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false));
        BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true));
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, OutputType::P2MR);
    }
    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(FreshRegtestWalletCanOptOutOfP2MROnlyManagers, RegtestUnrestrictedWalletTestingSetup)
{
    m_args.ForceSetArg("-keypool", util::ToString(SINGLE_ADDRESS_KEYPOOL_SIZE));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    auto wallet = TestLoadWallet(context);
    {
        LOCK(wallet->cs_wallet);
        for (const auto& output_type : SUPPORTED_OUTPUT_TYPES) {
            BOOST_CHECK(wallet->GetScriptPubKeyMan(output_type, /*internal=*/false));
            BOOST_CHECK(wallet->GetScriptPubKeyMan(output_type, /*internal=*/true));
        }
        BOOST_CHECK_EQUAL(wallet->m_default_address_type, DEFAULT_ADDRESS_TYPE);
    }
    TestUnloadWallet(std::move(wallet));
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

BOOST_FIXTURE_TEST_CASE(P2MRGetNewAddressDoesNotTopUpAboveLowWatermark, RegtestP2MROnlyWalletTestingSetup)
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
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);
    BOOST_CHECK_EQUAL(external_spk_man->GetP2MRReceiveKeyPoolLowWatermark(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    int32_t initial_range_end;
    {
        LOCK(external_spk_man->cs_desc_man);
        initial_range_end = external_spk_man->GetWalletDescriptor().range_end;
    }

    for (int i = 0; i < 4; ++i) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
        BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), static_cast<unsigned int>(keypool_size - i - 1));
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, initial_range_end);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2MRGetNewAddressSchedulesLowWatermarkRefill, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{32};
    m_args.ForceSetArg("-keypool", util::ToString(keypool_size));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    context.scheduler = Assert(m_node.scheduler).get();

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
    for (int64_t i = 0; i < keypool_size - int64_t{low_watermark}; ++i) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), low_watermark);

    int32_t range_end_at_watermark;
    {
        LOCK(external_spk_man->cs_desc_man);
        range_end_at_watermark = external_spk_man->GetWalletDescriptor().range_end;
    }
    MaybeScheduleP2MRKeyPoolRefill(context, wallet, OutputType::P2MR, /*internal=*/false);
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), low_watermark);
    {
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, range_end_at_watermark);
    }

    auto& scheduler = *Assert(m_node.scheduler);
    for (int i = 0; i < 10 && external_spk_man->GetKeyPoolSize() < keypool_size; ++i) {
        scheduler.MockForward(std::chrono::seconds{1});
        WaitForScheduler(scheduler);
    }
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), keypool_size);

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(P2MRGetNewAddressFallbackTopUpAtExhaustionWithoutScheduler, RegtestP2MROnlyWalletTestingSetup)
{
    constexpr int64_t keypool_size{17};
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

    for (int64_t i = 0; i < keypool_size; ++i) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), 0U);

    int32_t exhausted_range_end;
    {
        LOCK(external_spk_man->cs_desc_man);
        exhausted_range_end = external_spk_man->GetWalletDescriptor().range_end;
    }
    BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    BOOST_CHECK_EQUAL(external_spk_man->GetKeyPoolSize(), 0U);
    {
        LOCK(external_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(external_spk_man->GetWalletDescriptor().range_end, exhausted_range_end + 1);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(LockedEncryptedP2MRWalletUsesCachedKeysBelowLowWatermark, RegtestP2MROnlyWalletTestingSetup)
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
    auto wallet = CreateWallet(context, "locked_cached_low_watermark_test", std::nullopt, create_options, status, error, warnings);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE_EQUAL(status, DatabaseStatus::SUCCESS);
    BOOST_CHECK(wallet->IsLocked());
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
    BOOST_CHECK_EQUAL(external_spk_man->GetP2MRReceiveKeyPoolLowWatermark(), DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);

    for (int i = 0; i < 5; ++i) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    BOOST_CHECK_LT(external_spk_man->GetKeyPoolSize(), external_spk_man->GetP2MRReceiveKeyPoolLowWatermark());
    for (int i = 0; i < 15; ++i) {
        BOOST_REQUIRE(wallet->GetNewDestination(OutputType::P2MR, ""));
    }
    auto exhausted_addr = wallet->GetNewDestination(OutputType::P2MR, "");
    BOOST_CHECK(!exhausted_addr);
    BOOST_CHECK_EQUAL(util::ErrorString(exhausted_addr).original, "Error: Keypool ran out, please call keypoolrefill first");

    BOOST_CHECK(RemoveWallet(context, wallet, std::nullopt));
    WaitForDeleteWallet(std::move(wallet));
}

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
BOOST_AUTO_TEST_CASE(DescriptorTopUpWithDBThrowsWhenP2MRPersistenceNeedsLockedKey)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const SecureString passphrase{"test-passphrase"};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        wallet.m_keypool_size = SINGLE_ADDRESS_KEYPOOL_SIZE;
    }
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase, /*run_pending_initial_keypool_top_up=*/false));
    DescriptorScriptPubKeyMan* spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        CExtKey master_key;
        master_key.SetSeed(GenerateRandomKey());
        WalletBatch batch{wallet.GetDatabase()};
        spk_man = &wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::P2MR, /*internal=*/false);
    }
    BOOST_REQUIRE(spk_man);
    BOOST_CHECK_EQUAL(spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_REQUIRE(wallet.Lock());
    BOOST_REQUIRE(wallet.IsLocked());

    auto top_up_res{spk_man->TopUpWithInternalHintResult(/*internal_hint=*/false, SINGLE_ADDRESS_KEYPOOL_SIZE + 1)};
    BOOST_CHECK(!top_up_res);
    BOOST_CHECK_EQUAL(util::ErrorString(top_up_res).original, "wallet encryption key is unavailable for P2MR private-key persistence");
}

BOOST_AUTO_TEST_CASE(DescriptorTopUpWithDBAllowsLockedPublicP2MRWithoutPrivatePersistence)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
    }
    BOOST_REQUIRE(wallet.EncryptWallet(SecureString{"test-passphrase"}));
    BOOST_REQUIRE(wallet.IsLocked());

    const std::string desc_str{"mr(pk(" + HexStr(std::vector<unsigned char>(CPQCPubKey::SIZE, 0x11)) + "))"};
    FlatSigningProvider keys;
    std::string error;
    auto descs{Parse(desc_str, keys, error, /*require_checksum=*/false)};
    BOOST_REQUIRE_MESSAGE(descs.size() == 1U, error);
    WalletDescriptor desc{std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0};
    TestDescriptorScriptPubKeyMan spk_man{wallet, desc, SINGLE_ADDRESS_KEYPOOL_SIZE};
    WalletBatch batch{wallet.GetDatabase()};

    bool top_up{false};
    BOOST_CHECK_NO_THROW(top_up = spk_man.TopUpWithDB(batch, SINGLE_ADDRESS_KEYPOOL_SIZE, /*internal_hint=*/false));
    BOOST_CHECK(top_up);
    BOOST_CHECK_EQUAL(spk_man.GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
}

BOOST_AUTO_TEST_CASE(TopUpKeyPoolResultContinuesAfterDescriptorFailure)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const SecureString passphrase{"test-passphrase"};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET);
        wallet.m_keypool_size = SINGLE_ADDRESS_KEYPOOL_SIZE;
    }
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase, /*run_pending_initial_keypool_top_up=*/false));

    DescriptorScriptPubKeyMan* failing_spk_man{nullptr};
    DescriptorScriptPubKeyMan* continued_spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        CExtKey master_key;
        master_key.SetSeed(GenerateRandomKey());
        WalletBatch batch{wallet.GetDatabase()};
        failing_spk_man = &wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::P2MR, /*internal=*/false);
        continued_spk_man = &wallet.SetupDescriptorScriptPubKeyMan(batch, master_key, OutputType::BECH32, /*internal=*/true);
    }
    BOOST_REQUIRE(failing_spk_man);
    BOOST_REQUIRE(continued_spk_man);
    BOOST_CHECK_EQUAL(failing_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_CHECK_EQUAL(continued_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_REQUIRE(wallet.Lock());

    auto top_up_res{wallet.TopUpKeyPoolResult(SINGLE_ADDRESS_KEYPOOL_SIZE + 1)};
    BOOST_CHECK(!top_up_res);
    const std::string message{util::ErrorString(top_up_res).original};
    BOOST_CHECK(message.find("active external p2mr descriptor keypool") != std::string::npos);
    BOOST_CHECK(message.find("wallet encryption key is unavailable for P2MR private-key persistence") != std::string::npos);
    BOOST_CHECK_EQUAL(failing_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE);
    BOOST_CHECK_EQUAL(continued_spk_man->GetKeyPoolSize(), SINGLE_ADDRESS_KEYPOOL_SIZE + 1);
}

BOOST_AUTO_TEST_CASE(DescriptorTopUpWithDBKeepsExternalBatchMemoryOnPersistenceFailure)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey master_key;
    master_key.SetSeed(GenerateRandomKey());
    TestDescriptorScriptPubKeyMan spk_man{wallet, SINGLE_ADDRESS_KEYPOOL_SIZE};
    WalletBatch setup_batch{wallet.GetDatabase()};
    BOOST_REQUIRE(spk_man.SetupDescriptorGeneration(setup_batch, master_key, OutputType::P2MR, /*internal=*/false));

    auto& database = GetMockableDatabase(wallet);
    const auto previous_spks{spk_man.GetScriptPubKeys().size()};
    const unsigned int target_size{spk_man.GetKeyPoolSize() + 1};
    database.ResetCounts();
    database.m_write_fail_after = 1;
    WalletBatch top_up_batch{wallet.GetDatabase()};

    BOOST_CHECK_THROW(
        spk_man.TopUpWithDB(top_up_batch, target_size, /*internal_hint=*/false),
        std::runtime_error);
    BOOST_CHECK_GT(database.m_write_count, 1);
    BOOST_CHECK_EQUAL(spk_man.GetScriptPubKeys().size(), previous_spks + 1);
}
BOOST_AUTO_TEST_CASE(P2MRCanGenerateMultipleAddresses)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);
    BOOST_CHECK(p2mr_spk_man->IsHDEnabled());
    BOOST_CHECK(p2mr_spk_man->CanGetAddresses(/*internal=*/false));

    std::set<CTxDestination> addrs;
    for (int i = 0; i < 4; ++i) {
        auto addr = wallet->GetNewDestination(OutputType::P2MR, "");
        BOOST_REQUIRE(addr);
        addrs.insert(*addr);
    }
    BOOST_CHECK_EQUAL(addrs.size(), 4U);
    BOOST_CHECK(p2mr_spk_man->CanGetAddresses(/*internal=*/false));

}

BOOST_AUTO_TEST_CASE(P2MRDataHashSigningRetriesLaterLeavesAfterRuntimeFailure)
{
    CPQCKey first_key;
    CPQCKey second_key;
    first_key.MakeNewKey();
    second_key.MakeNewKey();

    CPQCPubKey first_pubkey{first_key.GetPubKey()};
    CPQCPubKey second_pubkey{second_key.GetPubKey()};
    CScript first_leaf{p2mr::BuildPKScript(first_pubkey)};
    CScript second_leaf{p2mr::BuildPKScript(second_pubkey)};

    if (ToBytes(second_leaf) < ToBytes(first_leaf)) {
        std::swap(first_key, second_key);
        std::swap(first_pubkey, second_pubkey);
        std::swap(first_leaf, second_leaf);
    }

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, ToBytes(first_leaf), P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, ToBytes(second_leaf), P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    const P2MRSpendData spenddata{builder.GetP2MRSpendData()};
    const auto failing_leaf_it{spenddata.scripts.find({ToBytes(first_leaf), P2MR_LEAF_VERSION_V1})};
    BOOST_REQUIRE(failing_leaf_it != spenddata.scripts.end());
    BOOST_REQUIRE(!failing_leaf_it->second.empty());
    const std::vector<unsigned char> failing_control_block{*failing_leaf_it->second.begin()};

    RuntimeFailPQCSigningProvider signing_provider;
    AddPQCSigningKeyForTest(signing_provider.provider, first_key);
    AddPQCSigningKeyForTest(signing_provider.provider, second_key);
    signing_provider.provider.mr_trees.emplace(output, builder);
    signing_provider.failing_pubkeys.insert(first_pubkey);

    const uint256 message_hash{uint256::ONE};
    const util::Result<DataPQCSignatureProof> proof{SignP2MRDataHash(
        signing_provider, output, message_hash, std::nullopt, std::nullopt, std::nullopt)};

    BOOST_REQUIRE(proof);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[first_pubkey], 1);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[second_pubkey], 1);
    BOOST_CHECK(proof->pubkey == second_pubkey);
    BOOST_CHECK(proof->leaf_script == second_leaf);
    BOOST_CHECK_EQUAL(proof->signature.size(), PQC_SIG_SIZE);
    BOOST_CHECK(second_pubkey.Verify(proof->datasig_hash, proof->signature));

    const util::Result<DataPQCSignatureProof> explicit_failing_leaf{SignP2MRDataHash(
        signing_provider,
        output,
        message_hash,
        std::nullopt,
        std::optional<CScript>{first_leaf},
        std::optional<std::vector<unsigned char>>{failing_control_block})};
    BOOST_CHECK(!explicit_failing_leaf);
    BOOST_CHECK_EQUAL(util::ErrorString(explicit_failing_leaf).original, "PQC data-hash signing failed");
}

BOOST_FIXTURE_TEST_CASE(NonRangedP2MRDescriptorDoesNotDeriveUnrelatedPQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CPQCKey p2mr_key;
    p2mr_key.MakeNewKey();
    const CPQCPubKey p2mr_pubkey = p2mr_key.GetPubKey();

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("mr(pk(" + HexStr(std::span{p2mr_pubkey.data(), p2mr_pubkey.size()}) + "))", provider, error, /* require_checksum=*/ false);
    BOOST_REQUIRE_EQUAL(descs.size(), 1U);

    const CKey unrelated_key = GenerateRandomKey();
    provider.keys.emplace(unrelated_key.GetPubKey().GetID(), unrelated_key);

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    auto spkm = wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false);
    BOOST_REQUIRE(spkm);

    BOOST_CHECK(spkm->get().GetPQCKeys().empty());

    int pqc_plain_records{0};
    for (const auto& [serialized_key, _] : GetMockableDatabase(wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::WALLETDESCRIPTORPQCKEY) {
            ++pqc_plain_records;
        }
    }
    BOOST_CHECK_EQUAL(pqc_plain_records, 0);
}

BOOST_FIXTURE_TEST_CASE(NonRangedP2MRDescriptorDoesNotUseUnrelatedSeedKey, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey account_extkey = DecodeExtKey("qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe");
    BOOST_REQUIRE(account_extkey.key.IsValid());
    for (const uint32_t child : {87U | 0x80000000U, 1U | 0x80000000U, 0U | 0x80000000U}) {
        CExtKey derived;
        BOOST_REQUIRE(account_extkey.Derive(derived, child));
        account_extkey = derived;
    }
    const std::string account_xprv = EncodeExtKey(account_extkey);
    const std::string account_xpub = EncodeExtPubKey(account_extkey.Neuter());
    const std::string suffix{"/0/0"};

    FlatSigningProvider cache_provider;
    std::string cache_error;
    auto cache_descs = Parse("mr(pk(pqc(" + account_xprv + suffix + ")))", cache_provider, cache_error, /* require_checksum=*/ false);
    BOOST_REQUIRE_EQUAL(cache_descs.size(), 1U);

    DescriptorCache cache;
    std::vector<CScript> cache_scripts;
    FlatSigningProvider cache_out_keys;
    BOOST_REQUIRE(cache_descs.at(0)->Expand(/*pos=*/0, cache_provider, cache_scripts, cache_out_keys, &cache));

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("mr(pk(pqc(" + account_xpub + suffix + ")))", provider, error, /* require_checksum=*/ false);
    BOOST_REQUIRE_EQUAL(descs.size(), 1U);

    const CKey unrelated_key = GenerateRandomKey();
    provider.keys.emplace(unrelated_key.GetPubKey().GetID(), unrelated_key);

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    w_desc.cache = cache;
    auto spkm = wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false);
    BOOST_REQUIRE(spkm);

    BOOST_CHECK(spkm->get().GetPQCKeys().empty());

    int pqc_plain_records{0};
    for (const auto& [serialized_key, _] : GetMockableDatabase(wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::WALLETDESCRIPTORPQCKEY) {
            ++pqc_plain_records;
        }
    }
    BOOST_CHECK_EQUAL(pqc_plain_records, 0);
}

BOOST_FIXTURE_TEST_CASE(NonRangedInternalP2MRDescriptorUsesMatchingPQCKey, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet.cs_wallet);
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey account_extkey = DecodeExtKey("qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe");
    BOOST_REQUIRE(account_extkey.key.IsValid());
    for (const uint32_t child : {87U | 0x80000000U, 1U | 0x80000000U, 0U | 0x80000000U}) {
        CExtKey derived;
        BOOST_REQUIRE(account_extkey.Derive(derived, child));
        account_extkey = derived;
    }
    CExtKey leaf_extkey = account_extkey;
    for (const uint32_t child : {0U, 0U}) {
        CExtKey derived;
        BOOST_REQUIRE(leaf_extkey.Derive(derived, child));
        leaf_extkey = derived;
    }

    const std::string account_xprv = EncodeExtKey(account_extkey);
    const std::string account_xpub = EncodeExtPubKey(account_extkey.Neuter());
    const std::string suffix{"/0/0"};

    FlatSigningProvider cache_provider;
    std::string cache_error;
    auto cache_descs = Parse("mr(pk(pqc(" + account_xprv + suffix + ")))", cache_provider, cache_error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!cache_descs.empty(), cache_error);

    DescriptorCache cache;
    std::vector<CScript> scripts;
    FlatSigningProvider cache_out_keys;
    BOOST_REQUIRE(cache_descs.at(0)->Expand(/*pos=*/0, cache_provider, scripts, cache_out_keys, &cache));
    BOOST_REQUIRE_EQUAL(cache_out_keys.p2mr_pubkeys.size(), 1U);
    const CPQCPubKey expected_p2mr_pubkey = cache_out_keys.p2mr_pubkeys.begin()->second;

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("mr(pk(pqc(" + account_xpub + suffix + ")))", provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);
    provider.keys.emplace(leaf_extkey.key.GetPubKey().GetID(), leaf_extkey.key);

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    w_desc.cache = std::move(cache);
    auto spkm = wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/true);
    BOOST_REQUIRE(spkm);

    const auto pqc_keys = spkm->get().GetPQCKeys();
    BOOST_REQUIRE_EQUAL(pqc_keys.size(), 1U);
    BOOST_CHECK(pqc_keys.at(0) == expected_p2mr_pubkey);
}

BOOST_FIXTURE_TEST_CASE(InternalRangedP2MRDescriptorGetSigningProviderUsesMatchingPQCKey, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    CExtKey account_extkey = DecodeExtKey("qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe");
    BOOST_REQUIRE(account_extkey.key.IsValid());
    for (const uint32_t child : {87U | 0x80000000U, 1U | 0x80000000U, 0U | 0x80000000U}) {
        CExtKey derived;
        BOOST_REQUIRE(account_extkey.Derive(derived, child));
        account_extkey = derived;
    }

    const std::string internal_range_desc{"mr(pk(pqc(" + EncodeExtPubKey(account_extkey.Neuter()) + "/1/*)))"};

    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse(internal_range_desc, provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);

    FlatSigningProvider private_provider;
    private_provider.keys.emplace(account_extkey.key.GetPubKey().GetID(), account_extkey.key);

    std::vector<CScript> scripts;
    FlatSigningProvider cache_out_keys;
    DescriptorCache cache;
    BOOST_REQUIRE(descs.at(0)->Expand(/*pos=*/0, private_provider, scripts, cache_out_keys, &cache));
    BOOST_REQUIRE_EQUAL(cache_out_keys.p2mr_pubkeys.size(), 1U);

    CExtKey internal_leaf_extkey = account_extkey;
    CExtKey derived;
    BOOST_REQUIRE(internal_leaf_extkey.Derive(derived, /*nChild=*/1));
    internal_leaf_extkey = derived;
    BOOST_REQUIRE(internal_leaf_extkey.Derive(derived, /*nChild=*/0));
    internal_leaf_extkey = derived;

    CPQCKey expected_internal_p2mr_key;
    BOOST_REQUIRE(DerivePQCKey(internal_leaf_extkey.key, /*account=*/0, /*change=*/1, /*index=*/0, expected_internal_p2mr_key));
    const auto key_exp_pos = cache_out_keys.p2mr_pubkeys.begin()->first;
    cache.CacheDerivedP2MRPubKey(key_exp_pos, /*der_index=*/0, expected_internal_p2mr_key.GetPubKey());

    WalletDescriptor w_desc(std::move(descs.at(0)), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
    w_desc.cache = std::move(cache);

    DescriptorScriptPubKeyMan* spkm{nullptr};
    {
        LOCK(wallet.cs_wallet);
        spkm = &Assert(wallet.AddWalletDescriptor(w_desc, private_provider, "", /*internal=*/true)).value().get();
    }
    BOOST_REQUIRE(spkm);

    CPubKey descriptor_pubkey;
    {
        LOCK(spkm->cs_desc_man);
        const WalletDescriptor& wallet_descriptor = spkm->GetWalletDescriptor();
        std::vector<CScript> cached_scripts;
        FlatSigningProvider cached_out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, cached_scripts, cached_out_keys));
        BOOST_REQUIRE_EQUAL(cached_out_keys.pubkeys.size(), 1U);
        descriptor_pubkey = cached_out_keys.pubkeys.begin()->second;
    }

    auto signing_provider = spkm->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(signing_provider);

    CPQCKey got_internal_p2mr_key;
    BOOST_REQUIRE(signing_provider->GetPQCKey(expected_internal_p2mr_key.GetPubKey(), got_internal_p2mr_key));
    BOOST_CHECK(got_internal_p2mr_key.GetPubKey() == expected_internal_p2mr_key.GetPubKey());
}

BOOST_AUTO_TEST_CASE(ChangeTypeFallbackUsesP2MROnP2MROnlyChain)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, CHANGE_FALLBACK_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);

        auto* bech32m_internal = wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true);
        BOOST_REQUIRE(bech32m_internal);
        wallet->DeactivateScriptPubKeyMan(bech32m_internal->GetID(), OutputType::BECH32M, /*internal=*/true);

        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        wallet->m_default_address_type = OutputType::BECH32;

        const CRecipient recipient{
            WitnessV0ScriptHash(CScript{} << OP_TRUE),
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };
        const OutputType change_type = wallet->TransactionChangeType(std::nullopt, {recipient});
        BOOST_CHECK_EQUAL(change_type, OutputType::P2MR);
    }

}

BOOST_AUTO_TEST_CASE(ChangeTypeFallbackUsesDefaultP2MRWhenAvailable)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, CHANGE_FALLBACK_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);

        auto* bech32m_internal = wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true);
        BOOST_REQUIRE(bech32m_internal);
        wallet->DeactivateScriptPubKeyMan(bech32m_internal->GetID(), OutputType::BECH32M, /*internal=*/true);

        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
        wallet->m_default_address_type = OutputType::P2MR;

        const CRecipient recipient{
            WitnessV0ScriptHash(CScript{} << OP_TRUE),
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };
        const OutputType change_type = wallet->TransactionChangeType(std::nullopt, {recipient});
        BOOST_CHECK_EQUAL(change_type, OutputType::P2MR);
    }

}

BOOST_AUTO_TEST_CASE(ChangeTypeRecipientMatchUsesP2MROnP2MROnlyChain)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, CHANGE_FALLBACK_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);

        auto* bech32m_internal = wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true);
        BOOST_REQUIRE(bech32m_internal);
        wallet->DeactivateScriptPubKeyMan(bech32m_internal->GetID(), OutputType::BECH32M, /*internal=*/true);

        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
        BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));

        const CRecipient p2mr_recipient{
            WitnessV2P2MR{},
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };
        const CRecipient wpkh_recipient{
            WitnessV0KeyHash(GenerateRandomKey().GetPubKey()),
            /*nAmount=*/1,
            /*fSubtractFeeFromAmount=*/false,
        };

        const OutputType change_type = wallet->TransactionChangeType(std::nullopt, {p2mr_recipient, wpkh_recipient});
        BOOST_CHECK_EQUAL(change_type, OutputType::P2MR);
    }

}

BOOST_AUTO_TEST_CASE(P2MRKeysAreEncryptedAtRest)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    {
        LOCK(wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetPQCKeys().empty());
    }

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsLocked());

    {
        LOCK(wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetPQCKeys().empty());
    }

    int pqc_plain_records{0};
    int pqc_crypted_records{0};
    int pqc_authenticated_crypted_records{0};
    for (const auto& [serialized_key, serialized_value] : GetMockableDatabase(*wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type == DBKeys::WALLETDESCRIPTORPQCKEY) {
            ++pqc_plain_records;
        } else if (record_type == DBKeys::WALLETDESCRIPTORPQCCKEY) {
            ++pqc_crypted_records;

            DataStream value_stream{serialized_value};
            std::vector<unsigned char> crypted_secret;
            uint32_t sig_counter{0};
            uint256 auth_tag;
            value_stream >> crypted_secret;
            BOOST_REQUIRE(!value_stream.eof());
            value_stream >> sig_counter;
            BOOST_REQUIRE(!value_stream.eof());
            value_stream >> auth_tag;
            BOOST_CHECK(value_stream.eof());
            ++pqc_authenticated_crypted_records;
        }
    }

    BOOST_CHECK_EQUAL(pqc_plain_records, 0);
    BOOST_CHECK_GT(pqc_crypted_records, 0);
    BOOST_CHECK_EQUAL(pqc_authenticated_crypted_records, pqc_crypted_records);

}

BOOST_AUTO_TEST_CASE(P2MREncryptedPQCAuthTagRejectsCiphertextTamper)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsLocked());

    MockableData records = GetMockableDatabase(*wallet).m_records;

    bool mutated_pqc_record{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> crypted_secret;
        uint32_t sig_counter{0};
        uint256 auth_tag;
        value_stream >> crypted_secret;
        BOOST_REQUIRE(!crypted_secret.empty());
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> auth_tag;
        BOOST_REQUIRE(value_stream.eof());

        crypted_secret.front() ^= 0x01;

        DataStream new_value;
        new_value << crypted_secret;
        new_value << sig_counter;
        new_value << auth_tag;
        serialized_value = SerializeData{new_value.begin(), new_value.end()};
        mutated_pqc_record = true;
        break;
    }
    BOOST_REQUIRE(mutated_pqc_record);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);

    bool unlocked{false};
    bool threw{false};
    try {
        unlocked = loaded_wallet->Unlock(passphrase);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    BOOST_CHECK(threw || !unlocked);
}

BOOST_AUTO_TEST_CASE(P2MRLegacyEncryptedPQCRecordsUpgradeOnUnlock)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsLocked());

    MockableData records = GetMockableDatabase(*wallet).m_records;

    int stripped_pqc_records{0};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> crypted_secret;
        uint32_t sig_counter{0};
        uint256 auth_tag;
        value_stream >> crypted_secret;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> auth_tag;
        BOOST_REQUIRE(value_stream.eof());

        DataStream legacy_value;
        legacy_value << crypted_secret;
        legacy_value << sig_counter;
        serialized_value = SerializeData{legacy_value.begin(), legacy_value.end()};
        ++stripped_pqc_records;
    }
    BOOST_REQUIRE_GT(stripped_pqc_records, 0);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);
    BOOST_REQUIRE(loaded_wallet->Unlock(passphrase));

    int upgraded_pqc_records{0};
    for (const auto& [serialized_key, serialized_value] : GetMockableDatabase(*loaded_wallet).m_records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> crypted_secret;
        uint32_t sig_counter{0};
        uint256 auth_tag;
        value_stream >> crypted_secret;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> auth_tag;
        BOOST_CHECK(value_stream.eof());
        ++upgraded_pqc_records;
    }
    BOOST_CHECK_EQUAL(upgraded_pqc_records, stripped_pqc_records);
}

BOOST_AUTO_TEST_CASE(P2MRPlaintextPQCRecordsRequireValidationBeforePrivateUse)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);

    PQCKeyValidationInfo info{loaded_wallet->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::PENDING);
    BOOST_CHECK_GT(info.pending_records, 0U);
    BOOST_CHECK_EQUAL(info.failed_records, 0U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(info.encryption_recommended);
    BOOST_CHECK(!loaded_wallet->IsPQCKeyValidationReadyForPrivateKeyUse());
    BOOST_CHECK(!loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        const auto pqc_keys{p2mr_spk_man->GetPQCKeys()};
        BOOST_REQUIRE(!pqc_keys.empty());
        const auto pending_key{p2mr_spk_man->GetNextPendingPlaintextPQCKey()};
        BOOST_REQUIRE(pending_key);
        BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(pending_key->first));
    }

    while (true) {
        const auto step_result{loaded_wallet->RunPlaintextPQCKeyValidationStep()};
        if (step_result == CWallet::PlaintextPQCKeyValidationStepResult::COMPLETE) break;
        BOOST_REQUIRE(step_result == CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS);
    }

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.pending_records, 0U);
    BOOST_CHECK_EQUAL(info.failed_records, 0U);
    BOOST_CHECK_GT(info.validated_records, 0U);
    BOOST_CHECK(!info.signing_blocked);
    BOOST_CHECK(info.encryption_recommended);
    BOOST_CHECK(loaded_wallet->IsPQCKeyValidationReadyForPrivateKeyUse());

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetPQCKeys().empty());
    }

    BOOST_REQUIRE(loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));
    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::NOT_REQUIRED);
    BOOST_CHECK_EQUAL(info.plaintext_records, 0U);
    BOOST_CHECK(!info.encryption_recommended);
}

BOOST_FIXTURE_TEST_CASE(PendingPlaintextPQCValidationCompletesWithOtherCryptedPQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    DescriptorScriptPubKeyMan spk_man{wallet, SINGLE_ADDRESS_KEYPOOL_SIZE};

    CPQCKey plaintext_key;
    plaintext_key.MakeNewKey();
    BOOST_REQUIRE(plaintext_key.IsValid());
    const CPQCPubKey plaintext_pubkey{plaintext_key.GetPubKey()};
    const CKeyingMaterial plaintext_secret{plaintext_key.data(), plaintext_key.data() + plaintext_key.size()};

    CPQCKey crypted_key;
    crypted_key.MakeNewKey();
    BOOST_REQUIRE(crypted_key.IsValid());
    const CPQCPubKey crypted_pubkey{crypted_key.GetPubKey()};
    BOOST_REQUIRE(!(plaintext_pubkey == crypted_pubkey));

    BOOST_REQUIRE(spk_man.AddPendingPlaintextPQCKey(plaintext_pubkey, plaintext_secret, /*sig_counter=*/7));
    BOOST_REQUIRE(spk_man.AddCryptedPQCKey(crypted_pubkey, {0x00}, /*sig_counter=*/3));
    BOOST_CHECK_EQUAL(spk_man.GetPQCKeys().size(), 2U);

    PQCKeyValidationInfo info{spk_man.GetPQCKeyValidationInfo()};
    BOOST_CHECK_EQUAL(info.pending_records, 1U);
    BOOST_CHECK(info.signing_blocked);

    BOOST_REQUIRE(spk_man.CompletePendingPlaintextPQCKeyValidation(plaintext_pubkey, plaintext_key, /*sig_counter=*/7));

    info = spk_man.GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.pending_records, 0U);
    BOOST_CHECK_EQUAL(info.failed_records, 0U);
    BOOST_CHECK_EQUAL(info.validated_records, 1U);
    BOOST_CHECK(!info.signing_blocked);

    const auto pqc_keys{spk_man.GetPQCKeys()};
    BOOST_CHECK_EQUAL(pqc_keys.size(), 2U);
}

BOOST_AUTO_TEST_CASE(CryptedPQCSigningProviderIgnoresFailedStalePlaintextKey)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->Unlock(passphrase));

    auto initial_provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(initial_provider);
    BOOST_REQUIRE_EQUAL(initial_provider->pqc_keys.count(pubkeys.pqc_pubkey), 1U);
    const CPQCKey crypted_private_key{initial_provider->pqc_keys.at(pubkeys.pqc_pubkey)};
    const auto counter_it{initial_provider->pqc_sig_counters.find(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(counter_it != initial_provider->pqc_sig_counters.end());
    const uint32_t crypted_sig_counter{counter_it->second};

    const CKeyingMaterial duplicate_secret{crypted_private_key.data(), crypted_private_key.data() + crypted_private_key.size()};
    BOOST_REQUIRE(p2mr_spk_man->AddPendingPlaintextPQCKey(pubkeys.pqc_pubkey, duplicate_secret, crypted_sig_counter));
    BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey));

    auto blocked_descriptor_provider{p2mr_spk_man->GetSigningProvider(pubkeys.descriptor_pubkey)};
    BOOST_REQUIRE(blocked_descriptor_provider);
    BOOST_CHECK_EQUAL(blocked_descriptor_provider->pqc_keys.count(pubkeys.pqc_pubkey), 0U);

    BOOST_REQUIRE(p2mr_spk_man->CompletePendingPlaintextPQCKeyValidation(pubkeys.pqc_pubkey, crypted_private_key, crypted_sig_counter));

    CPQCKey stale_key;
    stale_key.MakeNewKey();
    BOOST_REQUIRE(stale_key.IsValid());
    const CPQCPubKey stale_pubkey{stale_key.GetPubKey()};
    BOOST_REQUIRE(!(stale_pubkey == pubkeys.pqc_pubkey));
    const CKeyingMaterial stale_secret{stale_key.data(), stale_key.data() + stale_key.size()};
    BOOST_REQUIRE(p2mr_spk_man->AddPendingPlaintextPQCKey(stale_pubkey, stale_secret, /*sig_counter=*/0));
    BOOST_REQUIRE(p2mr_spk_man->FailPendingPlaintextPQCKeyValidation(stale_pubkey));

    const PQCKeyValidationInfo info{p2mr_spk_man->GetPQCKeyValidationInfo()};
    BOOST_CHECK_EQUAL(info.failed_records, 1U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(!info.encryption_recommended);

    auto descriptor_provider{p2mr_spk_man->GetSigningProvider(pubkeys.descriptor_pubkey)};
    BOOST_REQUIRE(descriptor_provider);
    BOOST_CHECK_EQUAL(descriptor_provider->pqc_keys.count(pubkeys.pqc_pubkey), 1U);

    auto pqc_provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(pqc_provider);
    BOOST_CHECK_EQUAL(pqc_provider->pqc_keys.count(pubkeys.pqc_pubkey), 1U);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(pqc_provider->pqc_counter_reserver(pubkeys.pqc_pubkey, /*count=*/1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, 1U);
}

BOOST_AUTO_TEST_CASE(MixedCryptedAndValidatedPlaintextPQCKeysRemainUnlockable)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->Unlock(passphrase));

    CPQCKey plaintext_key;
    plaintext_key.MakeNewKey();
    BOOST_REQUIRE(plaintext_key.IsValid());
    const CPQCPubKey plaintext_pubkey{plaintext_key.GetPubKey()};
    const CKeyingMaterial plaintext_secret{plaintext_key.data(), plaintext_key.data() + plaintext_key.size()};

    BOOST_REQUIRE(p2mr_spk_man->AddPendingPlaintextPQCKey(plaintext_pubkey, plaintext_secret, /*sig_counter=*/7));
    BOOST_REQUIRE(p2mr_spk_man->CompletePendingPlaintextPQCKeyValidation(plaintext_pubkey, plaintext_key, /*sig_counter=*/7));

    const PQCKeyValidationInfo info{p2mr_spk_man->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.validated_records, 1U);
    BOOST_CHECK(!info.signing_blocked);

    CScript p2mr_script;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        p2mr_script = scripts.at(0);
    }
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, p2mr_script);
    std::map<COutPoint, Coin> coins;
    coins.emplace(COutPoint{funding_tx.GetHash(), 0}, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    BOOST_REQUIRE(wallet->Lock());
    BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(plaintext_pubkey));
    auto locked_tx_provider = p2mr_spk_man->GetSigningProviderForTransaction(coins);
    BOOST_REQUIRE(locked_tx_provider);
    CPQCKey provider_key;
    BOOST_CHECK(!locked_tx_provider->GetPQCKey(plaintext_pubkey, provider_key));

    BOOST_REQUIRE(wallet->Unlock(passphrase));
    BOOST_CHECK(p2mr_spk_man->GetSigningProvider(plaintext_pubkey));
    auto unlocked_tx_provider = p2mr_spk_man->GetSigningProviderForTransaction(coins);
    BOOST_REQUIRE(unlocked_tx_provider);
    BOOST_CHECK(unlocked_tx_provider->GetPQCKey(plaintext_pubkey, provider_key));
}

BOOST_AUTO_TEST_CASE(P2MRWalletLoadRejectsTrustedRecordPubkeyTailMismatch)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

    bool mutated_pqc_record{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCKEY) continue;

        uint256 desc_id;
        CPQCPubKey pubkey;
        key_stream >> desc_id;
        key_stream >> pubkey;
        BOOST_REQUIRE(pubkey.IsValid());

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> secret;
        uint256 stored_hash;
        uint32_t sig_counter{0};
        value_stream >> secret;
        value_stream >> stored_hash;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE_EQUAL(secret.size(), CPQCKey::SIZE);

        secret.back() ^= 0x01;
        std::vector<unsigned char> to_hash;
        to_hash.reserve(pubkey.size() + secret.size() + sizeof(sig_counter));
        to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
        to_hash.insert(to_hash.end(), secret.begin(), secret.end());
        std::array<unsigned char, sizeof(sig_counter)> counter_bytes{};
        WriteLE32(counter_bytes.data(), sig_counter);
        to_hash.insert(to_hash.end(), counter_bytes.begin(), counter_bytes.end());

        DataStream new_value;
        new_value << secret;
        new_value << Hash(to_hash);
        new_value << sig_counter;
        serialized_value = SerializeData{new_value.begin(), new_value.end()};
        mutated_pqc_record = true;
        break;
    }
    BOOST_REQUIRE(mutated_pqc_record);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_CHECK(!loaded_wallet);
    BOOST_CHECK(error.original.find("Wallet corrupted") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(P2MRWalletLoadDefersTrustedRecordBodyTamperToValidation)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

    CPQCPubKey mutated_pubkey;
    bool mutated_pqc_record{false};
    for (auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        if (record_type != DBKeys::WALLETDESCRIPTORPQCKEY) continue;

        uint256 desc_id;
        CPQCPubKey pubkey;
        key_stream >> desc_id;
        key_stream >> pubkey;
        BOOST_REQUIRE(pubkey.IsValid());

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> secret;
        uint256 stored_hash;
        uint32_t sig_counter{0};
        value_stream >> secret;
        value_stream >> stored_hash;
        BOOST_REQUIRE(!value_stream.eof());
        value_stream >> sig_counter;
        BOOST_REQUIRE_EQUAL(secret.size(), CPQCKey::SIZE);

        secret.front() ^= 0x01;
        std::vector<unsigned char> to_hash;
        to_hash.reserve(pubkey.size() + secret.size() + sizeof(sig_counter));
        to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
        to_hash.insert(to_hash.end(), secret.begin(), secret.end());
        std::array<unsigned char, sizeof(sig_counter)> counter_bytes{};
        WriteLE32(counter_bytes.data(), sig_counter);
        to_hash.insert(to_hash.end(), counter_bytes.begin(), counter_bytes.end());

        DataStream new_value;
        new_value << secret;
        new_value << Hash(to_hash);
        new_value << sig_counter;
        serialized_value = SerializeData{new_value.begin(), new_value.end()};
        mutated_pubkey = pubkey;
        mutated_pqc_record = true;
        break;
    }
    BOOST_REQUIRE(mutated_pqc_record);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);

    PQCKeyValidationInfo info{loaded_wallet->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::PENDING);
    BOOST_CHECK_GT(info.pending_records, 0U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(info.encryption_recommended);
    BOOST_CHECK(!loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(mutated_pubkey));
    }

    CWallet::PlaintextPQCKeyValidationStepResult step_result{CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS};
    const size_t max_steps{info.pending_records};
    for (size_t i{0}; i < max_steps && step_result != CWallet::PlaintextPQCKeyValidationStepResult::FAILED; ++i) {
        step_result = loaded_wallet->RunPlaintextPQCKeyValidationStep();
    }
    BOOST_REQUIRE(step_result == CWallet::PlaintextPQCKeyValidationStepResult::FAILED);

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::FAILED);
    BOOST_CHECK_GT(info.failed_records, 0U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(!info.encryption_recommended);
    BOOST_CHECK(!loaded_wallet->IsPQCKeyValidationReadyForPrivateKeyUse());
    BOOST_CHECK(!loaded_wallet->EncryptWallet(SecureString{"test-passphrase"}));

    {
        LOCK(loaded_wallet->cs_wallet);
        auto* p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        BOOST_REQUIRE(p2mr_spk_man);
        BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(mutated_pubkey));
    }
}

BOOST_AUTO_TEST_CASE(P2MRPlaintextPQCValidationContinuesAfterFailure)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);
    MockableData records = GetMockableDatabase(*wallet).m_records;

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();

    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto loaded_wallet = CWallet::Create(
        context,
        "",
        std::make_unique<MockableDatabase>(records),
        WALLET_FLAG_DESCRIPTORS,
        error,
        warnings);
    BOOST_REQUIRE(loaded_wallet);

    PQCKeyValidationInfo info{loaded_wallet->GetPQCKeyValidationInfo()};
    BOOST_REQUIRE_GT(info.pending_records, 2U);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(loaded_wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(loaded_wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);
    const auto failed_pending_key{p2mr_spk_man->GetNextPendingPlaintextPQCKey()};
    BOOST_REQUIRE(failed_pending_key);
    BOOST_REQUIRE(p2mr_spk_man->FailPendingPlaintextPQCKeyValidation(failed_pending_key->first));

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_REQUIRE_EQUAL(info.failed_records, 1U);
    BOOST_REQUIRE_GT(info.pending_records, 1U);

    const auto step_result{loaded_wallet->RunPlaintextPQCKeyValidationStep()};
    BOOST_CHECK(step_result == CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS);

    info = loaded_wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK_EQUAL(info.failed_records, 1U);
    BOOST_CHECK_GT(info.pending_records, 0U);
    BOOST_CHECK(info.signing_blocked);
}

BOOST_FIXTURE_TEST_CASE(CachedP2MRDescriptorsPersistPQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.m_keypool_size = 1;
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    const std::string desc_str{
        "mr(pk(pqc(qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe/87h/1h/0h/0/*)))"};

    FlatSigningProvider provider;
    std::string error;
    auto parsed_descs = Parse(desc_str, provider, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!parsed_descs.empty(), error);

    DescriptorCache cache;
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts;
    BOOST_REQUIRE(parsed_descs.at(0)->Expand(/*pos=*/0, provider, scripts, out_keys, &cache));
    BOOST_REQUIRE_EQUAL(out_keys.pqc_keys.size(), 1U);

    WalletDescriptor w_desc(std::move(parsed_descs.at(0)), /*creation_time=*/1, /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    w_desc.cache = std::move(cache);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        p2mr_spk_man = &Assert(wallet.AddWalletDescriptor(w_desc, provider, "", /*internal=*/false)).value().get();
    }

    BOOST_REQUIRE(p2mr_spk_man);
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        BOOST_CHECK_EQUAL(p2mr_spk_man->GetWalletDescriptor().range_end, 1);
    }
    BOOST_CHECK_EQUAL(p2mr_spk_man->GetPQCKeys().size(), 1U);
}

BOOST_AUTO_TEST_CASE(P2MRWalletCanSignSingleInputSpend)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    CPubKey descriptor_pubkey;
    CScript p2mr_script;
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
        p2mr_script = scripts.at(0);
        descriptor_pubkey = out_keys.pubkeys.begin()->second;
    }

    auto provider = p2mr_spk_man->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_CHECK_EQUAL(provider->mr_trees.size(), 1U);
    BOOST_CHECK_EQUAL(provider->pqc_keys.size(), 1U);

    std::vector<std::vector<unsigned char>> solutions;
    BOOST_REQUIRE_EQUAL(Solver(p2mr_script, solutions), TxoutType::WITNESS_V2_P2MR);
    const WitnessV2P2MR output{std::span<const unsigned char>{solutions.at(0)}};
    P2MRSpendData spenddata;
    BOOST_REQUIRE(provider->GetP2MRSpendData(output, spenddata));
    BOOST_CHECK_EQUAL(spenddata.scripts.size(), 1U);

    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, p2mr_script);

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend_tx.vin.at(0).prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    const auto format_errors = [&input_errors]() {
        std::string message;
        for (const auto& [input_index, error] : input_errors) {
            if (!message.empty()) message += "; ";
            message += strprintf("input %d: %s", input_index, error.original);
        }
        return message;
    };

    bool signed_ok{false};
    {
        LOCK(wallet->cs_wallet);
        signed_ok = wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors);
    }
    BOOST_REQUIRE_MESSAGE(signed_ok, format_errors());
    BOOST_CHECK_MESSAGE(input_errors.empty(), format_errors());
    BOOST_CHECK(!spend_tx.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(P2MRWalletCanSignManyInputSpend)
{
    static constexpr size_t INPUT_COUNT{3};

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<int, bilingual_str> input_errors;
    const auto format_errors = [&input_errors]() {
        std::string message;
        for (const auto& [input_index, error] : input_errors) {
            if (!message.empty()) message += "; ";
            message += strprintf("input %d: %s", input_index, error.original);
        }
        return message;
    };

    size_t pqc_signature_count{0};
    bool signed_ok{false};
    {
        LOCK(wallet->cs_wallet);
        signed_ok = wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors, [&](const CPQCPubKey&, uint32_t, uint32_t) {
            ++pqc_signature_count;
        });
    }
    BOOST_REQUIRE_MESSAGE(signed_ok, format_errors());
    BOOST_CHECK_MESSAGE(input_errors.empty(), format_errors());
    BOOST_CHECK_EQUAL(pqc_signature_count, INPUT_COUNT);
    for (const CTxIn& input : spend_tx.vin) {
        BOOST_CHECK(!input.scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelSignsManyInputSpend)
{
    static constexpr size_t INPUT_COUNT{10};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, INPUT_COUNT);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    std::vector<CachedP2MRPubKeys> pubkeys;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }
    for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
        pubkeys.push_back(GetCachedP2MRPubKeys(*p2mr_spk_man, pos));
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.back().descriptor_pubkey, pubkeys.back().pqc_pubkey), 0U);
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    std::vector<SigningProgress> progress_events;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        },
        [&](const SigningProgress& progress) {
            progress_events.push_back(progress);
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK(std::get<0>(observed_ranges.at(input_index)) == pubkeys.at(input_index).pqc_pubkey);
        BOOST_CHECK_EQUAL(std::get<1>(observed_ranges.at(input_index)), 0U);
        BOOST_CHECK_EQUAL(std::get<2>(observed_ranges.at(input_index)), 1U);
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.at(input_index).descriptor_pubkey, pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }

    bool saw_reservation{false};
    bool saw_signing_complete{false};
    bool saw_finalizing_complete{false};
    unsigned int previous_signing_completed{0};
    for (const SigningProgress& progress : progress_events) {
        if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS) {
            saw_reservation = true;
            BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
            BOOST_CHECK(progress.completed <= progress.total);
        } else if (progress.phase == SigningProgressPhase::SIGNING_INPUTS) {
            BOOST_CHECK(progress.completed >= previous_signing_completed);
            BOOST_CHECK(progress.completed <= progress.total);
            previous_signing_completed = progress.completed;
            saw_signing_complete |= progress.completed == INPUT_COUNT;
        } else if (progress.phase == SigningProgressPhase::FINALIZING_TRANSACTION) {
            saw_finalizing_complete |= progress.completed == INPUT_COUNT;
        }
    }
    BOOST_CHECK(saw_reservation);
    BOOST_CHECK(saw_signing_complete);
    BOOST_CHECK(saw_finalizing_complete);
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelDefaultArgsUseAutoWorkers)
{
    static constexpr size_t INPUT_COUNT{3};

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    std::vector<SigningProgress> progress_events;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        },
        [&](const SigningProgress& progress) {
            progress_events.push_back(progress);
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK(std::get<0>(observed_ranges.at(input_index)) == workload.pubkeys.at(input_index).pqc_pubkey);
        BOOST_CHECK_EQUAL(std::get<1>(observed_ranges.at(input_index)), 0U);
        BOOST_CHECK_EQUAL(std::get<2>(observed_ranges.at(input_index)), 1U);
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }

    bool saw_reservation_complete{false};
    bool saw_signing_complete{false};
    for (const SigningProgress& progress : progress_events) {
        if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS) {
            BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
            saw_reservation_complete |= progress.completed == INPUT_COUNT;
        } else if (progress.phase == SigningProgressPhase::SIGNING_INPUTS) {
            BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
            saw_signing_complete |= progress.completed == INPUT_COUNT;
        }
    }
    BOOST_CHECK(saw_reservation_complete);
    BOOST_CHECK(saw_signing_complete);
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelIgnoresCancelAfterCounterReservation)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    std::vector<CachedP2MRPubKeys> pubkeys;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }
    for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
        pubkeys.push_back(GetCachedP2MRPubKeys(*p2mr_spk_man, pos));
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.back().descriptor_pubkey, pubkeys.back().pqc_pubkey), 0U);
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    bool reject_progress{false};
    bool saw_rejected_callback{false};
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors,
        {},
        [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && progress.completed == progress.total) {
                reject_progress = true;
            }
            if (reject_progress) {
                saw_rejected_callback = true;
                return false;
            }
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK(saw_rejected_callback);
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.at(input_index).descriptor_pubkey, pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletSerialIgnoresCancelAfterPQCSigning)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "0");

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};

    bool reject_progress{false};
    bool saw_non_cancellable_progress{false};
    unsigned int rejected_callbacks{0};
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        {},
        [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::SIGNING_INPUTS && progress.completed > 0) {
                reject_progress = true;
            }
            if (reject_progress) {
                saw_non_cancellable_progress |= !progress.cancellable;
                ++rejected_callbacks;
                return false;
            }
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK(saw_non_cancellable_progress);
    BOOST_CHECK_GT(rejected_callbacks, 0U);
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelSkipsCompleteInputs)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE_MESSAGE(workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors), FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    input_errors[0] = Untranslated("stale input 0 error");
    input_errors[1] = Untranslated("stale input 1 error");
    BOOST_REQUIRE_MESSAGE(workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        }), FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_CHECK(observed_ranges.empty());
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelReusesQueuedDuplicateKeySignature)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey{key.GetPubKey()};
    const CScript leaf_script{P2MRMultiAScript(/*threshold=*/2, {pubkey, pubkey})};
    const std::vector<unsigned char> leaf_script_bytes{ToBytes(leaf_script)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script_bytes, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);
    provider.mr_trees.emplace(output, builder);

    uint32_t next_counter{0};
    std::vector<uint32_t> reserved_counts;
    provider.pqc_counter_batch_reserver = [&](const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>& ranges) {
        BOOST_REQUIRE_EQUAL(counts.size(), 1U);
        const auto count_it{counts.find(pubkey)};
        BOOST_REQUIRE(count_it != counts.end());
        reserved_counts.push_back(count_it->second);
        ranges.emplace(pubkey, PQCSignatureCounterRange{
            .pubkey = pubkey,
            .previous_counter = next_counter,
            .reserved_counter = next_counter + count_it->second,
        });
        next_counter += count_it->second;
        return true;
    };

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    provider.pqc_counter_observer = [&](const CPQCPubKey& observed_pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
        observed_ranges.emplace_back(observed_pubkey, previous_counter, reserved_counter);
    };

    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, GetScriptForDestination(output));

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend_tx.vin.at(0).prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE_MESSAGE(SignTransaction(spend_tx, &provider, coins, SIGHASH_DEFAULT, input_errors), FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(reserved_counts.size(), 1U);
    BOOST_CHECK_EQUAL(reserved_counts.front(), 1U);
    BOOST_CHECK_EQUAL(next_counter, 1U);
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), 1U);
    BOOST_CHECK(std::get<0>(observed_ranges.front()) == pubkey);
    BOOST_CHECK_EQUAL(std::get<1>(observed_ranges.front()), 0U);
    BOOST_CHECK_EQUAL(std::get<2>(observed_ranges.front()), 1U);
    BOOST_CHECK(!spend_tx.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelFailsWhenBatchReservationFails)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    CPQCKey first_key;
    CPQCKey second_key;
    first_key.MakeNewKey();
    second_key.MakeNewKey();
    const CPQCPubKey first_pubkey{first_key.GetPubKey()};
    const CPQCPubKey second_pubkey{second_key.GetPubKey()};
    const CScript leaf_script{P2MRMultiAScript(/*threshold=*/1, {first_pubkey, second_pubkey})};
    const std::vector<unsigned char> leaf_script_bytes{ToBytes(leaf_script)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script_bytes, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(first_pubkey, first_key);
    provider.pqc_keys.emplace(second_pubkey, second_key);
    provider.mr_trees.emplace(output, builder);

    bool batch_attempted{false};
    provider.pqc_counter_batch_reserver = [&](const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>&) {
        batch_attempted = true;
        BOOST_REQUIRE_EQUAL(counts.size(), 1U);
        const auto count_it{counts.find(second_pubkey)};
        BOOST_REQUIRE(count_it != counts.end());
        BOOST_CHECK_EQUAL(count_it->second, 1U);
        return false;
    };

    std::vector<CPQCPubKey> serial_reservation_attempts;
    provider.pqc_counter_reserver = [&](const CPQCPubKey& pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        BOOST_CHECK_EQUAL(count, 1U);
        serial_reservation_attempts.push_back(pubkey);
        if (pubkey == second_pubkey) return false;
        BOOST_CHECK(pubkey == first_pubkey);
        previous_counter = 0;
        reserved_counter = 1;
        return true;
    };

    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, GetScriptForDestination(output));

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend_tx.vin.at(0).prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(spend_tx, &provider, coins, SIGHASH_DEFAULT, input_errors));
    BOOST_CHECK(batch_attempted);
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1U);
    BOOST_CHECK_EQUAL(input_errors.at(0).original, "PQC signature counter reservation failed");
    BOOST_CHECK(serial_reservation_attempts.empty());
    BOOST_CHECK(spend_tx.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelAutoThreadsAssignsSharedKeyCounters)
{
    static constexpr size_t INPUT_COUNT{10};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "0");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    CScript p2mr_script;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        p2mr_script = scripts.at(0);
    }
    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), 0U);

    CMutableTransaction funding_tx;
    for (size_t i{0}; i < INPUT_COUNT; ++i) {
        funding_tx.vout.emplace_back(1 * COIN, p2mr_script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            BOOST_CHECK(pubkey == pubkeys.pqc_pubkey);
            observed_ranges.emplace_back(previous_counter, reserved_counter);
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK(observed_ranges.at(input_index) == std::make_pair(static_cast<uint32_t>(input_index), static_cast<uint32_t>(input_index + 1)));
        BOOST_CHECK(!spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), INPUT_COUNT);
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelFailsExhaustedBatchWithoutBurningCounter)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    CScript p2mr_script;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        p2mr_script = scripts.at(0);
    }
    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};

    auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);

    CMutableTransaction funding_tx;
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        funding_tx.vout.emplace_back(1 * COIN, p2mr_script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors));
    BOOST_CHECK(!input_errors.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);
    for (const CTxIn& input : spend_tx.vin) {
        BOOST_CHECK(input.scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelSerialParallelABBenchmark)
{
    static constexpr size_t INPUT_COUNT{10};

    const auto sign_workload = [](P2MRSigningWorkload& workload) {
        std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
        std::map<int, bilingual_str> input_errors;
        const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
            [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
                observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
            })};

        BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
        BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
        BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
        for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
            BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
            BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        }
    };

    m_node.args->ForceSetArg("-walletpqcparallel", "0");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "0");
    auto serial_workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};
    const auto serial_start{std::chrono::steady_clock::now()};
    sign_workload(serial_workload);
    const auto serial_elapsed_us{std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - serial_start).count()};

    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "0");
    auto parallel_workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};
    const auto parallel_start{std::chrono::steady_clock::now()};
    sign_workload(parallel_workload);
    const auto parallel_elapsed_us{std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - parallel_start).count()};

    BOOST_TEST_MESSAGE(strprintf(
        "P2MR wallet signing A/B input_count=%u serial_us=%d parallel_auto_us=%d",
        static_cast<unsigned int>(INPUT_COUNT),
        serial_elapsed_us,
        parallel_elapsed_us));
}

BOOST_AUTO_TEST_CASE(P2MRBatchPQCReservationAdvancesCounterRange)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    const auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver);

    std::map<CPQCPubKey, uint32_t> counts{{pubkeys.pqc_pubkey, 3}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver(counts, ranges));

    BOOST_REQUIRE_EQUAL(ranges.size(), 1U);
    const auto& range{ranges.at(pubkeys.pqc_pubkey)};
    BOOST_CHECK(range.pubkey == pubkeys.pqc_pubkey);
    BOOST_CHECK_EQUAL(range.previous_counter, 0U);
    BOOST_CHECK_EQUAL(range.reserved_counter, 3U);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), 3U);
}

BOOST_AUTO_TEST_CASE(P2MRBatchPQCReservationRejectsNearLimitWithoutAdvancing)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);

    provider = p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver);

    std::map<CPQCPubKey, uint32_t> counts{{pubkeys.pqc_pubkey, 2}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    BOOST_CHECK(!provider->pqc_counter_batch_reserver(counts, ranges));
    BOOST_CHECK(ranges.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);
}

BOOST_AUTO_TEST_CASE(P2MRBatchPQCReservationRejectsMultipleKeysAtomically)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys first_pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    const CachedP2MRPubKeys second_pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/1)};
    BOOST_REQUIRE(!(first_pubkeys.pqc_pubkey == second_pubkeys.pqc_pubkey));

    auto provider{p2mr_spk_man->GetSigningProvider(first_pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(first_pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);

    provider = p2mr_spk_man->GetSigningProvider(first_pubkeys.pqc_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_REQUIRE(provider->pqc_counter_batch_reserver);

    std::map<CPQCPubKey, uint32_t> counts{{first_pubkeys.pqc_pubkey, 2}, {second_pubkeys.pqc_pubkey, 1}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    BOOST_CHECK(!provider->pqc_counter_batch_reserver(counts, ranges));
    BOOST_CHECK(ranges.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, first_pubkeys.descriptor_pubkey, first_pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, second_pubkeys.descriptor_pubkey, second_pubkeys.pqc_pubkey), 0U);
}

BOOST_FIXTURE_TEST_CASE(GetSigningProviderSkipsUndecryptablePQCKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const std::string desc_str{
        "mr(pk(pqc(qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe/87h/1h/0h/0/0)))"};

    DescriptorScriptPubKeyMan* p2mr_spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(p2mr_spk_man);

    CPubKey descriptor_pubkey;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
        descriptor_pubkey = out_keys.pubkeys.begin()->second;
    }

    const SecureString passphrase{"test-passphrase"};
    // This test only needs the descriptor under test to be encrypted. Avoid
    // unrelated replacement descriptor setup, which is expensive under MSan.
    wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    CPQCKey bogus_pqc_key;
    bogus_pqc_key.MakeNewKey();
    BOOST_REQUIRE(p2mr_spk_man->AddCryptedPQCKey(bogus_pqc_key.GetPubKey(), {0x00}));

    auto provider = p2mr_spk_man->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_CHECK_EQUAL(provider->pqc_keys.count(bogus_pqc_key.GetPubKey()), 0U);
    for (const auto& [_, key] : provider->pqc_keys) {
        BOOST_CHECK(key.IsValid());
    }
}

BOOST_FIXTURE_TEST_CASE(GetSigningProviderSkipsUndecryptableECDSAKeys, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    const std::string desc_str{
        "mr(pk(pqc(qprvYYfRPs43ZezRHV2Fi78WJfTBwdRACukt3egGGXq9z2sVzi51wUYEr1CDfiPnxtZRa5ZJRkMWqDSVgTAwyZ73G9FopkTcMmLh9UExP6efUpe/87h/1h/0h/0/0)))"};

    DescriptorScriptPubKeyMan* p2mr_spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(p2mr_spk_man);

    CPubKey descriptor_pubkey;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(out_keys.pubkeys.size(), 1U);
        descriptor_pubkey = out_keys.pubkeys.begin()->second;
    }

    const SecureString passphrase{"test-passphrase"};
    // This test only needs the descriptor under test to be encrypted. Avoid
    // unrelated replacement descriptor setup, which is expensive under MSan.
    wallet.SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    const CKey bogus_key = GenerateRandomKey();
    BOOST_REQUIRE(p2mr_spk_man->AddCryptedKey(bogus_key.GetPubKey().GetID(), bogus_key.GetPubKey(), {0x00}));

    auto provider = p2mr_spk_man->GetSigningProvider(descriptor_pubkey);
    BOOST_REQUIRE(provider);
    BOOST_CHECK_EQUAL(provider->keys.count(descriptor_pubkey.GetID()), 1U);
    BOOST_CHECK_EQUAL(provider->keys.count(bogus_key.GetPubKey().GetID()), 0U);
    for (const auto& [_, key] : provider->keys) {
        BOOST_CHECK(key.IsValid());
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
