// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_WALLET_TEST_WALLET_P2MR_TEST_UTIL_H
#define QBIT_WALLET_TEST_WALLET_P2MR_TEST_UTIL_H

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


inline constexpr std::array<OutputType, 1> P2MR_ONLY_OUTPUT_TYPES{OutputType::P2MR};
inline constexpr std::array<OutputType, 1> BECH32_ONLY_OUTPUT_TYPES{OutputType::BECH32};
inline constexpr std::array<OutputType, 3> CHANGE_FALLBACK_OUTPUT_TYPES{OutputType::BECH32M, OutputType::BECH32, OutputType::P2MR};
inline constexpr int64_t SINGLE_ADDRESS_KEYPOOL_SIZE{1};
inline constexpr int64_t FOUR_ADDRESS_KEYPOOL_SIZE{4};

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

namespace wallet_p2mr_test {
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

inline void WaitForScheduler(CScheduler& scheduler)
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

inline CachedP2MRPubKeys GetCachedP2MRPubKeys(DescriptorScriptPubKeyMan& spk_man, int32_t pos)
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

inline CScript GetCachedScriptPubKey(DescriptorScriptPubKeyMan& spk_man, int32_t index)
{
    LOCK(spk_man.cs_desc_man);
    const WalletDescriptor wallet_descriptor = spk_man.GetWalletDescriptor();
    std::vector<CScript> scripts;
    FlatSigningProvider out_keys;
    Assert(wallet_descriptor.descriptor->ExpandFromCache(index, wallet_descriptor.cache, scripts, out_keys));
    assert(scripts.size() == 1);
    return scripts.at(0);
}

inline uint32_t GetProviderPQCCounter(DescriptorScriptPubKeyMan& spk_man, const CPubKey& descriptor_pubkey, const CPQCPubKey& pqc_pubkey)
{
    const auto provider{spk_man.GetSigningProvider(descriptor_pubkey)};
    BOOST_REQUIRE(provider);
    const auto counter_it{provider->pqc_sig_counters.find(pqc_pubkey)};
    BOOST_REQUIRE(counter_it != provider->pqc_sig_counters.end());
    return counter_it->second;
}

inline std::string FormatInputErrors(const std::map<int, bilingual_str>& input_errors)
{
    std::string message;
    for (const auto& [input_index, error] : input_errors) {
        if (!message.empty()) message += "; ";
        message += strprintf("input %d: %s", input_index, error.original);
    }
    return message;
}

inline std::vector<unsigned char> ToBytes(const CScript& script)
{
    return {script.begin(), script.end()};
}

inline void AddPQCSigningKeyForTest(FlatSigningProvider& provider, const CPQCKey& key)
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

inline CScript P2MRMultiAScript(int threshold, const std::vector<CPQCPubKey>& pubkeys)
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

inline P2MRSigningWorkload MakeDistinctKeyP2MRSigningWorkload(interfaces::Chain& chain, size_t input_count)
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
} // namespace wallet_p2mr_test
} // namespace wallet

#endif // QBIT_WALLET_TEST_WALLET_P2MR_TEST_UTIL_H
