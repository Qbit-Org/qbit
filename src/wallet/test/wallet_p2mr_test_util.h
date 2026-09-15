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
#include <mutex>
#include <optional>
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

enum class MixedInputOwner {
    EXTERNAL,
    INTERNAL,
    UNOWNED,
};

//! Alternates external and internal inputs, starting with the requested manager.
inline std::vector<MixedInputOwner> InterleavedMixedInputs(size_t external_count, size_t internal_count, bool external_first)
{
    std::vector<MixedInputOwner> owners;
    for (size_t i{0}; i < std::max(external_count, internal_count); ++i) {
        const bool has_external{i < external_count};
        const bool has_internal{i < internal_count};
        if (external_first && has_external) owners.push_back(MixedInputOwner::EXTERNAL);
        if (has_internal) owners.push_back(MixedInputOwner::INTERNAL);
        if (!external_first && has_external) owners.push_back(MixedInputOwner::EXTERNAL);
    }
    return owners;
}

using PQCRecordKey = std::pair<uint256, CPQCPubKey>;

struct MixedManagerP2MRWorkload {
    std::unique_ptr<CWallet> wallet;
    DescriptorScriptPubKeyMan* external_spk_man{nullptr};
    DescriptorScriptPubKeyMan* internal_spk_man{nullptr};
    std::vector<MixedInputOwner> owners;
    //! Per input; empty for unowned inputs.
    std::vector<std::optional<CachedP2MRPubKeys>> pubkeys;
    CPQCKey unowned_key;
    TaprootBuilder unowned_builder;
    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;

    DescriptorScriptPubKeyMan& SpkMan(MixedInputOwner owner) const
    {
        assert(owner != MixedInputOwner::UNOWNED);
        return owner == MixedInputOwner::EXTERNAL ? *external_spk_man : *internal_spk_man;
    }

    uint256 DescId(MixedInputOwner owner) const { return SpkMan(owner).GetID(); }

    std::vector<unsigned int> InputsOwnedBy(MixedInputOwner owner) const
    {
        std::vector<unsigned int> inputs;
        for (unsigned int i{0}; i < owners.size(); ++i) {
            if (owners[i] == owner) inputs.push_back(i);
        }
        return inputs;
    }

    MixedInputOwner OwnerOf(const uint256& desc_id) const
    {
        if (desc_id == DescId(MixedInputOwner::EXTERNAL)) return MixedInputOwner::EXTERNAL;
        if (desc_id == DescId(MixedInputOwner::INTERNAL)) return MixedInputOwner::INTERNAL;
        return MixedInputOwner::UNOWNED;
    }

    PQCRecordKey RecordKey(unsigned int input_index) const
    {
        return {DescId(owners.at(input_index)), pubkeys.at(input_index)->pqc_pubkey};
    }
};

//! Builds one wallet whose external and internal P2MR managers each own the
//! inputs named by `owners`, in that order. Unowned inputs share one P2MR
//! output whose key the wallet never sees. Every input has a distinct amount.
inline MixedManagerP2MRWorkload MakeMixedManagerP2MRSigningWorkload(interfaces::Chain& chain, std::vector<MixedInputOwner> owners, size_t output_count = 1)
{
    const auto count_owner = [&](MixedInputOwner owner) {
        return static_cast<int64_t>(std::count(owners.begin(), owners.end(), owner));
    };
    const int64_t keypool_size{std::max<int64_t>({1, count_owner(MixedInputOwner::EXTERNAL), count_owner(MixedInputOwner::INTERNAL)})};

    MixedManagerP2MRWorkload workload;
    workload.wallet = CreateDescriptorWallet(chain, P2MR_ONLY_OUTPUT_TYPES, keypool_size);
    {
        LOCK(workload.wallet->cs_wallet);
        workload.external_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(workload.wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
        workload.internal_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(workload.wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    }
    BOOST_REQUIRE(workload.external_spk_man);
    BOOST_REQUIRE(workload.internal_spk_man);
    BOOST_REQUIRE(workload.external_spk_man->GetID() != workload.internal_spk_man->GetID());

    CScript unowned_script;
    if (count_owner(MixedInputOwner::UNOWNED) > 0) {
        workload.unowned_key.MakeNewKey();
        const CScript leaf_script{P2MRMultiAScript(/*threshold=*/1, {workload.unowned_key.GetPubKey()})};
        workload.unowned_builder.AddP2MR(/*depth=*/0, ToBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
        unowned_script = GetScriptForDestination(workload.unowned_builder.GetP2MROutput());
    }

    CMutableTransaction funding_tx;
    int32_t next_external_pos{0};
    int32_t next_internal_pos{0};
    CAmount total{0};
    for (size_t i{0}; i < owners.size(); ++i) {
        const CAmount amount{1 * COIN + static_cast<CAmount>(i) * 1'000};
        total += amount;
        if (owners[i] == MixedInputOwner::UNOWNED) {
            workload.pubkeys.emplace_back();
            funding_tx.vout.emplace_back(amount, unowned_script);
            continue;
        }
        const bool external{owners[i] == MixedInputOwner::EXTERNAL};
        const int32_t pos{external ? next_external_pos++ : next_internal_pos++};
        DescriptorScriptPubKeyMan& spk_man{external ? *workload.external_spk_man : *workload.internal_spk_man};
        workload.pubkeys.emplace_back(GetCachedP2MRPubKeys(spk_man, pos));
        funding_tx.vout.emplace_back(amount, GetCachedScriptPubKey(spk_man, pos));
    }

    const auto funding_txid{funding_tx.GetHash()};
    for (size_t i{0}; i < owners.size(); ++i) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(i)};
        workload.spend_tx.vin.emplace_back(prevout);
        workload.coins.emplace(prevout, Coin{funding_tx.vout.at(i), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    const CAmount output_amount{(total - 10'000) / static_cast<CAmount>(output_count)};
    for (size_t i{0}; i < output_count; ++i) {
        workload.spend_tx.vout.emplace_back(output_amount, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));
    }
    workload.owners = std::move(owners);
    return workload;
}

//! A signer for the workload's unowned output, backed by an in-memory counter.
inline FlatSigningProvider MakeUnownedP2MRSigningProvider(const MixedManagerP2MRWorkload& workload, uint32_t& next_counter)
{
    FlatSigningProvider provider;
    TaprootBuilder builder{workload.unowned_builder};
    provider.pqc_keys.emplace(workload.unowned_key.GetPubKey(), workload.unowned_key);
    provider.mr_trees.emplace(builder.GetP2MROutput(), builder);
    provider.pqc_counter_batch_reserver = [&next_counter](const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>& ranges) {
        for (const auto& [pubkey, count] : counts) {
            ranges.emplace(pubkey, PQCSignatureCounterRange{
                .pubkey = pubkey,
                .previous_counter = next_counter,
                .reserved_counter = next_counter + count,
            });
            next_counter += count;
        }
        return true;
    };
    return provider;
}

//! Decodes the signature counter of every descriptor PQC key record, plaintext or encrypted.
inline std::map<PQCRecordKey, uint32_t> ReadDurablePQCCounters(const MockableData& records)
{
    std::map<PQCRecordKey, uint32_t> counters;
    for (const auto& [serialized_key, serialized_value] : records) {
        DataStream key_stream{serialized_key};
        std::string record_type;
        key_stream >> record_type;
        const bool plaintext{record_type == DBKeys::WALLETDESCRIPTORPQCKEY};
        if (!plaintext && record_type != DBKeys::WALLETDESCRIPTORPQCCKEY) continue;

        uint256 desc_id;
        CPQCPubKey pubkey;
        key_stream >> desc_id >> pubkey;

        DataStream value_stream{serialized_value};
        std::vector<unsigned char> secret;
        uint32_t sig_counter{0};
        value_stream >> secret;
        if (plaintext) {
            uint256 hash;
            value_stream >> hash;
        }
        if (!value_stream.eof()) value_stream >> sig_counter;
        counters[{desc_id, pubkey}] = sig_counter;
    }
    return counters;
}

struct DurableCommit {
    uint64_t sequence{0};
    bool success{false};
    //! PQC key records this commit wrote, as [previous, reserved) counter ranges.
    std::map<PQCRecordKey, std::pair<uint32_t, uint32_t>> ranges;

    std::set<uint256> DescIds() const
    {
        std::set<uint256> desc_ids;
        for (const auto& [key, _] : ranges) desc_ids.insert(key.first);
        return desc_ids;
    }
};

struct ObservedCounterRange {
    CPQCPubKey pubkey;
    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    //! Recorder sequence at observation time; later commits have larger sequences.
    uint64_t sequence{0};
};

struct ObservedSigningCall {
    CPQCPubKey pubkey;
    uint32_t counter{0};
    uint64_t started{0};
    uint64_t finished{0};
    std::optional<bool> success;
};

//! Observes what the mock wallet database durably committed. A successful
//! commit's ranges are diffed against the previous successful commit; a failed
//! commit's ranges are the writes that its abort discards.
class DurableCounterRecorder : public PQCSigningObserver
{
public:
    explicit DurableCounterRecorder(CWallet& wallet, bool observe_signing = false)
        : m_database{GetMockableDatabase(wallet)}, m_committed{ReadDurablePQCCounters(m_database.m_records)}
    {
        if (observe_signing) m_signing_observer.emplace(*this);
        m_database.ResetCounts();
        m_database.m_txn_commit_result_hook = [this](bool success) { OnCommitResult(success); };
    }

    ~DurableCounterRecorder() override
    {
        m_database.m_txn_commit_result_hook = {};
        m_database.m_txn_commit_pass = true;
    }

    DurableCounterRecorder(const DurableCounterRecorder&) = delete;
    DurableCounterRecorder& operator=(const DurableCounterRecorder&) = delete;

    //! Runs after each commit result is recorded; may flip the database's failure knobs.
    std::function<void(const DurableCommit&)> on_commit;

    MockableDatabase& Database() const { return m_database; }
    const std::vector<DurableCommit>& Commits() const { return m_commits; }

    bool ObservingSigning() const { return m_signing_observer.has_value(); }

    std::map<uint64_t, ObservedSigningCall> SigningCalls() const
    {
        std::lock_guard lock{m_observation_mutex};
        return m_signing_calls;
    }

    uint64_t BeforeSign(const CPQCPubKey& pubkey, uint32_t counter) override
    {
        std::lock_guard lock{m_observation_mutex};
        const uint64_t call{++m_sequence};
        m_signing_calls.emplace(call, ObservedSigningCall{pubkey, counter, call, 0, std::nullopt});
        return call;
    }

    void AfterSign(uint64_t call, bool success) override
    {
        std::lock_guard lock{m_observation_mutex};
        auto& observation{m_signing_calls.at(call)};
        observation.finished = ++m_sequence;
        observation.success = success;
    }

    std::vector<DurableCommit> PQCCommits(bool success) const
    {
        std::vector<DurableCommit> commits;
        for (const auto& commit : m_commits) {
            if (commit.success == success && !commit.ranges.empty()) commits.push_back(commit);
        }
        return commits;
    }

    PQCSignatureCounterObserver MakeObserver(std::vector<ObservedCounterRange>& observed) const
    {
        return [this, &observed](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            std::lock_guard lock{m_observation_mutex};
            observed.push_back({pubkey, previous_counter, reserved_counter, m_sequence});
        };
    }

    //! True when a successful commit that precedes `observation` durably covers its counters.
    bool CommittedBefore(const ObservedCounterRange& observation) const
    {
        return std::any_of(m_commits.begin(), m_commits.end(), [&](const DurableCommit& commit) {
            if (!commit.success || commit.sequence > observation.sequence) return false;
            return std::any_of(commit.ranges.begin(), commit.ranges.end(), [&](const auto& entry) {
                return entry.first.second == observation.pubkey &&
                       entry.second.first <= observation.previous_counter &&
                       observation.reserved_counter <= entry.second.second;
            });
        });
    }

    std::string Format() const
    {
        std::string out;
        for (const auto& commit : m_commits) {
            if (commit.ranges.empty() && commit.success) continue;
            out += strprintf("\n  commit seq=%u success=%d", commit.sequence, commit.success);
            for (const auto& [key, range] : commit.ranges) {
                out += strprintf(" desc=%s.. [%u,%u)", key.first.GetHex().substr(0, 12), range.first, range.second);
            }
        }
        return out;
    }

private:
    void OnCommitResult(bool success)
    {
        auto current{ReadDurablePQCCounters(m_database.m_records)};
        DurableCommit commit{.success = success};
        for (const auto& [key, counter] : current) {
            const auto committed_it{m_committed.find(key)};
            const uint32_t previous{committed_it == m_committed.end() ? 0 : committed_it->second};
            if (committed_it == m_committed.end() || previous != counter) {
                commit.ranges.emplace(key, std::make_pair(previous, counter));
            }
        }
        if (success) m_committed = std::move(current);
        {
            // Share ordering with the real signer callbacks, including a signer
            // incorrectly started before this durable commit completed.
            std::lock_guard lock{m_observation_mutex};
            commit.sequence = ++m_sequence;
            m_commits.push_back(commit);
        }
        if (on_commit) on_commit(commit);
    }

    MockableDatabase& m_database;
    std::map<PQCRecordKey, uint32_t> m_committed;
    std::vector<DurableCommit> m_commits;
    mutable std::mutex m_observation_mutex;
    uint64_t m_sequence{0};
    std::map<uint64_t, ObservedSigningCall> m_signing_calls;
    // Declared last so the observer is detached before its recorded state dies.
    std::optional<ScopedPQCSigningObserver> m_signing_observer;
};

//! Verifies every input of `signed_tx` against all real spent outputs in
//! original input order, and checks the signed transaction is still
//! `unsigned_tx`. Returns the failing inputs and their script errors.
inline std::map<unsigned int, std::string> VerifyP2MRSpend(const CMutableTransaction& unsigned_tx, const CMutableTransaction& signed_tx, const std::map<COutPoint, Coin>& coins)
{
    const CTransaction tx{signed_tx};
    BOOST_CHECK(CTransaction{unsigned_tx}.GetHash() == tx.GetHash());
    std::vector<CTxOut> spent_outputs;
    for (const CTxIn& input : tx.vin) {
        spent_outputs.push_back(coins.at(input.prevout).out);
    }
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent_outputs}, /*force=*/true);

    std::map<unsigned int, std::string> failures;
    for (unsigned int i{0}; i < tx.vin.size(); ++i) {
        ScriptError serror{SCRIPT_ERR_OK};
        if (!VerifyScript(tx.vin[i].scriptSig, spent_outputs[i].scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                TransactionSignatureChecker(&tx, i, spent_outputs[i].nValue, txdata, MissingDataBehavior::FAIL), &serror)) {
            failures.emplace(i, ScriptErrorString(serror));
        }
    }
    return failures;
}

//! Loads a copy of the wallet database and returns each owned input's persisted counter.
inline std::map<PQCRecordKey, uint32_t> ReloadPQCCounters(interfaces::Chain& chain, const MixedManagerP2MRWorkload& workload)
{
    CWallet reloaded{&chain, "", DuplicateMockDatabase(GetMockableDatabase(*workload.wallet))};
    BOOST_REQUIRE(reloaded.LoadWallet() == DBErrors::LOAD_OK);
    const auto durable{ReadDurablePQCCounters(GetMockableDatabase(reloaded).m_records)};

    std::map<PQCRecordKey, uint32_t> counters;
    for (unsigned int i{0}; i < workload.owners.size(); ++i) {
        if (workload.owners[i] == MixedInputOwner::UNOWNED) continue;
        const PQCRecordKey key{workload.RecordKey(i)};
        ScriptPubKeyMan* spk_man{nullptr};
        {
            LOCK(reloaded.cs_wallet);
            spk_man = reloaded.GetScriptPubKeyMan(key.first);
        }
        BOOST_REQUIRE(spk_man);
        // Reloaded plaintext keys stay pending until validated, so read the loaded counter directly.
        const std::optional<uint32_t> loaded_counter{spk_man->GetPQCSignatureCounter(key.second)};
        BOOST_REQUIRE(loaded_counter.has_value());
        const uint32_t counter{*loaded_counter};
        BOOST_REQUIRE(durable.contains(key));
        BOOST_CHECK_EQUAL(durable.at(key), counter);
        counters[key] = counter;
    }
    return counters;
}

struct SerialSigningOracleResult {
    bool signed_ok{false};
    std::map<int, bilingual_str> input_errors;
    CMutableTransaction tx;
    std::map<PQCRecordKey, uint32_t> durable_counters;
};

//! Signs a copy of `tx` with serial PQC signing on a clone of the wallet database.
inline SerialSigningOracleResult RunSerialSigningOracle(interfaces::Chain& chain, ArgsManager& args, CWallet& wallet, const CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash)
{
    CWallet oracle{&chain, "", DuplicateMockDatabase(GetMockableDatabase(wallet))};
    BOOST_REQUIRE(oracle.LoadWallet() == DBErrors::LOAD_OK);
    // Loaded plaintext PQC keys cannot sign until validated.
    CWallet::PlaintextPQCKeyValidationStepResult step_result;
    do {
        step_result = oracle.RunPlaintextPQCKeyValidationStep();
    } while (step_result == CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS);
    BOOST_REQUIRE(step_result == CWallet::PlaintextPQCKeyValidationStepResult::COMPLETE);

    const bool parallel{args.GetBoolArg("-walletpqcparallel", true)};
    args.ForceSetArg("-walletpqcparallel", "0");
    SerialSigningOracleResult result{.tx = tx};
    result.signed_ok = oracle.SignTransaction(result.tx, coins, sighash, result.input_errors);
    args.ForceSetArg("-walletpqcparallel", parallel ? "1" : "0");
    result.durable_counters = ReadDurablePQCCounters(GetMockableDatabase(oracle).m_records);
    return result;
}
} // namespace wallet_p2mr_test
} // namespace wallet

#endif // QBIT_WALLET_TEST_WALLET_P2MR_TEST_UTIL_H
