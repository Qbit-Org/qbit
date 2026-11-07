// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <coins.h>
#include <consensus/validation.h>
#include <crypto/pqc.h>
#include <kernel/cs_main.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <atomic>
#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

namespace {
using valtype = std::vector<unsigned char>;

//! Epochs and iterations are fixed so every timed call checks a transaction
//! that was never checked before; reusing one would hit the full-script cache.
constexpr size_t ADMISSION_EPOCHS{5};
constexpr size_t ADMISSION_EPOCH_ITERATIONS{6};

//! Mempool admission checks standard flags first and then consensus flags. The
//! flag sets differ, so the consensus pass misses the full-script cache and
//! re-executes every input script against the same signature cache.
constexpr unsigned int POLICY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS};
constexpr unsigned int CONSENSUS_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS};

class CountingObserver final : public PQCSignatureCacheObserver
{
public:
    std::atomic<uint64_t> m_lookups{0};
    std::atomic<uint64_t> m_verifications{0};
    void Lookup(bool, bool) override { ++m_lookups; }
    void Verified(bool, bool) override { ++m_verifications; }
};

struct AdmissionPool {
    CCoinsView base;
    CCoinsViewCache coins{&base};
    std::vector<CTransactionRef> txs;
};

//! Build distinct pre-signed P2MR CHECKSIGPQC spends over prepared coins.
std::unique_ptr<AdmissionPool> BuildAdmissionPool(size_t tx_count, size_t sigs_per_tx)
{
    CPQCKey key;
    key.MakeNewKey();
    assert(key.IsValid());
    const CPQCPubKey pubkey{key.GetPubKey()};
    uint32_t signature_counter{0};

    const CScript leaf_script{CScript{} << valtype(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC};
    const valtype leaf_bytes(leaf_script.begin(), leaf_script.end());
    const valtype control_block{static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)};
    const uint256 leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_bytes)};
    const uint256 merkle_root{ComputeP2MRMerkleRoot(control_block, leaf_hash)};
    const CScript script_pubkey{CScript{} << OP_2 << valtype(merkle_root.begin(), merkle_root.end())};

    constexpr CAmount COIN_VALUE{100'000};
    CMutableTransaction credit;
    credit.version = 2;
    credit.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    credit.vout.assign(tx_count * sigs_per_tx, CTxOut{COIN_VALUE, script_pubkey});
    const CTransaction credit_tx{credit};

    auto pool{std::make_unique<AdmissionPool>()};
    AddCoins(pool->coins, credit_tx, /*nHeight=*/1);

    for (size_t t{0}; t < tx_count; ++t) {
        CMutableTransaction spend;
        spend.version = 2;
        std::vector<CTxOut> spent_outputs;
        for (size_t i{0}; i < sigs_per_tx; ++i) {
            const uint32_t n{static_cast<uint32_t>(t * sigs_per_tx + i)};
            spend.vin.emplace_back(COutPoint{credit_tx.GetHash(), n});
            spend.vin.back().scriptWitness.stack = {valtype(PQC_SIG_SIZE, 0x00), leaf_bytes, control_block};
            spent_outputs.push_back(credit_tx.vout[n]);
        }
        spend.vout.emplace_back(COIN_VALUE * static_cast<CAmount>(sigs_per_tx) - 10'000, script_pubkey);

        PrecomputedTransactionData txdata;
        txdata.Init(spend, std::move(spent_outputs));
        for (uint32_t i{0}; i < spend.vin.size(); ++i) {
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            execdata.m_tapleaf_hash = leaf_hash;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
            execdata.m_codeseparator_pos_init = true;
            uint256 sighash;
            assert(SignatureHashP2MR(sighash, execdata, spend, i, SIGHASH_DEFAULT, txdata, MissingDataBehavior::ASSERT_FAIL));
            valtype sig;
            assert(key.Sign(sighash, sig, signature_counter));
            spend.vin[i].scriptWitness.stack[0] = std::move(sig);
        }
        pool->txs.push_back(MakeTransactionRef(std::move(spend)));
    }
    return pool;
}

/**
 * Time the two-pass mempool admission script-check pattern for fresh
 * transactions against one long-lived validation cache with default sizes.
 * Signing and pool construction happen before timing.
 */
void RunAdmission(benchmark::Bench& bench, size_t sigs_per_tx, bool attach_observer)
{
    // Sanity-check runs force a single epoch with a single iteration.
    const bool sanity_check{bench.epochIterations() == 1};
    const size_t epochs{sanity_check ? 1 : ADMISSION_EPOCHS};
    const size_t iterations{sanity_check ? 1 : ADMISSION_EPOCH_ITERATIONS};

    const auto testing_setup{MakeNoLogFileContext<const BasicTestingSetup>()};
    const auto pool{BuildAdmissionPool(epochs * iterations, sigs_per_tx)};
    ValidationCache validation_cache{DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES, DEFAULT_SIGNATURE_CACHE_BYTES};
    CountingObserver observer;
    if (attach_observer) validation_cache.m_signature_cache.SetPQCObserverForTesting(&observer);

    size_t next{0};
    bench.epochs(epochs).epochIterations(iterations).unit("tx").run([&] {
        assert(next < pool->txs.size());
        const CTransaction& tx{*pool->txs[next++]};
        TxValidationState state;
        PrecomputedTransactionData txdata;
        LOCK(cs_main);
        const bool policy_ok{CheckInputScripts(tx, state, pool->coins, POLICY_FLAGS,
                                               /*cacheSigStore=*/true, /*cacheFullScriptStore=*/false,
                                               txdata, validation_cache, /*pvChecks=*/nullptr)};
        const bool consensus_ok{CheckInputScripts(tx, state, pool->coins, CONSENSUS_FLAGS,
                                                  /*cacheSigStore=*/true, /*cacheFullScriptStore=*/true,
                                                  txdata, validation_cache, /*pvChecks=*/nullptr)};
        assert(policy_ok && consensus_ok);
    });

    validation_cache.m_signature_cache.SetPQCObserverForTesting(nullptr);
}
} // namespace

static void CheckInputsP2MRPQCAdmission1Sig(benchmark::Bench& bench)
{
    RunAdmission(bench, /*sigs_per_tx=*/1, /*attach_observer=*/false);
}

static void CheckInputsP2MRPQCAdmission5Sig(benchmark::Bench& bench)
{
    RunAdmission(bench, /*sigs_per_tx=*/5, /*attach_observer=*/false);
}

//! Measures the test-only observer cost; not comparable with a baseline build.
static void CheckInputsP2MRPQCAdmission1SigObserved(benchmark::Bench& bench)
{
    RunAdmission(bench, /*sigs_per_tx=*/1, /*attach_observer=*/true);
}

BENCHMARK(CheckInputsP2MRPQCAdmission1Sig, benchmark::PriorityLevel::HIGH);
BENCHMARK(CheckInputsP2MRPQCAdmission5Sig, benchmark::PriorityLevel::HIGH);
BENCHMARK(CheckInputsP2MRPQCAdmission1SigObserved, benchmark::PriorityLevel::LOW);
