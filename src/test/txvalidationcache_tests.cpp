// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <crypto/pqc.h>
#include <key.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <utility>
#include <vector>

struct Dersig100Setup : public TestChain100Setup {
    Dersig100Setup()
        : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-p2mronly=0", "-testactivationheight=dersig@1002"}}} {}
};

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

struct P2MRPQCAdmissionSetup : public TestChain100Setup {
    P2MRPQCAdmissionSetup()
        : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-p2mronly=1"}}} {}
};

namespace {
enum class PQCCacheEventType { LOOKUP_HIT, LOOKUP_MISS, VERIFIED_OK, VERIFIED_FAIL };

struct PQCCacheEvent {
    PQCCacheEventType type;
    //! The erase flag for lookups, the inserted flag for verifications.
    bool flag;
    friend bool operator==(const PQCCacheEvent&, const PQCCacheEvent&) = default;
};

PQCCacheEvent PQCHit(bool erase) { return {PQCCacheEventType::LOOKUP_HIT, erase}; }
PQCCacheEvent PQCMiss(bool erase) { return {PQCCacheEventType::LOOKUP_MISS, erase}; }
PQCCacheEvent PQCVerifiedOk(bool inserted) { return {PQCCacheEventType::VERIFIED_OK, inserted}; }

/**
 * Render an admission event log. ATMP runs PolicyScriptChecks before
 * ConsensusScriptChecks, each checking every input once in order, and a
 * full-script cache hit emits no events. The pass label is therefore derived
 * from event order: the first input_count lookups (with the verifications that
 * follow them) belong to the policy pass, later ones to the consensus pass.
 */
std::string PQCEventsToString(const std::vector<PQCCacheEvent>& events, size_t input_count)
{
    std::string out;
    size_t lookups{0};
    for (const PQCCacheEvent& event : events) {
        const bool lookup{event.type == PQCCacheEventType::LOOKUP_HIT || event.type == PQCCacheEventType::LOOKUP_MISS};
        if (lookup) ++lookups;
        const std::string pass{lookups <= input_count ? "policy" : "consensus"};
        if (!out.empty()) out += ", ";
        switch (event.type) {
        case PQCCacheEventType::LOOKUP_HIT: out += strprintf("%s:HIT(erase=%d)", pass, event.flag); break;
        case PQCCacheEventType::LOOKUP_MISS: out += strprintf("%s:MISS(erase=%d)", pass, event.flag); break;
        case PQCCacheEventType::VERIFIED_OK: out += strprintf("%s:VERIFIED_OK(inserted=%d)", pass, event.flag); break;
        case PQCCacheEventType::VERIFIED_FAIL: out += strprintf("%s:VERIFIED_FAIL(inserted=%d)", pass, event.flag); break;
        }
    }
    return "[" + out + "]";
}

class RecordingPQCObserver final : public PQCSignatureCacheObserver
{
    Mutex m_mutex;
    std::vector<PQCCacheEvent> m_events GUARDED_BY(m_mutex);

public:
    void Lookup(bool hit, bool erase) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_events.push_back(hit ? PQCHit(erase) : PQCMiss(erase));
    }
    void Verified(bool valid, bool inserted) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_events.push_back({valid ? PQCCacheEventType::VERIFIED_OK : PQCCacheEventType::VERIFIED_FAIL, inserted});
    }
    std::vector<PQCCacheEvent> Take() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return std::exchange(m_events, {});
    }
};

//! Attach an observer for one scope; the cache has none attached outside it.
class ScopedPQCObserver
{
    SignatureCache& m_cache;

public:
    ScopedPQCObserver(SignatureCache& cache, PQCSignatureCacheObserver& observer) : m_cache{cache}
    {
        BOOST_REQUIRE(m_cache.GetPQCObserver() == nullptr);
        m_cache.SetPQCObserverForTesting(&observer);
    }
    ~ScopedPQCObserver() { m_cache.SetPQCObserverForTesting(nullptr); }
};
} // namespace

BOOST_AUTO_TEST_SUITE(txvalidationcache_tests)

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, Dersig100Setup)
{
    // Make sure skipping validation of transactions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    const auto ToMemPool = [this](const CMutableTransaction& tx) {
        LOCK(cs_main);

        const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        return result.m_result_type == MempoolAcceptResult::ResultType::VALID;
    };

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].version = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout.hash = m_coinbase_txns[0]->GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11*CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[0]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[1]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Final sanity test: first spend in *m_node.mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    }
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

// Run CheckInputScripts (using CoinsTip()) on the given transaction, for all script
// flags.  Test that CheckInputScripts passes for all flags that don't overlap with
// the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if
// the script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
// Capture this interaction with the upgraded_nop argument: set it when evaluating
// any script flag that is implemented as an upgraded NOP code.
static void ValidateCheckInputsForAllFlags(const CTransaction &tx, uint32_t failing_flags, bool add_to_cache, CCoinsViewCache& active_coins_tip, ValidationCache& validation_cache) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    PrecomputedTransactionData txdata;

    FastRandomContext insecure_rand(true);

    for (int count = 0; count < 10000; ++count) {
        TxValidationState state;

        // Randomly selects flag combinations
        uint32_t test_flags = (uint32_t) insecure_rand.randrange((SCRIPT_VERIFY_END_MARKER - 1) << 1);

        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH and WITNESS, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        }
        if ((test_flags & SCRIPT_VERIFY_WITNESS)) {
            // WITNESS requires P2SH
            test_flags |= SCRIPT_VERIFY_P2SH;
        }
        bool ret = CheckInputScripts(tx, state, &active_coins_tip, test_flags, true, add_to_cache, txdata, validation_cache, nullptr);
        // CheckInputScripts should succeed iff test_flags doesn't intersect with
        // failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        BOOST_CHECK_EQUAL(ret, expected_return_value);

        // Test the caching
        if (ret && add_to_cache) {
            // Check that we get a cache hit if the tx was valid
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputScripts(tx, state, &active_coins_tip, test_flags, true, add_to_cache, txdata, validation_cache, &scriptchecks));
            BOOST_CHECK(scriptchecks.empty());
        } else {
            // Check that we get script executions to check, if the transaction
            // was invalid, or we didn't add to cache.
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputScripts(tx, state, &active_coins_tip, test_flags, true, add_to_cache, txdata, validation_cache, &scriptchecks));
            BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, Dersig100Setup)
{
    // Test that passing CheckInputScripts with one set of script flags doesn't imply
    // that we would pass again with a different set of flags.
    CScript p2pk_scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey = GetScriptForDestination(ScriptHash(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CScript p2wpkh_scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(coinbaseKey));
    BOOST_CHECK(keystore.AddCScript(p2pk_scriptPubKey));

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY, SCRIPT_VERIFY_NULLDUMMY, uncompressed pubkey thing

    // Create 2 outputs that match the three scripts above, spending the first
    // coinbase tx.
    CMutableTransaction spend_tx;

    spend_tx.version = 1;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout.hash = m_coinbase_txns[0]->GetHash();
    spend_tx.vin[0].prevout.n = 0;
    spend_tx.vout.resize(4);
    spend_tx.vout[0].nValue = 11*CENT;
    spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
    spend_tx.vout[1].nValue = 11*CENT;
    spend_tx.vout[1].scriptPubKey = p2wpkh_scriptPubKey;
    spend_tx.vout[2].nValue = 11*CENT;
    spend_tx.vout[2].scriptPubKey = CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[3].nValue = 11*CENT;
    spend_tx.vout[3].scriptPubKey = CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Sign, with a non-DER signature
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(p2pk_scriptPubKey, spend_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char) 0); // padding byte makes this non-DER
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend_tx.vin[0].scriptSig << vchSig;
    }

    // Test that invalidity under a set of flags doesn't preclude validity
    // under other (eg consensus) flags.
    // spend_tx is invalid according to DERSIG
    {
        LOCK(cs_main);

        TxValidationState state;
        PrecomputedTransactionData ptd_spend_tx;

        BOOST_CHECK(!CheckInputScripts(CTransaction(spend_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, true, ptd_spend_tx, m_node.chainman->m_validation_cache, nullptr));

        // If we call again asking for scriptchecks (as happens in
        // ConnectBlock), we should add a script check object for this -- we're
        // not caching invalidity (if that changes, delete this test case).
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputScripts(CTransaction(spend_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, true, ptd_spend_tx, m_node.chainman->m_validation_cache, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1U);

        // Test that CheckInputScripts returns true iff DERSIG-enforcing flags are
        // not present.  Don't add these checks to the cache, so that we can
        // test later that block validation works fine in the absence of cached
        // successes.
        ValidateCheckInputsForAllFlags(CTransaction(spend_tx), SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC, false, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // And if we produce a block with this tx, it should be valid (DERSIG not
    // enabled yet), even though there's no cache entry.
    CBlock block;

    block = CreateAndProcessBlock({spend_tx}, p2pk_scriptPubKey);
    LOCK(cs_main);
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(m_node.chainman->ActiveChainstate().CoinsTip().GetBestBlock() == block.GetHash());

    // Test P2SH: construct a transaction that is valid without P2SH, and
    // then test validity with P2SH.
    {
        CMutableTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.version = 1;
        invalid_under_p2sh_tx.vin.resize(1);
        invalid_under_p2sh_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_under_p2sh_tx.vin[0].prevout.n = 0;
        invalid_under_p2sh_tx.vout.resize(1);
        invalid_under_p2sh_tx.vout[0].nValue = 11*CENT;
        invalid_under_p2sh_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        std::vector<unsigned char> vchSig2(p2pk_scriptPubKey.begin(), p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_under_p2sh_tx), SCRIPT_VERIFY_P2SH, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CMutableTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.version = 1;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin.resize(1);
        invalid_with_cltv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_cltv_tx.vin[0].prevout.n = 2;
        invalid_with_cltv_tx.vin[0].nSequence = 0;
        invalid_with_cltv_tx.vout.resize(1);
        invalid_with_cltv_tx.vout[0].nValue = 11*CENT;
        invalid_with_cltv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[2].scriptPubKey, invalid_with_cltv_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_with_cltv_tx), SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(CTransaction(invalid_with_cltv_tx), state, m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true, txdata, m_node.chainman->m_validation_cache, nullptr));
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CMutableTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.version = 2;
        invalid_with_csv_tx.vin.resize(1);
        invalid_with_csv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_csv_tx.vin[0].prevout.n = 3;
        invalid_with_csv_tx.vin[0].nSequence = 100;
        invalid_with_csv_tx.vout.resize(1);
        invalid_with_csv_tx.vout[0].nValue = 11*CENT;
        invalid_with_csv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[3].scriptPubKey, invalid_with_csv_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_with_csv_tx), SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(CTransaction(invalid_with_csv_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true, txdata, m_node.chainman->m_validation_cache, nullptr));
    }

    // TODO: add tests for remaining script flags

    // Test that passing CheckInputScripts with a valid witness doesn't imply success
    // for the same tx with a different witness.
    {
        CMutableTransaction valid_with_witness_tx;
        valid_with_witness_tx.version = 1;
        valid_with_witness_tx.vin.resize(1);
        valid_with_witness_tx.vin[0].prevout.hash = spend_tx.GetHash();
        valid_with_witness_tx.vin[0].prevout.n = 1;
        valid_with_witness_tx.vout.resize(1);
        valid_with_witness_tx.vout[0].nValue = 11*CENT;
        valid_with_witness_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        SignatureData sigdata;
        BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(valid_with_witness_tx, 0, 11 * CENT, SIGHASH_ALL), spend_tx.vout[1].scriptPubKey, sigdata));
        UpdateInput(valid_with_witness_tx.vin[0], sigdata);

        // This should be valid under all script flags.
        ValidateCheckInputsForAllFlags(CTransaction(valid_with_witness_tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Remove the witness, and check that it is now invalid.
        valid_with_witness_tx.vin[0].scriptWitness.SetNull();
        ValidateCheckInputsForAllFlags(CTransaction(valid_with_witness_tx), SCRIPT_VERIFY_WITNESS, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    {
        // Test a transaction with multiple inputs.
        CMutableTransaction tx;

        tx.version = 1;
        tx.vin.resize(2);
        tx.vin[0].prevout.hash = spend_tx.GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[1].prevout.hash = spend_tx.GetHash();
        tx.vin[1].prevout.n = 1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 22*CENT;
        tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        for (int i = 0; i < 2; ++i) {
            SignatureData sigdata;
            BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(tx, i, 11 * CENT, SIGHASH_ALL), spend_tx.vout[i].scriptPubKey, sigdata));
            UpdateInput(tx.vin[i], sigdata);
        }

        // This should be valid under all script flags
        ValidateCheckInputsForAllFlags(CTransaction(tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Check that if the second input is invalid, but the first input is
        // valid, the transaction is not cached.
        // Invalidate vin[1]
        tx.vin[1].scriptWitness.SetNull();

        TxValidationState state;
        PrecomputedTransactionData txdata;
        // This transaction is now invalid under segwit, because of the second input.
        BOOST_CHECK(!CheckInputScripts(CTransaction(tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, m_node.chainman->m_validation_cache, nullptr));

        std::vector<CScriptCheck> scriptchecks;
        // Make sure this transaction was not cached (ie because the first
        // input was valid)
        BOOST_CHECK(CheckInputScripts(CTransaction(tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, true, true, txdata, m_node.chainman->m_validation_cache, &scriptchecks));
        // Should get 2 script checks back -- caching is on a whole-transaction basis.
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2U);
    }
}

BOOST_FIXTURE_TEST_CASE(pqc_policy_consensus_reuse, P2MRPQCAdmissionSetup)
{
    using valtype = std::vector<unsigned char>;
    SignatureCache& signature_cache{m_node.chainman->m_validation_cache.m_signature_cache};

    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey{key.GetPubKey()};
    uint32_t signature_counter{0};

    const CScript leaf_script{CScript{} << valtype(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC};
    const valtype leaf_bytes(leaf_script.begin(), leaf_script.end());
    const valtype control_block{static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)};
    const uint256 leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_bytes)};
    const uint256 merkle_root{ComputeP2MRMerkleRoot(control_block, leaf_hash)};
    const CScript pqc_script_pubkey{CScript{} << OP_2 << valtype(merkle_root.begin(), merkle_root.end())};

    // Confirm four P2MR CHECKSIGPQC coins before any observer is attached.
    const CAmount coin_value{m_coinbase_txns[0]->vout[0].nValue / 8};
    const CMutableTransaction funding{CreateValidMempoolTransaction(
        /*input_transactions=*/{m_coinbase_txns[0]},
        /*inputs=*/{COutPoint{m_coinbase_txns[0]->GetHash(), 0}},
        /*input_height=*/COINBASE_MATURITY,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/std::vector<CTxOut>(4, CTxOut{coin_value, pqc_script_pubkey}),
        /*submit=*/false)};
    CreateAndProcessBlock({funding}, P2MROpTrueScript());
    for (uint32_t n{0}; n < funding.vout.size(); ++n) {
        BOOST_REQUIRE(WITH_LOCK(cs_main, return m_node.chainman->ActiveChainstate().CoinsTip().HaveCoin(COutPoint{funding.GetHash(), n})));
    }

    struct PQCSpend {
        CMutableTransaction tx;
        std::vector<uint256> entries;
    };
    const auto build_spend = [&](const std::vector<uint32_t>& vouts) {
        PQCSpend spend;
        spend.tx.version = 2;
        std::vector<CTxOut> spent_outputs;
        for (const uint32_t n : vouts) {
            spend.tx.vin.emplace_back(COutPoint{funding.GetHash(), n});
            spend.tx.vin.back().scriptWitness.stack = {valtype(PQC_SIG_SIZE, 0x00), leaf_bytes, control_block};
            spent_outputs.push_back(funding.vout[n]);
        }
        spend.tx.vout.emplace_back(coin_value * static_cast<CAmount>(vouts.size()) - 100'000, P2MROpTrueScript());
        PrecomputedTransactionData txdata;
        txdata.Init(spend.tx, std::move(spent_outputs));
        for (uint32_t i{0}; i < spend.tx.vin.size(); ++i) {
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            execdata.m_tapleaf_hash = leaf_hash;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
            execdata.m_codeseparator_pos_init = true;
            uint256 sighash;
            BOOST_REQUIRE(SignatureHashP2MR(sighash, execdata, spend.tx, i, SIGHASH_DEFAULT, txdata, MissingDataBehavior::ASSERT_FAIL));
            valtype sig;
            BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
            uint256 entry;
            signature_cache.ComputeEntryPQC(entry, sighash, sig, pubkey);
            spend.entries.push_back(entry);
            spend.tx.vin[i].scriptWitness.stack[0] = std::move(sig);
        }
        return spend;
    };
    const auto require_cold = [&](const PQCSpend& spend) {
        for (const uint256& entry : spend.entries) {
            BOOST_REQUIRE(!signature_cache.Get(entry, /*erase=*/false));
        }
    };
    const auto admit = [&](const CMutableTransaction& tx, bool test_accept, std::vector<PQCCacheEvent>& events) {
        RecordingPQCObserver observer;
        MempoolAcceptResult result{[&] {
            ScopedPQCObserver scoped{signature_cache, observer};
            MempoolAcceptResult inner{WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(MakeTransactionRef(tx), test_accept))};
            BOOST_REQUIRE(signature_cache.GetPQCObserver() == &observer);
            return inner;
        }()};
        events = observer.Take();
        return result;
    };
    const auto in_mempool = [&](const CMutableTransaction& tx) {
        return WITH_LOCK(m_node.mempool->cs, return m_node.mempool->exists(tx.GetHash()));
    };
    std::vector<PQCCacheEvent> events;

    // Fresh one-signature admission: one primitive verification in the policy
    // pass, reused by the consensus pass.
    const PQCSpend one{build_spend({0})};
    require_cold(one);
    const MempoolAcceptResult result_one{admit(one.tx, /*test_accept=*/false, events)};
    BOOST_TEST_MESSAGE("N=1 fresh admission: " << PQCEventsToString(events, 1));
    BOOST_CHECK_MESSAGE(result_one.m_result_type == MempoolAcceptResult::ResultType::VALID, result_one.m_state.ToString());
    BOOST_CHECK(events == (std::vector{PQCMiss(false), PQCVerifiedOk(true), PQCHit(false)}));
    BOOST_CHECK(in_mempool(one.tx));
    BOOST_CHECK(signature_cache.Get(one.entries[0], /*erase=*/false));

    // Fresh two-signature admission: two primitive verifications instead of four.
    const PQCSpend two{build_spend({1, 2})};
    require_cold(two);
    const MempoolAcceptResult result_two{admit(two.tx, /*test_accept=*/false, events)};
    BOOST_TEST_MESSAGE("N=2 fresh admission: " << PQCEventsToString(events, 2));
    BOOST_CHECK_MESSAGE(result_two.m_result_type == MempoolAcceptResult::ResultType::VALID, result_two.m_state.ToString());
    BOOST_CHECK(events == (std::vector{PQCMiss(false), PQCVerifiedOk(true), PQCMiss(false), PQCVerifiedOk(true), PQCHit(false), PQCHit(false)}));
    BOOST_CHECK(in_mempool(two.tx));

    // test_accept still runs both passes on a fresh transaction.
    const PQCSpend probe{build_spend({3})};
    require_cold(probe);
    const MempoolAcceptResult result_probe{admit(probe.tx, /*test_accept=*/true, events)};
    BOOST_TEST_MESSAGE("N=1 fresh test_accept: " << PQCEventsToString(events, 1));
    BOOST_CHECK_MESSAGE(result_probe.m_result_type == MempoolAcceptResult::ResultType::VALID, result_probe.m_state.ToString());
    BOOST_CHECK(events == (std::vector{PQCMiss(false), PQCVerifiedOk(true), PQCHit(false)}));
    BOOST_CHECK(!in_mempool(probe.tx));

    // Repeating test_accept re-executes the policy pass, which hits the
    // signature cache; the consensus pass is a full-script cache hit and emits
    // no events. A lone hit is not policy-to-consensus reuse evidence.
    const MempoolAcceptResult result_repeat{admit(probe.tx, /*test_accept=*/true, events)};
    BOOST_TEST_MESSAGE("N=1 repeated test_accept: " << PQCEventsToString(events, 1));
    BOOST_CHECK_MESSAGE(result_repeat.m_result_type == MempoolAcceptResult::ResultType::VALID, result_repeat.m_state.ToString());
    BOOST_CHECK(events == (std::vector{PQCHit(false)}));

    // Resubmitting a transaction already in the mempool is rejected before
    // script checks: a valid zero, not reuse evidence.
    const MempoolAcceptResult result_duplicate{admit(one.tx, /*test_accept=*/false, events)};
    BOOST_TEST_MESSAGE("N=1 duplicate submission: " << PQCEventsToString(events, 1) << " reject=" << result_duplicate.m_state.GetRejectReason());
    BOOST_CHECK(result_duplicate.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(result_duplicate.m_state.GetRejectReason(), "txn-already-in-mempool");
    BOOST_CHECK(events.empty());
}

BOOST_AUTO_TEST_SUITE_END()
