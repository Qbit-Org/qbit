// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqc.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <test/data/p2mr_pqc_witness_vectors.json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using valtype = std::vector<unsigned char>;

constexpr unsigned int P2MR_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_P2MR_RULES
};
constexpr unsigned int P2MR_LEGACY_WEIGHT_FLAGS{P2MR_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_P2MR_LEGACY_VALIDATION_WEIGHT};

enum class EventType { LOOKUP_HIT, LOOKUP_MISS, VERIFIED_OK, VERIFIED_FAIL };

struct Event {
    EventType type;
    //! The erase flag for lookups, the inserted flag for verifications.
    bool flag;
    friend bool operator==(const Event&, const Event&) = default;
};

Event Hit(bool erase) { return {EventType::LOOKUP_HIT, erase}; }
Event Miss(bool erase) { return {EventType::LOOKUP_MISS, erase}; }
Event Ok(bool inserted) { return {EventType::VERIFIED_OK, inserted}; }
Event Fail() { return {EventType::VERIFIED_FAIL, false}; }

std::vector<Event> Repeat(const std::vector<Event>& pattern, size_t count)
{
    std::vector<Event> out;
    for (size_t i{0}; i < count; ++i) out.insert(out.end(), pattern.begin(), pattern.end());
    return out;
}

std::string EventsToString(const std::vector<Event>& events)
{
    std::string out;
    for (const Event& event : events) {
        if (!out.empty()) out += ", ";
        switch (event.type) {
        case EventType::LOOKUP_HIT: out += strprintf("HIT(erase=%d)", event.flag); break;
        case EventType::LOOKUP_MISS: out += strprintf("MISS(erase=%d)", event.flag); break;
        case EventType::VERIFIED_OK: out += strprintf("VERIFIED_OK(inserted=%d)", event.flag); break;
        case EventType::VERIFIED_FAIL: out += strprintf("VERIFIED_FAIL(inserted=%d)", event.flag); break;
        }
    }
    return "[" + out + "]";
}

class RecordingPQCObserver final : public PQCSignatureCacheObserver
{
    Mutex m_mutex;
    std::vector<Event> m_events GUARDED_BY(m_mutex);

public:
    void Lookup(bool hit, bool erase) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_events.push_back(hit ? Hit(erase) : Miss(erase));
    }
    void Verified(bool valid, bool inserted) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_events.push_back({valid ? EventType::VERIFIED_OK : EventType::VERIFIED_FAIL, inserted});
    }
    std::vector<Event> Take() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return std::exchange(m_events, {});
    }
};

//! A signature cache with a recording observer attached for its whole lifetime.
class ObservedCache
{
public:
    SignatureCache cache;
    RecordingPQCObserver observer;

    explicit ObservedCache(size_t max_size_bytes) : cache{max_size_bytes}
    {
        cache.SetPQCObserverForTesting(&observer);
    }
    ~ObservedCache() { cache.SetPQCObserverForTesting(nullptr); }

    //! Compare and clear the recorded events. An unattached observer would
    //! record nothing, which must not be mistaken for a valid zero.
    std::vector<Event> CheckEvents(const std::vector<Event>& expected, std::string_view label)
    {
        BOOST_REQUIRE(cache.GetPQCObserver() == &observer);
        std::vector<Event> actual{observer.Take()};
        BOOST_CHECK_MESSAGE(actual == expected, label << ": expected " << EventsToString(expected) << ", got " << EventsToString(actual));
        return actual;
    }

    std::vector<Event> TakeEvents()
    {
        BOOST_REQUIRE(cache.GetPQCObserver() == &observer);
        return observer.Take();
    }
};

//! Uncached control: the base checker's primitive verification, never a zero-byte cache.
class UncachedChecker final : public TransactionSignatureChecker
{
public:
    using TransactionSignatureChecker::TransactionSignatureChecker;
    using TransactionSignatureChecker::VerifyPQCSignature;
};

struct PQCTuple {
    uint256 sighash;
    CPQCPubKey pubkey;
    valtype sig;
};

uint256 EntryPQC(const SignatureCache& cache, const PQCTuple& tuple)
{
    uint256 entry;
    cache.ComputeEntryPQC(entry, tuple.sighash, tuple.sig, tuple.pubkey);
    return entry;
}

valtype FlipFirstByte(valtype bytes)
{
    BOOST_REQUIRE(!bytes.empty());
    bytes[0] ^= 0x01;
    return bytes;
}

//! Transaction context for tuple-level checks, which do not read the transaction.
struct TupleContext {
    const CTransaction tx{CMutableTransaction{}};
    PrecomputedTransactionData txdata;

    CachingTransactionSignatureChecker Caching(SignatureCache& cache, bool store)
    {
        return CachingTransactionSignatureChecker{&tx, /*nInIn=*/0, /*amountIn=*/0, store, cache, txdata};
    }
    UncachedChecker Uncached() const
    {
        return UncachedChecker{&tx, /*nInIn=*/0, /*amountIn=*/0, txdata, MissingDataBehavior::ASSERT_FAIL};
    }
};

struct WitnessVector {
    std::string name;
    CMutableTransaction spend_tx;
    std::vector<CTxOut> spent_outputs;
    uint32_t input_index;
    CPQCPubKey pubkey;
    valtype raw_signature;
    ScriptError expected_error;
    std::optional<uint256> sighash;
};

valtype HexField(const UniValue& obj, const std::string& field)
{
    const UniValue& value{obj[field]};
    BOOST_REQUIRE_MESSAGE(value.isStr(), "missing string field " << field);
    return ParseHex(value.get_str());
}

std::vector<WitnessVector> LoadWitnessVectors()
{
    UniValue corpus;
    BOOST_REQUIRE(corpus.read(json_tests::p2mr_pqc_witness_vectors));
    const UniValue& vectors_json{corpus["vectors"]};
    BOOST_REQUIRE(vectors_json.isArray());

    std::vector<WitnessVector> vectors;
    for (const UniValue& vec : vectors_json.getValues()) {
        WitnessVector out;
        out.name = vec["name"].get_str();
        DataStream stream{HexField(vec, "spendTx")};
        stream >> TX_WITH_WITNESS(out.spend_tx);
        for (const UniValue& output : vec["spentOutputs"].getValues()) {
            const valtype script{HexField(output, "scriptPubKey")};
            out.spent_outputs.emplace_back(output["amount"].getInt<CAmount>(), CScript{script.begin(), script.end()});
        }
        out.input_index = vec["inputIndex"].getInt<uint32_t>();
        BOOST_REQUIRE_LT(out.input_index, out.spend_tx.vin.size());
        BOOST_REQUIRE_EQUAL(out.spent_outputs.size(), out.spend_tx.vin.size());
        out.pubkey = CPQCPubKey{HexField(vec, "pubkey")};
        BOOST_REQUIRE(out.pubkey.IsValid());
        out.raw_signature = HexField(vec, "signature");
        const valtype hash_type{HexField(vec, "hashType")};
        BOOST_REQUIRE_EQUAL(hash_type.size(), 1U);
        if (hash_type[0] != SIGHASH_DEFAULT) {
            BOOST_REQUIRE_EQUAL(out.raw_signature.back(), hash_type[0]);
            out.raw_signature.pop_back();
        }
        BOOST_REQUIRE_EQUAL(out.raw_signature.size(), PQC_SIG_SIZE);
        const std::string error{vec["expected"]["error"].get_str()};
        if (error == "SCRIPT_ERR_OK") {
            out.expected_error = SCRIPT_ERR_OK;
        } else {
            BOOST_REQUIRE_EQUAL(error, "SCRIPT_ERR_P2MR_SIG_HASHTYPE");
            out.expected_error = SCRIPT_ERR_P2MR_SIG_HASHTYPE;
        }
        if (vec.exists("p2mrSighash")) {
            const valtype sighash{HexField(vec, "p2mrSighash")};
            BOOST_REQUIRE_EQUAL(sighash.size(), uint256::size());
            out.sighash = uint256{std::span<const unsigned char>{sighash}};
        }
        BOOST_REQUIRE_EQUAL(out.sighash.has_value(), out.expected_error == SCRIPT_ERR_OK);
        vectors.push_back(std::move(out));
    }
    BOOST_REQUIRE_EQUAL(vectors.size(), 14U);
    return vectors;
}

const WitnessVector& FindVector(const std::vector<WitnessVector>& vectors, std::string_view name)
{
    for (const WitnessVector& vector : vectors) {
        if (vector.name == name) return vector;
    }
    BOOST_FAIL("missing vector " << name);
    return vectors.front();
}

PQCTuple AcceptedTuple(const WitnessVector& vector)
{
    BOOST_REQUIRE(vector.sighash);
    PQCTuple tuple{*vector.sighash, vector.pubkey, vector.raw_signature};
    BOOST_REQUIRE(tuple.pubkey.Verify(tuple.sighash, tuple.sig));
    return tuple;
}

std::vector<PQCTuple> AcceptedTuples(const std::vector<WitnessVector>& vectors)
{
    std::vector<PQCTuple> tuples;
    for (const WitnessVector& vector : vectors) {
        if (vector.expected_error == SCRIPT_ERR_OK) tuples.push_back(AcceptedTuple(vector));
    }
    return tuples;
}

struct ScriptOutcome {
    bool success;
    ScriptError error;
    friend bool operator==(const ScriptOutcome&, const ScriptOutcome&) = default;
};

std::string OutcomeToString(const ScriptOutcome& outcome)
{
    return strprintf("%s/%s", outcome.success ? "true" : "false", ScriptErrorString(outcome.error));
}

//! One transaction input with its precomputed data, verified via VerifyScript.
struct InputUnderTest {
    const CTransaction tx;
    uint32_t input_index;
    CTxOut spent_output;
    PrecomputedTransactionData txdata;

    InputUnderTest(const CMutableTransaction& mtx, std::vector<CTxOut> spent_outputs, uint32_t index)
        : tx{mtx}, input_index{index}, spent_output{spent_outputs.at(index)}
    {
        txdata.Init(tx, std::move(spent_outputs));
    }

    ScriptOutcome Verify(const BaseSignatureChecker& checker, unsigned int flags) const
    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool success{VerifyScript(tx.vin[input_index].scriptSig, spent_output.scriptPubKey,
                                        &tx.vin[input_index].scriptWitness, flags, checker, &err)};
        return {success, err};
    }
    ScriptOutcome VerifyUncached(unsigned int flags) const
    {
        return Verify(TransactionSignatureChecker{&tx, input_index, spent_output.nValue, txdata, MissingDataBehavior::ASSERT_FAIL}, flags);
    }
    ScriptOutcome VerifyCaching(SignatureCache& cache, bool store, unsigned int flags)
    {
        return Verify(CachingTransactionSignatureChecker{&tx, input_index, spent_output.nValue, store, cache, txdata}, flags);
    }
};

size_t CountEvents(const std::vector<Event>& events, const Event& event)
{
    return static_cast<size_t>(std::count(events.begin(), events.end(), event));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pqc_sigcache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_components_and_domain)
{
    const std::vector<WitnessVector> vectors{LoadWitnessVectors()};
    const WitnessVector& vector_a{FindVector(vectors, "single_key_default_sighash")};
    const PQCTuple a{AcceptedTuple(vector_a)};
    const PQCTuple b{AcceptedTuple(FindVector(vectors, "single_key_sighash_none"))};
    BOOST_REQUIRE(a.sighash != b.sighash);
    BOOST_REQUIRE(!(a.pubkey == b.pubkey));
    BOOST_REQUIRE(a.sig != b.sig);

    TupleContext ctx;
    ObservedCache observed{1 << 20};
    const auto checker{ctx.Caching(observed.cache, /*store=*/true)};

    BOOST_CHECK(checker.VerifyPQCSignature(a.sig, a.pubkey, a.sighash));
    observed.CheckEvents({Miss(false), Ok(true)}, "prime valid tuple");
    BOOST_CHECK(checker.VerifyPQCSignature(a.sig, a.pubkey, a.sighash));
    observed.CheckEvents({Hit(false)}, "primed tuple hits");

    const PQCTuple wrong_sig{a.sighash, a.pubkey, FlipFirstByte(a.sig)};
    std::vector<std::pair<std::string_view, PQCTuple>> variants{
        {"changed sighash", {b.sighash, a.pubkey, a.sig}},
        {"changed pubkey", {a.sighash, b.pubkey, a.sig}},
        {"changed signature", wrong_sig},
    };
    // Bind every byte of each component, including changes that preserve a
    // long prefix of a cached valid tuple.
    for (const bool last : {false, true}) {
        PQCTuple hash_variant{a};
        hash_variant.sighash.begin()[last ? a.sighash.size() - 1 : a.sighash.size() / 2] ^= 1;
        variants.emplace_back(last ? "last sighash byte" : "middle sighash byte", hash_variant);
        valtype pubkey_bytes(a.pubkey.begin(), a.pubkey.end());
        pubkey_bytes[last ? pubkey_bytes.size() - 1 : pubkey_bytes.size() / 2] ^= 1;
        variants.emplace_back(last ? "last pubkey byte" : "middle pubkey byte", PQCTuple{a.sighash, CPQCPubKey{pubkey_bytes}, a.sig});
        PQCTuple sig_variant{a};
        sig_variant.sig[last ? a.sig.size() - 1 : a.sig.size() / 2] ^= 1;
        variants.emplace_back(last ? "last signature byte" : "middle signature byte", sig_variant);
    }
    for (const auto& [label, variant] : variants) {
        BOOST_CHECK_MESSAGE(EntryPQC(observed.cache, variant) != EntryPQC(observed.cache, a), label);
        BOOST_CHECK_MESSAGE(!ctx.Uncached().VerifyPQCSignature(variant.sig, variant.pubkey, variant.sighash), label);
        BOOST_CHECK_MESSAGE(!checker.VerifyPQCSignature(variant.sig, variant.pubkey, variant.sighash), label);
        observed.CheckEvents({Miss(false), Fail()}, label);
        BOOST_CHECK_MESSAGE(!observed.cache.Get(EntryPQC(observed.cache, variant), /*erase=*/false), label);
    }

    // A PQC public key has the Schnorr x-only size, so the Schnorr domain can
    // hash exactly the bytes of the invalid tuple. An invalid CPubKey
    // contributes no bytes, so prefixing the signature with the PQC public key
    // hashes the same byte string in the ECDSA domain.
    uint256 schnorr_entry;
    observed.cache.ComputeEntrySchnorr(schnorr_entry, wrong_sig.sighash, wrong_sig.sig,
                                       XOnlyPubKey{std::span<const unsigned char>{wrong_sig.pubkey.data(), wrong_sig.pubkey.size()}});
    valtype ecdsa_sig(wrong_sig.pubkey.begin(), wrong_sig.pubkey.end());
    ecdsa_sig.insert(ecdsa_sig.end(), wrong_sig.sig.begin(), wrong_sig.sig.end());
    const CPubKey invalid_pubkey;
    BOOST_REQUIRE_EQUAL(invalid_pubkey.size(), 0U);
    uint256 ecdsa_entry;
    observed.cache.ComputeEntryECDSA(ecdsa_entry, wrong_sig.sighash, ecdsa_sig, invalid_pubkey);
    const uint256 pqc_entry{EntryPQC(observed.cache, wrong_sig)};
    BOOST_CHECK(pqc_entry != schnorr_entry);
    BOOST_CHECK(pqc_entry != ecdsa_entry);
    observed.cache.Set(schnorr_entry);
    observed.cache.Set(ecdsa_entry);
    BOOST_REQUIRE(observed.cache.Get(schnorr_entry, /*erase=*/false));
    BOOST_REQUIRE(observed.cache.Get(ecdsa_entry, /*erase=*/false));
    BOOST_CHECK(!checker.VerifyPQCSignature(wrong_sig.sig, wrong_sig.pubkey, wrong_sig.sighash));
    observed.CheckEvents({Miss(false), Fail()}, "other domains primed with identical bytes");

    // The cached tuple is reached only after the interpreter's size and
    // hashtype checks: the corpus spend hits the primed entry, while the same
    // raw signature with an explicit SIGHASH_DEFAULT byte never reaches the cache.
    InputUnderTest spend{vector_a.spend_tx, vector_a.spent_outputs, vector_a.input_index};
    BOOST_CHECK(spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS) == (ScriptOutcome{true, SCRIPT_ERR_OK}));
    observed.CheckEvents({Hit(false)}, "corpus spend reuses tuple entry");

    CMutableTransaction explicit_default{vector_a.spend_tx};
    explicit_default.vin[vector_a.input_index].scriptWitness.stack[0].push_back(SIGHASH_DEFAULT);
    InputUnderTest explicit_spend{explicit_default, vector_a.spent_outputs, vector_a.input_index};
    const ScriptOutcome expected_hashtype_error{false, SCRIPT_ERR_P2MR_SIG_HASHTYPE};
    BOOST_CHECK(explicit_spend.VerifyUncached(P2MR_SCRIPT_VERIFY_FLAGS) == expected_hashtype_error);
    BOOST_CHECK(explicit_spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS) == expected_hashtype_error);
    observed.CheckEvents({}, "explicit SIGHASH_DEFAULT byte stops before the cache");
}

BOOST_AUTO_TEST_CASE(failures_never_populate)
{
    const std::vector<WitnessVector> vectors{LoadWitnessVectors()};
    const PQCTuple valid{AcceptedTuple(FindVector(vectors, "single_key_default_sighash"))};
    const PQCTuple invalid{valid.sighash, valid.pubkey, FlipFirstByte(valid.sig)};

    TupleContext ctx;
    {
        ObservedCache observed{1 << 20};
        for (int i{0}; i < 3; ++i) {
            BOOST_CHECK(!ctx.Caching(observed.cache, /*store=*/true).VerifyPQCSignature(invalid.sig, invalid.pubkey, invalid.sighash));
            observed.CheckEvents({Miss(false), Fail()}, strprintf("invalid store call %d", i));
        }
        BOOST_CHECK(!ctx.Caching(observed.cache, /*store=*/false).VerifyPQCSignature(invalid.sig, invalid.pubkey, invalid.sighash));
        observed.CheckEvents({Miss(true), Fail()}, "invalid consume call");
        BOOST_CHECK(!observed.cache.Get(EntryPQC(observed.cache, invalid), /*erase=*/false));
    }

    size_t accepted{0};
    size_t rejected{0};
    BOOST_TEST_MESSAGE("vector | expected | uncached | cold | warm | cold events | warm events");
    for (const WitnessVector& vector : vectors) {
        const ScriptOutcome expected{vector.expected_error == SCRIPT_ERR_OK, vector.expected_error};
        InputUnderTest spend{vector.spend_tx, vector.spent_outputs, vector.input_index};
        ObservedCache observed{1 << 20};

        const ScriptOutcome uncached{spend.VerifyUncached(P2MR_SCRIPT_VERIFY_FLAGS)};
        const ScriptOutcome cold{spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS)};
        const std::vector<Event> cold_events{observed.TakeEvents()};
        const ScriptOutcome warm{spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS)};
        const std::vector<Event> warm_events{observed.TakeEvents()};
        BOOST_TEST_MESSAGE(vector.name << " | " << OutcomeToString(expected) << " | " << OutcomeToString(uncached)
                           << " | " << OutcomeToString(cold) << " | " << OutcomeToString(warm)
                           << " | " << EventsToString(cold_events) << " | " << EventsToString(warm_events));
        BOOST_CHECK_MESSAGE(uncached == expected, vector.name);
        BOOST_CHECK_MESSAGE(cold == expected, vector.name);
        BOOST_CHECK_MESSAGE(warm == expected, vector.name);

        if (vector.expected_error != SCRIPT_ERR_OK) {
            ++rejected;
            BOOST_CHECK_MESSAGE(cold_events.empty(), vector.name);
            BOOST_CHECK_MESSAGE(warm_events.empty(), vector.name);
            continue;
        }
        ++accepted;
        const size_t checks{cold_events.size() / 2};
        BOOST_CHECK_MESSAGE(checks >= 1, vector.name);
        BOOST_CHECK_MESSAGE(cold_events == Repeat({Miss(false), Ok(true)}, checks), vector.name);
        BOOST_CHECK_MESSAGE(warm_events == Repeat({Hit(false)}, checks), vector.name);

        CMutableTransaction mutated_tx{vector.spend_tx};
        auto& witness_sig{mutated_tx.vin[vector.input_index].scriptWitness.stack[0]};
        witness_sig = FlipFirstByte(witness_sig);
        InputUnderTest mutated{mutated_tx, vector.spent_outputs, vector.input_index};
        const ScriptOutcome expected_sig_error{false, SCRIPT_ERR_P2MR_SIG};
        ObservedCache mutated_observed{1 << 20};
        const ScriptOutcome mutated_uncached{mutated.VerifyUncached(P2MR_SCRIPT_VERIFY_FLAGS)};
        const ScriptOutcome mutated_cold{mutated.VerifyCaching(mutated_observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS)};
        const std::vector<Event> mutated_cold_events{mutated_observed.CheckEvents({Miss(false), Fail()}, vector.name + " mutated cold")};
        const ScriptOutcome mutated_warm{mutated.VerifyCaching(mutated_observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS)};
        const std::vector<Event> mutated_warm_events{mutated_observed.CheckEvents({Miss(false), Fail()}, vector.name + " mutated warm")};
        BOOST_TEST_MESSAGE(vector.name << "+flipped_sig | " << OutcomeToString(expected_sig_error) << " | " << OutcomeToString(mutated_uncached)
                           << " | " << OutcomeToString(mutated_cold) << " | " << OutcomeToString(mutated_warm)
                           << " | " << EventsToString(mutated_cold_events) << " | " << EventsToString(mutated_warm_events));
        BOOST_CHECK_MESSAGE(mutated_uncached == expected_sig_error, vector.name);
        BOOST_CHECK_MESSAGE(mutated_cold == expected_sig_error, vector.name);
        BOOST_CHECK_MESSAGE(mutated_warm == expected_sig_error, vector.name);
    }
    BOOST_CHECK_EQUAL(accepted, 10U);
    BOOST_CHECK_EQUAL(rejected, 4U);
}

BOOST_AUTO_TEST_CASE(warm_cache_preserves_p2mr_errors_and_weight)
{
    std::array<CPQCKey, 5> keys;
    std::vector<CPQCPubKey> pubkeys;
    for (auto& key : keys) {
        key.MakeNewKey();
        BOOST_REQUIRE(key.IsValid());
        pubkeys.push_back(key.GetPubKey());
    }
    CScript leaf_script;
    for (size_t i{0}; i < pubkeys.size(); ++i) {
        leaf_script << valtype(pubkeys[i].begin(), pubkeys[i].end()) << (i == 0 ? OP_CHECKSIGPQC : OP_CHECKSIGADD);
    }
    leaf_script << static_cast<int64_t>(keys.size()) << OP_NUMEQUAL;

    const valtype leaf_bytes(leaf_script.begin(), leaf_script.end());
    const valtype control_block{static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)};
    const uint256 leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_bytes)};
    const uint256 merkle_root{ComputeP2MRMerkleRoot(control_block, leaf_hash)};
    const CScript script_pubkey{CScript{} << OP_2 << valtype(merkle_root.begin(), merkle_root.end())};

    const CTransaction tx_credit{BuildCreditingTransaction(script_pubkey, /*nValue=*/1000)};
    CScriptWitness witness;
    witness.stack.assign(keys.size(), valtype(PQC_SIG_SIZE, 0x00));
    witness.stack.push_back(leaf_bytes);
    witness.stack.push_back(control_block);
    CMutableTransaction tx_spend{BuildSpendingTransaction(CScript{}, witness, tx_credit)};

    const auto make_execdata = [&](const CScriptWitness& full_witness) {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash = leaf_hash;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_validation_weight_left = ::GetSerializeSize(full_witness.stack) + VALIDATION_WEIGHT_OFFSET;
        execdata.m_validation_weight_left_init = true;
        return execdata;
    };

    {
        PrecomputedTransactionData sign_txdata;
        sign_txdata.Init(tx_spend, {tx_credit.vout[0]});
        ScriptExecutionData sign_execdata{make_execdata(witness)};
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashP2MR(sighash, sign_execdata, tx_spend, /*in_pos=*/0, SIGHASH_DEFAULT, sign_txdata, MissingDataBehavior::ASSERT_FAIL));
        for (size_t i{0}; i < keys.size(); ++i) {
            valtype sig;
            uint32_t counter{0};
            BOOST_REQUIRE(keys[i].Sign(sighash, sig, counter));
            tx_spend.vin[0].scriptWitness.stack[keys.size() - 1 - i] = std::move(sig);
        }
    }
    InputUnderTest spend{tx_spend, {tx_credit.vout[0]}, /*index=*/0};
    const ScriptOutcome weight_error{false, SCRIPT_ERR_P2MR_VALIDATION_WEIGHT};
    const ScriptOutcome success{true, SCRIPT_ERR_OK};

    // Legacy weight charges four signature operations and fails on the fifth
    // charge before its check; v2 weight checks all five.
    BOOST_CHECK(spend.VerifyUncached(P2MR_LEGACY_WEIGHT_FLAGS) == weight_error);
    BOOST_CHECK(spend.VerifyUncached(P2MR_SCRIPT_VERIFY_FLAGS) == success);
    {
        ObservedCache observed{1 << 20};
        BOOST_CHECK(spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_LEGACY_WEIGHT_FLAGS) == weight_error);
        observed.CheckEvents(Repeat({Miss(false), Ok(true)}, 4), "cold legacy");
        BOOST_CHECK(spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS) == success);
        std::vector<Event> prime_v2{Repeat({Hit(false)}, 4)};
        prime_v2.push_back(Miss(false));
        prime_v2.push_back(Ok(true));
        observed.CheckEvents(prime_v2, "v2 primes the fifth signature");
        BOOST_CHECK(spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_LEGACY_WEIGHT_FLAGS) == weight_error);
        observed.CheckEvents(Repeat({Hit(false)}, 4), "warm legacy");
        BOOST_CHECK(spend.VerifyCaching(observed.cache, /*store=*/true, P2MR_SCRIPT_VERIFY_FLAGS) == success);
        observed.CheckEvents(Repeat({Hit(false)}, 5), "warm v2");
    }

    // Compare the remaining validation-weight budget after direct script
    // execution under uncached, cold and warm checkers.
    struct EvalOutcome {
        ScriptOutcome outcome;
        int64_t weight_left;
    };
    const auto eval = [&](const BaseSignatureChecker& checker, unsigned int flags) {
        const CScriptWitness& full_witness{spend.tx.vin[0].scriptWitness};
        std::vector<valtype> stack(full_witness.stack.begin(), full_witness.stack.end() - 2);
        ScriptExecutionData execdata{make_execdata(full_witness)};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool result{EvalScript(stack, leaf_script, flags, checker, SigVersion::P2MR, execdata, &err)};
        return EvalOutcome{{result, err}, execdata.m_validation_weight_left};
    };
    const auto uncached_checker{TransactionSignatureChecker{&spend.tx, 0, spend.spent_output.nValue, spend.txdata, MissingDataBehavior::ASSERT_FAIL}};
    SignatureCache cold_legacy_cache{1 << 20};
    SignatureCache cold_v2_cache{1 << 20};
    const auto caching_checker = [&](SignatureCache& cache) {
        return CachingTransactionSignatureChecker{&spend.tx, 0, spend.spent_output.nValue, /*storeIn=*/true, cache, spend.txdata};
    };

    const EvalOutcome uncached_legacy{eval(uncached_checker, P2MR_LEGACY_WEIGHT_FLAGS)};
    const EvalOutcome uncached_v2{eval(uncached_checker, P2MR_SCRIPT_VERIFY_FLAGS)};
    const EvalOutcome cold_legacy{eval(caching_checker(cold_legacy_cache), P2MR_LEGACY_WEIGHT_FLAGS)};
    const EvalOutcome cold_v2{eval(caching_checker(cold_v2_cache), P2MR_SCRIPT_VERIFY_FLAGS)};
    // cold_v2_cache now holds all five signatures.
    const EvalOutcome warm_legacy{eval(caching_checker(cold_v2_cache), P2MR_LEGACY_WEIGHT_FLAGS)};
    const EvalOutcome warm_v2{eval(caching_checker(cold_v2_cache), P2MR_SCRIPT_VERIFY_FLAGS)};

    BOOST_TEST_MESSAGE(strprintf("legacy weight_left uncached=%d cold=%d warm=%d (%s, %s, %s)",
                                 uncached_legacy.weight_left, cold_legacy.weight_left, warm_legacy.weight_left,
                                 OutcomeToString(uncached_legacy.outcome), OutcomeToString(cold_legacy.outcome), OutcomeToString(warm_legacy.outcome)));
    BOOST_TEST_MESSAGE(strprintf("v2 weight_left uncached=%d cold=%d warm=%d (%s, %s, %s)",
                                 uncached_v2.weight_left, cold_v2.weight_left, warm_v2.weight_left,
                                 OutcomeToString(uncached_v2.outcome), OutcomeToString(cold_v2.outcome), OutcomeToString(warm_v2.outcome)));
    BOOST_CHECK(uncached_legacy.outcome == weight_error);
    BOOST_CHECK(cold_legacy.outcome == weight_error);
    BOOST_CHECK(warm_legacy.outcome == weight_error);
    BOOST_CHECK(uncached_v2.outcome == success);
    BOOST_CHECK(cold_v2.outcome == success);
    BOOST_CHECK(warm_v2.outcome == success);
    // Margins match the "5-of-5 default depth 0" row of the P2MR weight boundary matrix.
    BOOST_CHECK_EQUAL(uncached_legacy.weight_left, -9);
    BOOST_CHECK_EQUAL(cold_legacy.weight_left, uncached_legacy.weight_left);
    BOOST_CHECK_EQUAL(warm_legacy.weight_left, uncached_legacy.weight_left);
    BOOST_CHECK_EQUAL(uncached_v2.weight_left, 226);
    BOOST_CHECK_EQUAL(cold_v2.weight_left, uncached_v2.weight_left);
    BOOST_CHECK_EQUAL(warm_v2.weight_left, uncached_v2.weight_left);
}

BOOST_AUTO_TEST_CASE(store_consume_and_reclamation)
{
    const std::vector<WitnessVector> vectors{LoadWitnessVectors()};
    const PQCTuple valid{AcceptedTuple(FindVector(vectors, "single_key_default_sighash"))};
    TupleContext ctx;

    {
        ObservedCache observed{1 << 20};
        BOOST_CHECK(ctx.Caching(observed.cache, /*store=*/false).VerifyPQCSignature(valid.sig, valid.pubkey, valid.sighash));
        observed.CheckEvents({Miss(true), Ok(false)}, "non-store miss");
        BOOST_CHECK(!observed.cache.Get(EntryPQC(observed.cache, valid), /*erase=*/false));
    }

    {
        ObservedCache observed{1 << 20};
        BOOST_CHECK(ctx.Caching(observed.cache, /*store=*/true).VerifyPQCSignature(valid.sig, valid.pubkey, valid.sighash));
        observed.CheckEvents({Miss(false), Ok(true)}, "store miss");
        BOOST_CHECK(ctx.Caching(observed.cache, /*store=*/false).VerifyPQCSignature(valid.sig, valid.pubkey, valid.sighash));
        observed.CheckEvents({Hit(true)}, "consume hit");
        // Consumption only marks the entry discardable; it stays available until space is needed.
        BOOST_CHECK(observed.cache.Get(EntryPQC(observed.cache, valid), /*erase=*/false));
        BOOST_CHECK(ctx.Caching(observed.cache, /*store=*/false).VerifyPQCSignature(valid.sig, valid.pubkey, valid.sighash));
        observed.TakeEvents();
    }

    // Reclamation under insertion pressure on a seeded, deterministic cache.
    // Half the capacity is inserted, the older half of those entries is
    // consumed through the caching checker (one real signature, the rest
    // synthetic tuples that hit without verification), and then the other
    // half of the capacity is inserted.
    constexpr size_t CAPACITY{1024};
    struct ReclamationCounts {
        size_t consume_hits{0};
        size_t consumed_survivors{0};
        size_t kept_survivors{0};
        size_t fresh_survivors{0};
        bool real_survived{false};
    };
    const auto run = [&](bool consume) {
        SeedRandomForTest(SeedRand::ZEROS);
        ObservedCache observed{CAPACITY * sizeof(uint256)};
        std::vector<PQCTuple> tuples;
        tuples.push_back(valid);
        for (size_t i{1}; i < CAPACITY; ++i) {
            tuples.push_back({(HashWriter{} << uint64_t{i}).GetSHA256(), valid.pubkey, valid.sig});
        }
        std::vector<uint256> entries;
        for (const PQCTuple& tuple : tuples) entries.push_back(EntryPQC(observed.cache, tuple));

        ReclamationCounts counts;
        for (size_t i{0}; i < CAPACITY / 2; ++i) observed.cache.Set(entries[i]);
        if (consume) {
            const auto consumer{ctx.Caching(observed.cache, /*store=*/false)};
            for (size_t i{0}; i < CAPACITY / 4; ++i) {
                counts.consume_hits += consumer.VerifyPQCSignature(tuples[i].sig, tuples[i].pubkey, tuples[i].sighash);
            }
            const std::vector<Event> events{observed.TakeEvents()};
            BOOST_CHECK_EQUAL(CountEvents(events, Hit(true)), counts.consume_hits);
        }
        for (size_t i{CAPACITY / 2}; i < CAPACITY; ++i) observed.cache.Set(entries[i]);

        for (size_t i{0}; i < CAPACITY; ++i) {
            const bool present{observed.cache.Get(entries[i], /*erase=*/false)};
            if (i < CAPACITY / 4) {
                counts.consumed_survivors += present;
            } else if (i < CAPACITY / 2) {
                counts.kept_survivors += present;
            } else {
                counts.fresh_survivors += present;
            }
        }
        counts.real_survived = observed.cache.Get(entries[0], /*erase=*/false);
        BOOST_TEST_MESSAGE(strprintf("reclamation consume=%d: consume_hits=%u consumed_survivors=%u kept_survivors=%u fresh_survivors=%u real_survived=%d",
                                     consume, counts.consume_hits, counts.consumed_survivors, counts.kept_survivors, counts.fresh_survivors, counts.real_survived));
        return counts;
    };
    const ReclamationCounts consumed{run(/*consume=*/true)};
    const ReclamationCounts control{run(/*consume=*/false)};

    // Thresholds were calibrated once under SeedRand::ZEROS (consumed run:
    // 99 consumed and 208 kept survivors; control run: 216 and 212) and leave
    // a margin on each side.
    BOOST_CHECK_EQUAL(consumed.consume_hits, CAPACITY / 4);
    BOOST_CHECK_EQUAL(consumed.fresh_survivors, CAPACITY / 2);
    BOOST_CHECK_EQUAL(control.fresh_survivors, CAPACITY / 2);
    // Consumed entries are reclaimed ahead of entries that were kept.
    BOOST_CHECK_LE(consumed.consumed_survivors, CAPACITY / 8);
    BOOST_CHECK_GE(consumed.kept_survivors, 3 * CAPACITY / 16);
    // The paired control shows the difference comes from consumption.
    BOOST_CHECK_GE(control.consumed_survivors, 3 * CAPACITY / 16);
    BOOST_CHECK_GE(control.kept_survivors, 3 * CAPACITY / 16);
    BOOST_CHECK(control.real_survived || !consumed.real_survived);
}

BOOST_AUTO_TEST_CASE(shared_budget_and_eviction)
{
    constexpr size_t CAPACITY{1024};
    const auto synthetic_pqc = [](size_t i) {
        return PQCTuple{(HashWriter{} << uint64_t{i} << std::string{"pqc"}).GetSHA256(), CPQCPubKey{}, valtype(PQC_SIG_SIZE, static_cast<unsigned char>(i))};
    };
    const auto synthetic_schnorr_entry = [](const SignatureCache& cache, size_t i) {
        uint256 entry;
        const uint256 hash{(HashWriter{} << uint64_t{i} << std::string{"schnorr"}).GetSHA256()};
        const std::array<unsigned char, 32> key{};
        cache.ComputeEntrySchnorr(entry, hash, valtype(64, static_cast<unsigned char>(i)), XOnlyPubKey{key});
        return entry;
    };

    {
        SignatureCache cache{CAPACITY * sizeof(uint256)};
        std::vector<uint256> entries;
        for (size_t i{0}; i < 4 * CAPACITY; ++i) {
            entries.push_back(EntryPQC(cache, synthetic_pqc(i)));
            cache.Set(entries.back());
        }
        size_t survivors{0};
        for (const uint256& entry : entries) survivors += cache.Get(entry, /*erase=*/false);
        BOOST_TEST_MESSAGE(strprintf("pqc-only: survivors=%u capacity=%u", survivors, CAPACITY));
        BOOST_CHECK_LE(survivors, CAPACITY);
    }

    {
        SignatureCache cache{CAPACITY * sizeof(uint256)};
        std::vector<uint256> schnorr_entries;
        for (size_t i{0}; i < CAPACITY; ++i) {
            schnorr_entries.push_back(synthetic_schnorr_entry(cache, i));
            cache.Set(schnorr_entries.back());
        }
        std::vector<uint256> pqc_entries;
        for (size_t i{0}; i < 4 * CAPACITY; ++i) {
            pqc_entries.push_back(EntryPQC(cache, synthetic_pqc(i)));
            cache.Set(pqc_entries.back());
        }
        size_t schnorr_survivors{0};
        for (const uint256& entry : schnorr_entries) schnorr_survivors += cache.Get(entry, /*erase=*/false);
        size_t pqc_survivors{0};
        for (const uint256& entry : pqc_entries) pqc_survivors += cache.Get(entry, /*erase=*/false);
        BOOST_TEST_MESSAGE(strprintf("mixed: schnorr_survivors=%u pqc_survivors=%u capacity=%u", schnorr_survivors, pqc_survivors, CAPACITY));
        BOOST_CHECK_LE(schnorr_survivors + pqc_survivors, CAPACITY);
    }

    // The minimum allocation holds two elements. Fill it through the caching
    // checker with every valid corpus tuple and count PQC hits through the
    // checker as well, so a store private to the PQC path would be visible.
    {
        const std::vector<PQCTuple> tuples{AcceptedTuples(LoadWitnessVectors())};
        BOOST_REQUIRE_EQUAL(tuples.size(), 10U);
        TupleContext ctx;
        ObservedCache observed{0};
        std::vector<uint256> schnorr_entries;
        for (size_t i{0}; i < 16; ++i) {
            schnorr_entries.push_back(synthetic_schnorr_entry(observed.cache, i));
            observed.cache.Set(schnorr_entries.back());
        }
        const auto storer{ctx.Caching(observed.cache, /*store=*/true)};
        for (const PQCTuple& tuple : tuples) {
            BOOST_CHECK(storer.VerifyPQCSignature(tuple.sig, tuple.pubkey, tuple.sighash));
        }
        const std::vector<Event> store_events{observed.TakeEvents()};
        BOOST_CHECK_EQUAL(CountEvents(store_events, Ok(true)), tuples.size());

        size_t schnorr_survivors{0};
        for (const uint256& entry : schnorr_entries) schnorr_survivors += observed.cache.Get(entry, /*erase=*/false);
        const auto prober{ctx.Caching(observed.cache, /*store=*/false)};
        for (const PQCTuple& tuple : tuples) {
            BOOST_CHECK(prober.VerifyPQCSignature(tuple.sig, tuple.pubkey, tuple.sighash));
        }
        const std::vector<Event> probe_events{observed.TakeEvents()};
        const size_t pqc_hits{CountEvents(probe_events, Hit(true))};
        BOOST_CHECK_EQUAL(pqc_hits + CountEvents(probe_events, Miss(true)), tuples.size());
        BOOST_CHECK_EQUAL(CountEvents(probe_events, Ok(true)), 0U);
        BOOST_TEST_MESSAGE(strprintf("minimum: schnorr_survivors=%u pqc_hits=%u", schnorr_survivors, pqc_hits));
        BOOST_CHECK_LE(schnorr_survivors + pqc_hits, 2U);
    }

    {
        SignatureCache cache{0};
        std::vector<uint256> entries;
        for (size_t i{0}; i < 16; ++i) {
            entries.push_back(EntryPQC(cache, synthetic_pqc(i)));
            cache.Set(entries.back());
        }
        size_t survivors{0};
        for (const uint256& entry : entries) survivors += cache.Get(entry, /*erase=*/false);
        BOOST_CHECK_LE(survivors, 2U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
