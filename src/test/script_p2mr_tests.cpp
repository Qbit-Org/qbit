// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <crypto/pqc.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/p2mr.h>
#include <script/p2mr_sizing.h>
#include <script/sign.h>
#include <script/script.h>
#include <script/script_error.h>
#include <streams.h>
#include <test/data/p2mr_pqc_witness_vectors.json.h>
#include <test/data/p2mr_vectors.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <univalue.h>
#include <vector>

namespace {
using valtype = std::vector<unsigned char>;

constexpr unsigned int P2MR_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_P2MR_RULES
};

constexpr unsigned char P2MR_LEAF_VERSION_V1_CONTROL{static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)};

std::vector<unsigned char> ToByteVector(const uint256& hash)
{
    return std::vector<unsigned char>(hash.begin(), hash.end());
}

valtype ScriptBytes(const CScript& script)
{
    return valtype(script.begin(), script.end());
}

valtype ParseHexBytes(const char* hex)
{
    valtype bytes{ParseHex(hex)};
    assert(!bytes.empty() || hex[0] == '\0');
    return bytes;
}

CScript ScriptFromHex(const char* hex)
{
    const valtype bytes{ParseHexBytes(hex)};
    return CScript{bytes.begin(), bytes.end()};
}

uint256 Uint256FromHexBytes(const char* hex)
{
    const valtype bytes{ParseHexBytes(hex)};
    assert(bytes.size() == uint256::size());
    return uint256{bytes};
}

uint256 ComputeMerkleRootSingleLeaf(uint8_t leaf_version, const CScript& leaf_script)
{
    const uint256 leaf_hash = ComputeP2MRLeafHash(leaf_version, ScriptBytes(leaf_script));
    return ComputeP2MRMerkleRoot(std::vector<unsigned char>{static_cast<unsigned char>(leaf_version | 1)}, leaf_hash);
}

std::vector<unsigned char> ExpectedP2MRLeafPreimage(uint8_t leaf_version, const std::vector<unsigned char>& leaf_script)
{
    std::vector<unsigned char> preimage{leaf_version, static_cast<unsigned char>(leaf_script.size())};
    preimage.insert(preimage.end(), leaf_script.begin(), leaf_script.end());
    return preimage;
}

UniValue P2MRVectorTestData()
{
    UniValue tests;
    if (!tests.read(json_tests::p2mr_vectors) || !tests.isObject()) {
        throw std::runtime_error("p2mr_vectors.json must contain a JSON object");
    }
    BOOST_CHECK_EQUAL(tests["version"].getInt<int>(), 1);
    return tests;
}

uint256 VectorHash(const UniValue& obj, const std::string& field)
{
    const std::vector<unsigned char> bytes{ParseHex(obj[field].get_str())};
    if (bytes.size() != uint256::size()) {
        throw std::runtime_error("P2MR vector field is not a uint256: " + field);
    }
    return uint256{bytes};
}

ScriptError VectorScriptError(const std::string& name)
{
    if (name == "SCRIPT_ERR_P2MR_CONTROL_BIT0") return SCRIPT_ERR_P2MR_CONTROL_BIT0;
    if (name == "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE") return SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE;
    if (name == "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH") return SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
    BOOST_FAIL("unknown P2MR vector script error: " + name);
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

CScript BuildP2MRScriptPubKey(const uint256& merkle_root)
{
    return CScript{} << OP_2 << ToByteVector(merkle_root);
}

std::vector<unsigned char> PQCPubKeyBytes(const CPQCPubKey& pubkey)
{
    return std::vector<unsigned char>(pubkey.begin(), pubkey.end());
}

CScript BuildP2MRPkScript(const CPQCPubKey& pubkey)
{
    return CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKSIGPQC;
}

CScript BuildDropAllScript(size_t drop_count)
{
    CScript script;
    for (size_t i = 0; i < drop_count; ++i) {
        script << OP_DROP;
    }
    script << OP_TRUE;
    return script;
}

std::vector<valtype> BuildP2MRStackItemsForTotalBytes(size_t total_bytes)
{
    std::vector<valtype> stack_items;
    while (total_bytes > 0) {
        const size_t item_size{std::min<size_t>(MAX_P2MR_V1_STACK_ITEM_SIZE, total_bytes)};
        stack_items.emplace_back(item_size, 0x01);
        total_bytes -= item_size;
    }
    return stack_items;
}

CScript BuildP2MRMultiAScript(int threshold, const std::vector<CPQCPubKey>& pubkeys)
{
    CScript script;
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        script << PQCPubKeyBytes(pubkeys[i]) << (i == 0 ? OP_CHECKSIGPQC : OP_CHECKSIGADD);
    }
    script << threshold << OP_NUMEQUAL;
    return script;
}

valtype DataSigMessageHash(unsigned char fill)
{
    return valtype(32, fill);
}

valtype SignDataSigPQC(const CPQCKey& key, const valtype& msg_hash)
{
    BOOST_REQUIRE_EQUAL(msg_hash.size(), 32U);

    uint32_t signature_counter{0};
    valtype sig;
    BOOST_REQUIRE(key.Sign(ComputeQbitDataSigPQCHash(msg_hash), sig, signature_counter));
    BOOST_CHECK_EQUAL(signature_counter, 1U);
    BOOST_REQUIRE_EQUAL(sig.size(), PQC_SIG_SIZE);
    return sig;
}

valtype SignRawMessageHash(const CPQCKey& key, const valtype& msg_hash)
{
    BOOST_REQUIRE_EQUAL(msg_hash.size(), 32U);

    uint256 raw_hash;
    std::copy(msg_hash.begin(), msg_hash.end(), raw_hash.begin());

    uint32_t signature_counter{0};
    valtype sig;
    BOOST_REQUIRE(key.Sign(raw_hash, sig, signature_counter));
    BOOST_CHECK_EQUAL(signature_counter, 1U);
    BOOST_REQUIRE_EQUAL(sig.size(), PQC_SIG_SIZE);
    return sig;
}

CScript BuildP2MRDataSigScript(const CPQCPubKey& pubkey, const valtype& msg_hash)
{
    return CScript{} << msg_hash << PQCPubKeyBytes(pubkey) << OP_CHECKDATASIGPQC;
}

CScript BuildP2MRDataSigAddScript(int threshold, const std::vector<CPQCPubKey>& pubkeys, const valtype& msg_hash)
{
    CScript script;
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        if (i == 0) {
            script << msg_hash << OP_0 << PQCPubKeyBytes(pubkeys[i]) << OP_CHECKDATASIGADDPQC;
        } else {
            script << msg_hash << OP_SWAP << PQCPubKeyBytes(pubkeys[i]) << OP_CHECKDATASIGADDPQC;
        }
    }
    script << threshold << OP_NUMEQUAL;
    return script;
}

void AddPQCSigningKey(FlatSigningProvider& provider, const CPQCKey& key)
{
    const CPQCPubKey pubkey = key.GetPubKey();
    provider.pqc_keys.emplace(pubkey, key);
    provider.pqc_sig_counters.emplace(pubkey, 0);
}

bool ProduceP2MRSignature(const SigningProvider& provider, const CScript& script_pubkey, SignatureData& sigdata, ScriptError* err = nullptr)
{
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(100'000, script_pubkey);

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(90'000, CScript{} << OP_TRUE);

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, {funding_tx.vout.at(0)}, /*force=*/true);

    MutableTransactionSignatureCreator creator(spend_tx, 0, funding_tx.vout.at(0).nValue, &txdata, SIGHASH_DEFAULT);
    const bool complete = ProduceSignature(provider, creator, script_pubkey, sigdata);
    if (!complete && err != nullptr && sigdata.witness) {
        VerifyScript(sigdata.scriptSig, script_pubkey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker(), err);
    }
    return complete;
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

size_t CountNonEmptyP2MRSignatureItems(const CScriptWitness& witness, size_t pubkey_count)
{
    BOOST_REQUIRE_GE(witness.stack.size(), pubkey_count + 2);
    return static_cast<size_t>(std::count_if(witness.stack.begin(), witness.stack.begin() + pubkey_count, [](const auto& item) {
        return !item.empty();
    }));
}

struct P2MRSpendContext {
    CTransaction tx_credit;
    CMutableTransaction tx_spend;
    PrecomputedTransactionData txdata;
};

struct TaprootSpendContext {
    CTransaction tx_credit;
    CMutableTransaction tx_spend;
    PrecomputedTransactionData txdata;
};

struct MultiInputP2MRSigningContext {
    CTransaction tx_credit;
    CMutableTransaction tx_spend;
    std::map<COutPoint, Coin> coins;
};

MultiInputP2MRSigningContext BuildMultiInputP2MRSigningContext(const CScript& script_pubkey, size_t input_count)
{
    CMutableTransaction tx_credit_mut;
    for (size_t i{0}; i < input_count; ++i) {
        tx_credit_mut.vout.emplace_back(100'000 + static_cast<CAmount>(i), script_pubkey);
    }
    const CTransaction tx_credit{tx_credit_mut};

    CMutableTransaction tx_spend;
    std::map<COutPoint, Coin> coins;
    for (size_t i{0}; i < input_count; ++i) {
        COutPoint outpoint{tx_credit.GetHash(), static_cast<uint32_t>(i)};
        tx_spend.vin.emplace_back(outpoint);
        coins.emplace(outpoint, Coin{tx_credit.vout.at(i), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    tx_spend.vout.emplace_back(90'000, CScript{} << OP_TRUE);

    return {tx_credit, tx_spend, coins};
}

P2MRSpendContext BuildP2MRSpend(
    const CScript& script_pubkey,
    const CScript& leaf_script,
    const std::vector<valtype>& stack_items,
    const std::vector<unsigned char>& control_block)
{
    const CMutableTransaction tx_credit_mut = BuildCreditingTransaction(script_pubkey, /*nValue=*/1000);
    const CTransaction tx_credit{tx_credit_mut};

    CScriptWitness witness;
    for (const auto& item : stack_items) {
        witness.stack.push_back(item);
    }
    witness.stack.push_back(ScriptBytes(leaf_script));
    witness.stack.push_back(control_block);

    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, witness, tx_credit);

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});

    return P2MRSpendContext{tx_credit, tx_spend, txdata};
}

P2MRSpendContext BuildP2MRSpend(
    const CScript& leaf_script,
    const std::vector<valtype>& stack_items,
    const std::vector<unsigned char>& control_block,
    const uint256& program_root)
{
    const CScript script_pubkey = BuildP2MRScriptPubKey(program_root);
    return BuildP2MRSpend(script_pubkey, leaf_script, stack_items, control_block);
}

bool VerifySpend(const P2MRSpendContext& spend, unsigned int flags, ScriptError& err)
{
    return VerifyScript(
        spend.tx_spend.vin[0].scriptSig,
        spend.tx_credit.vout[0].scriptPubKey,
        &spend.tx_spend.vin[0].scriptWitness,
        flags,
        MutableTransactionSignatureChecker(
            &spend.tx_spend,
            0,
            spend.tx_credit.vout[0].nValue,
            spend.txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
}

TaprootSpendContext BuildTaprootScriptPathSpend(const CScript& leaf_script)
{
    TaprootBuilder builder;
    builder.Add(/*depth=*/0, leaf_script, TAPROOT_LEAF_TAPSCRIPT).Finalize(XOnlyPubKey::NUMS_H);

    const CScript script_pubkey = GetScriptForDestination(builder.GetOutput());
    const CMutableTransaction tx_credit_mut = BuildCreditingTransaction(script_pubkey, /*nValue=*/1000);
    const CTransaction tx_credit{tx_credit_mut};

    CScriptWitness witness;
    witness.stack.push_back(ScriptBytes(leaf_script));
    witness.stack.push_back(*builder.GetSpendData().scripts.begin()->second.begin());

    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, witness, tx_credit);

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});

    return TaprootSpendContext{tx_credit, tx_spend, txdata};
}

bool VerifyTaprootSpend(const TaprootSpendContext& spend, unsigned int flags, ScriptError& err)
{
    return VerifyScript(
        spend.tx_spend.vin[0].scriptSig,
        spend.tx_credit.vout[0].scriptPubKey,
        &spend.tx_spend.vin[0].scriptWitness,
        flags,
        MutableTransactionSignatureChecker(
            &spend.tx_spend,
            0,
            spend.tx_credit.vout[0].nValue,
            spend.txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
}

void RefreshSpendTxData(P2MRSpendContext& spend)
{
    spend.txdata = PrecomputedTransactionData{};
    std::vector<CTxOut> spent_outputs(spend.tx_spend.vin.size(), spend.tx_credit.vout[0]);
    spend.txdata.Init(spend.tx_spend, std::move(spent_outputs));
}

CScript BuildCTVScript(const uint256& ctv_hash)
{
    return CScript{} << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY;
}

CScript BuildCTVAndPQCChecksigScript(const uint256& ctv_hash, const CPQCPubKey& pubkey)
{
    return CScript{} << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY << OP_DROP << PQCPubKeyBytes(pubkey) << OP_CHECKSIGPQC;
}

CScript BuildCTVAndDataSigAddScript(const uint256& ctv_hash, int threshold, const std::vector<CPQCPubKey>& pubkeys, const valtype& msg_hash)
{
    CScript script = CScript{} << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY << OP_DROP;
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        if (i == 0) {
            script << msg_hash << OP_0 << PQCPubKeyBytes(pubkeys[i]) << OP_CHECKDATASIGADDPQC;
        } else {
            script << msg_hash << OP_SWAP << PQCPubKeyBytes(pubkeys[i]) << OP_CHECKDATASIGADDPQC;
        }
    }
    script << threshold << OP_NUMEQUAL;
    return script;
}

P2MRSpendContext BuildCTVSpend(const CScript& leaf_script, const std::vector<valtype>& stack_items = {})
{
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    return BuildP2MRSpend(
        leaf_script,
        stack_items,
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);
}

template <typename TxMutator>
P2MRSpendContext BuildCTVSpendWithComputedHash(TxMutator mutate)
{
    const CScript placeholder_script = BuildCTVScript(uint256::ZERO);
    P2MRSpendContext placeholder = BuildCTVSpend(placeholder_script);
    mutate(placeholder.tx_spend);
    RefreshSpendTxData(placeholder);
    const uint256 ctv_hash = GetDefaultCheckTemplateVerifyHash(placeholder.tx_spend, /*input_index=*/0, placeholder.txdata);

    P2MRSpendContext spend = BuildCTVSpend(BuildCTVScript(ctv_hash));
    mutate(spend.tx_spend);
    RefreshSpendTxData(spend);
    return spend;
}

P2MRSpendContext BuildCTVSpendWithComputedHash()
{
    return BuildCTVSpendWithComputedHash([](CMutableTransaction&) {});
}

template <typename Mutator>
void CheckCTVMutationFails(P2MRSpendContext spend, Mutator mutate)
{
    mutate(spend.tx_spend);
    RefreshSpendTxData(spend);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);
}

bool VerifyInputScript(const CScript& script_sig, const CScript& script_pubkey, const CScriptWitness& witness, unsigned int flags, ScriptError& err)
{
    const CMutableTransaction tx_credit_mut = BuildCreditingTransaction(script_pubkey, /*nValue=*/1000);
    const CTransaction tx_credit{tx_credit_mut};
    CMutableTransaction tx_spend = BuildSpendingTransaction(script_sig, witness, tx_credit);

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});

    return VerifyScript(
        tx_spend.vin[0].scriptSig,
        tx_credit.vout[0].scriptPubKey,
        &tx_spend.vin[0].scriptWitness,
        flags,
        MutableTransactionSignatureChecker(
            &tx_spend,
            0,
            tx_credit.vout[0].nValue,
            txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
}

bool VerifyBaseScript(const CScript& script_pubkey, unsigned int flags, ScriptError& err)
{
    return VerifyInputScript(CScript{}, script_pubkey, CScriptWitness{}, flags, err);
}

ScriptExecutionData BuildExecData(const CScript& leaf_script)
{
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;
    return execdata;
}

void SignP2MRLeaf(CPQCKey& key, const CScript& leaf_script, const P2MRSpendContext& spend, std::vector<unsigned char>& sig_out)
{
    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    BOOST_REQUIRE(key.Sign(sighash, sig_out, signature_counter));
    BOOST_CHECK_EQUAL(signature_counter, 1U);
}

struct P2MRWitnessVector {
    CMutableTransaction spend_tx;
    CScript prevout_script_pubkey;
    CAmount prevout_amount;
    valtype leaf_script;
    valtype control_block;
    CPQCPubKey pubkey;
    valtype signature;
    valtype p2mr_sigmsg;
    uint256 p2mr_sighash;
    uint256 wrong_domain_sighash;
    valtype wrong_domain_signature;
    CScript wrong_pubkey_script_pubkey;
    valtype wrong_pubkey_leaf_script;
};

valtype ParseHexField(const UniValue& obj, std::string_view field)
{
    const UniValue& value = obj[std::string{field}];
    BOOST_REQUIRE_MESSAGE(value.isStr(), "missing string field " << field);
    valtype bytes{ParseHex(value.get_str())};
    BOOST_REQUIRE_MESSAGE(!bytes.empty(), "invalid or empty hex field " << field);
    return bytes;
}

uint256 ParseRawUint256Field(const UniValue& obj, std::string_view field)
{
    const valtype bytes{ParseHexField(obj, field)};
    BOOST_REQUIRE_EQUAL(bytes.size(), uint256::size());
    return uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
}

CScript ParseScriptField(const UniValue& obj, std::string_view field)
{
    const valtype bytes{ParseHexField(obj, field)};
    return CScript{bytes.begin(), bytes.end()};
}

CMutableTransaction ParseMutableTransactionField(const UniValue& obj, std::string_view field)
{
    DataStream stream{ParseHexField(obj, field)};
    CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    return tx;
}

P2MRWitnessVector LoadIndependentP2MRWitnessVector()
{
    const UniValue vectors = read_json(json_tests::p2mr_pqc_witness_vectors);
    BOOST_REQUIRE_EQUAL(vectors.size(), 1U);
    const UniValue& vec = vectors[0].get_obj();

    const valtype pubkey_bytes{ParseHexField(vec, "pubkey")};
    BOOST_REQUIRE_EQUAL(pubkey_bytes.size(), PQC_PUBKEY_SIZE);
    CPQCPubKey pubkey{pubkey_bytes};
    BOOST_REQUIRE(pubkey.IsValid());

    P2MRWitnessVector out{
        .spend_tx = ParseMutableTransactionField(vec, "spendTx"),
        .prevout_script_pubkey = ParseScriptField(vec, "prevoutScriptPubKey"),
        .prevout_amount = vec["prevoutAmount"].getInt<CAmount>(),
        .leaf_script = ParseHexField(vec, "leafScript"),
        .control_block = ParseHexField(vec, "controlBlock"),
        .pubkey = pubkey,
        .signature = ParseHexField(vec, "signature"),
        .p2mr_sigmsg = ParseHexField(vec, "p2mrSigMsg"),
        .p2mr_sighash = ParseRawUint256Field(vec, "p2mrSighash"),
        .wrong_domain_sighash = ParseRawUint256Field(vec, "wrongDomainSighash"),
        .wrong_domain_signature = ParseHexField(vec, "wrongDomainSignature"),
        .wrong_pubkey_script_pubkey = ParseScriptField(vec, "wrongPubkeyScriptPubKey"),
        .wrong_pubkey_leaf_script = ParseHexField(vec, "wrongPubkeyLeafScript"),
    };

    BOOST_REQUIRE_EQUAL(out.signature.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE(!out.p2mr_sigmsg.empty());
    BOOST_REQUIRE(out.p2mr_sighash != out.wrong_domain_sighash);
    BOOST_REQUIRE_EQUAL(out.wrong_domain_signature.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE_EQUAL(out.spend_tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(out.spend_tx.vout.size(), 1U);
    BOOST_REQUIRE_EQUAL(out.spend_tx.vin[0].scriptWitness.stack.size(), 3U);
    BOOST_REQUIRE(out.spend_tx.vin[0].scriptWitness.stack[0] == out.signature);
    BOOST_REQUIRE(out.spend_tx.vin[0].scriptWitness.stack[1] == out.leaf_script);
    BOOST_REQUIRE(out.spend_tx.vin[0].scriptWitness.stack[2] == out.control_block);
    return out;
}

PrecomputedTransactionData PrecomputeVectorData(const CMutableTransaction& tx, const CScript& prevout_script_pubkey, CAmount prevout_amount)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, {CTxOut{prevout_amount, prevout_script_pubkey}});
    return txdata;
}

bool VerifyVectorSpend(const CMutableTransaction& tx, const CScript& prevout_script_pubkey, CAmount prevout_amount, ScriptError& err)
{
    PrecomputedTransactionData txdata{PrecomputeVectorData(tx, prevout_script_pubkey, prevout_amount)};
    return VerifyScript(
        tx.vin[0].scriptSig,
        prevout_script_pubkey,
        &tx.vin[0].scriptWitness,
        P2MR_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(
            &tx,
            0,
            prevout_amount,
            txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
}

void CheckVectorMutationFails(const P2MRWitnessVector& vector, CMutableTransaction tx, const CScript& prevout_script_pubkey, ScriptError expected_error)
{
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyVectorSpend(tx, prevout_script_pubkey, vector.prevout_amount, err));
    BOOST_CHECK_EQUAL(err, expected_error);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(script_p2mr_tests, BasicTestingSetup)

static_assert(MAX_P2MR_V1_STACK_ITEM_SIZE == 16 * 1024);
static_assert(MAX_P2MR_V1_CAT_RESULT_SIZE == 16 * 1024);
static_assert(MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES == 128 * 1024);
static_assert(MAX_STANDARD_P2MR_STACK_ITEM_SIZE == MAX_P2MR_V1_STACK_ITEM_SIZE);
static_assert(MAX_STANDARD_P2MR_TOTAL_INITIAL_STACK_BYTES == MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES);
static_assert(MAX_STACK_SIZE == 1000);
static_assert(MAX_STANDARD_TX_WEIGHT == 400'000);
static_assert(OP_CHECKDATASIGPQC == 0xbc);
static_assert(OP_CHECKDATASIGADDPQC == 0xbd);

BOOST_AUTO_TEST_CASE(p2mr_independent_commitment_vectors)
{
    const UniValue tests{P2MRVectorTestData()};
    const auto& vectors = tests["valid"].getValues();
    BOOST_REQUIRE(!vectors.empty());

    for (const auto& vec : vectors) {
        const std::string name{vec["name"].get_str()};
        BOOST_TEST_CONTEXT(name)
        {
            const std::vector<unsigned char> leaf_script_bytes{ParseHex(vec["leaf_script"].get_str())};
            BOOST_REQUIRE_LT(leaf_script_bytes.size(), 253U);
            const uint8_t leaf_version{static_cast<uint8_t>(vec["leaf_version"].getInt<int>())};

            const std::vector<unsigned char> expected_leaf_preimage{ExpectedP2MRLeafPreimage(leaf_version, leaf_script_bytes)};
            BOOST_CHECK_EQUAL(HexStr(expected_leaf_preimage), vec["leaf_preimage"].get_str());

            const uint256 leaf_hash{ComputeP2MRLeafHash(leaf_version, leaf_script_bytes)};
            BOOST_CHECK_EQUAL(HexStr(leaf_hash), vec["leaf_hash"].get_str());

            const std::vector<unsigned char> control_block{ParseHex(vec["control_block"].get_str())};
            BOOST_CHECK_EQUAL(control_block.front() & 1, 1);
            BOOST_CHECK_EQUAL(control_block.front() & P2MR_LEAF_VERSION_MASK, leaf_version);

            const auto& siblings = vec["siblings"].getValues();
            const auto& branch_preimages = vec["branch_preimages"].getValues();
            BOOST_REQUIRE_EQUAL(siblings.size(), branch_preimages.size());
            BOOST_CHECK_EQUAL(control_block.size(), P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE * siblings.size());

            uint256 branch_hash{leaf_hash};
            std::vector<unsigned char> expected_control{static_cast<unsigned char>(leaf_version | 1)};
            for (size_t i{0}; i < siblings.size(); ++i) {
                const uint256 sibling{ParseHex(siblings[i].get_str())};
                expected_control.insert(expected_control.end(), sibling.begin(), sibling.end());

                const bool branch_first{std::lexicographical_compare(branch_hash.begin(), branch_hash.end(), sibling.begin(), sibling.end())};
                std::vector<unsigned char> branch_preimage;
                if (branch_first) {
                    branch_preimage.insert(branch_preimage.end(), branch_hash.begin(), branch_hash.end());
                    branch_preimage.insert(branch_preimage.end(), sibling.begin(), sibling.end());
                } else {
                    branch_preimage.insert(branch_preimage.end(), sibling.begin(), sibling.end());
                    branch_preimage.insert(branch_preimage.end(), branch_hash.begin(), branch_hash.end());
                }
                BOOST_CHECK_EQUAL(HexStr(branch_preimage), branch_preimages[i].get_str());

                branch_hash = ComputeP2MRBranchHash(branch_hash, sibling);
            }
            BOOST_CHECK(control_block == expected_control);

            const uint256 merkle_root{VectorHash(vec, "merkle_root")};
            BOOST_CHECK_EQUAL(ComputeP2MRMerkleRoot(control_block, leaf_hash), merkle_root);
            BOOST_CHECK_EQUAL(branch_hash, merkle_root);
            BOOST_CHECK_EQUAL(HexStr(BuildP2MRScriptPubKey(merkle_root)), vec["scriptPubKey"].get_str());
            BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(WitnessV2P2MR{merkle_root})), vec["scriptPubKey"].get_str());

            SelectParams(ChainType::MAIN);
            BOOST_CHECK_EQUAL(EncodeDestination(WitnessV2P2MR{merkle_root}), vec["mainnet_address"].get_str());
            SelectParams(ChainType::REGTEST);
            BOOST_CHECK_EQUAL(EncodeDestination(WitnessV2P2MR{merkle_root}), vec["regtest_address"].get_str());

            const CScript leaf_script{leaf_script_bytes.begin(), leaf_script_bytes.end()};
            const P2MRSpendContext spend{BuildP2MRSpend(leaf_script, /*stack_items=*/{}, control_block, merkle_root)};
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        }
    }
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(p2mr_independent_negative_vectors)
{
    const UniValue tests{P2MRVectorTestData()};
    const auto& vectors = tests["invalid"].getValues();
    BOOST_REQUIRE(!vectors.empty());

    for (const auto& vec : vectors) {
        const std::string name{vec["name"].get_str()};
        BOOST_TEST_CONTEXT(name)
        {
            const std::vector<unsigned char> leaf_script_bytes{ParseHex(vec["leaf_script"].get_str())};
            BOOST_REQUIRE_LT(leaf_script_bytes.size(), 253U);
            const uint8_t leaf_version{static_cast<uint8_t>(vec["leaf_version"].getInt<int>())};
            const uint256 production_leaf_hash{ComputeP2MRLeafHash(leaf_version, leaf_script_bytes)};
            const std::vector<unsigned char> expected_leaf_preimage{ExpectedP2MRLeafPreimage(leaf_version, leaf_script_bytes)};

            if (!vec["wrong_leaf_preimage"].isNull()) {
                BOOST_CHECK_NE(HexStr(expected_leaf_preimage), vec["wrong_leaf_preimage"].get_str());
            }
            if (!vec["wrong_leaf_hash"].isNull()) {
                BOOST_CHECK_NE(HexStr(production_leaf_hash), vec["wrong_leaf_hash"].get_str());
            }
            if (!vec["wrong_merkle_root"].isNull()) {
                BOOST_CHECK_EQUAL(vec["wrong_merkle_root"].get_str(), vec["merkle_root"].get_str());
            }

            const std::vector<unsigned char> control_block{ParseHex(vec["control_block"].get_str())};
            const uint256 merkle_root{VectorHash(vec, "merkle_root")};
            const CScript leaf_script{leaf_script_bytes.begin(), leaf_script_bytes.end()};
            const P2MRSpendContext spend{BuildP2MRSpend(leaf_script, /*stack_items=*/{}, control_block, merkle_root)};

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
            BOOST_CHECK_EQUAL(err, VectorScriptError(vec["expected_error"].get_str()));
        }
    }
}

BOOST_AUTO_TEST_CASE(p2mr_pubkey_leaf_helpers_roundtrip)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = p2mr::BuildPKScript(pubkey);
    BOOST_CHECK(leaf_script == BuildP2MRPkScript(pubkey));

    const std::optional<CPQCPubKey> matched_pubkey = p2mr::MatchPK(leaf_script);
    BOOST_REQUIRE(matched_pubkey);
    BOOST_CHECK(*matched_pubkey == pubkey);

    BOOST_CHECK(!p2mr::MatchPK(CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKDATASIGPQC));
    BOOST_CHECK(!p2mr::MatchPK(CScript{} << valtype(CPQCPubKey::SIZE - 1, 0x01) << OP_CHECKSIGPQC));
    BOOST_CHECK(!p2mr::MatchPK(CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKSIGPQC << OP_TRUE));
}

BOOST_AUTO_TEST_CASE(p2mr_signing_single_key_consumes_one_counter)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = BuildP2MRPkScript(pubkey);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ScriptBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());

    FlatSigningProvider provider;
    AddPQCSigningKey(provider, key);
    provider.mr_trees.emplace(output, builder);

    std::map<CPQCPubKey, int> counter_advances;
    provider.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t new_counter) {
        BOOST_CHECK_EQUAL(new_counter, previous_counter + 1);
        ++counter_advances[seen_pubkey];
    };

    SignatureData sigdata;
    sigdata.p2mr_spenddata = builder.GetP2MRSpendData();
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_REQUIRE_MESSAGE(ProduceP2MRSignature(provider, script_pubkey, sigdata, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(counter_advances[pubkey], 1);
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(!sigdata.scriptWitness.stack.at(0).empty());
    BOOST_CHECK(sigdata.scriptWitness.stack.at(1) == ScriptBytes(leaf_script));
}

BOOST_AUTO_TEST_CASE(p2mr_sign_transaction_many_inputs_shared_key_consumes_unique_counters)
{
    static constexpr size_t INPUT_COUNT{4};

    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = BuildP2MRPkScript(pubkey);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ScriptBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());
    MultiInputP2MRSigningContext context = BuildMultiInputP2MRSigningContext(script_pubkey, INPUT_COUNT);

    FlatSigningProvider provider;
    AddPQCSigningKey(provider, key);
    provider.mr_trees.emplace(output, builder);

    std::mutex counter_mutex;
    bool reservation_valid{true};
    uint32_t authoritative_counter{0};
    std::vector<std::pair<uint32_t, uint32_t>> reserved_ranges;
    provider.pqc_counter_reserver = [&](const CPQCPubKey& seen_pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        std::lock_guard<std::mutex> lock(counter_mutex);
        if (seen_pubkey != pubkey || count != 1 || authoritative_counter > PQC_MAX_SIGNATURES - count) {
            reservation_valid = false;
            return false;
        }
        previous_counter = authoritative_counter;
        reserved_counter = authoritative_counter + count;
        authoritative_counter = reserved_counter;
        reserved_ranges.emplace_back(previous_counter, reserved_counter);
        return true;
    };

    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
    provider.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t new_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        observed_ranges.emplace_back(previous_counter, new_counter);
    };

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(SignTransaction(context.tx_spend, &provider, context.coins, SIGHASH_DEFAULT, input_errors));
    BOOST_CHECK(input_errors.empty());

    {
        std::lock_guard<std::mutex> lock(counter_mutex);
        BOOST_CHECK(reservation_valid);
        BOOST_CHECK_EQUAL(authoritative_counter, INPUT_COUNT);
        BOOST_REQUIRE_EQUAL(reserved_ranges.size(), INPUT_COUNT);
    }
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    std::sort(observed_ranges.begin(), observed_ranges.end());
    for (size_t i{0}; i < INPUT_COUNT; ++i) {
        BOOST_CHECK(observed_ranges[i] == std::make_pair(static_cast<uint32_t>(i), static_cast<uint32_t>(i + 1)));
    }
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters[pubkey], INPUT_COUNT);

    for (const CTxIn& txin : context.tx_spend.vin) {
        BOOST_REQUIRE_EQUAL(txin.scriptWitness.stack.size(), 3U);
        BOOST_CHECK(!txin.scriptWitness.stack.at(0).empty());
        BOOST_CHECK(txin.scriptWitness.stack.at(1) == ScriptBytes(leaf_script));
    }
}

BOOST_AUTO_TEST_CASE(p2mr_sign_transaction_shared_key_stops_at_usage_limit)
{
    static constexpr size_t INPUT_COUNT{2};

    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = BuildP2MRPkScript(pubkey);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ScriptBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());
    MultiInputP2MRSigningContext context = BuildMultiInputP2MRSigningContext(script_pubkey, INPUT_COUNT);

    FlatSigningProvider provider;
    AddPQCSigningKey(provider, key);
    provider.pqc_sig_counters[pubkey] = PQC_MAX_SIGNATURES - 1;
    provider.mr_trees.emplace(output, builder);

    std::mutex counter_mutex;
    uint32_t authoritative_counter{PQC_MAX_SIGNATURES - 1};
    provider.pqc_counter_reserver = [&](const CPQCPubKey& seen_pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        std::lock_guard<std::mutex> lock(counter_mutex);
        if (seen_pubkey != pubkey || count != 1 || authoritative_counter > PQC_MAX_SIGNATURES - count) {
            return false;
        }
        previous_counter = authoritative_counter;
        reserved_counter = authoritative_counter + count;
        authoritative_counter = reserved_counter;
        return true;
    };

    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
    provider.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t new_counter) {
        BOOST_CHECK(seen_pubkey == pubkey);
        observed_ranges.emplace_back(previous_counter, new_counter);
    };

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(context.tx_spend, &provider, context.coins, SIGHASH_DEFAULT, input_errors));
    BOOST_CHECK_EQUAL(input_errors.size(), 1U);

    {
        std::lock_guard<std::mutex> lock(counter_mutex);
        BOOST_CHECK_EQUAL(authoritative_counter, PQC_MAX_SIGNATURES);
    }
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), 1U);
    BOOST_CHECK(observed_ranges[0] == std::make_pair(PQC_MAX_SIGNATURES - 1, PQC_MAX_SIGNATURES));
    BOOST_CHECK_EQUAL(provider.pqc_sig_counters[pubkey], PQC_MAX_SIGNATURES);

    const size_t non_empty_signatures{static_cast<size_t>(std::count_if(context.tx_spend.vin.begin(), context.tx_spend.vin.end(), [](const CTxIn& txin) {
        return !txin.scriptWitness.stack.empty() && !txin.scriptWitness.stack.front().empty();
    }))};
    BOOST_CHECK_EQUAL(non_empty_signatures, 1U);
}

BOOST_AUTO_TEST_CASE(p2mr_signing_selects_leaf_before_consuming_counters)
{
    CPQCKey selected_key;
    CPQCKey discarded_key_a;
    CPQCKey discarded_key_b;
    selected_key.MakeNewKey();
    discarded_key_a.MakeNewKey();
    discarded_key_b.MakeNewKey();

    const CPQCPubKey selected_pubkey = selected_key.GetPubKey();
    const CPQCPubKey discarded_pubkey_a = discarded_key_a.GetPubKey();
    const CPQCPubKey discarded_pubkey_b = discarded_key_b.GetPubKey();
    const CScript selected_leaf = BuildP2MRPkScript(selected_pubkey);
    const CScript discarded_leaf = BuildP2MRMultiAScript(1, {discarded_pubkey_a, discarded_pubkey_b});

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, ScriptBytes(discarded_leaf), P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, ScriptBytes(selected_leaf), P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());

    FlatSigningProvider provider;
    AddPQCSigningKey(provider, selected_key);
    AddPQCSigningKey(provider, discarded_key_a);
    AddPQCSigningKey(provider, discarded_key_b);
    provider.mr_trees.emplace(output, builder);

    std::map<CPQCPubKey, int> counter_advances;
    provider.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t new_counter) {
        BOOST_CHECK_EQUAL(new_counter, previous_counter + 1);
        ++counter_advances[seen_pubkey];
    };

    SignatureData sigdata;
    sigdata.p2mr_spenddata = builder.GetP2MRSpendData();
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_REQUIRE_MESSAGE(ProduceP2MRSignature(provider, script_pubkey, sigdata, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(counter_advances[selected_pubkey], 1);
    BOOST_CHECK_EQUAL(counter_advances[discarded_pubkey_a], 0);
    BOOST_CHECK_EQUAL(counter_advances[discarded_pubkey_b], 0);
    BOOST_REQUIRE_GE(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(sigdata.scriptWitness.stack.at(sigdata.scriptWitness.stack.size() - 2) == ScriptBytes(selected_leaf));
}

BOOST_AUTO_TEST_CASE(p2mr_threshold_signing_uses_only_needed_counters)
{
    CPQCKey key_a;
    CPQCKey key_b;
    CPQCKey key_c;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    key_c.MakeNewKey();

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    const CPQCPubKey pubkey_c = key_c.GetPubKey();
    const CScript leaf_script = BuildP2MRMultiAScript(2, {pubkey_a, pubkey_b, pubkey_c});

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ScriptBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());

    FlatSigningProvider provider;
    AddPQCSigningKey(provider, key_a);
    AddPQCSigningKey(provider, key_b);
    AddPQCSigningKey(provider, key_c);
    provider.mr_trees.emplace(output, builder);

    std::map<CPQCPubKey, int> counter_advances;
    provider.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t new_counter) {
        BOOST_CHECK_EQUAL(new_counter, previous_counter + 1);
        ++counter_advances[seen_pubkey];
    };

    SignatureData sigdata;
    sigdata.p2mr_spenddata = builder.GetP2MRSpendData();
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_REQUIRE_MESSAGE(ProduceP2MRSignature(provider, script_pubkey, sigdata, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(counter_advances[pubkey_a] + counter_advances[pubkey_b] + counter_advances[pubkey_c], 2);
    BOOST_CHECK_EQUAL(CountNonEmptyP2MRSignatureItems(sigdata.scriptWitness, /*pubkey_count=*/3), 2U);
}

BOOST_AUTO_TEST_CASE(p2mr_signing_falls_back_to_other_keys_in_selected_leaf)
{
    CPQCKey key_a;
    CPQCKey key_b;
    CPQCKey key_c;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    key_c.MakeNewKey();

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    const CPQCPubKey pubkey_c = key_c.GetPubKey();
    const CScript leaf_script = BuildP2MRMultiAScript(2, {pubkey_a, pubkey_b, pubkey_c});

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ScriptBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());

    RuntimeFailPQCSigningProvider signing_provider;
    AddPQCSigningKey(signing_provider.provider, key_a);
    AddPQCSigningKey(signing_provider.provider, key_b);
    AddPQCSigningKey(signing_provider.provider, key_c);
    signing_provider.provider.mr_trees.emplace(output, builder);
    signing_provider.failing_pubkeys.insert(pubkey_c);

    SignatureData sigdata;
    sigdata.p2mr_spenddata = builder.GetP2MRSpendData();
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_REQUIRE_MESSAGE(ProduceP2MRSignature(signing_provider, script_pubkey, sigdata, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[pubkey_c], 1);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[pubkey_b], 1);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[pubkey_a], 1);
    BOOST_CHECK_EQUAL(CountNonEmptyP2MRSignatureItems(sigdata.scriptWitness, /*pubkey_count=*/3), 2U);
}

BOOST_AUTO_TEST_CASE(p2mr_signing_retries_other_leaves_after_runtime_failure)
{
    CPQCKey failing_key;
    CPQCKey backup_key_a;
    CPQCKey backup_key_b;
    failing_key.MakeNewKey();
    backup_key_a.MakeNewKey();
    backup_key_b.MakeNewKey();

    const CPQCPubKey failing_pubkey = failing_key.GetPubKey();
    const CPQCPubKey backup_pubkey_a = backup_key_a.GetPubKey();
    const CPQCPubKey backup_pubkey_b = backup_key_b.GetPubKey();
    const CScript failing_leaf = BuildP2MRPkScript(failing_pubkey);
    const CScript backup_leaf = BuildP2MRMultiAScript(1, {backup_pubkey_a, backup_pubkey_b});

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, ScriptBytes(failing_leaf), P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, ScriptBytes(backup_leaf), P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());

    RuntimeFailPQCSigningProvider signing_provider;
    AddPQCSigningKey(signing_provider.provider, failing_key);
    AddPQCSigningKey(signing_provider.provider, backup_key_a);
    AddPQCSigningKey(signing_provider.provider, backup_key_b);
    signing_provider.provider.mr_trees.emplace(output, builder);
    signing_provider.failing_pubkeys.insert(failing_pubkey);

    SignatureData sigdata;
    sigdata.p2mr_spenddata = builder.GetP2MRSpendData();
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_REQUIRE_MESSAGE(ProduceP2MRSignature(signing_provider, script_pubkey, sigdata, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[failing_pubkey], 1);
    BOOST_CHECK_EQUAL(signing_provider.sign_attempts[backup_pubkey_a] + signing_provider.sign_attempts[backup_pubkey_b], 1);
    BOOST_REQUIRE_GE(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK(sigdata.scriptWitness.stack.at(sigdata.scriptWitness.stack.size() - 2) == ScriptBytes(backup_leaf));
}

BOOST_AUTO_TEST_CASE(p2mr_dummy_creator_builds_dummy_witness_without_private_keys)
{
    CPQCKey key;
    key.MakeNewKey();

    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = BuildP2MRPkScript(pubkey);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, ScriptBytes(leaf_script), P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pubkey = BuildP2MRScriptPubKey(output.GetMerkleRoot());

    SignatureData sigdata;
    sigdata.p2mr_spenddata = builder.GetP2MRSpendData();
    BOOST_REQUIRE(ProduceSignature(DUMMY_SIGNING_PROVIDER, DUMMY_SIGNATURE_CREATOR, script_pubkey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 3U);
    BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack.at(0).size(), P2MR_V1_MAX_SIGNATURE_ITEM_SIZE);
    BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack.at(0).back(), SIGHASH_ALL);
    BOOST_CHECK(sigdata.scriptWitness.stack.at(1) == ScriptBytes(leaf_script));
}

BOOST_AUTO_TEST_CASE(p2mr_valid_single_leaf_op_true)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL}, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_fixed_single_leaf_vector)
{
    static constexpr const char* LEAF_SCRIPT_HEX{"51"};
    static constexpr const char* CONTROL_HEX{"c1"};
    static constexpr const char* LEAF_HASH_HEX{"5c4bb09e52c01be092fe020458a377ba81f004203e232a808f562e248827c7a0"};
    static constexpr const char* SCRIPT_PUBKEY_HEX{"52205c4bb09e52c01be092fe020458a377ba81f004203e232a808f562e248827c7a0"};

    const CScript leaf_script = ScriptFromHex(LEAF_SCRIPT_HEX);
    const CScript script_pubkey = ScriptFromHex(SCRIPT_PUBKEY_HEX);
    const valtype control_block = ParseHexBytes(CONTROL_HEX);
    const uint256 expected_leaf_hash = Uint256FromHexBytes(LEAF_HASH_HEX);

    BOOST_CHECK_EQUAL(HexStr(ScriptBytes(leaf_script)), LEAF_SCRIPT_HEX);
    BOOST_CHECK_EQUAL(HexStr(ScriptBytes(script_pubkey)), SCRIPT_PUBKEY_HEX);
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script)))), LEAF_HASH_HEX);
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(ComputeP2MRMerkleRoot(control_block, expected_leaf_hash))), LEAF_HASH_HEX);

    const P2MRSpendContext spend = BuildP2MRSpend(script_pubkey, leaf_script, /*stack_items=*/{}, control_block);
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    auto check_witness_program_mismatch = [](const P2MRSpendContext& spend) {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    };

    check_witness_program_mismatch(BuildP2MRSpend(
        script_pubkey,
        /*leaf_script=*/ScriptFromHex("00"),
        /*stack_items=*/{},
        control_block));

    check_witness_program_mismatch(BuildP2MRSpend(
        script_pubkey,
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/ParseHexBytes("c3")));

    check_witness_program_mismatch(BuildP2MRSpend(
        script_pubkey,
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/ParseHexBytes(
            "c1"
            "0000000000000000000000000000000000000000000000000000000000000000")));

    CScript mutated_script_pubkey{script_pubkey};
    mutated_script_pubkey.back() ^= 0x01;
    check_witness_program_mismatch(BuildP2MRSpend(
        mutated_script_pubkey,
        leaf_script,
        /*stack_items=*/{},
        control_block));
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_key_path_spend)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const CScript script_pubkey = BuildP2MRScriptPubKey(program_root);
    const CTransaction tx_credit{BuildCreditingTransaction(script_pubkey, /*nValue=*/1000)};

    CScriptWitness witness;
    witness.stack.push_back(valtype{0x01});
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, witness, tx_credit);

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});
    const P2MRSpendContext spend{tx_credit, tx_spend, txdata};

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_wrong_control_size)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL, 0x00}, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_empty_control_block)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, /*control_block=*/{}, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_accepts_max_control_path_length)
{
    const CScript leaf_script = CScript{} << OP_TRUE;

    // Maximal valid control block: 1 control byte + 128 merkle-path nodes.
    std::vector<unsigned char> control_block(P2MR_CONTROL_MAX_SIZE, 0x00);
    control_block[0] = P2MR_LEAF_VERSION_V1_CONTROL;

    const uint256 tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));
    const uint256 program_root = ComputeP2MRMerkleRoot(control_block, tapleaf_hash);
    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, control_block, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_control_block_larger_than_max)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    // Exceed the max while preserving the 1 + 32*n size shape.
    std::vector<unsigned char> control_block(P2MR_CONTROL_MAX_SIZE + P2MR_CONTROL_NODE_SIZE, 0x00);
    control_block[0] = P2MR_LEAF_VERSION_V1_CONTROL;

    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, control_block, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_control_block_one_byte_larger_than_max)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    std::vector<unsigned char> control_block(P2MR_CONTROL_MAX_SIZE + 1, 0x00);
    control_block[0] = P2MR_LEAF_VERSION_V1_CONTROL;

    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, control_block, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_control_byte_without_required_bit)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script, /*stack_items=*/{}, /*control_block=*/{P2MR_LEAF_VERSION_V1}, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_CONTROL_BIT0);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_commitment_mismatch)
{
    const CScript leaf_script_committed = CScript{} << OP_TRUE;
    const CScript leaf_script_spent = CScript{} << OP_FALSE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script_committed);

    const P2MRSpendContext spend = BuildP2MRSpend(leaf_script_spent, /*stack_items=*/{}, /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL}, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2mr_multi_leaf_merkle_path_verifies)
{
    const CScript left_leaf = CScript{} << OP_TRUE;
    const CScript right_leaf = CScript{} << OP_FALSE;

    const uint256 left_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(left_leaf));
    const uint256 right_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(right_leaf));
    const uint256 program_root = ComputeP2MRBranchHash(left_hash, right_hash);

    std::vector<unsigned char> control_block{P2MR_LEAF_VERSION_V1_CONTROL};
    const std::vector<unsigned char> merkle_sibling = ToByteVector(right_hash);
    control_block.insert(control_block.end(), merkle_sibling.begin(), merkle_sibling.end());

    const P2MRSpendContext spend = BuildP2MRSpend(left_leaf, /*stack_items=*/{}, control_block, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_fixed_two_leaf_branch_vector)
{
    static constexpr const char* LEFT_LEAF_SCRIPT_HEX{"51"};
    static constexpr const char* LEFT_LEAF_HASH_HEX{"5c4bb09e52c01be092fe020458a377ba81f004203e232a808f562e248827c7a0"};
    static constexpr const char* RIGHT_LEAF_HASH_HEX{"fae97225114b26d9ef3e3bea70f90d08fec30d9833c50b23e4a6cf8c33e6b200"};
    static constexpr const char* ROOT_HEX{"a5c90fea49992780b06c4ecb4f5e9a047af3aa6de9161a71636ec69f00049b52"};
    static constexpr const char* SCRIPT_PUBKEY_HEX{"5220a5c90fea49992780b06c4ecb4f5e9a047af3aa6de9161a71636ec69f00049b52"};

    const CScript left_leaf = ScriptFromHex(LEFT_LEAF_SCRIPT_HEX);
    const CScript script_pubkey = ScriptFromHex(SCRIPT_PUBKEY_HEX);
    valtype control_block = ParseHexBytes(
        "c1"
        "fae97225114b26d9ef3e3bea70f90d08fec30d9833c50b23e4a6cf8c33e6b200");
    const uint256 left_leaf_hash = Uint256FromHexBytes(LEFT_LEAF_HASH_HEX);
    const uint256 right_leaf_hash = Uint256FromHexBytes(RIGHT_LEAF_HASH_HEX);

    BOOST_CHECK_EQUAL(HexStr(ToByteVector(ComputeP2MRBranchHash(left_leaf_hash, right_leaf_hash))),
        ROOT_HEX);

    const P2MRSpendContext spend = BuildP2MRSpend(script_pubkey, left_leaf, /*stack_items=*/{}, control_block);
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    control_block.back() ^= 0x01;
    const P2MRSpendContext mutated_branch = BuildP2MRSpend(script_pubkey, left_leaf, /*stack_items=*/{}, control_block);
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!VerifySpend(mutated_branch, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2mr_tree_hash_domain_differs_from_taproot)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 tap_leaf_hash = ComputeTapleafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));
    const uint256 p2mr_leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));
    BOOST_CHECK(tap_leaf_hash != p2mr_leaf_hash);

    const uint256 tap_branch_hash = ComputeTapbranchHash(tap_leaf_hash, tap_leaf_hash);
    const uint256 p2mr_branch_hash = ComputeP2MRBranchHash(p2mr_leaf_hash, p2mr_leaf_hash);
    BOOST_CHECK(tap_branch_hash != p2mr_branch_hash);
}

BOOST_AUTO_TEST_CASE(p2mr_merkle_path_verifies_when_spent_leaf_hash_sorts_after_sibling)
{
    const CScript first_leaf = CScript{} << OP_TRUE;
    const CScript second_leaf = CScript{} << OP_TRUE << OP_NOP;

    const uint256 first_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(first_leaf));
    const uint256 second_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(second_leaf));
    const bool first_less = std::lexicographical_compare(first_hash.begin(), first_hash.end(), second_hash.begin(), second_hash.end());

    const CScript& spent_leaf = first_less ? second_leaf : first_leaf;
    const uint256& sibling_hash = first_less ? first_hash : second_hash;
    const uint256& spent_hash = first_less ? second_hash : first_hash;
    BOOST_CHECK(!std::lexicographical_compare(spent_hash.begin(), spent_hash.end(), sibling_hash.begin(), sibling_hash.end()));

    const uint256 program_root = ComputeP2MRBranchHash(first_hash, second_hash);
    std::vector<unsigned char> control_block{P2MR_LEAF_VERSION_V1_CONTROL};
    const std::vector<unsigned char> merkle_sibling = ToByteVector(sibling_hash);
    control_block.insert(control_block.end(), merkle_sibling.begin(), merkle_sibling.end());

    const P2MRSpendContext spend = BuildP2MRSpend(spent_leaf, /*stack_items=*/{}, control_block, program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_reserved_leaf_versions_policy_flag)
{
    // Include a valid masked leaf version outside the named constants to lock in
    // the intended "all unknown even leaf versions" upgrade-hook behavior.
    constexpr uint8_t ARBITRARY_UNKNOWN_LEAF_VERSION{0x8e};
    static_assert(IsValidP2MRLeafVersion(ARBITRARY_UNKNOWN_LEAF_VERSION));
    static_assert(ARBITRARY_UNKNOWN_LEAF_VERSION != P2MR_LEAF_VERSION_V1);
    static_assert(!IsReservedP2MRLeafVersion(ARBITRARY_UNKNOWN_LEAF_VERSION));
    static_assert(ARBITRARY_UNKNOWN_LEAF_VERSION != P2MR_LEAF_VERSION_RESERVED_1);
    static_assert(ARBITRARY_UNKNOWN_LEAF_VERSION != P2MR_LEAF_VERSION_RESERVED_2);
    static_assert(ARBITRARY_UNKNOWN_LEAF_VERSION != P2MR_LEAF_VERSION_RESERVED_3);

    constexpr std::array<uint8_t, 6> UPGRADABLE_LEAF_VERSIONS{
        P2MR_LEAF_VERSION_RESERVED_1,
        P2MR_LEAF_VERSION_RESERVED_2,
        P2MR_LEAF_VERSION_RESERVED_3,
        P2MR_LEAF_VERSION_EXPERIMENTAL_FIRST,
        P2MR_LEAF_VERSION_EXTENSION,
        ARBITRARY_UNKNOWN_LEAF_VERSION,
    };

    const CScript leaf_script = CScript{} << OP_TRUE;
    for (const uint8_t leaf_version : UPGRADABLE_LEAF_VERSIONS) {
        const uint256 program_root = ComputeMerkleRootSingleLeaf(leaf_version, leaf_script);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            // The 0xc0 stack-item envelope is v1-specific; reserved leaves keep
            // their own future resource model until activation defines one.
            /*stack_items=*/{std::vector<unsigned char>(MAX_P2MR_V1_STACK_ITEM_SIZE + 1, 0x42)},
            /*control_block=*/{static_cast<unsigned char>(leaf_version | 1)},
            program_root);

        {
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        }

        {
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION);
        }
    }
}

BOOST_AUTO_TEST_CASE(p2mr_future_even_leaf_version_uses_masked_control_byte)
{
    static constexpr uint8_t FUTURE_LEAF_VERSION{0xfe};
    const CScript leaf_script = CScript{} << OP_FALSE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(FUTURE_LEAF_VERSION, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/{static_cast<unsigned char>(FUTURE_LEAF_VERSION | 1)},
        program_root);

    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_accepts_valid_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
    BOOST_CHECK_EQUAL(signature_counter, 1U);

    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_accepts_independent_witness_vector)
{
    const P2MRWitnessVector vector{LoadIndependentP2MRWitnessVector()};
    const CScript leaf_script{vector.leaf_script.begin(), vector.leaf_script.end()};
    const PrecomputedTransactionData txdata{
        PrecomputeVectorData(vector.spend_tx, vector.prevout_script_pubkey, vector.prevout_amount)};

    BOOST_CHECK_EQUAL(
        HexStr(ToByteVector((HashWriter{HASHER_P2MR_SIGHASH} << std::span<const uint8_t>{vector.p2mr_sigmsg}).GetSHA256())),
        HexStr(ToByteVector(vector.p2mr_sighash)));
    BOOST_CHECK_EQUAL(
        HexStr(ToByteVector((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{vector.p2mr_sigmsg}).GetSHA256())),
        HexStr(ToByteVector(vector.wrong_domain_sighash)));

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        vector.spend_tx,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        txdata,
        MissingDataBehavior::ASSERT_FAIL));
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(sighash)), HexStr(ToByteVector(vector.p2mr_sighash)));
    BOOST_REQUIRE(vector.pubkey.Verify(vector.p2mr_sighash, vector.signature));

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyVectorSpend(vector.spend_tx, vector.prevout_script_pubkey, vector.prevout_amount, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_independent_witness_vector_near_misses)
{
    static constexpr uint8_t INVALID_SIGHASH_TYPE{0x04};

    const P2MRWitnessVector vector{LoadIndependentP2MRWitnessVector()};
    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_REQUIRE(VerifyVectorSpend(vector.spend_tx, vector.prevout_script_pubkey, vector.prevout_amount, err));
        BOOST_REQUIRE_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[0].scriptWitness.stack[0][0] ^= 0x01;
        CheckVectorMutationFails(vector, tx, vector.prevout_script_pubkey, SCRIPT_ERR_P2MR_SIG);
    }

    BOOST_REQUIRE(vector.pubkey.Verify(vector.wrong_domain_sighash, vector.wrong_domain_signature));
    BOOST_REQUIRE(!vector.pubkey.Verify(vector.p2mr_sighash, vector.wrong_domain_signature));
    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[0].scriptWitness.stack[0] = vector.wrong_domain_signature;
        CheckVectorMutationFails(vector, tx, vector.prevout_script_pubkey, SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[0].scriptWitness.stack[0].push_back(SIGHASH_DEFAULT);
        CheckVectorMutationFails(vector, tx, vector.prevout_script_pubkey, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[0].scriptWitness.stack[0].push_back(INVALID_SIGHASH_TYPE);
        CheckVectorMutationFails(vector, tx, vector.prevout_script_pubkey, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[0].scriptWitness.stack[1][1] ^= 0x01;
        CheckVectorMutationFails(vector, tx, vector.prevout_script_pubkey, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[0].scriptWitness.stack[1] = vector.wrong_pubkey_leaf_script;
        CheckVectorMutationFails(vector, tx, vector.wrong_pubkey_script_pubkey, SCRIPT_ERR_P2MR_SIG);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_legacy_checksig_with_valid_pqc_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKSIG;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    std::vector<unsigned char> sig;
    SignP2MRLeaf(key, leaf_script, spend, sig);
    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_CHECKSIG);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_legacy_checksigverify_with_valid_pqc_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKSIGVERIFY << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    std::vector<unsigned char> sig;
    SignP2MRLeaf(key, leaf_script, spend, sig);
    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_CHECKSIG);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_verify_form_accepts_valid_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKSIGPQC << OP_VERIFY << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    std::vector<unsigned char> sig;
    SignP2MRLeaf(key, leaf_script, spend, sig);
    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigadd_accepts_valid_multi_a_spend)
{
    CPQCKey key_a;
    CPQCKey key_b;
    CPQCKey key_c;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    key_c.MakeNewKey();

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    const CPQCPubKey pubkey_c = key_c.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());
    BOOST_REQUIRE(pubkey_c.IsValid());

    const CScript leaf_script = BuildP2MRMultiAScript(2, {pubkey_a, pubkey_b, pubkey_c});
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{valtype{}, std::vector<unsigned char>(PQC_SIG_SIZE, 0x00), std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    std::vector<unsigned char> sig_a;
    std::vector<unsigned char> sig_b;
    SignP2MRLeaf(key_a, leaf_script, spend, sig_a);
    SignP2MRLeaf(key_b, leaf_script, spend, sig_b);
    spend.tx_spend.vin[0].scriptWitness.stack[1] = sig_b;
    spend.tx_spend.vin[0].scriptWitness.stack[2] = sig_a;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_accepts_explicit_hashtype)
{
    static constexpr uint8_t EXPLICIT_HASHTYPE{SIGHASH_ALL};

    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        EXPLICIT_HASHTYPE,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
    BOOST_CHECK_EQUAL(signature_counter, 1U);

    sig.push_back(EXPLICIT_HASHTYPE);
    BOOST_REQUIRE_EQUAL(sig.size(), PQC_SIG_SIZE + 1);
    uint8_t hashtype;
    BOOST_REQUIRE(GetP2MRSignatureHashType(sig, hashtype));
    BOOST_CHECK_EQUAL(hashtype, EXPLICIT_HASHTYPE);

    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_create_pqc_signature_uses_canonical_size)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(MutableTransactionSignatureCreator(
        spend.tx_spend,
        /*input_idx=*/0,
        spend.tx_credit.vout[0].nValue,
        &spend.txdata,
        SIGHASH_DEFAULT)
        .CreatePQCSignature(provider, sig, pubkey, &leaf_hash, SigVersion::P2MR));
    BOOST_REQUIRE_EQUAL(sig.size(), PQC_SIG_SIZE);
    uint8_t hashtype;
    BOOST_REQUIRE(GetP2MRSignatureHashType(sig, hashtype));
    BOOST_CHECK_EQUAL(hashtype, SIGHASH_DEFAULT);

    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_sighash_domain_is_p2mr_specific)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    uint256 p2mr_hash;
    ScriptExecutionData p2mr_execdata = BuildExecData(leaf_script);
    BOOST_REQUIRE(SignatureHashP2MR(
        p2mr_hash,
        p2mr_execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint256 tapscript_hash;
    ScriptExecutionData tapscript_execdata = BuildExecData(leaf_script);
    tapscript_execdata.m_tapleaf_hash = ComputeTapleafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));
    BOOST_REQUIRE(SignatureHashSchnorr(
        tapscript_hash,
        tapscript_execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        SigVersion::TAPSCRIPT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    BOOST_CHECK(p2mr_hash != tapscript_hash);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_accepts_valid_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x42)};
    const CScript leaf_script = BuildP2MRDataSigScript(pubkey, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{SignDataSigPQC(key, msg_hash)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_accepts_witness_supplied_message_hash)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x49)};
    const CScript leaf_script = CScript{} << PQCPubKeyBytes(pubkey) << OP_CHECKDATASIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const valtype sig{SignDataSigPQC(key, msg_hash)};

    {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{sig, msg_hash},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{sig, DataSigMessageHash(0x4a)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_opcode_name_is_p2mr_only)
{
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKTEMPLATEVERIFY), "OP_CHECKTEMPLATEVERIFY");
    CScript ctv_script;
    ctv_script << OP_CHECKTEMPLATEVERIFY;
    BOOST_CHECK(!ctv_script.HasValidOps());
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_byte_is_bad_opcode_in_base_script)
{
    const CScript script_pubkey = CScript{} << OP_CHECKTEMPLATEVERIFY;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyBaseScript(script_pubkey, SCRIPT_VERIFY_P2SH, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_byte_remains_op_success_in_taproot)
{
    static constexpr unsigned int TAPROOT_SCRIPT_VERIFY_FLAGS{
        SCRIPT_VERIFY_P2SH |
        SCRIPT_VERIFY_WITNESS |
        SCRIPT_VERIFY_TAPROOT
    };

    const CScript leaf_script = CScript{} << OP_CHECKTEMPLATEVERIFY << OP_FALSE;
    const TaprootSpendContext spend = BuildTaprootScriptPathSpend(leaf_script);

    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifyTaprootSpend(spend, TAPROOT_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }
    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifyTaprootSpend(spend, TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_accepts_matching_template_hash)
{
    const P2MRSpendContext spend = BuildCTVSpendWithComputedHash();

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_fixed_spend_vector)
{
    static constexpr const char* CONTROL_HEX{"c1"};
    static constexpr const char* CTV_HASH_HEX{"6597328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28ac"};
    static constexpr const char* LEAF_SCRIPT_HEX{"206597328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28acbb"};
    static constexpr const char* ROOT_HEX{"7efd262261fb0e7917e65f9ba628fa12549527ec1649173648e6e637cfd017ac"};
    static constexpr const char* SCRIPT_PUBKEY_HEX{"52207efd262261fb0e7917e65f9ba628fa12549527ec1649173648e6e637cfd017ac"};
    static constexpr const char* WRONG_LEAF_SCRIPT_HEX{"206497328251a37cb785454f8315b503cefb55e79383bbb6b361c7ed0aa36c28acbb"};
    static constexpr const char* WRONG_SCRIPT_PUBKEY_HEX{"522093e9c5f8a9170f35989d4c55ec190d356e79743ac59d3428fedde4ddfe79b2e1"};

    const CScript leaf_script = ScriptFromHex(LEAF_SCRIPT_HEX);
    const CScript script_pubkey = ScriptFromHex(SCRIPT_PUBKEY_HEX);
    const valtype control_block = ParseHexBytes(CONTROL_HEX);

    BOOST_CHECK_EQUAL(HexStr(ScriptBytes(leaf_script)), LEAF_SCRIPT_HEX);
    BOOST_CHECK_EQUAL(HexStr(ScriptBytes(script_pubkey)), SCRIPT_PUBKEY_HEX);
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script)))), ROOT_HEX);

    P2MRSpendContext spend = BuildP2MRSpend(script_pubkey, leaf_script, /*stack_items=*/{}, control_block);
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(GetDefaultCheckTemplateVerifyHash(spend.tx_spend, /*input_index=*/0, spend.txdata))), CTV_HASH_HEX);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    const P2MRSpendContext wrong_ctv_hash = BuildP2MRSpend(
        ScriptFromHex(WRONG_SCRIPT_PUBKEY_HEX),
        ScriptFromHex(WRONG_LEAF_SCRIPT_HEX),
        /*stack_items=*/{},
        control_block);
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!VerifySpend(wrong_ctv_hash, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);

    ++spend.tx_spend.nLockTime;
    RefreshSpendTxData(spend);
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_empty_signature_returns_false)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x43)};
    const CScript leaf_script = CScript{} << msg_hash << PQCPubKeyBytes(pubkey) << OP_CHECKDATASIGPQC << OP_NOT;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{valtype{}},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_accepts_repeated_matching_template_hash)
{
    const CScript placeholder_script = CScript{} << ToByteVector(uint256::ZERO) << OP_CHECKTEMPLATEVERIFY << OP_CHECKTEMPLATEVERIFY;
    const P2MRSpendContext placeholder = BuildCTVSpend(placeholder_script);
    const uint256 ctv_hash = GetDefaultCheckTemplateVerifyHash(placeholder.tx_spend, /*input_index=*/0, placeholder.txdata);

    const CScript leaf_script = CScript{} << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY << OP_CHECKTEMPLATEVERIFY;
    const P2MRSpendContext spend = BuildCTVSpend(leaf_script);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_rejects_invalid_nonempty_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x44)};
    const CScript leaf_script = BuildP2MRDataSigScript(pubkey, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    valtype sig{SignDataSigPQC(key, msg_hash)};
    BOOST_REQUIRE(!sig.empty());
    sig[0] ^= 0x01;

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{sig},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_rejects_signature_size_boundaries)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x45)};
    const CScript leaf_script = BuildP2MRDataSigScript(pubkey, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    for (const size_t sig_size : {
        static_cast<size_t>(PQC_SIG_SIZE - 1),
        static_cast<size_t>(PQC_SIG_SIZE + 1),
    }) {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{valtype(sig_size, 0x01)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_rejects_message_hash_size_boundaries)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    for (const size_t msg_hash_size : {31U, 33U}) {
        const valtype msg_hash(msg_hash_size, 0x46);
        const CScript leaf_script = BuildP2MRDataSigScript(pubkey, msg_hash);
        const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{valtype(PQC_SIG_SIZE, 0x01)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_rejects_pubkey_size_boundaries)
{
    const valtype msg_hash{DataSigMessageHash(0x47)};

    for (const size_t pubkey_size : {0U, 31U, 33U}) {
        const CScript leaf_script = CScript{} << msg_hash << valtype(pubkey_size, 0x02) << OP_CHECKDATASIGPQC;
        const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{valtype(PQC_SIG_SIZE, 0x01)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_uses_data_signature_domain)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x48)};
    const CScript leaf_script = BuildP2MRDataSigScript(pubkey, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{SignDataSigPQC(key, msg_hash)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{SignRawMessageHash(key, msg_hash)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG);
    }

    {
        P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{valtype(PQC_SIG_SIZE, 0x00)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptExecutionData execdata = BuildExecData(leaf_script);
        uint256 tx_sighash;
        BOOST_REQUIRE(SignatureHashP2MR(
            tx_sighash,
            execdata,
            spend.tx_spend,
            /*in_pos=*/0,
            SIGHASH_DEFAULT,
            spend.txdata,
            MissingDataBehavior::ASSERT_FAIL));

        uint32_t signature_counter{0};
        valtype tx_sig;
        BOOST_REQUIRE(key.Sign(tx_sighash, tx_sig, signature_counter));
        BOOST_CHECK_EQUAL(signature_counter, 1U);
        spend.tx_spend.vin[0].scriptWitness.stack[0] = tx_sig;

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_accepts_n_of_n)
{
    CPQCKey key_a;
    CPQCKey key_b;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    BOOST_REQUIRE(key_a.IsValid());
    BOOST_REQUIRE(key_b.IsValid());

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x49)};
    const CScript leaf_script = BuildP2MRDataSigAddScript(2, {pubkey_a, pubkey_b}, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{SignDataSigPQC(key_b, msg_hash), SignDataSigPQC(key_a, msg_hash)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_accepts_m_of_n_with_empty_skip)
{
    CPQCKey key_a;
    CPQCKey key_b;
    CPQCKey key_c;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    key_c.MakeNewKey();
    BOOST_REQUIRE(key_a.IsValid());
    BOOST_REQUIRE(key_b.IsValid());
    BOOST_REQUIRE(key_c.IsValid());

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    const CPQCPubKey pubkey_c = key_c.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());
    BOOST_REQUIRE(pubkey_c.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x4a)};
    const CScript leaf_script = BuildP2MRDataSigAddScript(2, {pubkey_a, pubkey_b, pubkey_c}, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{SignDataSigPQC(key_c, msg_hash), valtype{}, SignDataSigPQC(key_a, msg_hash)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_threshold_failure_is_false)
{
    CPQCKey key_a;
    CPQCKey key_b;
    CPQCKey key_c;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    key_c.MakeNewKey();
    BOOST_REQUIRE(key_a.IsValid());
    BOOST_REQUIRE(key_b.IsValid());
    BOOST_REQUIRE(key_c.IsValid());

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    const CPQCPubKey pubkey_c = key_c.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());
    BOOST_REQUIRE(pubkey_c.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x4b)};
    const CScript leaf_script = BuildP2MRDataSigAddScript(2, {pubkey_a, pubkey_b, pubkey_c}, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{valtype{}, valtype{}, SignDataSigPQC(key_a, msg_hash)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_rejects_invalid_nonempty_signature)
{
    CPQCKey key_a;
    CPQCKey key_b;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    BOOST_REQUIRE(key_a.IsValid());
    BOOST_REQUIRE(key_b.IsValid());

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x4c)};
    const CScript leaf_script = BuildP2MRDataSigAddScript(2, {pubkey_a, pubkey_b}, msg_hash);
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    valtype sig_b{SignDataSigPQC(key_b, msg_hash)};
    BOOST_REQUIRE(!sig_b.empty());
    sig_b[0] ^= 0x01;

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{sig_b, SignDataSigPQC(key_a, msg_hash)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_rejects_stack_underflow)
{
    const CScript leaf_script = CScript{} << OP_CHECKDATASIGADDPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_rejects_mismatched_template_hash)
{
    const P2MRSpendContext matching_spend = BuildCTVSpendWithComputedHash();
    std::vector<unsigned char> wrong_hash_bytes = ToByteVector(GetDefaultCheckTemplateVerifyHash(
        matching_spend.tx_spend,
        /*input_index=*/0,
        matching_spend.txdata));
    wrong_hash_bytes[0] ^= 0x01;

    const uint256 wrong_hash{std::span<const unsigned char>{wrong_hash_bytes}};
    const P2MRSpendContext spend = BuildCTVSpend(BuildCTVScript(wrong_hash));

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_rejects_later_repeated_mismatch)
{
    const CScript placeholder_script = CScript{} << ToByteVector(uint256::ZERO) << OP_CHECKTEMPLATEVERIFY << ToByteVector(uint256::ZERO) << OP_CHECKTEMPLATEVERIFY;
    const P2MRSpendContext placeholder = BuildCTVSpend(placeholder_script);
    const uint256 ctv_hash = GetDefaultCheckTemplateVerifyHash(placeholder.tx_spend, /*input_index=*/0, placeholder.txdata);
    std::vector<unsigned char> wrong_hash_bytes = ToByteVector(ctv_hash);
    wrong_hash_bytes[0] ^= 0x01;
    const uint256 wrong_hash{std::span<const unsigned char>{wrong_hash_bytes}};

    const CScript leaf_script = CScript{} << ToByteVector(ctv_hash) << OP_CHECKTEMPLATEVERIFY << ToByteVector(wrong_hash) << OP_CHECKTEMPLATEVERIFY;
    const P2MRSpendContext spend = BuildCTVSpend(leaf_script);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_rejects_empty_stack)
{
    const CScript leaf_script = CScript{} << OP_CHECKTEMPLATEVERIFY;
    const P2MRSpendContext spend = BuildCTVSpend(leaf_script);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_validation_weight_enforced)
{
    const valtype msg_hash{DataSigMessageHash(0x4d)};
    const valtype pubkey_a(PQC_PUBKEY_SIZE, 0x11);
    const valtype pubkey_b(PQC_PUBKEY_SIZE, 0x22);
    const CScript leaf_script = CScript{}
        << msg_hash << OP_0 << pubkey_a << OP_CHECKDATASIGADDPQC
        << msg_hash << OP_SWAP << pubkey_b << OP_CHECKDATASIGADDPQC
        << OP_2 << OP_EQUAL;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{valtype{0x01}, valtype{0x01}},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(op_checkdatasigpqc_is_bad_opcode_outside_p2mr)
{
    static constexpr unsigned int TAPROOT_SCRIPT_VERIFY_FLAGS{
        SCRIPT_VERIFY_P2SH |
        SCRIPT_VERIFY_WITNESS |
        SCRIPT_VERIFY_TAPROOT
    };

    for (const opcodetype opcode : {OP_CHECKDATASIGPQC, OP_CHECKDATASIGADDPQC}) {
        const CScript datasig_script = CScript{} << opcode << OP_TRUE;
        const valtype datasig_script_bytes = ScriptBytes(datasig_script);

        {
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifyBaseScript(datasig_script, /*flags=*/SCRIPT_VERIFY_P2SH, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
        }

        {
            const CScript p2sh_script_pubkey = GetScriptForDestination(ScriptHash(datasig_script));
            const CScript script_sig = CScript{} << datasig_script_bytes;

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifyInputScript(
                script_sig, p2sh_script_pubkey, CScriptWitness{}, SCRIPT_VERIFY_P2SH, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
        }

        {
            const CScript witness_v0_script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(datasig_script));
            CScriptWitness witness;
            witness.stack.push_back(datasig_script_bytes);

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifyInputScript(
                CScript{}, witness_v0_script_pubkey, witness, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
        }

        {
            const TaprootSpendContext spend = BuildTaprootScriptPathSpend(datasig_script);

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(VerifyTaprootSpend(spend, TAPROOT_SCRIPT_VERIFY_FLAGS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        }

        {
            const TaprootSpendContext spend = BuildTaprootScriptPathSpend(datasig_script);

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifyTaprootSpend(
                spend, TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
        }
    }
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_wrong_length_is_consensus_noop_and_nonstandard)
{
    for (const size_t ctv_arg_size : {31U, 33U}) {
        const CScript leaf_script = CScript{} << std::vector<unsigned char>(ctv_arg_size, 0x01) << OP_CHECKTEMPLATEVERIFY;
        const P2MRSpendContext spend = BuildCTVSpend(leaf_script);

        {
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        }
        {
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
        }
    }
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_commits_to_transaction_fields)
{
    const P2MRSpendContext spend = BuildCTVSpendWithComputedHash();

    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        ++tx.version;
    });
    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        ++tx.nLockTime;
    });
    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        --tx.vin[0].nSequence;
    });
    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        ++tx.vout[0].nValue;
    });
    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1});
    });
    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    });
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_commits_to_output_order)
{
    const P2MRSpendContext spend = BuildCTVSpendWithComputedHash([](CMutableTransaction& tx) {
        tx.vout.emplace_back(1, CScript{} << OP_FALSE);
    });

    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        std::swap(tx.vout[0], tx.vout[1]);
    });
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_commits_to_input_order)
{
    const P2MRSpendContext spend = BuildCTVSpendWithComputedHash([](CMutableTransaction& tx) {
        tx.vin[0].nSequence = 1;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1}, CScript{}, 2);
    });

    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        std::swap(tx.vin[0].prevout, tx.vin[1].prevout);
        std::swap(tx.vin[0].scriptSig, tx.vin[1].scriptSig);
        std::swap(tx.vin[0].nSequence, tx.vin[1].nSequence);
    });
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_default_hash_commits_to_input_index_and_scriptsigs)
{
    CMutableTransaction tx;
    tx.version = 3;
    tx.nLockTime = 17;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, 1);
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1}, CScript{}, 2);
    tx.vout.emplace_back(100, CScript{} << OP_TRUE);

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_CHECK(txdata.m_ctv_ready);
    BOOST_CHECK(!txdata.m_ctv_has_nonempty_script_sigs);
    BOOST_CHECK(GetDefaultCheckTemplateVerifyHash(tx, 0, txdata) != GetDefaultCheckTemplateVerifyHash(tx, 1, txdata));

    CMutableTransaction with_scriptsig{tx};
    with_scriptsig.vin[1].scriptSig = CScript{} << std::vector<unsigned char>{0x01, 0x02};
    PrecomputedTransactionData with_scriptsig_data;
    with_scriptsig_data.Init(with_scriptsig, {}, /*force=*/true);
    BOOST_CHECK(with_scriptsig_data.m_ctv_ready);
    BOOST_CHECK(with_scriptsig_data.m_ctv_has_nonempty_script_sigs);
    BOOST_CHECK(GetDefaultCheckTemplateVerifyHash(tx, 0, txdata) != GetDefaultCheckTemplateVerifyHash(with_scriptsig, 0, with_scriptsig_data));

    CMutableTransaction mutated_scriptsig{with_scriptsig};
    mutated_scriptsig.vin[1].scriptSig = CScript{} << std::vector<unsigned char>{0x01, 0x03};
    PrecomputedTransactionData mutated_scriptsig_data;
    mutated_scriptsig_data.Init(mutated_scriptsig, {}, /*force=*/true);
    BOOST_CHECK(GetDefaultCheckTemplateVerifyHash(with_scriptsig, 0, with_scriptsig_data) != GetDefaultCheckTemplateVerifyHash(mutated_scriptsig, 0, mutated_scriptsig_data));
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_default_hash_reference_vectors)
{
    CMutableTransaction tx;
    tx.version = 3;
    tx.nLockTime = 17;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, 0xfffffffe);
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1}, CScript{}, 42);
    tx.vout.emplace_back(123456789, CScript{} << OP_TRUE);
    tx.vout.emplace_back(987654321, CScript{} << std::vector<unsigned char>{0x02, 0x03, 0x04});

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {}, /*force=*/true);
    BOOST_CHECK(txdata.m_ctv_ready);
    BOOST_CHECK(!txdata.m_ctv_has_nonempty_script_sigs);
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(GetDefaultCheckTemplateVerifyHash(tx, 0, txdata))), "4bd687b4313aaf7c5b807ec5ee6940e3a1cac9c63143e91e212a74865d6069df");
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(GetDefaultCheckTemplateVerifyHash(tx, 1, txdata))), "e34cbaa6054ea4f142b1b89e4839d031cfe95aeb284c974c73118be77e682dd9");

    CMutableTransaction with_scriptsig{tx};
    with_scriptsig.vin[1].scriptSig = CScript{} << std::vector<unsigned char>{0xaa, 0xbb, 0xcc};
    PrecomputedTransactionData with_scriptsig_data;
    with_scriptsig_data.Init(with_scriptsig, {}, /*force=*/true);
    BOOST_CHECK(with_scriptsig_data.m_ctv_ready);
    BOOST_CHECK(with_scriptsig_data.m_ctv_has_nonempty_script_sigs);
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(GetDefaultCheckTemplateVerifyHash(with_scriptsig, 0, with_scriptsig_data))), "edcdcb08373d2c0f30d5342c81e0d7b19b954e23748531a48357f6fa5c63af99");
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(GetDefaultCheckTemplateVerifyHash(with_scriptsig, 1, with_scriptsig_data))), "cb13fcd1e83bca2a1f77061ad356da7658447be753a8e97d9c66967c90dc334b");
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_with_checksigpqc_accepts_valid_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript placeholder_script = BuildCTVAndPQCChecksigScript(uint256::ZERO, pubkey);
    P2MRSpendContext placeholder = BuildCTVSpend(placeholder_script, {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)});
    const uint256 ctv_hash = GetDefaultCheckTemplateVerifyHash(placeholder.tx_spend, /*input_index=*/0, placeholder.txdata);

    const CScript leaf_script = BuildCTVAndPQCChecksigScript(ctv_hash, pubkey);
    P2MRSpendContext spend = BuildCTVSpend(leaf_script, {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)});

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
    BOOST_CHECK_EQUAL(signature_counter, 1U);

    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_with_checkdatasigaddpqc_accepts_valid_threshold)
{
    CPQCKey key_a;
    CPQCKey key_b;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    BOOST_REQUIRE(key_a.IsValid());
    BOOST_REQUIRE(key_b.IsValid());

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x4e)};
    const CScript placeholder_script = BuildCTVAndDataSigAddScript(uint256::ZERO, 2, {pubkey_a, pubkey_b}, msg_hash);
    const P2MRSpendContext placeholder = BuildCTVSpend(placeholder_script);
    const uint256 ctv_hash = GetDefaultCheckTemplateVerifyHash(placeholder.tx_spend, /*input_index=*/0, placeholder.txdata);

    const CScript leaf_script = BuildCTVAndDataSigAddScript(ctv_hash, 2, {pubkey_a, pubkey_b}, msg_hash);
    const P2MRSpendContext spend = BuildCTVSpend(leaf_script, {SignDataSigPQC(key_b, msg_hash), SignDataSigPQC(key_a, msg_hash)});

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_ctv_with_checkdatasigaddpqc_rejects_template_mismatch)
{
    CPQCKey key_a;
    CPQCKey key_b;
    key_a.MakeNewKey();
    key_b.MakeNewKey();
    BOOST_REQUIRE(key_a.IsValid());
    BOOST_REQUIRE(key_b.IsValid());

    const CPQCPubKey pubkey_a = key_a.GetPubKey();
    const CPQCPubKey pubkey_b = key_b.GetPubKey();
    BOOST_REQUIRE(pubkey_a.IsValid());
    BOOST_REQUIRE(pubkey_b.IsValid());

    const valtype msg_hash{DataSigMessageHash(0x4f)};
    const CScript placeholder_script = BuildCTVAndDataSigAddScript(uint256::ZERO, 2, {pubkey_a, pubkey_b}, msg_hash);
    const P2MRSpendContext placeholder = BuildCTVSpend(placeholder_script);
    const uint256 ctv_hash = GetDefaultCheckTemplateVerifyHash(placeholder.tx_spend, /*input_index=*/0, placeholder.txdata);

    const CScript leaf_script = BuildCTVAndDataSigAddScript(ctv_hash, 2, {pubkey_a, pubkey_b}, msg_hash);
    P2MRSpendContext spend = BuildCTVSpend(leaf_script, {SignDataSigPQC(key_b, msg_hash), SignDataSigPQC(key_a, msg_hash)});

    CheckCTVMutationFails(spend, [](CMutableTransaction& tx) {
        tx.vout[0].nValue -= 1;
    });
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_invalid_signature)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
    BOOST_REQUIRE(!sig.empty());
    sig[0] ^= 0x01;
    spend.tx_spend.vin[0].scriptWitness.stack[0] = sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_invalid_signature_size)
{
    const std::vector<unsigned char> pubkey(PQC_PUBKEY_SIZE, 0x02);
    const CScript leaf_script = CScript{} << pubkey << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE - 1, 0x01)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_empty_signature)
{
    const std::vector<unsigned char> pubkey(PQC_PUBKEY_SIZE, 0x02);
    const CScript leaf_script = CScript{} << pubkey << OP_CHECKSIGPQC << OP_VERIFY << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{valtype{}},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_oversized_signature)
{
    const std::vector<unsigned char> pubkey(PQC_PUBKEY_SIZE, 0x02);
    const CScript leaf_script = CScript{} << pubkey << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    std::vector<unsigned char> oversized_sig(PQC_SIG_SIZE + 2, 0x00);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{oversized_sig},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_wrong_pubkey_type)
{
    const CScript leaf_script = CScript{} << std::vector<unsigned char>{} << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    // Keep the witness budget above the per-sigop cost so PUBKEYTYPE is reached.
    std::vector<unsigned char> sig(PQC_SIG_SIZE, 0x00);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{sig},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_malformed_pubkey)
{
    const std::vector<unsigned char> malformed_pubkey(33, 0x02);
    const CScript leaf_script = CScript{} << malformed_pubkey << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    std::vector<unsigned char> sig(PQC_SIG_SIZE, 0x00);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{sig},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_non_32_byte_pubkey)
{
    const std::vector<unsigned char> malformed_pubkey(33, 0x02);
    const CScript leaf_script = CScript{} << malformed_pubkey << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
    }

    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_stack_underflow)
{
    const CScript leaf_script = CScript{} << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_sighash_default_byte_suffix)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
    BOOST_CHECK_EQUAL(sig.size(), PQC_SIG_SIZE);

    std::vector<unsigned char> witness_sig{sig};
    witness_sig.push_back(SIGHASH_DEFAULT);
    spend.tx_spend.vin[0].scriptWitness.stack[0] = witness_sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_invalid_sighash_byte_suffix)
{
    static constexpr uint8_t INVALID_SIGHASH_TYPE = 0x04;

    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQCPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptExecutionData execdata = BuildExecData(leaf_script);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashP2MR(
        sighash,
        execdata,
        spend.tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        spend.txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t signature_counter{0};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig, signature_counter));
    BOOST_CHECK_EQUAL(sig.size(), PQC_SIG_SIZE);

    std::vector<unsigned char> witness_sig{sig};
    witness_sig.push_back(INVALID_SIGHASH_TYPE);
    spend.tx_spend.vin[0].scriptWitness.stack[0] = witness_sig;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(p2mr_annex_present_path_succeeds)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);
    spend.tx_spend.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>{static_cast<unsigned char>(ANNEX_TAG), 0x01, 0x02});

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_annex_then_underflow_rejected)
{
    const CScript leaf_script = CScript{} << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    spend.tx_spend.vin[0].scriptWitness.stack = {
        std::vector<unsigned char>{0x01},
        std::vector<unsigned char>{static_cast<unsigned char>(ANNEX_TAG), 0xAA},
    };

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

BOOST_AUTO_TEST_CASE(p2mr_validation_weight_enforced_for_small_witness)
{
    const std::vector<unsigned char> malformed_pubkey_a(33, 0x11);
    const std::vector<unsigned char> malformed_pubkey_b(33, 0x22);

    const CScript leaf_script = CScript{}
        << OP_0
        << malformed_pubkey_a << OP_CHECKSIGADD
        << malformed_pubkey_b << OP_CHECKSIGADD
        << OP_2 << OP_EQUAL;

    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{valtype{0x01}, valtype{0x01}},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(p2mr_initial_stack_item_size_boundary)
{
    const CScript leaf_script = CScript{} << OP_DROP << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    for (const size_t item_size : {
        static_cast<size_t>(MAX_P2MR_V1_STACK_ITEM_SIZE - 1),
        static_cast<size_t>(MAX_P2MR_V1_STACK_ITEM_SIZE),
    }) {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{std::vector<unsigned char>(item_size, 0x01)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{std::vector<unsigned char>(MAX_P2MR_V1_STACK_ITEM_SIZE + 1, 0x01)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_initial_stack_total_bytes_boundary)
{
    for (const size_t total_bytes : {
        static_cast<size_t>(MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES - 1),
        static_cast<size_t>(MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES),
    }) {
        const std::vector<valtype> stack_items{BuildP2MRStackItemsForTotalBytes(total_bytes)};
        const CScript leaf_script{BuildDropAllScript(stack_items.size())};
        const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            stack_items,
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        const std::vector<valtype> stack_items{BuildP2MRStackItemsForTotalBytes(MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES + 1)};
        const CScript leaf_script{BuildDropAllScript(stack_items.size())};
        const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            stack_items,
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_stack_copy_amplification_item)
{
    const CScript leaf_script = CScript{} << OP_DUP << OP_DROP << OP_DROP << OP_TRUE;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
    const P2MRSpendContext spend = BuildP2MRSpend(
        leaf_script,
        /*stack_items=*/{std::vector<unsigned char>(MAX_P2MR_V1_STACK_ITEM_SIZE + 1, 0x01)},
        /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
        program_root);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_rejects_too_many_initial_stack_items)
{
    {
        const std::vector<valtype> stack_items(MAX_STACK_SIZE);
        const CScript leaf_script{BuildDropAllScript(stack_items.size())};
        const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            stack_items,
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        const CScript leaf_script = CScript{} << OP_TRUE;
        const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);
        const std::vector<valtype> stack_items(MAX_STACK_SIZE + 1);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            stack_items,
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_STACK_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_op_success_cannot_bypass_stack_resource_limits)
{
    const CScript leaf_script = CScript{} << OP_RESERVED;
    const uint256 program_root = ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script);

    {
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            /*stack_items=*/{std::vector<unsigned char>(MAX_P2MR_V1_STACK_ITEM_SIZE + 1, 0x01)},
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
    }

    {
        const std::vector<valtype> stack_items(MAX_STACK_SIZE + 1);
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            stack_items,
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_STACK_SIZE);
    }

    {
        const std::vector<valtype> stack_items{BuildP2MRStackItemsForTotalBytes(MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES + 1)};
        const P2MRSpendContext spend = BuildP2MRSpend(
            leaf_script,
            stack_items,
            /*control_block=*/{P2MR_LEAF_VERSION_V1_CONTROL},
            program_root);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(op_checksigpqc_is_invalid_outside_p2mr)
{
    const CScript checksigpqc_script = CScript{} << OP_CHECKSIGPQC << OP_TRUE;
    const valtype checksigpqc_script_bytes = ScriptBytes(checksigpqc_script);

    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifyBaseScript(checksigpqc_script, /*flags=*/SCRIPT_VERIFY_P2SH, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    }

    {
        const CScript p2sh_script_pubkey = GetScriptForDestination(ScriptHash(checksigpqc_script));
        const CScript script_sig = CScript{} << checksigpqc_script_bytes;

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifyInputScript(script_sig, p2sh_script_pubkey, CScriptWitness{}, SCRIPT_VERIFY_P2SH, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    }

    {
        const CScript witness_v0_script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(checksigpqc_script));
        CScriptWitness witness;
        witness.stack.push_back(checksigpqc_script_bytes);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifyInputScript(CScript{}, witness_v0_script_pubkey, witness, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    }

    {
        TaprootBuilder builder;
        builder.Add(/*depth=*/0, checksigpqc_script_bytes, TAPROOT_LEAF_TAPSCRIPT).Finalize(XOnlyPubKey::NUMS_H);
        const TaprootSpendData spend_data = builder.GetSpendData();
        const auto script_leaf = std::make_pair(checksigpqc_script_bytes, static_cast<int>(TAPROOT_LEAF_TAPSCRIPT));
        const auto& control_blocks = spend_data.scripts.at(script_leaf);
        CScriptWitness witness;
        witness.stack.push_back(checksigpqc_script_bytes);
        witness.stack.push_back(*control_blocks.begin());

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(!VerifyInputScript(
            CScript{},
            GetScriptForDestination(builder.GetOutput()),
            witness,
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT,
            err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    }

    {
        const CScript unexecuted = CScript{} << OP_FALSE << OP_IF << OP_CHECKSIGPQC << OP_ENDIF << OP_TRUE;
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifyBaseScript(unexecuted, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_SUITE_END()
