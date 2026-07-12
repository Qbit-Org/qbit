// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <crypto/pqc.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/p2mr.h>
#include <script/p2mr_sizing.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <streams.h>
#include <test/data/p2mr_cross_profile_vectors.json.h>
#include <test/data/p2mr_pqc_witness_vectors.json.h>
#include <test/data/p2mr_script_boundary_vectors.json.h>
#include <test/data/p2mr_v1_manifest.json.h>
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
    BOOST_CHECK_EQUAL(tests["schema_version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(tests["profile"].get_str(), "qbit-p2mr-v1");
    BOOST_CHECK_EQUAL(tests["profile_version"].getInt<int>(), 1);
    const std::set<std::string> expected_keys{
        "schema_version", "profile", "profile_version", "generator", "valid", "invalid"};
    const std::vector<std::string> keys{tests.getKeys()};
    const std::set<std::string> actual_keys{keys.begin(), keys.end()};
    BOOST_REQUIRE_MESSAGE(actual_keys == expected_keys, "p2mr_vectors.json has unknown or missing top-level fields");
    const UniValue& generator{tests["generator"].get_obj()};
    BOOST_CHECK_EQUAL(generator["id"].get_str(), "standalone-python");
    BOOST_CHECK_EQUAL(generator["version"].getInt<int>(), 1);
    BOOST_CHECK(!generator["uses_qbit_consensus_helpers"].get_bool());
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
    if (name == "SCRIPT_ERR_OK") return SCRIPT_ERR_OK;
    if (name == "SCRIPT_ERR_EVAL_FALSE") return SCRIPT_ERR_EVAL_FALSE;
    if (name == "SCRIPT_ERR_P2MR_CONTROL_BIT0") return SCRIPT_ERR_P2MR_CONTROL_BIT0;
    if (name == "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE") return SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE;
    if (name == "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH") return SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
    BOOST_FAIL("unknown P2MR vector script error: " + name);
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

std::string Sha256Hex(std::string_view bytes)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size())
        .Finalize(digest.data());
    return HexStr(digest);
}

void CheckExactObjectKeys(const UniValue& object, const std::set<std::string>& expected, std::string_view context)
{
    BOOST_REQUIRE_MESSAGE(object.isObject(), context << " must be an object");
    const std::vector<std::string> keys{object.getKeys()};
    const std::set<std::string> actual{keys.begin(), keys.end()};
    BOOST_REQUIRE_MESSAGE(actual == expected, context << " has unknown or missing fields");
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

ScriptExecutionData BuildExecData(const CScript& leaf_script, uint32_t codeseparator_pos)
{
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script));
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = codeseparator_pos;
    execdata.m_codeseparator_pos_init = true;
    return execdata;
}

ScriptExecutionData BuildExecData(const CScript& leaf_script)
{
    return BuildExecData(leaf_script, 0xFFFFFFFFUL);
}

ScriptExecutionData BuildExecData(const CScript& leaf_script, uint32_t codeseparator_pos, const valtype& annex)
{
    ScriptExecutionData execdata{BuildExecData(leaf_script, codeseparator_pos)};
    execdata.m_annex_hash = (HashWriter{} << annex).GetSHA256();
    execdata.m_annex_present = true;
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

struct DataSigAddVector {
    valtype message_hash;
    valtype wrong_message_hash;
    uint256 data_sig_hash;
    valtype control_block;
    CPQCPubKey pubkey_a;
    CPQCPubKey pubkey_b;
    CPQCPubKey pubkey_c;
    valtype signature_a;
    valtype signature_b;
    valtype signature_c;
    valtype raw_message_signature_a;
    valtype n_of_n_leaf_script;
    CScript n_of_n_script_pubkey;
    valtype m_of_n_leaf_script;
    CScript m_of_n_script_pubkey;
    valtype wrong_message_hash_leaf_script;
    CScript wrong_message_hash_script_pubkey;
    valtype wrong_pubkey_leaf_script;
    CScript wrong_pubkey_script_pubkey;
};

struct P2MRWitnessVector {
    std::string name;
    CMutableTransaction spend_tx;
    std::vector<CTxOut> spent_outputs;
    uint32_t input_index;
    uint8_t hash_type;
    uint32_t codeseparator_pos;
    valtype leaf_script;
    valtype control_block;
    std::optional<valtype> annex;
    std::optional<uint256> annex_hash;
    CPQCPubKey pubkey;
    valtype witness_signature;
    valtype raw_signature;
    ScriptError expected_error{SCRIPT_ERR_OK};
    std::optional<valtype> p2mr_sigmsg;
    std::optional<uint256> p2mr_sighash;
    std::optional<uint32_t> wrong_codeseparator_pos;
    std::optional<valtype> wrong_codeseparator_sigmsg;
    std::optional<uint256> wrong_codeseparator_sighash;
    std::optional<valtype> wrong_codeseparator_signature;
    std::optional<uint256> wrong_domain_sighash;
    std::optional<valtype> no_annex_sigmsg;
    std::optional<uint256> no_annex_sighash;
    std::optional<valtype> no_annex_signature;
    std::optional<valtype> data_sig_message_hash;
    std::optional<uint256> data_sig_hash;
    std::optional<CScript> data_sig_script_pubkey;
    std::optional<valtype> data_sig_leaf_script;
    std::optional<valtype> data_sig_control_block;
    std::optional<CPQCPubKey> data_sig_pubkey;
    std::optional<valtype> data_sig_signature;
    std::optional<valtype> data_sig_raw_message_signature;
    std::optional<CScript> data_sig_wrong_pubkey_script_pubkey;
    std::optional<valtype> data_sig_wrong_pubkey_leaf_script;
    std::optional<DataSigAddVector> data_sig_add;
};

valtype ParseHexField(const UniValue& obj, std::string_view field)
{
    const UniValue& value = obj[std::string{field}];
    BOOST_REQUIRE_MESSAGE(value.isStr(), "missing string field " << field);
    valtype bytes{ParseHex(value.get_str())};
    BOOST_REQUIRE_MESSAGE(!bytes.empty(), "invalid or empty hex field " << field);
    return bytes;
}

std::optional<valtype> ParseOptionalHexField(const UniValue& obj, std::string_view field)
{
    if (!obj.exists(std::string{field})) return std::nullopt;
    return ParseHexField(obj, field);
}

std::optional<valtype> ParseOptionalAnnexField(const UniValue& obj)
{
    if (!obj.exists("annex")) return std::nullopt;
    const UniValue& value = obj["annex"];
    BOOST_REQUIRE_MESSAGE(value.isStr(), "annex field must be a string");
    if (value.get_str() == "none") return std::nullopt;
    return ParseHexField(obj, "annex");
}

uint256 ParseRawUint256Field(const UniValue& obj, std::string_view field)
{
    const valtype bytes{ParseHexField(obj, field)};
    BOOST_REQUIRE_EQUAL(bytes.size(), uint256::size());
    return uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
}

std::optional<uint256> ParseOptionalRawUint256Field(const UniValue& obj, std::string_view field)
{
    if (!obj.exists(std::string{field})) return std::nullopt;
    return ParseRawUint256Field(obj, field);
}

CScript ParseScriptField(const UniValue& obj, std::string_view field)
{
    const valtype bytes{ParseHexField(obj, field)};
    return CScript{bytes.begin(), bytes.end()};
}

std::optional<CScript> ParseOptionalScriptField(const UniValue& obj, std::string_view field)
{
    if (!obj.exists(std::string{field})) return std::nullopt;
    return ParseScriptField(obj, field);
}

CPQCPubKey ParsePQCKeyField(const UniValue& obj, std::string_view field)
{
    const valtype pubkey_bytes{ParseHexField(obj, field)};
    BOOST_REQUIRE_EQUAL(pubkey_bytes.size(), PQC_PUBKEY_SIZE);
    CPQCPubKey pubkey{pubkey_bytes};
    BOOST_REQUIRE(pubkey.IsValid());
    return pubkey;
}

std::optional<CPQCPubKey> ParseOptionalPQCKeyField(const UniValue& obj, std::string_view field)
{
    if (!obj.exists(std::string{field})) return std::nullopt;
    return ParsePQCKeyField(obj, field);
}

CMutableTransaction ParseMutableTransactionField(const UniValue& obj, std::string_view field)
{
    DataStream stream{ParseHexField(obj, field)};
    CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    return tx;
}

std::optional<DataSigAddVector> ParseOptionalDataSigAddVector(const UniValue& vec)
{
    if (!vec.exists("dataSigAdd")) return std::nullopt;
    const UniValue& value{vec["dataSigAdd"]};
    BOOST_REQUIRE_MESSAGE(value.isObject(), "missing object field dataSigAdd");
    const UniValue& obj{value.get_obj()};

    DataSigAddVector out{
        .message_hash = ParseHexField(obj, "messageHash"),
        .wrong_message_hash = ParseHexField(obj, "wrongMessageHash"),
        .data_sig_hash = ParseRawUint256Field(obj, "dataSigHash"),
        .control_block = ParseHexField(obj, "controlBlock"),
        .pubkey_a = ParsePQCKeyField(obj, "pubkeyA"),
        .pubkey_b = ParsePQCKeyField(obj, "pubkeyB"),
        .pubkey_c = ParsePQCKeyField(obj, "pubkeyC"),
        .signature_a = ParseHexField(obj, "signatureA"),
        .signature_b = ParseHexField(obj, "signatureB"),
        .signature_c = ParseHexField(obj, "signatureC"),
        .raw_message_signature_a = ParseHexField(obj, "rawMessageSignatureA"),
        .n_of_n_leaf_script = ParseHexField(obj, "nOfNLeafScript"),
        .n_of_n_script_pubkey = ParseScriptField(obj, "nOfNScriptPubKey"),
        .m_of_n_leaf_script = ParseHexField(obj, "mOfNLeafScript"),
        .m_of_n_script_pubkey = ParseScriptField(obj, "mOfNScriptPubKey"),
        .wrong_message_hash_leaf_script = ParseHexField(obj, "wrongMessageHashLeafScript"),
        .wrong_message_hash_script_pubkey = ParseScriptField(obj, "wrongMessageHashScriptPubKey"),
        .wrong_pubkey_leaf_script = ParseHexField(obj, "wrongPubkeyLeafScript"),
        .wrong_pubkey_script_pubkey = ParseScriptField(obj, "wrongPubkeyScriptPubKey"),
    };

    BOOST_REQUIRE_EQUAL(out.message_hash.size(), uint256::size());
    BOOST_REQUIRE_EQUAL(out.wrong_message_hash.size(), uint256::size());
    BOOST_REQUIRE(out.message_hash != out.wrong_message_hash);
    BOOST_REQUIRE_EQUAL(out.control_block.size(), 1U);
    BOOST_REQUIRE_EQUAL(out.control_block[0], P2MR_LEAF_VERSION_V1_CONTROL);
    BOOST_REQUIRE_EQUAL(out.signature_a.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE_EQUAL(out.signature_b.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE_EQUAL(out.signature_c.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE_EQUAL(out.raw_message_signature_a.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE_EQUAL(out.n_of_n_script_pubkey.size(), 34U);
    BOOST_REQUIRE_EQUAL(out.m_of_n_script_pubkey.size(), 34U);
    BOOST_REQUIRE_EQUAL(out.wrong_message_hash_script_pubkey.size(), 34U);
    BOOST_REQUIRE_EQUAL(out.wrong_pubkey_script_pubkey.size(), 34U);
    return out;
}

uint8_t ParseHashTypeField(const UniValue& obj)
{
    const valtype bytes{ParseHexField(obj, "hashType")};
    BOOST_REQUIRE_EQUAL(bytes.size(), 1U);
    return bytes.front();
}

uint32_t ParseCodeSeparatorPositionField(const UniValue& obj, std::string_view field)
{
    const valtype bytes{ParseHexField(obj, field)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 4U);
    return uint32_t{bytes[0]} |
           (uint32_t{bytes[1]} << 8) |
           (uint32_t{bytes[2]} << 16) |
           (uint32_t{bytes[3]} << 24);
}

std::optional<uint32_t> ParseOptionalCodeSeparatorPositionField(const UniValue& obj, std::string_view field)
{
    if (!obj.exists(std::string{field})) return std::nullopt;
    return ParseCodeSeparatorPositionField(obj, field);
}

ScriptError ParseExpectedP2MRWitnessError(const UniValue& obj)
{
    const UniValue& expected{obj["expected"]};
    BOOST_REQUIRE_MESSAGE(expected.isObject(), "expected field must be an object");
    const UniValue& value{expected["error"]};
    BOOST_REQUIRE_MESSAGE(value.isStr(), "expected.error field must be a string");
    const std::string name{value.get_str()};
    if (name == "SCRIPT_ERR_OK") return SCRIPT_ERR_OK;
    if (name == "SCRIPT_ERR_P2MR_SIG_HASHTYPE") return SCRIPT_ERR_P2MR_SIG_HASHTYPE;

    BOOST_FAIL("unknown P2MR witness vector expectedError: " + name);
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

std::vector<CTxOut> ParseSpentOutputsField(const UniValue& obj)
{
    const UniValue& outputs = obj["spentOutputs"];
    BOOST_REQUIRE_MESSAGE(outputs.isArray(), "missing spentOutputs array");

    std::vector<CTxOut> spent_outputs;
    for (const UniValue& output_value : outputs.getValues()) {
        const UniValue& output = output_value.get_obj();
        spent_outputs.emplace_back(output["amount"].getInt<CAmount>(), ParseScriptField(output, "scriptPubKey"));
    }
    return spent_outputs;
}

P2MRWitnessVector ParseP2MRWitnessVector(const UniValue& vec)
{
    const std::string vector_id{vec["id"].get_str()};
    BOOST_REQUIRE_EQUAL(vector_id, vec["name"].get_str());
    const UniValue& generator{vec["generator"].get_obj()};
    CheckExactObjectKeys(generator, {"id", "version"}, "witness generator");
    const std::set<std::string> rust_owned_ids{
        "single_key_leading_codesep", "branch_codesep_true", "branch_codesep_false"};
    const std::string expected_generator{rust_owned_ids.contains(vector_id) ? "standalone-rust" : "standalone-python"};
    BOOST_REQUIRE_EQUAL(generator["id"].get_str(), expected_generator);
    BOOST_REQUIRE_EQUAL(generator["version"].getInt<int>(), 1);

    const valtype pubkey_bytes{ParseHexField(vec, "pubkey")};
    BOOST_REQUIRE_EQUAL(pubkey_bytes.size(), PQC_PUBKEY_SIZE);
    CPQCPubKey pubkey{pubkey_bytes};
    BOOST_REQUIRE(pubkey.IsValid());

    valtype witness_signature{ParseHexField(vec, "signature")};
    const uint8_t hash_type{ParseHashTypeField(vec)};
    valtype raw_signature{witness_signature};
    if (hash_type == SIGHASH_DEFAULT) {
        BOOST_REQUIRE_EQUAL(raw_signature.size(), PQC_SIG_SIZE);
    } else {
        BOOST_REQUIRE_EQUAL(raw_signature.size(), PQC_SIG_SIZE + 1);
        BOOST_REQUIRE_EQUAL(raw_signature.back(), hash_type);
        raw_signature.pop_back();
    }

    P2MRWitnessVector out{
        .name = vec["name"].get_str(),
        .spend_tx = ParseMutableTransactionField(vec, "spendTx"),
        .spent_outputs = ParseSpentOutputsField(vec),
        .input_index = vec["inputIndex"].getInt<uint32_t>(),
        .hash_type = hash_type,
        .codeseparator_pos = ParseCodeSeparatorPositionField(vec, "codeSeparatorPosition"),
        .leaf_script = ParseHexField(vec, "leafScript"),
        .control_block = ParseHexField(vec, "controlBlock"),
        .annex = ParseOptionalAnnexField(vec),
        .annex_hash = ParseOptionalRawUint256Field(vec, "annexHash"),
        .pubkey = pubkey,
        .witness_signature = std::move(witness_signature),
        .raw_signature = std::move(raw_signature),
        .expected_error = ParseExpectedP2MRWitnessError(vec),
        .p2mr_sigmsg = ParseOptionalHexField(vec, "p2mrSigMsg"),
        .p2mr_sighash = ParseOptionalRawUint256Field(vec, "p2mrSighash"),
        .wrong_codeseparator_pos = ParseOptionalCodeSeparatorPositionField(vec, "wrongCodeSeparatorPosition"),
        .wrong_codeseparator_sigmsg = ParseOptionalHexField(vec, "wrongCodeseparatorSigMsg"),
        .wrong_codeseparator_sighash = ParseOptionalRawUint256Field(vec, "wrongCodeseparatorSighash"),
        .wrong_codeseparator_signature = ParseOptionalHexField(vec, "wrongCodeseparatorSignature"),
        .wrong_domain_sighash = ParseOptionalRawUint256Field(vec, "wrongDomainSighash"),
        .no_annex_sigmsg = ParseOptionalHexField(vec, "noAnnexSigMsg"),
        .no_annex_sighash = ParseOptionalRawUint256Field(vec, "noAnnexSighash"),
        .no_annex_signature = ParseOptionalHexField(vec, "noAnnexSignature"),
        .data_sig_message_hash = ParseOptionalHexField(vec, "dataSigMessageHash"),
        .data_sig_hash = ParseOptionalRawUint256Field(vec, "dataSigHash"),
        .data_sig_script_pubkey = ParseOptionalScriptField(vec, "dataSigScriptPubKey"),
        .data_sig_leaf_script = ParseOptionalHexField(vec, "dataSigLeafScript"),
        .data_sig_control_block = ParseOptionalHexField(vec, "dataSigControlBlock"),
        .data_sig_pubkey = ParseOptionalPQCKeyField(vec, "dataSigPubkey"),
        .data_sig_signature = ParseOptionalHexField(vec, "dataSigSignature"),
        .data_sig_raw_message_signature = ParseOptionalHexField(vec, "dataSigRawMessageSignature"),
        .data_sig_wrong_pubkey_script_pubkey = ParseOptionalScriptField(vec, "dataSigWrongPubkeyScriptPubKey"),
        .data_sig_wrong_pubkey_leaf_script = ParseOptionalHexField(vec, "dataSigWrongPubkeyLeafScript"),
        .data_sig_add = ParseOptionalDataSigAddVector(vec),
    };

    const valtype leaf_version{ParseHexField(vec, "leafVersion")};
    const valtype epoch{ParseHexField(vec, "epoch")};
    const valtype spend_type{ParseHexField(vec, "spendType")};
    const valtype key_version{ParseHexField(vec, "keyVersion")};
    BOOST_REQUIRE_EQUAL(leaf_version.size(), 1U);
    BOOST_REQUIRE_EQUAL(epoch.size(), 1U);
    BOOST_REQUIRE_EQUAL(spend_type.size(), 1U);
    BOOST_REQUIRE_EQUAL(key_version.size(), 1U);
    BOOST_CHECK_EQUAL(leaf_version[0], P2MR_LEAF_VERSION_V1);
    BOOST_CHECK_EQUAL(epoch[0], 0U);
    BOOST_CHECK_EQUAL(spend_type[0], out.annex ? 3U : 2U);
    BOOST_CHECK_EQUAL(key_version[0], 0U);

    const uint256 leaf_hash{ParseRawUint256Field(vec, "leafHash")};
    BOOST_CHECK_EQUAL(leaf_hash, ComputeP2MRLeafHash(leaf_version[0], out.leaf_script));
    BOOST_REQUIRE(!out.control_block.empty());
    BOOST_CHECK_EQUAL(out.control_block[0] & P2MR_LEAF_VERSION_MASK, leaf_version[0]);
    const CAmount prevout_amount{vec["prevoutAmount"].getInt<CAmount>()};
    const CScript prevout_script_pubkey{ParseScriptField(vec, "prevoutScriptPubKey")};
    BOOST_REQUIRE_LT(out.input_index, out.spent_outputs.size());
    BOOST_CHECK_EQUAL(prevout_amount, out.spent_outputs[out.input_index].nValue);
    BOOST_CHECK(prevout_script_pubkey == out.spent_outputs[out.input_index].scriptPubKey);
    BOOST_CHECK(prevout_script_pubkey == BuildP2MRScriptPubKey(ComputeP2MRMerkleRoot(out.control_block, leaf_hash)));

    if (out.expected_error == SCRIPT_ERR_OK) {
        BOOST_REQUIRE(out.p2mr_sigmsg);
        BOOST_REQUIRE(out.p2mr_sighash);
        BOOST_REQUIRE(out.wrong_domain_sighash);
        BOOST_REQUIRE(!out.p2mr_sigmsg->empty());
        BOOST_REQUIRE(*out.p2mr_sighash != *out.wrong_domain_sighash);
        if (out.wrong_codeseparator_sighash) {
            BOOST_REQUIRE(out.wrong_codeseparator_pos);
            BOOST_REQUIRE(out.wrong_codeseparator_sigmsg);
            BOOST_REQUIRE(out.wrong_codeseparator_signature);
            BOOST_REQUIRE(*out.p2mr_sighash != *out.wrong_codeseparator_sighash);
            BOOST_REQUIRE_EQUAL(out.wrong_codeseparator_signature->size(), PQC_SIG_SIZE);
        }
    } else {
        BOOST_REQUIRE(!out.p2mr_sigmsg);
        BOOST_REQUIRE(!out.p2mr_sighash);
        BOOST_REQUIRE(!out.wrong_domain_sighash);
    }
    BOOST_REQUIRE_EQUAL(vec["digest_defined"].get_bool(), out.p2mr_sighash.has_value());
    const UniValue& expected{vec["expected"].get_obj()};
    BOOST_REQUIRE_EQUAL(expected["accepted"].get_bool(), out.expected_error == SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(
        expected["stage"].get_str(),
        out.expected_error == SCRIPT_ERR_OK ? "script-complete" : "sighash");
    BOOST_REQUIRE_EQUAL(out.raw_signature.size(), PQC_SIG_SIZE);
    BOOST_REQUIRE_EQUAL(out.spent_outputs.size(), out.spend_tx.vin.size());
    BOOST_REQUIRE_LT(out.input_index, out.spend_tx.vin.size());
    BOOST_REQUIRE_LT(out.input_index, out.spent_outputs.size());
    const auto& stack{out.spend_tx.vin[out.input_index].scriptWitness.stack};
    const auto& witness_items{vec["witness"].getValues()};
    BOOST_REQUIRE_EQUAL(witness_items.size(), stack.size());
    for (size_t index{0}; index < stack.size(); ++index) {
        BOOST_REQUIRE(stack[index] == ParseHex(witness_items[index].get_str()));
    }
    BOOST_REQUIRE_GE(stack.size(), out.annex ? 4U : 3U);
    BOOST_REQUIRE(stack[0] == out.witness_signature);
    const size_t leaf_index{out.annex ? 1U : stack.size() - 2};
    const size_t control_index{out.annex ? 2U : stack.size() - 1};
    BOOST_REQUIRE(stack[leaf_index] == out.leaf_script);
    BOOST_REQUIRE(stack[control_index] == out.control_block);
    if (out.annex) {
        BOOST_REQUIRE_EQUAL(stack.size(), 4U);
        BOOST_REQUIRE(out.annex_hash);
        BOOST_REQUIRE(out.no_annex_sigmsg);
        BOOST_REQUIRE(out.no_annex_sighash);
        BOOST_REQUIRE(out.no_annex_signature);
        BOOST_REQUIRE_EQUAL(out.no_annex_signature->size(), PQC_SIG_SIZE);
        BOOST_REQUIRE(stack[3] == *out.annex);
    }
    if (out.data_sig_message_hash) {
        BOOST_REQUIRE(out.data_sig_hash);
        BOOST_REQUIRE(out.data_sig_script_pubkey);
        BOOST_REQUIRE(out.data_sig_leaf_script);
        BOOST_REQUIRE(out.data_sig_control_block);
        BOOST_REQUIRE(out.data_sig_pubkey);
        BOOST_REQUIRE(out.data_sig_signature);
        BOOST_REQUIRE(out.data_sig_raw_message_signature);
        BOOST_REQUIRE(out.data_sig_wrong_pubkey_script_pubkey);
        BOOST_REQUIRE(out.data_sig_wrong_pubkey_leaf_script);
        BOOST_REQUIRE_EQUAL(out.data_sig_message_hash->size(), uint256::size());
        BOOST_REQUIRE_EQUAL(out.data_sig_signature->size(), PQC_SIG_SIZE);
        BOOST_REQUIRE_EQUAL(out.data_sig_raw_message_signature->size(), PQC_SIG_SIZE);
        BOOST_REQUIRE_EQUAL(out.data_sig_leaf_script->size(), CPQCPubKey::SIZE + 2);
        BOOST_REQUIRE_EQUAL(out.data_sig_control_block->size(), 1U);
        BOOST_REQUIRE_EQUAL((*out.data_sig_control_block)[0], P2MR_LEAF_VERSION_V1_CONTROL);
        BOOST_REQUIRE_EQUAL(out.data_sig_script_pubkey->size(), 34U);
        BOOST_REQUIRE_EQUAL(out.data_sig_wrong_pubkey_leaf_script->size(), out.data_sig_leaf_script->size());
        BOOST_REQUIRE_EQUAL(out.data_sig_wrong_pubkey_script_pubkey->size(), out.data_sig_script_pubkey->size());
    }
    if (out.data_sig_add) {
        const DataSigAddVector& add{*out.data_sig_add};
        BOOST_REQUIRE_EQUAL(add.message_hash.size(), uint256::size());
        BOOST_REQUIRE_EQUAL(add.wrong_message_hash.size(), uint256::size());
        BOOST_REQUIRE(add.message_hash != add.wrong_message_hash);
        BOOST_REQUIRE_EQUAL(add.control_block.size(), 1U);
        BOOST_REQUIRE_EQUAL(add.control_block[0], P2MR_LEAF_VERSION_V1_CONTROL);
        BOOST_REQUIRE_EQUAL(add.signature_a.size(), PQC_SIG_SIZE);
        BOOST_REQUIRE_EQUAL(add.signature_b.size(), PQC_SIG_SIZE);
        BOOST_REQUIRE_EQUAL(add.signature_c.size(), PQC_SIG_SIZE);
        BOOST_REQUIRE_EQUAL(add.raw_message_signature_a.size(), PQC_SIG_SIZE);
        BOOST_REQUIRE_EQUAL(add.n_of_n_script_pubkey.size(), 34U);
        BOOST_REQUIRE_EQUAL(add.m_of_n_script_pubkey.size(), 34U);
        BOOST_REQUIRE_EQUAL(add.wrong_message_hash_script_pubkey.size(), 34U);
        BOOST_REQUIRE_EQUAL(add.wrong_pubkey_script_pubkey.size(), 34U);
    }
    return out;
}

std::vector<P2MRWitnessVector> LoadIndependentP2MRWitnessVectors()
{
    UniValue corpus;
    BOOST_REQUIRE(corpus.read(json_tests::p2mr_pqc_witness_vectors));
    BOOST_REQUIRE(corpus.isObject());
    BOOST_REQUIRE_EQUAL(corpus["schema_version"].getInt<int>(), 1);
    BOOST_REQUIRE_EQUAL(corpus["profile"].get_str(), "qbit-p2mr-v1");
    BOOST_REQUIRE_EQUAL(corpus["profile_version"].getInt<int>(), 1);
    const std::vector<std::string> top_level_keys{corpus.getKeys()};
    const std::set<std::string> actual_keys{top_level_keys.begin(), top_level_keys.end()};
    const std::set<std::string> expected_keys{"schema_version", "profile", "profile_version", "vectors"};
    BOOST_REQUIRE_MESSAGE(actual_keys == expected_keys, "witness corpus has unknown or missing top-level fields");
    const UniValue& vectors_json{corpus["vectors"]};
    BOOST_REQUIRE(vectors_json.isArray());

    std::vector<P2MRWitnessVector> vectors;
    std::set<std::string> names;
    for (const UniValue& vec_json : vectors_json.getValues()) {
        P2MRWitnessVector vector{ParseP2MRWitnessVector(vec_json.get_obj())};
        names.insert(vector.name);
        vectors.push_back(std::move(vector));
    }

    const std::set<std::string> expected_names{
        "branch_codesep_false",
        "branch_codesep_true",
        "single_key_default_sighash",
        "single_key_default_sighash_annex_present",
        "single_key_leading_codesep",
        "single_key_sighash_none",
        "single_key_sighash_single_matching_output",
        "single_key_sighash_single_missing_first",
        "single_key_sighash_single_missing_beyond",
        "single_key_sighash_all_anyonecanpay",
        "single_key_sighash_none_anyonecanpay",
        "single_key_sighash_single_anyonecanpay",
        "single_key_sighash_single_anyonecanpay_missing_first",
        "single_key_sighash_single_anyonecanpay_missing_beyond",
    };
    BOOST_REQUIRE_EQUAL(vectors_json.size(), expected_names.size());
    BOOST_REQUIRE_EQUAL(names.size(), expected_names.size());
    for (const auto& name : expected_names) {
        BOOST_REQUIRE_MESSAGE(names.count(name) == 1, "missing vector " << name);
    }
    return vectors;
}

const P2MRWitnessVector& FindVector(const std::vector<P2MRWitnessVector>& vectors, std::string_view name)
{
    const auto it = std::find_if(vectors.begin(), vectors.end(), [&](const auto& vector) {
        return vector.name == name;
    });
    BOOST_REQUIRE_MESSAGE(it != vectors.end(), "missing vector " << name);
    return *it;
}

PrecomputedTransactionData PrecomputeVectorData(const CMutableTransaction& tx, const std::vector<CTxOut>& spent_outputs)
{
    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs_copy{spent_outputs};
    txdata.Init(tx, std::move(spent_outputs_copy));
    return txdata;
}

bool VerifyVectorSpend(const P2MRWitnessVector& vector, const CMutableTransaction& tx, const std::vector<CTxOut>& spent_outputs, ScriptError& err)
{
    BOOST_REQUIRE_LT(vector.input_index, tx.vin.size());
    BOOST_REQUIRE_LT(vector.input_index, spent_outputs.size());
    PrecomputedTransactionData txdata{PrecomputeVectorData(tx, spent_outputs)};
    const CTxOut& spent_output{spent_outputs[vector.input_index]};
    return VerifyScript(
        tx.vin[vector.input_index].scriptSig,
        spent_output.scriptPubKey,
        &tx.vin[vector.input_index].scriptWitness,
        P2MR_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(
            &tx,
            vector.input_index,
            spent_output.nValue,
            txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
}

CMutableTransaction BuildIndependentP2MRVectorSpend(std::vector<valtype> witness_items, const valtype& leaf_script, const valtype& control_block)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin[0].nSequence = 0xfffffffe;
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    tx.vin[0].scriptWitness.stack = std::move(witness_items);
    tx.vin[0].scriptWitness.stack.push_back(leaf_script);
    tx.vin[0].scriptWitness.stack.push_back(control_block);
    return tx;
}

CMutableTransaction BuildDataSigVectorSpend(const P2MRWitnessVector& vector)
{
    BOOST_REQUIRE_EQUAL(vector.input_index, 0U);
    BOOST_REQUIRE(vector.data_sig_signature);
    BOOST_REQUIRE(vector.data_sig_message_hash);
    BOOST_REQUIRE(vector.data_sig_leaf_script);
    BOOST_REQUIRE(vector.data_sig_control_block);

    return BuildIndependentP2MRVectorSpend(
        {*vector.data_sig_signature, *vector.data_sig_message_hash},
        *vector.data_sig_leaf_script,
        *vector.data_sig_control_block);
}

CMutableTransaction BuildDataSigAddNOfNVectorSpend(const DataSigAddVector& vector)
{
    return BuildIndependentP2MRVectorSpend(
        {vector.signature_b, vector.signature_a},
        vector.n_of_n_leaf_script,
        vector.control_block);
}

CMutableTransaction BuildDataSigAddMOfNVectorSpend(const DataSigAddVector& vector)
{
    return BuildIndependentP2MRVectorSpend(
        {vector.signature_c, valtype{}, vector.signature_a},
        vector.m_of_n_leaf_script,
        vector.control_block);
}

CMutableTransaction BuildDataSigAddThresholdFailureVectorSpend(const DataSigAddVector& vector)
{
    return BuildIndependentP2MRVectorSpend(
        {valtype{}, valtype{}, vector.signature_a},
        vector.m_of_n_leaf_script,
        vector.control_block);
}

std::vector<CTxOut> BuildSingleInputSpentOutputs(const P2MRWitnessVector& vector, const CScript& script_pubkey)
{
    BOOST_REQUIRE_EQUAL(vector.input_index, 0U);
    BOOST_REQUIRE_LT(vector.input_index, vector.spent_outputs.size());
    return {CTxOut{vector.spent_outputs[vector.input_index].nValue, script_pubkey}};
}

std::vector<CTxOut> BuildDataSigSpentOutputs(const P2MRWitnessVector& vector)
{
    BOOST_REQUIRE(vector.data_sig_script_pubkey);
    return BuildSingleInputSpentOutputs(vector, *vector.data_sig_script_pubkey);
}

bool VerifyVectorSpend(const P2MRWitnessVector& vector, ScriptError& err)
{
    return VerifyVectorSpend(vector, vector.spend_tx, vector.spent_outputs, err);
}

struct BoundaryExecution {
    bool accepted;
    ScriptError error;
};

ScriptError BoundaryScriptError(std::string_view name)
{
    if (name == "SCRIPT_ERR_OK") return SCRIPT_ERR_OK;
    if (name == "SCRIPT_ERR_EVAL_FALSE") return SCRIPT_ERR_EVAL_FALSE;
    if (name == "SCRIPT_ERR_VERIFY") return SCRIPT_ERR_VERIFY;
    if (name == "SCRIPT_ERR_PUSH_SIZE") return SCRIPT_ERR_PUSH_SIZE;
    if (name == "SCRIPT_ERR_STACK_SIZE") return SCRIPT_ERR_STACK_SIZE;
    if (name == "SCRIPT_ERR_BAD_OPCODE") return SCRIPT_ERR_BAD_OPCODE;
    if (name == "SCRIPT_ERR_CLEANSTACK") return SCRIPT_ERR_CLEANSTACK;
    if (name == "SCRIPT_ERR_PUBKEYTYPE") return SCRIPT_ERR_PUBKEYTYPE;
    if (name == "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION") return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;
    if (name == "SCRIPT_ERR_DISCOURAGE_OP_SUCCESS") return SCRIPT_ERR_DISCOURAGE_OP_SUCCESS;
    if (name == "SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY") return SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
    if (name == "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH") return SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
    if (name == "SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG") return SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG;
    if (name == "SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE") return SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE;
    if (name == "SCRIPT_ERR_P2MR_CONTROL_BIT0") return SCRIPT_ERR_P2MR_CONTROL_BIT0;
    if (name == "SCRIPT_ERR_P2MR_VALIDATION_WEIGHT") return SCRIPT_ERR_P2MR_VALIDATION_WEIGHT;
    if (name == "SCRIPT_ERR_P2MR_SIG_SIZE") return SCRIPT_ERR_P2MR_SIG_SIZE;
    if (name == "SCRIPT_ERR_P2MR_SIG") return SCRIPT_ERR_P2MR_SIG;
    if (name == "SCRIPT_ERR_P2MR_CHECKSIG") return SCRIPT_ERR_P2MR_CHECKSIG;
    if (name == "SCRIPT_ERR_TEMPLATE_MISMATCH") return SCRIPT_ERR_TEMPLATE_MISMATCH;
    BOOST_FAIL("unknown P2MR boundary error: " + std::string{name});
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

BoundaryExecution ExecuteBoundarySpend(const P2MRSpendContext& spend, unsigned int flags)
{
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool accepted{VerifySpend(spend, flags, error)};
    return {accepted, error};
}

BoundaryExecution ExecuteBoundaryFixtureSpend(
    const CMutableTransaction& tx,
    const std::vector<CTxOut>& spent_outputs,
    uint32_t input_index,
    unsigned int flags)
{
    BOOST_REQUIRE_LT(input_index, tx.vin.size());
    BOOST_REQUIRE_EQUAL(spent_outputs.size(), tx.vin.size());
    PrecomputedTransactionData txdata{PrecomputeVectorData(tx, spent_outputs)};
    const CTxOut& spent_output{spent_outputs[input_index]};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool accepted{VerifyScript(
        tx.vin[input_index].scriptSig,
        spent_output.scriptPubKey,
        &tx.vin[input_index].scriptWitness,
        flags,
        MutableTransactionSignatureChecker(
            &tx,
            input_index,
            spent_output.nValue,
            txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &error)};
    return {accepted, error};
}

UniValue DefaultP2MRWitnessFixtureJson()
{
    UniValue corpus;
    BOOST_REQUIRE(corpus.read(json_tests::p2mr_pqc_witness_vectors));
    for (const UniValue& value : corpus["vectors"].getValues()) {
        if (value["id"].get_str() == "single_key_default_sighash") return value.get_obj();
    }
    BOOST_FAIL("missing single_key_default_sighash fixture");
    return {};
}

void CheckBoundaryFixtureSelector(const UniValue& parameters, std::string_view artifact)
{
    BOOST_REQUIRE_EQUAL(parameters["fixture_file"].get_str(), "src/test/data/p2mr_pqc_witness_vectors.json");
    BOOST_REQUIRE_EQUAL(parameters["fixture_id"].get_str(), "single_key_default_sighash");
    BOOST_REQUIRE_EQUAL(parameters["artifact"].get_str(), artifact);
}

BoundaryExecution ExecuteP2MRBoundaryCase(const UniValue& test, unsigned int flags)
{
    const std::string scenario{test["scenario"].get_str()};
    const UniValue& parameters{test["parameters"].get_obj()};

    if (scenario == "witness-shape") {
        CheckExactObjectKeys(parameters, {"kind"}, "boundary witness-shape parameters");
        const CScript leaf_script{CScript{} << OP_TRUE};
        const uint256 root{ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)};
        P2MRSpendContext spend{BuildP2MRSpend(
            leaf_script, {}, {P2MR_LEAF_VERSION_V1_CONTROL}, root)};
        const std::string kind{parameters["kind"].get_str()};
        if (kind == "empty") {
            spend.tx_spend.vin[0].scriptWitness.stack.clear();
        } else if (kind == "one-element") {
            spend.tx_spend.vin[0].scriptWitness.stack = {valtype{0x01}};
        } else if (kind == "annex-underflow") {
            spend.tx_spend.vin[0].scriptWitness.stack = {valtype{0x01}, valtype{ANNEX_TAG}};
        } else {
            BOOST_FAIL("unknown boundary witness shape: " + kind);
        }
        return ExecuteBoundarySpend(spend, flags);
    }

    if (scenario == "control-path") {
        CheckExactObjectKeys(parameters, {"nodes", "mutation"}, "boundary control-path parameters");
        const int nodes{parameters["nodes"].getInt<int>()};
        BOOST_REQUIRE_GE(nodes, 0);
        BOOST_REQUIRE_LE(nodes, 129);
        const std::string mutation{parameters["mutation"].get_str()};
        const CScript leaf_script{CScript{} << OP_TRUE};
        const uint256 leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script))};
        valtype control(1 + static_cast<size_t>(nodes) * P2MR_CONTROL_NODE_SIZE, 0x00);
        control[0] = P2MR_LEAF_VERSION_V1_CONTROL;
        uint256 root{nodes <= static_cast<int>(P2MR_CONTROL_MAX_NODE_COUNT) ?
                         ComputeP2MRMerkleRoot(control, leaf_hash) :
                         leaf_hash};
        if (mutation == "append-byte") {
            control.push_back(0x00);
        } else if (mutation == "clear-marker") {
            control[0] &= 0xfe;
        } else if (mutation == "path-node") {
            BOOST_REQUIRE_EQUAL(nodes, 1);
            control.back() ^= 0x01;
        } else if (mutation == "program-root") {
            root.begin()[0] ^= 0x01;
        } else if (mutation != "none") {
            BOOST_FAIL("unknown boundary control mutation: " + mutation);
        }
        return ExecuteBoundarySpend(BuildP2MRSpend(leaf_script, {}, control, root), flags);
    }

    if (scenario == "leaf-version") {
        CheckExactObjectKeys(parameters, {"control_byte", "script"}, "boundary leaf-version parameters");
        const int control_value{parameters["control_byte"].getInt<int>()};
        BOOST_REQUIRE_GE(control_value, 0);
        BOOST_REQUIRE_LE(control_value, 255);
        const unsigned char control_byte{static_cast<unsigned char>(control_value)};
        BOOST_REQUIRE_EQUAL(control_byte & 1, 1);
        const std::string script_kind{parameters["script"].get_str()};
        BOOST_REQUIRE(script_kind == "true" || script_kind == "false");
        const CScript leaf_script{CScript{} << (script_kind == "true" ? OP_TRUE : OP_FALSE)};
        const uint8_t leaf_version{static_cast<uint8_t>(control_byte & P2MR_LEAF_VERSION_MASK)};
        const uint256 root{ComputeMerkleRootSingleLeaf(leaf_version, leaf_script)};
        return ExecuteBoundarySpend(BuildP2MRSpend(leaf_script, {}, {control_byte}, root), flags);
    }

    if (scenario == "opcode") {
        const std::string kind{parameters["kind"].get_str()};
        if (kind == "checksigpqc-valid" || kind == "checksigpqc-invalid") {
            const std::set<std::string> parameter_keys{kind == "checksigpqc-valid" ?
                                                           std::set<std::string>{"kind", "fixture_file", "fixture_id", "artifact"} :
                                                           std::set<std::string>{"kind", "fixture_file", "fixture_id", "artifact", "mutation"}};
            CheckExactObjectKeys(parameters, parameter_keys, "boundary CHECKSIGPQC fixture parameters");
            CheckBoundaryFixtureSelector(parameters, "transaction-checksigpqc");
            if (kind == "checksigpqc-invalid") {
                BOOST_REQUIRE_EQUAL(parameters["mutation"].get_str(), "flip-first-signature-byte");
            }
            const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
            const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
            CMutableTransaction tx{vector.spend_tx};
            if (kind == "checksigpqc-invalid") tx.vin[vector.input_index].scriptWitness.stack[0][0] ^= 0x01;
            return ExecuteBoundaryFixtureSpend(tx, vector.spent_outputs, vector.input_index, flags);
        }
        if (kind == "checksigpqc-empty") {
            CheckExactObjectKeys(parameters, {"kind"}, "boundary CHECKSIGPQC empty parameters");
            const CScript leaf_script{CScript{} << valtype(PQC_PUBKEY_SIZE, 0x02) << OP_CHECKSIGPQC << OP_VERIFY << OP_TRUE};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, {valtype{}}, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        if (kind == "checksigpqc-bad-size" || kind == "checksigpqc-bad-key") {
            CheckExactObjectKeys(parameters, {"kind"}, "boundary CHECKSIGPQC invalid parameters");
            const valtype pubkey{kind == "checksigpqc-bad-key" ? valtype{} : valtype(PQC_PUBKEY_SIZE, 0x02)};
            const valtype signature{kind == "checksigpqc-bad-size" ? valtype(PQC_SIG_SIZE - 1, 0x01) : valtype(PQC_SIG_SIZE, 0x01)};
            const CScript leaf_script{CScript{} << pubkey << OP_CHECKSIGPQC};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, {signature}, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        if (kind == "checksigadd-valid") {
            CheckExactObjectKeys(parameters, {"kind", "fixture_file", "fixture_id", "artifact"}, "boundary CHECKSIGADD fixture parameters");
            CheckBoundaryFixtureSelector(parameters, "checkSigAdd");
            const UniValue fixture{DefaultP2MRWitnessFixtureJson()};
            const UniValue& add{fixture["checkSigAdd"].get_obj()};
            CheckExactObjectKeys(
                add,
                {"provenance", "inputIndex", "spentOutputs", "spendTx", "leafVersion", "leafScript",
                 "controlBlock", "leafHash", "scriptPubKey", "pubkey", "signature", "p2mrSigMsg",
                 "p2mrSighash", "expected"},
                "CHECKSIGADD fixture");
            const uint32_t input_index{add["inputIndex"].getInt<uint32_t>()};
            const CMutableTransaction tx{ParseMutableTransactionField(add, "spendTx")};
            const std::vector<CTxOut> spent_outputs{ParseSpentOutputsField(add)};
            const valtype leaf_script{ParseHexField(add, "leafScript")};
            const valtype control_block{ParseHexField(add, "controlBlock")};
            const uint256 leaf_hash{ParseRawUint256Field(add, "leafHash")};
            BOOST_REQUIRE(ParseHexField(add, "leafVersion") == valtype{P2MR_LEAF_VERSION_V1});
            BOOST_REQUIRE(control_block == valtype{P2MR_LEAF_VERSION_V1_CONTROL});
            BOOST_CHECK_EQUAL(leaf_hash, ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_script));
            BOOST_CHECK(ParseScriptField(add, "scriptPubKey") == BuildP2MRScriptPubKey(leaf_hash));
            BOOST_REQUIRE_LT(input_index, tx.vin.size());
            BOOST_REQUIRE_EQUAL(tx.vin[input_index].scriptWitness.stack.size(), 3U);
            BOOST_CHECK(tx.vin[input_index].scriptWitness.stack[0] == ParseHexField(add, "signature"));
            BOOST_CHECK(tx.vin[input_index].scriptWitness.stack[1] == leaf_script);
            BOOST_CHECK(tx.vin[input_index].scriptWitness.stack[2] == control_block);
            return ExecuteBoundaryFixtureSpend(tx, spent_outputs, input_index, flags);
        }
        if (kind == "legacy-checksig" || kind == "legacy-checkmultisig") {
            CheckExactObjectKeys(parameters, {"kind"}, "boundary legacy opcode parameters");
            const CScript leaf_script{CScript{} << (kind == "legacy-checksig" ? OP_CHECKSIG : OP_CHECKMULTISIG)};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, {}, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        if (kind == "ctv-fixed") {
            CheckExactObjectKeys(
                parameters,
                {"kind", "control_block", "template_hash", "leaf_script", "script_pubkey"},
                "boundary fixed CTV parameters");
            const CScript leaf_script{ParseScriptField(parameters, "leaf_script")};
            const CScript script_pubkey{ParseScriptField(parameters, "script_pubkey")};
            const valtype control_block{ParseHexField(parameters, "control_block")};
            const uint256 template_hash{ParseRawUint256Field(parameters, "template_hash")};
            BOOST_REQUIRE(control_block == valtype{P2MR_LEAF_VERSION_V1_CONTROL});
            BOOST_CHECK(leaf_script == BuildCTVScript(template_hash));
            BOOST_CHECK(script_pubkey == BuildP2MRScriptPubKey(
                                             ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script))));
            P2MRSpendContext spend{BuildP2MRSpend(script_pubkey, leaf_script, {}, control_block)};
            return ExecuteBoundarySpend(spend, flags);
        }
        if (kind == "checkdatasigpqc-valid") {
            CheckExactObjectKeys(parameters, {"kind", "fixture_file", "fixture_id", "artifact"}, "boundary CHECKDATASIGPQC fixture parameters");
            CheckBoundaryFixtureSelector(parameters, "dataSig");
            const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
            const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
            const CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
            return ExecuteBoundaryFixtureSpend(tx, BuildDataSigSpentOutputs(vector), 0, flags);
        }
        if (kind == "checkdatasigaddpqc-valid") {
            CheckExactObjectKeys(parameters, {"kind", "fixture_file", "fixture_id", "artifact"}, "boundary CHECKDATASIGADDPQC fixture parameters");
            CheckBoundaryFixtureSelector(parameters, "dataSigAdd");
            const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
            const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
            BOOST_REQUIRE(vector.data_sig_add);
            const DataSigAddVector& add{*vector.data_sig_add};
            const CMutableTransaction tx{BuildDataSigAddNOfNVectorSpend(add)};
            const std::vector<CTxOut> spent_outputs{BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey)};
            return ExecuteBoundaryFixtureSpend(tx, spent_outputs, 0, flags);
        }
        if (kind == "op-success" || kind == "disabled") {
            CheckExactObjectKeys(parameters, {"kind"}, "boundary reserved opcode parameters");
            const opcodetype opcode{kind == "op-success" ? OP_RESERVED : OP_VERIF};
            const CScript leaf_script{CScript{} << opcode};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, {}, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        BOOST_FAIL("unknown boundary opcode kind: " + kind);
    }

    if (scenario == "resource") {
        const std::string kind{parameters["kind"].get_str()};
        if (kind == "stack-items" || kind == "item-bytes" || kind == "total-bytes") {
            CheckExactObjectKeys(parameters, {"kind", "value"}, "boundary size resource parameters");
            const int value{parameters["value"].getInt<int>()};
            BOOST_REQUIRE_GE(value, 0);
            std::vector<valtype> stack_items;
            if (kind == "stack-items") stack_items.resize(value);
            if (kind == "item-bytes") stack_items.emplace_back(value, 0x01);
            if (kind == "total-bytes") stack_items = BuildP2MRStackItemsForTotalBytes(value);
            const CScript leaf_script{BuildDropAllScript(stack_items.size())};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, stack_items, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        if (kind == "validation-weight") {
            CheckExactObjectKeys(parameters, {"kind", "nonempty_checks", "fixture_file", "fixture_id", "artifact"}, "boundary validation resource parameters");
            const int checks{parameters["nonempty_checks"].getInt<int>()};
            BOOST_REQUIRE(checks == 1 || checks == 2);
            const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
            const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
            CMutableTransaction tx;
            std::vector<CTxOut> spent_outputs;
            uint32_t input_index{0};
            if (checks == 1) {
                CheckBoundaryFixtureSelector(parameters, "transaction-checksigpqc");
                tx = vector.spend_tx;
                spent_outputs = vector.spent_outputs;
                input_index = vector.input_index;
            } else {
                CheckBoundaryFixtureSelector(parameters, "dataSigAdd");
                BOOST_REQUIRE(vector.data_sig_add);
                const DataSigAddVector& add{*vector.data_sig_add};
                tx = BuildDataSigAddNOfNVectorSpend(add);
                spent_outputs = BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey);
            }
            const int64_t budget{static_cast<int64_t>(GetSerializeSize(tx.vin[input_index].scriptWitness.stack)) + VALIDATION_WEIGHT_OFFSET};
            BOOST_CHECK_GE(budget, checks * VALIDATION_WEIGHT_PER_SIGOP_PQC);
            BOOST_CHECK_LT(budget, (checks + 1) * VALIDATION_WEIGHT_PER_SIGOP_PQC);
            return ExecuteBoundaryFixtureSpend(tx, spent_outputs, input_index, flags);
        }
        if (kind == "validation-weight-exceeded") {
            CheckExactObjectKeys(parameters, {"kind", "nonempty_checks"}, "boundary exceeded-weight parameters");
            BOOST_REQUIRE_EQUAL(parameters["nonempty_checks"].getInt<int>(), 2);
            const CScript leaf_script{CScript{}
                                      << OP_0
                                      << valtype(PQC_PUBKEY_SIZE, 0x11) << OP_CHECKSIGADD
                                      << valtype(PQC_PUBKEY_SIZE, 0x22) << OP_CHECKSIGADD
                                      << OP_2 << OP_EQUAL};
            P2MRSpendContext spend{BuildP2MRSpend(
                leaf_script, {valtype{0x01}, valtype{0x01}}, {P2MR_LEAF_VERSION_V1_CONTROL},
                ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script))};
            const int64_t budget{static_cast<int64_t>(GetSerializeSize(spend.tx_spend.vin[0].scriptWitness.stack)) + VALIDATION_WEIGHT_OFFSET};
            BOOST_CHECK_LT(budget, VALIDATION_WEIGHT_PER_SIGOP_PQC);
            return ExecuteBoundarySpend(spend, flags);
        }
        if (kind == "empty-signatures") {
            CheckExactObjectKeys(parameters, {"kind", "nonempty_checks"}, "boundary empty-signature parameters");
            BOOST_REQUIRE_EQUAL(parameters["nonempty_checks"].getInt<int>(), 0);
            CPQCKey key_a;
            CPQCKey key_b;
            key_a.MakeNewKey();
            key_b.MakeNewKey();
            const CScript leaf_script{BuildP2MRMultiAScript(0, {key_a.GetPubKey(), key_b.GetPubKey()})};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, {valtype{}, valtype{}}, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        if (kind == "clean-stack" || kind == "false-final") {
            CheckExactObjectKeys(parameters, {"kind", "value"}, "boundary final-stack parameters");
            const CScript leaf_script{kind == "clean-stack" ? CScript{} << OP_TRUE << OP_TRUE : CScript{} << OP_FALSE};
            return ExecuteBoundarySpend(BuildP2MRSpend(
                                            leaf_script, {}, {P2MR_LEAF_VERSION_V1_CONTROL},
                                            ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, leaf_script)),
                                        flags);
        }
        BOOST_FAIL("unknown boundary resource kind: " + kind);
    }

    BOOST_FAIL("unknown P2MR boundary scenario: " + scenario);
    return {false, SCRIPT_ERR_UNKNOWN_ERROR};
}

void CheckVectorMutationFails(const P2MRWitnessVector& vector, CMutableTransaction tx, std::vector<CTxOut> spent_outputs, ScriptError expected_error)
{
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(!VerifyVectorSpend(vector, tx, spent_outputs, err));
    BOOST_CHECK_EQUAL(err, expected_error);
}

void CheckVectorMutationPasses(const P2MRWitnessVector& vector, CMutableTransaction tx, std::vector<CTxOut> spent_outputs)
{
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyVectorSpend(vector, tx, spent_outputs, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
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
            BOOST_CHECK_EQUAL(vec["id"].get_str(), name);
            const UniValue& expected{vec["expected"].get_obj()};
            BOOST_CHECK(expected["accepted"].get_bool());
            BOOST_CHECK_EQUAL(expected["stage"].get_str(), "script-complete");
            BOOST_CHECK_EQUAL(expected["error"].get_str(), "SCRIPT_ERR_OK");
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
            BOOST_CHECK_EQUAL(vec["id"].get_str(), name);
            const UniValue& expected{vec["expected"].get_obj()};
            BOOST_CHECK(!expected["accepted"].get_bool());
            BOOST_CHECK_EQUAL(expected["error"].get_str(), vec["expected_error"].get_str());
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

BOOST_AUTO_TEST_CASE(p2mr_v1_manifest_matches_embedded_corpus)
{
    UniValue manifest;
    BOOST_REQUIRE(manifest.read(json_tests::p2mr_v1_manifest));
    BOOST_REQUIRE(manifest.isObject());
    BOOST_CHECK_EQUAL(manifest["schema_version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(manifest["profile"].get_str(), "qbit-p2mr-v1");
    BOOST_CHECK_EQUAL(manifest["profile_version"].getInt<int>(), 1);

    const std::vector<std::string> keys{manifest.getKeys()};
    const std::set<std::string> actual_keys{keys.begin(), keys.end()};
    const std::set<std::string> expected_keys{
        "schema_version", "profile", "profile_version", "specification",
        "reference_implementation", "ancestry", "case_count", "case_counts", "files"};
    BOOST_REQUIRE_MESSAGE(actual_keys == expected_keys, "P2MR v1 manifest has unknown or missing fields");
    BOOST_CHECK_EQUAL(manifest["specification"].get_str(), "doc/consensus/p2mr-v1.md");

    const UniValue& reference{manifest["reference_implementation"].get_obj()};
    CheckExactObjectKeys(reference, {"repository", "commit"}, "manifest reference_implementation");
    BOOST_CHECK_EQUAL(reference["repository"].get_str(), "Qbit-Org/qbit");
    BOOST_CHECK_EQUAL(reference["commit"].get_str(), "988756471aeecdf4463c04be49da2b7b89a98c21");

    const UniValue& ancestry{manifest["ancestry"].get_obj()};
    CheckExactObjectKeys(ancestry, {"name", "version", "commit", "normative"}, "manifest ancestry");
    BOOST_CHECK_EQUAL(ancestry["name"].get_str(), "BIP-360");
    BOOST_CHECK_EQUAL(ancestry["version"].get_str(), "0.12.0");
    BOOST_CHECK_EQUAL(ancestry["commit"].get_str(), "6740c533e8dce4e912f17ee85a6f627644e1b783");
    BOOST_CHECK(!ancestry["normative"].get_bool());

    const UniValue& counts{manifest["case_counts"].get_obj()};
    CheckExactObjectKeys(
        counts,
        {"commitment_valid", "commitment_invalid", "witness", "cross_profile", "script_boundary"},
        "manifest case_counts");
    BOOST_CHECK_EQUAL(counts["commitment_valid"].getInt<int>(), 4);
    BOOST_CHECK_EQUAL(counts["commitment_invalid"].getInt<int>(), 7);
    BOOST_CHECK_EQUAL(counts["witness"].getInt<int>(), 14);
    BOOST_CHECK_EQUAL(counts["cross_profile"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(counts["script_boundary"].getInt<int>(), 43);
    BOOST_CHECK_EQUAL(manifest["case_count"].getInt<int>(), 70);

    struct ManifestFile {
        std::string_view bytes;
        int case_count;
        std::string_view purpose;
    };
    const std::map<std::string, ManifestFile> embedded_files{
        {"src/test/data/p2mr_cross_profile_vectors.json",
         {json_tests::p2mr_cross_profile_vectors, 2, "qbit and pinned-profile boundary vectors"}},
        {"src/test/data/p2mr_pqc_witness_vectors.json",
         {json_tests::p2mr_pqc_witness_vectors, 14, "PQC sighash and witness vectors"}},
        {"src/test/data/p2mr_script_boundary_vectors.json",
         {json_tests::p2mr_script_boundary_vectors, 43, "script, control, leaf, opcode, and resource boundary vectors"}},
        {"src/test/data/p2mr_vectors.json",
         {json_tests::p2mr_vectors, 11, "commitment, control block, root, and address vectors"}},
    };
    const UniValue& files{manifest["files"]};
    BOOST_REQUIRE(files.isArray());
    BOOST_REQUIRE_EQUAL(files.size(), embedded_files.size());
    std::string previous_path;
    for (const UniValue& entry : files.getValues()) {
        CheckExactObjectKeys(entry, {"path", "purpose", "case_count", "sha256"}, "manifest file entry");
        const std::string path{entry["path"].get_str()};
        BOOST_CHECK(previous_path.empty() || previous_path < path);
        previous_path = path;
        const auto it{embedded_files.find(path)};
        BOOST_REQUIRE_MESSAGE(it != embedded_files.end(), "unknown manifest path " << path);
        BOOST_CHECK_EQUAL(entry["purpose"].get_str(), it->second.purpose);
        BOOST_CHECK_EQUAL(entry["case_count"].getInt<int>(), it->second.case_count);
        BOOST_CHECK_EQUAL(entry["sha256"].get_str(), Sha256Hex(it->second.bytes));
    }
}

BOOST_AUTO_TEST_CASE(p2mr_v1_cross_profile_qbit_results)
{
    UniValue corpus;
    BOOST_REQUIRE(corpus.read(json_tests::p2mr_cross_profile_vectors));
    BOOST_REQUIRE(corpus.isObject());
    BOOST_CHECK_EQUAL(corpus["schema_version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(corpus["profile"].get_str(), "qbit-p2mr-v1");
    BOOST_CHECK_EQUAL(corpus["profile_version"].getInt<int>(), 1);
    const std::vector<std::string> keys{corpus.getKeys()};
    const std::set<std::string> actual_keys{keys.begin(), keys.end()};
    const std::set<std::string> expected_keys{
        "schema_version", "profile", "profile_version", "comparison_profile", "vectors"};
    BOOST_REQUIRE_MESSAGE(actual_keys == expected_keys, "cross-profile corpus has unknown or missing fields");
    const UniValue& comparison_profile{corpus["comparison_profile"].get_obj()};
    CheckExactObjectKeys(
        comparison_profile, {"name", "version", "commit", "normative"}, "cross-profile identity");
    BOOST_CHECK_EQUAL(comparison_profile["name"].get_str(), "BIP-360");
    BOOST_CHECK_EQUAL(comparison_profile["version"].get_str(), "0.12.0");
    BOOST_CHECK_EQUAL(comparison_profile["commit"].get_str(), "6740c533e8dce4e912f17ee85a6f627644e1b783");
    BOOST_CHECK(!comparison_profile["normative"].get_bool());
    BOOST_REQUIRE_EQUAL(corpus["vectors"].size(), 2U);

    for (const UniValue& vec : corpus["vectors"].getValues()) {
        BOOST_TEST_CONTEXT(vec["id"].get_str())
        {
            CheckExactObjectKeys(
                vec,
                {"id", "name", "comparison_scope", "leaf_version", "leaf_script", "control_block",
                 "tapleaf_root", "p2mr_leaf_root", "scriptPubKey", "witness", "expected"},
                "cross-profile vector");
            BOOST_CHECK_EQUAL(vec["leaf_version"].get_str(), "c0");
            const CScript leaf_script{ScriptFromHex(vec["leaf_script"].get_str().c_str())};
            const std::vector<unsigned char> control_block{ParseHex(vec["control_block"].get_str())};
            const uint256 tapleaf_root{VectorHash(vec, "tapleaf_root")};
            const uint256 p2mr_leaf_root{VectorHash(vec, "p2mr_leaf_root")};
            BOOST_CHECK_EQUAL(ComputeTapleafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script)), tapleaf_root);
            BOOST_CHECK_EQUAL(ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf_script)), p2mr_leaf_root);
            BOOST_CHECK_NE(tapleaf_root, p2mr_leaf_root);

            const auto& witness{vec["witness"].getValues()};
            BOOST_REQUIRE_EQUAL(witness.size(), 2U);
            BOOST_CHECK_EQUAL(witness[0].get_str(), vec["leaf_script"].get_str());
            BOOST_CHECK_EQUAL(witness[1].get_str(), vec["control_block"].get_str());

            const CScript script_pubkey{ScriptFromHex(vec["scriptPubKey"].get_str().c_str())};
            const std::string vector_id{vec["id"].get_str()};
            const UniValue& all_expected{vec["expected"].get_obj()};
            const UniValue* comparison_expected{nullptr};
            if (vector_id == "pinned-bip-root-rejected-by-qbit") {
                BOOST_CHECK_EQUAL(vec["comparison_scope"].get_str(), "full-pinned-profile");
                CheckExactObjectKeys(all_expected, {"pinned_bip_360", "qbit_p2mr_v1"}, "cross-profile expected");
                comparison_expected = &all_expected["pinned_bip_360"];
                BOOST_CHECK(script_pubkey == BuildP2MRScriptPubKey(tapleaf_root));
            } else {
                BOOST_REQUIRE_EQUAL(vector_id, "qbit-root-executes-depth-zero-script");
                BOOST_CHECK_EQUAL(vec["comparison_scope"].get_str(), "isolated-depth-zero-rule-with-qbit-tags");
                CheckExactObjectKeys(
                    all_expected,
                    {"bip_style_depth_zero_with_qbit_tags", "qbit_p2mr_v1"},
                    "cross-profile expected");
                comparison_expected = &all_expected["bip_style_depth_zero_with_qbit_tags"];
                BOOST_CHECK(script_pubkey == BuildP2MRScriptPubKey(p2mr_leaf_root));
            }
            CheckExactObjectKeys(*comparison_expected, {"accepted", "stage", "error"}, "comparison-side expected");
            BOOST_CHECK((*comparison_expected)["accepted"].get_bool());
            BOOST_CHECK_EQUAL((*comparison_expected)["stage"].get_str(), "depth-zero-shortcut");
            BOOST_CHECK_EQUAL((*comparison_expected)["error"].get_str(), "SCRIPT_ERR_OK");

            const P2MRSpendContext spend{BuildP2MRSpend(
                script_pubkey, leaf_script, /*stack_items=*/{}, control_block)};
            const UniValue& expected{all_expected["qbit_p2mr_v1"].get_obj()};
            CheckExactObjectKeys(expected, {"accepted", "stage", "error"}, "qbit expected");
            BOOST_CHECK(!expected["accepted"].get_bool());
            const std::string error_name{expected["error"].get_str()};
            BOOST_CHECK_EQUAL(
                expected["stage"].get_str(),
                error_name == "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH" ? "commitment" : "script-execution");
            BOOST_CHECK(
                error_name == "SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH" || error_name == "SCRIPT_ERR_EVAL_FALSE");
            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS, err));
            BOOST_CHECK_EQUAL(err, VectorScriptError(error_name));
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
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    bool saw_non_default_codeseparator{false};
    bool saw_zero_codeseparator{false};
    bool saw_same_leaf_different_codeseparators{false};
    std::map<valtype, std::set<uint32_t>> codeseparators_by_leaf;

    for (const P2MRWitnessVector& vector : vectors) {
        if (vector.expected_error != SCRIPT_ERR_OK) continue;

        const CScript leaf_script{vector.leaf_script.begin(), vector.leaf_script.end()};
        const PrecomputedTransactionData txdata{PrecomputeVectorData(vector.spend_tx, vector.spent_outputs)};
        BOOST_REQUIRE(vector.p2mr_sigmsg);
        BOOST_REQUIRE(vector.p2mr_sighash);
        BOOST_REQUIRE(vector.wrong_domain_sighash);

        BOOST_TEST_CONTEXT(vector.name) {
            saw_non_default_codeseparator |= vector.codeseparator_pos != 0xFFFFFFFFUL;
            saw_zero_codeseparator |= vector.codeseparator_pos == 0;
            codeseparators_by_leaf[vector.leaf_script].insert(vector.codeseparator_pos);

            BOOST_CHECK_EQUAL(
                HexStr(ToByteVector((HashWriter{HASHER_P2MR_SIGHASH} << std::span<const uint8_t>{*vector.p2mr_sigmsg}).GetSHA256())),
                HexStr(ToByteVector(*vector.p2mr_sighash)));
            BOOST_CHECK_EQUAL(
                HexStr(ToByteVector((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{*vector.p2mr_sigmsg}).GetSHA256())),
                HexStr(ToByteVector(*vector.wrong_domain_sighash)));
            if (vector.wrong_codeseparator_sigmsg) {
                BOOST_REQUIRE(vector.wrong_codeseparator_sighash);
                BOOST_REQUIRE(vector.wrong_codeseparator_pos);
                BOOST_CHECK_EQUAL(
                    HexStr(ToByteVector((HashWriter{HASHER_P2MR_SIGHASH} << std::span<const uint8_t>{*vector.wrong_codeseparator_sigmsg}).GetSHA256())),
                    HexStr(ToByteVector(*vector.wrong_codeseparator_sighash)));
                BOOST_CHECK_NE(vector.codeseparator_pos, *vector.wrong_codeseparator_pos);
            }

            if (vector.codeseparator_pos != 0xFFFFFFFFUL) {
                static constexpr std::array<unsigned char, 4> DEFAULT_CODESEPARATOR_BYTES{0xff, 0xff, 0xff, 0xff};
                BOOST_REQUIRE_GE(vector.p2mr_sigmsg->size(), DEFAULT_CODESEPARATOR_BYTES.size());
                BOOST_CHECK(!std::equal(
                    DEFAULT_CODESEPARATOR_BYTES.begin(),
                    DEFAULT_CODESEPARATOR_BYTES.end(),
                    vector.p2mr_sigmsg->end() - DEFAULT_CODESEPARATOR_BYTES.size()));
            }

            ScriptExecutionData execdata = vector.annex ?
                BuildExecData(leaf_script, vector.codeseparator_pos, *vector.annex) :
                BuildExecData(leaf_script, vector.codeseparator_pos);
            if (vector.annex) {
                BOOST_REQUIRE(vector.annex_hash);
                BOOST_REQUIRE(vector.no_annex_sigmsg);
                BOOST_REQUIRE(vector.no_annex_sighash);
                BOOST_CHECK_EQUAL(HexStr(ToByteVector(execdata.m_annex_hash)), HexStr(ToByteVector(*vector.annex_hash)));
                BOOST_CHECK_EQUAL(
                    HexStr(ToByteVector((HashWriter{HASHER_P2MR_SIGHASH} << std::span<const uint8_t>{*vector.no_annex_sigmsg}).GetSHA256())),
                    HexStr(ToByteVector(*vector.no_annex_sighash)));
            }

            uint256 sighash;
            BOOST_REQUIRE(SignatureHashP2MR(
                sighash,
                execdata,
                vector.spend_tx,
                vector.input_index,
                vector.hash_type,
                txdata,
                MissingDataBehavior::ASSERT_FAIL));
            BOOST_CHECK_EQUAL(HexStr(ToByteVector(sighash)), HexStr(ToByteVector(*vector.p2mr_sighash)));
            BOOST_REQUIRE(vector.pubkey.Verify(*vector.p2mr_sighash, vector.raw_signature));
            BOOST_REQUIRE(!vector.pubkey.Verify(*vector.wrong_domain_sighash, vector.raw_signature));
            if (vector.wrong_codeseparator_sighash) {
                BOOST_REQUIRE(vector.wrong_codeseparator_pos);
                BOOST_REQUIRE(vector.wrong_codeseparator_signature);
                ScriptExecutionData wrong_codeseparator_execdata = BuildExecData(leaf_script, *vector.wrong_codeseparator_pos);
                uint256 wrong_codeseparator_sighash;
                BOOST_REQUIRE(SignatureHashP2MR(
                    wrong_codeseparator_sighash,
                    wrong_codeseparator_execdata,
                    vector.spend_tx,
                    vector.input_index,
                    vector.hash_type,
                    txdata,
                    MissingDataBehavior::ASSERT_FAIL));
                BOOST_CHECK_EQUAL(
                    HexStr(ToByteVector(wrong_codeseparator_sighash)),
                    HexStr(ToByteVector(*vector.wrong_codeseparator_sighash)));
                BOOST_REQUIRE(vector.pubkey.Verify(*vector.wrong_codeseparator_sighash, *vector.wrong_codeseparator_signature));
                BOOST_REQUIRE(!vector.pubkey.Verify(*vector.p2mr_sighash, *vector.wrong_codeseparator_signature));
            }

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(VerifyVectorSpend(vector, err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        }
    }

    for (const auto& [leaf_script, codeseparator_positions] : codeseparators_by_leaf) {
        saw_same_leaf_different_codeseparators |= codeseparator_positions.size() > 1;
    }
    BOOST_CHECK(saw_non_default_codeseparator);
    BOOST_CHECK(saw_zero_codeseparator);
    BOOST_CHECK(saw_same_leaf_different_codeseparators);
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_independent_witness_vector_near_misses)
{
    static constexpr uint8_t INVALID_SIGHASH_TYPE{0x04};

    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_REQUIRE(VerifyVectorSpend(vector, err));
        BOOST_REQUIRE_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[vector.input_index].scriptWitness.stack[0][0] ^= 0x01;
        CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[vector.input_index].scriptWitness.stack[0] = vector.raw_signature;
        tx.vin[vector.input_index].scriptWitness.stack[0][1] ^= 0x01;
        CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[vector.input_index].scriptWitness.stack[0].push_back(SIGHASH_DEFAULT);
        CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[vector.input_index].scriptWitness.stack[0].push_back(INVALID_SIGHASH_TYPE);
        CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        tx.vin[vector.input_index].scriptWitness.stack[1][1] ^= 0x01;
        CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    {
        CMutableTransaction tx{vector.spend_tx};
        valtype wrong_pubkey_leaf{vector.leaf_script};
        wrong_pubkey_leaf[1] ^= 0x01;
        const CScript wrong_pubkey_leaf_script{wrong_pubkey_leaf.begin(), wrong_pubkey_leaf.end()};
        std::vector<CTxOut> spent_outputs{vector.spent_outputs};
        spent_outputs[vector.input_index].scriptPubKey =
            BuildP2MRScriptPubKey(ComputeMerkleRootSingleLeaf(P2MR_LEAF_VERSION_V1, wrong_pubkey_leaf_script));
        tx.vin[vector.input_index].scriptWitness.stack[1] = std::move(wrong_pubkey_leaf);
        CheckVectorMutationFails(vector, tx, spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    const P2MRWitnessVector& annex_vector{FindVector(vectors, "single_key_default_sighash_annex_present")};
    BOOST_REQUIRE(annex_vector.annex);
    BOOST_REQUIRE(annex_vector.p2mr_sighash);
    BOOST_REQUIRE(annex_vector.no_annex_sighash);
    BOOST_REQUIRE(annex_vector.no_annex_signature);
    BOOST_REQUIRE(annex_vector.pubkey.Verify(*annex_vector.no_annex_sighash, *annex_vector.no_annex_signature));
    BOOST_REQUIRE(!annex_vector.pubkey.Verify(*annex_vector.p2mr_sighash, *annex_vector.no_annex_signature));
    {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_REQUIRE(VerifyVectorSpend(annex_vector, err));
        BOOST_REQUIRE_EQUAL(err, SCRIPT_ERR_OK);
    }
    {
        CMutableTransaction tx{annex_vector.spend_tx};
        tx.vin[annex_vector.input_index].scriptWitness.stack.pop_back();
        CheckVectorMutationFails(annex_vector, tx, annex_vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }
    {
        CMutableTransaction tx{annex_vector.spend_tx};
        BOOST_REQUIRE_GT(tx.vin[annex_vector.input_index].scriptWitness.stack[3].size(), 1U);
        tx.vin[annex_vector.input_index].scriptWitness.stack[3].back() ^= 0x01;
        CheckVectorMutationFails(annex_vector, tx, annex_vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }
    {
        CMutableTransaction tx{annex_vector.spend_tx};
        tx.vin[annex_vector.input_index].scriptWitness.stack[0] = *annex_vector.no_annex_signature;
        CheckVectorMutationFails(annex_vector, tx, annex_vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    const P2MRWitnessVector& leading_codesep_vector{FindVector(vectors, "single_key_leading_codesep")};
    BOOST_REQUIRE(leading_codesep_vector.wrong_codeseparator_sighash);
    BOOST_REQUIRE(leading_codesep_vector.wrong_codeseparator_signature);
    BOOST_REQUIRE(leading_codesep_vector.pubkey.Verify(
        *leading_codesep_vector.wrong_codeseparator_sighash,
        *leading_codesep_vector.wrong_codeseparator_signature));
    BOOST_REQUIRE(!leading_codesep_vector.pubkey.Verify(
        *leading_codesep_vector.p2mr_sighash,
        *leading_codesep_vector.wrong_codeseparator_signature));
    {
        CMutableTransaction tx{leading_codesep_vector.spend_tx};
        tx.vin[leading_codesep_vector.input_index].scriptWitness.stack[0] = *leading_codesep_vector.wrong_codeseparator_signature;
        CheckVectorMutationFails(leading_codesep_vector, tx, leading_codesep_vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    const P2MRWitnessVector& branch_true{FindVector(vectors, "branch_codesep_true")};
    const P2MRWitnessVector& branch_false{FindVector(vectors, "branch_codesep_false")};
    {
        CMutableTransaction tx{branch_true.spend_tx};
        tx.vin[branch_true.input_index].scriptWitness.stack[0] = branch_false.witness_signature;
        CheckVectorMutationFails(branch_true, tx, branch_true.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }
    {
        CMutableTransaction tx{branch_false.spend_tx};
        tx.vin[branch_false.input_index].scriptWitness.stack[0] = branch_true.witness_signature;
        CheckVectorMutationFails(branch_false, tx, branch_false.spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_rejects_independent_sighash_single_missing_output)
{
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    static constexpr std::array<std::string_view, 4> MISSING_OUTPUT_VECTOR_NAMES{{
        "single_key_sighash_single_missing_first",
        "single_key_sighash_single_missing_beyond",
        "single_key_sighash_single_anyonecanpay_missing_first",
        "single_key_sighash_single_anyonecanpay_missing_beyond",
    }};

    for (const std::string_view name : MISSING_OUTPUT_VECTOR_NAMES) {
        const P2MRWitnessVector& vector{FindVector(vectors, name)};
        BOOST_TEST_CONTEXT(vector.name) {
            BOOST_REQUIRE_EQUAL(vector.expected_error, SCRIPT_ERR_P2MR_SIG_HASHTYPE);
            BOOST_REQUIRE(vector.hash_type == SIGHASH_SINGLE || vector.hash_type == (SIGHASH_SINGLE | SIGHASH_ANYONECANPAY));
            BOOST_REQUIRE_EQUAL(vector.witness_signature.size(), PQC_SIG_SIZE + 1);
            BOOST_CHECK_EQUAL(vector.witness_signature.back(), vector.hash_type);
            BOOST_REQUIRE_GE(vector.input_index, vector.spend_tx.vout.size());
            BOOST_CHECK(!vector.p2mr_sigmsg);
            BOOST_CHECK(!vector.p2mr_sighash);

            const CScript leaf_script{vector.leaf_script.begin(), vector.leaf_script.end()};
            const PrecomputedTransactionData txdata{PrecomputeVectorData(vector.spend_tx, vector.spent_outputs)};
            ScriptExecutionData execdata = BuildExecData(leaf_script, vector.codeseparator_pos);
            uint256 sighash;
            // P2MR rejects missing-output SIGHASH_SINGLE instead of defining a
            // digest or inheriting legacy's uint256::ONE behavior.
            BOOST_CHECK(!SignatureHashP2MR(
                sighash,
                execdata,
                vector.spend_tx,
                vector.input_index,
                vector.hash_type,
                txdata,
                MissingDataBehavior::FAIL));

            ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
            BOOST_CHECK(!VerifyVectorSpend(vector, err));
            BOOST_CHECK_EQUAL(err, vector.expected_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checksigpqc_independent_witness_vectors_commit_expected_fields)
{
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};

    const auto other_input_index = [](const P2MRWitnessVector& vector) {
        BOOST_REQUIRE_GE(vector.spend_tx.vin.size(), 2U);
        return vector.input_index == 0 ? 1U : 0U;
    };
    const auto alternate_hash_type = [](uint8_t hash_type) -> uint8_t {
        switch (hash_type) {
        case SIGHASH_NONE:
            return SIGHASH_ALL;
        case SIGHASH_SINGLE:
            return SIGHASH_ALL;
        case SIGHASH_ALL | SIGHASH_ANYONECANPAY:
            return SIGHASH_NONE | SIGHASH_ANYONECANPAY;
        case SIGHASH_NONE | SIGHASH_ANYONECANPAY:
            return SIGHASH_ALL | SIGHASH_ANYONECANPAY;
        case SIGHASH_SINGLE | SIGHASH_ANYONECANPAY:
            return SIGHASH_ALL | SIGHASH_ANYONECANPAY;
        }
        assert(false);
    };

    const auto check_common_committed_fields = [&](const P2MRWitnessVector& vector) {
        BOOST_TEST_CONTEXT(vector.name) {
            {
                CMutableTransaction tx{vector.spend_tx};
                tx.version += 1;
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
            {
                CMutableTransaction tx{vector.spend_tx};
                tx.nLockTime += 1;
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
            {
                CMutableTransaction tx{vector.spend_tx};
                tx.vin[vector.input_index].prevout.n ^= 1;
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
            {
                CMutableTransaction tx{vector.spend_tx};
                tx.vin[vector.input_index].nSequence -= 1;
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
            {
                std::vector<CTxOut> spent_outputs{vector.spent_outputs};
                spent_outputs[vector.input_index].nValue += 1;
                CheckVectorMutationFails(vector, vector.spend_tx, spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
            {
                CMutableTransaction tx{vector.spend_tx};
                tx.vin[vector.input_index].scriptWitness.stack[1][1] ^= 0x01;
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
            {
                CMutableTransaction tx{vector.spend_tx};
                tx.vin[vector.input_index].scriptWitness.stack[0].back() = alternate_hash_type(vector.hash_type);
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
        }
    };

    const auto mutate_other_input = [&](const P2MRWitnessVector& vector, bool should_pass) {
        const size_t other_index{other_input_index(vector)};
        {
            CMutableTransaction tx{vector.spend_tx};
            tx.vin[other_index].prevout.n ^= 1;
            if (should_pass) {
                CheckVectorMutationPasses(vector, tx, vector.spent_outputs);
            } else {
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
        }
        {
            CMutableTransaction tx{vector.spend_tx};
            tx.vin[other_index].nSequence -= 1;
            if (should_pass) {
                CheckVectorMutationPasses(vector, tx, vector.spent_outputs);
            } else {
                CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
        }
        {
            std::vector<CTxOut> spent_outputs{vector.spent_outputs};
            spent_outputs[other_index].nValue += 1;
            if (should_pass) {
                CheckVectorMutationPasses(vector, vector.spend_tx, spent_outputs);
            } else {
                CheckVectorMutationFails(vector, vector.spend_tx, spent_outputs, SCRIPT_ERR_P2MR_SIG);
            }
        }
    };

    const auto mutate_output = [&](const P2MRWitnessVector& vector, size_t output_index, bool should_pass) {
        BOOST_REQUIRE_LT(output_index, vector.spend_tx.vout.size());
        CMutableTransaction tx{vector.spend_tx};
        tx.vout[output_index].nValue += 1;
        if (should_pass) {
            CheckVectorMutationPasses(vector, tx, vector.spent_outputs);
        } else {
            CheckVectorMutationFails(vector, tx, vector.spent_outputs, SCRIPT_ERR_P2MR_SIG);
        }
    };

    {
        const P2MRWitnessVector& vector{FindVector(vectors, "single_key_sighash_none")};
        check_common_committed_fields(vector);
        mutate_other_input(vector, /*should_pass=*/false);
        mutate_output(vector, /*output_index=*/0, /*should_pass=*/true);
        mutate_output(vector, /*output_index=*/1, /*should_pass=*/true);
    }
    {
        const P2MRWitnessVector& vector{FindVector(vectors, "single_key_sighash_single_matching_output")};
        check_common_committed_fields(vector);
        mutate_other_input(vector, /*should_pass=*/false);
        mutate_output(vector, /*output_index=*/0, /*should_pass=*/false);
        mutate_output(vector, /*output_index=*/1, /*should_pass=*/true);
    }
    {
        const P2MRWitnessVector& vector{FindVector(vectors, "single_key_sighash_all_anyonecanpay")};
        check_common_committed_fields(vector);
        mutate_other_input(vector, /*should_pass=*/true);
        mutate_output(vector, /*output_index=*/0, /*should_pass=*/false);
        mutate_output(vector, /*output_index=*/1, /*should_pass=*/false);
    }
    {
        const P2MRWitnessVector& vector{FindVector(vectors, "single_key_sighash_none_anyonecanpay")};
        check_common_committed_fields(vector);
        mutate_other_input(vector, /*should_pass=*/true);
        mutate_output(vector, /*output_index=*/0, /*should_pass=*/true);
        mutate_output(vector, /*output_index=*/1, /*should_pass=*/true);
    }
    {
        const P2MRWitnessVector& vector{FindVector(vectors, "single_key_sighash_single_anyonecanpay")};
        check_common_committed_fields(vector);
        mutate_other_input(vector, /*should_pass=*/true);
        mutate_output(vector, /*output_index=*/0, /*should_pass=*/false);
        mutate_output(vector, /*output_index=*/1, /*should_pass=*/true);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_accepts_independent_data_signature_vector)
{
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
    BOOST_REQUIRE(vector.data_sig_message_hash);
    BOOST_REQUIRE(vector.data_sig_hash);
    BOOST_REQUIRE(vector.data_sig_leaf_script);
    BOOST_REQUIRE(vector.data_sig_control_block);
    BOOST_REQUIRE(vector.data_sig_pubkey);
    BOOST_REQUIRE(vector.data_sig_signature);

    const valtype& data_sig_message_hash{*vector.data_sig_message_hash};
    const uint256& data_sig_hash{*vector.data_sig_hash};
    const valtype& data_sig_leaf_script{*vector.data_sig_leaf_script};
    const valtype& data_sig_control_block{*vector.data_sig_control_block};
    const CPQCPubKey& data_sig_pubkey{*vector.data_sig_pubkey};
    const valtype& data_sig_signature{*vector.data_sig_signature};

    const uint256 computed_datasig_hash{ComputeQbitDataSigPQCHash(data_sig_message_hash)};
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(computed_datasig_hash)), HexStr(ToByteVector(data_sig_hash)));
    BOOST_REQUIRE(data_sig_pubkey.Verify(data_sig_hash, data_sig_signature));

    const CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 4U);
    BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[0] == data_sig_signature);
    BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[1] == data_sig_message_hash);
    BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[2] == data_sig_leaf_script);
    BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[3] == data_sig_control_block);

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(VerifyVectorSpend(vector, tx, BuildDataSigSpentOutputs(vector), err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigpqc_rejects_independent_data_signature_vector_near_misses)
{
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
    BOOST_REQUIRE(vector.data_sig_message_hash);
    BOOST_REQUIRE(vector.data_sig_hash);
    BOOST_REQUIRE(vector.data_sig_pubkey);
    BOOST_REQUIRE(vector.data_sig_raw_message_signature);
    BOOST_REQUIRE(vector.data_sig_wrong_pubkey_script_pubkey);
    BOOST_REQUIRE(vector.data_sig_wrong_pubkey_leaf_script);

    const valtype& data_sig_message_hash{*vector.data_sig_message_hash};
    const uint256& data_sig_hash{*vector.data_sig_hash};
    const CPQCPubKey& data_sig_pubkey{*vector.data_sig_pubkey};
    const valtype& data_sig_raw_message_signature{*vector.data_sig_raw_message_signature};
    const CScript& data_sig_wrong_pubkey_script_pubkey{*vector.data_sig_wrong_pubkey_script_pubkey};
    const valtype& data_sig_wrong_pubkey_leaf_script{*vector.data_sig_wrong_pubkey_leaf_script};
    const std::vector<CTxOut> data_sig_spent_outputs{BuildDataSigSpentOutputs(vector)};
    const uint256 raw_message_hash{std::span<const unsigned char>{data_sig_message_hash.data(), data_sig_message_hash.size()}};

    {
        const CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_REQUIRE(VerifyVectorSpend(vector, tx, data_sig_spent_outputs, err));
        BOOST_REQUIRE_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
        tx.vin[0].scriptWitness.stack[0][0] ^= 0x01;
        CheckVectorMutationFails(vector, tx, data_sig_spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    BOOST_REQUIRE(data_sig_pubkey.Verify(raw_message_hash, data_sig_raw_message_signature));
    BOOST_REQUIRE(!data_sig_pubkey.Verify(data_sig_hash, data_sig_raw_message_signature));
    {
        CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
        tx.vin[0].scriptWitness.stack[0] = data_sig_raw_message_signature;
        CheckVectorMutationFails(vector, tx, data_sig_spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
        tx.vin[0].scriptWitness.stack[1][0] ^= 0x01;
        CheckVectorMutationFails(vector, tx, data_sig_spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
        tx.vin[0].scriptWitness.stack[2][1] ^= 0x01;
        CheckVectorMutationFails(vector, tx, data_sig_spent_outputs, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    {
        CMutableTransaction tx{BuildDataSigVectorSpend(vector)};
        tx.vin[0].scriptWitness.stack[2] = data_sig_wrong_pubkey_leaf_script;
        std::vector<CTxOut> wrong_pubkey_spent_outputs{data_sig_spent_outputs};
        wrong_pubkey_spent_outputs[0].scriptPubKey = data_sig_wrong_pubkey_script_pubkey;
        CheckVectorMutationFails(vector, tx, wrong_pubkey_spent_outputs, SCRIPT_ERR_P2MR_SIG);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_accepts_independent_threshold_vectors)
{
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
    BOOST_REQUIRE(vector.data_sig_add);
    const DataSigAddVector& add{*vector.data_sig_add};
    const uint256 computed_datasig_hash{ComputeQbitDataSigPQCHash(add.message_hash)};
    BOOST_CHECK_EQUAL(HexStr(ToByteVector(computed_datasig_hash)), HexStr(ToByteVector(add.data_sig_hash)));
    BOOST_REQUIRE(add.pubkey_a.Verify(add.data_sig_hash, add.signature_a));
    BOOST_REQUIRE(add.pubkey_b.Verify(add.data_sig_hash, add.signature_b));
    BOOST_REQUIRE(add.pubkey_c.Verify(add.data_sig_hash, add.signature_c));

    {
        const CMutableTransaction tx{BuildDataSigAddNOfNVectorSpend(add)};
        BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 4U);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[0] == add.signature_b);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[1] == add.signature_a);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[2] == add.n_of_n_leaf_script);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[3] == add.control_block);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifyVectorSpend(vector, tx, BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey), err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        const CMutableTransaction tx{BuildDataSigAddMOfNVectorSpend(add)};
        BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 5U);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[0] == add.signature_c);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[1].empty());
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[2] == add.signature_a);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[3] == add.m_of_n_leaf_script);
        BOOST_REQUIRE(tx.vin[0].scriptWitness.stack[4] == add.control_block);

        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(VerifyVectorSpend(vector, tx, BuildSingleInputSpentOutputs(vector, add.m_of_n_script_pubkey), err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(p2mr_checkdatasigaddpqc_rejects_independent_threshold_vector_near_misses)
{
    const std::vector<P2MRWitnessVector> vectors{LoadIndependentP2MRWitnessVectors()};
    const P2MRWitnessVector& vector{FindVector(vectors, "single_key_default_sighash")};
    BOOST_REQUIRE(vector.data_sig_add);
    const DataSigAddVector& add{*vector.data_sig_add};
    const uint256 raw_message_hash{std::span<const unsigned char>{add.message_hash.data(), add.message_hash.size()}};

    {
        const CMutableTransaction tx{BuildDataSigAddNOfNVectorSpend(add)};
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_REQUIRE(VerifyVectorSpend(vector, tx, BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey), err));
        BOOST_REQUIRE_EQUAL(err, SCRIPT_ERR_OK);
    }

    {
        CMutableTransaction tx{BuildDataSigAddThresholdFailureVectorSpend(add)};
        CheckVectorMutationFails(vector, tx, BuildSingleInputSpentOutputs(vector, add.m_of_n_script_pubkey), SCRIPT_ERR_EVAL_FALSE);
    }

    {
        CMutableTransaction tx{BuildDataSigAddNOfNVectorSpend(add)};
        tx.vin[0].scriptWitness.stack[0][0] ^= 0x01;
        CheckVectorMutationFails(vector, tx, BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey), SCRIPT_ERR_P2MR_SIG);
    }

    BOOST_REQUIRE(add.pubkey_a.Verify(raw_message_hash, add.raw_message_signature_a));
    BOOST_REQUIRE(!add.pubkey_a.Verify(add.data_sig_hash, add.raw_message_signature_a));
    {
        CMutableTransaction tx{BuildDataSigAddNOfNVectorSpend(add)};
        tx.vin[0].scriptWitness.stack[1] = add.raw_message_signature_a;
        CheckVectorMutationFails(vector, tx, BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey), SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{BuildIndependentP2MRVectorSpend(
            {add.signature_b, add.signature_a},
            add.wrong_message_hash_leaf_script,
            add.control_block)};
        CheckVectorMutationFails(vector, tx, BuildSingleInputSpentOutputs(vector, add.wrong_message_hash_script_pubkey), SCRIPT_ERR_P2MR_SIG);
    }

    {
        CMutableTransaction tx{BuildDataSigAddNOfNVectorSpend(add)};
        tx.vin[0].scriptWitness.stack[2][1] ^= 0x01;
        CheckVectorMutationFails(vector, tx, BuildSingleInputSpentOutputs(vector, add.n_of_n_script_pubkey), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    {
        CMutableTransaction tx{BuildIndependentP2MRVectorSpend(
            {add.signature_b, add.signature_a},
            add.wrong_pubkey_leaf_script,
            add.control_block)};
        CheckVectorMutationFails(vector, tx, BuildSingleInputSpentOutputs(vector, add.wrong_pubkey_script_pubkey), SCRIPT_ERR_P2MR_SIG);
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

BOOST_AUTO_TEST_CASE(p2mr_v1_script_boundary_vectors)
{
    UniValue corpus;
    BOOST_REQUIRE(corpus.read(json_tests::p2mr_script_boundary_vectors));
    CheckExactObjectKeys(
        corpus,
        {"schema_version", "profile", "profile_version", "limits", "cases"},
        "P2MR script boundary corpus");
    BOOST_CHECK_EQUAL(corpus["schema_version"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(corpus["profile"].get_str(), "qbit-p2mr-v1");
    BOOST_CHECK_EQUAL(corpus["profile_version"].getInt<int>(), 1);

    const UniValue& limits{corpus["limits"].get_obj()};
    CheckExactObjectKeys(
        limits,
        {"control_path_max_nodes", "initial_stack_max_items", "initial_stack_item_max_bytes",
         "initial_stack_total_max_bytes", "validation_weight_per_nonempty_pqc_check"},
        "P2MR script boundary limits");
    BOOST_CHECK_EQUAL(limits["control_path_max_nodes"].getInt<size_t>(), P2MR_CONTROL_MAX_NODE_COUNT);
    BOOST_CHECK_EQUAL(limits["initial_stack_max_items"].getInt<int>(), MAX_STACK_SIZE);
    BOOST_CHECK_EQUAL(limits["initial_stack_item_max_bytes"].getInt<unsigned int>(), MAX_P2MR_V1_STACK_ITEM_SIZE);
    BOOST_CHECK_EQUAL(limits["initial_stack_total_max_bytes"].getInt<unsigned int>(), MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES);
    BOOST_CHECK_EQUAL(limits["validation_weight_per_nonempty_pqc_check"].getInt<int64_t>(), VALIDATION_WEIGHT_PER_SIGOP_PQC);

    const UniValue& cases{corpus["cases"]};
    BOOST_REQUIRE(cases.isArray());
    BOOST_REQUIRE_EQUAL(cases.size(), 43U);
    std::set<std::string> ids;
    std::map<std::string, size_t> category_counts;
    const std::map<std::string, std::string> category_scenarios{
        {"witness-control", ""},
        {"leaf-version", "leaf-version"},
        {"opcode", "opcode"},
        {"resource", "resource"},
    };

    for (const UniValue& value : cases.getValues()) {
        const UniValue& test{value.get_obj()};
        CheckExactObjectKeys(
            test,
            {"id", "category", "scenario", "parameters", "consensus", "policy"},
            "P2MR script boundary case");
        const std::string id{test["id"].get_str()};
        const std::string category{test["category"].get_str()};
        const std::string scenario{test["scenario"].get_str()};
        BOOST_REQUIRE_MESSAGE(!id.empty() && ids.insert(id).second, "duplicate or empty boundary id " << id);
        BOOST_REQUIRE_MESSAGE(category_scenarios.contains(category), "unknown boundary category " << category);
        if (category == "witness-control") {
            BOOST_REQUIRE(scenario == "witness-shape" || scenario == "control-path");
        } else {
            BOOST_REQUIRE_EQUAL(scenario, category_scenarios.at(category));
        }
        ++category_counts[category];

        for (const auto& [name, flags] : std::array<std::pair<std::string_view, unsigned int>, 2>{{
                 {"consensus", P2MR_SCRIPT_VERIFY_FLAGS},
                 {"policy", STANDARD_SCRIPT_VERIFY_FLAGS},
             }}) {
            const UniValue& expected{test[std::string{name}].get_obj()};
            CheckExactObjectKeys(expected, {"accepted", "stage", "error"}, "P2MR boundary expected outcome");
            const bool expected_accepted{expected["accepted"].get_bool()};
            const std::string expected_stage{expected["stage"].get_str()};
            const ScriptError expected_error{BoundaryScriptError(expected["error"].get_str())};
            BOOST_REQUIRE(!expected_stage.empty());
            BOOST_REQUIRE_EQUAL(expected_accepted, expected_error == SCRIPT_ERR_OK);

            BOOST_TEST_CONTEXT(id << " (" << name << ")")
            {
                const BoundaryExecution actual{ExecuteP2MRBoundaryCase(test, flags)};
                BOOST_CHECK_EQUAL(actual.accepted, expected_accepted);
                BOOST_CHECK_EQUAL(actual.error, expected_error);
            }
        }
    }

    BOOST_CHECK_EQUAL(category_counts["witness-control"], 10U);
    BOOST_CHECK_EQUAL(category_counts["leaf-version"], 7U);
    BOOST_CHECK_EQUAL(category_counts["opcode"], 14U);
    BOOST_CHECK_EQUAL(category_counts["resource"], 12U);
}

BOOST_AUTO_TEST_SUITE_END()
