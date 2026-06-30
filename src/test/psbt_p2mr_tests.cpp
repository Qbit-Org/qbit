// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqc.h>
#include <psbt.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <span>
#include <vector>

namespace {

CPQCPubKey P2MRPubKey(unsigned char byte)
{
    return CPQCPubKey(std::vector<unsigned char>(CPQCPubKey::SIZE, byte));
}

uint256 ByteHash(unsigned char byte)
{
    return uint256(std::vector<unsigned char>(uint256::size(), byte));
}

std::vector<unsigned char> ControlBlock(unsigned char low_byte, unsigned char fill = 0x00, size_t nodes = 0)
{
    std::vector<unsigned char> control(P2MR_CONTROL_BASE_SIZE + nodes * P2MR_CONTROL_NODE_SIZE, fill);
    control[0] = low_byte;
    return control;
}

std::vector<unsigned char> P2MRSignature(unsigned char fill, bool with_hashtype = false)
{
    std::vector<unsigned char> sig(PQC_SIG_SIZE + (with_hashtype ? 1 : 0), fill);
    if (with_hashtype) sig.back() = SIGHASH_ALL;
    return sig;
}

std::vector<unsigned char> P2MRScriptSigKeyData(const CPQCPubKey& pubkey, const uint256& leaf_hash)
{
    std::vector<unsigned char> key_data(pubkey.begin(), pubkey.end());
    key_data.insert(key_data.end(), leaf_hash.begin(), leaf_hash.end());
    return key_data;
}

PartiallySignedTransaction RoundTrip(const PartiallySignedTransaction& psbt)
{
    DataStream ss{};
    ss << psbt;
    PartiallySignedTransaction decoded;
    ss >> decoded;
    return decoded;
}

DataStream QbitInputProprietary(uint64_t subtype, std::span<const unsigned char> key_data, const std::vector<unsigned char>& value)
{
    DataStream ss{};
    SerializeQbitProprietaryKey(ss, PSBT_IN_PROPRIETARY, subtype, key_data);
    ss << value;
    return ss;
}

DataStream StandardInputP2MRScriptSig(const CPQCPubKey& pubkey, const uint256& leaf_hash, const std::vector<unsigned char>& sig)
{
    DataStream ss{};
    SerializeToVector(ss, PSBT_IN_P2MR_SCRIPT_SIG, std::span{pubkey.data(), pubkey.size()}, leaf_hash);
    ss << sig;
    return ss;
}

DataStream StandardInputP2MRLeafScript(std::span<const unsigned char> control_block, const std::vector<unsigned char>& script, int leaf_version = P2MR_LEAF_VERSION_V1)
{
    DataStream ss{};
    SerializeToVector(ss, PSBT_IN_P2MR_LEAF_SCRIPT, control_block);
    std::vector<unsigned char> value(script.begin(), script.end());
    value.push_back(static_cast<unsigned char>(leaf_version));
    ss << value;
    return ss;
}

std::vector<unsigned char> Vec(const CScript& script)
{
    return std::vector<unsigned char>(script.begin(), script.end());
}

CScript P2MRLeafScript(const CPQCPubKey& pubkey)
{
    return CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
}

CScript P2MRMultiAScript(int threshold, const std::vector<CPQCPubKey>& pubkeys)
{
    CScript script;
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        script << std::vector<unsigned char>(pubkeys[i].begin(), pubkeys[i].end()) << (i == 0 ? OP_CHECKSIGPQC : OP_CHECKSIGADD);
    }
    script << threshold << OP_NUMEQUAL;
    return script;
}

CScript P2MRScriptPubKey(const uint256& merkle_root)
{
    return CScript{} << OP_2 << std::vector<unsigned char>(merkle_root.begin(), merkle_root.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(psbt_p2mr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(psbt_p2mr_roundtrip_preserves_qbit_fields)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0x01)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    const uint256 merkle_root = ByteHash(0x11);
    const uint256 leaf_hash = ByteHash(0x22);
    const std::vector<unsigned char> control_block = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x33, /*nodes=*/1);
    const std::vector<unsigned char> script_sig = P2MRSignature(0xaa);
    const std::vector<unsigned char> leaf_script{OP_TRUE};

    input.m_qbit_p2mr_merkle_root = merkle_root;
    input.m_qbit_p2mr_scripts[std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))].insert(control_block);
    input.m_qbit_p2mr_script_sigs.emplace(std::make_pair(P2MRPubKey(0x44), leaf_hash), script_sig);

    const PartiallySignedTransaction decoded = RoundTrip(psbt);
    const PSBTInput& decoded_input = decoded.inputs.at(0);

    BOOST_CHECK_EQUAL(decoded_input.m_qbit_p2mr_merkle_root, merkle_root);
    BOOST_REQUIRE_EQUAL(decoded_input.m_qbit_p2mr_scripts.size(), 1U);
    BOOST_CHECK(decoded_input.m_qbit_p2mr_scripts.contains(std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))));
    BOOST_CHECK_EQUAL(decoded_input.m_qbit_p2mr_scripts.at(std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))).count(control_block), 1U);
    BOOST_REQUIRE_EQUAL(decoded_input.m_qbit_p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(decoded_input.m_qbit_p2mr_script_sigs.at(std::make_pair(P2MRPubKey(0x44), leaf_hash)) == script_sig);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_roundtrip_preserves_multiple_script_signatures)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0x31)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    const uint256 leaf_hash = ByteHash(0x32);

    input.m_qbit_p2mr_script_sigs.emplace(std::make_pair(P2MRPubKey(0x41), leaf_hash), P2MRSignature(0xa1));
    input.m_qbit_p2mr_script_sigs.emplace(std::make_pair(P2MRPubKey(0x42), leaf_hash), P2MRSignature(0xa2));

    const PartiallySignedTransaction decoded = RoundTrip(psbt);
    const PSBTInput& decoded_input = decoded.inputs.at(0);

    BOOST_REQUIRE_EQUAL(decoded_input.m_qbit_p2mr_script_sigs.size(), 2U);
    BOOST_CHECK(decoded_input.m_qbit_p2mr_script_sigs.at(std::make_pair(P2MRPubKey(0x41), leaf_hash)) == P2MRSignature(0xa1));
    BOOST_CHECK(decoded_input.m_qbit_p2mr_script_sigs.at(std::make_pair(P2MRPubKey(0x42), leaf_hash)) == P2MRSignature(0xa2));
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_merge_unions_proprietary_fields)
{
    PSBTInput first;
    PSBTInput second;
    const std::vector<unsigned char> leaf_a{OP_TRUE};
    const std::vector<unsigned char> leaf_b{OP_FALSE};

    first.m_qbit_p2mr_merkle_root = ByteHash(0x01);
    first.m_qbit_p2mr_scripts[std::make_pair(leaf_a, int(P2MR_LEAF_VERSION_V1))].insert(ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)));
    second.m_qbit_p2mr_script_sigs.emplace(std::make_pair(P2MRPubKey(0x11), ByteHash(0x22)), P2MRSignature(0x02));
    second.m_qbit_p2mr_scripts[std::make_pair(leaf_b, int(P2MR_LEAF_VERSION_V1))].insert(ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x55, /*nodes=*/1));

    first.Merge(second);

    BOOST_CHECK_EQUAL(first.m_qbit_p2mr_merkle_root, ByteHash(0x01));
    BOOST_CHECK_EQUAL(first.m_qbit_p2mr_scripts.size(), 2U);
    BOOST_CHECK_EQUAL(first.m_qbit_p2mr_script_sigs.size(), 1U);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_merge_unions_control_blocks_for_same_leaf)
{
    PSBTInput first;
    PSBTInput second;
    const auto leaf = std::make_pair(std::vector<unsigned char>{OP_TRUE}, int(P2MR_LEAF_VERSION_V1));
    const std::vector<unsigned char> control_a = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x10, /*nodes=*/0);
    const std::vector<unsigned char> control_b = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x20, /*nodes=*/1);

    first.m_qbit_p2mr_scripts[leaf].insert(control_a);
    second.m_qbit_p2mr_scripts[leaf].insert(control_b);

    first.Merge(second);

    BOOST_REQUIRE_EQUAL(first.m_qbit_p2mr_scripts.size(), 1U);
    BOOST_CHECK_EQUAL(first.m_qbit_p2mr_scripts.at(leaf).count(control_a), 1U);
    BOOST_CHECK_EQUAL(first.m_qbit_p2mr_scripts.at(leaf).count(control_b), 1U);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_fill_signature_data_preserves_spenddata)
{
    PSBTInput input;
    const uint256 merkle_root = ByteHash(0x91);
    const uint256 leaf_hash = ByteHash(0x92);
    const std::vector<unsigned char> leaf_script{OP_TRUE};
    const std::vector<unsigned char> control_block = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x21, /*nodes=*/1);
    const std::vector<unsigned char> script_sig = P2MRSignature(0x03);

    input.m_qbit_p2mr_merkle_root = merkle_root;
    input.m_qbit_p2mr_scripts[std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))].insert(control_block);
    input.m_qbit_p2mr_script_sigs.emplace(std::make_pair(P2MRPubKey(0x33), leaf_hash), script_sig);

    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    BOOST_CHECK_EQUAL(sigdata.p2mr_spenddata.merkle_root, merkle_root);
    BOOST_REQUIRE_EQUAL(sigdata.p2mr_spenddata.scripts.size(), 1U);
    BOOST_CHECK_EQUAL(sigdata.p2mr_spenddata.scripts.at(std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))).count(control_block), 1U);
    BOOST_REQUIRE_EQUAL(sigdata.p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(sigdata.p2mr_script_sigs.at(std::make_pair(P2MRPubKey(0x33), leaf_hash)) == script_sig);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_from_signature_data_uses_builder_data)
{
    const std::vector<unsigned char> leaf_script{OP_TRUE};
    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const P2MRSpendData spenddata = builder.GetP2MRSpendData();
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_script);
    const std::vector<unsigned char> script_sig = P2MRSignature(0xaa);

    SignatureData sigdata;
    sigdata.p2mr_builder = builder;
    sigdata.p2mr_script_sigs.emplace(std::make_pair(P2MRPubKey(0x44), leaf_hash), script_sig);

    PSBTInput input;
    input.FromSignatureData(sigdata);

    BOOST_CHECK_EQUAL(input.m_qbit_p2mr_merkle_root, spenddata.merkle_root);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_scripts.size(), 1U);
    BOOST_CHECK(input.m_qbit_p2mr_scripts.contains(std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))));
    BOOST_CHECK_EQUAL(input.m_qbit_p2mr_scripts.at(std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))).size(), 1U);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(input.m_qbit_p2mr_script_sigs.at(std::make_pair(P2MRPubKey(0x44), leaf_hash)) == script_sig);

    SignatureData round_trip;
    input.FillSignatureData(round_trip);

    BOOST_CHECK_EQUAL(round_trip.p2mr_spenddata.merkle_root, spenddata.merkle_root);
    BOOST_REQUIRE_EQUAL(round_trip.p2mr_spenddata.scripts.size(), 1U);
    BOOST_CHECK(round_trip.p2mr_spenddata.scripts.contains(std::make_pair(leaf_script, int(P2MR_LEAF_VERSION_V1))));
    BOOST_CHECK_EQUAL(round_trip.p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(round_trip.p2mr_script_sigs.at(std::make_pair(P2MRPubKey(0x44), leaf_hash)) == script_sig);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_signing_canonicalizes_conflicting_merkle_root)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = P2MRLeafScript(pubkey);
    const std::vector<unsigned char> leaf_script_bytes = Vec(leaf_script);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_script_bytes);
    const std::vector<unsigned char> control_block = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1));
    const uint256 merkle_root = ComputeP2MRMerkleRoot(control_block, leaf_hash);
    const uint256 wrong_root = ByteHash(0xee);
    BOOST_REQUIRE(wrong_root != merkle_root);

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0x61)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    input.witness_utxo = CTxOut{50'000, P2MRScriptPubKey(merkle_root)};
    input.m_qbit_p2mr_merkle_root = wrong_root;
    input.m_qbit_p2mr_scripts[std::make_pair(leaf_script_bytes, int(P2MR_LEAF_VERSION_V1))].insert(control_block);

    FlatSigningProvider provider;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
    BOOST_CHECK_EQUAL(SignPSBTInput(provider, psbt, 0, &txdata, std::nullopt, nullptr, /*finalize=*/false), PSBTError::INCOMPLETE);
    BOOST_CHECK_EQUAL(input.m_qbit_p2mr_merkle_root, merkle_root);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_incremental_multisig_signing_accumulates_partial_sigs)
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
    const CScript leaf_script = P2MRMultiAScript(2, {pubkey_a, pubkey_b, pubkey_c});
    const std::vector<unsigned char> leaf_script_bytes = Vec(leaf_script);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_script_bytes);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script_bytes, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0xa1)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    input.witness_utxo = CTxOut{50'000, P2MRScriptPubKey(output.GetMerkleRoot())};
    input.m_qbit_p2mr_merkle_root = output.GetMerkleRoot();
    input.m_qbit_p2mr_scripts = builder.GetP2MRSpendData().scripts;

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    FlatSigningProvider first_signer;
    first_signer.pqc_keys.emplace(pubkey_a, key_a);
    BOOST_CHECK_EQUAL(SignPSBTInput(first_signer, psbt, 0, &txdata, std::nullopt, nullptr, /*finalize=*/false), PSBTError::INCOMPLETE);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(input.m_qbit_p2mr_script_sigs.contains(std::make_pair(pubkey_a, leaf_hash)));
    BOOST_CHECK(input.final_script_witness.IsNull());

    FlatSigningProvider second_signer;
    second_signer.pqc_keys.emplace(pubkey_b, key_b);
    BOOST_CHECK_EQUAL(SignPSBTInput(second_signer, psbt, 0, &txdata, std::nullopt, nullptr, /*finalize=*/false), PSBTError::OK);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_script_sigs.size(), 2U);
    BOOST_CHECK(input.m_qbit_p2mr_script_sigs.contains(std::make_pair(pubkey_a, leaf_hash)));
    BOOST_CHECK(input.m_qbit_p2mr_script_sigs.contains(std::make_pair(pubkey_b, leaf_hash)));
    BOOST_CHECK(input.final_script_witness.IsNull());

    CMutableTransaction result;
    BOOST_CHECK(FinalizeAndExtractPSBT(psbt, result));
    BOOST_CHECK(!result.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_cached_signature_verification_waits_for_complete_txdata)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = P2MRLeafScript(pubkey);
    const std::vector<unsigned char> leaf_script_bytes = Vec(leaf_script);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_script_bytes);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script_bytes, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0xb1)), 0));
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0xb2)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    input.witness_utxo = CTxOut{50'000, P2MRScriptPubKey(output.GetMerkleRoot())};
    input.m_qbit_p2mr_merkle_root = output.GetMerkleRoot();
    input.m_qbit_p2mr_scripts = builder.GetP2MRSpendData().scripts;
    psbt.inputs.at(1).witness_utxo = CTxOut{10'000, CScript{} << OP_TRUE};

    const PrecomputedTransactionData complete_txdata = PrecomputePSBTData(psbt);
    BOOST_REQUIRE(complete_txdata.m_spent_outputs_ready);
    BOOST_REQUIRE(complete_txdata.m_bip341_taproot_ready);

    FlatSigningProvider signer;
    signer.pqc_keys.emplace(pubkey, key);
    BOOST_CHECK_EQUAL(SignPSBTInput(signer, psbt, 0, &complete_txdata, std::nullopt, nullptr, /*finalize=*/false), PSBTError::OK);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(input.m_qbit_p2mr_script_sigs.contains(std::make_pair(pubkey, leaf_hash)));

    psbt.inputs.at(1).witness_utxo.SetNull();
    const PrecomputedTransactionData incomplete_txdata = PrecomputePSBTData(psbt);
    BOOST_REQUIRE(!incomplete_txdata.m_spent_outputs_ready);
    BOOST_REQUIRE(!incomplete_txdata.m_bip341_taproot_ready);

    FlatSigningProvider empty_provider;
    SignatureData out_sigdata;
    BOOST_CHECK_EQUAL(SignPSBTInput(empty_provider, psbt, 0, &incomplete_txdata, std::nullopt, &out_sigdata, /*finalize=*/false), PSBTError::INCOMPLETE);
    BOOST_CHECK(out_sigdata.invalid_p2mr_sigs.empty());
    BOOST_REQUIRE_EQUAL(psbt.inputs.at(0).m_qbit_p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(psbt.inputs.at(0).final_script_witness.IsNull());
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_incomplete_signing_limits_partial_counter_burn)
{
    CPQCKey local_key;
    CPQCKey missing_key_a;
    CPQCKey missing_key_b;
    CPQCKey missing_key_c;
    local_key.MakeNewKey();
    missing_key_a.MakeNewKey();
    missing_key_b.MakeNewKey();
    missing_key_c.MakeNewKey();

    const CPQCPubKey local_pubkey = local_key.GetPubKey();
    const CPQCPubKey missing_pubkey_a = missing_key_a.GetPubKey();
    const CPQCPubKey missing_pubkey_b = missing_key_b.GetPubKey();
    const CPQCPubKey missing_pubkey_c = missing_key_c.GetPubKey();
    const CScript leaf_a = P2MRMultiAScript(2, {local_pubkey, missing_pubkey_a});
    const CScript leaf_b = P2MRMultiAScript(2, {local_pubkey, missing_pubkey_b});
    const CScript leaf_c = P2MRMultiAScript(2, {local_pubkey, missing_pubkey_c});
    const std::vector<unsigned char> leaf_a_bytes = Vec(leaf_a);
    const std::vector<unsigned char> leaf_b_bytes = Vec(leaf_b);
    const std::vector<unsigned char> leaf_c_bytes = Vec(leaf_c);
    const uint256 leaf_a_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_a_bytes);
    const uint256 leaf_b_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_b_bytes);
    const uint256 leaf_c_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_c_bytes);

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/2, leaf_a_bytes, P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/2, leaf_b_bytes, P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, leaf_c_bytes, P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0xa2)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    input.witness_utxo = CTxOut{50'000, P2MRScriptPubKey(output.GetMerkleRoot())};
    input.m_qbit_p2mr_merkle_root = output.GetMerkleRoot();
    input.m_qbit_p2mr_scripts = builder.GetP2MRSpendData().scripts;

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    FlatSigningProvider signer;
    signer.pqc_keys.emplace(local_pubkey, local_key);

    int counter_advances{0};
    signer.pqc_counter_observer = [&](const CPQCPubKey& seen_pubkey, uint32_t previous_counter, uint32_t new_counter) {
        BOOST_CHECK(seen_pubkey == local_pubkey);
        BOOST_CHECK_EQUAL(new_counter, previous_counter + 1);
        ++counter_advances;
    };

    BOOST_CHECK_EQUAL(SignPSBTInput(signer, psbt, 0, &txdata, std::nullopt, nullptr, /*finalize=*/false), PSBTError::INCOMPLETE);
    BOOST_CHECK_EQUAL(counter_advances, 1);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_script_sigs.size(), 1U);

    const bool signed_leaf_a = input.m_qbit_p2mr_script_sigs.contains(std::make_pair(local_pubkey, leaf_a_hash));
    const bool signed_leaf_b = input.m_qbit_p2mr_script_sigs.contains(std::make_pair(local_pubkey, leaf_b_hash));
    const bool signed_leaf_c = input.m_qbit_p2mr_script_sigs.contains(std::make_pair(local_pubkey, leaf_c_hash));
    BOOST_CHECK_EQUAL(int(signed_leaf_a) + int(signed_leaf_b) + int(signed_leaf_c), 1);
    BOOST_CHECK(input.final_script_witness.IsNull());
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_duplicate_qbit_merkle_root)
{
    DataStream ss{};
    SerializeQbitProprietaryKey(ss, PSBT_IN_PROPRIETARY, PSBT_QBIT_IN_P2MR_MERKLE_ROOT);
    SerializeToVector(ss, ByteHash(0x11));
    SerializeQbitProprietaryKey(ss, PSBT_IN_PROPRIETARY, PSBT_QBIT_IN_P2MR_MERKLE_ROOT);
    SerializeToVector(ss, ByteHash(0x22));
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("Duplicate Key, qbit P2MR merkle root already provided") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_accepts_matching_standard_and_qbit_script_signature)
{
    const CPQCPubKey pubkey = P2MRPubKey(0x34);
    const uint256 leaf_hash = ByteHash(0x56);
    const std::vector<unsigned char> sig = P2MRSignature(0x78);
    const std::vector<unsigned char> key_data = P2MRScriptSigKeyData(pubkey, leaf_hash);

    DataStream ss{};
    SerializeToVector(ss, PSBT_IN_P2MR_SCRIPT_SIG, std::span{pubkey.data(), pubkey.size()}, leaf_hash);
    ss << sig;
    SerializeQbitProprietaryKey(ss, PSBT_IN_PROPRIETARY, PSBT_QBIT_IN_P2MR_SCRIPT_SIG, key_data);
    ss << sig;
    ss << PSBT_SEPARATOR;

    PSBTInput input(deserialize, ss);
    BOOST_REQUIRE_EQUAL(input.m_qbit_p2mr_script_sigs.size(), 1U);
    BOOST_CHECK(input.m_qbit_p2mr_script_sigs.at(std::make_pair(pubkey, leaf_hash)) == sig);
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_conflicting_standard_and_qbit_script_signature)
{
    const CPQCPubKey pubkey = P2MRPubKey(0x35);
    const uint256 leaf_hash = ByteHash(0x57);
    const std::vector<unsigned char> sig = P2MRSignature(0x79);
    const std::vector<unsigned char> conflicting_sig = P2MRSignature(0x7a);
    const std::vector<unsigned char> key_data = P2MRScriptSigKeyData(pubkey, leaf_hash);

    DataStream ss{};
    SerializeToVector(ss, PSBT_IN_P2MR_SCRIPT_SIG, std::span{pubkey.data(), pubkey.size()}, leaf_hash);
    ss << sig;
    SerializeQbitProprietaryKey(ss, PSBT_IN_PROPRIETARY, PSBT_QBIT_IN_P2MR_SCRIPT_SIG, key_data);
    ss << conflicting_sig;
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("Conflicting P2MR script signature for pubkey and leaf hash") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_invalid_standard_leaf_script_control_size)
{
    const std::vector<std::vector<unsigned char>> invalid_controls{
        {},
        {static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x00},
        std::vector<unsigned char>(P2MR_CONTROL_MAX_SIZE + 1, static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)),
    };

    for (const auto& control : invalid_controls) {
        DataStream ss = StandardInputP2MRLeafScript(control, std::vector<unsigned char>{OP_TRUE});
        ss << PSBT_SEPARATOR;
        BOOST_CHECK_EXCEPTION(
            PSBTInput input(deserialize, ss),
            std::ios_base::failure,
            [](const std::ios_base::failure& e) {
                return std::string{e.what()}.find("P2MR leaf script key has an invalid control block size") != std::string::npos;
            });
    }
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_invalid_leaf_script_control_size)
{
    const std::vector<unsigned char> invalid_control{static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1), 0x00};
    DataStream ss = QbitInputProprietary(
        PSBT_QBIT_IN_P2MR_LEAF_SCRIPT,
        invalid_control,
        std::vector<unsigned char>{OP_TRUE, static_cast<unsigned char>(P2MR_LEAF_VERSION_V1)});
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("qbit P2MR leaf script key has an invalid control block size") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_control_byte_without_required_bit)
{
    const std::vector<unsigned char> invalid_control{P2MR_LEAF_VERSION_V1};
    {
        DataStream ss = StandardInputP2MRLeafScript(invalid_control, std::vector<unsigned char>{OP_TRUE});
        ss << PSBT_SEPARATOR;
        BOOST_CHECK_EXCEPTION(
            PSBTInput input(deserialize, ss),
            std::ios_base::failure,
            [](const std::ios_base::failure& e) {
                return std::string{e.what()}.find("P2MR control byte bit 0 must be set") != std::string::npos;
            });
    }
    {
        DataStream ss = QbitInputProprietary(
            PSBT_QBIT_IN_P2MR_LEAF_SCRIPT,
            invalid_control,
            std::vector<unsigned char>{OP_TRUE, static_cast<unsigned char>(P2MR_LEAF_VERSION_V1)});
        ss << PSBT_SEPARATOR;
        BOOST_CHECK_EXCEPTION(
            PSBTInput input(deserialize, ss),
            std::ios_base::failure,
            [](const std::ios_base::failure& e) {
                return std::string{e.what()}.find("qbit P2MR control byte bit 0 must be set") != std::string::npos;
            });
    }
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_short_script_signature)
{
    std::vector<unsigned char> key_data(CPQCPubKey::SIZE + uint256::size(), 0x00);
    std::fill_n(key_data.begin(), CPQCPubKey::SIZE, 0x02);
    const std::vector<unsigned char> short_sig{0x00};
    DataStream ss = QbitInputProprietary(PSBT_QBIT_IN_P2MR_SCRIPT_SIG, key_data, short_sig);
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("qbit P2MR script signature is shorter than expected") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_oversized_nondefault_script_signature)
{
    std::vector<unsigned char> key_data(CPQCPubKey::SIZE + uint256::size(), 0x00);
    std::fill_n(key_data.begin(), CPQCPubKey::SIZE, 0x02);
    std::vector<unsigned char> oversized_sig(PQC_SIG_SIZE + 2, 0x55);
    oversized_sig.back() = SIGHASH_ALL;
    DataStream ss = QbitInputProprietary(PSBT_QBIT_IN_P2MR_SCRIPT_SIG, key_data, oversized_sig);
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("qbit P2MR script signature is longer than expected") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_default_sighash_suffix)
{
    std::vector<unsigned char> key_data(CPQCPubKey::SIZE + uint256::size(), 0x00);
    std::fill_n(key_data.begin(), CPQCPubKey::SIZE, 0x02);
    std::vector<unsigned char> sig = P2MRSignature(0x55, /*with_hashtype=*/true);
    sig.back() = SIGHASH_DEFAULT;
    DataStream ss = QbitInputProprietary(PSBT_QBIT_IN_P2MR_SCRIPT_SIG, key_data, sig);
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("qbit P2MR script signature has invalid sighash type") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_short_standard_script_signature)
{
    const std::vector<unsigned char> short_sig{0x00};
    DataStream ss = StandardInputP2MRScriptSig(P2MRPubKey(0x02), ByteHash(0x03), short_sig);
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("P2MR script signature is shorter than expected") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_oversized_nondefault_standard_script_signature)
{
    std::vector<unsigned char> oversized_sig(PQC_SIG_SIZE + 2, 0x55);
    oversized_sig.back() = SIGHASH_ALL;
    DataStream ss = StandardInputP2MRScriptSig(P2MRPubKey(0x02), ByteHash(0x03), oversized_sig);
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("P2MR script signature is longer than expected") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_rejects_default_sighash_suffix_standard_path)
{
    std::vector<unsigned char> sig = P2MRSignature(0x55, /*with_hashtype=*/true);
    sig.back() = SIGHASH_DEFAULT;
    DataStream ss = StandardInputP2MRScriptSig(P2MRPubKey(0x02), ByteHash(0x03), sig);
    ss << PSBT_SEPARATOR;

    BOOST_CHECK_EXCEPTION(
        PSBTInput input(deserialize, ss),
        std::ios_base::failure,
        [](const std::ios_base::failure& e) {
            return std::string{e.what()}.find("P2MR script signature has invalid sighash type") != std::string::npos;
        });
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_signing_refuses_reserved_leaf_versions)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();
    const CScript leaf_script = P2MRLeafScript(pubkey);
    const std::vector<unsigned char> leaf_script_bytes = Vec(leaf_script);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_RESERVED_1, leaf_script_bytes);
    const std::vector<unsigned char> control_block = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_RESERVED_1 | 1));
    const uint256 merkle_root = ComputeP2MRMerkleRoot(control_block, leaf_hash);

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0x71)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    input.witness_utxo = CTxOut{50'000, P2MRScriptPubKey(merkle_root)};
    input.m_qbit_p2mr_merkle_root = merkle_root;
    input.m_qbit_p2mr_scripts[std::make_pair(leaf_script_bytes, int(P2MR_LEAF_VERSION_RESERVED_1))].insert(control_block);

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);

    SignatureData out_sigdata;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
    BOOST_CHECK_EQUAL(SignPSBTInput(provider, psbt, 0, &txdata, std::nullopt, &out_sigdata, /*finalize=*/false), PSBTError::INCOMPLETE);
    BOOST_CHECK(out_sigdata.missing_p2mr_sigs.empty());
    BOOST_CHECK(psbt.inputs.at(0).m_qbit_p2mr_script_sigs.empty());
    BOOST_CHECK(psbt.inputs.at(0).final_script_witness.IsNull());
}

BOOST_AUTO_TEST_CASE(psbt_p2mr_finalization_refuses_reserved_leaf_versions)
{
    const CPQCPubKey pubkey = P2MRPubKey(0x81);
    const CScript leaf_script = P2MRLeafScript(pubkey);
    const std::vector<unsigned char> leaf_script_bytes = Vec(leaf_script);
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_RESERVED_1, leaf_script_bytes);
    const std::vector<unsigned char> control_block = ControlBlock(static_cast<unsigned char>(P2MR_LEAF_VERSION_RESERVED_1 | 1));
    const uint256 merkle_root = ComputeP2MRMerkleRoot(control_block, leaf_hash);

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(ByteHash(0x72)), 0));
    tx.vout.emplace_back(1234, CScript{} << OP_TRUE);

    PartiallySignedTransaction psbt{tx};
    PSBTInput& input = psbt.inputs.at(0);
    input.witness_utxo = CTxOut{50'000, P2MRScriptPubKey(merkle_root)};
    input.m_qbit_p2mr_merkle_root = merkle_root;
    input.m_qbit_p2mr_scripts[std::make_pair(leaf_script_bytes, int(P2MR_LEAF_VERSION_RESERVED_1))].insert(control_block);
    input.m_qbit_p2mr_script_sigs.emplace(std::make_pair(pubkey, leaf_hash), P2MRSignature(0x77));

    CMutableTransaction extracted;
    BOOST_CHECK(!FinalizeAndExtractPSBT(psbt, extracted));
    BOOST_CHECK(psbt.inputs.at(0).final_script_witness.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
