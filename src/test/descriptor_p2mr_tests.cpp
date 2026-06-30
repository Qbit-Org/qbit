// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <crypto/pqc.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/data/p2mr_vectors.json.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <optional>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

std::string HexPubkey(unsigned char byte)
{
    return HexStr(std::vector<unsigned char>(CPQCPubKey::SIZE, byte));
}

std::string HexPubkey31(unsigned char byte)
{
    return HexStr(std::vector<unsigned char>(CPQCPubKey::SIZE - 1, byte));
}

std::unique_ptr<Descriptor> ParseSingleDescriptor(const std::string& descriptor, FlatSigningProvider& provider)
{
    std::string error;
    auto parsed = Parse(descriptor, provider, error);
    BOOST_REQUIRE_MESSAGE(parsed.size() == 1, error);
    return std::move(parsed[0]);
}

std::optional<std::string> ParseError(const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error);
    if (!parsed.empty()) return std::nullopt;
    return error;
}

CScript ExpandSingleScript(const Descriptor& descriptor, FlatSigningProvider& provider_out)
{
    std::vector<CScript> scripts;
    BOOST_REQUIRE(descriptor.Expand(0, DUMMY_SIGNING_PROVIDER, scripts, provider_out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    return scripts[0];
}

CScript ExpandSingleScript(const Descriptor& descriptor, const SigningProvider& provider, FlatSigningProvider& provider_out)
{
    std::vector<CScript> scripts;
    BOOST_REQUIRE(descriptor.Expand(0, provider, scripts, provider_out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    return scripts[0];
}

WitnessV2P2MR ExtractP2MROutput(const CScript& script_pubkey)
{
    CTxDestination dest;
    BOOST_REQUIRE(ExtractDestination(script_pubkey, dest));
    const auto* p2mr = std::get_if<WitnessV2P2MR>(&dest);
    BOOST_REQUIRE(p2mr != nullptr);
    return *p2mr;
}

std::vector<unsigned char> Vec(const CScript& script)
{
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::string StripChecksum(const std::string& descriptor)
{
    if (descriptor.size() > 9 && descriptor[descriptor.size() - 9] == '#') {
        return descriptor.substr(0, descriptor.size() - 9);
    }
    return descriptor;
}

std::string MakeLeftDeepTree(const std::string& leaf, size_t depth)
{
    std::string tree = leaf;
    for (size_t i = 0; i < depth; ++i) {
        tree = "{" + tree + "," + leaf + "}";
    }
    return tree;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(descriptor_p2mr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(parse_single_pk_leaf_roundtrip)
{
    const std::string desc = "mr(pk(" + HexPubkey(0x11) + "))";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);

    BOOST_CHECK_EQUAL(StripChecksum(parsed->ToString()), desc);
    BOOST_CHECK(parsed->GetOutputType() && *parsed->GetOutputType() == OutputType::P2MR);
    BOOST_CHECK(parsed->IsSingleType());
    BOOST_CHECK(parsed->ScriptSize() && *parsed->ScriptSize() == 34);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    BOOST_CHECK_EQUAL(HexStr(script_pubkey), "5220157292fe6ab587365cd3b63e2922ef050ec33a9a45e9efd633f7d335e4b5c35e");
}

BOOST_AUTO_TEST_CASE(parse_two_leaf_tree_roundtrip)
{
    const std::string desc = "mr({pk(" + HexPubkey(0x11) + "),pk(" + HexPubkey(0x22) + ")})";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);
    BOOST_CHECK_EQUAL(StripChecksum(parsed->ToString()), desc);
}

BOOST_AUTO_TEST_CASE(parse_nested_tree_roundtrip)
{
    const std::string desc =
        "mr({pk(" + HexPubkey(0x11) + "),{pk(" + HexPubkey(0x22) + "),pk(" + HexPubkey(0x33) + ")}})";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);
    BOOST_CHECK_EQUAL(StripChecksum(parsed->ToString()), desc);
}

BOOST_AUTO_TEST_CASE(parse_multi_a_leaf_roundtrip)
{
    const std::string desc = "mr(multi_a(2," + HexPubkey(0x11) + "," + HexPubkey(0x22) + "," + HexPubkey(0x33) + "))";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);
    BOOST_CHECK_EQUAL(StripChecksum(parsed->ToString()), desc);
}

BOOST_AUTO_TEST_CASE(parse_sortedmulti_a_infers_as_multi_a)
{
    const std::string k1 = HexPubkey(0x11);
    const std::string k2 = HexPubkey(0x22);
    const std::string k3 = HexPubkey(0x33);
    const std::string sorted_desc = "mr(sortedmulti_a(2," + k3 + "," + k1 + "," + k2 + "))";

    FlatSigningProvider parsed_provider;
    auto parsed = ParseSingleDescriptor(sorted_desc, parsed_provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    auto inferred = InferDescriptor(script_pubkey, out_provider);
    BOOST_REQUIRE(inferred);

    const std::string expected = "mr(multi_a(2," + k1 + "," + k2 + "," + k3 + "))";
    BOOST_CHECK_EQUAL(StripChecksum(inferred->ToString()), expected);
}

BOOST_AUTO_TEST_CASE(parse_rejects_invalid_pubkey_length)
{
    const auto err = ParseError("mr(pk(" + HexPubkey31(0x11) + "))");
    BOOST_REQUIRE(err);
    BOOST_CHECK(err->find("pk():") != std::string::npos);
    BOOST_CHECK(err->find("32-byte PQC pubkey") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(parse_rejects_missing_tree)
{
    const auto err = ParseError("mr()");
    BOOST_REQUIRE(err);
    BOOST_CHECK_EQUAL(*err, "mr(): Missing script tree");
}

BOOST_AUTO_TEST_CASE(parse_rejects_taproot_style_internal_key_syntax)
{
    const auto err = ParseError("mr(" + HexPubkey(0x11) + ",pk(" + HexPubkey(0x22) + "))");
    BOOST_REQUIRE(err);
    BOOST_CHECK_EQUAL(*err, "A function is needed within P2MR");
}

BOOST_AUTO_TEST_CASE(expand_populates_mr_tree_provider_data)
{
    const std::string desc = "mr({pk(" + HexPubkey(0x11) + "),pk(" + HexPubkey(0x22) + ")})";
    FlatSigningProvider parsed_provider;
    auto parsed = ParseSingleDescriptor(desc, parsed_provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    const WitnessV2P2MR output = ExtractP2MROutput(script_pubkey);

    BOOST_REQUIRE_EQUAL(out_provider.mr_trees.size(), 1U);
    BOOST_CHECK(out_provider.mr_trees.contains(output));

    P2MRSpendData spenddata;
    BOOST_REQUIRE(out_provider.GetP2MRSpendData(output, spenddata));
    BOOST_CHECK_EQUAL(spenddata.merkle_root, output.GetMerkleRoot());
    BOOST_CHECK_EQUAL(spenddata.scripts.size(), 2U);
    for (const auto& [leaf, _] : spenddata.scripts) {
        BOOST_CHECK_EQUAL(leaf.second, int(P2MR_LEAF_VERSION_V1));
    }
}

BOOST_AUTO_TEST_CASE(infer_descriptor_with_spend_data_returns_mr)
{
    const std::string desc = "mr({pk(" + HexPubkey(0x11) + "),pk(" + HexPubkey(0x22) + ")})";
    FlatSigningProvider parsed_provider;
    auto parsed = ParseSingleDescriptor(desc, parsed_provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    auto inferred = InferDescriptor(script_pubkey, out_provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK_EQUAL(StripChecksum(inferred->ToString()), desc);
}

BOOST_AUTO_TEST_CASE(infer_descriptor_without_spend_data_falls_back_to_rawmr)
{
    const std::string desc = "mr(pk(" + HexPubkey(0x11) + "))";
    FlatSigningProvider parsed_provider;
    auto parsed = ParseSingleDescriptor(desc, parsed_provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);

    FlatSigningProvider empty_provider;
    auto inferred = InferDescriptor(script_pubkey, empty_provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK(inferred->ToString().rfind("rawmr(", 0) == 0);
    BOOST_CHECK(!inferred->IsSolvable());
    BOOST_CHECK(inferred->GetOutputType() && *inferred->GetOutputType() == OutputType::P2MR);
}

BOOST_AUTO_TEST_CASE(parse_rawmr_roundtrip)
{
    const std::string desc = "rawmr(" + HexPubkey(0x44) + ")";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);

    BOOST_CHECK_EQUAL(StripChecksum(parsed->ToString()), desc);
    BOOST_CHECK(parsed->GetOutputType() && *parsed->GetOutputType() == OutputType::P2MR);
    BOOST_CHECK(!parsed->IsSolvable());
    BOOST_CHECK(parsed->IsSingleType());
    BOOST_CHECK(parsed->ScriptSize() && *parsed->ScriptSize() == 34);
}

BOOST_AUTO_TEST_CASE(rawmr_fixed_address_vector)
{
    const std::string root = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const std::string desc = "rawmr(" + root + ")";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    BOOST_CHECK_EQUAL(HexStr(script_pubkey), "5220" + root);

    const WitnessV2P2MR output = ExtractP2MROutput(script_pubkey);
    SelectParams(ChainType::MAIN);
    BOOST_CHECK_EQUAL(EncodeDestination(output), "qb1zqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sjq57mw");
    SelectParams(ChainType::REGTEST);
    BOOST_CHECK_EQUAL(EncodeDestination(output), "qbrt1zqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s8kqqny");
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(rawmr_independent_p2mr_vectors)
{
    UniValue tests;
    BOOST_REQUIRE(tests.read(json_tests::p2mr_vectors));
    BOOST_REQUIRE(tests.isObject());
    BOOST_CHECK_EQUAL(tests["version"].getInt<int>(), 1);

    for (const auto& vec : tests["valid"].getValues()) {
        const std::string root{vec["merkle_root"].get_str()};
        const std::string desc{"rawmr(" + root + ")"};
        FlatSigningProvider provider;
        auto parsed = ParseSingleDescriptor(desc, provider);

        FlatSigningProvider out_provider;
        const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
        BOOST_CHECK_EQUAL(HexStr(script_pubkey), vec["scriptPubKey"].get_str());

        const WitnessV2P2MR output = ExtractP2MROutput(script_pubkey);
        SelectParams(ChainType::MAIN);
        BOOST_CHECK_EQUAL(EncodeDestination(output), vec["mainnet_address"].get_str());
        SelectParams(ChainType::REGTEST);
        BOOST_CHECK_EQUAL(EncodeDestination(output), vec["regtest_address"].get_str());
    }
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(pqc_descriptor_fixed_expansion_vector)
{
    SelectParams(ChainType::REGTEST);
    const std::string xprv = "qrpvV1brS3WRoVwgSKGgKRdVRsxe378zAczWKKN8VLzkndxBMbpDdYo2LAGgQp6Ncu3eBRZjRL2UB436gaQzspTF2NZfFSTa164fCWEr6ReDJGm";
    const std::string xpub = "qrpbSRJj3eCrXD2z3iQbhaESDr59kqgvZtx9cbX5yqsMHCcEf3rUW2X1BkQVAQvUC1y14Ly3zscn9BvKoe1VCyvM3wgoF9UgedXSaecaxhhYggh";
    const std::string desc = "mr(pk(pqc(" + xprv + "/1/1/0)))";
    FlatSigningProvider provider;
    auto parsed = ParseSingleDescriptor(desc, provider);

    BOOST_CHECK_EQUAL(StripChecksum(parsed->ToString()), "mr(pk(pqc(" + xpub + "/1/1/0)))");

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, provider, out_provider);
    BOOST_CHECK_EQUAL(HexStr(script_pubkey), "5220b6c785589cc97898d4ca2a044d63d1dd48714693ce7a0038b4fd3baafb32afe9");
    BOOST_REQUIRE_EQUAL(out_provider.p2mr_pubkeys.size(), 1U);
    BOOST_REQUIRE_EQUAL(out_provider.pqc_keys.size(), 1U);
    BOOST_CHECK_EQUAL(EncodeDestination(ExtractP2MROutput(script_pubkey)), "qbrt1zkmrc2kyue9uf34x29gzy6c73m4y8z35neeaqqw95l5a647ej4l5suqqg6f");
    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(parse_rejects_rawmr_invalid_hex)
{
    const auto err = ParseError("rawmr(nothex)");
    BOOST_REQUIRE(err);
    BOOST_CHECK_EQUAL(*err, "rawmr(): Merkle root is not hex");
}

BOOST_AUTO_TEST_CASE(parse_rejects_rawmr_wrong_length)
{
    const auto err = ParseError("rawmr(" + HexPubkey31(0x55) + ")");
    BOOST_REQUIRE(err);
    BOOST_CHECK(err->find("rawmr(): Merkle root must be") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(parse_rejects_rawmr_below_top_level)
{
    const auto err = ParseError("sh(rawmr(" + HexPubkey(0x66) + "))");
    BOOST_REQUIRE(err);
    BOOST_CHECK_EQUAL(*err, "Can only have rawmr at top level");
}

BOOST_AUTO_TEST_CASE(parse_rejects_excessive_mr_nesting)
{
    const std::string leaf = "pk(" + HexPubkey(0x77) + ")";
    const auto err = ParseError("mr(" + MakeLeftDeepTree(leaf, P2MR_CONTROL_MAX_NODE_COUNT + 1) + ")");
    BOOST_REQUIRE(err);
    BOOST_CHECK(err->find("mr() supports at most") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(parse_accepts_maximum_mr_nesting_and_infers_tree)
{
    const std::string leaf_desc = "pk(" + HexPubkey(0x78) + ")";
    const std::string desc = "mr(" + MakeLeftDeepTree(leaf_desc, P2MR_CONTROL_MAX_NODE_COUNT) + ")";
    FlatSigningProvider parsed_provider;
    auto parsed = ParseSingleDescriptor(desc, parsed_provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    const WitnessV2P2MR output = ExtractP2MROutput(script_pubkey);

    P2MRSpendData spenddata;
    BOOST_REQUIRE(out_provider.GetP2MRSpendData(output, spenddata));
    bool saw_max_depth_control{false};
    for (const auto& [_, controls] : spenddata.scripts) {
        for (const auto& control : controls) {
            if (control.size() == P2MR_CONTROL_MAX_SIZE) saw_max_depth_control = true;
            BOOST_CHECK(control.size() <= P2MR_CONTROL_MAX_SIZE);
        }
    }
    BOOST_CHECK(saw_max_depth_control);

    auto inferred = InferDescriptor(script_pubkey, out_provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK(inferred->ToString().rfind("mr(", 0) == 0);
}

BOOST_AUTO_TEST_CASE(infer_descriptor_duplicate_identical_subtrees)
{
    const std::string key_a = HexPubkey(0x79);
    const std::string key_b = HexPubkey(0x7a);
    const std::string subtree = "{pk(" + key_a + "),pk(" + key_b + ")}";
    const std::string desc = "mr({" + subtree + "," + subtree + "})";
    FlatSigningProvider parsed_provider;
    auto parsed = ParseSingleDescriptor(desc, parsed_provider);

    FlatSigningProvider out_provider;
    const CScript script_pubkey = ExpandSingleScript(*parsed, out_provider);
    auto inferred = InferDescriptor(script_pubkey, out_provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK_EQUAL(StripChecksum(inferred->ToString()), desc);
}

BOOST_AUTO_TEST_CASE(infer_descriptor_reserved_leaf_falls_back_to_rawmr)
{
    const CScript leaf = CScript{} << std::vector<unsigned char>(32, 0x11) << OP_CHECKSIGPQC;
    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf, P2MR_LEAF_VERSION_RESERVED_1).FinalizeP2MR();

    FlatSigningProvider provider;
    provider.mr_trees.emplace(builder.GetP2MROutput(), builder);

    auto inferred = InferDescriptor(GetScriptForDestination(builder.GetP2MROutput()), provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK(inferred->ToString().rfind("rawmr(", 0) == 0);
}

BOOST_AUTO_TEST_CASE(taproot_builder_single_leaf_control_block)
{
    const CScript leaf = CScript{} << std::vector<unsigned char>(32, 0x11) << OP_CHECKSIGPQC;
    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf, P2MR_LEAF_VERSION_V1).FinalizeP2MR();

    const auto spend = builder.GetP2MRSpendData();
    BOOST_REQUIRE_EQUAL(spend.scripts.size(), 1U);

    const auto key = std::make_pair(Vec(leaf), int(P2MR_LEAF_VERSION_V1));
    const auto it = spend.scripts.find(key);
    BOOST_REQUIRE(it != spend.scripts.end());
    BOOST_REQUIRE_EQUAL(it->second.size(), 1U);
    const std::vector<unsigned char> control = *it->second.begin();

    BOOST_CHECK_EQUAL(control.size(), P2MR_CONTROL_BASE_SIZE);
    BOOST_CHECK_EQUAL(control[0], static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1));

    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, std::span<const unsigned char>{leaf});
    const uint256 root = ComputeP2MRMerkleRoot(control, leaf_hash);
    BOOST_CHECK_EQUAL(root, spend.merkle_root);
    BOOST_CHECK_EQUAL(builder.GetP2MROutput().GetMerkleRoot(), root);
}

BOOST_AUTO_TEST_CASE(taproot_builder_two_leaf_control_blocks_match_root)
{
    const CScript left = CScript{} << std::vector<unsigned char>(32, 0x11) << OP_CHECKSIGPQC;
    const CScript right = CScript{} << std::vector<unsigned char>(32, 0x22) << OP_CHECKSIGPQC;
    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, left, P2MR_LEAF_VERSION_V1)
           .AddP2MR(/*depth=*/1, right, P2MR_LEAF_VERSION_V1)
           .FinalizeP2MR();
    const auto spend = builder.GetP2MRSpendData();

    BOOST_REQUIRE_EQUAL(spend.scripts.size(), 2U);
    for (const auto& [script_key, controls] : spend.scripts) {
        BOOST_REQUIRE_EQUAL(controls.size(), 1U);
        const std::vector<unsigned char> control = *controls.begin();
        BOOST_CHECK_EQUAL(control.size(), P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE);
        BOOST_CHECK_EQUAL(control[0], static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1));

        const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, script_key.first);
        const uint256 root = ComputeP2MRMerkleRoot(control, leaf_hash);
        BOOST_CHECK_EQUAL(root, spend.merkle_root);
    }
}

BOOST_AUTO_TEST_CASE(taproot_builder_p2mr_omitted_nodes)
{
    const CScript left = CScript{} << std::vector<unsigned char>(32, 0x11) << OP_CHECKSIGPQC;
    const CScript right = CScript{} << std::vector<unsigned char>(32, 0x22) << OP_CHECKSIGPQC;

    TaprootBuilder full;
    full.AddP2MR(/*depth=*/1, left, P2MR_LEAF_VERSION_V1)
        .AddP2MR(/*depth=*/1, right, P2MR_LEAF_VERSION_V1)
        .FinalizeP2MR();

    const uint256 right_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, std::span<const unsigned char>{right});
    TaprootBuilder omitted_right;
    omitted_right.AddP2MR(/*depth=*/1, left, P2MR_LEAF_VERSION_V1)
                 .AddOmittedP2MR(/*depth=*/1, right_hash)
                 .FinalizeP2MR();
    BOOST_CHECK_EQUAL(omitted_right.GetP2MROutput().GetMerkleRoot(), full.GetP2MROutput().GetMerkleRoot());

    const auto spend = omitted_right.GetP2MRSpendData();
    BOOST_REQUIRE_EQUAL(spend.scripts.size(), 1U);
    const auto key = std::make_pair(Vec(left), int(P2MR_LEAF_VERSION_V1));
    const auto it = spend.scripts.find(key);
    BOOST_REQUIRE(it != spend.scripts.end());
    BOOST_REQUIRE_EQUAL(it->second.size(), 1U);
    const std::vector<unsigned char> control = *it->second.begin();
    BOOST_REQUIRE_EQUAL(control.size(), P2MR_CONTROL_BASE_SIZE + P2MR_CONTROL_NODE_SIZE);
    BOOST_CHECK_EQUAL(uint256{std::span<const unsigned char>{control}.last(P2MR_CONTROL_NODE_SIZE)}, right_hash);

    const uint256 left_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, std::span<const unsigned char>{left});
    BOOST_CHECK_EQUAL(ComputeP2MRMerkleRoot(control, left_hash), full.GetP2MROutput().GetMerkleRoot());

    TaprootBuilder root_only;
    root_only.AddOmittedP2MR(/*depth=*/0, full.GetP2MROutput().GetMerkleRoot()).FinalizeP2MR();
    BOOST_CHECK_EQUAL(root_only.GetP2MROutput().GetMerkleRoot(), full.GetP2MROutput().GetMerkleRoot());
    BOOST_CHECK(root_only.GetP2MRSpendData().scripts.empty());

    TaprootBuilder mixed;
    mixed.AddP2MR(/*depth=*/1, left, P2MR_LEAF_VERSION_V1).AddOmitted(/*depth=*/1, right_hash);
    BOOST_CHECK(!mixed.IsValid());
}

BOOST_AUTO_TEST_CASE(p2mr_spend_data_merge_combines_scripts)
{
    const CScript a = CScript{} << std::vector<unsigned char>(32, 0x11) << OP_CHECKSIGPQC;
    const CScript b = CScript{} << std::vector<unsigned char>(32, 0x22) << OP_CHECKSIGPQC;

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, a, P2MR_LEAF_VERSION_V1)
           .AddP2MR(/*depth=*/1, b, P2MR_LEAF_VERSION_V1)
           .FinalizeP2MR();
    const P2MRSpendData full_spend = builder.GetP2MRSpendData();

    const auto key_a = std::make_pair(Vec(a), int(P2MR_LEAF_VERSION_V1));
    const auto key_b = std::make_pair(Vec(b), int(P2MR_LEAF_VERSION_V1));
    BOOST_REQUIRE(full_spend.scripts.contains(key_a));
    BOOST_REQUIRE(full_spend.scripts.contains(key_b));

    P2MRSpendData spend_a;
    spend_a.merkle_root = full_spend.merkle_root;
    spend_a.scripts.emplace(key_a, full_spend.scripts.at(key_a));

    P2MRSpendData spend_b;
    spend_b.merkle_root = full_spend.merkle_root;
    spend_b.scripts.emplace(key_b, full_spend.scripts.at(key_b));

    spend_a.Merge(spend_b);
    BOOST_CHECK_EQUAL(spend_a.merkle_root, full_spend.merkle_root);
    BOOST_CHECK(spend_a.scripts == full_spend.scripts);

    P2MRSpendData empty;
    empty.Merge(spend_b);
    BOOST_CHECK_EQUAL(empty.merkle_root, full_spend.merkle_root);
    BOOST_CHECK_EQUAL(empty.scripts.size(), 1U);
    BOOST_CHECK(empty.scripts.contains(key_b));
}

BOOST_AUTO_TEST_CASE(flat_signing_provider_p2mr_roundtrip)
{
    const CScript left = CScript{} << std::vector<unsigned char>(32, 0x11) << OP_CHECKSIGPQC;
    const CScript right = CScript{} << std::vector<unsigned char>(32, 0x22) << OP_CHECKSIGPQC;
    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/1, left, P2MR_LEAF_VERSION_V1)
           .AddP2MR(/*depth=*/1, right, P2MR_LEAF_VERSION_V1)
           .FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const P2MRSpendData expected_spend = builder.GetP2MRSpendData();

    FlatSigningProvider provider;
    provider.mr_trees.emplace(output, builder);

    TaprootBuilder got_builder;
    P2MRSpendData got_spend;
    BOOST_REQUIRE(provider.GetP2MRBuilder(output, got_builder));
    BOOST_REQUIRE(provider.GetP2MRSpendData(output, got_spend));
    BOOST_CHECK(got_builder.GetP2MROutput() == output);
    BOOST_CHECK(got_spend.scripts == expected_spend.scripts);
    BOOST_CHECK_EQUAL(got_spend.merkle_root, expected_spend.merkle_root);
}

BOOST_AUTO_TEST_SUITE_END()
