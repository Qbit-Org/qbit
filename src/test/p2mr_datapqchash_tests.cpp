// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <test/data/p2mr_datapqchash_vectors.json.h>

#include <addresstype.h>
#include <crypto/pqc.h>
#include <key_io.h>
#include <script/interpreter.h>
#include <script/p2mr.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <algorithm>
#include <span>
#include <string>
#include <vector>

namespace {

struct RegtestBasicTestingSetup : public BasicTestingSetup {
    RegtestBasicTestingSetup()
        : BasicTestingSetup{ChainType::REGTEST}
    {
    }
};

std::string HashToHex(const uint256& hash)
{
    return HexStr(std::span<const unsigned char>{hash.begin(), hash.end()});
}

uint256 ParseHashHex(const std::string& hex)
{
    const std::vector<unsigned char> bytes{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(bytes.size(), uint256::size());
    return uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
}

UniValue LoadPinnedDataPQCVector()
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(json_tests::p2mr_datapqchash_vectors));
    BOOST_REQUIRE(doc.isObject());
    BOOST_CHECK_EQUAL(doc["schema_version"].getInt<int>(), 1);
    const UniValue& vectors{doc["vectors"]};
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE_EQUAL(vectors.size(), 1U);
    return vectors[0];
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2mr_datapqchash_tests, RegtestBasicTestingSetup)

BOOST_AUTO_TEST_CASE(pinned_p2mr_datapqchash_vector_matches_hash_tree_address_and_signature)
{
    const UniValue vector{LoadPinnedDataPQCVector()};
    BOOST_CHECK_EQUAL(vector["name"].get_str(), "bounded30_two_leaf_p2mr_pubkey_regtest");
    BOOST_CHECK_EQUAL(vector["network"].get_str(), "regtest");
    BOOST_CHECK_EQUAL(vector["domain"].get_str(), "QbitDataSigPQC");
    BOOST_CHECK_EQUAL(vector["algorithm"].get_str(), "SLH-DSA-SHA2-128s-bounded30");
    BOOST_CHECK_EQUAL(vector["proof_mode"].get_str(), "p2mr-pubkey");
    BOOST_CHECK_EQUAL(vector["leaf_version"].getInt<int>(), P2MR_LEAF_VERSION_V1);

    const uint256 message_hash{ParseHashHex(vector["message_hash"].get_str())};
    const uint256 datasig_hash{ComputeQbitDataSigPQCHash(std::span<const unsigned char>{message_hash.begin(), message_hash.end()})};
    BOOST_CHECK_EQUAL(HashToHex(datasig_hash), vector["datasig_hash"].get_str());

    const std::vector<unsigned char> pubkey_bytes{ParseHex(vector["pubkey"].get_str())};
    const CPQCPubKey pubkey{pubkey_bytes};
    BOOST_REQUIRE(pubkey.IsValid());

    const std::vector<unsigned char> leaf_script_bytes{ParseHex(vector["leaf_script"].get_str())};
    const CScript leaf_script{leaf_script_bytes.begin(), leaf_script_bytes.end()};
    BOOST_CHECK(p2mr::BuildPKScript(pubkey) == leaf_script);

    const std::vector<unsigned char> sibling_leaf_script{ParseHex(vector["tree"]["sibling_leaf_script"].get_str())};
    const uint256 sibling_leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, sibling_leaf_script)};
    BOOST_CHECK_EQUAL(HashToHex(sibling_leaf_hash), vector["tree"]["sibling_leaf_hash"].get_str());

    const std::vector<unsigned char> control_block{ParseHex(vector["control_block"].get_str())};
    BOOST_REQUIRE_EQUAL(control_block.size(), 1U + uint256::size());
    BOOST_CHECK_EQUAL(control_block.front(), P2MR_LEAF_VERSION_V1 | 1);
    BOOST_CHECK(std::equal(sibling_leaf_hash.begin(), sibling_leaf_hash.end(), control_block.begin() + 1));

    const uint256 leaf_hash{ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_script_bytes)};
    const uint256 merkle_root{ComputeP2MRMerkleRoot(control_block, leaf_hash)};
    BOOST_CHECK_EQUAL(HashToHex(merkle_root), vector["p2mr_merkle_root"].get_str());

    const std::string address{vector["address"].get_str()};
    BOOST_CHECK_EQUAL(EncodeDestination(WitnessV2P2MR{merkle_root}), address);
    const CTxDestination decoded{DecodeDestination(address)};
    const auto* decoded_p2mr{std::get_if<WitnessV2P2MR>(&decoded)};
    BOOST_REQUIRE(decoded_p2mr);
    BOOST_CHECK(decoded_p2mr->GetMerkleRoot() == merkle_root);

    const std::vector<unsigned char> signature{ParseHex(vector["signature"].get_str())};
    BOOST_REQUIRE_EQUAL(signature.size(), PQC_SIG_SIZE);
    BOOST_CHECK(pubkey.Verify(datasig_hash, signature));
}

BOOST_AUTO_TEST_SUITE_END()
