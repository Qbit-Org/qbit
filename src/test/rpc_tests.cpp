// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <crypto/pqc.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/context.h>
#include <rpc/blockchain.h>
#include <rpc/client.h>
#include <rpc/rawtransaction_util.h>
#include <chainparamsbase.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <test/data/p2mr_vectors.json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <any>

#include <boost/test/unit_test.hpp>

using util::SplitString;

static UniValue JSON(std::string_view json)
{
    UniValue value;
    BOOST_CHECK(value.read(json));
    return value;
}

class HasJSON
{
public:
    explicit HasJSON(std::string json) : m_json(std::move(json)) {}
    bool operator()(const UniValue& value) const
    {
        std::string json{value.write()};
        BOOST_CHECK_EQUAL(json, m_json);
        return json == m_json;
    };

private:
    const std::string m_json;
};

class RPCTestingSetup : public TestingSetup
{
public:
    UniValue TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const;
    UniValue CallRPC(std::string args);
};

UniValue RPCTestingSetup::TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const
{
    UniValue transformed_params;
    CRPCTable table;
    CRPCCommand command{"category", "method", [&](const JSONRPCRequest& request, UniValue&, bool) -> bool { transformed_params = request.params; return true; }, arg_names, /*unique_id=*/0};
    table.appendCommand("method", &command);
    JSONRPCRequest request;
    request.strMethod = "method";
    request.params = params;
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    table.execute(request);
    return transformed_params;
}

UniValue RPCTestingSetup::CallRPC(std::string args)
{
    std::vector<std::string> vArgs{SplitString(args, ' ')};
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    try {
        UniValue result = tableRPC.execute(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(objError.find_value("message").get_str());
    }
}


BOOST_FIXTURE_TEST_SUITE(rpc_tests, RPCTestingSetup)

BOOST_AUTO_TEST_CASE(rpc_namedparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"arg3", false}, {"arg4", false}, {"arg5", false}};

    // Make sure named arguments are transformed into positional arguments in correct places separated by nulls
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg2": 2, "arg4": 4})"), arg_names).write(), "[null,2,null,4]");

    // Make sure named argument specified multiple times raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "arg2": 4})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified multiple times"})"));

    // Make sure named and positional arguments can be combined.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg5": 5, "args": [1, 2], "arg4": 4})"), arg_names).write(), "[1,2,null,4,5]");

    // Make sure a unknown named argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "unknown": 6})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Unknown named parameter unknown"})"));

    // Make sure an overlap between a named argument and positional argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1,2,3], "arg4": 4, "arg2": 2})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified twice both as positional and named argument"})"));

    // Make sure extra positional arguments can be passed through to the method implementation, as long as they don't overlap with named arguments.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"args": [1,2,3,4,5,6,7,8,9,10]})"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"([1,2,3,4,5,6,7,8,9,10])"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
}

BOOST_AUTO_TEST_CASE(rpc_namedonlyparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"opt1", true}, {"opt2", true}, {"options", false}};

    // Make sure optional parameters are really optional.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2})"), arg_names).write(), "[1,2]");

    // Make sure named-only parameters are passed as options.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "opt2": 20})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options can be passed directly.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "options":{"opt1": 10, "opt2": 20}})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options and named parameters conflict.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "options":{"opt1": 10}})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options conflicts with parameter opt1"})"));

    // Make sure options object specified through args array conflicts.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1, 2, {"opt1": 10}], "opt2": 20})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options specified twice both as positional and named argument"})"));
}

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {} extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), std::runtime_error);
    std::string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(r.get_obj().find_value("size").getInt<int>(), 193);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("locktime").getInt<int>(), 0);
    BOOST_CHECK_THROW(CallRPC(std::string("decoderawtransaction ")+rawtx+" extra"), std::runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false"));
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false extra"), std::runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(std::string("sendrawtransaction ")+rawtx+" extra"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_togglenetwork)
{
    UniValue r;

    r = CallRPC("getnetworkinfo");
    bool netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive false"));
    r = CallRPC("getnetworkinfo");
    int numConnection = r.get_obj().find_value("connections").getInt<int>();
    BOOST_CHECK_EQUAL(numConnection, 0);

    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, false);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive true"));
    r = CallRPC("getnetworkinfo");
    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    // input is a legacy 1-of-2 multisig:
    std::string prevout =
      "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
      "\"vout\":1,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
      "\"redeemScript\":\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ecefca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    BOOST_CHECK_EXCEPTION(CallRPC(std::string("createrawtransaction ") + prevout + " " +
      "{\"SdS9kSdbYeccJoS5dJs4djaYhqRFjcfmi5\":11}"), std::runtime_error, HasReason("Invalid qbit address"));

    const std::string p2mr_address{EncodeDestination(WitnessV2P2MR{})};
    r = CallRPC(std::string("createrawtransaction ")+prevout+" "+
      "{\""+p2mr_address+"\":11}");
    std::string notsigned = r.get_str();
    std::string privkey1 = "\"Qar5hbz3AHVKb84ZfMZAdpLCrmw72tQ3A37u31y2JYSvERLZSTH5\"";
    std::string privkey2 = "\"QZgBP5WnkDqDGj3uJKpqsGeZsyxiJHU4KeUN66zLZePMTXVwGRxy\"";
    BOOST_CHECK_EXCEPTION(CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" [] "+prevout),
                          std::runtime_error, HasReason("Only restricted-output-mode prevout scriptPubKeys are supported on this chain"));
    BOOST_CHECK_EXCEPTION(CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" ["+privkey1+","+privkey2+"] "+prevout),
                          std::runtime_error, HasReason("Legacy WIF private keys are disabled on this chain"));
}

BOOST_AUTO_TEST_CASE(rpc_parse_pqc_raw_private_key)
{
    CPQCKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());

    const std::string pqc_key = "pqc(" + HexStr(std::span<const unsigned char>{key.data(), key.size()}) + ")";
    FlatSigningProvider provider;
    std::string error;
    BOOST_CHECK(ParseRawTransactionKey(pqc_key, provider, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(provider.pqc_keys.size(), 1U);
    BOOST_CHECK(provider.pqc_keys.contains(key.GetPubKey()));

    FlatSigningProvider invalid_provider;
    BOOST_CHECK(!ParseRawTransactionKey("pqc(00)", invalid_provider, error));
    BOOST_CHECK_EQUAL(error, "Invalid PQC private key");
}

BOOST_AUTO_TEST_CASE(rpc_parse_prevouts_p2mr)
{
    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey = key.GetPubKey();

    CScript leaf_script;
    leaf_script << std::vector<unsigned char>{pubkey.begin(), pubkey.end()} << OP_CHECKSIGPQC;

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script, P2MR_LEAF_VERSION).FinalizeP2MR();
    const WitnessV2P2MR output = builder.GetP2MROutput();
    const CScript script_pub_key = GetScriptForDestination(output);
    const P2MRSpendData spenddata = builder.GetP2MRSpendData();
    const auto spend_it = spenddata.scripts.find({std::vector<unsigned char>{leaf_script.begin(), leaf_script.end()}, P2MR_LEAF_VERSION});
    BOOST_REQUIRE(spend_it != spenddata.scripts.end());
    BOOST_REQUIRE_EQUAL(spend_it->second.size(), 1U);

    const std::string prevtxs = strprintf(
        "[{\"txid\":\"%s\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.00000000,\"p2mrScript\":\"%s\",\"p2mrControlBlock\":\"%s\"}]",
        "0101010101010101010101010101010101010101010101010101010101010101",
        HexStr(script_pub_key),
        HexStr(leaf_script),
        HexStr(*spend_it->second.begin()));

    FlatSigningProvider provider;
    std::map<COutPoint, Coin> coins;
    ParsePrevouts(JSON(prevtxs), &provider, coins);

    P2MRSpendData parsed;
    BOOST_CHECK(provider.GetP2MRSpendData(output, parsed));
    BOOST_CHECK(parsed.merkle_root == output.GetMerkleRoot());
    BOOST_CHECK_EQUAL(parsed.scripts.size(), 1U);
    BOOST_CHECK(parsed.scripts.contains({std::vector<unsigned char>{leaf_script.begin(), leaf_script.end()}, P2MR_LEAF_VERSION}));

    UniValue p2mr_vectors;
    BOOST_REQUIRE(p2mr_vectors.read(json_tests::p2mr_vectors));
    const UniValue& vector = p2mr_vectors["valid"][0];
    const std::vector<unsigned char> vector_leaf_script{ParseHex(vector["leaf_script"].get_str())};
    const uint8_t vector_leaf_version{static_cast<uint8_t>(vector["leaf_version"].getInt<int>())};
    const std::string vector_prevtxs = strprintf(
        "[{\"txid\":\"%s\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.00000000,\"p2mrScript\":\"%s\",\"p2mrControlBlock\":\"%s\"}]",
        "0404040404040404040404040404040404040404040404040404040404040404",
        vector["scriptPubKey"].get_str(),
        vector["leaf_script"].get_str(),
        vector["control_block"].get_str());

    FlatSigningProvider vector_provider;
    std::map<COutPoint, Coin> vector_coins;
    ParsePrevouts(JSON(vector_prevtxs), &vector_provider, vector_coins);
    const WitnessV2P2MR vector_output{uint256{ParseHex(vector["merkle_root"].get_str())}};
    P2MRSpendData vector_parsed;
    BOOST_CHECK(vector_provider.GetP2MRSpendData(vector_output, vector_parsed));
    BOOST_CHECK_EQUAL(vector_parsed.merkle_root, vector_output.GetMerkleRoot());
    BOOST_CHECK(vector_parsed.scripts.contains({vector_leaf_script, vector_leaf_version}));

    const CScript anchor_script_pub_key = GetScriptForDestination(PayToAnchor{});
    const std::string anchor_prevtxs = strprintf(
        "[{\"txid\":\"%s\",\"vout\":1,\"scriptPubKey\":\"%s\",\"amount\":1.00000000}]",
        "0202020202020202020202020202020202020202020202020202020202020202",
        HexStr(anchor_script_pub_key));
    FlatSigningProvider anchor_provider;
    std::map<COutPoint, Coin> anchor_coins;
    BOOST_CHECK_NO_THROW(ParsePrevouts(JSON(anchor_prevtxs), &anchor_provider, anchor_coins));

    const std::vector<unsigned char> reserved_program(32, 0x03);
    const CScript reserved_script_pub_key = GetScriptForDestination(WitnessUnknown{3, reserved_program});
    const std::string reserved_prevtxs = strprintf(
        "[{\"txid\":\"%s\",\"vout\":2,\"scriptPubKey\":\"%s\",\"amount\":1.00000000}]",
        "0303030303030303030303030303030303030303030303030303030303030303",
        HexStr(reserved_script_pub_key));
    FlatSigningProvider reserved_provider;
    std::map<COutPoint, Coin> reserved_coins;
    BOOST_CHECK_NO_THROW(ParsePrevouts(JSON(reserved_prevtxs), &reserved_provider, reserved_coins));
    BOOST_CHECK(!NormalizeActiveHeight(-1).has_value());
    BOOST_CHECK_NO_THROW(ParsePrevouts(JSON(reserved_prevtxs), &reserved_provider, reserved_coins, NormalizeActiveHeight(-1)));
    const auto active_height = NormalizeActiveHeight(0);
    BOOST_REQUIRE(active_height.has_value());
    BOOST_CHECK_EQUAL(*active_height, 0);

    std::vector<unsigned char> invalid_control = *spend_it->second.begin();
    invalid_control[0] &= TAPROOT_LEAF_MASK;
    const std::string invalid_prevtxs = strprintf(
        "[{\"txid\":\"%s\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.00000000,\"p2mrScript\":\"%s\",\"p2mrControlBlock\":\"%s\"}]",
        "0101010101010101010101010101010101010101010101010101010101010101",
        HexStr(script_pub_key),
        HexStr(leaf_script),
        HexStr(invalid_control));
    FlatSigningProvider invalid_provider;
    std::map<COutPoint, Coin> invalid_coins;
    BOOST_CHECK_EXCEPTION(
        ParsePrevouts(JSON(invalid_prevtxs), &invalid_provider, invalid_coins),
        UniValue,
        HasJSON(R"({"code":-8,"message":"P2MR control byte bit 0 must be set"})"));
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\"}"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"somedata\":\"68656c6c6f776f726c64\"}"), std::runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345\"}"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345g\"}"), std::runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00000000");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.00000001");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "0.17622195");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "0.50000000");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "0.89898989");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1.00000000");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999.99999990");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999.99999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN/10000)*123456789).write(), "12345.67890000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN/10).write(), "-0.10000000");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000000).write(), "100000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000000).write(), "10000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000000).write(), "1000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000).write(), "100000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000).write(), "10000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000).write(), "1000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100).write(), "100.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10).write(), "10.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10).write(), "0.10000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100).write(), "0.01000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000).write(), "0.00100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000).write(), "0.00010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000).write(), "0.00001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000000).write(), "0.00000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000000).write(), "0.00000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000000).write(), "0.00000001");

    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max()).write(), "92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 1).write(), "92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 2).write(), "92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 3).write(), "92233720368.54775804");
    // ...
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 3).write(), "-92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 2).write(), "-92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 1).write(), "-92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min()).write(), "-92233720368.54775808");
}

static UniValue ValueFromString(const std::string& str) noexcept
{
    UniValue value;
    value.setNumStr(str);
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.00000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17622195")), 17622195LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50000000")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89898989")), 89898989LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.9999999")), 2099999999999990LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99999999")), 2099999999999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-8")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-7")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-6")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000000000000000000000000000000001e+30")), 1);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")), COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64")), COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); //should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.000000019")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001000000")), 1LL); //should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-6")), 19); //should pass, leading 0 is present
    BOOST_CHECK_EXCEPTION(AmountFromValue(".19e-6"), UniValue, HasJSON(R"({"code":-3,"message":"Invalid amount"})")); //should fail, no leading 0

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+11")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e11")), UniValue); //overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+9")), UniValue); //overflow error
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.0:8334")), std::runtime_error); //portnumber for setban not allowed
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 9907731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    int64_t banned_until{o1.find_value("banned_until").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, 9907731200); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    auto now = 10'000s;
    SetMockTime(now);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 200")));
    SetMockTime(now += 2s);
    const int64_t time_remaining_expected{198};
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    banned_until = o1.find_value("banned_until").getInt<int64_t>();
    const int64_t ban_created{o1.find_value("ban_created").getInt<int64_t>()};
    const int64_t ban_duration{o1.find_value("ban_duration").getInt<int64_t>()};
    const int64_t time_remaining{o1.find_value("time_remaining").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, time_remaining_expected + now.count());
    BOOST_CHECK_EQUAL(ban_duration, banned_until - ban_created);
    BOOST_CHECK_EQUAL(time_remaining, time_remaining_expected);

    // must throw an exception because 127.0.0.1 is in already banned subnet range
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.1.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);


    BOOST_CHECK_THROW(r = CallRPC(std::string("setban test add")), std::runtime_error); //invalid IP

    //IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_importpubkeydb_timestamp)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("importpubkeydb", {"[]", "false", "now"}));
    BOOST_CHECK(result[0].isArray());
    BOOST_CHECK_EQUAL(result[0].get_array().size(), 0U);
    BOOST_CHECK(!result[1].get_bool());
    BOOST_CHECK(result[2].isStr());
    BOOST_CHECK_EQUAL(result[2].get_str(), "now");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("importpubkeydb", {"[]", "false", "0"}));
    BOOST_CHECK(result[2].isNum());
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 0);

    BOOST_CHECK_NO_THROW(result = RPCConvertNamedValues("importpubkeydb", {"pubkeys=[]", "internal=false", "timestamp=now"}));
    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.find_value("pubkeys").isArray());
    BOOST_CHECK(!result.find_value("internal").get_bool());
    BOOST_CHECK(result.find_value("timestamp").isStr());
    BOOST_CHECK_EQUAL(result.find_value("timestamp").get_str(), "now");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_getnetworkhashps_lane)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("getnetworkhashps", {"120", "-1", "permissionless"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 120);
    BOOST_CHECK_EQUAL(result[1].getInt<int>(), -1);
    BOOST_CHECK(result[2].isStr());
    BOOST_CHECK_EQUAL(result[2].get_str(), "permissionless");

    BOOST_CHECK_NO_THROW(result = RPCConvertNamedValues("getnetworkhashps", {"nblocks=120", "height=-1", "lane=auxpow"}));
    BOOST_CHECK(result.isObject());
    BOOST_CHECK_EQUAL(result.find_value("nblocks").getInt<int>(), 120);
    BOOST_CHECK_EQUAL(result.find_value("height").getInt<int>(), -1);
    BOOST_CHECK(result.find_value("lane").isStr());
    BOOST_CHECK_EQUAL(result.find_value("lane").get_str(), "auxpow");
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_calculate_percentiles_by_weight)
{
    int64_t total_weight = 200;
    std::vector<std::pair<CAmount, int64_t>> feerates;
    feerates.reserve(200);
    CAmount result[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(1 ,1);
    }

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(2 ,1);
    }

    CalculatePercentilesByWeight(result, feerates, total_weight);
    BOOST_CHECK_EQUAL(result[0], 1);
    BOOST_CHECK_EQUAL(result[1], 1);
    BOOST_CHECK_EQUAL(result[2], 1);
    BOOST_CHECK_EQUAL(result[3], 2);
    BOOST_CHECK_EQUAL(result[4], 2);

    // Test with more pairs, and two pairs overlapping 2 percentiles.
    total_weight = 100;
    CAmount result2[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 16); //10th + 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15);  // 90th percentile

    CalculatePercentilesByWeight(result2, feerates, total_weight);

    BOOST_CHECK_EQUAL(result2[0], 2);
    BOOST_CHECK_EQUAL(result2[1], 2);
    BOOST_CHECK_EQUAL(result2[2], 4);
    BOOST_CHECK_EQUAL(result2[3], 4);
    BOOST_CHECK_EQUAL(result2[4], 9);

    // Same test as above, but one of the percentile-overlapping pairs is split in 2.
    total_weight = 100;
    CAmount result3[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 11); // 10th percentile
    feerates.emplace_back(2 , 5); // 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15); // 90th percentile

    CalculatePercentilesByWeight(result3, feerates, total_weight);

    BOOST_CHECK_EQUAL(result3[0], 2);
    BOOST_CHECK_EQUAL(result3[1], 2);
    BOOST_CHECK_EQUAL(result3[2], 4);
    BOOST_CHECK_EQUAL(result3[3], 4);
    BOOST_CHECK_EQUAL(result3[4], 9);

    // Test with one transaction spanning all percentiles.
    total_weight = 104;
    CAmount result4[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 100);
    feerates.emplace_back(2, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(999999, 1);

    CalculatePercentilesByWeight(result4, feerates, total_weight);

    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        BOOST_CHECK_EQUAL(result4[i], 1);
    }
}

// Make sure errors are triggered appropriately if parameters have the same names.
BOOST_AUTO_TEST_CASE(check_dup_param_names)
{
    enum ParamType { POSITIONAL, NAMED, NAMED_ONLY };
    auto make_rpc = [](std::vector<std::tuple<std::string, ParamType>> param_names) {
        std::vector<RPCArg> params;
        std::vector<RPCArg> options;
        auto push_options = [&] { if (!options.empty()) params.emplace_back(strprintf("options%i", params.size()), RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", std::move(options)); };
        for (auto& [param_name, param_type] : param_names) {
            if (param_type == POSITIONAL) {
                push_options();
                params.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description");
            } else {
                options.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description", RPCArgOptions{.also_positional = param_type == NAMED});
            }
        }
        push_options();
        return RPCHelpMan{"method_name", "description", params, RPCResults{}, RPCExamples{""}};
    };

    // No errors if parameter names are unique.
    make_rpc({{"p1", POSITIONAL}, {"p2", POSITIONAL}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED_ONLY}});

    // Error if parameters names are duplicates, unless one parameter is
    // positional and the other is named and .also_positional is true.
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", POSITIONAL}}), NonFatalCheckError);
    make_rpc({{"p1", POSITIONAL}, {"p1", NAMED}});
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    make_rpc({{"p1", NAMED}, {"p1", POSITIONAL}});
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", POSITIONAL}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED}}), NonFatalCheckError);
    BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED_ONLY}}), NonFatalCheckError);

    // Make sure duplicate aliases are detected too.
    BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p2|p1", NAMED_ONLY}}), NonFatalCheckError);
}

BOOST_AUTO_TEST_CASE(help_example)
{
    // test different argument types
    const RPCArgList& args = {{"foo", "bar"}, {"b", true}, {"n", 1}};
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", args), "> qbit-cli -named test foo=bar b=true n=1\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", args), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"foo\":\"bar\",\"b\":true,\"n\":1}}' -H 'content-type: application/json' http://127.0.0.1:8352/\n");

    // test shell escape
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b'ar"}}), "> qbit-cli -named test foo='b'''ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b\"ar"}}), "> qbit-cli -named test foo='b\"ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b ar"}}), "> qbit-cli -named test foo='b ar'\n");

    // test object params
    UniValue obj_value(UniValue::VOBJ);
    obj_value.pushKV("foo", "bar");
    obj_value.pushKV("b", false);
    obj_value.pushKV("n", 1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", obj_value}}), "> qbit-cli -named test name='{\"foo\":\"bar\",\"b\":false,\"n\":1}'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", obj_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":{\"foo\":\"bar\",\"b\":false,\"n\":1}}}' -H 'content-type: application/json' http://127.0.0.1:8352/\n");

    // test array params
    UniValue arr_value(UniValue::VARR);
    arr_value.push_back("bar");
    arr_value.push_back(false);
    arr_value.push_back(1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", arr_value}}), "> qbit-cli -named test name='[\"bar\",false,1]'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", arr_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":[\"bar\",false,1]}}' -H 'content-type: application/json' http://127.0.0.1:8352/\n");

    // test types don't matter for shell
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("foo", {{"arg", true}}), HelpExampleCliNamed("foo", {{"arg", "true"}}));

    // test types matter for Rpc
    BOOST_CHECK_NE(HelpExampleRpcNamed("foo", {{"arg", true}}), HelpExampleRpcNamed("foo", {{"arg", "true"}}));
}

BOOST_AUTO_TEST_CASE(default_rpc_ports)
{
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::MAIN)->RPCPort(), 8352);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::TESTNET)->RPCPort(), 18352);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::TESTNET4)->RPCPort(), 48352);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::SIGNET)->RPCPort(), 38352);
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::REGTEST)->RPCPort(), 18452);
}

static void CheckRpc(const std::vector<RPCArg>& params, const UniValue& args, RPCHelpMan::RPCMethodImpl test_impl)
{
    auto null_result{RPCResult{RPCResult::Type::NONE, "", "None"}};
    const RPCHelpMan rpc{"dummy", "dummy description", params, null_result, RPCExamples{""}, test_impl};
    JSONRPCRequest req;
    req.params = args;

    rpc.HandleRequest(req);
}

BOOST_AUTO_TEST_CASE(rpc_arg_helper)
{
    constexpr bool DEFAULT_BOOL = true;
    constexpr auto DEFAULT_STRING = "default";
    constexpr uint64_t DEFAULT_UINT64_T = 3;

    //! Parameters with which the RPCHelpMan is instantiated
    const std::vector<RPCArg> params{
        // Required arg
        {"req_int", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
        {"req_str", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
        // Default arg
        {"def_uint64_t", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_UINT64_T}, ""},
        {"def_string", RPCArg::Type::STR, RPCArg::Default{DEFAULT_STRING}, ""},
        {"def_bool", RPCArg::Type::BOOL, RPCArg::Default{DEFAULT_BOOL}, ""},
        // Optional arg without default
        {"opt_double", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
        {"opt_string", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}
    };

    //! Check that `self.Arg` returns the same value as the `request.params` accessors
    RPCHelpMan::RPCMethodImpl check_positional = [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            BOOST_CHECK_EQUAL(self.Arg<int>("req_int"), request.params[0].getInt<int>());
            BOOST_CHECK_EQUAL(self.Arg<std::string>("req_str"), request.params[1].get_str());
            BOOST_CHECK_EQUAL(self.Arg<uint64_t>("def_uint64_t"), request.params[2].isNull() ? DEFAULT_UINT64_T : request.params[2].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(self.Arg<std::string>("def_string"), request.params[3].isNull() ? DEFAULT_STRING : request.params[3].get_str());
            BOOST_CHECK_EQUAL(self.Arg<bool>("def_bool"), request.params[4].isNull() ? DEFAULT_BOOL : request.params[4].get_bool());
            if (!request.params[5].isNull()) {
                BOOST_CHECK_EQUAL(self.MaybeArg<double>("opt_double").value(), request.params[5].get_real());
            } else {
                BOOST_CHECK(!self.MaybeArg<double>("opt_double"));
            }
            if (!request.params[6].isNull()) {
                BOOST_CHECK(self.MaybeArg<std::string>("opt_string"));
                BOOST_CHECK_EQUAL(*self.MaybeArg<std::string>("opt_string"), request.params[6].get_str());
            } else {
                BOOST_CHECK(!self.MaybeArg<std::string>("opt_string"));
            }
            return UniValue{};
        };
    CheckRpc(params, UniValue{JSON(R"([5, "hello", null, null, null, null, null])")}, check_positional);
    CheckRpc(params, UniValue{JSON(R"([5, "hello", 4, "test", true, 1.23, "world"])")}, check_positional);
}

BOOST_AUTO_TEST_SUITE_END()
