// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <rpc/doc.h>
#include <rpc/server.h>
#include <rpc/util.h>

#include <optional>
#include <string>
#include <vector>

namespace {
const UniValue* FindMethodByName(const UniValue& manifest, const std::string& name)
{
    const UniValue& methods = manifest.get_obj().find_value("methods");
    for (const UniValue& method : methods.getValues()) {
        if (method.get_obj().find_value("name").get_str() == name) {
            return &method;
        }
    }
    return nullptr;
}

RPCHelpMan AlphaDoc()
{
    return RPCHelpMan{
        "alphadoc",
        "Alpha summary.\nAdditional alpha detail.",
        {},
        RPCResult{RPCResult::Type::NONE, "", "No result"},
        RPCExamples{""},
    };
}

RPCHelpMan ZetaDoc()
{
    return RPCHelpMan{
        "zetadoc",
        "Zeta summary.\nAdditional zeta detail.",
        {},
        RPCResult{RPCResult::Type::NONE, "", "No result"},
        RPCExamples{""},
    };
}

RPCHelpMan WalletDoc()
{
    return RPCHelpMan{
        "walletdoc",
        "Wallet summary.\nAdditional wallet detail.",
        {},
        RPCResult{RPCResult::Type::NONE, "", "No result"},
        RPCExamples{""},
    };
}

RPCHelpMan HiddenDoc()
{
    return RPCHelpMan{
        "hiddendoc",
        "Hidden summary.\nAdditional hidden detail.",
        {
            {"visible", RPCArg::Type::STR, RPCArg::Optional::NO, "Visible argument"},
            {"secret", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Hidden argument", RPCArgOptions{.hidden = true}},
            {"tail", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Trailing hidden argument"},
        },
        RPCResult{RPCResult::Type::STR, "", "ok"},
        RPCExamples{""},
    };
}
} // namespace

BOOST_AUTO_TEST_SUITE(rpc_doc_tests)

BOOST_AUTO_TEST_CASE(rpc_doc_manifest_orders_methods_by_category_and_name)
{
    const CRPCCommand commands[]{
        {"wallet", &WalletDoc},
        {"blockchain", &ZetaDoc},
        {"blockchain", &AlphaDoc},
    };

    CRPCTable table;
    table.appendCommand(commands[0].name, &commands[0], RPCComponent::WALLET);
    table.appendCommand(commands[1].name, &commands[1]);
    table.appendCommand(commands[2].name, &commands[2]);

    const UniValue manifest{BuildRPCDocsManifest(table.GetCommandDocs())};
    const UniValue& methods = manifest.get_obj().find_value("methods");

    BOOST_REQUIRE_EQUAL(methods.size(), 7U);
    BOOST_CHECK_EQUAL(methods[0].get_obj().find_value("category").get_str(), "blockchain");
    BOOST_CHECK_EQUAL(methods[0].get_obj().find_value("name").get_str(), "alphadoc");
    BOOST_CHECK_EQUAL(methods[1].get_obj().find_value("name").get_str(), "zetadoc");
    BOOST_CHECK_EQUAL(methods[6].get_obj().find_value("component").get_str(), "wallet");
    BOOST_CHECK_EQUAL(methods[6].get_obj().find_value("name").get_str(), "walletdoc");
}

BOOST_AUTO_TEST_CASE(rpc_doc_manifest_marks_hidden_methods_and_hidden_tail_args)
{
    const CRPCCommand hidden_command{"hidden", &HiddenDoc};

    CRPCTable table;
    table.appendCommand(hidden_command.name, &hidden_command);

    const UniValue manifest{BuildRPCDocsManifest(table.GetCommandDocs())};
    const UniValue* hidden_method{FindMethodByName(manifest, "hiddendoc")};
    BOOST_REQUIRE(hidden_method != nullptr);

    BOOST_CHECK(!hidden_method->get_obj().find_value("visible").get_bool());
    const UniValue& arguments = hidden_method->get_obj().find_value("arguments");
    BOOST_REQUIRE_EQUAL(arguments.size(), 3U);
    BOOST_CHECK(arguments[0].get_obj().find_value("hidden").isNull());
    BOOST_CHECK(arguments[1].get_obj().find_value("hidden").get_bool());
    BOOST_CHECK(arguments[2].get_obj().find_value("hidden").get_bool());
}

BOOST_AUTO_TEST_CASE(rpc_doc_manifest_marks_external_signer_requirements_from_registration_metadata)
{
    const CRPCCommand wallet_command{"wallet", &WalletDoc};

    CRPCTable table;
    table.appendCommand(wallet_command.name, &wallet_command, RPCComponent::WALLET, /*requires_external_signer=*/true);

    const UniValue manifest{BuildRPCDocsManifest(table.GetCommandDocs())};
    const UniValue* wallet_method{FindMethodByName(manifest, "walletdoc")};
    BOOST_REQUIRE(wallet_method != nullptr);

    const UniValue& feature_flags = wallet_method->get_obj().find_value("feature_flags");
    BOOST_CHECK(feature_flags.get_obj().find_value("requires_wallet").get_bool());
    BOOST_CHECK(feature_flags.get_obj().find_value("requires_external_signer").get_bool());
}

BOOST_AUTO_TEST_CASE(rpc_doc_serialization_emits_expected_shape)
{
    const RPCHelpMan doc{
        "serializedoc",
        "Summary line.\nAdditional detail paragraph.",
        {
            {"primary|zulu|alpha", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Primary amount"},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "Optional settings",
                {
                    {"mode|delta|beta", RPCArg::Type::STR, RPCArg::DefaultHint{"auto"}, "Selection mode"},
                    {"enabled", RPCArg::Type::BOOL, RPCArg::Default{true}, "Enable serialization"},
                }},
        },
        {
            RPCResult{"when enabled", RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "status", "Result status"},
                    {RPCResult::Type::NUM, "count", /*optional=*/true, "Item count"},
                }},
            RPCResult{RPCResult::Type::NONE, "", "No result"},
        },
        RPCExamples{
            HelpExampleCli("serializedoc", "1")
            + HelpExampleRpc("serializedoc", "[1]")
        },
    };

    const UniValue serialized{doc.ToUniValue({
        .category = "wallet",
        .component = "wallet",
        .visible = true,
        .requires_wallet = true,
    })};

    BOOST_CHECK_EQUAL(serialized.get_obj().find_value("name").get_str(), "serializedoc");
    BOOST_CHECK_EQUAL(serialized.get_obj().find_value("summary_line").get_str(), "Summary line.");
    BOOST_CHECK_EQUAL(serialized.get_obj().find_value("component").get_str(), "wallet");
    BOOST_CHECK(serialized.get_obj().find_value("feature_flags").get_obj().find_value("requires_wallet").get_bool());

    const UniValue& arguments = serialized.get_obj().find_value("arguments");
    BOOST_REQUIRE_EQUAL(arguments.size(), 2U);
    BOOST_CHECK_EQUAL(arguments[0].get_obj().find_value("type").get_str(), "AMOUNT");
    const UniValue& aliases = arguments[0].get_obj().find_value("aliases");
    BOOST_REQUIRE_EQUAL(aliases.size(), 2U);
    BOOST_CHECK_EQUAL(aliases[0].get_str(), "alpha");
    BOOST_CHECK_EQUAL(aliases[1].get_str(), "zulu");
    BOOST_CHECK(arguments[0].get_obj().find_value("required").get_bool());

    const UniValue& option_children = arguments[1].get_obj().find_value("children");
    BOOST_REQUIRE_EQUAL(option_children.size(), 2U);
    BOOST_CHECK_EQUAL(option_children[0].get_obj().find_value("default_kind").get_str(), "hint");
    BOOST_CHECK_EQUAL(option_children[0].get_obj().find_value("default_hint").get_str(), "auto");
    const UniValue& option_aliases = option_children[0].get_obj().find_value("aliases");
    BOOST_REQUIRE_EQUAL(option_aliases.size(), 2U);
    BOOST_CHECK_EQUAL(option_aliases[0].get_str(), "beta");
    BOOST_CHECK_EQUAL(option_aliases[1].get_str(), "delta");
    BOOST_CHECK_EQUAL(option_children[1].get_obj().find_value("default_kind").get_str(), "value");
    BOOST_CHECK(option_children[1].get_obj().find_value("default_value").get_bool());

    const UniValue& results = serialized.get_obj().find_value("results");
    BOOST_REQUIRE_EQUAL(results.size(), 2U);
    BOOST_CHECK_EQUAL(results[0].get_obj().find_value("conditional").get_str(), "when enabled");
    BOOST_CHECK(results[0].get_obj().find_value("children")[1].get_obj().find_value("optional").get_bool());

    const UniValue& examples = serialized.get_obj().find_value("examples");
    BOOST_REQUIRE_EQUAL(examples.size(), 2U);
    BOOST_CHECK_EQUAL(examples[0].get_str().substr(0, 9), "qbit-cli ");
    BOOST_CHECK_EQUAL(examples[1].get_str().substr(0, 4), "curl");

    const UniValue build_meta{BuildRPCDocsBuildMeta(std::vector<RPCCommandDoc>{{"wallet", "serializedoc", RPCComponent::WALLET, doc, false}})};
    BOOST_CHECK_EQUAL(build_meta.get_obj().find_value("schema_version").get_str(), "1");
    BOOST_CHECK_EQUAL(build_meta.get_obj().find_value("generator").get_str(), "qbit-rpcdocgen");
    BOOST_CHECK_EQUAL(build_meta.get_obj().find_value("method_count").getInt<int>(), 1);
    BOOST_CHECK(build_meta.get_obj().find_value("feature_matrix").get_obj().find_value("wallet").isBool());
}

BOOST_AUTO_TEST_SUITE_END()
