// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <bitcoin-build-info.h>

#include <clientversion.h>
#include <rpc/doc.h>
#include <rpc/server.h>
#include <rpc/util.h>

#include <algorithm>
#include <string>
#include <string_view>

namespace {
constexpr std::string_view RPC_DOCS_SCHEMA_VERSION{"1"};
constexpr std::string_view RPC_DOCS_PROJECT{"qbit"};
constexpr std::string_view RPC_DOCS_GENERATOR{"qbit-rpcdocgen"};

std::string RPCComponentToString(RPCComponent component)
{
    switch (component) {
    case RPCComponent::CORE: return "core";
    case RPCComponent::WALLET: return "wallet";
    case RPCComponent::ZMQ: return "zmq";
    case RPCComponent::SIGNER: return "signer";
    }
    NONFATAL_UNREACHABLE();
}

UniValue BuildFeatureMatrix()
{
    UniValue features{UniValue::VOBJ};
#ifdef ENABLE_WALLET
    features.pushKV("wallet", true);
#else
    features.pushKV("wallet", false);
#endif
#ifdef ENABLE_ZMQ
    features.pushKV("zmq", true);
#else
    features.pushKV("zmq", false);
#endif
#ifdef ENABLE_EXTERNAL_SIGNER
    features.pushKV("external_signer", true);
#else
    features.pushKV("external_signer", false);
#endif
    return features;
}

std::string GetSourceRef()
{
#ifdef BUILD_GIT_TAG
    return BUILD_GIT_TAG;
#elif defined(BUILD_GIT_COMMIT)
    return BUILD_GIT_COMMIT;
#else
    return {};
#endif
}

RPCHelpDocOptions BuildDocOptions(const RPCCommandDoc& doc)
{
    RPCHelpDocOptions options;
    options.category = doc.category;
    options.component = RPCComponentToString(doc.component);
    options.visible = doc.category != "hidden";
    options.requires_wallet = doc.component == RPCComponent::WALLET;
    options.requires_zmq = doc.component == RPCComponent::ZMQ;
    options.requires_external_signer = doc.component == RPCComponent::SIGNER || doc.requires_external_signer;
    return options;
}
} // namespace

UniValue BuildRPCDocsManifest(const std::vector<RPCCommandDoc>& docs)
{
    UniValue manifest{UniValue::VOBJ};
    manifest.pushKV("schema_version", std::string{RPC_DOCS_SCHEMA_VERSION});
    manifest.pushKV("project", std::string{RPC_DOCS_PROJECT});
    manifest.pushKV("project_version", FormatFullVersion());

    std::vector<const RPCCommandDoc*> sorted_docs;
    sorted_docs.reserve(docs.size());
    for (const auto& doc : docs) {
        sorted_docs.push_back(&doc);
    }
    std::ranges::sort(sorted_docs, [](const RPCCommandDoc* lhs, const RPCCommandDoc* rhs) {
        if (lhs->category != rhs->category) return lhs->category < rhs->category;
        return lhs->name < rhs->name;
    });

    UniValue methods{UniValue::VARR};
    for (const RPCCommandDoc* doc : sorted_docs) {
        methods.push_back(doc->help.ToUniValue(BuildDocOptions(*doc)));
    }
    manifest.pushKV("methods", std::move(methods));
    return manifest;
}

UniValue BuildRPCDocsBuildMeta(const std::vector<RPCCommandDoc>& docs)
{
    UniValue meta{UniValue::VOBJ};
    meta.pushKV("schema_version", std::string{RPC_DOCS_SCHEMA_VERSION});
    meta.pushKV("project", std::string{RPC_DOCS_PROJECT});
    meta.pushKV("project_version", FormatFullVersion());
    meta.pushKV("generator", std::string{RPC_DOCS_GENERATOR});

    const std::string source_ref{GetSourceRef()};
    if (!source_ref.empty()) {
        meta.pushKV("source_ref", source_ref);
    }

    meta.pushKV("feature_matrix", BuildFeatureMatrix());
    meta.pushKV("method_count", static_cast<int>(docs.size()));
    return meta;
}
