// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <rpc/doc.h>
#include <rpc/docgen.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <util/readwritefile.h>

#ifdef ENABLE_WALLET
#include <wallet/rpc/wallet.h>
#endif
#ifdef ENABLE_ZMQ
#include <zmq/zmqrpc.h>
#endif

#include <stdexcept>
#include <vector>

namespace {
constexpr auto RPC_DOCS_FILENAME = "rpc-docs.json";
constexpr auto RPC_DOCS_BUILD_META_FILENAME = "rpc-docs-build-meta.json";

std::vector<RPCCommandDoc> CollectRPCCommandDocs()
{
    CRPCTable table;
    RegisterAllCoreRPCCommands(table);
#ifdef ENABLE_WALLET
    wallet::RegisterWalletRPCCommands(table);
#endif
#ifdef ENABLE_ZMQ
    RegisterZMQRPCCommands(table);
#endif
    return table.GetCommandDocs();
}

void WriteJsonFile(const fs::path& path, const UniValue& value)
{
    if (!WriteBinaryFile(path, value.write(2) + "\n")) {
        throw std::runtime_error(strprintf("Unable to write %s", fs::PathToString(path)));
    }
}
} // namespace

void GenerateRPCDocs(const fs::path& output_dir)
{
    fs::create_directories(output_dir);
    if (!fs::is_directory(output_dir)) {
        throw std::runtime_error(strprintf("Output path is not a directory: %s", fs::PathToString(output_dir)));
    }

    const std::vector<RPCCommandDoc> docs{CollectRPCCommandDocs()};
    WriteJsonFile(output_dir / RPC_DOCS_FILENAME, BuildRPCDocsManifest(docs));
    WriteJsonFile(output_dir / RPC_DOCS_BUILD_META_FILENAME, BuildRPCDocsBuildMeta(docs));
}
