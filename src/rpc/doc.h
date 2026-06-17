// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_RPC_DOC_H
#define QBIT_RPC_DOC_H

#include <rpc/server.h>
#include <univalue.h>

#include <vector>

UniValue BuildRPCDocsManifest(const std::vector<RPCCommandDoc>& docs);
UniValue BuildRPCDocsBuildMeta(const std::vector<RPCCommandDoc>& docs);

#endif // QBIT_RPC_DOC_H
