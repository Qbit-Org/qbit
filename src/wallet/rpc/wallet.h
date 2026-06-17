// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_WALLET_RPC_WALLET_H
#define QBIT_WALLET_RPC_WALLET_H

#include <span.h>

class CRPCCommand;
class CRPCTable;

namespace wallet {
std::span<const CRPCCommand> GetWalletRPCCommands();
std::span<const CRPCCommand> GetWalletExternalSignerRPCCommands();
void RegisterWalletRPCCommands(CRPCTable& t);
} // namespace wallet

#endif // QBIT_WALLET_RPC_WALLET_H
