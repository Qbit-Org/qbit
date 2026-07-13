// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_WALLET_RPC_UTIL_H
#define QBIT_WALLET_RPC_UTIL_H

#include <rpc/util.h>
#include <script/script.h>
#include <wallet/pqc_usage.h>
#include <wallet/wallet.h>

#include <any>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

class JSONRPCRequest;
class UniValue;
struct Descriptor;
struct bilingual_str;

namespace wallet {
class LegacyScriptPubKeyMan;
enum class DatabaseStatus;
struct WalletContext;

extern const std::string HELP_REQUIRING_PASSPHRASE;
extern const std::string P2MR_BIP32_PUBLIC_DERIVATION_ERROR;
extern const std::string P2MR_DESCRIPTOR_EXPORT_WARNING;

static const RPCResult RESULT_LAST_PROCESSED_BLOCK { RPCResult::Type::OBJ, "lastprocessedblock", "hash and height of the block this information was generated on",{
    {RPCResult::Type::STR_HEX, "hash", "hash of the block this information was generated on"},
    {RPCResult::Type::NUM, "height", "height of the block this information was generated on"}}
};

/**
 * Figures out what wallet, if any, to use for a JSONRPCRequest.
 *
 * @param[in] request JSONRPCRequest that wishes to access a wallet
 * @return nullptr if no wallet should be used, or a pointer to the CWallet
 */
std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request);
bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request, std::string& wallet_name);
/**
 * Ensures that a wallet name is specified across the endpoint and wallet_name.
 * Throws `RPC_INVALID_PARAMETER` if none or different wallet names are specified.
 */
std::string EnsureUniqueWalletName(const JSONRPCRequest& request, const std::string* wallet_name);

void EnsureWalletIsUnlocked(const CWallet&);
WalletContext& EnsureWalletContext(const std::any& context);

bool GetAvoidReuseFlag(const CWallet& wallet, const UniValue& param);
std::string LabelFromValue(const UniValue& value);
OutputType ParseWalletOutputType(const CWallet& wallet, const std::string& type, std::string_view kind, bool internal);
OutputType ParseWalletOutputType(const std::string& type, std::string_view kind);
bool IsP2MRBIP32PublicDerivationDescriptor(const Descriptor& descriptor);
bool ShouldSuppressP2MRBIP32Descriptor(const Descriptor& descriptor, bool private_export);
//! Fetch parent descriptors of this scriptPubKey.
void PushParentDescriptors(const CWallet& wallet, const CScript& script_pubkey, UniValue& entry);
std::vector<RPCResult> PQCUsageRPCResults(bool include_warnings);
void AppendPQCUsage(UniValue& entry, const PQCUsageReport& report, bool include_warnings);

void HandleWalletError(const std::shared_ptr<CWallet> wallet, DatabaseStatus& status, bilingual_str& error);
void AppendLastProcessedBlock(UniValue& entry, const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} //  namespace wallet

#endif // QBIT_WALLET_RPC_UTIL_H
