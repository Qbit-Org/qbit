// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpc/util.h>

#include <common/url.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <util/any.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <set>
#include <string_view>
#include <univalue.h>

namespace wallet {
static const std::string WALLET_ENDPOINT_BASE = "/wallet/";
const std::string HELP_REQUIRING_PASSPHRASE{"\nRequires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.\n"};
const std::string P2MR_BIP32_PUBLIC_DERIVATION_ERROR{
    "BIP32 extended public keys cannot derive SPHINCS+/P2MR public keys. Use exportpubkeydb/importpubkeydb for watch-only P2MR tracking."};
const std::string P2MR_DESCRIPTOR_EXPORT_WARNING{
    "Omitted P2MR descriptors that use BIP32 extended public keys because they are not a SPHINCS+/P2MR public derivation interface. Use exportpubkeydb for watch-only P2MR tracking."};

bool GetAvoidReuseFlag(const CWallet& wallet, const UniValue& param) {
    bool can_avoid_reuse = wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    bool avoid_reuse = param.isNull() ? can_avoid_reuse : param.get_bool();

    if (avoid_reuse && !can_avoid_reuse) {
        throw JSONRPCError(RPC_WALLET_ERROR, "wallet does not have the \"avoid reuse\" feature enabled");
    }

    return avoid_reuse;
}

static OutputType ParseWalletOutputTypeImpl(const std::string& type, std::string_view kind, const CWallet* wallet, bool internal)
{
    std::optional<OutputType> parsed = ParseOutputType(type);
    if (!parsed) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown %s '%s'", kind, type));
    }

    if (!IsWalletOutputTypeAllowed(parsed.value())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s '%s' is not available on this chain", kind, type));
    }
    if (wallet && !HasWalletOutputTypeManager(*wallet, parsed.value(), internal)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s '%s' is not available in this wallet", kind, type));
    }
    return parsed.value();
}

OutputType ParseWalletOutputType(const CWallet& wallet, const std::string& type, std::string_view kind, bool internal)
{
    return ParseWalletOutputTypeImpl(type, kind, &wallet, internal);
}

OutputType ParseWalletOutputType(const std::string& type, std::string_view kind)
{
    return ParseWalletOutputTypeImpl(type, kind, nullptr, /*internal=*/false);
}

std::string EnsureUniqueWalletName(const JSONRPCRequest& request, const std::string* wallet_name)
{
    std::string endpoint_wallet;
    if (GetWalletNameFromJSONRPCRequest(request, endpoint_wallet)) {
        // wallet endpoint was used
        if (wallet_name && *wallet_name != endpoint_wallet) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "The RPC endpoint wallet and the wallet name parameter specify different wallets");
        }
        return endpoint_wallet;
    }

    // Not a wallet endpoint; parameter must be provided
    if (!wallet_name) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Either the RPC endpoint wallet or the wallet name parameter must be provided");
    }

    return *wallet_name;
}

bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request, std::string& wallet_name)
{
    if (request.URI.starts_with(WALLET_ENDPOINT_BASE)) {
        // wallet endpoint was used
        wallet_name = UrlDecode(std::string_view{request.URI}.substr(WALLET_ENDPOINT_BASE.size()));
        return true;
    }
    return false;
}

std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    CHECK_NONFATAL(request.mode == JSONRPCRequest::EXECUTE);
    WalletContext& context = EnsureWalletContext(request.context);

    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        std::shared_ptr<CWallet> pwallet = GetWallet(context, wallet_name);
        if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
        return pwallet;
    }

    size_t count{0};
    auto wallet = GetDefaultWallet(context, count);
    if (wallet) return wallet;

    if (count == 0) {
        throw JSONRPCError(
            RPC_WALLET_NOT_FOUND, "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. (Note: A default wallet is no longer automatically created)");
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Multiple wallets are loaded. Please select which wallet to use by requesting the RPC through the /wallet/<walletname> URI path.");
}

void EnsureWalletIsUnlocked(const CWallet& wallet)
{
    if (wallet.IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

WalletContext& EnsureWalletContext(const std::any& context)
{
    auto wallet_context = util::AnyPtr<WalletContext>(context);
    if (!wallet_context) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet context not found");
    }
    return *wallet_context;
}

std::string LabelFromValue(const UniValue& value)
{
    static const std::string empty_string;
    if (value.isNull()) return empty_string;

    const std::string& label{value.get_str()};
    if (label == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, "Invalid label name");
    return label;
}

bool IsP2MRBIP32PublicDerivationDescriptor(const Descriptor& descriptor)
{
    const auto output_type = descriptor.GetOutputType();
    if (!output_type || *output_type != OutputType::P2MR) return false;

    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> ext_pubs;
    descriptor.GetPubKeys(pubkeys, ext_pubs);
    return !ext_pubs.empty();
}

bool ShouldSuppressP2MRBIP32Descriptor(const Descriptor& descriptor, bool private_export)
{
    return !private_export && IsP2MROnlyWalletChain() && IsP2MRBIP32PublicDerivationDescriptor(descriptor);
}

void PushParentDescriptors(const CWallet& wallet, const CScript& script_pubkey, UniValue& entry)
{
    UniValue parent_descs(UniValue::VARR);
    for (const auto& desc: wallet.GetWalletDescriptors(script_pubkey)) {
        if (ShouldSuppressP2MRBIP32Descriptor(*desc.descriptor, /*private_export=*/false)) continue;

        std::string desc_str;
        FlatSigningProvider dummy_provider;
        if (!CHECK_NONFATAL(desc.descriptor->ToNormalizedString(dummy_provider, desc_str, &desc.cache))) continue;
        parent_descs.push_back(desc_str);
    }
    entry.pushKV("parent_descs", std::move(parent_descs));
}

std::vector<RPCResult> PQCUsageRPCResults(bool include_warnings)
{
    std::vector<RPCResult> results{
        {RPCResult::Type::ARR, "pqc_key_states", /*optional=*/true, "PQC usage state for local wallet keys that participated in this response.",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pubkey", "The hex-encoded PQC public key."},
                {RPCResult::Type::NUM, "pqc_signature_count", "The number of signatures used by this PQC key."},
                {RPCResult::Type::NUM, "pqc_signature_limit", "The hard signature limit for this PQC key."},
                {RPCResult::Type::NUM, "pqc_signatures_remaining", "The remaining signature budget for this PQC key."},
                {RPCResult::Type::STR, "pqc_limit_state", "The PQC usage state. One of `normal`, `warning`, `critical`, or `exhausted`."},
            }},
        }},
        {RPCResult::Type::STR, "pqc_overall_limit_state", /*optional=*/true, "The maximum PQC usage severity across `pqc_key_states`."},
        {RPCResult::Type::NUM, "pqc_signature_count", /*optional=*/true, "The number of signatures used by the single local PQC key associated with this response."},
        {RPCResult::Type::NUM, "pqc_signature_limit", /*optional=*/true, "The hard signature limit for the single local PQC key associated with this response."},
        {RPCResult::Type::NUM, "pqc_signatures_remaining", /*optional=*/true, "The remaining signature budget for the single local PQC key associated with this response."},
        {RPCResult::Type::STR, "pqc_limit_state", /*optional=*/true, "The PQC usage state for the single local PQC key associated with this response."},
    };
    if (include_warnings) {
        results.push_back({
            RPCResult::Type::ARR,
            "warnings",
            /*optional=*/true,
            "Human-readable warning lines emitted when PQC threshold transitions or reminder buckets fire.",
            {
                {RPCResult::Type::STR, "warning", ""},
            },
        });
    }
    return results;
}

void AppendPQCUsage(UniValue& entry, const PQCUsageReport& report, bool include_warnings)
{
    if (report.key_states.empty()) {
        return;
    }

    UniValue key_states(UniValue::VARR);
    for (const PQCUsageSnapshot& key_state : report.key_states) {
        UniValue state(UniValue::VOBJ);
        state.pushKV("pubkey", HexStr(std::span<const unsigned char>{key_state.pubkey.begin(), key_state.pubkey.end()}));
        state.pushKV("pqc_signature_count", static_cast<int64_t>(key_state.signature_count));
        state.pushKV("pqc_signature_limit", static_cast<int64_t>(key_state.signature_limit));
        state.pushKV("pqc_signatures_remaining", static_cast<int64_t>(key_state.signatures_remaining));
        state.pushKV("pqc_limit_state", std::string{PQCSignatureLimitStateName(key_state.limit_state)});
        key_states.push_back(std::move(state));
    }
    entry.pushKV("pqc_key_states", std::move(key_states));

    CHECK_NONFATAL(report.overall_state.has_value());
    entry.pushKV("pqc_overall_limit_state", std::string{PQCSignatureLimitStateName(*report.overall_state)});

    if (report.key_states.size() == 1) {
        const PQCUsageSnapshot& key_state = report.key_states.front();
        entry.pushKV("pqc_signature_count", static_cast<int64_t>(key_state.signature_count));
        entry.pushKV("pqc_signature_limit", static_cast<int64_t>(key_state.signature_limit));
        entry.pushKV("pqc_signatures_remaining", static_cast<int64_t>(key_state.signatures_remaining));
        entry.pushKV("pqc_limit_state", std::string{PQCSignatureLimitStateName(key_state.limit_state)});
    }

    if (include_warnings) {
        PushWarnings(FormatPQCUsageWarnings(report.warnings), entry);
    }
}

void LogPQCUsageWarnings(const CWallet& wallet, const PQCUsageReport& report)
{
    for (const bilingual_str& warning : FormatPQCUsageWarnings(report.warnings)) {
        wallet.WalletLogPrintf("PQC usage warning: %s\n", warning.original);
    }
}

void HandleWalletError(const std::shared_ptr<CWallet> wallet, DatabaseStatus& status, bilingual_str& error)
{
    if (!wallet) {
        // Map bad format to not found, since bad format is returned when the
        // wallet directory exists, but doesn't contain a data file.
        RPCErrorCode code = RPC_WALLET_ERROR;
        switch (status) {
            case DatabaseStatus::FAILED_NOT_FOUND:
            case DatabaseStatus::FAILED_BAD_FORMAT:
            case DatabaseStatus::FAILED_LEGACY_DISABLED:
                code = RPC_WALLET_NOT_FOUND;
                break;
            case DatabaseStatus::FAILED_ALREADY_LOADED:
                code = RPC_WALLET_ALREADY_LOADED;
                break;
            case DatabaseStatus::FAILED_ALREADY_EXISTS:
                code = RPC_WALLET_ALREADY_EXISTS;
                break;
            case DatabaseStatus::FAILED_INVALID_BACKUP_FILE:
                code = RPC_INVALID_PARAMETER;
                break;
            default: // RPC_WALLET_ERROR is returned for all other cases.
                break;
        }
        throw JSONRPCError(code, error.original);
    }
}

void AppendLastProcessedBlock(UniValue& entry, const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    UniValue lastprocessedblock{UniValue::VOBJ};
    lastprocessedblock.pushKV("hash", wallet.GetLastBlockHash().GetHex());
    lastprocessedblock.pushKV("height", wallet.GetLastBlockHeight());
    entry.pushKV("lastprocessedblock", std::move(lastprocessedblock));
}

} // namespace wallet
