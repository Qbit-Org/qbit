// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/signmessage.h>
#include <key_io.h>
#include <outputtype.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/pqc_usage.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

namespace wallet {
namespace {

std::string HashToHex(const uint256& hash)
{
    return HexStr(std::span<const unsigned char>{hash.begin(), hash.end()});
}

uint256 ParseDataHash(const UniValue& value, std::string_view name)
{
    const std::vector<unsigned char> bytes{ParseHexV(value, name)};
    if (bytes.size() != uint256::size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be exactly 32 bytes", name));
    }
    return uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
}

std::optional<CPQCPubKey> ParseOptionalP2MRPubKey(const UniValue& options)
{
    const UniValue& value{options.find_value("pubkey")};
    if (value.isNull()) return std::nullopt;
    const std::vector<unsigned char> bytes{ParseHexV(value, "pubkey")};
    CPQCPubKey pubkey{bytes};
    if (!pubkey.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "pubkey must be exactly 32 bytes");
    }
    return pubkey;
}

std::optional<CScript> ParseOptionalScript(const UniValue& options)
{
    const UniValue& value{options.find_value("leaf_script")};
    if (value.isNull()) return std::nullopt;
    const std::vector<unsigned char> bytes{ParseHexV(value, "leaf_script")};
    return CScript{bytes.begin(), bytes.end()};
}

std::optional<std::vector<unsigned char>> ParseOptionalControlBlock(const UniValue& options)
{
    const UniValue& value{options.find_value("control_block")};
    if (value.isNull()) return std::nullopt;
    return ParseHexV(value, "control_block");
}

void EnsurePQCKeyValidationReadyForSigning(const CWallet& wallet)
{
    const PQCKeyValidationInfo info{wallet.GetPQCKeyValidationInfo()};
    if (info.pending_records > 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: plaintext PQC wallet key validation is still in progress. Check getwalletinfo.pqc_key_validation before signing.");
    }
    if (info.failed_records > 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: plaintext PQC wallet key validation failed. Wallet signing is disabled until the wallet is restored or repaired.");
    }
}

void LogConsumedPQCDataHashCounters(const CWallet& wallet, const PQCUsageRecorder& recorder, const bilingual_str& error)
{
    for (const PQCUsageAdvance& advance : recorder.GetAdvances()) {
        wallet.WalletLogPrintf(
            "PQC data-hash signing consumed counter for pubkey %s [%u, %u) before failing: %s\n",
            HexStr(std::span<const unsigned char>{advance.pubkey.begin(), advance.pubkey.end()}),
            advance.previous_count,
            advance.new_count,
            error.original);
    }
}

} // namespace

RPCHelpMan signmessage()
{
    return RPCHelpMan{
        "signmessage",
        "Sign a message with the private key of an address" +
          HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The qbit address to use for the private key."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\", \"my message\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (IsP2MROnlyOutputChain()) {
                throw JSONRPCError(RPC_METHOD_DEPRECATED, "Legacy message signing is disabled on this chain");
            }

            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            EnsureWalletIsUnlocked(*pwallet);
            EnsurePQCKeyValidationReadyForSigning(*pwallet);

            std::string strAddress = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            CTxDestination dest = DecodeDestination(strAddress);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            const PKHash* pkhash = std::get_if<PKHash>(&dest);
            if (!pkhash) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
            }

            std::string signature;
            SigningResult err = pwallet->SignMessage(strMessage, *pkhash, signature);
            if (err == SigningResult::SIGNING_FAILED) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(err));
            } else if (err != SigningResult::OK) {
                throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
            }

            return signature;
        },
    };
}

RPCHelpMan signdatapqchash()
{
    return RPCHelpMan{
        "signdatapqchash",
        "Sign a 32-byte data hash with a PQC key committed by a wallet-owned P2MR address." +
          HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet-owned P2MR address whose committed pubkey should sign."},
            {"message_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte hash to sign, as hex."},
            {"options", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Options.",
                {
                    {"proof_mode", RPCArg::Type::STR, RPCArg::Default{"p2mr-pubkey"}, "Only \"p2mr-pubkey\" is supported."},
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional 32-byte P2MR pubkey to select when the address commits to more than one single-key leaf."},
                    {"leaf_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional exact P2MR leaf script to sign against."},
                    {"control_block", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional exact P2MR control block to prove with."},
                    {"include_pqc_usage", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include PQC key-usage counters and warnings in the result."},
                },
                RPCArgOptions{.oneline_description="options"}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            Cat(std::vector<RPCResult>{
                {RPCResult::Type::STR, "address", "The P2MR address used for the proof."},
                {RPCResult::Type::STR_HEX, "message_hash", "The caller-supplied 32-byte hash."},
                {RPCResult::Type::STR_HEX, "datasig_hash", "The qbit data-signature hash actually signed."},
                {RPCResult::Type::STR, "domain", "The data-signature domain."},
                {RPCResult::Type::STR, "algorithm", "The PQC signature algorithm."},
                {RPCResult::Type::STR, "proof_mode", "The proof mode."},
                {RPCResult::Type::STR_HEX, "pubkey", "The committed 32-byte P2MR pubkey."},
                {RPCResult::Type::STR_HEX, "signature", "The raw PQC signature."},
                {RPCResult::Type::NUM, "leaf_version", "The P2MR leaf version."},
                {RPCResult::Type::STR_HEX, "leaf_script", "The committed P2MR leaf script."},
                {RPCResult::Type::STR_HEX, "control_block", "The P2MR control block proving the leaf."},
                {RPCResult::Type::STR_HEX, "p2mr_merkle_root", "The P2MR Merkle root committed by the address."},
            }, PQCUsageRPCResults(/*include_warnings=*/true))
        },
        RPCExamples{
            HelpExampleCli("signdatapqchash", "\"qb1...\" \"0001020304050607080900010203040506070809000102030405060708090001\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);
            EnsurePQCKeyValidationReadyForSigning(*pwallet);

            const std::string address{self.Arg<std::string>("address")};
            const uint256 message_hash{ParseDataHash(request.params[1], "message_hash")};

            const UniValue& options_param{request.params[2]};
            const UniValue options{options_param.isNull() ? UniValue{UniValue::VOBJ} : options_param};
            RPCTypeCheckObj(options,
                {
                    {"proof_mode", UniValueType(UniValue::VSTR)},
                    {"pubkey", UniValueType(UniValue::VSTR)},
                    {"leaf_script", UniValueType(UniValue::VSTR)},
                    {"control_block", UniValueType(UniValue::VSTR)},
                    {"include_pqc_usage", UniValueType(UniValue::VBOOL)},
                }, true);

            const std::string proof_mode{options.exists("proof_mode") ? options.find_value("proof_mode").get_str() : "p2mr-pubkey"};
            if (proof_mode != "p2mr-pubkey") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only proof_mode \"p2mr-pubkey\" is currently supported");
            }

            const CTxDestination dest{DecodeDestination(address)};
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            const auto* output{std::get_if<WitnessV2P2MR>(&dest)};
            if (!output) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not a P2MR address");
            }

            const std::optional<CPQCPubKey> requested_pubkey{ParseOptionalP2MRPubKey(options)};
            const std::optional<CScript> requested_leaf_script{ParseOptionalScript(options)};
            const std::optional<std::vector<unsigned char>> requested_control_block{ParseOptionalControlBlock(options)};
            const bool include_pqc_usage{!options.exists("include_pqc_usage") || options.find_value("include_pqc_usage").get_bool()};

            PQCUsageRecorder pqc_usage_recorder;
            util::Result<DataPQCSignatureProof> proof{pwallet->SignDataPQCHash(
                *output, message_hash, requested_pubkey, requested_leaf_script, requested_control_block, pqc_usage_recorder.GetObserver())};
            const PQCUsageReport pqc_usage{BuildSigningPQCUsageReport(pqc_usage_recorder)};
            LogPQCUsageWarnings(*pwallet, pqc_usage);
            if (!proof) {
                const bilingual_str error{util::ErrorString(proof)};
                LogConsumedPQCDataHashCounters(*pwallet, pqc_usage_recorder, error);
                throw JSONRPCError(RPC_WALLET_ERROR, error.original);
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("address", address);
            result.pushKV("message_hash", HashToHex(proof->message_hash));
            result.pushKV("datasig_hash", HashToHex(proof->datasig_hash));
            result.pushKV("domain", "QbitDataSigPQC");
            result.pushKV("algorithm", "SLH-DSA-SHA2-128s-bounded30");
            result.pushKV("proof_mode", proof_mode);
            result.pushKV("pubkey", HexStr(std::span<const unsigned char>{proof->pubkey.begin(), proof->pubkey.end()}));
            result.pushKV("signature", HexStr(proof->signature));
            result.pushKV("leaf_version", static_cast<int>(proof->leaf_version));
            result.pushKV("leaf_script", HexStr(proof->leaf_script));
            result.pushKV("control_block", HexStr(proof->control_block));
            result.pushKV("p2mr_merkle_root", HashToHex(proof->output.GetMerkleRoot()));
            if (include_pqc_usage) {
                AppendPQCUsage(result, pqc_usage, /*include_warnings=*/true);
            }
            return result;
        },
    };
}
} // namespace wallet
