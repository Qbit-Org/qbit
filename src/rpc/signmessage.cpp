// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/signmessage.h>
#include <crypto/pqc.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/p2mr.h>
#include <util/strencodings.h>
#include <univalue.h>

#include <string>

static RPCHelpMan verifymessage()
{
    return RPCHelpMan{"verifymessage",
        "Verify a signed message.",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The qbit address to use for the signature."},
            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature provided by the signer in base 64 encoding (see signmessage)."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "If the signature is verified or not."
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifymessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\", \"signature\", \"my message\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (IsP2MROnlyOutputChain()) {
                throw JSONRPCError(RPC_METHOD_DEPRECATED, "Legacy message verification is disabled on this chain");
            }

            std::string strAddress = self.Arg<std::string>("address");
            std::string strSign = self.Arg<std::string>("signature");
            std::string strMessage = self.Arg<std::string>("message");

            switch (MessageVerify(strAddress, strSign, strMessage)) {
            case MessageVerificationResult::ERR_INVALID_ADDRESS:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
            case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
                throw JSONRPCError(RPC_TYPE_ERROR, "Malformed base64 encoding");
            case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
            case MessageVerificationResult::ERR_NOT_SIGNED:
                return false;
            case MessageVerificationResult::OK:
                return true;
            }

            return false;
        },
    };
}

static RPCHelpMan signmessagewithprivkey()
{
    return RPCHelpMan{
        "signmessagewithprivkey",
        "Sign a message with the private key of an address\n",
        {
            {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key to sign the message with."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
        },
        RPCExamples{
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"QbURpsSa6XFTg61KScF1yntyVDVb1742e2\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (IsP2MROnlyOutputChain()) {
                throw JSONRPCError(RPC_METHOD_DEPRECATED, "Legacy message signing is disabled on this chain");
            }

            std::string strPrivkey = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            CKey key = DecodeSecret(strPrivkey);
            if (!key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            }

            std::string signature;

            if (!MessageSign(key, strMessage, signature)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
            }

            return signature;
        },
    };
}

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

std::vector<unsigned char> ParseSizedHex(const UniValue& value, std::string_view name, size_t expected_size)
{
    std::vector<unsigned char> bytes{ParseHexV(value, name)};
    if (bytes.size() != expected_size) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be exactly %u bytes", name, expected_size));
    }
    return bytes;
}

UniValue InvalidDataPQCProof(std::string error)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("valid", false);
    result.pushKV("error", std::move(error));
    return result;
}

} // namespace

static RPCHelpMan verifydatapqchash()
{
    return RPCHelpMan{
        "verifydatapqchash",
        "Verify a P2MR/PQC data-hash signature proof.",
        {
            {"p2mr_proof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The proof returned by signdatapqchash.",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The P2MR address."},
                    {"message_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte hash that was signed."},
                    {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw PQC signature."},
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte P2MR pubkey."},
                    {"leaf_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The committed P2MR pubkey leaf script."},
                    {"control_block", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The P2MR control block proving the leaf."},
                    {"leaf_version", RPCArg::Type::NUM, RPCArg::Optional::NO, "The P2MR leaf version."},
                    {"proof_mode", RPCArg::Type::STR, RPCArg::Optional::NO, "Must be \"p2mr-pubkey\"."},
                },
                RPCArgOptions{.skip_type_check = true}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether the proof verifies."},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Failure reason when valid is false."},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The P2MR address."},
                {RPCResult::Type::STR_HEX, "message_hash", /*optional=*/true, "The caller-supplied 32-byte hash."},
                {RPCResult::Type::STR_HEX, "datasig_hash", /*optional=*/true, "The qbit data-signature hash that was verified."},
                {RPCResult::Type::STR_HEX, "pubkey", /*optional=*/true, "The committed 32-byte P2MR pubkey."},
                {RPCResult::Type::STR, "proof_mode", /*optional=*/true, "The proof mode."},
                {RPCResult::Type::STR_HEX, "p2mr_merkle_root", /*optional=*/true, "The P2MR Merkle root committed by the address."},
            }
        },
        RPCExamples{
            HelpExampleCli("verifydatapqchash", "'{\"address\":\"qb1...\",\"message_hash\":\"00...\",\"signature\":\"...\",\"pubkey\":\"...\",\"leaf_script\":\"...\",\"control_block\":\"c1\",\"leaf_version\":192,\"proof_mode\":\"p2mr-pubkey\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const UniValue& proof{request.params[0]};
            RPCTypeCheckObj(proof,
                {
                    {"address", UniValueType(UniValue::VSTR)},
                    {"message_hash", UniValueType(UniValue::VSTR)},
                    {"signature", UniValueType(UniValue::VSTR)},
                    {"pubkey", UniValueType(UniValue::VSTR)},
                    {"leaf_script", UniValueType(UniValue::VSTR)},
                    {"control_block", UniValueType(UniValue::VSTR)},
                    {"leaf_version", UniValueType(UniValue::VNUM)},
                    {"proof_mode", UniValueType(UniValue::VSTR)},
                }, /*fAllowNull=*/false, /*fStrict=*/false);

            const std::string proof_mode{proof.find_value("proof_mode").get_str()};
            if (proof_mode != "p2mr-pubkey") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only proof_mode \"p2mr-pubkey\" is currently supported");
            }

            const std::string address{proof.find_value("address").get_str()};
            const CTxDestination dest{DecodeDestination(address)};
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            const auto* output{std::get_if<WitnessV2P2MR>(&dest)};
            if (!output) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address is not a P2MR address");
            }

            const uint256 message_hash{ParseDataHash(proof.find_value("message_hash"), "message_hash")};
            const std::vector<unsigned char> signature{ParseSizedHex(proof.find_value("signature"), "signature", PQC_SIG_SIZE)};
            const std::vector<unsigned char> pubkey_bytes{ParseSizedHex(proof.find_value("pubkey"), "pubkey", PQC_PUBKEY_SIZE)};
            const CPQCPubKey pubkey{pubkey_bytes};
            if (!pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pubkey is invalid");
            }

            const std::vector<unsigned char> leaf_script_bytes{ParseHexV(proof.find_value("leaf_script"), "leaf_script")};
            const CScript leaf_script{leaf_script_bytes.begin(), leaf_script_bytes.end()};
            const std::optional<CPQCPubKey> leaf_pubkey{p2mr::MatchPK(leaf_script)};
            if (!leaf_pubkey || *leaf_pubkey != pubkey) {
                return InvalidDataPQCProof("leaf_script is not a single-key P2MR pubkey leaf for pubkey");
            }

            const int leaf_version_int{proof.find_value("leaf_version").getInt<int>()};
            if (leaf_version_int < 0 || leaf_version_int > 0xff) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "leaf_version out of range");
            }
            if (leaf_version_int != P2MR_LEAF_VERSION_V1) {
                return InvalidDataPQCProof("unsupported P2MR leaf version");
            }
            const uint8_t leaf_version{static_cast<uint8_t>(leaf_version_int)};

            const std::vector<unsigned char> control_block{ParseHexV(proof.find_value("control_block"), "control_block")};
            if (control_block.size() < P2MR_CONTROL_BASE_SIZE || control_block.size() > P2MR_CONTROL_MAX_SIZE ||
                ((control_block.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid P2MR control block size");
            }
            if ((control_block.front() & 1) == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2MR control byte bit 0 must be set");
            }
            if ((control_block.front() & TAPROOT_LEAF_MASK) != leaf_version) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "leaf_version does not match control_block");
            }

            const uint256 leaf_hash{ComputeP2MRLeafHash(leaf_version, leaf_script_bytes)};
            const uint256 merkle_root{ComputeP2MRMerkleRoot(control_block, leaf_hash)};
            if (merkle_root != output->GetMerkleRoot()) {
                return InvalidDataPQCProof("leaf_script/control_block do not match address");
            }

            const uint256 datasig_hash{ComputeQbitDataSigPQCHash(std::span<const unsigned char>{message_hash.begin(), message_hash.end()})};
            if (!pubkey.Verify(datasig_hash, signature)) {
                return InvalidDataPQCProof("signature does not verify");
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("valid", true);
            result.pushKV("address", address);
            result.pushKV("message_hash", HashToHex(message_hash));
            result.pushKV("datasig_hash", HashToHex(datasig_hash));
            result.pushKV("pubkey", HexStr(pubkey_bytes));
            result.pushKV("proof_mode", proof_mode);
            result.pushKV("p2mr_merkle_root", HashToHex(merkle_root));
            return result;
        },
    };
}

void RegisterSignMessageRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"util", &verifymessage},
        {"util", &verifydatapqchash},
        {"util", &signmessagewithprivkey},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
