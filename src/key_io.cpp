// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <outputtype.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstring>

/// Maximum witness length for Bech32 addresses.
static constexpr std::size_t BECH32_WITNESS_PROG_MAX_LEN = 40;

namespace {

/** Try to decode a base58check-encoded P2PKH or P2SH address from already-decoded data.
 *  Returns true and sets dest on success, or returns false and sets error_str on failure. */
bool TryDecodeBase58Destination(const std::vector<unsigned char>& data, const CChainParams& params,
                                CTxDestination& dest, std::string& error_str)
{
    uint160 hash;
    const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
    if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
        std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
        dest = PKHash(hash);
        return true;
    }
    const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
    if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
        std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
        dest = ScriptHash(hash);
        return true;
    }

    // Prefix matched but length was wrong
    if ((data.size() >= script_prefix.size() &&
            std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) ||
        (data.size() >= pubkey_prefix.size() &&
            std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin()))) {
        error_str = "Invalid length for Base58 address (P2PKH or P2SH)";
    } else {
        error_str = "Invalid or unsupported Base58-encoded address.";
    }
    return false;
}

void AddPrefixIfUnique(std::vector<std::vector<unsigned char>>& prefixes, std::vector<unsigned char> prefix)
{
    if (std::ranges::none_of(prefixes, [&](const auto& existing) { return existing == prefix; })) {
        prefixes.push_back(std::move(prefix));
    }
}

std::vector<std::vector<unsigned char>> KeyDecodePrefixes(const CChainParams::Base58Type type, const CChainParams& params)
{
    std::vector<std::vector<unsigned char>> prefixes{params.Base58Prefix(type)};

    switch (type) {
    case CChainParams::SECRET_KEY:
        AddPrefixIfUnique(prefixes, params.GetChainType() == ChainType::MAIN ?
            std::vector<unsigned char>{128} :
            std::vector<unsigned char>{239});
        break;
    case CChainParams::EXT_PUBLIC_KEY:
        AddPrefixIfUnique(prefixes, params.GetChainType() == ChainType::MAIN ?
            std::vector<unsigned char>{0x04, 0x88, 0xB2, 0x1E} :
            std::vector<unsigned char>{0x04, 0x35, 0x87, 0xCF});
        break;
    case CChainParams::EXT_SECRET_KEY:
        AddPrefixIfUnique(prefixes, params.GetChainType() == ChainType::MAIN ?
            std::vector<unsigned char>{0x04, 0x88, 0xAD, 0xE4} :
            std::vector<unsigned char>{0x04, 0x35, 0x83, 0x94});
        break;
    default:
        break;
    }

    return prefixes;
}

class DestinationEncoder
{
private:
    const CChainParams& m_params;

public:
    explicit DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const PKHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const ScriptHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const WitnessV0KeyHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(33);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV0ScriptHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV1Taproot& tap) const
    {
        std::vector<unsigned char> data = {1};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, tap.begin(), tap.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV2P2MR& p2mr) const
    {
        std::vector<unsigned char> data = {2};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, p2mr.begin(), p2mr.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessUnknown& id) const
    {
        const std::vector<unsigned char>& program = id.GetWitnessProgram();
        if (id.GetWitnessVersion() < 1 || id.GetWitnessVersion() > 16 || program.size() < 2 || program.size() > 40) {
            return {};
        }
        std::vector<unsigned char> data = {(unsigned char)id.GetWitnessVersion()};
        data.reserve(1 + (program.size() * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, program.begin(), program.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
    std::string operator()(const PubKeyDestination& pk) const { return {}; }
};

CTxDestination RejectUnsupportedDestinationType(CTxDestination dest, const CChainParams& params, std::string& error_str)
{
    if (!IsP2MROnlyOutputChain(params) || IsDestinationOutputTypeAllowed(dest, params)) {
        return dest;
    }
    error_str = strprintf("Address type is not supported on this chain; use a %s address.", FormatOutputType(OutputType::P2MR));
    return CNoDestination();
}

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations)
{
    std::vector<unsigned char> data;
    error_str = "";

    // Note this will be false if it is a valid Bech32 address for a different network.
    // Check for HRP followed by '1' separator to avoid collisions with base58 addresses
    // whose leading characters happen to match the bech32 HRP (e.g. qbit mainnet P2PKH
    // addresses starting with "Qb" vs bech32 HRP "qb").
    const auto& hrp = params.Bech32HRP();
    bool is_bech32 = (str.size() > hrp.size() && str[hrp.size()] == '1' &&
                      ToLower(str.substr(0, hrp.size())) == hrp);

    if (!is_bech32 && DecodeBase58Check(str, data, 21)) {
        CTxDestination dest;
        if (TryDecodeBase58Destination(data, params, dest, error_str)) {
            return RejectUnsupportedDestinationType(dest, params, error_str);
        }
        return CNoDestination();
    } else if (!is_bech32) {
        // Try Base58 decoding without the checksum, using a much larger max length
        if (!DecodeBase58(str, data, 100)) {
            error_str = "Invalid or unsupported Segwit (Bech32) or Base58 encoding.";
        } else {
            error_str = "Invalid checksum or length of Base58 address (P2PKH or P2SH)";
        }
        return CNoDestination();
    }

    data.clear();
    const auto dec = bech32::Decode(str);
    if (dec.encoding == bech32::Encoding::BECH32 || dec.encoding == bech32::Encoding::BECH32M) {
        if (dec.data.empty()) {
            error_str = "Empty Bech32 data section";
            return CNoDestination();
        }
        // Bech32 decoding
        if (dec.hrp != params.Bech32HRP()) {
            error_str = strprintf("Invalid or unsupported prefix for Segwit (Bech32) address (expected %s, got %s).", params.Bech32HRP(), dec.hrp);
            return CNoDestination();
        }
        int version = dec.data[0]; // The first 5 bit symbol is the witness version (0-16)
        if (version == 0 && dec.encoding != bech32::Encoding::BECH32) {
            error_str = "Version 0 witness address must use Bech32 checksum";
            return CNoDestination();
        }
        if (version != 0 && dec.encoding != bech32::Encoding::BECH32M) {
            error_str = "Version 1+ witness address must use Bech32m checksum";
            return CNoDestination();
        }
        // The rest of the symbols are converted witness program bytes.
        data.reserve(((dec.data.size() - 1) * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {

            std::string_view byte_str{data.size() == 1 ? "byte" : "bytes"};

            if (version == 0) {
                {
                    WitnessV0KeyHash keyid;
                    if (data.size() == keyid.size()) {
                        std::copy(data.begin(), data.end(), keyid.begin());
                        return RejectUnsupportedDestinationType(keyid, params, error_str);
                    }
                }
                {
                    WitnessV0ScriptHash scriptid;
                    if (data.size() == scriptid.size()) {
                        std::copy(data.begin(), data.end(), scriptid.begin());
                        return RejectUnsupportedDestinationType(scriptid, params, error_str);
                    }
                }

                error_str = strprintf("Invalid Bech32 v0 address program size (%d %s), per BIP141", data.size(), byte_str);
                return CNoDestination();
            }

            if (version == 1 && data.size() == WITNESS_V1_TAPROOT_SIZE) {
                static_assert(WITNESS_V1_TAPROOT_SIZE == WitnessV1Taproot::size());
                WitnessV1Taproot tap;
                std::copy(data.begin(), data.end(), tap.begin());
                return RejectUnsupportedDestinationType(tap, params, error_str);
            }

            if (version == 2 && data.size() == WITNESS_V2_P2MR_SIZE) {
                static_assert(WITNESS_V2_P2MR_SIZE == sizeof(uint256));
                WitnessV2P2MR p2mr;
                std::copy(data.begin(), data.end(), p2mr.begin());
                return RejectUnsupportedDestinationType(p2mr, params, error_str);
            }

            if (CScript::IsPayToAnchor(version, data)) {
                return RejectUnsupportedDestinationType(PayToAnchor(), params, error_str);
            }

            if (version > 16) {
                error_str = "Invalid Bech32 address witness version";
                return CNoDestination();
            }

            if (data.size() < 2 || data.size() > BECH32_WITNESS_PROG_MAX_LEN) {
                error_str = strprintf("Invalid Bech32 address program size (%d %s)", data.size(), byte_str);
                return CNoDestination();
            }

            return RejectUnsupportedDestinationType(WitnessUnknown{version, data}, params, error_str);
        } else {
            error_str = strprintf("Invalid padding in Bech32 data section");
            return CNoDestination();
        }
    }

    // If a string looked bech32-like by heuristic but failed bech32 decoding,
    // fall back to base58check decoding to avoid false negatives.
    if (is_bech32 && DecodeBase58Check(str, data, 21)) {
        CTxDestination dest;
        std::string base58_error;
        if (TryDecodeBase58Destination(data, params, dest, base58_error)) {
            return RejectUnsupportedDestinationType(dest, params, error_str);
        }
        // If base58 recognised a prefix but rejected on length, prefer
        // that error over the generic bech32 error location below.
        if (!base58_error.empty()) {
            error_str = base58_error;
            return CNoDestination();
        }
    }

    // Perform Bech32 error location
    auto res = bech32::LocateErrors(str);
    error_str = res.first;
    if (error_locations) *error_locations = std::move(res.second);
    return CNoDestination();
}
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 34)) {
        for (const auto& privkey_prefix : KeyDecodePrefixes(CChainParams::SECRET_KEY, Params())) {
            if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
                std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
                bool compressed = data.size() == 33 + privkey_prefix.size();
                key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
                break;
            }
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), UCharCast(key.begin()), UCharCast(key.end()));
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        for (const auto& prefix : KeyDecodePrefixes(CChainParams::EXT_PUBLIC_KEY, Params())) {
            if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
                key.Decode(data.data() + prefix.size());
                break;
            }
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str)
{
    CExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        for (const auto& prefix : KeyDecodePrefixes(CChainParams::EXT_SECRET_KEY, Params())) {
            if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
                key.Decode(data.data() + prefix.size());
                break;
            }
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest)
{
    return std::visit(DestinationEncoder(Params()), dest);
}

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations)
{
    return DecodeDestination(str, Params(), error_msg, error_locations);
}

CTxDestination DecodeDestination(const std::string& str)
{
    std::string error_msg;
    return DecodeDestination(str, error_msg);
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    return IsValidDestination(DecodeDestination(str, params, error_msg, nullptr));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}
