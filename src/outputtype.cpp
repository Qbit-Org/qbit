// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <outputtype.h>

#include <chainparams.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>

#include <cassert>
#include <algorithm>
#include <cstddef>
#include <limits>
#include <optional>
#include <string>

static const std::string OUTPUT_TYPE_STRING_LEGACY = "legacy";
static const std::string OUTPUT_TYPE_STRING_P2SH_SEGWIT = "p2sh-segwit";
static const std::string OUTPUT_TYPE_STRING_BECH32 = "bech32";
static const std::string OUTPUT_TYPE_STRING_BECH32M = "bech32m";
static const std::string OUTPUT_TYPE_STRING_P2MR = "p2mr";
static const std::string OUTPUT_TYPE_STRING_UNKNOWN = "unknown";

static constexpr auto P2MR_ONLY_OUTPUT_TYPES = std::array{OutputType::P2MR};
static constexpr std::size_t WITNESS_PROGRAM_MIN_SIZE{2};
static constexpr std::size_t WITNESS_PROGRAM_MAX_SIZE{40};

namespace {
bool IsOuterReservedWitnessDestinationAllowed(const CTxDestination& dest, const CChainParams& params, std::optional<int> height)
{
    const auto* witness_unknown = std::get_if<WitnessUnknown>(&dest);
    if (witness_unknown == nullptr) return false;

    const auto& witness_program = witness_unknown->GetWitnessProgram();
    const auto& consensus = params.GetConsensus();
    const bool outer_reserved_allowed = height.has_value() ?
        consensus.OuterReservedWitnessActiveAtHeight(*height) :
        consensus.nOuterReservedWitnessHeight != std::numeric_limits<int>::max();
    return outer_reserved_allowed &&
           IsReservedFutureWitnessVersion(witness_unknown->GetWitnessVersion()) &&
           witness_program.size() >= WITNESS_PROGRAM_MIN_SIZE &&
           witness_program.size() <= WITNESS_PROGRAM_MAX_SIZE;
}

bool IsDestinationOutputTypeAllowedInternal(const CTxDestination& dest, const CChainParams& params, std::optional<int> height)
{
    if (!IsP2MROnlyOutputChain(params)) return true;
    if (std::holds_alternative<PayToAnchor>(dest)) return true;
    if (IsOuterReservedWitnessDestinationAllowed(dest, params, height)) return true;
    const auto output_type = OutputTypeFromDestination(dest);
    return output_type.has_value() && IsOutputTypeAllowed(*output_type, params);
}
} // namespace

std::span<const OutputType> GetSupportedOutputTypes()
{
    return SUPPORTED_OUTPUT_TYPES;
}

bool IsP2MROnlyOutputChain(const CChainParams& params)
{
    return params.GetConsensus().fRestrictedOutputMode;
}

bool IsP2MROnlyOutputChain()
{
    return IsP2MROnlyOutputChain(Params());
}

std::span<const OutputType> GetAllowedOutputTypes(const CChainParams& params)
{
    return IsP2MROnlyOutputChain(params) ? std::span{P2MR_ONLY_OUTPUT_TYPES} : GetSupportedOutputTypes();
}

std::span<const OutputType> GetAllowedOutputTypes()
{
    return GetAllowedOutputTypes(Params());
}

bool IsOutputTypeAllowed(OutputType type, const CChainParams& params)
{
    const auto output_types = GetAllowedOutputTypes(params);
    return std::find(output_types.begin(), output_types.end(), type) != output_types.end();
}

bool IsOutputTypeAllowed(OutputType type)
{
    return IsOutputTypeAllowed(type, Params());
}

std::optional<OutputType> ParseOutputType(const std::string& type)
{
    if (type == OUTPUT_TYPE_STRING_LEGACY) {
        return OutputType::LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_P2SH_SEGWIT) {
        return OutputType::P2SH_SEGWIT;
    } else if (type == OUTPUT_TYPE_STRING_BECH32) {
        return OutputType::BECH32;
    } else if (type == OUTPUT_TYPE_STRING_BECH32M) {
        return OutputType::BECH32M;
    } else if (type == OUTPUT_TYPE_STRING_P2MR) {
        return OutputType::P2MR;
    }
    return std::nullopt;
}

bool IsDestinationOutputTypeAllowed(const CTxDestination& dest, const CChainParams& params)
{
    return IsDestinationOutputTypeAllowedInternal(dest, params, std::nullopt);
}

bool IsDestinationOutputTypeAllowed(const CTxDestination& dest)
{
    return IsDestinationOutputTypeAllowed(dest, Params());
}

bool IsDestinationOutputTypeAllowedAtHeight(const CTxDestination& dest, const CChainParams& params, int height)
{
    return IsDestinationOutputTypeAllowedInternal(dest, params, height);
}

bool IsDestinationOutputTypeAllowedAtHeight(const CTxDestination& dest, int height)
{
    return IsDestinationOutputTypeAllowedAtHeight(dest, Params(), height);
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY: return OUTPUT_TYPE_STRING_LEGACY;
    case OutputType::P2SH_SEGWIT: return OUTPUT_TYPE_STRING_P2SH_SEGWIT;
    case OutputType::BECH32: return OUTPUT_TYPE_STRING_BECH32;
    case OutputType::BECH32M: return OUTPUT_TYPE_STRING_BECH32M;
    case OutputType::P2MR: return OUTPUT_TYPE_STRING_P2MR;
    case OutputType::UNKNOWN: return OUTPUT_TYPE_STRING_UNKNOWN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::string FormatOutputTypes(std::span<const OutputType> output_types)
{
    return util::Join(output_types, ", ", [](const auto& i) { return "\"" + FormatOutputType(i) + "\""; });
}

CTxDestination AddAndGetDestinationForScript(FlatSigningProvider& keystore, const CScript& script, OutputType type)
{
    // Add script to keystore
    keystore.scripts.emplace(CScriptID(script), script);

    switch (type) {
    case OutputType::LEGACY:
        return ScriptHash(script);
    case OutputType::P2SH_SEGWIT:
    case OutputType::BECH32: {
        CTxDestination witdest = WitnessV0ScriptHash(script);
        CScript witprog = GetScriptForDestination(witdest);
        // Add the redeemscript, so that P2WSH and P2SH-P2WSH outputs are recognized as ours.
        keystore.scripts.emplace(CScriptID(witprog), witprog);
        if (type == OutputType::BECH32) {
            return witdest;
        } else {
            return ScriptHash(witprog);
        }
    }
    case OutputType::P2MR:
    case OutputType::BECH32M:
    case OutputType::UNKNOWN: {} // This function should not be used for P2MR/BECH32M/UNKNOWN, so let it assert
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) {
    if (std::holds_alternative<PKHash>(dest) ||
        std::holds_alternative<ScriptHash>(dest)) {
        return OutputType::LEGACY;
    }
    if (std::holds_alternative<WitnessV0KeyHash>(dest) ||
        std::holds_alternative<WitnessV0ScriptHash>(dest)) {
        return OutputType::BECH32;
    }
    if (std::holds_alternative<WitnessV2P2MR>(dest)) {
        return OutputType::P2MR;
    }
    if (std::holds_alternative<WitnessV1Taproot>(dest) ||
        std::holds_alternative<WitnessUnknown>(dest)) {
        return OutputType::BECH32M;
    }
    return std::nullopt;
}
