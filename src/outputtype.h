// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_OUTPUTTYPE_H
#define QBIT_OUTPUTTYPE_H

#include <addresstype.h>

#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

class CChainParams;
struct FlatSigningProvider;

enum class OutputType {
    LEGACY,
    P2SH_SEGWIT,
    BECH32,
    BECH32M,
    P2MR,
    UNKNOWN,
};

static constexpr auto SUPPORTED_OUTPUT_TYPES = std::array{
    OutputType::LEGACY,
    OutputType::P2SH_SEGWIT,
    OutputType::BECH32,
    OutputType::BECH32M,
    OutputType::P2MR,
};

std::span<const OutputType> GetSupportedOutputTypes();
std::span<const OutputType> GetAllowedOutputTypes(const CChainParams& params);
std::span<const OutputType> GetAllowedOutputTypes();
bool IsP2MROnlyOutputChain(const CChainParams& params);
bool IsP2MROnlyOutputChain();
bool IsOutputTypeAllowed(OutputType type, const CChainParams& params);
bool IsOutputTypeAllowed(OutputType type);
bool IsDestinationOutputTypeAllowed(const CTxDestination& dest, const CChainParams& params);
bool IsDestinationOutputTypeAllowed(const CTxDestination& dest);
bool IsDestinationOutputTypeAllowedAtHeight(const CTxDestination& dest, const CChainParams& params, int height);
bool IsDestinationOutputTypeAllowedAtHeight(const CTxDestination& dest, int height);
std::optional<OutputType> ParseOutputType(const std::string& str);
const std::string& FormatOutputType(OutputType type);
std::string FormatOutputTypes(std::span<const OutputType> output_types);

/**
 * Get a destination of the requested type (if possible) to the specified script.
 * This function will automatically add the script (and any other
 * necessary scripts) to the keystore.
 */
CTxDestination AddAndGetDestinationForScript(FlatSigningProvider& keystore, const CScript& script, OutputType);

/** Get the OutputType for a CTxDestination */
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest);

#endif // QBIT_OUTPUTTYPE_H
