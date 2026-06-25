// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_RPC_MINING_H
#define QBIT_RPC_MINING_H

#include <cstdint>
#include <string>

class CAuxPow;
class CChain;

/** Decode the AuxPoW hex layouts accepted by the submitauxblock RPC. */
CAuxPow DecodeHexAuxPow(const std::string& hex_auxpow);

/**
 * Return average network hashes per second based on the last `lookup` blocks,
 * or from the last difficulty change if `lookup` is -1.
 * If `height` is -1, compute the estimate from current chain tip.
 * If `height` is a valid block height, compute the estimate at that height.
 */
double EstimateNetworkHashPS(int lookup, int height, const CChain& active_chain);

/**
 * Return average native permissionless-lane hashes per second based on the
 * last `lookup` active-chain blocks. AuxPoW block work is excluded from the
 * numerator while the active-chain time window is preserved.
 */
double EstimatePermissionlessNetworkHashPS(int lookup, int height, const CChain& active_chain);

/**
 * Return average AuxPoW-lane hashes per second based on the last `lookup`
 * active-chain blocks. Permissionless block work is excluded from the numerator
 * while the active-chain time window is preserved.
 */
double EstimateAuxpowNetworkHashPS(int lookup, int height, const CChain& active_chain);

/** Default max iterations to try in RPC generatetodescriptor, generatetoaddress, and generateblock. */
static const uint64_t DEFAULT_MAX_TRIES{1000000};

/** Default same-tip createauxblock template age limit, in minutes. */
static constexpr int64_t DEFAULT_AUXPOW_TEMPLATE_EXPIRY_MINUTES{60};

/** Default same-tip createauxblock template count limit. */
static constexpr int64_t DEFAULT_AUXPOW_TEMPLATE_CACHE_LIMIT{1024};

#endif // QBIT_RPC_MINING_H
