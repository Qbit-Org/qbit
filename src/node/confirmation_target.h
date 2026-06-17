// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_NODE_CONFIRMATION_TARGET_H
#define QBIT_NODE_CONFIRMATION_TARGET_H

#include <cstdint>
#include <string>

namespace node {

struct ConfirmationResult {
    int required_confirmations;
    double required_minutes;
    double equivalent_btc_confirmations;
    double permissionless_hashrate;
    double auxpow_hashrate;
    double total_observed_hashrate;
    double orphan_rate;
    std::string security_level;
    double value_qbt;
    // Model parameters (for transparency / debugging)
    int btc_target_confirmations;
    int64_t block_time_seconds;
    double merge_mining_pct;
    double btc_hashrate;
    double orphan_rate_penalty;
    double security_per_confirmation;
    double cadence_merged_fraction;
};

class ConfirmationCalculator
{
public:
    /** BTC confirmation targets per security level. */
    static constexpr int BTC_CONFS_LOW = 1;
    static constexpr int BTC_CONFS_MEDIUM = 3;
    static constexpr int BTC_CONFS_HIGH = 6;
    static constexpr int BTC_CONFS_MAXIMUM = 60;

    /** Default estimated Bitcoin hashrate: 700 EH/s. */
    static constexpr double DEFAULT_BTC_HASHRATE = 7e20;

    static constexpr int MIN_CONFIRMATIONS = 1;
    static constexpr int MAX_CONFIRMATIONS = 100000;

    /** Map a security level string to the corresponding BTC confirmation target.
     *  Returns -1 for an unrecognised level. */
    static int BtcTargetForLevel(const std::string& level);

    /** Derive the merge-mined share from cadence lane spacings. */
    static double CadenceMergedFraction(
        int64_t legacy_spacing_seconds,
        int64_t auxpow_spacing_seconds,
        int64_t fallback_spacing_seconds);

    /** Compute the required number of qbit confirmations.
     *
     *  @param value_satoshis     Transaction value (informational, included in result).
     *  @param security_level     "low", "medium", "high", or "maximum".
     *                            Unknown values fall back to "maximum".
     *  @param use_observed_hashrate Use observed qbit chainwork instead of the
     *                            merge-mining percentage model.
     *  @param merge_mining_pct   Fallback/override fraction of BTC hashrate
     *                            merge-mining qbit (0.0-1.0).
     *  @param btc_hashrate       Estimated Bitcoin network hashrate in H/s.
     *  @param permissionless_hashrate Current qbit permissionless-lane hashrate in H/s.
     *  @param auxpow_hashrate    Current qbit AuxPoW-lane hashrate in H/s.
     *  @param orphan_rate        Current orphan/stale rate (from getorphanmetrics, 0.0-1.0).
     *  @param block_time_seconds Qbit block time in seconds (consensus parameter).
     *  @param legacy_spacing_seconds Target spacing for permissionless blocks.
     *  @param auxpow_spacing_seconds Target spacing for merge-mined blocks.
     */
    static ConfirmationResult Calculate(
        int64_t value_satoshis,
        const std::string& security_level,
        bool use_observed_hashrate,
        double merge_mining_pct,
        double btc_hashrate,
        double permissionless_hashrate,
        double auxpow_hashrate,
        double orphan_rate,
        int64_t block_time_seconds,
        int64_t legacy_spacing_seconds,
        int64_t auxpow_spacing_seconds);
};

} // namespace node

#endif // QBIT_NODE_CONFIRMATION_TARGET_H
