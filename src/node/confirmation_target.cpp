// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/confirmation_target.h>

#include <algorithm>
#include <cmath>
#include <string>

namespace node {

double ConfirmationCalculator::CadenceMergedFraction(
    int64_t legacy_spacing_seconds,
    int64_t auxpow_spacing_seconds,
    int64_t fallback_spacing_seconds)
{
    if (fallback_spacing_seconds <= 0) fallback_spacing_seconds = 60;
    if (legacy_spacing_seconds <= 0) legacy_spacing_seconds = fallback_spacing_seconds;
    if (auxpow_spacing_seconds <= 0) auxpow_spacing_seconds = fallback_spacing_seconds;

    const double total_spacing = static_cast<double>(legacy_spacing_seconds + auxpow_spacing_seconds);
    if (total_spacing <= 0.0) return 0.5;

    return static_cast<double>(legacy_spacing_seconds) / total_spacing;
}

int ConfirmationCalculator::BtcTargetForLevel(const std::string& level)
{
    if (level == "low") return BTC_CONFS_LOW;
    if (level == "medium") return BTC_CONFS_MEDIUM;
    if (level == "high") return BTC_CONFS_HIGH;
    if (level == "maximum") return BTC_CONFS_MAXIMUM;
    return -1;
}

ConfirmationResult ConfirmationCalculator::Calculate(
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
    int64_t auxpow_spacing_seconds)
{
    int btc_target = BtcTargetForLevel(security_level);
    std::string used_security_level{security_level};
    if (btc_target < 0) {
        // Defensive fallback for direct callers: if the level is invalid,
        // pick the most conservative target rather than silently returning
        // a low-security recommendation.
        btc_target = BTC_CONFS_MAXIMUM;
        used_security_level = "maximum";
    }

    // Clamp inputs to sane ranges.
    merge_mining_pct = std::clamp(merge_mining_pct, 0.0, 1.0);
    orphan_rate = std::clamp(orphan_rate, 0.0, 0.99);
    if (btc_hashrate <= 0.0) btc_hashrate = DEFAULT_BTC_HASHRATE;
    if (permissionless_hashrate < 0.0) permissionless_hashrate = 0.0;
    if (auxpow_hashrate < 0.0) auxpow_hashrate = 0.0;
    if (block_time_seconds <= 0) block_time_seconds = 60;

    const double total_observed_hashrate = permissionless_hashrate + auxpow_hashrate;
    const double cadence_merged_fraction = CadenceMergedFraction(
        legacy_spacing_seconds,
        auxpow_spacing_seconds,
        block_time_seconds);

    // ── Security model ──────────────────────────────────────────────
    //
    // Each qbit confirmation contributes some fraction of the security
    // of one Bitcoin confirmation. With observed chainwork, the lane
    // work/time estimates already include how frequently each lane produced
    // accepted work, so cadence must not be applied a second time.
    //
    // If observed AuxPoW work is unavailable, callers can fall back to the
    // launch-era merge-mining percentage model. In that mode, cadence
    // determines what fraction of blocks are merge-mined based on consensus
    // lane spacings.
    //
    //   security_per_conf
    //     = (block_time / 600) * (observed_qbit_hr / btc_hr)       [observed]
    //     = cadence_merged * merge_mining_pct
    //       + (1 - cadence_merged) * (permissionless_hr / btc_hr)  [fallback]
    //
    // Orphan penalty: some confirmations are "wasted" on blocks that go
    // stale.  Effective confirmations = n * (1 - orphan_rate), so we
    // need n / (1 - orphan_rate) raw confirmations.
    //
    //   required = btc_target / security_per_conf / (1 - orphan_rate)
    //
    const double native_fraction = (btc_hashrate > 0.0)
        ? permissionless_hashrate / btc_hashrate
        : 0.0;
    const double observed_fraction = (btc_hashrate > 0.0)
        ? total_observed_hashrate / btc_hashrate
        : 0.0;

    const double security_per_conf = (use_observed_hashrate && total_observed_hashrate > 0.0)
        ? (static_cast<double>(block_time_seconds) / 600.0) * observed_fraction
        : cadence_merged_fraction * merge_mining_pct +
            (1.0 - cadence_merged_fraction) * native_fraction;

    const double orphan_penalty = 1.0 / (1.0 - orphan_rate);
    const double fallback_block_time_ratio = 600.0 / static_cast<double>(block_time_seconds);

    double raw_required;
    double equivalent_btc;

    if (security_per_conf > 0.0) {
        raw_required = static_cast<double>(btc_target) / security_per_conf * orphan_penalty;
    } else {
        // No merge mining and negligible native hashrate: fall back to
        // a pure wall-clock scaling versus Bitcoin's 10 minute blocks.
        raw_required = static_cast<double>(btc_target) * fallback_block_time_ratio * orphan_penalty;
    }

    // Clamp the raw double BEFORE casting to int to avoid undefined behaviour
    // when raw_required exceeds INT_MAX (e.g. very small security_per_conf).
    const double clamped = std::clamp(std::ceil(raw_required),
                                      static_cast<double>(MIN_CONFIRMATIONS),
                                      static_cast<double>(MAX_CONFIRMATIONS));
    int required = static_cast<int>(clamped);

    // Compute equivalent BTC confirmations from the *actual* (possibly clamped)
    // confirmation count so exchanges don't overestimate their security.
    if (security_per_conf > 0.0) {
        equivalent_btc = static_cast<double>(required) * security_per_conf / orphan_penalty;
    } else {
        equivalent_btc = static_cast<double>(required) / fallback_block_time_ratio / orphan_penalty;
    }

    const double value_qbt = static_cast<double>(value_satoshis) / 1e8;
    const double required_minutes = static_cast<double>(required) * static_cast<double>(block_time_seconds) / 60.0;

    return ConfirmationResult{
        required,
        required_minutes,
        equivalent_btc,
        permissionless_hashrate,
        auxpow_hashrate,
        total_observed_hashrate,
        orphan_rate,
        used_security_level,
        value_qbt,
        btc_target,
        block_time_seconds,
        merge_mining_pct,
        btc_hashrate,
        orphan_penalty,
        security_per_conf,
        cadence_merged_fraction,
    };
}

} // namespace node
