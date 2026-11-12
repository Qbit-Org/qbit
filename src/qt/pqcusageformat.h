// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_PQCUSAGEFORMAT_H
#define QBIT_QT_PQCUSAGEFORMAT_H

#include <QString>

namespace wallet {
struct PQCUsageReport;
} // namespace wallet

/** Outcome of the transaction-signing attempt a PQC usage report belongs to. */
enum class PQCSigningOutcome {
    //! Signing finished (fully or partially) and consumed PQC signature capacity.
    Consumed,
    //! The operation failed after PQC signature capacity was consumed.
    FailedAfterConsumption,
};

/**
 * Format the wallet-local PQC usage of one transaction-signing attempt:
 * the overall state, every affected key (public key, signatures used, limit,
 * remaining capacity and limit state) and every usage warning.
 *
 * Returns an empty string when the report has no key states, so an absent
 * report is never presented as zero consumption.
 */
QString FormatPQCSigningUsagePlain(const wallet::PQCUsageReport& report);

//! Outcome sentence followed by FormatPQCSigningUsagePlain, or empty when the report has no key states.
QString FormatPQCSigningOutcomePlain(const wallet::PQCUsageReport& report, PQCSigningOutcome outcome);

#endif // QBIT_QT_PQCUSAGEFORMAT_H
