// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pqcusageformat.h>

#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/pqc_usage.h>

#include <span>

#include <QCoreApplication>
#include <QStringList>

namespace {
class PQCUsageFormat
{
    Q_DECLARE_TR_FUNCTIONS(PQCUsageFormat)

public:
    static QString StateLabel(wallet::PQCSignatureLimitState state)
    {
        switch (state) {
        case wallet::PQCSignatureLimitState::NORMAL:
            return tr("Normal");
        case wallet::PQCSignatureLimitState::WARNING:
            return tr("Warning");
        case wallet::PQCSignatureLimitState::CRITICAL:
            return tr("Critical");
        case wallet::PQCSignatureLimitState::EXHAUSTED:
            return tr("Exhausted");
        }
        return {};
    }

    static QString OutcomeSentence(PQCSigningOutcome outcome)
    {
        switch (outcome) {
        case PQCSigningOutcome::Consumed:
            return tr("PQC signature capacity was consumed during this signing attempt.");
        case PQCSigningOutcome::FailedAfterConsumption:
            return tr("The signing attempt failed after consuming PQC signature capacity.");
        }
        return {};
    }

    /** Usage lines as unescaped plain text, or an empty list for an empty report. */
    static QStringList UsageLines(const wallet::PQCUsageReport& report)
    {
        QStringList lines;
        if (report.key_states.empty()) return lines;

        if (report.overall_state.has_value()) {
            lines.append(tr("PQC usage state after this signing attempt: %1.").arg(StateLabel(*report.overall_state)));
        }
        for (const wallet::PQCUsageSnapshot& key_state : report.key_states) {
            lines.append(tr("PQC key %1: %2 of %3 signatures used, %4 remaining; state: %5.")
                             .arg(QString::fromStdString(HexStr(std::span<const unsigned char>{key_state.pubkey.begin(), key_state.pubkey.end()})))
                             .arg(key_state.signature_count)
                             .arg(key_state.signature_limit)
                             .arg(key_state.signatures_remaining)
                             .arg(StateLabel(key_state.limit_state)));
        }
        for (const bilingual_str& warning : wallet::FormatPQCUsageWarnings(report.warnings)) {
            lines.append(QString::fromStdString(warning.translated.empty() ? warning.original : warning.translated));
        }
        return lines;
    }
};
} // namespace

QString FormatPQCSigningUsagePlain(const wallet::PQCUsageReport& report)
{
    return PQCUsageFormat::UsageLines(report).join("\n");
}

QString FormatPQCSigningOutcomePlain(const wallet::PQCUsageReport& report, PQCSigningOutcome outcome)
{
    QStringList lines{PQCUsageFormat::UsageLines(report)};
    if (lines.empty()) return {};
    lines.prepend(PQCUsageFormat::OutcomeSentence(outcome));
    return lines.join("\n");
}
