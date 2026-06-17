// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_WALLET_PQC_USAGE_H
#define QBIT_WALLET_PQC_USAGE_H

#include <crypto/pqc.h>
#include <script/script.h>
#include <script/signingprovider.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <vector>

struct bilingual_str;

namespace wallet {
class CWallet;

static constexpr uint32_t PQC_WARNING_SIGNATURE_THRESHOLD = 1U << 28;
static constexpr uint32_t PQC_CRITICAL_SIGNATURE_THRESHOLD = PQC_MAX_SIGNATURES - (1U << 24);
static constexpr uint32_t PQC_WARNING_REMINDER_INTERVAL = 1U << 24;
static constexpr uint32_t PQC_CRITICAL_REMINDER_INTERVAL = 1U << 20;

enum class PQCSignatureLimitState {
    NORMAL,
    WARNING,
    CRITICAL,
    EXHAUSTED,
};

enum class PQCUsageWarningKind {
    TRANSITION,
    REMINDER,
};

struct PQCUsageSnapshot {
    CPQCPubKey pubkey;
    uint32_t signature_count;
    uint32_t signature_limit;
    uint32_t signatures_remaining;
    PQCSignatureLimitState limit_state;
};

struct PQCUsageAdvance {
    CPQCPubKey pubkey;
    uint32_t previous_count;
    uint32_t new_count;
};

struct PQCUsageWarning {
    CPQCPubKey pubkey;
    uint32_t previous_count;
    uint32_t new_count;
    PQCSignatureLimitState previous_state;
    PQCSignatureLimitState current_state;
    PQCUsageWarningKind kind;
};

struct PQCUsageReport {
    std::vector<PQCUsageSnapshot> key_states;
    std::optional<PQCSignatureLimitState> overall_state;
    std::vector<PQCUsageWarning> warnings;
};

class PQCUsageRecorder
{
public:
    void Observe(const CPQCPubKey& pubkey, uint32_t previous_count, uint32_t new_count);
    [[nodiscard]] bool Empty() const;
    [[nodiscard]] std::vector<PQCUsageAdvance> GetAdvances() const;
    [[nodiscard]] PQCSignatureCounterObserver GetObserver();

private:
    std::map<CPQCPubKey, PQCUsageAdvance> m_advances;
};

[[nodiscard]] PQCSignatureLimitState GetPQCSignatureLimitState(uint32_t signature_count);
[[nodiscard]] std::string_view PQCSignatureLimitStateName(PQCSignatureLimitState state);
[[nodiscard]] std::vector<bilingual_str> FormatPQCUsageWarnings(const std::vector<PQCUsageWarning>& warnings);
[[nodiscard]] PQCUsageReport BuildSigningPQCUsageReport(const PQCUsageRecorder& recorder);
[[nodiscard]] PQCUsageReport BuildGetAddressInfoPQCUsageReport(const CWallet& wallet, const CScript& script_pubkey);
} // namespace wallet

#endif // QBIT_WALLET_PQC_USAGE_H
