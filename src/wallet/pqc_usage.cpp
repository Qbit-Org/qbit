// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pqc_usage.h>

#include <addresstype.h>
#include <script/solver.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <string>

namespace wallet {
namespace {

[[nodiscard]] uint32_t SignaturesRemaining(uint32_t signature_count)
{
    if (signature_count >= PQC_MAX_SIGNATURES) {
        return 0;
    }
    return PQC_MAX_SIGNATURES - signature_count;
}

[[nodiscard]] uint32_t WarningReminderBucket(uint32_t signature_count)
{
    if (signature_count <= PQC_WARNING_SIGNATURE_THRESHOLD) {
        return 0;
    }
    return (signature_count - PQC_WARNING_SIGNATURE_THRESHOLD) / PQC_WARNING_REMINDER_INTERVAL;
}

[[nodiscard]] uint32_t CriticalReminderBucket(uint32_t signature_count)
{
    if (signature_count <= PQC_CRITICAL_SIGNATURE_THRESHOLD) {
        return 0;
    }
    return (signature_count - PQC_CRITICAL_SIGNATURE_THRESHOLD) / PQC_CRITICAL_REMINDER_INTERVAL;
}

[[nodiscard]] PQCUsageSnapshot MakeSnapshot(const CPQCPubKey& pubkey, uint32_t signature_count)
{
    return {
        .pubkey = pubkey,
        .signature_count = signature_count,
        .signature_limit = PQC_MAX_SIGNATURES,
        .signatures_remaining = SignaturesRemaining(signature_count),
        .limit_state = GetPQCSignatureLimitState(signature_count),
    };
}

[[nodiscard]] std::optional<PQCSignatureLimitState> AggregateState(const std::vector<PQCUsageSnapshot>& key_states)
{
    if (key_states.empty()) {
        return std::nullopt;
    }
    return std::max_element(
        key_states.begin(),
        key_states.end(),
        [](const PQCUsageSnapshot& lhs, const PQCUsageSnapshot& rhs) {
            return lhs.limit_state < rhs.limit_state;
        })->limit_state;
}

[[nodiscard]] std::string PubkeyHex(const CPQCPubKey& pubkey)
{
    return HexStr(std::span<const unsigned char>{pubkey.begin(), pubkey.end()});
}

[[nodiscard]] bilingual_str FormatPQCUsageWarning(const PQCUsageWarning& warning)
{
    const uint32_t remaining = SignaturesRemaining(warning.new_count);
    if (warning.kind == PQCUsageWarningKind::REMINDER) {
        return Untranslated(strprintf(
            "PQC key %s remains in %s usage range (%u of %u signatures used, %u remaining)",
            PubkeyHex(warning.pubkey),
            PQCSignatureLimitStateName(warning.current_state),
            warning.new_count,
            PQC_MAX_SIGNATURES,
            remaining));
    }
    if (warning.current_state == PQCSignatureLimitState::EXHAUSTED) {
        return Untranslated(strprintf(
            "PQC key %s reached the signature limit (%u of %u signatures used, %u remaining). Rotate to a new key/address.",
            PubkeyHex(warning.pubkey),
            warning.new_count,
            PQC_MAX_SIGNATURES,
            remaining));
    }
    return Untranslated(strprintf(
        "PQC key %s entered %s usage range (%u of %u signatures used, %u remaining)",
        PubkeyHex(warning.pubkey),
        PQCSignatureLimitStateName(warning.current_state),
        warning.new_count,
        PQC_MAX_SIGNATURES,
        remaining));
}

} // namespace

void PQCUsageRecorder::Observe(const CPQCPubKey& pubkey, uint32_t previous_count, uint32_t new_count)
{
    auto [it, inserted] = m_advances.try_emplace(pubkey, PQCUsageAdvance{pubkey, previous_count, new_count});
    if (!inserted) {
        it->second.previous_count = std::min(it->second.previous_count, previous_count);
        it->second.new_count = std::max(it->second.new_count, new_count);
    }
}

bool PQCUsageRecorder::Empty() const
{
    return m_advances.empty();
}

std::vector<PQCUsageAdvance> PQCUsageRecorder::GetAdvances() const
{
    std::vector<PQCUsageAdvance> advances;
    advances.reserve(m_advances.size());
    for (const auto& [_, advance] : m_advances) {
        advances.push_back(advance);
    }
    return advances;
}

PQCSignatureCounterObserver PQCUsageRecorder::GetObserver()
{
    return [this](const CPQCPubKey& pubkey, uint32_t previous_count, uint32_t new_count) {
        Observe(pubkey, previous_count, new_count);
    };
}

PQCSignatureLimitState GetPQCSignatureLimitState(uint32_t signature_count)
{
    if (signature_count >= PQC_MAX_SIGNATURES) {
        return PQCSignatureLimitState::EXHAUSTED;
    }
    if (signature_count >= PQC_CRITICAL_SIGNATURE_THRESHOLD) {
        return PQCSignatureLimitState::CRITICAL;
    }
    if (signature_count >= PQC_WARNING_SIGNATURE_THRESHOLD) {
        return PQCSignatureLimitState::WARNING;
    }
    return PQCSignatureLimitState::NORMAL;
}

std::string_view PQCSignatureLimitStateName(PQCSignatureLimitState state)
{
    switch (state) {
    case PQCSignatureLimitState::NORMAL:
        return "normal";
    case PQCSignatureLimitState::WARNING:
        return "warning";
    case PQCSignatureLimitState::CRITICAL:
        return "critical";
    case PQCSignatureLimitState::EXHAUSTED:
        return "exhausted";
    }
    return "normal";
}

std::vector<bilingual_str> FormatPQCUsageWarnings(const std::vector<PQCUsageWarning>& warnings)
{
    std::vector<bilingual_str> out;
    out.reserve(warnings.size());
    for (const PQCUsageWarning& warning : warnings) {
        out.push_back(FormatPQCUsageWarning(warning));
    }
    return out;
}

void LogPQCUsageWarnings(const CWallet& wallet, const PQCUsageReport& report)
{
    for (const bilingual_str& warning : FormatPQCUsageWarnings(report.warnings)) {
        wallet.WalletLogPrintf("PQC usage warning: %s\n", warning.original);
    }
}

void LogConsumedPQCDataHashCounters(const CWallet& wallet, const PQCUsageRecorder& recorder, const bilingual_str& error)
{
    for (const PQCUsageAdvance& advance : recorder.GetAdvances()) {
        wallet.WalletLogPrintf(
            "PQC data-hash signing consumed counter for pubkey %s [%u, %u) before failing: %s\n",
            HexStr(std::span<const unsigned char>{advance.pubkey.begin(), advance.pubkey.end()}),
            advance.previous_count,
            advance.new_count,
            error.original);
    }
}

PQCUsageReport BuildSigningPQCUsageReport(const PQCUsageRecorder& recorder)
{
    PQCUsageReport report;
    const std::vector<PQCUsageAdvance> advances = recorder.GetAdvances();
    report.key_states.reserve(advances.size());
    report.warnings.reserve(advances.size());

    for (const PQCUsageAdvance& advance : advances) {
        const PQCSignatureLimitState previous_state = GetPQCSignatureLimitState(advance.previous_count);
        const PQCSignatureLimitState current_state = GetPQCSignatureLimitState(advance.new_count);
        report.key_states.push_back(MakeSnapshot(advance.pubkey, advance.new_count));

        if (current_state != previous_state) {
            report.warnings.push_back({
                .pubkey = advance.pubkey,
                .previous_count = advance.previous_count,
                .new_count = advance.new_count,
                .previous_state = previous_state,
                .current_state = current_state,
                .kind = PQCUsageWarningKind::TRANSITION,
            });
            continue;
        }

        if (current_state == PQCSignatureLimitState::WARNING &&
            WarningReminderBucket(advance.new_count) > WarningReminderBucket(advance.previous_count)) {
            report.warnings.push_back({
                .pubkey = advance.pubkey,
                .previous_count = advance.previous_count,
                .new_count = advance.new_count,
                .previous_state = previous_state,
                .current_state = current_state,
                .kind = PQCUsageWarningKind::REMINDER,
            });
            continue;
        }

        if (current_state == PQCSignatureLimitState::CRITICAL &&
            CriticalReminderBucket(advance.new_count) > CriticalReminderBucket(advance.previous_count)) {
            report.warnings.push_back({
                .pubkey = advance.pubkey,
                .previous_count = advance.previous_count,
                .new_count = advance.new_count,
                .previous_state = previous_state,
                .current_state = current_state,
                .kind = PQCUsageWarningKind::REMINDER,
            });
        }
    }

    report.overall_state = AggregateState(report.key_states);
    return report;
}

PQCUsageReport BuildGetAddressInfoPQCUsageReport(const CWallet& wallet, const CScript& script_pubkey)
{
    PQCUsageReport report;
    CTxDestination destination;
    if (!ExtractDestination(script_pubkey, destination)) {
        return report;
    }
    const auto* output = std::get_if<WitnessV2P2MR>(&destination);
    if (!output) {
        return report;
    }

    std::map<CPQCPubKey, uint32_t> pqc_counters;
    for (ScriptPubKeyMan* spk_man : wallet.GetScriptPubKeyMans(script_pubkey)) {
        const auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) {
            continue;
        }

        std::unique_ptr<SigningProvider> provider = desc_spk_man->GetSolvingProvider(script_pubkey);
        if (!provider) {
            continue;
        }

        P2MRSpendData spenddata;
        if (!provider->GetP2MRSpendData(*output, spenddata)) {
            continue;
        }

        for (const auto& [leaf, _] : spenddata.scripts) {
            const CScript leaf_script(leaf.first.begin(), leaf.first.end());
            for (const CPQCPubKey& pubkey : ExtractP2MRPubkeys(leaf_script)) {
                const std::optional<uint32_t> counter = desc_spk_man->GetPQCSignatureCounter(pubkey);
                if (!counter) {
                    continue;
                }
                auto [it, inserted] = pqc_counters.emplace(pubkey, *counter);
                if (!inserted && *counter > it->second) {
                    it->second = *counter;
                }
            }
        }
    }

    report.key_states.reserve(pqc_counters.size());
    for (const auto& [pubkey, signature_count] : pqc_counters) {
        report.key_states.push_back(MakeSnapshot(pubkey, signature_count));
    }
    report.overall_state = AggregateState(report.key_states);
    return report;
}
} // namespace wallet
