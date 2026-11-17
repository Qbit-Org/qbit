// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace node {

namespace {
/** Parse a -txvalidationbudget value: 0 (disabled) or four durations in microseconds. The peer
 *  rate and cap must be positive, so that every peer can eventually validate transactions. */
std::optional<TxValidationBudgetOptions> ParseTxValidationBudget(const std::string& value)
{
    if (value == "0") return TxValidationBudgetOptions{.enabled = false};
    const std::vector<std::string> fields{util::SplitString(value, ',')};
    if (fields.size() != 4) return std::nullopt;
    std::vector<std::chrono::microseconds> durations;
    for (const std::string& field : fields) {
        const auto parsed{ToIntegral<int64_t>(field)};
        if (!parsed || *parsed < 0 || *parsed > MAX_TX_VALIDATION_BUDGET_SETTING.count()) return std::nullopt;
        durations.emplace_back(*parsed);
    }
    if (durations[0] <= std::chrono::microseconds{0} || durations[1] <= std::chrono::microseconds{0}) return std::nullopt;
    return TxValidationBudgetOptions{
        .enabled = true,
        .peer_rate = durations[0],
        .peer_cap = durations[1],
        .pool_rate = durations[2],
        .pool_cap = durations[3],
    };
}
} // namespace

util::Result<void> ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;

    if (auto value{argsman.GetBoolArg("-blocksonly")}) options.ignore_incoming_txs = *value;

    if (argsman.IsArgSet("-txvalidationbudget")) {
        const std::string value{argsman.GetArg("-txvalidationbudget", "")};
        const auto budget{ParseTxValidationBudget(value)};
        if (!budget) {
            return util::Error{Untranslated(strprintf(
                "Invalid -txvalidationbudget value '%s': expected 0 to disable, or <peer_rate>,<peer_cap>,<pool_rate>,<pool_cap> "
                "in microseconds, each from 0 to %d, with <peer_rate> and <peer_cap> at least 1",
                value, MAX_TX_VALIDATION_BUDGET_SETTING.count()))};
        }
        options.tx_validation_budget = *budget;
    }

    return {};
}

} // namespace node
