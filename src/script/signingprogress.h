// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_SIGNINGPROGRESS_H
#define QBIT_SCRIPT_SIGNINGPROGRESS_H

#include <functional>
#include <optional>

enum class SigningProgressPhase {
    PREPARING_TRANSACTION,
    RESERVING_PQC_COUNTERS,
    SIGNING_INPUTS,
    FINALIZING_TRANSACTION,
};

struct SigningProgress {
    SigningProgressPhase phase{SigningProgressPhase::PREPARING_TRANSACTION};
    unsigned int completed{0};
    unsigned int total{0};
    std::optional<unsigned int> input_index{};
    bool cancellable{true};
};

using SigningProgressCallback = std::function<bool(const SigningProgress&)>;

#endif // QBIT_SCRIPT_SIGNINGPROGRESS_H
