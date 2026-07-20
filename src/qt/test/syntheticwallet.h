// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_SYNTHETICWALLET_H
#define QBIT_QT_TEST_SYNTHETICWALLET_H

#include <interfaces/wallet.h>
#include <wallet/pqc_usage.h>

#include <condition_variable>
#include <memory>
#include <mutex>

namespace qt_test {

struct SyntheticWalletState {
    std::mutex mutex;
    std::condition_variable condition;
    bool create_entered{false};
    bool allow_create{true};
    bool wait_for_cancel{false};
    bool cancel_observed{false};
    bool create_finished{false};
    bool background_clone_destroyed{false};
    bool shutdown_complete{false};
    bool watchdog_released{false};
    bool encrypted{false};
    bool locked{false};
    int lock_calls{0};
    int unlock_calls{0};
    bool bump_enabled{false};
    bool bump_prepare_entered{false};
    bool bump_prepare_success{true};
    bool allow_bump_prepare{true};
    bool bump_prepare_cancel_observed{false};
    bool bump_sign_entered{false};
    bool bump_sign_success{true};
    bool bump_use_counters{true};
    bool allow_bump_reservation{true};
    bool bump_counters_reserved{false};
    bool external_bump_boundary_entered{false};
    bool allow_external_bump_boundary{true};
    bool allow_bump_sign{true};
    bool bump_cancel_observed{false};
    bool bump_commit_entered{false};
    bool bump_commit_success{true};
    bool bump_committed{false};
    bool external_signer{false};
};

std::unique_ptr<interfaces::Wallet> MakeSyntheticWallet(
    wallet::PQCUsageReport report = {},
    std::shared_ptr<SyntheticWalletState> state = std::make_shared<SyntheticWalletState>());
std::unique_ptr<interfaces::Wallet> MakeSyntheticWallet(
    interfaces::P2MRDataSignatureResult result,
    wallet::PQCUsageReport report = {});
std::unique_ptr<interfaces::Wallet> MakeSyntheticP2MRFailureWallet(
    bilingual_str error,
    wallet::PQCUsageReport report);

} // namespace qt_test

#endif // QBIT_QT_TEST_SYNTHETICWALLET_H
