// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_SYNTHETICWALLET_H
#define QBIT_QT_TEST_SYNTHETICWALLET_H

#include <interfaces/wallet.h>
#include <primitives/transaction.h>
#include <wallet/pqc_usage.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace qt_test {

struct SyntheticWalletState {
    std::mutex mutex;
    std::condition_variable condition;
    bool create_entered{false};
    bool allow_create{true};
    bool wait_for_cancel{false};
    bool cancel_observed{false};
    bool create_finished{false};
    //! Guarded by mutex. Each recorded event takes the next value, so events
    //! recorded on different threads can be ordered; zero means not recorded.
    uint64_t event_sequence{0};
    uint64_t create_finished_sequence{0};
    std::chrono::steady_clock::time_point create_finished_time;
    bool create_success{true};
    bool create_simulate_pqc_reservation{false};
    bool create_fail_before_reservation{false};
    bool create_counters_reserved{false};
    bool allow_create_completion{true};
    bool background_clone_destroyed{false};
    bool shutdown_complete{false};
    bool watchdog_released{false};
    bool encrypted{false};
    bool locked{false};
    //! Encryption latch. While encrypt_in_progress is set, calls that need
    //! the wallet locks in the real wallet block until the latch is released,
    //! so a GUI-thread call into the wallet during encryption stalls the test
    //! the same way it stalls the application.
    bool encrypt_entered{false};
    bool encrypt_in_progress{false};
    bool allow_encrypt{true};
    bool encrypt_success{true};
    //! Throw once the latch is released, as CWallet::EncryptWallet can after
    //! its database transaction has committed.
    bool encrypt_throw{false};
    bool encrypt_finished{false};
    uint64_t encrypt_finished_sequence{0};
    int encrypt_calls{0};
    std::thread::id encrypt_thread;
    std::function<void()> status_changed;
    bool psbt_sign_entered{false};
    bool allow_psbt_reservation{true};
    bool allow_psbt_completion{true};
    bool allow_psbt_post_signing{true};
    bool psbt_simulate_pqc_reservation{false};
    bool psbt_counters_reserved{false};
    bool psbt_input_signed{false};
    bool psbt_cancel_observed{false};
    bool psbt_sign_finished{false};
    bool psbt_fail{false};
    bool psbt_fail_before_reservation{false};
    int psbt_sign_calls{0};
    std::thread::id psbt_sign_thread;
    int lock_calls{0};
    int unlock_calls{0};
    bool bump_enabled{false};
    bool bump_prepare_entered{false};
    bool bump_prepare_success{true};
    bool allow_bump_prepare{true};
    bool bump_prepare_cancel_observed{false};
    bool bump_sign_entered{false};
    bool bump_sign_success{true};
    bool bump_fail_before_reservation{false};
    bool bump_use_counters{true};
    bool allow_bump_reservation{true};
    bool bump_counter_boundary_entered{false};
    bool allow_bump_counter_boundary{true};
    bool bump_counters_reserved{false};
    bool external_bump_boundary_entered{false};
    bool allow_external_bump_boundary{true};
    bool allow_bump_sign{true};
    bool bump_cancel_observed{false};
    bool bump_commit_entered{false};
    bool bump_commit_success{true};
    std::string bump_commit_error{"Original transaction changed while signing"};
    bool bump_committed{false};
    CMutableTransaction bump_committed_tx;
    bool external_signer{false};
    //! Report the wallet as watch-only, so the fee-bump confirmation offers
    //! "Create Unsigned" instead of a send button.
    bool private_keys_disabled{false};
    //! Make an unsigned PSBT draft come back already complete, which the
    //! fee-bump path reports as "Can't draft transaction.".
    bool psbt_draft_complete{false};
    std::function<void()> can_get_addresses_changed;
};

/**
 * Build a signing usage report for keys advanced by one signature to the given
 * counts, deriving each limit state and any state-transition warning the same
 * way the wallet does.
 */
wallet::PQCUsageReport MakeSyntheticPQCUsageReport(const std::vector<std::pair<CPQCPubKey, uint32_t>>& key_counts);

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
