// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/syntheticwallet.h>

#include <common/types.h>
#include <interfaces/handler.h>
#include <outputtype.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <util/translation.h>
#include <wallet/wallet.h>

#include <chrono>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>

namespace qt_test {
namespace {

using namespace std::chrono_literals;

class SyntheticWallet : public interfaces::Wallet
{
public:
    explicit SyntheticWallet(
        wallet::PQCUsageReport report,
        std::shared_ptr<SyntheticWalletState> state,
        bool background_clone = false)
        : m_report(std::move(report)), m_state(std::move(state)), m_background_clone(background_clone)
    {
    }
    explicit SyntheticWallet(interfaces::P2MRDataSignatureResult result, wallet::PQCUsageReport report)
        : m_p2mr_result(std::move(result)),
          m_p2mr_usage(std::make_shared<const wallet::PQCUsageReport>(std::move(report))),
          m_state(std::make_shared<SyntheticWalletState>()),
          m_background_clone(false)
    {
    }
    explicit SyntheticWallet(bilingual_str error, wallet::PQCUsageReport report)
        : m_p2mr_error(std::move(error)),
          m_p2mr_usage(std::make_shared<const wallet::PQCUsageReport>(std::move(report))),
          m_state(std::make_shared<SyntheticWalletState>()),
          m_background_clone(false)
    {
    }

    ~SyntheticWallet() override
    {
        if (!m_background_clone) return;
        {
            std::lock_guard lock{m_state->mutex};
            m_state->background_clone_destroyed = true;
        }
        m_state->condition.notify_all();
    }

    bool encryptWallet(const SecureString&) override
    {
        std::function<void()> status_changed;
        {
            std::lock_guard lock{m_state->mutex};
            // Like CWallet::EncryptWallet, which refuses a wallet that another
            // caller has encrypted and leaves it untouched.
            if (m_state->encrypted) {
                ++m_state->encrypt_calls;
                return false;
            }
            m_state->encrypt_entered = true;
            m_state->encrypt_in_progress = true;
            m_state->encrypt_finished = false;
            // CWallet::EncryptWallet stores the master key first, so the
            // wallet reports itself encrypted for the rest of the operation
            // and a status query goes on to wait for the wallet lock.
            m_state->encrypted = true;
            ++m_state->encrypt_calls;
            m_state->encrypt_thread = std::this_thread::get_id();
            status_changed = m_state->status_changed;
        }
        m_state->condition.notify_all();
        // Like CWallet::EncryptWallet, which unlocks the freshly encrypted keys
        // and notifies while it still holds the wallet locks.
        if (status_changed) status_changed();

        bool success{false};
        bool throw_after_commit{false};
        {
            std::unique_lock lock{m_state->mutex};
            m_state->condition.wait(lock, [this] { return m_state->allow_encrypt; });
            success = m_state->encrypt_success;
            throw_after_commit = m_state->encrypt_throw;
            if (success) {
                m_state->locked = true;
            } else {
                // A clean failure leaves the wallet unencrypted.
                m_state->encrypted = false;
            }
            m_state->encrypt_in_progress = false;
            m_state->encrypt_finished = true;
            m_state->encrypt_finished_sequence = ++m_state->event_sequence;
        }
        m_state->condition.notify_all();
        // An exception after the database transaction committed leaves the
        // wallet encrypted, releases the locks by unwinding and skips the
        // final status notification.
        if (throw_after_commit) throw std::runtime_error{"synthetic encryption failure after commit"};
        if (status_changed) status_changed();
        return success;
    }
    bool isCrypted() override
    {
        std::lock_guard lock{m_state->mutex};
        return m_state->encrypted;
    }
    bool lock() override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        m_state->locked = true;
        ++m_state->lock_calls;
        return true;
    }
    bool unlock(const SecureString&) override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        m_state->locked = false;
        ++m_state->unlock_calls;
        return true;
    }
    bool isLocked() override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        return m_state->locked;
    }
    bool changeWalletPassphrase(const SecureString&, const SecureString&) override { return false; }
    void abortRescan() override {}
    bool backupWallet(const std::string&) override { return false; }
    std::string getWalletName() override { return "synthetic-pqc-report"; }
    std::unique_ptr<interfaces::Wallet> clone() override
    {
        return std::make_unique<SyntheticWallet>(m_report, m_state, /*background_clone=*/true);
    }
    util::Result<CTxDestination> getNewDestination(const OutputType, const std::string&) override { return CTxDestination{PKHash{}}; }
    bool getPubKey(const CScript&, const CKeyID&, CPubKey&) override { return false; }
    SigningResult signMessage(const std::string&, const PKHash&, std::string&) override { return SigningResult::PRIVATE_KEY_NOT_AVAILABLE; }
    interfaces::P2MRDataSignatureAttempt signP2MRDataHash(const CTxDestination&, const uint256&) override
    {
        if (m_p2mr_result) {
            return {
                .result = *m_p2mr_result,
                .pqc_usage = m_p2mr_usage,
            };
        }
        return {
            .result = util::Error{m_p2mr_error.value_or(Untranslated("P2MR data-hash signing unavailable"))},
            .pqc_usage = m_p2mr_usage,
        };
    }
    bool isSpendable(const CTxDestination&) override { return false; }
    bool setAddressBook(const CTxDestination&, const std::string&, const std::optional<wallet::AddressPurpose>&) override { return false; }
    bool delAddressBook(const CTxDestination&) override { return false; }
    bool getAddress(const CTxDestination&, std::string*, wallet::AddressPurpose*) override { return false; }
    std::vector<interfaces::WalletAddress> getAddresses() override { return {}; }
    std::vector<OutputType> getAvailableAddressTypes() override { return {OutputType::P2MR}; }
    std::vector<std::string> getAddressReceiveRequests() override { return {}; }
    bool setAddressReceiveRequest(const CTxDestination&, const std::string&, const std::string&) override { return false; }
    util::Result<void> displayAddress(const CTxDestination&) override { return {}; }
    bool lockCoin(const COutPoint&, const bool) override { return false; }
    bool unlockCoin(const COutPoint&) override { return false; }
    bool isLockedCoin(const COutPoint&) override { return false; }
    void listLockedCoins(std::vector<COutPoint>&) override {}
    util::Result<CTransactionRef> createTransaction(const std::vector<wallet::CRecipient>& recipients,
        const wallet::CCoinControl&,
        bool,
        int& change_pos,
        CAmount& fee,
        wallet::PQCUsageReport* pqc_usage,
        const SigningProgressCallback& progress_callback) override
    {
        bool wait_for_cancel{false};
        {
            std::unique_lock lock{m_state->mutex};
            m_state->create_entered = true;
            wait_for_cancel = m_state->wait_for_cancel;
            m_state->condition.notify_all();
            if (!wait_for_cancel) {
                m_state->condition.wait(lock, [this] { return m_state->allow_create; });
            }
        }

        bool cancel_observed{false};
        if (wait_for_cancel) {
            while (true) {
                {
                    std::lock_guard lock{m_state->mutex};
                    if (m_state->allow_create) break;
                }
                if (progress_callback && !progress_callback(SigningProgress{
                        .phase = SigningProgressPhase::PREPARING_TRANSACTION,
                        .completed = 0,
                        .total = 1,
                        .cancellable = true,
                    })) {
                    cancel_observed = true;
                    break;
                }
                std::unique_lock lock{m_state->mutex};
                m_state->condition.wait_for(lock, 10ms, [this] { return m_state->allow_create; });
            }
        }

        {
            std::lock_guard lock{m_state->mutex};
            m_state->cancel_observed = cancel_observed;
            m_state->create_finished = true;
            m_state->create_finished_sequence = ++m_state->event_sequence;
            m_state->create_finished_time = std::chrono::steady_clock::now();
        }
        m_state->condition.notify_all();
        if (cancel_observed) {
            return util::Error{Untranslated("Transaction preparation cancelled")};
        }

        bool fail_before_reservation{false};
        bool simulate_reservation{false};
        bool create_success{true};
        {
            std::lock_guard lock{m_state->mutex};
            fail_before_reservation = m_state->create_fail_before_reservation;
            simulate_reservation = m_state->create_simulate_pqc_reservation;
            create_success = m_state->create_success;
        }
        if (fail_before_reservation) {
            return util::Error{Untranslated("Transaction preparation failed")};
        }
        if (simulate_reservation) {
            if (progress_callback) {
                progress_callback(SigningProgress{
                    .phase = SigningProgressPhase::RESERVING_PQC_COUNTERS,
                    .completed = 1,
                    .total = 1,
                    .cancellable = false,
                });
            }
            {
                std::unique_lock lock{m_state->mutex};
                m_state->create_counters_reserved = true;
                m_state->condition.notify_all();
                m_state->condition.wait(lock, [this] { return m_state->allow_create_completion; });
            }
            // Like the wallet backend, report consumed usage whether or not
            // creation succeeds once counters were reserved.
            if (pqc_usage) *pqc_usage = m_report;
        }
        if (!create_success) {
            return util::Error{Untranslated("Signing transaction failed")};
        }

        CMutableTransaction tx;
        if (!recipients.empty()) {
            tx.vout.emplace_back(recipients.front().nAmount, CScript{} << OP_TRUE);
        }
        change_pos = -1;
        fee = 1000;
        if (pqc_usage) {
            *pqc_usage = m_report;
        }
        return MakeTransactionRef(std::move(tx));
    }
    void commitTransaction(CTransactionRef, interfaces::WalletValueMap, interfaces::WalletOrderForm) override {}
    bool transactionCanBeAbandoned(const Txid&) override { return false; }
    bool abandonTransaction(const Txid&) override { return false; }
    bool transactionCanBeBumped(const Txid&) override
    {
        std::lock_guard lock{m_state->mutex};
        return m_state->bump_enabled;
    }
    bool createBumpTransaction(const Txid& txid,
        const wallet::CCoinControl&,
        std::vector<bilingual_str>& errors,
        CAmount& old_fee,
        CAmount& new_fee,
        CMutableTransaction& mtx,
        const SigningProgressCallback& progress_callback) override
    {
        std::unique_lock lock{m_state->mutex};
        m_state->bump_prepare_entered = true;
        m_state->condition.notify_all();
        const auto continue_preparation = [&] {
            if (!progress_callback || progress_callback({
                    .phase = SigningProgressPhase::PREPARING_TRANSACTION,
                    .completed = 0,
                    .total = 0,
                    .cancellable = true,
                })) {
                return true;
            }
            m_state->bump_prepare_cancel_observed = true;
            m_state->condition.notify_all();
            return false;
        };
        while (!m_state->allow_bump_prepare) {
            if (!continue_preparation()) return false;
            m_state->condition.wait_for(lock, 10ms, [this] { return m_state->allow_bump_prepare; });
        }
        if (!continue_preparation()) return false;
        if (!m_state->bump_prepare_success) {
            errors.emplace_back(Untranslated("Synthetic fee-bump preparation failed"));
            return false;
        }

        old_fee = 1000;
        new_fee = 2000;
        mtx = CMutableTransaction{};
        mtx.vin.emplace_back(COutPoint{txid, 0});
        mtx.vout.emplace_back(COIN - new_fee, CScript{} << OP_TRUE);
        return true;
    }
    bool signBumpTransaction(CMutableTransaction& mtx,
        wallet::PQCUsageReport* pqc_usage,
        const SigningProgressCallback& progress_callback) override
    {
        bool use_counters{false};
        bool external_signer{false};
        {
            std::lock_guard lock{m_state->mutex};
            m_state->bump_sign_entered = true;
            use_counters = m_state->bump_use_counters;
            external_signer = m_state->external_signer;
        }
        m_state->condition.notify_all();

        const auto report_progress = [&](SigningProgress progress) {
            if (!progress_callback || progress_callback(progress)) return true;
            std::lock_guard lock{m_state->mutex};
            m_state->bump_cancel_observed = true;
            m_state->condition.notify_all();
            return false;
        };
        while (true) {
            {
                std::lock_guard lock{m_state->mutex};
                if (m_state->allow_bump_reservation) break;
            }
            if (!report_progress({
                    .phase = SigningProgressPhase::PREPARING_TRANSACTION,
                    .completed = 0,
                    .total = 1,
                    .cancellable = true,
                })) {
                return false;
            }
            std::unique_lock lock{m_state->mutex};
            m_state->condition.wait_for(lock, 10ms, [this] { return m_state->allow_bump_reservation; });
        }

        {
            std::lock_guard lock{m_state->mutex};
            if (m_state->bump_fail_before_reservation) return false;
        }

        if (use_counters) {
            if (!report_progress({
                    .phase = SigningProgressPhase::RESERVING_PQC_COUNTERS,
                    .completed = 0,
                    .total = 1,
                    .cancellable = true,
                })) {
                return false;
            }
            {
                std::unique_lock lock{m_state->mutex};
                m_state->bump_counter_boundary_entered = true;
                m_state->condition.notify_all();
                m_state->condition.wait(lock, [this] { return m_state->allow_bump_counter_boundary; });
            }
            if (!report_progress({
                    .phase = SigningProgressPhase::RESERVING_PQC_COUNTERS,
                    .completed = 0,
                    .total = 1,
                    .cancellable = false,
                })) {
                return false;
            }
            {
                std::lock_guard lock{m_state->mutex};
                m_state->bump_counters_reserved = true;
            }
            m_state->condition.notify_all();
            report_progress({
                .phase = SigningProgressPhase::RESERVING_PQC_COUNTERS,
                .completed = 1,
                .total = 1,
                .cancellable = false,
            });
        }

        if (external_signer) {
            if (!report_progress({
                    .phase = SigningProgressPhase::SIGNING_INPUTS,
                    .completed = 0,
                    .total = 1,
                    .cancellable = true,
                })) {
                return false;
            }
            {
                std::lock_guard lock{m_state->mutex};
                m_state->external_bump_boundary_entered = true;
            }
            m_state->condition.notify_all();
            std::unique_lock lock{m_state->mutex};
            m_state->condition.wait(lock, [this] { return m_state->allow_external_bump_boundary; });
        }
        if (!report_progress({
            .phase = SigningProgressPhase::SIGNING_INPUTS,
            .completed = 0,
            .total = 1,
            .cancellable = !use_counters && !external_signer,
        })) {
            return false;
        }
        {
            std::unique_lock lock{m_state->mutex};
            m_state->condition.wait(lock, [this] { return m_state->allow_bump_sign; });
        }
        if (!use_counters && !external_signer && !report_progress({
                .phase = SigningProgressPhase::SIGNING_INPUTS,
                .completed = 0,
                .total = 1,
                .cancellable = true,
            })) {
            return false;
        }

        // Like the wallet backend, report consumed usage whether or not
        // signing succeeds once counters were reserved.
        if (pqc_usage && use_counters) *pqc_usage = m_report;
        {
            std::lock_guard lock{m_state->mutex};
            if (!m_state->bump_sign_success) return false;
        }
        mtx.vin.front().scriptWitness.stack.emplace_back(1, 1);
        report_progress({
            .phase = SigningProgressPhase::FINALIZING_TRANSACTION,
            .completed = 1,
            .total = 1,
            .cancellable = false,
        });
        return true;
    }
    bool commitBumpTransaction(const Txid&,
        CMutableTransaction&& mtx,
        std::vector<bilingual_str>& errors,
        Txid& bumped_txid) override
    {
        std::lock_guard lock{m_state->mutex};
        m_state->bump_commit_entered = true;
        if (!m_state->bump_commit_success) {
            errors.emplace_back(Untranslated(m_state->bump_commit_error));
            return false;
        }
        bumped_txid = mtx.GetHash();
        m_state->bump_committed = true;
        m_state->bump_committed_tx = mtx;
        m_state->condition.notify_all();
        return true;
    }
    // The real wallet reads transactions under its locks; tryGetTxStatus()
    // gives up instead of waiting for them.
    CTransactionRef getTx(const Txid& txid) override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        if (m_state->wallet_tx && m_state->wallet_tx->tx->GetHash() == txid) return m_state->wallet_tx->tx;
        return {};
    }
    interfaces::WalletTx getWalletTx(const Txid& txid) override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        if (m_state->wallet_tx && m_state->wallet_tx->tx->GetHash() == txid) return *m_state->wallet_tx;
        return {};
    }
    std::set<interfaces::WalletTx> getWalletTxs() override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        return {};
    }
    bool tryGetTxStatus(const Txid&, interfaces::WalletTxStatus&, int&, int64_t&) override { return false; }
    interfaces::WalletTx getWalletTxDetails(const Txid&, interfaces::WalletTxStatus&, interfaces::WalletOrderForm&, bool&, int&) override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        return {};
    }
    std::optional<common::PSBTError> fillPSBT(std::optional<int>,
        bool sign,
        bool,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete,
        wallet::PQCUsageReport* pqc_usage,
        const SigningProgressCallback& progress_callback) override
    {
        if (!sign) {
            if (n_signed) *n_signed = 1;
            {
                std::lock_guard lock{m_state->mutex};
                complete = m_state->psbt_draft_complete;
            }
            if (pqc_usage) *pqc_usage = {};
            return std::nullopt;
        }

        {
            std::lock_guard lock{m_state->mutex};
            m_state->psbt_sign_entered = true;
            m_state->psbt_sign_thread = std::this_thread::get_id();
            ++m_state->psbt_sign_calls;
        }
        m_state->condition.notify_all();

        const auto finish = [this](bool cancel_observed) {
            {
                std::lock_guard lock{m_state->mutex};
                m_state->psbt_cancel_observed = cancel_observed;
                m_state->psbt_sign_finished = true;
            }
            m_state->condition.notify_all();
        };
        const auto wait_for_stage = [this, &progress_callback](bool SyntheticWalletState::*allow,
                                                               SigningProgress progress) {
            while (true) {
                {
                    std::lock_guard lock{m_state->mutex};
                    if (m_state.get()->*allow) return true;
                }
                if (progress_callback && !progress_callback(progress) && progress.cancellable) return false;
                std::unique_lock lock{m_state->mutex};
                m_state->condition.wait_for(lock, 10ms, [this, allow] { return m_state.get()->*allow; });
            }
        };

        if (!wait_for_stage(&SyntheticWalletState::allow_psbt_reservation, SigningProgress{
                .phase = SigningProgressPhase::PREPARING_TRANSACTION,
                .completed = 0,
                .total = 1,
                .cancellable = true,
            })) {
            finish(/*cancel_observed=*/true);
            return common::PSBTError::INCOMPLETE;
        }

        bool simulate_reservation{false};
        bool fail_before_reservation{false};
        {
            std::lock_guard lock{m_state->mutex};
            simulate_reservation = m_state->psbt_simulate_pqc_reservation;
            fail_before_reservation = m_state->psbt_fail_before_reservation;
        }
        if (fail_before_reservation) {
            finish(/*cancel_observed=*/false);
            return common::PSBTError::UNSUPPORTED;
        }
        if (simulate_reservation) {
            if (progress_callback && !progress_callback(SigningProgress{
                    .phase = SigningProgressPhase::RESERVING_PQC_COUNTERS,
                    .completed = 0,
                    .total = 1,
                    .cancellable = true,
                })) {
                finish(/*cancel_observed=*/true);
                return common::PSBTError::INCOMPLETE;
            }
            {
                std::lock_guard lock{m_state->mutex};
                m_state->psbt_counters_reserved = true;
            }
            m_state->condition.notify_all();
            if (progress_callback) {
                progress_callback(SigningProgress{
                    .phase = SigningProgressPhase::RESERVING_PQC_COUNTERS,
                    .completed = 1,
                    .total = 1,
                    .cancellable = false,
                });
            }
        }

        if (!wait_for_stage(&SyntheticWalletState::allow_psbt_completion, SigningProgress{
                .phase = SigningProgressPhase::SIGNING_INPUTS,
                .completed = 0,
                .total = 1,
                .cancellable = !simulate_reservation,
            })) {
            finish(/*cancel_observed=*/true);
            return common::PSBTError::INCOMPLETE;
        }

        if (!psbtx.inputs.empty()) {
            psbtx.inputs.front().final_script_witness.stack = {{0x01}};
        }
        if (n_signed) *n_signed = psbtx.inputs.empty() ? 0 : 1;
        if (pqc_usage) *pqc_usage = m_report;
        {
            std::lock_guard lock{m_state->mutex};
            m_state->psbt_input_signed = true;
        }
        m_state->condition.notify_all();

        if (!wait_for_stage(&SyntheticWalletState::allow_psbt_post_signing, SigningProgress{
                .phase = SigningProgressPhase::SIGNING_INPUTS,
                .completed = psbtx.inputs.empty() ? 0U : 1U,
                .total = psbtx.inputs.empty() ? 0U : 1U,
                .cancellable = !simulate_reservation,
            })) {
            finish(/*cancel_observed=*/true);
            return common::PSBTError::INCOMPLETE;
        }

        bool fail{false};
        {
            std::lock_guard lock{m_state->mutex};
            fail = m_state->psbt_fail;
        }
        complete = !fail;
        finish(/*cancel_observed=*/false);
        return fail ? std::make_optional(common::PSBTError::SIGHASH_MISMATCH) : std::nullopt;
    }
    interfaces::WalletBalances getBalances() override { return {.balance = 50 * COIN}; }
    bool tryGetBalances(interfaces::WalletBalances& balances, uint256&) override
    {
        {
            std::lock_guard lock{m_state->mutex};
            if (m_state->encrypt_in_progress) return false;
        }
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return 50 * COIN; }
    CAmount getAvailableBalance(const wallet::CCoinControl&) override { return 50 * COIN; }
    bool txinIsMine(const CTxIn&) override { return false; }
    bool txoutIsMine(const CTxOut&) override { return false; }
    CAmount getDebit(const CTxIn&) override { return 0; }
    CAmount getCredit(const CTxOut&) override { return 0; }
    CoinsList listCoins() override { return {}; }
    std::vector<interfaces::WalletTxOut> getCoins(const std::vector<COutPoint>&) override { return {}; }
    CAmount getRequiredFee(unsigned int) override { return 0; }
    CAmount getMinimumFee(unsigned int, const wallet::CCoinControl&, int* returned_target, FeeReason* reason) override
    {
        if (returned_target) *returned_target = 6;
        if (reason) *reason = FeeReason::NONE;
        return 0;
    }
    unsigned int getConfirmTarget() override { return 6; }
    bool hdEnabled() override { return true; }
    bool canGetAddresses() override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        return true;
    }
    bool privateKeysDisabled() override
    {
        std::lock_guard lock{m_state->mutex};
        return m_state->private_keys_disabled;
    }
    bool taprootEnabled() override { return false; }
    bool hasExternalSigner() override
    {
        std::lock_guard lock{m_state->mutex};
        return m_state->external_signer;
    }
    OutputType getDefaultAddressType() override { return OutputType::P2MR; }
    CAmount getDefaultMaxTxFee() override { return MAX_MONEY; }
    wallet::PQCKeyValidationInfo getPQCKeyValidationInfo() const override
    {
        std::unique_lock lock{m_state->mutex};
        WaitForEncryption(lock);
        return {};
    }
    void remove() override {}
    std::unique_ptr<interfaces::Handler> handleUnload(UnloadFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleShowProgress(ShowProgressFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        {
            std::lock_guard lock{m_state->mutex};
            m_state->status_changed = std::move(fn);
        }
        std::weak_ptr<SyntheticWalletState> weak_state{m_state};
        return interfaces::MakeCleanupHandler([weak_state] {
            if (auto state = weak_state.lock()) {
                std::lock_guard lock{state->mutex};
                state->status_changed = {};
            }
        });
    }
    std::unique_ptr<interfaces::Handler> handleAddressBookChanged(AddressBookChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        uint64_t id;
        {
            std::lock_guard lock{m_state->mutex};
            id = ++m_state->transaction_changed_next_id;
            m_state->transaction_changed.emplace(id, std::move(fn));
        }
        std::weak_ptr<SyntheticWalletState> weak_state{m_state};
        return interfaces::MakeCleanupHandler([weak_state, id] {
            if (auto state = weak_state.lock()) {
                std::lock_guard lock{state->mutex};
                state->transaction_changed.erase(id);
            }
        });
    }
    std::unique_ptr<interfaces::Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        {
            std::lock_guard lock{m_state->mutex};
            m_state->can_get_addresses_changed = std::move(fn);
        }
        std::weak_ptr<SyntheticWalletState> weak_state{m_state};
        return interfaces::MakeCleanupHandler([weak_state] {
            if (auto state = weak_state.lock()) {
                std::lock_guard lock{state->mutex};
                state->can_get_addresses_changed = {};
            }
        });
    }

private:
    //! Stand in for the wallet locks that CWallet::EncryptWallet holds for
    //! the whole operation.
    void WaitForEncryption(std::unique_lock<std::mutex>& lock) const
    {
        m_state->condition.wait(lock, [this] { return !m_state->encrypt_in_progress; });
    }

    wallet::PQCUsageReport m_report;
    std::optional<interfaces::P2MRDataSignatureResult> m_p2mr_result;
    std::optional<bilingual_str> m_p2mr_error;
    std::shared_ptr<const wallet::PQCUsageReport> m_p2mr_usage;
    std::shared_ptr<SyntheticWalletState> m_state;
    const bool m_background_clone;
};

} // namespace

wallet::PQCUsageReport MakeSyntheticPQCUsageReport(const std::vector<std::pair<CPQCPubKey, uint32_t>>& key_counts)
{
    wallet::PQCUsageReport report;
    for (const auto& [pubkey, signature_count] : key_counts) {
        const uint32_t previous_count{signature_count == 0 ? 0 : signature_count - 1};
        const wallet::PQCSignatureLimitState previous_state{wallet::GetPQCSignatureLimitState(previous_count)};
        const wallet::PQCSignatureLimitState current_state{wallet::GetPQCSignatureLimitState(signature_count)};
        report.key_states.push_back({
            .pubkey = pubkey,
            .signature_count = signature_count,
            .signature_limit = PQC_MAX_SIGNATURES,
            .signatures_remaining = PQC_MAX_SIGNATURES - signature_count,
            .limit_state = current_state,
        });
        if (!report.overall_state || *report.overall_state < current_state) {
            report.overall_state = current_state;
        }
        if (current_state != previous_state) {
            report.warnings.push_back({
                .pubkey = pubkey,
                .previous_count = previous_count,
                .new_count = signature_count,
                .previous_state = previous_state,
                .current_state = current_state,
                .kind = wallet::PQCUsageWarningKind::TRANSITION,
            });
        }
    }
    return report;
}

std::unique_ptr<interfaces::Wallet> MakeSyntheticWallet(
    wallet::PQCUsageReport report,
    std::shared_ptr<SyntheticWalletState> state)
{
    return std::make_unique<SyntheticWallet>(std::move(report), std::move(state));
}

std::unique_ptr<interfaces::Wallet> MakeSyntheticWallet(
    interfaces::P2MRDataSignatureResult result,
    wallet::PQCUsageReport report)
{
    return std::make_unique<SyntheticWallet>(std::move(result), std::move(report));
}

std::unique_ptr<interfaces::Wallet> MakeSyntheticP2MRFailureWallet(
    bilingual_str error,
    wallet::PQCUsageReport report)
{
    return std::make_unique<SyntheticWallet>(std::move(error), std::move(report));
}

} // namespace qt_test
