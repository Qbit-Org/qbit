// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/syntheticwallet.h>

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

    bool encryptWallet(const SecureString&) override { return false; }
    bool isCrypted() override
    {
        std::lock_guard lock{m_state->mutex};
        return m_state->encrypted;
    }
    bool lock() override
    {
        std::lock_guard lock{m_state->mutex};
        m_state->locked = true;
        ++m_state->lock_calls;
        return true;
    }
    bool unlock(const SecureString&) override
    {
        std::lock_guard lock{m_state->mutex};
        m_state->locked = false;
        ++m_state->unlock_calls;
        return true;
    }
    bool isLocked() override
    {
        std::lock_guard lock{m_state->mutex};
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
        }
        m_state->condition.notify_all();
        if (cancel_observed) {
            return util::Error{Untranslated("Transaction preparation cancelled")};
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

        {
            std::lock_guard lock{m_state->mutex};
            if (!m_state->bump_sign_success) return false;
        }
        mtx.vin.front().scriptWitness.stack.emplace_back(1, 1);
        if (pqc_usage) *pqc_usage = m_report;
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
            errors.emplace_back(Untranslated("Original transaction changed while signing"));
            return false;
        }
        bumped_txid = mtx.GetHash();
        m_state->bump_committed = true;
        m_state->condition.notify_all();
        return true;
    }
    CTransactionRef getTx(const Txid&) override { return {}; }
    interfaces::WalletTx getWalletTx(const Txid&) override { return {}; }
    std::set<interfaces::WalletTx> getWalletTxs() override { return {}; }
    bool tryGetTxStatus(const Txid&, interfaces::WalletTxStatus&, int&, int64_t&) override { return false; }
    interfaces::WalletTx getWalletTxDetails(const Txid&, interfaces::WalletTxStatus&, interfaces::WalletOrderForm&, bool&, int&) override { return {}; }
    std::optional<common::PSBTError> fillPSBT(std::optional<int>, bool, bool, size_t*, PartiallySignedTransaction&, bool&, wallet::PQCUsageReport*) override { return std::nullopt; }
    interfaces::WalletBalances getBalances() override { return {.balance = 50 * COIN}; }
    bool tryGetBalances(interfaces::WalletBalances& balances, uint256&) override
    {
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
    bool canGetAddresses() override { return true; }
    bool privateKeysDisabled() override { return false; }
    bool taprootEnabled() override { return false; }
    bool hasExternalSigner() override
    {
        std::lock_guard lock{m_state->mutex};
        return m_state->external_signer;
    }
    OutputType getDefaultAddressType() override { return OutputType::P2MR; }
    CAmount getDefaultMaxTxFee() override { return MAX_MONEY; }
    wallet::PQCKeyValidationInfo getPQCKeyValidationInfo() const override { return {}; }
    void remove() override {}
    std::unique_ptr<interfaces::Handler> handleUnload(UnloadFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleShowProgress(ShowProgressFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleStatusChanged(StatusChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleAddressBookChanged(AddressBookChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleTransactionChanged(TransactionChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }
    std::unique_ptr<interfaces::Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn) override { return interfaces::MakeCleanupHandler([] {}); }

private:
    wallet::PQCUsageReport m_report;
    std::optional<interfaces::P2MRDataSignatureResult> m_p2mr_result;
    std::optional<bilingual_str> m_p2mr_error;
    std::shared_ptr<const wallet::PQCUsageReport> m_p2mr_usage;
    std::shared_ptr<SyntheticWalletState> m_state;
    const bool m_background_clone;
};

} // namespace

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
