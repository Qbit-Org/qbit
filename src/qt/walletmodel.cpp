// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletmodel.h>

#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/paymentserver.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/transactiontablemodel.h>

#include <common/args.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <logging.h>
#include <node/interface_ui.h>
#include <node/types.h>
#include <psbt.h>
#include <util/signing_timing.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/pqc_usage.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <vector>

#include <QDebug>
#include <QMetaObject>
#include <QMessageBox>
#include <QProgressBar>
#include <QProgressDialog>
#include <QSet>
#include <QThread>
#include <QTimer>

using wallet::CCoinControl;
using wallet::CRecipient;
using wallet::DEFAULT_DISABLE_WALLET;

struct WalletModel::BumpFeeResult {
    std::unique_ptr<interfaces::Wallet> wallet;
    Txid original_txid;
    Txid bumped_txid;
    std::vector<bilingual_str> errors;
    CAmount old_fee{0};
    CAmount new_fee{0};
    CMutableTransaction mtx;
    wallet::PQCUsageReport pqc_usage;
    bool prepared{false};
    bool signed_ok{false};
    bool committed{false};
    bool canceled{false};
};

struct WalletModel::BumpFeeProgress {
    BumpFeeProgressPhase phase{BumpFeeProgressPhase::Preparing};
    unsigned int completed{0};
    unsigned int total{0};
};

WalletModel::WalletModel(std::unique_ptr<interfaces::Wallet> wallet, ClientModel& client_model, const PlatformStyle *platformStyle, QObject *parent) :
    QObject(parent),
    m_wallet(std::move(wallet)),
    m_client_model(&client_model),
    m_node(client_model.node()),
    optionsModel(client_model.getOptionsModel()),
    timer(new QTimer(this))
{
    addressTableModel = new AddressTableModel(this);
    transactionTableModel = new TransactionTableModel(platformStyle, this);
    recentRequestsTableModel = new RecentRequestsTableModel(this);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    prepareForShutdown();
    finishBumpFeeThread();
    m_bump_fee_unlock_context.reset();
    unsubscribeFromCoreSignals();
}

void WalletModel::prepareForShutdown()
{
    m_bump_fee_cancel_requested = true;
    clearBumpFeeProgressDialog();
}

void WalletModel::startPollBalance()
{
    // Update the cached balance right away, so every view can make use of it,
    // so them don't need to waste resources recalculating it.
    pollBalanceChanged();

    // This timer will be fired repeatedly to update the balance
    // Since the QTimer::timeout is a private signal, it cannot be used
    // in the GUIUtil::ExceptionSafeConnect directly.
    connect(timer, &QTimer::timeout, this, &WalletModel::timerTimeout);
    GUIUtil::ExceptionSafeConnect(this, &WalletModel::timerTimeout, this, &WalletModel::pollBalanceChanged);
    timer->start(MODEL_UPDATE_DELAY);
}

void WalletModel::setClientModel(ClientModel* client_model)
{
    m_client_model = client_model;
    if (!m_client_model) timer->stop();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        cachedEncryptionStatus = newEncryptionStatus;
        Q_EMIT encryptionStatusChanged();
    }
    Q_EMIT pqcKeyValidationChanged();
}

void WalletModel::pollBalanceChanged()
{
    // Avoid recomputing wallet balances unless a TransactionChanged or
    // BlockTip notification was received.
    if (!fForceCheckBalanceChanged && m_cached_last_update_tip == getLastBlockProcessed()) return;

    // Try to get balances and return early if locks can't be acquired. This
    // avoids the GUI from getting stuck on periodical polls if the core is
    // holding the locks for a longer time - for example, during a wallet
    // rescan.
    interfaces::WalletBalances new_balances;
    uint256 block_hash;
    if (!m_wallet->tryGetBalances(new_balances, block_hash)) {
        return;
    }

    if (fForceCheckBalanceChanged || block_hash != m_cached_last_update_tip) {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        m_cached_last_update_tip = block_hash;

        checkBalanceChanged(new_balances);
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
{
    if (new_balances.balanceChanged(m_cached_balances)) {
        m_cached_balances = new_balances;
        Q_EMIT balanceChanged(new_balances);
    }
}

interfaces::WalletBalances WalletModel::getCachedBalance() const
{
    return m_cached_balances;
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, wallet::AddressPurpose purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

bool WalletModel::validateAddress(const QString& address) const
{
    return IsValidDestinationString(address.toStdString());
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl)
{
    return WalletModel::prepareTransaction(*m_wallet, transaction, coinControl, getCachedBalance().balance);
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(interfaces::Wallet& wallet, WalletModelTransaction& transaction, const CCoinControl& coinControl, CAmount cached_available_balance, const SigningProgressCallback& progress_callback)
{
    const bool timing_enabled{util::signing_timing::Enabled()};
    const uint64_t timing_id{timing_enabled ? util::signing_timing::CurrentOrNextId() : 0};
    const util::signing_timing::ScopedId timing_scope{timing_id};
    const auto timing_start{SteadyClock::now()};
    SteadyClock::duration validation_time{};
    SteadyClock::duration balance_time{};
    SteadyClock::duration create_transaction_time{};
    SteadyClock::duration postprocess_time{};
    unsigned int recipient_count{0};
    unsigned int output_count{0};
    CAmount fee_required{0};
    const auto log_prepare_timing = [&](StatusCode status, const char* status_label) {
        if (!timing_enabled) return;
        LogDebug(BCLog::BENCH,
            "qt-send-timing id=%llu phase=wallet_model_prepare recipients=%u outputs=%u "
            "validation_ms=%.2f balance_ms=%.2f create_transaction_ms=%.2f postprocess_ms=%.2f "
            "total_ms=%.2f fee=%lld status_code=%d status=%s\n",
            util::signing_timing::LogId(timing_id),
            recipient_count,
            output_count,
            Ticks<MillisecondsDouble>(validation_time),
            Ticks<MillisecondsDouble>(balance_time),
            Ticks<MillisecondsDouble>(create_transaction_time),
            Ticks<MillisecondsDouble>(postprocess_time),
            Ticks<MillisecondsDouble>(SteadyClock::now() - timing_start),
            static_cast<long long>(fee_required),
            static_cast<int>(status),
            status_label);
    };

    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;
    recipient_count = static_cast<unsigned int>(recipients.size());

    if(recipients.empty())
    {
        log_prepare_timing(OK, "empty");
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    const auto validation_start{SteadyClock::now()};
    for (const SendCoinsRecipient &rcp : recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;
        {   // User-entered bitcoin address / amount:
            if(!IsValidDestinationString(rcp.address.toStdString()))
            {
                validation_time = SteadyClock::now() - validation_start;
                log_prepare_timing(InvalidAddress, "invalid_address");
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                validation_time = SteadyClock::now() - validation_start;
                log_prepare_timing(InvalidAmount, "invalid_amount");
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            vecSend.emplace_back(CRecipient{DecodeDestination(rcp.address.toStdString()), rcp.amount, rcp.fSubtractFeeFromAmount});
            ++output_count;

            total += rcp.amount;
        }
    }
    validation_time = SteadyClock::now() - validation_start;
    if(setAddress.size() != nAddresses)
    {
        log_prepare_timing(DuplicateAddress, "duplicate_address");
        return DuplicateAddress;
    }

    // If no coin was manually selected, use the cached balance
    // Future: can merge this call with 'createTransaction'.
    const auto balance_start{SteadyClock::now()};
    CAmount nBalance = coinControl.HasSelected() ? wallet.getAvailableBalance(coinControl) : cached_available_balance;
    balance_time = SteadyClock::now() - balance_start;

    if(total > nBalance)
    {
        log_prepare_timing(AmountExceedsBalance, "amount_exceeds_balance");
        return AmountExceedsBalance;
    }

    try {
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        wallet::PQCUsageReport pqc_usage;

        auto& newTx = transaction.getWtx();
        transaction.setPQCUsageReport({});
        const auto create_transaction_start{SteadyClock::now()};
        const auto& res = wallet.createTransaction(vecSend,
                                                   coinControl,
                                                   /*sign=*/!wallet.privateKeysDisabled(),
                                                   nChangePosRet,
                                                   nFeeRequired,
                                                   &pqc_usage,
                                                   progress_callback);
        create_transaction_time = SteadyClock::now() - create_transaction_start;
        fee_required = nFeeRequired;
        const auto postprocess_start{SteadyClock::now()};
        newTx = res ? *res : nullptr;
        transaction.setTransactionFee(nFeeRequired);
        transaction.setPQCUsageReport(pqc_usage);
        if (fSubtractFeeFromAmount && newTx)
            transaction.reassignAmounts(nChangePosRet);
        postprocess_time = SteadyClock::now() - postprocess_start;

        if(!newTx)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                log_prepare_timing(AmountWithFeeExceedsBalance, "amount_with_fee_exceeds_balance");
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            log_prepare_timing(TransactionCreationFailed, "transaction_creation_failed");
            return SendCoinsReturn(TransactionCreationFailed, QString::fromStdString(util::ErrorString(res).translated));
        }

        // Reject absurdly high fee. (This can never happen because the
        // wallet never creates transactions with fee greater than
        // m_default_max_tx_fee. This merely a belt-and-suspenders check).
        if (nFeeRequired > wallet.getDefaultMaxTxFee()) {
            log_prepare_timing(AbsurdFee, "absurd_fee");
            return AbsurdFee;
        }
    } catch (const std::runtime_error& err) {
        // Something unexpected happened, instruct user to report this bug.
        log_prepare_timing(TransactionCreationFailed, "runtime_error");
        return SendCoinsReturn(TransactionCreationFailed, QString::fromStdString(err.what()));
    }

    log_prepare_timing(OK, "ok");
    return SendCoinsReturn(OK);
}

void WalletModel::sendCoins(WalletModelTransaction& transaction)
{
    const bool timing_enabled{util::signing_timing::Enabled()};
    const uint64_t timing_id{timing_enabled ? util::signing_timing::CurrentOrNextId() : 0};
    const util::signing_timing::ScopedId timing_scope{timing_id};
    const auto timing_start{SteadyClock::now()};
    SteadyClock::duration commit_time{};
    SteadyClock::duration address_book_time{};
    SteadyClock::duration balance_check_time{};
    const unsigned int recipient_count{static_cast<unsigned int>(transaction.getRecipients().size())};
    const auto log_send_coins_timing = [&](const char* status) {
        if (!timing_enabled) return;
        LogDebug(BCLog::BENCH,
            "qt-send-timing id=%llu phase=wallet_model_send recipients=%u "
            "commit_ms=%.2f address_book_ms=%.2f balance_check_ms=%.2f total_ms=%.2f status=%s\n",
            util::signing_timing::LogId(timing_id),
            recipient_count,
            Ticks<MillisecondsDouble>(commit_time),
            Ticks<MillisecondsDouble>(address_book_time),
            Ticks<MillisecondsDouble>(balance_check_time),
            Ticks<MillisecondsDouble>(SteadyClock::now() - timing_start),
            status);
    };

    QByteArray transaction_array; /* store serialized transaction */

    {
        std::vector<std::pair<std::string, std::string>> vOrderForm;
        for (const SendCoinsRecipient &rcp : transaction.getRecipients())
        {
            if (!rcp.message.isEmpty()) // Message from normal bitcoin:URI (bitcoin:123...?message=example)
                vOrderForm.emplace_back("Message", rcp.message.toStdString());
        }

        auto& newTx = transaction.getWtx();
        const auto commit_start{SteadyClock::now()};
        wallet().commitTransaction(newTx, /*value_map=*/{}, std::move(vOrderForm));
        commit_time = SteadyClock::now() - commit_start;

        DataStream ssTx;
        ssTx << TX_WITH_WITNESS(*newTx);
        transaction_array.append((const char*)ssTx.data(), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        {
            const auto address_book_start{SteadyClock::now()};
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = DecodeDestination(strAddress);
            std::string strLabel = rcp.label.toStdString();
            {
                // Check if we have a new address or an updated label
                std::string name;
                if (!m_wallet->getAddress(
                     dest, &name, /*purpose=*/nullptr))
                {
                    m_wallet->setAddressBook(dest, strLabel, wallet::AddressPurpose::SEND);
                }
                else if (name != strLabel)
                {
                    m_wallet->setAddressBook(dest, strLabel, {}); // {} means don't change purpose
                }
            }
            address_book_time += SteadyClock::now() - address_book_start;
        }
        Q_EMIT coinsSent(this, rcp, transaction_array);
    }

    const auto balance_check_start{SteadyClock::now()};
    checkBalanceChanged(m_wallet->getBalances()); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits
    balance_check_time = SteadyClock::now() - balance_check_start;
    log_send_coins_timing("ok");
}

OptionsModel* WalletModel::getOptionsModel() const
{
    return optionsModel;
}

AddressTableModel* WalletModel::getAddressTableModel() const
{
    return addressTableModel;
}

TransactionTableModel* WalletModel::getTransactionTableModel() const
{
    return transactionTableModel;
}

RecentRequestsTableModel* WalletModel::getRecentRequestsTableModel() const
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!m_wallet->isCrypted())
    {
        // A previous bug allowed for watchonly wallets to be encrypted (encryption keys set, but nothing is actually encrypted).
        // To avoid misrepresenting the encryption status of such wallets, we only return NoKeys for watchonly wallets that are unencrypted.
        if (m_wallet->privateKeysDisabled()) {
            return NoKeys;
        }
        return Unencrypted;
    }
    else if(m_wallet->isLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

wallet::PQCKeyValidationInfo WalletModel::getPQCKeyValidationInfo() const
{
    return m_wallet->getPQCKeyValidationInfo();
}

bool WalletModel::setWalletEncrypted(const SecureString& passphrase)
{
    return m_wallet->encryptWallet(passphrase);
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return m_wallet->lock();
    }
    else
    {
        // Unlock
        return m_wallet->unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    m_wallet->lock(); // Make sure wallet is locked before attempting pass change
    return m_wallet->changeWalletPassphrase(oldPass, newPass);
}

// Handlers for core signals
static void NotifyUnload(WalletModel* walletModel)
{
    qDebug() << "NotifyUnload";
    bool invoked = QMetaObject::invokeMethod(walletModel, "unload");
    assert(invoked);
}

static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel,
        const CTxDestination &address, const std::string &label, bool isMine,
        wallet::AddressPurpose purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(EncodeDestination(address));
    QString strLabel = QString::fromStdString(label);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + QString::number(static_cast<uint8_t>(purpose)) + " status=" + QString::number(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateAddressBook",
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(wallet::AddressPurpose, purpose),
                              Q_ARG(int, status));
    assert(invoked);
}

static void NotifyTransactionChanged(WalletModel *walletmodel, const Txid& hash, ChangeType status)
{
    Q_UNUSED(hash);
    Q_UNUSED(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
    assert(invoked);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    bool invoked = QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
    assert(invoked);
}

static void NotifyCanGetAddressesChanged(WalletModel* walletmodel)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "canGetAddressesChanged");
    assert(invoked);
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_unload = m_wallet->handleUnload(std::bind(&NotifyUnload, this));
    m_handler_status_changed = m_wallet->handleStatusChanged(std::bind(&NotifyKeyStoreStatusChanged, this));
    m_handler_address_book_changed = m_wallet->handleAddressBookChanged(std::bind(NotifyAddressBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    m_handler_transaction_changed = m_wallet->handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_show_progress = m_wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_can_get_addrs_changed = m_wallet->handleCanGetAddressesChanged(std::bind(NotifyCanGetAddressesChanged, this));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_unload->disconnect();
    m_handler_status_changed->disconnect();
    m_handler_address_book_changed->disconnect();
    m_handler_transaction_changed->disconnect();
    m_handler_show_progress->disconnect();
    m_handler_can_get_addrs_changed->disconnect();
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    // Bugs in earlier versions may have resulted in wallets with private keys disabled to become "encrypted"
    // (encryption keys are present, but not actually doing anything).
    // To avoid issues with such wallets, check if the wallet has private keys disabled, and if so, return a context
    // that indicates the wallet is not encrypted.
    if (m_wallet->privateKeysDisabled()) {
        return UnlockContext(this, /*valid=*/true, /*relock=*/false);
    }
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock)
{
}

WalletModel::UnlockContext::UnlockContext(UnlockContext&& other) noexcept:
        wallet(std::move(other.wallet)),
        valid(other.valid),
        relock(other.relock)
{
    other.wallet = nullptr;
    other.valid = false;
    other.relock = false;
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(wallet && valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

bool WalletModel::bumpFee(Txid hash)
{
    if (m_bump_fee_active) {
        Q_EMIT message(tr("Fee bump in progress"), tr("Wait for the current fee bump to finish."), CClientUIInterface::MSG_WARNING);
        return false;
    }

    std::unique_ptr<interfaces::Wallet> wallet{m_wallet->clone()};
    if (!wallet) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Wallet is no longer loaded."));
        return false;
    }

    m_bump_fee_active = true;
    startBumpFeePreparation(hash, std::move(wallet));
    return true;
}

void WalletModel::startBumpFeePreparation(Txid txid, std::unique_ptr<interfaces::Wallet> wallet)
{
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = true;

    clearBumpFeeProgressDialog();
    const uint64_t generation{++m_bump_fee_generation};
    m_bump_fee_cancel_requested = false;
    m_bump_fee_counters_reserved = false;

    m_bump_fee_progress_dialog = new QProgressDialog(nullptr);
    m_bump_fee_progress_dialog->setObjectName(QStringLiteral("bumpFeeProgressDialog"));
    m_bump_fee_progress_dialog->setWindowTitle(tr("Increasing Transaction Fee"));
    m_bump_fee_progress_dialog->setLabelText(tr("Preparing fee-bump transaction..."));
    m_bump_fee_progress_dialog->setCancelButtonText(tr("Cancel"));
    m_bump_fee_progress_bar = new QProgressBar(m_bump_fee_progress_dialog);
    m_bump_fee_progress_bar->setRange(0, 0);
    m_bump_fee_progress_dialog->setBar(m_bump_fee_progress_bar);
    m_bump_fee_progress_dialog->setMinimumDuration(250);
    m_bump_fee_progress_dialog->setAutoClose(false);
    m_bump_fee_progress_dialog->setAutoReset(false);
    m_bump_fee_progress_dialog->setWindowModality(Qt::ApplicationModal);
    GUIUtil::PolishProgressDialog(m_bump_fee_progress_dialog);
    connect(m_bump_fee_progress_dialog, &QProgressDialog::canceled, this, &WalletModel::cancelBumpFee);
    QPointer<QProgressDialog> progress_dialog{m_bump_fee_progress_dialog};
    QTimer::singleShot(250, this, [this, generation, progress_dialog] {
        if (generation == m_bump_fee_generation && progress_dialog && progress_dialog == m_bump_fee_progress_dialog) {
            progress_dialog->show();
        }
    });

    auto result{std::make_shared<BumpFeeResult>()};
    result->wallet = std::move(wallet);
    result->original_txid = txid;
    QPointer<WalletModel> model{this};
    std::atomic_bool* cancel_flag{&m_bump_fee_cancel_requested};
    m_bump_fee_thread = QThread::create([model, generation, result, coin_control, cancel_flag] {
        const SigningProgressCallback progress_callback = [cancel_flag](const SigningProgress&) {
            return !cancel_flag->load();
        };
        try {
            result->prepared = result->wallet->createBumpTransaction(
                result->original_txid,
                coin_control,
                result->errors,
                result->old_fee,
                result->new_fee,
                result->mtx,
                progress_callback);
        } catch (const std::exception& e) {
            result->errors.emplace_back(Untranslated(e.what()));
        }
        result->canceled = cancel_flag->load();
        if (!model) return;
        QMetaObject::invokeMethod(model, [model, generation, result] {
            if (model) model->bumpFeePrepared(generation, result);
        }, Qt::QueuedConnection);
    });
    m_bump_fee_thread->start();
}

void WalletModel::bumpFeePrepared(uint64_t generation, std::shared_ptr<BumpFeeResult> result)
{
    if (generation != m_bump_fee_generation) return;
    finishBumpFeeThread();
    clearBumpFeeProgressDialog();

    if (result->canceled || m_bump_fee_cancel_requested.load()) {
        resetBumpFeeState();
        return;
    }
    if (!result->prepared) {
        const QString error{result->errors.empty() ? QString{} : QString::fromStdString(result->errors.front().translated)};
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Increasing transaction fee failed") + "<br />(" + error + ")");
        resetBumpFeeState();
        return;
    }

    // allow a user based fee verification
    /*: Asks a user if they would like to manually increase the fee of a transaction that has already been created. */
    QString questionString = tr("Do you want to increase the fee?");
    questionString.append("<br />");
    questionString.append("<table style=\"text-align: left;\">");
    questionString.append("<tr><td>");
    questionString.append(tr("Current fee:"));
    questionString.append("</td><td>");
    questionString.append(QbitUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), result->old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("Increase:"));
    questionString.append("</td><td>");
    questionString.append(QbitUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), result->new_fee - result->old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("New fee:"));
    questionString.append("</td><td>");
    questionString.append(QbitUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), result->new_fee));
    questionString.append("</td></tr></table>");

    // Display warning in the "Confirm fee bump" window if the "Coin Control Features" option is enabled
    if (getOptionsModel()->getCoinControlFeatures()) {
        questionString.append("<br><br>");
        questionString.append(tr("Warning: This may pay the additional fee by reducing change outputs or adding inputs, when necessary. It may add a new change output if one does not already exist. These changes may potentially leak privacy."));
    }

    const bool enable_send{!wallet().privateKeysDisabled() || wallet().hasExternalSigner()};
    const bool always_show_unsigned{getOptionsModel()->getEnablePSBTControls()};
    auto confirmationDialog = new SendConfirmationDialog(tr("Confirm fee bump"), questionString, "", "", SEND_CONFIRM_DELAY, enable_send, always_show_unsigned, nullptr);
    confirmationDialog->setAttribute(Qt::WA_DeleteOnClose);
    // TODO: Replace QDialog::exec() with safer QDialog::show().
    const auto retval = static_cast<QMessageBox::StandardButton>(confirmationDialog->exec());

    if (generation != m_bump_fee_generation || m_bump_fee_cancel_requested.load()) {
        resetBumpFeeState();
        return;
    }

    // cancel sign&broadcast if user doesn't want to bump the fee
    if (retval != QMessageBox::Yes && retval != QMessageBox::Save) {
        resetBumpFeeState();
        return;
    }

    // Short-circuit if we are returning a bumped transaction PSBT to clipboard
    if (retval == QMessageBox::Save) {
        // "Create Unsigned" clicked
        PartiallySignedTransaction psbtx(result->mtx);
        bool complete = false;
        const auto err{result->wallet->fillPSBT(std::nullopt, /*sign=*/false, /*bip32derivs=*/true, nullptr, psbtx, complete)};
        if (err || complete) {
            QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't draft transaction."));
            resetBumpFeeState();
            return;
        }
        // Serialize the PSBT
        DataStream ssTx{};
        ssTx << psbtx;
        GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
        Q_EMIT message(tr("PSBT copied"), tr("Fee-bump PSBT copied to clipboard"), CClientUIInterface::MSG_INFORMATION | CClientUIInterface::MODAL);
        resetBumpFeeState();
        return;
    }

    m_bump_fee_unlock_context = std::make_unique<WalletModel::UnlockContext>(requestUnlock());
    if (!m_bump_fee_unlock_context->isValid()) {
        resetBumpFeeState();
        return;
    }
    if (generation != m_bump_fee_generation || m_bump_fee_cancel_requested.load()) {
        resetBumpFeeState();
        return;
    }

    assert(!m_wallet->privateKeysDisabled() || wallet().hasExternalSigner());

    startBumpFeeSigning(generation, std::move(result));
}

void WalletModel::startBumpFeeSigning(uint64_t generation, std::shared_ptr<BumpFeeResult> result)
{
    if (generation != m_bump_fee_generation || m_bump_fee_cancel_requested.load()) {
        resetBumpFeeState();
        return;
    }
    clearBumpFeeProgressDialog();
    m_bump_fee_counters_reserved = false;

    m_bump_fee_progress_dialog = new QProgressDialog(nullptr);
    m_bump_fee_progress_dialog->setObjectName(QStringLiteral("bumpFeeProgressDialog"));
    m_bump_fee_progress_dialog->setWindowTitle(tr("Increasing Transaction Fee"));
    m_bump_fee_progress_dialog->setLabelText(tr("Preparing transaction for signing..."));
    m_bump_fee_progress_dialog->setCancelButtonText(tr("Cancel"));
    m_bump_fee_progress_bar = new QProgressBar(m_bump_fee_progress_dialog);
    m_bump_fee_progress_bar->setRange(0, 0);
    m_bump_fee_progress_dialog->setBar(m_bump_fee_progress_bar);
    m_bump_fee_progress_dialog->setMinimumDuration(250);
    m_bump_fee_progress_dialog->setAutoClose(false);
    m_bump_fee_progress_dialog->setAutoReset(false);
    m_bump_fee_progress_dialog->setWindowModality(Qt::ApplicationModal);
    GUIUtil::PolishProgressDialog(m_bump_fee_progress_dialog);
    connect(m_bump_fee_progress_dialog, &QProgressDialog::canceled, this, &WalletModel::cancelBumpFee);
    QPointer<QProgressDialog> progress_dialog{m_bump_fee_progress_dialog};
    QTimer::singleShot(250, this, [this, generation, progress_dialog] {
        if (generation == m_bump_fee_generation && progress_dialog && progress_dialog == m_bump_fee_progress_dialog) {
            progress_dialog->show();
        }
    });

    QPointer<WalletModel> model{this};
    std::atomic_bool* cancel_flag{&m_bump_fee_cancel_requested};
    std::atomic_bool* counters_reserved_flag{&m_bump_fee_counters_reserved};
    m_bump_fee_thread = QThread::create([model, generation, result, cancel_flag, counters_reserved_flag] {
        const auto post_progress = [model, generation, cancel_flag](BumpFeeProgress progress, bool cancellable) {
            if (!model || (cancellable && cancel_flag->load())) return false;
            QMetaObject::invokeMethod(model, [model, generation, progress] {
                if (model) model->bumpFeeProgress(generation, progress);
            }, Qt::QueuedConnection);
            return !cancellable || !cancel_flag->load();
        };
        const SigningProgressCallback progress_callback = [post_progress, counters_reserved_flag](const SigningProgress& progress) {
            if (!progress.cancellable) counters_reserved_flag->store(true);
            bool cancellable{progress.cancellable && !counters_reserved_flag->load()};
            BumpFeeProgress mapped;
            mapped.completed = progress.completed;
            mapped.total = progress.total;
            switch (progress.phase) {
            case SigningProgressPhase::PREPARING_TRANSACTION:
                mapped.phase = BumpFeeProgressPhase::Preparing;
                break;
            case SigningProgressPhase::RESERVING_PQC_COUNTERS:
                mapped.phase = BumpFeeProgressPhase::Reserving;
                if (progress.total > 0 && progress.completed >= progress.total) {
                    counters_reserved_flag->store(true);
                    cancellable = false;
                }
                break;
            case SigningProgressPhase::SIGNING_INPUTS:
                mapped.phase = BumpFeeProgressPhase::Signing;
                break;
            case SigningProgressPhase::FINALIZING_TRANSACTION:
                mapped.phase = BumpFeeProgressPhase::Finalizing;
                break;
            }
            return post_progress(mapped, cancellable);
        };

        try {
            result->signed_ok = result->wallet->signBumpTransaction(result->mtx, &result->pqc_usage, progress_callback);
            if (cancel_flag->load() && !counters_reserved_flag->load()) {
                result->canceled = true;
            } else if (result->signed_ok) {
                post_progress(BumpFeeProgress{.phase = BumpFeeProgressPhase::Committing}, /*cancellable=*/false);
                result->committed = result->wallet->commitBumpTransaction(
                    result->original_txid, std::move(result->mtx), result->errors, result->bumped_txid);
            }
        } catch (const std::exception& e) {
            result->errors.emplace_back(Untranslated(e.what()));
        }

        if (!model) return;
        QMetaObject::invokeMethod(model, [model, generation, result] {
            if (model) model->bumpFeeFinished(generation, result);
        }, Qt::QueuedConnection);
    });
    m_bump_fee_thread->start();
}

void WalletModel::bumpFeeProgress(uint64_t generation, BumpFeeProgress progress)
{
    if (generation != m_bump_fee_generation || !m_bump_fee_progress_dialog || !m_bump_fee_progress_bar) return;

    QPointer<QProgressDialog> dialog{m_bump_fee_progress_dialog};
    QPointer<QProgressBar> bar{m_bump_fee_progress_bar};
    if (!dialog || !bar) return;
    if (m_bump_fee_counters_reserved.load()) {
        dialog->setCancelButton(nullptr);
        if (!dialog || !bar) return;
    }

    switch (progress.phase) {
    case BumpFeeProgressPhase::Preparing:
        dialog->setLabelText(tr("Preparing transaction for signing..."));
        if (!dialog || !bar) return;
        bar->setRange(0, 0);
        break;
    case BumpFeeProgressPhase::Reserving:
        dialog->setLabelText(tr("Reserving signing counters..."));
        if (!dialog || !bar) return;
        bar->setRange(0, 0);
        break;
    case BumpFeeProgressPhase::Signing:
        if (progress.total == 0) {
            dialog->setLabelText(tr("Signing inputs..."));
            if (!dialog || !bar) return;
            bar->setRange(0, 0);
        } else {
            progress.completed = std::min(progress.completed, progress.total);
            dialog->setLabelText(tr("Signing inputs: %1 of %2 complete...").arg(progress.completed).arg(progress.total));
            if (!dialog || !bar) return;
            bar->setRange(0, static_cast<int>(progress.total));
            if (!bar) return;
            bar->setValue(static_cast<int>(progress.completed));
        }
        break;
    case BumpFeeProgressPhase::Finalizing:
        dialog->setLabelText(tr("Finalizing transaction..."));
        if (!dialog || !bar) return;
        bar->setRange(0, 0);
        break;
    case BumpFeeProgressPhase::Committing:
        dialog->setLabelText(tr("Committing fee-bump transaction..."));
        if (!dialog || !bar) return;
        bar->setRange(0, 0);
        break;
    }
}

void WalletModel::bumpFeeFinished(uint64_t generation, std::shared_ptr<BumpFeeResult> result)
{
    if (generation != m_bump_fee_generation) return;
    finishBumpFeeThread();
    clearBumpFeeProgressDialog();
    m_bump_fee_unlock_context.reset();

    if (result->canceled) {
        resetBumpFeeState();
        return;
    }
    if (!result->signed_ok) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't sign transaction."));
        resetBumpFeeState();
        return;
    }
    if (!result->committed) {
        const QString error{result->errors.empty() ? QString{} : QString::fromStdString(result->errors.front().translated)};
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Could not commit transaction") + "<br />(" + error + ")");
        resetBumpFeeState();
        return;
    }

    const Txid original_txid{result->original_txid};
    const Txid bumped_txid{result->bumped_txid};
    resetBumpFeeState();
    Q_EMIT feeBumped(original_txid, bumped_txid);
}

void WalletModel::cancelBumpFee()
{
    if (m_bump_fee_counters_reserved.load()) {
        m_bump_fee_cancel_requested = false;
        if (m_bump_fee_progress_dialog) {
            m_bump_fee_progress_dialog->setCancelButton(nullptr);
            m_bump_fee_progress_dialog->setLabelText(tr("Finalizing transaction..."));
        }
        return;
    }
    m_bump_fee_cancel_requested = true;
    if (m_bump_fee_progress_dialog) {
        m_bump_fee_progress_dialog->setCancelButton(nullptr);
        m_bump_fee_progress_dialog->setLabelText(tr("Canceling fee bump..."));
        if (m_bump_fee_progress_bar) m_bump_fee_progress_bar->setRange(0, 0);
    }
}

void WalletModel::clearBumpFeeProgressDialog()
{
    if (!m_bump_fee_progress_dialog) return;
    QProgressDialog* dialog{m_bump_fee_progress_dialog};
    m_bump_fee_progress_dialog = nullptr;
    m_bump_fee_progress_bar = nullptr;
    disconnect(dialog, nullptr, this, nullptr);
    dialog->close();
    dialog->deleteLater();
}

void WalletModel::finishBumpFeeThread()
{
    if (!m_bump_fee_thread) return;
    QThread* thread{m_bump_fee_thread};
    m_bump_fee_thread = nullptr;
    thread->wait();
    delete thread;
}

void WalletModel::resetBumpFeeState()
{
    ++m_bump_fee_generation;
    m_bump_fee_active = false;
    m_bump_fee_cancel_requested = false;
    m_bump_fee_counters_reserved = false;
    clearBumpFeeProgressDialog();
    m_bump_fee_unlock_context.reset();
}

void WalletModel::displayAddress(std::string sAddress) const
{
    CTxDestination dest = DecodeDestination(sAddress);
    try {
        util::Result<void> result = m_wallet->displayAddress(dest);
        if (!result) {
            QMessageBox::warning(nullptr, tr("Signer error"), QString::fromStdString(util::ErrorString(result).translated));
        }
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Can't display address"), e.what());
    }
}

bool WalletModel::isWalletEnabled()
{
   return !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

QString WalletModel::getWalletName() const
{
    return QString::fromStdString(m_wallet->getWalletName());
}

QString WalletModel::getDisplayName() const
{
    return GUIUtil::WalletDisplayName(getWalletName());
}

bool WalletModel::isMultiwallet() const
{
    return m_node.walletLoader().getWallets().size() > 1;
}

void WalletModel::refresh(bool pk_hash_only)
{
    addressTableModel = new AddressTableModel(this, pk_hash_only);
}

uint256 WalletModel::getLastBlockProcessed() const
{
    return m_client_model ? m_client_model->getBestBlockHash() : uint256{};
}

CAmount WalletModel::getAvailableBalance(const CCoinControl* control)
{
    // No selected coins, return the cached balance
    if (!control || !control->HasSelected()) {
        const interfaces::WalletBalances& balances = getCachedBalance();
        return balances.balance;
    }
    // Fetch balance from the wallet, taking into account the selected coins
    return wallet().getAvailableBalance(*control);
}
