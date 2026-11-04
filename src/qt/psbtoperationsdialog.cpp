// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/psbtoperationsdialog.h>

#include <common/args.h>
#include <common/messages.h>
#include <core_io.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <logging.h>
#include <node/psbt.h>
#include <node/types.h>
#include <policy/policy.h>
#include <qt/qbitunits.h>
#include <qt/forms/ui_psbtoperationsdialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/pqcusageformat.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/pqc_usage.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>

#include <QCloseEvent>
#include <QMetaObject>
#include <QProgressBar>
#include <QProgressDialog>
#include <QStringList>
#include <QThread>
#include <QTimer>

using common::TransactionErrorString;
using node::AnalyzePSBT;
using node::DEFAULT_MAX_RAW_TX_FEE_RATE;
using node::PSBTAnalysis;
using node::TransactionError;

namespace {
QString AppendPQCUsageStatus(QString message, const wallet::PQCUsageReport& report, PQCSigningOutcome outcome)
{
    const QString usage{FormatPQCSigningOutcomePlain(report, outcome)};
    if (usage.isEmpty()) return message;
    return message + "\n" + usage;
}

//! English summary of the per-key usage and its warnings for the debug log.
std::string PQCUsageLogText(const wallet::PQCUsageReport& report)
{
    std::string text;
    for (const wallet::PQCUsageSnapshot& key_state : report.key_states) {
        text += strprintf(" PQC key %s: %u of %u signatures used, %u remaining, state %s.",
                          HexStr(std::span<const unsigned char>{key_state.pubkey.begin(), key_state.pubkey.end()}),
                          key_state.signature_count,
                          key_state.signature_limit,
                          key_state.signatures_remaining,
                          wallet::PQCSignatureLimitStateName(key_state.limit_state));
    }
    for (const bilingual_str& warning : wallet::FormatPQCUsageWarnings(report.warnings)) {
        text += " " + warning.original;
    }
    return text;
}

/**
 * Save a signed PSBT that its dialog can no longer show to the data
 * directory, where File > Load PSBT can open it, and describe the outcome for
 * the debug log. The PSBT itself stays out of the log, which users share.
 */
std::string SaveUnshownPSBT(const PartiallySignedTransaction& psbt) noexcept
{
    // Runs from the destructor too, so no filesystem error may escape.
    try {
        DataStream stream{};
        stream << psbt;
        const std::string stem{strprintf("unshown-psbt-%s-%d", psbt.tx->GetHash().ToString(), TicksSinceEpoch<std::chrono::seconds>(SystemClock::now()))};
        for (int attempt{0}; attempt < 100; ++attempt) {
            const fs::path path{gArgs.GetDataDirNet() / fs::u8path(attempt == 0 ? stem + ".psbt" : strprintf("%s-%d.psbt", stem, attempt))};
            if (fs::exists(path)) continue;
            std::ofstream out{path, std::ofstream::out | std::ofstream::binary};
            out << stream.str();
            out.close();
            if (out) return strprintf("The signed PSBT was saved to %s.", fs::quoted(fs::PathToString(path)));
            std::error_code ec;
            fs::remove(path, ec);
            break;
        }
    } catch (const std::exception&) {
    }
    return "The signed PSBT could not be saved to the data directory and was discarded.";
}

//! Signing progress that stays on screen until the worker reports. Escape
//! without a Cancel button would otherwise hide it while signing continues;
//! the window close button still requests cancellation through canceled().
class SigningProgressDialog final : public QProgressDialog
{
public:
    explicit SigningProgressDialog(QWidget* parent) : QProgressDialog(parent) {}

    void reject() override {}
};

std::unique_ptr<interfaces::Wallet> GetBackgroundWallet(interfaces::Node& node, const std::string& wallet_name)
{
    for (auto& wallet : node.walletLoader().getWallets()) {
        if (wallet && wallet->getWalletName() == wallet_name) {
            return std::move(wallet);
        }
    }
    return nullptr;
}
} // namespace

struct PSBTOperationsDialog::SignResult {
    PartiallySignedTransaction psbt;
    std::optional<common::PSBTError> error;
    std::string exception;
    size_t n_signed{0};
    bool complete{false};
    bool cancel_observed{false};
    wallet::PQCUsageReport pqc_usage;
    //! Set by the worker once the fields above hold its outcome.
    bool done{false};
};

PSBTOperationsDialog::PSBTOperationsDialog(
    QWidget* parent, WalletModel* wallet_model, ClientModel* client_model) : QDialog(parent, GUIUtil::dialog_flags),
                                                                             m_ui(new Ui::PSBTOperationsDialog),
                                                                             m_wallet_model(wallet_model),
                                                                             m_client_model(client_model)
{
    m_ui->setupUi(this);
    m_ui->statusBar->setWordWrap(true);

    connect(m_ui->signTransactionButton, &QPushButton::clicked, this, &PSBTOperationsDialog::signTransaction);
    connect(m_ui->broadcastTransactionButton, &QPushButton::clicked, this, &PSBTOperationsDialog::broadcastTransaction);
    connect(m_ui->copyToClipboardButton, &QPushButton::clicked, this, &PSBTOperationsDialog::copyToClipboard);
    connect(m_ui->saveButton, &QPushButton::clicked, this, &PSBTOperationsDialog::saveTransaction);

    connect(m_ui->closeButton, &QPushButton::clicked, this, &PSBTOperationsDialog::close);

    m_ui->signTransactionButton->setEnabled(false);
    m_ui->broadcastTransactionButton->setEnabled(false);
}

PSBTOperationsDialog::~PSBTOperationsDialog()
{
    m_sign_cancel_requested = true;
    clearSignProgressDialog();
    if (m_sign_thread) {
        QThread* thread = m_sign_thread;
        m_sign_thread = nullptr;
        disconnect(thread, nullptr, this, nullptr);
        thread->wait();
        delete thread;
    }
    // The worker can finish after the event loop has stopped, as at
    // application exit, and never deliver its result. Report it instead.
    if (m_pending_sign_result && m_pending_sign_result->done) logUnshownSignResult(*m_pending_sign_result);
    m_sign_unlock_context.reset();
    delete m_ui;
}

void PSBTOperationsDialog::prepareForShutdown()
{
    m_shutdown_requested = true;
    if (m_signatures_unexported) {
        LogWarning("PSBT dialog was shut down before its signed PSBT was copied, saved or broadcast. %s\n",
                   SaveUnshownPSBT(m_transaction_data));
        m_signatures_unexported = false;
    }
    // The worker honours the request only before it reserves counters, so
    // an attempt past that point finishes and is logged on completion.
    m_sign_cancel_requested = true;
    clearSignProgressDialog();
}

void PSBTOperationsDialog::reject()
{
    if (m_pending_sign_result) return;
    // Closing the dialog discards its PSBT by the user's choice, so a
    // shutdown before the deferred delete must not save it.
    m_signatures_unexported = false;
    QDialog::reject();
}

void PSBTOperationsDialog::closeEvent(QCloseEvent* event)
{
    if (m_pending_sign_result) {
        event->ignore();
        return;
    }
    QDialog::closeEvent(event);
}

void PSBTOperationsDialog::openWithPSBT(PartiallySignedTransaction psbtx)
{
    m_transaction_data = psbtx;

    bool complete = FinalizePSBT(psbtx); // Make sure all existing signatures are fully combined before checking for completeness.
    if (m_wallet_model) {
        size_t n_could_sign;
        const auto err{m_wallet_model->wallet().fillPSBT(std::nullopt, /*sign=*/false, /*bip32derivs=*/true, &n_could_sign, m_transaction_data, complete)};
        if (err) {
            showStatus(tr("Failed to load transaction: %1")
                           .arg(QString::fromStdString(PSBTErrorString(*err).translated)),
                       StatusLevel::ERR);
            return;
        }
        m_ui->signTransactionButton->setEnabled(!complete && !m_wallet_model->wallet().privateKeysDisabled() && n_could_sign > 0);
    } else {
        m_ui->signTransactionButton->setEnabled(false);
    }

    m_ui->broadcastTransactionButton->setEnabled(complete);

    updateTransactionDisplay();
}

void PSBTOperationsDialog::signTransaction()
{
    if (m_sign_thread || !m_wallet_model || m_shutdown_requested) {
        return;
    }

    m_sign_unlock_context = std::make_unique<WalletModel::UnlockContext>(m_wallet_model->requestUnlock());
    if (!m_sign_unlock_context->isValid()) {
        m_sign_unlock_context.reset();
        showStatus(tr("Cannot sign inputs while wallet is locked."), StatusLevel::WARN);
        return;
    }

    std::unique_ptr<interfaces::Wallet> wallet = m_wallet_model->wallet().clone();
    if (!wallet) {
        wallet = GetBackgroundWallet(m_wallet_model->node(), m_wallet_model->wallet().getWalletName());
    }
    if (!wallet) {
        showStatus(tr("Failed to sign transaction: Wallet is no longer loaded."), StatusLevel::ERR);
        m_sign_unlock_context.reset();
        return;
    }

    clearSignProgressDialog();
    const uint64_t generation = ++m_sign_generation;
    m_sign_cancel_requested = false;
    m_sign_counters_reserved = false;
    m_last_sign_pqc_usage.reset();
    setSigningControlsEnabled(false);

    m_sign_progress_dialog = new SigningProgressDialog(this);
    m_sign_progress_dialog->setObjectName(QStringLiteral("psbtSigningProgressDialog"));
    m_sign_progress_dialog->setWindowTitle(tr("Signing Transaction"));
    m_sign_progress_dialog->setLabelText(tr("Preparing transaction..."));
    m_sign_progress_dialog->setCancelButtonText(tr("Cancel"));
    m_sign_progress_bar = new QProgressBar(m_sign_progress_dialog);
    m_sign_progress_bar->setRange(0, 0);
    m_sign_progress_dialog->setBar(m_sign_progress_bar);
    m_sign_progress_dialog->setMinimumDuration(250);
    m_sign_progress_dialog->setAutoClose(false);
    m_sign_progress_dialog->setAutoReset(false);
    m_sign_progress_dialog->setWindowModality(Qt::ApplicationModal);
    GUIUtil::PolishProgressDialog(m_sign_progress_dialog);
    connect(m_sign_progress_dialog, &QProgressDialog::canceled, this, &PSBTOperationsDialog::cancelSignTransaction);
    QTimer::singleShot(250, m_sign_progress_dialog, [this, generation] {
        if (generation == m_sign_generation && m_sign_progress_dialog) {
            m_sign_progress_dialog->show();
        }
    });

    QPointer<PSBTOperationsDialog> dialog(this);
    std::atomic_bool* cancel_flag = &m_sign_cancel_requested;
    std::atomic_bool* counters_reserved_flag = &m_sign_counters_reserved;
    auto result = std::make_shared<SignResult>();
    result->psbt = m_transaction_data;
    m_pending_sign_result = result;
    QThread* thread = QThread::create([dialog,
                                       generation,
                                       wallet = std::move(wallet),
                                       result,
                                       cancel_flag,
                                       counters_reserved_flag]() mutable {
        SigningProgressCallback progress_callback = [dialog, generation, result, cancel_flag, counters_reserved_flag](const SigningProgress& progress) {
            if (!progress.cancellable) counters_reserved_flag->store(true);
            const bool cancellable{progress.cancellable && !counters_reserved_flag->load()};
            if (dialog) {
                QMetaObject::invokeMethod(dialog, [dialog, generation, progress] {
                    if (dialog) dialog->signTransactionProgress(generation, progress);
                }, Qt::QueuedConnection);
            }
            if (!cancellable) return true;
            if (cancel_flag->load()) {
                result->cancel_observed = true;
                return false;
            }
            return true;
        };
        try {
            result->error = wallet->fillPSBT(std::nullopt,
                                             /*sign=*/true,
                                             /*bip32derivs=*/true,
                                             &result->n_signed,
                                             result->psbt,
                                             result->complete,
                                             &result->pqc_usage,
                                             progress_callback);
        } catch (const std::exception& e) {
            result->exception = e.what();
        }
        result->done = true;
        if (!dialog) return;
        QMetaObject::invokeMethod(dialog, [dialog, generation, result] {
            if (dialog) dialog->signTransactionFinished(generation, result);
        }, Qt::QueuedConnection);
    });

    m_sign_thread = thread;
    connect(thread, &QThread::finished, this, [this, thread] {
        if (m_sign_thread == thread) {
            m_sign_thread = nullptr;
            thread->deleteLater();
        }
    });
    thread->start();
}

void PSBTOperationsDialog::signTransactionProgress(uint64_t generation, SigningProgress progress)
{
    if (generation != m_sign_generation || !m_sign_progress_dialog || !m_sign_progress_bar) return;

    if (!progress.cancellable || m_sign_counters_reserved.load()) {
        m_sign_counters_reserved = true;
        m_sign_progress_dialog->setCancelButton(nullptr);
    }
    if (m_sign_cancel_requested.load() && !m_sign_counters_reserved.load()) return;

    switch (progress.phase) {
    case SigningProgressPhase::PREPARING_TRANSACTION:
        m_sign_progress_dialog->setLabelText(tr("Preparing transaction..."));
        m_sign_progress_bar->setRange(0, 0);
        break;
    case SigningProgressPhase::RESERVING_PQC_COUNTERS:
        m_sign_progress_dialog->setLabelText(tr("Reserving signing counters..."));
        m_sign_progress_bar->setRange(0, 0);
        break;
    case SigningProgressPhase::SIGNING_INPUTS:
        if (progress.total == 0) {
            m_sign_progress_dialog->setLabelText(tr("Signing inputs..."));
            m_sign_progress_bar->setRange(0, 0);
        } else {
            progress.completed = std::min(progress.completed, progress.total);
            m_sign_progress_dialog->setLabelText(tr("Signing inputs: %1 of %2 complete...").arg(progress.completed).arg(progress.total));
            m_sign_progress_bar->setRange(0, static_cast<int>(progress.total));
            m_sign_progress_bar->setValue(static_cast<int>(progress.completed));
        }
        break;
    case SigningProgressPhase::FINALIZING_TRANSACTION:
        m_sign_progress_dialog->setLabelText(tr("Finalizing transaction..."));
        m_sign_progress_bar->setRange(0, 0);
        break;
    case SigningProgressPhase::VERIFYING_TRANSACTION:
        m_sign_progress_dialog->setLabelText(tr("Verifying transaction..."));
        if (progress.total == 0) {
            m_sign_progress_bar->setRange(0, 0);
        } else {
            progress.completed = std::min(progress.completed, progress.total);
            m_sign_progress_bar->setRange(0, static_cast<int>(progress.total));
            m_sign_progress_bar->setValue(static_cast<int>(progress.completed));
        }
        break;
    }
}

void PSBTOperationsDialog::signTransactionFinished(uint64_t generation, std::shared_ptr<SignResult> result)
{
    if (generation != m_sign_generation) return;
    ++m_sign_generation;
    m_pending_sign_result.reset();

    const bool unlock_valid{m_sign_unlock_context && m_sign_unlock_context->isValid()};
    m_sign_cancel_requested = false;
    m_sign_counters_reserved = false;
    clearSignProgressDialog();
    if (m_shutdown_requested) {
        // Every window is hidden and the wallet and client models may already
        // be deleted, so report through the debug log instead.
        logUnshownSignResult(*result);
        m_sign_unlock_context.reset();
        return;
    }
    m_last_sign_pqc_usage = std::make_shared<const wallet::PQCUsageReport>(std::move(result->pqc_usage));
    const auto show_result_status = [this](QString message, StatusLevel level) {
        showStatus(AppendPQCUsageStatus(std::move(message), *m_last_sign_pqc_usage, PQCSigningOutcome::Consumed), level);
    };
    const auto show_failure_status = [this](QString message, StatusLevel level) {
        showStatus(AppendPQCUsageStatus(std::move(message), *m_last_sign_pqc_usage, PQCSigningOutcome::FailedAfterConsumption), level);
    };

    if (result->cancel_observed && result->error == common::PSBTError::INCOMPLETE) {
        show_failure_status(tr("Transaction signing canceled."), StatusLevel::INFO);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }
    if (!result->exception.empty()) {
        show_failure_status(tr("Failed to sign transaction: %1").arg(QString::fromLocal8Bit(result->exception.c_str())), StatusLevel::ERR);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }
    if (result->error) {
        show_failure_status(tr("Failed to sign transaction: %1")
                               .arg(QString::fromStdString(PSBTErrorString(*result->error).translated)),
                           StatusLevel::ERR);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }

    // The signatures do not depend on the wallet: if it was unloaded while
    // signing, keep them so the PSBT can still be copied, saved or broadcast.
    const bool wallet_unloaded{!m_wallet_model};
    m_transaction_data = std::move(result->psbt);
    if (result->n_signed > 0) m_signatures_unexported = true;
    updateTransactionDisplay();
    setSigningControlsEnabled(true);

    QString message;
    StatusLevel level{StatusLevel::INFO};
    if (!result->complete && !unlock_valid) {
        message = tr("Cannot sign inputs while wallet is locked.");
        level = StatusLevel::WARN;
    } else if (!result->complete && result->n_signed < 1) {
        message = tr("Could not sign any more inputs.");
        level = StatusLevel::WARN;
    } else if (!result->complete) {
        message = tr("Signed %1 inputs, but more signatures are still required.").arg(result->n_signed);
    } else {
        message = tr("Signed transaction successfully. Transaction is ready to broadcast.");
        m_ui->broadcastTransactionButton->setEnabled(true);
    }
    if (wallet_unloaded) {
        message += " " + tr("The wallet was unloaded while signing.");
        level = StatusLevel::WARN;
    }
    show_result_status(message, level);
    m_sign_unlock_context.reset();
}

void PSBTOperationsDialog::logUnshownSignResult(const SignResult& result)
{
    const std::string usage{PQCUsageLogText(result.pqc_usage)};
    if (result.cancel_observed && result.error == common::PSBTError::INCOMPLETE) {
        LogInfo("PSBT signing was canceled because its dialog was shut down or destroyed.%s\n", usage);
    } else if (!result.exception.empty()) {
        LogWarning("PSBT signing failed after its dialog was shut down or destroyed: %s.%s\n", result.exception, usage);
    } else if (result.error) {
        LogWarning("PSBT signing failed after its dialog was shut down or destroyed: %s.%s\n", PSBTErrorString(*result.error).original, usage);
    } else {
        LogWarning("PSBT signing finished after its dialog was shut down or destroyed, so the result was not shown: %u input(s) signed, transaction %s.%s %s\n",
                   result.n_signed,
                   result.complete ? "complete" : "incomplete",
                   usage,
                   result.n_signed > 0 ? SaveUnshownPSBT(result.psbt) : "Nothing was signed.");
    }
}

void PSBTOperationsDialog::cancelSignTransaction()
{
    // Counters reserved: signing can no longer stop. Otherwise request
    // cancellation, which the worker can still lose to a reservation that is
    // already under way. Either way Qt has hidden the progress dialog, so show
    // it again until the worker reports.
    const bool counters_reserved{m_sign_counters_reserved.load()};
    m_sign_cancel_requested = !counters_reserved;
    if (!m_sign_progress_dialog) return;
    m_sign_progress_dialog->setCancelButton(nullptr);
    if (m_sign_progress_bar) m_sign_progress_bar->setRange(0, 0);
    m_sign_progress_dialog->setLabelText(counters_reserved ? tr("Finishing transaction signing...")
                                                           : tr("Canceling transaction signing..."));
    m_sign_progress_dialog->show();
}

void PSBTOperationsDialog::clearSignProgressDialog()
{
    if (!m_sign_progress_dialog) return;
    QProgressDialog* dialog = m_sign_progress_dialog;
    m_sign_progress_dialog = nullptr;
    m_sign_progress_bar = nullptr;
    disconnect(dialog, nullptr, this, nullptr);
    dialog->hide();
    dialog->deleteLater();
}

void PSBTOperationsDialog::setSigningControlsEnabled(bool enabled)
{
    m_ui->copyToClipboardButton->setEnabled(enabled);
    m_ui->saveButton->setEnabled(enabled);
    if (!enabled) {
        m_ui->signTransactionButton->setEnabled(false);
        m_ui->broadcastTransactionButton->setEnabled(false);
        return;
    }

    PartiallySignedTransaction finalized{m_transaction_data};
    const bool complete{FinalizePSBT(finalized)};
    const size_t n_could_sign{m_wallet_model ? couldSignInputs(m_transaction_data) : 0};
    m_ui->signTransactionButton->setEnabled(
        m_wallet_model && !complete && !m_wallet_model->wallet().privateKeysDisabled() && n_could_sign > 0);
    m_ui->broadcastTransactionButton->setEnabled(complete);
}

void PSBTOperationsDialog::broadcastTransaction()
{
    CMutableTransaction mtx;
    if (!FinalizeAndExtractPSBT(m_transaction_data, mtx)) {
        // This is never expected to fail unless we were given a malformed PSBT
        // (e.g. with an invalid signature.)
        showStatus(tr("Unknown error processing transaction."), StatusLevel::ERR);
        return;
    }

    CTransactionRef tx = MakeTransactionRef(mtx);
    std::string err_string;
    TransactionError error =
        m_client_model->node().broadcastTransaction(tx, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), err_string);

    if (error == TransactionError::OK) {
        m_signatures_unexported = false;
        showStatus(tr("Transaction broadcast successfully! Transaction ID: %1")
            .arg(QString::fromStdString(tx->GetHash().GetHex())), StatusLevel::INFO);
    } else {
        showStatus(tr("Transaction broadcast failed: %1")
            .arg(QString::fromStdString(TransactionErrorString(error).translated)), StatusLevel::ERR);
    }
}

void PSBTOperationsDialog::copyToClipboard() {
    DataStream ssTx{};
    ssTx << m_transaction_data;
    GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
    m_signatures_unexported = false;
    showStatus(tr("PSBT copied to clipboard."), StatusLevel::INFO);
}

void PSBTOperationsDialog::saveTransaction() {
    DataStream ssTx{};
    ssTx << m_transaction_data;

    QString selected_filter;
    QString filename_suggestion = "";
    bool first = true;
    for (const CTxOut& out : m_transaction_data.tx->vout) {
        if (!first) {
            filename_suggestion.append("-");
        }
        CTxDestination address;
        ExtractDestination(out.scriptPubKey, address);
        QString amount = QbitUnits::format(m_client_model->getOptionsModel()->getDisplayUnit(), out.nValue);
        QString address_str = QString::fromStdString(EncodeDestination(address));
        filename_suggestion.append(address_str + "-" + amount);
        first = false;
    }
    filename_suggestion.append(".psbt");
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Save Transaction Data"), filename_suggestion,
        //: Expanded name of the binary PSBT file format. See: BIP 174.
        tr("Partially Signed Transaction (Binary)") + QLatin1String(" (*.psbt)"), &selected_filter);
    if (filename.isEmpty()) {
        return;
    }
    std::ofstream out{filename.toLocal8Bit().data(), std::ofstream::out | std::ofstream::binary};
    out << ssTx.str();
    out.close();
    if (!out) {
        showStatus(tr("Failed to save PSBT to disk."), StatusLevel::ERR);
        return;
    }
    m_signatures_unexported = false;
    showStatus(tr("PSBT saved to disk."), StatusLevel::INFO);
}

void PSBTOperationsDialog::updateTransactionDisplay() {
    m_ui->transactionDescription->setText(renderTransaction(m_transaction_data));
    showTransactionStatus(m_transaction_data);
}

QString PSBTOperationsDialog::renderTransaction(const PartiallySignedTransaction &psbtx)
{
    QString tx_description;
    QLatin1String bullet_point(" * ");
    CAmount totalAmount = 0;
    for (const CTxOut& out : psbtx.tx->vout) {
        CTxDestination address;
        ExtractDestination(out.scriptPubKey, address);
        totalAmount += out.nValue;
        tx_description.append(bullet_point).append(tr("Sends %1 to %2")
            .arg(QbitUnits::formatWithUnit(QbitUnit::QBT, out.nValue))
            .arg(QString::fromStdString(EncodeDestination(address))));
        // Check if the address is one of ours
        if (m_wallet_model != nullptr && m_wallet_model->wallet().txoutIsMine(out)) tx_description.append(" (" + tr("own address") + ")");
        tx_description.append("<br>");
    }

    PSBTAnalysis analysis = AnalyzePSBT(psbtx);
    tx_description.append(bullet_point);
    if (!*analysis.fee) {
        // This happens if the transaction is missing input UTXO information.
        tx_description.append(tr("Unable to calculate transaction fee or total transaction amount."));
    } else {
        tx_description.append(tr("Pays transaction fee: "));
        tx_description.append(QbitUnits::formatWithUnit(QbitUnit::QBT, *analysis.fee));

        // add total amount in all subdivision units
        tx_description.append("<hr />");
        QStringList alternativeUnits;
        for (const QbitUnits::Unit u : QbitUnits::availableUnits())
        {
            if(u != m_client_model->getOptionsModel()->getDisplayUnit()) {
                alternativeUnits.append(QbitUnits::formatHtmlWithUnit(u, totalAmount));
            }
        }
        tx_description.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
            .arg(QbitUnits::formatHtmlWithUnit(m_client_model->getOptionsModel()->getDisplayUnit(), totalAmount)));
        tx_description.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
            .arg(alternativeUnits.join(" " + tr("or") + " ")));
    }

    size_t num_unsigned = CountPSBTUnsignedInputs(psbtx);
    if (num_unsigned > 0) {
        tx_description.append("<br><br>");
        tx_description.append(tr("Transaction has %1 unsigned inputs.").arg(QString::number(num_unsigned)));
    }

    return tx_description;
}

void PSBTOperationsDialog::showStatus(const QString &msg, StatusLevel level) {
    m_ui->statusBar->setText(msg);
    switch (level) {
        case StatusLevel::INFO: {
            m_ui->statusBar->setStyleSheet("QLabel { background-color : lightgreen }");
            break;
        }
        case StatusLevel::WARN: {
            m_ui->statusBar->setStyleSheet("QLabel { background-color : orange }");
            break;
        }
        case StatusLevel::ERR: {
            m_ui->statusBar->setStyleSheet("QLabel { background-color : red }");
            break;
        }
    }
    m_ui->statusBar->show();
}

size_t PSBTOperationsDialog::couldSignInputs(const PartiallySignedTransaction &psbtx) {
    if (!m_wallet_model) {
        return 0;
    }

    size_t n_signed;
    bool complete;
    const auto err{m_wallet_model->wallet().fillPSBT(std::nullopt, /*sign=*/false, /*bip32derivs=*/false, &n_signed, m_transaction_data, complete)};

    if (err) {
        return 0;
    }
    return n_signed;
}

void PSBTOperationsDialog::showTransactionStatus(const PartiallySignedTransaction &psbtx) {
    PSBTAnalysis analysis = AnalyzePSBT(psbtx);
    size_t n_could_sign = couldSignInputs(psbtx);

    switch (analysis.next) {
        case PSBTRole::UPDATER: {
            showStatus(tr("Transaction is missing some information about inputs."), StatusLevel::WARN);
            break;
        }
        case PSBTRole::SIGNER: {
            QString need_sig_text = tr("Transaction still needs signature(s).");
            StatusLevel level = StatusLevel::INFO;
            if (!m_wallet_model) {
                need_sig_text += " " + tr("(But no wallet is loaded.)");
                level = StatusLevel::WARN;
            } else if (m_wallet_model->wallet().privateKeysDisabled()) {
                need_sig_text += " " + tr("(But this wallet cannot sign transactions.)");
                level = StatusLevel::WARN;
            } else if (n_could_sign < 1) {
                need_sig_text += " " + tr("(But this wallet does not have the right keys.)"); // XXX wording
                level = StatusLevel::WARN;
            }
            showStatus(need_sig_text, level);
            break;
        }
        case PSBTRole::FINALIZER:
        case PSBTRole::EXTRACTOR: {
            showStatus(tr("Transaction is fully signed and ready for broadcast."), StatusLevel::INFO);
            break;
        }
        default: {
            showStatus(tr("Transaction status is unknown."), StatusLevel::ERR);
            break;
        }
    }
}
