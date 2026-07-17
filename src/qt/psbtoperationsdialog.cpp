// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/psbtoperationsdialog.h>

#include <common/messages.h>
#include <core_io.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <node/psbt.h>
#include <node/types.h>
#include <policy/policy.h>
#include <qt/qbitunits.h>
#include <qt/forms/ui_psbtoperationsdialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <wallet/pqc_usage.h>

#include <algorithm>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <QMetaObject>
#include <QProgressBar>
#include <QProgressDialog>
#include <QThread>
#include <QTimer>

using common::TransactionErrorString;
using node::AnalyzePSBT;
using node::DEFAULT_MAX_RAW_TX_FEE_RATE;
using node::PSBTAnalysis;
using node::TransactionError;

namespace {
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
    wallet::PQCUsageReport pqc_usage;
};

PSBTOperationsDialog::PSBTOperationsDialog(
    QWidget* parent, WalletModel* wallet_model, ClientModel* client_model) : QDialog(parent, GUIUtil::dialog_flags),
                                                                             m_ui(new Ui::PSBTOperationsDialog),
                                                                             m_wallet_model(wallet_model),
                                                                             m_client_model(client_model)
{
    m_ui->setupUi(this);

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
    m_sign_unlock_context.reset();
    delete m_ui;
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
    if (m_sign_thread || !m_wallet_model) {
        return;
    }

    m_sign_unlock_context = std::make_unique<WalletModel::UnlockContext>(m_wallet_model->requestUnlock());

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

    m_sign_progress_dialog = new QProgressDialog(this);
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
    QThread* thread = QThread::create([dialog,
                                       generation,
                                       wallet = std::move(wallet),
                                       psbt = m_transaction_data,
                                       cancel_flag,
                                       counters_reserved_flag]() mutable {
        auto result = std::make_shared<SignResult>();
        result->psbt = std::move(psbt);
        SigningProgressCallback progress_callback = [dialog, generation, cancel_flag, counters_reserved_flag](const SigningProgress& progress) {
            if (!progress.cancellable) counters_reserved_flag->store(true);
            const bool cancellable{progress.cancellable && !counters_reserved_flag->load()};
            if (dialog) {
                QMetaObject::invokeMethod(dialog, [dialog, generation, progress] {
                    if (dialog) dialog->signTransactionProgress(generation, progress);
                }, Qt::QueuedConnection);
            }
            if (!cancellable) return true;
            return dialog && !cancel_flag->load();
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

    const bool cancel_requested{m_sign_cancel_requested.load()};
    const bool counters_reserved{m_sign_counters_reserved.load()};
    const bool unlock_valid{m_sign_unlock_context && m_sign_unlock_context->isValid()};
    m_sign_cancel_requested = false;
    m_sign_counters_reserved = false;
    clearSignProgressDialog();
    m_last_sign_pqc_usage = std::make_shared<const wallet::PQCUsageReport>(std::move(result->pqc_usage));

    if (!m_wallet_model) {
        showStatus(tr("Failed to sign transaction: Wallet is no longer loaded."), StatusLevel::ERR);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }
    if (cancel_requested && !counters_reserved) {
        showStatus(tr("Transaction signing canceled."), StatusLevel::INFO);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }
    if (!result->exception.empty()) {
        showStatus(tr("Failed to sign transaction: %1").arg(QString::fromLocal8Bit(result->exception.c_str())), StatusLevel::ERR);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }
    if (result->error) {
        showStatus(tr("Failed to sign transaction: %1")
                       .arg(QString::fromStdString(PSBTErrorString(*result->error).translated)),
                   StatusLevel::ERR);
        m_sign_unlock_context.reset();
        setSigningControlsEnabled(true);
        return;
    }

    m_transaction_data = std::move(result->psbt);
    updateTransactionDisplay();
    setSigningControlsEnabled(true);

    if (!result->complete && !unlock_valid) {
        showStatus(tr("Cannot sign inputs while wallet is locked."), StatusLevel::WARN);
    } else if (!result->complete && result->n_signed < 1) {
        showStatus(tr("Could not sign any more inputs."), StatusLevel::WARN);
    } else if (!result->complete) {
        showStatus(tr("Signed %1 inputs, but more signatures are still required.").arg(result->n_signed),
            StatusLevel::INFO);
    } else {
        showStatus(tr("Signed transaction successfully. Transaction is ready to broadcast."),
            StatusLevel::INFO);
        m_ui->broadcastTransactionButton->setEnabled(true);
    }
    m_sign_unlock_context.reset();
}

void PSBTOperationsDialog::cancelSignTransaction()
{
    if (m_sign_counters_reserved.load()) {
        m_sign_cancel_requested = false;
        if (m_sign_progress_dialog) {
            m_sign_progress_dialog->setCancelButton(nullptr);
            if (m_sign_progress_bar) m_sign_progress_bar->setRange(0, 0);
            m_sign_progress_dialog->setLabelText(tr("Finishing transaction signing..."));
            m_sign_progress_dialog->show();
        }
        return;
    }
    m_sign_cancel_requested = true;
    if (m_sign_progress_dialog) {
        m_sign_progress_dialog->setCancelButton(nullptr);
        if (m_sign_progress_bar) m_sign_progress_bar->setRange(0, 0);
        m_sign_progress_dialog->setLabelText(tr("Canceling transaction signing..."));
    }
}

void PSBTOperationsDialog::clearSignProgressDialog()
{
    if (!m_sign_progress_dialog) return;
    QProgressDialog* dialog = m_sign_progress_dialog;
    m_sign_progress_dialog = nullptr;
    m_sign_progress_bar = nullptr;
    disconnect(dialog, nullptr, this, nullptr);
    dialog->close();
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
