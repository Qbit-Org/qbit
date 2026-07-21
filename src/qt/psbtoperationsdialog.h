// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_PSBTOPERATIONSDIALOG_H
#define QBIT_QT_PSBTOPERATIONSDIALOG_H

#include <QDialog>
#include <QPointer>
#include <QString>

#include <atomic>
#include <cstdint>
#include <memory>

#include <psbt.h>
#include <qt/clientmodel.h>
#include <qt/walletmodel.h>

class QProgressBar;
class QProgressDialog;
class QThread;
namespace wallet {
struct PQCUsageReport;
} // namespace wallet

namespace Ui {
class PSBTOperationsDialog;
}

/** Dialog showing transaction details. */
class PSBTOperationsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PSBTOperationsDialog(QWidget* parent, WalletModel* walletModel, ClientModel* clientModel);
    ~PSBTOperationsDialog();

    void openWithPSBT(PartiallySignedTransaction psbtx);

public Q_SLOTS:
    void signTransaction();
    void broadcastTransaction();
    void copyToClipboard();
    void saveTransaction();

private:
    struct SignResult;

    Ui::PSBTOperationsDialog* m_ui;
    PartiallySignedTransaction m_transaction_data;
    QPointer<WalletModel> m_wallet_model;
    ClientModel* m_client_model;
    std::unique_ptr<WalletModel::UnlockContext> m_sign_unlock_context;
    QPointer<QProgressDialog> m_sign_progress_dialog;
    QPointer<QProgressBar> m_sign_progress_bar;
    QThread* m_sign_thread{nullptr};
    uint64_t m_sign_generation{0};
    std::atomic_bool m_sign_cancel_requested{false};
    std::atomic_bool m_sign_counters_reserved{false};
    std::shared_ptr<const wallet::PQCUsageReport> m_last_sign_pqc_usage;

    enum class StatusLevel {
        INFO,
        WARN,
        ERR
    };

    size_t couldSignInputs(const PartiallySignedTransaction &psbtx);
    void updateTransactionDisplay();
    QString renderTransaction(const PartiallySignedTransaction &psbtx);
    void showStatus(const QString &msg, StatusLevel level);
    void showTransactionStatus(const PartiallySignedTransaction &psbtx);
    void signTransactionProgress(uint64_t generation, SigningProgress progress);
    void signTransactionFinished(uint64_t generation, std::shared_ptr<SignResult> result);

private Q_SLOTS:
    void cancelSignTransaction();

private:
    void clearSignProgressDialog();
    void setSigningControlsEnabled(bool enabled);
};

#endif // QBIT_QT_PSBTOPERATIONSDIALOG_H
