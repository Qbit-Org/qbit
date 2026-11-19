// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TRANSACTIONTABLEMODEL_H
#define QBIT_QT_TRANSACTIONTABLEMODEL_H

#include <qt/qbitunits.h>

#include <QAbstractTableModel>
#include <QStringList>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace interfaces {
class Handler;
}

class AddressTableModel;
class PlatformStyle;
class TransactionRecord;
class TransactionTablePriv;
class WalletModel;

/** UI model for the transaction table of a wallet.
 */
class TransactionTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit TransactionTableModel(const PlatformStyle *platformStyle, WalletModel *parent = nullptr);
    ~TransactionTableModel();

    enum ColumnIndex {
        Status = 0,
        Date = 1,
        Type = 2,
        ToAddress = 3,
        Amount = 4
    };

    /** Roles to get specific information from a transaction row.
        These are independent of column.
    */
    enum RoleIndex {
        /** Type of transaction */
        TypeRole = Qt::UserRole,
        /** Date and time this transaction was created */
        DateRole,
        /** Long description (HTML format) */
        LongDescriptionRole,
        /** Address of transaction */
        AddressRole,
        /** Label of address related to transaction */
        LabelRole,
        /** Net amount of transaction */
        AmountRole,
        /** Transaction hash */
        TxHashRole,
        /** Transaction data, hex-encoded */
        TxHexRole,
        /** Whole transaction as plain text */
        TxPlainTextRole,
        /** Is transaction confirmed? */
        ConfirmedRole,
        /** Formatted amount, without brackets when unconfirmed */
        FormattedAmountRole,
        /** Transaction status (TransactionRecord::Status) */
        StatusRole,
        /** Unprocessed icon */
        RawDecorationRole,
    };

    int rowCount(const QModelIndex &parent) const override;
    int columnCount(const QModelIndex &parent) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    QModelIndex index(int row, int column, const QModelIndex & parent = QModelIndex()) const override;
    bool processingQueuedTransactions() const { return fProcessingQueuedTransactions; }
    /** Replay, in arrival order, the updates held back while the wallet was
        being encrypted. Called by the wallet model once the encryption has
        released the wallet, whoever started it. */
    void deliverDeferredUpdates();
    /** The address book entry for an encoded address was added, changed or
        removed. Rows show labels from an address table model, so views are
        notified of the rows that show this address, in one signal for the
        address column from the first such row to the last. That happens in
        one pass for every address changed meanwhile, once control has
        returned to the event loop: this is called from the wallet's
        notification, which holds the wallet lock when the change was made
        on this thread. Called by the wallet model once its address table
        models have the update. */
    void updateAddressLabel(const QString &address);
    /** Number of label passes over the rows so far, for tests. */
    uint64_t labelPassCount() const { return m_label_passes; }

private:
    WalletModel *walletModel;
    /** The address table model the rows read their labels from: the one the
        wallet model was created with, which lists every address. The wallet
        model keeps it current, also after WalletModel::refresh() has handed
        out one that lists only legacy addresses. */
    AddressTableModel* const m_address_table_model;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    std::unique_ptr<interfaces::Handler> m_handler_show_progress;
    QStringList columns;
    TransactionTablePriv *priv;
    bool fProcessingQueuedTransactions{false};
    /** Transaction updates and balloon-limit changes received from the event
        loop while the wallet was being encrypted. Applying an update reads
        the wallet, which blocks while the encryption holds its locks,
        so they wait here for deliverDeferredUpdates(). */
    std::vector<std::function<void()>> m_deferred_updates;
    /** Encoded addresses whose address book entry changed since the last
        label pass, and whether the next pass is queued. */
    std::unordered_set<std::string> m_changed_labels;
    bool m_label_pass_queued{false};
    uint64_t m_label_passes{0};
    /** Counts insertions and removals of rows, so that a label pass whose
        listeners change the rows can tell that its row numbers are stale. */
    uint64_t m_row_changes{0};
    const PlatformStyle *platformStyle;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    QString lookupAddress(const std::string &address, bool tooltip) const;
    QVariant addressColor(const TransactionRecord *wtx) const;
    QString formatTxStatus(const TransactionRecord *wtx) const;
    QString formatTxDate(const TransactionRecord *wtx) const;
    QString formatTxType(const TransactionRecord *wtx) const;
    QString formatTxToAddress(const TransactionRecord *wtx, bool tooltip) const;
    QString formatTxAmount(const TransactionRecord *wtx, bool showUnconfirmed=true, QbitUnits::SeparatorStyle separators=QbitUnits::SeparatorStyle::STANDARD) const;
    QString formatTooltip(const TransactionRecord *rec) const;
    QVariant txStatusDecoration(const TransactionRecord *wtx) const;
    QVariant txAddressDecoration(const TransactionRecord *wtx) const;
    void queueLabelPass();
    void updateChangedLabels();

public Q_SLOTS:
    /* New transaction, or transaction changed status */
    void updateTransaction(const QString &hash, int status, bool showTransaction);
    void updateConfirmations();
    void updateDisplayUnit();
    /** Updates the column title to "Amount (DisplayUnit)" and emits headerDataChanged() signal for table headers to react. */
    void updateAmountColumnTitle();
    /* Needed to update fProcessingQueuedTransactions through a QueuedConnection */
    void setProcessingQueuedTransactions(bool value);

    friend class TransactionTablePriv;
};

#endif // QBIT_QT_TRANSACTIONTABLEMODEL_H
