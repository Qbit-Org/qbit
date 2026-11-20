// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_ADDRESSTABLEMODEL_H
#define QBIT_QT_ADDRESSTABLEMODEL_H

#include <optional>

#include <QAbstractTableModel>
#include <QStringList>

enum class OutputType;

class AddressTablePriv;
class WalletModel;

namespace interfaces {
class Wallet;
struct WalletAddress;
}
namespace wallet {
enum class AddressPurpose;
} // namespace wallet

/**
   Qt model of the address book in the core. This allows views to access and modify the address book.
 */
class AddressTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit AddressTableModel(WalletModel *parent = nullptr, bool pk_hash_only = false);
    ~AddressTableModel();

    enum ColumnIndex {
        Label = 0,   /**< User specified label */
        Address = 1  /**< Bitcoin address */
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of address (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_ADDRESS,        /**< Unparseable address */
        DUPLICATE_ADDRESS,      /**< Address already in address book */
        WALLET_UNLOCK_FAILURE,  /**< Wallet could not be unlocked to create new receiving address */
        KEY_GENERATION_FAILURE  /**< Generating a new public key for a receiving address failed */
    };

    static const QString Send;      /**< Specifies send address */
    static const QString Receive;   /**< Specifies receive address */

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const override;
    int columnCount(const QModelIndex &parent) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    bool setData(const QModelIndex &index, const QVariant &value, int role) override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    QModelIndex index(int row, int column, const QModelIndex &parent) const override;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    /*@}*/

    /* Add an address to the model.
       Returns the added address on success, and an empty string otherwise.
     */
    QString addRow(const QString &type, const QString &label, const QString &address, const OutputType address_type);

    /** Look up label for address in address book, if not found return empty string. */
    QString labelForAddress(const QString &address) const;

    /** Look up label for address in this model's rows, without reading the
        wallet. If not found return empty string. The rows follow the
        wallet's address book notifications, so the answer lags the wallet
        until those are delivered: use it to show a label, as the transaction
        list does on every repaint and filter pass, not to decide what to
        write. */
    QString cachedLabelForAddress(const QString &address) const;

    /** Look up purpose for address in address book, if not found return empty string. */
    std::optional<wallet::AddressPurpose> purposeForAddress(const QString &address) const;

    /** The status (a ChangeType) updateEntry() needs to make this model's
        row for an encoded address show entry, the address book entry the
        wallet lists for it, or to remove the row if entry is null.
        std::nullopt if the row already shows it: same label and type, or no
        row and no entry. */
    std::optional<int> changeToEntry(const QString &address, const interfaces::WalletAddress* entry) const;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    int lookupAddress(const QString &address) const;

    EditStatus getEditStatus() const { return editStatus; }

    OutputType GetDefaultAddressType() const;

    QString GetWalletDisplayName() const;

private:
    WalletModel* const walletModel;
    AddressTablePriv *priv = nullptr;
    QStringList columns;
    EditStatus editStatus = OK;

    /** Look up address book data given an address string. Answered from the
        cached rows while the wallet is being encrypted, as the wallet would
        block on its locks until the encryption finishes. */
    bool getAddressData(const QString &address, std::string* name, wallet::AddressPurpose* purpose) const;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, bool isMine, wallet::AddressPurpose purpose, int status);

    friend class AddressTablePriv;
};

#endif // QBIT_QT_ADDRESSTABLEMODEL_H
