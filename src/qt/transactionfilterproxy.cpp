// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionfilterproxy.h>

#include <qt/transactiontablemodel.h>
#include <qt/transactionrecord.h>

#include <algorithm>
#include <cstdlib>
#include <optional>

TransactionFilterProxy::TransactionFilterProxy(QObject* parent)
    : QSortFilterProxyModel(parent),
      m_search_string(),
      typeFilter(ALL_TYPES)
{
}

bool TransactionFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);

    int status = index.data(TransactionTableModel::StatusRole).toInt();
    if (!showInactive && status == TransactionStatus::Conflicted)
        return false;

    int type = index.data(TransactionTableModel::TypeRole).toInt();
    if (!(TYPE(type) & typeFilter))
        return false;

    qint64 amount = llabs(index.data(TransactionTableModel::AmountRole).toLongLong());
    if (amount < minAmount)
        return false;

    // The date is converted to local time, so read it only for a date range.
    if (dateFrom || dateTo) {
        QDateTime datetime = index.data(TransactionTableModel::DateRole).toDateTime();
        if (dateFrom && datetime < *dateFrom) return false;
        if (dateTo && datetime > *dateTo) return false;
    }

    // Every string contains the empty string, so an empty search accepts the
    // row without reading the address, txid and label. Of those, the txid is
    // hex-encoded and the label waits for the wallet lock, so they go last.
    if (m_search_string.isEmpty()) return true;
    return index.data(TransactionTableModel::AddressRole).toString().contains(m_search_string, Qt::CaseInsensitive) ||
           index.data(TransactionTableModel::TxHashRole).toString().contains(m_search_string, Qt::CaseInsensitive) ||
           index.data(TransactionTableModel::LabelRole).toString().contains(m_search_string, Qt::CaseInsensitive);
}

void TransactionFilterProxy::setDateRange(const std::optional<QDateTime>& from, const std::optional<QDateTime>& to)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif

    dateFrom = from;
    dateTo = to;

#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

void TransactionFilterProxy::setSearchString(const QString &search_string)
{
    if (m_search_string == search_string) return;

#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif

    m_search_string = search_string;

#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

void TransactionFilterProxy::setTypeFilter(quint32 modes)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif

    this->typeFilter = modes;

#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

void TransactionFilterProxy::setMinAmount(const CAmount& minimum)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif

    this->minAmount = minimum;

#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

void TransactionFilterProxy::setShowInactive(bool _showInactive)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif

    this->showInactive = _showInactive;

#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}
