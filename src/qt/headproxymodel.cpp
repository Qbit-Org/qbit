// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/headproxymodel.h>

#include <algorithm>

HeadProxyModel::HeadProxyModel(int limit, QObject* parent)
    : QAbstractProxyModel(parent), m_limit{std::max(limit, 0)}
{
}

HeadProxyModel::~HeadProxyModel() = default;

void HeadProxyModel::setSourceModel(QAbstractItemModel* source_model)
{
    if (source_model == sourceModel()) return;

    finishPendingChange();
    // A slot on the old source's modelAboutToBeReset can replace the source
    // while the proxy's own reset is open: end that reset here, once.
    if (!m_resetting) beginResetModel();
    for (const auto& connection : m_source_connections) disconnect(connection);
    m_source_connections.clear();
    m_resetting = false;

    QAbstractProxyModel::setSourceModel(source_model);

    if (source_model) {
        m_source_connections = {
            connect(source_model, &QAbstractItemModel::rowsAboutToBeInserted, this, &HeadProxyModel::sourceRowsAboutToBeInserted),
            connect(source_model, &QAbstractItemModel::rowsInserted, this, &HeadProxyModel::sourceRowsInserted),
            connect(source_model, &QAbstractItemModel::rowsAboutToBeRemoved, this, &HeadProxyModel::sourceRowsAboutToBeRemoved),
            connect(source_model, &QAbstractItemModel::rowsRemoved, this, &HeadProxyModel::sourceRowsRemoved),
            // A move can carry rows into and out of the head, or change the
            // number of top-level rows, which the proxy reports as a change of
            // layout.
            connect(source_model, &QAbstractItemModel::rowsAboutToBeMoved, this,
                    [this](const QModelIndex& source_parent, int first, int, const QModelIndex& destination_parent, int destination) {
                        if (source_parent.isValid() && destination_parent.isValid()) return;
                        if (!source_parent.isValid() && !destination_parent.isValid() && first >= m_limit && destination >= m_limit) return;
                        sourceLayoutAboutToBeChanged(QAbstractItemModel::NoLayoutChangeHint);
                    }),
            connect(source_model, &QAbstractItemModel::rowsMoved, this,
                    [this] { sourceLayoutChanged(QAbstractItemModel::NoLayoutChangeHint); }),
            connect(source_model, &QAbstractItemModel::layoutAboutToBeChanged, this,
                    [this](const QList<QPersistentModelIndex>&, QAbstractItemModel::LayoutChangeHint hint) { sourceLayoutAboutToBeChanged(hint); }),
            connect(source_model, &QAbstractItemModel::layoutChanged, this,
                    [this](const QList<QPersistentModelIndex>&, QAbstractItemModel::LayoutChangeHint hint) { sourceLayoutChanged(hint); }),
            connect(source_model, &QAbstractItemModel::dataChanged, this, &HeadProxyModel::sourceDataChanged),
            connect(source_model, &QAbstractItemModel::headerDataChanged, this, &HeadProxyModel::sourceHeaderDataChanged),
            connect(source_model, &QAbstractItemModel::modelAboutToBeReset, this, &HeadProxyModel::sourceAboutToBeReset),
            connect(source_model, &QAbstractItemModel::modelReset, this, &HeadProxyModel::sourceReset),
            // Columns do not change in the models this proxy is used with, so
            // a change of columns resets it instead of being translated.
            connect(source_model, &QAbstractItemModel::columnsAboutToBeInserted, this, &HeadProxyModel::sourceAboutToBeReset),
            connect(source_model, &QAbstractItemModel::columnsInserted, this, &HeadProxyModel::sourceReset),
            connect(source_model, &QAbstractItemModel::columnsAboutToBeRemoved, this, &HeadProxyModel::sourceAboutToBeReset),
            connect(source_model, &QAbstractItemModel::columnsRemoved, this, &HeadProxyModel::sourceReset),
            connect(source_model, &QAbstractItemModel::columnsAboutToBeMoved, this, &HeadProxyModel::sourceAboutToBeReset),
            connect(source_model, &QAbstractItemModel::columnsMoved, this, &HeadProxyModel::sourceReset),
            connect(source_model, &QObject::destroyed, this, &HeadProxyModel::sourceDestroyed),
        };
    }

    m_rows = targetRows();
    endResetModel();
}

QModelIndex HeadProxyModel::index(int row, int column, const QModelIndex& parent) const
{
    if (parent.isValid() || row < 0 || row >= m_rows || column < 0 || column >= columnCount()) return {};
    return createIndex(row, column);
}

QModelIndex HeadProxyModel::parent(const QModelIndex&) const
{
    return {};
}

int HeadProxyModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : m_rows;
}

int HeadProxyModel::columnCount(const QModelIndex& parent) const
{
    if (parent.isValid() || !sourceModel()) return 0;
    return sourceModel()->columnCount();
}

bool HeadProxyModel::hasChildren(const QModelIndex& parent) const
{
    return rowCount(parent) > 0 && columnCount(parent) > 0;
}

QVariant HeadProxyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (!sourceModel()) return {};
    if (orientation == Qt::Vertical && (section < 0 || section >= m_rows)) return {};
    return sourceModel()->headerData(section, orientation, role);
}

QModelIndex HeadProxyModel::mapToSource(const QModelIndex& proxy_index) const
{
    if (!proxy_index.isValid() || proxy_index.model() != this || !sourceModel()) return {};
    // An index kept from before a change can name a row the proxy no longer
    // shows, while the source still has it.
    if (proxy_index.row() >= m_rows || proxy_index.column() >= columnCount()) return {};
    return sourceModel()->index(proxy_index.row(), proxy_index.column());
}

QModelIndex HeadProxyModel::mapFromSource(const QModelIndex& source_index) const
{
    if (!source_index.isValid() || source_index.model() != sourceModel() || source_index.parent().isValid()) return {};
    return index(source_index.row(), source_index.column());
}

int HeadProxyModel::targetRows() const
{
    return sourceModel() ? std::clamp(sourceModel()->rowCount(), 0, m_limit) : 0;
}

void HeadProxyModel::finishPendingChange()
{
    // The source reset, went away or was replaced part way through a change
    // it announced. Close the proxy's own change, so that its views see
    // paired signals, before the reset that follows.
    if (m_pending_insert > 0) {
        m_rows += m_pending_insert;
        m_pending_insert = 0;
        endInsertRows();
    }
    if (m_pending_remove > 0) {
        m_rows -= m_pending_remove;
        m_pending_remove = 0;
        endRemoveRows();
    }
    if (m_layout_pending) {
        m_layout_pending = false;
        changePersistentIndexList(m_layout_proxy_indexes, QModelIndexList(m_layout_proxy_indexes.size()));
        m_layout_proxy_indexes.clear();
        m_layout_source_indexes.clear();
        Q_EMIT layoutChanged();
    }
}

void HeadProxyModel::syncRowCount()
{
    const int target{targetRows()};
    if (target > m_rows) {
        beginInsertRows({}, m_rows, target - 1);
        m_rows = target;
        endInsertRows();
    } else if (target < m_rows) {
        beginRemoveRows({}, target, m_rows - 1);
        m_rows = target;
        endRemoveRows();
    }
}

void HeadProxyModel::sourceRowsAboutToBeInserted(const QModelIndex& parent, int first, int last)
{
    if (parent.isValid() || m_resetting || first >= m_limit || first > m_rows) return;

    const int inserted{std::min(last, m_limit - 1) - first + 1};
    const int overflow{m_rows + inserted - m_limit};
    if (overflow > 0) {
        // The rows pushed past the limit leave first. The source has not
        // changed yet, so the rows that stay still show their source rows.
        beginRemoveRows({}, m_rows - overflow, m_rows - 1);
        m_rows -= overflow;
        endRemoveRows();
    }
    beginInsertRows({}, first, first + inserted - 1);
    m_pending_insert = inserted;
}

void HeadProxyModel::sourceRowsInserted(const QModelIndex& parent, int, int)
{
    if (parent.isValid() || m_resetting) return;

    if (m_pending_insert > 0) {
        m_rows += m_pending_insert;
        m_pending_insert = 0;
        endInsertRows();
    }
    syncRowCount();
}

void HeadProxyModel::sourceRowsAboutToBeRemoved(const QModelIndex& parent, int first, int last)
{
    if (parent.isValid() || m_resetting || first >= m_rows) return;

    const int removed{std::min(last, m_rows - 1) - first + 1};
    beginRemoveRows({}, first, first + removed - 1);
    m_pending_remove = removed;
}

void HeadProxyModel::sourceRowsRemoved(const QModelIndex& parent, int, int)
{
    if (parent.isValid() || m_resetting) return;

    if (m_pending_remove > 0) {
        m_rows -= m_pending_remove;
        m_pending_remove = 0;
        endRemoveRows();
    }
    // The rows after the removed ones move up, and the next source rows, if
    // any, fill the head again.
    syncRowCount();
}

void HeadProxyModel::sourceLayoutAboutToBeChanged(QAbstractItemModel::LayoutChangeHint hint)
{
    if (m_resetting || m_layout_pending) return;

    m_layout_pending = true;
    Q_EMIT layoutAboutToBeChanged({}, hint);
    // Remember which source row each persistent index stands for. The source
    // keeps those up to date through its change, and only the proxy's own
    // persistent indexes, a handful held by its views, are tracked.
    m_layout_proxy_indexes = persistentIndexList();
    m_layout_source_indexes.clear();
    m_layout_source_indexes.reserve(m_layout_proxy_indexes.size());
    for (const QModelIndex& proxy_index : m_layout_proxy_indexes) {
        m_layout_source_indexes.append(QPersistentModelIndex{mapToSource(proxy_index)});
    }
}

void HeadProxyModel::sourceLayoutChanged(QAbstractItemModel::LayoutChangeHint hint)
{
    if (m_resetting || !m_layout_pending) return;

    m_layout_pending = false;
    // A layout change should keep the source's row count, but a
    // QSortFilterProxyModel whose filter changed before an invalidate() can
    // change it, so follow the source's rows as they are now.
    m_rows = targetRows();
    QModelIndexList moved_to;
    moved_to.reserve(m_layout_source_indexes.size());
    for (const QPersistentModelIndex& source_index : m_layout_source_indexes) {
        // An index whose source row left the head is no longer valid.
        moved_to.append(source_index.isValid() ? mapFromSource(source_index) : QModelIndex{});
    }
    changePersistentIndexList(m_layout_proxy_indexes, moved_to);
    m_layout_proxy_indexes.clear();
    m_layout_source_indexes.clear();
    Q_EMIT layoutChanged({}, hint);
}

void HeadProxyModel::sourceDataChanged(const QModelIndex& top_left, const QModelIndex& bottom_right, const QList<int>& roles)
{
    if (m_resetting || !top_left.isValid() || !bottom_right.isValid() || top_left.parent().isValid()) return;

    const int top{top_left.row()};
    if (top >= m_rows) return;
    const int bottom{std::min(bottom_right.row(), m_rows - 1)};
    Q_EMIT dataChanged(index(top, top_left.column()), index(bottom, bottom_right.column()), roles);
}

void HeadProxyModel::sourceHeaderDataChanged(Qt::Orientation orientation, int first, int last)
{
    if (m_resetting) return;

    if (orientation == Qt::Vertical) {
        if (first >= m_rows) return;
        last = std::min(last, m_rows - 1);
    }
    Q_EMIT headerDataChanged(orientation, first, last);
}

void HeadProxyModel::sourceAboutToBeReset()
{
    if (m_resetting) return;

    finishPendingChange();
    m_resetting = true;
    beginResetModel();
}

void HeadProxyModel::sourceReset()
{
    if (!m_resetting) sourceAboutToBeReset();

    m_rows = targetRows();
    m_resetting = false;
    endResetModel();
}

void HeadProxyModel::sourceDestroyed()
{
    // The source is part way through its destruction: show no rows, and do
    // not ask it for its rows.
    sourceAboutToBeReset();
    m_source_connections.clear();
    m_rows = 0;
    m_resetting = false;
    endResetModel();
}
