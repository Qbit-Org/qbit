// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_HEADPROXYMODEL_H
#define QBIT_QT_HEADPROXYMODEL_H

#include <QAbstractItemModel>
#include <QAbstractProxyModel>
#include <QList>
#include <QMetaObject>
#include <QModelIndex>
#include <QPersistentModelIndex>
#include <QVariant>

/**
 * Expose the first rows of a flat (list or table) source model, with all of
 * its columns and roles.
 *
 * The proxy has min(limit, source rows) rows: row r is source row r. It
 * translates the source's row, layout, data and reset signals so that its
 * rows are always the first rows of the source, and does work proportional
 * to its own rows, not the source's, when the source changes. Children of
 * source rows are not exposed.
 */
class HeadProxyModel : public QAbstractProxyModel
{
    Q_OBJECT

public:
    explicit HeadProxyModel(int limit, QObject* parent = nullptr);
    ~HeadProxyModel() override;

    void setSourceModel(QAbstractItemModel* source_model) override;

    QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex& child) const override;
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    bool hasChildren(const QModelIndex& parent = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    QModelIndex mapToSource(const QModelIndex& proxy_index) const override;
    QModelIndex mapFromSource(const QModelIndex& source_index) const override;

private:
    //! The rows the proxy should show now.
    int targetRows() const;
    //! End an insertion, removal or layout change the proxy began.
    void finishPendingChange();
    //! Add or remove rows at the end until the proxy shows targetRows().
    void syncRowCount();

    void sourceRowsAboutToBeInserted(const QModelIndex& parent, int first, int last);
    void sourceRowsInserted(const QModelIndex& parent, int first, int last);
    void sourceRowsAboutToBeRemoved(const QModelIndex& parent, int first, int last);
    void sourceRowsRemoved(const QModelIndex& parent, int first, int last);
    void sourceLayoutAboutToBeChanged(QAbstractItemModel::LayoutChangeHint hint);
    void sourceLayoutChanged(QAbstractItemModel::LayoutChangeHint hint);
    void sourceDataChanged(const QModelIndex& top_left, const QModelIndex& bottom_right, const QList<int>& roles);
    void sourceHeaderDataChanged(Qt::Orientation orientation, int first, int last);
    void sourceAboutToBeReset();
    void sourceReset();
    void sourceDestroyed();

    const int m_limit;
    //! Rows the proxy currently reports. It lags the source between a
    //! source's "about to" signal and the matching "done" signal.
    int m_rows{0};
    //! Rows announced by a beginInsertRows() or beginRemoveRows() that the
    //! source's matching signal completes.
    int m_pending_insert{0};
    int m_pending_remove{0};
    bool m_resetting{false};
    //! A layout change or move announced by the source is in progress.
    bool m_layout_pending{false};
    //! The proxy's persistent indexes and the source rows they stood for
    //! when the source announced a layout change or a move.
    QModelIndexList m_layout_proxy_indexes;
    QList<QPersistentModelIndex> m_layout_source_indexes;
    QList<QMetaObject::Connection> m_source_connections;
};

#endif // QBIT_QT_HEADPROXYMODEL_H
