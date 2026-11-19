// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionoverviewwidget.h>

#include <qt/headproxymodel.h>
#include <qt/transactiontablemodel.h>

#include <QAbstractItemModel>
#include <QListView>
#include <QSize>
#include <QSizePolicy>
#include <QWidget>

#include <algorithm>

TransactionOverviewWidget::TransactionOverviewWidget(QWidget* parent)
    : QListView(parent) {}

QSize TransactionOverviewWidget::sizeHint() const
{
    int height{QListView::sizeHint().height()};
    // The list shows the first rows of the history through a HeadProxyModel.
    // Keep the height it had when it held the whole history with the other
    // rows hidden: one row's height for each of them.
    if (const auto* head{qobject_cast<const HeadProxyModel*>(model())}; head && head->sourceModel() && head->rowCount() > 0) {
        const qint64 more_rows{head->sourceModel()->rowCount() - head->rowCount()};
        const qint64 row_height{sizeHintForIndex(head->index(0, modelColumn())).height()};
        if (more_rows > 0 && row_height > 0) {
            height = static_cast<int>(std::min<qint64>(QWIDGETSIZE_MAX, height + more_rows * row_height));
        }
    }
    return {sizeHintForColumn(TransactionTableModel::ToAddress), height};
}

void TransactionOverviewWidget::showEvent(QShowEvent* event)
{
    Q_UNUSED(event);
    QSizePolicy sp = sizePolicy();
    sp.setHorizontalPolicy(QSizePolicy::Minimum);
    setSizePolicy(sp);
}
