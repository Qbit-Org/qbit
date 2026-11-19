// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_OVERVIEWPAGETESTS_H
#define QBIT_QT_TEST_OVERVIEWPAGETESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class OverviewPageTests : public QObject
{
    Q_OBJECT

public:
    explicit OverviewPageTests(interfaces::Node& node) : m_node(node) {}

private:
    interfaces::Node& m_node;

private Q_SLOTS:
    void headProxyModelTests();
    void headProxyModelBoundedWork();
    void recentTransactionsTests();
    void recentTransactionsLongHistory();
};

#endif // QBIT_QT_TEST_OVERVIEWPAGETESTS_H
