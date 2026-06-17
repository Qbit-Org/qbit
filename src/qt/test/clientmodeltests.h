// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_CLIENTMODELTESTS_H
#define QBIT_QT_TEST_CLIENTMODELTESTS_H

#include <QObject>

namespace interfaces {
class Node;
} // namespace interfaces

class ClientModelTests : public QObject
{
    Q_OBJECT

public:
    explicit ClientModelTests(interfaces::Node& node) : m_node(node) {}

private Q_SLOTS:
    void ibdBlockTipsAreCoalescedAndFlushLatest();
    void reindexHeaderTipsAreCoalescedAndFlushLatest();
    void postInitTipInvalidatesPendingIbdFlush();
    void syncTypeTransitionEmitsImmediately();
    void stopCancelsPendingIbdFlush();

private:
    interfaces::Node& m_node;
};

#endif // QBIT_QT_TEST_CLIENTMODELTESTS_H
