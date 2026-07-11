// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef QBIT_QT_TEST_WALLETACTIVITYTESTS_H
#define QBIT_QT_TEST_WALLETACTIVITYTESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class WalletActivityTests : public QObject
{
    Q_OBJECT

public:
    explicit WalletActivityTests(interfaces::Node& node) : m_node(node) {}

private Q_SLOTS:
    void createWalletProgress_data();
    void createWalletProgress();
    void ordinaryLoadAndShutdown();

private:
    interfaces::Node& m_node;
};

#endif // QBIT_QT_TEST_WALLETACTIVITYTESTS_H
