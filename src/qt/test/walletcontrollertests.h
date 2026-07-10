// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_WALLETCONTROLLERTESTS_H
#define QBIT_QT_TEST_WALLETCONTROLLERTESTS_H

#include <QObject>

namespace interfaces {
class Node;
} // namespace interfaces

class WalletControllerTests : public QObject
{
    Q_OBJECT

public:
    explicit WalletControllerTests(interfaces::Node& node) : m_node(node) {}

private Q_SLOTS:
    void notificationDoesNotBlockGuiThread();
    void shutdownDropsPendingAdoption();
    void startupLoadFinishesAfterAdoption();

private:
    interfaces::Node& m_node;
};

#endif // QBIT_QT_TEST_WALLETCONTROLLERTESTS_H
