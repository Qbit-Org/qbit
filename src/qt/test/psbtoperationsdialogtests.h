// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_PSBTOPERATIONSDIALOGTESTS_H
#define QBIT_QT_TEST_PSBTOPERATIONSDIALOGTESTS_H

#include <memory>

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class PSBTOperationsDialogTests : public QObject
{
    Q_OBJECT

public:
    explicit PSBTOperationsDialogTests(interfaces::Node& node);
    ~PSBTOperationsDialogTests();

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void eventLoopResponsiveWhileSigningPaused();
    void successfulCompletionUpdatesDisplayOnce();
    void cancellationBeforeCounterReservation();
    void lateCancellationDoesNotDropCompletedPSBT();
    void cancellationAfterCounterReservationIsIgnored();
    void dialogDestructionBeforeCompletion();
    void walletUnloadDuringSigning();
    void signingFailurePreservesOriginalPSBT();

private:
    struct Context;
    interfaces::Node& m_node;
    std::unique_ptr<Context> m_context;
};

#endif // QBIT_QT_TEST_PSBTOPERATIONSDIALOGTESTS_H
