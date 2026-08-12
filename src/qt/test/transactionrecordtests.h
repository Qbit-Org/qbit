// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_TRANSACTIONRECORDTESTS_H
#define QBIT_QT_TEST_TRANSACTIONRECORDTESTS_H

#include <QObject>

class TransactionRecordTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void feeBearingChangeOnlyPayment();
    void ordinaryPaymentWithChange();
    void zeroFeeChangeOnlyPayment();
};

#endif // QBIT_QT_TEST_TRANSACTIONRECORDTESTS_H
