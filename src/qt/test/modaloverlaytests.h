// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_MODALOVERLAYTESTS_H
#define QBIT_QT_TEST_MODALOVERLAYTESTS_H

#include <QObject>

class ModalOverlayTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void headersPresyncProgressStaysVisible();
    void hiddenTipUpdateRendersLatestTipWhenShown();
    void hiddenTipUpdateResetsStaleEtaWhenShown();
    void repeatedVisibleTipUpdatesReuseVisibleState();
    void progressSampleHistoryIsBounded();
    void incompleteProgressDoesNotRoundToComplete();
};

#endif // QBIT_QT_TEST_MODALOVERLAYTESTS_H
