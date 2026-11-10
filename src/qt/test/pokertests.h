// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_POKERTESTS_H
#define QBIT_QT_TEST_POKERTESTS_H

#include <QObject>
#include <QTest>

class PokerTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void cardText();
    void handRanking();
    void handCensus();
    void sevenCardHands();
    void headsUpHand();
    void minimumRaise();
    void shortAllInRaise();
    void sidePots();
    void splitPotOddChip();
    void walkAndShortBlinds();
    void illegalActions();
    void equityEstimates();
    void chenScores();
    void botStyles();
    void preActions();
    void randomTables();
    void tableWindow();
    void headsUpSitOut();
    void bigStacks();
    void raiseSlider();
};

#endif // QBIT_QT_TEST_POKERTESTS_H
