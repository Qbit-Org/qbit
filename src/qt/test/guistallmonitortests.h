// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_GUISTALLMONITORTESTS_H
#define QBIT_QT_TEST_GUISTALLMONITORTESTS_H

#include <logging.h>

#include <memory>
#include <unordered_map>

#include <QObject>

struct BasicTestingSetup;

class GuiStallMonitorTests : public QObject
{
    Q_OBJECT

public:
    GuiStallMonitorTests();
    ~GuiStallMonitorTests() override;

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void startsOnlyWithQtCategory();
    void silentWithoutQtCategory();
    void logsOnlyGapsOverThreshold();
    void logsOneLinePerStall();
    void logsStallInProgressWhenStopped();
    void stopsWithOwner();
    void nestedEventLoopServicesHeartbeat();
    void logsRealStall();

private:
    //! Starts logging, so that lines reach the captures.
    std::unique_ptr<BasicTestingSetup> m_setup;
    //! The logging configuration before the tests, restored after them.
    BCLog::CategoryMask m_categories{0};
    BCLog::Level m_level{BCLog::Level::Debug};
    std::unordered_map<BCLog::LogFlags, BCLog::Level> m_category_levels;
};

#endif // QBIT_QT_TEST_GUISTALLMONITORTESTS_H
