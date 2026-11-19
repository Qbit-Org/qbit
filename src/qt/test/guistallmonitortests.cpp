// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/guistallmonitortests.h>

#include <logging.h>
#include <qt/guistallmonitor.h>
#include <qt/test/util.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <QEventLoop>
#include <QPointer>
#include <QString>
#include <QTest>
#include <QThread>
#include <QTimer>

// Every test except logsRealStall reads a fake clock, so a pause of the test
// process cannot change what is logged. logsRealStall uses the real clock and
// timer, and asserts only what a pause cannot undo.

namespace {
using namespace std::chrono_literals;

const std::string STALL_TEXT{"GUI event loop not serviced for "};
constexpr auto THRESHOLD{100ms};
constexpr auto INTERVAL{25ms};
//! Bounds the waits on the real event loop. Far above any pause of the test
//! process seen on CI, and below the QtTest function timeout.
constexpr int WAIT_TIMEOUT_MS{120000};

//! A clock that moves only when a test moves it.
struct FakeClock {
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::time_point{} + 1h};
    GuiStallMonitor::Clock Function()
    {
        return [this] { return now; };
    }
};

size_t StallLines(const LogCapture& log)
{
    return log.findAll({STALL_TEXT}).size();
}

//! The durations, in milliseconds, of the stall lines logged.
std::vector<int64_t> StallDurations(const LogCapture& log)
{
    std::vector<int64_t> durations;
    for (const std::string& line : log.findAll({STALL_TEXT})) {
        const std::string_view rest{std::string_view{line}.substr(line.find(STALL_TEXT) + STALL_TEXT.size())};
        const std::optional<int64_t> duration{ToIntegral<int64_t>(rest.substr(0, rest.find(' ')))};
        if (duration) durations.push_back(*duration);
    }
    return durations;
}
} // namespace

GuiStallMonitorTests::GuiStallMonitorTests() = default;
GuiStallMonitorTests::~GuiStallMonitorTests() = default;

void GuiStallMonitorTests::initTestCase()
{
    m_categories = LogInstance().GetCategoryMask();
    m_level = LogInstance().LogLevel();
    m_category_levels = LogInstance().CategoryLevels();
    m_setup = std::make_unique<BasicTestingSetup>(ChainType::REGTEST);
}

void GuiStallMonitorTests::cleanupTestCase()
{
    m_setup.reset();
    LogInstance().DisableCategory(BCLog::ALL);
    LogInstance().EnableCategory(static_cast<BCLog::LogFlags>(m_categories));
    LogInstance().SetLogLevel(m_level);
    LogInstance().SetCategoryLogLevel(m_category_levels);
}

void GuiStallMonitorTests::startsOnlyWithQtCategory()
{
    const LogCapture log;
    QObject owner;

    LogInstance().DisableCategory(BCLog::QT);
    QVERIFY(!GuiStallMonitor::StartIfLogging(owner));
    QVERIFY(owner.findChildren<GuiStallMonitor*>().isEmpty());
    QVERIFY(log.find({"GUI stall monitor"}).empty());

    LogInstance().EnableCategory(BCLog::QT);
    GuiStallMonitor* const monitor{GuiStallMonitor::StartIfLogging(owner)};
    QVERIFY(monitor);
    QCOMPARE(monitor->parent(), &owner);
    QCOMPARE(monitor->thread(), QThread::currentThread());
    QVERIFY(monitor->threshold() == GuiStallMonitor::DEFAULT_THRESHOLD);
    QVERIFY(monitor->interval() == GuiStallMonitor::DEFAULT_INTERVAL);
    QVERIFY(!log.find({"GUI stall monitor started (threshold 100 ms, heartbeat every 25 ms)"}).empty());
}

void GuiStallMonitorTests::silentWithoutQtCategory()
{
    const LogCapture log;
    LogInstance().DisableCategory(BCLog::QT);

    // A monitor that runs while the category is off, as one does after the
    // logging RPC disables it, logs nothing, not even for a stall that the
    // next heartbeat or the destructor would report.
    FakeClock clock;
    {
        GuiStallMonitor monitor{THRESHOLD, INTERVAL, nullptr, clock.Function()};
        clock.now += 5s;
        monitor.heartbeat();
        clock.now += 5s;
    }
    QVERIFY(log.find({"GUI event loop"}).empty());
    QVERIFY(log.find({"GUI stall monitor"}).empty());
}

void GuiStallMonitorTests::logsOnlyGapsOverThreshold()
{
    const LogCapture log;
    LogInstance().EnableCategory(BCLog::QT);
    FakeClock clock;
    GuiStallMonitor monitor{THRESHOLD, INTERVAL, nullptr, clock.Function()};

    // Heartbeats on time, and one exactly a threshold late, are not stalls.
    for (int i{0}; i < 10; ++i) {
        clock.now += INTERVAL;
        monitor.heartbeat();
    }
    clock.now += INTERVAL + THRESHOLD;
    monitor.heartbeat();
    QCOMPARE(StallLines(log), size_t{0});

    // One a millisecond later is, and the line states the whole gap.
    clock.now += INTERVAL + THRESHOLD + 1ms;
    monitor.heartbeat();
    QCOMPARE(StallLines(log), size_t{1});
    QVERIFY(!log.find({"GUI event loop not serviced for 126 ms (gap between heartbeats due every 25 ms)"}).empty());
    QCOMPARE(monitor.heartbeats(), uint64_t{12});
}

void GuiStallMonitorTests::logsOneLinePerStall()
{
    const LogCapture log;
    LogInstance().EnableCategory(BCLog::QT);
    FakeClock clock;
    GuiStallMonitor monitor{THRESHOLD, INTERVAL, nullptr, clock.Function()};
    clock.now += INTERVAL;
    monitor.heartbeat();

    // A stall of many intervals gives one line, from the heartbeat that ends
    // it. Heartbeats right after it, at once or on time, start a new gap.
    clock.now += 5s;
    monitor.heartbeat();
    monitor.heartbeat();
    for (int i{0}; i < 10; ++i) {
        clock.now += INTERVAL;
        monitor.heartbeat();
    }
    QCOMPARE(StallLines(log), size_t{1});
    QVERIFY(!log.find({"GUI event loop not serviced for 5000 ms ("}).empty());

    // The next stall gives the next line.
    clock.now += 2s;
    monitor.heartbeat();
    QCOMPARE(StallLines(log), size_t{2});
    QVERIFY(!log.find({"GUI event loop not serviced for 2000 ms ("}).empty());
}

void GuiStallMonitorTests::logsStallInProgressWhenStopped()
{
    const LogCapture log;
    LogInstance().EnableCategory(BCLog::QT);
    FakeClock clock;

    // Shutdown deletes the client model, and with it the monitor, before the
    // event loop resumes. The destructor logs the stall up to then.
    auto monitor{std::make_unique<GuiStallMonitor>(THRESHOLD, INTERVAL, nullptr, clock.Function())};
    clock.now += INTERVAL;
    monitor->heartbeat();
    clock.now += 3s;
    monitor.reset();
    QCOMPARE(StallLines(log), size_t{1});
    QVERIFY(!log.find({"GUI event loop not serviced for 3000 ms when the stall monitor stopped"}).empty());

    // A monitor deleted on time logs no stall.
    monitor = std::make_unique<GuiStallMonitor>(THRESHOLD, INTERVAL, nullptr, clock.Function());
    clock.now += INTERVAL;
    monitor->heartbeat();
    clock.now += INTERVAL;
    monitor.reset();
    QCOMPARE(StallLines(log), size_t{1});
}

void GuiStallMonitorTests::stopsWithOwner()
{
    const LogCapture log;
    LogInstance().EnableCategory(BCLog::QT);
    FakeClock clock;

    // BitcoinApplication gives the monitor to the client model, so it stops
    // when the client model is deleted, at shutdown or otherwise.
    auto owner{std::make_unique<QObject>()};
    QPointer<GuiStallMonitor> monitor{new GuiStallMonitor{THRESHOLD, INTERVAL, owner.get(), clock.Function()}};
    clock.now += INTERVAL;
    monitor->heartbeat();
    clock.now += INTERVAL;
    monitor->heartbeat();
    owner.reset();
    QVERIFY(monitor.isNull());
    QVERIFY(!log.find({"GUI stall monitor stopped after 2 heartbeats"}).empty());
}

void GuiStallMonitorTests::nestedEventLoopServicesHeartbeat()
{
    const LogCapture log;
    LogInstance().EnableCategory(BCLog::QT);

    // The real timer drives the heartbeat. The clock moves on by less than a
    // stall at each read, so the time between real heartbeats, including any
    // pause of the test process, does not matter here.
    FakeClock clock;
    GuiStallMonitor monitor{THRESHOLD, INTERVAL, nullptr, [&clock] { return clock.now += 20ms; }};

    // One event runs a nested event loop, as a modal dialog's exec() does,
    // until the heartbeat has run in it several times. A design that timed
    // each event, or let only the outer loop's heartbeats end a gap, would
    // see the whole nested loop as one gap of at least those reads.
    constexpr uint64_t NESTED_HEARTBEATS{8};
    bool nested_done{false};
    uint64_t nested_heartbeats{0};
    QTimer::singleShot(0, &monitor, [&] {
        const uint64_t heartbeats_before{monitor.heartbeats()};
        QEventLoop nested;
        QTimer poll;
        QObject::connect(&poll, &QTimer::timeout, &nested, [&] {
            if (monitor.heartbeats() - heartbeats_before >= NESTED_HEARTBEATS) nested.quit();
        });
        poll.start(5ms);
        QTimer::singleShot(std::chrono::milliseconds{WAIT_TIMEOUT_MS}, &nested, &QEventLoop::quit);
        nested.exec();
        nested_heartbeats = monitor.heartbeats() - heartbeats_before;
        nested_done = true;
    });
    QVERIFY(QTest::qWaitFor([&] { return nested_done; }, 2 * WAIT_TIMEOUT_MS));
    QVERIFY2(nested_heartbeats >= NESTED_HEARTBEATS,
             qPrintable(QString("%1 heartbeats in the nested event loop").arg(nested_heartbeats)));

    // Heartbeats of the outer loop after it end the gap that the nested loop
    // would have made.
    const uint64_t heartbeats_after{monitor.heartbeats()};
    QVERIFY(QTest::qWaitFor([&] { return monitor.heartbeats() >= heartbeats_after + 2; }, WAIT_TIMEOUT_MS));
    QCOMPARE(StallLines(log), size_t{0});
}

void GuiStallMonitorTests::logsRealStall()
{
    const LogCapture log;
    LogInstance().EnableCategory(BCLog::QT);

    // The real clock and timer. Keep the loop from being serviced for a
    // measured time. A pause of the process can only add to the gap or add
    // lines, so it cannot undo what is checked: a line of at least that time.
    GuiStallMonitor monitor{THRESHOLD, INTERVAL, nullptr};
    QVERIFY(QTest::qWaitFor([&] { return monitor.heartbeats() >= 1; }, WAIT_TIMEOUT_MS));
    const auto start{std::chrono::steady_clock::now()};
    std::this_thread::sleep_for(3 * THRESHOLD);
    const auto blocked{std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start)};
    const uint64_t heartbeats_after{monitor.heartbeats()};
    QVERIFY(QTest::qWaitFor([&] { return monitor.heartbeats() > heartbeats_after; }, WAIT_TIMEOUT_MS));

    int64_t longest{0};
    for (const int64_t duration : StallDurations(log)) longest = std::max(longest, duration);
    QVERIFY2(longest >= blocked.count(), qPrintable(QString("Longest logged stall %1 ms for a %2 ms block").arg(longest).arg(blocked.count())));
}
