// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/guistallmonitor.h>

#include <logging.h>
#include <util/time.h>

#include <utility>

GuiStallMonitor* GuiStallMonitor::StartIfLogging(QObject& parent)
{
    if (!LogAcceptCategory(BCLog::QT, BCLog::Level::Debug)) return nullptr;
    return new GuiStallMonitor(DEFAULT_THRESHOLD, DEFAULT_INTERVAL, &parent);
}

GuiStallMonitor::GuiStallMonitor(std::chrono::milliseconds threshold, std::chrono::milliseconds interval, QObject* parent, Clock clock)
    : QObject(parent),
      m_threshold(threshold),
      m_interval(interval),
      m_clock(clock ? std::move(clock) : Clock{[] { return std::chrono::steady_clock::now(); }})
{
    m_timer.setTimerType(Qt::PreciseTimer);
    m_timer.setInterval(m_interval);
    connect(&m_timer, &QTimer::timeout, this, &GuiStallMonitor::heartbeat);
    // The first gap runs from here, so work the caller does before returning
    // to the event loop counts.
    m_last_heartbeat = m_clock();
    m_timer.start();
    // Without this line, the absence of stall lines would not show that the
    // loop was measured.
    LogDebug(BCLog::QT, "GUI stall monitor started (threshold %d ms, heartbeat every %d ms)",
             m_threshold.count(), m_interval.count());
}

GuiStallMonitor::~GuiStallMonitor()
{
    // A stall still in progress ends here instead of at a heartbeat. Shutdown
    // deletes the monitor before the event loop resumes, so without this a
    // stall in shutdown would leave only the line below.
    const auto gap{m_clock() - m_last_heartbeat};
    if (gap - m_interval > m_threshold) {
        LogDebug(BCLog::QT, "GUI event loop not serviced for %d ms when the stall monitor stopped (gap since the last heartbeat, due every %d ms)",
                 Ticks<std::chrono::milliseconds>(gap), m_interval.count());
    }
    LogDebug(BCLog::QT, "GUI stall monitor stopped after %d heartbeats", m_heartbeats);
}

void GuiStallMonitor::heartbeat()
{
    const auto now{m_clock()};
    const auto gap{now - m_last_heartbeat};
    m_last_heartbeat = now;
    ++m_heartbeats;
    // This heartbeat was due at most one interval after the previous one, so
    // it waited at least gap - interval for the loop. See the class comment.
    if (gap - m_interval > m_threshold) {
        LogDebug(BCLog::QT, "GUI event loop not serviced for %d ms (gap between heartbeats due every %d ms)",
                 Ticks<std::chrono::milliseconds>(gap), m_interval.count());
    }
}
