// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_GUISTALLMONITOR_H
#define QBIT_QT_GUISTALLMONITOR_H

#include <QObject>
#include <QTimer>

#include <chrono>
#include <cstdint>
#include <functional>

/**
 * Log, in the qt debug category, each time the GUI thread's event loop was
 * not serviced for longer than a threshold.
 *
 * A repeating timer on the GUI thread, the heartbeat, records the
 * std::chrono::steady_clock time each time it runs. A timer runs only when
 * its thread's event loop gets round to it, so the gap between two
 * heartbeats bounds how long the loop went without servicing timers:
 * - The gap is an upper bound, because the loop ran at both of its ends.
 * - The gap less one interval is a lower bound if the second heartbeat was
 *   due no later than one interval after the first, and ran on the loop's
 *   next pass after that. Both hold on Linux with either event dispatcher Qt
 *   uses there: the UNIX one in release builds (depends builds Qt with
 *   -no-glib) and the GLib one in distribution builds of Qt. They share the
 *   timer list, which makes a repeating precise timer due again no later than
 *   one interval after it last ran, and both run due timers on every pass.
 *   (Qt 4's GLib dispatcher ran timers at idle priority, so a loop busy with
 *   other events could delay them while the window still responded. Qt 6's
 *   does not.) Where the system timer is coarser than the interval, as on
 *   Windows with its timer tick of about 15.6 ms, a heartbeat can fall due
 *   later, and the bound and the guarantee below are looser by that delay.
 * A stall is logged when the gap less one interval exceeds the threshold.
 * With the timer due on time, nothing shorter than the threshold is logged,
 * and a stall longer than the threshold plus one interval always is.
 * The line states the measured gap, which overstates the stall by less than
 * one interval plus the timer's dispatch delay. It is written by the first
 * heartbeat after the loop resumes, so a stall gives one line however long it
 * lasts. A stall still in progress when the monitor is deleted, as one in
 * shutdown is, is logged by the destructor with the gap up to then.
 *
 * A nested event loop, such as QDialog::exec() or QEventLoop::exec(),
 * services timers, so time spent in one is not a stall. Timing each event, for
 * example around QApplication::notify(), would count a whole nested loop as one
 * long event.
 *
 * The line says what was measured and not why. Known false positives:
 * - System sleep. std::chrono::steady_clock does not advance while the system
 *   is suspended on Linux (CLOCK_MONOTONIC), so a suspend is not reported
 *   there. Where the clock does advance across a suspend, the suspend is
 *   logged as one stall when the loop resumes. Nothing here filters it.
 * - macOS App Nap and timer coalescing. While the window is hidden, macOS may
 *   run the application's timers late, which shows as a gap even when the
 *   loop was idle. BitcoinGUI disables App Nap while the node reports initial
 *   sync or reindex. Outside that period nothing here filters these gaps. The
 *   heartbeat is a Qt::PreciseTimer, so Qt itself does not coarsen it.
 * - A debugger that stops the process. The clock keeps running, and the stop
 *   is logged as one stall when the process resumes. Nothing here filters it.
 * A loop that keeps processing other work without getting round to due timers
 * also shows a gap. That is logged as well: the timers, and any work they
 * drive, were not serviced.
 *
 * Known limit: a stall is logged only once the loop resumes or the monitor is
 * deleted. A freeze that ends with the process being killed or force-quit
 * leaves no line.
 *
 * -debug=qt enables the monitor, and so do plain -debug and -debug=1, which
 * enable every category.
 */
class GuiStallMonitor : public QObject
{
    Q_OBJECT

public:
    /**
     * About the longest delay that still feels immediate, and six frames at
     * 60 Hz. Shorter gaps happen in normal use (laying out or painting a large
     * view) and would bury the per-block stalls this diagnostic is for.
     */
    static constexpr std::chrono::milliseconds DEFAULT_THRESHOLD{100};
    /**
     * A logged gap overstates the stall by at most about a quarter of the
     * default threshold, at 40 wakeups a second while the monitor runs.
     */
    static constexpr std::chrono::milliseconds DEFAULT_INTERVAL{25};

    /**
     * Start a monitor with the default threshold and interval, owned by
     * parent and running on the calling thread, if the qt log category is
     * enabled at debug level. Return it, or return nullptr and start nothing.
     * The category is checked only here: enabling it later does not start a
     * monitor, and disabling it later only silences one.
     */
    static GuiStallMonitor* StartIfLogging(QObject& parent);

    //! Source of the heartbeat times. Tests pass a fake one.
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    //! A monitor that reads clock, or std::chrono::steady_clock if it is empty.
    GuiStallMonitor(std::chrono::milliseconds threshold, std::chrono::milliseconds interval, QObject* parent, Clock clock = {});
    ~GuiStallMonitor() override;

    //! Record one heartbeat, and log the gap since the previous one if it was
    //! a stall. The timer calls this; a test with a fake clock calls it
    //! directly, without running the event loop.
    void heartbeat();

    std::chrono::milliseconds threshold() const { return m_threshold; }
    std::chrono::milliseconds interval() const { return m_interval; }
    //! Heartbeats run so far.
    uint64_t heartbeats() const { return m_heartbeats; }

private:
    //! Log gap as a stall if it is one. at_stop says that the monitor's
    //! deletion ended the gap, not a heartbeat.
    void logIfStall(std::chrono::steady_clock::duration gap, bool at_stop) const;

    const std::chrono::milliseconds m_threshold;
    const std::chrono::milliseconds m_interval;
    const Clock m_clock;
    QTimer m_timer;
    std::chrono::steady_clock::time_point m_last_heartbeat;
    uint64_t m_heartbeats{0};
};

#endif // QBIT_QT_GUISTALLMONITOR_H
