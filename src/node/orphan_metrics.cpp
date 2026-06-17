// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/orphan_metrics.h>

#include <logging.h>
#include <uint256.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>

void node::OrphanMetrics::PushEvent(EventType type, int height)
{
    AssertLockHeld(m_mutex);

    m_events.push_back({type, height, TicksSinceEpoch<std::chrono::seconds>(NodeClock::now())});
    if (m_events.size() > MAX_EVENTS) {
        m_events.pop_front();
    }
}

double node::OrphanMetrics::UpdateAlertState()
{
    AssertLockHeld(m_mutex);

    const size_t window_total{std::min(ALERT_WINDOW, m_events.size())};
    uint64_t window_stale{0};
    for (size_t idx = 0; idx < window_total; ++idx) {
        const StaleBlockEvent& event{m_events[m_events.size() - 1 - idx]};
        if (event.type == EventType::STALE) {
            ++window_stale;
        }
    }

    const double orphan_rate{
        window_total > 0
            ? static_cast<double>(window_stale) / static_cast<double>(window_total)
            : 0.0};
    if (orphan_rate > ALERT_THRESHOLD) {
        if (!m_alert_active) {
            LogWarning(
                "Stale block rate alert: rate=%.4f stale=%u total=%u window=%u threshold=%.2f\n",
                orphan_rate,
                static_cast<unsigned int>(window_stale),
                static_cast<unsigned int>(window_total),
                static_cast<unsigned int>(ALERT_WINDOW),
                ALERT_THRESHOLD);
        }
        m_alert_active = true;
        return orphan_rate;
    }
    m_alert_active = false;
    return orphan_rate;
}

void node::OrphanMetrics::RecordBlockConnected(int height)
{
    LOCK(m_mutex);
    PushEvent(EventType::CONNECTED, height);
    ++m_lifetime_connected;
    UpdateAlertState();
}

bool node::OrphanMetrics::RecordStaleBlock(int height, const uint256& hash)
{
    LOCK(m_mutex);

    // Deduplicate: skip if this block hash was already recorded.
    // Null hashes bypass dedup (used by test helpers).
    if (!hash.IsNull() && !m_seen_stale_hashes.insert(hash).second) {
        return false;
    }
    // Bound the seen-set to prevent unbounded memory growth.
    // Re-insert the current hash so its dedup protection survives the clear.
    if (m_seen_stale_hashes.size() > MAX_EVENTS) {
        m_seen_stale_hashes.clear();
        m_seen_stale_hashes.insert(hash);
    }

    PushEvent(EventType::STALE, height);
    ++m_lifetime_stale;
    m_last_stale_height = height;
    m_last_stale_time = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    const double rate{UpdateAlertState()};
    LogInfo("Stale block detected: height=%d hash=%s (orphan rate: %.1f%% over last %u blocks)\n",
            height, hash.ToString(), rate * 100.0, static_cast<unsigned int>(std::min(ALERT_WINDOW, m_events.size())));
    return true;
}

void node::OrphanMetrics::RecordReorg(int depth)
{
    LogInfo("Chain reorganization: depth=%d\n", depth);

    LOCK(m_mutex);
    m_deepest_reorg = std::max(m_deepest_reorg, depth);
    ++m_lifetime_reorgs;
}

node::OrphanMetrics::MetricsSnapshot node::OrphanMetrics::GetSnapshot(size_t window) const
{
    MetricsSnapshot snapshot{};
    snapshot.window_blocks = std::min(window, MAX_EVENTS);

    LOCK(m_mutex);

    const size_t window_total{std::min(snapshot.window_blocks, m_events.size())};
    snapshot.window_total = window_total;
    for (size_t idx = 0; idx < window_total; ++idx) {
        const StaleBlockEvent& event{m_events[m_events.size() - 1 - idx]};
        if (event.type == EventType::STALE) {
            ++snapshot.window_stale;
        }
    }
    snapshot.orphan_rate = window_total > 0
        ? static_cast<double>(snapshot.window_stale) / static_cast<double>(window_total)
        : 0.0;
    snapshot.lifetime_blocks_connected = m_lifetime_connected.load(std::memory_order_relaxed);
    snapshot.lifetime_stale_blocks = m_lifetime_stale.load(std::memory_order_relaxed);
    snapshot.lifetime_reorgs = m_lifetime_reorgs.load(std::memory_order_relaxed);
    snapshot.deepest_reorg = m_deepest_reorg;
    snapshot.last_stale_height = m_last_stale_height;
    snapshot.last_stale_time = m_last_stale_time;
    snapshot.alert = m_alert_active;
    return snapshot;
}
