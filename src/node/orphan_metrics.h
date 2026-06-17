// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_NODE_ORPHAN_METRICS_H
#define QBIT_NODE_ORPHAN_METRICS_H

#include <sync.h>
#include <uint256.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <set>

namespace node {
class OrphanMetrics
{
public:
    enum class EventType {
        CONNECTED,
        STALE,
    };

    struct StaleBlockEvent {
        EventType type;
        int height;
        int64_t time;
    };

    struct MetricsSnapshot {
        size_t window_blocks{0};
        uint64_t window_total{0};
        uint64_t window_stale{0};
        double orphan_rate{0.0};
        uint64_t lifetime_blocks_connected{0};
        uint64_t lifetime_stale_blocks{0};
        uint64_t lifetime_reorgs{0};
        int deepest_reorg{0};
        int64_t last_stale_height{-1};
        int64_t last_stale_time{0};
        bool alert{false};
    };

    void RecordBlockConnected(int height) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool RecordStaleBlock(int height, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void RecordReorg(int depth) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    MetricsSnapshot GetSnapshot(size_t window = 1000) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    static constexpr size_t MAX_EVENTS{10000};
    static constexpr size_t ALERT_WINDOW{1000};
    static constexpr double ALERT_THRESHOLD{0.10};

    void PushEvent(EventType type, int height) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** Update alert state and return the current orphan rate over ALERT_WINDOW. */
    double UpdateAlertState() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    std::deque<StaleBlockEvent> m_events GUARDED_BY(m_mutex){};
    std::set<uint256> m_seen_stale_hashes GUARDED_BY(m_mutex){};

    std::atomic<uint64_t> m_lifetime_connected{0};
    std::atomic<uint64_t> m_lifetime_stale{0};
    std::atomic<uint64_t> m_lifetime_reorgs{0};

    int m_deepest_reorg GUARDED_BY(m_mutex){0};
    int64_t m_last_stale_height GUARDED_BY(m_mutex){-1};
    int64_t m_last_stale_time GUARDED_BY(m_mutex){0};
    bool m_alert_active GUARDED_BY(m_mutex){false};
};
} // namespace node

#endif // QBIT_NODE_ORPHAN_METRICS_H
