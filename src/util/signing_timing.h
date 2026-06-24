// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_UTIL_SIGNING_TIMING_H
#define QBIT_UTIL_SIGNING_TIMING_H

#include <logging.h>

#include <atomic>
#include <cstdint>

namespace util::signing_timing {

inline thread_local uint64_t g_current_id{0};
inline std::atomic<uint64_t> g_next_id{0};

inline bool Enabled()
{
    return LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
}

inline bool TraceEnabled()
{
    return LogAcceptCategory(BCLog::BENCH, BCLog::Level::Trace);
}

inline uint64_t CurrentId()
{
    return g_current_id;
}

inline uint64_t NextId()
{
    return g_next_id.fetch_add(1, std::memory_order_relaxed) + 1;
}

inline uint64_t CurrentOrNextId()
{
    const uint64_t current{CurrentId()};
    return current != 0 ? current : NextId();
}

inline unsigned long long LogId(uint64_t id)
{
    return static_cast<unsigned long long>(id);
}

class ScopedId
{
    bool m_active{false};
    uint64_t m_previous{0};

public:
    explicit ScopedId(uint64_t id) : m_active{id != 0}, m_previous{g_current_id}
    {
        if (m_active) g_current_id = id;
    }

    ScopedId(const ScopedId&) = delete;
    ScopedId& operator=(const ScopedId&) = delete;

    ~ScopedId()
    {
        if (m_active) g_current_id = m_previous;
    }
};

} // namespace util::signing_timing

#endif // QBIT_UTIL_SIGNING_TIMING_H
