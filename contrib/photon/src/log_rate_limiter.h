#ifndef QBIT_PHOTON_SRC_LOG_RATE_LIMITER_H
#define QBIT_PHOTON_SRC_LOG_RATE_LIMITER_H

#include <clock.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace photon {

class LogRateLimiter final {
public:
    explicit LogRateLimiter(std::chrono::milliseconds interval)
        : m_interval(interval)
    {
    }

    [[nodiscard]] std::optional<std::string> Record(Clock::TimePoint now, std::string_view message)
    {
        ++m_total;

        if (!m_next_log.has_value() || now >= *m_next_log) {
            std::string output{message};
            if (m_suppressed_since_last > 0) {
                output += " (suppressed " + std::to_string(m_suppressed_since_last)
                          + " similar messages; total=" + std::to_string(m_total) + ")";
                m_suppressed_since_last = 0;
            }
            m_next_log = now + m_interval;
            return output;
        }

        ++m_suppressed_total;
        ++m_suppressed_since_last;
        return std::nullopt;
    }

    [[nodiscard]] std::uint64_t total() const
    {
        return m_total;
    }

    [[nodiscard]] std::uint64_t suppressed() const
    {
        return m_suppressed_total;
    }

private:
    std::chrono::milliseconds m_interval;
    std::optional<Clock::TimePoint> m_next_log{};
    std::uint64_t m_total{0};
    std::uint64_t m_suppressed_total{0};
    std::uint64_t m_suppressed_since_last{0};
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_LOG_RATE_LIMITER_H
