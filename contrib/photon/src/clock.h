#ifndef QBIT_PHOTON_SRC_CLOCK_H
#define QBIT_PHOTON_SRC_CLOCK_H

#include <chrono>

namespace photon {

class Clock {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    virtual ~Clock() = default;
    [[nodiscard]] virtual TimePoint Now() const = 0;
};

class SystemClock final : public Clock {
public:
    [[nodiscard]] TimePoint Now() const override
    {
        return std::chrono::steady_clock::now();
    }
};

class MockClock final : public Clock {
public:
    explicit MockClock(TimePoint now = TimePoint{})
        : m_now(now)
    {
    }

    [[nodiscard]] TimePoint Now() const override
    {
        return m_now;
    }

    void SetNow(TimePoint now)
    {
        m_now = now;
    }

    void Advance(std::chrono::milliseconds delta)
    {
        m_now += delta;
    }

private:
    TimePoint m_now;
};

} // namespace photon

#endif // QBIT_PHOTON_SRC_CLOCK_H
