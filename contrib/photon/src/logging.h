#ifndef QBIT_PHOTON_SRC_LOGGING_H
#define QBIT_PHOTON_SRC_LOGGING_H

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>

namespace photon::logging {

enum class LogLevel {
    kError = 0,
    kWarn = 1,
    kInfo = 2,
};

inline std::atomic<int>& GlobalLogLevel()
{
    static std::atomic<int> level{static_cast<int>(LogLevel::kInfo)};
    return level;
}

inline std::mutex& LogMutex()
{
    static std::mutex mutex;
    return mutex;
}

inline const char* LogLevelName(LogLevel level)
{
    switch (level) {
    case LogLevel::kInfo:
        return "INFO";
    case LogLevel::kWarn:
        return "WARN";
    case LogLevel::kError:
        return "ERROR";
    }

    return "UNKNOWN";
}

inline std::string TimestampIso8601()
{
    const auto now = std::chrono::system_clock::now();
    const auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    const std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &now_time);
#else
    gmtime_r(&now_time, &utc_tm);
#endif

    std::ostringstream out;
    out << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%S")
        << '.'
        << std::setw(3)
        << std::setfill('0')
        << (epoch_ms.count() % 1000)
        << 'Z';
    return out.str();
}

inline void SetLogLevel(LogLevel level)
{
    GlobalLogLevel().store(static_cast<int>(level), std::memory_order_relaxed);
}

inline bool ShouldLog(LogLevel level)
{
    return static_cast<int>(level) <= GlobalLogLevel().load(std::memory_order_relaxed);
}

inline void Log(LogLevel level, const std::string& message)
{
    if (!ShouldLog(level)) {
        return;
    }

    std::lock_guard<std::mutex> lock(LogMutex());
    std::fprintf(stderr, "%s [%s] %s\n", TimestampIso8601().c_str(), LogLevelName(level), message.c_str());
}

inline std::optional<LogLevel> ParseLogLevel(std::string value)
{
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    if (value == "info") {
        return LogLevel::kInfo;
    }
    if (value == "warn" || value == "warning") {
        return LogLevel::kWarn;
    }
    if (value == "error") {
        return LogLevel::kError;
    }

    return std::nullopt;
}

} // namespace photon::logging

#define LOG_INFO(message) ::photon::logging::Log(::photon::logging::LogLevel::kInfo, (message))
#define LOG_WARN(message) ::photon::logging::Log(::photon::logging::LogLevel::kWarn, (message))
#define LOG_ERROR(message) ::photon::logging::Log(::photon::logging::LogLevel::kError, (message))

#endif // QBIT_PHOTON_SRC_LOGGING_H
