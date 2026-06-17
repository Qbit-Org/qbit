#ifndef QBIT_PHOTON_TEST_TEST_HARNESS_H
#define QBIT_PHOTON_TEST_TEST_HARNESS_H

#include <iostream>
#include <string_view>

namespace photon::test {

inline int g_failures = 0;

inline void Check(bool condition, std::string_view expression, std::string_view file, int line)
{
    if (condition) {
        return;
    }

    std::cerr << file << ":" << line << " CHECK failed: " << expression << '\n';
    ++g_failures;
}

inline int Finish()
{
    if (g_failures != 0) {
        std::cerr << g_failures << " checks failed\n";
        return 1;
    }
    return 0;
}

} // namespace photon::test

#define CHECK(expr) ::photon::test::Check((expr), #expr, __FILE__, __LINE__)

#endif // QBIT_PHOTON_TEST_TEST_HARNESS_H
