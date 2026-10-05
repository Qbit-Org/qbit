// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_COMPAT_CPUID_H
#define QBIT_COMPAT_CPUID_H

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#define HAVE_GETCPUID

#include <cpuid.h>

#include <cstdint>

// We can't use cpuid.h's __get_cpuid as it does not support subleafs.
void static inline GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
#ifdef __GNUC__
    __cpuid_count(leaf, subleaf, a, b, c, d);
#else
  __asm__ ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(leaf), "2"(subleaf));
#endif
}

/** Read extended control register `index` (XCR0 for 0). Faults unless CPUID leaf 1 reports OSXSAVE. */
static inline uint64_t XGetBV(uint32_t index) noexcept
{
    uint32_t a, d;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(index));
    return (uint64_t{d} << 32) | a;
}

#endif // defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#endif // QBIT_COMPAT_CPUID_H
