// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_COMPAT_CPU_FEATURES_H
#define QBIT_COMPAT_CPU_FEATURES_H

#include <cstdint>

/**
 * Standalone x86 feature detection for code that dispatches at run time.
 *
 * This deliberately shares only the CPUID and XGETBV primitives with
 * SHA256AutoDetect, whose selection logic is tuned for SHA256 (it skips leaf 7
 * without SSE4 and drops AVX2 when SHA-NI is present).
 */
namespace cpu_features {

inline constexpr uint32_t LEAF1_ECX_SSSE3{uint32_t{1} << 9};
inline constexpr uint32_t LEAF1_ECX_SSE41{uint32_t{1} << 19};
inline constexpr uint32_t LEAF1_ECX_POPCNT{uint32_t{1} << 23};
inline constexpr uint32_t LEAF1_ECX_OSXSAVE{uint32_t{1} << 27};
inline constexpr uint32_t LEAF1_ECX_AVX{uint32_t{1} << 28};
inline constexpr uint32_t LEAF7_EBX_AVX2{uint32_t{1} << 5};
inline constexpr uint32_t LEAF7_EBX_BMI2{uint32_t{1} << 8};
/** XCR0 bits for XMM (SSE) and YMM (AVX) register state saved by the OS. */
inline constexpr uint64_t XCR0_XMM_YMM{0x6};

struct X86Features {
    uint32_t max_basic_leaf{0};
    uint32_t leaf1_ecx{0};
    uint32_t leaf7_ebx{0};
    uint64_t xcr0{0};
};

using CpuidFn = void (*)(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
using XGetBVFn = uint64_t (*)(uint32_t index);

/**
 * Query the supported leaves through the given primitives, then read XCR0
 * only if leaf 1 reports both OSXSAVE and AVX. Exposed so tests can supply
 * synthetic primitives.
 */
X86Features DetectX86Features(CpuidFn cpuid, XGetBVFn xgetbv) noexcept;

/** Query this CPU and OS. All fields are zero on non-x86 targets and unsupported compilers. */
X86Features DetectX86Features() noexcept;

/** Whether the CPU supports AVX2 and the OS saves YMM state, so AVX2 code can run. */
constexpr bool HasUsableAVX2(const X86Features& f) noexcept
{
    return f.max_basic_leaf >= 7 &&
           (f.leaf1_ecx & LEAF1_ECX_OSXSAVE) != 0 &&
           (f.leaf1_ecx & LEAF1_ECX_AVX) != 0 &&
           (f.xcr0 & XCR0_XMM_YMM) == XCR0_XMM_YMM &&
           (f.leaf7_ebx & LEAF7_EBX_AVX2) != 0;
}

/** HasUsableAVX2() for this CPU and OS, detected on first call and then cached. */
bool HasUsableAVX2() noexcept;

/**
 * Whether this CPU and OS can run mlkem-native's x86_64 assembly. Besides
 * AVX2 (with AVX and the OS saving YMM state), that assembly executes SSSE3,
 * SSE4.1, POPCNT and BMI2 instructions, which a CPUID mask in a virtual
 * machine can hide even when AVX2 is shown. The list comes from an audit of
 * the assembled objects; doc/subtrees/mlkem-native.md says how to repeat it.
 */
constexpr bool HasMlkemX86Native(const X86Features& f) noexcept
{
    return HasUsableAVX2(f) &&
           (f.leaf1_ecx & LEAF1_ECX_SSSE3) != 0 &&
           (f.leaf1_ecx & LEAF1_ECX_SSE41) != 0 &&
           (f.leaf1_ecx & LEAF1_ECX_POPCNT) != 0 &&
           (f.leaf7_ebx & LEAF7_EBX_BMI2) != 0;
}

/** HasMlkemX86Native() for this CPU and OS, detected on first call and then cached. */
bool HasMlkemX86Native() noexcept;

} // namespace cpu_features

#endif // QBIT_COMPAT_CPU_FEATURES_H
