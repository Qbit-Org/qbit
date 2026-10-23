// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <compat/cpu_features.h>

#include <compat/cpuid.h>

namespace cpu_features {

X86Features DetectX86Features(CpuidFn cpuid, XGetBVFn xgetbv) noexcept
{
    X86Features f;
    uint32_t a{0}, b{0}, c{0}, d{0};
    cpuid(0, 0, a, b, c, d);
    f.max_basic_leaf = a;
    if (f.max_basic_leaf >= 1) {
        cpuid(1, 0, a, b, c, d);
        f.leaf1_ecx = c;
    }
    if (f.max_basic_leaf >= 7) {
        cpuid(7, 0, a, b, c, d);
        f.leaf7_ebx = b;
    }
    // XGETBV faults unless the OS enabled it, which leaf 1 reports as OSXSAVE.
    if ((f.leaf1_ecx & LEAF1_ECX_OSXSAVE) != 0 && (f.leaf1_ecx & LEAF1_ECX_AVX) != 0) {
        f.xcr0 = xgetbv(0);
    }
    return f;
}

X86Features DetectX86Features() noexcept
{
#if defined(HAVE_GETCPUID)
    return DetectX86Features(GetCPUID, XGetBV);
#else
    return {};
#endif
}

bool HasUsableAVX2() noexcept
{
    static const bool usable{HasUsableAVX2(DetectX86Features())};
    return usable;
}

bool HasMlkemX86Native() noexcept
{
    static const bool usable{HasMlkemX86Native(DetectX86Features())};
    return usable;
}

} // namespace cpu_features
