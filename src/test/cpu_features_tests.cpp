// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <compat/cpu_features.h>
#include <compat/cpuid.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

using namespace cpu_features;

namespace {

constexpr uint32_t LEAF7_EBX_SHA{uint32_t{1} << 29};

constexpr X86Features AVX2_USABLE{
    .max_basic_leaf = 7,
    .leaf1_ecx = LEAF1_ECX_OSXSAVE | LEAF1_ECX_AVX,
    .leaf7_ebx = LEAF7_EBX_AVX2,
    .xcr0 = XCR0_XMM_YMM,
};

constexpr X86Features MLKEM_X86_NATIVE{
    .max_basic_leaf = 7,
    .leaf1_ecx = LEAF1_ECX_OSXSAVE | LEAF1_ECX_AVX | LEAF1_ECX_SSSE3 | LEAF1_ECX_SSE41 | LEAF1_ECX_POPCNT,
    .leaf7_ebx = LEAF7_EBX_AVX2 | LEAF7_EBX_BMI2,
    .xcr0 = XCR0_XMM_YMM,
};

/** A synthetic CPU for DetectX86Features: answers CPUID like hardware and records every query. */
struct FakeCpu {
    X86Features features;
    std::vector<uint32_t> leaves;
    int xgetbv_calls{0};
    bool xgetbv_faulted{false};
};
FakeCpu g_cpu;

void FakeCpuid(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    g_cpu.leaves.push_back(leaf);
    const bool supported{leaf <= g_cpu.features.max_basic_leaf};
    a = leaf == 0 ? g_cpu.features.max_basic_leaf : 0;
    // Real CPUs answer an unsupported leaf with another leaf's data; report
    // AVX2 there so that reading it would show up as a wrong result.
    b = leaf == 7 ? (supported ? g_cpu.features.leaf7_ebx : LEAF7_EBX_AVX2) : 0;
    c = leaf == 1 ? g_cpu.features.leaf1_ecx : 0;
    d = 0;
    (void)subleaf;
}

uint64_t FakeXGetBV(uint32_t index)
{
    ++g_cpu.xgetbv_calls;
    if ((g_cpu.features.leaf1_ecx & LEAF1_ECX_OSXSAVE) == 0) g_cpu.xgetbv_faulted = true;
    return index == 0 ? g_cpu.features.xcr0 : 0;
}

X86Features DetectFake(const X86Features& features)
{
    g_cpu = FakeCpu{};
    g_cpu.features = features;
    return DetectX86Features(FakeCpuid, FakeXGetBV);
}

} // namespace

BOOST_AUTO_TEST_SUITE(cpu_features_tests)

BOOST_AUTO_TEST_CASE(usable_avx2_matrix)
{
    static_assert(HasUsableAVX2(AVX2_USABLE));
    static_assert(!HasUsableAVX2(X86Features{}));

    // Clearing any single requirement makes AVX2 unusable.
    X86Features f{AVX2_USABLE};
    f.max_basic_leaf = 6;
    BOOST_CHECK(!HasUsableAVX2(f));
    f = AVX2_USABLE;
    f.leaf1_ecx &= ~LEAF1_ECX_OSXSAVE;
    BOOST_CHECK(!HasUsableAVX2(f));
    f = AVX2_USABLE;
    f.leaf1_ecx &= ~LEAF1_ECX_AVX;
    BOOST_CHECK(!HasUsableAVX2(f));
    f = AVX2_USABLE;
    f.xcr0 = 0x4; // YMM without XMM state
    BOOST_CHECK(!HasUsableAVX2(f));
    f = AVX2_USABLE;
    f.xcr0 = 0x3; // x87 and XMM, but no YMM state
    BOOST_CHECK(!HasUsableAVX2(f));
    f = AVX2_USABLE;
    f.leaf7_ebx &= ~LEAF7_EBX_AVX2;
    BOOST_CHECK(!HasUsableAVX2(f));

    // Unrelated bits, SHA-NI included, change nothing.
    f = AVX2_USABLE;
    f.leaf7_ebx |= LEAF7_EBX_SHA;
    f.xcr0 |= 0xe1;
    f.max_basic_leaf = 0x24;
    BOOST_CHECK(HasUsableAVX2(f));

    // Detection reads exactly what the CPU reports.
    BOOST_CHECK(HasUsableAVX2(DetectFake(AVX2_USABLE)));
    BOOST_CHECK_EQUAL(g_cpu.xgetbv_calls, 1);
    BOOST_CHECK(!g_cpu.xgetbv_faulted);
    BOOST_CHECK(g_cpu.leaves == (std::vector<uint32_t>{0, 1, 7}));

    // Without OSXSAVE, XGETBV would fault, so it must not run.
    f = AVX2_USABLE;
    f.leaf1_ecx &= ~LEAF1_ECX_OSXSAVE;
    BOOST_CHECK(!HasUsableAVX2(DetectFake(f)));
    BOOST_CHECK_EQUAL(g_cpu.xgetbv_calls, 0);
    BOOST_CHECK(!g_cpu.xgetbv_faulted);

    // Without AVX, XCR0 is irrelevant and is not read either.
    f = AVX2_USABLE;
    f.leaf1_ecx &= ~LEAF1_ECX_AVX;
    BOOST_CHECK(!HasUsableAVX2(DetectFake(f)));
    BOOST_CHECK_EQUAL(g_cpu.xgetbv_calls, 0);

    // The OS does not save YMM state.
    f = AVX2_USABLE;
    f.xcr0 = 0x3;
    BOOST_CHECK(!HasUsableAVX2(DetectFake(f)));
    BOOST_CHECK_EQUAL(g_cpu.xgetbv_calls, 1);

    // Leaf 7 is never queried when the CPU does not support it, even though
    // the fake would report AVX2 there.
    f = AVX2_USABLE;
    f.max_basic_leaf = 6;
    BOOST_CHECK(!HasUsableAVX2(DetectFake(f)));
    BOOST_CHECK(g_cpu.leaves == (std::vector<uint32_t>{0, 1}));
    BOOST_CHECK_EQUAL(DetectFake(f).leaf7_ebx, 0U);

    f = AVX2_USABLE;
    f.max_basic_leaf = 0;
    BOOST_CHECK(!HasUsableAVX2(DetectFake(f)));
    BOOST_CHECK(g_cpu.leaves == (std::vector<uint32_t>{0}));
    BOOST_CHECK_EQUAL(g_cpu.xgetbv_calls, 0);
}

BOOST_AUTO_TEST_CASE(mlkem_x86_native_matrix)
{
    static_assert(HasMlkemX86Native(MLKEM_X86_NATIVE));
    static_assert(HasUsableAVX2(MLKEM_X86_NATIVE));
    // AVX2 alone is not enough: the assembly also executes SSSE3, SSE4.1, POPCNT and BMI2.
    static_assert(!HasMlkemX86Native(AVX2_USABLE));

    // Clearing any single requirement, the AVX2 ones included, makes the backend unusable.
    const auto without_leaf1{[](uint32_t bit) { X86Features f{MLKEM_X86_NATIVE}; f.leaf1_ecx &= ~bit; return f; }};
    const auto without_leaf7{[](uint32_t bit) { X86Features f{MLKEM_X86_NATIVE}; f.leaf7_ebx &= ~bit; return f; }};
    BOOST_CHECK(!HasMlkemX86Native(without_leaf1(LEAF1_ECX_SSSE3)));
    BOOST_CHECK(!HasMlkemX86Native(without_leaf1(LEAF1_ECX_SSE41)));
    BOOST_CHECK(!HasMlkemX86Native(without_leaf1(LEAF1_ECX_POPCNT)));
    BOOST_CHECK(!HasMlkemX86Native(without_leaf1(LEAF1_ECX_OSXSAVE)));
    BOOST_CHECK(!HasMlkemX86Native(without_leaf1(LEAF1_ECX_AVX)));
    BOOST_CHECK(!HasMlkemX86Native(without_leaf7(LEAF7_EBX_BMI2)));
    BOOST_CHECK(!HasMlkemX86Native(without_leaf7(LEAF7_EBX_AVX2)));
    X86Features f{MLKEM_X86_NATIVE};
    f.max_basic_leaf = 6;
    BOOST_CHECK(!HasMlkemX86Native(f));
    f = MLKEM_X86_NATIVE;
    f.xcr0 = 0x3;
    BOOST_CHECK(!HasMlkemX86Native(f));
    // Masking BMI2 or POPCNT leaves AVX2 usable, which is exactly why AVX2 alone is not checked.
    BOOST_CHECK(HasUsableAVX2(without_leaf7(LEAF7_EBX_BMI2)));
    BOOST_CHECK(HasUsableAVX2(without_leaf1(LEAF1_ECX_POPCNT)));

    // Unrelated bits change nothing.
    f = MLKEM_X86_NATIVE;
    f.leaf7_ebx |= LEAF7_EBX_SHA;
    f.leaf1_ecx |= uint32_t{1} << 20; // SSE4.2
    BOOST_CHECK(HasMlkemX86Native(f));

    // Detection gathers every bit the check reads.
    BOOST_CHECK(HasMlkemX86Native(DetectFake(MLKEM_X86_NATIVE)));
    BOOST_CHECK(!HasMlkemX86Native(DetectFake(without_leaf7(LEAF7_EBX_BMI2))));
    BOOST_CHECK(!HasMlkemX86Native(DetectFake(without_leaf1(LEAF1_ECX_POPCNT))));
}

BOOST_AUTO_TEST_CASE(usable_avx2_host)
{
    const X86Features detected{DetectX86Features()};
    BOOST_CHECK_EQUAL(HasUsableAVX2(), HasUsableAVX2(detected));
    // The cached answer is stable.
    BOOST_CHECK_EQUAL(HasUsableAVX2(), HasUsableAVX2());
#if defined(HAVE_GETCPUID) && (defined(__GNUC__) || defined(__clang__))
    BOOST_TEST_MESSAGE("host: avx2=" << HasUsableAVX2() << " mlkem_x86_native=" << HasMlkemX86Native()
                       << " sha_ni=" << ((detected.leaf7_ebx & LEAF7_EBX_SHA) != 0));
    BOOST_CHECK_EQUAL(HasMlkemX86Native(), HasMlkemX86Native(detected));
#ifdef HAVE_BUILTIN_CPU_SUPPORTS
    // The compiler's own detection, as an independent check.
    __builtin_cpu_init();
    BOOST_CHECK_EQUAL(HasUsableAVX2(), __builtin_cpu_supports("avx2") != 0);
    BOOST_CHECK_EQUAL(HasMlkemX86Native(), __builtin_cpu_supports("avx2") && __builtin_cpu_supports("ssse3") &&
                                               __builtin_cpu_supports("sse4.1") && __builtin_cpu_supports("popcnt") &&
                                               __builtin_cpu_supports("bmi2"));
#endif
#else
    // Non-x86 targets and unsupported compilers never report AVX2.
    BOOST_CHECK(!HasUsableAVX2());
    BOOST_CHECK(!HasMlkemX86Native());
    BOOST_CHECK_EQUAL(detected.max_basic_leaf, 0U);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
