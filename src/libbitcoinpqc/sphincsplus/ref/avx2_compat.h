#ifndef SPX_AVX2_COMPAT_H
#define SPX_AVX2_COMPAT_H

#include "opt_flags.h"

#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

static inline int spx_has_avx2(void)
{
    if (spx_opt_disable_simd()) {
        return 0;
    }

#if defined(SPX_AVX2) && (defined(__x86_64__) || defined(__i386__))
#if defined(__APPLE__)
    int has_avx2 = 0;
    size_t len = sizeof(has_avx2);
    if (sysctlbyname("hw.optional.avx2_0", &has_avx2, &len, NULL, 0) != 0) {
        return 0;
    }
    return has_avx2 == 1;
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("avx2");
#else
    return 0;
#endif
#endif
    return 0;
}

#endif
