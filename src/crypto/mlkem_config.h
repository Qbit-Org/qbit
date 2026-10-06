// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_CRYPTO_MLKEM_CONFIG_H
#define QBIT_CRYPTO_MLKEM_CONFIG_H

// qbit's configuration of the vendored mlkem-native library, selected with
// MLK_CONFIG_FILE in place of upstream's mlkem/mlkem_native_config.h, which
// documents every option used here. cmake/mlkem-native.cmake decides whether
// native code may be built and passes that decision in:
//
//   QBIT_MLKEM_NATIVE  build the native backends for this target (x86_64 with
//                      the SysV ABI, or AArch64 with NEON on Apple: AArch64
//                      ELF targets stay portable because the assembly would
//                      strip their BTI and PAC marking);
//   MLK_CONFIG_NO_ASM  no assembly at all (MSVC and other toolchains without
//                      GNU assembler support).
//
// Neither set means portable C with inline-assembly value barriers.

#define MLK_CONFIG_PARAMETER_SET 1024
#define MLK_CONFIG_NAMESPACE_PREFIX qbit_mlkem1024
// Only the deterministic APIs exist: callers supply all entropy.
#define MLK_CONFIG_NO_RANDOMIZED_API

#if defined(MLK_BUILD_INTERNAL)

#define MLK_CONFIG_CUSTOM_ZEROIZE
#define MLK_CONFIG_CUSTOM_CAPABILITY_FUNC

// After the options sys.h reads, before the code that needs its definitions.
#include <mlkem/src/sys.h>

#if defined(QBIT_MLKEM_NATIVE)
#if defined(MLK_CONFIG_NO_ASM)
#error "QBIT_MLKEM_NATIVE and MLK_CONFIG_NO_ASM are both set; cmake/mlkem-native.cmake sets at most one."
#endif
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#error "MemorySanitizer cannot see writes made by assembly; configure with WITH_MLKEM_NATIVE=AUTO or OFF."
#endif
#endif
#if defined(MLK_SYS_AARCH64) && defined(__ELF__)
#error "mlkem-native AArch64 assembly has no BTI landing pads or GNU property note; AArch64 ELF builds are portable only."
#endif
// Enable a backend only where qbit selects and tests one. Never define these
// to 0: upstream checks whether they are defined.
#if (defined(MLK_SYS_X86_64) && defined(MLK_SYSV_ABI_SUPPORTED)) || \
    (defined(MLK_SYS_AARCH64) && defined(MLK_SYS_AARCH64_NEON) && defined(MLK_SYS_APPLE))
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_ARITH_BACKEND_FILE "crypto/mlkem_arith_backend.h"
#define MLK_CONFIG_FIPS202_BACKEND_FILE "crypto/mlkem_fips202_backend.h"
#else
#error "QBIT_MLKEM_NATIVE is set, but qbit has no native ML-KEM backend for this target; cmake/mlkem-native.cmake and this header disagree."
#endif
#endif // QBIT_MLKEM_NATIVE

#if !defined(__ASSEMBLER__)
#include <crypto/mlkem_shim.h>

static MLK_INLINE void mlk_zeroize(void* ptr, size_t len)
{
    qbit_mlkem_zeroize(ptr, len);
}

// Backends call this 80 to 100 times per operation, so it reads only state
// that crypto/mlkem.cpp cached before the operation started. Capabilities qbit
// does not use, MLK_SYS_CAP_AARCH64_SHA3 included, are never available.
MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_sys_check_capability(mlk_sys_cap cap)
{
#if defined(MLK_SYS_X86_64)
    // Upstream gates its whole x86_64 backend on this one capability, so the
    // answer covers every extension that assembly executes, not only AVX2.
    if (cap == MLK_SYS_CAP_X86_64_AVX2) return qbit_mlkem_has_avx2() ? 1 : 0;
#endif
#if defined(MLK_SYS_AARCH64)
    if (cap == MLK_SYS_CAP_AARCH64_NEON) return qbit_mlkem_has_neon() ? 1 : 0;
#endif
    (void)cap;
    return 0;
}
#endif // !__ASSEMBLER__

#endif // MLK_BUILD_INTERNAL

#endif // QBIT_CRYPTO_MLKEM_CONFIG_H
