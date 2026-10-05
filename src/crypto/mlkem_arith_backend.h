// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_CRYPTO_MLKEM_ARITH_BACKEND_H
#define QBIT_CRYPTO_MLKEM_ARITH_BACKEND_H

// mlkem-native arithmetic backend (MLK_CONFIG_ARITH_BACKEND_FILE), used only
// when crypto/mlkem_config.h enables native code.
//
// Upstream's default selector, native/meta.h, picks the x86_64 backend only
// when the compiler itself targets AVX2, which baseline release builds do not.
// qbit includes the backend unconditionally instead: it is assembly plus
// constant tables, and every entry point asks mlk_sys_check_capability()
// before running, so CPUs without AVX2 take the portable C path. qbit answers
// MLK_SYS_CAP_X86_64_AVX2 for every extension the assembly executes (AVX2,
// SSSE3, SSE4.1, POPCNT, BMI2), not only the AVX2 its name says.

#if defined(MLK_SYS_X86_64)
#define QBIT_MLKEM_ARITH_BACKEND_NAME "x86_64-avx2"
#include <mlkem/src/native/x86_64/meta.h>
#elif defined(MLK_SYS_AARCH64)
#define QBIT_MLKEM_ARITH_BACKEND_NAME "aarch64-neon"
#include <mlkem/src/native/aarch64/meta.h>
#else
#error "No mlkem-native arithmetic backend for this target."
#endif

#endif // QBIT_CRYPTO_MLKEM_ARITH_BACKEND_H
