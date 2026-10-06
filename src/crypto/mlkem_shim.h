// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_CRYPTO_MLKEM_SHIM_H
#define QBIT_CRYPTO_MLKEM_SHIM_H

// C ABI between mlkem-native, which is C compiled with crypto/mlkem_config.h,
// and qbit's C++ code. mlkem-native's assembly includes the configuration too,
// so the declarations are hidden from the assembler.

#if !defined(__ASSEMBLER__)
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Implemented in C++, in crypto/mlkem.cpp.

/** Wipe len bytes at ptr. Forwards to memory_cleanse. */
void qbit_mlkem_zeroize(void* ptr, size_t len);
/**
 * 1 if mlkem-native may run its x86_64 assembly now, else 0. Besides AVX2 that
 * assembly needs SSSE3, SSE4.1, POPCNT and BMI2 (cpu_features::HasMlkemX86Native).
 * Reads cached state only.
 */
int qbit_mlkem_has_avx2(void);
/** 1 if mlkem-native may run its AArch64 code now, else 0. Reads cached state only. */
int qbit_mlkem_has_neon(void);

// Implemented in C, in crypto/mlkem_backend.c, with mlkem-native's configuration.

/** Name of the native arithmetic backend compiled in, or "portable". */
const char* qbit_mlkem_compiled_arith_backend(void);
/** Name of the native Keccak backend compiled in, or "portable". */
const char* qbit_mlkem_compiled_keccak_backend(void);

#ifdef __cplusplus
}
#endif
#endif // !__ASSEMBLER__

#endif // QBIT_CRYPTO_MLKEM_SHIM_H
