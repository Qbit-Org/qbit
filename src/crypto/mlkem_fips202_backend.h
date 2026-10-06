// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_CRYPTO_MLKEM_FIPS202_BACKEND_H
#define QBIT_CRYPTO_MLKEM_FIPS202_BACKEND_H

// mlkem-native Keccak backend (MLK_CONFIG_FIPS202_BACKEND_FILE), used only
// when crypto/mlkem_config.h enables native code. See
// crypto/mlkem_arith_backend.h for why the backend is chosen here rather than
// by upstream's fips202/native/auto.h.

#if defined(MLK_SYS_X86_64)
#define QBIT_MLKEM_KECCAK_BACKEND_NAME "x86_64-avx2"
#include <mlkem/src/fips202/native/x86_64/keccak_f1600_x4_avx2.h>

#elif defined(MLK_SYS_AARCH64)
#define QBIT_MLKEM_KECCAK_BACKEND_NAME "aarch64"
// The Keccak upstream picks for AArch64 without the SHA3 extension, used on
// Apple too even though Apple CPUs have it, so that every native AArch64 build
// runs the same code. (Native AArch64 is Apple-only for now; see
// crypto/mlkem_config.h.)
#include <mlkem/src/fips202/native/aarch64/x4_v8a_scalar.h>

// Single-lane Keccak. This mirrors mlkem/src/fips202/native/aarch64/x1_scalar.h
// of mlkem-native v2.0.0 (d1b2fe782888bdb761a50336012923180be7f502): the same
// macros and the same proved assembly routine. The one difference is the
// capability check. Upstream's x1 entry point runs its scalar assembly
// unconditionally, so the portable override could not reach it, and
// mlkem::GetBackendNames() would claim portable Keccak while assembly ran.
// Here it falls back to C whenever the AArch64 capability is off. On every
// library update, diff upstream's x1_scalar.h against this block (see
// doc/subtrees/mlkem-native.md).
#define MLK_USE_NATIVE_FIPS202_X1
#define MLK_FIPS202_AARCH64_NEED_X1_SCALAR
#if !defined(__ASSEMBLER__)
#include <mlkem/src/fips202/native/api.h>
#include <mlkem/src/fips202/native/aarch64/src/fips202_native_aarch64.h>
MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_keccak_f1600_x1_native(uint64_t* state)
{
    if (!mlk_sys_check_capability(MLK_SYS_CAP_AARCH64_NEON)) {
        return MLK_NATIVE_FUNC_FALLBACK;
    }

    mlk_keccak_f1600_x1_scalar_aarch64_asm(state, mlk_keccakf1600_round_constants);
    return MLK_NATIVE_FUNC_SUCCESS;
}
#endif // !__ASSEMBLER__

#else
#error "No mlkem-native Keccak backend for this target."
#endif

#endif // QBIT_CRYPTO_MLKEM_FIPS202_BACKEND_H
