// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

// Reports which native backends mlkem-native was compiled with. This file is
// built with the same configuration and flags as mlkem-native's single
// compilation unit, so the backend headers it sees are the ones compiled in.

#include <mlkem/src/common.h>

#include <crypto/mlkem_shim.h>

const char* qbit_mlkem_compiled_arith_backend(void)
{
#if defined(QBIT_MLKEM_ARITH_BACKEND_NAME)
    return QBIT_MLKEM_ARITH_BACKEND_NAME;
#else
    return "portable";
#endif
}

const char* qbit_mlkem_compiled_keccak_backend(void)
{
#if defined(QBIT_MLKEM_KECCAK_BACKEND_NAME)
    return QBIT_MLKEM_KECCAK_BACKEND_NAME;
#else
    return "portable";
#endif
}
