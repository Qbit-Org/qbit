#ifndef LIBBITCOINPQC_SECURE_ZERO_H
#define LIBBITCOINPQC_SECURE_ZERO_H

#include <stddef.h>

static inline void bitcoin_pqc_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len > 0) {
        *p++ = 0;
        len--;
    }
}

/*
 * Bytes of released stack that bitcoin_pqc_burn_stack() overwrites. The SHA-2
 * compression functions keep the message schedule and working variables in
 * locals that may spill to the stack, and that schedule is reversible to the
 * hashed block (SK_SEED, SK_PRF, derived seeds). Burning once when a
 * secret-key entry point returns covers every frame the call released, at the
 * cost of one wipe per call rather than one per compression.
 *
 * The burn is sized to the stack the calls already use, so it adds little to
 * the caller's stack requirement. Measured by painting the stack (x86-64 GCC,
 * AVX2 path): optimized native keygen/sign use about 13 KiB below the entry
 * point, unoptimized builds about 200 KiB (the -O0 AVX2 8-way transform frame
 * alone is ~190 KiB). Emscripten -O3 keygen/sign use about 1.6 KiB of the
 * linear-memory stack; its reference SHA-2 keeps the schedule in WASM locals.
 * Frames deeper than the burn on another compiler or target are not covered;
 * define BITCOIN_PQC_BURN_STACK_BYTES to match a measured depth.
 */
#ifndef BITCOIN_PQC_BURN_STACK_BYTES
#if defined(__EMSCRIPTEN__)
#define BITCOIN_PQC_BURN_STACK_BYTES (4u * 1024u)
#elif (defined(__GNUC__) || defined(__clang__)) && !defined(__OPTIMIZE__)
#define BITCOIN_PQC_BURN_STACK_BYTES (208u * 1024u)
#else
#define BITCOIN_PQC_BURN_STACK_BYTES (16u * 1024u)
#endif
#endif

#if BITCOIN_PQC_BURN_STACK_BYTES < 1
#error "BITCOIN_PQC_BURN_STACK_BYTES must be positive"
#endif

/* Must not be inlined: the scratch array has to occupy the frames the
   just-returned call released, below the caller's frame. "unused" keeps
   translation units that include this header without burning quiet. */
#if defined(__GNUC__) || defined(__clang__)
#define BITCOIN_PQC_BURN_STACK_ATTRS __attribute__((noinline, unused))
#elif defined(_MSC_VER)
#define BITCOIN_PQC_BURN_STACK_ATTRS __inline __declspec(noinline)
#else
#define BITCOIN_PQC_BURN_STACK_ATTRS
#endif

static BITCOIN_PQC_BURN_STACK_ATTRS void bitcoin_pqc_burn_stack(void) {
    unsigned char scratch[BITCOIN_PQC_BURN_STACK_BYTES];

    bitcoin_pqc_secure_zero(scratch, sizeof(scratch));
}

#endif /* LIBBITCOINPQC_SECURE_ZERO_H */
