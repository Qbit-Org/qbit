#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"
#include "../../src/secure_zero.h"

#define MIN_ENTROPY_SIZE 128u
#define SPX_N_BYTES 16u
/* Probe at least 64 KiB past the burn, so the paint check below the burned
   window keeps its room when BITCOIN_PQC_BURN_STACK_BYTES is overridden. */
#if BITCOIN_PQC_BURN_STACK_BYTES + 64u * 1024u > 320u * 1024u
#define PROBE_STACK_BYTES (BITCOIN_PQC_BURN_STACK_BYTES + 64u * 1024u)
#else
#define PROBE_STACK_BYTES (320u * 1024u)
#endif

static void fill_entropy(uint8_t *out, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)(0x5au + (uint8_t)((i * 29u) & 0xffu));
    }
}

static int fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

/*
 * Scan the stack region just released by the library call for an exact copy
 * of a secret-key component. The probe frame overlaps the frames the call used, so a scratch
 * copy that was not wiped before return is still visible here.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static int stack_contains(const uint8_t *needle, size_t needle_len) {
    volatile uint8_t probe[PROBE_STACK_BYTES];
    size_t i;
    size_t j;

    for (i = 0; i + needle_len <= sizeof(probe); i++) {
        for (j = 0; j < needle_len; j++) {
            if (probe[i + j] != needle[j]) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

/*
 * The library burns BITCOIN_PQC_BURN_STACK_BYTES of released stack when a
 * secret-key entry point returns. Paint the region first so a missing burn
 * leaves the call's own residue rather than fresh zero pages, then require
 * the burned window below the entry point's frames to be zero, and the
 * region below that window to still hold the paint: a call that runs deeper
 * than the burn leaves its unwiped frames there. BURN_CHECK_SKIP_BYTES allows
 * for the entry-point wrapper frames above the burn, for the burn's own frame
 * below it, and for the probe frame's own layout at the bottom.
 */
#define STACK_PAINT 0xa5u
#define BURN_CHECK_SKIP_BYTES (2u * 1024u)
#define BURN_CHECK_BYTES (BITCOIN_PQC_BURN_STACK_BYTES - 2u * BURN_CHECK_SKIP_BYTES)
#define PAINT_CHECK_END (PROBE_STACK_BYTES - BITCOIN_PQC_BURN_STACK_BYTES - 2u * BURN_CHECK_SKIP_BYTES)

#if BITCOIN_PQC_BURN_STACK_BYTES <= 2u * BURN_CHECK_SKIP_BYTES || \
    BITCOIN_PQC_BURN_STACK_BYTES + 4u * BURN_CHECK_SKIP_BYTES > PROBE_STACK_BYTES
#error "stack scrub test window does not fit BITCOIN_PQC_BURN_STACK_BYTES"
#endif

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static void stack_paint(void) {
    volatile uint8_t probe[PROBE_STACK_BYTES];
    size_t i;

    for (i = 0; i < sizeof(probe); i++) {
        probe[i] = STACK_PAINT;
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static int stack_burned(void) {
    volatile uint8_t probe[PROBE_STACK_BYTES];
    size_t end = sizeof(probe) - BURN_CHECK_SKIP_BYTES;
    size_t i;

    for (i = end - BURN_CHECK_BYTES; i < end; i++) {
        if (probe[i] != 0) {
            return 0;
        }
    }
    return 1;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static size_t stack_overrun_depth(void) {
    volatile uint8_t probe[PROBE_STACK_BYTES];
    size_t i;

    for (i = BURN_CHECK_SKIP_BYTES; i < PAINT_CHECK_END; i++) {
        if (probe[i] != STACK_PAINT) {
            return sizeof(probe) - i;
        }
    }
    return 0;
}

/* Take both window results before printing, because fprintf would overwrite
   the paint. */
static int check_burn(int burned, size_t overrun_depth, const char *call) {
    int rc = 0;

    if (!burned) {
        fprintf(stderr, "released stack not burned after %s\n", call);
        rc = 1;
    }
    if (overrun_depth != 0) {
        fprintf(stderr,
                "%s left unburned stack %zu bytes below the probe top, past the %u-byte burn\n",
                call, overrun_depth, (unsigned)BITCOIN_PQC_BURN_STACK_BYTES);
        rc = 1;
    }
    return rc;
}

int main(void) {
    uint8_t *entropy = malloc(MIN_ENTROPY_SIZE);
    uint8_t *pk = malloc(SLH_DSA_PUBLIC_KEY_SIZE);
    uint8_t *sk = malloc(SLH_DSA_SECRET_KEY_SIZE);
    uint8_t *sig = malloc(SLH_DSA_SIGNATURE_SIZE);
    uint8_t *sk_seed = malloc(SPX_N_BYTES);
    uint8_t *sk_prf = malloc(SPX_N_BYTES);
    static const uint8_t message[32] = {0x01};
    uint8_t derandomized[64];
    size_t siglen = SLH_DSA_SIGNATURE_SIZE;
    int burned;
    size_t overrun_depth;
    int rc = 0;

    if (entropy == NULL || pk == NULL || sk == NULL || sig == NULL ||
        sk_seed == NULL || sk_prf == NULL) {
        return fail("allocation failed");
    }

    fill_entropy(entropy, MIN_ENTROPY_SIZE);
    stack_paint();
    if (slh_dsa_keygen(pk, sk, entropy, MIN_ENTROPY_SIZE) != 0) {
        return fail("slh_dsa_keygen should succeed");
    }
    burned = stack_burned();
    overrun_depth = stack_overrun_depth();
    rc |= check_burn(burned, overrun_depth, "slh_dsa_keygen");
    memcpy(sk_seed, sk, SPX_N_BYTES);
    memcpy(sk_prf, sk + SPX_N_BYTES, SPX_N_BYTES);
    if (stack_contains(sk_seed, SPX_N_BYTES)) {
        rc |= fail("SK_SEED copy left on the stack after slh_dsa_keygen");
    }
    if (stack_contains(sk_prf, SPX_N_BYTES)) {
        rc |= fail("SK_PRF copy left on the stack after slh_dsa_keygen");
    }

    stack_paint();
    if (slh_dsa_secret_key_validate(sk, SLH_DSA_SECRET_KEY_SIZE) != 0) {
        return fail("slh_dsa_secret_key_validate should succeed");
    }
    burned = stack_burned();
    overrun_depth = stack_overrun_depth();
    rc |= check_burn(burned, overrun_depth, "slh_dsa_secret_key_validate");

    stack_paint();
    slh_dsa_derandomize(derandomized, message, sizeof(message), sk);
    burned = stack_burned();
    overrun_depth = stack_overrun_depth();
    rc |= check_burn(burned, overrun_depth, "slh_dsa_derandomize");

    stack_paint();
    if (slh_dsa_sign(sig, &siglen, message, sizeof(message), sk) != 0) {
        return fail("slh_dsa_sign should succeed");
    }
    burned = stack_burned();
    overrun_depth = stack_overrun_depth();
    rc |= check_burn(burned, overrun_depth, "slh_dsa_sign");
    if (stack_contains(sk_seed, SPX_N_BYTES)) {
        rc |= fail("SK_SEED copy left on the stack after slh_dsa_sign");
    }
    if (stack_contains(sk_prf, SPX_N_BYTES)) {
        rc |= fail("SK_PRF copy left on the stack after slh_dsa_sign");
    }

    if (rc == 0) {
        printf("SLH-DSA stack scrub test passed\n");
    }
    free(entropy);
    free(pk);
    free(sk);
    free(sig);
    free(sk_seed);
    free(sk_prf);
    return rc;
}
