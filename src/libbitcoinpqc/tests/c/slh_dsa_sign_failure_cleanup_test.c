#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"

#ifndef BITCOINPQC_WOTSC_MAX_COUNTER
#define BITCOINPQC_WOTSC_MAX_COUNTER 0xffffu
#endif

#define MIN_ENTROPY_SIZE 128u
#define LOW_CAP_MESSAGE_COUNT 32u

static void fill_entropy(uint8_t *out, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)(0x41u + (uint8_t)((i * 31u) & 0xffu));
    }
}

static void store_u64_le(uint8_t out[8], uint64_t value) {
    size_t i;

    for (i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value >> (8u * i));
    }
}

static int fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int signature_is_zero(const uint8_t *sig, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        if (sig[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int test_low_wots_cap_clears_failed_signature(void) {
    uint8_t entropy[MIN_ENTROPY_SIZE];
    uint8_t pk[SLH_DSA_PUBLIC_KEY_SIZE];
    uint8_t sk[SLH_DSA_SECRET_KEY_SIZE];
    unsigned int counter;

    fill_entropy(entropy, sizeof(entropy));
    if (slh_dsa_keygen(pk, sk, entropy, sizeof(entropy)) != 0) {
        return fail("slh_dsa_keygen should succeed");
    }

    for (counter = 0; counter < LOW_CAP_MESSAGE_COUNT; counter++) {
        uint8_t message[8];
        uint8_t sig[SLH_DSA_SIGNATURE_SIZE];
        size_t siglen = SLH_DSA_SIGNATURE_SIZE;
        bitcoin_pqc_sign_stats_t stats = {0};
        int result;

        store_u64_le(message, (uint64_t)counter);
        memset(sig, 0xa5, sizeof(sig));

        result = slh_dsa_sign_with_stats(
            sig,
            &siglen,
            message,
            sizeof(message),
            sk,
            &stats
        );

        if (result == 0) {
            continue;
        }
        if (siglen != 0) {
            return fail("failed signing should reset siglen to zero");
        }
        if ((stats.cap_exceeded & BITCOIN_PQC_SIGN_LIMIT_WOTSC) == 0) {
            return fail("failed signing should report WOTS+C cap exceeded");
        }
        if (!signature_is_zero(sig, sizeof(sig))) {
            return fail("failed signing should zero caller-owned signature buffer");
        }

        printf("SLH-DSA failed-signature cleanup test passed\n");
        return 0;
    }

    return fail("low WOTS+C cap unexpectedly signed the deterministic corpus");
}

int main(void) {
#if BITCOINPQC_WOTSC_MAX_COUNTER == 0
    return test_low_wots_cap_clears_failed_signature();
#else
    printf("SLH-DSA failed-signature cleanup test skipped without low WOTS+C cap\n");
    return 0;
#endif
}
