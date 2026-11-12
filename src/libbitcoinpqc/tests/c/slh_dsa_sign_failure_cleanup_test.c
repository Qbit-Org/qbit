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

/* A rejected argument must leave the caller with the same cleanup as any
   other failure: zeroed sig and *siglen == 0 wherever those pointers are
   usable, and stats untouched because signing never started. */
static int expect_rejected_sign_clears_outputs(
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const char *label
) {
    uint8_t sig[SLH_DSA_SIGNATURE_SIZE];
    size_t siglen = SLH_DSA_SIGNATURE_SIZE;
    bitcoin_pqc_sign_stats_t stats;
    bitcoin_pqc_sign_stats_t stats_before;
    int result;

    memset(sig, 0xa5, sizeof(sig));
    result = slh_dsa_sign(sig, &siglen, m, mlen, sk);
    if (result != -1) {
        fprintf(stderr, "%s: slh_dsa_sign should return -1, got %d\n", label, result);
        return 1;
    }
    if (siglen != 0) {
        fprintf(stderr, "%s: rejected slh_dsa_sign should reset siglen to zero\n", label);
        return 1;
    }
    if (!signature_is_zero(sig, sizeof(sig))) {
        fprintf(stderr, "%s: rejected slh_dsa_sign should zero the signature buffer\n", label);
        return 1;
    }

    memset(sig, 0xa5, sizeof(sig));
    siglen = SLH_DSA_SIGNATURE_SIZE;
    memset(&stats, 0x5a, sizeof(stats));
    memcpy(&stats_before, &stats, sizeof(stats));
    result = slh_dsa_sign_with_stats(sig, &siglen, m, mlen, sk, &stats);
    if (result != -1) {
        fprintf(stderr, "%s: slh_dsa_sign_with_stats should return -1, got %d\n", label, result);
        return 1;
    }
    if (siglen != 0 || !signature_is_zero(sig, sizeof(sig))) {
        fprintf(stderr, "%s: rejected slh_dsa_sign_with_stats should clear sig and siglen\n", label);
        return 1;
    }
    if (memcmp(&stats, &stats_before, sizeof(stats)) != 0) {
        fprintf(stderr, "%s: rejected slh_dsa_sign_with_stats should leave stats unchanged\n", label);
        return 1;
    }

    return 0;
}

static int test_rejected_arguments_clear_outputs(void) {
    static const uint8_t message[8] = {0x71, 0x62, 0x69, 0x74, 0x2d, 0x70, 0x71, 0x63};
    uint8_t entropy[MIN_ENTROPY_SIZE];
    uint8_t pk[SLH_DSA_PUBLIC_KEY_SIZE];
    uint8_t sk[SLH_DSA_SECRET_KEY_SIZE];
    uint8_t sig[SLH_DSA_SIGNATURE_SIZE];
    size_t siglen;
    bitcoin_pqc_sign_stats_t stats;
    bitcoin_pqc_sign_stats_t stats_before;
    int result;

    fill_entropy(entropy, sizeof(entropy));
    if (slh_dsa_keygen(pk, sk, entropy, sizeof(entropy)) != 0) {
        return fail("slh_dsa_keygen should succeed");
    }

    if (expect_rejected_sign_clears_outputs(NULL, sizeof(message), sk, "NULL message with nonzero mlen") ||
        expect_rejected_sign_clears_outputs(message, sizeof(message), NULL, "NULL secret key")) {
        return 1;
    }

    /* Only the non-NULL output can be written. */
    siglen = SLH_DSA_SIGNATURE_SIZE;
    result = slh_dsa_sign(NULL, &siglen, message, sizeof(message), sk);
    if (result != -1 || siglen != 0) {
        return fail("NULL sig: slh_dsa_sign should return -1 and reset siglen to zero");
    }
    memset(sig, 0xa5, sizeof(sig));
    result = slh_dsa_sign(sig, NULL, message, sizeof(message), sk);
    if (result != -1 || !signature_is_zero(sig, sizeof(sig))) {
        return fail("NULL siglen: slh_dsa_sign should return -1 and zero the signature buffer");
    }

    /* A rejected key fails before signing starts, so stats stay untouched. */
    sk[SLH_DSA_SECRET_KEY_SIZE - 1] ^= 0x80u;
    memset(sig, 0xa5, sizeof(sig));
    siglen = SLH_DSA_SIGNATURE_SIZE;
    memset(&stats, 0x5a, sizeof(stats));
    memcpy(&stats_before, &stats, sizeof(stats));
    result = slh_dsa_sign_with_stats(sig, &siglen, message, sizeof(message), sk, &stats);
    if (result != SLH_DSA_SIGN_ERROR_BAD_KEY) {
        fprintf(stderr, "inconsistent key: expected %d, got %d\n", SLH_DSA_SIGN_ERROR_BAD_KEY, result);
        return 1;
    }
    if (siglen != 0 || !signature_is_zero(sig, sizeof(sig))) {
        return fail("inconsistent key: slh_dsa_sign_with_stats should clear sig and siglen");
    }
    if (memcmp(&stats, &stats_before, sizeof(stats)) != 0) {
        return fail("inconsistent key: slh_dsa_sign_with_stats should leave stats unchanged");
    }

    printf("SLH-DSA rejected-argument cleanup test passed\n");
    return 0;
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
    if (test_rejected_arguments_clear_outputs()) {
        return 1;
    }
#if BITCOINPQC_WOTSC_MAX_COUNTER == 0
    return test_low_wots_cap_clears_failed_signature();
#else
    printf("SLH-DSA failed-signature cleanup test skipped without low WOTS+C cap\n");
    return 0;
#endif
}
