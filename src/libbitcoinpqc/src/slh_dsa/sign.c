#include <stdio.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"
#include "../secure_zero.h"

#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/sign_stats.h"

/* Debug mode flag - set to 0 to disable debug output */
#define SLH_DSA_DEBUG 0

/* Conditional debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (SLH_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

/*
 * External declaration for the random data utilities
 * These are implemented in src/slh_dsa/utils.c
 */
extern void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void slh_dsa_setup_custom_random(void);
extern void slh_dsa_restore_original_random(void);
extern void slh_dsa_random_source_clear_failure(void);
extern int slh_dsa_random_source_failed(void);
extern void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

int slh_dsa_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    return slh_dsa_sign_with_stats(sig, siglen, m, mlen, sk, NULL);
}

int slh_dsa_sign_with_stats(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    bitcoin_pqc_sign_stats_t *stats
) {
    if (!sig || !siglen || (!m && mlen != 0) || !sk) {
        return -1;
    }

    if (slh_dsa_secret_key_validate(sk, SLH_DSA_SECRET_KEY_SIZE) != 0) {
        bitcoin_pqc_secure_zero(sig, CRYPTO_BYTES);
        *siglen = 0;
        return -1;
    }

    DEBUG_PRINT("SLH-DSA sign: Starting to sign message of length %zu\n", mlen);

    const uint8_t empty_message = 0;
    const uint8_t *message = m ? m : &empty_message;

    /* Deterministic signing randomization derived from (sk || message). */
    uint8_t deterministic_seed[64];
    bitcoin_pqc_sign_stats_t scratch_stats;
    bitcoin_pqc_sign_stats_t *active_stats = stats ? stats : &scratch_stats;

    slh_dsa_random_source_clear_failure();
    slh_dsa_derandomize(deterministic_seed, message, mlen, sk);
    if (slh_dsa_random_source_failed()) {
        bitcoin_pqc_secure_zero(sig, CRYPTO_BYTES);
        *siglen = 0;
        bitcoin_pqc_secure_zero(deterministic_seed, sizeof(deterministic_seed));
        return -1;
    }

    slh_dsa_init_random_source(deterministic_seed, sizeof(deterministic_seed));
    slh_dsa_setup_custom_random();
    bitcoin_pqc_sign_stats_begin(active_stats);

    int result = crypto_sign_signature(sig, siglen, message, mlen, sk);
    int random_source_failed = slh_dsa_random_source_failed();
    DEBUG_PRINT("SLH-DSA sign: signature result = %d, length = %zu\n", result, *siglen);

    bitcoin_pqc_sign_stats_end();
    slh_dsa_restore_original_random();
    bitcoin_pqc_secure_zero(deterministic_seed, sizeof(deterministic_seed));

    if (random_source_failed) {
        bitcoin_pqc_secure_zero(sig, CRYPTO_BYTES);
        *siglen = 0;
        return -1;
    }

    if (result != 0) {
        bitcoin_pqc_secure_zero(sig, CRYPTO_BYTES);
        *siglen = 0;
    }

    return result;
}
