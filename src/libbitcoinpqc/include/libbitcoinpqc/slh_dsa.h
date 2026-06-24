/**
 * @file slh_dsa.h
 * @brief SLH-DSA-SHA2-128s (bounded, h=30) specific functions
 */

#ifndef BITCOIN_PQC_SLH_DSA_H
#define BITCOIN_PQC_SLH_DSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "libbitcoinpqc/sign_stats.h"

/* SLH-DSA-SHA2-128s-bounded30 constants */
#define SLH_DSA_PUBLIC_KEY_SIZE 32
#define SLH_DSA_SECRET_KEY_SIZE 64
#define SLH_DSA_SIGNATURE_SIZE 3680
#define SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE 128

/* Backward-compatible aliases for explicit profile naming */
#define SLH_DSA_SHA2_128S_BOUNDED30_PUBLIC_KEY_SIZE SLH_DSA_PUBLIC_KEY_SIZE
#define SLH_DSA_SHA2_128S_BOUNDED30_SECRET_KEY_SIZE SLH_DSA_SECRET_KEY_SIZE
#define SLH_DSA_SHA2_128S_BOUNDED30_SIGNATURE_SIZE SLH_DSA_SIGNATURE_SIZE

/**
 * @brief Generate an SLH-DSA-SHA2-128s-bounded30 key pair.
 *
 * On success, pk and sk are a self-consistent same-call output pair. The secret
 * key layout is [SK_SEED || SK_PRF || PUB_SEED || root], and the public key
 * layout is [PUB_SEED || root]. Key generation computes the root before
 * returning, so trusted callers that immediately adopt output written by this
 * call do not need to call slh_dsa_secret_key_validate() only to recheck that
 * root.
 *
 * This trusted-output contract applies only to output from the successful
 * slh_dsa_keygen() call. Imported, deserialized, or otherwise untrusted
 * exact-size secret material must still be checked with
 * slh_dsa_secret_key_validate() before acceptance.
 */
int slh_dsa_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Validate that an SLH-DSA secret key is internally consistent.
 *
 * This recomputes the public root from SK_SEED and PUB_SEED and compares it to
 * the stored root. It does not sign and does not consume bounded30 signing use.
 */
int slh_dsa_secret_key_validate(const uint8_t *sk, size_t sk_size);

/**
 * @brief Sign a message using SLH-DSA-SHA2-128s-bounded30.
 *
 * Signing derives the SPHINCS+ optrand input from the secret key and message;
 * it does not fall back to process-global OS entropy.
 * @param m Message bytes. May be NULL only when mlen is zero.
 */
int slh_dsa_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
);

/**
 * @brief Sign and report FORS+C/WOTS+C signing grind counters.
 *
 * @param stats Optional stats output. When non-NULL, zeroed and populated even
 *              when signing fails because a signing cap is exceeded.
 */
int slh_dsa_sign_with_stats(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    bitcoin_pqc_sign_stats_t *stats
);

/**
 * @brief Verify an SLH-DSA-SHA2-128s-bounded30 signature.
 *
 * @param m Message bytes. May be NULL only when mlen is zero.
 */
int slh_dsa_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
);

/**
 * Generates deterministic signing randomness from a message and secret key.
 *
 * @param seed Output buffer for generated randomness (64 bytes)
 * @param m Message to sign. May be NULL only when mlen is zero.
 * @param mlen Message length
 * @param sk Secret key
 */
void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif /* BITCOIN_PQC_SLH_DSA_H */
