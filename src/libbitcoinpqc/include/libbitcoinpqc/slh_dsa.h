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

/*
 * slh_dsa_sign() and slh_dsa_sign_with_stats() return 0 on success and a
 * negative value on failure. SLH_DSA_SIGN_ERROR_BAD_KEY identifies a secret
 * key that fails slh_dsa_secret_key_validate(); it is distinct from the
 * generic -1 and from the internal bounded30 signing-limit sentinel, so a
 * caller can tell a rejected key from a failed signing operation without a
 * second validation pass. bitcoin_pqc_sign() maps it to
 * BITCOIN_PQC_ERROR_BAD_KEY.
 */
#define SLH_DSA_SIGN_ERROR_BAD_KEY (-101)

/*
 * slh_dsa_keygen() returns 0 on success and a negative value on failure.
 * SLH_DSA_KEYGEN_ERROR_OUT_OF_MEMORY identifies a failed internal allocation
 * (the seed-derivation buffer grows with random_data_size); it is distinct
 * from the generic -1 so bitcoin_pqc_keygen() can report it as
 * BITCOIN_PQC_ERROR_OUT_OF_MEMORY instead of BITCOIN_PQC_ERROR_BAD_KEY.
 */
#define SLH_DSA_KEYGEN_ERROR_OUT_OF_MEMORY (-102)

/*
 * Stack requirement: slh_dsa_keygen(), slh_dsa_secret_key_validate(),
 * slh_dsa_sign(), slh_dsa_sign_with_stats() and slh_dsa_derandomize()
 * overwrite the stack they released before returning, so callers need about
 * 16 KiB of free stack in optimized native builds (about 288 KiB unoptimized,
 * 4 KiB under Emscripten). The size is BITCOIN_PQC_BURN_STACK_BYTES in
 * src/secure_zero.h and can be overridden at build time.
 */

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
 *
 * @return 0 on success, SLH_DSA_KEYGEN_ERROR_OUT_OF_MEMORY if an internal
 *         allocation fails, or -1 for rejected arguments (NULL pointers or
 *         too little random data) and any other failure.
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
 * @param sig Output buffer of at least SLH_DSA_SIGNATURE_SIZE bytes whenever
 *            it is non-NULL; every failure path writes to it.
 * @param m Message bytes. May be NULL only when mlen is zero.
 * @return 0 on success, -1 if sig, siglen or sk is NULL or m is NULL with a
 *         nonzero mlen, SLH_DSA_SIGN_ERROR_BAD_KEY if sk fails
 *         slh_dsa_secret_key_validate(), or another negative value on any
 *         other failure. On every failure, including rejected arguments, sig
 *         is zeroed and *siglen is set to 0; a NULL sig or siglen is the only
 *         output that is not written.
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
 *              when signing fails because a signing cap is exceeded. Left
 *              unchanged when the call fails before signing starts (rejected
 *              arguments or SLH_DSA_SIGN_ERROR_BAD_KEY).
 * @return As slh_dsa_sign(), including its failure cleanup of sig and *siglen.
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
