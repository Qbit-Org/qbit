/**
 * @file bitcoinpqc.h
 * @brief Main header file for the Bitcoin PQC library
 *
 * This library provides a single stateless SLH-DSA-SHA2-128s profile
 * for use with qbit.
 */

#ifndef BITCOIN_PQC_H
#define BITCOIN_PQC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "libbitcoinpqc/sign_stats.h"

/* Common error codes */
typedef enum {
    BITCOIN_PQC_OK = 0,
    BITCOIN_PQC_ERROR_BAD_ARG = -1,
    BITCOIN_PQC_ERROR_BAD_KEY = -2,
    BITCOIN_PQC_ERROR_BAD_SIGNATURE = -3,
    BITCOIN_PQC_ERROR_NOT_IMPLEMENTED = -4,
    BITCOIN_PQC_ERROR_SIGNING_LIMIT = -5
} bitcoin_pqc_error_t;

/**
 * @brief Key pair structure
 *
 * Ownership rules:
 * - Callers must initialize this struct to all-zero before passing it to
 *   bitcoin_pqc_keygen.
 * - On success, the library owns the allocated buffers until the caller passes
 *   the same struct to bitcoin_pqc_keypair_free.
 * - On failure, the struct is left unchanged and no ownership is transferred.
 * - A struct with non-NULL pointers or nonzero sizes is rejected by
 *   bitcoin_pqc_keygen; free it before reuse.
 */
typedef struct {
    void *public_key;
    void *secret_key;
    size_t public_key_size;
    size_t secret_key_size;
} bitcoin_pqc_keypair_t;

/**
 * @brief Signature structure
 *
 * Ownership rules:
 * - Callers must initialize this struct to all-zero before passing it to
 *   bitcoin_pqc_sign.
 * - On success, the library owns the allocated buffer until the caller passes
 *   the same struct to bitcoin_pqc_signature_free.
 * - On failure, the struct is left unchanged and no ownership is transferred.
 * - A struct with a non-NULL pointer or nonzero size is rejected by
 *   bitcoin_pqc_sign; free it before reuse.
 */
typedef struct {
    uint8_t *signature;
    size_t signature_size;
} bitcoin_pqc_signature_t;

/**
 * @brief Get the public key size.
 */
size_t bitcoin_pqc_public_key_size(void);

/**
 * @brief Get the secret key size.
 */
size_t bitcoin_pqc_secret_key_size(void);

/**
 * @brief Get the signature size.
 */
size_t bitcoin_pqc_signature_size(void);

/**
 * @brief Generate a key pair.
 *
 * @param keypair Pointer to a zero-initialized keypair structure to populate.
 *                Non-empty output structures are rejected without being freed
 *                or overwritten.
 * @param random_data User-provided random data (entropy). All bytes are mixed
 *                    into the internal 48-byte SLH-DSA seed with domain
 *                    separation and input-length binding.
 * @param random_data_size Size of random data, must be >= 128 bytes.
 * @return BITCOIN_PQC_OK on success, error code otherwise
 *
 * On success, public_key and secret_key are a self-consistent generated pair.
 * The generated secret key already contains the root computed during keygen, so
 * trusted callers that immediately adopt this same-call output do not need to
 * call bitcoin_pqc_secret_key_validate() only to recompute that root.
 * Imported, deserialized, or otherwise untrusted exact-size secret material
 * must still be validated before acceptance.
 */
bitcoin_pqc_error_t bitcoin_pqc_keygen(
    bitcoin_pqc_keypair_t *keypair,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Validate that a secret key is internally consistent.
 *
 * This recomputes the public root from the secret key seed material and does
 * not perform a signing operation.
 *
 * @param secret_key Secret key buffer of bitcoin_pqc_secret_key_size() bytes.
 * @param secret_key_size Size of secret_key.
 * @return BITCOIN_PQC_OK for a consistent key, BITCOIN_PQC_ERROR_BAD_ARG for
 *         NULL input, or BITCOIN_PQC_ERROR_BAD_KEY for wrong-size or
 *         inconsistent key material.
 */
bitcoin_pqc_error_t bitcoin_pqc_secret_key_validate(
    const uint8_t *secret_key,
    size_t secret_key_size
);

/**
 * @brief Free resources associated with a keypair.
 *
 * The function securely wipes allocated key buffers before releasing them,
 * sets pointers and sizes to zero, accepts NULL, and is safe to call repeatedly
 * on the same struct after a successful first call.
 */
void bitcoin_pqc_keypair_free(bitcoin_pqc_keypair_t *keypair);

/**
 * @brief Sign a message.
 *
 * @param secret_key Secret key buffer of bitcoin_pqc_secret_key_size() bytes.
 * @param secret_key_size Size of secret_key.
 * @param message Message bytes. May be NULL only when message_size is zero.
 * @param message_size Size of message.
 * @param signature Pointer to a zero-initialized signature structure to
 *                  populate. Non-empty output structures are rejected without
 *                  being freed or overwritten.
 * @return BITCOIN_PQC_OK on success, error code otherwise
 */
bitcoin_pqc_error_t bitcoin_pqc_sign(
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature
);

/**
 * @brief Sign a message and report bounded30 signing grind statistics.
 *
 * @param secret_key Secret key buffer of bitcoin_pqc_secret_key_size() bytes.
 * @param secret_key_size Size of secret_key.
 * @param message Message bytes. May be NULL only when message_size is zero.
 * @param message_size Size of message.
 * @param signature Pointer to a zero-initialized signature structure to
 *                  populate. Non-empty output structures are rejected without
 *                  being freed or overwritten.
 * @param stats Optional stats output. When non-NULL, zeroed and populated even
 *              when signing fails because a signing cap is exceeded.
 * @return BITCOIN_PQC_OK on success, error code otherwise
 */
bitcoin_pqc_error_t bitcoin_pqc_sign_with_stats(
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature,
    bitcoin_pqc_sign_stats_t *stats
);

/**
 * @brief Free resources associated with a signature.
 *
 * The function securely wipes the allocated signature buffer before releasing
 * it, sets pointer and size to zero, accepts NULL, and is safe to call
 * repeatedly on the same struct after a successful first call.
 */
void bitcoin_pqc_signature_free(bitcoin_pqc_signature_t *signature);

/**
 * @brief Verify a signature.
 *
 * @param public_key Public key buffer of bitcoin_pqc_public_key_size() bytes.
 * @param public_key_size Size of public_key.
 * @param message Message bytes. May be NULL only when message_size is zero.
 * @param message_size Size of message.
 * @param signature Signature bytes, exactly bitcoin_pqc_signature_size().
 * @param signature_size Size of signature.
 * @return BITCOIN_PQC_OK on success, error code otherwise
 */
bitcoin_pqc_error_t bitcoin_pqc_verify(
    const uint8_t *public_key,
    size_t public_key_size,
    const uint8_t *message,
    size_t message_size,
    const uint8_t *signature,
    size_t signature_size
);

/* Algorithm-specific header includes */
#include "slh_dsa.h"

#ifdef __cplusplus
}
#endif

#endif /* BITCOIN_PQC_H */
