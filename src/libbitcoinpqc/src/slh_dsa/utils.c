#include <stdlib.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"
#include "../secure_zero.h"

#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/randombytes.h"

#define SHA256_BLOCK_BYTES 64
#define SHA256_INC_STATE_BYTES 40

#if CRYPTO_SECRETKEYBYTES != SHA256_BLOCK_BYTES
#error "slh_dsa_derandomize expects the bounded30 secret key to be one SHA-256 block."
#endif

/* From sphincsplus/ref/sha2.c */
void sha256_inc_init(uint8_t *state);
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

/* Provide a custom random bytes function that uses user-provided entropy. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define LIBBITCOINPQC_THREAD_LOCAL _Thread_local
#elif defined(_MSC_VER)
#define LIBBITCOINPQC_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#define LIBBITCOINPQC_THREAD_LOCAL __thread
#else
#error "Thread-local storage is required for SLH-DSA random source isolation on this compiler."
#endif

static LIBBITCOINPQC_THREAD_LOCAL const uint8_t *g_random_data = NULL;
static LIBBITCOINPQC_THREAD_LOCAL size_t g_random_data_size = 0;
static LIBBITCOINPQC_THREAD_LOCAL size_t g_random_data_offset = 0;
static LIBBITCOINPQC_THREAD_LOCAL int g_random_source_failed = 0;

void slh_dsa_random_source_clear_failure(void) {
    g_random_source_failed = 0;
}

int slh_dsa_random_source_failed(void) {
    return g_random_source_failed;
}

static void mark_random_source_failed(void) {
    g_random_source_failed = 1;
}

void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size) {
    g_random_data = random_data;
    g_random_data_size = random_data_size;
    g_random_data_offset = 0;
    slh_dsa_random_source_clear_failure();
}

/* Hook points retained for interface consistency. */
void slh_dsa_setup_custom_random(void) {}

void slh_dsa_restore_original_random(void) {
    g_random_data = NULL;
    g_random_data_size = 0;
    g_random_data_offset = 0;
}

void custom_slh_randombytes_impl(uint8_t *out, size_t outlen) {
    if (outlen == 0) {
        return;
    }

    if (!out) {
        mark_random_source_failed();
        return;
    }

    if (g_random_data == NULL || g_random_data_size == 0) {
        mark_random_source_failed();
        /* Keep the output initialized; callers must fail closed on the flag. */
        bitcoin_pqc_secure_zero(out, outlen);
        return;
    }

    size_t position = 0;
    while (position < outlen) {
        size_t remaining = g_random_data_size - g_random_data_offset;
        size_t to_copy = outlen - position;
        if (to_copy > remaining) {
            to_copy = remaining;
        }

        memcpy(out + position, g_random_data + g_random_data_offset, to_copy);

        position += to_copy;
        g_random_data_offset = (g_random_data_offset + to_copy) % g_random_data_size;
    }
}

void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    if (!seed || (!m && mlen != 0) || !sk) {
        if (seed) {
            bitcoin_pqc_secure_zero(seed, 64);
        }
        mark_random_source_failed();
        return;
    }

    uint8_t state[SHA256_INC_STATE_BYTES];
    uint8_t digest0[32];
    uint8_t digest1_input[33];
    const uint8_t empty_message = 0;
    const uint8_t *message = m ? m : &empty_message;

    sha256_inc_init(state);
    sha256_inc_blocks(state, sk, CRYPTO_SECRETKEYBYTES / SHA256_BLOCK_BYTES);
    sha256_inc_finalize(digest0, state, message, mlen);
    memcpy(seed, digest0, sizeof(digest0));

    memcpy(digest1_input, digest0, sizeof(digest0));
    digest1_input[32] = 1;
    sha256(seed + 32, digest1_input, sizeof(digest1_input));

    bitcoin_pqc_secure_zero(state, sizeof(state));
    bitcoin_pqc_secure_zero(digest0, sizeof(digest0));
    bitcoin_pqc_secure_zero(digest1_input, sizeof(digest1_input));
}
