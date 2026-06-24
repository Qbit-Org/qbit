/**
 * @file test_helpers.c
 * @brief Test-only helpers that expose internal SPHINCS+ functions via FFI.
 *
 * These wrappers replicate the bit-extraction logic from the static functions
 * message_to_indices (fors.c) and forsc_compressed_index (sign.c) so that
 * Rust integration tests can exercise the real parameter-dependent extraction
 * without modifying production source files.
 */

#ifndef BITCOINPQC_ENABLE_TEST_HELPERS
#error "test_helpers.c is test-only; enable BITCOINPQC_ENABLE_TEST_HELPERS to build it"
#endif

#include <stdint.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "context.h"
#include "hash.h"
#include "opt_flags.h"
#include "randombytes.h"
#include "sign_stats.h"

void slh_dsa_restore_original_random(void);
void slh_dsa_random_source_clear_failure(void);
int slh_dsa_random_source_failed(void);

int bitcoin_pqc_test_raw_slh_keypair_without_random_source(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    slh_dsa_restore_original_random();
    return crypto_sign_keypair(pk, sk);
}

int bitcoin_pqc_test_raw_slh_sign_without_random_source(void)
{
    uint8_t seed[CRYPTO_SEEDBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    size_t siglen = 0;
    static const uint8_t message[] = "entropy failure signing test";

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        return -1;
    }

    slh_dsa_restore_original_random();
    if (crypto_sign_signature(sig, &siglen, message, sizeof(message) - 1, sk) != 0) {
        return -1;
    }

    return siglen == CRYPTO_BYTES ? 0 : -1;
}

int bitcoin_pqc_test_seed_keypair_with_prefilled_root_tail(
    uint8_t *pk,
    size_t pk_len,
    uint8_t *sk,
    size_t sk_len,
    uint8_t root_tail_prefill,
    bitcoin_pqc_sign_stats_t *stats)
{
    uint8_t seed[CRYPTO_SEEDBYTES];
    int rc;

    if (!pk || !sk || !stats) {
        return -1;
    }
    if (pk_len != CRYPTO_PUBLICKEYBYTES || sk_len != CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0xB7u + ((i * 31u) & 0xFFu));
    }

    memset(pk, 0xC3, pk_len);
    memset(sk, 0, sk_len);
    memset(sk + 3 * SPX_N, root_tail_prefill, SPX_N);

    bitcoin_pqc_sign_stats_begin(stats);
    rc = crypto_sign_seed_keypair(pk, sk, seed);
    bitcoin_pqc_sign_stats_end();

    memset(seed, 0, sizeof(seed));
    return rc;
}

int bitcoin_pqc_test_message_to_indices(
    uint32_t *indices_out,
    const uint8_t *mhash,
    size_t mhash_len)
{
    unsigned int i, j;
    unsigned int offset = 0;

    if (!indices_out || !mhash || mhash_len < SPX_FORS_MSG_BYTES) {
        return -1;
    }

    /* Exact logic from fors.c message_to_indices: extract SPX_FORS_SIG_TREES
       indices of SPX_FORS_HEIGHT bits each from the message hash. */
    for (i = 0; i < SPX_FORS_SIG_TREES; i++) {
        indices_out[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices_out[i] ^= ((mhash[offset >> 3] >> (offset & 0x7)) & 1u) << j;
            offset++;
        }
    }

    return 0;
}

uint32_t bitcoin_pqc_test_forsc_compressed_index(
    const uint8_t *mhash,
    size_t mhash_len)
{
    uint32_t idx = 0;
    unsigned int offset = (unsigned int)SPX_FORS_SIG_TREES * SPX_FORS_HEIGHT;
    unsigned int j;

    if (!mhash || mhash_len < SPX_FORS_MSG_BYTES) {
        return UINT32_MAX;
    }

    /* Exact logic from sign.c forsc_compressed_index: extract the compressed
       tree index starting at bit offset SPX_FORS_SIG_TREES * SPX_FORS_HEIGHT. */
    for (j = 0; j < SPX_FORS_HEIGHT; j++) {
        idx ^= (uint32_t)(((mhash[offset >> 3] >> (offset & 0x7)) & 1u) << j);
        offset++;
    }

    return idx;
}

uint32_t bitcoin_pqc_test_compressed_index(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *pk,
    size_t pk_len,
    const uint8_t *msg,
    size_t msg_len)
{
    spx_ctx ctx;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    uint64_t tree;
    uint32_t leaf_idx;

    if (!sig || !pk) return UINT32_MAX;
    if (sig_len != SPX_BYTES) return UINT32_MAX;
    if (pk_len != SPX_PK_BYTES) return UINT32_MAX;
    if (msg_len > 0 && !msg) return UINT32_MAX;

    /* Initialize context from public key (first SPX_N bytes = pub_seed). */
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);

    /* R is the first SPX_N bytes of the signature. */
    hash_message(mhash, &tree, &leaf_idx, sig, pk, msg, (unsigned long long)msg_len, &ctx);

    return bitcoin_pqc_test_forsc_compressed_index(mhash, SPX_FORS_MSG_BYTES);
}

int bitcoin_pqc_test_randombytes_without_source(uint8_t *out, size_t out_len)
{
    if (!out && out_len != 0) return -1;

    slh_dsa_restore_original_random();
    slh_dsa_random_source_clear_failure();
    randombytes(out, (unsigned long long)out_len);

    return slh_dsa_random_source_failed() ? -1 : 0;
}

int bitcoin_pqc_test_crypto_keypair_without_source(
    uint8_t *pk,
    size_t pk_len,
    uint8_t *sk,
    size_t sk_len)
{
    int rc;

    if (!pk || !sk) return -1;
    if (pk_len != CRYPTO_PUBLICKEYBYTES) return -1;
    if (sk_len != CRYPTO_SECRETKEYBYTES) return -1;

    slh_dsa_restore_original_random();
    slh_dsa_random_source_clear_failure();
    rc = crypto_sign_keypair(pk, sk);

    if (rc != 0 || slh_dsa_random_source_failed()) {
        memset(pk, 0, pk_len);
        memset(sk, 0, sk_len);
        return -1;
    }

    return 0;
}

int bitcoin_pqc_test_crypto_signature_without_source(
    uint8_t *sig,
    size_t sig_len,
    size_t *actual_sig_len,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    size_t sk_len)
{
    int rc;
    const uint8_t empty_message = 0;
    const uint8_t *message = m ? m : &empty_message;

    if (!sig || !actual_sig_len || !sk) return -1;
    if (sig_len != CRYPTO_BYTES) return -1;
    if (sk_len != CRYPTO_SECRETKEYBYTES) return -1;
    if (!m && mlen != 0) return -1;

    *actual_sig_len = sig_len;
    slh_dsa_restore_original_random();
    slh_dsa_random_source_clear_failure();
    rc = crypto_sign_signature(sig, actual_sig_len, message, mlen, sk);

    if (rc != 0 || slh_dsa_random_source_failed()) {
        memset(sig, 0, sig_len);
        *actual_sig_len = 0;
        return -1;
    }

    return 0;
}

int bitcoin_pqc_test_crypto_combined_sign_without_source(
    uint8_t *sm,
    size_t sm_len,
    unsigned long long *smlen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    size_t sk_len)
{
    const uint8_t empty_message = 0;
    const uint8_t *message = m ? m : &empty_message;

    if (!sm || !smlen || !sk) return -1;
    if (sk_len != CRYPTO_SECRETKEYBYTES) return -1;
    if (!m && mlen != 0) return -1;
    if (mlen > (size_t)-1 - CRYPTO_BYTES) return -1;
    if (sm_len < CRYPTO_BYTES + mlen) return -1;

    *smlen = (unsigned long long)sm_len;
    slh_dsa_restore_original_random();
    slh_dsa_random_source_clear_failure();

    return crypto_sign(sm, smlen, message, (unsigned long long)mlen, sk);
}

int bitcoin_pqc_test_runtime_env_knobs_enabled(void)
{
    return SPX_RUNTIME_ENV_KNOBS_ENABLED;
}

int bitcoin_pqc_test_sha_backend_mode(void)
{
    return spx_opt_sha_backend_mode();
}

int bitcoin_pqc_test_disable_sha_accel(void)
{
    return spx_opt_disable_sha_accel();
}

int bitcoin_pqc_test_disable_simd(void)
{
    return spx_opt_disable_simd();
}

int bitcoin_pqc_test_profile_scalar(void)
{
    return spx_opt_profile_is("scalar");
}
