#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"
#include "sign_stats.h"
#if defined(SPX_WOTSC_TARGET)
#include "sha2.h"
#endif

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}

#if defined(SPX_WOTSC_TARGET)
/*
 * WOTS+C: deterministically hash msg || counter until the derived WOTS message
 * has the desired checksum target. This lets us omit checksum chains.
 */
static void wotsc_hash_counter(unsigned char *compressed_msg,
                               unsigned int *checksum_out,
                               const unsigned char *msg,
                               uint32_t counter)
{
    unsigned char hash_in[SPX_N + 2];
    unsigned char hash_out[SPX_SHA256_OUTPUT_BYTES];
    unsigned int lengths[SPX_WOTS_LEN1];
    unsigned int checksum;
    unsigned int i;

    memcpy(hash_in, msg, SPX_N);
    hash_in[SPX_N] = (unsigned char)(counter >> 8);
    hash_in[SPX_N + 1] = (unsigned char)counter;

    sha256(hash_out, hash_in, sizeof(hash_in));
    memcpy(compressed_msg, hash_out, SPX_N);

    base_w(lengths, SPX_WOTS_LEN1, compressed_msg);
    checksum = 0;
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        checksum += SPX_WOTS_W - 1 - lengths[i];
    }
    if (checksum_out) {
        *checksum_out = checksum;
    }
}

static int wotsc_compress_message_checked_bounded(unsigned char *compressed_msg,
                                                  const unsigned char *msg,
                                                  uint32_t max_counter,
                                                  uint32_t *counter_out,
                                                  unsigned int *checksum_out)
{
    uint32_t counter;
    unsigned int checksum;

    for (counter = 0;; counter++) {
        uint32_t attempts = counter + 1u;
        wotsc_hash_counter(compressed_msg, &checksum, msg, counter);
        if (checksum == SPX_WOTSC_TARGET) {
            if (counter_out) {
                *counter_out = counter;
            }
            if (checksum_out) {
                *checksum_out = checksum;
            }
            bitcoin_pqc_sign_stats_record_wotsc_attempts(attempts);
            return 0;
        }
        if (counter == max_counter) {
            bitcoin_pqc_sign_stats_record_wotsc_attempts(attempts);
            bitcoin_pqc_sign_stats_record_wotsc_cap();
            return BITCOINPQC_SIGN_LIMIT_EXCEEDED;
        }
    }
}

static int wotsc_compress_message_checked(unsigned char *compressed_msg,
                                          const unsigned char *msg,
                                          uint32_t *counter_out,
                                          unsigned int *checksum_out)
{
    uint32_t max_counter = bitcoin_pqc_sign_stats_current()
        ? (uint32_t)BITCOINPQC_WOTSC_MAX_COUNTER
        : 0xFFFFu;

    return wotsc_compress_message_checked_bounded(
        compressed_msg, msg, max_counter, counter_out, checksum_out);
}

#if defined(BITCOINPQC_ENABLE_TEST_HELPERS)
typedef struct {
    uint32_t n;
    uint32_t w;
    uint32_t logw;
    uint32_t len1;
    uint32_t len2;
    uint32_t len;
    uint32_t target;
    uint32_t wots_bytes;
    uint32_t wots_pk_bytes;
    uint32_t fors_bytes;
    uint32_t d;
    uint32_t tree_height;
    uint32_t auth_path_bytes;
    uint32_t signature_bytes;
} bitcoin_pqc_test_wotsc_params_t;

int bitcoin_pqc_test_wotsc_params(bitcoin_pqc_test_wotsc_params_t *params)
{
    if (!params) {
        return -1;
    }

    params->n = SPX_N;
    params->w = SPX_WOTS_W;
    params->logw = SPX_WOTS_LOGW;
    params->len1 = SPX_WOTS_LEN1;
    params->len2 = SPX_WOTS_LEN2;
    params->len = SPX_WOTS_LEN;
    params->target = SPX_WOTSC_TARGET;
    params->wots_bytes = SPX_WOTS_BYTES;
    params->wots_pk_bytes = SPX_WOTS_PK_BYTES;
    params->fors_bytes = SPX_FORS_BYTES;
    params->d = SPX_D;
    params->tree_height = SPX_TREE_HEIGHT;
    params->auth_path_bytes = SPX_TREE_HEIGHT * SPX_N;
    params->signature_bytes = SPX_BYTES;

    return 0;
}

int bitcoin_pqc_test_wotsc_hash_counter(unsigned char *compressed_msg,
                                        size_t compressed_msg_len,
                                        uint32_t *checksum_out,
                                        const unsigned char *msg,
                                        size_t msg_len,
                                        uint32_t counter)
{
    unsigned int checksum;

    if (!compressed_msg || !checksum_out || !msg) {
        return -1;
    }
    if (compressed_msg_len < SPX_N || msg_len != SPX_N || counter > 0xFFFFu) {
        return -1;
    }

    wotsc_hash_counter(compressed_msg, &checksum, msg, counter);
    *checksum_out = (uint32_t)checksum;
    return 0;
}

int bitcoin_pqc_test_wotsc_derive(unsigned char *compressed_msg,
                                  size_t compressed_msg_len,
                                  uint32_t *lengths_out,
                                  size_t lengths_len,
                                  uint32_t *counter_out,
                                  uint32_t *checksum_out,
                                  const unsigned char *msg,
                                  size_t msg_len)
{
    unsigned int lengths[SPX_WOTS_LEN1];
    unsigned int checksum;
    unsigned int i;

    if (!compressed_msg || !lengths_out || !counter_out || !checksum_out || !msg) {
        return -1;
    }
    if (compressed_msg_len < SPX_N || lengths_len < SPX_WOTS_LEN1 || msg_len != SPX_N) {
        return -1;
    }
    if (wotsc_compress_message_checked(
            compressed_msg, msg, counter_out, &checksum) != 0) {
        return -1;
    }

    base_w(lengths, SPX_WOTS_LEN1, compressed_msg);
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        lengths_out[i] = (uint32_t)lengths[i];
    }
    *checksum_out = (uint32_t)checksum;
    return 0;
}

int bitcoin_pqc_test_wotsc_derive_with_limit(unsigned char *compressed_msg,
                                             size_t compressed_msg_len,
                                             uint32_t *lengths_out,
                                             size_t lengths_len,
                                             uint32_t *counter_out,
                                             uint32_t *checksum_out,
                                             const unsigned char *msg,
                                             size_t msg_len,
                                             uint32_t max_counter)
{
    unsigned int lengths[SPX_WOTS_LEN1];
    unsigned int checksum;
    unsigned int i;

    if (!compressed_msg || !lengths_out || !counter_out || !checksum_out || !msg) {
        return -1;
    }
    if (compressed_msg_len < SPX_N || lengths_len < SPX_WOTS_LEN1 ||
            msg_len != SPX_N || max_counter > 0xFFFFu) {
        return -1;
    }
    if (wotsc_compress_message_checked_bounded(
            compressed_msg, msg, max_counter, counter_out, &checksum) != 0) {
        return -1;
    }

    base_w(lengths, SPX_WOTS_LEN1, compressed_msg);
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        lengths_out[i] = (uint32_t)lengths[i];
    }
    *checksum_out = (uint32_t)checksum;
    return 0;
}
#endif

/* Takes a message and derives the matching chain lengths. */
int chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    unsigned char compressed_msg[SPX_N];
    int result;

    result = wotsc_compress_message_checked(compressed_msg, msg, NULL, NULL);
    if (result != 0) {
        return result;
    }
    base_w(lengths, SPX_WOTS_LEN1, compressed_msg);
    return 0;
}
#else
/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
int chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
    return 0;
}
#endif

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
int wots_pk_from_sig(unsigned char *pk,
                     const unsigned char *sig, const unsigned char *msg,
                     const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;

    if (chain_lengths(lengths, msg) != 0) {
        return -1;
    }

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i*SPX_N, sig + i*SPX_N,
                  lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
    }

    return 0;
}
