/*
 * Copyright (c) 2026-present The qbit core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://opensource.org/license/mit.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libbitcoinpqc/bitcoinpqc.h"

#define DEFAULT_CASES 3u
#define MAX_CASES 10u
#define KEYGEN_RANDOM_BYTES 128u
#define MESSAGE_BYTES 96u

int bitcoin_pqc_test_runtime_env_knobs_enabled(void);
int bitcoin_pqc_test_sha_backend_mode(void);
int bitcoin_pqc_test_disable_simd(void);

enum {
    SPX_SHA_BACKEND_AUTO = 0,
    SPX_SHA_BACKEND_SCALAR = 1,
    SPX_SHA_BACKEND_ARM = 2,
    SPX_SHA_BACKEND_X86 = 3,
    SPX_SHA_BACKEND_COMMONCRYPTO = 4
};

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--cases N] --expected-mode scalar|auto|x86\n"
            "\n"
            "Runs deterministic libbitcoinpqc signing cases for one forced backend mode.\n",
            program);
}

static int parse_size_arg(const char *value, size_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    *out = (size_t)parsed;
    return 0;
}

static int expected_mode_value(const char *mode)
{
    if (strcmp(mode, "scalar") == 0) return SPX_SHA_BACKEND_SCALAR;
    if (strcmp(mode, "auto") == 0) return SPX_SHA_BACKEND_AUTO;
    if (strcmp(mode, "x86") == 0) return SPX_SHA_BACKEND_X86;
    return -1;
}

static const char *mode_name(int mode)
{
    switch (mode) {
    case SPX_SHA_BACKEND_AUTO:
        return "auto";
    case SPX_SHA_BACKEND_SCALAR:
        return "scalar";
    case SPX_SHA_BACKEND_ARM:
        return "arm";
    case SPX_SHA_BACKEND_X86:
        return "x86";
    case SPX_SHA_BACKEND_COMMONCRYPTO:
        return "commoncrypto";
    default:
        return "unknown";
    }
}

static void fill_deterministic(uint8_t *out, size_t len, size_t case_index, uint64_t domain)
{
    uint64_t x = 0x9e3779b97f4a7c15ULL ^
                 ((uint64_t)(case_index + 1u) * 0xbf58476d1ce4e5b9ULL) ^
                 domain;
    for (size_t i = 0; i < len; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out[i] = (uint8_t)((x * 0x2545f4914f6cdd1dULL) >> 56);
    }
}

static void print_hex(const uint8_t *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        putchar(hex[data[i] >> 4]);
        putchar(hex[data[i] & 0x0fu]);
    }
}

static void print_stats(const bitcoin_pqc_sign_stats_t *stats)
{
    printf("forsc_attempts=%" PRIu32
           ",forsc_max_attempts=%" PRIu32
           ",wotsc_layer_count=%" PRIu32
           ",wotsc_max_attempts=%" PRIu32
           ",wotsc_max_observed_attempts=%" PRIu32
           ",cap_exceeded=%" PRIu32
           ",wotsc_attempts=",
           stats->forsc_attempts,
           stats->forsc_max_attempts,
           stats->wotsc_layer_count,
           stats->wotsc_max_attempts,
           stats->wotsc_max_observed_attempts,
           stats->cap_exceeded);
    for (size_t i = 0; i < BITCOIN_PQC_SIGN_WOTSC_LAYERS; ++i) {
        if (i != 0) putchar('.');
        printf("%" PRIu32, stats->wotsc_attempts[i]);
    }
}

static int run_case(size_t case_index)
{
    uint8_t random_data[KEYGEN_RANDOM_BYTES];
    uint8_t message[MESSAGE_BYTES];
    bitcoin_pqc_keypair_t keypair = {0};
    bitcoin_pqc_signature_t signature = {0};
    bitcoin_pqc_sign_stats_t stats;
    bitcoin_pqc_error_t err;
    size_t message_size = case_index % (MESSAGE_BYTES + 1u);
    const uint8_t *message_ptr;
    int result = 1;

    fill_deterministic(random_data, sizeof(random_data), case_index, 0x6b657967656eULL);
    fill_deterministic(message, sizeof(message), case_index, 0x6d657373616765ULL);
    message_ptr = message_size == 0 ? NULL : message;

    err = bitcoin_pqc_keygen(&keypair, random_data, sizeof(random_data));
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "case %zu: bitcoin_pqc_keygen failed with error %d\n", case_index, (int)err);
        goto out;
    }

    if (keypair.public_key_size != bitcoin_pqc_public_key_size() ||
        keypair.secret_key_size != bitcoin_pqc_secret_key_size()) {
        fprintf(stderr, "case %zu: keypair has unexpected shape\n", case_index);
        goto out;
    }

    err = bitcoin_pqc_secret_key_validate(keypair.secret_key, keypair.secret_key_size);
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "case %zu: bitcoin_pqc_secret_key_validate failed with error %d\n", case_index, (int)err);
        goto out;
    }

    err = bitcoin_pqc_sign_with_stats(
        keypair.secret_key,
        keypair.secret_key_size,
        message_ptr,
        message_size,
        &signature,
        &stats);
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "case %zu: bitcoin_pqc_sign_with_stats failed with error %d\n", case_index, (int)err);
        goto out;
    }

    if (signature.signature == NULL || signature.signature_size != bitcoin_pqc_signature_size()) {
        fprintf(stderr, "case %zu: signature has unexpected shape\n", case_index);
        goto out;
    }

    err = bitcoin_pqc_verify(
        keypair.public_key,
        keypair.public_key_size,
        message_ptr,
        message_size,
        signature.signature,
        signature.signature_size);
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "case %zu: bitcoin_pqc_verify(valid) failed with error %d\n", case_index, (int)err);
        goto out;
    }

    printf("case=%zu:pk=", case_index);
    print_hex((const uint8_t *)keypair.public_key, keypair.public_key_size);
    printf(":sig=");
    print_hex(signature.signature, signature.signature_size);
    printf(":stats=");
    print_stats(&stats);
    putchar(';');

    signature.signature[signature.signature_size - 1u] ^= 0x01u;
    err = bitcoin_pqc_verify(
        keypair.public_key,
        keypair.public_key_size,
        message_ptr,
        message_size,
        signature.signature,
        signature.signature_size);
    if (err == BITCOIN_PQC_OK) {
        fprintf(stderr, "case %zu: bitcoin_pqc_verify accepted a mutated signature\n", case_index);
        goto out;
    }

    result = 0;

out:
    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
    memset(random_data, 0, sizeof(random_data));
    memset(message, 0, sizeof(message));
    return result;
}

int main(int argc, char **argv)
{
    size_t cases = DEFAULT_CASES;
    const char *expected_mode = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--cases") == 0 && i + 1 < argc) {
            if (parse_size_arg(argv[++i], &cases) != 0 || cases == 0 || cases > MAX_CASES) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--expected-mode") == 0 && i + 1 < argc) {
            expected_mode = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (expected_mode == NULL || expected_mode_value(expected_mode) < 0) {
        usage(argv[0]);
        return 2;
    }

    if (bitcoin_pqc_test_runtime_env_knobs_enabled() != 1) {
        fprintf(stderr, "runtime backend environment knobs are not enabled\n");
        return 1;
    }

    int actual_mode = bitcoin_pqc_test_sha_backend_mode();
    int expected_mode_id = expected_mode_value(expected_mode);
    int disable_simd = bitcoin_pqc_test_disable_simd();
    if (actual_mode != expected_mode_id) {
        fprintf(stderr,
                "expected SHA backend mode %s/%d, got %s/%d\n",
                expected_mode,
                expected_mode_id,
                mode_name(actual_mode),
                actual_mode);
        return 1;
    }
    if (strcmp(expected_mode, "scalar") == 0 && disable_simd != 1) {
        fprintf(stderr, "expected scalar mode to disable SIMD, got %d\n", disable_simd);
        return 1;
    }
    if (strcmp(expected_mode, "scalar") != 0 && disable_simd != 0) {
        fprintf(stderr, "expected %s mode to leave SIMD enabled, got %d\n", expected_mode, disable_simd);
        return 1;
    }

    printf("BACKEND_MODE:%s actual=%s/%d disable_simd=%d cases=%zu\n",
           expected_mode,
           mode_name(actual_mode),
           actual_mode,
           disable_simd,
           cases);
    printf("BACKEND_SIGN_RESULT:");
    for (size_t i = 0; i < cases; ++i) {
        if (run_case(i) != 0) {
            putchar('\n');
            return 1;
        }
    }
    putchar('\n');

    return 0;
}
