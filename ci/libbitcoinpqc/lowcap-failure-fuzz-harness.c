// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <libbitcoinpqc/bitcoinpqc.h>
#include <libbitcoinpqc/slh_dsa.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)       \
    do {                         \
        if (!(condition)) {      \
            abort();             \
        }                        \
    } while (0)

static void fill_entropy(uint8_t entropy[SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE], const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE; ++i) {
        entropy[i] = (uint8_t)(0xa5u ^ (uint8_t)(i * 13u));
    }
    for (size_t i = 0; i < size; ++i) {
        entropy[(i * 7u) % SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE] ^=
            (uint8_t)(data[i] + (uint8_t)i);
    }
}

static int all_zero(const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t entropy[SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE];
    uint8_t public_key[SLH_DSA_PUBLIC_KEY_SIZE];
    uint8_t secret_key[SLH_DSA_SECRET_KEY_SIZE];

    fill_entropy(entropy, data, size);
    REQUIRE(slh_dsa_keygen(public_key, secret_key, entropy, sizeof(entropy)) == 0);

    uint8_t signature[SLH_DSA_SIGNATURE_SIZE];
    memset(signature, 0xa5, sizeof(signature));
    size_t signature_len = sizeof(signature);
    bitcoin_pqc_sign_stats_t stats = {0};
    const int raw_ret = slh_dsa_sign_with_stats(
        signature,
        &signature_len,
        data,
        size,
        secret_key,
        &stats);

    REQUIRE(stats.wotsc_max_attempts == 1);
    if (raw_ret == 0) {
        REQUIRE(signature_len == SLH_DSA_SIGNATURE_SIZE);
        REQUIRE(slh_dsa_verify(signature, signature_len, data, size, public_key) == 0);
    } else {
        REQUIRE(signature_len == 0);
        REQUIRE(all_zero(signature, sizeof(signature)));
        REQUIRE((stats.cap_exceeded & BITCOIN_PQC_SIGN_LIMIT_WOTSC) != 0 ||
               (stats.cap_exceeded & BITCOIN_PQC_SIGN_LIMIT_FORSC) != 0);
    }

    bitcoin_pqc_signature_t safe_signature = {0};
    bitcoin_pqc_sign_stats_t safe_stats = {0};
    const bitcoin_pqc_error_t safe_ret = bitcoin_pqc_sign_with_stats(
        secret_key,
        sizeof(secret_key),
        data,
        size,
        &safe_signature,
        &safe_stats);
    REQUIRE(safe_stats.wotsc_max_attempts == 1);
    if (safe_ret == BITCOIN_PQC_OK) {
        REQUIRE(safe_signature.signature != NULL);
        REQUIRE(safe_signature.signature_size == bitcoin_pqc_signature_size());
        REQUIRE(bitcoin_pqc_verify(
            public_key,
            sizeof(public_key),
            data,
            size,
            safe_signature.signature,
            safe_signature.signature_size) == BITCOIN_PQC_OK);
    } else {
        REQUIRE(safe_signature.signature == NULL);
        REQUIRE(safe_signature.signature_size == 0);
    }
    bitcoin_pqc_signature_free(&safe_signature);
    return 0;
}
