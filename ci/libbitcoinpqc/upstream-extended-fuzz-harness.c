// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <libbitcoinpqc/bitcoinpqc.h>

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
        entropy[i] = (uint8_t)(0x42u + (uint8_t)(i * 17u));
    }
    for (size_t i = 0; i < size; ++i) {
        entropy[i % SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE] ^=
            (uint8_t)(data[i] + (uint8_t)(i * 31u));
    }
}

static void mutate_one(uint8_t *bytes, size_t size, const uint8_t *data, size_t data_size)
{
    if (size == 0 || data_size == 0) {
        return;
    }
    const size_t pos = data[0] % size;
    const uint8_t bit = (uint8_t)(1u << (data_size > 1 ? (data[1] & 7u) : 0u));
    bytes[pos] ^= bit;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t entropy[SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE];
    fill_entropy(entropy, data, size);

    bitcoin_pqc_keypair_t keypair = {0};
    REQUIRE(bitcoin_pqc_keygen(&keypair, entropy, sizeof(entropy)) == BITCOIN_PQC_OK);
    REQUIRE(keypair.public_key != NULL);
    REQUIRE(keypair.secret_key != NULL);
    REQUIRE(keypair.public_key_size == bitcoin_pqc_public_key_size());
    REQUIRE(keypair.secret_key_size == bitcoin_pqc_secret_key_size());
    REQUIRE(bitcoin_pqc_secret_key_validate(keypair.secret_key, keypair.secret_key_size) == BITCOIN_PQC_OK);

    bitcoin_pqc_signature_t signature = {0};
    const bitcoin_pqc_error_t sign_ret = bitcoin_pqc_sign(
        keypair.secret_key,
        keypair.secret_key_size,
        data,
        size,
        &signature);
    REQUIRE(sign_ret == BITCOIN_PQC_OK);
    REQUIRE(signature.signature != NULL);
    REQUIRE(signature.signature_size == bitcoin_pqc_signature_size());
    REQUIRE(bitcoin_pqc_verify(
        keypair.public_key,
        keypair.public_key_size,
        data,
        size,
        signature.signature,
        signature.signature_size) == BITCOIN_PQC_OK);

    uint8_t mutated_signature[SLH_DSA_SIGNATURE_SIZE];
    memcpy(mutated_signature, signature.signature, sizeof(mutated_signature));
    mutate_one(mutated_signature, sizeof(mutated_signature), data, size);
    if (size > 0) {
        REQUIRE(bitcoin_pqc_verify(
            keypair.public_key,
            keypair.public_key_size,
            data,
            size,
            mutated_signature,
            sizeof(mutated_signature)) != BITCOIN_PQC_OK);
    }

    uint8_t mutated_public_key[SLH_DSA_PUBLIC_KEY_SIZE];
    memcpy(mutated_public_key, keypair.public_key, sizeof(mutated_public_key));
    const uint8_t *public_key_mutation_data = data;
    size_t public_key_mutation_size = size;
    if (size > 2) {
        public_key_mutation_data = data + 2;
        public_key_mutation_size = size - 2;
    }
    mutate_one(mutated_public_key, sizeof(mutated_public_key), public_key_mutation_data, public_key_mutation_size);
    if (size > 0) {
        REQUIRE(bitcoin_pqc_verify(
            mutated_public_key,
            sizeof(mutated_public_key),
            data,
            size,
            signature.signature,
            signature.signature_size) != BITCOIN_PQC_OK);
    }

    uint8_t malformed_secret[SLH_DSA_SECRET_KEY_SIZE];
    memcpy(malformed_secret, keypair.secret_key, sizeof(malformed_secret));
    malformed_secret[sizeof(malformed_secret) - 1] ^= 0x80u;
    REQUIRE(bitcoin_pqc_secret_key_validate(malformed_secret, sizeof(malformed_secret)) != BITCOIN_PQC_OK);

    bitcoin_pqc_signature_t rejected_signature = {0};
    REQUIRE(bitcoin_pqc_sign(
        malformed_secret,
        sizeof(malformed_secret),
        data,
        size,
        &rejected_signature) != BITCOIN_PQC_OK);
    REQUIRE(rejected_signature.signature == NULL);
    REQUIRE(rejected_signature.signature_size == 0);

    REQUIRE(bitcoin_pqc_verify(
        keypair.public_key,
        keypair.public_key_size - 1,
        data,
        size,
        signature.signature,
        signature.signature_size) != BITCOIN_PQC_OK);
    REQUIRE(bitcoin_pqc_verify(
        keypair.public_key,
        keypair.public_key_size,
        data,
        size,
        signature.signature,
        signature.signature_size - 1) != BITCOIN_PQC_OK);

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_signature_free(&rejected_signature);
    bitcoin_pqc_keypair_free(&keypair);
    return 0;
}
