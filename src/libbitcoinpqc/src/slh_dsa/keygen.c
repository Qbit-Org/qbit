#include <stdlib.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"

#include "../../sphincsplus/ref/api.h"
#include "../secure_zero.h"

#define SHA512_OUTPUT_BYTES 64

#if CRYPTO_SEEDBYTES > SHA512_OUTPUT_BYTES
#error "SLH-DSA keygen seed derivation requires SHA-512 output to cover CRYPTO_SEEDBYTES"
#endif

/* From sphincsplus/ref/sha2.c */
void sha512(uint8_t *out, const uint8_t *in, size_t inlen);

static const uint8_t KEYGEN_DERIVE_DOMAIN[] =
    "libbitcoinpqc-qbit/slh-dsa-sha2-128s-bounded30/keygen/v1";

static void store_u64_le(uint8_t out[8], uint64_t value) {
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

static int derive_keygen_seed_v1(
    uint8_t seed[CRYPTO_SEEDBYTES],
    const uint8_t *random_data,
    size_t random_data_size
) {
    const size_t domain_size = sizeof(KEYGEN_DERIVE_DOMAIN) - 1;
    const size_t metadata_size = domain_size + 1 + 8;
    if (random_data_size > SIZE_MAX - metadata_size) {
        return -1;
    }

    const size_t input_size = metadata_size + random_data_size;
    uint8_t *input = malloc(input_size);
    if (!input) {
        return -1;
    }

    memcpy(input, KEYGEN_DERIVE_DOMAIN, domain_size);
    input[domain_size] = 0;
    store_u64_le(input + domain_size + 1, (uint64_t)random_data_size);
    memcpy(input + metadata_size, random_data, random_data_size);

    uint8_t digest[SHA512_OUTPUT_BYTES];
    sha512(digest, input, input_size);
    memcpy(seed, digest, CRYPTO_SEEDBYTES);

    bitcoin_pqc_secure_zero(digest, sizeof(digest));
    bitcoin_pqc_secure_zero(input, input_size);
    free(input);

    return 0;
}

int slh_dsa_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE) {
        return -1;
    }

    uint8_t seed[CRYPTO_SEEDBYTES];
    if (derive_keygen_seed_v1(seed, random_data, random_data_size) != 0) {
        return -1;
    }

    int result = crypto_sign_seed_keypair(pk, sk, seed);
    bitcoin_pqc_secure_zero(seed, sizeof(seed));

    return result;
}
