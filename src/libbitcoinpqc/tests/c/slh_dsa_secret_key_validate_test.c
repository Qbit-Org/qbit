#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libbitcoinpqc/bitcoinpqc.h"
#include "libbitcoinpqc/slh_dsa.h"

#define MIN_ENTROPY_SIZE 128u

static void fill_entropy(uint8_t *out, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)(0x63u + (uint8_t)((i * 29u) & 0xffu));
    }
}

static int fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int expect_low_level_ok(int rc, const char *message) {
    if (rc != 0) {
        fprintf(stderr, "%s: rc=%d\n", message, rc);
        return 1;
    }
    return 0;
}

static int expect_low_level_reject(int rc, const char *message) {
    if (rc == 0) {
        fprintf(stderr, "%s: rc=%d\n", message, rc);
        return 1;
    }
    return 0;
}

static int expect_high_level(bitcoin_pqc_error_t actual,
                             bitcoin_pqc_error_t expected,
                             const char *message) {
    if (actual != expected) {
        fprintf(stderr, "%s: rc=%d expected=%d\n", message, (int)actual, (int)expected);
        return 1;
    }
    return 0;
}

static int expect_bytes_equal(
    const uint8_t *actual,
    const uint8_t *expected,
    size_t len,
    const char *message
) {
    if (memcmp(actual, expected, len) != 0) {
        fprintf(stderr, "%s\n", message);
        return 1;
    }
    return 0;
}

static int signature_is_zero(const uint8_t *sig, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        if (sig[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void copy_and_mutate(uint8_t *out, const uint8_t *sk, size_t index) {
    memcpy(out, sk, SLH_DSA_SECRET_KEY_SIZE);
    out[index] ^= 0x80u;
}

static int test_keygen_trusted_output_contract(void) {
    uint8_t entropy[MIN_ENTROPY_SIZE];
    uint8_t pk[SLH_DSA_PUBLIC_KEY_SIZE];
    uint8_t sk[SLH_DSA_SECRET_KEY_SIZE];
    const size_t n = SLH_DSA_SECRET_KEY_SIZE / 4u;

    if (SLH_DSA_SECRET_KEY_SIZE != 4u * n || SLH_DSA_PUBLIC_KEY_SIZE != 2u * n) {
        return fail("unexpected SLH-DSA key layout constants");
    }

    fill_entropy(entropy, sizeof(entropy));
    if (slh_dsa_keygen(pk, sk, entropy, sizeof(entropy)) != 0) {
        return fail("slh_dsa_keygen should succeed");
    }

    if (expect_bytes_equal(
            pk,
            sk + 2u * n,
            SLH_DSA_PUBLIC_KEY_SIZE,
            "generated public key should match PUB_SEED || root in the secret key")) {
        return 1;
    }

    if (expect_low_level_ok(
            slh_dsa_secret_key_validate(sk, sizeof(sk)),
            "generated secret key should satisfy the validator contract")) {
        return 1;
    }

    return 0;
}

static int test_secret_key_validate(void) {
    uint8_t entropy[MIN_ENTROPY_SIZE];
    uint8_t pk[SLH_DSA_PUBLIC_KEY_SIZE];
    uint8_t sk[SLH_DSA_SECRET_KEY_SIZE];
    uint8_t mutated[SLH_DSA_SECRET_KEY_SIZE];
    uint8_t sig[SLH_DSA_SIGNATURE_SIZE];
    const uint8_t message[] = "mutated-root-tail";
    const size_t n = SLH_DSA_SECRET_KEY_SIZE / 4u;
    size_t siglen;

    if (SLH_DSA_SECRET_KEY_SIZE != 4u * n || SLH_DSA_PUBLIC_KEY_SIZE != 2u * n) {
        return fail("unexpected SLH-DSA key layout constants");
    }

    fill_entropy(entropy, sizeof(entropy));
    if (slh_dsa_keygen(pk, sk, entropy, sizeof(entropy)) != 0) {
        return fail("slh_dsa_keygen should succeed");
    }

    if (expect_low_level_ok(
            slh_dsa_secret_key_validate(sk, sizeof(sk)),
            "valid generated secret key should validate")) {
        return 1;
    }
    if (expect_high_level(
            bitcoin_pqc_secret_key_validate(sk, sizeof(sk)),
            BITCOIN_PQC_OK,
            "high-level valid generated secret key should validate")) {
        return 1;
    }

    copy_and_mutate(mutated, sk, 0u);
    if (expect_low_level_reject(
            slh_dsa_secret_key_validate(mutated, sizeof(mutated)),
            "SK_SEED mutation should fail validation")) {
        return 1;
    }
    if (expect_high_level(
            bitcoin_pqc_secret_key_validate(mutated, sizeof(mutated)),
            BITCOIN_PQC_ERROR_BAD_KEY,
            "high-level SK_SEED mutation should be BAD_KEY")) {
        return 1;
    }

    copy_and_mutate(mutated, sk, 2u * n);
    if (expect_low_level_reject(
            slh_dsa_secret_key_validate(mutated, sizeof(mutated)),
            "PUB_SEED mutation should fail validation")) {
        return 1;
    }

    copy_and_mutate(mutated, sk, 3u * n);
    if (expect_low_level_reject(
            slh_dsa_secret_key_validate(mutated, sizeof(mutated)),
            "root mutation should fail validation")) {
        return 1;
    }
    memset(sig, 0xa5, sizeof(sig));
    siglen = sizeof(sig);
    if (expect_low_level_reject(
            slh_dsa_sign(sig, &siglen, message, sizeof(message) - 1u, mutated),
            "low-level signing should reject a mutated root tail")) {
        return 1;
    }
    if (siglen != 0) {
        return fail("rejected mutated root tail should reset siglen");
    }
    if (!signature_is_zero(sig, sizeof(sig))) {
        return fail("rejected mutated root tail should zero the signature buffer");
    }

    copy_and_mutate(mutated, sk, n);
    if (expect_low_level_ok(
            slh_dsa_secret_key_validate(mutated, sizeof(mutated)),
            "SK_PRF-only mutation should not affect public-root validation")) {
        return 1;
    }

    if (expect_low_level_reject(
            slh_dsa_secret_key_validate(sk, sizeof(sk) - 1u),
            "short secret key should fail validation")) {
        return 1;
    }
    if (expect_low_level_reject(
            slh_dsa_secret_key_validate(sk, sizeof(sk) + 1u),
            "long secret key size should fail validation")) {
        return 1;
    }
    if (expect_low_level_reject(
            slh_dsa_secret_key_validate(NULL, sizeof(sk)),
            "NULL secret key should fail validation")) {
        return 1;
    }

    if (expect_high_level(
            bitcoin_pqc_secret_key_validate(sk, sizeof(sk) - 1u),
            BITCOIN_PQC_ERROR_BAD_KEY,
            "high-level wrong size should be BAD_KEY")) {
        return 1;
    }
    if (expect_high_level(
            bitcoin_pqc_secret_key_validate(NULL, sizeof(sk)),
            BITCOIN_PQC_ERROR_BAD_ARG,
            "high-level NULL should be BAD_ARG")) {
        return 1;
    }

    return 0;
}

int main(void) {
    if (test_keygen_trusted_output_contract() || test_secret_key_validate()) {
        return 1;
    }

    printf("SLH-DSA secret key validation tests passed\n");
    return 0;
}
