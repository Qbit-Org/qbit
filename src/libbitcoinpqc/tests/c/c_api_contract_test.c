#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libbitcoinpqc/bitcoinpqc.h"

#define MIN_ENTROPY_SIZE 128u
#define LONG_ENTROPY_SIZE 160u

static void fill_entropy(uint8_t *out, size_t len, uint8_t seed) {
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)(seed + (uint8_t)((i * 37u) & 0xffu));
    }
}

static int fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int expect_ok(bitcoin_pqc_error_t rc, const char *message) {
    if (rc != BITCOIN_PQC_OK) {
        fprintf(stderr, "%s: rc=%d\n", message, (int)rc);
        return 1;
    }
    return 0;
}

static int expect_bad_arg(bitcoin_pqc_error_t rc, const char *message) {
    if (rc != BITCOIN_PQC_ERROR_BAD_ARG) {
        fprintf(stderr, "%s: rc=%d\n", message, (int)rc);
        return 1;
    }
    return 0;
}

static int keypair_is_empty(const bitcoin_pqc_keypair_t *keypair) {
    return keypair->public_key == NULL &&
           keypair->secret_key == NULL &&
           keypair->public_key_size == 0 &&
           keypair->secret_key_size == 0;
}

static int signature_is_empty(const bitcoin_pqc_signature_t *signature) {
    return signature->signature == NULL &&
           signature->signature_size == 0;
}

static int keypair_fields_equal(
    const bitcoin_pqc_keypair_t *lhs,
    const bitcoin_pqc_keypair_t *rhs
) {
    return lhs->public_key == rhs->public_key &&
           lhs->secret_key == rhs->secret_key &&
           lhs->public_key_size == rhs->public_key_size &&
           lhs->secret_key_size == rhs->secret_key_size;
}

static int signature_fields_equal(
    const bitcoin_pqc_signature_t *lhs,
    const bitcoin_pqc_signature_t *rhs
) {
    return lhs->signature == rhs->signature &&
           lhs->signature_size == rhs->signature_size;
}

static int keypairs_equal(
    const bitcoin_pqc_keypair_t *lhs,
    const bitcoin_pqc_keypair_t *rhs
) {
    return lhs->public_key_size == rhs->public_key_size &&
           lhs->secret_key_size == rhs->secret_key_size &&
           memcmp(lhs->public_key, rhs->public_key, lhs->public_key_size) == 0 &&
           memcmp(lhs->secret_key, rhs->secret_key, lhs->secret_key_size) == 0;
}

static int keygen_checked(
    bitcoin_pqc_keypair_t *keypair,
    const uint8_t *entropy,
    size_t entropy_size
) {
    bitcoin_pqc_error_t rc = bitcoin_pqc_keygen(keypair, entropy, entropy_size);
    if (expect_ok(rc, "bitcoin_pqc_keygen should succeed")) {
        return 1;
    }

    if (!keypair->public_key || !keypair->secret_key) {
        return fail("keygen returned null key buffers");
    }
    if (keypair->public_key_size != bitcoin_pqc_public_key_size()) {
        return fail("keygen returned unexpected public key size");
    }
    if (keypair->secret_key_size != bitcoin_pqc_secret_key_size()) {
        return fail("keygen returned unexpected secret key size");
    }

    return 0;
}

static int test_keygen_output_lifecycle(void) {
    uint8_t entropy[MIN_ENTROPY_SIZE];
    uint8_t sentinel_public = 0xa5u;
    uint8_t sentinel_secret = 0x5au;
    bitcoin_pqc_keypair_t keypair = {0};
    bitcoin_pqc_keypair_t occupied_cases[] = {
        {(void *)&sentinel_public, NULL, 0, 0},
        {NULL, (void *)&sentinel_secret, 0, 0},
        {NULL, NULL, 1, 0},
        {NULL, NULL, 0, 1},
    };
    size_t i;

    fill_entropy(entropy, sizeof(entropy), 0x10u);

    if (keygen_checked(&keypair, entropy, sizeof(entropy))) {
        return 1;
    }

    bitcoin_pqc_keypair_free(&keypair);
    if (!keypair_is_empty(&keypair)) {
        return fail("keypair_free did not reset returned keypair");
    }

    bitcoin_pqc_keypair_free(&keypair);
    if (!keypair_is_empty(&keypair)) {
        return fail("second keypair_free did not leave keypair empty");
    }

    if (keygen_checked(&keypair, entropy, sizeof(entropy))) {
        return 1;
    }
    bitcoin_pqc_keypair_free(&keypair);

    for (i = 0; i < sizeof(occupied_cases) / sizeof(occupied_cases[0]); i++) {
        bitcoin_pqc_keypair_t before = occupied_cases[i];
        bitcoin_pqc_error_t rc =
            bitcoin_pqc_keygen(&occupied_cases[i], entropy, sizeof(entropy));
        if (expect_bad_arg(rc, "non-empty keypair output should be rejected")) {
            return 1;
        }
        if (!keypair_fields_equal(&before, &occupied_cases[i])) {
            return fail("non-empty keypair output was overwritten");
        }
    }

    return 0;
}

static int test_signature_output_lifecycle(void) {
    static const uint8_t message[] = "c api lifecycle";
    uint8_t entropy[MIN_ENTROPY_SIZE];
    uint8_t sentinel_signature = 0x3cu;
    bitcoin_pqc_keypair_t keypair = {0};
    bitcoin_pqc_signature_t signature = {0};
    bitcoin_pqc_sign_stats_t stats = {0};
    bitcoin_pqc_signature_t occupied_cases[] = {
        {&sentinel_signature, 0},
        {NULL, 1},
    };
    size_t i;

    fill_entropy(entropy, sizeof(entropy), 0x20u);
    if (keygen_checked(&keypair, entropy, sizeof(entropy))) {
        return 1;
    }

    if (expect_ok(
            bitcoin_pqc_sign_with_stats(
                (const uint8_t *)keypair.secret_key,
                keypair.secret_key_size,
                message,
                sizeof(message) - 1,
                &signature,
                &stats),
            "bitcoin_pqc_sign should succeed")) {
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }
    if (!signature.signature || signature.signature_size != bitcoin_pqc_signature_size()) {
        bitcoin_pqc_keypair_free(&keypair);
        return fail("sign returned invalid signature output");
    }
    if (stats.forsc_attempts == 0 ||
            stats.forsc_attempts > stats.forsc_max_attempts ||
            stats.wotsc_layer_count != BITCOIN_PQC_SIGN_WOTSC_LAYERS ||
            stats.wotsc_max_observed_attempts == 0 ||
            stats.wotsc_max_observed_attempts > stats.wotsc_max_attempts ||
            stats.cap_exceeded != BITCOIN_PQC_SIGN_LIMIT_NONE) {
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return fail("sign stats did not report expected bounded30 counters");
    }

    bitcoin_pqc_signature_free(&signature);
    if (!signature_is_empty(&signature)) {
        bitcoin_pqc_keypair_free(&keypair);
        return fail("signature_free did not reset returned signature");
    }

    bitcoin_pqc_signature_free(&signature);
    if (!signature_is_empty(&signature)) {
        bitcoin_pqc_keypair_free(&keypair);
        return fail("second signature_free did not leave signature empty");
    }

    if (expect_ok(
            bitcoin_pqc_sign(
                (const uint8_t *)keypair.secret_key,
                keypair.secret_key_size,
                message,
                sizeof(message) - 1,
                &signature),
            "bitcoin_pqc_sign should succeed after signature free")) {
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }
    bitcoin_pqc_signature_free(&signature);

    for (i = 0; i < sizeof(occupied_cases) / sizeof(occupied_cases[0]); i++) {
        bitcoin_pqc_signature_t before = occupied_cases[i];
        bitcoin_pqc_error_t rc =
            bitcoin_pqc_sign(
                (const uint8_t *)keypair.secret_key,
                keypair.secret_key_size,
                message,
                sizeof(message) - 1,
                &occupied_cases[i]);
        if (expect_bad_arg(rc, "non-empty signature output should be rejected")) {
            bitcoin_pqc_keypair_free(&keypair);
            return 1;
        }
        if (!signature_fields_equal(&before, &occupied_cases[i])) {
            bitcoin_pqc_keypair_free(&keypair);
            return fail("non-empty signature output was overwritten");
        }
    }

    bitcoin_pqc_keypair_free(&keypair);
    return 0;
}

static int test_null_empty_message_sign_verify(void) {
    uint8_t entropy[MIN_ENTROPY_SIZE];
    bitcoin_pqc_keypair_t keypair = {0};
    bitcoin_pqc_signature_t signature = {0};
    bitcoin_pqc_signature_t rejected_signature = {0};

    fill_entropy(entropy, sizeof(entropy), 0x30u);
    if (keygen_checked(&keypair, entropy, sizeof(entropy))) {
        return 1;
    }

    if (expect_ok(
            bitcoin_pqc_sign(
                (const uint8_t *)keypair.secret_key,
                keypair.secret_key_size,
                NULL,
                0,
                &signature),
            "signing NULL empty message should succeed")) {
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    if (expect_ok(
            bitcoin_pqc_verify(
                (const uint8_t *)keypair.public_key,
                keypair.public_key_size,
                NULL,
                0,
                signature.signature,
                signature.signature_size),
            "verifying NULL empty message should succeed")) {
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    if (expect_bad_arg(
            bitcoin_pqc_sign(
                (const uint8_t *)keypair.secret_key,
                keypair.secret_key_size,
                NULL,
                1,
                &rejected_signature),
            "signing NULL non-empty message should be rejected")) {
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }
    if (!signature_is_empty(&rejected_signature)) {
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return fail("rejected NULL non-empty sign mutated signature output");
    }

    if (expect_bad_arg(
            bitcoin_pqc_verify(
                (const uint8_t *)keypair.public_key,
                keypair.public_key_size,
                NULL,
                1,
                signature.signature,
                signature.signature_size),
            "verifying NULL non-empty message should be rejected")) {
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
    return 0;
}

static int assert_entropy_mutation_changes_keypair(size_t entropy_size, size_t mutation_index) {
    uint8_t base_entropy[LONG_ENTROPY_SIZE];
    uint8_t mutated_entropy[LONG_ENTROPY_SIZE];
    bitcoin_pqc_keypair_t base = {0};
    bitcoin_pqc_keypair_t repeated = {0};
    bitcoin_pqc_keypair_t mutated = {0};
    int failed = 0;

    fill_entropy(base_entropy, entropy_size, 0x40u);
    memcpy(mutated_entropy, base_entropy, entropy_size);
    mutated_entropy[mutation_index] ^= 0x80u;

    if (keygen_checked(&base, base_entropy, entropy_size) ||
        keygen_checked(&repeated, base_entropy, entropy_size) ||
        keygen_checked(&mutated, mutated_entropy, entropy_size)) {
        failed = 1;
        goto cleanup;
    }

    if (!keypairs_equal(&base, &repeated)) {
        fprintf(stderr, "same full entropy input did not reproduce keypair\n");
        failed = 1;
        goto cleanup;
    }

    if (keypairs_equal(&base, &mutated)) {
        fprintf(stderr,
                "entropy mutation at byte %zu of %zu did not change keypair\n",
                mutation_index,
                entropy_size);
        failed = 1;
    }

cleanup:
    bitcoin_pqc_keypair_free(&mutated);
    bitcoin_pqc_keypair_free(&repeated);
    bitcoin_pqc_keypair_free(&base);
    return failed;
}

static int test_keygen_uses_all_entropy_bytes(void) {
    if (assert_entropy_mutation_changes_keypair(MIN_ENTROPY_SIZE, 48u)) {
        return 1;
    }
    if (assert_entropy_mutation_changes_keypair(MIN_ENTROPY_SIZE, 127u)) {
        return 1;
    }
    if (assert_entropy_mutation_changes_keypair(LONG_ENTROPY_SIZE, LONG_ENTROPY_SIZE - 1u)) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_keygen_output_lifecycle() ||
        test_signature_output_lifecycle() ||
        test_null_empty_message_sign_verify() ||
        test_keygen_uses_all_entropy_bytes()) {
        return 1;
    }

    printf("C API contract tests passed\n");
    return 0;
}
