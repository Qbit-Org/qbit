#include <stdlib.h>
#include <string.h>

#include "libbitcoinpqc/bitcoinpqc.h"
#include "libbitcoinpqc/slh_dsa.h"
#include "secure_zero.h"
#include "../sphincsplus/ref/sign_stats.h"

static const uint8_t EMPTY_MESSAGE[1] = {0};

static int keypair_output_is_empty(const bitcoin_pqc_keypair_t *keypair) {
    return keypair->public_key == NULL &&
           keypair->secret_key == NULL &&
           keypair->public_key_size == 0 &&
           keypair->secret_key_size == 0;
}

static int signature_output_is_empty(const bitcoin_pqc_signature_t *signature) {
    return signature->signature == NULL &&
           signature->signature_size == 0;
}

size_t bitcoin_pqc_public_key_size(void) {
    return SLH_DSA_PUBLIC_KEY_SIZE;
}

size_t bitcoin_pqc_secret_key_size(void) {
    return SLH_DSA_SECRET_KEY_SIZE;
}

size_t bitcoin_pqc_signature_size(void) {
    return SLH_DSA_SIGNATURE_SIZE;
}

bitcoin_pqc_error_t bitcoin_pqc_keygen(
    bitcoin_pqc_keypair_t *keypair,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!keypair || !random_data) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (!keypair_output_is_empty(keypair)) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (random_data_size < SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    size_t pk_size = bitcoin_pqc_public_key_size();
    size_t sk_size = bitcoin_pqc_secret_key_size();

    uint8_t *pk = malloc(pk_size);
    uint8_t *sk = malloc(sk_size);

    if (!pk || !sk) {
        bitcoin_pqc_secure_zero(pk, pk_size);
        bitcoin_pqc_secure_zero(sk, sk_size);
        free(pk);
        free(sk);
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (slh_dsa_keygen(pk, sk, random_data, random_data_size) != 0) {
        bitcoin_pqc_secure_zero(pk, pk_size);
        bitcoin_pqc_secure_zero(sk, sk_size);
        free(pk);
        free(sk);
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    keypair->public_key = pk;
    keypair->secret_key = sk;
    keypair->public_key_size = pk_size;
    keypair->secret_key_size = sk_size;

    return BITCOIN_PQC_OK;
}

bitcoin_pqc_error_t bitcoin_pqc_secret_key_validate(
    const uint8_t *secret_key,
    size_t secret_key_size
) {
    if (!secret_key) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (slh_dsa_secret_key_validate(secret_key, secret_key_size) != 0) {
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    return BITCOIN_PQC_OK;
}

void bitcoin_pqc_keypair_free(bitcoin_pqc_keypair_t *keypair) {
    if (!keypair) {
        return;
    }

    if (keypair->public_key) {
        bitcoin_pqc_secure_zero(keypair->public_key, keypair->public_key_size);
        free(keypair->public_key);
        keypair->public_key = NULL;
    }

    if (keypair->secret_key) {
        bitcoin_pqc_secure_zero(keypair->secret_key, keypair->secret_key_size);
        free(keypair->secret_key);
        keypair->secret_key = NULL;
    }

    keypair->public_key_size = 0;
    keypair->secret_key_size = 0;
}

static bitcoin_pqc_error_t bitcoin_pqc_sign_impl(
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature,
    bitcoin_pqc_sign_stats_t *stats
) {
    if (!secret_key || !signature) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (!message && message_size != 0) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (!signature_output_is_empty(signature)) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (secret_key_size != bitcoin_pqc_secret_key_size()) {
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    size_t public_key_size = bitcoin_pqc_public_key_size();
    const uint8_t *derived_public_key = secret_key + (secret_key_size - public_key_size);

    size_t expected_sig_size = bitcoin_pqc_signature_size();
    uint8_t *sig = malloc(expected_sig_size);
    if (!sig) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    size_t actual_sig_len = 0;
    const uint8_t *message_ptr = message ? message : EMPTY_MESSAGE;
    int result = slh_dsa_sign_with_stats(
        sig,
        &actual_sig_len,
        message_ptr,
        message_size,
        secret_key,
        stats
    );
    if (result != 0 || actual_sig_len != expected_sig_size) {
        bitcoin_pqc_secure_zero(sig, expected_sig_size);
        free(sig);
        if (result == BITCOINPQC_SIGN_LIMIT_EXCEEDED) {
            return BITCOIN_PQC_ERROR_SIGNING_LIMIT;
        }
        return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    if (slh_dsa_verify(sig, actual_sig_len, message_ptr, message_size, derived_public_key) != 0) {
        bitcoin_pqc_secure_zero(sig, expected_sig_size);
        free(sig);
        return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    signature->signature = sig;
    signature->signature_size = actual_sig_len;

    return BITCOIN_PQC_OK;
}

bitcoin_pqc_error_t bitcoin_pqc_sign(
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature
) {
    return bitcoin_pqc_sign_impl(
        secret_key,
        secret_key_size,
        message,
        message_size,
        signature,
        NULL
    );
}

bitcoin_pqc_error_t bitcoin_pqc_sign_with_stats(
    const uint8_t *secret_key,
    size_t secret_key_size,
    const uint8_t *message,
    size_t message_size,
    bitcoin_pqc_signature_t *signature,
    bitcoin_pqc_sign_stats_t *stats
) {
    return bitcoin_pqc_sign_impl(
        secret_key,
        secret_key_size,
        message,
        message_size,
        signature,
        stats
    );
}

void bitcoin_pqc_signature_free(bitcoin_pqc_signature_t *signature) {
    if (!signature) {
        return;
    }

    if (signature->signature) {
        bitcoin_pqc_secure_zero(signature->signature, signature->signature_size);
        free(signature->signature);
        signature->signature = NULL;
    }

    signature->signature_size = 0;
}

bitcoin_pqc_error_t bitcoin_pqc_verify(
    const uint8_t *public_key,
    size_t public_key_size,
    const uint8_t *message,
    size_t message_size,
    const uint8_t *signature,
    size_t signature_size
) {
    if (!public_key || !signature) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (!message && message_size != 0) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    if (public_key_size != bitcoin_pqc_public_key_size()) {
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    if (signature_size != bitcoin_pqc_signature_size()) {
        return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    const uint8_t *message_ptr = message ? message : EMPTY_MESSAGE;
    if (slh_dsa_verify(signature, signature_size, message_ptr, message_size, public_key) != 0) {
        return BITCOIN_PQC_ERROR_BAD_SIGNATURE;
    }

    return BITCOIN_PQC_OK;
}
