#include "libbitcoinpqc/slh_dsa.h"

#include "../../sphincsplus/ref/api.h"

int slh_dsa_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (!sig || (!m && mlen != 0) || !pk) {
        return -1;
    }

    const uint8_t empty_message = 0;
    const uint8_t *message = m ? m : &empty_message;

    return crypto_sign_verify(sig, siglen, message, mlen, pk);
}
