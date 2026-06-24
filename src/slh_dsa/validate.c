#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libbitcoinpqc/slh_dsa.h"

#include "../../sphincsplus/ref/context.h"
#include "../../sphincsplus/ref/hash.h"
#include "../../sphincsplus/ref/merkle.h"
#include "../../sphincsplus/ref/params.h"
#include "../secure_zero.h"

#if SLH_DSA_SECRET_KEY_SIZE != (4 * SPX_N)
#error "SLH-DSA secret-key validator expects [SK_SEED || SK_PRF || PUB_SEED || root]"
#endif

static int bytes_equal(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(lhs[i] ^ rhs[i]);
    }

    return diff == 0;
}

int slh_dsa_secret_key_validate(const uint8_t *sk, size_t sk_size) {
    spx_ctx ctx;
    uint8_t root[SPX_N];
    int result = -1;

    if (!sk || sk_size != SLH_DSA_SECRET_KEY_SIZE) {
        return -1;
    }

    memset(&ctx, 0, sizeof(ctx));
    memset(root, 0, sizeof(root));

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, sk + 2 * SPX_N, SPX_N);

    initialize_hash_function(&ctx);

    if (merkle_gen_root(root, &ctx) != 0) {
        goto cleanup;
    }

    if (bytes_equal(root, sk + 3 * SPX_N, SPX_N)) {
        result = 0;
    }

cleanup:
    bitcoin_pqc_secure_zero(root, sizeof(root));
    bitcoin_pqc_secure_zero(&ctx, sizeof(ctx));
    return result;
}
