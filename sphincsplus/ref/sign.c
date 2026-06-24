#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "params.h"
#include "wots.h"
#include "fors.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "randombytes.h"
#include "sign_stats.h"
#include "utils.h"
#include "merkle.h"

#if defined(CUSTOM_RANDOMBYTES)
extern void slh_dsa_random_source_clear_failure(void);
extern int slh_dsa_random_source_failed(void);
#endif

static void secure_zero_local(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    spx_ctx ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2*SPX_N, SPX_N);

    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    /* Compute root node of the top-most subtree. */
    if (merkle_gen_root(sk + 3*SPX_N, &ctx) != 0) {
        return -1;
    }

    memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N);

    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[CRYPTO_SEEDBYTES];

#if defined(CUSTOM_RANDOMBYTES)
    slh_dsa_random_source_clear_failure();
#endif
    randombytes(seed, CRYPTO_SEEDBYTES);
#if defined(CUSTOM_RANDOMBYTES)
    if (slh_dsa_random_source_failed()) {
        secure_zero_local(seed, sizeof(seed));
        return -1;
    }
#endif

    int result = crypto_sign_seed_keypair(pk, sk, seed);
    secure_zero_local(seed, sizeof(seed));

    return result;
}

#if SPX_FORS_SIG_TREES < SPX_FORS_TREES
/*
 * FORS+C: extract the index for the compressed FORS tree from mhash.
 * This tree is the first one not included in the signature.
 */
static uint32_t forsc_compressed_index(const unsigned char *mhash)
{
    uint32_t idx = 0;
    unsigned int offset = (unsigned int)SPX_FORS_SIG_TREES * SPX_FORS_HEIGHT;
    unsigned int j;

    for (j = 0; j < SPX_FORS_HEIGHT; j++) {
        idx ^= (uint32_t)(((mhash[offset >> 3] >> (offset & 0x7)) & 1u) << j);
        offset++;
    }

    return idx;
}
#endif

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    spx_ctx ctx;

    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    /* Compute the digest randomization value R. */
#if defined(CUSTOM_RANDOMBYTES)
    slh_dsa_random_source_clear_failure();
#endif
    randombytes(optrand, SPX_N);
#if defined(CUSTOM_RANDOMBYTES)
    if (slh_dsa_random_source_failed()) {
        secure_zero_local(optrand, sizeof(optrand));
        *siglen = 0;
        return -1;
    }
#endif
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
#if SPX_FORS_SIG_TREES < SPX_FORS_TREES
    /* FORS+C salt grinding: vary R until the compressed tree index is 0. */
    {
        unsigned char r_base[SPX_N];
        uint32_t ctr = 0;
        uint32_t attempts = 0;

        memcpy(r_base, sig, SPX_N);
        for (;;) {
            attempts++;
            hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
            if (forsc_compressed_index(mhash) == 0) {
                bitcoin_pqc_sign_stats_record_forsc_attempts(attempts);
                break;
            }
            if (attempts >= (uint32_t)BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS) {
                bitcoin_pqc_sign_stats_record_forsc_attempts(attempts);
                bitcoin_pqc_sign_stats_record_forsc_cap();
                *siglen = 0;
                return BITCOINPQC_SIGN_LIMIT_EXCEEDED;
            }

            ctr++;
            /* Exhausted all 2^32 tweaks of sig[0..3] without a hit. */
            if (ctr == 0) {
                return -1;
            }
            memcpy(sig, r_base, SPX_N);
            sig[0] ^= (unsigned char)(ctr);
            sig[1] ^= (unsigned char)(ctr >> 8);
            sig[2] ^= (unsigned char)(ctr >> 16);
            sig[3] ^= (unsigned char)(ctr >> 24);
        }
    }
#else
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
#endif
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        int merkle_result = merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        if (merkle_result != 0) {
            *siglen = 0;
            return merkle_result;
        }
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);

#if SPX_FORS_SIG_TREES < SPX_FORS_TREES
    /* FORS+C: reject if the compressed tree index is not zero. */
    if (forsc_compressed_index(mhash) != 0) {
        return -1;
    }
#endif

    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        if (wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr) != 0) {
            return -1;
        }
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N)) {
        return -1;
    }

    return 0;
}


/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    size_t siglen;

    int result = crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk);
    if (result != 0) {
        memset(sm, 0, SPX_BYTES);
        *smlen = 0;
        return result;
    }

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}
