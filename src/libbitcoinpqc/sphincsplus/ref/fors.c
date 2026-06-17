#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fors.h"
#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "opt_flags.h"

#if defined(SPX_AVX2)
#include "hashx8.h"
#include "thashx8.h"
#include "utilsx8.h"
#endif

#include "avx2_compat.h"

#if defined(__APPLE__) || defined(__unix__)
#include <pthread.h>
#define SPX_FORS_USE_PTHREADS 1
#endif

static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
                        uint32_t fors_leaf_addr[8])
{
    prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};

static void fors_gen_leafx1(unsigned char *leaf,
                            const spx_ctx *ctx,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, leaf,
                    ctx, fors_leaf_addr);
}

#if defined(SPX_AVX2)
static void fors_gen_skx8(unsigned char *sk0,
                          unsigned char *sk1,
                          unsigned char *sk2,
                          unsigned char *sk3,
                          unsigned char *sk4,
                          unsigned char *sk5,
                          unsigned char *sk6,
                          unsigned char *sk7,
                          const spx_ctx *ctx,
                          uint32_t fors_leaf_addrx8[8 * 8])
{
    prf_addrx8(sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7, ctx, fors_leaf_addrx8);
}

static void fors_sk_to_leafx8(unsigned char *leaf0,
                              unsigned char *leaf1,
                              unsigned char *leaf2,
                              unsigned char *leaf3,
                              unsigned char *leaf4,
                              unsigned char *leaf5,
                              unsigned char *leaf6,
                              unsigned char *leaf7,
                              const unsigned char *sk0,
                              const unsigned char *sk1,
                              const unsigned char *sk2,
                              const unsigned char *sk3,
                              const unsigned char *sk4,
                              const unsigned char *sk5,
                              const unsigned char *sk6,
                              const unsigned char *sk7,
                              const spx_ctx *ctx,
                              uint32_t fors_leaf_addrx8[8 * 8])
{
    thashx8(leaf0, leaf1, leaf2, leaf3, leaf4, leaf5, leaf6, leaf7,
            sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7,
            1, ctx, fors_leaf_addrx8);
}

struct fors_gen_leaf_info_x8 {
    uint32_t leaf_addrx[8 * 8];
};

static void fors_gen_leafx8(unsigned char *leaf,
                            const spx_ctx *ctx,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info_x8 *fors_info = info;
    uint32_t *fors_leaf_addrx8 = fors_info->leaf_addrx;
    unsigned int j;

    for (j = 0; j < 8; ++j) {
        set_tree_index(fors_leaf_addrx8 + j * 8, addr_idx + j);
        set_type(fors_leaf_addrx8 + j * 8, SPX_ADDR_TYPE_FORSPRF);
    }

    fors_gen_skx8(leaf + 0 * SPX_N,
                  leaf + 1 * SPX_N,
                  leaf + 2 * SPX_N,
                  leaf + 3 * SPX_N,
                  leaf + 4 * SPX_N,
                  leaf + 5 * SPX_N,
                  leaf + 6 * SPX_N,
                  leaf + 7 * SPX_N,
                  ctx, fors_leaf_addrx8);

    for (j = 0; j < 8; ++j) {
        set_type(fors_leaf_addrx8 + j * 8, SPX_ADDR_TYPE_FORSTREE);
    }

    fors_sk_to_leafx8(leaf + 0 * SPX_N,
                      leaf + 1 * SPX_N,
                      leaf + 2 * SPX_N,
                      leaf + 3 * SPX_N,
                      leaf + 4 * SPX_N,
                      leaf + 5 * SPX_N,
                      leaf + 6 * SPX_N,
                      leaf + 7 * SPX_N,
                      leaf + 0 * SPX_N,
                      leaf + 1 * SPX_N,
                      leaf + 2 * SPX_N,
                      leaf + 3 * SPX_N,
                      leaf + 4 * SPX_N,
                      leaf + 5 * SPX_N,
                      leaf + 6 * SPX_N,
                      leaf + 7 * SPX_N,
                      ctx, fors_leaf_addrx8);
}
#endif

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_SIG_TREES bits.
 * Assumes indices has space for SPX_FORS_SIG_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_SIG_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 1u) << j;
            offset++;
        }
    }
}

#define SPX_FORS_TREE_SIG_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_N)

static void fors_sign_tree(unsigned char *sig_tree, unsigned char *root_out,
                           const spx_ctx *ctx, const uint32_t fors_addr[8],
                           uint32_t leaf_idx, uint32_t tree_num)
{
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_tree_addr[8] = {0};
    uint32_t idx_offset = tree_num * (1U << SPX_FORS_HEIGHT);

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    set_tree_height(fors_tree_addr, 0);
    set_tree_index(fors_tree_addr, leaf_idx + idx_offset);
    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

    /* Include the secret key part that produces the selected leaf node. */
    fors_gen_sk(sig_tree, ctx, fors_tree_addr);
    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);

    /* Compute the authentication path for this leaf node. */
    treehashx1(root_out, sig_tree + SPX_N, ctx,
               leaf_idx, idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx1,
               fors_tree_addr, &fors_info);
}

#if defined(SPX_AVX2)
static void fors_sign_tree_avx2(unsigned char *sig_tree, unsigned char *root_out,
                                const spx_ctx *ctx, const uint32_t fors_addr[8],
                                uint32_t leaf_idx, uint32_t tree_num)
{
    struct fors_gen_leaf_info_x8 fors_info = {0};
    uint32_t *fors_leaf_addrx8 = fors_info.leaf_addrx;
    uint32_t fors_tree_addrx8[8 * 8] = {0};
    uint32_t idx_offset = tree_num * (1U << SPX_FORS_HEIGHT);
    unsigned int j;

    for (j = 0; j < 8; ++j) {
        copy_keypair_addr(fors_tree_addrx8 + 8 * j, fors_addr);
        set_type(fors_tree_addrx8 + 8 * j, SPX_ADDR_TYPE_FORSTREE);
        copy_keypair_addr(fors_leaf_addrx8 + 8 * j, fors_addr);
    }

    set_tree_height(fors_tree_addrx8, 0);
    set_tree_index(fors_tree_addrx8, leaf_idx + idx_offset);
    set_type(fors_tree_addrx8, SPX_ADDR_TYPE_FORSPRF);

    fors_gen_sk(sig_tree, ctx, fors_tree_addrx8);
    set_type(fors_tree_addrx8, SPX_ADDR_TYPE_FORSTREE);

    treehashx8(root_out, sig_tree + SPX_N, ctx,
               leaf_idx, idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx8,
               fors_tree_addrx8, &fors_info);
}
#endif

#if defined(SPX_FORS_USE_PTHREADS)
typedef struct {
    unsigned char *sig_base;
    unsigned char *roots;
    const uint32_t *indices;
    const spx_ctx *ctx;
    const uint32_t *fors_addr;
    uint32_t begin;
    uint32_t end;
} fors_sign_worker_args;

static void *fors_sign_worker(void *arg)
{
    fors_sign_worker_args *args = (fors_sign_worker_args *)arg;
    uint32_t i;

    for (i = args->begin; i < args->end; ++i) {
        unsigned char *sig_tree = args->sig_base + ((size_t)i * SPX_FORS_TREE_SIG_BYTES);
        unsigned char *root_out = args->roots + ((size_t)i * SPX_N);
        fors_sign_tree(sig_tree, root_out, args->ctx, args->fors_addr, args->indices[i], i);
    }

    return NULL;
}

static uint32_t fors_sign_worker_count(void)
{
    uint32_t workers = 1;
#if SPX_RUNTIME_ENV_KNOBS_ENABLED
    const char *env_threads = getenv("SPX_FORS_THREADS");

    if (env_threads != NULL && env_threads[0] != '\0') {
        unsigned long configured = strtoul(env_threads, NULL, 10);
        if (configured > 0) {
            workers = (uint32_t)configured;
        }
    }
#endif

    if (workers > SPX_FORS_SIG_TREES) {
        workers = SPX_FORS_SIG_TREES;
    }
    if (workers == 0) {
        workers = 1;
    }
    return workers;
}
#endif

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_SIG_TREES bits.
 */
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_SIG_TREES];
    unsigned char roots[SPX_FORS_SIG_TREES * SPX_N];
    uint32_t fors_pk_addr[8] = {0};
    unsigned int i;

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

#if defined(SPX_AVX2) && (defined(__x86_64__) || defined(__i386__))
    if (spx_has_avx2()) {
        for (i = 0; i < SPX_FORS_SIG_TREES; ++i) {
            unsigned char *sig_tree = sig + ((size_t)i * SPX_FORS_TREE_SIG_BYTES);
            unsigned char *root_out = roots + ((size_t)i * SPX_N);
            fors_sign_tree_avx2(sig_tree, root_out, ctx, fors_addr, indices[i], i);
        }
        goto fors_sign_done;
    }
#endif

    {
        unsigned char *sig_base = sig;
        unsigned int scalar_start = 0;
#if defined(SPX_FORS_USE_PTHREADS)
        uint32_t workers = fors_sign_worker_count();
        if (workers > 1) {
            pthread_t threads[SPX_FORS_SIG_TREES];
            fors_sign_worker_args args[SPX_FORS_SIG_TREES];
            uint32_t start = 0;
            uint32_t t;
            uint32_t launched = 0;
            int spawn_failed = 0;

            for (t = 0; t < workers; ++t) {
                uint32_t remaining_trees = SPX_FORS_SIG_TREES - start;
                uint32_t remaining_workers = workers - t;
                uint32_t share = (remaining_trees + remaining_workers - 1) / remaining_workers;
                uint32_t end = start + share;

                args[t].sig_base = sig_base;
                args[t].roots = roots;
                args[t].indices = indices;
                args[t].ctx = ctx;
                args[t].fors_addr = fors_addr;
                args[t].begin = start;
                args[t].end = end;

                if (pthread_create(&threads[t], NULL, fors_sign_worker, &args[t]) != 0) {
                    spawn_failed = 1;
                    break;
                }

                launched++;
                start = end;
            }

            for (t = 0; t < launched; ++t) {
                pthread_join(threads[t], NULL);
            }

            scalar_start = start;
            if (!spawn_failed && start == SPX_FORS_SIG_TREES) {
                goto fors_sign_done;
            }
        }
#endif

        for (i = scalar_start; i < SPX_FORS_SIG_TREES; i++) {
            unsigned char *sig_tree = sig_base + ((size_t)i * SPX_FORS_TREE_SIG_BYTES);
            unsigned char *root_out = roots + ((size_t)i * SPX_N);
            fors_sign_tree(sig_tree, root_out, ctx, fors_addr, indices[i], i);
        }
    }

fors_sign_done:

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_SIG_TREES, ctx, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_SIG_TREES bits.
 */
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx* ctx,
                      const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_SIG_TREES];
    unsigned char roots[SPX_FORS_SIG_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_SIG_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        compute_root(roots + i*SPX_N, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_SIG_TREES, ctx, fors_pk_addr);
}
