#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"
#include "merkle.h"
#include "address.h"
#include "params.h"

#if defined(SPX_AVX2)
#include "utilsx8.h"
#include "wotsx8.h"
#endif

#include "avx2_compat.h"

static int merkle_sign_scalar(uint8_t *sig, unsigned char *root,
                              const spx_ctx *ctx,
                              uint32_t wots_addr[8], uint32_t tree_addr[8],
                              uint32_t idx_leaf)
{
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = {0};
    unsigned steps[SPX_WOTS_LEN];
    int chain_result;

    if (idx_leaf != SPX_NO_SIGN_LEAF) {
        info.wots_sig = sig;
        chain_result = chain_lengths(steps, root);
        if (chain_result != 0) {
            return chain_result;
        }
        info.wots_steps = steps;
    } else {
        info.wots_sig = NULL;
        info.wots_steps = NULL;
    }

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1(root, auth_path, ctx,
               idx_leaf, 0,
               SPX_TREE_HEIGHT,
               wots_gen_leafx1,
               tree_addr, &info);
    return 0;
}

#if defined(SPX_AVX2)
static int merkle_sign_avx2(uint8_t *sig, unsigned char *root,
                            const spx_ctx *ctx,
                            uint32_t wots_addr[8], uint32_t tree_addr[8],
                            uint32_t idx_leaf)
{
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    uint32_t tree_addrx8[8 * 8] = {0};
    struct leaf_info_x8 info = {0};
    unsigned steps[SPX_WOTS_LEN];
    int j;
    int chain_result;

    if (idx_leaf != SPX_NO_SIGN_LEAF) {
        info.wots_sig = sig;
        chain_result = chain_lengths(steps, root);
        if (chain_result != 0) {
            return chain_result;
        }
        info.wots_steps = steps;
    } else {
        info.wots_sig = NULL;
        info.wots_steps = NULL;
    }

    for (j = 0; j < 8; ++j) {
        set_type(&tree_addrx8[8 * j], SPX_ADDR_TYPE_HASHTREE);
        set_type(&info.leaf_addr[8 * j], SPX_ADDR_TYPE_WOTS);
        set_type(&info.pk_addr[8 * j], SPX_ADDR_TYPE_WOTSPK);
        copy_subtree_addr(&tree_addrx8[8 * j], tree_addr);
        copy_subtree_addr(&info.leaf_addr[8 * j], wots_addr);
        copy_subtree_addr(&info.pk_addr[8 * j], wots_addr);
    }

    info.wots_sign_leaf = idx_leaf;

    treehashx8(root, auth_path, ctx,
               idx_leaf, 0,
               SPX_TREE_HEIGHT,
               wots_gen_leafx8,
               tree_addrx8, &info);
    return 0;
}
#endif

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
int merkle_sign(uint8_t *sig, unsigned char *root,
                const spx_ctx *ctx,
                uint32_t wots_addr[8], uint32_t tree_addr[8],
                uint32_t idx_leaf)
{
#if defined(SPX_AVX2) && (defined(__x86_64__) || defined(__i386__))
    if (spx_has_avx2()) {
        return merkle_sign_avx2(sig, root, ctx, wots_addr, tree_addr, idx_leaf);
    }
#endif

    return merkle_sign_scalar(sig, root, ctx, wots_addr, tree_addr, idx_leaf);
}

/* Compute root node of the top-most subtree. */
int merkle_gen_root(unsigned char *root, const spx_ctx *ctx)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    return merkle_sign(auth_path, root, ctx,
                       wots_addr, top_tree_addr,
                       SPX_NO_SIGN_LEAF);
}
