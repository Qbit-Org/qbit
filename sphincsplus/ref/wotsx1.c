#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"

#if defined(SPX_AVX2)
#include "hashx8.h"
#include "thashx8.h"
#include "wotsx8.h"
#endif

#include "avx2_compat.h"

/*
 * This generates a WOTS public key
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with this WOTS key
 */
static void wots_gen_leafx1_scalar(unsigned char *dest,
                                   const spx_ctx *ctx,
                                   uint32_t leaf_idx, void *v_info)
{
    struct leaf_info_x1 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, k;
    unsigned char pk_buffer[ SPX_WOTS_BYTES ];
    unsigned char *buffer;
    int do_sign;

    do_sign = info->wots_steps != NULL &&
              info->wots_sig != NULL &&
              info->wots_sign_leaf != SPX_NO_SIGN_LEAF &&
              leaf_idx == info->wots_sign_leaf;

    set_keypair_addr( leaf_addr, leaf_idx );
    set_keypair_addr( pk_addr, leaf_idx );

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N) {
        uint32_t wots_k = do_sign ? info->wots_steps[i] : SPX_NO_SIGN_LEAF;

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k=0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (do_sign && k == wots_k) {
                memcpy( info->wots_sig + i * SPX_N, buffer, SPX_N );
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W - 1) break;

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash(dest, pk_buffer, SPX_WOTS_LEN, ctx, pk_addr);
}

#if defined(SPX_AVX2)
static void wots_gen_leafx1_avx2(unsigned char *dest,
                                 const spx_ctx *ctx,
                                 uint32_t leaf_idx, void *v_info)
{
    struct leaf_info_x1 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, j, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES];
    int do_sign;
    uint32_t addrs[8 * 8];
    unsigned char bufs_storage[8 * SPX_N];
    unsigned char empty[SPX_N] = {0};
    unsigned char *bufs[8];

    do_sign = info->wots_steps != NULL &&
              info->wots_sig != NULL &&
              info->wots_sign_leaf != SPX_NO_SIGN_LEAF &&
              leaf_idx == info->wots_sign_leaf;

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0; i < SPX_WOTS_LEN; i += 8) {
        unsigned int lanes = SPX_WOTS_LEN - i;
        if (lanes > 8) {
            lanes = 8;
        }

        for (j = 0; j < 8; ++j) {
            memcpy(addrs + j * 8, leaf_addr, 8 * sizeof(uint32_t));
            bufs[j] = bufs_storage + j * SPX_N;
            if (j < lanes) {
                set_chain_addr(addrs + j * 8, i + j);
            } else {
                set_chain_addr(addrs + j * 8, 0);
                bufs[j] = empty;
            }
            set_hash_addr(addrs + j * 8, 0);
            set_type(addrs + j * 8, SPX_ADDR_TYPE_WOTSPRF);
        }

        prf_addrx8(bufs[0], bufs[1], bufs[2], bufs[3],
                   bufs[4], bufs[5], bufs[6], bufs[7],
                   ctx, addrs);

        for (j = 0; j < lanes; ++j) {
            set_type(addrs + j * 8, SPX_ADDR_TYPE_WOTS);
        }

        for (k = 0;; ++k) {
            for (j = 0; j < lanes; ++j) {
                uint32_t wots_k = do_sign ? info->wots_steps[i + j] : SPX_NO_SIGN_LEAF;
                if (do_sign && k == wots_k) {
                    memcpy(info->wots_sig + (i + j) * SPX_N, bufs[j], SPX_N);
                }
            }

            if (k == SPX_WOTS_W - 1) {
                break;
            }

            for (j = 0; j < lanes; ++j) {
                set_hash_addr(addrs + j * 8, k);
            }

            thashx8(bufs[0], bufs[1], bufs[2], bufs[3],
                    bufs[4], bufs[5], bufs[6], bufs[7],
                    bufs[0], bufs[1], bufs[2], bufs[3],
                    bufs[4], bufs[5], bufs[6], bufs[7],
                    1, ctx, addrs);
        }

        for (j = 0; j < lanes; ++j) {
            memcpy(pk_buffer + (i + j) * SPX_N, bufs[j], SPX_N);
        }
    }

    thash(dest, pk_buffer, SPX_WOTS_LEN, ctx, pk_addr);
}

void wots_gen_leafx8(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info)
{
    struct leaf_info_x8 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, j, k;
    unsigned char pk_buffer[8 * SPX_WOTS_BYTES];
    unsigned int wots_offset = SPX_WOTS_BYTES;
    unsigned char *buffer;
    int do_sign;
    unsigned int wots_sign_index;

    do_sign = info->wots_steps != NULL &&
              info->wots_sig != NULL &&
              info->wots_sign_leaf != SPX_NO_SIGN_LEAF &&
              ((leaf_idx ^ info->wots_sign_leaf) & ~UINT32_C(7)) == 0;
    if (do_sign) {
        wots_sign_index = info->wots_sign_leaf & 7u;
    } else {
        wots_sign_index = 0;
    }

    for (j = 0; j < 8; ++j) {
        set_keypair_addr(leaf_addr + j * 8, leaf_idx + j);
        set_keypair_addr(pk_addr + j * 8, leaf_idx + j);
    }

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; ++i, buffer += SPX_N) {
        uint32_t wots_k = do_sign ? info->wots_steps[i] : SPX_NO_SIGN_LEAF;

        for (j = 0; j < 8; ++j) {
            set_chain_addr(leaf_addr + j * 8, i);
            set_hash_addr(leaf_addr + j * 8, 0);
            set_type(leaf_addr + j * 8, SPX_ADDR_TYPE_WOTSPRF);
        }

        prf_addrx8(buffer + 0 * wots_offset,
                   buffer + 1 * wots_offset,
                   buffer + 2 * wots_offset,
                   buffer + 3 * wots_offset,
                   buffer + 4 * wots_offset,
                   buffer + 5 * wots_offset,
                   buffer + 6 * wots_offset,
                   buffer + 7 * wots_offset,
                   ctx, leaf_addr);

        for (j = 0; j < 8; ++j) {
            set_type(leaf_addr + j * 8, SPX_ADDR_TYPE_WOTS);
        }

        for (k = 0;; ++k) {
            if (do_sign && k == wots_k) {
                memcpy(info->wots_sig + i * SPX_N,
                       buffer + wots_sign_index * wots_offset,
                       SPX_N);
            }

            if (k == SPX_WOTS_W - 1) {
                break;
            }

            for (j = 0; j < 8; ++j) {
                set_hash_addr(leaf_addr + j * 8, k);
            }

            thashx8(buffer + 0 * wots_offset,
                    buffer + 1 * wots_offset,
                    buffer + 2 * wots_offset,
                    buffer + 3 * wots_offset,
                    buffer + 4 * wots_offset,
                    buffer + 5 * wots_offset,
                    buffer + 6 * wots_offset,
                    buffer + 7 * wots_offset,
                    buffer + 0 * wots_offset,
                    buffer + 1 * wots_offset,
                    buffer + 2 * wots_offset,
                    buffer + 3 * wots_offset,
                    buffer + 4 * wots_offset,
                    buffer + 5 * wots_offset,
                    buffer + 6 * wots_offset,
                    buffer + 7 * wots_offset,
                    1, ctx, leaf_addr);
        }
    }

    thashx8(dest + 0 * SPX_N,
            dest + 1 * SPX_N,
            dest + 2 * SPX_N,
            dest + 3 * SPX_N,
            dest + 4 * SPX_N,
            dest + 5 * SPX_N,
            dest + 6 * SPX_N,
            dest + 7 * SPX_N,
            pk_buffer + 0 * wots_offset,
            pk_buffer + 1 * wots_offset,
            pk_buffer + 2 * wots_offset,
            pk_buffer + 3 * wots_offset,
            pk_buffer + 4 * wots_offset,
            pk_buffer + 5 * wots_offset,
            pk_buffer + 6 * wots_offset,
            pk_buffer + 7 * wots_offset,
            SPX_WOTS_LEN, ctx, pk_addr);
}
#endif

void wots_gen_leafx1(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info)
{
#if defined(SPX_AVX2) && (defined(__x86_64__) || defined(__i386__))
    if (spx_has_avx2()) {
        wots_gen_leafx1_avx2(dest, ctx, leaf_idx, v_info);
        return;
    }
#endif
    wots_gen_leafx1_scalar(dest, ctx, leaf_idx, v_info);
}
