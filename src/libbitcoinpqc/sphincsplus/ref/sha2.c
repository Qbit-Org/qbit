/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "opt_flags.h"
#include "utils.h"
#include "sha2.h"
#include "sha2_armv8_sha.h"
#include "sha2_x86_shani.h"

#if defined(__APPLE__) && defined(__has_include)
#if __has_include(<CommonCrypto/CommonDigest.h>)
#include <CommonCrypto/CommonDigest.h>
#define SPX_USE_COMMONCRYPTO_SHA2 1
#endif
#endif

#if defined(__clang__) || defined(__GNUC__)
#define SPX_SHA_ATOMIC_LOAD_PTR(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define SPX_SHA_ATOMIC_STORE_PTR(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)
#else
#define SPX_SHA_ATOMIC_LOAD_PTR(ptr) (*(ptr))
#define SPX_SHA_ATOMIC_STORE_PTR(ptr, value) (*(ptr) = (value))
#endif

static uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
           (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

static uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
           (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
           (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
           (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}

static void store_bigendian_32(uint8_t *x, uint64_t u) {
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

static void store_bigendian_64(uint8_t *x, uint64_t u) {
    x[7] = (uint8_t) u;
    u >>= 8;
    x[6] = (uint8_t) u;
    u >>= 8;
    x[5] = (uint8_t) u;
    u >>= 8;
    x[4] = (uint8_t) u;
    u >>= 8;
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

/*
 * SHA-2 arithmetic is defined modulo 2^32 / 2^64.
 * Compute additions in wider intermediates to keep sanitizer-integer quiet.
 */
static inline uint32_t spx_add32(uint32_t lhs, uint32_t rhs)
{
    return (uint32_t)((uint64_t)lhs + (uint64_t)rhs);
}

static inline uint32_t spx_add32_4(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    return spx_add32(spx_add32(a, b), spx_add32(c, d));
}

static inline uint32_t spx_add32_5(uint32_t a, uint32_t b, uint32_t c,
                                   uint32_t d, uint32_t e)
{
    return spx_add32(spx_add32_4(a, b, c, d), e);
}

static inline uint64_t spx_add64(uint64_t lhs, uint64_t rhs)
{
#if defined(__SIZEOF_INT128__)
    return (uint64_t)(((__uint128_t)lhs) + ((__uint128_t)rhs));
#else
    uint64_t lo = (lhs & UINT64_C(0xffffffff)) + (rhs & UINT64_C(0xffffffff));
    uint64_t hi = (lhs >> 32) + (rhs >> 32) + (lo >> 32);
    return ((hi & UINT64_C(0xffffffff)) << 32) | (lo & UINT64_C(0xffffffff));
#endif
}

static inline uint64_t spx_add64_4(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    return spx_add64(spx_add64(a, b), spx_add64(c, d));
}

static inline uint64_t spx_add64_5(uint64_t a, uint64_t b, uint64_t c,
                                   uint64_t d, uint64_t e)
{
    return spx_add64(spx_add64_4(a, b, c, d), e);
}

#define SHR(x, c) ((x) >> (c))
#define ROTR_32(x, c) \
    (((x) >> (c)) | (((x) & ((((uint32_t)1) << (c)) - 1)) << (32 - (c))))
#define ROTR_64(x, c) \
    (((x) >> (c)) | (((x) & ((((uint64_t)1) << (c)) - 1)) << (64 - (c))))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0_32(x) (ROTR_32(x, 2) ^ ROTR_32(x,13) ^ ROTR_32(x,22))
#define Sigma1_32(x) (ROTR_32(x, 6) ^ ROTR_32(x,11) ^ ROTR_32(x,25))
#define sigma0_32(x) (ROTR_32(x, 7) ^ ROTR_32(x,18) ^ SHR(x, 3))
#define sigma1_32(x) (ROTR_32(x,17) ^ ROTR_32(x,19) ^ SHR(x,10))

#define Sigma0_64(x) (ROTR_64(x,28) ^ ROTR_64(x,34) ^ ROTR_64(x,39))
#define Sigma1_64(x) (ROTR_64(x,14) ^ ROTR_64(x,18) ^ ROTR_64(x,41))
#define sigma0_64(x) (ROTR_64(x, 1) ^ ROTR_64(x, 8) ^ SHR(x,7))
#define sigma1_64(x) (ROTR_64(x,19) ^ ROTR_64(x,61) ^ SHR(x,6))

#define M_32(w0, w14, w9, w1) \
    w0 = spx_add32_4(sigma1_32(w14), (w9), sigma0_32(w1), (w0));
#define M_64(w0, w14, w9, w1) \
    w0 = spx_add64_4(sigma1_64(w14), (w9), sigma0_64(w1), (w0));

#define EXPAND_32           \
    M_32(w0, w14, w9, w1)   \
    M_32(w1, w15, w10, w2)  \
    M_32(w2, w0, w11, w3)   \
    M_32(w3, w1, w12, w4)   \
    M_32(w4, w2, w13, w5)   \
    M_32(w5, w3, w14, w6)   \
    M_32(w6, w4, w15, w7)   \
    M_32(w7, w5, w0, w8)    \
    M_32(w8, w6, w1, w9)    \
    M_32(w9, w7, w2, w10)   \
    M_32(w10, w8, w3, w11)  \
    M_32(w11, w9, w4, w12)  \
    M_32(w12, w10, w5, w13) \
    M_32(w13, w11, w6, w14) \
    M_32(w14, w12, w7, w15) \
    M_32(w15, w13, w8, w0)

#define EXPAND_64 \
  M_64(w0 ,w14,w9 ,w1 ) \
  M_64(w1 ,w15,w10,w2 ) \
  M_64(w2 ,w0 ,w11,w3 ) \
  M_64(w3 ,w1 ,w12,w4 ) \
  M_64(w4 ,w2 ,w13,w5 ) \
  M_64(w5 ,w3 ,w14,w6 ) \
  M_64(w6 ,w4 ,w15,w7 ) \
  M_64(w7 ,w5 ,w0 ,w8 ) \
  M_64(w8 ,w6 ,w1 ,w9 ) \
  M_64(w9 ,w7 ,w2 ,w10) \
  M_64(w10,w8 ,w3 ,w11) \
  M_64(w11,w9 ,w4 ,w12) \
  M_64(w12,w10,w5 ,w13) \
  M_64(w13,w11,w6 ,w14) \
  M_64(w14,w12,w7 ,w15) \
  M_64(w15,w13,w8 ,w0 )

#define F_32(w, k) \
    T1 = spx_add32_5(h, Sigma1_32(e), Ch(e, f, g), (uint32_t)(k), (w)); \
    T2 = spx_add32(Sigma0_32(a), Maj(a, b, c)); \
    h = g; \
    g = f; \
    f = e; \
    e = spx_add32(d, T1); \
    d = c; \
    c = b; \
    b = a; \
    a = spx_add32(T1, T2);

#define F_64(w,k) \
    T1 = spx_add64_5(h, Sigma1_64(e), Ch(e,f,g), (k), (w)); \
    T2 = spx_add64(Sigma0_64(a), Maj(a,b,c)); \
    h = g; \
    g = f; \
    f = e; \
    e = spx_add64(d, T1); \
    d = c; \
    c = b; \
    b = a; \
    a = spx_add64(T1, T2);

static size_t crypto_hashblocks_sha256_ref(uint8_t *statebytes,
                                           const uint8_t *in, size_t inlen) {
    uint32_t state[8];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t T1;
    uint32_t T2;

    a = load_bigendian_32(statebytes + 0);
    state[0] = a;
    b = load_bigendian_32(statebytes + 4);
    state[1] = b;
    c = load_bigendian_32(statebytes + 8);
    state[2] = c;
    d = load_bigendian_32(statebytes + 12);
    state[3] = d;
    e = load_bigendian_32(statebytes + 16);
    state[4] = e;
    f = load_bigendian_32(statebytes + 20);
    state[5] = f;
    g = load_bigendian_32(statebytes + 24);
    state[6] = g;
    h = load_bigendian_32(statebytes + 28);
    state[7] = h;

    while (inlen >= 64) {
        uint32_t w0  = load_bigendian_32(in + 0);
        uint32_t w1  = load_bigendian_32(in + 4);
        uint32_t w2  = load_bigendian_32(in + 8);
        uint32_t w3  = load_bigendian_32(in + 12);
        uint32_t w4  = load_bigendian_32(in + 16);
        uint32_t w5  = load_bigendian_32(in + 20);
        uint32_t w6  = load_bigendian_32(in + 24);
        uint32_t w7  = load_bigendian_32(in + 28);
        uint32_t w8  = load_bigendian_32(in + 32);
        uint32_t w9  = load_bigendian_32(in + 36);
        uint32_t w10 = load_bigendian_32(in + 40);
        uint32_t w11 = load_bigendian_32(in + 44);
        uint32_t w12 = load_bigendian_32(in + 48);
        uint32_t w13 = load_bigendian_32(in + 52);
        uint32_t w14 = load_bigendian_32(in + 56);
        uint32_t w15 = load_bigendian_32(in + 60);

        F_32(w0, 0x428a2f98)
        F_32(w1, 0x71374491)
        F_32(w2, 0xb5c0fbcf)
        F_32(w3, 0xe9b5dba5)
        F_32(w4, 0x3956c25b)
        F_32(w5, 0x59f111f1)
        F_32(w6, 0x923f82a4)
        F_32(w7, 0xab1c5ed5)
        F_32(w8, 0xd807aa98)
        F_32(w9, 0x12835b01)
        F_32(w10, 0x243185be)
        F_32(w11, 0x550c7dc3)
        F_32(w12, 0x72be5d74)
        F_32(w13, 0x80deb1fe)
        F_32(w14, 0x9bdc06a7)
        F_32(w15, 0xc19bf174)

        EXPAND_32

        F_32(w0, 0xe49b69c1)
        F_32(w1, 0xefbe4786)
        F_32(w2, 0x0fc19dc6)
        F_32(w3, 0x240ca1cc)
        F_32(w4, 0x2de92c6f)
        F_32(w5, 0x4a7484aa)
        F_32(w6, 0x5cb0a9dc)
        F_32(w7, 0x76f988da)
        F_32(w8, 0x983e5152)
        F_32(w9, 0xa831c66d)
        F_32(w10, 0xb00327c8)
        F_32(w11, 0xbf597fc7)
        F_32(w12, 0xc6e00bf3)
        F_32(w13, 0xd5a79147)
        F_32(w14, 0x06ca6351)
        F_32(w15, 0x14292967)

        EXPAND_32

        F_32(w0, 0x27b70a85)
        F_32(w1, 0x2e1b2138)
        F_32(w2, 0x4d2c6dfc)
        F_32(w3, 0x53380d13)
        F_32(w4, 0x650a7354)
        F_32(w5, 0x766a0abb)
        F_32(w6, 0x81c2c92e)
        F_32(w7, 0x92722c85)
        F_32(w8, 0xa2bfe8a1)
        F_32(w9, 0xa81a664b)
        F_32(w10, 0xc24b8b70)
        F_32(w11, 0xc76c51a3)
        F_32(w12, 0xd192e819)
        F_32(w13, 0xd6990624)
        F_32(w14, 0xf40e3585)
        F_32(w15, 0x106aa070)

        EXPAND_32

        F_32(w0, 0x19a4c116)
        F_32(w1, 0x1e376c08)
        F_32(w2, 0x2748774c)
        F_32(w3, 0x34b0bcb5)
        F_32(w4, 0x391c0cb3)
        F_32(w5, 0x4ed8aa4a)
        F_32(w6, 0x5b9cca4f)
        F_32(w7, 0x682e6ff3)
        F_32(w8, 0x748f82ee)
        F_32(w9, 0x78a5636f)
        F_32(w10, 0x84c87814)
        F_32(w11, 0x8cc70208)
        F_32(w12, 0x90befffa)
        F_32(w13, 0xa4506ceb)
        F_32(w14, 0xbef9a3f7)
        F_32(w15, 0xc67178f2)

        a = spx_add32(a, state[0]);
        b = spx_add32(b, state[1]);
        c = spx_add32(c, state[2]);
        d = spx_add32(d, state[3]);
        e = spx_add32(e, state[4]);
        f = spx_add32(f, state[5]);
        g = spx_add32(g, state[6]);
        h = spx_add32(h, state[7]);

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 64;
        inlen -= 64;
    }

    store_bigendian_32(statebytes + 0, state[0]);
    store_bigendian_32(statebytes + 4, state[1]);
    store_bigendian_32(statebytes + 8, state[2]);
    store_bigendian_32(statebytes + 12, state[3]);
    store_bigendian_32(statebytes + 16, state[4]);
    store_bigendian_32(statebytes + 20, state[5]);
    store_bigendian_32(statebytes + 24, state[6]);
    store_bigendian_32(statebytes + 28, state[7]);

    return inlen;
}

static int crypto_hashblocks_sha512_ref(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen)
{
  uint64_t state[8];
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
  uint64_t e;
  uint64_t f;
  uint64_t g;
  uint64_t h;
  uint64_t T1;
  uint64_t T2;

  a = load_bigendian_64(statebytes +  0); state[0] = a;
  b = load_bigendian_64(statebytes +  8); state[1] = b;
  c = load_bigendian_64(statebytes + 16); state[2] = c;
  d = load_bigendian_64(statebytes + 24); state[3] = d;
  e = load_bigendian_64(statebytes + 32); state[4] = e;
  f = load_bigendian_64(statebytes + 40); state[5] = f;
  g = load_bigendian_64(statebytes + 48); state[6] = g;
  h = load_bigendian_64(statebytes + 56); state[7] = h;

  while (inlen >= 128) {
    uint64_t w0  = load_bigendian_64(in +   0);
    uint64_t w1  = load_bigendian_64(in +   8);
    uint64_t w2  = load_bigendian_64(in +  16);
    uint64_t w3  = load_bigendian_64(in +  24);
    uint64_t w4  = load_bigendian_64(in +  32);
    uint64_t w5  = load_bigendian_64(in +  40);
    uint64_t w6  = load_bigendian_64(in +  48);
    uint64_t w7  = load_bigendian_64(in +  56);
    uint64_t w8  = load_bigendian_64(in +  64);
    uint64_t w9  = load_bigendian_64(in +  72);
    uint64_t w10 = load_bigendian_64(in +  80);
    uint64_t w11 = load_bigendian_64(in +  88);
    uint64_t w12 = load_bigendian_64(in +  96);
    uint64_t w13 = load_bigendian_64(in + 104);
    uint64_t w14 = load_bigendian_64(in + 112);
    uint64_t w15 = load_bigendian_64(in + 120);

    F_64(w0 ,0x428a2f98d728ae22ULL)
    F_64(w1 ,0x7137449123ef65cdULL)
    F_64(w2 ,0xb5c0fbcfec4d3b2fULL)
    F_64(w3 ,0xe9b5dba58189dbbcULL)
    F_64(w4 ,0x3956c25bf348b538ULL)
    F_64(w5 ,0x59f111f1b605d019ULL)
    F_64(w6 ,0x923f82a4af194f9bULL)
    F_64(w7 ,0xab1c5ed5da6d8118ULL)
    F_64(w8 ,0xd807aa98a3030242ULL)
    F_64(w9 ,0x12835b0145706fbeULL)
    F_64(w10,0x243185be4ee4b28cULL)
    F_64(w11,0x550c7dc3d5ffb4e2ULL)
    F_64(w12,0x72be5d74f27b896fULL)
    F_64(w13,0x80deb1fe3b1696b1ULL)
    F_64(w14,0x9bdc06a725c71235ULL)
    F_64(w15,0xc19bf174cf692694ULL)

    EXPAND_64

    F_64(w0 ,0xe49b69c19ef14ad2ULL)
    F_64(w1 ,0xefbe4786384f25e3ULL)
    F_64(w2 ,0x0fc19dc68b8cd5b5ULL)
    F_64(w3 ,0x240ca1cc77ac9c65ULL)
    F_64(w4 ,0x2de92c6f592b0275ULL)
    F_64(w5 ,0x4a7484aa6ea6e483ULL)
    F_64(w6 ,0x5cb0a9dcbd41fbd4ULL)
    F_64(w7 ,0x76f988da831153b5ULL)
    F_64(w8 ,0x983e5152ee66dfabULL)
    F_64(w9 ,0xa831c66d2db43210ULL)
    F_64(w10,0xb00327c898fb213fULL)
    F_64(w11,0xbf597fc7beef0ee4ULL)
    F_64(w12,0xc6e00bf33da88fc2ULL)
    F_64(w13,0xd5a79147930aa725ULL)
    F_64(w14,0x06ca6351e003826fULL)
    F_64(w15,0x142929670a0e6e70ULL)

    EXPAND_64

    F_64(w0 ,0x27b70a8546d22ffcULL)
    F_64(w1 ,0x2e1b21385c26c926ULL)
    F_64(w2 ,0x4d2c6dfc5ac42aedULL)
    F_64(w3 ,0x53380d139d95b3dfULL)
    F_64(w4 ,0x650a73548baf63deULL)
    F_64(w5 ,0x766a0abb3c77b2a8ULL)
    F_64(w6 ,0x81c2c92e47edaee6ULL)
    F_64(w7 ,0x92722c851482353bULL)
    F_64(w8 ,0xa2bfe8a14cf10364ULL)
    F_64(w9 ,0xa81a664bbc423001ULL)
    F_64(w10,0xc24b8b70d0f89791ULL)
    F_64(w11,0xc76c51a30654be30ULL)
    F_64(w12,0xd192e819d6ef5218ULL)
    F_64(w13,0xd69906245565a910ULL)
    F_64(w14,0xf40e35855771202aULL)
    F_64(w15,0x106aa07032bbd1b8ULL)

    EXPAND_64

    F_64(w0 ,0x19a4c116b8d2d0c8ULL)
    F_64(w1 ,0x1e376c085141ab53ULL)
    F_64(w2 ,0x2748774cdf8eeb99ULL)
    F_64(w3 ,0x34b0bcb5e19b48a8ULL)
    F_64(w4 ,0x391c0cb3c5c95a63ULL)
    F_64(w5 ,0x4ed8aa4ae3418acbULL)
    F_64(w6 ,0x5b9cca4f7763e373ULL)
    F_64(w7 ,0x682e6ff3d6b2b8a3ULL)
    F_64(w8 ,0x748f82ee5defb2fcULL)
    F_64(w9 ,0x78a5636f43172f60ULL)
    F_64(w10,0x84c87814a1f0ab72ULL)
    F_64(w11,0x8cc702081a6439ecULL)
    F_64(w12,0x90befffa23631e28ULL)
    F_64(w13,0xa4506cebde82bde9ULL)
    F_64(w14,0xbef9a3f7b2c67915ULL)
    F_64(w15,0xc67178f2e372532bULL)

    EXPAND_64

    F_64(w0 ,0xca273eceea26619cULL)
    F_64(w1 ,0xd186b8c721c0c207ULL)
    F_64(w2 ,0xeada7dd6cde0eb1eULL)
    F_64(w3 ,0xf57d4f7fee6ed178ULL)
    F_64(w4 ,0x06f067aa72176fbaULL)
    F_64(w5 ,0x0a637dc5a2c898a6ULL)
    F_64(w6 ,0x113f9804bef90daeULL)
    F_64(w7 ,0x1b710b35131c471bULL)
    F_64(w8 ,0x28db77f523047d84ULL)
    F_64(w9 ,0x32caab7b40c72493ULL)
    F_64(w10,0x3c9ebe0a15c9bebcULL)
    F_64(w11,0x431d67c49c100d4cULL)
    F_64(w12,0x4cc5d4becb3e42b6ULL)
    F_64(w13,0x597f299cfc657e2aULL)
    F_64(w14,0x5fcb6fab3ad6faecULL)
    F_64(w15,0x6c44198c4a475817ULL)

    a = spx_add64(a, state[0]);
    b = spx_add64(b, state[1]);
    c = spx_add64(c, state[2]);
    d = spx_add64(d, state[3]);
    e = spx_add64(e, state[4]);
    f = spx_add64(f, state[5]);
    g = spx_add64(g, state[6]);
    h = spx_add64(h, state[7]);
  
    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    in += 128;
    inlen -= 128;
  }

  store_bigendian_64(statebytes +  0,state[0]);
  store_bigendian_64(statebytes +  8,state[1]);
  store_bigendian_64(statebytes + 16,state[2]);
  store_bigendian_64(statebytes + 24,state[3]);
  store_bigendian_64(statebytes + 32,state[4]);
  store_bigendian_64(statebytes + 40,state[5]);
  store_bigendian_64(statebytes + 48,state[6]);
  store_bigendian_64(statebytes + 56,state[7]);

  return (int)inlen;
}

#if defined(SPX_USE_COMMONCRYPTO_SHA2)
static size_t spx_cc_sha256_hashblocks(uint8_t *statebytes, const uint8_t *in, size_t inlen)
{
    CC_SHA256_CTX ctx;
    size_t i;
    size_t full_bytes = inlen & ~((size_t)SPX_SHA256_BLOCK_BYTES - 1U);

    if (full_bytes == 0) {
        return inlen;
    }

    memset(&ctx, 0, sizeof(ctx));
    for (i = 0; i < 8; ++i) {
        ctx.hash[i] = (CC_LONG)load_bigendian_32(statebytes + 4 * i);
    }
    CC_SHA256_Update(&ctx, in, (CC_LONG)full_bytes);
    for (i = 0; i < 8; ++i) {
        store_bigendian_32(statebytes + 4 * i, (uint32_t)ctx.hash[i]);
    }

    return inlen - full_bytes;
}

static int spx_cc_sha512_hashblocks(unsigned char *statebytes,
                                    const unsigned char *in,
                                    unsigned long long inlen)
{
    CC_SHA512_CTX ctx;
    size_t i;
    size_t full_bytes = (size_t)inlen & ~((size_t)SPX_SHA512_BLOCK_BYTES - 1U);

    if (full_bytes == 0) {
        return (int)inlen;
    }

    memset(&ctx, 0, sizeof(ctx));
    for (i = 0; i < 8; ++i) {
        ctx.hash[i] = (CC_LONG64)load_bigendian_64(statebytes + 8 * i);
    }
    CC_SHA512_Update(&ctx, in, (CC_LONG)full_bytes);
    for (i = 0; i < 8; ++i) {
        store_bigendian_64(statebytes + 8 * i, (uint64_t)ctx.hash[i]);
    }

    return (int)(inlen - full_bytes);
}
#endif

typedef size_t (*spx_sha256_hashblocks_impl_fn)(uint8_t *statebytes,
                                                const uint8_t *in,
                                                size_t inlen);
typedef int (*spx_sha512_hashblocks_impl_fn)(unsigned char *statebytes,
                                             const unsigned char *in,
                                             unsigned long long inlen);

static spx_sha256_hashblocks_impl_fn spx_sha256_hashblocks_impl = NULL;
static spx_sha512_hashblocks_impl_fn spx_sha512_hashblocks_impl = NULL;

static spx_sha256_hashblocks_impl_fn spx_sha256_select_hashblocks_impl(void)
{
    int mode = spx_opt_sha_backend_mode();

    if (spx_opt_disable_sha_accel() || mode == SPX_SHA_BACKEND_SCALAR) {
        return crypto_hashblocks_sha256_ref;
    }

#if defined(SPX_ENABLE_ARM_SHA)
    if (mode == SPX_SHA_BACKEND_ARM) {
        if (spx_sha2_arm_can_use_sha256()) {
            return spx_sha2_arm_hashblocks_sha256;
        }
        return crypto_hashblocks_sha256_ref;
    }
#else
    if (mode == SPX_SHA_BACKEND_ARM) {
        return crypto_hashblocks_sha256_ref;
    }
#endif

    if (mode == SPX_SHA_BACKEND_X86) {
        if (spx_sha2_x86_can_use_sha256_ni()) {
            return spx_sha2_x86_hashblocks_sha256;
        }
        return crypto_hashblocks_sha256_ref;
    }

    if (mode == SPX_SHA_BACKEND_COMMONCRYPTO) {
#if defined(SPX_USE_COMMONCRYPTO_SHA2)
        return spx_cc_sha256_hashblocks;
#else
        return crypto_hashblocks_sha256_ref;
#endif
    }

    if (spx_sha2_x86_can_use_sha256_ni()) {
        return spx_sha2_x86_hashblocks_sha256;
    }

#if defined(SPX_ENABLE_ARM_SHA)
    if (spx_sha2_arm_can_use_sha256()) {
        return spx_sha2_arm_hashblocks_sha256;
    }
#endif

#if defined(SPX_USE_COMMONCRYPTO_SHA2)
    return spx_cc_sha256_hashblocks;
#else
    return crypto_hashblocks_sha256_ref;
#endif
}

static spx_sha512_hashblocks_impl_fn spx_sha512_select_hashblocks_impl(void)
{
    int mode = spx_opt_sha_backend_mode();

    if (spx_opt_disable_sha_accel() || mode == SPX_SHA_BACKEND_SCALAR) {
        return crypto_hashblocks_sha512_ref;
    }

#if defined(SPX_ENABLE_ARM_SHA)
    if (mode == SPX_SHA_BACKEND_ARM) {
        if (spx_sha2_arm_can_use_sha512()) {
            return spx_sha2_arm_hashblocks_sha512;
        }
        return crypto_hashblocks_sha512_ref;
    }
#else
    if (mode == SPX_SHA_BACKEND_ARM) {
        return crypto_hashblocks_sha512_ref;
    }
#endif

    if (mode == SPX_SHA_BACKEND_X86) {
        if (spx_sha2_x86_can_use_sha512_ni()) {
            return spx_sha2_x86_hashblocks_sha512;
        }
        return crypto_hashblocks_sha512_ref;
    }

    if (mode == SPX_SHA_BACKEND_COMMONCRYPTO) {
#if defined(SPX_USE_COMMONCRYPTO_SHA2)
        return spx_cc_sha512_hashblocks;
#else
        return crypto_hashblocks_sha512_ref;
#endif
    }

    if (spx_sha2_x86_can_use_sha512_ni()) {
        return spx_sha2_x86_hashblocks_sha512;
    }

#if defined(SPX_ENABLE_ARM_SHA)
    if (spx_sha2_arm_can_use_sha512()) {
        return spx_sha2_arm_hashblocks_sha512;
    }
#endif

#if defined(SPX_USE_COMMONCRYPTO_SHA2)
    return spx_cc_sha512_hashblocks;
#else
    return crypto_hashblocks_sha512_ref;
#endif
}

static spx_sha256_hashblocks_impl_fn spx_sha256_get_hashblocks_impl(void)
{
    spx_sha256_hashblocks_impl_fn impl =
        SPX_SHA_ATOMIC_LOAD_PTR(&spx_sha256_hashblocks_impl);

    if (impl == NULL) {
        impl = spx_sha256_select_hashblocks_impl();
        SPX_SHA_ATOMIC_STORE_PTR(&spx_sha256_hashblocks_impl, impl);
    }

    return impl;
}

static spx_sha512_hashblocks_impl_fn spx_sha512_get_hashblocks_impl(void)
{
    spx_sha512_hashblocks_impl_fn impl =
        SPX_SHA_ATOMIC_LOAD_PTR(&spx_sha512_hashblocks_impl);

    if (impl == NULL) {
        impl = spx_sha512_select_hashblocks_impl();
        SPX_SHA_ATOMIC_STORE_PTR(&spx_sha512_hashblocks_impl, impl);
    }

    return impl;
}

static size_t crypto_hashblocks_sha256(uint8_t *statebytes,
                                       const uint8_t *in, size_t inlen)
{
    return spx_sha256_get_hashblocks_impl()(statebytes, in, inlen);
}

static int crypto_hashblocks_sha512(unsigned char *statebytes,
                                    const unsigned char *in,
                                    unsigned long long inlen)
{
    return spx_sha512_get_hashblocks_impl()(statebytes, in, inlen);
}


static const uint8_t iv_256[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};

static const uint8_t iv_512[64] = {
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
    0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
    0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
    0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
    0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
    0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
};

void sha256_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_256[i];
    }
    for (size_t i = 32; i < 40; ++i) {
        state[i] = 0;
    }
}

void sha512_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 64; ++i) {
        state[i] = iv_512[i];
    }
    for (size_t i = 64; i < 72; ++i) {
        state[i] = 0;
    }
}

void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);

    crypto_hashblocks_sha256(state, in, 64 * inblocks);
    bytes += 64 * inblocks;

    store_bigendian_64(state + 32, bytes);
}

void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 64);

    crypto_hashblocks_sha512(state, in, 128 * inblocks);
    bytes += 128 * inblocks;

    store_bigendian_64(state + 64, bytes);
}

void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = load_bigendian_64(state + 32) + inlen;

    crypto_hashblocks_sha256(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; ++i) {
            padded[i] = 0;
        }
        padded[56] = (uint8_t) (bytes >> 53);
        padded[57] = (uint8_t) (bytes >> 45);
        padded[58] = (uint8_t) (bytes >> 37);
        padded[59] = (uint8_t) (bytes >> 29);
        padded[60] = (uint8_t) (bytes >> 21);
        padded[61] = (uint8_t) (bytes >> 13);
        padded[62] = (uint8_t) (bytes >> 5);
        padded[63] = (uint8_t) (bytes << 3);
        crypto_hashblocks_sha256(state, padded, 64);
    } else {
        for (size_t i = inlen + 1; i < 120; ++i) {
            padded[i] = 0;
        }
        padded[120] = (uint8_t) (bytes >> 53);
        padded[121] = (uint8_t) (bytes >> 45);
        padded[122] = (uint8_t) (bytes >> 37);
        padded[123] = (uint8_t) (bytes >> 29);
        padded[124] = (uint8_t) (bytes >> 21);
        padded[125] = (uint8_t) (bytes >> 13);
        padded[126] = (uint8_t) (bytes >> 5);
        padded[127] = (uint8_t) (bytes << 3);
        crypto_hashblocks_sha256(state, padded, 128);
    }

    for (size_t i = 0; i < 32; ++i) {
        out[i] = state[i];
    }

}

void sha512_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen) {
    uint8_t padded[256];
    uint64_t bytes = load_bigendian_64(state + 64) + inlen;

    crypto_hashblocks_sha512(state, in, inlen);
    in += inlen;
    inlen &= 127;
    in -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 112) {
        for (size_t i = inlen + 1; i < 119; ++i) {
            padded[i] = 0;
        }
        padded[119] = (uint8_t) (bytes >> 61);
        padded[120] = (uint8_t) (bytes >> 53);
        padded[121] = (uint8_t) (bytes >> 45);
        padded[122] = (uint8_t) (bytes >> 37);
        padded[123] = (uint8_t) (bytes >> 29);
        padded[124] = (uint8_t) (bytes >> 21);
        padded[125] = (uint8_t) (bytes >> 13);
        padded[126] = (uint8_t) (bytes >> 5);
        padded[127] = (uint8_t) (bytes << 3);
        crypto_hashblocks_sha512(state, padded, 128);
    } else {
        for (size_t i = inlen + 1; i < 247; ++i) {
            padded[i] = 0;
        }
        padded[247] = (uint8_t) (bytes >> 61);
        padded[248] = (uint8_t) (bytes >> 53);
        padded[249] = (uint8_t) (bytes >> 45);
        padded[250] = (uint8_t) (bytes >> 37);
        padded[251] = (uint8_t) (bytes >> 29);
        padded[252] = (uint8_t) (bytes >> 21);
        padded[253] = (uint8_t) (bytes >> 13);
        padded[254] = (uint8_t) (bytes >> 5);
        padded[255] = (uint8_t) (bytes << 3);
        crypto_hashblocks_sha512(state, padded, 256);
    }

    for (size_t i = 0; i < 64; ++i) {
        out[i] = state[i];
    }
}

void sha256(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint8_t state[40];

    sha256_inc_init(state);
    sha256_inc_finalize(out, state, in, inlen);
}

void sha512(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint8_t state[72];

    sha512_inc_init(state);
    sha512_inc_finalize(out, state, in, inlen);
}

/**
 * mgf1 function based on the SHA-256 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SHA256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SHA256_OUTPUT_BYTES);
    }
}

/*
 * mgf1 function based on the SHA-512 hash function
 */
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SHA512 output.. */
    for (i = 0; (i+1)*SPX_SHA512_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sha512(out, inbuf, inlen + 4);
        out += SPX_SHA512_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SHA512_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sha512(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SHA512_OUTPUT_BYTES);
    }
}


/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused in thash
 **/
void seed_state(spx_ctx *ctx) {
    uint8_t block[SPX_SHA512_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = ctx->pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SHA512_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }
    /* block has been properly initialized for both SHA-256 and SHA-512 */

    sha256_inc_init(ctx->state_seeded);
    sha256_inc_blocks(ctx->state_seeded, block, 1);
#if SPX_SHA512
    sha512_inc_init(ctx->state_seeded_512);
    sha512_inc_blocks(ctx->state_seeded_512, block, 1);
#endif
}
