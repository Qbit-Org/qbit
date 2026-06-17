#include <stddef.h>
#include <stdint.h>

#include "sha2_x86_shani.h"

#if !defined(__APPLE__) && (defined(__x86_64__) || defined(__i386__))
#define SPX_SHA2_X86_BACKEND 1
#else
#define SPX_SHA2_X86_BACKEND 0
#endif

#if SPX_SHA2_X86_BACKEND && (defined(__clang__) || defined(__GNUC__))

#include <immintrin.h>

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if __has_builtin(__builtin_ia32_sha256rnds2) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 8))
#define SPX_HAVE_SHA256_INTRINSICS 1
#endif

#if __has_builtin(__builtin_ia32_vsha512rnds2) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 14))
#define SPX_HAVE_SHA512_INTRINSICS 1
#endif

#define SPX_ATOMIC_LOAD(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define SPX_ATOMIC_STORE(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELAXED)

static uint32_t spx_load_be32(const uint8_t *x) {
    return (uint32_t)x[3] | ((uint32_t)x[2] << 8) | ((uint32_t)x[1] << 16) | ((uint32_t)x[0] << 24);
}

static uint64_t spx_load_be64(const uint8_t *x) {
    return (uint64_t)x[7] | ((uint64_t)x[6] << 8) | ((uint64_t)x[5] << 16) | ((uint64_t)x[4] << 24) |
           ((uint64_t)x[3] << 32) | ((uint64_t)x[2] << 40) | ((uint64_t)x[1] << 48) | ((uint64_t)x[0] << 56);
}

static void spx_store_be32(uint8_t *x, uint32_t u) {
    x[0] = (uint8_t)(u >> 24);
    x[1] = (uint8_t)(u >> 16);
    x[2] = (uint8_t)(u >> 8);
    x[3] = (uint8_t)u;
}

static void spx_store_be64(uint8_t *x, uint64_t u) {
    x[0] = (uint8_t)(u >> 56);
    x[1] = (uint8_t)(u >> 48);
    x[2] = (uint8_t)(u >> 40);
    x[3] = (uint8_t)(u >> 32);
    x[4] = (uint8_t)(u >> 24);
    x[5] = (uint8_t)(u >> 16);
    x[6] = (uint8_t)(u >> 8);
    x[7] = (uint8_t)u;
}

static void spx_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
#if defined(__i386__) && defined(__PIC__)
    __asm__ volatile("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
                     : "=a"(*eax), "=&r"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "0"(leaf), "2"(subleaf));
#else
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "0"(leaf), "2"(subleaf));
#endif
}

static uint64_t spx_xgetbv0(void) {
    uint32_t eax;
    uint32_t edx;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t)edx << 32) | eax;
}

static int spx_sha256_ni_available = -1;
static int spx_sha512_ni_available = -1;

#if defined(SPX_HAVE_SHA256_INTRINSICS)
__attribute__((target("sha,ssse3,sse4.1")))
static void spx_sha256_process_x86(uint32_t state[8], const uint8_t *data, size_t length) {
    __m128i state0;
    __m128i state1;
    __m128i msg;
    __m128i tmp;
    __m128i msg0;
    __m128i msg1;
    __m128i msg2;
    __m128i msg3;
    __m128i abef_save;
    __m128i cdgh_save;
    const __m128i bswap_mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    tmp = _mm_loadu_si128((const __m128i *)&state[0]);
    state1 = _mm_loadu_si128((const __m128i *)&state[4]);

    tmp = _mm_shuffle_epi32(tmp, 0xB1);          /* CDAB */
    state1 = _mm_shuffle_epi32(state1, 0x1B);    /* EFGH */
    state0 = _mm_alignr_epi8(tmp, state1, 8);    /* ABEF */
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); /* CDGH */

    while (length >= 64) {
        abef_save = state0;
        cdgh_save = state1;

        msg = _mm_loadu_si128((const __m128i *)(data + 0));
        msg0 = _mm_shuffle_epi8(msg, bswap_mask);
        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        msg1 = _mm_loadu_si128((const __m128i *)(data + 16));
        msg1 = _mm_shuffle_epi8(msg1, bswap_mask);
        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        msg2 = _mm_loadu_si128((const __m128i *)(data + 32));
        msg2 = _mm_shuffle_epi8(msg2, bswap_mask);
        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        msg3 = _mm_loadu_si128((const __m128i *)(data + 48));
        msg3 = _mm_shuffle_epi8(msg3, bswap_mask);
        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);

        data += 64;
        length -= 64;
    }

    tmp = _mm_shuffle_epi32(state0, 0x1B);       /* FEBA */
    state1 = _mm_shuffle_epi32(state1, 0xB1);    /* DCHG */
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); /* DCBA */
    state1 = _mm_alignr_epi8(state1, tmp, 8);    /* ABEF */

    _mm_storeu_si128((__m128i *)&state[0], state0);
    _mm_storeu_si128((__m128i *)&state[4], state1);
}
#endif

#if defined(SPX_HAVE_SHA512_INTRINSICS)
static const uint64_t spx_sha512_k[80] __attribute__((aligned(32))) = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL,
};

__attribute__((target("sha512,avx,avx2")))
static inline void spx_sha512_permute_state(__m256i *state0, __m256i *state1) {
    __m256i tmp;
    *state0 = _mm256_shuffle_epi32(*state0, 0x4E);
    *state1 = _mm256_shuffle_epi32(*state1, 0x4E);
    tmp = *state0;
    *state0 = _mm256_permute2x128_si256(*state0, *state1, 0x13);
    *state1 = _mm256_permute2x128_si256(tmp, *state1, 0x02);
}

__attribute__((target("sha512,avx,avx2")))
static inline void spx_sha512_4rounds(__m256i *state0, __m256i *state1, const __m256i msg, const __m256i k) {
    const __m256i wk = _mm256_add_epi64(msg, k);
    *state0 = _mm256_sha512rnds2_epi64(*state0, *state1, _mm256_extracti128_si256(wk, 0));
    *state1 = _mm256_sha512rnds2_epi64(*state1, *state0, _mm256_extracti128_si256(wk, 1));
}

__attribute__((target("sha512,avx,avx2")))
static inline void spx_sha512_msg_expand(__m256i *m0, __m256i *m1, __m256i *m2, __m256i *m3) {
    *m3 = _mm256_sha512msg1_epi64(*m3, _mm256_extracti128_si256(*m0, 0));
    *m2 = _mm256_add_epi64(*m2, _mm256_permute4x64_epi64(_mm256_blend_epi32(*m0, *m1, 0x03), 0x39));
    *m2 = _mm256_sha512msg2_epi64(*m2, *m1);
}

__attribute__((target("sha512,avx,avx2")))
static void spx_sha512_process_x86(uint64_t state[8], const uint8_t *input, size_t length) {
    const __m256i bswap_mask =
        _mm256_set_epi64x(0x08090A0B0C0D0E0FULL, 0x0001020304050607ULL, 0x08090A0B0C0D0E0FULL,
                          0x0001020304050607ULL);
    const __m256i *k = (const __m256i *)(const void *)spx_sha512_k;

    __m256i state0 = _mm256_loadu_si256((const __m256i *)(const void *)&state[0]);
    __m256i state1 = _mm256_loadu_si256((const __m256i *)(const void *)&state[4]);

    spx_sha512_permute_state(&state0, &state1);

    while (length >= 128) {
        const __m256i state0_save = state0;
        const __m256i state1_save = state1;
        __m256i m0 = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(input + 0)), bswap_mask);
        __m256i m1 = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(input + 32)), bswap_mask);
        __m256i m2 = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(input + 64)), bswap_mask);
        __m256i m3 = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(input + 96)), bswap_mask);
        size_t r;

        spx_sha512_4rounds(&state0, &state1, m0, _mm256_loadu_si256(&k[0]));
        spx_sha512_4rounds(&state0, &state1, m1, _mm256_loadu_si256(&k[1]));
        m0 = _mm256_sha512msg1_epi64(m0, _mm256_extracti128_si256(m1, 0));

        for (r = 2; r != 18; r += 4) {
            spx_sha512_4rounds(&state0, &state1, m2, _mm256_loadu_si256(&k[r + 0]));
            spx_sha512_msg_expand(&m2, &m3, &m0, &m1);

            spx_sha512_4rounds(&state0, &state1, m3, _mm256_loadu_si256(&k[r + 1]));
            spx_sha512_msg_expand(&m3, &m0, &m1, &m2);

            spx_sha512_4rounds(&state0, &state1, m0, _mm256_loadu_si256(&k[r + 2]));
            spx_sha512_msg_expand(&m0, &m1, &m2, &m3);

            spx_sha512_4rounds(&state0, &state1, m1, _mm256_loadu_si256(&k[r + 3]));
            spx_sha512_msg_expand(&m1, &m2, &m3, &m0);
        }

        spx_sha512_4rounds(&state0, &state1, m2, _mm256_loadu_si256(&k[18]));
        spx_sha512_4rounds(&state0, &state1, m3, _mm256_loadu_si256(&k[19]));

        state0 = _mm256_add_epi64(state0, state0_save);
        state1 = _mm256_add_epi64(state1, state1_save);

        input += 128;
        length -= 128;
    }

    spx_sha512_permute_state(&state0, &state1);

    _mm256_storeu_si256((__m256i *)(void *)&state[0], state0);
    _mm256_storeu_si256((__m256i *)(void *)&state[4], state1);
}
#endif

static int spx_detect_sha256_ni(void) {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    spx_cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    if (eax < 7U) {
        return 0;
    }

    spx_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1U << 9)) == 0U || (ecx & (1U << 19)) == 0U) {
        return 0;
    }

    spx_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    return (ebx & (1U << 29)) != 0U;
}

static int spx_detect_sha512_ni(void) {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    spx_cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    if (eax < 7U) {
        return 0;
    }

    spx_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if ((ecx & (1U << 9)) == 0U || (ecx & (1U << 19)) == 0U) {
        return 0;
    }
    if ((ecx & (1U << 27)) == 0U || (ecx & (1U << 28)) == 0U) {
        return 0;
    }
    if ((spx_xgetbv0() & 0x6U) != 0x6U) {
        return 0;
    }

    spx_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    if ((ebx & (1U << 5)) == 0U || eax < 1U) {
        return 0;
    }

    spx_cpuid(7, 1, &eax, &ebx, &ecx, &edx);
    return (eax & (1U << 0)) != 0U;
}

int spx_sha2_x86_can_use_sha256_ni(void) {
#if defined(SPX_HAVE_SHA256_INTRINSICS)
    int cached = SPX_ATOMIC_LOAD(&spx_sha256_ni_available);
    if (cached < 0) {
        cached = spx_detect_sha256_ni() ? 1 : 0;
        SPX_ATOMIC_STORE(&spx_sha256_ni_available, cached);
    }
    return cached;
#else
    return 0;
#endif
}

int spx_sha2_x86_can_use_sha512_ni(void) {
#if defined(SPX_HAVE_SHA512_INTRINSICS)
    int cached = SPX_ATOMIC_LOAD(&spx_sha512_ni_available);
    if (cached < 0) {
        cached = spx_detect_sha512_ni() ? 1 : 0;
        SPX_ATOMIC_STORE(&spx_sha512_ni_available, cached);
    }
    return cached;
#else
    return 0;
#endif
}

size_t spx_sha2_x86_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen) {
#if defined(SPX_HAVE_SHA256_INTRINSICS)
    size_t full_bytes = inlen & ~((size_t)63U);
    uint32_t state[8];
    size_t i;

    if (full_bytes == 0 || !spx_sha2_x86_can_use_sha256_ni()) {
        return inlen;
    }

    for (i = 0; i < 8; ++i) {
        state[i] = spx_load_be32(statebytes + 4 * i);
    }

    spx_sha256_process_x86(state, in, full_bytes);

    for (i = 0; i < 8; ++i) {
        spx_store_be32(statebytes + 4 * i, state[i]);
    }

    return inlen - full_bytes;
#else
    (void)statebytes;
    (void)in;
    return inlen;
#endif
}

int spx_sha2_x86_hashblocks_sha512(unsigned char *statebytes, const unsigned char *in, unsigned long long inlen) {
#if defined(SPX_HAVE_SHA512_INTRINSICS)
    size_t full_bytes = (size_t)inlen & ~((size_t)127U);
    uint64_t state[8];
    size_t i;

    if (full_bytes == 0 || !spx_sha2_x86_can_use_sha512_ni()) {
        return (int)inlen;
    }

    for (i = 0; i < 8; ++i) {
        state[i] = spx_load_be64(statebytes + 8 * i);
    }

    spx_sha512_process_x86(state, in, full_bytes);

    for (i = 0; i < 8; ++i) {
        spx_store_be64(statebytes + 8 * i, state[i]);
    }

    return (int)(inlen - full_bytes);
#else
    (void)statebytes;
    (void)in;
    return (int)inlen;
#endif
}

#else

int spx_sha2_x86_can_use_sha256_ni(void) {
    return 0;
}

int spx_sha2_x86_can_use_sha512_ni(void) {
    return 0;
}

size_t spx_sha2_x86_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen) {
    (void)statebytes;
    (void)in;
    return inlen;
}

int spx_sha2_x86_hashblocks_sha512(unsigned char *statebytes, const unsigned char *in, unsigned long long inlen) {
    (void)statebytes;
    (void)in;
    return (int)inlen;
}

#endif
