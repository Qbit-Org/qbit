#include <stddef.h>
#include <stdint.h>

#include "opt_flags.h"
#include "sha2_armv8_sha.h"

#if defined(__linux__) && (defined(__aarch64__) || defined(__arm__))
#include <sys/auxv.h>
#if defined(__has_include)
#if __has_include(<asm/hwcap.h>)
#include <asm/hwcap.h>
#endif
#endif
#endif

#if (defined(__aarch64__) || defined(__arm__)) && defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#define SPX_ARM_SHA256_INTRINSICS 1
#else
#define SPX_ARM_SHA256_INTRINSICS 0
#endif

#if defined(__clang__) || defined(__GNUC__)
#define SPX_ARM_ATOMIC_LOAD(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define SPX_ARM_ATOMIC_STORE(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELAXED)
#else
#define SPX_ARM_ATOMIC_LOAD(ptr) (*(ptr))
#define SPX_ARM_ATOMIC_STORE(ptr, value) (*(ptr) = (value))
#endif

static uint32_t spx_load_be32(const uint8_t *x)
{
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
           (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

static void spx_store_be32(uint8_t *x, uint32_t u)
{
    x[0] = (uint8_t)(u >> 24);
    x[1] = (uint8_t)(u >> 16);
    x[2] = (uint8_t)(u >> 8);
    x[3] = (uint8_t)u;
}

#if SPX_ARM_SHA256_INTRINSICS
static const uint32_t spx_sha256_round_consts[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static uint32x4_t spx_load_be_u32x4(const uint8_t *in)
{
    return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(in)));
}

static void spx_sha256_process_arm(uint32_t state[8], const uint8_t *in, size_t inlen)
{
    uint32x4_t state0 = {state[0], state[1], state[2], state[3]};
    uint32x4_t state1 = {state[4], state[5], state[6], state[7]};

#define SPX_SHA256_ROUND4(MSG, OFFSET)                                  \
    do {                                                                 \
        uint32x4_t tmp = vaddq_u32((MSG), vld1q_u32(spx_sha256_round_consts + (OFFSET))); \
        state1 = vsha256hq_u32(state1, state0, tmp);                    \
        state0 = vsha256h2q_u32(state0, state1, tmp);                   \
    } while (0)

    while (inlen >= 64) {
        uint32x4_t saved0 = state0;
        uint32x4_t saved1 = state1;
        uint32x4_t msg0 = spx_load_be_u32x4(in + 0);
        uint32x4_t msg1 = spx_load_be_u32x4(in + 16);
        uint32x4_t msg2 = spx_load_be_u32x4(in + 32);
        uint32x4_t msg3 = spx_load_be_u32x4(in + 48);

        SPX_SHA256_ROUND4(msg0, 0);
        SPX_SHA256_ROUND4(msg1, 4);
        SPX_SHA256_ROUND4(msg2, 8);
        SPX_SHA256_ROUND4(msg3, 12);

        msg0 = vsha256su0q_u32(msg0, msg1);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);
        SPX_SHA256_ROUND4(msg0, 16);

        msg1 = vsha256su0q_u32(msg1, msg2);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);
        SPX_SHA256_ROUND4(msg1, 20);

        msg2 = vsha256su0q_u32(msg2, msg3);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);
        SPX_SHA256_ROUND4(msg2, 24);

        msg3 = vsha256su0q_u32(msg3, msg0);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);
        SPX_SHA256_ROUND4(msg3, 28);

        msg0 = vsha256su0q_u32(msg0, msg1);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);
        SPX_SHA256_ROUND4(msg0, 32);

        msg1 = vsha256su0q_u32(msg1, msg2);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);
        SPX_SHA256_ROUND4(msg1, 36);

        msg2 = vsha256su0q_u32(msg2, msg3);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);
        SPX_SHA256_ROUND4(msg2, 40);

        msg3 = vsha256su0q_u32(msg3, msg0);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);
        SPX_SHA256_ROUND4(msg3, 44);

        msg0 = vsha256su0q_u32(msg0, msg1);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);
        SPX_SHA256_ROUND4(msg0, 48);

        msg1 = vsha256su0q_u32(msg1, msg2);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);
        SPX_SHA256_ROUND4(msg1, 52);

        msg2 = vsha256su0q_u32(msg2, msg3);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);
        SPX_SHA256_ROUND4(msg2, 56);

        msg3 = vsha256su0q_u32(msg3, msg0);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);
        SPX_SHA256_ROUND4(msg3, 60);

        state0 = vaddq_u32(state0, saved0);
        state1 = vaddq_u32(state1, saved1);

        in += 64;
        inlen -= 64;
    }

#undef SPX_SHA256_ROUND4

    state[0] = vgetq_lane_u32(state0, 0);
    state[1] = vgetq_lane_u32(state0, 1);
    state[2] = vgetq_lane_u32(state0, 2);
    state[3] = vgetq_lane_u32(state0, 3);
    state[4] = vgetq_lane_u32(state1, 0);
    state[5] = vgetq_lane_u32(state1, 1);
    state[6] = vgetq_lane_u32(state1, 2);
    state[7] = vgetq_lane_u32(state1, 3);
}
#endif

static int spx_detect_arm_sha256_support(void)
{
#if defined(SPX_ENABLE_ARM_SHA)
#if SPX_ARM_SHA256_INTRINSICS
#if defined(__APPLE__)
    return 1;
#elif defined(__linux__) && defined(HWCAP_SHA2)
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#else
    return 1;
#endif
#else
    return 0;
#endif
#else
    return 0;
#endif
}

int spx_sha2_arm_can_use_sha256(void)
{
    /*
     * Keep ARM SHA-256 intrinsics backend disabled until the backend passes
     * differential/KAT validation across full input coverage.
     */
    (void)spx_detect_arm_sha256_support;
    return 0;
}

int spx_sha2_arm_can_use_sha512(void)
{
    return 0;
}

size_t spx_sha2_arm_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen)
{
#if defined(SPX_ENABLE_ARM_SHA)
#if SPX_ARM_SHA256_INTRINSICS
    uint32_t state[8];
    size_t i;
    size_t full_bytes = inlen & ~((size_t)63U);

    if (full_bytes == 0 || !spx_sha2_arm_can_use_sha256()) {
        return inlen;
    }

    for (i = 0; i < 8; ++i) {
        state[i] = spx_load_be32(statebytes + 4 * i);
    }

    spx_sha256_process_arm(state, in, full_bytes);

    for (i = 0; i < 8; ++i) {
        spx_store_be32(statebytes + 4 * i, state[i]);
    }

    return inlen - full_bytes;
#else
    (void)statebytes;
    (void)in;
    return inlen;
#endif
#else
    (void)statebytes;
    (void)in;
    return inlen;
#endif
}

int spx_sha2_arm_hashblocks_sha512(unsigned char *statebytes,
                                   const unsigned char *in,
                                   unsigned long long inlen)
{
    (void)statebytes;
    (void)in;
    return (int)inlen;
}
