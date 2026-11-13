#ifndef SPX_SHA2_H
#define SPX_SHA2_H

#include "params.h"

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#define SPX_SHA512_BLOCK_BYTES 128
#define SPX_SHA512_OUTPUT_BYTES 64

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
    #error Linking against SHA-256 with N larger than 32 bytes is not supported
#endif

#define SPX_SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>

void sha256_inc_init(uint8_t *state);
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

void sha512_inc_init(uint8_t *state);
void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha512_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha512(uint8_t *out, const uint8_t *in, size_t inlen);

#if defined(BITCOINPQC_ENABLE_TEST_HELPERS)
enum spx_sha2_impl_id {
    SPX_SHA2_IMPL_UNINITIALIZED = 0,
    SPX_SHA2_IMPL_SCALAR = 1,
    SPX_SHA2_IMPL_X86_SHA_NI = 2,
    SPX_SHA2_IMPL_ARM_SHA = 3,
    SPX_SHA2_IMPL_COMMONCRYPTO = 4,
    SPX_SHA2_IMPL_UNKNOWN = 5
};

/* Passively observe the cached implementation without initializing it. */
int spx_sha2_test_sha256_impl(void);
int spx_sha2_test_sha512_impl(void);
#endif

#define mgf1_256 SPX_NAMESPACE(mgf1_256)
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define mgf1_512 SPX_NAMESPACE(mgf1_512)
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define seed_state SPX_NAMESPACE(seed_state)
void seed_state(spx_ctx *ctx);


#endif
