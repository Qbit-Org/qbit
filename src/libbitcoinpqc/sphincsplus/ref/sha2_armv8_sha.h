#ifndef SPHINCSPLUS_REF_SHA2_ARMV8_SHA_H
#define SPHINCSPLUS_REF_SHA2_ARMV8_SHA_H

#include <stddef.h>
#include <stdint.h>

int spx_sha2_arm_can_use_sha256(void);
int spx_sha2_arm_can_use_sha512(void);

size_t spx_sha2_arm_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen);
int spx_sha2_arm_hashblocks_sha512(unsigned char *statebytes,
                                   const unsigned char *in,
                                   unsigned long long inlen);

#endif /* SPHINCSPLUS_REF_SHA2_ARMV8_SHA_H */
