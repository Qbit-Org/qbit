#ifndef SPHINCSPLUS_REF_SHA2_X86_SHANI_H
#define SPHINCSPLUS_REF_SHA2_X86_SHANI_H

#include <stddef.h>
#include <stdint.h>

int spx_sha2_x86_can_use_sha256_ni(void);
int spx_sha2_x86_can_use_sha512_ni(void);

size_t spx_sha2_x86_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen);
int spx_sha2_x86_hashblocks_sha512(unsigned char *statebytes,
                                   const unsigned char *in,
                                   unsigned long long inlen);

#endif /* SPHINCSPLUS_REF_SHA2_X86_SHANI_H */
