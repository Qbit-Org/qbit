// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_CRYPTO_SHA256_H
#define QBIT_CRYPTO_SHA256_H

#include <cstdint>
#include <cstdlib>
#include <string>

/** A hasher class for SHA-256. */
class CSHA256
{
private:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes{0};

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    CSHA256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA256& Reset();
};

namespace sha256_implementation {
enum UseImplementation : uint8_t {
    STANDARD = 0,
    USE_SSE4 = 1 << 0,
    USE_AVX2 = 1 << 1,
    USE_SHANI = 1 << 2,
    USE_SSE4_AND_AVX2 = USE_SSE4 | USE_AVX2,
    USE_SSE4_AND_SHANI = USE_SSE4 | USE_SHANI,
    USE_ALL = USE_SSE4 | USE_AVX2 | USE_SHANI,
};

/** The x86 CPUID and XGETBV queries, as compat/cpuid.h's GetCPUID and XGetBV. */
using CpuidFn = void (*)(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
using XGetBVFn = uint64_t (*)(uint32_t index);
}

/** Autodetect the best available SHA256 implementation.
 *  Returns the name of the implementation.
 */
std::string SHA256AutoDetect(sha256_implementation::UseImplementation use_implementation = sha256_implementation::USE_ALL);

/** SHA256AutoDetect with the x86 CPUID and XGETBV queries answered by the
 *  given functions, so that tests can present synthetic CPUs; other targets
 *  ignore them. The selected code runs its self-test, so a synthetic CPU must
 *  not claim an extension this one lacks.
 */
std::string SHA256AutoDetect(sha256_implementation::UseImplementation use_implementation,
                             sha256_implementation::CpuidFn cpuid, sha256_implementation::XGetBVFn xgetbv);

/** Compute multiple double-SHA256's of 64-byte blobs.
 *  output:  pointer to a blocks*32 byte output buffer
 *  input:   pointer to a blocks*64 byte input buffer
 *  blocks:  the number of hashes to compute.
 */
void SHA256D64(unsigned char* output, const unsigned char* input, size_t blocks);

#endif // QBIT_CRYPTO_SHA256_H
