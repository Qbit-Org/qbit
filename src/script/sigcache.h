// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_SIGCACHE_H
#define QBIT_SCRIPT_SIGCACHE_H

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <cuckoocache.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>
#include <util/hasher.h>

#include <atomic>
#include <cstddef>
#include <shared_mutex>
#include <vector>

class CPQCPubKey;
class CPubKey;
class CTransaction;
class XOnlyPubKey;

// DoS prevention: limit cache size to 32MiB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MiB)
static constexpr size_t DEFAULT_VALIDATION_CACHE_BYTES{32 << 20};
static constexpr size_t DEFAULT_SIGNATURE_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static constexpr size_t DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static_assert(DEFAULT_VALIDATION_CACHE_BYTES == DEFAULT_SIGNATURE_CACHE_BYTES + DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES);

/**
 * Test-only observer of PQC transaction-signature cache activity. Production
 * code never installs one; it must not influence validation results.
 */
class PQCSignatureCacheObserver
{
public:
    virtual ~PQCSignatureCacheObserver() = default;
    //! Called once per PQC transaction-signature cache lookup.
    virtual void Lookup(bool hit, bool erase) = 0;
    //! Called once per primitive PQC verification performed after a cache miss.
    virtual void Verified(bool valid, bool inserted) = 0;
};

/**
 * Valid signature cache, to avoid doing expensive ECDSA, Schnorr and PQC
 * signature checking twice for every transaction (once when accepted into
 * memory pool, and again when accepted into the block chain)
 */
class SignatureCache
{
private:
    //! Entries are SHA256(nonce || 'E', 'S' or 'P' || 31 zero bytes || signature hash || public key || signature):
    CSHA256 m_salted_hasher_ecdsa;
    CSHA256 m_salted_hasher_schnorr;
    CSHA256 m_salted_hasher_pqc;
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;
    std::shared_mutex cs_sigcache;
    std::atomic<PQCSignatureCacheObserver*> m_pqc_observer{nullptr};

public:
    SignatureCache(size_t max_size_bytes);

    SignatureCache(const SignatureCache&) = delete;
    SignatureCache& operator=(const SignatureCache&) = delete;

    void ComputeEntryECDSA(uint256& entry, const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey) const;

    void ComputeEntrySchnorr(uint256& entry, const uint256 &hash, std::span<const unsigned char> sig, const XOnlyPubKey& pubkey) const;

    void ComputeEntryPQC(uint256& entry, const uint256& hash, std::span<const unsigned char> sig, const CPQCPubKey& pubkey) const;

    bool Get(const uint256& entry, const bool erase);

    void Set(const uint256& entry);

    //! Test-only. Production code never installs an observer.
    void SetPQCObserverForTesting(PQCSignatureCacheObserver* observer) { m_pqc_observer.store(observer); }
    PQCSignatureCacheObserver* GetPQCObserver() const { return m_pqc_observer.load(std::memory_order_relaxed); }
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    bool store;
    SignatureCache& m_signature_cache;

public:
    CachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn, SignatureCache& signature_cache, PrecomputedTransactionData& txdataIn) : TransactionSignatureChecker(txToIn, nInIn, amountIn, txdataIn, MissingDataBehavior::ASSERT_FAIL), store(storeIn), m_signature_cache(signature_cache)  {}

    bool VerifyECDSASignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const override;
    bool VerifySchnorrSignature(std::span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const override;
    bool VerifyPQCSignature(std::span<const unsigned char> sig, const CPQCPubKey& pubkey, const uint256& sighash) const override;
};

#endif // QBIT_SCRIPT_SIGCACHE_H
