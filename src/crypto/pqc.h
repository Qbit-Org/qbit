// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_CRYPTO_PQC_H
#define QBIT_CRYPTO_PQC_H

#include <libbitcoinpqc/slh_dsa.h>
#include <pubkey.h>
#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

// Bounded SLH-DSA-SHA2-128s (h=30) constants from libbitcoinpqc.
constexpr size_t PQC_PUBKEY_SIZE = SLH_DSA_PUBLIC_KEY_SIZE;
constexpr size_t PQC_SIG_SIZE = SLH_DSA_SIGNATURE_SIZE;
constexpr size_t PQC_SECKEY_SIZE = SLH_DSA_SECRET_KEY_SIZE;
constexpr size_t PQC_KEYGEN_RANDOM_DATA_SIZE = SLH_DSA_KEYGEN_RANDOM_DATA_MIN_SIZE;
static_assert(PQC_PUBKEY_SIZE == SLH_DSA_SHA2_128S_BOUNDED30_PUBLIC_KEY_SIZE);
static_assert(PQC_SIG_SIZE == SLH_DSA_SHA2_128S_BOUNDED30_SIGNATURE_SIZE);
static_assert(PQC_SECKEY_SIZE == SLH_DSA_SHA2_128S_BOUNDED30_SECRET_KEY_SIZE);
static_assert(PQC_KEYGEN_RANDOM_DATA_SIZE >= 128);

// SLH-DSA-SHA2-128s-bounded30 usage bound.
constexpr uint32_t PQC_MAX_SIGNATURES = 1U << 30;

class CPQCPubKey
{
public:
    static constexpr unsigned int SIZE = PQC_PUBKEY_SIZE;

private:
    std::array<unsigned char, SIZE> m_data{};
    bool m_valid{false};

public:
    CPQCPubKey() = default;
    explicit CPQCPubKey(std::span<const unsigned char> data)
    {
        if (data.size() != SIZE) return;
        std::memcpy(m_data.data(), data.data(), SIZE);
        m_valid = true;
    }

    bool IsValid() const { return m_valid; }
    bool Verify(const uint256& hash, std::span<const unsigned char> sig) const
    {
        if (!m_valid || sig.size() != PQC_SIG_SIZE) return false;
        return slh_dsa_verify(sig.data(), sig.size(), hash.begin(), hash.size(), m_data.data()) == 0;
    }
    CKeyID GetID() const
    {
        if (!m_valid) return {};
        return CKeyID(Hash160(std::span{m_data}));
    }

    unsigned int size() const { return m_valid ? SIZE : 0; }
    const unsigned char* data() const { return m_data.data(); }
    const unsigned char* begin() const { return data(); }
    const unsigned char* end() const { return data() + size(); }

    friend bool operator==(const CPQCPubKey& a, const CPQCPubKey& b)
    {
        return a.m_valid == b.m_valid && a.m_data == b.m_data;
    }
    friend bool operator<(const CPQCPubKey& a, const CPQCPubKey& b)
    {
        if (a.m_valid != b.m_valid) return a.m_valid < b.m_valid;
        return a.m_data < b.m_data;
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const unsigned int len = size();
        ::WriteCompactSize(s, len);
        if (len != 0) {
            s << std::span{m_data}.first(len);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const unsigned int len(::ReadCompactSize(s));
        if (len <= SIZE) {
            std::array<unsigned char, SIZE> data{};
            if (len != 0) {
                s >> std::span{data}.first(len);
            }
            if (len == SIZE) {
                m_data = data;
                m_valid = true;
            } else {
                m_data.fill(0);
                m_valid = false;
            }
        } else {
            s.ignore(len);
            m_data.fill(0);
            m_valid = false;
        }
    }
};

class CPQCKey
{
public:
    static constexpr unsigned int SIZE = PQC_SECKEY_SIZE;

private:
    using KeyType = std::array<unsigned char, SIZE>;

    secure_unique_ptr<KeyType> m_keydata;
    std::array<unsigned char, PQC_PUBKEY_SIZE> m_pubkey{};
    bool m_pubkey_valid{false};

    void MakeKeyData()
    {
        if (!m_keydata) m_keydata = make_secure_unique<KeyType>();
    }

    void ClearKeyData()
    {
        m_keydata.reset();
        m_pubkey.fill(0);
        m_pubkey_valid = false;
    }

    void SetFromTrustedKeyMaterial(std::span<const unsigned char> secret_key, std::span<const unsigned char> public_key);

    friend bool DerivePQCKey(std::span<const unsigned char> master_seed, uint32_t account, uint32_t change, uint32_t index, CPQCKey& key_out);

public:
    CPQCKey() noexcept = default;
    CPQCKey(CPQCKey&&) noexcept = default;
    CPQCKey& operator=(CPQCKey&&) noexcept = default;

    CPQCKey(const CPQCKey& other) { *this = other; }

    CPQCKey& operator=(const CPQCKey& other);

    bool IsValid() const { return m_keydata && m_pubkey_valid; }
    unsigned int size() const { return m_keydata ? SIZE : 0; }
    const unsigned char* data() const { return m_keydata ? m_keydata->data() : nullptr; }

    void MakeNewKey();
    void Set(const unsigned char* begin, const unsigned char* end);
    //! Restore key material that was already authenticated by wallet persistence.
    //! This skips the expensive SLH-DSA root recomputation; use Set() for untrusted imports.
    void SetFromTrustedWalletRecord(std::span<const unsigned char> secret_key, const CPQCPubKey& public_key);

    bool Sign(const uint256& hash, std::vector<unsigned char>& sig, uint32_t& counter_inout) const;
    CPQCPubKey GetPubKey() const;

    friend bool operator==(const CPQCKey& a, const CPQCKey& b);
};

class CKey;
bool DerivePQCKey(std::span<const unsigned char> master_seed, uint32_t account, uint32_t change, uint32_t index, CPQCKey& key_out);
bool DerivePQCKey(const CKey& master_seed, uint32_t account, uint32_t change, uint32_t index, CPQCKey& key_out);

#endif // QBIT_CRYPTO_PQC_H
