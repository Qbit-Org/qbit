// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqc.h>

#include <crypto/common.h>
#include <crypto/hmac_sha256.h>
#include <hash.h>
#include <key.h>
#include <random.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace {

std::atomic<PQCSigningObserver*> g_signing_observer{nullptr};

constexpr size_t MAX_RAND_CHUNK_SIZE = 32;
constexpr std::string_view PQC_HKDF_INFO_PREFIX{"qbit/sphincs+/1"};
constexpr char PQC_HKDF_SALT[] = "qbit-sphincs-v1";

#if defined(__GNUC__)
#define PQC_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define PQC_NOINLINE __declspec(noinline)
#else
#error No known noinline attribute for this platform.
#endif

using SecretKeyBytes = std::array<unsigned char, PQC_SECKEY_SIZE>;
using PubKeyBytes = std::array<unsigned char, PQC_PUBKEY_SIZE>;

/**
 * libbitcoinpqc returns from SLH-DSA key generation, secret-key validation and
 * signing without clearing its stack frames, which hold secret-key material
 * (SK_SEED, SK_PRF and values derived from them). Key derivation also holds
 * the HD master seed and HMAC state in its own frame. Each of these operations
 * therefore runs in one of the non-inlined *Impl() functions below, and the
 * public function overwrites the stack it released with BurnReleasedStack()
 * once the Impl() function returns, on success and failure paths.
 *
 * The integrated build always compiles the library with optimization. Measured
 * by painting the stack (x86-64 GCC -O2), the library calls use at most
 * 12,232 bytes and the Impl() frames add less than 1 KiB, so
 * PQC_STACK_BURN_BYTES (32 KiB) is about 2.5 times the deepest use;
 * pqc_tests checks that the burn covers every byte the operations write. It is
 * kept small because the burn adds its frame to the deepest signing call
 * chain, and musl gives threads only 128 KiB of stack by default.
 */

//! Overwrite the stack released by the Impl() function that just returned.
//! Must not be inlined: the buffer has to occupy the frames below the caller
//! that the operation used.
PQC_NOINLINE void BurnReleasedStack()
{
    std::array<unsigned char, PQC_STACK_BURN_BYTES> scratch;
    memory_cleanse(scratch.data(), scratch.size());
}

PQC_NOINLINE int GenerateKeyImpl(SecretKeyBytes& seckey, PubKeyBytes& pubkey)
{
    std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE> random_data{};
    // The RNG backend extracts at most 32 bytes per call.
    for (size_t offset = 0; offset < random_data.size(); offset += MAX_RAND_CHUNK_SIZE) {
        const size_t chunk_size = std::min(MAX_RAND_CHUNK_SIZE, random_data.size() - offset);
        GetStrongRandBytes(std::span<unsigned char>{random_data}.subspan(offset, chunk_size));
    }

    const int keygen_ret = slh_dsa_keygen(pubkey.data(), seckey.data(), random_data.data(), random_data.size());
    memory_cleanse(random_data.data(), random_data.size());
    return keygen_ret;
}

PQC_NOINLINE int ValidateSecretKeyImpl(const unsigned char* seckey)
{
    return slh_dsa_secret_key_validate(seckey, PQC_SECKEY_SIZE);
}

PQC_NOINLINE int SignImpl(unsigned char* sig, size_t& siglen, const uint256& hash, const unsigned char* seckey)
{
    return slh_dsa_sign(sig, &siglen, hash.begin(), hash.size(), seckey);
}

PQC_NOINLINE bool DeriveKeyImpl(std::span<const unsigned char> master_seed, uint32_t account, uint32_t change, uint32_t index,
                                SecretKeyBytes& seckey, PubKeyBytes& pubkey)
{
    std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> prk{};
    CHMAC_SHA256(reinterpret_cast<const unsigned char*>(PQC_HKDF_SALT), strlen(PQC_HKDF_SALT))
        .Write(master_seed.data(), master_seed.size())
        .Finalize(prk.data());

    std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE> random_data{};
    std::array<unsigned char, PQC_HKDF_INFO_PREFIX.size() + 12> info{};
    std::copy(PQC_HKDF_INFO_PREFIX.begin(), PQC_HKDF_INFO_PREFIX.end(), info.begin());
    WriteLE32(info.data() + PQC_HKDF_INFO_PREFIX.size(), account);
    WriteLE32(info.data() + PQC_HKDF_INFO_PREFIX.size() + 4, change);
    WriteLE32(info.data() + PQC_HKDF_INFO_PREFIX.size() + 8, index);

    std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> block{};
    std::array<unsigned char, CHMAC_SHA256::OUTPUT_SIZE> previous{};
    size_t previous_size = 0;
    size_t offset = 0;
    uint8_t counter = 1;
    while (offset < random_data.size()) {
        CHMAC_SHA256 hmac(prk.data(), prk.size());
        if (previous_size > 0) {
            hmac.Write(previous.data(), previous_size);
        }
        hmac.Write(info.data(), info.size()).Write(&counter, 1).Finalize(block.data());

        const size_t copy_size = std::min(block.size(), random_data.size() - offset);
        std::copy_n(block.data(), copy_size, random_data.data() + offset);
        offset += copy_size;
        previous = block;
        previous_size = block.size();

        if (counter == std::numeric_limits<uint8_t>::max() && offset < random_data.size()) {
            memory_cleanse(prk.data(), prk.size());
            memory_cleanse(random_data.data(), random_data.size());
            memory_cleanse(block.data(), block.size());
            memory_cleanse(previous.data(), previous.size());
            return false;
        }
        ++counter;
    }

    const int keygen_ret = slh_dsa_keygen(pubkey.data(), seckey.data(), random_data.data(), random_data.size());
    memory_cleanse(prk.data(), prk.size());
    memory_cleanse(random_data.data(), random_data.size());
    memory_cleanse(block.data(), block.size());
    memory_cleanse(previous.data(), previous.size());
    return keygen_ret == 0;
}
} // namespace

ScopedPQCSigningObserver::ScopedPQCSigningObserver(PQCSigningObserver& observer)
{
    PQCSigningObserver* expected{nullptr};
    if (!g_signing_observer.compare_exchange_strong(expected, &observer)) {
        throw std::logic_error("A PQC signing observer is already installed");
    }
}

ScopedPQCSigningObserver::~ScopedPQCSigningObserver()
{
    g_signing_observer.store(nullptr);
}

CPQCKey& CPQCKey::operator=(const CPQCKey& other)
{
    if (this != &other) {
        if (other.m_keydata) {
            MakeKeyData();
            *m_keydata = *other.m_keydata;
            m_pubkey = other.m_pubkey;
            m_pubkey_valid = other.m_pubkey_valid;
        } else {
            ClearKeyData();
        }
    }
    return *this;
}

void CPQCKey::MakeNewKey()
{
    MakeKeyData();

    std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey{};
    const int keygen_ret = GenerateKeyImpl(*m_keydata, pubkey);
    BurnReleasedStack();
    if (keygen_ret != 0) {
        ClearKeyData();
        return;
    }

    m_pubkey = pubkey;
    m_pubkey_valid = true;
}

void CPQCKey::SetFromTrustedKeyMaterial(std::span<const unsigned char> secret_key, std::span<const unsigned char> public_key)
{
    if (secret_key.size() != SIZE || public_key.size() != PQC_PUBKEY_SIZE ||
        secret_key.data() == nullptr || public_key.data() == nullptr ||
        !std::equal(public_key.begin(), public_key.end(), secret_key.end() - PQC_PUBKEY_SIZE)) {
        ClearKeyData();
        return;
    }

    MakeKeyData();
    std::memcpy(m_keydata->data(), secret_key.data(), SIZE);
    std::memcpy(m_pubkey.data(), public_key.data(), PQC_PUBKEY_SIZE);
    m_pubkey_valid = true;
}

void CPQCKey::SetFromTrustedWalletRecord(std::span<const unsigned char> secret_key, const CPQCPubKey& public_key)
{
    if (!public_key.IsValid()) {
        ClearKeyData();
        return;
    }

    SetFromTrustedKeyMaterial(secret_key, std::span<const unsigned char>{public_key.data(), public_key.size()});
}

void CPQCKey::Set(const unsigned char* begin, const unsigned char* end)
{
    if (!begin || !end || static_cast<size_t>(end - begin) != SIZE) {
        ClearKeyData();
        return;
    }
    const int validate_ret = ValidateSecretKeyImpl(begin);
    BurnReleasedStack();
    if (validate_ret != 0) {
        ClearKeyData();
        return;
    }

    MakeKeyData();
    std::memcpy(m_keydata->data(), begin, SIZE);

    // SLH-DSA sk format is [SK_SEED || SK_PRF || PUB_SEED || root], while
    // pk is [PUB_SEED || root]. Copy the tail of sk to recover pk.
    std::memcpy(m_pubkey.data(), m_keydata->data() + (SIZE - PQC_PUBKEY_SIZE), PQC_PUBKEY_SIZE);
    m_pubkey_valid = true;
}

bool CPQCKey::Sign(const uint256& hash, std::vector<unsigned char>& sig, uint32_t& counter_inout) const
{
    PQCSigningObserver* const observer{g_signing_observer.load()};
    const uint64_t call{observer ? observer->BeforeSign(GetPubKey(), counter_inout) : 0};
    const auto finish = [&](bool success) {
        if (observer) observer->AfterSign(call, success);
        return success;
    };
    if (!IsValid() || counter_inout >= PQC_MAX_SIGNATURES) return finish(false);

    std::vector<unsigned char> candidate_sig(PQC_SIG_SIZE);
    size_t siglen = candidate_sig.size();
    const int sign_ret = SignImpl(candidate_sig.data(), siglen, hash, m_keydata->data());
    BurnReleasedStack();
    if (sign_ret != 0 || siglen != PQC_SIG_SIZE) {
        memory_cleanse(candidate_sig.data(), candidate_sig.size());
        return finish(false);
    }

    sig = std::move(candidate_sig);
    ++counter_inout;
    return finish(true);
}

CPQCPubKey CPQCKey::GetPubKey() const
{
    if (!IsValid()) return {};
    return CPQCPubKey(std::span<const unsigned char>{m_pubkey.data(), m_pubkey.size()});
}

bool operator==(const CPQCKey& a, const CPQCKey& b)
{
    if (a.size() != b.size()) return false;
    if (a.size() == 0) return true;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

bool DerivePQCKey(std::span<const unsigned char> master_seed, uint32_t account, uint32_t change, uint32_t index, CPQCKey& key_out)
{
    if (master_seed.empty()) return false;

    std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey{};
    SecretKeyBytes seckey{};
    const bool derived{DeriveKeyImpl(master_seed, account, change, index, seckey, pubkey)};
    if (derived) {
        key_out.SetFromTrustedKeyMaterial(
            std::span<const unsigned char>{seckey.data(), seckey.size()},
            std::span<const unsigned char>{pubkey.data(), pubkey.size()});
    }
    memory_cleanse(seckey.data(), seckey.size());
    BurnReleasedStack();

    return derived && key_out.IsValid() && key_out.GetPubKey() == CPQCPubKey(std::span<const unsigned char>{pubkey.data(), pubkey.size()});
}

bool DerivePQCKey(const CKey& master_seed, uint32_t account, uint32_t change, uint32_t index, CPQCKey& key_out)
{
    const auto* seed_ptr = reinterpret_cast<const unsigned char*>(master_seed.begin());
    return DerivePQCKey(std::span<const unsigned char>{seed_ptr, master_seed.size()}, account, change, index, key_out);
}
