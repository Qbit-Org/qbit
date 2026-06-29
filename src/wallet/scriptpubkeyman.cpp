// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <crypto/common.h>
#include <crypto/hmac_sha256.h>
#include <node/types.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/p2mr.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>

#include <algorithm>
#include <array>
#include <exception>
#include <optional>
#include <set>
#include <span>
#include <string_view>

using common::PSBTError;
using util::ToString;

namespace wallet {

typedef std::vector<unsigned char> valtype;

// Legacy wallet IsMine(). Used only in migration
// DO NOT USE ANYTHING IN THIS NAMESPACE OUTSIDE OF MIGRATION
namespace {

uint256 GetPQCKeyIV(const CPQCPubKey& pubkey)
{
    return Hash(std::span{pubkey.data(), pubkey.size()});
}

uint256 GetCryptedPQCKeyAuthTag(const CKeyingMaterial& master_key, const uint256& desc_id, const CPQCPubKey& pubkey, std::span<const unsigned char> secret, uint32_t sig_counter)
{
    static constexpr std::string_view PQC_CKEY_AUTH_DOMAIN{"qbit wallet pqc ckey v1"};
    std::array<unsigned char, sizeof(sig_counter)> counter_bytes{};
    WriteLE32(counter_bytes.data(), sig_counter);

    uint256 out;
    CHMAC_SHA256(master_key.data(), master_key.size())
        .Write(UCharCast(PQC_CKEY_AUTH_DOMAIN.data()), PQC_CKEY_AUTH_DOMAIN.size())
        .Write(desc_id.data(), desc_id.size())
        .Write(pubkey.data(), pubkey.size())
        .Write(secret.data(), secret.size())
        .Write(counter_bytes.data(), counter_bytes.size())
        .Finalize(out.data());
    return out;
}

bool DecryptPQCKey(const CKeyingMaterial& master_key, const uint256& desc_id, const CryptedPQCKeyRecord& crypted_key, const CPQCPubKey& pubkey, uint32_t sig_counter, CPQCKey& key, std::optional<uint256>* legacy_auth_tag_out = nullptr)
{
    if (legacy_auth_tag_out) legacy_auth_tag_out->reset();

    CKeyingMaterial secret;
    if (!DecryptSecret(master_key, crypted_key.crypted_secret, GetPQCKeyIV(pubkey), secret)) {
        return false;
    }
    if (secret.size() != CPQCKey::SIZE) {
        return false;
    }

    const auto secret_span{std::span<const unsigned char>{secret.data(), secret.size()}};
    const uint256 auth_tag{GetCryptedPQCKeyAuthTag(master_key, desc_id, pubkey, secret_span, sig_counter)};
    if (crypted_key.auth_tag) {
        if (auth_tag != *crypted_key.auth_tag) {
            return false;
        }
        key.SetFromTrustedWalletRecord(secret_span, pubkey);
    } else {
        key.Set(secret.data(), secret.data() + secret.size());
    }

    const bool valid{key.IsValid() && key.GetPubKey() == pubkey};
    if (valid && legacy_auth_tag_out && !crypted_key.auth_tag) {
        *legacy_auth_tag_out = auth_tag;
    }
    return valid;
}

} // namespace

std::vector<CPQCPubKey> ExtractP2MRPubkeys(const CScript& script)
{
    std::vector<CPQCPubKey> pubkeys;
    if (auto multi_a = p2mr::MatchMultiA(script)) {
        pubkeys.reserve(multi_a->keyspans.size());
        for (const auto& keyspan : multi_a->keyspans) {
            CPQCPubKey pubkey{keyspan};
            if (pubkey.IsValid()) {
                pubkeys.push_back(pubkey);
            }
        }
        return pubkeys;
    }

    if (script.size() == 34 && script[0] == 32 && script[33] == OP_CHECKSIGPQC) {
        CPQCPubKey pubkey{std::span<const unsigned char>{script}.subspan(1, CPQCPubKey::SIZE)};
        if (pubkey.IsValid()) {
            pubkeys.push_back(pubkey);
        }
    }

    return pubkeys;
}

namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion
{
    TOP = 0,        //!< scriptPubKey execution
    P2SH = 1,       //!< P2SH redeemScript
    WITNESS_V0 = 2, //!< P2WSH witness script execution
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult
{
    NO = 0,         //!< Not ours
    WATCH_ONLY = 1, //!< Included in watch-only balance
    SPENDABLE = 2,  //!< Included in all balances
    INVALID = 3,    //!< Not spendable by anyone (uncompressed pubkey in segwit, P2SH inside P2SH or witness, witness inside witness)
};

bool PermitsUncompressed(IsMineSigVersion sigversion)
{
    return sigversion == IsMineSigVersion::TOP || sigversion == IsMineSigVersion::P2SH;
}

bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyDataSPKM& keystore)
{
    for (const valtype& pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) return false;
    }
    return true;
}

bool ShouldDeferCreateKeyPoolTopUp(const WalletDescriptor& descriptor, int64_t keypool_size)
{
    if (descriptor.deferred_create_keypool_top_up.has_value()) {
        return *descriptor.deferred_create_keypool_top_up;
    }

    if (!descriptor.descriptor || !descriptor.descriptor->IsSingleType() || !descriptor.descriptor->IsRange()) {
        return false;
    }
    const auto output_type = descriptor.descriptor->GetOutputType();
    return output_type && *output_type == OutputType::P2MR &&
           descriptor.range_end < descriptor.next_index + keypool_size;
}

//! Recursively solve script and return spendable/watchonly/invalid status.
//!
//! @param keystore            legacy key and script store
//! @param scriptPubKey        script to solve
//! @param sigversion          script type (top-level / redeemscript / witnessscript)
//! @param recurse_scripthash  whether to recurse into nested p2sh and p2wsh
//!                            scripts or simply treat any script that has been
//!                            stored in the keystore as spendable
// NOLINTNEXTLINE(misc-no-recursion)
IsMineResult LegacyWalletIsMineInnerDONOTUSE(const LegacyDataSPKM& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion, bool recurse_scripthash=true)
{
    IsMineResult ret = IsMineResult::NO;

    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    CKeyID keyID;
    switch (whichType) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
    case TxoutType::WITNESS_V1_TAPROOT:
    case TxoutType::WITNESS_V2_P2MR:
    case TxoutType::ANCHOR:
        break;
    case TxoutType::PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (!PermitsUncompressed(sigversion) && vSolutions[0].size() != 33) {
            return IsMineResult::INVALID;
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::WITNESS_V0_KEYHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WPKH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        ret = std::max(ret, LegacyWalletIsMineInnerDONOTUSE(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
        break;
    }
    case TxoutType::PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!PermitsUncompressed(sigversion)) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                return IsMineResult::INVALID;
            }
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::SCRIPTHASH:
    {
        if (sigversion != IsMineSigVersion::TOP) {
            // P2SH inside P2WSH or P2SH is invalid.
            return IsMineResult::INVALID;
        }
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::P2SH) : IsMineResult::SPENDABLE);
        }
        break;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WSH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        CScriptID scriptID{RIPEMD160(vSolutions[0])};
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::WITNESS_V0) : IsMineResult::SPENDABLE);
        }
        break;
    }

    case TxoutType::MULTISIG:
    {
        // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
        if (sigversion == IsMineSigVersion::TOP) {
            break;
        }

        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (!PermitsUncompressed(sigversion)) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    return IsMineResult::INVALID;
                }
            }
        }
        if (HaveKeys(keys, keystore)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    } // no default case, so the compiler can warn about missing cases

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

DescriptorScriptPubKeyMan::DescriptorScriptPubKeyMan(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size)
    : ScriptPubKeyMan(storage),
      m_keypool_size(keypool_size),
      m_wallet_descriptor(descriptor)
{
}

DescriptorScriptPubKeyMan::DescriptorScriptPubKeyMan(WalletStorage& storage, int64_t keypool_size)
    : ScriptPubKeyMan(storage),
      m_keypool_size(keypool_size)
{
}

bool LegacyDataSPKM::IsMine(const CScript& script) const
{
    switch (LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return false;
    case IsMineResult::WATCH_ONLY:
    case IsMineResult::SPENDABLE:
        return true;
    }
    assert(false);
}

bool LegacyDataSPKM::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    {
        LOCK(cs_KeyStore);
        assert(mapKeys.empty());

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        WalletBatch batch(m_storage.GetDatabase());
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(master_key, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
            else {
                // Rewrite these encrypted keys with checksums
                batch.WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
            }
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || !keyPass)
            return false;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

std::unique_ptr<SigningProvider> LegacyDataSPKM::GetSolvingProvider(const CScript& script) const
{
    return std::make_unique<LegacySigningProvider>(*this);
}

bool LegacyDataSPKM::CanProvide(const CScript& script, SignatureData& sigdata)
{
    IsMineResult ismine = LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP, /* recurse_scripthash= */ false);
    if (ismine == IsMineResult::SPENDABLE || ismine == IsMineResult::WATCH_ONLY) {
        // If ismine, it means we recognize keys or script ids in the script, or
        // are watching the script itself, and we can at least provide metadata
        // or solving information, even if not able to sign fully.
        return true;
    } else {
        // If, given the stuff in sigdata, we could make a valid signature, then we can provide for this script
        ProduceSignature(*this, DUMMY_SIGNATURE_CREATOR, script, sigdata);
        if (!sigdata.signatures.empty()) {
            // If we could make signatures, make sure we have a private key to actually make a signature
            bool has_privkeys = false;
            for (const auto& key_sig_pair : sigdata.signatures) {
                has_privkeys |= HaveKey(key_sig_pair.first);
            }
            return has_privkeys;
        }
        return false;
    }
}

bool LegacyDataSPKM::LoadKey(const CKey& key, const CPubKey &pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool LegacyDataSPKM::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}

void LegacyDataSPKM::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    mapKeyMetadata[keyID] = meta;
}

void LegacyDataSPKM::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    m_script_metadata[script_id] = meta;
}

bool LegacyDataSPKM::AddKeyPubKeyInner(const CKey& key, const CPubKey& pubkey)
{
    LOCK(cs_KeyStore);
    return FillableSigningProvider::AddKeyPubKey(key, pubkey);
}

bool LegacyDataSPKM::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyDataSPKM::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapKeys.empty());

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyDataSPKM::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool LegacyDataSPKM::LoadWatchOnly(const CScript &dest)
{
    return AddWatchOnlyInMem(dest);
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    std::vector<std::vector<unsigned char>> solutions;
    return Solver(dest, solutions) == TxoutType::PUBKEY &&
        (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
}

bool LegacyDataSPKM::AddWatchOnlyInMem(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

void LegacyDataSPKM::LoadHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    m_hd_chain = chain;
}

void LegacyDataSPKM::AddInactiveHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    assert(!chain.seed_id.IsNull());
    m_inactive_hd_chains[chain.seed_id] = chain;
}

bool LegacyDataSPKM::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool LegacyDataSPKM::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, vchCryptedSecret, vchPubKey, keyOut);
        });
    }
    return false;
}

bool LegacyDataSPKM::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    CKeyMetadata meta;
    {
        LOCK(cs_KeyStore);
        auto it = mapKeyMetadata.find(keyID);
        if (it == mapKeyMetadata.end()) {
            return false;
        }
        meta = it->second;
    }
    if (meta.has_key_origin) {
        std::copy(meta.key_origin.fingerprint, meta.key_origin.fingerprint + 4, info.fingerprint);
        info.path = meta.key_origin.path;
    } else { // Single pubkeys get the master fingerprint of themselves
        std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    }
    return true;
}

bool LegacyDataSPKM::GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const
{
    LOCK(cs_KeyStore);
    WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    if (it != mapWatchKeys.end()) {
        pubkey_out = it->second;
        return true;
    }
    return false;
}

bool LegacyDataSPKM::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        if (!FillableSigningProvider::GetPubKey(address, vchPubKeyOut)) {
            return GetWatchPubKey(address, vchPubKeyOut);
        }
        return true;
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return GetWatchPubKey(address, vchPubKeyOut);
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetCandidateScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> candidate_spks;

    // For every private key in the wallet, there should be a P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH
    const auto& add_pubkey = [&candidate_spks](const CPubKey& pub) -> void {
        candidate_spks.insert(GetScriptForRawPubKey(pub));
        candidate_spks.insert(GetScriptForDestination(PKHash(pub)));

        CScript wpkh = GetScriptForDestination(WitnessV0KeyHash(pub));
        candidate_spks.insert(wpkh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wpkh)));
    };
    for (const auto& [_, key] : mapKeys) {
        add_pubkey(key.GetPubKey());
    }
    for (const auto& [_, ckeypair] : mapCryptedKeys) {
        add_pubkey(ckeypair.first);
    }

    // mapScripts contains all redeemScripts and witnessScripts. Therefore each script in it has
    // itself, P2SH, P2WSH, and P2SH-P2WSH as a candidate.
    // Invalid scripts such as P2SH-P2SH and P2WSH-P2SH, among others, will be added as candidates.
    // Callers of this function will need to remove such scripts.
    const auto& add_script = [&candidate_spks](const CScript& script) -> void {
        candidate_spks.insert(script);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(script)));

        CScript wsh = GetScriptForDestination(WitnessV0ScriptHash(script));
        candidate_spks.insert(wsh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wsh)));
    };
    for (const auto& [_, script] : mapScripts) {
        add_script(script);
    }

    // Although setWatchOnly should only contain output scripts, we will also include each script's
    // P2SH, P2WSH, and P2SH-P2WSH as a precaution.
    for (const auto& script : setWatchOnly) {
        add_script(script);
    }

    return candidate_spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetScriptPubKeys() const
{
    // Run IsMine() on each candidate output script. Any script that IsMine is an output
    // script to return.
    // This both filters out things that are not watched by the wallet, and things that are invalid.
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        if (IsMine(script)) {
            spks.insert(script);
        }
    }

    return spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetNotMineScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : setWatchOnly) {
        if (!IsMine(script)) spks.insert(script);
    }
    return spks;
}

std::optional<MigrationData> LegacyDataSPKM::MigrateToDescriptor()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked()) {
        return std::nullopt;
    }

    MigrationData out;

    std::unordered_set<CScript, SaltedSipHasher> spks{GetScriptPubKeys()};

    // Get all key ids
    std::set<CKeyID> keyids;
    for (const auto& key_pair : mapKeys) {
        keyids.insert(key_pair.first);
    }
    for (const auto& key_pair : mapCryptedKeys) {
        keyids.insert(key_pair.first);
    }

    // Get key metadata and figure out which keys don't have a seed
    // Note that we do not ignore the seeds themselves because they are considered IsMine!
    for (auto keyid_it = keyids.begin(); keyid_it != keyids.end();) {
        const CKeyID& keyid = *keyid_it;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            const CKeyMetadata& meta = it->second;
            if (meta.hdKeypath == "s" || meta.hdKeypath == "m") {
                keyid_it++;
                continue;
            }
            if (!meta.hd_seed_id.IsNull() && (m_hd_chain.seed_id == meta.hd_seed_id || m_inactive_hd_chains.count(meta.hd_seed_id) > 0)) {
                keyid_it = keyids.erase(keyid_it);
                continue;
            }
        }
        keyid_it++;
    }

    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) {
        LogPrintf("Error generating descriptors for migration, cannot initialize db transaction\n");
        return std::nullopt;
    }

    // keyids is now all non-HD keys. Each key will have its own combo descriptor
    for (const CKeyID& keyid : keyids) {
        CKey key;
        if (!GetKey(keyid, key)) {
            assert(false);
        }

        // Get birthdate from key meta
        uint64_t creation_time = 0;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // Get the key origin
        // Maybe this doesn't matter because floating keys here shouldn't have origins
        KeyOriginInfo info;
        bool has_info = GetKeyOrigin(keyid, info);
        std::string origin_str = has_info ? "[" + HexStr(info.fingerprint) + FormatHDKeypath(info.path) + "]" : "";

        // Construct the combo descriptor
        std::string desc_str = "combo(" + origin_str + HexStr(key.GetPubKey()) + ")";
        FlatSigningProvider keys;
        std::string error;
        std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
        CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
        WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);

        // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
        auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
        WITH_LOCK(desc_spk_man->cs_desc_man, desc_spk_man->AddDescriptorKeyWithDB(batch, key, key.GetPubKey()));
        desc_spk_man->TopUpWithDB(batch);
        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        // Remove the scriptPubKeys from our current set
        for (const CScript& spk : desc_spks) {
            size_t erased = spks.erase(spk);
            assert(erased == 1);
            assert(IsMine(spk));
        }

        out.desc_spkms.push_back(std::move(desc_spk_man));
    }

    // Handle HD keys by using the CHDChains
    std::vector<CHDChain> chains;
    chains.push_back(m_hd_chain);
    for (const auto& chain_pair : m_inactive_hd_chains) {
        chains.push_back(chain_pair.second);
    }

    bool can_support_hd_split_feature = m_hd_chain.nVersion >= CHDChain::VERSION_HD_CHAIN_SPLIT;

    for (const CHDChain& chain : chains) {
        for (int i = 0; i < 2; ++i) {
            // Skip if doing internal chain and split chain is not supported
            if (chain.seed_id.IsNull() || (i == 1 && !can_support_hd_split_feature)) {
                continue;
            }
            // Get the master xprv
            CKey seed_key;
            if (!GetKey(chain.seed_id, seed_key)) {
                assert(false);
            }
            CExtKey master_key;
            master_key.SetSeed(seed_key);

            // Make the combo descriptor
            std::string xpub = EncodeExtPubKey(master_key.Neuter());
            std::string desc_str = "combo(" + xpub + "/0h/" + ToString(i) + "h/*h)";
            FlatSigningProvider keys;
            std::string error;
            std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
            CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
            uint32_t chain_counter = std::max((i == 1 ? chain.nInternalChainCounter : chain.nExternalChainCounter), (uint32_t)0);
            WalletDescriptor w_desc(std::move(descs.at(0)), 0, 0, chain_counter, 0);

            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
            WITH_LOCK(desc_spk_man->cs_desc_man, desc_spk_man->AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey()));
            desc_spk_man->TopUpWithDB(batch);
            auto desc_spks = desc_spk_man->GetScriptPubKeys();

            // Remove the scriptPubKeys from our current set
            for (const CScript& spk : desc_spks) {
                size_t erased = spks.erase(spk);
                assert(erased == 1);
                assert(IsMine(spk));
            }

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }
    }
    // Add the current master seed to the migration data
    if (!m_hd_chain.seed_id.IsNull()) {
        CKey seed_key;
        if (!GetKey(m_hd_chain.seed_id, seed_key)) {
            assert(false);
        }
        out.master_key.SetSeed(seed_key);
    }

    // Handle the rest of the scriptPubKeys which must be imports and may not have all info
    for (auto it = spks.begin(); it != spks.end();) {
        const CScript& spk = *it;

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& mit = m_script_metadata.find(CScriptID(spk));
        if (mit != m_script_metadata.end()) {
            creation_time = mit->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(spk, *GetSolvingProvider(spk));

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed.
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error);
            if (parsed_descs.empty()) {
                // Remove this scriptPubKey from the set
                it = spks.erase(it);
                continue;
            }
        }

        // Get the private keys for this descriptor
        std::vector<CScript> scripts;
        FlatSigningProvider keys;
        if (!desc->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, keys)) {
            assert(false);
        }
        std::set<CKeyID> privkeyids;
        for (const auto& key_orig_pair : keys.origins) {
            privkeyids.insert(key_orig_pair.first);
        }

        std::vector<CScript> desc_spks;

        // Make the descriptor string with private keys
        std::string desc_str;
        bool watchonly = !desc->ToPrivateString(*this, desc_str);
        if (watchonly && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            out.watch_descs.emplace_back(desc->ToString(), creation_time);

            // Get the scriptPubKeys without writing this to the wallet
            FlatSigningProvider provider;
            desc->Expand(0, provider, desc_spks, provider);
        } else {
            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
            auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
            for (const auto& keyid : privkeyids) {
                CKey key;
                if (!GetKey(keyid, key)) {
                    continue;
                }
                WITH_LOCK(desc_spk_man->cs_desc_man, desc_spk_man->AddDescriptorKeyWithDB(batch, key, key.GetPubKey()));
            }
            desc_spk_man->TopUpWithDB(batch);
            auto desc_spks_set = desc_spk_man->GetScriptPubKeys();
            desc_spks.insert(desc_spks.end(), desc_spks_set.begin(), desc_spks_set.end());

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // Remove the scriptPubKeys from our current set
        for (const CScript& desc_spk : desc_spks) {
            auto del_it = spks.find(desc_spk);
            assert(del_it != spks.end());
            assert(IsMine(desc_spk));
            it = spks.erase(del_it);
        }
    }

    // Make sure that we have accounted for all scriptPubKeys
    if (!Assume(spks.empty())) {
        LogPrintf("%s\n", STR_INTERNAL_BUG("Error: Some output scripts were not migrated.\n"));
        return std::nullopt;
    }

    // Legacy wallets can also contain scripts whose P2SH, P2WSH, or P2SH-P2WSH it is not watching for
    // but can provide script data to a PSBT spending them. These "solvable" output scripts will need to
    // be put into the separate "solvables" wallet.
    // These can be detected by going through the entire candidate output scripts, finding the not IsMine scripts,
    // and checking CanProvide() which will dummy sign.
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        // Since we only care about P2SH, P2WSH, and P2SH-P2WSH, filter out any scripts that are not those
        if (!script.IsPayToScriptHash() && !script.IsPayToWitnessScriptHash()) {
            continue;
        }
        if (IsMine(script)) {
            continue;
        }
        SignatureData dummy_sigdata;
        if (!CanProvide(script, dummy_sigdata)) {
            continue;
        }

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& it = m_script_metadata.find(CScriptID(script));
        if (it != m_script_metadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(script, *GetSolvingProvider(script));
        if (!desc->IsSolvable()) {
            // The wallet was able to provide some information, but not enough to make a descriptor that actually
            // contains anything useful. This is probably because the script itself is actually unsignable (e.g. P2WSH-P2WSH).
            continue;
        }

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error, false);
            if (parsed_descs.empty()) {
                continue;
            }
        }

        out.solvable_descs.emplace_back(desc->ToString(), creation_time);
    }

    // Finalize transaction
    if (!batch.TxnCommit()) {
        LogPrintf("Error generating descriptors for migration, cannot commit db transaction\n");
        return std::nullopt;
    }

    return out;
}

bool LegacyDataSPKM::DeleteRecordsWithDB(WalletBatch& batch)
{
    LOCK(cs_KeyStore);
    return batch.EraseRecords(DBKeys::LEGACY_TYPES);
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    // Returns true if this descriptor supports getting new addresses. Conditions where we may be unable to fetch them (e.g. locked) are caught later
    if (!CanGetAddresses()) {
        return util::Error{_("No addresses available")};
    }
    {
        LOCK(cs_desc_man);
        assert(m_wallet_descriptor.descriptor->IsSingleType()); // This is a combo descriptor which should not be an active descriptor
        std::optional<OutputType> desc_addr_type = m_wallet_descriptor.descriptor->GetOutputType();
        assert(desc_addr_type);
        if (type != *desc_addr_type) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
        }

        if (!m_deferred_create_keypool_top_up && !IsRangedP2MRDescriptorNoLock()) {
            TopUp();
        }

        // Get the scriptPubKey from the descriptor
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (m_wallet_descriptor.next_index >= m_wallet_descriptor.range_end && !TopUp(1)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }

        CTxDestination dest;
        if (!ExtractDestination(scripts_temp[0], dest)) {
            return util::Error{_("Error: Cannot extract destination from the generated scriptpubkey")}; // shouldn't happen
        }
        m_wallet_descriptor.next_index++;
        if (IsRangedP2MRDescriptorNoLock() && !m_deferred_create_keypool_top_up) {
            m_wallet_descriptor.deferred_create_keypool_top_up = false;
        }
        WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
        return dest;
    }
}

bool DescriptorScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_desc_man);
    return m_map_script_pub_keys.contains(script);
}

bool DescriptorScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty() ||
        (!m_map_pqc_keys.empty() && m_map_crypted_keys.empty() && m_map_crypted_pqc_keys.empty())) {
        return false;
    }

    bool keyPass = m_map_crypted_keys.empty() && m_map_crypted_pqc_keys.empty(); // Always pass when there are no encrypted keys
    bool keyFail = false;
    for (const auto& mi : m_map_crypted_keys) {
        const CPubKey &pubkey = mi.second.first;
        const std::vector<unsigned char> &crypted_secret = mi.second.second;
        CKey key;
        if (!DecryptKey(master_key, crypted_secret, pubkey, key)) {
            keyFail = true;
            break;
        }
        keyPass = true;
        if (m_decryption_thoroughly_checked)
            break;
    }
    if (!keyFail) {
        const bool has_legacy_crypted_pqc_keys{std::any_of(m_map_crypted_pqc_keys.begin(), m_map_crypted_pqc_keys.end(), [](const auto& entry) {
            return !entry.second.auth_tag.has_value();
        })};
        WalletBatch batch(m_storage.GetDatabase());
        for (auto& [pubkey, crypted_key] : m_map_crypted_pqc_keys) {
            CPQCKey key;
            const auto counter_it{m_map_pqc_sig_counters.find(pubkey)};
            const uint32_t sig_counter{counter_it != m_map_pqc_sig_counters.end() ? counter_it->second : 0};
            std::optional<uint256> legacy_auth_tag;
            if (!DecryptPQCKey(master_key, m_wallet_descriptor.id, crypted_key, pubkey, sig_counter, key, &legacy_auth_tag)) {
                keyFail = true;
                break;
            }
            if (legacy_auth_tag &&
                batch.WriteCryptedDescriptorPQCKey(m_wallet_descriptor.id, pubkey, crypted_key.crypted_secret, sig_counter, &*legacy_auth_tag)) {
                crypted_key.auth_tag = *legacy_auth_tag;
            }
            keyPass = true;
            if (m_decryption_thoroughly_checked && !has_legacy_crypted_pqc_keys) {
                break;
            }
        }
    }
    if (keyPass && keyFail) {
        LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
        throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
    }
    if (keyFail || !keyPass) {
        return false;
    }
    m_decryption_thoroughly_checked = true;
    return true;
}

bool DescriptorScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_desc_man);
    if (HasBlockedPlaintextPQCKeys()) {
        return false;
    }
    if (!m_map_crypted_keys.empty() || !m_map_crypted_pqc_keys.empty()) {
        return false;
    }

    for (const KeyMap::value_type& key_in : m_map_keys)
    {
        const CKey &key = key_in.second;
        CPubKey pubkey = key.GetPubKey();
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        std::vector<unsigned char> crypted_secret;
        if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }
        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        batch->WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    }
    for (const auto& [pubkey, key] : m_map_pqc_keys) {
        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret(key.data(), key.data() + key.size());
        if (!EncryptSecret(master_key, secret, GetPQCKeyIV(pubkey), crypted_secret)) {
            return false;
        }
        const auto counter_it = m_map_pqc_sig_counters.find(pubkey);
        const uint32_t sig_counter = counter_it != m_map_pqc_sig_counters.end() ? counter_it->second : 0;
        const uint256 auth_tag{GetCryptedPQCKeyAuthTag(master_key, GetID(), pubkey, std::span<const unsigned char>{secret.data(), secret.size()}, sig_counter)};
        m_map_crypted_pqc_keys[pubkey] = CryptedPQCKeyRecord{crypted_secret, auth_tag};
        batch->WriteCryptedDescriptorPQCKey(GetID(), pubkey, crypted_secret, sig_counter, &auth_tag);
    }
    m_map_keys.clear();
    m_map_pqc_keys.clear();
    return true;
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, int64_t& index, bool allow_internal_p2mr_refill)
{
    LOCK(cs_desc_man);
    if (internal && allow_internal_p2mr_refill) {
        MaybeTopUpInternalP2MRKeyPool();
    }
    auto op_dest = GetNewDestination(type);
    index = m_wallet_descriptor.next_index - 1;
    return op_dest;
}

void DescriptorScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
    LOCK(cs_desc_man);
    // Only return when the index was the most recent
    if (m_wallet_descriptor.next_index - 1 == index) {
        m_wallet_descriptor.next_index--;
    }
    WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
    NotifyCanGetAddressesChanged();
}

std::map<CKeyID, CKey> DescriptorScriptPubKeyMan::GetKeys() const
{
    KeyMap keys;
    CryptedKeyMap crypted_keys;
    const bool has_encryption_keys = m_storage.HasEncryptionKeys();
    std::optional<CKeyingMaterial> encryption_key;
    if (has_encryption_keys) {
        m_storage.WithEncryptionKey([&](const CKeyingMaterial& key) {
            if (!key.empty()) {
                encryption_key = key;
            }
            return true;
        });
    }
    {
        LOCK(cs_desc_man);
        keys = m_map_keys;
        if (has_encryption_keys) {
            crypted_keys = m_map_crypted_keys;
        }
    }

    if (has_encryption_keys && !crypted_keys.empty()) {
        if (!encryption_key) {
            return keys;
        }
        for (const auto& [key_id, crypted_pair] : crypted_keys) {
            const CPubKey& pubkey = crypted_pair.first;
            const std::vector<unsigned char>& crypted_secret = crypted_pair.second;
            CKey key;
            if (!DecryptKey(*encryption_key, crypted_secret, pubkey, key)) {
                continue;
            }
            keys[key_id] = key;
        }
    }
    return keys;
}

bool DescriptorScriptPubKeyMan::HasPrivKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    return m_map_keys.contains(keyid) || m_map_crypted_keys.contains(keyid);
}

std::optional<CKey> DescriptorScriptPubKeyMan::GetKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        const auto& it = m_map_crypted_keys.find(keyid);
        if (it == m_map_crypted_keys.end()) {
            return std::nullopt;
        }
        const std::vector<unsigned char>& crypted_secret = it->second.second;
        CKey key;
        if (!Assume(m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, crypted_secret, it->second.first, key);
        }))) {
            return std::nullopt;
        }
        return key;
    }
    const auto& it = m_map_keys.find(keyid);
    if (it == m_map_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool DescriptorScriptPubKeyMan::TopUp(unsigned int size)
{
    return TopUpResult(size).has_value();
}

util::Result<void> DescriptorScriptPubKeyMan::TopUpResult(unsigned int size)
{
    return TopUpWithInternalHintResult(std::nullopt, size);
}

bool DescriptorScriptPubKeyMan::TopUpWithInternalHint(std::optional<bool> internal_hint, unsigned int size)
{
    return TopUpWithInternalHintResult(internal_hint, size).has_value();
}

DescriptorScriptPubKeyMan::TopUpPreparation DescriptorScriptPubKeyMan::PrepareTopUp(std::optional<bool> internal_hint) const
{
    TopUpPreparation prepared;
    prepared.spkman_is_internal = internal_hint.has_value() ? internal_hint : m_storage.IsInternalScriptPubKeyMan(this);
    prepared.provider.keys = GetKeys();
    prepared.has_encryption_keys = m_storage.HasEncryptionKeys();
    if (prepared.has_encryption_keys) {
        m_storage.WithEncryptionKey([&](const CKeyingMaterial& key) {
            if (!key.empty()) {
                prepared.encryption_key = key;
            }
            return true;
        });
    }
    return prepared;
}

util::Result<void> DescriptorScriptPubKeyMan::TopUpWithInternalHintResult(std::optional<bool> internal_hint, unsigned int size)
{
    const TopUpPreparation prepared{PrepareTopUp(internal_hint)};
    LOCK(cs_desc_man);
    // Keep descriptor and database lock ordering aligned with address reservation.
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) {
        return util::Error{_("Error starting descriptors keypool top-up database transaction")};
    }
    util::Result<void> res{TopUpWithDBPreparedResult(batch, size, prepared, /*throw_on_persistence_error=*/false, /*rollback_state_on_error=*/true)};
    if (!res) {
        if (!batch.TxnAbort()) {
            throw std::runtime_error(strprintf(
                "Error during descriptors keypool top up. Cannot abort changes for wallet [%s]: %s",
                m_storage.LogName(), util::ErrorString(res).original));
        }
        return res;
    }
    if (!batch.TxnCommit()) throw std::runtime_error(strprintf("Error during descriptors keypool top up. Cannot commit changes for wallet [%s]", m_storage.LogName()));
    return {};
}

bool DescriptorScriptPubKeyMan::TopUpWithDB(WalletBatch& batch, unsigned int size, std::optional<bool> internal_hint)
{
    return TopUpWithDBResult(batch, size, internal_hint, /*throw_on_persistence_error=*/true, /*rollback_state_on_error=*/false).has_value();
}

util::Result<void> DescriptorScriptPubKeyMan::TopUpWithDBResult(WalletBatch& batch, unsigned int size, std::optional<bool> internal_hint, bool throw_on_persistence_error, bool rollback_state_on_error)
{
    const TopUpPreparation prepared{PrepareTopUp(internal_hint)};
    LOCK(cs_desc_man);
    return TopUpWithDBPreparedResult(batch, size, prepared, throw_on_persistence_error, rollback_state_on_error);
}

util::Result<void> DescriptorScriptPubKeyMan::TopUpWithDBPreparedResult(WalletBatch& batch, unsigned int size, const TopUpPreparation& prepared, bool throw_on_persistence_error, bool rollback_state_on_error)
{
    AssertLockHeld(cs_desc_man);
    const int32_t old_range_start{m_wallet_descriptor.range_start};
    const int32_t old_range_end{m_wallet_descriptor.range_end};
    const std::optional<bool> old_descriptor_deferred_create_keypool_top_up{m_wallet_descriptor.deferred_create_keypool_top_up};
    const int32_t old_max_cached_index{m_max_cached_index};
    const bool old_deferred_create_keypool_top_up{m_deferred_create_keypool_top_up};
    DescriptorCache added_cache_items;
    std::map<CScript, std::optional<int32_t>> old_script_pub_key_values;
    std::set<CPubKey> added_pubkeys;
    struct OldPQCKeyState {
        std::optional<CPQCKey> key;
        std::optional<CryptedPQCKeyRecord> crypted_key;
        std::optional<uint32_t> sig_counter;
    };
    std::map<CPQCPubKey, OldPQCKeyState> old_pqc_key_values;
    bool has_persisted_top_up_writes{false};
    const auto remember_script_pub_key = [&](const CScript& script) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) {
        if (old_script_pub_key_values.contains(script)) return;
        const auto it = m_map_script_pub_keys.find(script);
        old_script_pub_key_values.emplace(script, it == m_map_script_pub_keys.end() ? std::nullopt : std::optional<int32_t>{it->second});
    };
    const auto remember_pqc_key = [&](const CPQCPubKey& pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) {
        if (old_pqc_key_values.contains(pubkey)) return;
        OldPQCKeyState state;
        if (const auto it = m_map_pqc_keys.find(pubkey); it != m_map_pqc_keys.end()) {
            state.key = it->second;
        }
        if (const auto it = m_map_crypted_pqc_keys.find(pubkey); it != m_map_crypted_pqc_keys.end()) {
            state.crypted_key = it->second;
        }
        if (const auto it = m_map_pqc_sig_counters.find(pubkey); it != m_map_pqc_sig_counters.end()) {
            state.sig_counter = it->second;
        }
        old_pqc_key_values.emplace(pubkey, std::move(state));
    };
    const auto restore_top_up_state = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) {
        m_wallet_descriptor.range_start = old_range_start;
        m_wallet_descriptor.range_end = old_range_end;
        m_wallet_descriptor.deferred_create_keypool_top_up = old_descriptor_deferred_create_keypool_top_up;
        m_wallet_descriptor.cache.Remove(added_cache_items);
        m_max_cached_index = old_max_cached_index;
        for (const auto& [script, old_index] : old_script_pub_key_values) {
            if (old_index) {
                m_map_script_pub_keys[script] = *old_index;
            } else {
                m_map_script_pub_keys.erase(script);
            }
        }
        for (const CPubKey& pubkey : added_pubkeys) {
            m_map_pubkeys.erase(pubkey);
        }
        for (const auto& [pubkey, old_state] : old_pqc_key_values) {
            if (old_state.key) {
                m_map_pqc_keys[pubkey] = *old_state.key;
            } else {
                m_map_pqc_keys.erase(pubkey);
            }
            if (old_state.crypted_key) {
                m_map_crypted_pqc_keys[pubkey] = *old_state.crypted_key;
            } else {
                m_map_crypted_pqc_keys.erase(pubkey);
            }
            if (old_state.sig_counter) {
                m_map_pqc_sig_counters[pubkey] = *old_state.sig_counter;
            } else {
                m_map_pqc_sig_counters.erase(pubkey);
            }
        }
        m_deferred_create_keypool_top_up = old_deferred_create_keypool_top_up;
    };
    const auto restore_top_up_state_if_safe = [&](bool persistence_write_may_have_started) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) {
        if (rollback_state_on_error || (!persistence_write_may_have_started && !has_persisted_top_up_writes)) {
            restore_top_up_state();
        }
    };
    const auto top_up_error = [&](bilingual_str error) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) -> util::Result<void> {
        restore_top_up_state_if_safe(/*persistence_write_may_have_started=*/false);
        return util::Error{std::move(error)};
    };
    const auto persistence_error = [&](bilingual_str error, bool persistence_write_may_have_started = true) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man) -> util::Result<void> {
        restore_top_up_state_if_safe(persistence_write_may_have_started);
        if (throw_on_persistence_error) throw std::runtime_error(error.original);
        return util::Error{std::move(error)};
    };
    std::set<CScript> new_spks;
    unsigned int target_size;
    if (size > 0) {
        target_size = size;
    } else {
        target_size = m_keypool_size;
    }

    // Calculate the new range_end
    int32_t new_range_end = std::max(m_wallet_descriptor.next_index + (int32_t)target_size, m_wallet_descriptor.range_end);

    // If the descriptor is not ranged, we actually just want to fill the first cache item
    if (!m_wallet_descriptor.descriptor->IsRange()) {
        new_range_end = 1;
        m_wallet_descriptor.range_end = 1;
        m_wallet_descriptor.range_start = 0;
    }

    const bool is_p2mr = m_wallet_descriptor.descriptor->GetOutputType() &&
                         *m_wallet_descriptor.descriptor->GetOutputType() == OutputType::P2MR;
    const bool use_legacy_p2mr_derivation = is_p2mr && !m_wallet_descriptor.descriptor->IsRange();
    bool has_ecdsa_p2mr_source = false;
    bool has_private_p2mr_source = false;
    std::optional<CKey> pqc_master_key;
    if (is_p2mr) {
        std::set<CPubKey> pubkeys;
        std::set<CExtPubKey> ext_pubs;
        m_wallet_descriptor.descriptor->GetPubKeys(pubkeys, ext_pubs);
        has_ecdsa_p2mr_source = !pubkeys.empty() || !ext_pubs.empty();
        for (const auto& pubkey : pubkeys) {
            has_private_p2mr_source |= HasPrivKey(pubkey.GetID());
            const auto it = prepared.provider.keys.find(pubkey.GetID());
            if (it != prepared.provider.keys.end()) {
                pqc_master_key = it->second;
                break;
            }
        }
        for (const auto& ext_pub : ext_pubs) {
            has_private_p2mr_source |= HasPrivKey(ext_pub.pubkey.GetID());
            if (pqc_master_key) continue;
            const auto it = prepared.provider.keys.find(ext_pub.pubkey.GetID());
            if (it != prepared.provider.keys.end()) {
                pqc_master_key = it->second;
            }
        }
    }
    const bool can_derive_pqc = use_legacy_p2mr_derivation && has_ecdsa_p2mr_source && pqc_master_key.has_value();

    uint256 id = GetID();
    for (int32_t i = m_max_cached_index + 1; i < new_range_end; ++i) {
        if (can_derive_pqc) {
            const auto* seed_ptr = reinterpret_cast<const unsigned char*>(pqc_master_key->begin());
            const uint32_t pqc_index = 0;
            if (prepared.spkman_is_internal.has_value()) {
                // Non-ranged pqc(...) descriptors always expand the address path
                // via change=0, so keep the pre-derived private key aligned.
                const uint32_t change = 0U;
                CPQCKey pqc_key;
                if (!DerivePQCKey(std::span<const unsigned char>{seed_ptr, pqc_master_key->size()}, /*account=*/0, change, pqc_index, pqc_key)) {
                    return top_up_error(Untranslated(strprintf("failed to derive P2MR private key at descriptor index %d", i)));
                }
                const CPQCPubKey pqc_pub = pqc_key.GetPubKey();
                const bool had_pqc_key = m_map_pqc_keys.contains(pqc_pub) || m_map_crypted_pqc_keys.contains(pqc_pub) || m_pending_plaintext_pqc_keys.contains(pqc_pub);
                remember_pqc_key(pqc_pub);
                if (!AddDescriptorPQCKeyWithDB(batch, pqc_pub, pqc_key, prepared.has_encryption_keys, prepared.encryption_key ? &*prepared.encryption_key : nullptr)) {
                    if (prepared.has_encryption_keys && !prepared.encryption_key) {
                        return persistence_error(_("wallet encryption key is unavailable for P2MR private-key persistence"), /*persistence_write_may_have_started=*/false);
                    }
                    return persistence_error(Untranslated(strprintf("failed to write P2MR private key at descriptor index %d", i)));
                }
                has_persisted_top_up_writes |= !had_pqc_key;
            } else {
                // Preserve legacy behavior if this SPKM is not active in either internal/external slot.
                for (const uint32_t change : {0U, 1U}) {
                    CPQCKey pqc_key;
                    if (!DerivePQCKey(std::span<const unsigned char>{seed_ptr, pqc_master_key->size()}, /*account=*/0, change, pqc_index, pqc_key)) {
                        return top_up_error(Untranslated(strprintf("failed to derive P2MR private key at descriptor index %d", i)));
                    }
                    const CPQCPubKey pqc_pub = pqc_key.GetPubKey();
                    const bool had_pqc_key = m_map_pqc_keys.contains(pqc_pub) || m_map_crypted_pqc_keys.contains(pqc_pub) || m_pending_plaintext_pqc_keys.contains(pqc_pub);
                    remember_pqc_key(pqc_pub);
                    if (!AddDescriptorPQCKeyWithDB(batch, pqc_pub, pqc_key, prepared.has_encryption_keys, prepared.encryption_key ? &*prepared.encryption_key : nullptr)) {
                        if (prepared.has_encryption_keys && !prepared.encryption_key) {
                            return persistence_error(_("wallet encryption key is unavailable for P2MR private-key persistence"), /*persistence_write_may_have_started=*/false);
                        }
                        return persistence_error(Untranslated(strprintf("failed to write P2MR private key at descriptor index %d", i)));
                    }
                    has_persisted_top_up_writes |= !had_pqc_key;
                }
            }
        }

        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        DescriptorCache temp_cache;
        // Maybe we have a cached xpub and we can expand from the cache first
        const bool expanded_from_cache = m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys);
        if (!expanded_from_cache) {
            if (!m_wallet_descriptor.descriptor->Expand(i, prepared.provider, scripts_temp, out_keys, &temp_cache)) {
                if (is_p2mr && prepared.has_encryption_keys && !prepared.encryption_key && has_private_p2mr_source) {
                    return persistence_error(_("wallet encryption key is unavailable for P2MR private-key persistence"), /*persistence_write_may_have_started=*/false);
                }
                return top_up_error(Untranslated(strprintf("descriptor expansion failed at index %d; private derivation material may be missing or unavailable", i)));
            }
        }
        if (is_p2mr) {
            if (expanded_from_cache) {
                // Cache entries only retain the derived PQC pubkey. Re-expand the
                // private side so imported cached descriptors can still persist the
                // signable PQC keys the wallet needs.
                m_wallet_descriptor.descriptor->ExpandPrivate(i, prepared.provider, out_keys);
            }
            if (prepared.has_encryption_keys && !prepared.encryption_key && has_private_p2mr_source) {
                for (const auto& p2mr_pair : out_keys.p2mr_pubkeys) {
                    const CPQCPubKey& pqc_pub = p2mr_pair.second;
                    const bool has_pqc_key = m_map_pqc_keys.contains(pqc_pub) || m_map_crypted_pqc_keys.contains(pqc_pub) || m_pending_plaintext_pqc_keys.contains(pqc_pub);
                    if (!has_pqc_key && !out_keys.pqc_keys.contains(pqc_pub)) {
                        return persistence_error(_("wallet encryption key is unavailable for P2MR private-key persistence"), /*persistence_write_may_have_started=*/false);
                    }
                }
            }
            for (const auto& [pqc_pub, pqc_key] : out_keys.pqc_keys) {
                const bool had_pqc_key = m_map_pqc_keys.contains(pqc_pub) || m_map_crypted_pqc_keys.contains(pqc_pub) || m_pending_plaintext_pqc_keys.contains(pqc_pub);
                remember_pqc_key(pqc_pub);
                if (!AddDescriptorPQCKeyWithDB(batch, pqc_pub, pqc_key, prepared.has_encryption_keys, prepared.encryption_key ? &*prepared.encryption_key : nullptr)) {
                    if (prepared.has_encryption_keys && !prepared.encryption_key) {
                        return persistence_error(_("wallet encryption key is unavailable for P2MR private-key persistence"), /*persistence_write_may_have_started=*/false);
                    }
                    return persistence_error(Untranslated(strprintf("failed to write P2MR private key at descriptor index %d", i)));
                }
                has_persisted_top_up_writes |= !had_pqc_key;
            }
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            remember_script_pub_key(script);
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and its private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
            added_pubkeys.insert(pubkey);
        }
        // Merge and write the cache
        DescriptorCache new_items = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
        added_cache_items.MergeAndDiff(new_items);
        if (!batch.WriteDescriptorCacheItems(id, new_items)) {
            return persistence_error(Untranslated(strprintf("failed to write descriptor cache at index %d", i)));
        }
        has_persisted_top_up_writes = true;
        m_max_cached_index++;
    }
    m_wallet_descriptor.range_end = new_range_end;
    if (m_wallet_descriptor.range_end >= m_wallet_descriptor.next_index + m_keypool_size) {
        m_deferred_create_keypool_top_up = false;
    }
    if (m_wallet_descriptor.deferred_create_keypool_top_up.has_value() || !m_deferred_create_keypool_top_up) {
        m_wallet_descriptor.deferred_create_keypool_top_up = m_deferred_create_keypool_top_up;
    }
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        return persistence_error(Untranslated("failed to write descriptor after keypool top-up"));
    }
    has_persisted_top_up_writes = true;

    // By this point, the cache size should be the size of the entire range
    assert(m_wallet_descriptor.range_end - 1 == m_max_cached_index);

    m_storage.TopUpCallback(new_spks, this);
    NotifyCanGetAddressesChanged();
    return {};
}

std::vector<WalletDestination> DescriptorScriptPubKeyMan::MarkUnusedAddresses(const CScript& script, const MarkUnusedAddressesOptions& options)
{
    std::vector<WalletDestination> result;
    bool p2mr_refill{false};
    bool non_p2mr_top_up{false};
    unsigned int p2mr_refill_target{0};
    unsigned int p2mr_full_refill_target{0};
    unsigned int p2mr_remaining{0};
    unsigned int p2mr_low_watermark{0};
    std::string p2mr_descriptor_id;

    {
        LOCK(cs_desc_man);
        if (!m_map_script_pub_keys.contains(script)) return result;

        int32_t index = m_map_script_pub_keys[script];
        bool advanced_next_index{false};
        if (index >= m_wallet_descriptor.next_index) {
            WalletLogPrintf("%s: Detected a used keypool item at index %d, mark all keypool items up to this item as used\n", __func__, index);
            auto out_keys = std::make_unique<FlatSigningProvider>();
            std::vector<CScript> scripts_temp;
            while (index >= m_wallet_descriptor.next_index) {
                scripts_temp.clear();
                if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) {
                    throw std::runtime_error(std::string(__func__) + ": Unable to expand descriptor from cache");
                }
                CTxDestination dest;
                ExtractDestination(scripts_temp[0], dest);
                result.push_back({dest, std::nullopt});
                m_wallet_descriptor.next_index++;
                advanced_next_index = true;
            }
        }
        if (m_deferred_create_keypool_top_up) {
            if (advanced_next_index) {
                m_wallet_descriptor.deferred_create_keypool_top_up = true;
                WalletBatch batch(m_storage.GetDatabase());
                if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
                    throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
                }
                NotifyCanGetAddressesChanged();
            }
        } else if (IsRangedP2MRDescriptorNoLock()) {
            if (advanced_next_index) {
                m_wallet_descriptor.deferred_create_keypool_top_up = false;
                WalletBatch batch(m_storage.GetDatabase());
                if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
                    throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
                }
                NotifyCanGetAddressesChanged();
            }
            const bool needs_p2mr_refill{
                options.preserve_full_keypool_lookahead ?
                    GetKeyPoolSizeNoLock() < static_cast<unsigned int>(m_keypool_size) :
                    NeedsP2MRKeyPoolRefillNoLock()};
            if (!needs_p2mr_refill) {
                return result;
            }

            p2mr_refill = true;
            p2mr_refill_target = options.preserve_full_keypool_lookahead ? 0 : GetP2MRReceiveKeyPoolRefillStepTargetNoLock();
            p2mr_full_refill_target = static_cast<unsigned int>(m_keypool_size);
            p2mr_remaining = GetKeyPoolSizeNoLock();
            p2mr_low_watermark = GetP2MRReceiveKeyPoolLowWatermarkNoLock();
            p2mr_descriptor_id = GetID().ToString();
        } else {
            non_p2mr_top_up = true;
        }
    }

    if (p2mr_refill) {
        if (m_storage.IsLocked()) {
            WalletLogPrintf("%s: P2MR keypool low-watermark refill deferred for locked wallet (descriptor id %s, remaining=%u, low_watermark=%u)\n",
                __func__, p2mr_descriptor_id, p2mr_remaining, p2mr_low_watermark);
            return result;
        }

        util::Result<void> res{TopUpWithInternalHintResult(options.internal_hint, p2mr_refill_target)};
        if (!res) {
            WalletLogPrintf("%s: P2MR keypool low-watermark refill failed (descriptor id %s, target=%u, remaining=%u): %s\n",
                __func__, p2mr_descriptor_id, p2mr_refill_target == 0 ? p2mr_full_refill_target : p2mr_refill_target, GetKeyPoolSize(), util::ErrorString(res).original);
        }
    } else if (non_p2mr_top_up) {
        util::Result<void> res{TopUpWithInternalHintResult(options.internal_hint)};
        if (!res) {
            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
        }
    }

    return result;
}

void DescriptorScriptPubKeyMan::AddDescriptorKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!AddDescriptorKeyWithDB(batch, key, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor private key failed");
    }
}

bool DescriptorScriptPubKeyMan::AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_desc_man);
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // Check if provided key already exists
    if (m_map_keys.find(pubkey.GetID()) != m_map_keys.end() ||
        m_map_crypted_keys.find(pubkey.GetID()) != m_map_crypted_keys.end()) {
        return true;
    }

    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        if (!m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return EncryptSecret(encryption_key, secret, pubkey.GetHash(), crypted_secret);
            })) {
            return false;
        }

        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        return batch.WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    } else {
        m_map_keys[pubkey.GetID()] = key;
        return batch.WriteDescriptorKey(GetID(), pubkey, key.GetPrivKey());
    }
}

bool DescriptorScriptPubKeyMan::AddDescriptorPQCKeyWithDB(WalletBatch& batch, const CPQCPubKey& pubkey, const CPQCKey& key, bool has_encryption_keys, const CKeyingMaterial* encryption_key)
{
    AssertLockHeld(cs_desc_man);
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    if (m_map_pqc_keys.contains(pubkey) || m_map_crypted_pqc_keys.contains(pubkey) || m_pending_plaintext_pqc_keys.contains(pubkey)) {
        return true;
    }

    if (has_encryption_keys) {
        if (encryption_key == nullptr) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret(key.data(), key.data() + key.size());
        if (!EncryptSecret(*encryption_key, secret, GetPQCKeyIV(pubkey), crypted_secret)) {
            return false;
        }

        const uint256 auth_tag{GetCryptedPQCKeyAuthTag(*encryption_key, GetID(), pubkey, std::span<const unsigned char>{secret.data(), secret.size()}, /*sig_counter=*/0)};
        m_map_crypted_pqc_keys[pubkey] = CryptedPQCKeyRecord{crypted_secret, auth_tag};
        if (!batch.WriteCryptedDescriptorPQCKey(GetID(), pubkey, crypted_secret, /*sig_counter=*/0, &auth_tag)) {
            m_map_crypted_pqc_keys.erase(pubkey);
            return false;
        }
        m_map_pqc_sig_counters.emplace(pubkey, 0);
        return true;
    }

    m_map_pqc_keys[pubkey] = key;
    if (!batch.WriteDescriptorPQCKey(GetID(), pubkey, key, /*sig_counter=*/0)) {
        m_map_pqc_keys.erase(pubkey);
        return false;
    }
    m_map_pqc_sig_counters.emplace(pubkey, 0);
    return true;
}

bool DescriptorScriptPubKeyMan::SetupDescriptorGeneration(WalletBatch& batch, const CExtKey& master_key, OutputType addr_type, bool internal, unsigned int initial_keypool_size)
{
    LOCK(cs_desc_man);
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // Ignore when there is already a descriptor
    if (m_wallet_descriptor.descriptor) {
        return false;
    }

    m_wallet_descriptor = GenerateWalletDescriptor(master_key.Neuter(), addr_type, internal);

    // Store the master private key, and descriptor
    if (!AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey())) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor master private key failed");
    }
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // Wallet creation on P2MR-only chains seeds a small synchronous pool first,
    // then refills the remainder after create returns.
    m_deferred_create_keypool_top_up = initial_keypool_size > 0 && initial_keypool_size < m_keypool_size;
    m_wallet_descriptor.deferred_create_keypool_top_up = m_deferred_create_keypool_top_up;
    const unsigned int top_up_size = m_deferred_create_keypool_top_up ? initial_keypool_size : 0;
    TopUpWithDB(batch, top_up_size, internal);

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

bool DescriptorScriptPubKeyMan::HasDeferredCreateKeyPoolTopUp() const
{
    LOCK(cs_desc_man);
    return m_deferred_create_keypool_top_up;
}

void DescriptorScriptPubKeyMan::MaybeRestoreDeferredCreateKeyPoolTopUp()
{
    LOCK(cs_desc_man);
    m_deferred_create_keypool_top_up = ShouldDeferCreateKeyPoolTopUp(m_wallet_descriptor, m_keypool_size);
}

bool DescriptorScriptPubKeyMan::IsRangedP2MRDescriptorNoLock() const
{
    AssertLockHeld(cs_desc_man);
    if (!m_wallet_descriptor.descriptor) return false;
    const std::optional<OutputType> output_type{m_wallet_descriptor.descriptor->GetOutputType()};
    return output_type && *output_type == OutputType::P2MR && m_wallet_descriptor.descriptor->IsRange();
}

bool DescriptorScriptPubKeyMan::IsRangedP2MRDescriptor() const
{
    LOCK(cs_desc_man);
    return IsRangedP2MRDescriptorNoLock();
}

unsigned int DescriptorScriptPubKeyMan::GetKeyPoolSizeNoLock() const
{
    AssertLockHeld(cs_desc_man);
    if (m_wallet_descriptor.range_end <= m_wallet_descriptor.next_index) return 0;
    return static_cast<unsigned int>(m_wallet_descriptor.range_end - m_wallet_descriptor.next_index);
}

bool DescriptorScriptPubKeyMan::NeedsP2MRKeyPoolRefillNoLock() const
{
    AssertLockHeld(cs_desc_man);
    return IsRangedP2MRDescriptorNoLock() &&
           !m_deferred_create_keypool_top_up &&
           GetKeyPoolSizeNoLock() < static_cast<unsigned int>(m_keypool_size) &&
           GetKeyPoolSizeNoLock() <= GetP2MRReceiveKeyPoolLowWatermarkNoLock();
}

void DescriptorScriptPubKeyMan::MaybeTopUpInternalP2MRKeyPool()
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.IsLocked() || !NeedsP2MRKeyPoolRefillNoLock()) return;

    const unsigned int target{GetP2MRReceiveKeyPoolRefillStepTargetNoLock()};
    if (target == 0) return;
    try {
        util::Result<void> res{TopUpWithInternalHintResult(/*internal_hint=*/true, target)};
        if (!res) {
            WalletLogPrintf("P2MR change keypool inline low-watermark refill failed (descriptor id %s, target=%u, remaining=%u): %s\n",
                GetID().ToString(), target, GetKeyPoolSizeNoLock(), util::ErrorString(res).original);
        }
    } catch (const std::exception& e) {
        WalletLogPrintf("P2MR change keypool inline low-watermark refill failed (descriptor id %s, target=%u, remaining=%u): %s\n",
            GetID().ToString(), target, GetKeyPoolSizeNoLock(), e.what());
    }
}

unsigned int DescriptorScriptPubKeyMan::GetP2MRReceiveKeyPoolLowWatermarkNoLock() const
{
    AssertLockHeld(cs_desc_man);
    return std::min<int64_t>(
        m_keypool_size,
        std::max<int64_t>(DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL, m_keypool_size / 10));
}

unsigned int DescriptorScriptPubKeyMan::GetP2MRReceiveKeyPoolLowWatermark() const
{
    LOCK(cs_desc_man);
    return GetP2MRReceiveKeyPoolLowWatermarkNoLock();
}

bool DescriptorScriptPubKeyMan::NeedsP2MRReceiveKeyPoolRefill() const
{
    LOCK(cs_desc_man);
    return NeedsP2MRKeyPoolRefillNoLock();
}

bool DescriptorScriptPubKeyMan::P2MRReceiveKeyPoolFull() const
{
    LOCK(cs_desc_man);
    return !IsRangedP2MRDescriptorNoLock() ||
           GetKeyPoolSizeNoLock() >= static_cast<unsigned int>(m_keypool_size);
}

unsigned int DescriptorScriptPubKeyMan::GetP2MRReceiveKeyPoolRefillStepTargetNoLock() const
{
    AssertLockHeld(cs_desc_man);
    if (!IsRangedP2MRDescriptorNoLock()) return 0;
    return std::min<int64_t>(
        m_keypool_size,
        int64_t{GetKeyPoolSizeNoLock()} + DEFAULT_CREATE_WALLET_P2MR_WARM_KEYPOOL);
}

unsigned int DescriptorScriptPubKeyMan::GetP2MRReceiveKeyPoolRefillStepTarget() const
{
    LOCK(cs_desc_man);
    return GetP2MRReceiveKeyPoolRefillStepTargetNoLock();
}

bool DescriptorScriptPubKeyMan::IsHDEnabled() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.descriptor->IsRange();
}

bool DescriptorScriptPubKeyMan::CanGetAddresses(bool internal) const
{
    // We can only give out addresses from descriptors that are single type (not combo) and ranged.
    // P2MR is an exception: non-ranged descriptors can hand out their single cached address.
    LOCK(cs_desc_man);
    const bool is_range = m_wallet_descriptor.descriptor->IsRange();
    const auto output_type = m_wallet_descriptor.descriptor->GetOutputType();
    const bool is_p2mr = output_type && *output_type == OutputType::P2MR;
    if (!m_wallet_descriptor.descriptor->IsSingleType() || (!is_range && !is_p2mr)) {
        return false;
    }

    if (is_range) {
        if (!is_p2mr) {
            return HavePrivateKeys() || m_wallet_descriptor.next_index < m_wallet_descriptor.range_end;
        }

        // Ranged P2MR descriptors derive new PQC keys from the wallet seed.
        const bool have_ecdsa_derivation_keys = !m_map_keys.empty() || !m_map_crypted_keys.empty();
        return have_ecdsa_derivation_keys || m_wallet_descriptor.next_index < m_wallet_descriptor.range_end;
    }

    // Non-ranged P2MR descriptors can only provide the single cached destination.
    return m_wallet_descriptor.next_index < m_wallet_descriptor.range_end;
}

bool DescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_desc_man);
    return !m_map_keys.empty() || !m_map_crypted_keys.empty() || !m_map_pqc_keys.empty() || !m_map_crypted_pqc_keys.empty() || !m_pending_plaintext_pqc_keys.empty();
}

bool DescriptorScriptPubKeyMan::HaveCryptedKeys() const
{
    LOCK(cs_desc_man);
    return !m_map_crypted_keys.empty() || !m_map_crypted_pqc_keys.empty();
}

bool DescriptorScriptPubKeyMan::HasBlockedPlaintextPQCKeys() const
{
    AssertLockHeld(cs_desc_man);
    return !m_pending_plaintext_pqc_keys.empty() || !m_failed_plaintext_pqc_keys.empty();
}

bool DescriptorScriptPubKeyMan::IsPlaintextPQCKeyBlocked(const CPQCPubKey& pubkey) const
{
    AssertLockHeld(cs_desc_man);
    if (m_pending_plaintext_pqc_keys.contains(pubkey)) return true;
    return m_failed_plaintext_pqc_keys.contains(pubkey) && !m_map_crypted_pqc_keys.contains(pubkey);
}

std::set<CPQCPubKey> DescriptorScriptPubKeyMan::GetBlockedPlaintextPQCKeys() const
{
    AssertLockHeld(cs_desc_man);
    std::set<CPQCPubKey> blocked_pubkeys;
    for (const auto& [pubkey, _] : m_pending_plaintext_pqc_keys) {
        blocked_pubkeys.insert(pubkey);
    }
    for (const CPQCPubKey& pubkey : m_failed_plaintext_pqc_keys) {
        if (!m_map_crypted_pqc_keys.contains(pubkey)) {
            blocked_pubkeys.insert(pubkey);
        }
    }
    return blocked_pubkeys;
}

PQCKeyValidationInfo DescriptorScriptPubKeyMan::GetPQCKeyValidationInfo() const
{
    LOCK(cs_desc_man);
    PQCKeyValidationInfo info;
    info.pending_records = m_pending_plaintext_pqc_keys.size();
    info.validated_records = m_map_pqc_keys.size();
    info.failed_records = m_failed_plaintext_pqc_keys.size();
    info.plaintext_records = info.pending_records + info.validated_records + info.failed_records;
    info.signing_blocked = info.pending_records > 0 || info.failed_records > 0;
    info.encryption_recommended = info.plaintext_records > 0 && info.failed_records == 0;

    if (info.failed_records > 0) {
        info.status = PQCKeyValidationStatus::FAILED;
    } else if (info.pending_records > 0) {
        info.status = PQCKeyValidationStatus::PENDING;
    } else if (info.plaintext_records > 0) {
        info.status = PQCKeyValidationStatus::COMPLETE;
    } else {
        info.status = PQCKeyValidationStatus::NOT_REQUIRED;
    }

    if (info.plaintext_records > 0) {
        info.progress = static_cast<double>(info.validated_records) / static_cast<double>(info.plaintext_records);
    }
    return info;
}

unsigned int DescriptorScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_desc_man);
    return GetKeyPoolSizeNoLock();
}

int64_t DescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.creation_time;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CScript& script, bool include_private, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    int32_t index;
    {
        LOCK(cs_desc_man);

        // Find the index of the script
        auto it = m_map_script_pub_keys.find(script);
        if (it == m_map_script_pub_keys.end()) {
            return nullptr;
        }
        index = it->second;
    }

    return GetSigningProvider(index, include_private, pqc_counter_observer);
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CPubKey& pubkey, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    int32_t index;
    {
        LOCK(cs_desc_man);

        // Find index of the pubkey
        auto it = m_map_pubkeys.find(pubkey);
        if (it == m_map_pubkeys.end()) {
            return nullptr;
        }
        index = it->second;
    }

    // Always try to get the signing provider with private keys. This function should only be called during signing anyways
    std::unique_ptr<FlatSigningProvider> out = GetSigningProvider(index, true, pqc_counter_observer);
    if (!out || !out->HaveKey(pubkey.GetID())) {
        return nullptr;
    }
    return out;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CPQCPubKey& pubkey, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    std::optional<CPQCKey> plain_key;
    std::optional<CryptedPQCKeyRecord> crypted_key;
    uint256 desc_id;
    uint32_t sig_counter{0};
    bool has_encryption_keys{false};

    {
        LOCK(cs_desc_man);
        desc_id = m_wallet_descriptor.id;
        has_encryption_keys = m_storage.HasEncryptionKeys();
        if (IsPlaintextPQCKeyBlocked(pubkey)) return nullptr;

        if (const auto it = m_map_pqc_keys.find(pubkey); it != m_map_pqc_keys.end()) {
            plain_key = it->second;
        } else if (const auto it = m_map_crypted_pqc_keys.find(pubkey); it != m_map_crypted_pqc_keys.end()) {
            crypted_key = it->second;
        } else {
            return nullptr;
        }

        if (const auto counter_it = m_map_pqc_sig_counters.find(pubkey); counter_it != m_map_pqc_sig_counters.end()) {
            sig_counter = counter_it->second;
        }
    }

    if (plain_key.has_value() && has_encryption_keys && m_storage.IsLocked()) return nullptr;

    if (crypted_key.has_value()) {
        if (m_storage.IsLocked()) return nullptr;

        CPQCKey decrypted_key;
        bool decrypted{false};
        m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            decrypted = DecryptPQCKey(encryption_key, desc_id, *crypted_key, pubkey, sig_counter, decrypted_key);
            return true;
        });
        if (!decrypted) return nullptr;
        plain_key = decrypted_key;
    }

    if (!plain_key.has_value()) return nullptr;

    auto out = std::make_unique<FlatSigningProvider>();
    out->pqc_keys.emplace(pubkey, *plain_key);
    out->pqc_sig_counters.emplace(pubkey, sig_counter);
    out->pqc_counter_reserver = MakePQCSignatureCounterReserver();
    out->pqc_counter_batch_reserver = MakePQCSignatureCounterBatchReserver();
    out->pqc_counter_observer = pqc_counter_observer;
    return out;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(int32_t index, bool include_private, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();
    std::shared_ptr<Descriptor> descriptor;
    uint256 desc_id;
    bool have_private_keys{false};
    bool has_encryption_keys{false};
    KeyMap keys;
    CryptedKeyMap crypted_keys;
    PQCKeyMap pqc_keys;
    CryptedPQCKeyMap crypted_pqc_keys;
    std::map<CPQCPubKey, uint32_t> pqc_sig_counters;
    std::set<CPQCPubKey> blocked_pqc_keys;

    {
        LOCK(cs_desc_man);
        desc_id = m_wallet_descriptor.id;
        descriptor = m_wallet_descriptor.descriptor;

        // Fetch SigningProvider from cache to avoid re-deriving
        auto it = m_map_signing_providers.find(index);
        if (it != m_map_signing_providers.end()) {
            out_keys->Merge(FlatSigningProvider{it->second});
        } else {
            // Get the scripts, keys, and key origins for this script
            std::vector<CScript> scripts_temp;
            if (!descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) return nullptr;

            // Cache SigningProvider so we don't need to re-derive if we need this SigningProvider again
            m_map_signing_providers[index] = *out_keys;
        }

        if (include_private) {
            have_private_keys = !m_map_keys.empty() || !m_map_crypted_keys.empty() || !m_map_pqc_keys.empty() || !m_map_crypted_pqc_keys.empty();
            if (have_private_keys) {
                blocked_pqc_keys = GetBlockedPlaintextPQCKeys();
                has_encryption_keys = m_storage.HasEncryptionKeys();
                keys = m_map_keys;
                crypted_keys = m_map_crypted_keys;
                pqc_keys = m_map_pqc_keys;
                for (auto it = pqc_keys.begin(); it != pqc_keys.end();) {
                    if (blocked_pqc_keys.contains(it->first)) {
                        it = pqc_keys.erase(it);
                    } else {
                        ++it;
                    }
                }
                crypted_pqc_keys = m_map_crypted_pqc_keys;
                for (auto it = crypted_pqc_keys.begin(); it != crypted_pqc_keys.end();) {
                    if (blocked_pqc_keys.contains(it->first)) {
                        it = crypted_pqc_keys.erase(it);
                    } else {
                        ++it;
                    }
                }
                pqc_sig_counters = m_map_pqc_sig_counters;
            }
        }
    }

    if (!include_private || !have_private_keys) {
        out_keys->pqc_counter_observer = pqc_counter_observer;
        return out_keys;
    }

    FlatSigningProvider master_provider;
    master_provider.keys = std::move(keys);

    // Build private providers after releasing cs_desc_man to preserve the wallet->descriptor lock order.
    const bool encrypted_locked{has_encryption_keys && m_storage.IsLocked()};
    if (encrypted_locked) {
        pqc_keys.clear();
        pqc_sig_counters.clear();
    }
    if (has_encryption_keys && !encrypted_locked) {
        m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            for (const auto& [_, key_pair] : crypted_keys) {
                const CPubKey& pubkey = key_pair.first;
                const std::vector<unsigned char>& crypted_secret = key_pair.second;
                CKey key;
                if (!DecryptKey(encryption_key, crypted_secret, pubkey, key)) {
                    continue;
                }
                master_provider.keys[pubkey.GetID()] = key;
            }
            for (const auto& [pubkey, crypted_key] : crypted_pqc_keys) {
                CPQCKey key;
                const auto counter_it{pqc_sig_counters.find(pubkey)};
                const uint32_t sig_counter{counter_it != pqc_sig_counters.end() ? counter_it->second : 0};
                if (!DecryptPQCKey(encryption_key, desc_id, crypted_key, pubkey, sig_counter, key)) {
                    continue;
                }
                pqc_keys[pubkey] = key;
            }
            return true;
        });
    }

    descriptor->ExpandPrivate(index, master_provider, *out_keys);
    out_keys->pqc_keys.insert(pqc_keys.begin(), pqc_keys.end());
    out_keys->pqc_sig_counters.insert(pqc_sig_counters.begin(), pqc_sig_counters.end());
    for (const CPQCPubKey& pubkey : blocked_pqc_keys) {
        out_keys->pqc_keys.erase(pubkey);
        out_keys->pqc_sig_counters.erase(pubkey);
    }
    out_keys->pqc_counter_reserver = MakePQCSignatureCounterReserver();
    out_keys->pqc_counter_batch_reserver = MakePQCSignatureCounterBatchReserver();
    out_keys->pqc_counter_observer = pqc_counter_observer;

    return out_keys;
}

bool DescriptorScriptPubKeyMan::ReservePQCSignatureCounters(const CPQCPubKey& pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) const
{
    std::map<CPQCPubKey, uint32_t> counts{{pubkey, count}};
    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    if (!ReservePQCSignatureCountersBatch(counts, ranges)) return false;

    const auto range_it{ranges.find(pubkey)};
    if (range_it == ranges.end()) return false;
    previous_counter = range_it->second.previous_counter;
    reserved_counter = range_it->second.reserved_counter;
    return true;
}

bool DescriptorScriptPubKeyMan::ReservePQCSignatureCountersBatch(const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>& ranges) const
{
    ranges.clear();
    if (counts.empty()) return false;
    for (const auto& [_, count] : counts) {
        if (count == 0 || count > PQC_MAX_SIGNATURES) return false;
    }

    struct CryptedPQCUpdate {
        CPQCPubKey pubkey;
        uint256 auth_tag;
    };

    std::map<CPQCPubKey, PQCSignatureCounterRange> reserved_ranges;
    std::vector<CryptedPQCUpdate> crypted_updates;
    LOCK(cs_desc_man);

    for (const auto& [pubkey, count] : counts) {
        if (IsPlaintextPQCKeyBlocked(pubkey)) return false;

        const auto key_it = m_map_pqc_keys.find(pubkey);
        const auto crypted_key_it = m_map_crypted_pqc_keys.find(pubkey);
        if (key_it == m_map_pqc_keys.end() && crypted_key_it == m_map_crypted_pqc_keys.end()) return false;

        const auto counter_it = m_map_pqc_sig_counters.find(pubkey);
        if (counter_it == m_map_pqc_sig_counters.end()) return false;
        if (counter_it->second > PQC_MAX_SIGNATURES - count) return false;

        reserved_ranges.emplace(pubkey, PQCSignatureCounterRange{
            .pubkey = pubkey,
            .previous_counter = counter_it->second,
            .reserved_counter = counter_it->second + count,
        });
    }

    const uint256 desc_id{m_wallet_descriptor.id};

    for (const auto& [pubkey, range] : reserved_ranges) {
        const auto crypted_key_it = m_map_crypted_pqc_keys.find(pubkey);
        if (crypted_key_it == m_map_crypted_pqc_keys.end()) continue;

        uint256 auth_tag;
        if (!m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                CKeyingMaterial secret;
                if (!DecryptSecret(encryption_key, crypted_key_it->second.crypted_secret, GetPQCKeyIV(pubkey), secret) || secret.size() != CPQCKey::SIZE) {
                    return false;
                }
                auth_tag = GetCryptedPQCKeyAuthTag(encryption_key, desc_id, pubkey, std::span<const unsigned char>{secret.data(), secret.size()}, range.reserved_counter);
                return true;
            })) {
            return false;
        }
        crypted_updates.push_back(CryptedPQCUpdate{pubkey, auth_tag});
    }

    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) return false;

    for (const auto& [pubkey, range] : reserved_ranges) {
        if (const auto key_it = m_map_pqc_keys.find(pubkey); key_it != m_map_pqc_keys.end()) {
            if (!batch.WriteDescriptorPQCKey(desc_id, pubkey, key_it->second, range.reserved_counter)) {
                batch.TxnAbort();
                return false;
            }
            continue;
        }

        const auto crypted_key_it = m_map_crypted_pqc_keys.find(pubkey);
        const CryptedPQCUpdate* update{nullptr};
        for (const auto& crypted_update : crypted_updates) {
            if (crypted_update.pubkey == pubkey) {
                update = &crypted_update;
                break;
            }
        }
        if (crypted_key_it == m_map_crypted_pqc_keys.end() || update == nullptr) {
            batch.TxnAbort();
            return false;
        }

        if (!batch.WriteCryptedDescriptorPQCKey(desc_id, pubkey, crypted_key_it->second.crypted_secret, range.reserved_counter, &update->auth_tag)) {
            batch.TxnAbort();
            return false;
        }
    }

    if (!batch.TxnCommit()) {
        batch.TxnAbort();
        return false;
    }

    for (const auto& [pubkey, range] : reserved_ranges) {
        m_map_pqc_sig_counters[pubkey] = range.reserved_counter;
    }
    for (const auto& update : crypted_updates) {
        if (auto crypted_key_it = m_map_crypted_pqc_keys.find(update.pubkey); crypted_key_it != m_map_crypted_pqc_keys.end()) {
            crypted_key_it->second.auth_tag = update.auth_tag;
        }
    }

    ranges = std::move(reserved_ranges);
    return true;
}

PQCSignatureCounterReserver DescriptorScriptPubKeyMan::MakePQCSignatureCounterReserver() const
{
    const std::weak_ptr<void> lifetime{m_lifetime};
    const DescriptorScriptPubKeyMan* self{this};
    WalletStorage* storage{&m_storage};
    return [self, storage, lifetime](const CPQCPubKey& pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        return storage->WithWalletLock([&] {
            if (!lifetime.lock()) return false;
            return self->ReservePQCSignatureCounters(pubkey, count, previous_counter, reserved_counter);
        });
    };
}

PQCSignatureCounterBatchReserver DescriptorScriptPubKeyMan::MakePQCSignatureCounterBatchReserver() const
{
    const std::weak_ptr<void> lifetime{m_lifetime};
    const DescriptorScriptPubKeyMan* self{this};
    WalletStorage* storage{&m_storage};
    return [self, storage, lifetime](const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>& ranges) {
        return storage->WithWalletLock([&] {
            if (!lifetime.lock()) return false;
            return self->ReservePQCSignatureCountersBatch(counts, ranges);
        });
    };
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSolvingProvider(const CScript& script) const
{
    return GetSigningProvider(script, false);
}

bool DescriptorScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return IsMine(script);
}

bool DescriptorScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    std::unique_ptr<SigningProvider> keys = GetSigningProviderForTransaction(coins, pqc_counter_observer);
    return ::SignTransaction(tx, keys ? keys.get() : &DUMMY_SIGNING_PROVIDER, coins, sighash, input_errors);
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSigningProviderForTransaction(const std::map<COutPoint, Coin>& coins, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    bool has_provider_data{false};
    std::vector<int32_t> provider_indices;
    std::set<int32_t> seen_indices;
    std::shared_ptr<Descriptor> descriptor;
    uint256 desc_id;
    bool have_private_keys{false};
    bool has_encryption_keys{false};
    KeyMap private_keys;
    CryptedKeyMap crypted_keys;
    PQCKeyMap pqc_keys;
    CryptedPQCKeyMap crypted_pqc_keys;
    std::map<CPQCPubKey, uint32_t> pqc_sig_counters;
    std::set<CPQCPubKey> blocked_pqc_keys;

    {
        LOCK(cs_desc_man);
        desc_id = m_wallet_descriptor.id;
        descriptor = m_wallet_descriptor.descriptor;

        for (const auto& coin_pair : coins) {
            const auto script_it = m_map_script_pub_keys.find(coin_pair.second.out.scriptPubKey);
            if (script_it == m_map_script_pub_keys.end()) continue;

            const int32_t index{script_it->second};
            if (!seen_indices.insert(index).second) continue;

            FlatSigningProvider index_keys;
            auto provider_it = m_map_signing_providers.find(index);
            if (provider_it != m_map_signing_providers.end()) {
                index_keys = provider_it->second;
            } else {
                std::vector<CScript> scripts_temp;
                if (!descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, index_keys)) continue;
                m_map_signing_providers[index] = index_keys;
            }

            keys->Merge(std::move(index_keys));
            provider_indices.push_back(index);
            has_provider_data = true;
        }

        if (!has_provider_data) return nullptr;

        have_private_keys = !m_map_keys.empty() || !m_map_crypted_keys.empty() || !m_map_pqc_keys.empty() || !m_map_crypted_pqc_keys.empty();
        if (have_private_keys) {
            blocked_pqc_keys = GetBlockedPlaintextPQCKeys();
            has_encryption_keys = m_storage.HasEncryptionKeys();
            private_keys = m_map_keys;
            crypted_keys = m_map_crypted_keys;
            pqc_keys = m_map_pqc_keys;
            for (auto it = pqc_keys.begin(); it != pqc_keys.end();) {
                if (blocked_pqc_keys.contains(it->first)) {
                    it = pqc_keys.erase(it);
                } else {
                    ++it;
                }
            }
            crypted_pqc_keys = m_map_crypted_pqc_keys;
            for (auto it = crypted_pqc_keys.begin(); it != crypted_pqc_keys.end();) {
                if (blocked_pqc_keys.contains(it->first)) {
                    it = crypted_pqc_keys.erase(it);
                } else {
                    ++it;
                }
            }
            pqc_sig_counters = m_map_pqc_sig_counters;
        }
    }

    if (!have_private_keys) {
        keys->pqc_counter_observer = pqc_counter_observer;
        return keys;
    }

    FlatSigningProvider master_provider;
    master_provider.keys = std::move(private_keys);

    // Build private providers after releasing cs_desc_man to preserve the wallet->descriptor lock order.
    const bool encrypted_locked{has_encryption_keys && m_storage.IsLocked()};
    if (encrypted_locked) {
        pqc_keys.clear();
        pqc_sig_counters.clear();
    }
    if (has_encryption_keys && !encrypted_locked) {
        m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            for (const auto& [_, key_pair] : crypted_keys) {
                const CPubKey& pubkey = key_pair.first;
                const std::vector<unsigned char>& crypted_secret = key_pair.second;
                CKey key;
                if (!DecryptKey(encryption_key, crypted_secret, pubkey, key)) {
                    continue;
                }
                master_provider.keys[pubkey.GetID()] = key;
            }
            for (const auto& [pubkey, crypted_key] : crypted_pqc_keys) {
                CPQCKey key;
                const auto counter_it{pqc_sig_counters.find(pubkey)};
                const uint32_t sig_counter{counter_it != pqc_sig_counters.end() ? counter_it->second : 0};
                if (!DecryptPQCKey(encryption_key, desc_id, crypted_key, pubkey, sig_counter, key)) {
                    continue;
                }
                pqc_keys[pubkey] = key;
            }
            return true;
        });
    }

    for (const int32_t index : provider_indices) {
        descriptor->ExpandPrivate(index, master_provider, *keys);
    }
    keys->pqc_keys.insert(pqc_keys.begin(), pqc_keys.end());
    keys->pqc_sig_counters.insert(pqc_sig_counters.begin(), pqc_sig_counters.end());
    for (const CPQCPubKey& pubkey : blocked_pqc_keys) {
        keys->pqc_keys.erase(pubkey);
        keys->pqc_sig_counters.erase(pubkey);
    }
    keys->pqc_counter_reserver = MakePQCSignatureCounterReserver();
    keys->pqc_counter_batch_reserver = MakePQCSignatureCounterBatchReserver();
    keys->pqc_counter_observer = pqc_counter_observer;

    return keys;
}

enum class PSBTInputScriptLookup {
    OK,
    MISSING,
    INVALID_PREVOUT,
};

static PSBTInputScriptLookup GetPSBTInputScript(const PartiallySignedTransaction& psbtx, unsigned int input_index, CScript& script)
{
    const CTxIn& txin = psbtx.tx->vin[input_index];
    const PSBTInput& input = psbtx.inputs.at(input_index);

    if (!input.witness_utxo.IsNull()) {
        script = input.witness_utxo.scriptPubKey;
        return PSBTInputScriptLookup::OK;
    }

    if (input.non_witness_utxo) {
        if (txin.prevout.n >= input.non_witness_utxo->vout.size()) {
            return PSBTInputScriptLookup::INVALID_PREVOUT;
        }
        script = input.non_witness_utxo->vout[txin.prevout.n].scriptPubKey;
        return PSBTInputScriptLookup::OK;
    }

    return PSBTInputScriptLookup::MISSING;
}

SigningResult DescriptorScriptPubKeyMan::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(GetScriptForDestination(pkhash), true);
    if (!keys) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    CKey key;
    if (!keys->GetKey(ToKeyID(pkhash), key)) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    if (!MessageSign(key, message, str_sig)) {
        return SigningResult::SIGNING_FAILED;
    }
    return SigningResult::OK;
}

static const std::vector<unsigned char>* FindValidP2MRDataProofControlBlock(
    const std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>& control_blocks,
    std::span<const unsigned char> script_bytes,
    int leaf_version,
    const WitnessV2P2MR& output,
    const std::optional<std::vector<unsigned char>>& requested_control_block)
{
    if (leaf_version < 0 || leaf_version > 0xff) return nullptr;

    const uint256 leaf_hash = ComputeP2MRLeafHash(static_cast<uint8_t>(leaf_version), script_bytes);
    for (const auto& control_block : control_blocks) {
        if (requested_control_block && control_block != *requested_control_block) continue;
        if (control_block.size() < P2MR_CONTROL_BASE_SIZE || control_block.size() > P2MR_CONTROL_MAX_SIZE ||
            ((control_block.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
            continue;
        }
        if ((control_block.front() & 1) == 0) continue;
        if ((control_block.front() & TAPROOT_LEAF_MASK) != leaf_version) continue;
        if (ComputeP2MRMerkleRoot(control_block, leaf_hash) != output.GetMerkleRoot()) continue;
        return &control_block;
    }
    return nullptr;
}

util::Result<DataPQCSignatureProof> SignP2MRDataHash(
    const SigningProvider& provider,
    const WitnessV2P2MR& output,
    const uint256& message_hash,
    const std::optional<CPQCPubKey>& requested_pubkey,
    const std::optional<CScript>& requested_leaf_script,
    const std::optional<std::vector<unsigned char>>& requested_control_block)
{
    P2MRSpendData spenddata;
    TaprootBuilder builder;
    if (provider.GetP2MRSpendData(output, spenddata)) {
        // Already populated.
    } else if (provider.GetP2MRBuilder(output, builder)) {
        spenddata.Merge(builder.GetP2MRSpendData());
    }

    if (spenddata.scripts.empty()) {
        return util::Error{_("P2MR spend data is not available for this address")};
    }

    bool found_matching_leaf{false};
    bool found_signable_key{false};
    bool found_exhausted_key{false};
    bool signing_failed{false};
    const std::vector<unsigned char> requested_leaf_bytes = requested_leaf_script ?
        std::vector<unsigned char>{requested_leaf_script->begin(), requested_leaf_script->end()} :
        std::vector<unsigned char>{};
    const uint256 datasig_hash = ComputeQbitDataSigPQCHash(std::span<const unsigned char>{message_hash.begin(), message_hash.end()});

    for (const auto& [key, control_blocks] : spenddata.scripts) {
        const auto& [script_bytes, leaf_version] = key;
        if (leaf_version != P2MR_LEAF_VERSION_V1) continue;
        if (requested_leaf_script && script_bytes != requested_leaf_bytes) continue;

        const CScript leaf_script{script_bytes.begin(), script_bytes.end()};
        const std::optional<CPQCPubKey> pubkey = p2mr::MatchPK(leaf_script);
        if (!pubkey) continue;
        if (requested_pubkey && *pubkey != *requested_pubkey) continue;

        const std::vector<unsigned char>* control_block = FindValidP2MRDataProofControlBlock(
            control_blocks, script_bytes, leaf_version, output, requested_control_block);
        if (!control_block) continue;

        found_matching_leaf = true;
        if (!provider.CanSignPQC(*pubkey)) {
            if (provider.IsPQCSignatureCounterExhausted(*pubkey)) found_exhausted_key = true;
            continue;
        }
        found_signable_key = true;

        std::vector<unsigned char> signature;
        if (!provider.SignPQC(*pubkey, datasig_hash, signature)) {
            signing_failed = true;
            continue;
        }

        DataPQCSignatureProof proof;
        proof.output = output;
        proof.message_hash = message_hash;
        proof.datasig_hash = datasig_hash;
        proof.pubkey = *pubkey;
        proof.signature = std::move(signature);
        proof.leaf_script = leaf_script;
        proof.control_block = *control_block;
        proof.leaf_version = static_cast<uint8_t>(leaf_version);
        return proof;
    }

    if (found_matching_leaf && found_exhausted_key && !found_signable_key) {
        return util::Error{_("PQC signature budget is exhausted for the selected P2MR pubkey leaf")};
    }
    if (found_matching_leaf && !found_signable_key) {
        return util::Error{_("Private key is not available for the selected P2MR pubkey leaf")};
    }
    if (signing_failed) {
        return util::Error{_("PQC data-hash signing failed")};
    }
    return util::Error{_("No supported single-key P2MR pubkey leaf was found for this address")};
}

util::Result<DataPQCSignatureProof> DescriptorScriptPubKeyMan::SignDataPQCHash(
    const WitnessV2P2MR& output,
    const uint256& message_hash,
    const std::optional<CPQCPubKey>& requested_pubkey,
    const std::optional<CScript>& requested_leaf_script,
    const std::optional<std::vector<unsigned char>>& requested_control_block,
    const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    const CScript script_pub_key = GetScriptForDestination(output);
    std::unique_ptr<FlatSigningProvider> provider = GetSigningProvider(script_pub_key, /*include_private=*/true, pqc_counter_observer);
    if (!provider) {
        return util::Error{_("P2MR address is not available in this wallet")};
    }

    return SignP2MRDataHash(*provider, output, message_hash, requested_pubkey, requested_leaf_script, requested_control_block);
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProviderForPSBTInput(const CScript& script, const PSBTInput& input, bool sign, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    auto keys = std::make_unique<FlatSigningProvider>();
    std::unique_ptr<FlatSigningProvider> script_keys = GetSigningProvider(script, /*include_private=*/sign, pqc_counter_observer);
    if (script_keys) {
        keys->Merge(std::move(*script_keys));
        return keys;
    }

    bool has_provider_data{false};
    std::vector<CPubKey> pubkeys;
    pubkeys.reserve(input.hd_keypaths.size() + 2);

    for (const auto& [pk, _] : input.hd_keypaths) {
        pubkeys.push_back(pk);
    }

    std::vector<std::vector<unsigned char>> sols;
    const TxoutType script_type = Solver(script, sols);
    if (script_type == TxoutType::WITNESS_V1_TAPROOT) {
        sols[0].insert(sols[0].begin(), 0x02);
        pubkeys.emplace_back(sols[0]);
        sols[0][0] = 0x03;
        pubkeys.emplace_back(sols[0]);
    }

    for (const auto& pk_pair : input.m_tap_bip32_paths) {
        const XOnlyPubKey& pubkey = pk_pair.first;
        for (unsigned char prefix : {0x02, 0x03}) {
            unsigned char b[33] = {prefix};
            std::copy(pubkey.begin(), pubkey.end(), b + 1);
            CPubKey fullpubkey;
            fullpubkey.Set(b, b + 33);
            pubkeys.push_back(fullpubkey);
        }
    }

    for (const auto& pubkey : pubkeys) {
        std::unique_ptr<FlatSigningProvider> pk_keys = GetSigningProvider(pubkey, pqc_counter_observer);
        if (pk_keys) {
            keys->Merge(std::move(*pk_keys));
            has_provider_data = true;
        }
    }

    if (script_type == TxoutType::WITNESS_V2_P2MR) {
        for (const auto& [leaf, _] : input.m_qbit_p2mr_scripts) {
            const CScript p2mr_script(leaf.first.begin(), leaf.first.end());
            for (const CPQCPubKey& pubkey : ExtractP2MRPubkeys(p2mr_script)) {
                std::unique_ptr<FlatSigningProvider> pqc_keys = GetSigningProvider(pubkey, pqc_counter_observer);
                if (pqc_keys) {
                    keys->Merge(std::move(*pqc_keys));
                    has_provider_data = true;
                }
            }
        }
    }

    if (!has_provider_data) return nullptr;
    return keys;
}

std::optional<PSBTSigningProvider> DescriptorScriptPubKeyMan::GetSigningProviderForPSBT(const PartiallySignedTransaction& psbtx, bool sign, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    auto keys = std::make_unique<FlatSigningProvider>();
    std::set<unsigned int> input_indexes;
    bool has_provider_data{false};

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        CScript script;
        if (GetPSBTInputScript(psbtx, i, script) != PSBTInputScriptLookup::OK) {
            continue;
        }

        if (std::unique_ptr<FlatSigningProvider> input_keys = GetSigningProviderForPSBTInput(script, input, sign, pqc_counter_observer)) {
            keys->Merge(std::move(*input_keys));
            input_indexes.insert(i);
            has_provider_data = true;
        }
    }

    for (const CTxOut& txout : psbtx.tx->vout) {
        std::unique_ptr<FlatSigningProvider> output_keys = GetSigningProvider(txout.scriptPubKey, /*include_private=*/false);
        if (output_keys) {
            keys->Merge(std::move(*output_keys));
            has_provider_data = true;
        }
    }

    if (!has_provider_data) return std::nullopt;
    return PSBTSigningProvider{std::move(keys), std::move(input_indexes)};
}

std::optional<PSBTError> DescriptorScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize, const PQCSignatureCounterObserver& pqc_counter_observer) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        const PSBTInputScriptLookup script_lookup{GetPSBTInputScript(psbtx, i, script)};
        if (script_lookup == PSBTInputScriptLookup::INVALID_PREVOUT) {
            return PSBTError::MISSING_INPUTS;
        }
        if (script_lookup == PSBTInputScriptLookup::MISSING) {
            continue;
        }

        std::unique_ptr<FlatSigningProvider> keys = GetSigningProviderForPSBTInput(script, input, sign, pqc_counter_observer);
        if (!keys) keys = std::make_unique<FlatSigningProvider>();

        PSBTError res = SignPSBTInput(HidingSigningProvider(keys.get(), /*hide_secret=*/!sign, /*hide_origin=*/!bip32derivs), psbtx, i, &txdata, sighash_type, nullptr, finalize);
        if (res != PSBTError::OK && res != PSBTError::INCOMPLETE) {
            return res;
        }

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // Fill in the bip32 keypaths and redeemscripts for the outputs so that hardware wallets can identify change
    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        std::unique_ptr<SigningProvider> keys = GetSolvingProvider(psbtx.tx->vout.at(i).scriptPubKey);
        if (!keys) {
            continue;
        }
        UpdatePSBTOutput(HidingSigningProvider(keys.get(), /*hide_secret=*/true, /*hide_origin=*/!bip32derivs), psbtx, i);
    }

    return {};
}

std::unique_ptr<CKeyMetadata> DescriptorScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    std::unique_ptr<SigningProvider> provider = GetSigningProvider(GetScriptForDestination(dest));
    if (provider) {
        KeyOriginInfo orig;
        CKeyID key_id = GetKeyForDestination(*provider, dest);
        if (provider->GetKeyOrigin(key_id, orig)) {
            LOCK(cs_desc_man);
            std::unique_ptr<CKeyMetadata> meta = std::make_unique<CKeyMetadata>();
            meta->key_origin = orig;
            meta->has_key_origin = true;
            meta->nCreateTime = m_wallet_descriptor.creation_time;
            return meta;
        }
    }
    return nullptr;
}

std::optional<uint32_t> DescriptorScriptPubKeyMan::GetPQCSignatureCounter(const CPQCPubKey& pubkey) const
{
    LOCK(cs_desc_man);
    const bool have_local_key = m_map_pqc_keys.contains(pubkey) || m_map_crypted_pqc_keys.contains(pubkey) ||
                                m_pending_plaintext_pqc_keys.contains(pubkey) || m_failed_plaintext_pqc_keys.contains(pubkey);
    if (!have_local_key) {
        return std::nullopt;
    }
    if (const auto counter_it = m_map_pqc_sig_counters.find(pubkey); counter_it != m_map_pqc_sig_counters.end()) {
        return counter_it->second;
    }
    return 0;
}

uint256 DescriptorScriptPubKeyMan::GetID() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.id;
}

void DescriptorScriptPubKeyMan::SetCache(const DescriptorCache& cache)
{
    LOCK(cs_desc_man);
    std::set<CScript> new_spks;
    m_wallet_descriptor.cache = cache;
    for (int32_t i = m_wallet_descriptor.range_start; i < m_wallet_descriptor.range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            throw std::runtime_error("Error: Unable to expand wallet descriptor from cache");
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            if (m_map_script_pub_keys.count(script) != 0) {
                throw std::runtime_error(strprintf("Error: Already loaded script at index %d as being at index %d", i, m_map_script_pub_keys[script]));
            }
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and its private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        m_max_cached_index++;
    }
    // Make sure the wallet knows about our new spks
    m_storage.TopUpCallback(new_spks, this);
}

bool DescriptorScriptPubKeyMan::AddKey(const CKeyID& key_id, const CKey& key)
{
    LOCK(cs_desc_man);
    m_map_keys[key_id] = key;
    return true;
}

bool DescriptorScriptPubKeyMan::AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    m_map_crypted_keys[key_id] = make_pair(pubkey, crypted_key);
    return true;
}

bool DescriptorScriptPubKeyMan::AddPQCKey(const CPQCPubKey& pubkey, const CPQCKey& key, uint32_t sig_counter)
{
    LOCK(cs_desc_man);
    if (!m_map_crypted_pqc_keys.empty()) {
        return false;
    }
    m_map_pqc_keys[pubkey] = key;
    m_map_pqc_sig_counters[pubkey] = sig_counter;
    return true;
}

bool DescriptorScriptPubKeyMan::AddPendingPlaintextPQCKey(const CPQCPubKey& pubkey, CKeyingMaterial secret, uint32_t sig_counter)
{
    LOCK(cs_desc_man);
    if (m_map_pqc_keys.contains(pubkey) || m_pending_plaintext_pqc_keys.contains(pubkey)) {
        return false;
    }
    m_failed_plaintext_pqc_keys.erase(pubkey);
    m_pending_plaintext_pqc_keys.emplace(pubkey, PendingPlaintextPQCKey{std::move(secret), sig_counter});
    m_map_pqc_sig_counters[pubkey] = sig_counter;
    return true;
}

std::optional<std::pair<CPQCPubKey, PendingPlaintextPQCKey>> DescriptorScriptPubKeyMan::GetNextPendingPlaintextPQCKey() const
{
    LOCK(cs_desc_man);
    if (m_pending_plaintext_pqc_keys.empty()) return std::nullopt;
    const auto& [pubkey, pending_key] = *m_pending_plaintext_pqc_keys.begin();
    return std::make_pair(pubkey, pending_key);
}

bool DescriptorScriptPubKeyMan::CompletePendingPlaintextPQCKeyValidation(const CPQCPubKey& pubkey, const CPQCKey& key, uint32_t sig_counter)
{
    LOCK(cs_desc_man);
    const auto pending_it = m_pending_plaintext_pqc_keys.find(pubkey);
    if (pending_it == m_pending_plaintext_pqc_keys.end()) {
        return false;
    }
    if (!m_map_crypted_pqc_keys.contains(pubkey)) {
        m_map_pqc_keys[pubkey] = key;
        m_map_pqc_sig_counters[pubkey] = sig_counter;
    }
    m_pending_plaintext_pqc_keys.erase(pending_it);
    m_failed_plaintext_pqc_keys.erase(pubkey);
    return true;
}

bool DescriptorScriptPubKeyMan::FailPendingPlaintextPQCKeyValidation(const CPQCPubKey& pubkey)
{
    LOCK(cs_desc_man);
    const auto pending_it = m_pending_plaintext_pqc_keys.find(pubkey);
    if (pending_it == m_pending_plaintext_pqc_keys.end()) {
        return false;
    }
    m_pending_plaintext_pqc_keys.erase(pending_it);
    m_failed_plaintext_pqc_keys.insert(pubkey);
    return true;
}

bool DescriptorScriptPubKeyMan::AddCryptedPQCKey(const CPQCPubKey& pubkey, const std::vector<unsigned char>& crypted_key, uint32_t sig_counter, std::optional<uint256> auth_tag)
{
    LOCK(cs_desc_man);
    if (!m_map_pqc_keys.empty()) {
        return false;
    }

    m_map_crypted_pqc_keys[pubkey] = CryptedPQCKeyRecord{crypted_key, auth_tag};
    m_map_pqc_sig_counters[pubkey] = sig_counter;
    return true;
}

std::vector<CPQCPubKey> DescriptorScriptPubKeyMan::GetPQCKeys() const
{
    LOCK(cs_desc_man);
    std::vector<CPQCPubKey> keys;
    keys.reserve(m_map_pqc_keys.size() + m_map_crypted_pqc_keys.size() + m_pending_plaintext_pqc_keys.size());
    for (const auto& [pubkey, _] : m_map_pqc_keys) {
        keys.push_back(pubkey);
    }
    for (const auto& [pubkey, _] : m_map_crypted_pqc_keys) {
        keys.push_back(pubkey);
    }
    for (const auto& [pubkey, _] : m_pending_plaintext_pqc_keys) {
        if (m_map_pqc_keys.contains(pubkey) || m_map_crypted_pqc_keys.contains(pubkey)) continue;
        keys.push_back(pubkey);
    }
    return keys;
}

bool DescriptorScriptPubKeyMan::HasWalletDescriptor(const WalletDescriptor& desc) const
{
    LOCK(cs_desc_man);
    return !m_wallet_descriptor.id.IsNull() && !desc.id.IsNull() && m_wallet_descriptor.id == desc.id;
}

void DescriptorScriptPubKeyMan::WriteDescriptor()
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }
}

WalletDescriptor DescriptorScriptPubKeyMan::GetWalletDescriptor() const
{
    return m_wallet_descriptor;
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys() const
{
    return GetScriptPubKeys(0);
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys(int32_t minimum_index) const
{
    LOCK(cs_desc_man);
    std::unordered_set<CScript, SaltedSipHasher> script_pub_keys;
    script_pub_keys.reserve(m_map_script_pub_keys.size());

    for (auto const& [script_pub_key, index] : m_map_script_pub_keys) {
        if (index >= minimum_index) script_pub_keys.insert(script_pub_key);
    }
    return script_pub_keys;
}

int32_t DescriptorScriptPubKeyMan::GetEndRange() const
{
    return m_max_cached_index + 1;
}

bool DescriptorScriptPubKeyMan::GetDescriptorString(std::string& out, const bool priv) const
{
    FlatSigningProvider provider;
    provider.keys = GetKeys();

    LOCK(cs_desc_man);

    if (priv) {
        // For the private version, always return the master key to avoid
        // exposing child private keys. The risk implications of exposing child
        // private keys together with the parent xpub may be non-obvious for users.
        return m_wallet_descriptor.descriptor->ToPrivateString(provider, out);
    }

    return m_wallet_descriptor.descriptor->ToNormalizedString(provider, out, &m_wallet_descriptor.cache);
}

void DescriptorScriptPubKeyMan::UpgradeDescriptorCache()
{
    if (m_storage.IsLocked() || m_storage.IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    LOCK(cs_desc_man);
    // Skip if we have the last hardened xpub cache
    if (m_wallet_descriptor.cache.GetCachedLastHardenedExtPubKeys().size() > 0) {
        return;
    }

    // Expand the descriptor
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts_temp;
    DescriptorCache temp_cache;
    if (!m_wallet_descriptor.descriptor->Expand(0, provider, scripts_temp, out_keys, &temp_cache)){
        throw std::runtime_error("Unable to expand descriptor");
    }

    // Cache the last hardened xpubs
    DescriptorCache diff = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
    if (!WalletBatch(m_storage.GetDatabase()).WriteDescriptorCacheItems(GetID(), diff)) {
        throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
    }
}

util::Result<void> DescriptorScriptPubKeyMan::UpdateWalletDescriptor(WalletDescriptor& descriptor)
{
    LOCK(cs_desc_man);
    std::string error;
    if (!CanUpdateToWalletDescriptor(descriptor, error)) {
        return util::Error{Untranslated(std::move(error))};
    }

    m_map_pubkeys.clear();
    m_map_script_pub_keys.clear();
    m_max_cached_index = -1;
    m_wallet_descriptor = descriptor;

    NotifyFirstKeyTimeChanged(this, m_wallet_descriptor.creation_time);
    return {};
}

bool DescriptorScriptPubKeyMan::CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error)
{
    LOCK(cs_desc_man);
    if (!HasWalletDescriptor(descriptor)) {
        error = "can only update matching descriptor";
        return false;
    }

    if (!descriptor.descriptor->IsRange()) {
        // Skip range check for non-range descriptors
        return true;
    }

    if (descriptor.range_start > m_wallet_descriptor.range_start ||
        descriptor.range_end < m_wallet_descriptor.range_end) {
        // Use inclusive range for error
        error = strprintf("new range must include current range = [%d,%d]",
                          m_wallet_descriptor.range_start,
                          m_wallet_descriptor.range_end - 1);
        return false;
    }

    return true;
}
} // namespace wallet
