// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <key.h>
#include <logging.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/keyorigin.h>
#include <script/miniscript.h>
#include <script/p2mr.h>
#include <script/p2mr_sizing.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/signing_timing.h>
#include <util/thread.h>
#include <util/time.h>
#include <util/translation.h>
#include <util/vector.h>

#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <optional>
#include <thread>

typedef std::vector<unsigned char> valtype;

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount}, checker{&m_txto, nIn, amount, MissingDataBehavior::FAIL},
      m_txdata(nullptr)
{
}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type)
    : m_txto{tx}, nIn{input_idx}, nHashType{hash_type}, amount{amount},
      checker{txdata ? MutableTransactionSignatureChecker{&m_txto, nIn, amount, *txdata, MissingDataBehavior::FAIL} :
                       MutableTransactionSignatureChecker{&m_txto, nIn, amount, MissingDataBehavior::FAIL}},
      m_txdata(txdata)
{
}

bool MutableTransactionSignatureCreator::CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0);

    CKey key;
    if (!provider.GetKey(address, key))
        return false;

    // Signing with uncompressed keys is disabled in witness scripts
    if (sigversion == SigVersion::WITNESS_V0 && !key.IsCompressed())
        return false;

    // Signing without known amount does not work in witness scripts.
    if (sigversion == SigVersion::WITNESS_V0 && !MoneyRange(amount)) return false;

    // BASE/WITNESS_V0 signatures don't support explicit SIGHASH_DEFAULT, use SIGHASH_ALL instead.
    const int hashtype = nHashType == SIGHASH_DEFAULT ? SIGHASH_ALL : nHashType;

    uint256 hash = SignatureHash(scriptCode, m_txto, nIn, hashtype, amount, sigversion, m_txdata);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)hashtype);
    return true;
}

bool MutableTransactionSignatureCreator::CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    CKey key;
    if (!provider.GetKeyByXOnly(pubkey, key)) return false;

    // BIP341/BIP342 signing needs lots of precomputed transaction data. While some
    // (non-SIGHASH_DEFAULT) sighash modes exist that can work with just some subset
    // of data present, for now, only support signing when everything is provided.
    if (!m_txdata || !m_txdata->m_bip341_taproot_ready || !m_txdata->m_spent_outputs_ready) return false;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.
    if (sigversion == SigVersion::TAPSCRIPT) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        if (!leaf_hash) return false; // BIP342 signing needs leaf hash.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = *leaf_hash;
    }
    uint256 hash;
    if (!SignatureHashSchnorr(hash, execdata, m_txto, nIn, nHashType, sigversion, *m_txdata, MissingDataBehavior::FAIL)) return false;
    sig.resize(64);
    // Use uint256{} as aux_rnd for now.
    if (!key.SignSchnorr(hash, sig, merkle_root, {})) return false;
    if (nHashType) sig.push_back(nHashType);
    return true;
}

bool MutableTransactionSignatureCreator::CreatePQCSignatureHash(uint256& hash, const uint256& leaf_hash, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::P2MR);

    if (!m_txdata || !m_txdata->m_bip341_taproot_ready || !m_txdata->m_spent_outputs_ready) return false;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false; // Only support annex-less signing for now.
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR signing for now.
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_hash;

    return SignatureHashP2MR(hash, execdata, m_txto, nIn, nHashType, *m_txdata, MissingDataBehavior::FAIL);
}

bool MutableTransactionSignatureCreator::CreatePQCSignature(const SigningProvider& provider, std::vector<unsigned char>& sig, const CPQCPubKey& pubkey, const uint256* leaf_hash, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::P2MR);
    if (!leaf_hash) return false;

    uint256 hash;
    if (!CreatePQCSignatureHash(hash, *leaf_hash, sigversion)) return false;

    std::vector<unsigned char> raw_sig;
    if (!provider.SignPQC(pubkey, hash, raw_sig)) return false;
    sig = std::move(raw_sig);
    if (nHashType) sig.push_back(nHashType);
    return true;
}

bool MutableTransactionSignatureCreator::CanCreatePQCSignature(const SigningProvider& provider, const CPQCPubKey& pubkey) const
{
    return provider.CanSignPQC(pubkey);
}

bool MutableTransactionSignatureCreator::VerifyP2MRScriptSignature(std::span<const unsigned char> sig, const CPQCPubKey& pubkey, const uint256& leaf_hash, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::P2MR);
    if (!m_txdata ||
        !m_txdata->m_bip341_taproot_ready ||
        !m_txdata->m_spent_outputs_ready) return true;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_hash;
    return checker.CheckPQCSignature(sig, std::span{pubkey.data(), pubkey.size()}, sigversion, execdata);
}

size_t MutableTransactionSignatureCreator::P2MRSignatureSize() const
{
    return PQC_SIG_SIZE + (nHashType ? 1 : 0);
}

static bool GetCScript(const SigningProvider& provider, const SignatureData& sigdata, const CScriptID& scriptid, CScript& script)
{
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    } else if (CScriptID(sigdata.witness_script) == scriptid) {
        script = sigdata.witness_script;
        return true;
    }
    return false;
}

static bool GetPubKey(const SigningProvider& provider, const SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey lists
    const auto& pk_it = sigdata.misc_pubkeys.find(address);
    if (pk_it != sigdata.misc_pubkeys.end()) {
        pubkey = pk_it->second.first;
        return true;
    }
    const auto& tap_pk_it = sigdata.tap_pubkeys.find(address);
    if (tap_pk_it != sigdata.tap_pubkeys.end()) {
        pubkey = tap_pk_it->second.GetEvenCorrespondingCPubKey();
        return true;
    }
    // Query the underlying provider
    return provider.GetPubKey(address, pubkey);
}

static bool CreateSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPubKey& pubkey, const CScript& scriptcode, SigVersion sigversion)
{
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.find(keyid);
    if (it != sigdata.signatures.end()) {
        sig_out = it->second.second;
        return true;
    }
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(keyid, info)) {
        sigdata.misc_pubkeys.emplace(keyid, std::make_pair(pubkey, std::move(info)));
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        auto i = sigdata.signatures.emplace(keyid, SigPair(pubkey, sig_out));
        assert(i.second);
        return true;
    }
    // Could not make signature or signature not found, add keyid to missing
    sigdata.missing_sigs.push_back(keyid);
    return false;
}

static bool CreateTaprootScriptSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const XOnlyPubKey& pubkey, const uint256& leaf_hash, SigVersion sigversion)
{
    KeyOriginInfo info;
    if (provider.GetKeyOriginByXOnly(pubkey, info)) {
        auto it = sigdata.taproot_misc_pubkeys.find(pubkey);
        if (it == sigdata.taproot_misc_pubkeys.end()) {
            sigdata.taproot_misc_pubkeys.emplace(pubkey, std::make_pair(std::set<uint256>({leaf_hash}), info));
        } else {
            it->second.first.insert(leaf_hash);
        }
    }

    auto lookup_key = std::make_pair(pubkey, leaf_hash);
    auto it = sigdata.taproot_script_sigs.find(lookup_key);
    if (it != sigdata.taproot_script_sigs.end()) {
        sig_out = it->second;
        return true;
    }
    if (creator.CreateSchnorrSig(provider, sig_out, pubkey, &leaf_hash, nullptr, sigversion)) {
        sigdata.taproot_script_sigs[lookup_key] = sig_out;
        return true;
    }
    return false;
}

static const std::vector<unsigned char>* LookupValidP2MRScriptSig(const SignatureData& sigdata, const BaseSignatureCreator& creator, const CPQCPubKey& pubkey, const uint256& leaf_hash, bool* invalid_cached_sig = nullptr)
{
    if (invalid_cached_sig) *invalid_cached_sig = false;
    auto lookup_key = std::make_pair(pubkey, leaf_hash);
    auto it = sigdata.p2mr_script_sigs.find(lookup_key);
    if (it == sigdata.p2mr_script_sigs.end()) return nullptr;

    uint8_t hashtype;
    if (!GetP2MRSignatureHashType(it->second, hashtype) ||
        !creator.VerifyP2MRScriptSignature(it->second, pubkey, leaf_hash, SigVersion::P2MR)) {
        if (invalid_cached_sig) *invalid_cached_sig = true;
        return nullptr;
    }
    return &it->second;
}

static void AddUniqueP2MRPubKey(std::vector<CPQCPubKey>& pubkeys, const CPQCPubKey& pubkey)
{
    if (std::find(pubkeys.begin(), pubkeys.end(), pubkey) == pubkeys.end()) {
        pubkeys.push_back(pubkey);
    }
}

static void AddMissingP2MRScriptSig(SignatureData& sigdata, const CPQCPubKey& pubkey)
{
    AddUniqueP2MRPubKey(sigdata.missing_p2mr_sigs, pubkey);
}

static void AddInvalidP2MRScriptSig(SignatureData& sigdata, const CPQCPubKey& pubkey)
{
    AddUniqueP2MRPubKey(sigdata.invalid_p2mr_sigs, pubkey);
}

static bool CreateP2MRScriptSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPQCPubKey& pubkey, const uint256& leaf_hash, SigVersion sigversion)
{
    bool invalid_cached_sig{false};
    if (const auto* cached_sig = LookupValidP2MRScriptSig(sigdata, creator, pubkey, leaf_hash, &invalid_cached_sig)) {
        sig_out = *cached_sig;
        return true;
    }
    if (invalid_cached_sig) {
        AddInvalidP2MRScriptSig(sigdata, pubkey);
        return false;
    }
    if (creator.CreatePQCSignature(provider, sig_out, pubkey, &leaf_hash, sigversion)) {
        sigdata.p2mr_script_sigs[std::make_pair(pubkey, leaf_hash)] = sig_out;
        return true;
    }
    AddMissingP2MRScriptSig(sigdata, pubkey);
    return false;
}

static bool ParseP2MRScript(std::span<const unsigned char> script_bytes, std::vector<CPQCPubKey>& pubkeys, int& threshold)
{
    constexpr unsigned char PUBKEY_PUSH_SIZE = static_cast<unsigned char>(CPQCPubKey::SIZE);
    constexpr size_t PK_SCRIPT_SIZE = 1 + CPQCPubKey::SIZE + 1; // <pushlen><pubkey><checksig op>

    pubkeys.clear();
    threshold = 0;

    // Recognize pk(KEY): <32-byte key> OP_CHECKSIGPQC
    if (script_bytes.size() == PK_SCRIPT_SIZE && script_bytes[0] == PUBKEY_PUSH_SIZE && script_bytes[CPQCPubKey::SIZE + 1] == OP_CHECKSIGPQC) {
        CPQCPubKey key{script_bytes.subspan(1, CPQCPubKey::SIZE)};
        if (!key.IsValid()) return false;
        pubkeys.emplace_back(key);
        threshold = 1;
        return true;
    }

    CScript script(script_bytes.begin(), script_bytes.end());
    const auto multi_a = p2mr::MatchMultiA(script);
    if (!multi_a) return false;

    pubkeys.reserve(multi_a->keyspans.size());
    for (const auto keyspan : multi_a->keyspans) {
        CPQCPubKey key{keyspan};
        if (!key.IsValid()) return false;
        pubkeys.emplace_back(key);
    }
    threshold = multi_a->threshold;
    return true;
}

template<typename M, typename K, typename V>
miniscript::Availability MsLookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return miniscript::Availability::YES;
    }
    return miniscript::Availability::NO;
}

/**
 * Context for solving a Miniscript.
 * If enough material (access to keys, hash preimages, ..) is given, produces a valid satisfaction.
 */
template<typename Pk>
struct Satisfier {
    using Key = Pk;

    const SigningProvider& m_provider;
    SignatureData& m_sig_data;
    const BaseSignatureCreator& m_creator;
    const CScript& m_witness_script;
    //! The context of the script we are satisfying (either P2WSH or Tapscript).
    const miniscript::MiniscriptContext m_script_ctx;

    explicit Satisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                       const BaseSignatureCreator& creator LIFETIMEBOUND,
                       const CScript& witscript LIFETIMEBOUND,
                       miniscript::MiniscriptContext script_ctx) : m_provider(provider),
                                                                   m_sig_data(sig_data),
                                                                   m_creator(creator),
                                                                   m_witness_script(witscript),
                                                                   m_script_ctx(script_ctx) {}

    static bool KeyCompare(const Key& a, const Key& b) {
        return a < b;
    }

    //! Get a CPubKey from a key hash. Note the key hash may be of an xonly pubkey.
    template<typename I>
    std::optional<CPubKey> CPubFromPKHBytes(I first, I last) const {
        assert(last - first == 20);
        CPubKey pubkey;
        CKeyID key_id;
        std::copy(first, last, key_id.begin());
        if (GetPubKey(m_provider, m_sig_data, key_id, pubkey)) return pubkey;
        m_sig_data.missing_pubkeys.push_back(key_id);
        return {};
    }

    //! Conversion to raw public key.
    std::vector<unsigned char> ToPKBytes(const Key& key) const { return {key.begin(), key.end()}; }

    //! Time lock satisfactions.
    bool CheckAfter(uint32_t value) const { return m_creator.Checker().CheckLockTime(CScriptNum(value)); }
    bool CheckOlder(uint32_t value) const { return m_creator.Checker().CheckSequence(CScriptNum(value)); }

    //! Hash preimage satisfactions.
    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.sha256_preimages, hash, preimage);
    }
    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.ripemd160_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash256_preimages, hash, preimage);
    }
    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const {
        return MsLookupHelper(m_sig_data.hash160_preimages, hash, preimage);
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

/** Miniscript satisfier specific to P2WSH context. */
struct WshSatisfier: Satisfier<CPubKey> {
    explicit WshSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& witscript LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator, witscript, miniscript::MiniscriptContext::P2WSH) {}

    //! Conversion from a raw compressed public key.
    template <typename I>
    std::optional<CPubKey> FromPKBytes(I first, I last) const {
        CPubKey pubkey{first, last};
        if (pubkey.IsValid()) return pubkey;
        return {};
    }

    //! Conversion from a raw compressed public key hash.
    template<typename I>
    std::optional<CPubKey> FromPKHBytes(I first, I last) const {
        return Satisfier::CPubFromPKHBytes(first, last);
    }

    //! Satisfy an ECDSA signature check.
    miniscript::Availability Sign(const CPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateSig(m_creator, m_sig_data, m_provider, sig, key, m_witness_script, SigVersion::WITNESS_V0)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

/** Miniscript satisfier specific to Tapscript context. */
struct TapSatisfier: Satisfier<XOnlyPubKey> {
    const uint256& m_leaf_hash;

    explicit TapSatisfier(const SigningProvider& provider LIFETIMEBOUND, SignatureData& sig_data LIFETIMEBOUND,
                          const BaseSignatureCreator& creator LIFETIMEBOUND, const CScript& script LIFETIMEBOUND,
                          const uint256& leaf_hash LIFETIMEBOUND)
                          : Satisfier(provider, sig_data, creator, script, miniscript::MiniscriptContext::TAPSCRIPT),
                            m_leaf_hash(leaf_hash) {}

    //! Conversion from a raw xonly public key.
    template <typename I>
    std::optional<XOnlyPubKey> FromPKBytes(I first, I last) const {
        if (last - first != 32) return {};
        XOnlyPubKey pubkey;
        std::copy(first, last, pubkey.begin());
        return pubkey;
    }

    //! Conversion from a raw xonly public key hash.
    template<typename I>
    std::optional<XOnlyPubKey> FromPKHBytes(I first, I last) const {
        if (auto pubkey = Satisfier::CPubFromPKHBytes(first, last)) return XOnlyPubKey{*pubkey};
        return {};
    }

    //! Satisfy a BIP340 signature check.
    miniscript::Availability Sign(const XOnlyPubKey& key, std::vector<unsigned char>& sig) const {
        if (CreateTaprootScriptSig(m_creator, m_sig_data, m_provider, sig, key, m_leaf_hash, SigVersion::TAPSCRIPT)) {
            return miniscript::Availability::YES;
        }
        return miniscript::Availability::NO;
    }
};

static bool SignTaprootScript(const SigningProvider& provider, const BaseSignatureCreator& creator, SignatureData& sigdata, int leaf_version, std::span<const unsigned char> script_bytes, std::vector<valtype>& result)
{
    // Only BIP342 tapscript signing is supported for now.
    if (leaf_version != TAPROOT_LEAF_TAPSCRIPT) return false;

    uint256 leaf_hash = ComputeTapleafHash(leaf_version, script_bytes);
    CScript script = CScript(script_bytes.begin(), script_bytes.end());

    TapSatisfier ms_satisfier{provider, sigdata, creator, script, leaf_hash};
    const auto ms = miniscript::FromScript(script, ms_satisfier);
    return ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
}

struct P2MRScriptSigningPlan {
    std::vector<unsigned char> script;
    std::vector<unsigned char> control_block;
    std::vector<CPQCPubKey> pubkeys;
    std::vector<bool> candidate_pubkeys;
    uint256 leaf_hash;
    int threshold{0};
    int missing_signatures{0};
    int new_signatures{0};
    bool complete{false};
    size_t witness_size{0};
};

static bool BuildP2MRScriptSigningPlan(const SigningProvider& provider, const BaseSignatureCreator& creator, SignatureData& sigdata, int leaf_version, std::span<const unsigned char> script_bytes, const std::vector<unsigned char>& control_block, P2MRScriptSigningPlan& plan)
{
    // Pre-activation, signing/finalization stays pinned to P2MR v1 leaves only.
    if (leaf_version != P2MR_LEAF_VERSION_V1) return false;

    std::vector<CPQCPubKey> pubkeys;
    int threshold{0};
    if (!ParseP2MRScript(script_bytes, pubkeys, threshold)) return false;

    const uint256 leaf_hash = ComputeP2MRLeafHash(leaf_version, script_bytes);
    std::vector<bool> candidate_pubkeys(pubkeys.size(), false);
    int num_candidates{0};
    int num_cached_signatures{0};

    bool has_invalid_cached_sig{false};
    for (const auto& pubkey : pubkeys) {
        bool invalid_cached_sig{false};
        LookupValidP2MRScriptSig(sigdata, creator, pubkey, leaf_hash, &invalid_cached_sig);
        if (invalid_cached_sig) {
            AddInvalidP2MRScriptSig(sigdata, pubkey);
            has_invalid_cached_sig = true;
        }
    }
    if (has_invalid_cached_sig) return false;

    for (size_t index = 0; index < pubkeys.size(); ++index) {
        if (LookupValidP2MRScriptSig(sigdata, creator, pubkeys[index], leaf_hash) != nullptr) {
            candidate_pubkeys[index] = true;
            ++num_candidates;
            ++num_cached_signatures;
        } else if (creator.CanCreatePQCSignature(provider, pubkeys[index])) {
            candidate_pubkeys[index] = true;
            ++num_candidates;
        }
    }
    if (num_candidates < threshold) {
        for (const auto& pubkey : pubkeys) {
            if (LookupValidP2MRScriptSig(sigdata, creator, pubkey, leaf_hash) == nullptr &&
                !creator.CanCreatePQCSignature(provider, pubkey)) {
                AddMissingP2MRScriptSig(sigdata, pubkey);
            }
        }
        if (num_candidates == 0) return false;
    }

    std::vector<valtype> estimated_stack;
    estimated_stack.reserve(pubkeys.size() + 2);
    // Witness element order must be reverse-key-order to satisfy CHECKSIGADD stack semantics.
    int num_estimated_signatures{0};
    for (size_t i = pubkeys.size(); i > 0; --i) {
        const size_t index{i - 1};
        if (!candidate_pubkeys[index] || num_estimated_signatures >= threshold) {
            estimated_stack.emplace_back();
        } else if (const auto* cached_sig = LookupValidP2MRScriptSig(sigdata, creator, pubkeys[index], leaf_hash)) {
            estimated_stack.push_back(*cached_sig);
            ++num_estimated_signatures;
        } else {
            estimated_stack.emplace_back(creator.P2MRSignatureSize(), 0);
            ++num_estimated_signatures;
        }
    }
    estimated_stack.emplace_back(script_bytes.begin(), script_bytes.end());
    estimated_stack.push_back(control_block);

    plan.script.assign(script_bytes.begin(), script_bytes.end());
    plan.control_block = control_block;
    plan.pubkeys = std::move(pubkeys);
    plan.candidate_pubkeys = std::move(candidate_pubkeys);
    plan.leaf_hash = leaf_hash;
    plan.threshold = threshold;
    plan.complete = num_candidates >= threshold;
    plan.missing_signatures = std::max(0, threshold - num_candidates);
    plan.new_signatures = std::max(0, std::min(threshold, num_candidates) - num_cached_signatures);
    plan.witness_size = GetSerializeSize(estimated_stack);
    return true;
}

static int SignP2MRScript(const SigningProvider& provider, const BaseSignatureCreator& creator, SignatureData& sigdata, const P2MRScriptSigningPlan& plan, std::vector<valtype>& result)
{
    int num_signed{0};

    result.clear();
    result.reserve(plan.pubkeys.size());
    for (size_t i = plan.pubkeys.size(); i > 0; --i) {
        const size_t index{i - 1};
        if (!plan.candidate_pubkeys[index] || num_signed >= plan.threshold) {
            result.emplace_back();
            continue;
        }
        std::vector<unsigned char> sig;
        if (CreateP2MRScriptSig(creator, sigdata, provider, sig, plan.pubkeys[index], plan.leaf_hash, SigVersion::P2MR)) {
            ++num_signed;
            result.push_back(std::move(sig));
        } else {
            result.emplace_back();
        }
    }

    return num_signed;
}

static const std::vector<unsigned char>* FindValidP2MRControlBlock(const std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>& control_blocks, std::span<const unsigned char> script_bytes, int leaf_version, const WitnessV2P2MR& output)
{
    if (leaf_version < 0 || leaf_version > 0xff) return nullptr;

    const uint256 leaf_hash = ComputeP2MRLeafHash(leaf_version, script_bytes);
    const uint256 merkle_root{std::span<const unsigned char>(output)};

    for (const auto& control_block : control_blocks) {
        if (control_block.size() < P2MR_CONTROL_BASE_SIZE || control_block.size() > P2MR_CONTROL_MAX_SIZE ||
            ((control_block.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
            continue;
        }
        if ((control_block[0] & 1) == 0) continue;
        if ((control_block[0] & TAPROOT_LEAF_MASK) != leaf_version) continue;
        if (ComputeP2MRMerkleRoot(control_block, leaf_hash) != merkle_root) continue;
        return &control_block;
    }

    return nullptr;
}

static bool SignTaproot(const SigningProvider& provider, const BaseSignatureCreator& creator, const WitnessV1Taproot& output, SignatureData& sigdata, std::vector<valtype>& result)
{
    TaprootSpendData spenddata;
    TaprootBuilder builder;

    // Gather information about this output.
    if (provider.GetTaprootSpendData(output, spenddata)) {
        sigdata.tr_spenddata.Merge(spenddata);
    }
    if (provider.GetTaprootBuilder(output, builder)) {
        sigdata.tr_builder = builder;
    }

    // Try key path spending.
    {
        KeyOriginInfo info;
        if (provider.GetKeyOriginByXOnly(sigdata.tr_spenddata.internal_key, info)) {
            auto it = sigdata.taproot_misc_pubkeys.find(sigdata.tr_spenddata.internal_key);
            if (it == sigdata.taproot_misc_pubkeys.end()) {
                sigdata.taproot_misc_pubkeys.emplace(sigdata.tr_spenddata.internal_key, std::make_pair(std::set<uint256>(), info));
            }
        }

        std::vector<unsigned char> sig;
        if (sigdata.taproot_key_path_sig.size() == 0) {
            if (creator.CreateSchnorrSig(provider, sig, sigdata.tr_spenddata.internal_key, nullptr, &sigdata.tr_spenddata.merkle_root, SigVersion::TAPROOT)) {
                sigdata.taproot_key_path_sig = sig;
            }
        }
        if (sigdata.taproot_key_path_sig.size() == 0) {
            if (creator.CreateSchnorrSig(provider, sig, output, nullptr, nullptr, SigVersion::TAPROOT)) {
                sigdata.taproot_key_path_sig = sig;
            }
        }
        if (sigdata.taproot_key_path_sig.size()) {
            result = Vector(sigdata.taproot_key_path_sig);
            return true;
        }
    }

    // Try script path spending.
    std::vector<std::vector<unsigned char>> smallest_result_stack;
    for (const auto& [key, control_blocks] : sigdata.tr_spenddata.scripts) {
        const auto& [script, leaf_ver] = key;
        std::vector<std::vector<unsigned char>> result_stack;
        if (SignTaprootScript(provider, creator, sigdata, leaf_ver, script, result_stack)) {
            result_stack.emplace_back(std::begin(script), std::end(script)); // Push the script
            result_stack.push_back(*control_blocks.begin()); // Push the smallest control block
            if (smallest_result_stack.size() == 0 ||
                GetSerializeSize(result_stack) < GetSerializeSize(smallest_result_stack)) {
                smallest_result_stack = std::move(result_stack);
            }
        }
    }
    if (smallest_result_stack.size() != 0) {
        result = std::move(smallest_result_stack);
        return true;
    }

    return false;
}

static bool SignP2MR(const SigningProvider& provider, const BaseSignatureCreator& creator, const WitnessV2P2MR& output, SignatureData& sigdata, std::vector<valtype>& result)
{
    P2MRSpendData spenddata;
    TaprootBuilder builder;

    if (provider.GetP2MRSpendData(output, spenddata)) {
        sigdata.p2mr_spenddata.Merge(spenddata);
    }
    if (provider.GetP2MRBuilder(output, builder)) {
        sigdata.p2mr_builder = builder;
    }
    if (sigdata.p2mr_spenddata.scripts.empty() && sigdata.p2mr_builder.has_value()) {
        sigdata.p2mr_spenddata.Merge(sigdata.p2mr_builder->GetP2MRSpendData());
    }

    std::vector<P2MRScriptSigningPlan> complete_plans;
    std::vector<P2MRScriptSigningPlan> partial_plans;
    for (const auto& [key, control_blocks] : sigdata.p2mr_spenddata.scripts) {
        const auto& [script, leaf_ver] = key;
        const auto* control_block = FindValidP2MRControlBlock(control_blocks, script, leaf_ver, output);
        if (control_block == nullptr) continue;
        P2MRScriptSigningPlan plan;
        if (BuildP2MRScriptSigningPlan(provider, creator, sigdata, leaf_ver, script, *control_block, plan)) {
            if (plan.complete) {
                complete_plans.push_back(std::move(plan));
            } else {
                partial_plans.push_back(std::move(plan));
            }
        }
    }
    if (!sigdata.invalid_p2mr_sigs.empty()) return false;

    std::stable_sort(complete_plans.begin(), complete_plans.end(), [](const auto& a, const auto& b) {
        return a.witness_size < b.witness_size;
    });
    for (const auto& plan : complete_plans) {
        std::vector<std::vector<unsigned char>> result_stack;
        if (SignP2MRScript(provider, creator, sigdata, plan, result_stack) < plan.threshold) continue;
        result_stack.push_back(plan.script); // Push script
        result_stack.push_back(plan.control_block); // Push the smallest valid control block
        result = std::move(result_stack);
        return true;
    }

    // If no complete witness can be produced, still create one partial P2MR
    // signature plan for PSBT handoff to other signers. Limiting the fallback
    // to the best partial plan avoids burning PQC counters across adversarial
    // many-leaf incomplete PSBTs.
    std::stable_sort(partial_plans.begin(), partial_plans.end(), [](const auto& a, const auto& b) {
        if (a.missing_signatures != b.missing_signatures) return a.missing_signatures < b.missing_signatures;
        if (a.new_signatures != b.new_signatures) return a.new_signatures < b.new_signatures;
        return a.witness_size < b.witness_size;
    });
    if (!partial_plans.empty()) {
        std::vector<std::vector<unsigned char>> result_stack;
        SignP2MRScript(provider, creator, sigdata, partial_plans.front(), result_stack);
    }
    return false;
}

static std::optional<P2MRScriptSigningPlan> SelectCompleteP2MRSigningPlan(const SigningProvider& provider, const BaseSignatureCreator& creator, const WitnessV2P2MR& output, SignatureData& sigdata)
{
    P2MRSpendData spenddata;
    TaprootBuilder builder;

    if (provider.GetP2MRSpendData(output, spenddata)) {
        sigdata.p2mr_spenddata.Merge(spenddata);
    }
    if (provider.GetP2MRBuilder(output, builder)) {
        sigdata.p2mr_builder = builder;
    }
    if (sigdata.p2mr_spenddata.scripts.empty() && sigdata.p2mr_builder.has_value()) {
        sigdata.p2mr_spenddata.Merge(sigdata.p2mr_builder->GetP2MRSpendData());
    }

    std::vector<P2MRScriptSigningPlan> complete_plans;
    for (const auto& [key, control_blocks] : sigdata.p2mr_spenddata.scripts) {
        const auto& [script, leaf_ver] = key;
        const auto* control_block = FindValidP2MRControlBlock(control_blocks, script, leaf_ver, output);
        if (control_block == nullptr) continue;

        P2MRScriptSigningPlan plan;
        if (BuildP2MRScriptSigningPlan(provider, creator, sigdata, leaf_ver, script, *control_block, plan) && plan.complete) {
            complete_plans.push_back(std::move(plan));
        }
    }
    if (!sigdata.invalid_p2mr_sigs.empty() || complete_plans.empty()) return std::nullopt;

    std::stable_sort(complete_plans.begin(), complete_plans.end(), [](const auto& a, const auto& b) {
        return a.witness_size < b.witness_size;
    });
    return std::move(complete_plans.front());
}

static bool CompleteP2MRWitnessAlreadyPresent(const CTxIn& txin, const WitnessV2P2MR& output, const BaseSignatureCreator& creator)
{
    const auto& stack{txin.scriptWitness.stack};
    if (!txin.scriptSig.empty() || stack.size() < 3) return false;

    const std::vector<unsigned char>& script{stack[stack.size() - 2]};
    const std::vector<unsigned char>& control_block{stack.back()};
    if (control_block.empty()) return false;

    const int leaf_version{control_block[0] & TAPROOT_LEAF_MASK};
    std::set<std::vector<unsigned char>, ShortestVectorFirstComparator> control_blocks;
    control_blocks.insert(control_block);
    if (FindValidP2MRControlBlock(control_blocks, script, leaf_version, output) == nullptr) return false;

    std::vector<CPQCPubKey> pubkeys;
    int threshold{0};
    if (!ParseP2MRScript(script, pubkeys, threshold)) return false;

    const size_t signature_items{stack.size() - 2};
    if (signature_items != pubkeys.size()) return false;

    const uint256 leaf_hash{ComputeP2MRLeafHash(leaf_version, script)};
    int valid_signatures{0};
    for (size_t pubkey_pos{pubkeys.size()}; pubkey_pos > 0; --pubkey_pos) {
        const size_t pubkey_index{pubkey_pos - 1};
        const size_t stack_index{pubkeys.size() - pubkey_pos};
        const auto& signature{stack[stack_index]};
        if (signature.empty()) continue;

        uint8_t hashtype;
        if (!GetP2MRSignatureHashType(signature, hashtype) ||
            !creator.VerifyP2MRScriptSignature(signature, pubkeys[pubkey_index], leaf_hash, SigVersion::P2MR)) {
            return false;
        }
        ++valid_signatures;
    }
    return valid_signatures >= threshold;
}

namespace {
class NoPQCSigningProvider final : public SigningProvider
{
private:
    const SigningProvider& m_provider;

public:
    explicit NoPQCSigningProvider(const SigningProvider& provider) : m_provider{provider} {}

    bool GetCScript(const CScriptID& scriptid, CScript& script) const override { return m_provider.GetCScript(scriptid, script); }
    bool HaveCScript(const CScriptID& scriptid) const override { return m_provider.HaveCScript(scriptid); }
    bool GetPubKey(const CKeyID& address, CPubKey& pubkey) const override { return m_provider.GetPubKey(address, pubkey); }
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override { return m_provider.GetKeyOrigin(keyid, info); }
    bool GetTaprootSpendData(const XOnlyPubKey& output_key, TaprootSpendData& spenddata) const override { return m_provider.GetTaprootSpendData(output_key, spenddata); }
    bool GetTaprootBuilder(const XOnlyPubKey& output_key, TaprootBuilder& builder) const override { return m_provider.GetTaprootBuilder(output_key, builder); }
    bool GetP2MRSpendData(const WitnessV2P2MR& output, P2MRSpendData& spenddata) const override { return m_provider.GetP2MRSpendData(output, spenddata); }
    bool GetP2MRBuilder(const WitnessV2P2MR& output, TaprootBuilder& builder) const override { return m_provider.GetP2MRBuilder(output, builder); }
    std::vector<CPubKey> GetMuSig2ParticipantPubkeys(const CPubKey& pubkey) const override { return m_provider.GetMuSig2ParticipantPubkeys(pubkey); }
};
} // namespace

struct ParallelPQCSigningJob {
    unsigned int input_index{0};
    CPQCPubKey pubkey;
    CPQCKey key;
    uint256 leaf_hash;
    uint256 sighash;
    int sighash_type{SIGHASH_DEFAULT};
    uint32_t assigned_counter{0};
};

struct ParallelPQCSigningResult {
    bool success{false};
    std::vector<unsigned char> signature;
};

struct ParallelPQCInputPlan {
    CScript prev_pub_key;
    CAmount amount{0};
    SignatureData sigdata;
    P2MRScriptSigningPlan script_plan;
    std::vector<size_t> job_indices;
};

static unsigned int GetParallelPQCSigningWorkerCount(size_t jobs)
{
    if (jobs == 0) return 0;
    const int64_t configured_threads{gArgs.GetIntArg("-walletpqcsignthreads", 0)};
    if (configured_threads < 0) return 0;
    if (configured_threads > 0) {
        return static_cast<unsigned int>(std::min<uint64_t>(static_cast<uint64_t>(configured_threads), jobs));
    }

    const int cores{std::max(1, GetNumCores() - 1)};
    return std::min<unsigned int>({
        static_cast<unsigned int>(cores),
        4U,
        static_cast<unsigned int>(jobs),
    });
}

static bool NotifySigningProgressPhase(const SigningProgressCallback& progress_callback, SigningProgressPhase phase, unsigned int completed, unsigned int total, std::optional<unsigned int> input_index = std::nullopt, bool cancellable = true)
{
    if (!progress_callback) return true;
    const bool should_continue{progress_callback({
        .phase = phase,
        .completed = completed,
        .total = total,
        .input_index = input_index,
        .cancellable = cancellable})};
    return should_continue || !cancellable;
}

static std::optional<bool> TrySignTransactionPQCParallel(
    CMutableTransaction& mtx,
    const FlatSigningProvider& provider,
    const std::map<COutPoint, Coin>& coins,
    int nHashType,
    const PrecomputedTransactionData& txdata,
    std::map<int, bilingual_str>& input_errors,
    const SigningProgressCallback& progress_callback)
{
    if (!gArgs.GetBoolArg("-walletpqcparallel", true)) return std::nullopt;
    if (!provider.pqc_counter_batch_reserver) return std::nullopt;
    if (mtx.vin.empty()) return std::nullopt;
    if (!NotifySigningProgressPhase(progress_callback, SigningProgressPhase::PREPARING_TRANSACTION, 0, static_cast<unsigned int>(mtx.vin.size()))) {
        input_errors[0] = _("Signing cancelled");
        return false;
    }

    const bool fHashSingle{(nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE};
    std::vector<ParallelPQCInputPlan> input_plans;
    input_plans.reserve(mtx.vin.size());
    std::vector<ParallelPQCSigningJob> jobs;
    std::map<CPQCPubKey, uint32_t> counts;

    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        if (fHashSingle && i >= mtx.vout.size()) return std::nullopt;

        const auto coin_it = coins.find(mtx.vin[i].prevout);
        if (coin_it == coins.end() || coin_it->second.IsSpent()) return std::nullopt;
        const CTxOut& txout{coin_it->second.out};
        if (txout.nValue == MAX_MONEY) return std::nullopt;

        std::vector<valtype> solutions;
        if (Solver(txout.scriptPubKey, solutions) != TxoutType::WITNESS_V2_P2MR) return std::nullopt;

        ParallelPQCInputPlan input_plan;
        input_plan.prev_pub_key = txout.scriptPubKey;
        input_plan.amount = txout.nValue;
        input_plan.sigdata = DataFromTransaction(mtx, i, txout);
        const WitnessV2P2MR output{uint256{std::span<const unsigned char>(solutions[0])}};
        MutableTransactionSignatureCreator creator{mtx, i, txout.nValue, &txdata, nHashType};
        if (input_plan.sigdata.complete || CompleteP2MRWitnessAlreadyPresent(mtx.vin[i], output, creator)) {
            input_plan.sigdata.complete = true;
            input_plans.push_back(std::move(input_plan));
            continue;
        }

        auto script_plan = SelectCompleteP2MRSigningPlan(provider, creator, output, input_plan.sigdata);
        if (!script_plan.has_value()) return std::nullopt;
        input_plan.script_plan = std::move(*script_plan);

        std::map<std::pair<CPQCPubKey, uint256>, size_t> queued_jobs;
        int num_signed{0};
        for (size_t pubkey_pos = input_plan.script_plan.pubkeys.size(); pubkey_pos > 0; --pubkey_pos) {
            const size_t index{pubkey_pos - 1};
            if (!input_plan.script_plan.candidate_pubkeys[index] || num_signed >= input_plan.script_plan.threshold) {
                continue;
            }
            const CPQCPubKey& pubkey{input_plan.script_plan.pubkeys[index]};
            if (LookupValidP2MRScriptSig(input_plan.sigdata, creator, pubkey, input_plan.script_plan.leaf_hash) != nullptr) {
                ++num_signed;
                continue;
            }

            const auto queued_key{std::make_pair(pubkey, input_plan.script_plan.leaf_hash)};
            if (queued_jobs.contains(queued_key)) {
                ++num_signed;
                continue;
            }

            CPQCKey key;
            if (!provider.GetPQCKey(pubkey, key) || !key.IsValid()) return std::nullopt;

            uint256 sighash;
            if (!creator.CreatePQCSignatureHash(sighash, input_plan.script_plan.leaf_hash, SigVersion::P2MR)) return std::nullopt;

            const size_t job_index{jobs.size()};
            input_plan.job_indices.push_back(job_index);
            queued_jobs.emplace(queued_key, job_index);
            jobs.push_back({
                .input_index = i,
                .pubkey = pubkey,
                .key = std::move(key),
                .leaf_hash = input_plan.script_plan.leaf_hash,
                .sighash = sighash,
                .sighash_type = nHashType,
            });
            ++counts[pubkey];
            ++num_signed;
        }
        if (num_signed < input_plan.script_plan.threshold) return std::nullopt;
        input_plans.push_back(std::move(input_plan));
    }

    if (jobs.empty()) {
        const bool all_inputs_complete{std::all_of(input_plans.begin(), input_plans.end(), [](const auto& input_plan) {
            return input_plan.sigdata.complete;
        })};
        if (!all_inputs_complete) return std::nullopt;
        input_errors.clear();
        return true;
    }
    const unsigned int worker_count{GetParallelPQCSigningWorkerCount(jobs.size())};
    if (worker_count == 0) return std::nullopt;

    const unsigned int reservation_total{static_cast<unsigned int>(counts.size())};
    if (!NotifySigningProgressPhase(progress_callback, SigningProgressPhase::RESERVING_PQC_COUNTERS, 0, reservation_total)) {
        input_errors[0] = _("Signing cancelled");
        return false;
    }

    std::map<CPQCPubKey, PQCSignatureCounterRange> ranges;
    if (!provider.pqc_counter_batch_reserver(counts, ranges)) {
        input_errors[0] = _("PQC signature counter reservation failed");
        return false;
    }
    if (ranges.size() != counts.size()) {
        input_errors[0] = _("PQC signature counter reservation failed");
        return false;
    }

    std::map<CPQCPubKey, uint32_t> cursors;
    for (const auto& [pubkey, count] : counts) {
        const auto range_it{ranges.find(pubkey)};
        if (range_it == ranges.end() ||
            range_it->second.pubkey != pubkey ||
            range_it->second.reserved_counter < range_it->second.previous_counter ||
            range_it->second.reserved_counter - range_it->second.previous_counter != count) {
            input_errors[0] = _("PQC signature counter reservation failed");
            return false;
        }
        cursors.emplace(pubkey, range_it->second.previous_counter);
    }
    for (auto& job : jobs) {
        auto cursor_it{cursors.find(job.pubkey)};
        if (cursor_it == cursors.end()) {
            input_errors[job.input_index] = _("PQC signature counter reservation failed");
            return false;
        }
        job.assigned_counter = cursor_it->second++;
        if (provider.pqc_counter_observer) {
            provider.pqc_counter_observer(job.pubkey, job.assigned_counter, job.assigned_counter + 1);
        }
    }
    for (const auto& [pubkey, range] : ranges) {
        if (cursors[pubkey] != range.reserved_counter) {
            input_errors[0] = _("PQC signature counter reservation failed");
            return false;
        }
    }

    // Counters are committed from this point; later progress callbacks are informational.
    NotifySigningProgressPhase(progress_callback, SigningProgressPhase::RESERVING_PQC_COUNTERS, reservation_total, reservation_total, std::nullopt, /*cancellable=*/false);

    std::vector<ParallelPQCSigningResult> results(jobs.size());
    std::atomic<size_t> next_job{0};
    std::atomic_bool cancel_requested{false};
    std::atomic_bool worker_failed{false};
    std::atomic<unsigned int> completed_inputs{0};
    std::vector<std::atomic<unsigned int>> remaining_jobs_by_input(input_plans.size());
    for (size_t i = 0; i < input_plans.size(); ++i) {
        remaining_jobs_by_input[i].store(static_cast<unsigned int>(input_plans[i].job_indices.size()));
        if (input_plans[i].job_indices.empty()) {
            ++completed_inputs;
        }
    }

    std::mutex progress_mutex;
    const auto notify_completed_input = [&](unsigned int input_index) {
        const unsigned int completed{++completed_inputs};
        std::lock_guard<std::mutex> lock{progress_mutex};
        NotifySigningProgressPhase(progress_callback, SigningProgressPhase::SIGNING_INPUTS, completed, static_cast<unsigned int>(mtx.vin.size()), input_index, /*cancellable=*/false);
    };

    NotifySigningProgressPhase(progress_callback, SigningProgressPhase::SIGNING_INPUTS, completed_inputs.load(), static_cast<unsigned int>(mtx.vin.size()), std::nullopt, /*cancellable=*/false);

    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    try {
        for (unsigned int worker_index = 0; worker_index < worker_count; ++worker_index) {
            workers.emplace_back(&util::TraceThread, "walletpqc", [&] {
                try {
                    while (!cancel_requested.load()) {
                        const size_t job_index{next_job.fetch_add(1)};
                        if (job_index >= jobs.size()) break;

                        const ParallelPQCSigningJob& job{jobs[job_index]};
                        uint32_t counter{job.assigned_counter};
                        std::vector<unsigned char> signature;
                        const bool signed_ok{job.key.Sign(job.sighash, signature, counter)};
                        if (!signed_ok || counter != job.assigned_counter + 1) {
                            worker_failed.store(true);
                            cancel_requested.store(true);
                            break;
                        }
                        if (job.sighash_type) {
                            signature.push_back(static_cast<unsigned char>(job.sighash_type));
                        }
                        results[job_index] = {
                            .success = true,
                            .signature = std::move(signature),
                        };

                        auto& remaining{remaining_jobs_by_input[job.input_index]};
                        if (remaining.fetch_sub(1) == 1) {
                            notify_completed_input(job.input_index);
                        }
                    }
                } catch (const std::exception&) {
                    worker_failed.store(true);
                    cancel_requested.store(true);
                } catch (...) {
                    worker_failed.store(true);
                    cancel_requested.store(true);
                }
            });
        }
    } catch (const std::exception&) {
        worker_failed.store(true);
        cancel_requested.store(true);
    } catch (...) {
        worker_failed.store(true);
        cancel_requested.store(true);
    }
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }

    if (worker_failed.load()) {
        for (size_t job_index = 0; job_index < jobs.size(); ++job_index) {
            const auto& job{jobs[job_index]};
            if (!results[job_index].success) {
                input_errors[job.input_index] = _("PQC signing failed");
                return false;
            }
        }
    }
    if (cancel_requested.load()) {
        for (size_t job_index = 0; job_index < jobs.size(); ++job_index) {
            const auto& job{jobs[job_index]};
            if (!results[job_index].success) {
                input_errors[job.input_index] = _("Signing cancelled");
                return false;
            }
        }
    }
    for (size_t job_index = 0; job_index < results.size(); ++job_index) {
        if (!results[job_index].success) {
            input_errors[jobs[job_index].input_index] = _("PQC signing failed");
            return false;
        }
    }

    NoPQCSigningProvider finalizing_provider{provider};
    unsigned int finalized_inputs{0};
    NotifySigningProgressPhase(progress_callback, SigningProgressPhase::FINALIZING_TRANSACTION, finalized_inputs, static_cast<unsigned int>(mtx.vin.size()), std::nullopt, /*cancellable=*/false);
    const CTransaction txConst{mtx};
    unsigned int complete_inputs{0};
    for (unsigned int i = 0; i < input_plans.size(); ++i) {
        auto& input_plan{input_plans[i]};
        for (const size_t job_index : input_plan.job_indices) {
            const auto& job{jobs[job_index]};
            input_plan.sigdata.p2mr_script_sigs[std::make_pair(job.pubkey, job.leaf_hash)] = results[job_index].signature;
        }

        MutableTransactionSignatureCreator creator{mtx, i, input_plan.amount, &txdata, nHashType};
        if (!ProduceSignature(finalizing_provider, creator, input_plan.prev_pub_key, input_plan.sigdata)) {
            input_errors[i] = _("PQC signing failed");
        }
        UpdateInput(mtx.vin[i], input_plan.sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        bool verify_failed{false};
        if (!input_plan.sigdata.complete) {
            verify_failed = !VerifyScript(mtx.vin[i].scriptSig, input_plan.prev_pub_key, &mtx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, input_plan.amount, txdata, MissingDataBehavior::FAIL), &serror);
        }
        if (verify_failed) {
            input_errors[i] = Untranslated(ScriptErrorString(serror));
        } else if (input_plan.sigdata.complete) {
            ++complete_inputs;
            input_errors.erase(i);
        }

        ++finalized_inputs;
        NotifySigningProgressPhase(progress_callback, SigningProgressPhase::FINALIZING_TRANSACTION, finalized_inputs, static_cast<unsigned int>(mtx.vin.size()), i, /*cancellable=*/false);
    }

    if (util::signing_timing::TraceEnabled()) {
        LogTrace(BCLog::BENCH,
            "wallet-sign-timing phase=script_pqc_parallel inputs=%u jobs=%u workers=%u complete_inputs=%u errors=%u\n",
            static_cast<unsigned int>(mtx.vin.size()),
            static_cast<unsigned int>(jobs.size()),
            worker_count,
            complete_inputs,
            static_cast<unsigned int>(input_errors.size()));
    }
    return input_errors.empty();
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TxoutType::SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, TxoutType& whichTypeRet, SigVersion sigversion, SignatureData& sigdata)
{
    CScript scriptRet;
    ret.clear();
    std::vector<unsigned char> sig;

    std::vector<valtype> vSolutions;
    whichTypeRet = Solver(scriptPubKey, vSolutions);

    switch (whichTypeRet) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
        return false;
    case TxoutType::PUBKEY:
        if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        return true;
    case TxoutType::PUBKEYHASH: {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (!GetPubKey(provider, sigdata, keyID, pubkey)) {
            // Pubkey could not be found, add to missing
            sigdata.missing_pubkeys.push_back(keyID);
            return false;
        }
        if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        ret.push_back(ToByteVector(pubkey));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        uint160 h160{vSolutions[0]};
        if (GetCScript(provider, sigdata, CScriptID{h160}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find redeemScript, add to missing
        sigdata.missing_redeem_script = h160;
        return false;
    }
    case TxoutType::MULTISIG: {
        size_t required = vSolutions.front()[0];
        ret.emplace_back(); // workaround CHECKMULTISIG bug
        for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
            CPubKey pubkey = CPubKey(vSolutions[i]);
            // We need to always call CreateSig in order to fill sigdata with all
            // possible signatures that we can create. This will allow further PSBT
            // processing to work as it needs all possible signature and pubkey pairs
            if (CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) {
                if (ret.size() < required + 1) {
                    ret.push_back(std::move(sig));
                }
            }
        }
        bool ok = ret.size() == required + 1;
        for (size_t i = 0; i + ret.size() < required + 1; ++i) {
            ret.emplace_back();
        }
        return ok;
    }
    case TxoutType::WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TxoutType::WITNESS_V0_SCRIPTHASH:
        if (GetCScript(provider, sigdata, CScriptID{RIPEMD160(vSolutions[0])}, scriptRet)) {
            ret.emplace_back(scriptRet.begin(), scriptRet.end());
            return true;
        }
        // Could not find witnessScript, add to missing
        sigdata.missing_witness_script = uint256(vSolutions[0]);
        return false;

    case TxoutType::WITNESS_V1_TAPROOT:
        return SignTaproot(provider, creator, WitnessV1Taproot(XOnlyPubKey{vSolutions[0]}), sigdata, ret);

    case TxoutType::WITNESS_V2_P2MR:
        return SignP2MR(provider, creator, WitnessV2P2MR{uint256{std::span<const unsigned char>(vSolutions[0])}}, sigdata, ret);

    case TxoutType::ANCHOR:
        return true;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else if (v.size() == 1 && v[0] == 0x81) {
            result << OP_1NEGATE;
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    if (sigdata.complete) return true;

    std::vector<valtype> result;
    TxoutType whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, SigVersion::BASE, sigdata);
    bool P2SH = false;
    CScript subscript;

    if (solved && whichType == TxoutType::SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        subscript = CScript(result[0].begin(), result[0].end());
        sigdata.redeem_script = subscript;
        solved = solved && SignStep(provider, creator, subscript, result, whichType, SigVersion::BASE, sigdata) && whichType != TxoutType::SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TxoutType::WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        TxoutType subType;
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata);
        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    }
    else if (solved && whichType == TxoutType::WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        sigdata.witness_script = witnessscript;

        TxoutType subType{TxoutType::NONSTANDARD};
        solved = solved && SignStep(provider, creator, witnessscript, result, subType, SigVersion::WITNESS_V0, sigdata) && subType != TxoutType::SCRIPTHASH && subType != TxoutType::WITNESS_V0_SCRIPTHASH && subType != TxoutType::WITNESS_V0_KEYHASH;

        // If we couldn't find a solution with the legacy satisfier, try satisfying the script using Miniscript.
        // Note we need to check if the result stack is empty before, because it might be used even if the Script
        // isn't fully solved. For instance the CHECKMULTISIG satisfaction in SignStep() pushes partial signatures
        // and the extractor relies on this behaviour to combine witnesses.
        if (!solved && result.empty()) {
            WshSatisfier ms_satisfier{provider, sigdata, creator, witnessscript};
            const auto ms = miniscript::FromScript(witnessscript, ms_satisfier);
            solved = ms && ms->Satisfy(ms_satisfier, result) == miniscript::Availability::YES;
        }
        result.emplace_back(witnessscript.begin(), witnessscript.end());

        sigdata.scriptWitness.stack = result;
        sigdata.witness = true;
        result.clear();
    } else if (whichType == TxoutType::WITNESS_V1_TAPROOT && !P2SH) {
        sigdata.witness = true;
        if (solved) {
            sigdata.scriptWitness.stack = std::move(result);
        }
        result.clear();
    } else if (whichType == TxoutType::WITNESS_V2_P2MR && !P2SH) {
        sigdata.witness = true;
        if (solved) {
            sigdata.scriptWitness.stack = std::move(result);
        }
        result.clear();
    } else if (solved && whichType == TxoutType::WITNESS_UNKNOWN) {
        sigdata.witness = true;
    }

    if (!sigdata.witness) sigdata.scriptWitness.stack.clear();
    if (P2SH) {
        result.emplace_back(subscript.begin(), subscript.end());
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    sigdata.complete = solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
    return sigdata.complete;
}

namespace {
class SignatureExtractorChecker final : public DeferringSignatureChecker
{
private:
    SignatureData& sigdata;

public:
    SignatureExtractorChecker(SignatureData& sigdata, BaseSignatureChecker& checker) : DeferringSignatureChecker(checker), sigdata(sigdata) {}

    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        if (m_checker.CheckECDSASignature(scriptSig, vchPubKey, scriptCode, sigversion)) {
            CPubKey pubkey(vchPubKey);
            sigdata.signatures.emplace(pubkey.GetID(), SigPair(pubkey, scriptSig));
            return true;
        }
        return false;
    }
};

struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() = delete;
    Stacks(const Stacks&) = delete;
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) {
        EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
    }
};
}

// Extracts signatures and scripts from incomplete scriptSigs. Please do not extend this, use PSBT instead
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    Stacks stack(data);

    // Get signatures
    MutableTransactionSignatureChecker tx_checker(&tx, nIn, txout.nValue, MissingDataBehavior::FAIL);
    SignatureExtractorChecker extractor_checker(data, tx_checker);
    if (VerifyScript(data.scriptSig, txout.scriptPubKey, &data.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, extractor_checker)) {
        data.complete = true;
        return data;
    }

    // Get scripts
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType script_type = Solver(txout.scriptPubKey, solutions);
    SigVersion sigversion = SigVersion::BASE;
    CScript next_script = txout.scriptPubKey;

    if (script_type == TxoutType::SCRIPTHASH && !stack.script.empty() && !stack.script.back().empty()) {
        // Get the redeemScript
        CScript redeem_script(stack.script.back().begin(), stack.script.back().end());
        data.redeem_script = redeem_script;
        next_script = std::move(redeem_script);

        // Get redeemScript type
        script_type = Solver(next_script, solutions);
        stack.script.pop_back();
    }
    if (script_type == TxoutType::WITNESS_V0_SCRIPTHASH && !stack.witness.empty() && !stack.witness.back().empty()) {
        // Get the witnessScript
        CScript witness_script(stack.witness.back().begin(), stack.witness.back().end());
        data.witness_script = witness_script;
        next_script = std::move(witness_script);

        // Get witnessScript type
        script_type = Solver(next_script, solutions);
        stack.witness.pop_back();
        stack.script = std::move(stack.witness);
        stack.witness.clear();
        sigversion = SigVersion::WITNESS_V0;
    }
    if (script_type == TxoutType::MULTISIG && !stack.script.empty()) {
        // Build a map of pubkey -> signature by matching sigs to pubkeys:
        assert(solutions.size() > 1);
        unsigned int num_pubkeys = solutions.size()-2;
        unsigned int last_success_key = 0;
        for (const valtype& sig : stack.script) {
            for (unsigned int i = last_success_key; i < num_pubkeys; ++i) {
                const valtype& pubkey = solutions[i+1];
                // We either have a signature for this pubkey, or we have found a signature and it is valid
                if (data.signatures.count(CPubKey(pubkey).GetID()) || extractor_checker.CheckECDSASignature(sig, pubkey, next_script, sigversion)) {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }

    return data;
}

void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
    input.scriptWitness = data.scriptWitness;
}

void SignatureData::MergeSignatureData(SignatureData sigdata)
{
    if (complete) return;
    if (sigdata.complete) {
        *this = std::move(sigdata);
        return;
    }
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    tr_spenddata.Merge(std::move(sigdata.tr_spenddata));
    if (!tr_builder.has_value() && sigdata.tr_builder.has_value()) {
        tr_builder = std::move(sigdata.tr_builder);
    }
    p2mr_spenddata.Merge(std::move(sigdata.p2mr_spenddata));
    if (!p2mr_builder.has_value() && sigdata.p2mr_builder.has_value()) {
        p2mr_builder = std::move(sigdata.p2mr_builder);
    }
    if (taproot_key_path_sig.empty() && !sigdata.taproot_key_path_sig.empty()) {
        taproot_key_path_sig = std::move(sigdata.taproot_key_path_sig);
    }
    taproot_script_sigs.insert(std::make_move_iterator(sigdata.taproot_script_sigs.begin()), std::make_move_iterator(sigdata.taproot_script_sigs.end()));
    p2mr_script_sigs.insert(std::make_move_iterator(sigdata.p2mr_script_sigs.begin()), std::make_move_iterator(sigdata.p2mr_script_sigs.end()));
    signatures.insert(std::make_move_iterator(sigdata.signatures.begin()), std::make_move_iterator(sigdata.signatures.end()));
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker final : public BaseSignatureChecker
{
public:
    DummySignatureChecker() = default;
    bool CheckECDSASignature(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override { return sig.size() != 0; }
    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror) const override { return sig.size() != 0; }
    bool CheckPQCSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror) const override { return !sig.empty(); }
    bool CheckLockTime(const CScriptNum& nLockTime) const override { return true; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return true; }
};
}

const BaseSignatureChecker& DUMMY_CHECKER = DummySignatureChecker();

namespace {
class DummySignatureCreator final : public BaseSignatureCreator {
private:
    char m_r_len = 32;
    char m_s_len = 32;
public:
    DummySignatureCreator(char r_len, char s_len) : m_r_len(r_len), m_s_len(s_len) {}
    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override
    {
        // Create a dummy signature that is a valid DER-encoding
        vchSig.assign(m_r_len + m_s_len + 7, '\000');
        vchSig[0] = 0x30;
        vchSig[1] = m_r_len + m_s_len + 4;
        vchSig[2] = 0x02;
        vchSig[3] = m_r_len;
        vchSig[4] = 0x01;
        vchSig[4 + m_r_len] = 0x02;
        vchSig[5 + m_r_len] = m_s_len;
        vchSig[6 + m_r_len] = 0x01;
        vchSig[6 + m_r_len + m_s_len] = SIGHASH_ALL;
        return true;
    }
    bool CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* tweak, SigVersion sigversion) const override
    {
        sig.assign(64, '\000');
        return true;
    }
    bool CreatePQCSignature(const SigningProvider& provider, std::vector<unsigned char>& sig, const CPQCPubKey& pubkey, const uint256* leaf_hash, SigVersion sigversion) const override
    {
        sig.assign(P2MR_V1_MAX_SIGNATURE_ITEM_SIZE, '\000');
        sig.back() = SIGHASH_ALL;
        return true;
    }
    bool CanCreatePQCSignature(const SigningProvider& provider, const CPQCPubKey& pubkey) const override { return true; }
    size_t P2MRSignatureSize() const override { return P2MR_V1_MAX_SIGNATURE_ITEM_SIZE; }
};

}

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator(32, 32);
const BaseSignatureCreator& DUMMY_MAXIMUM_SIGNATURE_CREATOR = DummySignatureCreator(33, 32);

bool IsSegWitOutput(const SigningProvider& provider, const CScript& script)
{
    int version;
    valtype program;
    if (script.IsWitnessProgram(version, program)) return true;
    if (script.IsPayToScriptHash()) {
        std::vector<valtype> solutions;
        auto whichtype = Solver(script, solutions);
        if (whichtype == TxoutType::SCRIPTHASH) {
            auto h160 = uint160(solutions[0]);
            CScript subscript;
            if (provider.GetCScript(CScriptID{h160}, subscript)) {
                if (subscript.IsWitnessProgram(version, program)) return true;
            }
        }
    }
    return false;
}

bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors, const SigningProgressCallback& progress_callback)
{
    const bool timing_enabled{util::signing_timing::Enabled()};
    const uint64_t timing_id{timing_enabled ? util::signing_timing::CurrentOrNextId() : 0};
    const util::signing_timing::ScopedId timing_scope{timing_id};
    const auto timing_start{SteadyClock::now()};
    SteadyClock::duration precompute_time{};
    SteadyClock::duration data_time{};
    SteadyClock::duration produce_time{};
    SteadyClock::duration update_time{};
    SteadyClock::duration verify_time{};
    unsigned int produce_attempts{0};
    unsigned int verify_attempts{0};
    unsigned int complete_inputs{0};
    bool spent_outputs_ready{false};

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    {
        const auto precompute_start{SteadyClock::now()};
        for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
            CTxIn& txin = mtx.vin[i];
            auto coin = coins.find(txin.prevout);
            if (coin == coins.end() || coin->second.IsSpent()) {
                txdata.Init(txConst, /*spent_outputs=*/{}, /*force=*/true);
                break;
            } else {
                spent_outputs.emplace_back(coin->second.out.nValue, coin->second.out.scriptPubKey);
            }
        }
        spent_outputs_ready = spent_outputs.size() == mtx.vin.size();
        if (spent_outputs_ready) {
            txdata.Init(txConst, std::move(spent_outputs), true);
        }
        precompute_time = SteadyClock::now() - precompute_start;
    }

    const auto notify_signing_progress = [&](unsigned int completed, std::optional<unsigned int> input_index = std::nullopt, bool cancellable = true) {
        if (!progress_callback) return true;
        const bool should_continue{progress_callback({
            .phase = SigningProgressPhase::SIGNING_INPUTS,
            .completed = completed,
            .total = static_cast<unsigned int>(mtx.vin.size()),
            .input_index = input_index,
            .cancellable = cancellable})};
        return should_continue || !cancellable;
    };

    if (const auto* flat_provider{dynamic_cast<const FlatSigningProvider*>(keystore)}) {
        if (std::optional<bool> parallel_result = TrySignTransactionPQCParallel(mtx, *flat_provider, coins, nHashType, txdata, input_errors, progress_callback)) {
            return *parallel_result;
        }
    }

    unsigned int processed_inputs{0};
    bool pqc_counter_committed{false};
    if (!notify_signing_progress(processed_inputs)) {
        if (!mtx.vin.empty()) {
            input_errors[0] = _("Signing cancelled");
        }
        return false;
    }

    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        if (!notify_signing_progress(processed_inputs, i, !pqc_counter_committed)) {
            input_errors[i] = _("Signing cancelled");
            return false;
        }

        CTxIn& txin = mtx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = _("Input not found or already spent");
            ++processed_inputs;
            if (!notify_signing_progress(processed_inputs, i, !pqc_counter_committed)) {
                if (i + 1 < mtx.vin.size()) {
                    input_errors[i + 1] = _("Signing cancelled");
                }
                return false;
            }
            continue;
        }
        const CScript& prevPubKey = coin->second.out.scriptPubKey;
        const CAmount& amount = coin->second.out.nValue;

        const auto data_start{SteadyClock::now()};
        SignatureData sigdata = DataFromTransaction(mtx, i, coin->second.out);
        data_time += SteadyClock::now() - data_start;
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        const size_t p2mr_sigs_before{sigdata.p2mr_script_sigs.size()};
        if (!fHashSingle || (i < mtx.vout.size())) {
            const auto produce_start{SteadyClock::now()};
            ProduceSignature(*keystore, MutableTransactionSignatureCreator(mtx, i, amount, &txdata, nHashType), prevPubKey, sigdata);
            produce_time += SteadyClock::now() - produce_start;
            ++produce_attempts;
        }
        pqc_counter_committed |= sigdata.p2mr_script_sigs.size() > p2mr_sigs_before;

        const auto update_start{SteadyClock::now()};
        UpdateInput(txin, sigdata);
        update_time += SteadyClock::now() - update_start;

        // amount must be specified for valid segwit signature
        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            ++processed_inputs;
            if (!notify_signing_progress(processed_inputs, i, !pqc_counter_committed)) {
                if (i + 1 < mtx.vin.size()) {
                    input_errors[i + 1] = _("Signing cancelled");
                }
                return false;
            }
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        bool verified{false};
        bool verify_failed{false};
        if (!sigdata.complete) {
            const auto verify_start{SteadyClock::now()};
            verify_failed = !VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount, txdata, MissingDataBehavior::FAIL), &serror);
            verify_time += SteadyClock::now() - verify_start;
            verified = true;
        }
        if (verify_failed) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                // Verification failed (possibly due to insufficient signatures).
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            // If this input succeeds, make sure there is no error set for it
            input_errors.erase(i);
        }
        if (verified) ++verify_attempts;
        if (sigdata.complete) ++complete_inputs;
        if (util::signing_timing::TraceEnabled()) {
            LogTrace(BCLog::BENCH,
                "wallet-sign-timing id=%llu phase=script_sign_input input=%u complete=%d verified=%d errors=%u\n",
                util::signing_timing::LogId(timing_id),
                i,
                sigdata.complete,
                verified,
                static_cast<unsigned int>(input_errors.size()));
        }
        ++processed_inputs;
        if (!notify_signing_progress(processed_inputs, i, !pqc_counter_committed)) {
            if (i + 1 < mtx.vin.size()) {
                input_errors[i + 1] = _("Signing cancelled");
                return false;
            }
        }
    }
    const bool success{input_errors.empty()};
    if (timing_enabled) {
        LogDebug(BCLog::BENCH,
            "wallet-sign-timing id=%llu phase=script_sign inputs=%u coins=%u spent_outputs_ready=%d "
            "precompute_ms=%.2f data_ms=%.2f produce_ms=%.2f update_ms=%.2f verify_ms=%.2f "
            "produce_attempts=%u verify_attempts=%u complete_inputs=%u errors=%u total_ms=%.2f success=%d\n",
            util::signing_timing::LogId(timing_id),
            static_cast<unsigned int>(mtx.vin.size()),
            static_cast<unsigned int>(coins.size()),
            spent_outputs_ready,
            Ticks<MillisecondsDouble>(precompute_time),
            Ticks<MillisecondsDouble>(data_time),
            Ticks<MillisecondsDouble>(produce_time),
            Ticks<MillisecondsDouble>(update_time),
            Ticks<MillisecondsDouble>(verify_time),
            produce_attempts,
            verify_attempts,
            complete_inputs,
            static_cast<unsigned int>(input_errors.size()),
            Ticks<MillisecondsDouble>(SteadyClock::now() - timing_start),
            success);
    }
    return success;
}
