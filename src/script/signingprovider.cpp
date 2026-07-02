// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/keyorigin.h>
#include <script/interpreter.h>
#include <script/merkle_script_tree.h>
#include <script/signingprovider.h>

#include <logging.h>
#include <util/strencodings.h>
#include <util/signing_timing.h>
#include <util/time.h>

const SigningProvider& DUMMY_SIGNING_PROVIDER = SigningProvider();

template<typename M, typename K, typename V>
bool LookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}

bool SigningProvider::SignPQC(const CPQCPubKey&, const uint256&, std::vector<unsigned char>&) const
{
    // PQC signing requires provider-managed signature counters. Providers that
    // expose signable PQC keys must override this method instead of relying on
    // an unsafe key-only fallback.
    return false;
}

bool HidingSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    return m_provider->GetCScript(scriptid, script);
}

bool HidingSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    if (m_hide_secret) return false;
    return m_provider->GetKey(keyid, key);
}

bool HidingSigningProvider::GetPQCKey(const CPQCPubKey& pubkey, CPQCKey& key) const
{
    if (m_hide_secret) return false;
    return m_provider->GetPQCKey(pubkey, key);
}

bool HidingSigningProvider::CanSignPQC(const CPQCPubKey& pubkey) const
{
    if (m_hide_secret) return false;
    return m_provider->CanSignPQC(pubkey);
}

bool HidingSigningProvider::IsPQCSignatureCounterExhausted(const CPQCPubKey& pubkey) const
{
    if (m_hide_secret) return false;
    return m_provider->IsPQCSignatureCounterExhausted(pubkey);
}

bool HidingSigningProvider::SignPQC(const CPQCPubKey& pubkey, const uint256& hash, std::vector<unsigned char>& sig) const
{
    if (m_hide_secret) return false;
    return m_provider->SignPQC(pubkey, hash, sig);
}

bool HidingSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    if (m_hide_origin) return false;
    return m_provider->GetKeyOrigin(keyid, info);
}

bool HidingSigningProvider::GetTaprootSpendData(const XOnlyPubKey& output_key, TaprootSpendData& spenddata) const
{
    return m_provider->GetTaprootSpendData(output_key, spenddata);
}
bool HidingSigningProvider::GetTaprootBuilder(const XOnlyPubKey& output_key, TaprootBuilder& builder) const
{
    return m_provider->GetTaprootBuilder(output_key, builder);
}
bool HidingSigningProvider::GetP2MRSpendData(const WitnessV2P2MR& output, P2MRSpendData& spenddata) const
{
    return m_provider->GetP2MRSpendData(output, spenddata);
}
bool HidingSigningProvider::GetP2MRBuilder(const WitnessV2P2MR& output, TaprootBuilder& builder) const
{
    return m_provider->GetP2MRBuilder(output, builder);
}
std::vector<CPubKey> HidingSigningProvider::GetMuSig2ParticipantPubkeys(const CPubKey& pubkey) const
{
    if (m_hide_origin) return {};
    return m_provider->GetMuSig2ParticipantPubkeys(pubkey);
}

bool FlatSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const { return LookupHelper(scripts, scriptid, script); }
bool FlatSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const { return LookupHelper(pubkeys, keyid, pubkey); }
bool FlatSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    std::pair<CPubKey, KeyOriginInfo> out;
    bool ret = LookupHelper(origins, keyid, out);
    if (ret) info = std::move(out.second);
    return ret;
}
bool FlatSigningProvider::HaveKey(const CKeyID &keyid) const
{
    CKey key;
    return LookupHelper(keys, keyid, key);
}
bool FlatSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const { return LookupHelper(keys, keyid, key); }
bool FlatSigningProvider::GetPQCKey(const CPQCPubKey& pubkey, CPQCKey& key) const { return LookupHelper(pqc_keys, pubkey, key); }
bool FlatSigningProvider::CanSignPQC(const CPQCPubKey& pubkey) const
{
    CPQCKey key;
    if (!LookupHelper(pqc_keys, pubkey, key)) return false;
    if (!key.IsValid()) return false;

    const auto counter_it = pqc_sig_counters.find(pubkey);
    const uint32_t previous_counter = counter_it != pqc_sig_counters.end() ? counter_it->second : 0;
    return previous_counter < PQC_MAX_SIGNATURES;
}

bool FlatSigningProvider::IsPQCSignatureCounterExhausted(const CPQCPubKey& pubkey) const
{
    CPQCKey key;
    if (!LookupHelper(pqc_keys, pubkey, key)) return false;
    if (!key.IsValid()) return false;

    const auto counter_it = pqc_sig_counters.find(pubkey);
    const uint32_t previous_counter = counter_it != pqc_sig_counters.end() ? counter_it->second : 0;
    return previous_counter >= PQC_MAX_SIGNATURES;
}

bool FlatSigningProvider::SignPQC(const CPQCPubKey& pubkey, const uint256& hash, std::vector<unsigned char>& sig) const
{
    const bool timing_enabled{util::signing_timing::Enabled() && util::signing_timing::CurrentId() != 0};
    const uint64_t timing_id{util::signing_timing::CurrentId()};
    const auto timing_start{SteadyClock::now()};
    SteadyClock::duration reserve_time{};
    SteadyClock::duration raw_sign_time{};
    SteadyClock::duration rollback_time{};
    SteadyClock::duration observer_time{};
    const bool has_reserver{static_cast<bool>(pqc_counter_reserver)};
    const bool has_writer{static_cast<bool>(pqc_counter_writer)};
    const auto log_pqc_sign_timing = [&](bool success, const char* status) {
        if (!timing_enabled) return;
        LogDebug(BCLog::BENCH,
            "wallet-sign-timing id=%llu phase=pqc_sign reserve_ms=%.2f raw_sign_ms=%.2f "
            "rollback_ms=%.2f observer_ms=%.2f total_ms=%.2f success=%d reserver=%d writer=%d status=%s\n",
            util::signing_timing::LogId(timing_id),
            Ticks<MillisecondsDouble>(reserve_time),
            Ticks<MillisecondsDouble>(raw_sign_time),
            Ticks<MillisecondsDouble>(rollback_time),
            Ticks<MillisecondsDouble>(observer_time),
            Ticks<MillisecondsDouble>(SteadyClock::now() - timing_start),
            success,
            has_reserver,
            has_writer,
            status);
    };

    CPQCKey key;
    if (!LookupHelper(pqc_keys, pubkey, key)) {
        log_pqc_sign_timing(/*success=*/false, "missing_key");
        return false;
    }
    if (!key.IsValid()) {
        log_pqc_sign_timing(/*success=*/false, "invalid_key");
        return false;
    }

    const auto counter_it = pqc_sig_counters.find(pubkey);
    const bool has_prior_counter = counter_it != pqc_sig_counters.end();
    const uint32_t previous_counter = has_prior_counter ? counter_it->second : 0;
    uint32_t reserved_previous_counter = previous_counter;
    uint32_t reserved_counter = previous_counter + 1;
    uint32_t counter = previous_counter;
    bool committed_reservation{false};
    const auto observe_counter_advance = [&](uint32_t observed_previous_counter, uint32_t observed_reserved_counter) {
        pqc_sig_counters[pubkey] = observed_reserved_counter;
        if (pqc_counter_observer) {
            const auto observer_start{SteadyClock::now()};
            pqc_counter_observer(pubkey, observed_previous_counter, observed_reserved_counter);
            observer_time += SteadyClock::now() - observer_start;
        }
    };
    if (previous_counter >= PQC_MAX_SIGNATURES) {
        log_pqc_sign_timing(/*success=*/false, "limit_exceeded");
        return false;
    }

    if (pqc_counter_reserver) {
        const auto reserve_start{SteadyClock::now()};
        const bool reserved{pqc_counter_reserver(pubkey, /*count=*/1, reserved_previous_counter, reserved_counter)};
        reserve_time = SteadyClock::now() - reserve_start;
        if (!reserved) {
            log_pqc_sign_timing(/*success=*/false, "reserve_failed");
            return false;
        }
        if (reserved_previous_counter >= PQC_MAX_SIGNATURES ||
            reserved_counter != reserved_previous_counter + 1) {
            LogPrintf("%s: PQC counter reserver returned invalid range [%u, %u)\n", __func__, reserved_previous_counter, reserved_counter);
            log_pqc_sign_timing(/*success=*/false, "invalid_reservation");
            return false;
        }
        counter = reserved_previous_counter;
        committed_reservation = true;
        // Wallet-backed reservations have already been durably committed by
        // the reserver. Treat that counter range as consumed even if the raw
        // signer fails below; reusing it would be less safe than overcounting.
        observe_counter_advance(reserved_previous_counter, reserved_counter);
    } else if (pqc_counter_writer) {
        // Reserve exactly one counter value in authoritative storage first.
        const auto reserve_start{SteadyClock::now()};
        const bool reserved{pqc_counter_writer(pubkey, previous_counter, reserved_counter)};
        reserve_time = SteadyClock::now() - reserve_start;
        if (!reserved) {
            log_pqc_sign_timing(/*success=*/false, "reserve_failed");
            return false;
        }
    }

    const auto raw_sign_start{SteadyClock::now()};
    const bool signed_ok = pqc_raw_signer ? pqc_raw_signer(key, hash, sig, counter) : key.Sign(hash, sig, counter);
    raw_sign_time = SteadyClock::now() - raw_sign_start;
    if (!signed_ok || counter != reserved_counter) {
        if (signed_ok) {
            LogPrintf("%s: PQC signer returned unexpected counter %u (expected %u)\n", __func__, counter, reserved_counter);
        }
        if (committed_reservation) {
            LogPrintf("%s: PQC signing failed after committed counter reservation for pubkey %s [%u, %u)\n",
                __func__,
                HexStr(std::span<const unsigned char>{pubkey.begin(), pubkey.end()}),
                reserved_previous_counter,
                reserved_counter);
        } else if (pqc_counter_writer && !pqc_counter_reserver) {
            // Best-effort rollback of reservation if signing failed.
            const auto rollback_start{SteadyClock::now()};
            if (!pqc_counter_writer(pubkey, reserved_counter, previous_counter)) {
                // If rollback could not be applied, keep local cache at reserved state.
                pqc_sig_counters[pubkey] = reserved_counter;
            } else if (has_prior_counter) {
                pqc_sig_counters[pubkey] = previous_counter;
            } else {
                pqc_sig_counters.erase(pubkey);
            }
            rollback_time = SteadyClock::now() - rollback_start;
        }
        sig.clear();
        log_pqc_sign_timing(/*success=*/false, signed_ok ? "unexpected_counter" : "sign_failed");
        return false;
    }

    if (!committed_reservation) {
        observe_counter_advance(reserved_previous_counter, reserved_counter);
    }
    log_pqc_sign_timing(/*success=*/true, "ok");
    return true;
}
bool FlatSigningProvider::GetTaprootSpendData(const XOnlyPubKey& output_key, TaprootSpendData& spenddata) const
{
    TaprootBuilder builder;
    if (LookupHelper(tr_trees, output_key, builder)) {
        spenddata = builder.GetSpendData();
        return true;
    }
    return false;
}
bool FlatSigningProvider::GetTaprootBuilder(const XOnlyPubKey& output_key, TaprootBuilder& builder) const
{
    return LookupHelper(tr_trees, output_key, builder);
}
bool FlatSigningProvider::GetP2MRSpendData(const WitnessV2P2MR& output, P2MRSpendData& spenddata) const
{
    if (LookupHelper(p2mr_spenddata, output, spenddata)) {
        return true;
    }
    TaprootBuilder builder;
    if (LookupHelper(mr_trees, output, builder)) {
        spenddata = builder.GetP2MRSpendData();
        return true;
    }
    return false;
}
bool FlatSigningProvider::GetP2MRBuilder(const WitnessV2P2MR& output, TaprootBuilder& builder) const
{
    return LookupHelper(mr_trees, output, builder);
}

std::vector<CPubKey> FlatSigningProvider::GetMuSig2ParticipantPubkeys(const CPubKey& pubkey) const
{
    std::vector<CPubKey> participant_pubkeys;
    LookupHelper(aggregate_pubkeys, pubkey, participant_pubkeys);
    return participant_pubkeys;
}

FlatSigningProvider& FlatSigningProvider::Merge(FlatSigningProvider&& b)
{
    scripts.merge(b.scripts);
    pubkeys.merge(b.pubkeys);
    keys.merge(b.keys);
    pqc_keys.merge(b.pqc_keys);
    for (const auto& [pubkey, counter] : b.pqc_sig_counters) {
        auto [it, inserted] = pqc_sig_counters.emplace(pubkey, counter);
        if (!inserted && counter > it->second) {
            it->second = counter;
        }
    }
    if (!pqc_counter_writer && b.pqc_counter_writer) {
        pqc_counter_writer = std::move(b.pqc_counter_writer);
    }
    if (!pqc_counter_reserver && b.pqc_counter_reserver) {
        pqc_counter_reserver = std::move(b.pqc_counter_reserver);
    }
    if (!pqc_counter_batch_reserver && b.pqc_counter_batch_reserver) {
        pqc_counter_batch_reserver = std::move(b.pqc_counter_batch_reserver);
    }
    if (!pqc_counter_observer && b.pqc_counter_observer) {
        pqc_counter_observer = std::move(b.pqc_counter_observer);
    }
    if (!pqc_raw_signer && b.pqc_raw_signer) {
        pqc_raw_signer = std::move(b.pqc_raw_signer);
    }
    p2mr_pubkeys.merge(b.p2mr_pubkeys);
    for (auto& [output, spenddata] : b.p2mr_spenddata) {
        p2mr_spenddata[output].Merge(std::move(spenddata));
    }
    origins.merge(b.origins);
    tr_trees.merge(b.tr_trees);
    mr_trees.merge(b.mr_trees);
    aggregate_pubkeys.merge(b.aggregate_pubkeys);
    return *this;
}

void FillableSigningProvider::ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);
    CKeyID key_id = pubkey.GetID();
    // This adds the redeemscripts necessary to detect P2WPKH and P2SH-P2WPKH
    // outputs. Technically P2WPKH outputs don't have a redeemscript to be
    // spent. However, our current IsMine logic requires the corresponding
    // P2SH-P2WPKH redeemscript to be present in the wallet in order to accept
    // payment even to P2WPKH outputs.
    // Also note that having superfluous scripts in the keystore never hurts.
    // They're only used to guide recursion in signing and IsMine logic - if
    // a script is present but we can't do anything with it, it has no effect.
    // "Implicitly" refers to fact that scripts are derived automatically from
    // existing keys, and are present in memory, even without being explicitly
    // loaded (e.g. from a file).
    if (pubkey.IsCompressed()) {
        CScript script = GetScriptForDestination(WitnessV0KeyHash(key_id));
        // This does not use AddCScript, as it may be overridden.
        CScriptID id(script);
        mapScripts[id] = std::move(script);
    }
}

bool FillableSigningProvider::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool FillableSigningProvider::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    ImplicitlyLearnRelatedKeyScripts(pubkey);
    return true;
}

bool FillableSigningProvider::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    return mapKeys.count(address) > 0;
}

std::set<CKeyID> FillableSigningProvider::GetKeys() const
{
    LOCK(cs_KeyStore);
    std::set<CKeyID> set_address;
    for (const auto& mi : mapKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool FillableSigningProvider::GetKey(const CKeyID &address, CKey &keyOut) const
{
    LOCK(cs_KeyStore);
    KeyMap::const_iterator mi = mapKeys.find(address);
    if (mi != mapKeys.end()) {
        keyOut = mi->second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        LogError("FillableSigningProvider::AddCScript(): redeemScripts > %i bytes are invalid\n", MAX_SCRIPT_ELEMENT_SIZE);
        return false;
    }

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool FillableSigningProvider::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

std::set<CScriptID> FillableSigningProvider::GetCScripts() const
{
    LOCK(cs_KeyStore);
    std::set<CScriptID> set_script;
    for (const auto& mi : mapScripts) {
        set_script.insert(mi.first);
    }
    return set_script;
}

bool FillableSigningProvider::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

CKeyID GetKeyForDestination(const SigningProvider& store, const CTxDestination& dest)
{
    // Only supports destinations which map to single public keys:
    // P2PKH, P2WPKH, P2SH-P2WPKH, P2TR
    if (auto id = std::get_if<PKHash>(&dest)) {
        return ToKeyID(*id);
    }
    if (auto witness_id = std::get_if<WitnessV0KeyHash>(&dest)) {
        return ToKeyID(*witness_id);
    }
    if (auto script_hash = std::get_if<ScriptHash>(&dest)) {
        CScript script;
        CScriptID script_id = ToScriptID(*script_hash);
        CTxDestination inner_dest;
        if (store.GetCScript(script_id, script) && ExtractDestination(script, inner_dest)) {
            if (auto inner_witness_id = std::get_if<WitnessV0KeyHash>(&inner_dest)) {
                return ToKeyID(*inner_witness_id);
            }
        }
    }
    if (auto output_key = std::get_if<WitnessV1Taproot>(&dest)) {
        TaprootSpendData spenddata;
        CPubKey pub;
        if (store.GetTaprootSpendData(*output_key, spenddata)
            && !spenddata.internal_key.IsNull()
            && spenddata.merkle_root.IsNull()
            && store.GetPubKeyByXOnly(spenddata.internal_key, pub)) {
            return pub.GetID();
        }
    }
    return CKeyID();
}

void MultiSigningProvider::AddProvider(std::unique_ptr<SigningProvider> provider)
{
    m_providers.push_back(std::move(provider));
}

bool MultiSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetCScript(scriptid, script)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetPubKey(keyid, pubkey)) return true;
    }
    return false;
}


bool MultiSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetKeyOrigin(keyid, info)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetKey(keyid, key)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetPQCKey(const CPQCPubKey& pubkey, CPQCKey& key) const
{
    for (const auto& provider : m_providers) {
        if (provider->GetPQCKey(pubkey, key)) return true;
    }
    return false;
}

bool MultiSigningProvider::CanSignPQC(const CPQCPubKey& pubkey) const
{
    for (const auto& provider : m_providers) {
        if (provider->CanSignPQC(pubkey)) return true;
    }
    return false;
}

bool MultiSigningProvider::IsPQCSignatureCounterExhausted(const CPQCPubKey& pubkey) const
{
    for (const auto& provider : m_providers) {
        if (provider->IsPQCSignatureCounterExhausted(pubkey)) return true;
    }
    return false;
}

bool MultiSigningProvider::SignPQC(const CPQCPubKey& pubkey, const uint256& hash, std::vector<unsigned char>& sig) const
{
    for (const auto& provider : m_providers) {
        if (provider->SignPQC(pubkey, hash, sig)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetTaprootSpendData(const XOnlyPubKey& output_key, TaprootSpendData& spenddata) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetTaprootSpendData(output_key, spenddata)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetTaprootBuilder(const XOnlyPubKey& output_key, TaprootBuilder& builder) const
{
    for (const auto& provider: m_providers) {
        if (provider->GetTaprootBuilder(output_key, builder)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetP2MRSpendData(const WitnessV2P2MR& output, P2MRSpendData& spenddata) const
{
    for (const auto& provider : m_providers) {
        if (provider->GetP2MRSpendData(output, spenddata)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetP2MRBuilder(const WitnessV2P2MR& output, TaprootBuilder& builder) const
{
    for (const auto& provider : m_providers) {
        if (provider->GetP2MRBuilder(output, builder)) return true;
    }
    return false;
}

/*static*/ TaprootBuilder::NodeInfo TaprootBuilder::Combine(NodeInfo&& a, NodeInfo&& b, bool p2mr_tree)
{
    NodeInfo ret;
    /* Iterate over all tracked leaves in a, add b's hash to their Merkle branch, and move them to ret. */
    for (auto& leaf : a.leaves) {
        leaf.merkle_branch.push_back(b.hash);
        ret.leaves.emplace_back(std::move(leaf));
    }
    /* Iterate over all tracked leaves in b, add a's hash to their Merkle branch, and move them to ret. */
    for (auto& leaf : b.leaves) {
        leaf.merkle_branch.push_back(a.hash);
        ret.leaves.emplace_back(std::move(leaf));
    }
    ret.hash = p2mr_tree ? ComputeP2MRBranchHash(a.hash, b.hash) : ComputeTapbranchHash(a.hash, b.hash);
    return ret;
}

void ScriptMerkleSpendData::MergeScripts(ScriptMerkleSpendData other)
{
    if (merkle_root.IsNull() && !other.merkle_root.IsNull()) {
        merkle_root = other.merkle_root;
    }
    for (auto& [key, control_blocks] : other.scripts) {
        scripts[key].merge(std::move(control_blocks));
    }
}

void TaprootSpendData::Merge(TaprootSpendData other)
{
    // TODO: figure out how to better deal with conflicting information
    // being merged.
    if (internal_key.IsNull() && !other.internal_key.IsNull()) {
        internal_key = other.internal_key;
    }
    MergeScripts(std::move(other));
}

void P2MRSpendData::Merge(P2MRSpendData other)
{
    MergeScripts(std::move(other));
}

void TaprootBuilder::PopulateSpendScripts(ScriptMerkleBranches& scripts, size_t control_base_size, size_t control_node_size,
                                          unsigned char parity_bit, bool include_internal_key) const
{
    if (m_branch.empty()) return;

    for (const auto& leaf : m_branch[0]->leaves) {
        std::vector<unsigned char> control_block;
        control_block.resize(control_base_size + control_node_size * leaf.merkle_branch.size());
        control_block[0] = leaf.leaf_version | parity_bit;
        if (include_internal_key) {
            std::copy(m_internal_key.begin(), m_internal_key.end(), control_block.begin() + 1);
        }
        if (leaf.merkle_branch.size()) {
            for (size_t i = 0; i < leaf.merkle_branch.size(); ++i) {
                const auto& branch_hash = leaf.merkle_branch[i];
                assert(control_node_size == branch_hash.size());
                std::copy(branch_hash.begin(), branch_hash.end(), control_block.begin() + control_base_size + i * control_node_size);
            }
        }
        scripts[{leaf.script, leaf.leaf_version}].insert(std::move(control_block));
    }
}

void TaprootBuilder::Insert(TaprootBuilder::NodeInfo&& node, int depth)
{
    assert(depth >= 0 && (size_t)depth <= TAPROOT_CONTROL_MAX_NODE_COUNT);
    /* We cannot insert a leaf at a lower depth while a deeper branch is unfinished. Doing
     * so would mean the Add() invocations do not correspond to a DFS traversal of a
     * binary tree. */
    if ((size_t)depth + 1 < m_branch.size()) {
        m_valid = false;
        return;
    }
    /* As long as an entry in the branch exists at the specified depth, combine it and propagate up.
     * The 'node' variable is overwritten here with the newly combined node. */
    while (m_valid && m_branch.size() > (size_t)depth && m_branch[depth].has_value()) {
        node = Combine(std::move(node), std::move(*m_branch[depth]), m_p2mr_tree);
        m_branch.pop_back();
        if (depth == 0) m_valid = false; /* Can't propagate further up than the root */
        --depth;
    }
    if (m_valid) {
        /* Make sure the branch is big enough to place the new node. */
        if (m_branch.size() <= (size_t)depth) m_branch.resize((size_t)depth + 1);
        assert(!m_branch[depth].has_value());
        m_branch[depth] = std::move(node);
    }
}

/*static*/ bool TaprootBuilder::ValidDepths(const std::vector<int>& depths)
{
    std::vector<bool> branch;
    for (int depth : depths) {
        // This inner loop corresponds to effectively the same logic on branch
        // as what Insert() performs on the m_branch variable. Instead of
        // storing a NodeInfo object, just remember whether or not there is one
        // at that depth.
        if (depth < 0 || (size_t)depth > TAPROOT_CONTROL_MAX_NODE_COUNT) return false;
        if ((size_t)depth + 1 < branch.size()) return false;
        while (branch.size() > (size_t)depth && branch[depth]) {
            branch.pop_back();
            if (depth == 0) return false;
            --depth;
        }
        if (branch.size() <= (size_t)depth) branch.resize((size_t)depth + 1);
        assert(!branch[depth]);
        branch[depth] = true;
    }
    // And this check corresponds to the IsComplete() check on m_branch.
    return branch.size() == 0 || (branch.size() == 1 && branch[0]);
}

void TaprootBuilder::SetTreeType(bool p2mr_tree)
{
    if (!m_tree_type_set) {
        m_tree_type_set = true;
        m_p2mr_tree = p2mr_tree;
    } else if (m_p2mr_tree != p2mr_tree) {
        m_valid = false;
    }
}

TaprootBuilder& TaprootBuilder::AddInternal(int depth, std::span<const unsigned char> script, int leaf_version, bool track, bool p2mr_tree)
{
    assert((leaf_version & ~TAPROOT_LEAF_MASK) == 0);
    SetTreeType(p2mr_tree);
    if (!IsValid()) return *this;
    /* Construct NodeInfo object with leaf hash and (if track is true) also leaf information. */
    NodeInfo node;
    node.hash = p2mr_tree ? ComputeP2MRLeafHash(leaf_version, script) : ComputeTapleafHash(leaf_version, script);
    if (track) node.leaves.emplace_back(LeafInfo{std::vector<unsigned char>(script.begin(), script.end()), leaf_version, {}});
    /* Insert into the branch. */
    Insert(std::move(node), depth);
    return *this;
}

TaprootBuilder& TaprootBuilder::Add(int depth, std::span<const unsigned char> script, int leaf_version, bool track)
{
    return AddInternal(depth, script, leaf_version, track, /*p2mr_tree=*/false);
}

TaprootBuilder& TaprootBuilder::AddP2MR(int depth, std::span<const unsigned char> script, int leaf_version, bool track)
{
    return AddInternal(depth, script, leaf_version, track, /*p2mr_tree=*/true);
}

TaprootBuilder& TaprootBuilder::AddOmittedInternal(int depth, const uint256& hash, bool p2mr_tree)
{
    SetTreeType(p2mr_tree);
    if (!IsValid()) return *this;
    /* Construct NodeInfo object with the hash directly, and insert it into the branch. */
    NodeInfo node;
    node.hash = hash;
    Insert(std::move(node), depth);
    return *this;
}

TaprootBuilder& TaprootBuilder::AddOmitted(int depth, const uint256& hash)
{
    return AddOmittedInternal(depth, hash, /*p2mr_tree=*/false);
}

TaprootBuilder& TaprootBuilder::AddOmittedP2MR(int depth, const uint256& hash)
{
    return AddOmittedInternal(depth, hash, /*p2mr_tree=*/true);
}

TaprootBuilder& TaprootBuilder::Finalize(const XOnlyPubKey& internal_key)
{
    /* Can only call this function when IsComplete() is true. */
    assert(IsComplete());
    SetTreeType(/*p2mr_tree=*/false);
    assert(!m_p2mr_tree);
    m_internal_key = internal_key;
    auto ret = m_internal_key.CreateTapTweak(m_branch.size() == 0 ? nullptr : &m_branch[0]->hash);
    assert(ret.has_value());
    std::tie(m_output_key, m_parity) = *ret;
    return *this;
}

TaprootBuilder& TaprootBuilder::FinalizeP2MR()
{
    assert(IsComplete());
    SetTreeType(/*p2mr_tree=*/true);
    assert(m_p2mr_tree);
    return *this;
}

WitnessV1Taproot TaprootBuilder::GetOutput() { return WitnessV1Taproot{m_output_key}; }
WitnessV2P2MR TaprootBuilder::GetP2MROutput()
{
    assert(IsComplete());
    assert(m_p2mr_tree);
    return WitnessV2P2MR{m_branch.size() == 0 ? uint256{} : m_branch[0]->hash};
}

TaprootSpendData TaprootBuilder::GetSpendData() const
{
    assert(IsComplete());
    assert(!m_p2mr_tree);
    assert(m_output_key.IsFullyValid());
    TaprootSpendData spd;
    spd.merkle_root = m_branch.size() == 0 ? uint256() : m_branch[0]->hash;
    spd.internal_key = m_internal_key;
    PopulateSpendScripts(spd.scripts, TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE, m_parity ? 1 : 0, true);
    return spd;
}

P2MRSpendData TaprootBuilder::GetP2MRSpendData() const
{
    assert(IsComplete());
    assert(m_p2mr_tree);
    P2MRSpendData spd;
    spd.merkle_root = m_branch.size() == 0 ? uint256() : m_branch[0]->hash;
    PopulateSpendScripts(spd.scripts, P2MR_CONTROL_BASE_SIZE, P2MR_CONTROL_NODE_SIZE, 1, false);
    return spd;
}

std::optional<std::vector<std::tuple<int, std::vector<unsigned char>, int>>> InferTaprootTree(const TaprootSpendData& spenddata, const XOnlyPubKey& output)
{
    // Verify that the output matches the assumed Merkle root and internal key.
    auto tweak = spenddata.internal_key.CreateTapTweak(spenddata.merkle_root.IsNull() ? nullptr : &spenddata.merkle_root);
    if (!tweak || tweak->first != output) return std::nullopt;

    return merkle_tree_inference::InferMerkleScriptTree(
        spenddata.merkle_root,
        spenddata.scripts,
        TAPROOT_CONTROL_BASE_SIZE,
        TAPROOT_CONTROL_MAX_SIZE,
        TAPROOT_CONTROL_NODE_SIZE,
        [](const std::vector<unsigned char>& control, const uint256& leaf_hash, const uint256& merkle_root) {
            return ComputeTaprootMerkleRoot(control, leaf_hash) == merkle_root;
        },
        [](int leaf_ver, const std::vector<unsigned char>& script) {
            return ComputeTapleafHash(static_cast<uint8_t>(leaf_ver), script);
        },
        [](const uint256& a, const uint256& b) {
            return ComputeTapbranchHash(a, b);
        });
}

std::vector<std::tuple<uint8_t, uint8_t, std::vector<unsigned char>>> TaprootBuilder::GetTreeTuples() const
{
    assert(IsComplete());
    std::vector<std::tuple<uint8_t, uint8_t, std::vector<unsigned char>>> tuples;
    if (m_branch.size()) {
        const auto& leaves = m_branch[0]->leaves;
        for (const auto& leaf : leaves) {
            assert(leaf.merkle_branch.size() <= TAPROOT_CONTROL_MAX_NODE_COUNT);
            uint8_t depth = (uint8_t)leaf.merkle_branch.size();
            uint8_t leaf_ver = (uint8_t)leaf.leaf_version;
            tuples.emplace_back(depth, leaf_ver, leaf.script);
        }
    }
    return tuples;
}
