// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_WALLET_SCRIPTPUBKEYMAN_H
#define QBIT_WALLET_SCRIPTPUBKEYMAN_H

#include <addresstype.h>
#include <common/messages.h>
#include <common/signmessage.h>
#include <common/types.h>
#include <logging.h>
#include <node/types.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <util/result.h>
#include <util/time.h>
#include <wallet/crypter.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <boost/signals2/signal.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

enum class OutputType;

namespace wallet {
struct MigrationData;
class ScriptPubKeyMan;
std::vector<CPQCPubKey> ExtractP2MRPubkeys(const CScript& script);

struct PSBTSigningProvider
{
    std::unique_ptr<SigningProvider> provider;
    std::set<unsigned int> input_indexes;
};

struct DataPQCSignatureProof
{
    WitnessV2P2MR output;
    uint256 message_hash;
    uint256 datasig_hash;
    CPQCPubKey pubkey;
    std::vector<unsigned char> signature;
    CScript leaf_script;
    std::vector<unsigned char> control_block;
    uint8_t leaf_version{P2MR_LEAF_VERSION_V1};
};

struct PendingPlaintextPQCKey {
    CKeyingMaterial secret;
    uint32_t sig_counter{0};
};

/** Sign a 32-byte data hash with a PQC key committed by a single-key P2MR pubkey leaf. */
util::Result<DataPQCSignatureProof> SignP2MRDataHash(
    const SigningProvider& provider,
    const WitnessV2P2MR& output,
    const uint256& message_hash,
    const std::optional<CPQCPubKey>& requested_pubkey,
    const std::optional<CScript>& requested_leaf_script,
    const std::optional<std::vector<unsigned char>>& requested_control_block);

// Wallet storage things that ScriptPubKeyMans need in order to be able to store things to the wallet database.
// It provides access to things that are part of the entire wallet and not specific to a ScriptPubKeyMan such as
// wallet flags, wallet version, encryption keys, encryption status, and the database itself. This allows a
// ScriptPubKeyMan to have callbacks into CWallet without causing a circular dependency.
// WalletStorage should be the same for all ScriptPubKeyMans of a wallet.
class WalletStorage
{
public:
    virtual ~WalletStorage() = default;
    virtual std::string LogName() const = 0;
    virtual WalletDatabase& GetDatabase() const = 0;
    virtual bool IsWalletFlagSet(uint64_t) const = 0;
    virtual void UnsetBlankWalletFlag(WalletBatch&) = 0;
    //! Pass the encryption key to cb().
    virtual bool WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const = 0;
    virtual bool HasEncryptionKeys() const = 0;
    virtual bool IsLocked() const = 0;
    virtual bool WithWalletLock(std::function<bool()> cb) const = 0;
    virtual std::optional<bool> IsInternalScriptPubKeyMan(const ScriptPubKeyMan* spk_man) const = 0;
    //! Callback function for after TopUp completes containing any scripts that were added by a SPKMan
    virtual void TopUpCallback(const std::set<CScript>&, ScriptPubKeyMan*) = 0;
};

//! Constant representing an unknown spkm creation time
static constexpr int64_t UNKNOWN_TIME = std::numeric_limits<int64_t>::max();

//! Default for -keypool
static const unsigned int DEFAULT_KEYPOOL_SIZE = 1000;

std::vector<CKeyID> GetAffectedKeys(const CScript& spk, const SigningProvider& provider);

struct WalletDestination
{
    CTxDestination dest;
    std::optional<bool> internal;
};

struct CryptedPQCKeyRecord
{
    std::vector<unsigned char> crypted_secret;
    std::optional<uint256> auth_tag;
};

/*
 * A class implementing ScriptPubKeyMan manages some (or all) scriptPubKeys used in a wallet.
 * It contains the scripts and keys related to the scriptPubKeys it manages.
 * A ScriptPubKeyMan will be able to give out scriptPubKeys to be used, as well as marking
 * when a scriptPubKey has been used. It also handles when and how to store a scriptPubKey
 * and its related scripts and keys, including encryption.
 */
class ScriptPubKeyMan
{
protected:
    WalletStorage& m_storage;
    std::shared_ptr<void> m_lifetime{std::make_shared<bool>(true)};

public:
    explicit ScriptPubKeyMan(WalletStorage& storage) : m_storage(storage) {}
    virtual ~ScriptPubKeyMan() = default;
    virtual util::Result<CTxDestination> GetNewDestination(const OutputType type) { return util::Error{Untranslated("Not supported")}; }
    virtual bool IsMine(const CScript& script) const { return false; }

    //! Check that the given decryption key is valid for this ScriptPubKeyMan, i.e. it decrypts all of the keys handled by it.
    virtual bool CheckDecryptionKey(const CKeyingMaterial& master_key) { return false; }
    virtual bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) { return false; }

    virtual util::Result<CTxDestination> GetReservedDestination(const OutputType type, bool internal, int64_t& index) { return util::Error{Untranslated("Not supported")}; }
    virtual void KeepDestination(int64_t index, const OutputType& type) {}
    virtual void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) {}

    /** Fills internal address pool. Use within ScriptPubKeyMan implementations should be used sparingly and only
      * when something from the address pool is removed, excluding GetNewDestination and GetReservedDestination.
      * External wallet code is primarily responsible for topping up prior to fetching new addresses
      */
    virtual bool TopUp(unsigned int size = 0) { return false; }
    virtual util::Result<void> TopUpResult(unsigned int size = 0)
    {
        if (!TopUp(size)) return util::Error{_("scriptPubKey manager top-up failed")};
        return {};
    }

    /** Mark unused addresses as being used
     * Affects all keys up to and including the one determined by provided script.
     *
     * @param script determines the last key to mark as used
     *
     * @return All of the addresses affected
     */
    virtual std::vector<WalletDestination> MarkUnusedAddresses(const CScript& script) { return {}; }

    /* Returns true if HD is enabled */
    virtual bool IsHDEnabled() const { return false; }

    /* Returns true if the wallet can give out new addresses. This means it has keys in the keypool or can generate new keys */
    virtual bool CanGetAddresses(bool internal = false) const { return false; }

    virtual bool HavePrivateKeys() const { return false; }
    virtual bool HaveCryptedKeys() const { return false; }
    virtual PQCKeyValidationInfo GetPQCKeyValidationInfo() const { return {}; }
    std::weak_ptr<void> GetLifetimeToken() const { return m_lifetime; }

    //! The action to do when the DB needs rewrite
    virtual void RewriteDB() {}

    virtual unsigned int GetKeyPoolSize() const { return 0; }

    virtual int64_t GetTimeFirstKey() const { return 0; }

    virtual std::unique_ptr<CKeyMetadata> GetMetadata(const CTxDestination& dest) const { return nullptr; }
    virtual std::optional<uint32_t> GetPQCSignatureCounter(const CPQCPubKey& pubkey) const { return std::nullopt; }

    virtual std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const { return nullptr; }

    /** Whether this ScriptPubKeyMan can provide a SigningProvider (via GetSolvingProvider) that, combined with
      * sigdata, can produce solving data.
      */
    virtual bool CanProvide(const CScript& script, SignatureData& sigdata) { return false; }

    /** Creates new signatures and adds them to the transaction. Returns whether all inputs were signed */
    virtual bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const { return false; }
    /** Collect a provider snapshot for transaction signing. The caller can use it after releasing the wallet lock. */
    virtual std::unique_ptr<SigningProvider> GetSigningProviderForTransaction(const std::map<COutPoint, Coin>& coins, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const { return nullptr; }
    /** Sign a message with the given script */
    virtual SigningResult SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const { return SigningResult::SIGNING_FAILED; };
    /** Sign a 32-byte data hash with a PQC key committed by a single-key P2MR pubkey leaf. */
    virtual util::Result<DataPQCSignatureProof> SignDataPQCHash(
        const WitnessV2P2MR& output,
        const uint256& message_hash,
        const std::optional<CPQCPubKey>& requested_pubkey,
        const std::optional<CScript>& requested_leaf_script,
        const std::optional<std::vector<unsigned char>>& requested_control_block,
        const PQCSignatureCounterObserver& pqc_counter_observer = {}) const
    {
        return util::Error{Untranslated("P2MR data-hash signing is unsupported by this wallet")};
    }
    /** Adds script and derivation path information to a PSBT, and optionally signs it. */
    virtual std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type = std::nullopt, bool sign = true, bool bip32derivs = false, int* n_signed = nullptr, bool finalize = true, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const { return common::PSBTError::UNSUPPORTED; }
    /** Collect a provider snapshot for PSBT filling. The caller can use it after releasing the wallet lock. */
    virtual std::optional<PSBTSigningProvider> GetSigningProviderForPSBT(const PartiallySignedTransaction& psbt, bool sign = true, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const { return std::nullopt; }

    virtual uint256 GetID() const { return uint256(); }

    /** Returns a set of all the scriptPubKeys that this ScriptPubKeyMan watches */
    virtual std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const { return {}; };

    /** Prepends the wallet name in logging output to ease debugging in multi-wallet use cases */
    template <typename... Params>
    void WalletLogPrintf(util::ConstevalFormatString<sizeof...(Params)> wallet_fmt, const Params&... params) const
    {
        LogInfo("[%s] %s", m_storage.LogName(), tfm::format(wallet_fmt, params...));
    };

    /** Keypool has new keys */
    boost::signals2::signal<void ()> NotifyCanGetAddressesChanged;

    /** Birth time changed */
    boost::signals2::signal<void (const ScriptPubKeyMan* spkm, int64_t new_birth_time)> NotifyFirstKeyTimeChanged;
};

/** OutputTypes supported by the LegacyScriptPubKeyMan */
static const std::unordered_set<OutputType> LEGACY_OUTPUT_TYPES {
    OutputType::LEGACY,
    OutputType::P2SH_SEGWIT,
    OutputType::BECH32,
};

// Manages the data for a LegacyScriptPubKeyMan.
// This is the minimum necessary to load a legacy wallet so that it can be migrated.
class LegacyDataSPKM : public ScriptPubKeyMan, public FillableSigningProvider
{
private:
    using WatchOnlySet = std::set<CScript>;
    using WatchKeyMap = std::map<CKeyID, CPubKey>;
    using CryptedKeyMap = std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>>;

    CryptedKeyMap mapCryptedKeys GUARDED_BY(cs_KeyStore);
    WatchOnlySet setWatchOnly GUARDED_BY(cs_KeyStore);
    WatchKeyMap mapWatchKeys GUARDED_BY(cs_KeyStore);

    /* the HD chain data model (external chain counters) */
    CHDChain m_hd_chain;
    std::unordered_map<CKeyID, CHDChain, SaltedSipHasher> m_inactive_hd_chains;

    //! keeps track of whether Unlock has run a thorough check before
    bool fDecryptionThoroughlyChecked = true;

    bool AddWatchOnlyInMem(const CScript &dest);
    virtual bool AddKeyPubKeyInner(const CKey& key, const CPubKey &pubkey);
    bool AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);

    // Helper function to retrieve a conservative superset of all output scripts that may be relevant to this LegacyDataSPKM.
    // It may include scripts that are invalid or not actually watched by this LegacyDataSPKM.
    // Used only in migration.
    std::unordered_set<CScript, SaltedSipHasher> GetCandidateScriptPubKeys() const;

    bool IsMine(const CScript& script) const override;
    bool CanProvide(const CScript& script, SignatureData& sigdata) override;
public:
    using ScriptPubKeyMan::ScriptPubKeyMan;

    // Map from Key ID to key metadata.
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata GUARDED_BY(cs_KeyStore);

    // Map from Script ID to key metadata (for watch-only keys).
    std::map<CScriptID, CKeyMetadata> m_script_metadata GUARDED_BY(cs_KeyStore);

    // ScriptPubKeyMan overrides
    bool CheckDecryptionKey(const CKeyingMaterial& master_key) override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;
    uint256 GetID() const override { return uint256::ONE; }

    // FillableSigningProvider overrides
    bool HaveKey(const CKeyID &address) const override;
    bool GetKey(const CKeyID &address, CKey& keyOut) const override;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const override;
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override;

    //! Load metadata (used by LoadWallet)
    virtual void LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &metadata);
    virtual void LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &metadata);

    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);
    //! Returns whether the watch-only script is in the wallet
    bool HaveWatchOnly(const CScript &dest) const;
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid);
    //! Adds a CScript to the store
    bool LoadCScript(const CScript& redeemScript);
    //! Load a HD chain model (used by LoadWallet)
    void LoadHDChain(const CHDChain& chain);
    void AddInactiveHDChain(const CHDChain& chain);
    const CHDChain& GetHDChain() const { return m_hd_chain; }

    //! Fetches a pubkey from mapWatchKeys if it exists there
    bool GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const;

    /**
     * Retrieves scripts that were imported by bugs into the legacy spkm and are
     * simply invalid, such as a sh(sh(pkh())) script, or not watched.
     */
    std::unordered_set<CScript, SaltedSipHasher> GetNotMineScriptPubKeys() const;

    /** Get the DescriptorScriptPubKeyMans (with private keys) that have the same scriptPubKeys as this LegacyScriptPubKeyMan.
     * Does not modify this ScriptPubKeyMan. */
    std::optional<MigrationData> MigrateToDescriptor();
    /** Delete all the records of this LegacyScriptPubKeyMan from disk*/
    bool DeleteRecordsWithDB(WalletBatch& batch);
};

/** Wraps a LegacyScriptPubKeyMan so that it can be returned in a new unique_ptr. Does not provide privkeys */
class LegacySigningProvider : public SigningProvider
{
private:
    const LegacyDataSPKM& m_spk_man;
public:
    explicit LegacySigningProvider(const LegacyDataSPKM& spk_man) : m_spk_man(spk_man) {}

    bool GetCScript(const CScriptID &scriptid, CScript& script) const override { return m_spk_man.GetCScript(scriptid, script); }
    bool HaveCScript(const CScriptID &scriptid) const override { return m_spk_man.HaveCScript(scriptid); }
    bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const override { return m_spk_man.GetPubKey(address, pubkey); }
    bool GetKey(const CKeyID &address, CKey& key) const override { return false; }
    bool HaveKey(const CKeyID &address) const override { return false; }
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override { return m_spk_man.GetKeyOrigin(keyid, info); }
};

class DescriptorScriptPubKeyMan : public ScriptPubKeyMan
{
    friend class LegacyDataSPKM;
private:
    using ScriptPubKeyMap = std::map<CScript, int32_t>; // Map of scripts to descriptor range index
    using PubKeyMap = std::map<CPubKey, int32_t>; // Map of pubkeys involved in scripts to descriptor range index
    using CryptedKeyMap = std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>>;
    using KeyMap = std::map<CKeyID, CKey>;
    using CryptedPQCKeyMap = std::map<CPQCPubKey, CryptedPQCKeyRecord>;
    using PQCKeyMap = std::map<CPQCPubKey, CPQCKey>;
    using PendingPlaintextPQCKeyMap = std::map<CPQCPubKey, PendingPlaintextPQCKey>;

    ScriptPubKeyMap m_map_script_pub_keys GUARDED_BY(cs_desc_man);
    PubKeyMap m_map_pubkeys GUARDED_BY(cs_desc_man);
    int32_t m_max_cached_index = -1;

    KeyMap m_map_keys GUARDED_BY(cs_desc_man);
    CryptedKeyMap m_map_crypted_keys GUARDED_BY(cs_desc_man);
    mutable CryptedPQCKeyMap m_map_crypted_pqc_keys GUARDED_BY(cs_desc_man);
    PQCKeyMap m_map_pqc_keys GUARDED_BY(cs_desc_man);
    PendingPlaintextPQCKeyMap m_pending_plaintext_pqc_keys GUARDED_BY(cs_desc_man);
    std::set<CPQCPubKey> m_failed_plaintext_pqc_keys GUARDED_BY(cs_desc_man);
    mutable std::map<CPQCPubKey, uint32_t> m_map_pqc_sig_counters GUARDED_BY(cs_desc_man);

    //! keeps track of whether Unlock has run a thorough check before
    bool m_decryption_thoroughly_checked = false;

    //! Number of pre-generated keys/scripts (part of the look-ahead process, used to detect payments)
    int64_t m_keypool_size GUARDED_BY(cs_desc_man){DEFAULT_KEYPOOL_SIZE};
    //! True when a ranged P2MR descriptor is intentionally underfilled and still owes a full top-up.
    bool m_deferred_create_keypool_top_up GUARDED_BY(cs_desc_man){false};

    bool AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool AddDescriptorPQCKeyWithDB(WalletBatch& batch, const CPQCPubKey& pubkey, const CPQCKey& key, bool has_encryption_keys = false, const CKeyingMaterial* encryption_key = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool HasBlockedPlaintextPQCKeys() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool IsPlaintextPQCKeyBlocked(const CPQCPubKey& pubkey) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::set<CPQCPubKey> GetBlockedPlaintextPQCKeys() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool ReservePQCSignatureCounters(const CPQCPubKey& pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) const;
    bool ReservePQCSignatureCountersBatch(const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>& ranges) const;
    PQCSignatureCounterReserver MakePQCSignatureCounterReserver() const;
    PQCSignatureCounterBatchReserver MakePQCSignatureCounterBatchReserver() const;

    KeyMap GetKeys() const;

    // Cached FlatSigningProviders to avoid regenerating them each time they are needed.
    mutable std::map<int32_t, FlatSigningProvider> m_map_signing_providers;
    // Fetch the SigningProvider for the given script and optionally include private keys
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CScript& script, bool include_private = false, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const;
    // Fetch the SigningProvider for a given index and optionally include private keys. Called by the above functions.
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(int32_t index, bool include_private = false, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const;
    std::unique_ptr<FlatSigningProvider> GetSigningProviderForPSBTInput(const CScript& script, const PSBTInput& input, bool sign, const PQCSignatureCounterObserver& pqc_counter_observer) const;

protected:
    WalletDescriptor m_wallet_descriptor GUARDED_BY(cs_desc_man);

    //! Same as 'TopUp' but designed for use within a batch transaction context
    bool TopUpWithDB(WalletBatch& batch, unsigned int size = 0, std::optional<bool> internal_hint = std::nullopt);
    util::Result<void> TopUpWithDBResult(WalletBatch& batch, unsigned int size = 0, std::optional<bool> internal_hint = std::nullopt, bool throw_on_persistence_error = false, bool rollback_state_on_error = true);

public:
    DescriptorScriptPubKeyMan(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size);
    DescriptorScriptPubKeyMan(WalletStorage& storage, int64_t keypool_size);

    mutable RecursiveMutex cs_desc_man;

    util::Result<CTxDestination> GetNewDestination(const OutputType type) override;
    bool IsMine(const CScript& script) const override;

    bool CheckDecryptionKey(const CKeyingMaterial& master_key) override;
    bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) override;

    util::Result<CTxDestination> GetReservedDestination(const OutputType type, bool internal, int64_t& index) override;
    void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) override;

    // Tops up the descriptor cache and m_map_script_pub_keys. The cache is stored in the wallet file
    // and is used to expand the descriptor in GetNewDestination. DescriptorScriptPubKeyMan relies
    // more on ephemeral data than LegacyScriptPubKeyMan. For wallets using unhardened derivation
    // (with or without private keys), the "keypool" is a single xpub.
    bool TopUp(unsigned int size = 0) override;
    util::Result<void> TopUpResult(unsigned int size = 0) override;
    bool TopUpWithInternalHint(std::optional<bool> internal_hint, unsigned int size = 0);
    util::Result<void> TopUpWithInternalHintResult(std::optional<bool> internal_hint, unsigned int size = 0);

    std::vector<WalletDestination> MarkUnusedAddresses(const CScript& script) override;

    bool IsHDEnabled() const override;

    //! Setup descriptors based on the given CExtkey
    bool SetupDescriptorGeneration(WalletBatch& batch, const CExtKey& master_key, OutputType addr_type, bool internal, unsigned int initial_keypool_size = 0);
    bool HasDeferredCreateKeyPoolTopUp() const;
    void MaybeRestoreDeferredCreateKeyPoolTopUp();

    bool HavePrivateKeys() const override;
    bool HasPrivKey(const CKeyID& keyid) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    //! Retrieve the particular key if it is available. Returns nullopt if the key is not in the wallet, or if the wallet is locked.
    std::optional<CKey> GetKey(const CKeyID& keyid) const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    bool HaveCryptedKeys() const override;
    PQCKeyValidationInfo GetPQCKeyValidationInfo() const override;

    unsigned int GetKeyPoolSize() const override;

    int64_t GetTimeFirstKey() const override;

    std::unique_ptr<CKeyMetadata> GetMetadata(const CTxDestination& dest) const override;
    std::optional<uint32_t> GetPQCSignatureCounter(const CPQCPubKey& pubkey) const override;

    bool CanGetAddresses(bool internal = false) const override;

    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;

    bool CanProvide(const CScript& script, SignatureData& sigdata) override;

    // Fetch the SigningProvider for the given pubkey and always include private keys. This should only be called by signing code.
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CPubKey& pubkey, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const;
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CPQCPubKey& pubkey, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const;

    bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const override;
    std::unique_ptr<SigningProvider> GetSigningProviderForTransaction(const std::map<COutPoint, Coin>& coins, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const override;
    SigningResult SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const override;
    util::Result<DataPQCSignatureProof> SignDataPQCHash(
        const WitnessV2P2MR& output,
        const uint256& message_hash,
        const std::optional<CPQCPubKey>& requested_pubkey,
        const std::optional<CScript>& requested_leaf_script,
        const std::optional<std::vector<unsigned char>>& requested_control_block,
        const PQCSignatureCounterObserver& pqc_counter_observer = {}) const override;
    std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type = std::nullopt, bool sign = true, bool bip32derivs = false, int* n_signed = nullptr, bool finalize = true, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const override;
    std::optional<PSBTSigningProvider> GetSigningProviderForPSBT(const PartiallySignedTransaction& psbt, bool sign = true, const PQCSignatureCounterObserver& pqc_counter_observer = {}) const override;

    uint256 GetID() const override;

    void SetCache(const DescriptorCache& cache);

    bool AddKey(const CKeyID& key_id, const CKey& key);
    bool AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key);
    bool AddCryptedPQCKey(const CPQCPubKey& pubkey, const std::vector<unsigned char>& crypted_key, uint32_t sig_counter = 0, std::optional<uint256> auth_tag = std::nullopt);
    bool AddPQCKey(const CPQCPubKey& pubkey, const CPQCKey& key, uint32_t sig_counter = 0);
    bool AddPendingPlaintextPQCKey(const CPQCPubKey& pubkey, CKeyingMaterial secret, uint32_t sig_counter = 0);
    std::optional<std::pair<CPQCPubKey, PendingPlaintextPQCKey>> GetNextPendingPlaintextPQCKey() const;
    bool CompletePendingPlaintextPQCKeyValidation(const CPQCPubKey& pubkey, const CPQCKey& key, uint32_t sig_counter);
    bool FailPendingPlaintextPQCKeyValidation(const CPQCPubKey& pubkey);
    std::vector<CPQCPubKey> GetPQCKeys() const;

    bool HasWalletDescriptor(const WalletDescriptor& desc) const;
    util::Result<void> UpdateWalletDescriptor(WalletDescriptor& descriptor);
    bool CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error);
    void AddDescriptorKey(const CKey& key, const CPubKey &pubkey);
    void WriteDescriptor();

    WalletDescriptor GetWalletDescriptor() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys(int32_t minimum_index) const;
    int32_t GetEndRange() const;

    [[nodiscard]] bool GetDescriptorString(std::string& out, const bool priv) const;

    void UpgradeDescriptorCache();
};

/** struct containing information needed for migrating legacy wallets to descriptor wallets */
struct MigrationData
{
    CExtKey master_key;
    std::vector<std::pair<std::string, int64_t>> watch_descs;
    std::vector<std::pair<std::string, int64_t>> solvable_descs;
    std::vector<std::unique_ptr<DescriptorScriptPubKeyMan>> desc_spkms;
    std::shared_ptr<CWallet> watchonly_wallet{nullptr};
    std::shared_ptr<CWallet> solvable_wallet{nullptr};
};

} // namespace wallet

#endif // QBIT_WALLET_SCRIPTPUBKEYMAN_H
