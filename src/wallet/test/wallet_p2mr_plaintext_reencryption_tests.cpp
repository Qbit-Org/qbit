// Copyright (c) 2026 The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

#include <interfaces/wallet.h>

#include <algorithm>
#include <condition_variable>
#include <future>
#include <thread>

namespace wallet {
using namespace wallet_p2mr_test;

namespace {
const SecureString PASSPHRASE{"test-passphrase"};

struct OldDescriptorKey {
    CPQCPubKey pubkey;
    std::vector<unsigned char> secret;
    CScript script;
};

SerializeData PQCKeyRecordKey(const std::string& type, const uint256& desc_id, const CPQCPubKey& pubkey)
{
    DataStream key;
    key << std::make_pair(type, std::make_pair(desc_id, pubkey));
    return {key.begin(), key.end()};
}

//! Writes the plaintext record v1.0.0 writes. A corrupt record still loads but
//! fails background validation.
void PutPlaintextRecord(MockableData& records, const uint256& desc_id, const OldDescriptorKey& key, uint32_t sig_counter, bool corrupt = false)
{
    std::vector<unsigned char> secret{key.secret};
    if (corrupt) secret.front() ^= 0x01;
    std::vector<unsigned char> to_hash(key.pubkey.begin(), key.pubkey.end());
    to_hash.insert(to_hash.end(), secret.begin(), secret.end());
    std::array<unsigned char, sizeof(sig_counter)> counter_bytes{};
    WriteLE32(counter_bytes.data(), sig_counter);
    to_hash.insert(to_hash.end(), counter_bytes.begin(), counter_bytes.end());

    DataStream value;
    value << secret << Hash(to_hash) << sig_counter;
    records[PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, desc_id, key.pubkey)] = SerializeData{value.begin(), value.end()};
}

bool HasPlaintextRecord(const MockableData& records, const uint256& desc_id, const CPQCPubKey& pubkey)
{
    return records.contains(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, desc_id, pubkey));
}

std::optional<uint32_t> CryptedRecordCounter(const MockableData& records, const uint256& desc_id, const CPQCPubKey& pubkey)
{
    const auto it{records.find(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCCKEY, desc_id, pubkey))};
    if (it == records.end()) return std::nullopt;
    DataStream value{it->second};
    std::vector<unsigned char> crypted_secret;
    uint32_t sig_counter{0};
    uint256 auth_tag;
    value >> crypted_secret >> sig_counter >> auth_tag;
    BOOST_CHECK(value.eof());
    return sig_counter;
}

bool HasAuthTag(const MockableData& records, const uint256& desc_id, const CPQCPubKey& pubkey)
{
    DataStream value{records.at(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCCKEY, desc_id, pubkey))};
    std::vector<unsigned char> crypted_secret;
    uint32_t sig_counter{0};
    value >> crypted_secret >> sig_counter;
    return !value.eof();
}

//! Rewrites a crypted record in the format older versions wrote, without an auth tag.
void StripAuthTag(MockableData& records, const uint256& desc_id, const CPQCPubKey& pubkey)
{
    SerializeData& serialized{records.at(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCCKEY, desc_id, pubkey))};
    DataStream value{serialized};
    std::vector<unsigned char> crypted_secret;
    uint32_t sig_counter{0};
    uint256 auth_tag;
    value >> crypted_secret >> sig_counter >> auth_tag;
    DataStream legacy;
    legacy << crypted_secret << sig_counter;
    serialized = SerializeData{legacy.begin(), legacy.end()};
}

size_t CountPlaintextPQCRecords(const MockableData& records)
{
    return std::count_if(records.begin(), records.end(), [](const auto& record) {
        DataStream key{record.first};
        std::string type;
        key >> type;
        return type == DBKeys::WALLETDESCRIPTORPQCKEY;
    });
}

bool HasRewriteRecord(const MockableData& records)
{
    DataStream key;
    key << DBKeys::POST_ENCRYPTION_REWRITE;
    return records.contains(SerializeData{key.begin(), key.end()});
}

bool RecordsContain(const MockableData& records, std::span<const unsigned char> needle)
{
    return std::any_of(records.begin(), records.end(), [&](const auto& record) {
        const auto& value{record.second};
        return std::search(value.begin(), value.end(), needle.begin(), needle.end(),
                           [](std::byte a, unsigned char b) { return a == std::byte{b}; }) != value.end();
    });
}

DescriptorScriptPubKeyMan& GetDescriptor(CWallet& wallet, const uint256& desc_id)
{
    auto* spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(WITH_LOCK(wallet.cs_wallet, return wallet.GetScriptPubKeyMan(desc_id)))};
    BOOST_REQUIRE(spk_man);
    return *spk_man;
}

void FinishValidation(CWallet& wallet)
{
    while (wallet.RunPlaintextPQCKeyValidationStep() == CWallet::PlaintextPQCKeyValidationStepResult::IN_PROGRESS) {}
}

void CheckReported(const CWallet& wallet, size_t plaintext_records)
{
    const PQCKeyValidationInfo info{wallet.GetPQCKeyValidationInfo()};
    BOOST_CHECK_EQUAL(info.plaintext_records, plaintext_records);
    BOOST_CHECK(info.reencryption_required);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(!info.encryption_recommended);
}

void CheckNotReported(const CWallet& wallet)
{
    const PQCKeyValidationInfo info{wallet.GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::NOT_REQUIRED);
    BOOST_CHECK_EQUAL(info.plaintext_records, 0U);
    BOOST_CHECK(!info.reencryption_required);
    BOOST_CHECK(!info.signing_blocked);
}

struct Spend {
    CMutableTransaction tx;
    std::map<COutPoint, Coin> coins;
};

Spend MakeSpend(const CScript& script)
{
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, script);
    Spend spend;
    const COutPoint prevout{funding_tx.GetHash(), 0};
    spend.tx.vin.emplace_back(prevout);
    spend.tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));
    spend.coins.emplace(prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    return spend;
}

bool Sign(const CWallet& wallet, const CScript& script, const SigningProgressCallback& progress_callback = {})
{
    Spend spend{MakeSpend(script)};
    std::map<int, bilingual_str> input_errors;
    return wallet.SignTransaction(spend.tx, spend.coins, SIGHASH_DEFAULT, input_errors, {}, progress_callback);
}
} // namespace

//! An encrypted wallet whose pre-encryption descriptor holds the plaintext
//! rows a v1.0.0 top-up racing encryptwallet leaves behind (#283).
struct PlaintextReencryptionSetup : public WalletTestingSetup {
    WalletContext context;
    uint256 desc_id;
    std::vector<OldDescriptorKey> keys;
    MockableData encrypted_records;

    PlaintextReencryptionSetup()
    {
        m_args.ForceSetArg("-keypool", "4");
        context.args = &m_args;
        context.chain = m_node.chain.get();

        auto wallet{CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE)};
        DescriptorScriptPubKeyMan* spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(WITH_LOCK(wallet->cs_wallet, return wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)))};
        BOOST_REQUIRE(spk_man);
        desc_id = spk_man->GetID();
        const MockableData plaintext_records{GetMockableDatabase(*wallet).m_records};
        for (int32_t pos{0}; pos < FOUR_ADDRESS_KEYPOOL_SIZE; ++pos) {
            OldDescriptorKey key;
            key.pubkey = GetCachedP2MRPubKeys(*spk_man, pos).pqc_pubkey;
            key.script = GetCachedScriptPubKey(*spk_man, pos);
            const auto it{plaintext_records.find(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, desc_id, key.pubkey))};
            BOOST_REQUIRE(it != plaintext_records.end());
            DataStream value{it->second};
            value >> key.secret;
            keys.push_back(std::move(key));
        }

        // Encryption creates a new seed, so this descriptor becomes inactive
        // and its keys are crypted at counter 0. Advance one to counter 4.
        BOOST_REQUIRE(wallet->EncryptWallet(PASSPHRASE));
        BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
        const auto provider{spk_man->GetSigningProvider(keys.at(3).pubkey)};
        BOOST_REQUIRE(provider);
        uint32_t previous_counter{0};
        uint32_t reserved_counter{0};
        BOOST_REQUIRE(provider->pqc_counter_reserver(keys.at(3).pubkey, /*count=*/4, previous_counter, reserved_counter));
        BOOST_REQUIRE_EQUAL(reserved_counter, 4U);
        BOOST_REQUIRE(wallet->Lock());
        encrypted_records = GetMockableDatabase(*wallet).m_records;
        BOOST_REQUIRE_EQUAL(CountPlaintextPQCRecords(encrypted_records), 0U);
    }

    //! Key 0 has only a plaintext record, at counter 3. Key 1 has a plaintext
    //! record at counter 5 next to its crypted one at 0; key 3 has one at 1
    //! next to its crypted one at 4. Like v1.0.0, there is no record of a
    //! rewrite after encryption.
    MockableData AffectedRecords() const
    {
        MockableData records{encrypted_records};
        DataStream rewrite_key;
        rewrite_key << DBKeys::POST_ENCRYPTION_REWRITE;
        BOOST_REQUIRE(records.erase(SerializeData{rewrite_key.begin(), rewrite_key.end()}) == 1);
        records.erase(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCCKEY, desc_id, keys.at(0).pubkey));
        PutPlaintextRecord(records, desc_id, keys.at(0), /*sig_counter=*/3);
        PutPlaintextRecord(records, desc_id, keys.at(1), /*sig_counter=*/5);
        PutPlaintextRecord(records, desc_id, keys.at(3), /*sig_counter=*/1);
        return records;
    }

    std::shared_ptr<CWallet> Load(const MockableData& records)
    {
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        auto wallet{CWallet::Create(context, "", std::make_unique<MockableDatabase>(records), WALLET_FLAG_DESCRIPTORS, error, warnings)};
        BOOST_REQUIRE_MESSAGE(wallet, error.original);
        return wallet;
    }

    //! Loads the affected records, validates them while locked and unlocks
    //! without re-encrypting, as the low-level unlock does.
    std::shared_ptr<CWallet> LoadValidatedAndUnlocked(const MockableData& records)
    {
        auto wallet{Load(records)};
        FinishValidation(*wallet);
        BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
        return wallet;
    }
};

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_plaintext_reencryption_tests, PlaintextReencryptionSetup)

BOOST_AUTO_TEST_CASE(EncryptedWalletReportsAndRefusesPlaintextPQCKeys)
{
    const MockableData records{AffectedRecords()};
    auto wallet{Load(records)};

    // Pending records count: they are plaintext on disk before validation.
    PQCKeyValidationInfo info{wallet->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::PENDING);
    BOOST_CHECK_EQUAL(info.pending_records, 3U);
    CheckReported(*wallet, 3);
    // Usage already reports the higher counter of a key's records.
    BOOST_CHECK_EQUAL(*GetDescriptor(*wallet, desc_id).GetPQCSignatureCounter(keys.at(1).pubkey), 5U);
    // The load rewrote the file, but the plaintext records are still live.
    BOOST_CHECK_EQUAL(GetMockableDatabase(*wallet).m_rewrite_count, 1);
    BOOST_CHECK(HasRewriteRecord(GetMockableDatabase(*wallet).m_records));
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(GetMockableDatabase(*wallet).m_records), 3U);

    FinishValidation(*wallet);
    info = wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.validated_records, 3U);
    CheckReported(*wallet, 3);
    BOOST_CHECK(wallet->IsLocked());

    // The low-level unlock does not re-encrypt, so the refusal is visible.
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
    CheckReported(*wallet, 3);
    DescriptorScriptPubKeyMan& spk_man{GetDescriptor(*wallet, desc_id)};
    for (const size_t i : {0, 1, 3}) {
        BOOST_CHECK(!spk_man.GetSigningProvider(keys.at(i).pubkey));
        BOOST_CHECK(!Sign(*wallet, keys.at(i).script));
    }
    // Unaffected keys still sign.
    BOOST_CHECK(spk_man.GetSigningProvider(keys.at(2).pubkey));

    // Neither the refusal nor the attempts rewrote a record.
    const MockableData& after{GetMockableDatabase(*wallet).m_records};
    for (const size_t i : {0, 1, 3}) {
        const auto record_key{PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, desc_id, keys.at(i).pubkey)};
        BOOST_CHECK(after.at(record_key) == records.at(record_key));
    }
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(after, desc_id, keys.at(1).pubkey), 0U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(after, desc_id, keys.at(3).pubkey), 4U);

    // Usage reports the higher counter of a key's records.
    BOOST_CHECK_EQUAL(*spk_man.GetPQCSignatureCounter(keys.at(0).pubkey), 3U);
    BOOST_CHECK_EQUAL(*spk_man.GetPQCSignatureCounter(keys.at(1).pubkey), 5U);
    BOOST_CHECK_EQUAL(*spk_man.GetPQCSignatureCounter(keys.at(3).pubkey), 4U);
}

BOOST_AUTO_TEST_CASE(UnlockReencryptsPlaintextPQCKeysAtTheHigherCounter)
{
    auto wallet{Load(AffectedRecords())};
    FinishValidation(*wallet);
    GetMockableDatabase(*wallet).ResetCounts();

    // The GUI unlock path re-encrypts once its unlock has returned.
    auto wallet_interface{interfaces::MakeWallet(context, wallet)};
    BOOST_REQUIRE(wallet_interface->unlock(PASSPHRASE));
    CheckNotReported(*wallet);

    MockableDatabase& db{GetMockableDatabase(*wallet)};
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 1);
    BOOST_CHECK(HasRewriteRecord(db.m_records));
    for (const size_t i : {0, 1, 3}) {
        BOOST_CHECK(!RecordsContain(db.m_records, keys.at(i).secret));
    }
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, keys.at(0).pubkey), 3U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, keys.at(1).pubkey), 5U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, keys.at(3).pubkey), 4U);

    DescriptorScriptPubKeyMan& spk_man{GetDescriptor(*wallet, desc_id)};
    for (const size_t i : {0, 1, 3}) {
        BOOST_CHECK(spk_man.GetSigningProvider(keys.at(i).pubkey));
    }

    // The new records authenticate: a reload unlocks, keeps the counters and
    // signs from the next one.
    const MockableData records{db.m_records};
    wallet_interface.reset();
    wallet.reset();
    auto reloaded{Load(records)};
    CheckNotReported(*reloaded);
    BOOST_REQUIRE(reloaded->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
    DescriptorScriptPubKeyMan& reloaded_spk_man{GetDescriptor(*reloaded, desc_id)};
    BOOST_CHECK_EQUAL(*reloaded_spk_man.GetPQCSignatureCounter(keys.at(0).pubkey), 3U);
    BOOST_CHECK_EQUAL(*reloaded_spk_man.GetPQCSignatureCounter(keys.at(1).pubkey), 5U);
    BOOST_CHECK_EQUAL(*reloaded_spk_man.GetPQCSignatureCounter(keys.at(3).pubkey), 4U);
    BOOST_CHECK(Sign(*reloaded, keys.at(0).script));
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(GetMockableDatabase(*reloaded).m_records, desc_id, keys.at(0).pubkey), 4U);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(GetMockableDatabase(*reloaded).m_records), 0U);
}

BOOST_AUTO_TEST_CASE(ReencryptionErrorDoesNotEscapeUnlockOrValidation)
{
    auto wallet{Load(AffectedRecords())};
    wallet->m_before_reencrypt_pqc_keys_locks = [] { throw std::runtime_error{"injected re-encryption failure"}; };

    // Validation can finish on the scheduler thread, which an exception would stop.
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
    BOOST_CHECK_NO_THROW(FinishValidation(*wallet));
    CheckReported(*wallet, 3);
    BOOST_REQUIRE(wallet->Lock());

    // The GUI unlock still unlocks; the records stay reported and refused.
    auto wallet_interface{interfaces::MakeWallet(context, wallet)};
    bool unlocked{false};
    BOOST_CHECK_NO_THROW(unlocked = wallet_interface->unlock(PASSPHRASE));
    BOOST_CHECK(unlocked);
    BOOST_CHECK(!wallet->IsLocked());
    CheckReported(*wallet, 3);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(GetMockableDatabase(*wallet).m_records), 3U);

    wallet->m_before_reencrypt_pqc_keys_locks = nullptr;
    BOOST_REQUIRE(wallet_interface->unlock(PASSPHRASE));
    CheckNotReported(*wallet);
}

BOOST_AUTO_TEST_CASE(NoReencryptionWithoutACryptedKeyToVerifyThePassphrase)
{
    // Without any crypted key, unlocking cannot tell a wrong master key from
    // the right one, so the plaintext records must stay as they are.
    MockableData records{AffectedRecords()};
    std::erase_if(records, [](const auto& record) {
        DataStream key{record.first};
        std::string type;
        key >> type;
        return type == DBKeys::WALLETDESCRIPTORCKEY || type == DBKeys::WALLETDESCRIPTORPQCCKEY;
    });
    auto wallet{LoadValidatedAndUnlocked(records)};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    db.ResetCounts();
    const MockableData before{db.m_records};

    BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK(db.m_records == before);
    BOOST_CHECK_EQUAL(db.m_txn_begin_count, 0);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 3U);
    CheckReported(*wallet, 3);
}

BOOST_AUTO_TEST_CASE(TopUpLeavesAFailedRecordAlone)
{
    // Learn the key a top-up will derive at the next index.
    auto source{CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE)};
    const MockableData unencrypted_records{GetMockableDatabase(*source).m_records};
    auto* source_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(WITH_LOCK(source->cs_wallet, return source->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)))};
    BOOST_REQUIRE(source_spk_man);
    const uint256 source_desc_id{source_spk_man->GetID()};
    BOOST_REQUIRE(source_spk_man->TopUp(FOUR_ADDRESS_KEYPOOL_SIZE + 1));
    OldDescriptorKey next_key;
    next_key.pubkey = GetCachedP2MRPubKeys(*source_spk_man, FOUR_ADDRESS_KEYPOOL_SIZE).pqc_pubkey;
    DataStream value{GetMockableDatabase(*source).m_records.at(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, source_desc_id, next_key.pubkey))};
    value >> next_key.secret;

    // Encrypt the wallet as it was before that top-up, then add a record for
    // that key that fails validation.
    auto encrypted{Load(unencrypted_records)};
    FinishValidation(*encrypted);
    BOOST_REQUIRE(encrypted->EncryptWallet(PASSPHRASE));
    MockableData records{GetMockableDatabase(*encrypted).m_records};
    encrypted.reset();
    PutPlaintextRecord(records, source_desc_id, next_key, /*sig_counter=*/52, /*corrupt=*/true);
    const SerializeData plaintext_key{PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, source_desc_id, next_key.pubkey)};
    const SerializeData plaintext_value{records.at(plaintext_key)};

    auto wallet{LoadValidatedAndUnlocked(records)};
    BOOST_REQUIRE_EQUAL(wallet->GetPQCKeyValidationInfo().failed_records, 1U);
    DescriptorScriptPubKeyMan& spk_man{GetDescriptor(*wallet, source_desc_id)};
    BOOST_REQUIRE(spk_man.TopUp(FOUR_ADDRESS_KEYPOOL_SIZE + 1));

    // The top-up kept the failed record and wrote no record at counter 0.
    const MockableData& after{GetMockableDatabase(*wallet).m_records};
    BOOST_CHECK(after.at(plaintext_key) == plaintext_value);
    BOOST_CHECK(!CryptedRecordCounter(after, source_desc_id, next_key.pubkey));
    BOOST_CHECK(!spk_man.GetSigningProvider(next_key.pubkey));
    CheckReported(*wallet, 1);
}

BOOST_AUTO_TEST_CASE(NothingToReencryptIsANoOp)
{
    auto wallet{Load(encrypted_records)};
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    db.ResetCounts();
    bool hook_ran{false};
    wallet->m_before_reencrypt_pqc_keys_locks = [&] { hook_ran = true; };
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK(!hook_ran);
    BOOST_CHECK_EQUAL(db.m_txn_begin_count, 0);
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 0);
    BOOST_CHECK_EQUAL(db.m_write_count, 0);
}

BOOST_AUTO_TEST_CASE(PendingValidationKeyIsReencryptedWhenValidationFinishes)
{
    auto wallet{Load(AffectedRecords())};
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));

    // An unvalidated record is never re-encrypted.
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    db.ResetCounts();
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK_EQUAL(db.m_txn_begin_count, 0);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 3U);
    CheckReported(*wallet, 3);

    // The step that finishes validation re-encrypts while the wallet is unlocked.
    FinishValidation(*wallet);
    CheckNotReported(*wallet);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, keys.at(0).pubkey), 3U);
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 1);
}

BOOST_AUTO_TEST_CASE(ValidationFinishingWhileLockedWaitsForUnlock)
{
    auto wallet{Load(AffectedRecords())};
    FinishValidation(*wallet);
    CheckReported(*wallet, 3);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(GetMockableDatabase(*wallet).m_records), 3U);
    BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());

    // ChangeWalletPassphrase unlocks internally but does not re-encrypt.
    const SecureString new_passphrase{"new-passphrase"};
    BOOST_REQUIRE(wallet->ChangeWalletPassphrase(PASSPHRASE, new_passphrase));
    BOOST_CHECK(wallet->IsLocked());
    CheckReported(*wallet, 3);

    BOOST_REQUIRE(wallet->Unlock(new_passphrase, /*run_pending_initial_keypool_top_up=*/false));
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    CheckNotReported(*wallet);
}

BOOST_AUTO_TEST_CASE(FailedValidationRecordIsNeitherAdoptedNorReencrypted)
{
    MockableData records{AffectedRecords()};
    records.erase(PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCCKEY, desc_id, keys.at(2).pubkey));
    PutPlaintextRecord(records, desc_id, keys.at(2), /*sig_counter=*/0, /*corrupt=*/true);
    auto wallet{LoadValidatedAndUnlocked(records)};

    PQCKeyValidationInfo info{wallet->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::FAILED);
    BOOST_CHECK_EQUAL(info.failed_records, 1U);

    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    const MockableData& after{GetMockableDatabase(*wallet).m_records};
    BOOST_CHECK(HasPlaintextRecord(after, desc_id, keys.at(2).pubkey));
    BOOST_CHECK(!CryptedRecordCounter(after, desc_id, keys.at(2).pubkey));
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(after), 1U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(after, desc_id, keys.at(0).pubkey), 3U);

    info = wallet->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::FAILED);
    BOOST_CHECK_EQUAL(info.validated_records, 0U);
    CheckReported(*wallet, 1);
    BOOST_CHECK(!wallet->IsPQCKeyValidationReadyForPrivateKeyUse());
    BOOST_CHECK(!GetDescriptor(*wallet, desc_id).GetSigningProvider(keys.at(2).pubkey));
}

BOOST_AUTO_TEST_CASE(ReencryptionFailureMovesNoKeyAndRetries)
{
    const MockableData records{AffectedRecords()};
    for (const bool fail_commit : {true, false}) {
        auto wallet{LoadValidatedAndUnlocked(records)};
        MockableDatabase& db{GetMockableDatabase(*wallet)};
        db.ResetCounts();
        if (fail_commit) {
            db.m_txn_commit_pass = false;
        } else {
            // The second crypted record fails to write.
            db.m_write_fail_after = 1;
        }

        const MockableData before{db.m_records};
        BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());
        BOOST_CHECK(db.m_records == before);
        BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 3U);
        BOOST_CHECK_EQUAL(db.m_rewrite_count, 0);
        CheckReported(*wallet, 3);
        DescriptorScriptPubKeyMan& spk_man{GetDescriptor(*wallet, desc_id)};
        for (const size_t i : {0, 1, 3}) {
            BOOST_CHECK(!spk_man.GetSigningProvider(keys.at(i).pubkey));
        }
        BOOST_CHECK_EQUAL(*spk_man.GetPQCSignatureCounter(keys.at(1).pubkey), 5U);

        db.m_txn_commit_pass = true;
        db.m_write_fail_after = -1;
        BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
        CheckNotReported(*wallet);
        BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
        BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, keys.at(1).pubkey), 5U);
    }
}

BOOST_AUTO_TEST_CASE(PlaintextEraseFailureMovesNoKeyAndRetries)
{
    auto wallet{LoadValidatedAndUnlocked(AffectedRecords())};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    db.ResetCounts();
    // Every plaintext erase fails, without aborting the transaction.
    DataStream prefix;
    prefix << DBKeys::WALLETDESCRIPTORPQCKEY;
    db.m_erase_fail_prefix = SerializeData{prefix.begin(), prefix.end()};

    const MockableData before{db.m_records};
    BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK(db.m_records == before);
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 0);
    CheckReported(*wallet, 3);
    DescriptorScriptPubKeyMan& spk_man{GetDescriptor(*wallet, desc_id)};
    for (const size_t i : {0, 1, 3}) {
        BOOST_CHECK(!spk_man.GetSigningProvider(keys.at(i).pubkey));
    }

    db.m_erase_fail_prefix.reset();
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    CheckNotReported(*wallet);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
    BOOST_CHECK(HasRewriteRecord(db.m_records));
}

BOOST_AUTO_TEST_CASE(TopUpParkedAfterItsSnapshotCommitsAfterReencryption)
{
    auto wallet{LoadValidatedAndUnlocked(AffectedRecords())};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    DescriptorScriptPubKeyMan& spk_man{GetDescriptor(*wallet, desc_id)};

    // The top-up takes its key snapshot, then waits before its descriptor lock.
    std::promise<void> reached;
    std::promise<void> release;
    const std::shared_future<void> released{release.get_future()};
    spk_man.m_after_prepare_top_up = [&] {
        reached.set_value();
        released.wait();
    };
    std::future<bool> top_up{std::async(std::launch::async, [&] { return spk_man.TopUp(FOUR_ADDRESS_KEYPOOL_SIZE + 2); })};
    struct Releaser {
        std::promise<void>& release;
        bool done{false};
        void operator()() { if (!done) release.set_value(); done = true; }
        ~Releaser() { (*this)(); }
    } releaser{release};
    BOOST_REQUIRE(reached.get_future().wait_for(std::chrono::seconds{30}) == std::future_status::ready);

    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
    releaser();
    BOOST_CHECK(top_up.get());
    spk_man.m_after_prepare_top_up = {};

    // The top-up then committed its new keys encrypted.
    CheckNotReported(*wallet);
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
    for (const int32_t pos : {int32_t{FOUR_ADDRESS_KEYPOOL_SIZE}, int32_t{FOUR_ADDRESS_KEYPOOL_SIZE + 1}}) {
        BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, GetCachedP2MRPubKeys(spk_man, pos).pqc_pubkey), 0U);
    }
}

BOOST_AUTO_TEST_CASE(LegacyTagUpgradeLeavesShadowingPlaintextRecord)
{
    // Key 1's crypted record, at counter 0, has no auth tag and a plaintext
    // record at counter 5 next to it. Key 2 only has a legacy crypted record.
    MockableData records{AffectedRecords()};
    StripAuthTag(records, desc_id, keys.at(1).pubkey);
    StripAuthTag(records, desc_id, keys.at(2).pubkey);

    // The first unlock upgrades legacy records, but leaves key 1 alone: its
    // upgrade would erase the plaintext record at the lower counter.
    auto wallet{LoadValidatedAndUnlocked(records)};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    BOOST_CHECK(HasAuthTag(db.m_records, desc_id, keys.at(2).pubkey));
    BOOST_CHECK(!HasAuthTag(db.m_records, desc_id, keys.at(1).pubkey));
    BOOST_CHECK(HasPlaintextRecord(db.m_records, desc_id, keys.at(1).pubkey));

    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK(!HasPlaintextRecord(db.m_records, desc_id, keys.at(1).pubkey));
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(db.m_records, desc_id, keys.at(1).pubkey), 5U);

    const MockableData reencrypted{db.m_records};
    wallet.reset();
    auto reloaded{Load(reencrypted)};
    BOOST_REQUIRE(reloaded->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
    BOOST_CHECK_EQUAL(*GetDescriptor(*reloaded, desc_id).GetPQCSignatureCounter(keys.at(1).pubkey), 5U);
}

BOOST_AUTO_TEST_CASE(FailedRecordShadowingCryptedRecordStaysRefused)
{
    // Key 2 keeps its crypted record, next to a plaintext record that fails validation.
    MockableData records{AffectedRecords()};
    PutPlaintextRecord(records, desc_id, keys.at(2), /*sig_counter=*/9, /*corrupt=*/true);
    const SerializeData plaintext_key{PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCKEY, desc_id, keys.at(2).pubkey)};
    const SerializeData crypted_key{PQCKeyRecordKey(DBKeys::WALLETDESCRIPTORPQCCKEY, desc_id, keys.at(2).pubkey)};
    const SerializeData plaintext_value{records.at(plaintext_key)};
    const SerializeData crypted_value{records.at(crypted_key)};

    auto wallet{LoadValidatedAndUnlocked(records)};
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK_EQUAL(wallet->GetPQCKeyValidationInfo().failed_records, 1U);
    CheckReported(*wallet, 1);
    BOOST_CHECK(!GetDescriptor(*wallet, desc_id).GetSigningProvider(keys.at(2).pubkey));
    BOOST_CHECK(!Sign(*wallet, keys.at(2).script));
    const MockableData& after{GetMockableDatabase(*wallet).m_records};
    BOOST_CHECK(after.at(plaintext_key) == plaintext_value);
    BOOST_CHECK(after.at(crypted_key) == crypted_value);

    // The state survives a reload.
    const MockableData saved{after};
    wallet.reset();
    auto reloaded{LoadValidatedAndUnlocked(saved)};
    BOOST_CHECK_EQUAL(reloaded->GetPQCKeyValidationInfo().failed_records, 1U);
    CheckReported(*reloaded, 1);
    BOOST_CHECK(!GetDescriptor(*reloaded, desc_id).GetSigningProvider(keys.at(2).pubkey));
    BOOST_CHECK(GetMockableDatabase(*reloaded).m_records.at(plaintext_key) == plaintext_value);
}

BOOST_AUTO_TEST_CASE(RewriteFailureIsRetriedAtNextLoadWithoutBlockingSigning)
{
    auto wallet{LoadValidatedAndUnlocked(AffectedRecords())};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    BOOST_REQUIRE(HasRewriteRecord(db.m_records));
    db.ResetCounts();
    db.m_rewrite_pass = false;

    // The transaction erased the rewrite record and committed; the rewrite failed.
    BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 1);
    BOOST_CHECK(!HasRewriteRecord(db.m_records));
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(db.m_records), 0U);
    CheckNotReported(*wallet);
    BOOST_CHECK(GetDescriptor(*wallet, desc_id).GetSigningProvider(keys.at(0).pubkey));

    // An unlock does not retry the rewrite; the next load does.
    db.m_rewrite_pass = true;
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 1);
    const MockableData records{db.m_records};
    wallet.reset();
    auto reloaded{Load(records)};
    BOOST_CHECK_EQUAL(GetMockableDatabase(*reloaded).m_rewrite_count, 1);
    BOOST_CHECK(HasRewriteRecord(GetMockableDatabase(*reloaded).m_records));
    CheckNotReported(*reloaded);
}

BOOST_AUTO_TEST_CASE(BackupAfterFailedRewriteRewritesFirstOrIsRefused)
{
    auto wallet{LoadValidatedAndUnlocked(AffectedRecords())};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    db.ResetCounts();
    db.m_rewrite_pass = false;
    BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());
    BOOST_REQUIRE(!HasRewriteRecord(db.m_records));
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 1);

    // A copy would include the old records' bytes, so while the rewrite
    // still fails the backup is refused.
    const std::string destination{fs::PathToString(m_args.GetDataDirBase() / "reencrypted.bak")};
    BOOST_CHECK(!wallet->BackupWallet(destination));
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 2);
    BOOST_CHECK(!HasRewriteRecord(db.m_records));

    // Once the rewrite works, the backup rewrites the file first.
    db.m_rewrite_pass = true;
    BOOST_CHECK(wallet->BackupWallet(destination));
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 3);
    BOOST_CHECK(HasRewriteRecord(db.m_records));
    BOOST_CHECK(wallet->BackupWallet(destination));
    BOOST_CHECK_EQUAL(db.m_rewrite_count, 3);
}

BOOST_AUTO_TEST_CASE(RelockBeforeReencryptionLeavesWalletReported)
{
    auto wallet{LoadValidatedAndUnlocked(AffectedRecords())};
    wallet->m_before_reencrypt_pqc_keys_locks = [&] { BOOST_REQUIRE(wallet->Lock()); };

    const MockableData before{GetMockableDatabase(*wallet).m_records};
    BOOST_CHECK(!wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(GetMockableDatabase(*wallet).m_records == before);
    CheckReported(*wallet, 3);

    wallet->m_before_reencrypt_pqc_keys_locks = nullptr;
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    CheckNotReported(*wallet);
}

BOOST_AUTO_TEST_CASE(WalletLockWaitsForBackgroundReencryption)
{
    auto wallet{Load(AffectedRecords())};
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE, /*run_pending_initial_keypool_top_up=*/false));

    // A walletlock arriving once the transaction is open must wait for it.
    std::future<bool> lock_result;
    bool lock_waited{false};
    wallet->m_after_reencrypt_pqc_keys_txn_begin = [&] {
        lock_result = std::async(std::launch::async, [&] { return wallet->Lock(); });
        lock_waited = lock_result.wait_for(std::chrono::milliseconds{200}) == std::future_status::timeout;
    };
    // The validation step that finishes validation runs the re-encryption.
    FinishValidation(*wallet);
    BOOST_REQUIRE(lock_result.valid());
    BOOST_CHECK(lock_waited);
    BOOST_CHECK(lock_result.get());
    BOOST_CHECK(wallet->IsLocked());

    // All or nothing: every record moved before the lock took effect.
    CheckNotReported(*wallet);
    const MockableData& after{GetMockableDatabase(*wallet).m_records};
    BOOST_CHECK_EQUAL(CountPlaintextPQCRecords(after), 0U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(after, desc_id, keys.at(0).pubkey), 3U);
    BOOST_CHECK_EQUAL(*CryptedRecordCounter(after, desc_id, keys.at(1).pubkey), 5U);
}

BOOST_AUTO_TEST_CASE(ReencryptionWaitsForActiveSigner)
{
    auto wallet{LoadValidatedAndUnlocked(AffectedRecords())};
    auto* active_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(WITH_LOCK(wallet->cs_wallet, return wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false)))};
    BOOST_REQUIRE(active_spk_man);
    const uint256 active_id{active_spk_man->GetID()};
    BOOST_REQUIRE(active_id != desc_id);
    const CScript active_script{GetCachedScriptPubKey(*active_spk_man, 0)};
    const CPQCPubKey active_pubkey{GetCachedP2MRPubKeys(*active_spk_man, 0).pqc_pubkey};
    MockableDatabase& db{GetMockableDatabase(*wallet)};
    BOOST_REQUIRE_EQUAL(*CryptedRecordCounter(db.m_records, active_id, active_pubkey), 0U);

    std::mutex mutex;
    std::condition_variable cv;
    bool signer_active{false};
    bool reencryption_started{false};
    wallet->m_before_reencrypt_pqc_keys_locks = [&] {
        std::lock_guard lock{mutex};
        reencryption_started = true;
        cv.notify_all();
    };

    // The signer pauses inside its active-signing snapshot, before it reserves
    // a counter, until the re-encryption has started and is waiting for it.
    std::future<bool> signed_result{std::async(std::launch::async, [&] {
        bool paused{false};
        return Sign(*wallet, active_script, [&](const SigningProgress&) {
            if (!paused) {
                paused = true;
                std::unique_lock lock{mutex};
                signer_active = true;
                cv.notify_all();
                cv.wait_for(lock, std::chrono::seconds{30}, [&] { return reencryption_started; });
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds{100});
            }
            return true;
        });
    })};
    {
        std::unique_lock lock{mutex};
        BOOST_REQUIRE(cv.wait_for(lock, std::chrono::seconds{30}, [&] { return signer_active; }));
    }

    // The signer's counter reservation commits inside its snapshot, so the
    // re-encryption only begins its transaction after the signer is done.
    std::optional<uint32_t> signer_counter_at_txn_begin;
    wallet->m_after_reencrypt_pqc_keys_txn_begin = [&] {
        signer_counter_at_txn_begin = CryptedRecordCounter(db.m_records, active_id, active_pubkey);
    };
    BOOST_CHECK(wallet->ReencryptPlaintextPQCKeys());
    BOOST_CHECK(signed_result.get());
    BOOST_REQUIRE(signer_counter_at_txn_begin);
    BOOST_CHECK_EQUAL(*signer_counter_at_txn_begin, 1U);
    CheckNotReported(*wallet);
    BOOST_CHECK(Sign(*wallet, keys.at(0).script));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
