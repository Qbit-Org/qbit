// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

#include <thread>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_crypted_provider_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(CryptedPQCSigningProviderIgnoresFailedStalePlaintextKey)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->Unlock(passphrase));

    auto initial_provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(initial_provider);
    BOOST_REQUIRE_EQUAL(initial_provider->pqc_keys.count(pubkeys.pqc_pubkey), 1U);
    const CPQCKey crypted_private_key{initial_provider->pqc_keys.at(pubkeys.pqc_pubkey)};
    const auto counter_it{initial_provider->pqc_sig_counters.find(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(counter_it != initial_provider->pqc_sig_counters.end());
    const uint32_t crypted_sig_counter{counter_it->second};

    const CKeyingMaterial duplicate_secret{crypted_private_key.data(), crypted_private_key.data() + crypted_private_key.size()};
    BOOST_REQUIRE(p2mr_spk_man->AddPendingPlaintextPQCKey(pubkeys.pqc_pubkey, duplicate_secret, crypted_sig_counter));
    BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey));

    auto blocked_descriptor_provider{p2mr_spk_man->GetSigningProvider(pubkeys.descriptor_pubkey)};
    BOOST_REQUIRE(blocked_descriptor_provider);
    BOOST_CHECK_EQUAL(blocked_descriptor_provider->pqc_keys.count(pubkeys.pqc_pubkey), 0U);

    BOOST_REQUIRE(p2mr_spk_man->CompletePendingPlaintextPQCKeyValidation(pubkeys.pqc_pubkey, crypted_private_key, crypted_sig_counter));
    // The validated duplicate is a plaintext record in an encrypted wallet:
    // the key stays refused until re-encryption keeps its crypted record.
    BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey));
    BOOST_REQUIRE(wallet->ReencryptPlaintextPQCKeys());

    CPQCKey stale_key;
    stale_key.MakeNewKey();
    BOOST_REQUIRE(stale_key.IsValid());
    const CPQCPubKey stale_pubkey{stale_key.GetPubKey()};
    BOOST_REQUIRE(!(stale_pubkey == pubkeys.pqc_pubkey));
    const CKeyingMaterial stale_secret{stale_key.data(), stale_key.data() + stale_key.size()};
    BOOST_REQUIRE(p2mr_spk_man->AddPendingPlaintextPQCKey(stale_pubkey, stale_secret, /*sig_counter=*/0));
    BOOST_REQUIRE(p2mr_spk_man->FailPendingPlaintextPQCKeyValidation(stale_pubkey));

    const PQCKeyValidationInfo info{p2mr_spk_man->GetPQCKeyValidationInfo()};
    BOOST_CHECK_EQUAL(info.failed_records, 1U);
    BOOST_CHECK(info.signing_blocked);
    BOOST_CHECK(!info.encryption_recommended);

    auto descriptor_provider{p2mr_spk_man->GetSigningProvider(pubkeys.descriptor_pubkey)};
    BOOST_REQUIRE(descriptor_provider);
    BOOST_CHECK_EQUAL(descriptor_provider->pqc_keys.count(pubkeys.pqc_pubkey), 1U);

    auto pqc_provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(pqc_provider);
    BOOST_CHECK_EQUAL(pqc_provider->pqc_keys.count(pubkeys.pqc_pubkey), 1U);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(pqc_provider->pqc_counter_reserver(pubkeys.pqc_pubkey, /*count=*/1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, 1U);
}

BOOST_AUTO_TEST_CASE(MixedCryptedAndValidatedPlaintextPQCKeysRemainUnlockable)
{
    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->Unlock(passphrase));

    CPQCKey plaintext_key;
    plaintext_key.MakeNewKey();
    BOOST_REQUIRE(plaintext_key.IsValid());
    const CPQCPubKey plaintext_pubkey{plaintext_key.GetPubKey()};
    const CKeyingMaterial plaintext_secret{plaintext_key.data(), plaintext_key.data() + plaintext_key.size()};

    BOOST_REQUIRE(p2mr_spk_man->AddPendingPlaintextPQCKey(plaintext_pubkey, plaintext_secret, /*sig_counter=*/7));
    BOOST_REQUIRE(p2mr_spk_man->CompletePendingPlaintextPQCKeyValidation(plaintext_pubkey, plaintext_key, /*sig_counter=*/7));

    // An encrypted wallet keeps a validated plaintext key out of signing
    // until it is re-encrypted.
    PQCKeyValidationInfo info{p2mr_spk_man->GetPQCKeyValidationInfo()};
    BOOST_CHECK(info.status == PQCKeyValidationStatus::COMPLETE);
    BOOST_CHECK_EQUAL(info.validated_records, 1U);
    BOOST_CHECK(info.reencryption_required);
    BOOST_CHECK(info.signing_blocked);

    CScript p2mr_script;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        std::vector<CScript> scripts;
        FlatSigningProvider out_keys;
        BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(/*pos=*/0, wallet_descriptor.cache, scripts, out_keys));
        BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
        p2mr_script = scripts.at(0);
    }
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, p2mr_script);
    std::map<COutPoint, Coin> coins;
    coins.emplace(COutPoint{funding_tx.GetHash(), 0}, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    BOOST_REQUIRE(wallet->Lock());
    BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(plaintext_pubkey));
    auto locked_tx_provider = p2mr_spk_man->GetSigningProviderForTransaction(coins);
    BOOST_REQUIRE(locked_tx_provider);
    CPQCKey provider_key;
    BOOST_CHECK(!locked_tx_provider->GetPQCKey(plaintext_pubkey, provider_key));

    BOOST_REQUIRE(wallet->Unlock(passphrase));
    BOOST_CHECK(!p2mr_spk_man->GetSigningProvider(plaintext_pubkey));
    auto refused_tx_provider = p2mr_spk_man->GetSigningProviderForTransaction(coins);
    BOOST_REQUIRE(refused_tx_provider);
    BOOST_CHECK(!refused_tx_provider->GetPQCKey(plaintext_pubkey, provider_key));

    BOOST_REQUIRE(wallet->ReencryptPlaintextPQCKeys());
    info = p2mr_spk_man->GetPQCKeyValidationInfo();
    BOOST_CHECK(info.status == PQCKeyValidationStatus::NOT_REQUIRED);
    BOOST_CHECK(!info.signing_blocked);
    BOOST_CHECK_EQUAL(*p2mr_spk_man->GetPQCSignatureCounter(plaintext_pubkey), 7U);
    BOOST_CHECK(p2mr_spk_man->GetSigningProvider(plaintext_pubkey));
    auto unlocked_tx_provider = p2mr_spk_man->GetSigningProviderForTransaction(coins);
    BOOST_REQUIRE(unlocked_tx_provider);
    BOOST_CHECK(unlocked_tx_provider->GetPQCKey(plaintext_pubkey, provider_key));

    BOOST_REQUIRE(wallet->Lock());
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    BOOST_CHECK(p2mr_spk_man->GetSigningProvider(plaintext_pubkey));
}

BOOST_AUTO_TEST_CASE(SignTransactionFreesDecryptedProvidersBeforeLockReturns)
{
    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, /*input_count=*/1)};
    CWallet& wallet{*workload.wallet};
    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet.Unlock(passphrase));

    // Each signing provider keeps a copy of the counter observer, so a copy is
    // destroyed while its provider frees the decrypted keys. The first counter
    // reservation starts a Lock(), which must not return before then.
    struct LockProbeState {
        explicit LockProbeState(CWallet& probe_wallet) : wallet{probe_wallet} {}

        CWallet& wallet;
        std::thread locker{};
        std::atomic_bool lock_requested{false};
        std::atomic_bool lock_returned{false};
        std::atomic_bool probing{true};
        std::atomic<int> probes{0};
        std::atomic<int> lock_returned_before_free{0};
    };
    struct LockProbe {
        std::shared_ptr<LockProbeState> state;

        explicit LockProbe(std::shared_ptr<LockProbeState> probe_state) : state{std::move(probe_state)} {}
        LockProbe(const LockProbe&) = default;
        LockProbe(LockProbe&&) = default;
        ~LockProbe()
        {
            if (!state || !state->probing || !state->lock_requested) return;
            ++state->probes;
            // Give a Lock() that is no longer waiting for signers time to return.
            for (int i = 0; i < 50 && !state->lock_returned; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }
            if (state->lock_returned) ++state->lock_returned_before_free;
        }

        void operator()(const CPQCPubKey&, uint32_t, uint32_t) const
        {
            if (state->lock_requested.exchange(true)) return;
            state->locker = std::thread{[probe_state = state.get()] {
                probe_state->wallet.Lock();
                probe_state->lock_returned = true;
            }};
        }
    };

    auto state{std::make_shared<LockProbeState>(wallet)};
    std::map<int, bilingual_str> input_errors;
    bool signed_ok{false};
    {
        const PQCSignatureCounterObserver observer{LockProbe{state}};
        signed_ok = wallet.SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, observer);
        state->probing = false;
    }
    BOOST_REQUIRE(state->lock_requested);
    state->locker.join();

    BOOST_CHECK_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK(state->lock_returned);
    BOOST_CHECK(wallet.IsLocked());
    BOOST_CHECK_GE(state->probes.load(), 1);
    BOOST_CHECK_EQUAL(state->lock_returned_before_free.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
