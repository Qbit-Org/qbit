// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_parallel_signing_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(P2MRWalletParallelSignsManyInputSpend)
{
    static constexpr size_t INPUT_COUNT{10};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, INPUT_COUNT);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    std::vector<CachedP2MRPubKeys> pubkeys;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }
    for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
        pubkeys.push_back(GetCachedP2MRPubKeys(*p2mr_spk_man, pos));
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.back().descriptor_pubkey, pubkeys.back().pqc_pubkey), 0U);
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    std::vector<SigningProgress> progress_events;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        },
        [&](const SigningProgress& progress) {
            progress_events.push_back(progress);
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK(std::get<0>(observed_ranges.at(input_index)) == pubkeys.at(input_index).pqc_pubkey);
        BOOST_CHECK_EQUAL(std::get<1>(observed_ranges.at(input_index)), 0U);
        BOOST_CHECK_EQUAL(std::get<2>(observed_ranges.at(input_index)), 1U);
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.at(input_index).descriptor_pubkey, pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }

    bool saw_reservation{false};
    bool saw_signing_complete{false};
    bool saw_finalizing_complete{false};
    unsigned int previous_signing_completed{0};
    for (const SigningProgress& progress : progress_events) {
        if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS) {
            saw_reservation = true;
            BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
            BOOST_CHECK(progress.completed <= progress.total);
        } else if (progress.phase == SigningProgressPhase::SIGNING_INPUTS) {
            BOOST_CHECK(progress.completed >= previous_signing_completed);
            BOOST_CHECK(progress.completed <= progress.total);
            previous_signing_completed = progress.completed;
            saw_signing_complete |= progress.completed == INPUT_COUNT;
        } else if (progress.phase == SigningProgressPhase::FINALIZING_TRANSACTION) {
            saw_finalizing_complete |= progress.completed == INPUT_COUNT;
        }
    }
    BOOST_CHECK(saw_reservation);
    BOOST_CHECK(saw_signing_complete);
    BOOST_CHECK(saw_finalizing_complete);
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelDefaultArgsUseAutoWorkers)
{
    static constexpr size_t INPUT_COUNT{3};

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    std::vector<SigningProgress> progress_events;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        },
        [&](const SigningProgress& progress) {
            progress_events.push_back(progress);
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK(std::get<0>(observed_ranges.at(input_index)) == workload.pubkeys.at(input_index).pqc_pubkey);
        BOOST_CHECK_EQUAL(std::get<1>(observed_ranges.at(input_index)), 0U);
        BOOST_CHECK_EQUAL(std::get<2>(observed_ranges.at(input_index)), 1U);
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }

    bool saw_reservation_complete{false};
    bool saw_signing_complete{false};
    for (const SigningProgress& progress : progress_events) {
        if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS) {
            BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
            saw_reservation_complete |= progress.completed == INPUT_COUNT;
        } else if (progress.phase == SigningProgressPhase::SIGNING_INPUTS) {
            BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
            saw_signing_complete |= progress.completed == INPUT_COUNT;
        }
    }
    BOOST_CHECK(saw_reservation_complete);
    BOOST_CHECK(saw_signing_complete);
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelIgnoresCancelAfterCounterReservation)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, FOUR_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

    std::vector<CScript> p2mr_scripts;
    std::vector<CachedP2MRPubKeys> pubkeys;
    {
        LOCK(p2mr_spk_man->cs_desc_man);
        const WalletDescriptor wallet_descriptor = p2mr_spk_man->GetWalletDescriptor();
        for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
            std::vector<CScript> scripts;
            FlatSigningProvider out_keys;
            BOOST_REQUIRE(wallet_descriptor.descriptor->ExpandFromCache(pos, wallet_descriptor.cache, scripts, out_keys));
            BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
            p2mr_scripts.push_back(scripts.at(0));
        }
    }
    for (int32_t pos{0}; pos < static_cast<int32_t>(INPUT_COUNT); ++pos) {
        pubkeys.push_back(GetCachedP2MRPubKeys(*p2mr_spk_man, pos));
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.back().descriptor_pubkey, pubkeys.back().pqc_pubkey), 0U);
    }

    CMutableTransaction funding_tx;
    for (const CScript& script : p2mr_scripts) {
        funding_tx.vout.emplace_back(1 * COIN, script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    bool reject_progress{false};
    bool saw_rejected_callback{false};
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors,
        {},
        [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && progress.completed == progress.total) {
                reject_progress = true;
            }
            if (reject_progress) {
                saw_rejected_callback = true;
                return false;
            }
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK(saw_rejected_callback);
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.at(input_index).descriptor_pubkey, pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletSerialIgnoresCancelAfterPQCSigning)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "0");

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};

    bool reject_progress{false};
    bool saw_non_cancellable_progress{false};
    unsigned int rejected_callbacks{0};
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        {},
        [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::SIGNING_INPUTS && progress.completed > 0) {
                reject_progress = true;
            }
            if (reject_progress) {
                saw_non_cancellable_progress |= !progress.cancellable;
                ++rejected_callbacks;
                return false;
            }
            return true;
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK(saw_non_cancellable_progress);
    BOOST_CHECK_GT(rejected_callbacks, 0U);
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelSkipsCompleteInputs)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE_MESSAGE(workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors), FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    input_errors[0] = Untranslated("stale input 0 error");
    input_errors[1] = Untranslated("stale input 1 error");
    BOOST_REQUIRE_MESSAGE(workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        }), FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_CHECK(observed_ranges.empty());
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelReusesQueuedDuplicateKeySignature)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    CPQCKey key;
    key.MakeNewKey();
    const CPQCPubKey pubkey{key.GetPubKey()};
    const CScript leaf_script{P2MRMultiAScript(/*threshold=*/2, {pubkey, pubkey})};
    const std::vector<unsigned char> leaf_script_bytes{ToBytes(leaf_script)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script_bytes, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(pubkey, key);
    provider.mr_trees.emplace(output, builder);

    uint32_t next_counter{0};
    std::vector<uint32_t> reserved_counts;
    provider.pqc_counter_batch_reserver = [&](const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>& ranges) {
        BOOST_REQUIRE_EQUAL(counts.size(), 1U);
        const auto count_it{counts.find(pubkey)};
        BOOST_REQUIRE(count_it != counts.end());
        reserved_counts.push_back(count_it->second);
        ranges.emplace(pubkey, PQCSignatureCounterRange{
            .pubkey = pubkey,
            .previous_counter = next_counter,
            .reserved_counter = next_counter + count_it->second,
        });
        next_counter += count_it->second;
        return true;
    };

    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    provider.pqc_counter_observer = [&](const CPQCPubKey& observed_pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
        observed_ranges.emplace_back(observed_pubkey, previous_counter, reserved_counter);
    };

    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, GetScriptForDestination(output));

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend_tx.vin.at(0).prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE_MESSAGE(SignTransaction(spend_tx, &provider, coins, SIGHASH_DEFAULT, input_errors), FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(reserved_counts.size(), 1U);
    BOOST_CHECK_EQUAL(reserved_counts.front(), 1U);
    BOOST_CHECK_EQUAL(next_counter, 1U);
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), 1U);
    BOOST_CHECK(std::get<0>(observed_ranges.front()) == pubkey);
    BOOST_CHECK_EQUAL(std::get<1>(observed_ranges.front()), 0U);
    BOOST_CHECK_EQUAL(std::get<2>(observed_ranges.front()), 1U);
    BOOST_CHECK(!spend_tx.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelFailsWhenBatchReservationFails)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    CPQCKey first_key;
    CPQCKey second_key;
    first_key.MakeNewKey();
    second_key.MakeNewKey();
    const CPQCPubKey first_pubkey{first_key.GetPubKey()};
    const CPQCPubKey second_pubkey{second_key.GetPubKey()};
    const CScript leaf_script{P2MRMultiAScript(/*threshold=*/1, {first_pubkey, second_pubkey})};
    const std::vector<unsigned char> leaf_script_bytes{ToBytes(leaf_script)};

    TaprootBuilder builder;
    builder.AddP2MR(/*depth=*/0, leaf_script_bytes, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    const WitnessV2P2MR output{builder.GetP2MROutput()};

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(first_pubkey, first_key);
    provider.pqc_keys.emplace(second_pubkey, second_key);
    provider.mr_trees.emplace(output, builder);

    bool batch_attempted{false};
    provider.pqc_counter_batch_reserver = [&](const std::map<CPQCPubKey, uint32_t>& counts, std::map<CPQCPubKey, PQCSignatureCounterRange>&) {
        batch_attempted = true;
        BOOST_REQUIRE_EQUAL(counts.size(), 1U);
        const auto count_it{counts.find(second_pubkey)};
        BOOST_REQUIRE(count_it != counts.end());
        BOOST_CHECK_EQUAL(count_it->second, 1U);
        return false;
    };

    std::vector<CPQCPubKey> serial_reservation_attempts;
    provider.pqc_counter_reserver = [&](const CPQCPubKey& pubkey, uint32_t count, uint32_t& previous_counter, uint32_t& reserved_counter) {
        BOOST_CHECK_EQUAL(count, 1U);
        serial_reservation_attempts.push_back(pubkey);
        if (pubkey == second_pubkey) return false;
        BOOST_CHECK(pubkey == first_pubkey);
        previous_counter = 0;
        reserved_counter = 1;
        return true;
    };

    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(1 * COIN, GetScriptForDestination(output));

    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend_tx.vout.emplace_back(1 * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend_tx.vin.at(0).prevout, Coin{funding_tx.vout.at(0), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(spend_tx, &provider, coins, SIGHASH_DEFAULT, input_errors));
    BOOST_CHECK(batch_attempted);
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1U);
    BOOST_CHECK_EQUAL(input_errors.at(0).original, "PQC signature counter reservation failed");
    BOOST_CHECK(serial_reservation_attempts.empty());
    BOOST_CHECK(spend_tx.vin.at(0).scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelAutoThreadsAssignsSharedKeyCounters)
{
    static constexpr size_t INPUT_COUNT{10};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "0");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

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
    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), 0U);

    CMutableTransaction funding_tx;
    for (size_t i{0}; i < INPUT_COUNT; ++i) {
        funding_tx.vout.emplace_back(1 * COIN, p2mr_script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            BOOST_CHECK(pubkey == pubkeys.pqc_pubkey);
            observed_ranges.emplace_back(previous_counter, reserved_counter);
        })};

    BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
    BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        BOOST_CHECK(observed_ranges.at(input_index) == std::make_pair(static_cast<uint32_t>(input_index), static_cast<uint32_t>(input_index + 1)));
        BOOST_CHECK(!spend_tx.vin.at(input_index).scriptWitness.IsNull());
    }
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), INPUT_COUNT);
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelFailsExhaustedBatchWithoutBurningCounter)
{
    static constexpr size_t INPUT_COUNT{2};
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    auto wallet = CreateDescriptorWallet(*m_node.chain, P2MR_ONLY_OUTPUT_TYPES, SINGLE_ADDRESS_KEYPOOL_SIZE);

    DescriptorScriptPubKeyMan* p2mr_spk_man{nullptr};
    {
        LOCK(wallet->cs_wallet);
        p2mr_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    }
    BOOST_REQUIRE(p2mr_spk_man);

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
    const CachedP2MRPubKeys pubkeys{GetCachedP2MRPubKeys(*p2mr_spk_man, /*pos=*/0)};

    auto provider{p2mr_spk_man->GetSigningProvider(pubkeys.pqc_pubkey)};
    BOOST_REQUIRE(provider);

    uint32_t previous_counter{0};
    uint32_t reserved_counter{0};
    BOOST_REQUIRE(provider->pqc_counter_reserver(pubkeys.pqc_pubkey, PQC_MAX_SIGNATURES - 1, previous_counter, reserved_counter));
    BOOST_CHECK_EQUAL(previous_counter, 0U);
    BOOST_CHECK_EQUAL(reserved_counter, PQC_MAX_SIGNATURES - 1);

    CMutableTransaction funding_tx;
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        funding_tx.vout.emplace_back(1 * COIN, p2mr_script);
    }

    CMutableTransaction spend_tx;
    std::map<COutPoint, Coin> coins;
    const auto funding_txid{funding_tx.GetHash()};
    for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
        const COutPoint prevout{funding_txid, static_cast<uint32_t>(input_index)};
        spend_tx.vin.emplace_back(prevout);
        coins.emplace(prevout, Coin{funding_tx.vout.at(input_index), /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    }
    spend_tx.vout.emplace_back(static_cast<CAmount>(INPUT_COUNT) * COIN - 10'000, GetScriptForRawPubKey(GenerateRandomKey().GetPubKey()));

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!wallet->SignTransaction(spend_tx, coins, SIGHASH_DEFAULT, input_errors));
    BOOST_CHECK(!input_errors.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), PQC_MAX_SIGNATURES - 1);
    for (const CTxIn& input : spend_tx.vin) {
        BOOST_CHECK(input.scriptWitness.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletParallelSerialParallelABBenchmark)
{
    static constexpr size_t INPUT_COUNT{10};

    const auto sign_workload = [](P2MRSigningWorkload& workload) {
        std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
        std::map<int, bilingual_str> input_errors;
        const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
            [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
                observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
            })};

        BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
        BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));
        BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
        for (size_t input_index{0}; input_index < INPUT_COUNT; ++input_index) {
            BOOST_CHECK(!workload.spend_tx.vin.at(input_index).scriptWitness.IsNull());
            BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.at(input_index).descriptor_pubkey, workload.pubkeys.at(input_index).pqc_pubkey), 1U);
        }
    };

    m_node.args->ForceSetArg("-walletpqcparallel", "0");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "0");
    auto serial_workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};
    const auto serial_start{std::chrono::steady_clock::now()};
    sign_workload(serial_workload);
    const auto serial_elapsed_us{std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - serial_start).count()};

    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "0");
    auto parallel_workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};
    const auto parallel_start{std::chrono::steady_clock::now()};
    sign_workload(parallel_workload);
    const auto parallel_elapsed_us{std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - parallel_start).count()};

    BOOST_TEST_MESSAGE(strprintf(
        "P2MR wallet signing A/B input_count=%u serial_us=%d parallel_auto_us=%d",
        static_cast<unsigned int>(INPUT_COUNT),
        serial_elapsed_us,
        parallel_elapsed_us));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
