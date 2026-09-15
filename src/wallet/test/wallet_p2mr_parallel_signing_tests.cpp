// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_p2mr_test_util.h>

#include <common/system.h>
#include <interfaces/wallet.h>
#include <util/strencodings.h>
#include <wallet/pqc_usage.h>

#include <algorithm>
#include <cstdlib>
#include <optional>

#ifndef WIN32
#include <sys/resource.h>
#endif

namespace wallet {
using namespace wallet_p2mr_test;

BOOST_FIXTURE_TEST_SUITE(wallet_p2mr_parallel_signing_tests, WalletTestingSetup)

static PartiallySignedTransaction MakePSBT(const P2MRSigningWorkload& workload)
{
    PartiallySignedTransaction psbt{workload.spend_tx};
    for (size_t i = 0; i < workload.spend_tx.vin.size(); ++i) {
        psbt.inputs.at(i).witness_utxo = workload.coins.at(workload.spend_tx.vin.at(i).prevout).out;
    }
    return psbt;
}

BOOST_AUTO_TEST_CASE(P2MRWalletPSBTProgressCancelsBeforeReservation)
{
    static constexpr size_t INPUT_COUNT{2};
    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};
    PartiallySignedTransaction psbt{MakePSBT(workload)};

    bool complete{false};
    size_t n_signed{0};
    bool saw_reserving{false};
    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    const auto error{workload.wallet->FillPSBT(
        psbt,
        complete,
        std::nullopt,
        /*sign=*/true,
        /*bip32derivs=*/true,
        &n_signed,
        /*finalize=*/true,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        },
        [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && progress.cancellable) {
                saw_reserving = true;
                return false;
            }
            return true;
        })};

    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(*error, PSBTError::INCOMPLETE);
    BOOST_CHECK(saw_reserving);
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(n_signed, 0U);
    BOOST_CHECK(observed_ranges.empty());
    for (const auto& pubkeys : workload.pubkeys) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), 0U);
    }
}

BOOST_AUTO_TEST_CASE(P2MRWalletPSBTProgressIgnoresCancelAfterReservation)
{
    static constexpr size_t INPUT_COUNT{2};
    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, INPUT_COUNT)};
    PartiallySignedTransaction psbt{MakePSBT(workload)};

    bool complete{false};
    size_t n_signed{0};
    bool saw_committed_reservation{false};
    bool saw_signing_complete{false};
    bool saw_verification_complete{false};
    std::vector<std::tuple<CPQCPubKey, uint32_t, uint32_t>> observed_ranges;
    const auto error{workload.wallet->FillPSBT(
        psbt,
        complete,
        std::nullopt,
        /*sign=*/true,
        /*bip32derivs=*/true,
        &n_signed,
        /*finalize=*/true,
        [&](const CPQCPubKey& pubkey, uint32_t previous_counter, uint32_t reserved_counter) {
            observed_ranges.emplace_back(pubkey, previous_counter, reserved_counter);
        },
        [&](const SigningProgress& progress) {
            if (!progress.cancellable) saw_committed_reservation = true;
            if (progress.phase == SigningProgressPhase::SIGNING_INPUTS) {
                BOOST_CHECK_EQUAL(progress.total, INPUT_COUNT);
                saw_signing_complete |= progress.completed == INPUT_COUNT;
            }
            if (progress.phase == SigningProgressPhase::VERIFYING_TRANSACTION) {
                saw_verification_complete |= progress.completed == INPUT_COUNT;
            }
            return progress.cancellable;
        })};

    BOOST_CHECK(!error);
    BOOST_CHECK(complete);
    BOOST_CHECK_EQUAL(n_signed, INPUT_COUNT);
    BOOST_CHECK(saw_committed_reservation);
    BOOST_CHECK(saw_signing_complete);
    BOOST_CHECK(saw_verification_complete);
    BOOST_REQUIRE_EQUAL(observed_ranges.size(), INPUT_COUNT);
    for (const auto& pubkeys : workload.pubkeys) {
        BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey), 1U);
    }
}

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

BOOST_AUTO_TEST_CASE(P2MRWalletParallelHonorsCancelAtCounterReservationBoundary)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "1");

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, /*input_count=*/1)};
    bool saw_cancellable_reservation{false};
    bool saw_reservation_boundary{false};
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        {},
        [&](const SigningProgress& progress) {
            if (progress.phase != SigningProgressPhase::RESERVING_PQC_COUNTERS) return true;
            if (progress.cancellable) {
                saw_cancellable_reservation = true;
                return true;
            }
            if (progress.completed == 0) {
                saw_reservation_boundary = true;
                return false;
            }
            return true;
        })};

    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(saw_cancellable_reservation);
    BOOST_CHECK(saw_reservation_boundary);
    BOOST_CHECK(!input_errors.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.front().descriptor_pubkey, workload.pubkeys.front().pqc_pubkey), 0U);
    BOOST_CHECK(workload.spend_tx.vin.front().scriptWitness.IsNull());
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

BOOST_AUTO_TEST_CASE(P2MRWalletSerialHonorsCancelAtCounterReservationBoundary)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "0");

    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, /*input_count=*/1)};
    bool saw_reservation_boundary{false};
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
        {},
        [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS &&
                !progress.cancellable && progress.completed == 0) {
                saw_reservation_boundary = true;
                return false;
            }
            return true;
        })};

    BOOST_CHECK(!signed_ok);
    BOOST_CHECK(saw_reservation_boundary);
    BOOST_CHECK(!input_errors.empty());
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man, workload.pubkeys.front().descriptor_pubkey, workload.pubkeys.front().pqc_pubkey), 0U);
    BOOST_CHECK(workload.spend_tx.vin.front().scriptWitness.IsNull());
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

BOOST_AUTO_TEST_CASE(P2MRCreateTransactionFailureReportsConsumedUsage)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "0");
    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, /*input_count=*/1)};
    std::shared_ptr<CWallet> wallet{std::move(workload.wallet)};
    WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(0, uint256{}));

    CMutableTransaction funding;
    funding.vout.push_back(workload.coins.begin()->second.out);
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(funding), TxStateInactive{}));
    // The P2MR input consumes a durable PQC counter before the second input
    // fails to sign, so creation fails after counter reservation.
    CMutableTransaction unsignable;
    unsignable.vout.emplace_back(COIN, CScript{} << OP_FALSE);
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(unsignable), TxStateInactive{}));

    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = false;
    coin_control.m_feerate = CFeeRate{1'000};
    coin_control.destChange = PKHash{GenerateRandomKey().GetPubKey()};
    coin_control.Select(workload.coins.begin()->first);
    PreselectedInput& unsignable_input{coin_control.Select(COutPoint{unsignable.GetHash(), 0})};
    unsignable_input.SetTxOut(unsignable.vout.front());
    unsignable_input.SetInputWeight(GetTransactionInputWeight(CTxIn{}));

    WalletContext context;
    auto wallet_interface{interfaces::MakeWallet(context, wallet)};
    const std::vector<CRecipient> recipients{{PKHash{GenerateRandomKey().GetPubKey()}, COIN, /*subtract_fee=*/false}};
    int change_pos{-1};
    CAmount fee{0};
    PQCUsageReport usage;
    const auto result{wallet_interface->createTransaction(recipients, coin_control, /*sign=*/true, change_pos, fee, &usage)};
    BOOST_REQUIRE(!result);
    BOOST_CHECK_EQUAL(util::ErrorString(result).original, "Signing transaction failed");
    BOOST_REQUIRE_EQUAL(usage.key_states.size(), 1U);
    BOOST_CHECK(usage.key_states.front().pubkey == workload.pubkeys.front().pqc_pubkey);
    BOOST_CHECK_EQUAL(usage.key_states.front().signature_count, 1U);
    BOOST_CHECK_EQUAL(GetProviderPQCCounter(*workload.p2mr_spk_man,
        workload.pubkeys.front().descriptor_pubkey, workload.pubkeys.front().pqc_pubkey), 1U);
}

static constexpr MixedInputOwner EXTERNAL{MixedInputOwner::EXTERNAL};
static constexpr MixedInputOwner INTERNAL{MixedInputOwner::INTERNAL};
static constexpr MixedInputOwner UNOWNED{MixedInputOwner::UNOWNED};

static const char* OwnerName(MixedInputOwner owner)
{
    switch (owner) {
    case MixedInputOwner::EXTERNAL: return "external";
    case MixedInputOwner::INTERNAL: return "internal";
    case MixedInputOwner::UNOWNED: return "unowned";
    }
    assert(false);
}

static MixedInputOwner OtherManager(MixedInputOwner owner)
{
    return owner == EXTERNAL ? INTERNAL : EXTERNAL;
}

static std::set<int> ErrorIndices(const std::map<int, bilingual_str>& input_errors)
{
    std::set<int> indices;
    for (const auto& [index, _] : input_errors) indices.insert(index);
    return indices;
}

static std::set<unsigned int> FailingInputs(const std::map<unsigned int, std::string>& failures)
{
    std::set<unsigned int> inputs;
    for (const auto& [index, _] : failures) inputs.insert(index);
    return inputs;
}

static std::set<unsigned int> AsSet(const std::vector<unsigned int>& inputs)
{
    return {inputs.begin(), inputs.end()};
}

static bool HasSigningCancelled(const std::map<int, bilingual_str>& input_errors)
{
    return std::any_of(input_errors.begin(), input_errors.end(), [](const auto& entry) {
        return entry.second.original == "Signing cancelled";
    });
}

static bool IsReservationGuard(const SigningProgress& progress)
{
    return progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && !progress.cancellable && progress.completed == 0;
}

static uint32_t MemoryPQCCounter(const MixedManagerP2MRWorkload& workload, unsigned int input)
{
    const auto& pubkeys{*workload.pubkeys.at(input)};
    return GetProviderPQCCounter(workload.SpkMan(workload.owners.at(input)), pubkeys.descriptor_pubkey, pubkeys.pqc_pubkey);
}

//! The only manager a durable commit wrote to.
static MixedInputOwner CommitOwner(const MixedManagerP2MRWorkload& workload, const DurableCommit& commit)
{
    BOOST_REQUIRE_EQUAL(commit.DescIds().size(), 1U);
    const MixedInputOwner owner{workload.OwnerOf(*commit.DescIds().begin())};
    BOOST_REQUIRE(owner != UNOWNED);
    return owner;
}

//! Checks a commit wrote exactly the keys of `inputs`, each as [previous_counter, previous_counter + 1).
static void CheckCommitRanges(const MixedManagerP2MRWorkload& workload, const DurableCommit& commit, const std::vector<unsigned int>& inputs, uint32_t previous_counter)
{
    BOOST_CHECK_EQUAL(commit.ranges.size(), inputs.size());
    for (const unsigned int input : inputs) {
        const auto range_it{commit.ranges.find(workload.RecordKey(input))};
        BOOST_REQUIRE_MESSAGE(range_it != commit.ranges.end(), strprintf("commit %u misses input %u", commit.sequence, input));
        BOOST_CHECK_EQUAL(range_it->second.first, previous_counter);
        BOOST_CHECK_EQUAL(range_it->second.second, previous_counter + 1);
    }
}

static void CheckPQCCounters(interfaces::Chain& chain, const MixedManagerP2MRWorkload& workload, const std::vector<unsigned int>& inputs, uint32_t expected)
{
    const auto reloaded{ReloadPQCCounters(chain, workload)};
    for (const unsigned int input : inputs) {
        BOOST_CHECK_EQUAL(MemoryPQCCounter(workload, input), expected);
        BOOST_CHECK_EQUAL(reloaded.at(workload.RecordKey(input)), expected);
    }
}

static void CheckCountersCommittedBeforeUse(const DurableCounterRecorder& recorder, const std::vector<ObservedCounterRange>& observed)
{
    for (const auto& observation : observed) {
        BOOST_CHECK_MESSAGE(recorder.CommittedBefore(observation),
            strprintf("counter range [%u,%u) observed at sequence %u without an earlier durable commit",
                observation.previous_counter, observation.reserved_counter, observation.sequence));
    }
}

static std::string FormatReloadedCounters(interfaces::Chain& chain, const MixedManagerP2MRWorkload& workload)
{
    std::string out;
    for (const auto& [key, counter] : ReloadPQCCounters(chain, workload)) {
        out += strprintf(" %s:desc=%s..=%u", OwnerName(workload.OwnerOf(key.first)), key.first.GetHex().substr(0, 12), counter);
    }
    return out;
}

static void LogDurableEvidence(const std::string& label, interfaces::Chain& chain, const MixedManagerP2MRWorkload& workload, const DurableCounterRecorder& recorder)
{
    BOOST_TEST_MESSAGE(strprintf("%s external_desc=%s.. internal_desc=%s.. aborts=%d%s\n  reloaded:%s",
        label,
        workload.DescId(EXTERNAL).GetHex().substr(0, 12),
        workload.DescId(INTERNAL).GetHex().substr(0, 12),
        recorder.Database().m_txn_abort_count,
        recorder.Format(),
        FormatReloadedCounters(chain, workload)));
}

BOOST_AUTO_TEST_CASE(MixedManagersUseTwoDurableBatches)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    for (const bool external_first : {true, false}) {
        auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, InterleavedMixedInputs(4, 4, external_first))};
        const CMutableTransaction unsigned_tx{workload.spend_tx};

        DurableCounterRecorder recorder{*workload.wallet};
        std::vector<ObservedCounterRange> observed;
        std::map<int, bilingual_str> input_errors;
        const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
            recorder.MakeObserver(observed),
            [](const SigningProgress&) { return true; })};
        LogDurableEvidence(strprintf("MixedManagersUseTwoDurableBatches external_first=%d", external_first), *m_node.chain, workload, recorder);

        BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
        BOOST_CHECK_MESSAGE(input_errors.empty(), FormatInputErrors(input_errors));

        // One durable batch per manager: a serial fallback would add one-key commits.
        const auto commits{recorder.PQCCommits(/*success=*/true)};
        BOOST_REQUIRE_EQUAL(commits.size(), 2U);
        BOOST_CHECK(recorder.PQCCommits(/*success=*/false).empty());
        BOOST_CHECK_EQUAL(recorder.Database().m_txn_abort_count, 0);
        std::set<MixedInputOwner> committed_owners;
        for (const auto& commit : commits) {
            const MixedInputOwner owner{CommitOwner(workload, commit)};
            committed_owners.insert(owner);
            CheckCommitRanges(workload, commit, workload.InputsOwnedBy(owner), /*previous_counter=*/0);
        }
        BOOST_CHECK(committed_owners == std::set<MixedInputOwner>({EXTERNAL, INTERNAL}));

        BOOST_CHECK_EQUAL(observed.size(), 8U);
        CheckCountersCommittedBeforeUse(recorder, observed);
        CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(EXTERNAL), 1);
        CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(INTERNAL), 1);

        const auto failures{VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins)};
        BOOST_CHECK_MESSAGE(failures.empty(), strprintf("%u inputs failed independent verification", failures.size()));
    }
}

BOOST_AUTO_TEST_CASE(MixedManagersKeepForeignInputErrors)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    for (const bool reversed : {false, true}) {
        std::vector<MixedInputOwner> owners{EXTERNAL, UNOWNED, INTERNAL, EXTERNAL, EXTERNAL, INTERNAL};
        if (reversed) std::reverse(owners.begin(), owners.end());
        const unsigned int unowned_input{reversed ? 4U : 1U};
        const unsigned int precompleted_input{reversed ? 2U : 3U};
        auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
        BOOST_REQUIRE(workload.owners.at(unowned_input) == UNOWNED);
        BOOST_REQUIRE(workload.owners.at(precompleted_input) == EXTERNAL);

        // Complete one external input first, through a provider that only knows that input.
        {
            const COutPoint prevout{workload.spend_tx.vin.at(precompleted_input).prevout};
            const std::map<COutPoint, Coin> precompleted_coins{{prevout, workload.coins.at(prevout)}};
            const auto provider{workload.external_spk_man->GetSigningProviderForTransaction(precompleted_coins)};
            BOOST_REQUIRE(provider);
            std::map<int, bilingual_str> presign_errors;
            BOOST_CHECK(!SignTransaction(workload.spend_tx, provider.get(), workload.coins, SIGHASH_DEFAULT, presign_errors));
        }
        const CMutableTransaction presigned_tx{workload.spend_tx};
        BOOST_REQUIRE(!VerifyP2MRSpend(presigned_tx, presigned_tx, workload.coins).contains(precompleted_input));
        const auto precompleted_witness{presigned_tx.vin.at(precompleted_input).scriptWitness.stack};

        const auto oracle{RunSerialSigningOracle(*m_node.chain, *m_node.args, *workload.wallet, presigned_tx, workload.coins, SIGHASH_DEFAULT)};

        DurableCounterRecorder recorder{*workload.wallet};
        std::vector<ObservedCounterRange> observed;
        std::vector<SigningProgress> progress_events;
        std::map<int, bilingual_str> input_errors;
        const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors,
            recorder.MakeObserver(observed),
            [&](const SigningProgress& progress) {
                progress_events.push_back(progress);
                return true;
            })};
        LogDurableEvidence(strprintf("MixedManagersKeepForeignInputErrors reversed=%d errors={%s} oracle_errors={%s}",
                               reversed, FormatInputErrors(input_errors), FormatInputErrors(oracle.input_errors)),
            *m_node.chain, workload, recorder);

        // The unowned input keeps the transaction incomplete, at its original index.
        BOOST_CHECK(!signed_ok);
        BOOST_CHECK(!oracle.signed_ok);
        BOOST_CHECK(ErrorIndices(input_errors) == std::set<int>{static_cast<int>(unowned_input)});
        BOOST_CHECK(ErrorIndices(input_errors) == ErrorIndices(oracle.input_errors));
        for (const auto& [index, error] : input_errors) {
            BOOST_CHECK(!error.original.empty());
            if (oracle.input_errors.contains(index)) BOOST_CHECK_EQUAL(error.original, oracle.input_errors.at(index).original);
        }
        BOOST_CHECK(workload.spend_tx.vin.at(unowned_input).scriptWitness.IsNull());
        BOOST_CHECK(workload.spend_tx.vin.at(precompleted_input).scriptWitness.stack == precompleted_witness);
        BOOST_CHECK(FailingInputs(VerifyP2MRSpend(presigned_tx, workload.spend_tx, workload.coins)) == std::set<unsigned int>{unowned_input});

        // One batch per manager, covering only that manager's unsigned inputs.
        const auto commits{recorder.PQCCommits(/*success=*/true)};
        BOOST_REQUIRE_EQUAL(commits.size(), 2U);
        BOOST_CHECK(recorder.PQCCommits(/*success=*/false).empty());
        std::set<MixedInputOwner> committed_owners;
        for (const auto& commit : commits) {
            const MixedInputOwner owner{CommitOwner(workload, commit)};
            committed_owners.insert(owner);
            std::vector<unsigned int> unsigned_inputs{workload.InputsOwnedBy(owner)};
            std::erase(unsigned_inputs, precompleted_input);
            CheckCommitRanges(workload, commit, unsigned_inputs, /*previous_counter=*/0);
        }
        BOOST_CHECK(committed_owners == std::set<MixedInputOwner>({EXTERNAL, INTERNAL}));
        CheckCountersCommittedBeforeUse(recorder, observed);
        CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(EXTERNAL), 1);
        CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(INTERNAL), 1);

        // Persisted counters match the serial oracle, except that serial signing
        // re-signs the already complete input and consumes one more counter for
        // it (pre-existing serial behaviour, not changed here).
        const auto durable_counters{ReadDurablePQCCounters(recorder.Database().m_records)};
        BOOST_CHECK_EQUAL(durable_counters.size(), oracle.durable_counters.size());
        for (const auto& [key, counter] : durable_counters) {
            BOOST_REQUIRE(oracle.durable_counters.contains(key));
            const uint32_t serial_extra{key == workload.RecordKey(precompleted_input) ? 1U : 0U};
            BOOST_CHECK_EQUAL(oracle.durable_counters.at(key), counter + serial_extra);
        }

        // Completed inputs only grow across providers and never include the unowned input.
        unsigned int completed{0};
        bool saw_signing_progress{false};
        for (const SigningProgress& progress : progress_events) {
            if (progress.phase != SigningProgressPhase::SIGNING_INPUTS) continue;
            saw_signing_progress = true;
            BOOST_CHECK_EQUAL(progress.total, owners.size());
            BOOST_CHECK_GE(progress.completed, completed);
            BOOST_CHECK_LT(progress.completed, owners.size());
            completed = progress.completed;
        }
        BOOST_CHECK(saw_signing_progress);
        BOOST_CHECK_EQUAL(completed, owners.size() - 1);

        // A provider-local batch alone must report failure with every foreign index.
        CMutableTransaction direct_tx{presigned_tx};
        const auto external_provider{workload.external_spk_man->GetSigningProviderForTransaction(workload.coins)};
        BOOST_REQUIRE(external_provider);
        std::map<int, bilingual_str> direct_errors;
        BOOST_CHECK(!SignTransaction(direct_tx, external_provider.get(), workload.coins, SIGHASH_DEFAULT, direct_errors));
        std::set<unsigned int> foreign_inputs{AsSet(workload.InputsOwnedBy(INTERNAL))};
        foreign_inputs.insert(unowned_input);
        std::set<int> foreign_indices;
        for (const unsigned int input : foreign_inputs) foreign_indices.insert(static_cast<int>(input));
        BOOST_CHECK(ErrorIndices(direct_errors) == foreign_indices);
        BOOST_CHECK(FailingInputs(VerifyP2MRSpend(presigned_tx, direct_tx, workload.coins)) == foreign_inputs);
        for (const unsigned int input : foreign_inputs) {
            BOOST_CHECK(direct_tx.vin.at(input).scriptWitness.IsNull());
        }
    }
}

BOOST_AUTO_TEST_CASE(MixedManagersPreserveSighashContext)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    const std::array<std::pair<int, bool>, 4> cases{{
        {SIGHASH_DEFAULT, true},
        {SIGHASH_ALL, false},
        {SIGHASH_ALL | SIGHASH_ANYONECANPAY, true},
        {SIGHASH_SINGLE, false},
    }};
    for (const auto& [sighash, external_first] : cases) {
        std::vector<MixedInputOwner> owners{InterleavedMixedInputs(2, 2, external_first)};
        static constexpr unsigned int UNOWNED_INPUT{2};
        owners.insert(owners.begin() + UNOWNED_INPUT, UNOWNED);
        auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners, /*output_count=*/owners.size())};

        // The unowned input is completed by its own signer before the wallet
        // signs, serially so the fixture does not depend on the parallel planner.
        uint32_t unowned_counter{0};
        const FlatSigningProvider unowned_provider{MakeUnownedP2MRSigningProvider(workload, unowned_counter)};
        std::map<int, bilingual_str> unowned_errors;
        m_node.args->ForceSetArg("-walletpqcparallel", "0");
        BOOST_CHECK(!SignTransaction(workload.spend_tx, &unowned_provider, workload.coins, sighash, unowned_errors));
        m_node.args->ForceSetArg("-walletpqcparallel", "1");
        const CMutableTransaction presigned_tx{workload.spend_tx};
        BOOST_REQUIRE(!VerifyP2MRSpend(presigned_tx, presigned_tx, workload.coins).contains(UNOWNED_INPUT));

        DurableCounterRecorder recorder{*workload.wallet};
        std::map<int, bilingual_str> input_errors;
        const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, sighash, input_errors)};
        LogDurableEvidence(strprintf("MixedManagersPreserveSighashContext sighash=0x%02x external_first=%d", sighash, external_first), *m_node.chain, workload, recorder);

        BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
        const auto failures{VerifyP2MRSpend(presigned_tx, workload.spend_tx, workload.coins)};
        for (const auto& [input, error] : failures) {
            BOOST_ERROR(strprintf("sighash=0x%02x input %u failed independent verification: %s", sighash, input, error));
        }
        for (unsigned int input{0}; input < owners.size(); ++input) {
            const auto& stack{workload.spend_tx.vin.at(input).scriptWitness.stack};
            BOOST_REQUIRE_GE(stack.size(), 3U);
            BOOST_CHECK_EQUAL(stack.front().size(), PQC_SIG_SIZE + (sighash == SIGHASH_DEFAULT ? 0 : 1));
            if (sighash != SIGHASH_DEFAULT) BOOST_CHECK_EQUAL(stack.front().back(), sighash);
        }

        // Negative control: the signatures commit to the unowned coin's amount unless ANYONECANPAY.
        auto tampered_coins{workload.coins};
        tampered_coins.at(workload.spend_tx.vin.at(UNOWNED_INPUT).prevout).out.nValue -= 1;
        std::set<unsigned int> expected_tampered{UNOWNED_INPUT};
        if (!(sighash & SIGHASH_ANYONECANPAY)) {
            for (unsigned int input{0}; input < owners.size(); ++input) expected_tampered.insert(input);
        }
        BOOST_CHECK(FailingInputs(VerifyP2MRSpend(presigned_tx, workload.spend_tx, tampered_coins)) == expected_tampered);

        const auto commits{recorder.PQCCommits(/*success=*/true)};
        BOOST_REQUIRE_EQUAL(commits.size(), 2U);
        for (const auto& commit : commits) {
            CheckCommitRanges(workload, commit, workload.InputsOwnedBy(CommitOwner(workload, commit)), /*previous_counter=*/0);
        }
    }
}

//! Fails the first durable commit that writes PQC counters to the wallet
//! after another one succeeded, and returns {committed manager, failed manager}.
static std::pair<MixedInputOwner, MixedInputOwner> SignWithSecondCommitFailure(interfaces::Chain& chain, MixedManagerP2MRWorkload& workload, const CMutableTransaction& unsigned_tx, const std::string& label)
{
    DurableCounterRecorder recorder{*workload.wallet};
    bool injected{false};
    recorder.on_commit = [&](const DurableCommit& commit) {
        if (commit.success && !commit.ranges.empty() && !injected) {
            injected = true;
            recorder.Database().m_txn_commit_pass = false;
        } else if (!commit.success) {
            recorder.Database().m_txn_commit_pass = true;
        }
    };
    std::vector<ObservedCounterRange> observed;
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, recorder.MakeObserver(observed), {})};
    LogDurableEvidence(label, chain, workload, recorder);

    BOOST_CHECK(!signed_ok);
    const auto succeeded{recorder.PQCCommits(/*success=*/true)};
    const auto failed{recorder.PQCCommits(/*success=*/false)};
    BOOST_REQUIRE_EQUAL(succeeded.size(), 1U);
    BOOST_REQUIRE_EQUAL(failed.size(), 1U);
    const MixedInputOwner committed{CommitOwner(workload, succeeded.front())};
    const MixedInputOwner failed_owner{CommitOwner(workload, failed.front())};
    BOOST_REQUIRE(committed != failed_owner);
    CheckCommitRanges(workload, succeeded.front(), workload.InputsOwnedBy(committed), /*previous_counter=*/0);
    BOOST_CHECK_GE(recorder.Database().m_txn_abort_count, 1);

    // The committed manager's counters stay consumed; the failed manager signed nothing.
    CheckPQCCounters(chain, workload, workload.InputsOwnedBy(committed), 1);
    CheckPQCCounters(chain, workload, workload.InputsOwnedBy(failed_owner), 0);
    for (const unsigned int input : workload.InputsOwnedBy(failed_owner)) {
        BOOST_CHECK(workload.spend_tx.vin.at(input).scriptWitness.IsNull());
    }
    BOOST_CHECK(FailingInputs(VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins)) == AsSet(workload.InputsOwnedBy(failed_owner)));
    CheckCountersCommittedBeforeUse(recorder, observed);
    return {committed, failed_owner};
}

BOOST_AUTO_TEST_CASE(MixedManagersPreserveDurableCountersOnFailure)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    for (const bool external_first : {true, false}) {
        const auto owners{InterleavedMixedInputs(2, 2, external_first)};

        // (a) The first manager's batch commit fails before anything was signed.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
            const CMutableTransaction unsigned_tx{workload.spend_tx};
            DurableCounterRecorder recorder{*workload.wallet};
            recorder.Database().m_txn_commit_pass = false;
            recorder.on_commit = [&](const DurableCommit& commit) {
                if (!commit.success) recorder.Database().m_txn_commit_pass = true;
            };
            std::vector<ObservedCounterRange> observed;
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, recorder.MakeObserver(observed), {})};
            LogDurableEvidence(strprintf("MixedManagersPreserveDurableCountersOnFailure(a) external_first=%d", external_first), *m_node.chain, workload, recorder);

            BOOST_CHECK(!signed_ok);
            const auto failed{recorder.PQCCommits(/*success=*/false)};
            BOOST_REQUIRE_EQUAL(failed.size(), 1U);
            const MixedInputOwner failed_owner{CommitOwner(workload, failed.front())};
            const MixedInputOwner other_owner{OtherManager(failed_owner)};
            // No serial retry for the failed manager; the other manager still batches (P-F1).
            const auto succeeded{recorder.PQCCommits(/*success=*/true)};
            BOOST_REQUIRE_EQUAL(succeeded.size(), 1U);
            BOOST_CHECK(CommitOwner(workload, succeeded.front()) == other_owner);
            CheckCommitRanges(workload, succeeded.front(), workload.InputsOwnedBy(other_owner), /*previous_counter=*/0);
            BOOST_CHECK_GE(recorder.Database().m_txn_abort_count, 1);

            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(failed_owner), 0);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(other_owner), 1);
            for (const unsigned int input : workload.InputsOwnedBy(failed_owner)) {
                BOOST_CHECK(workload.spend_tx.vin.at(input).scriptWitness.IsNull());
            }
            BOOST_CHECK(FailingInputs(VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins)) == AsSet(workload.InputsOwnedBy(failed_owner)));
            BOOST_CHECK_EQUAL(observed.size(), workload.InputsOwnedBy(other_owner).size());
            CheckCountersCommittedBeforeUse(recorder, observed);
        }

        // (b) then (c): the second commit fails; a retry of the same transaction
        // reuses the committed manager's witnesses and reserves only for the other.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
            const CMutableTransaction unsigned_tx{workload.spend_tx};
            const auto [committed, failed_owner] = SignWithSecondCommitFailure(*m_node.chain, workload, unsigned_tx,
                strprintf("MixedManagersPreserveDurableCountersOnFailure(b->c) external_first=%d", external_first));

            // The committed manager's own inputs are complete and it sees only
            // foreign inputs: its provider reports them and reserves nothing.
            {
                DurableCounterRecorder direct_recorder{*workload.wallet};
                CMutableTransaction direct_tx{workload.spend_tx};
                const auto provider{workload.SpkMan(committed).GetSigningProviderForTransaction(workload.coins)};
                BOOST_REQUIRE(provider);
                std::map<int, bilingual_str> direct_errors;
                BOOST_CHECK(!SignTransaction(direct_tx, provider.get(), workload.coins, SIGHASH_DEFAULT, direct_errors));
                std::set<int> foreign_indices;
                for (const unsigned int input : workload.InputsOwnedBy(failed_owner)) foreign_indices.insert(static_cast<int>(input));
                BOOST_CHECK(ErrorIndices(direct_errors) == foreign_indices);
                BOOST_CHECK(direct_recorder.Commits().empty());
                for (unsigned int input{0}; input < direct_tx.vin.size(); ++input) {
                    BOOST_CHECK(direct_tx.vin[input].scriptWitness.stack == workload.spend_tx.vin[input].scriptWitness.stack);
                }
                CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(committed), 1);
            }

            DurableCounterRecorder recorder{*workload.wallet};
            std::vector<ObservedCounterRange> observed;
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, recorder.MakeObserver(observed), {})};
            LogDurableEvidence(strprintf("MixedManagersPreserveDurableCountersOnFailure(c) external_first=%d", external_first), *m_node.chain, workload, recorder);

            BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
            const auto commits{recorder.PQCCommits(/*success=*/true)};
            BOOST_REQUIRE_EQUAL(commits.size(), 1U);
            BOOST_CHECK(recorder.PQCCommits(/*success=*/false).empty());
            BOOST_CHECK(CommitOwner(workload, commits.front()) == failed_owner);
            CheckCommitRanges(workload, commits.front(), workload.InputsOwnedBy(failed_owner), /*previous_counter=*/0);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(committed), 1);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(failed_owner), 1);
            BOOST_CHECK(VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins).empty());
            CheckCountersCommittedBeforeUse(recorder, observed);
        }

        // (b) then (d): a rebuilt unsigned transaction never reuses consumed counters.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
            const CMutableTransaction unsigned_tx{workload.spend_tx};
            const auto [committed, failed_owner] = SignWithSecondCommitFailure(*m_node.chain, workload, unsigned_tx,
                strprintf("MixedManagersPreserveDurableCountersOnFailure(b->d) external_first=%d", external_first));

            workload.spend_tx = unsigned_tx;
            DurableCounterRecorder recorder{*workload.wallet};
            std::vector<ObservedCounterRange> observed;
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, recorder.MakeObserver(observed), {})};
            LogDurableEvidence(strprintf("MixedManagersPreserveDurableCountersOnFailure(d) external_first=%d", external_first), *m_node.chain, workload, recorder);

            BOOST_REQUIRE_MESSAGE(signed_ok, FormatInputErrors(input_errors));
            const auto commits{recorder.PQCCommits(/*success=*/true)};
            BOOST_REQUIRE_EQUAL(commits.size(), 2U);
            for (const auto& commit : commits) {
                const MixedInputOwner owner{CommitOwner(workload, commit)};
                CheckCommitRanges(workload, commit, workload.InputsOwnedBy(owner), /*previous_counter=*/owner == committed ? 1 : 0);
            }
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(committed), 2);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(failed_owner), 1);
            BOOST_CHECK(VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins).empty());
            CheckCountersCommittedBeforeUse(recorder, observed);
        }
    }
}

BOOST_AUTO_TEST_CASE(MixedManagersHonorReservationBoundary)
{
    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "2");

    for (const bool external_first : {true, false}) {
        const auto owners{InterleavedMixedInputs(2, 2, external_first)};
        const auto all_inputs = [&](const MixedManagerP2MRWorkload& workload) {
            std::vector<unsigned int> inputs{workload.InputsOwnedBy(EXTERNAL)};
            const auto internal_inputs{workload.InputsOwnedBy(INTERNAL)};
            inputs.insert(inputs.end(), internal_inputs.begin(), internal_inputs.end());
            return inputs;
        };

        // (a) A one-shot cancel at the first manager's guard stops every manager.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
            DurableCounterRecorder recorder{*workload.wallet};
            unsigned int guard_events{0};
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, {},
                [&](const SigningProgress& progress) {
                    return !(IsReservationGuard(progress) && ++guard_events == 1);
                })};
            LogDurableEvidence(strprintf("MixedManagersHonorReservationBoundary(a) external_first=%d errors={%s}", external_first, FormatInputErrors(input_errors)), *m_node.chain, workload, recorder);

            BOOST_CHECK(!signed_ok);
            BOOST_CHECK_EQUAL(guard_events, 1U);
            BOOST_CHECK(HasSigningCancelled(input_errors));
            BOOST_CHECK(recorder.PQCCommits(/*success=*/true).empty());
            BOOST_CHECK(recorder.PQCCommits(/*success=*/false).empty());
            CheckPQCCounters(*m_node.chain, workload, all_inputs(workload), 0);
            for (const CTxIn& input : workload.spend_tx.vin) BOOST_CHECK(input.scriptWitness.IsNull());
        }

        // (b) A cancel at the second manager's guard keeps the first manager's commit.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
            const CMutableTransaction unsigned_tx{workload.spend_tx};
            DurableCounterRecorder recorder{*workload.wallet};
            unsigned int guard_events{0};
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, {},
                [&](const SigningProgress& progress) {
                    return !(IsReservationGuard(progress) && ++guard_events == 2);
                })};
            LogDurableEvidence(strprintf("MixedManagersHonorReservationBoundary(b) external_first=%d errors={%s}", external_first, FormatInputErrors(input_errors)), *m_node.chain, workload, recorder);

            BOOST_CHECK(!signed_ok);
            BOOST_CHECK_EQUAL(guard_events, 2U);
            BOOST_CHECK(HasSigningCancelled(input_errors));
            const auto commits{recorder.PQCCommits(/*success=*/true)};
            BOOST_REQUIRE_EQUAL(commits.size(), 1U);
            BOOST_CHECK(recorder.PQCCommits(/*success=*/false).empty());
            const MixedInputOwner committed{CommitOwner(workload, commits.front())};
            CheckCommitRanges(workload, commits.front(), workload.InputsOwnedBy(committed), /*previous_counter=*/0);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(committed), 1);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(OtherManager(committed)), 0);
            BOOST_CHECK(FailingInputs(VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins)) == AsSet(workload.InputsOwnedBy(OtherManager(committed))));
            for (const unsigned int input : workload.InputsOwnedBy(OtherManager(committed))) {
                BOOST_CHECK(workload.spend_tx.vin.at(input).scriptWitness.IsNull());
            }
        }

        // (c) Serial fallback: SIGHASH_SINGLE with a missing output makes every
        // provider sign serially; a one-shot cancel at its first per-signature
        // guard stops the remaining manager too.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners, /*output_count=*/owners.size() - 1)};
            DurableCounterRecorder recorder{*workload.wallet};
            unsigned int guard_events{0};
            bool saw_batch_reservation{false};
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_SINGLE, input_errors, {},
                [&](const SigningProgress& progress) {
                    saw_batch_reservation |= progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && progress.cancellable;
                    return !(IsReservationGuard(progress) && ++guard_events == 1);
                })};
            LogDurableEvidence(strprintf("MixedManagersHonorReservationBoundary(c) external_first=%d errors={%s}", external_first, FormatInputErrors(input_errors)), *m_node.chain, workload, recorder);

            BOOST_CHECK(!signed_ok);
            BOOST_CHECK(!saw_batch_reservation);
            BOOST_CHECK_EQUAL(guard_events, 1U);
            BOOST_CHECK(HasSigningCancelled(input_errors));
            BOOST_CHECK(recorder.PQCCommits(/*success=*/true).empty());
            BOOST_CHECK(recorder.PQCCommits(/*success=*/false).empty());
            CheckPQCCounters(*m_node.chain, workload, all_inputs(workload), 0);
            for (const CTxIn& input : workload.spend_tx.vin) BOOST_CHECK(input.scriptWitness.IsNull());
        }

        // (d) A cancel after the first manager committed is informational for
        // that manager, and stops the next manager before its reservation.
        {
            auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
            const CMutableTransaction unsigned_tx{workload.spend_tx};
            DurableCounterRecorder recorder{*workload.wallet};
            bool reject{false};
            std::map<int, bilingual_str> input_errors;
            const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors, {},
                [&](const SigningProgress& progress) {
                    reject |= progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && progress.total > 0 && progress.completed == progress.total;
                    return !reject;
                })};
            LogDurableEvidence(strprintf("MixedManagersHonorReservationBoundary(d) external_first=%d errors={%s}", external_first, FormatInputErrors(input_errors)), *m_node.chain, workload, recorder);

            BOOST_CHECK(!signed_ok);
            BOOST_CHECK(reject);
            BOOST_CHECK(HasSigningCancelled(input_errors));
            const auto commits{recorder.PQCCommits(/*success=*/true)};
            BOOST_REQUIRE_EQUAL(commits.size(), 1U);
            const MixedInputOwner committed{CommitOwner(workload, commits.front())};
            CheckCommitRanges(workload, commits.front(), workload.InputsOwnedBy(committed), /*previous_counter=*/0);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(committed), 1);
            CheckPQCCounters(*m_node.chain, workload, workload.InputsOwnedBy(OtherManager(committed)), 0);
            BOOST_CHECK(FailingInputs(VerifyP2MRSpend(unsigned_tx, workload.spend_tx, workload.coins)) == AsSet(workload.InputsOwnedBy(OtherManager(committed))));
        }
    }
}

static std::optional<int64_t> ProcessCpuMicros()
{
#ifndef WIN32
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) return std::nullopt;
    return (int64_t{usage.ru_utime.tv_sec} + usage.ru_stime.tv_sec) * 1'000'000 + usage.ru_utime.tv_usec + usage.ru_stime.tv_usec;
#else
    return std::nullopt;
#endif
}

BOOST_AUTO_TEST_CASE(P2MRWalletMixedManagerSerialParallelABBenchmark)
{
    // Measurement runs set P2MR_MIXED_AB_INPUTS_PER_MANAGER (e.g. 25) on a
    // Release build. The default keeps this case a cheap smoke test.
    size_t per_manager{1};
    if (const char* configured{std::getenv("P2MR_MIXED_AB_INPUTS_PER_MANAGER")}) {
        if (const auto parsed{ToIntegral<uint16_t>(configured)}; parsed && *parsed > 0) per_manager = *parsed;
    }

    const auto run = [&](const std::string& layout, const std::vector<MixedInputOwner>& owners, const std::string& threads, bool hook) {
        m_node.args->ForceSetArg("-walletpqcparallel", "1");
        m_node.args->ForceSetArg("-walletpqcsignthreads", threads);
        auto workload{MakeMixedManagerP2MRSigningWorkload(*m_node.chain, owners)};
        auto& database{GetMockableDatabase(*workload.wallet)};
        std::optional<DurableCounterRecorder> recorder;
        if (hook) recorder.emplace(*workload.wallet);
        database.ResetCounts();
        const auto counters_before{ReadDurablePQCCounters(database.m_records)};

        std::map<int, bilingual_str> input_errors;
        const auto cpu_before{ProcessCpuMicros()};
        const auto start{std::chrono::steady_clock::now()};
        const bool signed_ok{workload.wallet->SignTransaction(workload.spend_tx, workload.coins, SIGHASH_DEFAULT, input_errors)};
        const auto elapsed_us{std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count()};
        const auto cpu_after{ProcessCpuMicros()};
        BOOST_CHECK_MESSAGE(signed_ok, FormatInputErrors(input_errors));

        size_t signatures{0};
        for (const CTxIn& input : workload.spend_tx.vin) {
            const auto& stack{input.scriptWitness.stack};
            for (size_t i{0}; i + 2 < stack.size(); ++i) signatures += !stack[i].empty();
        }
        uint64_t counter_delta{0};
        for (const auto& [key, counter] : ReadDurablePQCCounters(database.m_records)) {
            counter_delta += counter - (counters_before.contains(key) ? counters_before.at(key) : 0);
        }

        std::string commits{"unmeasured(hook_off)"};
        if (recorder) {
            std::map<uint256, std::pair<size_t, uint64_t>> by_desc;
            for (const auto& commit : recorder->PQCCommits(/*success=*/true)) {
                for (const uint256& desc_id : commit.DescIds()) ++by_desc[desc_id].first;
                for (const auto& [key, range] : commit.ranges) by_desc[key.first].second += range.second - range.first;
            }
            commits.clear();
            for (const auto& [desc_id, counts] : by_desc) {
                commits += strprintf("%s:desc=%s..:commits=%u:reserved=%u ", OwnerName(workload.OwnerOf(desc_id)), desc_id.GetHex().substr(0, 12), counts.first, counts.second);
            }
            commits += strprintf("failed_pqc_commits=%u", recorder->PQCCommits(/*success=*/false).size());
        }

        const size_t largest_provider_jobs{std::max(workload.InputsOwnedBy(EXTERNAL).size(), workload.InputsOwnedBy(INTERNAL).size())};
        const unsigned int configured_workers{threads == "0" ?
            std::min<unsigned int>({static_cast<unsigned int>(std::max(1, GetNumCores() - 1)), 4U, static_cast<unsigned int>(largest_provider_jobs)}) :
            std::min<unsigned int>(static_cast<unsigned int>(*ToIntegral<uint16_t>(threads)), static_cast<unsigned int>(largest_provider_jobs))};
        const std::string cpu_us{cpu_before && cpu_after ? strprintf("%d", *cpu_after - *cpu_before) : "unknown"};
        const std::string cpu_wall{cpu_before && cpu_after && elapsed_us > 0 ? strprintf("%.2f", double(*cpu_after - *cpu_before) / double(elapsed_us)) : "unknown"};
        BOOST_TEST_MESSAGE(strprintf(
            "mixed-manager A/B layout=%s inputs=%u hook=%s walletpqcsignthreads=%s configured_workers_per_provider=%u cores=%d "
            "signed_ok=%d elapsed_us(steady_clock)=%d process_cpu_us(getrusage)=%s cpu_per_wall=%s "
            "witness_signatures=%u durable_counter_delta=%u txn_commits_total=%d %s",
            layout, owners.size(), hook ? "on" : "off", threads, configured_workers, GetNumCores(),
            signed_ok, elapsed_us, cpu_us, cpu_wall,
            signatures, counter_delta, database.m_txn_commit_count, commits));
    };

    const auto mixed{InterleavedMixedInputs(per_manager, per_manager, /*external_first=*/true)};
    const auto control{InterleavedMixedInputs(2 * per_manager, 0, /*external_first=*/true)};
    run("warmup_discarded", InterleavedMixedInputs(1, 1, /*external_first=*/true), "4", /*hook=*/false);
    for (const auto& [layout, owners] : {std::make_pair(std::string{"mixed"}, mixed), std::make_pair(std::string{"external_only_control"}, control)}) {
        run(layout, owners, "4", /*hook=*/false);
        run(layout, owners, "4", /*hook=*/true);
        run(layout, owners, "0", /*hook=*/false);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
