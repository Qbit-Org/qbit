// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <util/strencodings.h>
#include <wallet/feebumper.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_p2mr_test_util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <future>

namespace wallet {
namespace feebumper {
BOOST_FIXTURE_TEST_SUITE(feebumper_tests, WalletTestingSetup)

static void CheckMaxWeightComputation(const std::string& script_str, const std::vector<std::string>& witness_str_stack, const std::string& prevout_script_str, int64_t expected_max_weight)
{
    std::vector script_data(ParseHex(script_str));
    CScript script(script_data.begin(), script_data.end());
    CTxIn input(Txid{}, 0, script);

    for (const auto& s : witness_str_stack) {
        input.scriptWitness.stack.push_back(ParseHex(s));
    }

    std::vector prevout_script_data(ParseHex(prevout_script_str));
    CScript prevout_script(prevout_script_data.begin(), prevout_script_data.end());

    int64_t weight = GetTransactionInputWeight(input);
    SignatureWeights weights;
    SignatureWeightChecker size_checker(weights, DUMMY_CHECKER);
    bool script_ok = VerifyScript(input.scriptSig, prevout_script, &input.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, size_checker);
    BOOST_CHECK(script_ok);
    weight += weights.GetWeightDiffToMax();
    BOOST_CHECK_EQUAL(weight, expected_max_weight);
}

BOOST_AUTO_TEST_CASE(external_max_weight_test)
{
    // P2PKH
    CheckMaxWeightComputation("453042021f03c8957c5ce12940ee6e3333ecc3f633d9a1ac53a55b3ce0351c617fa96abe021f0dccdcce3ef45a63998be9ec748b561baf077b8e862941d0cd5ec08f5afe68012102fccfeb395f0ecd3a77e7bc31c3bc61dc987418b18e395d441057b42ca043f22c", {}, "76a914f60dcfd3392b28adc7662669603641f578eed72d88ac", 149);
    // P2SH-P2WPKH
    CheckMaxWeightComputation("160014001dca1b22c599b5a56a87c78417ad2ff39552f1", {"3042021f5443c58eaf45f3e5ef46f8516f966b334a7d497cedda4edb2b9fad57c90c3b021f63a77cb56cde848e2e2dd20b487eec2f53101f634193786083f60b4d23a82301", "026cfe86116f161057deb240201d6b82ebd4f161e0200d63dc9aca65a1d6b38bb7"}, "a9147c8ab5ad7708b97ccb6b483d57aba48ee85214df87", 172);
    // P2WPKH
    CheckMaxWeightComputation("", {"3042021f0f8906f0394979d5b737134773e5b88bf036c7d63542301d600ab677ba5a59021f0e9fe07e62c113045fa1c1532e2914720e8854d189c4f5b8c88f57956b704401", "0359edba11ed1a0568094a6296a16c4d5ee4c8cfe2f5e2e6826871b5ecf8188f79"}, "00149961a78658030cc824af4c54fbf5294bec0cabdd", 149);
    // P2WSH HTLC
    CheckMaxWeightComputation("", {"3042021f5c4c29e6b686aae5b6d0751e90208592ea96d26bc81d78b0d3871a94a21fa8021f74dc2f971e438ccece8699c8fd15704c41df219ab37b63264f2147d15c34d801", "01", "6321024cf55e52ec8af7866617dc4e7ff8433758e98799906d80e066c6f32033f685f967029000b275210214827893e2dcbe4ad6c20bd743288edad21100404eb7f52ccd6062fd0e7808f268ac"}, "002089e84892873c679b1129edea246e484fd914c2601f776d4f2f4a001eb8059703", 195);
}

BOOST_AUTO_TEST_CASE(external_signer_honors_cancellation_at_command_boundary)
{
    m_wallet.SetWalletFlag(WALLET_FLAG_EXTERNAL_SIGNER);
    CMutableTransaction mtx;
    int progress_calls{0};

    BOOST_CHECK(!feebumper::SignTransaction(m_wallet, mtx, {}, [&](const SigningProgress& progress) {
        ++progress_calls;
        return progress.cancellable;
    }));
    BOOST_CHECK_EQUAL(progress_calls, 3);
}

BOOST_AUTO_TEST_CASE(p2mr_signing_releases_wallet_lock)
{
    using namespace std::chrono_literals;
    using namespace wallet_p2mr_test;
    struct AbortBeforeCryptographicSigning {};

    m_node.args->ForceSetArg("-walletpqcparallel", "1");
    m_node.args->ForceSetArg("-walletpqcsignthreads", "1");
    auto workload{MakeDistinctKeyP2MRSigningWorkload(*m_node.chain, /*input_count=*/1)};

    CMutableTransaction funding_tx;
    funding_tx.vout.resize(workload.coins.size());
    Txid funding_txid;
    for (const auto& [outpoint, coin] : workload.coins) {
        funding_txid = outpoint.hash;
        funding_tx.vout.at(outpoint.n) = coin.out;
    }
    BOOST_REQUIRE(funding_tx.GetHash() == funding_txid);
    BOOST_REQUIRE(workload.wallet->AddToWallet(MakeTransactionRef(funding_tx), TxStateInactive{}));

    std::promise<void> signing_paused;
    std::future<void> paused_future{signing_paused.get_future()};
    std::promise<void> resume_signing;
    std::shared_future<void> resume_future{resume_signing.get_future()};
    std::atomic_bool pause_reported{false};
    auto sign_future{std::async(std::launch::async, [&] {
        return feebumper::SignTransaction(*workload.wallet, workload.spend_tx, {}, [&](const SigningProgress& progress) {
            if (progress.phase == SigningProgressPhase::RESERVING_PQC_COUNTERS && !progress.cancellable &&
                !pause_reported.exchange(true)) {
                signing_paused.set_value();
                resume_future.wait();
                throw AbortBeforeCryptographicSigning{};
            }
            return true;
        });
    })};

    if (paused_future.wait_for(5s) != std::future_status::ready) {
        resume_signing.set_value();
        BOOST_FAIL("Timed out waiting for fee-bump signing pause");
    }
    {
        TRY_LOCK(workload.wallet->cs_wallet, wallet_lock);
        BOOST_CHECK(static_cast<bool>(wallet_lock));
    }

    resume_signing.set_value();
    BOOST_CHECK_THROW(sign_future.get(), AbortBeforeCryptographicSigning);
}

BOOST_AUTO_TEST_CASE(commit_revalidates_fee_after_signing)
{
    CMutableTransaction funding;
    funding.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(funding), TxStateInactive{}));

    CMutableTransaction original;
    original.vin.emplace_back(COutPoint{funding.GetHash(), 0});
    original.vout.emplace_back(9'000, CScript{} << OP_TRUE);
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(original), TxStateInactive{}));

    CMutableTransaction stale_replacement{original};
    std::vector<bilingual_str> errors;
    Txid bumped_txid;
    const Result commit_result{CommitTransaction(m_wallet, original.GetHash(), std::move(stale_replacement), errors, bumped_txid)};
    BOOST_CHECK(commit_result == Result::WALLET_ERROR);
    BOOST_REQUIRE_EQUAL(errors.size(), 1U);
    BOOST_CHECK_EQUAL(errors.front().original, "Replacement transaction fee is no longer higher than the original fee");
    BOOST_CHECK(bumped_txid.IsNull());
}

BOOST_AUTO_TEST_CASE(commit_revalidates_competing_wallet_spend)
{
    CMutableTransaction funding;
    funding.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(funding), TxStateInactive{}));

    CMutableTransaction original;
    original.vin.emplace_back(COutPoint{funding.GetHash(), 0});
    original.vout.emplace_back(9'000, CScript{} << OP_TRUE);
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(original), TxStateInactive{}));

    CMutableTransaction replacement{original};
    replacement.vout.front().nValue = 8'900;

    CMutableTransaction competing{original};
    competing.nLockTime = 1;
    competing.vout.front().nValue = 8'800;
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(competing), TxStateInactive{}));

    std::vector<bilingual_str> errors;
    Txid bumped_txid;
    const Result commit_result{CommitTransaction(m_wallet, original.GetHash(), std::move(replacement), errors, bumped_txid)};
    BOOST_CHECK(commit_result == Result::WALLET_ERROR);
    BOOST_REQUIRE_EQUAL(errors.size(), 1U);
    BOOST_CHECK(errors.front().original.find("is already spent by wallet transaction") != std::string::npos);
    BOOST_CHECK(bumped_txid.IsNull());
}

BOOST_AUTO_TEST_CASE(commit_allows_replacing_replacement_chain)
{
    m_wallet.SetBroadcastTransactions(false);

    CMutableTransaction funding;
    funding.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(funding), TxStateInactive{}));

    CMutableTransaction original;
    original.vin.emplace_back(COutPoint{funding.GetHash(), 0});
    original.vout.emplace_back(9'000, CScript{} << OP_TRUE);

    CMutableTransaction first_replacement{original};
    first_replacement.vout.front().nValue = 8'900;

    CMutableTransaction second_replacement{original};
    second_replacement.vout.front().nValue = 8'800;

    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(original), TxStateInactive{}, [&](CWalletTx& wtx, bool) {
        wtx.mapValue["replaced_by_txid"] = first_replacement.GetHash().ToString();
        return true;
    }));
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(first_replacement), TxStateInactive{}, [&](CWalletTx& wtx, bool) {
        wtx.mapValue["replaces_txid"] = original.GetHash().ToString();
        wtx.mapValue["replaced_by_txid"] = second_replacement.GetHash().ToString();
        return true;
    }));
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(second_replacement), TxStateInactive{}, [&](CWalletTx& wtx, bool) {
        wtx.mapValue["replaces_txid"] = first_replacement.GetHash().ToString();
        return true;
    }));

    {
        LOCK(m_wallet.cs_wallet);
        BOOST_CHECK(!m_wallet.mapWallet.at(original.GetHash()).isMempoolConflicted());
        BOOST_CHECK(!m_wallet.mapWallet.at(first_replacement.GetHash()).isMempoolConflicted());
    }

    CMutableTransaction final_replacement{original};
    final_replacement.vout.front().nValue = 8'700;
    const Txid expected_bumped_txid{final_replacement.GetHash()};
    std::vector<bilingual_str> errors;
    Txid bumped_txid;
    const Result commit_result{CommitTransaction(m_wallet, second_replacement.GetHash(), std::move(final_replacement), errors, bumped_txid)};
    BOOST_CHECK(commit_result == Result::OK);
    BOOST_CHECK(errors.empty());
    BOOST_CHECK(bumped_txid == expected_bumped_txid);
}

BOOST_AUTO_TEST_CASE(commit_allows_replacement_with_missing_forward_lineage)
{
    m_wallet.SetBroadcastTransactions(false);

    CMutableTransaction funding;
    funding.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(funding), TxStateInactive{}));

    CMutableTransaction original;
    original.vin.emplace_back(COutPoint{funding.GetHash(), 0});
    original.vout.emplace_back(9'000, CScript{} << OP_TRUE);

    CMutableTransaction first_replacement{original};
    first_replacement.vout.front().nValue = 8'900;

    // Simulate reloading after the replacement was persisted but the
    // reciprocal MarkReplaced update was not.
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(original), TxStateInactive{}));
    BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(first_replacement), TxStateInactive{}, [&](CWalletTx& wtx, bool) {
        wtx.mapValue["replaces_txid"] = original.GetHash().ToString();
        return true;
    }));

    CMutableTransaction second_replacement{original};
    second_replacement.vout.front().nValue = 8'800;
    const Txid expected_bumped_txid{second_replacement.GetHash()};
    std::vector<bilingual_str> errors;
    Txid bumped_txid;
    const Result commit_result{CommitTransaction(m_wallet, first_replacement.GetHash(), std::move(second_replacement), errors, bumped_txid)};
    BOOST_CHECK(commit_result == Result::OK);
    BOOST_CHECK(errors.empty());
    BOOST_CHECK(bumped_txid == expected_bumped_txid);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace feebumper
} // namespace wallet
