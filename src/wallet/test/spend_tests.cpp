// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/fees.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/solver.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_p2mr_test_util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <future>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace wallet {
RPCHelpMan send();

BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(SubtractFee, UnrestrictedRegtestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    // Set the discard rate explicitly, as -discardfee would. Without fee estimates
    // it would otherwise fall to the fallback fee and keep the leftover as change.
    wallet->m_discard_rate = CFeeRate{DEFAULT_DISCARD_FEE};
    wallet->m_discard_rate_set = true;

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    const CAmount coinbase_value{GetBlockSubsidy(1, Params().GetConsensus())};
    auto check_tx = [&wallet, coinbase_value](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), coinbase_value - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, UnrestrictedRegtestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, one initial subsidy each, to the wallet.
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO.
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs cover.
    const CAmount coinbase_subsidy{GetBlockSubsidy(1, Params().GetConsensus())};
    const CAmount target_amount{5 * coinbase_subsidy + 1};
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/target_amount, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to spend more than a wallet with 5 coinbases can cover. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send its 4 coinbase outputs.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_FIXTURE_TEST_CASE(CreateTransactionReturnsChangeDestinationAfterSigningFailure, UnrestrictedRegtestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    const SecureString passphrase{"test-passphrase"};
    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_REQUIRE(wallet->IsLocked());

    auto get_internal_keypool_size = [&wallet]() {
        LOCK(wallet->cs_wallet);
        ScriptPubKeyMan* spk_man{wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true)};
        BOOST_REQUIRE(spk_man);
        return spk_man->GetKeyPoolSize();
    };

    const unsigned int keypool_size_before{get_internal_keypool_size()};
    BOOST_REQUIRE_GT(keypool_size_before, 0U);

    const CAmount coinbase_value{GetBlockSubsidy(1, Params().GetConsensus())};
    CRecipient recipient{PubKeyDestination({}), coinbase_value / 2, /*subtract_fee=*/false};
    CCoinControl coin_control;
    coin_control.m_change_type = OutputType::BECH32;

    const auto res{CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true)};
    BOOST_REQUIRE(!res);
    BOOST_CHECK_EQUAL(util::ErrorString(res).original, "Signing transaction failed");
    BOOST_CHECK_EQUAL(get_internal_keypool_size(), keypool_size_before);
}

//! A wallet with five mature coins that the send RPC can reach, and a way to
//! park one send call after it signs and before it commits.
struct SendRPCSetup : public UnrestrictedRegtestChain100Setup {
    WalletContext m_wallet_context;
    std::shared_ptr<CWallet> m_wallet;
    std::vector<COutPoint> m_coins;

    std::promise<void> m_parked;
    std::promise<void> m_release;
    std::shared_future<void> m_release_future{m_release.get_future().share()};
    std::atomic<bool> m_park_next{false};
    std::atomic<bool> m_released{false};
    std::future<std::pair<UniValue, UniValue>> m_parked_call;

    SendRPCSetup()
    {
        for (int i = 0; i < 5; ++i) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        m_wallet_context.chain = m_node.chain.get();
        m_wallet_context.args = &m_args;
        m_wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey, BECH32_ONLY_OUTPUT_TYPES, /*keypool_size=*/10);
        AddWallet(m_wallet_context, m_wallet);
        LOCK(m_wallet->cs_wallet);
        for (const COutput& coin : AvailableCoins(*m_wallet).All()) m_coins.push_back(coin.outpoint);
        BOOST_REQUIRE_EQUAL(m_coins.size(), 5U);
        m_wallet->m_before_send_commit = [this] {
            if (!m_park_next.exchange(false)) return;
            m_parked.set_value();
            m_release_future.wait();
        };
    }

    ~SendRPCSetup()
    {
        // Let a parked call finish, even when a failed check ended the test early.
        Release();
        if (m_parked_call.valid()) m_parked_call.wait();
        m_wallet->m_before_send_commit = {};
        RemoveWallet(m_wallet_context, m_wallet, /*load_on_start=*/std::nullopt);
    }

    //! Call send with these inputs and options; return its result or the error it threw.
    std::pair<UniValue, UniValue> Send(const std::vector<COutPoint>& inputs, UniValue options)
    {
        UniValue outputs{UniValue::VARR};
        UniValue output{UniValue::VOBJ};
        output.pushKV(EncodeDestination(*Assert(m_wallet->GetNewDestination(OutputType::BECH32, ""))), ValueFromAmount(COIN));
        outputs.push_back(std::move(output));
        UniValue input_array{UniValue::VARR};
        for (const COutPoint& input : inputs) {
            UniValue entry{UniValue::VOBJ};
            entry.pushKV("txid", input.hash.GetHex());
            entry.pushKV("vout", input.n);
            input_array.push_back(std::move(entry));
        }
        options.pushKV("inputs", std::move(input_array));
        JSONRPCRequest request;
        request.context = &m_wallet_context;
        request.params = UniValue{UniValue::VARR};
        request.params.push_back(std::move(outputs));
        for (int i = 0; i < 3; ++i) request.params.push_back(UniValue{});
        request.params.push_back(std::move(options));
        try {
            return {send().HandleRequest(request), UniValue{}};
        } catch (const UniValue& error) {
            return {UniValue{}, error};
        }
    }

    //! Start a send call that parks after it signs, and wait until it does.
    void StartParkedSend(const std::vector<COutPoint>& inputs, const UniValue& options)
    {
        m_park_next = true;
        m_parked_call = std::async(std::launch::async, [this, inputs, options] {
            auto result{Send(inputs, options)};
            // A call that failed before it signed must not leave the test waiting.
            if (m_park_next.exchange(false)) m_parked.set_value();
            return result;
        });
        m_parked.get_future().wait();
    }

    void Release()
    {
        if (!m_released.exchange(true)) m_release.set_value();
    }

    //! Let the parked call commit, and return its result or the error it threw.
    std::pair<UniValue, UniValue> FinishParkedSend()
    {
        Release();
        return m_parked_call.get();
    }

    static UniValue FeeRate(int sat_per_vb, bool lock_unspents = false)
    {
        UniValue options{UniValue::VOBJ};
        options.pushKV("fee_rate", sat_per_vb);
        if (lock_unspents) options.pushKV("lock_unspents", true);
        return options;
    }

    std::set<COutPoint> LockedCoins()
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<COutPoint> locked;
        m_wallet->ListLockedCoins(locked);
        return {locked.begin(), locked.end()};
    }
};

static void CheckConcurrentSpendError(const UniValue& error, const COutPoint& input, const UniValue& winner)
{
    BOOST_REQUIRE(error.isObject());
    BOOST_CHECK_EQUAL(error["code"].getInt<int>(), RPC_WALLET_ERROR);
    BOOST_CHECK_EQUAL(error["message"].get_str(), strprintf("Input %s:%u was spent by concurrent transaction %s. This transaction was not added to the wallet or broadcast; the call can be retried.", input.hash.GetHex(), input.n, winner["txid"].get_str()));
}

// Two send calls replace the same wallet transaction. The one that commits
// second started while the original was the input's only spender, so it fails
// and adds nothing to the wallet.
BOOST_FIXTURE_TEST_CASE(ConcurrentSendReplacementsSucceedOnce, SendRPCSetup)
{
    const COutPoint& coin{m_coins.at(0)};
    const auto [original, original_error]{Send({coin}, FeeRate(10))};
    BOOST_REQUIRE(original_error.isNull());

    StartParkedSend({coin}, FeeRate(20));
    const auto [winner, winner_error]{Send({coin}, FeeRate(20))};
    BOOST_REQUIRE(winner_error.isNull());
    const auto [loser_result, loser_error]{FinishParkedSend()};

    BOOST_CHECK(loser_result.isNull());
    CheckConcurrentSpendError(loser_error, coin, winner);
    LOCK(m_wallet->cs_wallet);
    BOOST_CHECK(m_wallet->GetSpendingTxs(coin) == (std::set<Txid>{Txid::FromHex(original["txid"].get_str()).value(), Txid::FromHex(winner["txid"].get_str()).value()}));
}

// A send call with lock_unspents that loses the race unlocks the inputs it
// locked, as committing them would have, except an input the user had locked.
BOOST_FIXTURE_TEST_CASE(ConcurrentSendLoserReleasesItsCoinLocks, SendRPCSetup)
{
    const COutPoint& user_locked{m_coins.back()};
    WITH_LOCK(m_wallet->cs_wallet, m_wallet->LockCoin(user_locked, /*persist=*/false));

    StartParkedSend(m_coins, FeeRate(10, /*lock_unspents=*/true));
    BOOST_CHECK(LockedCoins() == (std::set<COutPoint>{m_coins.begin(), m_coins.end()}));
    const auto [winner, winner_error]{Send({m_coins.at(0)}, FeeRate(10))};
    BOOST_REQUIRE(winner_error.isNull());
    const auto [loser_result, loser_error]{FinishParkedSend()};

    BOOST_CHECK(loser_result.isNull());
    CheckConcurrentSpendError(loser_error, m_coins.at(0), winner);
    BOOST_CHECK(LockedCoins() == std::set<COutPoint>{user_locked});
}

BOOST_AUTO_TEST_CASE(discard_rate_without_fee_estimate)
{
    // With no estimate for the longest target, the fallback fee (raised to the
    // required fee rate) stands in for it unless -discardfee was set, and the
    // dust relay fee remains the floor.
    CWallet& wallet{m_wallet};
    BOOST_REQUIRE(wallet.chain().estimateSmartFee(wallet.chain().estimateMaxBlocks(), /*conservative=*/false) == CFeeRate{0});
    const CAmount dust_relay_fee{wallet.chain().relayDustFee().GetFeePerK()};
    BOOST_REQUIRE_GT(dust_relay_fee, DEFAULT_FALLBACK_FEE);
    BOOST_REQUIRE_LT(dust_relay_fee, DEFAULT_DISCARD_FEE);

    const auto discard_rate = [&wallet](CAmount fallback_fee, std::optional<CAmount> discard_fee) {
        wallet.m_fallback_fee = CFeeRate{fallback_fee};
        wallet.m_allow_fallback_fee = fallback_fee != 0;
        wallet.m_discard_rate = CFeeRate{discard_fee.value_or(DEFAULT_DISCARD_FEE)};
        wallet.m_discard_rate_set = discard_fee.has_value();
        return GetDiscardRate(wallet).GetFeePerK();
    };

    // The default fallback is below the dust relay fee, so change is discarded
    // only up to the dust relay floor, not at the 40x higher -discardfee default.
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_FALLBACK_FEE, std::nullopt), dust_relay_fee);
    BOOST_CHECK_EQUAL(discard_rate(dust_relay_fee, std::nullopt), dust_relay_fee);
    BOOST_CHECK_EQUAL(discard_rate(dust_relay_fee + 1, std::nullopt), dust_relay_fee + 1);
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_DISCARD_FEE - 1, std::nullopt), DEFAULT_DISCARD_FEE - 1);
    // A fallback at or above the -discardfee default leaves the default in place,
    // as before. The functional test framework's fallbackfee=0.0002 is such a case.
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_DISCARD_FEE, std::nullopt), DEFAULT_DISCARD_FEE);
    BOOST_CHECK_EQUAL(discard_rate(20000, std::nullopt), DEFAULT_DISCARD_FEE);
    // -fallbackfee=0 has no rate to stand in.
    BOOST_CHECK_EQUAL(discard_rate(0, std::nullopt), DEFAULT_DISCARD_FEE);
    // An explicit -discardfee is used unchanged, even when it equals the default.
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_FALLBACK_FEE, DEFAULT_DISCARD_FEE), DEFAULT_DISCARD_FEE);
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_FALLBACK_FEE, 5000), 5000);
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_FALLBACK_FEE, 0), dust_relay_fee);
    // The stand-in is raised to the required fee rate, which spending the change will need too.
    wallet.m_min_fee = CFeeRate{DEFAULT_FALLBACK_FEE * 4};
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_FALLBACK_FEE, std::nullopt), DEFAULT_FALLBACK_FEE * 4);
    BOOST_CHECK_EQUAL(discard_rate(DEFAULT_FALLBACK_FEE, 5000), 5000);
}

BOOST_AUTO_TEST_CASE(minimum_fee_rate_reports_unavailable_estimate)
{
    // A minimum fee rate can replace the FALLBACK reason, but the fee
    // calculation must still say that there was no estimate.
    CWallet& wallet{m_wallet};
    CCoinControl coin_control;
    const auto check = [&](CAmount expected_feerate, FeeReason expected_reason, bool expected_unavailable) {
        FeeCalculation fee_calc;
        BOOST_CHECK_EQUAL(GetMinimumFeeRate(wallet, coin_control, &fee_calc).GetFeePerK(), expected_feerate);
        BOOST_CHECK(fee_calc.reason == expected_reason);
        BOOST_CHECK_EQUAL(fee_calc.estimate_unavailable, expected_unavailable);
    };

    check(DEFAULT_FALLBACK_FEE, FeeReason::FALLBACK, true);
    // -mintxfee above the fallback fee
    wallet.m_min_fee = CFeeRate{DEFAULT_FALLBACK_FEE * 4};
    check(DEFAULT_FALLBACK_FEE * 4, FeeReason::REQUIRED, true);
    // An explicit fee rate does not use estimation
    coin_control.m_feerate = CFeeRate{DEFAULT_FALLBACK_FEE * 8};
    check(DEFAULT_FALLBACK_FEE * 8, FeeReason::PAYTXFEE, false);
    // -fallbackfee=0 still returns a zero FALLBACK rate, which fails the send
    coin_control.m_feerate.reset();
    wallet.m_fallback_fee = CFeeRate{0};
    wallet.m_allow_fallback_fee = false;
    check(0, FeeReason::FALLBACK, true);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
