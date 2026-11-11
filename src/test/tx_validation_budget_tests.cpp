// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <net_processing.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using Credit = TxValidationBudget::Credit;
using Account = TxValidationBudget::Account;

namespace {
/** An arbitrary start time on the node clock. */
constexpr std::chrono::microseconds T0{1'700'000'000s};

const TxValidationBudgetOptions DEFAULT_BUDGET{};

/** Default budget without a pool, so only a peer's own credit can allow a validation. */
const TxValidationBudgetOptions NO_POOL_BUDGET{.pool_rate = 0us, .pool_cap = 0us};

/** Refill account's own credit to the cap (100 ms at 500 us per second), so that the peer can use it. */
void Establish(TxValidationBudget& budget, Account& account, std::chrono::microseconds& now)
{
    now += 200s;
    BOOST_REQUIRE(budget.MayValidate(account, /*exempt=*/false, now));
    BOOST_REQUIRE(account.IsEstablished());
    BOOST_REQUIRE(account.GetCredit() == Credit{DEFAULT_TX_VALIDATION_PEER_CAP});
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(tx_validation_budget_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(credit_accrues_and_caps)
{
    TxValidationBudget budget{DEFAULT_BUDGET, T0};
    Account account{T0};

    // Own credit starts at zero; the pool starts full.
    BOOST_CHECK(account.GetCredit() == Credit::zero());
    BOOST_CHECK(!account.IsEstablished());
    BOOST_CHECK(budget.GetPoolCredit() == Credit{DEFAULT_TX_VALIDATION_POOL_CAP});

    // Own credit grows at the peer rate (500 us per second) up to the cap (100 ms, after 200 s).
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, T0 + 10s));
    BOOST_CHECK(account.GetCredit() == Credit{5ms});
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, T0 + 199s));
    BOOST_CHECK(account.GetCredit() == Credit{99'500us});
    BOOST_CHECK(!account.IsEstablished());
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, T0 + 200s));
    BOOST_CHECK(account.GetCredit() == Credit{100ms});
    BOOST_CHECK(account.IsEstablished());
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, T0 + 10'000s));
    BOOST_CHECK(account.GetCredit() == Credit{100ms});

    // The pool, and the peer's share of it, are charged for a peer that cannot use its own
    // credit. The pool then grows at the pool rate (50 ms per second) up to its cap (500 ms).
    Account young{T0 + 10'000s};
    budget.Charge(young, /*exempt=*/false, 300ms, T0 + 10'000s);
    BOOST_CHECK(budget.GetPoolCredit() == Credit{200ms});
    BOOST_CHECK(young.GetCredit() == Credit::zero());
    BOOST_CHECK(young.GetPoolShareUsed() == Credit{300ms});
    BOOST_CHECK(young.GetTotalCharged() == 300ms);
    Account other{T0 + 10'000s};
    BOOST_CHECK(budget.MayValidate(other, /*exempt=*/false, T0 + 10'001s));
    BOOST_CHECK(budget.GetPoolCredit() == Credit{250ms});
    BOOST_CHECK(budget.MayValidate(other, /*exempt=*/false, T0 + 10'100s));
    BOOST_CHECK(budget.GetPoolCredit() == Credit{500ms});

    // A peer's share of the pool grows back at a tenth of the pool rate (5 ms per second).
    BOOST_CHECK(!budget.MayValidate(young, /*exempt=*/false, T0 + 10'010s));
    BOOST_CHECK(young.GetPoolShareUsed() == Credit{250ms});
    BOOST_CHECK(budget.MayValidate(young, /*exempt=*/false, T0 + 10'100s));
    BOOST_CHECK(young.GetPoolShareUsed() == Credit::zero());

    // Many small refills add exactly as much as one large one.
    Account small_steps{T0};
    std::chrono::microseconds now{T0};
    for (int i{0}; i < 1'000; ++i) {
        now += 1ms;
        budget.MayValidate(small_steps, /*exempt=*/false, now);
    }
    BOOST_CHECK(small_steps.GetCredit() == Credit{500us});
}

BOOST_AUTO_TEST_CASE(debt_throttles_until_repaid)
{
    TxValidationBudget budget{NO_POOL_BUDGET, T0};
    Account account{T0};
    std::chrono::microseconds now{T0};

    // Without a pool, a new peer cannot validate until its own credit can be used.
    BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now));
    Establish(budget, account, now);

    // A validation that costs more than the credit leaves a debt of 50 ms.
    budget.Charge(account, /*exempt=*/false, 150ms, now);
    BOOST_CHECK(account.GetCredit() == Credit{-50ms});
    BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now));

    // The debt is repaid after debt / rate = 100 s. The peer may validate again only once its
    // credit is positive, one microsecond later.
    BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now + 100s - 1us));
    BOOST_CHECK(account.GetCredit() < Credit::zero());
    BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now + 100s));
    BOOST_CHECK(account.GetCredit() == Credit::zero());
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, now + 100s + 1us));
    BOOST_CHECK(account.GetCredit() > Credit::zero());

    // Each charge counts in the total, whatever balance it was taken from.
    BOOST_CHECK(account.GetTotalCharged() == 150ms);
}

BOOST_AUTO_TEST_CASE(pool_is_shared_by_peers_without_credit)
{
    TxValidationBudget budget{DEFAULT_BUDGET, T0};
    std::chrono::microseconds now{T0};
    Account established{now};
    Establish(budget, established, now);
    Account young{now};

    // A peer with no usable own credit draws on the pool; its own credit keeps growing.
    BOOST_CHECK(budget.MayValidate(young, /*exempt=*/false, now));
    budget.Charge(young, /*exempt=*/false, 600ms, now);
    BOOST_CHECK(budget.GetPoolCredit() == Credit{-100ms});
    BOOST_CHECK(young.GetCredit() == Credit::zero());

    // Once the pool is exhausted, peers without usable own credit are throttled, including a new
    // connection and a young peer that holds credit it cannot use yet.
    BOOST_CHECK(!budget.MayValidate(young, /*exempt=*/false, now));
    Account other_young{now};
    BOOST_CHECK(!budget.MayValidate(other_young, /*exempt=*/false, now));

    // An established peer with positive own credit is not affected, and pays from its own credit.
    BOOST_CHECK(budget.MayValidate(established, /*exempt=*/false, now));
    budget.Charge(established, /*exempt=*/false, 1ms, now);
    BOOST_CHECK(established.GetCredit() == Credit{99ms});
    BOOST_CHECK(budget.GetPoolCredit() == Credit{-100ms});

    // The pool is positive again 2 s plus one microsecond later, for the peers that have not used
    // up their share of it.
    BOOST_CHECK(!budget.MayValidate(young, /*exempt=*/false, now + 2s));
    BOOST_CHECK(budget.GetPoolCredit() == Credit::zero());
    BOOST_CHECK(young.GetCredit() == Credit{1ms});
    BOOST_CHECK(budget.MayValidate(other_young, /*exempt=*/false, now + 2s + 1us));

    // The peer that took the pool below zero has used more than its share (50 ms), and draws on
    // the pool again once it has earned back all but its share, at 5 ms per second: (600 ms -
    // 50 ms) / 5 ms per second = 110 s later.
    BOOST_CHECK(!budget.MayValidate(young, /*exempt=*/false, now + 2s + 1us));
    BOOST_CHECK(!budget.MayValidate(young, /*exempt=*/false, now + 110s));
    BOOST_CHECK(young.GetPoolShareUsed() == Credit{50ms});
    BOOST_CHECK(budget.MayValidate(young, /*exempt=*/false, now + 110s + 1us));
}

BOOST_AUTO_TEST_CASE(pool_share_limits_each_peer)
{
    const Credit share{Credit{DEFAULT_TX_VALIDATION_POOL_CAP} / TX_VALIDATION_POOL_SHARES};
    BOOST_REQUIRE(share == Credit{50ms});
    TxValidationBudget budget{DEFAULT_BUDGET, T0};
    std::chrono::microseconds now{T0};

    // A peer without usable own credit draws on the pool while it has used less than its share
    // (50 ms). The validation that takes it past its share is charged in full.
    Account greedy{now};
    int validations{0};
    while (budget.MayValidate(greedy, /*exempt=*/false, now)) {
        budget.Charge(greedy, /*exempt=*/false, 7ms, now);
        ++validations;
    }
    BOOST_CHECK_EQUAL(validations, 8);
    BOOST_CHECK(greedy.GetPoolShareUsed() == Credit{56ms});
    BOOST_CHECK(budget.GetPoolCredit() == Credit{444ms});
    BOOST_CHECK(greedy.GetCredit() == Credit::zero());

    // The rest of the pool stays available to the other peers, each within its own share.
    Account other{now};
    BOOST_CHECK(budget.MayValidate(other, /*exempt=*/false, now));
    budget.Charge(other, /*exempt=*/false, 49ms, now);
    BOOST_CHECK(budget.MayValidate(other, /*exempt=*/false, now));
    budget.Charge(other, /*exempt=*/false, 1ms, now);
    BOOST_CHECK(!budget.MayValidate(other, /*exempt=*/false, now));
    BOOST_CHECK(budget.GetPoolCredit() == Credit{394ms});
    Account newcomer{now};
    BOOST_CHECK(budget.MayValidate(newcomer, /*exempt=*/false, now));

    // A share grows back at a tenth of the pool rate, 5 ms per second: the greedy peer, 6 ms over
    // its share, may draw again 1.2 s later.
    BOOST_CHECK(!budget.MayValidate(greedy, /*exempt=*/false, now + 1200ms));
    BOOST_CHECK(greedy.GetPoolShareUsed() == share);
    BOOST_CHECK(budget.MayValidate(greedy, /*exempt=*/false, now + 1200ms + 1us));
    BOOST_CHECK(budget.MayValidate(greedy, /*exempt=*/false, now + 1h));
    BOOST_CHECK(greedy.GetPoolShareUsed() == Credit::zero());

    // A peer with usable own credit does not touch its share of the pool.
    Account established{now};
    Establish(budget, established, now);
    budget.Charge(established, /*exempt=*/false, 10ms, now);
    BOOST_CHECK(established.GetCredit() == Credit{90ms});
    BOOST_CHECK(established.GetPoolShareUsed() == Credit::zero());
    // Once its own credit is used up, it draws on the pool within its share like any other peer.
    budget.Charge(established, /*exempt=*/false, 90ms, now);
    BOOST_CHECK(established.GetCredit() == Credit::zero());
    BOOST_CHECK(budget.MayValidate(established, /*exempt=*/false, now));
    budget.Charge(established, /*exempt=*/false, 60ms, now);
    BOOST_CHECK(established.GetCredit() == Credit::zero());
    BOOST_CHECK(established.GetPoolShareUsed() == Credit{60ms});
    BOOST_CHECK(!budget.MayValidate(established, /*exempt=*/false, now));
}

BOOST_AUTO_TEST_CASE(one_peer_cannot_keep_the_pool_empty)
{
    // A peer that sends a rejected transaction costing 1 ms every 10 ms for 100 s draws at most
    // its share at once plus a tenth of the pool rate over time; the pool stays positive.
    TxValidationBudget budget{DEFAULT_BUDGET, T0};
    Account heavy{T0};
    std::chrono::microseconds charged{0};
    Credit lowest_pool{budget.GetPoolCredit()};
    for (std::chrono::microseconds now{T0}; now < T0 + 100s; now += 10ms) {
        if (budget.MayValidate(heavy, /*exempt=*/false, now)) {
            budget.Charge(heavy, /*exempt=*/false, 1ms, now);
            charged += 1ms;
        }
        lowest_pool = std::min(lowest_pool, budget.GetPoolCredit());
    }
    BOOST_CHECK(lowest_pool > Credit::zero());
    BOOST_CHECK(!heavy.IsEstablished());
    BOOST_CHECK(charged <= 50ms + 100 * 5ms + 1ms);
    BOOST_CHECK(charged >= 50ms + 99 * 5ms);

    // It takes TX_VALIDATION_POOL_SHARES peers drawing at their limit to empty the pool: with
    // one fewer, the pool stays positive.
    for (const int64_t count : {TX_VALIDATION_POOL_SHARES - 1, TX_VALIDATION_POOL_SHARES}) {
        TxValidationBudget shared{DEFAULT_BUDGET, T0};
        std::vector<Account> peers(count, Account{T0});
        bool emptied{false};
        for (std::chrono::microseconds now{T0}; now < T0 + 100s; now += 10ms) {
            for (Account& peer : peers) {
                if (shared.MayValidate(peer, /*exempt=*/false, now)) shared.Charge(peer, /*exempt=*/false, 1ms, now);
            }
            if (shared.GetPoolCredit() <= Credit::zero()) emptied = true;
        }
        BOOST_CHECK_EQUAL(emptied, count == TX_VALIDATION_POOL_SHARES);
    }
}

BOOST_AUTO_TEST_CASE(new_connections_draw_on_the_pool_only)
{
    TxValidationBudget budget{NO_POOL_BUDGET, T0};
    std::chrono::microseconds now{T0};

    // A peer that reconnects starts again with an account whose own credit cannot be used until
    // it has reached the cap, so with the pool exhausted a reconnecting peer is not validated.
    for (int connection{0}; connection < 10; ++connection) {
        Account account{now};
        now += 1s;
        BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now));
        BOOST_CHECK(account.GetCredit() == Credit{500us});
        BOOST_CHECK(!account.IsEstablished());
    }

    // A connection that stays until its credit is full can use it.
    Account account{now};
    BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now + 200s - 1us));
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, now + 200s));
    BOOST_CHECK(account.IsEstablished());

    // After that, the peer can use its own credit while it is positive, also after a debt.
    budget.Charge(account, /*exempt=*/false, 101ms, now + 200s);
    BOOST_CHECK(!budget.MayValidate(account, /*exempt=*/false, now + 202s));
    BOOST_CHECK(budget.MayValidate(account, /*exempt=*/false, now + 202s + 1us));
}

BOOST_AUTO_TEST_CASE(exempt_peers_and_disabled_budget)
{
    TxValidationBudget budget{NO_POOL_BUDGET, T0};
    Account exempt{T0};

    // An exempt peer is never throttled and never charged, but its time is still counted.
    for (int i{0}; i < 10; ++i) {
        BOOST_CHECK(budget.MayValidate(exempt, /*exempt=*/true, T0));
        budget.Charge(exempt, /*exempt=*/true, 1s, T0);
    }
    BOOST_CHECK(exempt.GetCredit() == Credit::zero());
    BOOST_CHECK(exempt.GetTotalCharged() == 10s);

    // An exempt peer never touches the pool.
    TxValidationBudget pooled{DEFAULT_BUDGET, T0};
    Account exempt_pooled{T0};
    pooled.Charge(exempt_pooled, /*exempt=*/true, 1s, T0);
    BOOST_CHECK(pooled.GetPoolCredit() == Credit{DEFAULT_TX_VALIDATION_POOL_CAP});
    BOOST_CHECK(exempt_pooled.GetPoolShareUsed() == Credit::zero());
    BOOST_CHECK(exempt_pooled.GetTotalCharged() == 1s);

    // A disabled budget throttles nobody and charges nothing, but still counts the time.
    TxValidationBudget disabled{TxValidationBudgetOptions{.enabled = false, .pool_rate = 0us, .pool_cap = 0us}, T0};
    Account account{T0};
    for (int i{0}; i < 10; ++i) {
        BOOST_CHECK(disabled.MayValidate(account, /*exempt=*/false, T0));
        disabled.Charge(account, /*exempt=*/false, 1s, T0);
    }
    BOOST_CHECK(account.GetCredit() == Credit::zero());
    BOOST_CHECK(account.GetTotalCharged() == 10s);
}

BOOST_AUTO_TEST_CASE(balances_floor_and_clock_changes)
{
    // A peer's debt stops at the floor; its total keeps counting, without overflowing.
    TxValidationBudget budget{NO_POOL_BUDGET, T0};
    std::chrono::microseconds now{T0};
    Account established{now};
    Establish(budget, established, now);
    budget.Charge(established, /*exempt=*/false, 1h, now);
    BOOST_CHECK(established.GetCredit() == Credit{TX_VALIDATION_CREDIT_FLOOR});
    budget.Charge(established, /*exempt=*/false, std::chrono::microseconds::max(), now);
    BOOST_CHECK(established.GetCredit() == Credit{TX_VALIDATION_CREDIT_FLOOR});
    BOOST_CHECK(established.GetTotalCharged() == std::chrono::microseconds::max());

    // A negative cost is charged as zero.
    Account other{now};
    budget.Charge(other, /*exempt=*/false, -1s, now);
    BOOST_CHECK(other.GetTotalCharged() == 0us);
    BOOST_CHECK(other.GetCredit() == Credit::zero());

    // A clock that moves backwards adds nothing, and growth restarts from the new time.
    BOOST_CHECK(!budget.MayValidate(established, /*exempt=*/false, now - 1h));
    BOOST_CHECK(established.GetCredit() == Credit{TX_VALIDATION_CREDIT_FLOOR});
    BOOST_CHECK(!budget.MayValidate(established, /*exempt=*/false, now - 1h + 10s));
    BOOST_CHECK(established.GetCredit() == Credit{TX_VALIDATION_CREDIT_FLOOR} + Credit{5ms});

    // A very large step forward fills a balance to its cap without overflowing.
    const std::chrono::microseconds far_future{std::chrono::years{1000}};
    BOOST_CHECK(budget.MayValidate(established, /*exempt=*/false, far_future));
    BOOST_CHECK(established.GetCredit() == Credit{DEFAULT_TX_VALIDATION_PEER_CAP});

    // The pool's debt, and a peer's share of the pool, stop at the floor too: the pool is
    // positive again after 1 s / 50 ms per second = 20 s, the peer's share after
    // 1 s / 5 ms per second = 200 s. Both refill to their caps. (The peers' own credit is not
    // usable before an hour has passed.)
    TxValidationBudget pooled{TxValidationBudgetOptions{.peer_cap = 1h}, T0};
    Account young{T0};
    pooled.Charge(young, /*exempt=*/false, 1h, T0);
    BOOST_CHECK(pooled.GetPoolCredit() == Credit{TX_VALIDATION_CREDIT_FLOOR});
    BOOST_CHECK(young.GetPoolShareUsed() == Credit{DEFAULT_TX_VALIDATION_POOL_CAP} / TX_VALIDATION_POOL_SHARES - Credit{TX_VALIDATION_CREDIT_FLOOR});
    BOOST_CHECK(young.GetCredit() == Credit::zero());
    BOOST_CHECK(!pooled.MayValidate(young, /*exempt=*/false, T0));
    Account other_young{T0};
    BOOST_CHECK(!pooled.MayValidate(other_young, /*exempt=*/false, T0 + 20s));
    BOOST_CHECK(pooled.MayValidate(other_young, /*exempt=*/false, T0 + 20s + 1us));
    BOOST_CHECK(!pooled.MayValidate(young, /*exempt=*/false, T0 + 200s));
    BOOST_CHECK(pooled.MayValidate(young, /*exempt=*/false, T0 + 200s + 1us));
    Account late{far_future};
    BOOST_CHECK(pooled.MayValidate(late, /*exempt=*/false, far_future));
    BOOST_CHECK(pooled.GetPoolCredit() == Credit{DEFAULT_TX_VALIDATION_POOL_CAP});
    BOOST_CHECK(pooled.MayValidate(young, /*exempt=*/false, far_future));
    BOOST_CHECK(young.GetPoolShareUsed() == Credit::zero());

    // Settings beyond the accepted range are clamped.
    TxValidationBudget clamped{TxValidationBudgetOptions{.peer_rate = std::chrono::microseconds::max(), .peer_cap = -1s,
                                                         .pool_rate = -1s, .pool_cap = std::chrono::microseconds::max()},
                               T0};
    BOOST_CHECK(clamped.GetOptions().peer_rate == MAX_TX_VALIDATION_BUDGET_SETTING);
    BOOST_CHECK(clamped.GetOptions().peer_cap == 0us);
    BOOST_CHECK(clamped.GetOptions().pool_rate == 0us);
    BOOST_CHECK(clamped.GetOptions().pool_cap == MAX_TX_VALIDATION_BUDGET_SETTING);
    BOOST_CHECK(clamped.GetPoolCredit() == Credit{MAX_TX_VALIDATION_BUDGET_SETTING});
}

BOOST_AUTO_TEST_CASE(charged_validation_results)
{
    // Every TxValidationResult value, in declaration order. Only rejections for a reason in the
    // transaction itself are charged. An enumerator missing from IsTxValidationTimeCharged() makes
    // the compiler warn about its switch; one missing from this table fails the checks below.
    const std::vector<std::pair<TxValidationResult, bool>> expected{
        {TxValidationResult::TX_RESULT_UNSET, false},
        {TxValidationResult::TX_CONSENSUS, true},
        {TxValidationResult::TX_INPUTS_NOT_STANDARD, true},
        {TxValidationResult::TX_NOT_STANDARD, true},
        {TxValidationResult::TX_MISSING_INPUTS, false},
        {TxValidationResult::TX_PREMATURE_SPEND, false},
        {TxValidationResult::TX_WITNESS_MUTATED, true},
        {TxValidationResult::TX_WITNESS_STRIPPED, true},
        {TxValidationResult::TX_CONFLICT, false},
        {TxValidationResult::TX_MEMPOOL_POLICY, false},
        {TxValidationResult::TX_NO_MEMPOOL, false},
        {TxValidationResult::TX_RECONSIDERABLE, false},
        {TxValidationResult::TX_UNKNOWN, false},
    };
    for (size_t i{0}; i < expected.size(); ++i) {
        const auto& [result, charged]{expected[i]};
        BOOST_CHECK_EQUAL(static_cast<size_t>(result), i);
        BOOST_CHECK_MESSAGE(IsTxValidationTimeCharged(result) == std::optional<bool>{charged}, "result " << i);
    }
    // The first value after the last enumerator is not classified.
    BOOST_CHECK(!IsTxValidationTimeCharged(static_cast<TxValidationResult>(expected.size())).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
