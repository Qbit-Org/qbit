// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/orphan_metrics.h>
#include <test/util/setup_common.h>
#include <test/util/random.h>
#include <util/time.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <deque>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {
void AddConnected(node::OrphanMetrics& metrics, int count, int start_height = 1)
{
    for (int i = 0; i < count; ++i) {
        metrics.RecordBlockConnected(start_height + i);
    }
}

void AddStale(node::OrphanMetrics& metrics, int count, int start_height = 1)
{
    for (int i = 0; i < count; ++i) {
        metrics.RecordStaleBlock(start_height + i, uint256{});
    }
}

void CheckRate(double actual, double expected)
{
    BOOST_CHECK(std::abs(actual - expected) < 1e-12);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(orphan_metrics_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(orphan_metrics_empty)
{
    node::OrphanMetrics metrics;
    const auto snapshot = metrics.GetSnapshot();
    BOOST_CHECK_EQUAL(snapshot.window_blocks, 1000U);
    BOOST_CHECK_EQUAL(snapshot.window_total, 0U);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 0U);
    CheckRate(snapshot.orphan_rate, 0.0);
    BOOST_CHECK_EQUAL(snapshot.lifetime_blocks_connected, 0U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 0U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_reorgs, 0U);
    BOOST_CHECK_EQUAL(snapshot.deepest_reorg, 0);
    BOOST_CHECK_EQUAL(snapshot.last_stale_height, -1);
    BOOST_CHECK_EQUAL(snapshot.last_stale_time, 0);
    BOOST_CHECK(!snapshot.alert);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_blocks_only)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 100);
    const auto snapshot = metrics.GetSnapshot(100);
    BOOST_CHECK_EQUAL(snapshot.window_total, 100U);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 0U);
    CheckRate(snapshot.orphan_rate, 0.0);
    BOOST_CHECK_EQUAL(snapshot.lifetime_blocks_connected, 100U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 0U);
    BOOST_CHECK(!snapshot.alert);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_with_stale)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 95);
    AddStale(metrics, 5, 96);
    const auto snapshot = metrics.GetSnapshot(100);
    BOOST_CHECK_EQUAL(snapshot.window_total, 100U);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 5U);
    CheckRate(snapshot.orphan_rate, 0.05);
    BOOST_CHECK_EQUAL(snapshot.lifetime_blocks_connected, 95U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 5U);
    BOOST_CHECK(!snapshot.alert);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_alert_threshold)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 89);
    AddStale(metrics, 11, 90);
    const auto snapshot = metrics.GetSnapshot(100);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 11U);
    CheckRate(snapshot.orphan_rate, 0.11);
    BOOST_CHECK(snapshot.alert);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_below_threshold)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 90);
    AddStale(metrics, 10, 91);
    const auto snapshot = metrics.GetSnapshot(100);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 10U);
    CheckRate(snapshot.orphan_rate, 0.10);
    BOOST_CHECK(!snapshot.alert);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_rolling_window)
{
    node::OrphanMetrics metrics;
    AddStale(metrics, 5);
    AddConnected(metrics, 10, 6);

    const auto short_window = metrics.GetSnapshot(10);
    BOOST_CHECK_EQUAL(short_window.window_total, 10U);
    BOOST_CHECK_EQUAL(short_window.window_stale, 0U);
    CheckRate(short_window.orphan_rate, 0.0);

    const auto wide_window = metrics.GetSnapshot(15);
    BOOST_CHECK_EQUAL(wide_window.window_total, 15U);
    BOOST_CHECK_EQUAL(wide_window.window_stale, 5U);
    CheckRate(wide_window.orphan_rate, 5.0 / 15.0);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_custom_window)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 5);
    AddStale(metrics, 2, 6);
    AddConnected(metrics, 3, 8);

    const auto snapshot = metrics.GetSnapshot(5);
    BOOST_CHECK_EQUAL(snapshot.window_blocks, 5U);
    BOOST_CHECK_EQUAL(snapshot.window_total, 5U);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 2U);
    CheckRate(snapshot.orphan_rate, 0.4);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_window_larger_than_data)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 6);
    AddStale(metrics, 2, 7);

    const auto snapshot = metrics.GetSnapshot(100);
    BOOST_CHECK_EQUAL(snapshot.window_blocks, 100U);
    BOOST_CHECK_EQUAL(snapshot.window_total, 8U);
    BOOST_CHECK_EQUAL(snapshot.window_stale, 2U);
    CheckRate(snapshot.orphan_rate, 0.25);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_reorg_tracking)
{
    node::OrphanMetrics metrics;
    metrics.RecordReorg(1);
    metrics.RecordReorg(3);
    metrics.RecordReorg(2);

    const auto snapshot = metrics.GetSnapshot();
    BOOST_CHECK_EQUAL(snapshot.lifetime_reorgs, 3U);
    BOOST_CHECK_EQUAL(snapshot.deepest_reorg, 3);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_last_stale_tracking)
{
    node::OrphanMetrics metrics;
    SetMockTime(100s);
    metrics.RecordStaleBlock(101, uint256{});
    SetMockTime(200s);
    metrics.RecordStaleBlock(102, uint256{});
    SetMockTime(0s);

    const auto snapshot = metrics.GetSnapshot();
    BOOST_CHECK_EQUAL(snapshot.last_stale_height, 102);
    BOOST_CHECK_EQUAL(snapshot.last_stale_time, 200);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_thread_safety)
{
    node::OrphanMetrics metrics;
    static constexpr int THREADS{4};
    static constexpr int EVENTS_PER_THREAD{1000};

    std::vector<std::thread> workers;
    workers.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t) {
        workers.emplace_back([&metrics, t]() {
            for (int i = 0; i < EVENTS_PER_THREAD; ++i) {
                if ((i + t) % 3 == 0) {
                    metrics.RecordStaleBlock(i, uint256{});
                } else {
                    metrics.RecordBlockConnected(i);
                }
            }
        });
    }
    for (std::thread& worker : workers) {
        worker.join();
    }

    const auto snapshot = metrics.GetSnapshot(10000);
    BOOST_CHECK_EQUAL(snapshot.window_total, 4000U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_blocks_connected + snapshot.lifetime_stale_blocks, 4000U);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_ibd_guard)
{
    node::OrphanMetrics metrics;
    metrics.RecordStaleBlock(3, uint256{});
    metrics.RecordBlockConnected(4);
    const auto snapshot = metrics.GetSnapshot();
    BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 1U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_blocks_connected, 1U);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_deque_trimming)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 15000);
    const auto snapshot = metrics.GetSnapshot(20000);
    BOOST_CHECK_EQUAL(snapshot.window_blocks, 10000U);
    BOOST_CHECK_EQUAL(snapshot.window_total, 10000U);
    BOOST_CHECK_EQUAL(snapshot.lifetime_blocks_connected, 15000U);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_rate_precision)
{
    node::OrphanMetrics metrics;
    AddConnected(metrics, 999);
    AddStale(metrics, 1, 1000);
    const auto snapshot = metrics.GetSnapshot(1000);
    CheckRate(snapshot.orphan_rate, 0.001);
}

BOOST_AUTO_TEST_CASE(orphan_metrics_alert_recovery_and_retrigger)
{
    node::OrphanMetrics metrics;

    AddConnected(metrics, 89);
    AddStale(metrics, 11, 90);
    {
        const auto snapshot = metrics.GetSnapshot(1000);
        BOOST_CHECK(snapshot.alert);
        BOOST_CHECK(snapshot.orphan_rate > 0.10);
    }

    // Bring stale rate down to exactly 10% in the alert window.
    AddConnected(metrics, 10, 101);
    {
        const auto snapshot = metrics.GetSnapshot(1000);
        BOOST_CHECK(!snapshot.alert);
        CheckRate(snapshot.orphan_rate, 0.10);
    }

    // Cross back above 10% and ensure alert is re-triggered.
    AddStale(metrics, 1, 111);
    {
        const auto snapshot = metrics.GetSnapshot(1000);
        BOOST_CHECK(snapshot.alert);
        BOOST_CHECK(snapshot.orphan_rate > 0.10);
    }
}

BOOST_AUTO_TEST_CASE(orphan_metrics_randomized_invariants)
{
    node::OrphanMetrics metrics;
    FastRandomContext rng{/*fDeterministic=*/true};

    static constexpr size_t MAX_EVENTS{10000};
    static constexpr size_t ALERT_WINDOW{1000};

    std::deque<bool> model_events;
    uint64_t lifetime_connected{0};
    uint64_t lifetime_stale{0};
    uint64_t lifetime_reorgs{0};
    int deepest_reorg{0};

    auto count_last_stale = [&](size_t window) {
        const size_t total{std::min(window, model_events.size())};
        uint64_t stale{0};
        for (size_t i = 0; i < total; ++i) {
            if (model_events[model_events.size() - 1 - i]) ++stale;
        }
        return std::make_pair(total, stale);
    };

    for (int i = 0; i < 20000; ++i) {
        if (rng.randrange(5) == 0) {
            const int depth{1 + static_cast<int>(rng.randrange(8))};
            metrics.RecordReorg(depth);
            ++lifetime_reorgs;
            deepest_reorg = std::max(deepest_reorg, depth);
        }

        if (rng.randrange(3) == 0) {
            metrics.RecordStaleBlock(i + 1, uint256{});
            model_events.push_back(true);
            ++lifetime_stale;
        } else {
            metrics.RecordBlockConnected(i + 1);
            model_events.push_back(false);
            ++lifetime_connected;
        }

        if (model_events.size() > MAX_EVENTS) {
            model_events.pop_front();
        }

        if (i % 257 == 0) {
            const auto snapshot_full{metrics.GetSnapshot(MAX_EVENTS)};
            const auto [exp_total_full, exp_stale_full]{count_last_stale(MAX_EVENTS)};
            BOOST_CHECK_EQUAL(snapshot_full.window_blocks, MAX_EVENTS);
            BOOST_CHECK_EQUAL(snapshot_full.window_total, exp_total_full);
            BOOST_CHECK_EQUAL(snapshot_full.window_stale, exp_stale_full);
            BOOST_CHECK_EQUAL(snapshot_full.lifetime_blocks_connected, lifetime_connected);
            BOOST_CHECK_EQUAL(snapshot_full.lifetime_stale_blocks, lifetime_stale);
            BOOST_CHECK_EQUAL(snapshot_full.lifetime_reorgs, lifetime_reorgs);
            BOOST_CHECK_EQUAL(snapshot_full.deepest_reorg, deepest_reorg);
            if (exp_total_full > 0) {
                CheckRate(snapshot_full.orphan_rate, static_cast<double>(exp_stale_full) / static_cast<double>(exp_total_full));
            } else {
                CheckRate(snapshot_full.orphan_rate, 0.0);
            }

            const size_t random_window{static_cast<size_t>(1 + rng.randrange(2000))};
            const auto snapshot_window{metrics.GetSnapshot(random_window)};
            const auto [exp_total_window, exp_stale_window]{count_last_stale(random_window)};
            BOOST_CHECK_EQUAL(snapshot_window.window_total, exp_total_window);
            BOOST_CHECK_EQUAL(snapshot_window.window_stale, exp_stale_window);
            if (exp_total_window > 0) {
                CheckRate(snapshot_window.orphan_rate, static_cast<double>(exp_stale_window) / static_cast<double>(exp_total_window));
            } else {
                CheckRate(snapshot_window.orphan_rate, 0.0);
            }

            const auto [exp_alert_total, exp_alert_stale]{count_last_stale(ALERT_WINDOW)};
            const bool exp_alert{
                exp_alert_total > 0 &&
                static_cast<double>(exp_alert_stale) / static_cast<double>(exp_alert_total) > 0.10};
            BOOST_CHECK_EQUAL(snapshot_full.alert, exp_alert);
        }
    }
}

BOOST_AUTO_TEST_CASE(orphan_metrics_dedup)
{
    node::OrphanMetrics metrics;

    const uint256 hash_a{uint256::ONE};
    uint256 hash_b{uint256::ONE};
    *hash_b.data() = 0x02;

    // Two distinct hashes -- both should be recorded.
    BOOST_CHECK(metrics.RecordStaleBlock(100, hash_a));
    BOOST_CHECK(metrics.RecordStaleBlock(101, hash_b));
    {
        const auto snapshot = metrics.GetSnapshot();
        BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 2U);
        BOOST_CHECK_EQUAL(snapshot.window_stale, 2U);
    }

    // Duplicate of hash_a -- should be suppressed.
    BOOST_CHECK(!metrics.RecordStaleBlock(100, hash_a));
    {
        const auto snapshot = metrics.GetSnapshot();
        BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 2U);
        BOOST_CHECK_EQUAL(snapshot.window_stale, 2U);
    }

    // Duplicate of hash_b -- should be suppressed.
    BOOST_CHECK(!metrics.RecordStaleBlock(101, hash_b));
    {
        const auto snapshot = metrics.GetSnapshot();
        BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 2U);
    }

    // Null hash should always pass through (backward compat with test helpers).
    BOOST_CHECK(metrics.RecordStaleBlock(102, uint256{}));
    BOOST_CHECK(metrics.RecordStaleBlock(103, uint256{}));
    {
        const auto snapshot = metrics.GetSnapshot();
        BOOST_CHECK_EQUAL(snapshot.lifetime_stale_blocks, 4U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
