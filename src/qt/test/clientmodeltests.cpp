// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/clientmodeltests.h>

#include <chain.h>
#include <node/interface_ui.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/optionsmodel.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

#include <QSignalSpy>
#include <QTest>

#include <chrono>

namespace {
constexpr int64_t BASE_BLOCK_TIME{1'700'000'000};
constexpr int SYNC_WAIT_MS{static_cast<int>(count_milliseconds(SYNC_UPDATE_DELAY + 250ms))};

void NotifyBlockTip(SynchronizationState state, int height)
{
    CBlockHeader header;
    header.nTime = BASE_BLOCK_TIME + height;
    CBlockIndex index{header};
    index.nHeight = height;
    const uint256 hash{uint256::ONE};
    index.phashBlock = &hash;
    uiInterface.NotifyBlockTip(state, index, /*verification_progress=*/height / 100.0);
}

void NotifyHeaderTip(SynchronizationState state, int height, bool presync = false)
{
    uiInterface.NotifyHeaderTip(state, height, BASE_BLOCK_TIME + height, presync);
}

int SignalCountArgument(const QSignalSpy& spy, int index)
{
    return spy.at(index).at(0).toInt();
}
} // namespace

void ClientModelTests::ibdBlockTipsAreCoalescedAndFlushLatest()
{
    OptionsModel options_model{m_node};
    ClientModel client_model{m_node, &options_model};
    QSignalSpy spy{&client_model, &ClientModel::numBlocksChanged};
    QVERIFY(spy.isValid());

    for (int height{1}; height <= 5; ++height) {
        NotifyBlockTip(SynchronizationState::INIT_DOWNLOAD, height);
    }

    QCOMPARE(spy.count(), 1);
    QCOMPARE(SignalCountArgument(spy, 0), 1);

    QVERIFY(spy.wait(SYNC_WAIT_MS));
    QCOMPARE(spy.count(), 2);
    QCOMPARE(SignalCountArgument(spy, 1), 5);
}

void ClientModelTests::reindexHeaderTipsAreCoalescedAndFlushLatest()
{
    OptionsModel options_model{m_node};
    ClientModel client_model{m_node, &options_model};
    QSignalSpy spy{&client_model, &ClientModel::numBlocksChanged};
    QVERIFY(spy.isValid());

    for (int height{100}; height <= 104; ++height) {
        NotifyHeaderTip(SynchronizationState::INIT_REINDEX, height);
    }

    QCOMPARE(spy.count(), 1);
    QCOMPARE(SignalCountArgument(spy, 0), 100);

    QVERIFY(spy.wait(SYNC_WAIT_MS));
    QCOMPARE(spy.count(), 2);
    QCOMPARE(SignalCountArgument(spy, 1), 104);
}

void ClientModelTests::postInitTipInvalidatesPendingIbdFlush()
{
    OptionsModel options_model{m_node};
    ClientModel client_model{m_node, &options_model};
    QSignalSpy spy{&client_model, &ClientModel::numBlocksChanged};
    QVERIFY(spy.isValid());

    NotifyBlockTip(SynchronizationState::INIT_DOWNLOAD, 10);
    QCOMPARE(spy.count(), 1);
    spy.clear();

    NotifyBlockTip(SynchronizationState::INIT_DOWNLOAD, 11);
    QCOMPARE(spy.count(), 0);

    NotifyBlockTip(SynchronizationState::POST_INIT, 12);
    QCOMPARE(spy.count(), 1);
    QCOMPARE(SignalCountArgument(spy, 0), 12);

    QTest::qWait(SYNC_WAIT_MS);
    QCOMPARE(spy.count(), 1);
}

void ClientModelTests::syncTypeTransitionEmitsImmediately()
{
    OptionsModel options_model{m_node};
    ClientModel client_model{m_node, &options_model};
    QSignalSpy spy{&client_model, &ClientModel::numBlocksChanged};
    QVERIFY(spy.isValid());

    NotifyHeaderTip(SynchronizationState::INIT_DOWNLOAD, 100);
    QCOMPARE(spy.count(), 1);
    spy.clear();

    NotifyHeaderTip(SynchronizationState::INIT_DOWNLOAD, 101);
    QCOMPARE(spy.count(), 1);
    QCOMPARE(SignalCountArgument(spy, 0), 101);
    spy.clear();

    NotifyBlockTip(SynchronizationState::INIT_DOWNLOAD, 50);
    QCOMPARE(spy.count(), 1);
    QCOMPARE(SignalCountArgument(spy, 0), 50);

    QTest::qWait(SYNC_WAIT_MS);
    QCOMPARE(spy.count(), 1);
}

void ClientModelTests::stopCancelsPendingIbdFlush()
{
    OptionsModel options_model{m_node};
    ClientModel client_model{m_node, &options_model};
    QSignalSpy spy{&client_model, &ClientModel::numBlocksChanged};
    QVERIFY(spy.isValid());

    NotifyBlockTip(SynchronizationState::INIT_DOWNLOAD, 20);
    QCOMPARE(spy.count(), 1);
    spy.clear();

    NotifyBlockTip(SynchronizationState::INIT_DOWNLOAD, 21);
    QCOMPARE(spy.count(), 0);

    client_model.stop();
    QTest::qWait(SYNC_WAIT_MS);
    QCOMPARE(spy.count(), 0);
}
