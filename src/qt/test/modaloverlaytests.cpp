// Copyright (c) 2026-present The qbit developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/modaloverlaytests.h>

#include <chainparams.h>
#include <qt/modaloverlay.h>

#include <QDateTime>
#include <QLabel>
#include <QTest>

void ModalOverlayTests::headersPresyncProgressStaysVisible()
{
    ModalOverlay overlay{/*enable_wallet=*/false, /*parent=*/nullptr};
    QLabel* blocks_left{overlay.findChild<QLabel*>("numberOfBlocksLeft")};
    QLabel* progress_label{overlay.findChild<QLabel*>("labelSyncDone")};
    QLabel* progress_value{overlay.findChild<QLabel*>("percentageProgress")};
    QVERIFY(blocks_left);
    QVERIFY(progress_label);
    QVERIFY(progress_value);

    overlay.setKnownBestHeight(/*count=*/0, QDateTime::currentDateTime(), /*presync=*/false);
    QVERIFY(blocks_left->text().contains("Unknown"));
    QCOMPARE(progress_label->text(), QString("Progress"));

    overlay.setKnownBestHeight(/*count=*/0, QDateTime::currentDateTime(), /*presync=*/true);
    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    QCOMPARE(progress_label->text(), QString("Headers pre-sync progress"));
    QCOMPARE(progress_value->text(), QString("~"));
    overlay.finishHeadersPresync();

    const QDateTime presync_date{QDateTime::currentDateTime().addSecs(-3600)};
    overlay.setKnownBestHeight(/*count=*/1000, presync_date, /*presync=*/true);

    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    QVERIFY(blocks_left->text().contains("1000"));
    QCOMPARE(progress_label->text(), QString("Headers pre-sync progress"));
    QVERIFY(!progress_value->text().isEmpty());
    QVERIFY(progress_value->text() != QString("100.00%"));
    const QString presync_progress{progress_value->text()};

    overlay.setKnownBestHeight(/*count=*/100, presync_date.addSecs(-1800), /*presync=*/false);
    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    QVERIFY(blocks_left->text().contains("1000"));
    QCOMPARE(progress_label->text(), QString("Headers pre-sync progress"));

    overlay.tipUpdate(/*count=*/0, presync_date.addSecs(-3600), /*nVerificationProgress=*/1.0);
    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    QCOMPARE(progress_label->text(), QString("Headers pre-sync progress"));
    QVERIFY(progress_value->text() != QString("100.00%"));

    overlay.setKnownBestHeight(/*count=*/1000, presync_date, /*presync=*/false);
    QVERIFY(blocks_left->text().contains("Syncing Headers"));
    QVERIFY(!blocks_left->text().contains("Pre-syncing Headers"));
    QCOMPARE(progress_label->text(), QString("Progress"));
    QCOMPARE(progress_value->text(), QString("~"));
    QVERIFY(progress_value->text() != presync_progress);

    overlay.setKnownBestHeight(/*count=*/2000, presync_date, /*presync=*/true);
    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    overlay.finishHeadersPresync();
    QVERIFY(blocks_left->text().contains("Syncing Headers"));
    QVERIFY(!blocks_left->text().contains("Pre-syncing Headers"));
    QCOMPARE(progress_label->text(), QString("Progress"));
    QCOMPARE(progress_value->text(), QString("~"));

    overlay.showHide(/*hide=*/false, /*userRequested=*/true);
    overlay.tipUpdate(/*count=*/0, presync_date.addSecs(-3600), /*nVerificationProgress=*/1.0);
    QVERIFY(!blocks_left->text().contains("Pre-syncing Headers"));
    QCOMPARE(progress_value->text(), QString("99.99%"));

    overlay.setKnownBestHeight(/*count=*/3000, presync_date, /*presync=*/false);
    overlay.setKnownBestHeight(/*count=*/3000, presync_date, /*presync=*/true);
    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    overlay.setKnownBestHeight(/*count=*/3000, presync_date, /*presync=*/false);
    QVERIFY(blocks_left->text().contains("Syncing Headers"));
    QVERIFY(!blocks_left->text().contains("Unknown…"));
    QCOMPARE(progress_label->text(), QString("Progress"));
    QCOMPARE(progress_value->text(), QString("~"));

    overlay.setKnownBestHeight(/*count=*/5000, presync_date, /*presync=*/true);
    overlay.setKnownBestHeight(/*count=*/3000, presync_date.addSecs(1800), /*presync=*/false);
    QVERIFY(blocks_left->text().contains("Pre-syncing Headers"));
    QVERIFY(blocks_left->text().contains("5000"));
    overlay.finishHeadersPresync();
    QVERIFY(blocks_left->text().contains("Syncing Headers"));
    QVERIFY(blocks_left->text().contains("3000"));
}

void ModalOverlayTests::hiddenTipUpdateRendersLatestTipWhenShown()
{
    ModalOverlay overlay{/*enable_wallet=*/false, /*parent=*/nullptr};
    QLabel* blocks_left{overlay.findChild<QLabel*>("numberOfBlocksLeft")};
    QLabel* block_date{overlay.findChild<QLabel*>("newestBlockDate")};
    QLabel* progress_value{overlay.findChild<QLabel*>("percentageProgress")};
    QVERIFY(blocks_left);
    QVERIFY(block_date);
    QVERIFY(progress_value);

    const QDateTime header_date{QDateTime::currentDateTime()};
    const QDateTime tip_date{header_date.addSecs(-3600)};
    overlay.setKnownBestHeight(/*count=*/200, header_date, /*presync=*/false);

    const QString initial_block_date{block_date->text()};
    const QString initial_progress{progress_value->text()};
    overlay.tipUpdate(/*count=*/100, tip_date, /*nVerificationProgress=*/0.1234);

    QCOMPARE(block_date->text(), initial_block_date);
    QCOMPARE(progress_value->text(), initial_progress);
    QCOMPARE(overlay.blockProcessTime.size(), 0);

    overlay.showHide(/*hide=*/false, /*userRequested=*/true);

    QCOMPARE(block_date->text(), tip_date.toString());
    QCOMPARE(progress_value->text(), QString("12.34%"));
    QCOMPARE(blocks_left->text(), QString("100"));
    QCOMPARE(overlay.blockProcessTime.size(), 1);
}

void ModalOverlayTests::hiddenTipUpdateResetsStaleEtaWhenShown()
{
    ModalOverlay overlay{/*enable_wallet=*/false, /*parent=*/nullptr};
    QLabel* progress_increase{overlay.findChild<QLabel*>("progressIncreasePerH")};
    QLabel* expected_time_left{overlay.findChild<QLabel*>("expectedTimeLeft")};
    QVERIFY(progress_increase);
    QVERIFY(expected_time_left);

    overlay.showHide(/*hide=*/false, /*userRequested=*/true);
    progress_increase->setText(QString("99.00%"));
    expected_time_left->setText(QString("1 day"));

    const qint64 old_sample_time{QDateTime::currentMSecsSinceEpoch() - 600 * 1000};
    overlay.blockProcessTime.push_front(qMakePair(old_sample_time, 0.10));
    overlay.m_last_progress_metrics_update_msecs = old_sample_time;

    overlay.showHide(/*hide=*/true, /*userRequested=*/true);
    overlay.tipUpdate(/*count=*/100, QDateTime::currentDateTime().addSecs(-3600), /*nVerificationProgress=*/0.20);
    overlay.showHide(/*hide=*/false, /*userRequested=*/true);

    QCOMPARE(progress_increase->text(), QString("calculating…"));
    QCOMPARE(expected_time_left->text(), QString("calculating…"));
    QCOMPARE(overlay.blockProcessTime.size(), 1);
}

void ModalOverlayTests::repeatedVisibleTipUpdatesReuseVisibleState()
{
    ModalOverlay overlay{/*enable_wallet=*/false, /*parent=*/nullptr};
    QLabel* block_date{overlay.findChild<QLabel*>("newestBlockDate")};
    QLabel* progress_value{overlay.findChild<QLabel*>("percentageProgress")};
    QVERIFY(block_date);
    QVERIFY(progress_value);

    const QDateTime header_date{QDateTime::currentDateTime()};
    const QDateTime tip_date{header_date.addSecs(-3600)};
    overlay.setKnownBestHeight(/*count=*/200, header_date, /*presync=*/false);
    overlay.showHide(/*hide=*/false, /*userRequested=*/true);
    overlay.tipUpdate(/*count=*/100, tip_date, /*nVerificationProgress=*/0.12345);

    const QString rendered_block_date{block_date->text()};
    const QString rendered_progress{progress_value->text()};
    const qsizetype sample_count{overlay.blockProcessTime.size()};

    overlay.tipUpdate(/*count=*/100, tip_date, /*nVerificationProgress=*/0.12345);

    QCOMPARE(block_date->text(), rendered_block_date);
    QCOMPARE(progress_value->text(), rendered_progress);
    QCOMPARE(overlay.blockProcessTime.size(), sample_count);
}

void ModalOverlayTests::progressSampleHistoryIsBounded()
{
    ModalOverlay overlay{/*enable_wallet=*/false, /*parent=*/nullptr};
    overlay.setKnownBestHeight(/*count=*/4000, QDateTime::currentDateTime(), /*presync=*/false);
    overlay.showHide(/*hide=*/false, /*userRequested=*/true);

    const QDateTime tip_date{QDateTime::currentDateTime().addSecs(-3600)};
    for (int i = 0; i < 3000; ++i) {
        overlay.tipUpdate(/*count=*/i, tip_date, /*nVerificationProgress=*/i / 3000.0);
    }

    QVERIFY(overlay.blockProcessTime.size() <= 2048);
}

void ModalOverlayTests::incompleteProgressDoesNotRoundToComplete()
{
    ModalOverlay overlay{/*enable_wallet=*/false, /*parent=*/nullptr};
    QLabel* blocks_left{overlay.findChild<QLabel*>("numberOfBlocksLeft")};
    QLabel* progress_value{overlay.findChild<QLabel*>("percentageProgress")};
    QVERIFY(blocks_left);
    QVERIFY(progress_value);

    overlay.showHide(/*hide=*/false, /*userRequested=*/true);

    const QDateTime now{QDateTime::currentDateTime()};
    overlay.tipUpdate(/*count=*/100, now, /*nVerificationProgress=*/1.0);
    QCOMPARE(progress_value->text(), QString("100.00%"));

    overlay.tipUpdate(/*count=*/100, now.addSecs(-2 * 60 * 60), /*nVerificationProgress=*/1.0);
    QCOMPARE(progress_value->text(), QString("99.99%"));

    const int64_t target_spacing{Params().GetConsensus().nPowTargetSpacing};
    const QDateTime header_date{QDateTime::currentDateTime().addSecs(-30 * target_spacing)};
    overlay.setKnownBestHeight(/*count=*/1'500'000, header_date, /*presync=*/false);
    QVERIFY(blocks_left->text().contains("99.9%"));
    QVERIFY(!blocks_left->text().contains("100.0%"));

    overlay.setKnownBestHeight(/*count=*/1'500'000, header_date, /*presync=*/true);
    QCOMPARE(progress_value->text(), QString("99.9%"));
}
