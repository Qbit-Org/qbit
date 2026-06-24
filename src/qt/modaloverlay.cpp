// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/modaloverlay.h>
#include <qt/forms/ui_modaloverlay.h>

#include <chain.h>
#include <chainparams.h>
#include <qt/guiutil.h>

#include <QEasingCurve>
#include <QPropertyAnimation>
#include <QResizeEvent>

namespace {
static constexpr qint64 PROGRESS_METRICS_UPDATE_DELAY_MS{1000};
static constexpr qint64 PROGRESS_SAMPLE_WINDOW_MS{500 * 1000};
static constexpr int MAX_PROGRESS_SAMPLES{2048};

QString HeaderSyncProgress(int height, const QDateTime& blockDate)
{
    int est_headers_left = blockDate.secsTo(QDateTime::currentDateTime()) / Params().GetConsensus().nPowTargetSpacing;
    if (est_headers_left < 0) est_headers_left = 0;

    const int headers_estimate{height + est_headers_left};
    if (headers_estimate <= 0) return {};

    return GUIUtil::formatSyncPercentage(static_cast<double>(height) / headers_estimate, /*decimals=*/1, /*incomplete=*/est_headers_left > 0);
}

void SetLabelText(QLabel* label, const QString& text)
{
    if (label->text() != text) {
        label->setText(text);
    }
}
} // namespace

ModalOverlay::ModalOverlay(bool enable_wallet, QWidget* parent)
    : QWidget(parent),
      ui(new Ui::ModalOverlay),
      bestHeaderDate(QDateTime())
{
    ui->setupUi(this);
    connect(ui->closeButton, &QPushButton::clicked, this, &ModalOverlay::closeClicked);
    if (parent) {
        parent->installEventFilter(this);
        raise();
    }
    ui->closeButton->installEventFilter(this);

    blockProcessTime.clear();
    setVisible(false);
    if (!enable_wallet) {
        ui->infoText->setVisible(false);
        ui->infoTextStrong->setText(tr("%1 is currently syncing.  It will download headers and blocks from peers and validate them until reaching the tip of the block chain.").arg(CLIENT_NAME));
    }

    m_animation.setTargetObject(this);
    m_animation.setPropertyName("pos");
    m_animation.setDuration(300 /* ms */);
    m_animation.setEasingCurve(QEasingCurve::OutQuad);
}

ModalOverlay::~ModalOverlay()
{
    delete ui;
}

bool ModalOverlay::eventFilter(QObject * obj, QEvent * ev) {
    if (obj == parent()) {
        if (ev->type() == QEvent::Resize) {
            QResizeEvent * rev = static_cast<QResizeEvent*>(ev);
            resize(rev->size());
            if (!layerIsVisible)
                setGeometry(0, height(), width(), height());

            if (m_animation.endValue().toPoint().y() > 0) {
                m_animation.setEndValue(QPoint(0, height()));
            }
        }
        else if (ev->type() == QEvent::ChildAdded) {
            raise();
        }
    }

    if (obj == ui->closeButton && ev->type() == QEvent::FocusOut && layerIsVisible) {
        ui->closeButton->setFocus(Qt::OtherFocusReason);
    }

    return QWidget::eventFilter(obj, ev);
}

//! Tracks parent widget changes
bool ModalOverlay::event(QEvent* ev) {
    if (ev->type() == QEvent::ParentAboutToChange) {
        if (parent()) parent()->removeEventFilter(this);
    }
    else if (ev->type() == QEvent::ParentChange) {
        if (parent()) {
            parent()->installEventFilter(this);
            raise();
        }
    }
    return QWidget::event(ev);
}

void ModalOverlay::setKnownBestHeight(int count, const QDateTime& blockDate, bool presync)
{
    if (presync) {
        m_headers_presync_active = true;
        m_headers_presync_height = count;
        m_headers_presync_date = blockDate;
        UpdateHeaderPresyncLabel(count, blockDate);
        return;
    }

    if (!presync && count > bestHeaderHeight) {
        bestHeaderHeight = count;
        bestHeaderDate = blockDate;
    }

    if (m_headers_presync_active) {
        if (count < m_headers_presync_height) {
            UpdateHeaderPresyncLabel(m_headers_presync_height, m_headers_presync_date);
            return;
        }
        finishHeadersPresync();
    }

    if (!presync && bestHeaderHeight == count) {
        UpdateHeaderSyncLabel();
    }
}

void ModalOverlay::finishHeadersPresync()
{
    if (!m_headers_presync_active) return;

    m_headers_presync_active = false;
    SetLabelText(ui->labelSyncDone, tr("Progress"));
    SetLabelText(ui->percentageProgress, QStringLiteral("~"));
    if (bestHeaderDate.isValid()) {
        UpdateHeaderSyncLabel();
    } else {
        SetLabelText(ui->numberOfBlocksLeft, tr("Unknown…"));
    }
}

void ModalOverlay::tipUpdate(int count, const QDateTime& blockDate, double nVerificationProgress)
{
    m_has_latest_tip = true;
    m_latest_tip_count = count;
    m_latest_tip_date = blockDate;
    m_latest_tip_verification_progress = nVerificationProgress;

    if (!layerIsVisible) return;

    renderLatestTip();
}

void ModalOverlay::renderLatestTip()
{
    if (m_headers_presync_active) {
        UpdateHeaderPresyncLabel(m_headers_presync_height, m_headers_presync_date);
        return;
    }

    if (!m_has_latest_tip) return;

    const int count{m_latest_tip_count};
    const QDateTime& blockDate{m_latest_tip_date};
    const double nVerificationProgress{m_latest_tip_verification_progress};

    QDateTime currentDate = QDateTime::currentDateTime();
    const qint64 current_time_msecs{currentDate.toMSecsSinceEpoch()};
    const bool incomplete_sync{
        blockDate.secsTo(currentDate) >= MAX_BLOCK_TIME_GAP ||
        (bestHeaderDate.isValid() && bestHeaderHeight > count)};
    const QString percentage_progress{GUIUtil::formatSyncPercentage(nVerificationProgress, /*decimals=*/2, incomplete_sync) + "%"};
    const bool update_progress_metrics{
        ui->percentageProgress->text() != percentage_progress ||
        m_last_progress_metrics_update_msecs == 0 ||
        current_time_msecs - m_last_progress_metrics_update_msecs >= PROGRESS_METRICS_UPDATE_DELAY_MS};

    if (update_progress_metrics) {
        // keep a vector of samples of verification progress at height
        blockProcessTime.push_front(qMakePair(current_time_msecs, nVerificationProgress));
        const qint64 oldest_sample_time{current_time_msecs - PROGRESS_SAMPLE_WINDOW_MS};
        while (!blockProcessTime.isEmpty() && blockProcessTime.back().first < oldest_sample_time) {
            blockProcessTime.removeLast();
        }
        if (blockProcessTime.count() > MAX_PROGRESS_SAMPLES) {
            blockProcessTime.remove(MAX_PROGRESS_SAMPLES, blockProcessTime.count() - MAX_PROGRESS_SAMPLES);
        }
    }

    if (update_progress_metrics && blockProcessTime.size() < 2) {
        SetLabelText(ui->progressIncreasePerH, tr("calculating…"));
        SetLabelText(ui->expectedTimeLeft, tr("calculating…"));
    }

    // show progress speed if we have more than one sample
    if (update_progress_metrics && blockProcessTime.size() >= 2) {
        double progressDelta = 0;
        double progressPerHour = 0;
        qint64 timeDelta = 0;
        qint64 remainingMSecs = 0;
        double remainingProgress = 1.0 - nVerificationProgress;
        for (int i = 1; i < blockProcessTime.size(); i++) {
            QPair<qint64, double> sample = blockProcessTime[i];

            // take first sample after 500 seconds or last available one
            if (sample.first < (current_time_msecs - PROGRESS_SAMPLE_WINDOW_MS) || i == blockProcessTime.size() - 1) {
                progressDelta = blockProcessTime[0].second - sample.second;
                timeDelta = blockProcessTime[0].first - sample.first;
                const bool has_progress_rate{progressDelta > 0 && timeDelta > 0};
                progressPerHour = has_progress_rate ? progressDelta / (double)timeDelta * 1000 * 3600 : 0;
                remainingMSecs = has_progress_rate ? remainingProgress / progressDelta * timeDelta : -1;
                break;
            }
        }
        // show progress increase per hour
        SetLabelText(ui->progressIncreasePerH, QString::number(progressPerHour * 100, 'f', 2) + "%");

        // show expected remaining time
        if(remainingMSecs >= 0) {
            SetLabelText(ui->expectedTimeLeft, GUIUtil::formatNiceTimeOffset(remainingMSecs / 1000.0));
        } else {
            SetLabelText(ui->expectedTimeLeft, QObject::tr("unknown"));
        }

    }
    if (update_progress_metrics) {
        m_last_progress_metrics_update_msecs = current_time_msecs;
    }

    // show the last block date
    SetLabelText(ui->newestBlockDate, blockDate.toString());

    // show the percentage done according to nVerificationProgress
    SetLabelText(ui->percentageProgress, percentage_progress);

    if (!bestHeaderDate.isValid())
        // not syncing
        return;

    // estimate the number of headers left based on nPowTargetSpacing
    // and check if the gui is not aware of the best header (happens rarely)
    int estimateNumHeadersLeft = bestHeaderDate.secsTo(currentDate) / Params().GetConsensus().nPowTargetSpacing;
    bool hasBestHeader = bestHeaderHeight >= count;

    // show remaining number of blocks
    if (estimateNumHeadersLeft < HEADER_HEIGHT_DELTA_SYNC && hasBestHeader) {
        SetLabelText(ui->numberOfBlocksLeft, QString::number(bestHeaderHeight - count));
    } else {
        UpdateHeaderSyncLabel();
        SetLabelText(ui->expectedTimeLeft, tr("Unknown…"));
    }
}

void ModalOverlay::UpdateHeaderSyncLabel() {
    const QString progress{HeaderSyncProgress(bestHeaderHeight, bestHeaderDate)};
    SetLabelText(ui->labelSyncDone, tr("Progress"));
    if (progress.isEmpty()) {
        SetLabelText(ui->numberOfBlocksLeft, tr("Unknown…"));
        return;
    }
    SetLabelText(ui->numberOfBlocksLeft, tr("Unknown. Syncing Headers (%1, %2%)…").arg(bestHeaderHeight).arg(progress));
}

void ModalOverlay::UpdateHeaderPresyncLabel(int height, const QDateTime& blockDate) {
    const QString progress{HeaderSyncProgress(height, blockDate)};
    SetLabelText(ui->labelSyncDone, tr("Headers pre-sync progress"));
    if (progress.isEmpty()) {
        SetLabelText(ui->percentageProgress, QStringLiteral("~"));
        SetLabelText(ui->numberOfBlocksLeft, tr("Unknown. Pre-syncing Headers (%1)…").arg(height));
        return;
    }
    SetLabelText(ui->percentageProgress, progress + "%");
    SetLabelText(ui->numberOfBlocksLeft, tr("Unknown. Pre-syncing Headers (%1, %2%)…").arg(height).arg(progress));
}

void ModalOverlay::toggleVisibility()
{
    showHide(layerIsVisible, true);
    if (!layerIsVisible)
        userClosed = true;
}

void ModalOverlay::showHide(bool hide, bool userRequested)
{
    if ( (layerIsVisible && !hide) || (!layerIsVisible && hide) || (!hide && userClosed && !userRequested))
        return;

    Q_EMIT triggered(hide);

    if (!isVisible() && !hide)
        setVisible(true);

    m_animation.setStartValue(QPoint(0, hide ? 0 : height()));
    // The eventFilter() updates the endValue if it is required for QEvent::Resize.
    m_animation.setEndValue(QPoint(0, hide ? height() : 0));
    m_animation.start(QAbstractAnimation::KeepWhenStopped);
    layerIsVisible = !hide;

    if (layerIsVisible) {
        renderLatestTip();
        ui->closeButton->setFocus(Qt::OtherFocusReason);
    }
}

void ModalOverlay::closeClicked()
{
    showHide(true);
    userClosed = true;
}
