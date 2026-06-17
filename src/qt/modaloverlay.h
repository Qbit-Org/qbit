// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_MODALOVERLAY_H
#define QBIT_QT_MODALOVERLAY_H

#include <QDateTime>
#include <QPropertyAnimation>
#include <QWidget>

//! The required delta of headers to the estimated number of available headers until we show the IBD progress
static constexpr int HEADER_HEIGHT_DELTA_SYNC = 24;

namespace Ui {
    class ModalOverlay;
}

/** Modal overlay to display information about the chain-sync state */
class ModalOverlay : public QWidget
{
    Q_OBJECT

public:
    explicit ModalOverlay(bool enable_wallet, QWidget *parent);
    ~ModalOverlay();

    void tipUpdate(int count, const QDateTime& blockDate, double nVerificationProgress);
    void setKnownBestHeight(int count, const QDateTime& blockDate, bool presync);
    void finishHeadersPresync();

    // will show or hide the modal layer
    void showHide(bool hide = false, bool userRequested = false);
    bool isLayerVisible() const { return layerIsVisible; }

public Q_SLOTS:
    void toggleVisibility();
    void closeClicked();

Q_SIGNALS:
    void triggered(bool hidden);

protected:
    bool eventFilter(QObject * obj, QEvent * ev) override;
    bool event(QEvent* ev) override;

private:
    friend class ModalOverlayTests;

    Ui::ModalOverlay *ui;
    int bestHeaderHeight{0}; // best known height (based on the headers)
    QDateTime bestHeaderDate;
    bool m_headers_presync_active{false};
    int m_headers_presync_height{0};
    QDateTime m_headers_presync_date;
    bool m_has_latest_tip{false};
    int m_latest_tip_count{0};
    QDateTime m_latest_tip_date;
    double m_latest_tip_verification_progress{0.0};
    qint64 m_last_progress_metrics_update_msecs{0};
    QVector<QPair<qint64, double> > blockProcessTime;
    bool layerIsVisible{false};
    bool userClosed{false};
    QPropertyAnimation m_animation;
    void renderLatestTip();
    void UpdateHeaderSyncLabel();
    void UpdateHeaderPresyncLabel(int height, const QDateTime& blockDate);
};

#endif // QBIT_QT_MODALOVERLAY_H
