// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_CLIENTMODEL_H
#define QBIT_QT_CLIENTMODEL_H

#include <QObject>
#include <QDateTime>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <sync.h>
#include <uint256.h>

#include <netaddress.h>

class BanTableModel;
class CBlockIndex;
class OptionsModel;
class PeerTableModel;
class PeerTableSortProxy;
enum class SynchronizationState;
struct LocalServiceInfo;

namespace interfaces {
class Handler;
class Node;
struct BlockTip;
}

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

enum class BlockSource {
    NONE,
    DISK,
    NETWORK,
};

enum class SyncType {
    HEADER_PRESYNC,
    HEADER_SYNC,
    BLOCK_SYNC
};

enum NumConnections {
    CONNECTIONS_NONE = 0,
    CONNECTIONS_IN   = (1U << 0),
    CONNECTIONS_OUT  = (1U << 1),
    CONNECTIONS_ALL  = (CONNECTIONS_IN | CONNECTIONS_OUT),
};

/** Model for Bitcoin network client. */
class ClientModel : public QObject
{
    Q_OBJECT

public:
    explicit ClientModel(interfaces::Node& node, OptionsModel *optionsModel, QObject *parent = nullptr);
    ~ClientModel();

    void stop();

    interfaces::Node& node() const { return m_node; }
    OptionsModel *getOptionsModel();
    PeerTableModel *getPeerTableModel();
    PeerTableSortProxy* peerTableSortProxy();
    BanTableModel *getBanTableModel();

    //! Return number of connections, default is in- and outbound (total)
    int getNumConnections(unsigned int flags = CONNECTIONS_ALL) const;
    std::map<CNetAddr, LocalServiceInfo> getNetLocalAddresses() const;
    int getNumBlocks() const;
    uint256 getBestBlockHash() EXCLUSIVE_LOCKS_REQUIRED(!m_cached_tip_mutex);
    int getHeaderTipHeight() const;
    int64_t getHeaderTipTime() const;

    //! Returns the block source of the current importing/syncing state
    BlockSource getBlockSource() const;
    //! Return warnings to be displayed in status bar
    QString getStatusBarWarnings() const;

    QString formatFullVersion() const;
    QString formatSubVersion() const;
    bool isReleaseVersion() const;
    QString formatClientStartupTime() const;
    QString dataDir() const;
    QString blocksDir() const;

    bool getProxyInfo(std::string& ip_port) const;

    // caches for the best header: hash, number of blocks and block time
    mutable std::atomic<int> cachedBestHeaderHeight;
    mutable std::atomic<int64_t> cachedBestHeaderTime;
    mutable std::atomic<int> m_cached_num_blocks{-1};

    Mutex m_cached_tip_mutex;
    uint256 m_cached_tip_blocks GUARDED_BY(m_cached_tip_mutex){};

private:
    interfaces::Node& m_node;
    std::vector<std::unique_ptr<interfaces::Handler>> m_event_handlers;
    OptionsModel *optionsModel;
    PeerTableModel* peerTableModel{nullptr};
    PeerTableSortProxy* m_peer_table_sort_proxy{nullptr};
    BanTableModel* banTableModel{nullptr};

    //! A thread to interact with m_node asynchronously
    QThread* const m_thread;

    struct SyncUpdate {
        int count{0};
        int64_t block_time{0};
        double verification_progress{0.0};
        SyncType synctype{SyncType::BLOCK_SYNC};
        SynchronizationState sync_state{};
    };

    Mutex m_sync_update_mutex;
    std::optional<SyncUpdate> m_pending_sync_update GUARDED_BY(m_sync_update_mutex);
    std::optional<SyncType> m_last_sync_update_type GUARDED_BY(m_sync_update_mutex);
    std::optional<SynchronizationState> m_last_sync_update_state GUARDED_BY(m_sync_update_mutex);
    std::chrono::steady_clock::time_point m_last_sync_update_time GUARDED_BY(m_sync_update_mutex);
    bool m_sync_update_flush_scheduled GUARDED_BY(m_sync_update_mutex){false};
    uint64_t m_sync_update_flush_generation GUARDED_BY(m_sync_update_mutex){0};

    void TipChanged(SynchronizationState sync_state, interfaces::BlockTip tip, double verification_progress, SyncType synctype) EXCLUSIVE_LOCKS_REQUIRED(!m_cached_tip_mutex, !m_sync_update_mutex);
    void ProcessSyncUpdate(SyncUpdate update) EXCLUSIVE_LOCKS_REQUIRED(!m_sync_update_mutex);
    void EmitNumBlocksChanged(const SyncUpdate& update);
    void ScheduleSyncUpdateFlush(std::chrono::milliseconds delay, uint64_t generation);
    void FlushPendingSyncUpdate(uint64_t generation) NO_THREAD_SAFETY_ANALYSIS;
    void CancelPendingSyncUpdate() NO_THREAD_SAFETY_ANALYSIS;
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

Q_SIGNALS:
    void numConnectionsChanged(int count);
    void numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType header, SynchronizationState sync_state);
    void mempoolSizeChanged(long count, size_t mempoolSizeInBytes, size_t mempoolMaxSizeInBytes);
    void networkActiveChanged(bool networkActive);
    void alertsChanged(const QString &warnings);
    void bytesChanged(quint64 totalBytesIn, quint64 totalBytesOut);

    //! Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

    // Show progress dialog e.g. for verifychain
    void showProgress(const QString &title, int nProgress);
};

#endif // QBIT_QT_CLIENTMODEL_H
