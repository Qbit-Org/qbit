// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_NET_PROCESSING_H
#define QBIT_NET_PROCESSING_H

#include <consensus/amount.h>
#include <net.h>
#include <node/txorphanage.h>
#include <protocol.h>
#include <threadsafety.h>
#include <validationinterface.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <ratio>
#include <string>
#include <vector>

class AddrMan;
class CTxMemPool;
class ChainstateManager;
class BanMan;
class CBlockIndex;
class CScheduler;
class DataStream;
class uint256;
enum class TxValidationResult;

namespace node {
class Warnings;
} // namespace node

/** Whether transaction reconciliation protocol should be enabled by default. */
static constexpr bool DEFAULT_TXRECONCILIATION_ENABLE{false};
/** Default number of non-mempool transactions to keep around for block reconstruction. Includes
    orphan, replaced, and rejected transactions. */
static const uint32_t DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN{100};
static const bool DEFAULT_PEERBLOOMFILTERS = false;
static const bool DEFAULT_PEERBLOCKFILTERS = false;
/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
static const unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;

/** Default credit, per second of connection time, that a peer earns for the time spent
 *  validating its transactions that are rejected (see TxValidationBudget). */
static constexpr std::chrono::microseconds DEFAULT_TX_VALIDATION_PEER_RATE{500};
/** Default maximum credit a peer can hold. */
static constexpr std::chrono::microseconds DEFAULT_TX_VALIDATION_PEER_CAP{100'000};
/** Default refill, per second, of the node-wide pool used by peers that have no own credit to use. */
static constexpr std::chrono::microseconds DEFAULT_TX_VALIDATION_POOL_RATE{50'000};
/** Default size of the node-wide pool. */
static constexpr std::chrono::microseconds DEFAULT_TX_VALIDATION_POOL_CAP{500'000};
/** Lowest balance that a peer's credit or the pool can reach. */
static constexpr std::chrono::microseconds TX_VALIDATION_CREDIT_FLOOR{-1'000'000};
/** Largest value accepted for any of the four TxValidationBudgetOptions durations. */
static constexpr std::chrono::microseconds MAX_TX_VALIDATION_BUDGET_SETTING{std::chrono::hours{1}};

/** Settings of the TxValidationBudget. */
struct TxValidationBudgetOptions {
    //! Whether the budget is enforced. Validation time is measured and reported either way.
    bool enabled{true};
    //! Credit a peer earns per second of connection time.
    std::chrono::microseconds peer_rate{DEFAULT_TX_VALIDATION_PEER_RATE};
    //! Maximum credit a peer can hold.
    std::chrono::microseconds peer_cap{DEFAULT_TX_VALIDATION_PEER_CAP};
    //! Credit added to the node-wide pool per second.
    std::chrono::microseconds pool_rate{DEFAULT_TX_VALIDATION_POOL_RATE};
    //! Maximum credit the node-wide pool can hold. The pool starts full.
    std::chrono::microseconds pool_cap{DEFAULT_TX_VALIDATION_POOL_CAP};
};

/**
 * Whether the time spent validating a transaction that was rejected with this result is
 * charged to the peer that sent it. Only rejections caused by the transaction itself are
 * charged; rejections that depend on our chain or mempool state are not.
 *
 * @returns std::nullopt if result is not a known TxValidationResult value.
 */
std::optional<bool> IsTxValidationTimeCharged(TxValidationResult result);

/**
 * Bounds the time spent validating transactions that peers send and that are then rejected
 * for a reason in the transaction itself (see IsTxValidationTimeCharged).
 *
 * Each peer has its own credit, which starts at zero and grows by peer_rate per second up to
 * peer_cap. A peer can use its own credit once the credit has reached peer_cap for the first
 * time; until then, and whenever it has no positive credit, it draws on a node-wide pool that
 * starts full and grows by pool_rate per second up to pool_cap. A new connection therefore
 * draws on the pool only, and reconnecting does not give a peer more credit.
 *
 * Validation time is charged after the transaction has been validated, so a balance can go
 * negative, down to TX_VALIDATION_CREDIT_FLOOR. A peer that can neither use its own credit nor
 * draw on the pool is throttled: its transactions are not validated until its credit or the
 * pool is positive again. Exempt peers are never throttled and are never charged.
 *
 * Over time, the time charged is therefore bounded by peer_rate for each connected peer plus
 * pool_rate, apart from the transaction that takes a balance below zero, which is charged in
 * full down to the floor. A peer's debt ends with its connection, but a new connection can use
 * its own credit only after peer_cap / peer_rate seconds.
 *
 * Credit grows with the (mockable) node clock passed in as now. If the clock moves backwards,
 * nothing is added and growth restarts from the new time. Not thread-safe.
 */
class TxValidationBudget
{
public:
    /** Balances are kept in picoseconds, so that frequent small refills lose nothing to rounding. */
    using Credit = std::chrono::duration<int64_t, std::pico>;

    /** The account of one peer connection. */
    class Account
    {
    public:
        explicit Account(std::chrono::microseconds now) : m_last_refill{now} {}

        /** The peer's own credit as of the last refill. */
        Credit GetCredit() const { return m_credit; }
        /** Whether the peer's own credit has reached the cap, after which the peer can use it. */
        bool IsEstablished() const { return m_established; }
        /** Total validation time charged, including time not deducted because the peer is exempt. */
        std::chrono::microseconds GetTotalCharged() const { return m_total_charged; }

    private:
        friend class TxValidationBudget;
        Credit m_credit{0};
        std::chrono::microseconds m_last_refill;
        bool m_established{false};
        std::chrono::microseconds m_total_charged{0};
    };

    TxValidationBudget(const TxValidationBudgetOptions& options, std::chrono::microseconds now);

    /** Whether a transaction from the peer that owns account may be validated now. */
    bool MayValidate(Account& account, bool exempt, std::chrono::microseconds now);

    /** Charge cost, the time spent validating a rejected transaction from the peer that owns account. */
    void Charge(Account& account, bool exempt, std::chrono::microseconds cost, std::chrono::microseconds now);

    /** The pool's balance as of the last refill. */
    Credit GetPoolCredit() const { return m_pool_credit; }

    const TxValidationBudgetOptions& GetOptions() const { return m_options; }

private:
    const TxValidationBudgetOptions m_options;
    Credit m_pool_credit;
    std::chrono::microseconds m_pool_last_refill;

    void RefillAccount(Account& account, std::chrono::microseconds now) const;
    void RefillPool(std::chrono::microseconds now);
    /** Whether the peer can use its own credit (otherwise it draws on the pool). */
    static bool CanUseOwnCredit(const Account& account) { return account.m_established && account.m_credit > Credit::zero(); }
};

/** Transaction validation budget figures for one peer. */
struct TxValidationStats {
    //! Total time spent validating this peer's transactions that were rejected for a reason in the
    //! transaction itself (charged time, also counted for exempt peers).
    std::chrono::microseconds failed_time{0};
    //! Whether this peer's transactions are currently not validated because it is over its budget.
    bool throttled{false};
    //! Number of transactions received from this peer that were dropped without validation because
    //! it was over its budget.
    uint64_t dropped{0};
};

struct CNodeStateStats {
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::chrono::microseconds m_ping_wait;
    std::vector<int> vHeightInFlight;
    bool m_relay_txs;
    CAmount m_fee_filter_received;
    uint64_t m_addr_processed = 0;
    uint64_t m_addr_rate_limited = 0;
    bool m_addr_relay_enabled{false};
    ServiceFlags their_services;
    int64_t presync_height{-1};
    std::chrono::seconds time_offset{0};
    //! Set once the version handshake with the peer has completed.
    std::optional<TxValidationStats> m_tx_validation;
};

struct PeerManagerInfo {
    std::chrono::seconds median_outbound_time_offset{0s};
    bool ignores_incoming_txs{false};
};

class PeerManager : public CValidationInterface, public NetEventsInterface
{
public:
    struct Options {
        //! Whether this node is running in -blocksonly mode
        bool ignore_incoming_txs{DEFAULT_BLOCKSONLY};
        //! Whether transaction reconciliation protocol is enabled
        bool reconcile_txs{DEFAULT_TXRECONCILIATION_ENABLE};
        //! Number of non-mempool transactions to keep around for block reconstruction. Includes
        //! orphan, replaced, and rejected transactions.
        uint32_t max_extra_txs{DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN};
        //! Whether all P2P messages are captured to disk
        bool capture_messages{false};
        //! Whether or not the internal RNG behaves deterministically (this is
        //! a test-only option).
        bool deterministic_rng{false};
        //! Number of headers sent in one getheaders message result (this is
        //! a test-only option).
        uint32_t max_headers_result{MAX_HEADERS_RESULTS};
        //! Budget for the time spent validating transactions from peers that are then rejected.
        TxValidationBudgetOptions tx_validation_budget{};
    };

    static std::unique_ptr<PeerManager> make(CConnman& connman, AddrMan& addrman,
                                             BanMan* banman, ChainstateManager& chainman,
                                             CTxMemPool& pool, node::Warnings& warnings, Options opts);
    virtual ~PeerManager() = default;

    /**
     * Attempt to manually fetch block from a given peer. We must already have the header.
     *
     * @param[in]  peer_id      The peer id
     * @param[in]  block_index  The blockindex
     * @returns std::nullopt if a request was successfully made, otherwise an error message
     */
    virtual std::optional<std::string> FetchBlock(NodeId peer_id, const CBlockIndex& block_index) = 0;

    /** Begin running background tasks, should only be called once */
    virtual void StartScheduledTasks(CScheduler& scheduler) = 0;

    /** Get statistics from node state */
    virtual bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) const = 0;

    /** Test-only access to whether a block request from a peer was marked stripped. */
    virtual std::optional<bool> RequestedStrippedForTest(NodeId nodeid, const uint256& hash) const = 0;

    /** Test-only access to the recorded source peer for a received block hash. */
    virtual std::optional<NodeId> BlockSourcePeerForTest(const uint256& hash) const = 0;

    /** Test-only helper to mark a witness recovery request in flight for a peer. */
    virtual bool RequestWitnessRecoveryForTest(NodeId nodeid, const CBlockIndex& block_index) = 0;

    /** Test-only setter for peer best-known block state. */
    virtual void SetBestKnownBlockForTest(NodeId nodeid, const CBlockIndex& block_index) = 0;

    /** Test-only wrapper for headers direct fetch. */
    virtual void HeadersDirectFetchBlocksForTest(CNode& node, const CBlockIndex& last_header) = 0;

    virtual std::vector<node::TxOrphanage::OrphanInfo> GetOrphanTransactions() = 0;

    /** Get peer manager info. */
    virtual PeerManagerInfo GetInfo() const = 0;

    /** Relay transaction to all peers. */
    virtual void RelayTransaction(const Txid& txid, const Wtxid& wtxid) = 0;

    /** Send ping message to all peers */
    virtual void SendPings() = 0;

    /** Set the height of the best block and its time (seconds since epoch). */
    virtual void SetBestBlock(int height, std::chrono::seconds time) = 0;

    /* Public for unit testing. */
    virtual void UnitTestMisbehaving(NodeId peer_id) = 0;

    /**
     * Evict extra outbound peers. If we think our tip may be stale, connect to an extra outbound.
     * Public for unit testing.
     */
    virtual void CheckForStaleTipAndEvictPeers() = 0;

    /** Process a single message from a peer. Public for fuzz testing */
    virtual void ProcessMessage(CNode& pfrom, const std::string& msg_type, DataStream& vRecv,
                                const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /** This function is used for testing the stale tip eviction logic, see denialofservice_tests.cpp */
    virtual void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) = 0;

    /**
     * Gets the set of service flags which are "desirable" for a given peer.
     *
     * These are the flags which are required for a peer to support for them
     * to be "interesting" to us, ie for us to wish to use one of our few
     * outbound connection slots for or for us to wish to prioritize keeping
     * their connection around.
     *
     * Relevant service flags may be peer- and state-specific in that the
     * version of the peer may determine which flags are required (eg in the
     * case of NODE_NETWORK_LIMITED where we seek out NODE_NETWORK peers
     * unless they set NODE_NETWORK_LIMITED and we are out of IBD, in which
     * case NODE_NETWORK_LIMITED suffices).
     *
     * Thus, generally, avoid calling with 'services' == NODE_NONE, unless
     * state-specific flags must absolutely be avoided. When called with
     * 'services' == NODE_NONE, the returned desirable service flags are
     * guaranteed to not change dependent on state - ie they are suitable for
     * use when describing peers which we know to be desirable, but for which
     * we do not have a confirmed set of service flags.
    */
    virtual ServiceFlags GetDesirableServiceFlags(ServiceFlags services) const = 0;

    /** Whether a peer advertises service flags that make it unsuitable for some connection types. */
    virtual bool HasUndesirableServiceFlags(ServiceFlags services) const override = 0;
};

#endif // QBIT_NET_PROCESSING_H
