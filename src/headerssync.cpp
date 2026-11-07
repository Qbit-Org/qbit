// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <headerssync.h>
#include <logging.h>
#include <pow.h>
#include <serialize.h>
#include <util/check.h>
#include <util/time.h>
#include <util/vector.h>

// The two constants below are computed using the simulation script in
// contrib/devtools/headerssync-params.py.

//! Store one header commitment per HEADER_COMMITMENT_PERIOD blocks.
constexpr size_t HEADER_COMMITMENT_PERIOD{632};

//! Only feed headers to validation once this many headers on top have been
//! received and validated against commitments.
constexpr size_t REDOWNLOAD_BUFFER_SIZE{15009}; // 15009/632 = ~23.7 commitments

//! Number of headers in a full headers message. Keep this synchronized with
//! MAX_HEADERS_RESULTS in net_processing.h without including it here, since
//! net_processing depends on headerssync.
constexpr size_t HEADERS_MESSAGE_SIZE{2000};

//! Maximum serialized AuxPoW payload bytes that can be retained by the
//! redownload lookahead. This is derived from the number of full headers
//! messages that can overlap the redownload buffer plus the current message
//! being processed before PopHeadersReadyForAcceptance() drains it.
constexpr size_t MAX_REDOWNLOAD_AUXPOW_SERIALIZED_SIZE{
    ((REDOWNLOAD_BUFFER_SIZE + HEADERS_MESSAGE_SIZE + HEADERS_MESSAGE_SIZE - 1) / HEADERS_MESSAGE_SIZE) *
    MAX_PROTOCOL_MESSAGE_LENGTH};

// Our memory analysis assumes at most 64 bytes for a CompressedHeader (so we
// should re-calculate parameters if we grow it further).
static_assert(sizeof(CompressedHeader) <= 64);

size_t CompressedHeader::AuxpowSerializedSize() const
{
    if (!auxpow) return 0;
    if (!auxpow->coinbase_tx) return 0;
    return GetSerializeSize(*auxpow);
}

HeadersSyncState::HeadersSyncState(NodeId id, const Consensus::Params& consensus_params,
        const CBlockIndex* chain_start, const arith_uint256& minimum_required_work) :
    m_commit_offset(FastRandomContext().randrange<unsigned>(HEADER_COMMITMENT_PERIOD)),
    m_id(id), m_consensus_params(consensus_params),
    m_chain_start(chain_start),
    m_minimum_required_work(minimum_required_work),
    m_current_chain_work(chain_start->nChainWork),
    m_last_header_received(m_chain_start->GetBlockHeader()),
    m_current_height(chain_start->nHeight)
{
    // Estimate the number of blocks that could possibly exist on the peer's
    // chain *right now* using 6 blocks/second (fastest blockrate given the MTP
    // rule) times the number of seconds from the last allowed block until
    // today. This serves as a memory bound on how many commitments we might
    // store from this peer, and we can safely give up syncing if the peer
    // exceeds this bound, because it's not possible for a consensus-valid
    // chain to be longer than this (at the current time -- in the future we
    // could try again, if necessary, to sync a longer chain).
    // Header sync must admit histories produced under the legacy two-hour
    // future-time rule, even when the v2 rule is active at the current tip.
    const int64_t commitment_time{
        Ticks<std::chrono::seconds>(NodeClock::now() - NodeSeconds{std::chrono::seconds{chain_start->GetMedianTimePast()}}) +
        MAX_FUTURE_BLOCK_TIME_LEGACY};
    if (commitment_time > 0) {
        m_max_commitments = 6 * static_cast<uint64_t>(commitment_time) / HEADER_COMMITMENT_PERIOD;
    }
    m_presync_difficulty = MakeHeaderDifficultyState();
    m_redownload_difficulty = MakeHeaderDifficultyState();

    LogDebug(BCLog::NET, "Initial headers sync started with peer=%d: height=%i, max_commitments=%i, min_work=%s\n", m_id, m_current_height, m_max_commitments, m_minimum_required_work.ToString());
}

HeadersSyncState::HeaderDifficultyState HeadersSyncState::MakeHeaderDifficultyState() const
{
    HeaderDifficultyState state;
    state.last_header = m_chain_start->GetBlockHeader();
    state.height = m_chain_start->nHeight;
    state.auxpow_count = m_chain_start->nAuxPow;

    const int anchor_height{m_consensus_params.asertAnchorParams.nHeight};
    const auto to_header_state = [](const CBlockIndex& pindex) {
        return ASERTHeaderState{pindex.nHeight, pindex.GetBlockTime(), pindex.nAuxPow};
    };
    if (const CBlockIndex* permissionless = m_chain_start->GetPreviousBlockForLane(/*auxpow=*/false, anchor_height)) {
        state.previous_permissionless = to_header_state(*permissionless);
    }
    if (const CBlockIndex* auxpow = m_chain_start->GetPreviousBlockForLane(/*auxpow=*/true, anchor_height)) {
        state.previous_auxpow = to_header_state(*auxpow);
    }

    return state;
}

bool HeadersSyncState::ValidateAndAdvanceHeaderDifficulty(HeaderDifficultyState& state, const CBlockHeader& current)
{
    const int64_t next_height = state.height + 1;

    if (!PermittedDifficultyTransition(m_consensus_params,
                                       next_height,
                                       state.last_header.nBits,
                                       current.nBits,
                                       state.last_header.GetBlockTime(),
                                       current.GetBlockTime())) {
        return false;
    }

    if (!m_consensus_params.fPowNoRetargeting &&
        m_consensus_params.fPowUseASERT &&
        m_consensus_params.CadenceActiveAtHeight(static_cast<int>(next_height))) {
        const bool current_is_auxpow{current.SignalsAuxpow()};
        const int64_t target_spacing{GetCadenceTargetSpacing(m_consensus_params, current_is_auxpow)};
        uint32_t expected_nbits{0};
        const uint32_t pow_limit_nbits{UintToArith256(m_consensus_params.powLimit).GetCompact()};
        if (m_consensus_params.fPowAllowMinDifficultyBlocks &&
            current.GetBlockTime() > state.last_header.GetBlockTime() + target_spacing * 2) {
            expected_nbits = pow_limit_nbits;
        } else {
            expected_nbits = GetNextASERTWorkRequired(current_is_auxpow ? state.previous_auxpow : state.previous_permissionless,
                                                      current_is_auxpow,
                                                      m_consensus_params);
        }
        if (current.nBits != expected_nbits) return false;
    }

    const bool current_is_auxpow{current.SignalsAuxpow()};
    state.auxpow_count += current_is_auxpow ? 1 : 0;
    const ASERTHeaderState current_state{next_height, current.GetBlockTime(), state.auxpow_count};
    if (current_is_auxpow) {
        state.previous_auxpow = current_state;
    } else {
        state.previous_permissionless = current_state;
    }
    state.last_header = current;
    state.height = next_height;
    return true;
}

/** Free any memory in use, and mark this object as no longer usable. This is
 * required to guarantee that we won't reuse this object with the same
 * SaltedUint256Hasher for another sync. */
void HeadersSyncState::Finalize()
{
    Assume(m_download_state != State::FINAL);
    ClearShrink(m_header_commitments);
    m_last_header_received.SetNull();
    ClearShrink(m_redownloaded_headers);
    m_redownload_buffer_last_hash.SetNull();
    m_redownload_buffer_first_prev_hash.SetNull();
    m_redownload_auxpow_serialized_size = 0;
    m_process_all_remaining_headers = false;
    m_current_height = 0;

    m_download_state = State::FINAL;
}

/** Process the next batch of headers received from our peer.
 *  Validate and store commitments, and compare total chainwork to our target to
 *  see if we can switch to REDOWNLOAD mode.  */
HeadersSyncState::ProcessingResult HeadersSyncState::ProcessNextHeaders(const
        std::vector<CBlockHeader>& received_headers, const bool full_headers_message)
{
    ProcessingResult ret;

    Assume(!received_headers.empty());
    if (received_headers.empty()) return ret;

    Assume(m_download_state != State::FINAL);
    if (m_download_state == State::FINAL) return ret;

    if (m_download_state == State::PRESYNC) {
        // During PRESYNC, we minimally validate block headers and
        // occasionally add commitments to them, until we reach our work
        // threshold (at which point m_download_state is updated to REDOWNLOAD).
        ret.success = ValidateAndStoreHeadersCommitments(received_headers);
        if (ret.success) {
            if (full_headers_message || m_download_state == State::REDOWNLOAD) {
                // A full headers message means the peer may have more to give us;
                // also if we just switched to REDOWNLOAD then we need to re-request
                // headers from the beginning.
                ret.request_more = true;
            } else {
                Assume(m_download_state == State::PRESYNC);
                // If we're in PRESYNC and we get a non-full headers
                // message, then the peer's chain has ended and definitely doesn't
                // have enough work, so we can stop our sync.
                LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: incomplete headers message at height=%i (presync phase)\n", m_id, m_current_height);
            }
        }
    } else if (m_download_state == State::REDOWNLOAD) {
        // During REDOWNLOAD, we compare our stored commitments to what we
        // receive, and add headers to our redownload buffer. When the buffer
        // gets big enough (meaning that we've checked enough commitments),
        // we'll return a batch of headers to the caller for processing.
        ret.success = true;
        for (const auto& hdr : received_headers) {
            if (!ValidateAndStoreRedownloadedHeader(hdr)) {
                // Something went wrong -- the peer gave us an unexpected chain.
                // We could consider looking at the reason for failure and
                // punishing the peer, but for now just give up on sync.
                ret.success = false;
                break;
            }
        }

        if (ret.success) {
            // Return any headers that are ready for acceptance.
            ret.pow_validated_headers = PopHeadersReadyForAcceptance();

            // If we hit our target blockhash, then all remaining headers will be
            // returned and we can clear any leftover internal state.
            if (m_redownloaded_headers.empty() && m_process_all_remaining_headers) {
                LogDebug(BCLog::NET, "Initial headers sync complete with peer=%d: releasing all at height=%i (redownload phase)\n", m_id, m_redownload_buffer_last_height);
            } else if (full_headers_message) {
                // If the headers message is full, we need to request more.
                ret.request_more = true;
            } else {
                // For some reason our peer gave us a high-work chain, but is now
                // declining to serve us that full chain again. Give up.
                // Note that there's no more processing to be done with these
                // headers, so we can still return success.
                LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: incomplete headers message at height=%i (redownload phase)\n", m_id, m_redownload_buffer_last_height);
            }
        }
    }

    if (!(ret.success && ret.request_more)) Finalize();
    return ret;
}

bool HeadersSyncState::ValidateAndStoreHeadersCommitments(const std::vector<CBlockHeader>& headers)
{
    // The caller should not give us an empty set of headers.
    Assume(headers.size() > 0);
    if (headers.size() == 0) return true;

    Assume(m_download_state == State::PRESYNC);
    if (m_download_state != State::PRESYNC) return false;

    if (headers[0].hashPrevBlock != m_last_header_received.GetHash()) {
        // Somehow our peer gave us a header that doesn't connect.
        // This might be benign -- perhaps our peer reorged away from the chain
        // they were on. Give up on this sync for now (likely we will start a
        // new sync with a new starting point).
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: non-continuous headers at height=%i (presync phase)\n", m_id, m_current_height);
        return false;
    }

    // If it does connect, (minimally) validate and occasionally store
    // commitments.
    for (const auto& hdr : headers) {
        if (!ValidateAndProcessSingleHeader(hdr)) {
            return false;
        }
    }

    if (m_current_chain_work >= m_minimum_required_work) {
        m_redownloaded_headers.clear();
        m_redownload_buffer_last_height = m_chain_start->nHeight;
        m_redownload_buffer_first_prev_hash = m_chain_start->GetBlockHash();
        m_redownload_buffer_last_hash = m_chain_start->GetBlockHash();
        m_redownload_auxpow_serialized_size = 0;
        m_redownload_chain_work = m_chain_start->nChainWork;
        m_redownload_difficulty = MakeHeaderDifficultyState();
        m_download_state = State::REDOWNLOAD;
        LogDebug(BCLog::NET, "Initial headers sync transition with peer=%d: reached sufficient work at height=%i, redownloading from height=%i\n", m_id, m_current_height, m_redownload_buffer_last_height);
    }
    return true;
}

bool HeadersSyncState::ValidateAndProcessSingleHeader(const CBlockHeader& current)
{
    Assume(m_download_state == State::PRESYNC);
    if (m_download_state != State::PRESYNC) return false;

    int next_height = m_current_height + 1;

    if (!ValidateAndAdvanceHeaderDifficulty(m_presync_difficulty, current)) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (presync phase)\n", m_id, next_height);
        return false;
    }

    if (next_height % HEADER_COMMITMENT_PERIOD == m_commit_offset) {
        // Add a commitment.
        m_header_commitments.push_back(m_hasher(current.GetHash()) & 1);
        if (m_header_commitments.size() > m_max_commitments) {
            // The peer's chain is too long; give up.
            // It's possible the chain grew since we started the sync; so
            // potentially we could succeed in syncing the peer's chain if we
            // try again later.
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: exceeded max commitments at height=%i (presync phase)\n", m_id, next_height);
            return false;
        }
    }

    m_current_chain_work += GetBlockProof(CBlockIndex(current));
    m_last_header_received = current;
    m_current_height = next_height;

    return true;
}

bool HeadersSyncState::ValidateAndStoreRedownloadedHeader(const CBlockHeader& header)
{
    Assume(m_download_state == State::REDOWNLOAD);
    if (m_download_state != State::REDOWNLOAD) return false;

    int64_t next_height = m_redownload_buffer_last_height + 1;

    // Ensure that we're working on a header that connects to the chain we're
    // downloading.
    if (header.hashPrevBlock != m_redownload_buffer_last_hash) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: non-continuous headers at height=%i (redownload phase)\n", m_id, next_height);
        return false;
    }

    if (!ValidateAndAdvanceHeaderDifficulty(m_redownload_difficulty, header)) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (redownload phase)\n", m_id, next_height);
        return false;
    }

    // Track work on the redownloaded chain
    m_redownload_chain_work += GetBlockProof(CBlockIndex(header));

    if (m_redownload_chain_work >= m_minimum_required_work) {
        m_process_all_remaining_headers = true;
    }

    // If we're at a header for which we previously stored a commitment, verify
    // it is correct. Failure will result in aborting download.
    // Also, don't check commitments once we've gotten to our target blockhash;
    // it's possible our peer has extended its chain between our first sync and
    // our second, and we don't want to return failure after we've seen our
    // target blockhash just because we ran out of commitments.
    if (!m_process_all_remaining_headers && next_height % HEADER_COMMITMENT_PERIOD == m_commit_offset) {
        if (m_header_commitments.size() == 0) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: commitment overrun at height=%i (redownload phase)\n", m_id, next_height);
            // Somehow our peer managed to feed us a different chain and
            // we've run out of commitments.
            return false;
        }
        bool commitment = m_hasher(header.GetHash()) & 1;
        bool expected_commitment = m_header_commitments.front();
        m_header_commitments.pop_front();
        if (commitment != expected_commitment) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: commitment mismatch at height=%i (redownload phase)\n", m_id, next_height);
            return false;
        }
    }

    // Store this header for later processing.
    CompressedHeader compressed_header{header};
    const size_t auxpow_serialized_size{compressed_header.AuxpowSerializedSize()};
    if (auxpow_serialized_size > MAX_REDOWNLOAD_AUXPOW_SERIALIZED_SIZE - m_redownload_auxpow_serialized_size) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: retained auxpow serialized size exceeded limit at height=%i (redownload phase)\n", m_id, next_height);
        return false;
    }
    m_redownload_auxpow_serialized_size += auxpow_serialized_size;
    m_redownloaded_headers.push_back(std::move(compressed_header));
    m_redownload_buffer_last_height = next_height;
    m_redownload_buffer_last_hash = header.GetHash();

    return true;
}

std::vector<CBlockHeader> HeadersSyncState::PopHeadersReadyForAcceptance()
{
    std::vector<CBlockHeader> ret;

    Assume(m_download_state == State::REDOWNLOAD);
    if (m_download_state != State::REDOWNLOAD) return ret;

    while (m_redownloaded_headers.size() > REDOWNLOAD_BUFFER_SIZE ||
            (m_redownloaded_headers.size() > 0 && m_process_all_remaining_headers)) {
        ret.emplace_back(m_redownloaded_headers.front().GetFullHeader(m_redownload_buffer_first_prev_hash));
        m_redownload_auxpow_serialized_size -= m_redownloaded_headers.front().AuxpowSerializedSize();
        m_redownloaded_headers.pop_front();
        m_redownload_buffer_first_prev_hash = ret.back().GetHash();
    }
    return ret;
}

CBlockLocator HeadersSyncState::NextHeadersRequestLocator() const
{
    Assume(m_download_state != State::FINAL);
    if (m_download_state == State::FINAL) return {};

    auto chain_start_locator = LocatorEntries(m_chain_start);
    std::vector<uint256> locator;

    if (m_download_state == State::PRESYNC) {
        // During pre-synchronization, we continue from the last header received.
        locator.push_back(m_last_header_received.GetHash());
    }

    if (m_download_state == State::REDOWNLOAD) {
        // During redownload, we will download from the last received header that we stored.
        locator.push_back(m_redownload_buffer_last_hash);
    }

    locator.insert(locator.end(), chain_start_locator.begin(), chain_start_locator.end());

    return CBlockLocator{std::move(locator)};
}
