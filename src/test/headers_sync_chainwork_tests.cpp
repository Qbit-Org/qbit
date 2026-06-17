// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <net.h>
#include <pow.h>
#include <primitives/pureheader.h>
#include <serialize.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);

    CBlockHeader MakeHeader(const uint256& prev_hash, int32_t version, uint32_t n_time, uint32_t n_bits);
    arith_uint256 ClaimedWork(const CBlockIndex& chain_start, const std::vector<CBlockHeader>& headers);
    void FinalizeIndex(CBlockIndex& index, const uint256& hash, CBlockIndex* pprev, int height, uint64_t auxpow_count, arith_uint256 chain_work);
    void AssertHeadersSyncAccepts(const Consensus::Params& consensus, const CBlockIndex& chain_start, const std::vector<CBlockHeader>& headers);
    void AssertHeadersSyncRejects(const Consensus::Params& consensus, const CBlockIndex& chain_start, const std::vector<CBlockHeader>& headers);
    std::shared_ptr<const CAuxPow> MakeAuxpowPayloadWithScriptSigSize(size_t script_sig_size);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetHash(), starting_header.nBits, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

CBlockHeader HeadersGeneratorSetup::MakeHeader(const uint256& prev_hash, const int32_t version, const uint32_t n_time, const uint32_t n_bits)
{
    CBlockHeader header;
    header.nVersion = version;
    header.hashPrevBlock = prev_hash;
    header.nTime = n_time;
    header.nBits = n_bits;
    return header;
}

arith_uint256 HeadersGeneratorSetup::ClaimedWork(const CBlockIndex& chain_start, const std::vector<CBlockHeader>& headers)
{
    arith_uint256 work{chain_start.nChainWork};
    for (const CBlockHeader& header : headers) {
        work += GetBlockProof(CBlockIndex{header});
    }
    return work;
}

void HeadersGeneratorSetup::FinalizeIndex(CBlockIndex& index, const uint256& hash, CBlockIndex* pprev, const int height, const uint64_t auxpow_count, const arith_uint256 chain_work)
{
    index.phashBlock = &hash;
    index.pprev = pprev;
    index.nHeight = height;
    index.nAuxPow = auxpow_count;
    index.nChainWork = chain_work;
    index.BuildSkip();
}

void HeadersGeneratorSetup::AssertHeadersSyncAccepts(const Consensus::Params& consensus, const CBlockIndex& chain_start, const std::vector<CBlockHeader>& headers)
{
    HeadersSyncState hss{/*id=*/0, consensus, &chain_start, ClaimedWork(chain_start, headers)};

    auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);
    BOOST_REQUIRE(result.success);
    BOOST_REQUIRE(result.request_more);
    BOOST_REQUIRE(hss.GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), headers.size());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

void HeadersGeneratorSetup::AssertHeadersSyncRejects(const Consensus::Params& consensus, const CBlockIndex& chain_start, const std::vector<CBlockHeader>& headers)
{
    HeadersSyncState hss{/*id=*/0, consensus, &chain_start, ClaimedWork(chain_start, headers)};

    const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

std::shared_ptr<const CAuxPow> HeadersGeneratorSetup::MakeAuxpowPayloadWithScriptSigSize(const size_t script_sig_size)
{
    auto auxpow = std::make_shared<CAuxPow>();
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig.resize(script_sig_size);
    coinbase.vout.resize(1);
    auxpow->coinbase_tx = MakeTransactionRef(std::move(coinbase));
    BOOST_REQUIRE_GE(GetSerializeSize(*auxpow), script_sig_size);
    return auxpow;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(headers_sync_accepts_genesis_to_permissionless_anchor_jumps)
{
    // These shipped networks fail on current develop because presync compares
    // the first permissionless ASERT target to the adjacent genesis target.
    for (const ChainType chain_type : {ChainType::MAIN, ChainType::SIGNET}) {
        const auto chain_params = CreateChainParams(*m_node.args, chain_type);
        const auto& consensus = chain_params->GetConsensus();
        BOOST_REQUIRE(consensus.fPowUseASERT);
        BOOST_REQUIRE(consensus.CadenceActiveAtHeight(1));

        CBlockIndex genesis{chain_params->GenesisBlock()};
        const uint256 genesis_hash{chain_params->GenesisBlock().GetHash()};
        FinalizeIndex(genesis, genesis_hash, /*pprev=*/nullptr, /*height=*/0, /*auxpow_count=*/0, GetBlockProof(genesis));

        const CBlockHeader permissionless = MakeHeader(genesis.GetBlockHash(),
                                                       MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0),
                                                       consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                                       consensus.asertAnchorParams.nBitsLegacy);
        AssertHeadersSyncAccepts(consensus, genesis, {permissionless});
    }
}

BOOST_AUTO_TEST_CASE(headers_sync_accepts_signet_permissionless_to_auxpow_anchor_jump)
{
    // This covers a mixed-lane regression where an honest signet
    // permissionless-to-AuxPoW transition is rejected by the adjacent 2x guard.
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto& consensus = chain_params->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.CadenceActiveAtHeight(2));
    BOOST_REQUIRE_NE(consensus.asertAnchorParams.nBitsLegacy, consensus.asertAnchorParams.nBitsAuxPow);

    CBlockIndex genesis{chain_params->GenesisBlock()};
    const uint256 genesis_hash{chain_params->GenesisBlock().GetHash()};
    FinalizeIndex(genesis, genesis_hash, /*pprev=*/nullptr, /*height=*/0, /*auxpow_count=*/0, GetBlockProof(genesis));

    const CBlockHeader permissionless_header = MakeHeader(genesis.GetBlockHash(),
                                                          MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0),
                                                          consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                                          consensus.asertAnchorParams.nBitsLegacy);
    CBlockIndex permissionless{permissionless_header};
    const uint256 permissionless_hash{permissionless_header.GetHash()};
    FinalizeIndex(permissionless,
                  permissionless_hash,
                  &genesis,
                  /*height=*/1,
                  /*auxpow_count=*/0,
                  genesis.nChainWork + GetBlockProof(permissionless));

    const CBlockHeader auxpow = MakeHeader(permissionless.GetBlockHash(),
                                           MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0),
                                           permissionless_header.nTime + consensus.nPowTargetSpacing,
                                           consensus.asertAnchorParams.nBitsAuxPow);
    AssertHeadersSyncAccepts(consensus, permissionless, {auxpow});
}

BOOST_AUTO_TEST_CASE(headers_sync_redownload_preserves_auxpow_payload)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto& consensus = chain_params->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.CadenceActiveAtHeight(2));

    CBlockIndex genesis{chain_params->GenesisBlock()};
    const uint256 genesis_hash{chain_params->GenesisBlock().GetHash()};
    FinalizeIndex(genesis, genesis_hash, /*pprev=*/nullptr, /*height=*/0, /*auxpow_count=*/0, GetBlockProof(genesis));

    const CBlockHeader permissionless_header = MakeHeader(genesis.GetBlockHash(),
                                                          MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0),
                                                          consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                                          consensus.asertAnchorParams.nBitsLegacy);
    CBlockIndex permissionless{permissionless_header};
    const uint256 permissionless_hash{permissionless_header.GetHash()};
    FinalizeIndex(permissionless,
                  permissionless_hash,
                  &genesis,
                  /*height=*/1,
                  /*auxpow_count=*/0,
                  genesis.nChainWork + GetBlockProof(permissionless));

    CBlockHeader auxpow = MakeHeader(permissionless.GetBlockHash(),
                                     MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0),
                                     permissionless_header.nTime + consensus.nPowTargetSpacing,
                                     consensus.asertAnchorParams.nBitsAuxPow);
    auxpow.auxpow = MakeAuxpowPayloadWithScriptSigSize(0);

    HeadersSyncState hss{/*id=*/0, consensus, &permissionless, ClaimedWork(permissionless, {auxpow})};
    auto result = hss.ProcessNextHeaders({auxpow}, /*full_headers_message=*/true);
    BOOST_REQUIRE(result.success);
    BOOST_REQUIRE(result.request_more);
    BOOST_REQUIRE(hss.GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss.ProcessNextHeaders({auxpow}, /*full_headers_message=*/true);
    BOOST_REQUIRE(result.success);
    BOOST_REQUIRE(!result.request_more);
    BOOST_REQUIRE_EQUAL(result.pow_validated_headers.size(), 1);
    BOOST_CHECK(result.pow_validated_headers.front().SignalsAuxpow());
    BOOST_REQUIRE(result.pow_validated_headers.front().HasAuxpow());
    BOOST_CHECK(result.pow_validated_headers.front().auxpow == auxpow.auxpow);
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(headers_sync_redownload_rejects_auxpow_payloads_beyond_protocol_window)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto& consensus = chain_params->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.CadenceActiveAtHeight(2));

    CBlockIndex genesis{chain_params->GenesisBlock()};
    const uint256 genesis_hash{chain_params->GenesisBlock().GetHash()};
    FinalizeIndex(genesis, genesis_hash, /*pprev=*/nullptr, /*height=*/0, /*auxpow_count=*/0, GetBlockProof(genesis));

    const CBlockHeader permissionless_header = MakeHeader(genesis.GetBlockHash(),
                                                          MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0),
                                                          consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                                          consensus.asertAnchorParams.nBitsLegacy);
    CBlockIndex permissionless{permissionless_header};
    const uint256 permissionless_hash{permissionless_header.GetHash()};
    FinalizeIndex(permissionless,
                  permissionless_hash,
                  &genesis,
                  /*height=*/1,
                  /*auxpow_count=*/0,
                  genesis.nChainWork + GetBlockProof(permissionless));

    CBlockHeader oversized_auxpow = MakeHeader(permissionless.GetBlockHash(),
                                               MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0),
                                               permissionless_header.nTime + consensus.nPowTargetSpacing,
                                               consensus.asertAnchorParams.nBitsAuxPow);
    oversized_auxpow.auxpow = MakeAuxpowPayloadWithScriptSigSize(MAX_PROTOCOL_MESSAGE_LENGTH * 10);

    HeadersSyncState hss{/*id=*/0, consensus, &permissionless, ClaimedWork(permissionless, {oversized_auxpow})};
    auto result = hss.ProcessNextHeaders({oversized_auxpow}, /*full_headers_message=*/true);
    BOOST_REQUIRE(result.success);
    BOOST_REQUIRE(result.request_more);
    BOOST_REQUIRE(hss.GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss.ProcessNextHeaders({oversized_auxpow}, /*full_headers_message=*/true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(headers_sync_rejects_wrong_signet_auxpow_bits)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto& consensus = chain_params->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE_NE(consensus.asertAnchorParams.nBitsLegacy, consensus.asertAnchorParams.nBitsAuxPow);

    CBlockIndex genesis{chain_params->GenesisBlock()};
    const uint256 genesis_hash{chain_params->GenesisBlock().GetHash()};
    FinalizeIndex(genesis, genesis_hash, /*pprev=*/nullptr, /*height=*/0, /*auxpow_count=*/0, GetBlockProof(genesis));

    const CBlockHeader permissionless_header = MakeHeader(genesis.GetBlockHash(),
                                                          MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0),
                                                          consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                                          consensus.asertAnchorParams.nBitsLegacy);
    CBlockIndex permissionless{permissionless_header};
    const uint256 permissionless_hash{permissionless_header.GetHash()};
    FinalizeIndex(permissionless,
                  permissionless_hash,
                  &genesis,
                  /*height=*/1,
                  /*auxpow_count=*/0,
                  genesis.nChainWork + GetBlockProof(permissionless));

    CBlockHeader wrong_auxpow = MakeHeader(permissionless.GetBlockHash(),
                                           MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0),
                                           permissionless_header.nTime + consensus.nPowTargetSpacing,
                                           consensus.asertAnchorParams.nBitsLegacy);
    AssertHeadersSyncRejects(consensus, permissionless, {wrong_auxpow});
}

BOOST_AUTO_TEST_SUITE_END()
