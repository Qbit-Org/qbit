// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bench/bench.h>

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <headerssync.h>
#include <pow.h>
#include <primitives/block.h>
#include <util/chaintype.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>

namespace {
class CadenceBenchChain
{
public:
    explicit CadenceBenchChain(const Consensus::Params& consensus, const size_t starvation_distance)
    {
        const int32_t permissionless_version{MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0)};
        const int32_t auxpow_version{MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0)};

        Append(permissionless_version,
               consensus.asertAnchorParams.nBlockTime,
               consensus.asertAnchorParams.nBitsLegacy);
        Append(auxpow_version,
               m_indexes.back().nTime + static_cast<uint32_t>(consensus.nPowTargetSpacingAuxPow),
               consensus.asertAnchorParams.nBitsAuxPow);
        for (size_t i = 0; i < starvation_distance; ++i) {
            Append(permissionless_version,
                   m_indexes.back().nTime + static_cast<uint32_t>(consensus.nPowTargetSpacingLegacy),
                   consensus.asertAnchorParams.nBitsLegacy);
        }

        m_next_auxpow.nVersion = auxpow_version;
        m_next_auxpow.hashPrevBlock = Tip().GetBlockHash();
        m_next_auxpow.nTime = Tip().nTime + 1;
        m_next_auxpow.nBits = GetNextWorkRequired(&Tip(), &m_next_auxpow, consensus);
    }

    const CBlockIndex& Tip() const { return m_indexes.back(); }
    const CBlockHeader& NextAuxpow() const { return m_next_auxpow; }

private:
    void Append(const int32_t version, const uint32_t time, const uint32_t bits)
    {
        CBlockHeader header;
        header.nVersion = version;
        header.hashPrevBlock = m_indexes.empty() ? uint256{} : m_indexes.back().GetBlockHash();
        header.nTime = time;
        header.nBits = bits;

        m_indexes.emplace_back(header);
        m_hashes.emplace_back(header.GetHash());
        CBlockIndex& index{m_indexes.back()};
        index.phashBlock = &m_hashes.back();
        index.pprev = m_indexes.size() == 1 ? nullptr : &m_indexes[m_indexes.size() - 2];
        index.nHeight = index.pprev == nullptr ? 0 : index.pprev->nHeight + 1;
        index.nAuxPow = (index.pprev == nullptr ? 0 : index.pprev->nAuxPow) + (header.SignalsAuxpow() ? 1 : 0);
        index.nChainWork = (index.pprev == nullptr ? arith_uint256{} : index.pprev->nChainWork) + GetBlockProof(index);
        index.BuildSkip();
        index.BuildCadenceLaneLinks();
    }

    std::deque<CBlockIndex> m_indexes;
    std::deque<uint256> m_hashes;
    CBlockHeader m_next_auxpow;
};

size_t StarvationDistance(const benchmark::Bench& bench)
{
    return std::max<size_t>(1, static_cast<size_t>(bench.complexityN()));
}

void CadenceLaneLookup(benchmark::Bench& bench)
{
    ArgsManager args;
    const auto chain_params{CreateChainParams(args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};
    CadenceBenchChain chain{consensus, StarvationDistance(bench)};

    bench.run([&] {
        ankerl::nanobench::doNotOptimizeAway(GetNextWorkRequired(&chain.Tip(), &chain.NextAuxpow(), consensus));
    });
}

void CadenceHeadersSyncInit(benchmark::Bench& bench)
{
    ArgsManager args;
    const auto chain_params{CreateChainParams(args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};
    CadenceBenchChain chain{consensus, StarvationDistance(bench)};
    const arith_uint256 minimum_work{chain.Tip().nChainWork + GetBlockProof(CBlockIndex{chain.NextAuxpow()})};

    bench.run([&] {
        HeadersSyncState state{/*id=*/0, consensus, &chain.Tip(), minimum_work};
        ankerl::nanobench::doNotOptimizeAway(state.GetState());
    });
}
} // namespace

BENCHMARK(CadenceLaneLookup, benchmark::PriorityLevel::HIGH);
BENCHMARK(CadenceHeadersSyncInit, benchmark::PriorityLevel::HIGH);
