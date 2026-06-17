// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>
#include <util/check.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

void initialize_asert()
{
    SelectParams(ChainType::TESTNET4);
}

FUZZ_TARGET(asert_math, .init = initialize_asert)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const Consensus::Params& consensus_params = Params().GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus_params.powLimit);

    LIMITED_WHILE(fuzzed_data_provider.remaining_bytes() > 0, 10000) {
        arith_uint256 ref_target = ConsumeArithUInt256(fuzzed_data_provider);
        if (ref_target == 0 || ref_target > pow_limit) {
            ref_target = arith_uint256().SetCompact(consensus_params.asertAnchorParams.nBits);
        }

        const int64_t n_height_diff = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 1'000'000);
        const int64_t n_skew = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(-1'000'000'000, 1'000'000'000);
        const int64_t n_time_diff = (consensus_params.nPowTargetSpacing * n_height_diff) + n_skew;

        const arith_uint256 next = CalculateASERT(ref_target,
                                                  consensus_params.nPowTargetSpacing,
                                                  n_time_diff,
                                                  n_height_diff,
                                                  pow_limit,
                                                  consensus_params.nASERTHalfLife);
        Assert(next >= arith_uint256(1));
        Assert(next <= pow_limit);

        bool negative{false};
        bool overflow{false};
        arith_uint256 roundtrip;
        roundtrip.SetCompact(next.GetCompact(), &negative, &overflow);
        Assert(!negative);
        Assert(!overflow);
    }
}

FUZZ_TARGET(asert_chain_transition, .init = initialize_asert)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const Consensus::Params& consensus_params = Params().GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus_params.powLimit);

    CBlockHeader anchor_header;
    anchor_header.nTime = static_cast<uint32_t>(consensus_params.asertAnchorParams.nBlockTime);
    anchor_header.nBits = consensus_params.asertAnchorParams.nBits;
    auto anchor_index = std::make_unique<CBlockIndex>(anchor_header);
    anchor_index->nHeight = consensus_params.asertAnchorParams.nHeight;
    anchor_index->nTime = anchor_header.nTime;
    anchor_index->nBits = anchor_header.nBits;

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    chain.emplace_back(std::move(anchor_index));

    // Exercise long ASERT sequences to catch accumulated drift/rounding issues.
    LIMITED_WHILE(fuzzed_data_provider.remaining_bytes() > 0, 12000) {
        CBlockIndex* prev = chain.back().get();
        const uint32_t delta = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(
            1, static_cast<uint32_t>(consensus_params.nPowTargetSpacing * 4));

        CBlockHeader next_header;
        next_header.nTime = prev->GetBlockTime() + delta;
        if (next_header.nTime <= prev->GetBlockTime()) break;

        const uint32_t next_bits = GetNextWorkRequired(prev, &next_header, consensus_params);
        const auto next_target = DeriveTarget(next_bits, consensus_params.powLimit);
        Assert(next_target.has_value());
        Assert(*next_target >= arith_uint256(1));
        Assert(*next_target <= pow_limit);

        next_header.nBits = next_bits;
        auto next_index = std::make_unique<CBlockIndex>(next_header);
        next_index->pprev = prev;
        next_index->nHeight = prev->nHeight + 1;
        next_index->nTime = next_header.nTime;
        next_index->nBits = next_bits;
        chain.emplace_back(std::move(next_index));
    }
}

FUZZ_TARGET(asert_edge_cases, .init = initialize_asert)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const Consensus::Params& consensus_params = Params().GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus_params.powLimit);
    const arith_uint256 fallback_ref_target = arith_uint256().SetCompact(consensus_params.asertAnchorParams.nBits);
    const int64_t spacing = consensus_params.nPowTargetSpacing;
    const int64_t max_skew = (int64_t{1} << 46) - 1;

    LIMITED_WHILE(fuzzed_data_provider.remaining_bytes() > 0, 1024) {
        arith_uint256 ref_target = ConsumeArithUInt256(fuzzed_data_provider);
        if (ref_target == 0 || ref_target > pow_limit) {
            ref_target = fallback_ref_target;
        }

        const std::array<int64_t, 6> half_life_values{
            int64_t{1},
            int64_t{2},
            int64_t{16},
            int64_t{1024},
            consensus_params.nASERTHalfLife,
            std::numeric_limits<int32_t>::max(),
        };
        const int64_t half_life = fuzzed_data_provider.PickValueInArray(half_life_values);

        const std::array<int64_t, 6> height_values{
            int64_t{0},
            int64_t{1},
            int64_t{2},
            int64_t{1000},
            int64_t{1'000'000},
            int64_t{10'000'000},
        };
        const int64_t n_height_diff = fuzzed_data_provider.PickValueInArray(height_values);
        const int64_t expected_time = spacing * n_height_diff;

        const std::array<int64_t, 7> skew_values{
            -max_skew,
            -half_life,
            -1,
            0,
            1,
            half_life,
            max_skew,
        };
        const int64_t skew = fuzzed_data_provider.PickValueInArray(skew_values);
        const int64_t n_time_diff = expected_time + skew;

        const arith_uint256 next = CalculateASERT(ref_target,
                                                  spacing,
                                                  n_time_diff,
                                                  n_height_diff,
                                                  pow_limit,
                                                  half_life);
        Assert(next >= arith_uint256(1));
        Assert(next <= pow_limit);

        bool negative{false};
        bool overflow{false};
        arith_uint256 roundtrip;
        roundtrip.SetCompact(next.GetCompact(), &negative, &overflow);
        Assert(!negative);
        Assert(!overflow);
    }
}
