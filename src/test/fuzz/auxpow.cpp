// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <streams.h>
#include <util/chaintype.h>
#include <validation.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>

namespace {
[[nodiscard]] std::vector<uint256> ConsumeHashes(FuzzedDataProvider& fuzzed_data_provider)
{
    std::vector<uint256> hashes;
    const size_t count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 16);
    hashes.reserve(count);
    while (hashes.size() < count) {
        hashes.push_back(ConsumeUInt256(fuzzed_data_provider));
    }
    return hashes;
}

[[nodiscard]] CPureBlockHeader ConsumePureBlockHeader(FuzzedDataProvider& fuzzed_data_provider)
{
    CPureBlockHeader header;
    header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    if (header.SignalsAuxpow()) {
        header.nVersion &= ~BLOCK_VERSION_AUXPOW;
    }
    header.hashPrevBlock = ConsumeUInt256(fuzzed_data_provider);
    header.hashMerkleRoot = ConsumeUInt256(fuzzed_data_provider);
    header.nTime = ConsumeTime(fuzzed_data_provider);
    header.nBits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    header.nNonce = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    return header;
}

[[nodiscard]] std::shared_ptr<const CAuxPow> ConsumeAuxPow(FuzzedDataProvider& fuzzed_data_provider)
{
    auto auxpow = std::make_shared<CAuxPow>();
    auxpow->coinbase_tx = MakeTransactionRef(ConsumeTransaction(fuzzed_data_provider, std::nullopt));
    auxpow->coinbase_merkle_branch = ConsumeHashes(fuzzed_data_provider);
    auxpow->coinbase_branch_index = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    auxpow->chain_merkle_branch = ConsumeHashes(fuzzed_data_provider);
    auxpow->chain_index = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    auxpow->parent_block = ConsumePureBlockHeader(fuzzed_data_provider);
    return auxpow;
}

[[nodiscard]] CBlockHeader ConsumeBlockHeader(FuzzedDataProvider& fuzzed_data_provider)
{
    CBlockHeader header;
    const auto pure_header = ConsumePureBlockHeader(fuzzed_data_provider);
    header.nVersion = pure_header.nVersion;
    header.hashPrevBlock = pure_header.hashPrevBlock;
    header.hashMerkleRoot = pure_header.hashMerkleRoot;
    header.nTime = pure_header.nTime;
    header.nBits = pure_header.nBits;
    header.nNonce = pure_header.nNonce;

    if (fuzzed_data_provider.ConsumeBool()) {
        header.auxpow = ConsumeAuxPow(fuzzed_data_provider);
        header.nVersion = MakeVersion(
            fuzzed_data_provider.ConsumeIntegral<uint16_t>(),
            /*auxpow=*/true,
            fuzzed_data_provider.ConsumeIntegral<uint8_t>());
    }
    return header;
}
} // namespace

void initialize_auxpow()
{
    SelectParams(ChainType::MAIN);
}

FUZZ_TARGET(auxpow,
    .init = initialize_auxpow,
    .disable_leak_detection = true)
{
    try {
        FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
        const Consensus::Params& consensus = Params().GetConsensus();

        if (fuzzed_data_provider.ConsumeBool()) {
            const auto auxpow_payload = ConsumeAuxPow(fuzzed_data_provider);
            const uint256 aux_hash = ConsumeUInt256(fuzzed_data_provider);
            const uint32_t target_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            const uint16_t chain_id = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
            const uint32_t nonce = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            const uint32_t index = auxpow_payload->chain_index < 0 ? 0U : static_cast<uint32_t>(auxpow_payload->chain_index);

            (void)auxpow::CheckMerkleBranch(aux_hash, auxpow_payload->chain_merkle_branch, index);
            if (auxpow_payload->chain_merkle_branch.size() < std::numeric_limits<uint32_t>::digits) {
                (void)auxpow::GetExpectedIndex(nonce, chain_id, auxpow_payload->chain_merkle_branch.size());
            }
            const auto commitment_validation = fuzzed_data_provider.PickValueInArray({
                auxpow::CommitmentValidation::EITHER,
                auxpow::CommitmentValidation::INTERNAL,
                auxpow::CommitmentValidation::DISPLAY,
            });
            (void)auxpow_payload->Validate(aux_hash, consensus, target_bits, chain_id, fuzzed_data_provider.ConsumeBool(), commitment_validation);
        }

        if (fuzzed_data_provider.ConsumeBool()) {
            const CBlockHeader block_header = ConsumeBlockHeader(fuzzed_data_provider);
            (void)block_header.GetHash();
            (void)block_header.SignalsAuxpow();
            (void)block_header.HasAuxpow();
            (void)auxpow::Validate(block_header, consensus, fuzzed_data_provider.ConsumeBool());

            CBlock block{block_header};
            (void)block.GetBlockHeader();
            (void)block.ToString();
        }

        if (fuzzed_data_provider.ConsumeBool()) {
            CBlock block{ConsumeBlockHeader(fuzzed_data_provider)};
            const size_t tx_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 4);
            block.vtx.reserve(tx_count);
            while (block.vtx.size() < tx_count) {
                block.vtx.push_back(MakeTransactionRef(ConsumeTransaction(fuzzed_data_provider, std::nullopt)));
            }
            block.hashMerkleRoot = block.vtx.front()->GetHash().ToUint256();

            BlockValidationState state;
            (void)CheckBlock(block, state, consensus, fuzzed_data_provider.ConsumeBool(), fuzzed_data_provider.ConsumeBool());
            (void)auxpow::Validate(block.GetBlockHeader(), consensus, fuzzed_data_provider.ConsumeBool());
        }
    } catch (const std::ios_base::failure&) {
        return;
    }
}
