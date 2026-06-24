// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <node/miner.h>
#include <pow.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <vector>

using node::BlockAssembler;

namespace {
static constexpr std::array<unsigned char, 4> MERGED_MINING_HEADER{0xfa, 0xbe, 0x6d, 0x6d};
static constexpr uint8_t DB_BLOCK_INDEX_LEGACY_TEST_KEY{'b'};

std::vector<unsigned char> SerializeCommitmentFooter(uint32_t merkle_size, uint32_t nonce);

struct LegacyDiskBlockIndexWithoutAuxpowPayload {
    int height;
    uint32_t status;
    unsigned int tx_count;
    uint64_t auxpow_count;
    int file;
    unsigned int data_pos;
    int32_t version;
    uint256 prev_hash;
    uint256 merkle_root;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        int disk_version{CBlockIndex::DUMMY_VERSION};
        stream << VARINT_MODE(disk_version, VarIntMode::NONNEGATIVE_SIGNED);
        stream << VARINT_MODE(height, VarIntMode::NONNEGATIVE_SIGNED);
        stream << VARINT(status);
        stream << VARINT(tx_count);
        stream << VARINT(auxpow_count);
        if (status & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) stream << VARINT_MODE(file, VarIntMode::NONNEGATIVE_SIGNED);
        if (status & BLOCK_HAVE_DATA) stream << VARINT(data_pos);
        stream << version;
        stream << prev_hash;
        stream << merkle_root;
        stream << time;
        stream << bits;
        stream << nonce;
    }
};

CTransactionRef MakeParentCoinbase(const std::vector<unsigned char>& commitment)
{
    CMutableTransaction tx;
    tx.version = 1;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vin[0].scriptSig = CScript{} << commitment;
    tx.vout[0].nValue = 0;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;
    return MakeTransactionRef(std::move(tx));
}

std::vector<unsigned char> InternalUint256Bytes(const uint256& value)
{
    return {value.begin(), value.end()};
}

std::vector<unsigned char> AuxpowCommitmentRootBytes(const uint256& root)
{
    auto bytes = InternalUint256Bytes(root);
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}

std::vector<unsigned char> MakeCommitment(std::vector<unsigned char> prefix, const std::vector<unsigned char>& root, const uint32_t merkle_size, const uint32_t nonce)
{
    prefix.insert(prefix.end(), root.begin(), root.end());
    const auto footer = SerializeCommitmentFooter(merkle_size, nonce);
    prefix.insert(prefix.end(), footer.begin(), footer.end());
    return prefix;
}

std::vector<unsigned char> MakeCommitment(std::vector<unsigned char> prefix, const uint256& root, const uint32_t merkle_size, const uint32_t nonce)
{
    return MakeCommitment(std::move(prefix), AuxpowCommitmentRootBytes(root), merkle_size, nonce);
}

std::shared_ptr<const CAuxPow> MakeAuxpowPayload(const uint256& aux_block_hash, const Consensus::Params& consensus, const uint32_t target_bits, const uint32_t parent_time)
{
    auto auxpow = std::make_shared<CAuxPow>();
    auxpow->coinbase_merkle_branch.clear();
    auxpow->coinbase_branch_index = 0;
    auxpow->chain_merkle_branch.clear();
    auxpow->chain_index = 0;

    std::vector<unsigned char> commitment;
    commitment.insert(commitment.end(), MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end());
    commitment = MakeCommitment(std::move(commitment), aux_block_hash, /*merkle_size=*/1, /*nonce=*/0);

    auxpow->coinbase_tx = MakeParentCoinbase(commitment);
    auxpow->parent_block.nVersion = 1;
    auxpow->parent_block.hashPrevBlock.SetNull();
    auxpow->parent_block.hashMerkleRoot = auxpow->coinbase_tx->GetHash().ToUint256();
    auxpow->parent_block.nTime = parent_time;
    auxpow->parent_block.nBits = target_bits;
    auxpow->parent_block.nNonce = 0;
    while (!CheckProofOfWork(auxpow->parent_block.GetHash(), target_bits, consensus)) {
        ++auxpow->parent_block.nNonce;
    }

    return auxpow;
}

CBlockHeader MakeAuxpowHeader(const Consensus::Params& consensus)
{
    CBlockHeader header;
    header.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    header.hashPrevBlock = uint256{1};
    header.hashMerkleRoot = uint256{2};
    header.nTime = 1'738'713'700;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce = 0;
    header.auxpow = MakeAuxpowPayload(header.GetHash(), consensus, header.nBits, header.nTime);
    return header;
}

std::vector<unsigned char> SerializeCommitmentFooter(const uint32_t merkle_size, const uint32_t nonce)
{
    std::vector<unsigned char> footer(sizeof(uint32_t) * 2);
    WriteLE32(footer.data(), merkle_size);
    WriteLE32(footer.data() + sizeof(uint32_t), nonce);
    return footer;
}

std::shared_ptr<const CAuxPow> WithCoinbaseScriptSig(const CAuxPow& original, const std::vector<unsigned char>& script_sig)
{
    auto auxpow = std::make_shared<CAuxPow>(original);
    CMutableTransaction coinbase{*auxpow->coinbase_tx};
    coinbase.vin[0].scriptSig = CScript{} << script_sig;
    auxpow->coinbase_tx = MakeTransactionRef(std::move(coinbase));
    auxpow->parent_block.hashMerkleRoot = auxpow->coinbase_tx->GetHash().ToUint256();
    return auxpow;
}

struct AuxpowRegTestingSetup : public TestingSetup {
    AuxpowRegTestingSetup()
        : TestingSetup{ChainType::REGTEST, {.extra_args = {"-p2mronly=0"}}} {}

    std::shared_ptr<CBlock> CreateBlockTemplate()
    {
        BlockAssembler::Options options;
        options.coinbase_output_script = CScript{} << OP_TRUE;
        auto block_template = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
        return std::make_shared<CBlock>(block_template->block);
    }

    void FinalizeBlock(CBlock& block)
    {
        const CBlockIndex* prev_block{WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(block.hashPrevBlock))};
        m_node.chainman->GenerateCoinbaseCommitment(block, prev_block);
        block.hashMerkleRoot = BlockMerkleRoot(block);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

// Selected structural validation cases in this suite mirror
// namecoin-core/src/test/auxpow_tests.cpp (Daniel Kraft, MIT).
// qbit intentionally diverges in slot-index assignment: GetExpectedIndex()
// uses two LCG rounds rather than Namecoin's additional merkle-height rounds.

BOOST_AUTO_TEST_CASE(auxpow_header_roundtrip_preserves_payload_and_hash)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const CBlockHeader header = MakeAuxpowHeader(consensus);

    const uint256 original_hash = header.GetHash();
    DataStream stream;
    stream << header;

    CBlockHeader decoded;
    stream >> decoded;

    BOOST_CHECK(decoded.HasAuxpow());
    BOOST_CHECK(decoded.SignalsAuxpow());
    BOOST_CHECK_EQUAL(decoded.GetHash(), original_hash);
    BOOST_CHECK(decoded.auxpow->coinbase_tx->IsCoinBase());
    BOOST_CHECK_EQUAL(decoded.auxpow->GetParentBlockHash(), header.auxpow->GetParentBlockHash());
}

BOOST_AUTO_TEST_CASE(auxpow_block_roundtrip_preserves_payload_and_merkle_root)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlock block;
    block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    block.hashPrevBlock = uint256{12};
    block.nTime = 1'738'713'705;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce = 0;
    block.vtx = {MakeParentCoinbase({0x51})};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.auxpow = MakeAuxpowPayload(block.GetHash(), consensus, block.nBits, block.nTime);

    DataStream stream;
    stream << TX_WITH_WITNESS(block);

    CBlock decoded;
    stream >> TX_WITH_WITNESS(decoded);

    BOOST_CHECK(decoded.HasAuxpow());
    BOOST_CHECK_EQUAL(decoded.GetHash(), block.GetHash());
    BOOST_CHECK_EQUAL(decoded.hashMerkleRoot, block.hashMerkleRoot);
    BOOST_CHECK_EQUAL(decoded.vtx.size(), block.vtx.size());
    BOOST_CHECK_EQUAL(BlockMerkleRoot(decoded), decoded.hashMerkleRoot);
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_missing_and_unexpected_payload)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader missing_payload;
    missing_payload.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    missing_payload.hashPrevBlock = uint256{3};
    missing_payload.hashMerkleRoot = uint256{4};
    missing_payload.nTime = 1'738'713'701;
    missing_payload.nBits = UintToArith256(consensus.powLimit).GetCompact();

    const auto missing = auxpow::Validate(missing_payload, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(missing.has_value());
    BOOST_CHECK_EQUAL(missing->reject_reason, "bad-auxpow-missing-payload");

    CBlockHeader unexpected_payload;
    unexpected_payload.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    unexpected_payload.hashPrevBlock = uint256{5};
    unexpected_payload.hashMerkleRoot = uint256{6};
    unexpected_payload.nTime = 1'738'713'702;
    unexpected_payload.nBits = UintToArith256(consensus.powLimit).GetCompact();
    unexpected_payload.auxpow = MakeAuxpowPayload(unexpected_payload.GetHash(), consensus, unexpected_payload.nBits, unexpected_payload.nTime);

    const auto unexpected = auxpow::Validate(unexpected_payload, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(unexpected.has_value());
    BOOST_CHECK_EQUAL(unexpected->reject_reason, "bad-auxpow-unexpected-payload");
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_wrong_chainid)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader wrong_chainid;
    wrong_chainid.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId + 1), /*auxpow=*/true, /*version_bits=*/0);
    wrong_chainid.hashPrevBlock = uint256{7};
    wrong_chainid.hashMerkleRoot = uint256{8};
    wrong_chainid.nTime = 1'738'713'703;
    wrong_chainid.nBits = UintToArith256(consensus.powLimit).GetCompact();

    const auto err = auxpow::Validate(wrong_chainid, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(err.has_value());
    BOOST_CHECK_EQUAL(err->reject_reason, "bad-auxpow-chainid");
}

BOOST_AUTO_TEST_CASE(auxpow_expected_index_vectors_document_qbit_slot_math)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    // qbit intentionally omits the merkle-height-dependent extra LCG rounds
    // used by Namecoin, so these vectors pin qbit's slot assignment.
    BOOST_CHECK_EQUAL(auxpow::GetExpectedIndex(/*nonce=*/0, /*chain_id=*/1, /*merkle_height=*/0), 0);
    BOOST_CHECK_EQUAL(auxpow::GetExpectedIndex(/*nonce=*/0, /*chain_id=*/1, /*merkle_height=*/1), 1);
    BOOST_CHECK_EQUAL(auxpow::GetExpectedIndex(/*nonce=*/0, consensus.nAuxpowChainId, /*merkle_height=*/4), 12);
    BOOST_CHECK_EQUAL(auxpow::GetExpectedIndex(/*nonce=*/0x12345678, consensus.nAuxpowChainId, /*merkle_height=*/4), 4);
    BOOST_CHECK_EQUAL(auxpow::GetExpectedIndex(/*nonce=*/0, consensus.nAuxpowChainId, /*merkle_height=*/32), 882684108);
    BOOST_CHECK_EQUAL(auxpow::GetExpectedIndex(std::numeric_limits<uint32_t>::max(),
                                               consensus.nAuxpowChainId,
                                               auxpow::MAX_CHAIN_MERKLE_BRANCH_LENGTH),
                      838473315);
}

BOOST_AUTO_TEST_CASE(auxpow_merkle_branch_respects_left_and_right_positions)
{
    const uint256 leaf{21};
    const std::vector<uint256> branch{uint256{22}};

    BOOST_CHECK_NE(auxpow::CheckMerkleBranch(leaf, branch, /*index=*/0),
                   auxpow::CheckMerkleBranch(leaf, branch, /*index=*/1));
}

BOOST_AUTO_TEST_CASE(auxpow_validates_parent_pow_and_slot_rules)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const CBlockHeader valid_header = MakeAuxpowHeader(consensus);
    BOOST_CHECK(!auxpow::Validate(valid_header, consensus));

    CBlockHeader bad_parent_pow{valid_header};
    auto bad_parent_auxpow = std::make_shared<CAuxPow>(*valid_header.auxpow);
    do {
        ++bad_parent_auxpow->parent_block.nNonce;
    } while (CheckProofOfWork(bad_parent_auxpow->GetParentBlockHash(), bad_parent_pow.nBits, consensus));
    bad_parent_pow.auxpow = bad_parent_auxpow;
    const auto bad_pow = auxpow::Validate(bad_parent_pow, consensus);
    BOOST_REQUIRE(bad_pow.has_value());
    BOOST_CHECK_EQUAL(bad_pow->reject_reason, "bad-auxpow-parent-hash");

    CBlockHeader bad_slot{valid_header};
    auto bad_slot_auxpow = std::make_shared<CAuxPow>(*valid_header.auxpow);
    bad_slot_auxpow->chain_index = 1;
    bad_slot.auxpow = bad_slot_auxpow;
    const auto bad_index = auxpow::Validate(bad_slot, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(bad_index.has_value());
    BOOST_CHECK_EQUAL(bad_index->reject_reason, "bad-auxpow-chain-index");
}

BOOST_AUTO_TEST_CASE(auxpow_parent_header_version_bits_are_parent_chain_data)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    CBlockHeader header = MakeAuxpowHeader(consensus);
    auto parent_version_auxpow = std::make_shared<CAuxPow>(*header.auxpow);
    parent_version_auxpow->parent_block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    BOOST_CHECK(parent_version_auxpow->parent_block.SignalsAuxpow());
    BOOST_CHECK_EQUAL(parent_version_auxpow->parent_block.GetChainId(), consensus.nAuxpowChainId);

    parent_version_auxpow->parent_block.nNonce = 0;
    while (!CheckProofOfWork(parent_version_auxpow->GetParentBlockHash(), header.nBits, consensus)) {
        ++parent_version_auxpow->parent_block.nNonce;
    }
    header.auxpow = parent_version_auxpow;

    BOOST_CHECK(!auxpow::Validate(header, consensus));
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_malformed_coinbase_merkle_branch)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    CBlockHeader header = MakeAuxpowHeader(consensus);

    auto malformed_branch_auxpow = std::make_shared<CAuxPow>(*header.auxpow);
    malformed_branch_auxpow->coinbase_merkle_branch.emplace_back(42);
    header.auxpow = malformed_branch_auxpow;

    const auto err = auxpow::Validate(header, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(err.has_value());
    BOOST_CHECK_EQUAL(err->reject_reason, "bad-auxpow-coinbase-branch");
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_coinbase_merkle_branch_height_overflow)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    CBlockHeader header = MakeAuxpowHeader(consensus);

    auto oversized_branch = std::make_shared<CAuxPow>(*header.auxpow);
    oversized_branch->coinbase_merkle_branch.resize(std::numeric_limits<uint32_t>::digits);
    header.auxpow = oversized_branch;

    const auto err = auxpow::Validate(header, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(err.has_value());
    BOOST_CHECK_EQUAL(err->reject_reason, "bad-auxpow-coinbase-branch-size");
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_duplicate_merged_mining_headers)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    CBlockHeader header = MakeAuxpowHeader(consensus);

    auto duplicate_header_auxpow = std::make_shared<CAuxPow>(*header.auxpow);
    CMutableTransaction coinbase{*duplicate_header_auxpow->coinbase_tx};
    coinbase.vin[0].scriptSig << std::vector<unsigned char>{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    duplicate_header_auxpow->coinbase_tx = MakeTransactionRef(std::move(coinbase));
    duplicate_header_auxpow->parent_block.hashMerkleRoot = duplicate_header_auxpow->coinbase_tx->GetHash().ToUint256();
    header.auxpow = duplicate_header_auxpow;

    const auto err = auxpow::Validate(header, consensus, /*check_pow=*/false);
    BOOST_REQUIRE(err.has_value());
    BOOST_CHECK_EQUAL(err->reject_reason, "bad-auxpow-commitment");
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_structural_validation_failures)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const auto expect_reject = [&](const CBlockHeader& header, const char* reason) {
        const auto err = auxpow::Validate(header, consensus, /*check_pow=*/false);
        BOOST_REQUIRE(err.has_value());
        BOOST_CHECK_EQUAL(err->reject_reason, reason);
    };

    CBlockHeader missing_coinbase = MakeAuxpowHeader(consensus);
    auto missing_coinbase_auxpow = std::make_shared<CAuxPow>(*missing_coinbase.auxpow);
    missing_coinbase_auxpow->coinbase_tx.reset();
    missing_coinbase.auxpow = missing_coinbase_auxpow;
    expect_reject(missing_coinbase, "bad-auxpow-coinbase");

    CBlockHeader negative_coinbase_index = MakeAuxpowHeader(consensus);
    auto negative_coinbase_index_auxpow = std::make_shared<CAuxPow>(*negative_coinbase_index.auxpow);
    negative_coinbase_index_auxpow->coinbase_branch_index = -1;
    negative_coinbase_index.auxpow = negative_coinbase_index_auxpow;
    expect_reject(negative_coinbase_index, "bad-auxpow-coinbase-index");

    CBlockHeader nonzero_coinbase_index = MakeAuxpowHeader(consensus);
    auto nonzero_coinbase_index_auxpow = std::make_shared<CAuxPow>(*nonzero_coinbase_index.auxpow);
    nonzero_coinbase_index_auxpow->coinbase_branch_index = 1;
    nonzero_coinbase_index.auxpow = nonzero_coinbase_index_auxpow;
    expect_reject(nonzero_coinbase_index, "bad-auxpow-coinbase-index");

    CBlockHeader negative_chain_index = MakeAuxpowHeader(consensus);
    auto negative_chain_index_auxpow = std::make_shared<CAuxPow>(*negative_chain_index.auxpow);
    negative_chain_index_auxpow->chain_index = -1;
    negative_chain_index.auxpow = negative_chain_index_auxpow;
    expect_reject(negative_chain_index, "bad-auxpow-chain-index");

    CBlockHeader oversized_chain_branch = MakeAuxpowHeader(consensus);
    auto oversized_chain_branch_auxpow = std::make_shared<CAuxPow>(*oversized_chain_branch.auxpow);
    oversized_chain_branch_auxpow->chain_merkle_branch.resize(auxpow::MAX_CHAIN_MERKLE_BRANCH_LENGTH + 1);
    oversized_chain_branch.auxpow = oversized_chain_branch_auxpow;
    expect_reject(oversized_chain_branch, "bad-auxpow-chain-branch-size");

    CBlockHeader coinbase_index_out_of_range = MakeAuxpowHeader(consensus);
    auto coinbase_index_out_of_range_auxpow = std::make_shared<CAuxPow>(*coinbase_index_out_of_range.auxpow);
    coinbase_index_out_of_range_auxpow->coinbase_merkle_branch.resize(1);
    coinbase_index_out_of_range_auxpow->coinbase_branch_index = 2;
    coinbase_index_out_of_range.auxpow = coinbase_index_out_of_range_auxpow;
    expect_reject(coinbase_index_out_of_range, "bad-auxpow-coinbase-index");
}

BOOST_AUTO_TEST_CASE(auxpow_accepts_legacy_commitment_without_merged_mining_header)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader header = MakeAuxpowHeader(consensus);
    header.auxpow = WithCoinbaseScriptSig(*header.auxpow,
                                          MakeCommitment(/*prefix=*/{}, header.GetHash(), /*merkle_size=*/1, /*nonce=*/0));

    BOOST_CHECK(!auxpow::Validate(header, consensus, /*check_pow=*/false));
}

BOOST_AUTO_TEST_CASE(auxpow_commitment_validation_modes_match_activation_plan)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader display_order = MakeAuxpowHeader(consensus);
    BOOST_CHECK(!auxpow::Validate(display_order, consensus, /*check_pow=*/false));
    BOOST_CHECK(!auxpow::Validate(display_order, consensus, /*check_pow=*/false, auxpow::CommitmentValidation::DISPLAY));
    const auto display_as_internal = auxpow::Validate(display_order, consensus, /*check_pow=*/false, auxpow::CommitmentValidation::INTERNAL);
    BOOST_REQUIRE(display_as_internal.has_value());
    BOOST_CHECK_EQUAL(display_as_internal->reject_reason, "bad-auxpow-commitment");

    CBlockHeader internal_order = MakeAuxpowHeader(consensus);
    std::vector<unsigned char> prefix{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    internal_order.auxpow = WithCoinbaseScriptSig(*internal_order.auxpow,
                                                  MakeCommitment(std::move(prefix), InternalUint256Bytes(internal_order.GetHash()), /*merkle_size=*/1, /*nonce=*/0));
    BOOST_CHECK(!auxpow::Validate(internal_order, consensus, /*check_pow=*/false));
    BOOST_CHECK(!auxpow::Validate(internal_order, consensus, /*check_pow=*/false, auxpow::CommitmentValidation::INTERNAL));
    const auto internal_as_display = auxpow::Validate(internal_order, consensus, /*check_pow=*/false, auxpow::CommitmentValidation::DISPLAY);
    BOOST_REQUIRE(internal_as_display.has_value());
    BOOST_CHECK_EQUAL(internal_as_display->reject_reason, "bad-auxpow-commitment");
}

BOOST_AUTO_TEST_CASE(auxpow_commitment_validation_height_helper)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    consensus.nAuxpowDisplayCommitmentHeight = 20'500;

    BOOST_CHECK(auxpow::CommitmentValidationForHeight(consensus, 20'499) == auxpow::CommitmentValidation::INTERNAL);
    BOOST_CHECK(auxpow::CommitmentValidationForHeight(consensus, 20'500) == auxpow::CommitmentValidation::DISPLAY);
    BOOST_CHECK(auxpow::CommitmentValidationForHeight(consensus, 20'501) == auxpow::CommitmentValidation::DISPLAY);
}

BOOST_AUTO_TEST_CASE(auxpow_rejects_commitment_shape_failures)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const auto expect_reject = [&](const CBlockHeader& header, const char* reason) {
        const auto err = auxpow::Validate(header, consensus, /*check_pow=*/false);
        BOOST_REQUIRE(err.has_value());
        BOOST_CHECK_EQUAL(err->reject_reason, reason);
    };

    CBlockHeader missing_root = MakeAuxpowHeader(consensus);
    std::vector<unsigned char> header_only{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    const auto footer = SerializeCommitmentFooter(/*merkle_size=*/1, /*nonce=*/0);
    header_only.insert(header_only.end(), footer.begin(), footer.end());
    missing_root.auxpow = WithCoinbaseScriptSig(*missing_root.auxpow, header_only);
    expect_reject(missing_root, "bad-auxpow-commitment");

    CBlockHeader separated_root = MakeAuxpowHeader(consensus);
    std::vector<unsigned char> separated_prefix{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    separated_prefix.push_back(0x00);
    separated_root.auxpow = WithCoinbaseScriptSig(*separated_root.auxpow,
                                                  MakeCommitment(std::move(separated_prefix), separated_root.GetHash(), /*merkle_size=*/1, /*nonce=*/0));
    expect_reject(separated_root, "bad-auxpow-commitment");

    CBlockHeader legacy_offset = MakeAuxpowHeader(consensus);
    std::vector<unsigned char> deep_prefix(auxpow::LEGACY_COMMITMENT_START_LIMIT + 1, 0x00);
    legacy_offset.auxpow = WithCoinbaseScriptSig(*legacy_offset.auxpow,
                                                 MakeCommitment(std::move(deep_prefix), legacy_offset.GetHash(), /*merkle_size=*/1, /*nonce=*/0));
    expect_reject(legacy_offset, "bad-auxpow-commitment");

    CBlockHeader missing_footer = MakeAuxpowHeader(consensus);
    std::vector<unsigned char> no_footer{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    const auto missing_footer_hash = AuxpowCommitmentRootBytes(missing_footer.GetHash());
    no_footer.insert(no_footer.end(), missing_footer_hash.begin(), missing_footer_hash.end());
    missing_footer.auxpow = WithCoinbaseScriptSig(*missing_footer.auxpow, no_footer);
    expect_reject(missing_footer, "bad-auxpow-commitment");

    CBlockHeader wrong_merkle_size = MakeAuxpowHeader(consensus);
    std::vector<unsigned char> size_prefix{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    wrong_merkle_size.auxpow = WithCoinbaseScriptSig(*wrong_merkle_size.auxpow,
                                                     MakeCommitment(std::move(size_prefix), wrong_merkle_size.GetHash(), /*merkle_size=*/2, /*nonce=*/0));
    expect_reject(wrong_merkle_size, "bad-auxpow-merkle-size");

    CBlockHeader wrong_expected_index = MakeAuxpowHeader(consensus);
    auto wrong_expected_index_auxpow = std::make_shared<CAuxPow>(*wrong_expected_index.auxpow);
    wrong_expected_index_auxpow->chain_merkle_branch = {uint256{13}};
    const int32_t expected_index = auxpow::GetExpectedIndex(/*nonce=*/0, consensus.nAuxpowChainId, wrong_expected_index_auxpow->chain_merkle_branch.size());
    wrong_expected_index_auxpow->chain_index = expected_index == 0 ? 1 : 0;
    const uint256 chain_root = auxpow::CheckMerkleBranch(wrong_expected_index.GetHash(),
                                                         wrong_expected_index_auxpow->chain_merkle_branch,
                                                         static_cast<uint32_t>(wrong_expected_index_auxpow->chain_index));
    std::vector<unsigned char> index_prefix{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    wrong_expected_index.auxpow = WithCoinbaseScriptSig(*wrong_expected_index_auxpow,
                                                        MakeCommitment(std::move(index_prefix), chain_root, /*merkle_size=*/2, /*nonce=*/0));
    expect_reject(wrong_expected_index, "bad-auxpow-chain-index");
}

BOOST_AUTO_TEST_CASE(auxpow_disk_block_index_roundtrip_persists_count)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader permissionless_header;
    permissionless_header.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    permissionless_header.hashPrevBlock = uint256{};
    permissionless_header.hashMerkleRoot = uint256{8};
    permissionless_header.nTime = 1'738'713'703;
    permissionless_header.nBits = UintToArith256(consensus.powLimit).GetCompact();

    CBlockHeader auxpow_header = MakeAuxpowHeader(consensus);

    CBlockIndex parent{permissionless_header};
    const uint256 parent_hash{auxpow_header.hashPrevBlock};
    parent.phashBlock = &parent_hash;
    parent.nHeight = 0;
    parent.nAuxPow = 0;

    CBlockIndex child{auxpow_header};
    const uint256 child_hash{auxpow_header.GetHash()};
    child.phashBlock = &child_hash;
    child.pprev = &parent;
    child.nHeight = 1;
    child.nAuxPow = 1;

    CDiskBlockIndex disk_index{&child};
    DataStream stream;
    stream << disk_index;

    CDiskBlockIndex decoded;
    stream >> decoded;

    BOOST_CHECK_EQUAL(decoded.nAuxPow, 1U);
    BOOST_CHECK_EQUAL(decoded.nHeight, 1);
    BOOST_CHECK_EQUAL(decoded.nVersion, auxpow_header.nVersion);
    BOOST_REQUIRE(decoded.auxpow);
    BOOST_CHECK_EQUAL(decoded.auxpow->GetParentBlockHash(), auxpow_header.auxpow->GetParentBlockHash());

    DataStream header_stream;
    BOOST_CHECK_NO_THROW(header_stream << child.GetBlockHeader());

    CBlockHeader decoded_header;
    header_stream >> decoded_header;

    BOOST_REQUIRE(decoded_header.HasAuxpow());
    BOOST_CHECK_EQUAL(decoded_header.GetHash(), child.GetBlockHash());
    BOOST_CHECK_EQUAL(decoded_header.auxpow->GetParentBlockHash(), auxpow_header.auxpow->GetParentBlockHash());
}

BOOST_AUTO_TEST_CASE(permissionless_disk_block_index_roundtrip_omits_auxpow_payload)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader permissionless_header;
    permissionless_header.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    permissionless_header.hashPrevBlock = uint256{};
    permissionless_header.hashMerkleRoot = uint256{12};
    permissionless_header.nTime = 1'738'713'705;
    permissionless_header.nBits = UintToArith256(consensus.powLimit).GetCompact();

    CBlockIndex block_index{permissionless_header};
    const uint256 block_hash{permissionless_header.GetHash()};
    block_index.phashBlock = &block_hash;
    block_index.nHeight = 0;
    block_index.nAuxPow = 0;

    CDiskBlockIndex disk_index{&block_index};
    DataStream stream;
    BOOST_CHECK_NO_THROW(stream << disk_index);

    CDiskBlockIndex decoded;
    BOOST_CHECK_NO_THROW(stream >> decoded);

    BOOST_CHECK(decoded.IsPermissionless());
    BOOST_CHECK_EQUAL(decoded.nAuxPow, 0U);
    BOOST_CHECK(!decoded.auxpow);
    BOOST_CHECK_EQUAL(decoded.ConstructBlockHash(), block_hash);
}

BOOST_AUTO_TEST_CASE(auxpow_disk_block_index_reload_preserves_payload)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    CBlockHeader header = MakeAuxpowHeader(consensus);
    header.hashPrevBlock.SetNull();
    header.auxpow = MakeAuxpowPayload(header.GetHash(), consensus, header.nBits, header.nTime);

    const uint256 hash{header.GetHash()};
    BOOST_CHECK(!auxpow::Validate(header, consensus));

    CBlockIndex block_index{header};
    block_index.phashBlock = &hash;
    block_index.nHeight = 0;
    block_index.nAuxPow = 1;

    kernel::BlockTreeDB block_tree(DBParams{
        .path = "",
        .cache_bytes = 1 << 20,
        .memory_only = true,
    });
    BOOST_REQUIRE(block_tree.WriteBatchSync({}, /*nLastFile=*/0, {&block_index}));

    node::BlockMap loaded;
    const auto insert_block_index = [&](const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        if (block_hash.IsNull()) return static_cast<CBlockIndex*>(nullptr);
        const auto [it, inserted] = loaded.try_emplace(block_hash);
        if (inserted) {
            it->second.phashBlock = &it->first;
        }
        return &it->second;
    };

    const bool loaded_ok = WITH_LOCK(::cs_main, return block_tree.LoadBlockIndexGuts(consensus, insert_block_index, m_interrupt));
    BOOST_CHECK(loaded_ok);

    const auto it = loaded.find(hash);
    BOOST_REQUIRE(it != loaded.end());
    BOOST_CHECK_EQUAL(it->second.nAuxPow, 1U);
    BOOST_CHECK(it->second.SignalsAuxpow());
    BOOST_REQUIRE(it->second.auxpow);

    DataStream header_stream;
    BOOST_CHECK_NO_THROW(header_stream << it->second.GetBlockHeader());

    CBlockHeader decoded_header;
    header_stream >> decoded_header;

    BOOST_REQUIRE(decoded_header.HasAuxpow());
    BOOST_CHECK_EQUAL(decoded_header.GetHash(), hash);
    BOOST_CHECK_EQUAL(decoded_header.auxpow->GetParentBlockHash(), header.auxpow->GetParentBlockHash());
}

BOOST_AUTO_TEST_CASE(auxpow_legacy_disk_block_index_entry_without_payload_still_deserializes)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader header;
    header.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256{11};
    header.nTime = 1'738'713'704;
    header.nBits = Params().GenesisBlock().nBits;
    header.nNonce = 0;
    while (CheckProofOfWork(header.GetHash(), header.nBits, consensus)) {
        ++header.nNonce;
    }

    CBlockIndex block_index{header};
    block_index.nHeight = 0;
    block_index.nAuxPow = 1;

    const int height = block_index.nHeight;
    const uint32_t status = 0;
    const unsigned int tx_count = 0;
    const uint64_t auxpow_count = block_index.nAuxPow;

    DataStream stream;
    int version = CBlockIndex::DUMMY_VERSION;
    stream << VARINT_MODE(version, VarIntMode::NONNEGATIVE_SIGNED);
    stream << VARINT_MODE(height, VarIntMode::NONNEGATIVE_SIGNED);
    stream << VARINT(status);
    stream << VARINT(tx_count);
    stream << VARINT(auxpow_count);
    stream << block_index.nVersion;
    stream << header.hashPrevBlock;
    stream << block_index.hashMerkleRoot;
    stream << block_index.nTime;
    stream << block_index.nBits;
    stream << block_index.nNonce;

    CDiskBlockIndex decoded;
    stream >> decoded;

    BOOST_CHECK_EQUAL(decoded.nAuxPow, 1U);
    BOOST_CHECK(decoded.SignalsAuxpow());
    BOOST_CHECK(!decoded.auxpow);
}

BOOST_AUTO_TEST_CASE(auxpow_legacy_block_index_load_recovers_payload_from_block_data)
{
    const auto& params = Params();
    const auto& consensus = params.GetConsensus();

    node::KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = params,
        .use_xor = false,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = "",
            .cache_bytes = 1 << 20,
            .memory_only = true,
        },
    };
    node::BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    CBlock block;
    block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    block.hashPrevBlock.SetNull();
    block.nTime = 1'738'713'707;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce = 0;
    block.vtx = {MakeParentCoinbase({0x51})};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.auxpow = MakeAuxpowPayload(block.GetHash(), consensus, block.nBits, block.nTime);
    BOOST_REQUIRE(!auxpow::Validate(block, consensus));

    const uint256 block_hash{block.GetHash()};
    const FlatFilePos block_pos{blockman.WriteBlock(block, /*nHeight=*/0)};
    BOOST_REQUIRE(!block_pos.IsNull());

    const LegacyDiskBlockIndexWithoutAuxpowPayload legacy_index{
        .height = 0,
        .status = BLOCK_VALID_TREE | BLOCK_HAVE_DATA,
        .tx_count = static_cast<unsigned int>(block.vtx.size()),
        .auxpow_count = 1,
        .file = block_pos.nFile,
        .data_pos = block_pos.nPos,
        .version = block.nVersion,
        .prev_hash = block.hashPrevBlock,
        .merkle_root = block.hashMerkleRoot,
        .time = block.nTime,
        .bits = block.nBits,
        .nonce = block.nNonce,
    };

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(blockman.m_block_tree_db->WriteBatchSync(
            {{block_pos.nFile, blockman.GetBlockFileInfo(block_pos.nFile)}},
            /*nLastFile=*/block_pos.nFile,
            {}));
        BOOST_REQUIRE(blockman.m_block_tree_db->Write(std::make_pair(DB_BLOCK_INDEX_LEGACY_TEST_KEY, block_hash), legacy_index));
        BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt) == node::BlockIndexLoadResult::SUCCESS);
        CBlockIndex* loaded_index{blockman.LookupBlockIndex(block_hash)};
        BOOST_REQUIRE(loaded_index);
        BOOST_REQUIRE(loaded_index->auxpow);
        BOOST_CHECK_EQUAL(loaded_index->auxpow->GetParentBlockHash(), block.auxpow->GetParentBlockHash());
        BOOST_REQUIRE(blockman.WriteBlockIndexDB());

        CDiskBlockIndex persisted;
        BOOST_REQUIRE(blockman.m_block_tree_db->Read(std::make_pair(DB_BLOCK_INDEX_LEGACY_TEST_KEY, block_hash), persisted));
        BOOST_REQUIRE(persisted.auxpow);
        BOOST_CHECK_EQUAL(persisted.auxpow->GetParentBlockHash(), block.auxpow->GetParentBlockHash());
    }
}

BOOST_AUTO_TEST_CASE(auxpow_legacy_pruned_block_index_load_requests_reindex)
{
    const auto& params = Params();
    const auto& consensus = params.GetConsensus();

    node::KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = params,
        .use_xor = false,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = "",
            .cache_bytes = 1 << 20,
            .memory_only = true,
        },
    };
    node::BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    CBlockHeader header;
    header.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256{12};
    header.nTime = 1'738'713'708;
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    header.nNonce = 0;

    const uint256 block_hash{header.GetHash()};
    const LegacyDiskBlockIndexWithoutAuxpowPayload legacy_index{
        .height = 0,
        .status = BLOCK_VALID_TREE,
        .tx_count = 1,
        .auxpow_count = 1,
        .file = 0,
        .data_pos = 0,
        .version = header.nVersion,
        .prev_hash = header.hashPrevBlock,
        .merkle_root = header.hashMerkleRoot,
        .time = header.nTime,
        .bits = header.nBits,
        .nonce = header.nNonce,
    };

    {
        LOCK(::cs_main);
        BOOST_REQUIRE(blockman.m_block_tree_db->Write(std::make_pair(DB_BLOCK_INDEX_LEGACY_TEST_KEY, block_hash), legacy_index));
        BOOST_CHECK(blockman.LoadBlockIndexDB(std::nullopt) == node::BlockIndexLoadResult::LEGACY_AUXPOW_REQUIRES_REINDEX);
    }
}

BOOST_AUTO_TEST_CASE(pre_dummy_disk_block_index_entry_defaults_auxpow_count_to_zero)
{
    CBlockHeader header;
    header.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256{17};
    header.nTime = 1'738'713'706;
    header.nBits = Params().GenesisBlock().nBits;
    header.nNonce = 0;

    CBlockIndex block_index{header};
    block_index.nHeight = 0;

    const int height = block_index.nHeight;
    const uint32_t status = 0;
    const unsigned int tx_count = 0;

    DataStream stream;
    int version = CBlockIndex::DUMMY_VERSION - 1;
    stream << VARINT_MODE(version, VarIntMode::NONNEGATIVE_SIGNED);
    stream << VARINT_MODE(height, VarIntMode::NONNEGATIVE_SIGNED);
    stream << VARINT(status);
    stream << VARINT(tx_count);
    stream << block_index.nVersion;
    stream << header.hashPrevBlock;
    stream << block_index.hashMerkleRoot;
    stream << block_index.nTime;
    stream << block_index.nBits;
    stream << block_index.nNonce;

    CDiskBlockIndex decoded;
    stream >> decoded;

    BOOST_CHECK_EQUAL(decoded.nAuxPow, 0U);
    BOOST_CHECK(!decoded.auxpow);
}

BOOST_AUTO_TEST_CASE(auxpow_payload_disk_block_index_entry_without_optional_flag_still_deserializes)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    CBlockHeader header = MakeAuxpowHeader(consensus);

    CBlockIndex block_index{header};
    block_index.nHeight = 0;
    block_index.nAuxPow = 1;

    const int height = block_index.nHeight;
    const uint32_t status = 0;
    const unsigned int tx_count = 0;
    const uint64_t auxpow_count = block_index.nAuxPow;

    DataStream stream;
    int version = CBlockIndex::AUXPOW_PAYLOAD_VERSION;
    stream << VARINT_MODE(version, VarIntMode::NONNEGATIVE_SIGNED);
    stream << VARINT_MODE(height, VarIntMode::NONNEGATIVE_SIGNED);
    stream << VARINT(status);
    stream << VARINT(tx_count);
    stream << VARINT(auxpow_count);
    stream << block_index.auxpow;
    stream << block_index.nVersion;
    stream << header.hashPrevBlock;
    stream << block_index.hashMerkleRoot;
    stream << block_index.nTime;
    stream << block_index.nBits;
    stream << block_index.nNonce;

    CDiskBlockIndex decoded;
    stream >> decoded;

    BOOST_CHECK_EQUAL(decoded.nAuxPow, 1U);
    BOOST_REQUIRE(decoded.auxpow);
    BOOST_CHECK_EQUAL(decoded.auxpow->GetParentBlockHash(), block_index.auxpow->GetParentBlockHash());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(auxpow_tests_validation, AuxpowRegTestingSetup)

BOOST_AUTO_TEST_CASE(auxpow_header_reject_reason_and_index_accounting)
{
    bool new_block{false};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(std::make_shared<CBlock>(Params().GenesisBlock()), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));

    auto missing_payload_block = CreateBlockTemplate();
    missing_payload_block->nVersion = MakeVersion(static_cast<uint16_t>(Params().GetConsensus().nAuxpowChainId), /*auxpow=*/true, missing_payload_block->GetVersionBits());
    FinalizeBlock(*missing_payload_block);

    BlockValidationState state;
    const CBlockIndex* pindex{nullptr};
    BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders({{missing_payload_block->GetBlockHeader()}}, /*min_pow_checked=*/true, state, &pindex));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-auxpow-missing-payload");

    auto auxpow_block = CreateBlockTemplate();
    auxpow_block->nVersion = MakeVersion(static_cast<uint16_t>(Params().GetConsensus().nAuxpowChainId), /*auxpow=*/true, auxpow_block->GetVersionBits());
    FinalizeBlock(*auxpow_block);
    auxpow_block->auxpow = MakeAuxpowPayload(auxpow_block->GetHash(), Params().GetConsensus(), auxpow_block->nBits, auxpow_block->nTime);

    state = BlockValidationState{};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlockHeaders({{auxpow_block->GetBlockHeader()}}, /*min_pow_checked=*/true, state, &pindex));
    BOOST_REQUIRE(pindex != nullptr);
    BOOST_CHECK_EQUAL(pindex->nAuxPow, 1U);

    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(auxpow_block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    const CBlockIndex* tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip != nullptr);
    BOOST_CHECK_EQUAL(tip->nAuxPow, 1U);
}

BOOST_AUTO_TEST_CASE(has_valid_proof_of_work_rejects_bad_permissionless_headers)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chain_params->GetConsensus();

    const CBlockHeader good_header = chain_params->GenesisBlock().GetBlockHeader();

    CBlockHeader bad_header;
    bad_header.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    bad_header.hashPrevBlock = uint256{19};
    bad_header.hashMerkleRoot = uint256{20};
    bad_header.nTime = good_header.nTime;
    bad_header.nBits = good_header.nBits;
    bad_header.nNonce = 0;
    BOOST_REQUIRE(!CheckProofOfWork(bad_header.GetHash(), bad_header.nBits, consensus));

    BOOST_CHECK(HasValidProofOfWork({good_header}, consensus));
    BOOST_CHECK(!HasValidProofOfWork({good_header, bad_header}, consensus));
}

BOOST_AUTO_TEST_SUITE_END()
