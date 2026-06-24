// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <core_io.h>
#include <pow.h>
#include <primitives/pureheader.h>
#include <test/data/mainnet_launch_difficulty.json.h>
#include <test/data/testnet4_launch_difficulty.json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

namespace {
struct Rational {
    arith_uint256 num;
    arith_uint256 den;
};

Rational ParseDecimal(std::string_view value)
{
    arith_uint256 num{0};
    arith_uint256 den{1};
    bool seen_decimal{false};

    if (value.empty()) throw std::runtime_error{"empty decimal"};

    for (const char c : value) {
        if (c == '.') {
            if (seen_decimal) throw std::runtime_error{"duplicate decimal point"};
            seen_decimal = true;
            continue;
        }
        if (c < '0' || c > '9') throw std::runtime_error{"invalid decimal digit"};
        num *= 10;
        num += static_cast<uint64_t>(c - '0');
        if (seen_decimal) den *= 10;
    }

    return {num, den};
}

Rational FromInt(const uint64_t value)
{
    return {value, 1};
}

Rational Add(const Rational& a, const Rational& b)
{
    return {(a.num * b.den) + (b.num * a.den), a.den * b.den};
}

Rational Mul(const Rational& a, const Rational& b)
{
    return {a.num * b.num, a.den * b.den};
}

Rational Div(const Rational& a, const Rational& b)
{
    if (b.num == 0) throw std::runtime_error{"division by zero"};
    return {a.num * b.den, a.den * b.num};
}

Rational Pow10(const unsigned int exponent)
{
    arith_uint256 value{1};
    for (unsigned int i{0}; i < exponent; ++i) {
        value *= 10;
    }
    return {value, 1};
}

const UniValue& RequiredObject(const UniValue& obj, std::string_view key)
{
    const UniValue& value = obj.find_value(std::string{key});
    if (!value.isObject()) throw std::runtime_error{"missing object"};
    return value.get_obj();
}

std::string RequiredString(const UniValue& obj, std::string_view key)
{
    const UniValue& value = obj.find_value(std::string{key});
    if (!value.isStr()) throw std::runtime_error{"missing string"};
    return value.get_str();
}

uint32_t ParseUint32(const std::string& value)
{
    uint64_t parsed{0};
    if (value.empty()) throw std::runtime_error{"empty uint32"};
    for (const char c : value) {
        if (c < '0' || c > '9') throw std::runtime_error{"invalid uint32 digit"};
        parsed *= 10;
        parsed += static_cast<uint64_t>(c - '0');
        if (parsed > std::numeric_limits<uint32_t>::max()) throw std::runtime_error{"uint32 overflow"};
    }
    return static_cast<uint32_t>(parsed);
}

uint32_t ParseBits(const std::string& bits)
{
    std::string_view view{bits};
    if (view.starts_with("0x") || view.starts_with("0X")) {
        view.remove_prefix(2);
    }
    if (view.empty() || view.size() > 8) throw std::runtime_error{"invalid compact bits"};

    uint32_t parsed{0};
    for (const char c : view) {
        parsed <<= 4;
        if (c >= '0' && c <= '9') {
            parsed += static_cast<uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            parsed += static_cast<uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            parsed += static_cast<uint32_t>(c - 'A' + 10);
        } else {
            throw std::runtime_error{"invalid compact bits"};
        }
    }
    return parsed;
}

arith_uint256 MulDivFloor(const arith_uint256& value, const arith_uint256& multiplier, const arith_uint256& divisor)
{
    if (divisor == 0) throw std::runtime_error{"division by zero"};

    const arith_uint256 quotient = value / divisor;
    const arith_uint256 remainder = value - (quotient * divisor);
    return (quotient * multiplier) + ((remainder * multiplier) / divisor);
}

uint32_t DifficultyToBits(const Rational& difficulty, const uint32_t pow_limit_bits)
{
    if (difficulty.num <= 0 || difficulty.den <= 0) throw std::runtime_error{"invalid difficulty"};

    const arith_uint256 diff1_target = arith_uint256{0xffff} << (8 * (0x1d - 3));
    arith_uint256 target = MulDivFloor(diff1_target, difficulty.den, difficulty.num);

    bool neg;
    bool over;
    arith_uint256 pow_limit_target;
    pow_limit_target.SetCompact(pow_limit_bits, &neg, &over);
    if (neg || over || pow_limit_target == 0) throw std::runtime_error{"invalid pow limit"};
    if (target > pow_limit_target) target = pow_limit_target;

    return target.GetCompact();
}

uint32_t CalculateHashrateTargetBits(const UniValue& lane, const uint32_t pow_limit_bits)
{
    const Rational hashrate_th_s = ParseDecimal(RequiredString(lane, "hashrate_th_s"));
    const Rational target_spacing = ParseDecimal(RequiredString(lane, "target_spacing_sec"));
    const Rational expected_hashes = Mul(Mul(hashrate_th_s, Pow10(12)), target_spacing);
    const Rational difficulty = Div(expected_hashes, FromInt(uint64_t{1} << 32));

    return DifficultyToBits(difficulty, pow_limit_bits);
}

uint32_t CalculatePermissionlessLaunchBits(const UniValue& config)
{
    const UniValue& lane = RequiredObject(config, "permissionless");
    const std::string model = RequiredString(lane, "model");
    const uint32_t pow_limit_bits = ParseBits(RequiredString(config, "pow_limit_bits"));
    if (model == "hashrate_target") {
        return CalculateHashrateTargetBits(lane, pow_limit_bits);
    }
    if (model == "fixed_bits") {
        return ParseBits(RequiredString(lane, "bits"));
    }
    if (model != "fdv_hashprice") {
        throw std::runtime_error{"unexpected permissionless model"};
    }

    const Rational fdv = ParseDecimal(RequiredString(lane, "fdv_usd"));
    const Rational total_supply = ParseDecimal(RequiredString(lane, "total_supply_qbt"));
    const Rational subsidy = ParseDecimal(RequiredString(lane, "subsidy_qbt"));
    const Rational fees = ParseDecimal(RequiredString(lane, "expected_fees_qbt"));
    const Rational hashprice = ParseDecimal(RequiredString(lane, "hashprice_usd_per_ph_day"));

    const Rational block_value = Mul(Div(fdv, total_supply), Add(subsidy, fees));
    const Rational hashes_per_ph_day = Mul(Pow10(15), FromInt(86400));
    const Rational hashprice_per_hash = Div(hashprice, hashes_per_ph_day);
    const Rational difficulty = Div(block_value, Mul(hashprice_per_hash, FromInt(uint64_t{1} << 32)));

    return DifficultyToBits(difficulty, pow_limit_bits);
}

uint32_t CalculateAuxPowLaunchBits(const UniValue& config)
{
    const UniValue& lane = RequiredObject(config, "auxpow");
    const std::string model = RequiredString(lane, "model");
    const uint32_t pow_limit_bits = ParseBits(RequiredString(config, "pow_limit_bits"));
    if (model == "hashrate_target") {
        return CalculateHashrateTargetBits(lane, pow_limit_bits);
    }
    if (model == "fixed_bits") {
        return ParseBits(RequiredString(lane, "bits"));
    }
    if (model != "bitcoin_hashrate_share") {
        throw std::runtime_error{"unexpected auxpow model"};
    }

    const Rational bitcoin_hashrate_eh_s = ParseDecimal(RequiredString(lane, "bitcoin_global_hashrate_eh_s"));
    const Rational hashrate_share = ParseDecimal(RequiredString(lane, "hashrate_share"));
    const Rational target_spacing = ParseDecimal(RequiredString(lane, "target_spacing_sec"));

    const Rational hashes_per_second = Mul(Mul(bitcoin_hashrate_eh_s, Pow10(18)), hashrate_share);
    const Rational expected_hashes_per_block = Mul(hashes_per_second, target_spacing);
    const Rational difficulty = Div(expected_hashes_per_block, FromInt(uint64_t{1} << 32));

    return DifficultyToBits(difficulty, pow_limit_bits);
}

uint32_t CalculateGenesisLaunchBits(const UniValue& config)
{
    const UniValue& genesis = RequiredObject(config, "genesis");
    const uint32_t pow_limit_bits = ParseBits(RequiredString(config, "pow_limit_bits"));
    const std::string model = RequiredString(genesis, "model");
    if (model == "hashrate_target") {
        return CalculateHashrateTargetBits(genesis, pow_limit_bits);
    }
    if (model == "fixed_bits") {
        return ParseBits(RequiredString(genesis, "bits"));
    }
    throw std::runtime_error{"unexpected genesis model"};
}

UniValue ReadLaunchDifficultyConfig(std::string_view json)
{
    UniValue config;
    if (!config.read(json) || !config.isObject()) {
        throw std::runtime_error{"invalid launch difficulty config"};
    }
    return config;
}

UniValue ReadMainnetLaunchDifficultyConfig()
{
    return ReadLaunchDifficultyConfig(json_tests::mainnet_launch_difficulty);
}

UniValue ReadTestnet4LaunchDifficultyConfig()
{
    return ReadLaunchDifficultyConfig(json_tests::testnet4_launch_difficulty);
}

uint32_t LegacyAnchorBits(const Consensus::Params& consensus)
{
    return consensus.asertAnchorParams.nBitsLegacy != 0 ? consensus.asertAnchorParams.nBitsLegacy
                                                        : consensus.asertAnchorParams.nBits;
}

int64_t LegacyTargetSpacing(const Consensus::Params& consensus)
{
    return consensus.nPowTargetSpacingLegacy > 0 ? consensus.nPowTargetSpacingLegacy
                                                 : consensus.nPowTargetSpacing;
}
} // namespace

BOOST_AUTO_TEST_CASE(get_next_work_asert_on_target)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chain_params->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    const uint32_t anchor_bits = LegacyAnchorBits(consensus);
    const int64_t target_spacing = LegacyTargetSpacing(consensus);

    CBlockIndex pindex_last;
    pindex_last.nHeight = consensus.asertAnchorParams.nHeight;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime;
    pindex_last.nBits = anchor_bits;

    CBlockHeader next_block{};
    next_block.nTime = pindex_last.nTime + target_spacing;

    const unsigned int next_bits = GetNextWorkRequired(&pindex_last, &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, anchor_bits);
}

BOOST_AUTO_TEST_CASE(get_next_work_asert_pow_limit)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus = chain_params->GetConsensus();
    BOOST_REQUIRE(!consensus.fPowAllowMinDifficultyBlocks);
    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;
    const int64_t target_spacing = LegacyTargetSpacing(consensus);

    CBlockIndex pindex_last;
    pindex_last.nHeight = consensus.asertAnchorParams.nHeight + 100;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime + (100 * target_spacing) + (100 * consensus.nASERTHalfLife);
    pindex_last.nBits = LegacyAnchorBits(consensus);

    CBlockHeader next_block{};
    next_block.nTime = pindex_last.nTime + (target_spacing * 3);

    const unsigned int next_bits = GetNextWorkRequired(&pindex_last, &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, UintToArith256(consensus.powLimit).GetCompact());
}

BOOST_AUTO_TEST_CASE(get_next_work_asert_lower_limit_actual)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chain_params->GetConsensus();
    const uint32_t anchor_bits = LegacyAnchorBits(consensus);
    const int64_t target_spacing = LegacyTargetSpacing(consensus);

    CBlockIndex pindex_on_schedule;
    pindex_on_schedule.nHeight = consensus.asertAnchorParams.nHeight + 120;
    pindex_on_schedule.nTime = consensus.asertAnchorParams.nBlockTime + (120 * target_spacing);
    pindex_on_schedule.nBits = anchor_bits;

    CBlockIndex pindex_fast;
    pindex_fast.nHeight = pindex_on_schedule.nHeight;
    pindex_fast.nTime = pindex_on_schedule.nTime;
    pindex_fast.nBits = pindex_on_schedule.nBits;
    pindex_fast.nTime -= 7200;

    CBlockHeader next_on_schedule{};
    next_on_schedule.nTime = pindex_on_schedule.nTime + target_spacing;
    CBlockHeader next_fast{};
    next_fast.nTime = pindex_fast.nTime + target_spacing;

    const auto target_on_schedule = DeriveTarget(GetNextWorkRequired(&pindex_on_schedule, &next_on_schedule, consensus), consensus.powLimit);
    const auto target_fast = DeriveTarget(GetNextWorkRequired(&pindex_fast, &next_fast, consensus), consensus.powLimit);
    BOOST_REQUIRE(target_on_schedule.has_value());
    BOOST_REQUIRE(target_fast.has_value());
    BOOST_CHECK(*target_fast < *target_on_schedule);
}

BOOST_AUTO_TEST_CASE(get_next_work_asert_upper_limit_actual)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus = chain_params->GetConsensus();
    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;
    const int64_t target_spacing = LegacyTargetSpacing(consensus);

    CBlockIndex pindex_on_schedule;
    pindex_on_schedule.nHeight = consensus.asertAnchorParams.nHeight + 120;
    pindex_on_schedule.nTime = consensus.asertAnchorParams.nBlockTime + (120 * target_spacing);
    pindex_on_schedule.nBits = LegacyAnchorBits(consensus);

    CBlockIndex pindex_slow;
    pindex_slow.nHeight = pindex_on_schedule.nHeight;
    pindex_slow.nTime = pindex_on_schedule.nTime;
    pindex_slow.nBits = pindex_on_schedule.nBits;
    pindex_slow.nTime += consensus.nASERTHalfLife;

    CBlockHeader next_on_schedule{};
    next_on_schedule.nTime = pindex_on_schedule.nTime + target_spacing;
    CBlockHeader next_slow{};
    next_slow.nTime = pindex_slow.nTime + target_spacing;

    const auto target_on_schedule = DeriveTarget(GetNextWorkRequired(&pindex_on_schedule, &next_on_schedule, consensus), consensus.powLimit);
    const auto target_slow = DeriveTarget(GetNextWorkRequired(&pindex_slow, &next_slow, consensus), consensus.powLimit);
    BOOST_REQUIRE(target_on_schedule.has_value());
    BOOST_REQUIRE(target_slow.has_value());
    BOOST_CHECK(*target_slow > *target_on_schedule);
}

BOOST_AUTO_TEST_CASE(get_next_work_asert_null_pblock_regression)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const auto& consensus = chain_params->GetConsensus();
    const int64_t target_spacing = LegacyTargetSpacing(consensus);
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    CBlockIndex pindex_last;
    pindex_last.nHeight = consensus.asertAnchorParams.nHeight + 50;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime + (50 * target_spacing);
    pindex_last.nBits = LegacyAnchorBits(consensus);

    const unsigned int null_header_bits = GetNextWorkRequired(&pindex_last, nullptr, consensus);

    CBlockHeader on_time_block{};
    on_time_block.nTime = pindex_last.nTime + target_spacing;
    const unsigned int on_time_bits = GetNextWorkRequired(&pindex_last, &on_time_block, consensus);

    BOOST_CHECK_EQUAL(null_header_bits, on_time_bits);
}

BOOST_AUTO_TEST_CASE(get_next_work_legacy_null_pblock_regression)
{
    ArgsManager legacy_args;
    legacy_args.ForceSetArg("-legacyretarget", "1");
    const auto consensus = CreateChainParams(legacy_args, ChainType::REGTEST)->GetConsensus();
    BOOST_REQUIRE(!consensus.fPowUseASERT);
    BOOST_REQUIRE(!consensus.fPowNoRetargeting);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    CBlockIndex pindex_last;
    pindex_last.nHeight = 1;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacing;
    pindex_last.nBits = UintToArith256(consensus.powLimit).GetCompact();

    const unsigned int null_header_bits = GetNextWorkRequired(&pindex_last, nullptr, consensus);
    BOOST_CHECK_EQUAL(null_header_bits, pindex_last.nBits);
}

BOOST_AUTO_TEST_CASE(get_next_work_legacy_retarget_clamps_powlimit_regression)
{
    ArgsManager legacy_args;
    legacy_args.ForceSetArg("-legacyretarget", "1");
    const auto consensus = CreateChainParams(legacy_args, ChainType::REGTEST)->GetConsensus();
    BOOST_REQUIRE(!consensus.fPowUseASERT);
    BOOST_REQUIRE(!consensus.fPowNoRetargeting);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    const int interval = consensus.DifficultyAdjustmentInterval();
    BOOST_REQUIRE(interval > 1);

    std::vector<CBlockIndex> chain(interval);
    const uint32_t pow_limit_nbits = UintToArith256(consensus.powLimit).GetCompact();
    const int64_t first_time = 1'000'000;
    const int64_t extreme_gap = consensus.nPowTargetTimespan * 100;

    for (int i = 0; i < interval; ++i) {
        chain[i].nHeight = i;
        chain[i].nBits = pow_limit_nbits;
        chain[i].nTime = (i == interval - 1) ? first_time + extreme_gap : first_time + i * consensus.nPowTargetSpacing;
        chain[i].pprev = (i > 0) ? &chain[i - 1] : nullptr;
        chain[i].BuildSkip();
    }

    CBlockHeader next_block{};
    next_block.nTime = chain.back().nTime + consensus.nPowTargetSpacing;
    const unsigned int next_bits = GetNextWorkRequired(&chain.back(), &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, pow_limit_nbits);
}

BOOST_AUTO_TEST_CASE(get_next_work_legacy_min_difficulty_uses_track_timeout)
{
    ArgsManager legacy_args;
    legacy_args.ForceSetArg("-legacyretarget", "1");
    const auto consensus = CreateChainParams(legacy_args, ChainType::REGTEST)->GetConsensus();
    BOOST_REQUIRE(!consensus.fPowUseASERT);
    BOOST_REQUIRE(!consensus.fPowNoRetargeting);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    CBlockIndex pindex_last;
    pindex_last.nHeight = 1;
    pindex_last.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy;
    pindex_last.nBits = 0x1f00ffff;

    CBlockHeader next_block{};
    next_block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    next_block.nTime = pindex_last.nTime + (consensus.nPowTargetSpacing * 2) + 1;

    BOOST_REQUIRE(next_block.nTime < pindex_last.nTime + (consensus.nPowTargetSpacingAuxPow * 2));
    const unsigned int next_bits = GetNextWorkRequired(&pindex_last, &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, pindex_last.nBits);
    BOOST_CHECK_NE(next_bits, UintToArith256(consensus.powLimit).GetCompact());
}

BOOST_AUTO_TEST_CASE(get_next_work_legacy_pre_activation_uses_base_timeout)
{
    ArgsManager legacy_args;
    legacy_args.ForceSetArg("-legacyretarget", "1");
    auto consensus = CreateChainParams(legacy_args, ChainType::REGTEST)->GetConsensus();
    BOOST_REQUIRE(!consensus.fPowUseASERT);
    BOOST_REQUIRE(!consensus.fPowNoRetargeting);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);
    consensus.nCadenceActivationHeight = 100;

    CBlockIndex pindex_last;
    pindex_last.nHeight = 1;
    pindex_last.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacing;
    pindex_last.nBits = 0x1f00ffff;

    CBlockHeader next_block{};
    next_block.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    next_block.nTime = pindex_last.nTime + (consensus.nPowTargetSpacing * 2) + 1;

    BOOST_REQUIRE(next_block.nTime < pindex_last.nTime + (consensus.nPowTargetSpacingAuxPow * 2));
    const unsigned int next_bits = GetNextWorkRequired(&pindex_last, &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, UintToArith256(consensus.powLimit).GetCompact());
}

BOOST_AUTO_TEST_CASE(get_next_work_asert_falls_back_to_global_spacing_and_anchor_bits)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    consensus.nPowTargetSpacingLegacy = 0;
    consensus.nPowTargetSpacingAuxPow = 0;
    consensus.asertAnchorParams.nBitsLegacy = 0;
    consensus.asertAnchorParams.nBitsAuxPow = 0;

    CBlockIndex pindex_last;
    pindex_last.nHeight = consensus.asertAnchorParams.nHeight;
    pindex_last.nTime = consensus.asertAnchorParams.nBlockTime;
    pindex_last.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    pindex_last.nBits = consensus.asertAnchorParams.nBits;

    CBlockHeader next_block{};
    next_block.nVersion = pindex_last.nVersion;
    next_block.nTime = pindex_last.nTime + consensus.nPowTargetSpacing;

    BOOST_CHECK_EQUAL(GetNextWorkRequired(&pindex_last, &next_block, consensus), consensus.asertAnchorParams.nBits);
}

BOOST_AUTO_TEST_CASE(permitted_transition_pre_cadence_asert_rejects_abrupt_hardening)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    consensus.nCadenceActivationHeight = 200;

    arith_uint256 old_target;
    old_target.SetCompact(LegacyAnchorBits(consensus));
    BOOST_REQUIRE(old_target > arith_uint256(1));

    const arith_uint256 too_hard_target = old_target >> 20;
    const arith_uint256 mild_hardening = old_target - (old_target >> 10);

    BOOST_REQUIRE(too_hard_target > arith_uint256(0));
    BOOST_REQUIRE(DeriveTarget(old_target.GetCompact(), consensus.powLimit).has_value());
    BOOST_REQUIRE(DeriveTarget(too_hard_target.GetCompact(), consensus.powLimit).has_value());
    BOOST_REQUIRE(DeriveTarget(mild_hardening.GetCompact(), consensus.powLimit).has_value());

    BOOST_CHECK(!PermittedDifficultyTransition(consensus,
                                               /*height=*/1,
                                               old_target.GetCompact(),
                                               too_hard_target.GetCompact()));
    BOOST_CHECK(PermittedDifficultyTransition(consensus,
                                              /*height=*/1,
                                              old_target.GetCompact(),
                                              mild_hardening.GetCompact()));
}

BOOST_AUTO_TEST_CASE(permitted_transition_cadence_allows_lane_anchor_jumps_without_context)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::SIGNET)->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.CadenceActiveAtHeight(1));
    BOOST_REQUIRE_NE(consensus.asertAnchorParams.nBitsLegacy, consensus.asertAnchorParams.nBitsAuxPow);

    BOOST_CHECK(PermittedDifficultyTransition(consensus,
                                              /*height=*/1,
                                              /*old_nbits=*/0x1f00ffff,
                                              consensus.asertAnchorParams.nBitsLegacy,
                                              consensus.asertAnchorParams.nBlockTime,
                                              consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy));
    BOOST_CHECK(PermittedDifficultyTransition(consensus,
                                              /*height=*/2,
                                              consensus.asertAnchorParams.nBitsLegacy,
                                              consensus.asertAnchorParams.nBitsAuxPow,
                                              consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                              consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy + consensus.nPowTargetSpacing));
    BOOST_CHECK(!PermittedDifficultyTransition(consensus,
                                               /*height=*/2,
                                               consensus.asertAnchorParams.nBitsLegacy,
                                               /*new_nbits=*/0x207fffff,
                                               consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy,
                                               consensus.asertAnchorParams.nBlockTime + consensus.nPowTargetSpacingLegacy + consensus.nPowTargetSpacing));
}

BOOST_AUTO_TEST_CASE(permitted_transition_pre_cadence_uses_exact_asert)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    consensus.nCadenceActivationHeight = 200;

    const uint32_t old_nbits = LegacyAnchorBits(consensus);
    const int64_t old_block_time = consensus.asertAnchorParams.nBlockTime + (10 * consensus.nPowTargetSpacing);
    const int64_t new_block_time = old_block_time + consensus.nPowTargetSpacing;
    const uint32_t expected_nbits = CalculateASERT(arith_uint256().SetCompact(consensus.asertAnchorParams.nBits),
                                                   consensus.nPowTargetSpacing,
                                                   old_block_time - consensus.asertAnchorParams.nBlockTime,
                                                   /*nHeightDiff=*/10,
                                                   UintToArith256(consensus.powLimit),
                                                   consensus.nASERTHalfLife)
                                       .GetCompact();

    arith_uint256 too_hard_target;
    too_hard_target.SetCompact(expected_nbits);
    too_hard_target >>= 12;
    BOOST_REQUIRE(too_hard_target > arith_uint256(0));
    BOOST_REQUIRE(DeriveTarget(too_hard_target.GetCompact(), consensus.powLimit).has_value());

    BOOST_CHECK(PermittedDifficultyTransition(consensus,
                                              /*height=*/11,
                                              old_nbits,
                                              expected_nbits,
                                              old_block_time,
                                              new_block_time));
    BOOST_CHECK(!PermittedDifficultyTransition(consensus,
                                               /*height=*/11,
                                               old_nbits,
                                               too_hard_target.GetCompact(),
                                               old_block_time,
                                               new_block_time));
}

BOOST_AUTO_TEST_CASE(permitted_transition_pre_cadence_testnet_min_difficulty_timeout)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET)->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);
    consensus.nCadenceActivationHeight = 200;
    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;

    const uint32_t old_nbits = LegacyAnchorBits(consensus);
    const uint32_t pow_limit_nbits = UintToArith256(consensus.powLimit).GetCompact();
    BOOST_REQUIRE(old_nbits != pow_limit_nbits);

    const int64_t old_block_time = consensus.asertAnchorParams.nBlockTime + (10 * consensus.nPowTargetSpacing);
    const int64_t late_block_time = old_block_time + (consensus.nPowTargetSpacing * 2) + 1;

    BOOST_CHECK(PermittedDifficultyTransition(consensus,
                                              /*height=*/11,
                                              old_nbits,
                                              pow_limit_nbits,
                                              old_block_time,
                                              late_block_time));
    BOOST_CHECK(!PermittedDifficultyTransition(consensus,
                                               /*height=*/11,
                                               old_nbits,
                                               old_nbits,
                                               old_block_time,
                                               late_block_time));
}

BOOST_AUTO_TEST_CASE(permitted_transition_asert_testnet_allows_powlimit_recovery)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET)->GetConsensus();
    BOOST_REQUIRE(consensus.fPowUseASERT);
    BOOST_REQUIRE(consensus.fPowAllowMinDifficultyBlocks);

    consensus.asertAnchorParams.nBits = 0x1c00ffff;
    consensus.asertAnchorParams.nBitsLegacy = 0x1c00ffff;

    const uint32_t pow_limit_nbits = UintToArith256(consensus.powLimit).GetCompact();
    const uint32_t asert_nbits = LegacyAnchorBits(consensus);
    BOOST_REQUIRE(pow_limit_nbits != asert_nbits);
    BOOST_REQUIRE(DeriveTarget(asert_nbits, consensus.powLimit).has_value());

    const int64_t old_block_time = consensus.asertAnchorParams.nBlockTime + 100 * consensus.nPowTargetSpacing;
    const int64_t new_block_time = old_block_time + consensus.nPowTargetSpacing;

    BOOST_CHECK(PermittedDifficultyTransition(consensus,
                                              /*height=*/101,
                                              pow_limit_nbits,
                                              asert_nbits,
                                              old_block_time,
                                              new_block_time));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    if (consensus.fPowUseASERT) {
        BOOST_CHECK_GT(consensus.nASERTHalfLife, 0);
        BOOST_CHECK_GE(consensus.asertAnchorParams.nHeight, 0);
        BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBlockTime, chainParams->GenesisBlock().nTime);

        arith_uint256 asert_anchor_compact;
        asert_anchor_compact.SetCompact(consensus.asertAnchorParams.nBits, &neg, &over);
        BOOST_CHECK(!neg && asert_anchor_compact != 0);
        BOOST_CHECK(!over);
        BOOST_CHECK(UintToArith256(consensus.powLimit) >= asert_anchor_compact);

        arith_uint256 legacy_anchor_compact;
        legacy_anchor_compact.SetCompact(consensus.asertAnchorParams.nBitsLegacy, &neg, &over);
        BOOST_CHECK(!neg && legacy_anchor_compact != 0);
        BOOST_CHECK(!over);
        BOOST_CHECK(UintToArith256(consensus.powLimit) >= legacy_anchor_compact);

        arith_uint256 auxpow_anchor_compact;
        auxpow_anchor_compact.SetCompact(consensus.asertAnchorParams.nBitsAuxPow, &neg, &over);
        BOOST_CHECK(!neg && auxpow_anchor_compact != 0);
        BOOST_CHECK(!over);
        BOOST_CHECK(UintToArith256(consensus.powLimit) >= auxpow_anchor_compact);
    }

    const ChainTxData& tx_data{chainParams->TxData()};
    BOOST_CHECK_GT(tx_data.dTxRate, 0.0);
    if (chain_type != ChainType::REGTEST) {
        BOOST_CHECK_EQUAL(tx_data.nTime, chainParams->GenesisBlock().nTime);
        BOOST_CHECK_EQUAL(tx_data.tx_count, 1U);
        BOOST_CHECK_CLOSE(tx_data.dTxRate, 1.0 / static_cast<double>(consensus.nPowTargetSpacing), 1e-12);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_placeholder_has_no_public_bootstrap)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chain_params->GetConsensus();

    BOOST_CHECK(chain_params->DNSSeeds().empty());
    BOOST_CHECK(chain_params->FixedSeeds().empty());
    BOOST_CHECK(consensus.nMinimumChainWork.IsNull());
    BOOST_CHECK(consensus.defaultAssumeValid.IsNull());
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_auxpow_chain_id_is_placeholder)
{
    const auto main_consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const auto testnet4_consensus = CreateChainParams(*m_node.args, ChainType::TESTNET4)->GetConsensus();

    BOOST_CHECK_EQUAL(testnet4_consensus.nAuxpowChainId, 31430);
    BOOST_CHECK_EQUAL(main_consensus.nAuxpowChainId, testnet4_consensus.nAuxpowChainId);
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_launch_difficulty_config)
{
    const UniValue config = ReadMainnetLaunchDifficultyConfig();
    const uint32_t permissionless_bits = CalculatePermissionlessLaunchBits(config);
    const uint32_t auxpow_bits = CalculateAuxPowLaunchBits(config);
    const uint32_t temporary_genesis_bits = ParseBits(RequiredString(RequiredObject(config, "genesis"), "temporary_bits"));

    const auto chain_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chain_params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.fPowUseASERT, true);
    BOOST_CHECK_EQUAL(consensus.nCadenceActivationHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingLegacy, 75);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingAuxPow, 300);

    BOOST_CHECK_EQUAL(chain_params->GenesisBlock().nBits, temporary_genesis_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBits, permissionless_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsLegacy, permissionless_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsAuxPow, auxpow_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nHeight, 0);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nAuxPow, 0U);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBlockTime, chain_params->GenesisBlock().nTime);

    CBlockIndex genesis{chain_params->GenesisBlock()};
    genesis.nHeight = consensus.asertAnchorParams.nHeight;
    genesis.nAuxPow = consensus.asertAnchorParams.nAuxPow;

    CBlockHeader next_permissionless{};
    next_permissionless.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    next_permissionless.nTime = genesis.nTime + static_cast<uint32_t>(consensus.nPowTargetSpacingLegacy);

    CBlockHeader next_auxpow{};
    next_auxpow.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    next_auxpow.nTime = genesis.nTime + static_cast<uint32_t>(consensus.nPowTargetSpacingAuxPow);

    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next_permissionless, consensus), permissionless_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next_auxpow, consensus), auxpow_bits);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_chainwork_checkpoint)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const auto& consensus = chain_params->GetConsensus();

    BOOST_CHECK_EQUAL(
        consensus.nMinimumChainWork.ToString(),
        "0000000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK_EQUAL(
        consensus.defaultAssumeValid.ToString(),
        "0000000000000000000000000000000000000000000000000000000000000000");
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_seeds)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const auto& dns_seeds = chain_params->DNSSeeds();

    BOOST_REQUIRE_EQUAL(dns_seeds.size(), 2U);
    BOOST_CHECK_EQUAL(dns_seeds[0], "coherence-testnet4.qbit.org");
    BOOST_CHECK_EQUAL(dns_seeds[1], "triplet-testnet4.qbit.org");
    BOOST_CHECK_EQUAL(chain_params->FixedSeeds().size(), 16U);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_outerwitness_defaults)
{
    const auto main_consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const auto testnet_consensus = CreateChainParams(*m_node.args, ChainType::TESTNET)->GetConsensus();
    const auto testnet4_consensus = CreateChainParams(*m_node.args, ChainType::TESTNET4)->GetConsensus();
    const auto signet_consensus = CreateChainParams(*m_node.args, ChainType::SIGNET)->GetConsensus();
    const auto regtest_consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();

    BOOST_CHECK_EQUAL(main_consensus.nOuterReservedWitnessHeight, 0);
    BOOST_CHECK_EQUAL(testnet_consensus.nOuterReservedWitnessHeight, 0);
    BOOST_CHECK_EQUAL(signet_consensus.nOuterReservedWitnessHeight, 0);
    BOOST_CHECK_EQUAL(testnet4_consensus.nOuterReservedWitnessHeight, 0);
    BOOST_CHECK_EQUAL(regtest_consensus.nOuterReservedWitnessHeight, std::numeric_limits<int>::max());
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_launch_anchor)
{
    const UniValue config = ReadTestnet4LaunchDifficultyConfig();
    const UniValue& genesis_config = RequiredObject(config, "genesis");
    const UniValue& mined_genesis = RequiredObject(genesis_config, "mined");
    const uint32_t genesis_bits = CalculateGenesisLaunchBits(config);
    const uint32_t permissionless_bits = CalculatePermissionlessLaunchBits(config);
    const uint32_t auxpow_bits = CalculateAuxPowLaunchBits(config);

    const auto chain_params = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const CBlock& genesis_block = chain_params->GenesisBlock();
    const auto& consensus = chain_params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.fPowUseASERT, true);
    BOOST_CHECK(!consensus.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK_EQUAL(consensus.nCadenceActivationHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingLegacy, 75);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacingAuxPow, 300);

    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nHeight, 0);
    BOOST_CHECK_EQUAL(
        RequiredString(genesis_config, "timestamp_message"),
        "Financial Times 12/Jun/2026 Quantum computing revolution is closer than you think");
    BOOST_CHECK_EQUAL(
        RequiredString(genesis_config, "timestamp_source_url"),
        "https://www.ft.com/content/7e461be0-5c13-4a93-a0f8-0659ae5505a2");
    BOOST_CHECK_EQUAL(RequiredString(genesis_config, "max_coinbase_script_sig_bytes"), "100");
    BOOST_CHECK_EQUAL(RequiredString(genesis_config, "max_second_push_extranonce_bytes"), "8");
    BOOST_CHECK_EQUAL(genesis_block.nVersion, static_cast<int32_t>(ParseUint32(RequiredString(mined_genesis, "nversion"))));
    BOOST_CHECK_EQUAL(genesis_block.nTime, ParseUint32(RequiredString(mined_genesis, "ntime")));
    BOOST_CHECK_EQUAL(genesis_block.nBits, ParseBits(RequiredString(mined_genesis, "nbits")));
    BOOST_CHECK_EQUAL(genesis_block.nNonce, ParseUint32(RequiredString(mined_genesis, "nnonce")));
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock.ToString(), RequiredString(mined_genesis, "hash"));
    BOOST_CHECK_EQUAL(genesis_block.GetHash().ToString(), RequiredString(mined_genesis, "hash"));
    BOOST_CHECK_EQUAL(genesis_block.hashMerkleRoot.ToString(), RequiredString(mined_genesis, "merkle_root"));
    BOOST_REQUIRE_EQUAL(genesis_block.vtx.size(), 1U);
    BOOST_REQUIRE_EQUAL(genesis_block.vtx[0]->vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(genesis_block.vtx[0]->vout.size(), 1U);
    BOOST_CHECK_EQUAL(HexStr(genesis_block.vtx[0]->vin[0].scriptSig), RequiredString(mined_genesis, "coinbase_script_sig_hex"));
    BOOST_CHECK_EQUAL(HexStr(genesis_block.vtx[0]->vout[0].scriptPubKey), RequiredString(mined_genesis, "genesis_output_script_hex"));
    BOOST_CHECK_EQUAL(EncodeHexTx(*genesis_block.vtx[0]), RequiredString(mined_genesis, "coinbase_tx_hex"));
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBlockTime, genesis_block.nTime);
    BOOST_CHECK_EQUAL(genesis_block.nBits, genesis_bits);
    BOOST_CHECK_EQUAL(permissionless_bits, genesis_bits);
    BOOST_CHECK_EQUAL(auxpow_bits, genesis_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBits, permissionless_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsLegacy, permissionless_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsAuxPow, auxpow_bits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nAuxPow, 0U);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBlockTime, chain_params->GenesisBlock().nTime);

    CBlockIndex genesis{chain_params->GenesisBlock()};
    genesis.nHeight = consensus.asertAnchorParams.nHeight;
    genesis.nAuxPow = consensus.asertAnchorParams.nAuxPow;

    CBlockHeader next_permissionless{};
    next_permissionless.nVersion = MakeVersion(/*chain_id=*/0, /*auxpow=*/false, /*version_bits=*/0);
    next_permissionless.nTime = genesis.nTime + static_cast<uint32_t>(consensus.nPowTargetSpacingLegacy);

    CBlockHeader next_auxpow{};
    next_auxpow.nVersion = MakeVersion(static_cast<uint16_t>(consensus.nAuxpowChainId), /*auxpow=*/true, /*version_bits=*/0);
    next_auxpow.nTime = genesis.nTime + static_cast<uint32_t>(consensus.nPowTargetSpacingAuxPow);

    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next_permissionless, consensus), permissionless_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next_auxpow, consensus), auxpow_bits);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_launch_anchor)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::SIGNET)->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nHeight, 0);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBits, 0x1e00f99bU);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsLegacy, 0x1e00f99bU);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBitsAuxPow, 0x1b0d1b64U);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nAuxPow, 0U);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBlockTime, 1775433600);
}

BOOST_AUTO_TEST_CASE(CalculateASERT_large_powlimit_regression)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET4)->GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);

    // This exercises the previous overflow path: large ref target, maximal
    // fractional factor, and qbit's 240-bit powLimit.
    const arith_uint256 next = CalculateASERT(pow_limit,
                                              consensus.nPowTargetSpacing,
                                              consensus.nASERTHalfLife - 1,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(next, pow_limit);
}

BOOST_AUTO_TEST_CASE(CalculateASERT_bounds_and_monotonicity)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET4)->GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    const arith_uint256 ref_target = arith_uint256().SetCompact(consensus.asertAnchorParams.nBits);

    const int64_t height_diff = 120;
    const int64_t ideal_time = consensus.nPowTargetSpacing * height_diff;

    const arith_uint256 on_schedule = CalculateASERT(ref_target,
                                                     consensus.nPowTargetSpacing,
                                                     ideal_time,
                                                     height_diff,
                                                     pow_limit,
                                                     consensus.nASERTHalfLife);
    const arith_uint256 faster = CalculateASERT(ref_target,
                                                consensus.nPowTargetSpacing,
                                                ideal_time - 600,
                                                height_diff,
                                                pow_limit,
                                                consensus.nASERTHalfLife);
    const arith_uint256 slower = CalculateASERT(ref_target,
                                                consensus.nPowTargetSpacing,
                                                ideal_time + 600,
                                                height_diff,
                                                pow_limit,
                                                consensus.nASERTHalfLife);

    BOOST_CHECK(on_schedule >= arith_uint256(1));
    BOOST_CHECK(on_schedule <= pow_limit);
    BOOST_CHECK(faster >= arith_uint256(1));
    BOOST_CHECK(faster <= pow_limit);
    BOOST_CHECK(slower >= arith_uint256(1));
    BOOST_CHECK(slower <= pow_limit);
    BOOST_CHECK(faster < on_schedule);
    BOOST_CHECK(slower > on_schedule);
}

BOOST_AUTO_TEST_CASE(CalculateASERT_minimum_target_floor)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET4)->GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);

    const arith_uint256 next = CalculateASERT(arith_uint256(1),
                                              consensus.nPowTargetSpacing,
                                              -1'000'000,
                                              0,
                                              pow_limit,
                                              consensus.nASERTHalfLife);
    BOOST_CHECK_EQUAL(next, arith_uint256(1));
}

BOOST_AUTO_TEST_CASE(CalculateASERT_shift_overflow_uses_powlimit)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET4)->GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);

    const arith_uint256 next = CalculateASERT(/*refTarget=*/arith_uint256(1),
                                              /*nPowTargetSpacing=*/1,
                                              /*nTimeDiff=*/304,
                                              /*nHeightDiff=*/0,
                                              pow_limit,
                                              /*nHalfLife=*/1);
    BOOST_CHECK_EQUAL(next, pow_limit);
}

BOOST_AUTO_TEST_CASE(Testnet4_genesis_anchor_regression)
{
    const auto chain_params = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const auto& consensus = chain_params->GetConsensus();
    const uint32_t anchor_bits = consensus.asertAnchorParams.nBitsLegacy != 0 ? consensus.asertAnchorParams.nBitsLegacy
                                                                              : consensus.asertAnchorParams.nBits;
    const int64_t target_spacing = consensus.nPowTargetSpacingLegacy > 0 ? consensus.nPowTargetSpacingLegacy
                                                                         : consensus.nPowTargetSpacing;

    BOOST_CHECK_EQUAL(consensus.asertAnchorParams.nBlockTime, chain_params->GenesisBlock().nTime);

    CBlockIndex pindex_last;
    pindex_last.nHeight = 0;
    pindex_last.nTime = chain_params->GenesisBlock().nTime;
    pindex_last.nBits = chain_params->GenesisBlock().nBits;

    CBlockHeader next_block{};
    next_block.nTime = pindex_last.nTime + target_spacing;

    const unsigned int next_bits = GetNextWorkRequired(&pindex_last, &next_block, consensus);
    BOOST_CHECK_EQUAL(next_bits, anchor_bits);
}

BOOST_AUTO_TEST_SUITE_END()
