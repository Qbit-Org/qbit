// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bech32.h>
#include <chainparams.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/interpreter.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <vector>

namespace {

constexpr std::array<unsigned char, WITNESS_V2_P2MR_SIZE> P2MR_PROGRAM{
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
};

uint256 KnownMerkleRoot()
{
    uint256 merkle_root;
    std::copy(P2MR_PROGRAM.begin(), P2MR_PROGRAM.end(), merkle_root.begin());
    return merkle_root;
}

WitnessV2P2MR KnownP2MRDestination()
{
    return WitnessV2P2MR{KnownMerkleRoot()};
}

std::string EncodeWitnessAddress(const int version, const std::span<const unsigned char> program, const bech32::Encoding encoding)
{
    std::vector<uint8_t> data{static_cast<uint8_t>(version)};
    data.reserve(1 + (program.size() * 8 + 4) / 5);
    ConvertBits<8, 5, true>([&](uint8_t c) { data.push_back(c); }, program.begin(), program.end());
    return bech32::Encode(encoding, Params().Bech32HRP(), data);
}

struct KeyIOP2MRTestingSetup : public BasicTestingSetup {
    // Generic witness decode cases switch to regtest; keep regtest unrestricted there.
    KeyIOP2MRTestingSetup()
        : BasicTestingSetup{ChainType::MAIN, {.extra_args = {"-p2mronly=0"}}} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(key_io_p2mr_tests, KeyIOP2MRTestingSetup)

BOOST_AUTO_TEST_CASE(p2mr_encode_mainnet)
{
    SelectParams(ChainType::MAIN);
    const std::string address = EncodeDestination(KnownP2MRDestination());
    BOOST_CHECK_EQUAL(address.substr(0, 4), "qb1z");
}

BOOST_AUTO_TEST_CASE(p2mr_encode_testnet)
{
    SelectParams(ChainType::TESTNET);
    const std::string address = EncodeDestination(KnownP2MRDestination());
    BOOST_CHECK_EQUAL(address.substr(0, 4), "tq1z");
}

BOOST_AUTO_TEST_CASE(p2mr_encode_regtest)
{
    SelectParams(ChainType::REGTEST);
    const std::string address = EncodeDestination(KnownP2MRDestination());
    BOOST_CHECK_EQUAL(address.substr(0, 6), "qbrt1z");
}

BOOST_AUTO_TEST_CASE(p2mr_decode_valid)
{
    SelectParams(ChainType::MAIN);
    const std::string address = EncodeDestination(KnownP2MRDestination());

    const CTxDestination decoded = DecodeDestination(address);
    const auto* p2mr = std::get_if<WitnessV2P2MR>(&decoded);
    BOOST_REQUIRE(p2mr != nullptr);
    BOOST_CHECK(*p2mr == KnownP2MRDestination());
}

BOOST_AUTO_TEST_CASE(p2mr_decode_roundtrip)
{
    SelectParams(ChainType::REGTEST);
    const std::string encoded = EncodeDestination(KnownP2MRDestination());
    const CTxDestination decoded = DecodeDestination(encoded);

    const auto* p2mr = std::get_if<WitnessV2P2MR>(&decoded);
    BOOST_REQUIRE(p2mr != nullptr);
    BOOST_CHECK_EQUAL(EncodeDestination(*p2mr), encoded);
}

BOOST_AUTO_TEST_CASE(p2mr_decode_wrong_version)
{
    SelectParams(ChainType::REGTEST);
    const std::string v0_address = EncodeDestination(WitnessV0ScriptHash{KnownMerkleRoot()});

    std::string error;
    const CTxDestination decoded = DecodeDestination(v0_address, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(std::holds_alternative<WitnessV0ScriptHash>(decoded));
    BOOST_CHECK(!std::holds_alternative<WitnessV2P2MR>(decoded));
}

BOOST_AUTO_TEST_CASE(p2mr_decode_wrong_size)
{
    SelectParams(ChainType::REGTEST);
    const std::vector<unsigned char> short_program(20, 0x42);
    const std::string address = EncodeWitnessAddress(/*version=*/2, short_program, bech32::Encoding::BECH32M);

    std::string error;
    const CTxDestination decoded = DecodeDestination(address, error);
    BOOST_CHECK(error.empty());
    const auto* unknown = std::get_if<WitnessUnknown>(&decoded);
    BOOST_REQUIRE(unknown != nullptr);
    BOOST_CHECK_EQUAL(unknown->GetWitnessVersion(), 2U);
    BOOST_CHECK_EQUAL_COLLECTIONS(unknown->GetWitnessProgram().begin(), unknown->GetWitnessProgram().end(), short_program.begin(), short_program.end());
}

BOOST_AUTO_TEST_CASE(p2mr_only_chains_reject_non_p2mr_addresses)
{
    SelectParams(ChainType::MAIN);
    const std::string v0_address = EncodeDestination(WitnessV0ScriptHash{KnownMerkleRoot()});

    std::string error;
    const CTxDestination decoded = DecodeDestination(v0_address, error);
    BOOST_CHECK(!IsValidDestination(decoded));
    BOOST_CHECK_EQUAL(error, "Address type is not supported on this chain; use a p2mr address.");
}

BOOST_AUTO_TEST_CASE(p2mr_only_chains_allow_pay_to_anchor_addresses)
{
    SelectParams(ChainType::MAIN);
    const std::string anchor_address = EncodeDestination(PayToAnchor{});

    std::string error;
    const CTxDestination decoded = DecodeDestination(anchor_address, error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(std::holds_alternative<PayToAnchor>(decoded));
    BOOST_CHECK(IsDestinationOutputTypeAllowed(decoded));
}

BOOST_AUTO_TEST_CASE(p2mr_only_launch_chains_allow_outer_reserved_witness_addresses)
{
    SelectParams(ChainType::MAIN);

    for (const int version : {3, 16}) {
        const std::vector<unsigned char> reserved_program(32, static_cast<unsigned char>(version));
        const std::string reserved_address = EncodeWitnessAddress(version, reserved_program, bech32::Encoding::BECH32M);

        std::string error;
        const CTxDestination decoded = DecodeDestination(reserved_address, error);
        BOOST_CHECK(error.empty());
        const auto* unknown = std::get_if<WitnessUnknown>(&decoded);
        BOOST_REQUIRE(unknown != nullptr);
        BOOST_CHECK_EQUAL(unknown->GetWitnessVersion(), static_cast<unsigned int>(version));
        BOOST_CHECK_EQUAL_COLLECTIONS(unknown->GetWitnessProgram().begin(), unknown->GetWitnessProgram().end(), reserved_program.begin(), reserved_program.end());
        BOOST_CHECK(IsDestinationOutputTypeAllowed(decoded));
    }
}

BOOST_AUTO_TEST_CASE(p2mr_only_delayed_outer_reserved_witness_activation)
{
    const std::vector<unsigned char> reserved_program(32, 0x03);
    const CTxDestination reserved = WitnessUnknown{3, reserved_program};
    const auto inactive_params = CChainParams::RegTest({.restricted_output_mode = true});
    const auto delayed_params = CChainParams::RegTest({.outer_witness_activation_height = 10, .restricted_output_mode = true});

    BOOST_CHECK(!IsDestinationOutputTypeAllowed(reserved, *inactive_params));
    BOOST_CHECK(IsDestinationOutputTypeAllowed(reserved, *delayed_params));
    BOOST_CHECK(!IsDestinationOutputTypeAllowedAtHeight(reserved, *delayed_params, 9));
    BOOST_CHECK(IsDestinationOutputTypeAllowedAtHeight(reserved, *delayed_params, 10));
}

BOOST_AUTO_TEST_CASE(p2mr_only_launch_chains_reject_non_reserved_unknown_witness_addresses)
{
    SelectParams(ChainType::MAIN);
    const std::vector<unsigned char> non_reserved_program(20, 0x42);
    const std::string non_reserved_address = EncodeWitnessAddress(/*version=*/2, non_reserved_program, bech32::Encoding::BECH32M);

    std::string error;
    const CTxDestination decoded = DecodeDestination(non_reserved_address, error);
    BOOST_CHECK(!IsValidDestination(decoded));
    BOOST_CHECK_EQUAL(error, "Address type is not supported on this chain; use a p2mr address.");
}

BOOST_AUTO_TEST_CASE(p2mr_constructor_rejects_wrong_size)
{
    const std::vector<unsigned char> short_program(WITNESS_V2_P2MR_SIZE - 1, 0x42);
    const std::vector<unsigned char> long_program(WITNESS_V2_P2MR_SIZE + 1, 0x42);

    BOOST_CHECK_THROW(WitnessV2P2MR{std::span<const unsigned char>{short_program}}, std::invalid_argument);
    BOOST_CHECK_THROW(WitnessV2P2MR{std::span<const unsigned char>{long_program}}, std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(p2mr_decode_wrong_checksum)
{
    SelectParams(ChainType::MAIN);
    std::string address = EncodeDestination(KnownP2MRDestination());
    address.back() = (address.back() == 'q') ? 'p' : 'q';

    std::string error;
    const CTxDestination decoded = DecodeDestination(address, error);
    BOOST_CHECK(!IsValidDestination(decoded));
    BOOST_CHECK(!error.empty());
}

BOOST_AUTO_TEST_CASE(p2mr_decode_bech32_not_bech32m)
{
    SelectParams(ChainType::MAIN);
    const std::string address = EncodeWitnessAddress(/*version=*/2, P2MR_PROGRAM, bech32::Encoding::BECH32);

    std::string error;
    const CTxDestination decoded = DecodeDestination(address, error);
    BOOST_CHECK(!IsValidDestination(decoded));
    BOOST_CHECK_EQUAL(error, "Version 1+ witness address must use Bech32m checksum");
}

BOOST_AUTO_TEST_CASE(p2mr_extract_destination)
{
    const CScript script_pub_key = CScript{} << OP_2 << std::vector<unsigned char>{P2MR_PROGRAM.begin(), P2MR_PROGRAM.end()};
    CTxDestination destination;
    BOOST_REQUIRE(ExtractDestination(script_pub_key, destination));

    const auto* p2mr = std::get_if<WitnessV2P2MR>(&destination);
    BOOST_REQUIRE(p2mr != nullptr);
    BOOST_CHECK(*p2mr == KnownP2MRDestination());
}

BOOST_AUTO_TEST_CASE(p2mr_get_script_for_destination)
{
    const CScript script_pub_key = GetScriptForDestination(KnownP2MRDestination());
    BOOST_CHECK_EQUAL(script_pub_key.size(), 34U);
    BOOST_CHECK_EQUAL(script_pub_key[0], OP_2);
    BOOST_CHECK_EQUAL(script_pub_key[1], WITNESS_V2_P2MR_SIZE);
}

BOOST_AUTO_TEST_CASE(p2mr_output_type)
{
    const std::optional<OutputType> output_type = OutputTypeFromDestination(KnownP2MRDestination());
    BOOST_REQUIRE(output_type.has_value());
    BOOST_CHECK(*output_type == OutputType::P2MR);
}

BOOST_AUTO_TEST_CASE(p2mr_parse_output_type)
{
    const std::optional<OutputType> parsed = ParseOutputType("p2mr");
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(*parsed == OutputType::P2MR);
    BOOST_CHECK_EQUAL(FormatOutputType(*parsed), "p2mr");
}

BOOST_AUTO_TEST_CASE(p2mr_is_valid_destination)
{
    BOOST_CHECK(IsValidDestination(KnownP2MRDestination()));
}

BOOST_AUTO_TEST_CASE(p2mr_all_zero_program)
{
    SelectParams(ChainType::REGTEST);
    const std::array<unsigned char, WITNESS_V2_P2MR_SIZE> zero_program{};
    uint256 zero_merkle_root;
    std::copy(zero_program.begin(), zero_program.end(), zero_merkle_root.begin());
    const WitnessV2P2MR p2mr_zero{zero_merkle_root};
    const std::string address = EncodeDestination(p2mr_zero);
    const CTxDestination decoded = DecodeDestination(address);
    const auto* p2mr = std::get_if<WitnessV2P2MR>(&decoded);
    BOOST_REQUIRE(p2mr != nullptr);
    BOOST_CHECK(std::all_of(p2mr->begin(), p2mr->end(), [](unsigned char c) { return c == 0; }));
}

BOOST_AUTO_TEST_SUITE_END()
