// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <versionbits.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(blockversion_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blockversion_codec_roundtrip)
{
    constexpr uint16_t chain_id{31430};
    constexpr uint8_t version_bits{0b10100101};
    const int32_t version{MakeVersion(chain_id, /*auxpow=*/true, version_bits)};

    BOOST_CHECK(HasBIP9TopBitsShape(version));
    BOOST_CHECK(IsAuxpowVersion(version));
    BOOST_CHECK_EQUAL(ExtractChainId(version), chain_id);
    BOOST_CHECK_EQUAL(ExtractVersionBits(version), version_bits);
    BOOST_CHECK_EQUAL(ReservedBits(version), 0);
}

BOOST_AUTO_TEST_CASE(blockversion_shape_checks)
{
    BOOST_CHECK(HasBIP9TopBitsShape(VERSIONBITS_TOP_BITS));
    BOOST_CHECK(HasCanonicalVersionLayout(4));
    BOOST_CHECK(!HasCanonicalVersionLayout(0x00000100));
    BOOST_CHECK(!HasCanonicalVersionLayout(0x00000600));
    BOOST_CHECK(!HasBIP9TopBitsShape(0x40000000));
    BOOST_CHECK(!HasCanonicalVersionLayout(0x40000000));
    BOOST_CHECK(!IsAuxpowVersion(1337));

    const int32_t with_reserved{MakeVersion(/*chain_id=*/1, /*auxpow=*/false, /*version_bits=*/0) |
                                (0b1010 << BLOCK_VERSION_RESERVED_SHIFT)};
    BOOST_CHECK_EQUAL(ReservedBits(with_reserved), 0b1010);
}

BOOST_AUTO_TEST_CASE(blockversion_repack_preserves_versionbits)
{
    const int32_t bip9_version{VERSIONBITS_TOP_BITS | (1 << 0) | (1 << 7)};
    constexpr uint16_t chain_id{31430};
    const int32_t merged_version{MakeVersion(chain_id, /*auxpow=*/true, ExtractVersionBits(bip9_version))};

    BOOST_CHECK_EQUAL(ExtractVersionBits(merged_version), ExtractVersionBits(bip9_version));
    BOOST_CHECK_EQUAL(merged_version & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
    BOOST_CHECK_EQUAL(ExtractChainId(merged_version), chain_id);
    BOOST_CHECK(IsAuxpowVersion(merged_version));
}

BOOST_AUTO_TEST_CASE(blockversion_permissionless_rolling_mask_is_chain_id_only)
{
    BOOST_CHECK_EQUAL(BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK, static_cast<uint32_t>(BLOCK_VERSION_CHAIN_ID_MASK));
    BOOST_CHECK_EQUAL(BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK & static_cast<uint32_t>(BLOCK_VERSION_TOP_MASK), 0U);
    BOOST_CHECK_EQUAL(BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK & static_cast<uint32_t>(BLOCK_VERSION_RESERVED_MASK), 0U);
    BOOST_CHECK_EQUAL(BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK & static_cast<uint32_t>(BLOCK_VERSION_AUXPOW), 0U);
    BOOST_CHECK_EQUAL(BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK & static_cast<uint32_t>(BLOCK_VERSION_SIGNAL_MASK), 0U);

    constexpr uint8_t version_bits{0x5a};
    const uint32_t base{static_cast<uint32_t>(MakeVersion(/*chain_id=*/0, /*auxpow=*/false, version_bits))};
    const int32_t rolled{static_cast<int32_t>((base & ~BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK) |
                                             BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK)};

    BOOST_CHECK(HasCanonicalVersionLayout(rolled));
    BOOST_CHECK(!IsAuxpowVersion(rolled));
    BOOST_CHECK_EQUAL(ReservedBits(rolled), 0);
    BOOST_CHECK_EQUAL(ExtractVersionBits(rolled), version_bits);
    BOOST_CHECK_EQUAL(ExtractChainId(rolled), std::numeric_limits<uint16_t>::max());
}

BOOST_AUTO_TEST_CASE(blockversion_permissionless_rolling_mask_eligibility)
{
    constexpr uint8_t version_bits{0x5a};

    BOOST_CHECK_EQUAL(GetPermissionlessVersionRollingMask(MakeVersion(/*chain_id=*/0, /*auxpow=*/false, version_bits)),
                      BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK);
    BOOST_CHECK_EQUAL(GetPermissionlessVersionRollingMask(4), 0U);
    BOOST_CHECK_EQUAL(GetPermissionlessVersionRollingMask(MakeVersion(/*chain_id=*/31430, /*auxpow=*/true, version_bits)), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
