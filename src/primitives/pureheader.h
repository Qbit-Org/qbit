// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_PRIMITIVES_PUREHEADER_H
#define QBIT_PRIMITIVES_PUREHEADER_H

#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <cstdint>

/** Canonical 32-bit block version field layout used by qbit cadence consensus:
 * [top_bits:3][chain_id:16][reserved:4][auxpow_flag:1][version_bits:8]
 */
static constexpr int32_t BLOCK_VERSION_TOP_BITS{0x20000000};
static constexpr int32_t BLOCK_VERSION_TOP_MASK{static_cast<int32_t>(0xE0000000U)};
static constexpr int32_t BLOCK_VERSION_CHAIN_ID_MASK{0x1FFFE000};
static constexpr int32_t BLOCK_VERSION_RESERVED_MASK{0x00001E00};
static constexpr int32_t BLOCK_VERSION_AUXPOW{0x00000100};
static constexpr int32_t BLOCK_VERSION_SIGNAL_MASK{0x000000FF};
// BIP310-compatible permissionless mining may roll qbit's chain-id field.
// The chain-id field is consensus-significant only when BLOCK_VERSION_AUXPOW
// is set, so permissionless jobs keep low deployment signals, reserved bits,
// the AuxPoW flag, and top bits fixed while exposing Bitcoin-style ASICBoost
// bits 13..28 to miners.
static constexpr uint32_t BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK{static_cast<uint32_t>(BLOCK_VERSION_CHAIN_ID_MASK)};
static constexpr uint32_t BLOCK_VERSION_LAYOUT_MASK{
    static_cast<uint32_t>(BLOCK_VERSION_TOP_MASK) |
    static_cast<uint32_t>(BLOCK_VERSION_CHAIN_ID_MASK) |
    static_cast<uint32_t>(BLOCK_VERSION_RESERVED_MASK) |
    static_cast<uint32_t>(BLOCK_VERSION_AUXPOW)
};
static constexpr int BLOCK_VERSION_CHAIN_ID_SHIFT{13};
static constexpr int BLOCK_VERSION_RESERVED_SHIFT{9};
static constexpr int BLOCK_VERSION_SIGNAL_BITS{8};

static constexpr bool HasBIP9TopBitsShape(const int32_t version)
{
    return (version & BLOCK_VERSION_TOP_MASK) == BLOCK_VERSION_TOP_BITS;
}

static constexpr bool HasCanonicalVersionLayout(const int32_t version)
{
    return (static_cast<uint32_t>(version) & BLOCK_VERSION_LAYOUT_MASK) == 0 || HasBIP9TopBitsShape(version);
}

static constexpr uint16_t ExtractChainId(const int32_t version)
{
    return (static_cast<uint32_t>(version) & BLOCK_VERSION_CHAIN_ID_MASK) >> BLOCK_VERSION_CHAIN_ID_SHIFT;
}

static constexpr uint8_t ExtractVersionBits(const int32_t version)
{
    return static_cast<uint32_t>(version) & BLOCK_VERSION_SIGNAL_MASK;
}

static constexpr bool IsAuxpowVersion(const int32_t version)
{
    // The auxpow flag is only meaningful inside qbit's canonical version layout.
    return HasBIP9TopBitsShape(version) && (version & BLOCK_VERSION_AUXPOW) != 0;
}

static constexpr uint32_t GetPermissionlessVersionRollingMask(const int32_t version)
{
    return HasBIP9TopBitsShape(version) && !IsAuxpowVersion(version) ? BLOCK_VERSION_PERMISSIONLESS_ROLLING_MASK : uint32_t{0};
}

static constexpr uint8_t ReservedBits(const int32_t version)
{
    return (static_cast<uint32_t>(version) & BLOCK_VERSION_RESERVED_MASK) >> BLOCK_VERSION_RESERVED_SHIFT;
}

static constexpr int32_t MakeVersion(const uint16_t chain_id, const bool auxpow, const uint8_t version_bits)
{
    return BLOCK_VERSION_TOP_BITS |
           (static_cast<int32_t>(chain_id) << BLOCK_VERSION_CHAIN_ID_SHIFT) |
           (auxpow ? BLOCK_VERSION_AUXPOW : 0) |
           static_cast<int32_t>(version_bits);
}

class CPureBlockHeader
{
public:
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CPureBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    bool HasVersionTopBits() const
    {
        return (nVersion & BLOCK_VERSION_TOP_MASK) != 0;
    }

    bool SignalsAuxpow() const
    {
        return IsAuxpowVersion(nVersion);
    }

    bool IsPermissionless() const
    {
        return !SignalsAuxpow();
    }

    bool HasReservedVersionBits() const
    {
        return ReservedBits(nVersion) != 0;
    }

    uint16_t GetChainId() const
    {
        return ExtractChainId(nVersion);
    }

    uint8_t GetVersionBits() const
    {
        return ExtractVersionBits(nVersion);
    }

    uint256 GetHash() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

#endif // QBIT_PRIMITIVES_PUREHEADER_H
