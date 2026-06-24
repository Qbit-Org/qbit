// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// https://developercommunity.visualstudio.com/t/Bogus-C7595-error-on-valid-C20-code/10906093
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static constexpr int QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID{31430};
static constexpr int QBIT_TEST_CHAIN_AUXPOW_CHAIN_ID{QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID};
static constexpr int QBIT_TESTNET4_AUXPOW_DISPLAY_COMMITMENT_HEIGHT{20'500};

// Mainnet is not launched. This placeholder intentionally matches public
// testnet only while mainnet params are still development scaffolding. Replace
// it with a distinct final value before mainnet is enabled or reset.
static constexpr int QBIT_MAINNET_PLACEHOLDER_AUXPOW_CHAIN_ID{QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID};

static CBlock CreateGenesisBlock(const CScript& genesisInputScript, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = genesisInputScript;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const CScript genesisInputScript = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Build the qbit development genesis block.
 *
 * Headline: "qbit/v0.1 development genesis - not for production use"
 * Output: 33 zero bytes + OP_CHECKSIG (unspendable, follows testnet4 pattern)
 * Reward: 210 QBT
 *
 * This is a development placeholder. Before mainnet launch:
 * - Replace headline with a real, dateable publication headline
 * - Finalize production nBits from sourced launch assumptions
 * - Re-mine with C/CUDA at real difficulty
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "qbit/v0.1 development genesis - not for production use";
    const CScript genesisOutputScript = CScript() << "000000000000000000000000000000000000000000000000000000000000000000"_hex << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateTestNet4GenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const auto genesisInputScriptBytes = ParseHex("04ffff001d0800000008f44100004c5146696e616e6369616c2054696d65732031322f4a756e2f32303236205175616e74756d20636f6d707574696e67207265766f6c7574696f6e20697320636c6f736572207468616e20796f75207468696e6b");
    const CScript genesisInputScript{genesisInputScriptBytes.begin(), genesisInputScriptBytes.end()};
    const CScript genesisOutputScript = CScript() << "000000000000000000000000000000000000000000000000000000000000000000"_hex << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static ChainTxData LaunchChainTxData(const CBlock& genesis, int64_t target_spacing)
{
    assert(target_spacing > 0);
    return ChainTxData{
        .nTime = genesis.nTime,
        .tx_count = 1,
        .dTxRate = 1.0 / target_spacing,
    };
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyInitial = 210 * COIN;
        consensus.nSubsidyStepInterval = 43'200;
        consensus.nSubsidyStepdownNumerator = 598;
        consensus.nSubsidyStepdownDenominator = 625;
        // qbit: no script_flag_exceptions — clean chain from genesis
        consensus.BIP34Height = 0; // Active from genesis
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        // Pre-launch network: reserve the outer witness namespace from genesis so future v3..v16 families can soft-fork on top of the launch baseline.
        consensus.nOuterReservedWitnessHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // Retained for DifficultyAdjustmentInterval(); ASERT replaces epoch retarget.
        consensus.nCadenceActivationHeight = 0; // Clean-slate network: cadence rules are active from genesis unless a test override says otherwise.
        consensus.nAuxpowDisplayCommitmentHeight = 0;
        consensus.nPowTargetSpacing = 60; // 1-minute blocks
        consensus.nPowTargetSpacingLegacy = 75; // Use 75s/300s lane spacing for an exact 4:1 permissionless:merged split at a 60s aggregate cadence.
        consensus.nPowTargetSpacingAuxPow = 300;
        consensus.nAuxpowChainId = QBIT_MAINNET_PLACEHOLDER_AUXPOW_CHAIN_ID;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.fRestrictedOutputMode = true;
        consensus.fPowUseASERT = true;
        consensus.nASERTHalfLife = 2 * 60 * 60;
        // Draft launch calibration from src/test/data/mainnet_launch_difficulty.json:
        // permissionless uses $100M FDV and $30.67/PH/day hashprice; AuxPoW uses
        // 1% of a rounded 1000 EH/s Bitcoin hashrate at 300s target spacing.
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x1810c357, 0x1810c357, 0x180192f8, 0, 1738713600};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 19152; // 95% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 20160;

        // Deployment of Taproot (BIPs 340-342) — active from genesis on qbit
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 19152; // 95% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 20160;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x44; // SHA-256("qbit:mainnet:v1")[0:4]
        pchMessageStart[1] = 0x4f;
        pchMessageStart[2] = 0x24;
        pchMessageStart[3] = 0xa8;
        nDefaultPort = 8355;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1; // qbit: placeholder, chain doesn't exist yet
        m_assumed_chain_state_size = 1;

        // Temporary development genesis target. ASERT lane anchors below carry the
        // draft launch difficulty until the final mainnet genesis is mined.
        genesis = CreateGenesisBlock(1738713600, 45609, 0x1f00ffff, 1, consensus.nSubsidyInitial);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.BIP34Hash = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256{"0000324188278d089b5eabd9b62bf874c7512677cea90720af51ea5a61a2f997"});
        assert(genesis.hashMerkleRoot == uint256{"773941c57f540b7e0f841db6de90bf4f29d305d8233224c2581025c684387313"});

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // qbit: no DNS seeds yet — network doesn't exist
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,58);  // 'Q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);  // 'S'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,159);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x03, 0xf7, 0x28, 0x15}; // qpub
        base58Prefixes[EXT_SECRET_KEY] = {0x03, 0xf7, 0x23, 0xdb}; // qprv

        bech32_hrp = "qb";

        vFixedSeeds.clear(); // qbit: no fixed seeds yet

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {}; // qbit: no assumeUTXO snapshots yet

        chainTxData = LaunchChainTxData(genesis, consensus.nPowTargetSpacing);
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyInitial = 210 * COIN;
        consensus.nSubsidyStepInterval = 43'200;
        consensus.nSubsidyStepdownNumerator = 598;
        consensus.nSubsidyStepdownDenominator = 625;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        // Pre-launch network: reserve the outer witness namespace from genesis so future v3..v16 families can soft-fork on top of the launch baseline.
        consensus.nOuterReservedWitnessHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}; // Development difficulty
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // Retained for DifficultyAdjustmentInterval()
        consensus.nCadenceActivationHeight = 0;
        consensus.nAuxpowDisplayCommitmentHeight = 0;
        consensus.nPowTargetSpacing = 60;
        consensus.nPowTargetSpacingLegacy = 75;
        consensus.nPowTargetSpacingAuxPow = 300;
        consensus.nAuxpowChainId = QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.fRestrictedOutputMode = true;
        consensus.fPowUseASERT = true;
        consensus.nASERTHalfLife = 2 * 60 * 60;
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x1d00ffff, 0x1d00ffff, 0x1d00ffff, 0, 1738713601};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 15120; // 75% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 20160;

        // Deployment of Taproot (BIPs 340-342) — active from genesis on qbit
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 15120; // 75% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 20160;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xc3; // SHA-256("qbit:testnet:v1")[0:4]
        pchMessageStart[1] = 0xd3;
        pchMessageStart[2] = 0x0a;
        pchMessageStart[3] = 0x67;
        nDefaultPort = 18355;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1738713601, 88582, 0x1f00ffff, 1, consensus.nSubsidyInitial);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.BIP34Hash = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256{"0000c20791706c6940a43d75db44d1ae9dadeb637cedfbaa5cf293435eeaab3c"});
        assert(genesis.hashMerkleRoot == uint256{"773941c57f540b7e0f841db6de90bf4f29d305d8233224c2581025c684387313"});

        vFixedSeeds.clear();
        vSeeds.clear();
        // qbit: no DNS seeds yet

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120); // 'q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125); // 's'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,178);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xdb, 0xad}; // tqpb
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xdc, 0x31}; // tqpv

        bech32_hrp = "tq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {};

        chainTxData = LaunchChainTxData(genesis, consensus.nPowTargetSpacing);
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyInitial = 210 * COIN;
        consensus.nSubsidyStepInterval = 43'200;
        consensus.nSubsidyStepdownNumerator = 598;
        consensus.nSubsidyStepdownDenominator = 625;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        // Match launch restricted-output semantics on the public rehearsal network.
        consensus.nOuterReservedWitnessHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nCadenceActivationHeight = 0;
        consensus.nAuxpowDisplayCommitmentHeight = QBIT_TESTNET4_AUXPOW_DISPLAY_COMMITMENT_HEIGHT;
        consensus.nPowTargetSpacing = 60;
        consensus.nPowTargetSpacingLegacy = 75;
        consensus.nPowTargetSpacingAuxPow = 300;
        consensus.nAuxpowChainId = QBIT_PUBLIC_TESTNET_AUXPOW_CHAIN_ID;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.fRestrictedOutputMode = true;
        consensus.fPowUseASERT = true;
        consensus.nASERTHalfLife = 2 * 60 * 60;
        // Low-difficulty testnet4 reset calibration from
        // src/test/data/testnet4_launch_difficulty.json. Genesis and both
        // Cadence lanes share the externally mined reset target.
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x1a7f1ab5, 0x1a7f1ab5, 0x1a7f1ab5, 0, 1781704709};

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 15120; // 75% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 20160;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 15120; // 75% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 20160;

        // Reset chain starts without a mined post-genesis chainwork floor or
        // assume-valid checkpoint.
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xc7; // SHA-256("qbit:testnet4:v2")[0:4]
        pchMessageStart[1] = 0xc4;
        pchMessageStart[2] = 0x16;
        pchMessageStart[3] = 0x40;
        nDefaultPort = 48355;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        // qbit testnet4: low-difficulty public reset genesis.
        genesis = CreateTestNet4GenesisBlock(1781704709, 2528738861, 0x1a7f1ab5, 1, consensus.nSubsidyInitial);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.BIP34Hash = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256{"000000000000796fe86bbc0bf1b66a07e4b4c0676f74b54cf7e5ce8b3f1a0090"});
        assert(genesis.hashMerkleRoot == uint256{"66bf018c3377135cdc87f66ed4926b6a3be5aeef890841a3cfebaff9dfb91ed0"});

        vFixedSeeds = std::vector<uint8_t>(chainparams_seed_testnet4.begin(), chainparams_seed_testnet4.end());
        vSeeds.emplace_back("coherence-testnet4.qbit.org");
        vSeeds.emplace_back("triplet-testnet4.qbit.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120); // 'q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125); // 's'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,178);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xdb, 0xad}; // tqpb
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xdc, 0x31}; // tqpv

        bech32_hrp = "tq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        m_assumeutxo_data = {};

        chainTxData = LaunchChainTxData(genesis, consensus.nPowTargetSpacing);
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            // qbit signet uses an open challenge by default and has no predefined seed set yet.
            bin = "51"_hex_v_u8; // OP_TRUE
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            LogInfo("Signet with challenge %s", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyInitial = 210 * COIN;
        consensus.nSubsidyStepInterval = 43'200;
        consensus.nSubsidyStepdownNumerator = 598;
        consensus.nSubsidyStepdownDenominator = 625;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        // Reset network: reserve the outer witness namespace from genesis so future v3..v16 families can soft-fork on top of the relaunched baseline.
        consensus.nOuterReservedWitnessHeight = 0;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nCadenceActivationHeight = 0;
        consensus.nAuxpowDisplayCommitmentHeight = 0;
        consensus.nPowTargetSpacing = 60;
        consensus.nPowTargetSpacingLegacy = 75;
        consensus.nPowTargetSpacingAuxPow = 300;
        consensus.nAuxpowChainId = QBIT_TEST_CHAIN_AUXPOW_CHAIN_ID;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.fRestrictedOutputMode = true;
        consensus.fPowUseASERT = true;
        consensus.nASERTHalfLife = 2 * 60 * 60;
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x1e00f99b, 0x1e00f99b, 0x1b0d1b64, 0, 1775433600};
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 18144; // 90% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 20160;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 18144; // 90% of 20160
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 20160;

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38355;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1775433600, 260258, 0x1f00ffff, 1, consensus.nSubsidyInitial);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.BIP34Hash = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256{"0000000a5698c727f05cbdaeaff3e48b48ab187aeb03414e783ea81fed14d65c"});
        assert(genesis.hashMerkleRoot == uint256{"773941c57f540b7e0f841db6de90bf4f29d305d8233224c2581025c684387313"});

        m_assumeutxo_data = {};
        chainTxData = LaunchChainTxData(genesis, consensus.nPowTargetSpacing);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120); // 'q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125); // 's'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,178);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xdb, 0xad}; // tqpb
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xdc, 0x31}; // tqpv

        bech32_hrp = "tq";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyInitial = 210 * COIN;
        consensus.nSubsidyStepInterval = 150; // Keep short for regtest
        consensus.nSubsidyStepdownNumerator = 598;
        consensus.nSubsidyStepdownDenominator = 625;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.nCadenceActivationHeight = opts.cadence_activation_height.value_or(0); // Always active unless overridden
        consensus.nAuxpowDisplayCommitmentHeight = opts.auxpow_display_commitment_height.value_or(0); // Always active unless overridden
        consensus.nOuterReservedWitnessHeight = opts.outer_witness_activation_height.value_or(std::numeric_limits<int>::max());
        consensus.P2MRHeight = opts.p2mr_activation_height.value_or(0); // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 60;
        consensus.nPowTargetSpacingLegacy = 75;
        consensus.nPowTargetSpacingAuxPow = 300;
        consensus.nAuxpowChainId = QBIT_TEST_CHAIN_AUXPOW_CHAIN_ID;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = !(opts.asert || opts.legacy_retarget);
        consensus.fRestrictedOutputMode = opts.restricted_output_mode;
        consensus.fPowUseASERT = opts.asert;
        consensus.nASERTHalfLife = 2 * 60 * 60;
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x207fffff, 0x207fffff, 0x207fffff, 0, 1738713602};

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108; // 75%
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].period = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].threshold = 108; // 75%
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].period = 144;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xa6; // SHA-256("qbit:regtest:v1")[0:4]
        pchMessageStart[1] = 0x6b;
        pchMessageStart[2] = 0x1f;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18460;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateGenesisBlock(1738713602, 1, 0x207fffff, 1, consensus.nSubsidyInitial);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"0ee96aa77c4b600850e349344fa21b107e805f5370ddc7a6189db12cf69acce6"});
        assert(genesis.hashMerkleRoot == uint256{"773941c57f540b7e0f841db6de90bf4f29d305d8233224c2581025c684387313"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;
        m_witness_pruning_enabled = opts.witness_pruning_enabled;

        // qbit: regtest assumeUTXO snapshots need to be regenerated after chain is running.
        // Bitcoin's regtest hashes are invalid on qbit's regtest (different genesis).
        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0.001, // Set a non-zero rate to make it testable
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,120); // 'q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125); // 's'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,166);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x03, 0xf7, 0xd7, 0xb5}; // qrpb
        base58Prefixes[EXT_SECRET_KEY] = {0x03, 0xf7, 0xd8, 0x3a}; // qrpv

        bech32_hrp = "qbrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
