// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqc.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace {
using valtype = std::vector<unsigned char>;

constexpr unsigned int P2MR_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_P2MR_RULES
};

enum class LeafMode {
    VALID_CHECKSIGPQC,
    VERIFY_TRUE,
    INVALID_PUBKEY,
    OP_TRUE,
    CHECKSIGADD_WEIGHT,
    CHECKDATASIGPQC_BOUNDARY,
    CHECKDATASIGADDPQC_WEIGHT,
    STACK_ITEM_BOUNDARY,
    STACK_COPY_BOUNDARY,
    STACK_COUNT_BOUNDARY,
    STACK_TOTAL_BOUNDARY,
    OP_SUCCESS_RESOURCE_LIMITS,
    CTV_MATCHING,
    CTV_REPEATED_MATCHING,
    CTV_WRONG_LENGTH_BOUNDARY,
    CTV_WITH_CHECKSIGPQC,
};

struct LeafConfig {
    CScript committed_leaf;
    CScript witness_leaf;
    std::vector<valtype> stack_items;
    std::optional<CPQCPubKey> signing_pubkey;
};

struct P2MRSpend {
    CTransaction tx_credit;
    CMutableTransaction tx_spend;
    PrecomputedTransactionData txdata;
    uint256 leaf_hash;
};

void initialize_p2mr_script()
{
    static const auto testing_setup = MakeNoLogFileContext<const BasicTestingSetup>();
    (void)testing_setup;
}

std::vector<unsigned char> ScriptBytes(const CScript& script)
{
    return std::vector<unsigned char>(script.begin(), script.end());
}

CScript BuildDropAllScript(size_t drop_count)
{
    CScript script;
    for (size_t i = 0; i < drop_count; ++i) {
        script << OP_DROP;
    }
    script << OP_TRUE;
    return script;
}

std::vector<unsigned char> BuildDefaultCTVHashBytes()
{
    CMutableTransaction tx_template;
    tx_template.version = 1;
    tx_template.nLockTime = 0;
    tx_template.vin.resize(1);
    tx_template.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx_template.vout.resize(1);
    tx_template.vout[0].nValue = 1000;
    tx_template.vout[0].scriptPubKey = CScript{};

    PrecomputedTransactionData txdata;
    txdata.Init(tx_template, {}, /*force=*/true);
    const uint256 ctv_hash{GetDefaultCheckTemplateVerifyHash(tx_template, /*input_index=*/0, txdata)};
    return std::vector<unsigned char>(ctv_hash.begin(), ctv_hash.end());
}

std::vector<valtype> BuildP2MRStackItemsForTotalBytes(size_t total_bytes)
{
    std::vector<valtype> stack_items;
    while (total_bytes > 0) {
        const size_t item_size{std::min<size_t>(MAX_P2MR_V1_STACK_ITEM_SIZE, total_bytes)};
        stack_items.emplace_back(item_size, 0x42);
        total_bytes -= item_size;
    }
    return stack_items;
}

CPQCKey ConsumePQCKey(FuzzedDataProvider& fuzzed_data_provider)
{
    std::vector<unsigned char> random_data{fuzzed_data_provider.ConsumeBytes<unsigned char>(PQC_KEYGEN_RANDOM_DATA_SIZE)};
    random_data.resize(PQC_KEYGEN_RANDOM_DATA_SIZE);

    std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_bytes{};
    std::array<unsigned char, PQC_SECKEY_SIZE> seckey_bytes{};
    if (slh_dsa_keygen(pubkey_bytes.data(), seckey_bytes.data(), random_data.data(), random_data.size()) != 0) {
        return {};
    }

    CPQCKey key;
    key.Set(seckey_bytes.data(), seckey_bytes.data() + seckey_bytes.size());
    return key;
}

LeafConfig BuildLeafConfig(FuzzedDataProvider& fuzzed_data_provider, const CPQCPubKey& pubkey)
{
    const std::vector<unsigned char> pqc_pubkey(pubkey.begin(), pubkey.end());
    const LeafMode mode = fuzzed_data_provider.PickValueInArray<LeafMode>({
        LeafMode::VALID_CHECKSIGPQC,
        LeafMode::VERIFY_TRUE,
        LeafMode::INVALID_PUBKEY,
        LeafMode::OP_TRUE,
        LeafMode::CHECKSIGADD_WEIGHT,
        LeafMode::CHECKDATASIGPQC_BOUNDARY,
        LeafMode::CHECKDATASIGADDPQC_WEIGHT,
        LeafMode::STACK_ITEM_BOUNDARY,
        LeafMode::STACK_COPY_BOUNDARY,
        LeafMode::STACK_COUNT_BOUNDARY,
        LeafMode::STACK_TOTAL_BOUNDARY,
        LeafMode::OP_SUCCESS_RESOURCE_LIMITS,
        LeafMode::CTV_MATCHING,
        LeafMode::CTV_REPEATED_MATCHING,
        LeafMode::CTV_WRONG_LENGTH_BOUNDARY,
        LeafMode::CTV_WITH_CHECKSIGPQC,
    });

    switch (mode) {
    case LeafMode::VALID_CHECKSIGPQC: {
        const CScript leaf = CScript{} << pqc_pubkey << OP_CHECKSIGPQC;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
            .signing_pubkey = pubkey,
        };
    }
    case LeafMode::VERIFY_TRUE: {
        const CScript leaf = CScript{} << pqc_pubkey << OP_CHECKSIGPQC << OP_VERIFY << OP_TRUE;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
            .signing_pubkey = pubkey,
        };
    }
    case LeafMode::INVALID_PUBKEY: {
        const CScript leaf = CScript{} << std::vector<unsigned char>{} << OP_CHECKSIGPQC;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::OP_TRUE: {
        const CScript leaf = CScript{} << OP_TRUE;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CHECKSIGADD_WEIGHT: {
        const std::vector<unsigned char> malformed_pubkey_a(33, 0x11);
        const std::vector<unsigned char> malformed_pubkey_b(33, 0x22);
        const CScript leaf = CScript{}
            << OP_0
            << malformed_pubkey_a << OP_CHECKSIGADD
            << malformed_pubkey_b << OP_CHECKSIGADD
            << OP_2 << OP_EQUAL;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {valtype{0x01}, valtype{0x01}},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CHECKDATASIGPQC_BOUNDARY: {
        const size_t sig_size = fuzzed_data_provider.PickValueInArray<size_t>({
            0,
            PQC_SIG_SIZE - 1,
            PQC_SIG_SIZE,
            PQC_SIG_SIZE + 1,
        });
        const size_t msg_hash_size = fuzzed_data_provider.PickValueInArray<size_t>({31, 32, 33});
        const size_t pubkey_size = fuzzed_data_provider.PickValueInArray<size_t>({31, 32, 33});
        const CScript leaf = CScript{}
            << std::vector<unsigned char>(msg_hash_size, 0x44)
            << std::vector<unsigned char>(pubkey_size, 0x55)
            << OP_CHECKDATASIGPQC;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(sig_size, 0x01)},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CHECKDATASIGADDPQC_WEIGHT: {
        const size_t sig_size_a = fuzzed_data_provider.PickValueInArray<size_t>({
            0,
            1,
            PQC_SIG_SIZE - 1,
            PQC_SIG_SIZE,
            PQC_SIG_SIZE + 1,
        });
        const size_t sig_size_b = fuzzed_data_provider.PickValueInArray<size_t>({
            0,
            1,
            PQC_SIG_SIZE - 1,
            PQC_SIG_SIZE,
            PQC_SIG_SIZE + 1,
        });
        const size_t msg_hash_size = fuzzed_data_provider.PickValueInArray<size_t>({31, 32, 33});
        const std::vector<unsigned char> msg_hash(msg_hash_size, 0x66);
        const CScript leaf = CScript{}
            << msg_hash << OP_0 << std::vector<unsigned char>(PQC_PUBKEY_SIZE, 0x11) << OP_CHECKDATASIGADDPQC
            << msg_hash << OP_SWAP << std::vector<unsigned char>(PQC_PUBKEY_SIZE, 0x22) << OP_CHECKDATASIGADDPQC
            << OP_2 << OP_EQUAL;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {
                std::vector<unsigned char>(sig_size_b, 0x02),
                std::vector<unsigned char>(sig_size_a, 0x01),
            },
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::STACK_ITEM_BOUNDARY: {
        const CScript leaf = CScript{} << OP_DROP << OP_TRUE;
        const size_t size = fuzzed_data_provider.PickValueInArray<size_t>({
            MAX_P2MR_V1_STACK_ITEM_SIZE - 1,
            MAX_P2MR_V1_STACK_ITEM_SIZE,
            MAX_P2MR_V1_STACK_ITEM_SIZE + 1,
        });
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(size, 0x42)},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::STACK_COPY_BOUNDARY: {
        const CScript leaf = CScript{} << OP_DUP << OP_DROP << OP_DROP << OP_TRUE;
        const size_t size = fuzzed_data_provider.PickValueInArray<size_t>({
            MAX_P2MR_V1_STACK_ITEM_SIZE,
            MAX_P2MR_V1_STACK_ITEM_SIZE + 1,
        });
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(size, 0x42)},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::STACK_COUNT_BOUNDARY: {
        const CScript leaf = CScript{} << OP_TRUE;
        const size_t count = fuzzed_data_provider.PickValueInArray<size_t>({
            MAX_STACK_SIZE - 1,
            MAX_STACK_SIZE,
            MAX_STACK_SIZE + 1,
        });
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = std::vector<valtype>(count),
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::STACK_TOTAL_BOUNDARY: {
        const size_t total_bytes = fuzzed_data_provider.PickValueInArray<size_t>({
            MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES - 1,
            MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES,
            MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES + 1,
        });
        std::vector<valtype> stack_items{BuildP2MRStackItemsForTotalBytes(total_bytes)};
        const CScript leaf = BuildDropAllScript(stack_items.size());
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = std::move(stack_items),
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::OP_SUCCESS_RESOURCE_LIMITS: {
        const CScript leaf = CScript{} << OP_RESERVED;
        std::vector<valtype> stack_items;
        const int resource_case = fuzzed_data_provider.PickValueInArray<int>({0, 1, 2});
        if (resource_case == 0) {
            const size_t size = fuzzed_data_provider.PickValueInArray<size_t>({
                MAX_P2MR_V1_STACK_ITEM_SIZE,
                MAX_P2MR_V1_STACK_ITEM_SIZE + 1,
            });
            stack_items = {std::vector<unsigned char>(size, 0x42)};
        } else if (resource_case == 1) {
            const size_t count = fuzzed_data_provider.PickValueInArray<size_t>({
                MAX_STACK_SIZE,
                MAX_STACK_SIZE + 1,
            });
            stack_items = std::vector<valtype>(count);
        } else {
            const size_t total_bytes = fuzzed_data_provider.PickValueInArray<size_t>({
                MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES,
                MAX_P2MR_V1_TOTAL_INITIAL_STACK_BYTES + 1,
            });
            stack_items = BuildP2MRStackItemsForTotalBytes(total_bytes);
        }
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = std::move(stack_items),
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CTV_MATCHING: {
        const CScript leaf = CScript{} << BuildDefaultCTVHashBytes() << OP_CHECKTEMPLATEVERIFY;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CTV_REPEATED_MATCHING: {
        const CScript leaf = CScript{} << BuildDefaultCTVHashBytes() << OP_CHECKTEMPLATEVERIFY << OP_CHECKTEMPLATEVERIFY;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CTV_WRONG_LENGTH_BOUNDARY: {
        const size_t size = fuzzed_data_provider.PickValueInArray<size_t>({
            0,
            31,
            32,
            33,
            MAX_P2MR_V1_STACK_ITEM_SIZE,
        });
        const CScript leaf = CScript{} << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_TRUE;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(size, 0x42)},
            .signing_pubkey = std::nullopt,
        };
    }
    case LeafMode::CTV_WITH_CHECKSIGPQC: {
        const CScript leaf = CScript{} << BuildDefaultCTVHashBytes() << OP_CHECKTEMPLATEVERIFY << OP_DROP << pqc_pubkey << OP_CHECKSIGPQC;
        return {
            .committed_leaf = leaf,
            .witness_leaf = leaf,
            .stack_items = {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00)},
            .signing_pubkey = pubkey,
        };
    }
    }

    return {};
}

CScript BuildSiblingLeaf(FuzzedDataProvider& fuzzed_data_provider)
{
    if (fuzzed_data_provider.ConsumeBool()) {
        return CScript{} << OP_FALSE;
    }

    const std::vector<unsigned char> malformed_pubkey(33, 0x33);
    return CScript{} << malformed_pubkey << OP_CHECKSIGPQC;
}

std::optional<P2MRSpend> BuildSpend(
    const CScript& committed_leaf,
    const CScript& witness_leaf,
    const std::vector<valtype>& stack_items,
    FuzzedDataProvider& fuzzed_data_provider)
{
    TaprootBuilder builder;
    if (fuzzed_data_provider.ConsumeBool()) {
        builder.AddP2MR(/*depth=*/1, committed_leaf, P2MR_LEAF_VERSION_V1)
               .AddP2MR(/*depth=*/1, BuildSiblingLeaf(fuzzed_data_provider), P2MR_LEAF_VERSION_V1)
               .FinalizeP2MR();
    } else {
        builder.AddP2MR(/*depth=*/0, committed_leaf, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
    }

    const WitnessV2P2MR output = builder.GetP2MROutput();
    const P2MRSpendData spenddata = builder.GetP2MRSpendData();
    const auto spend_key = std::make_pair(ScriptBytes(committed_leaf), int(P2MR_LEAF_VERSION_V1));
    const auto spend_it = spenddata.scripts.find(spend_key);
    if (spend_it == spenddata.scripts.end() || spend_it->second.empty()) {
        return std::nullopt;
    }

    std::vector<unsigned char> control_block = *spend_it->second.begin();
    if (fuzzed_data_provider.ConsumeBool()) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (!control_block.empty()) control_block[0] ^= 0x01;
            },
            [&] {
                if (!control_block.empty()) control_block.pop_back();
            },
            [&] {
                control_block.push_back(fuzzed_data_provider.ConsumeIntegral<unsigned char>());
            });
    }

    const CMutableTransaction tx_credit_mut = BuildCreditingTransaction(GetScriptForDestination(output), /*nValue=*/1000);
    const CTransaction tx_credit{tx_credit_mut};

    CScriptWitness witness;
    witness.stack = stack_items;
    witness.stack.push_back(ScriptBytes(witness_leaf));
    witness.stack.push_back(control_block);

    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, witness, tx_credit);
    if (fuzzed_data_provider.ConsumeBool()) {
        tx_spend.vin[0].scriptWitness.stack.push_back(
            std::vector<unsigned char>{static_cast<unsigned char>(ANNEX_TAG), 0x01, 0x02});
    }

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});

    return P2MRSpend{
        .tx_credit = tx_credit,
        .tx_spend = tx_spend,
        .txdata = txdata,
        .leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(committed_leaf)),
    };
}

void MaybeReplaceSignature(
    FuzzedDataProvider& fuzzed_data_provider,
    const CPQCKey& key,
    const std::optional<CPQCPubKey>& signing_pubkey,
    P2MRSpend& spend)
{
    if (!signing_pubkey || spend.tx_spend.vin[0].scriptWitness.stack.empty()) return;

    FlatSigningProvider provider;
    provider.pqc_keys.emplace(*signing_pubkey, key);

    const int hash_type = fuzzed_data_provider.PickValueInArray<int>({
        SIGHASH_DEFAULT,
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    });

    MutableTransactionSignatureCreator creator{
        spend.tx_spend,
        /*input_idx=*/0,
        spend.tx_credit.vout[0].nValue,
        &spend.txdata,
        hash_type,
    };

    std::vector<unsigned char> sig;
    if (!creator.CreatePQCSignature(provider, sig, *signing_pubkey, &spend.leaf_hash, SigVersion::P2MR)) return;

    if (fuzzed_data_provider.ConsumeBool() && !sig.empty()) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                const size_t pos = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, sig.size() - 1);
                sig[pos] ^= 0x01;
            },
            [&] {
                sig.push_back(0x04);
            },
            [&] {
                sig.front() = 0x02;
            },
            [&] {
                sig.resize(sig.size() - 1);
            });
    }

    spend.tx_spend.vin[0].scriptWitness.stack[0] = std::move(sig);
}

bool VerifySpend(const P2MRSpend& spend, unsigned int flags)
{
    ScriptError err;
    return VerifyScript(
        spend.tx_spend.vin[0].scriptSig,
        spend.tx_credit.vout[0].scriptPubKey,
        &spend.tx_spend.vin[0].scriptWitness,
        flags,
        MutableTransactionSignatureChecker(
            &spend.tx_spend,
            0,
            spend.tx_credit.vout[0].nValue,
            spend.txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
}

enum class InputMode {
    LEGACY,
    FIXTURE,
    GENERATION,
    UNSUPPORTED_VERSION,
};

struct TaggedInput {
    InputMode mode;
    std::span<const uint8_t> data;
};

/**
 * Tagged inputs start with "QBFX", a target tag byte and a format version byte
 * (see test/fuzz/qbit_corpora/README.md). Version 1 is followed by a selector
 * byte: a low nibble of 0xF (1/16 of selector values) runs the legacy
 * generation body on the remaining bytes, every other value runs the fixture
 * body. Inputs without the tag keep the legacy layout byte for byte.
 */
TaggedInput ParseTaggedInput(std::span<const uint8_t> buffer, uint8_t target_tag)
{
    static constexpr std::array<uint8_t, 4> MAGIC{'Q', 'B', 'F', 'X'};
    static constexpr uint8_t FORMAT_VERSION_1{0x01};
    if (buffer.size() < MAGIC.size() + 2 || !std::equal(MAGIC.begin(), MAGIC.end(), buffer.begin()) ||
        buffer[MAGIC.size()] != target_tag) {
        return {InputMode::LEGACY, buffer};
    }
    // Unknown versions are ignored rather than reinterpreted as another layout.
    if (buffer[MAGIC.size() + 1] != FORMAT_VERSION_1) return {InputMode::UNSUPPORTED_VERSION, {}};
    const std::span<const uint8_t> body{buffer.subspan(MAGIC.size() + 2)};
    if (body.empty()) return {InputMode::FIXTURE, body};
    const bool generation{(body[0] & 0x0F) == 0x0F};
    return {generation ? InputMode::GENERATION : InputMode::FIXTURE, body.subspan(1)};
}

struct P2MRFixture {
    P2MRSpend spend;
    uint256 wtxid;
};

/**
 * Signed single-leaf spends for the VALID_CHECKSIGPQC, VERIFY_TRUE and
 * CTV_WITH_CHECKSIGPQC leaf modes, each with SIGHASH_DEFAULT and SIGHASH_ALL.
 * Built on first use so that legacy and generation inputs never pay for, or
 * get coverage from, fixture signing.
 */
const std::vector<P2MRFixture>& GetP2MRFixtures()
{
    static const auto fixtures = [] {
        std::array<unsigned char, PQC_KEYGEN_RANDOM_DATA_SIZE> random_data{};
        for (size_t i = 0; i < random_data.size(); ++i) {
            random_data[i] = static_cast<unsigned char>(0x5A ^ (i * 0x2F));
        }
        std::array<unsigned char, PQC_PUBKEY_SIZE> pubkey_bytes{};
        std::array<unsigned char, PQC_SECKEY_SIZE> seckey_bytes{};
        const int keygen_ret{slh_dsa_keygen(pubkey_bytes.data(), seckey_bytes.data(), random_data.data(), random_data.size())};
        assert(keygen_ret == 0);

        CPQCKey key;
        key.Set(seckey_bytes.data(), seckey_bytes.data() + seckey_bytes.size());
        assert(key.IsValid());
        const CPQCPubKey pubkey{key.GetPubKey()};
        assert(pubkey.IsValid());
        const std::vector<unsigned char> pqc_pubkey(pubkey.begin(), pubkey.end());

        const std::array<CScript, 3> leaves{
            CScript{} << pqc_pubkey << OP_CHECKSIGPQC,
            CScript{} << pqc_pubkey << OP_CHECKSIGPQC << OP_VERIFY << OP_TRUE,
            CScript{} << BuildDefaultCTVHashBytes() << OP_CHECKTEMPLATEVERIFY << OP_DROP << pqc_pubkey << OP_CHECKSIGPQC,
        };

        std::vector<P2MRFixture> out;
        out.reserve(leaves.size() * 2);
        for (const CScript& leaf : leaves) {
            for (const int hash_type : {SIGHASH_DEFAULT, SIGHASH_ALL}) {
                TaprootBuilder builder;
                builder.AddP2MR(/*depth=*/0, leaf, P2MR_LEAF_VERSION_V1).FinalizeP2MR();
                const P2MRSpendData spenddata{builder.GetP2MRSpendData()};
                const auto spend_it{spenddata.scripts.find(std::make_pair(ScriptBytes(leaf), int(P2MR_LEAF_VERSION_V1)))};
                assert(spend_it != spenddata.scripts.end() && !spend_it->second.empty());

                const CTransaction tx_credit{BuildCreditingTransaction(GetScriptForDestination(builder.GetP2MROutput()), /*nValue=*/1000)};
                CScriptWitness witness;
                witness.stack = {std::vector<unsigned char>(PQC_SIG_SIZE, 0x00), ScriptBytes(leaf), *spend_it->second.begin()};
                P2MRSpend spend{
                    .tx_credit = tx_credit,
                    .tx_spend = BuildSpendingTransaction(CScript{}, witness, tx_credit),
                    .txdata = {},
                    .leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, ScriptBytes(leaf)),
                };
                spend.txdata.Init(spend.tx_spend, {spend.tx_credit.vout[0]});

                FlatSigningProvider provider;
                provider.pqc_keys.emplace(pubkey, key);
                MutableTransactionSignatureCreator creator{
                    spend.tx_spend,
                    /*input_idx=*/0,
                    spend.tx_credit.vout[0].nValue,
                    &spend.txdata,
                    hash_type,
                };
                std::vector<unsigned char> sig;
                const bool signed_ok{creator.CreatePQCSignature(provider, sig, pubkey, &spend.leaf_hash, SigVersion::P2MR)};
                assert(signed_ok);
                spend.tx_spend.vin[0].scriptWitness.stack[0] = std::move(sig);
                assert(VerifySpend(spend, P2MR_SCRIPT_VERIFY_FLAGS));

                const uint256 wtxid{CTransaction{spend.tx_spend}.GetWitnessHash().ToUint256()};
                P2MRFixture fixture{.spend = std::move(spend), .wtxid = wtxid};
                out.push_back(std::move(fixture));
            }
        }
        return out;
    }();
    return fixtures;
}

void FixtureP2MRScriptInput(FuzzedDataProvider& fuzzed_data_provider)
{
    const auto& fixtures{GetP2MRFixtures()};
    const P2MRFixture& fixture{fixtures[fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, fixtures.size() - 1)]};
    P2MRSpend spend{fixture.spend};
    std::vector<valtype>& stack{spend.tx_spend.vin[0].scriptWitness.stack};
    unsigned int flags{P2MR_SCRIPT_VERIFY_FLAGS};
    bool tx_changed{false};

    // The fixture witness is [signature, leaf script, control block].
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 8) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (stack.empty() || stack[0].empty()) return;
                const size_t pos{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, stack[0].size() - 1)};
                stack[0][pos] ^= static_cast<unsigned char>(1U << fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 7));
            },
            [&] {
                if (stack.empty()) return;
                stack[0].resize(PQC_SIG_SIZE + 1);
                stack[0].back() = fuzzed_data_provider.ConsumeIntegral<unsigned char>();
            },
            [&] {
                if (stack.empty()) return;
                stack[0].resize(PQC_SIG_SIZE);
            },
            [&] {
                if (stack.size() < 2) return;
                stack[1] = ScriptBytes(ConsumeScript(fuzzed_data_provider));
            },
            [&] {
                if (stack.size() < 3 || stack[2].empty()) return;
                CallOneOf(
                    fuzzed_data_provider,
                    [&] { stack[2][0] ^= 0x01; },
                    [&] { stack[2].pop_back(); },
                    [&] { stack[2].push_back(fuzzed_data_provider.ConsumeIntegral<unsigned char>()); });
            },
            [&] {
                stack.push_back(std::vector<unsigned char>{static_cast<unsigned char>(ANNEX_TAG), fuzzed_data_provider.ConsumeIntegral<unsigned char>()});
            },
            [&] {
                stack.insert(stack.begin(), ConsumeRandomLengthByteVector(fuzzed_data_provider, /*max_length=*/128));
            },
            [&] {
                if (!stack.empty()) stack.pop_back();
            },
            [&] {
                spend.tx_spend.nLockTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                tx_changed = true;
            },
            [&] {
                spend.tx_spend.vout[0].nValue = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 2000);
                tx_changed = true;
            },
            [&] {
                spend.tx_spend.vin[0].nSequence = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                tx_changed = true;
            },
            [&] {
                flags |= fuzzed_data_provider.PickValueInArray<unsigned int>({
                    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
                    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                });
            });
    }

    if (tx_changed) {
        // Witness data is not part of the precomputed hashes, transaction fields are.
        spend.txdata = PrecomputedTransactionData{};
        spend.txdata.Init(spend.tx_spend, {spend.tx_credit.vout[0]});
    }

    const bool untouched{flags == P2MR_SCRIPT_VERIFY_FLAGS &&
                         CTransaction{spend.tx_spend}.GetWitnessHash().ToUint256() == fixture.wtxid};
    const bool valid{VerifySpend(spend, flags)};
    // The fixture was accepted when it was built, so an unmodified clone must still be accepted.
    if (untouched) assert(valid);
}

void LegacyP2MRScriptInput(FuzzedDataProvider& fuzzed_data_provider)
{
    const CPQCKey key = ConsumePQCKey(fuzzed_data_provider);
    if (!key.IsValid()) return;
    const CPQCPubKey pubkey = key.GetPubKey();
    if (!pubkey.IsValid()) return;

    LeafConfig leaf = BuildLeafConfig(fuzzed_data_provider, pubkey);
    if (fuzzed_data_provider.ConsumeBool()) {
        leaf.witness_leaf = ConsumeScript(fuzzed_data_provider);
    }

    const std::optional<P2MRSpend> spend = BuildSpend(leaf.committed_leaf, leaf.witness_leaf, leaf.stack_items, fuzzed_data_provider);
    if (!spend || spend->tx_credit.vout.empty() || spend->tx_spend.vin.empty()) return;

    P2MRSpend spend_value = *spend;
    MaybeReplaceSignature(fuzzed_data_provider, key, leaf.signing_pubkey, spend_value);

    unsigned int flags = P2MR_SCRIPT_VERIFY_FLAGS;
    if (fuzzed_data_provider.ConsumeBool()) flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;
    if (fuzzed_data_provider.ConsumeBool()) flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;
    if (fuzzed_data_provider.ConsumeBool()) flags |= SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS;

    (void)VerifySpend(spend_value, flags);
}
} // namespace

FUZZ_TARGET(p2mr_script, .init = initialize_p2mr_script)
{
    const TaggedInput input{ParseTaggedInput(buffer, 'M')};
    FuzzedDataProvider fuzzed_data_provider(input.data.data(), input.data.size());
    switch (input.mode) {
    case InputMode::LEGACY:
    case InputMode::GENERATION:
        LegacyP2MRScriptInput(fuzzed_data_provider);
        return;
    case InputMode::FIXTURE:
        FixtureP2MRScriptInput(fuzzed_data_provider);
        return;
    case InputMode::UNSUPPORTED_VERSION:
        return;
    }
}
