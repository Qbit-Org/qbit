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
#include <cstdint>
#include <optional>
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
} // namespace

FUZZ_TARGET(p2mr_script, .init = initialize_p2mr_script)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

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
