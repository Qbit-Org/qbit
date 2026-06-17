// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <crypto/pqc.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/transaction_utils.h>

#include <cassert>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {
using valtype = std::vector<unsigned char>;

constexpr unsigned int P2MR_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_P2SH |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_P2MR_RULES
};

valtype ScriptBytes(const CScript& script)
{
    return valtype(script.begin(), script.end());
}

CScript BuildP2MRScriptPubKey(const uint256& merkle_root)
{
    return CScript{} << OP_2 << ToByteVector(merkle_root);
}

struct PQCVerifyBenchData {
    CPQCPubKey pubkey;
    uint256 hash;
    std::vector<unsigned char> signature;
};

PQCVerifyBenchData BuildPQCVerifyBenchData()
{
    CPQCKey key;
    key.MakeNewKey();
    assert(key.IsValid());

    const CPQCPubKey pubkey = key.GetPubKey();
    assert(pubkey.IsValid());

    const uint256 hash = (HashWriter{} << 0x494244 << 0x505143).GetHash();

    uint32_t counter{0};
    std::vector<unsigned char> signature;
    assert(key.Sign(hash, signature, counter));
    assert(counter == 1U);
    assert(pubkey.Verify(hash, signature));

    return {pubkey, hash, signature};
}

struct P2MRVerifyScriptBenchData {
    CTransaction tx_credit;
    CMutableTransaction tx_spend;
    PrecomputedTransactionData txdata;
};

P2MRVerifyScriptBenchData BuildP2MRVerifyScriptBenchData()
{
    CPQCKey key;
    key.MakeNewKey();
    assert(key.IsValid());

    const CPQCPubKey pubkey = key.GetPubKey();
    assert(pubkey.IsValid());

    const CScript leaf_script = CScript{} << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIGPQC;
    const uint256 tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, ScriptBytes(leaf_script));
    const std::vector<unsigned char> control_block{static_cast<unsigned char>(P2MR_LEAF_VERSION | 1)};
    const uint256 merkle_root = ComputeP2MRMerkleRoot(control_block, tapleaf_hash);

    const CMutableTransaction tx_credit_mut = BuildCreditingTransaction(BuildP2MRScriptPubKey(merkle_root), /*nValue=*/1000);
    const CTransaction tx_credit{tx_credit_mut};

    CScriptWitness witness;
    witness.stack.emplace_back(PQC_SIG_SIZE, 0x00);
    witness.stack.push_back(ScriptBytes(leaf_script));
    witness.stack.push_back(control_block);

    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, witness, tx_credit);

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash = tapleaf_hash;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;

    uint256 sighash;
    assert(SignatureHashP2MR(
        sighash,
        execdata,
        tx_spend,
        /*in_pos=*/0,
        SIGHASH_DEFAULT,
        txdata,
        MissingDataBehavior::ASSERT_FAIL));

    uint32_t counter{0};
    std::vector<unsigned char> raw_signature;
    assert(key.Sign(sighash, raw_signature, counter));
    assert(counter == 1U);

    tx_spend.vin[0].scriptWitness.stack[0] = raw_signature;

    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool success = VerifyScript(
        tx_spend.vin[0].scriptSig,
        tx_credit.vout[0].scriptPubKey,
        &tx_spend.vin[0].scriptWitness,
        P2MR_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(
            &tx_spend,
            0,
            tx_credit.vout[0].nValue,
            txdata,
            MissingDataBehavior::ASSERT_FAIL),
        &err);
    assert(success);
    assert(err == SCRIPT_ERR_OK);

    return {tx_credit, tx_spend, txdata};
}

std::array<unsigned char, 32> BuildPQCSeed()
{
    std::array<unsigned char, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<unsigned char>(i);
    }
    return seed;
}

} // namespace

static void DerivePQCKeyBench(benchmark::Bench& bench)
{
    const auto seed = BuildPQCSeed();
    uint32_t index{0};
    bench.batch(1).unit("key").minEpochIterations(5).run([&] {
        CPQCKey key;
        assert(DerivePQCKey(std::span<const unsigned char>{seed}, /*account=*/0, /*change=*/0, index++, key));
        assert(key.IsValid());
    });
}

static void PQCVerify(benchmark::Bench& bench)
{
    const auto data = BuildPQCVerifyBenchData();
    bench.batch(1).unit("sig").minEpochIterations(10).run([&] {
        assert(data.pubkey.Verify(data.hash, data.signature));
    });
}

static void VerifyScriptP2MRChecksigPQC(benchmark::Bench& bench)
{
    const auto data = BuildP2MRVerifyScriptBenchData();
    bench.batch(1).unit("spend").minEpochIterations(5).run([&] {
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool success = VerifyScript(
            data.tx_spend.vin[0].scriptSig,
            data.tx_credit.vout[0].scriptPubKey,
            &data.tx_spend.vin[0].scriptWitness,
            P2MR_SCRIPT_VERIFY_FLAGS,
            MutableTransactionSignatureChecker(
                &data.tx_spend,
                0,
                data.tx_credit.vout[0].nValue,
                data.txdata,
                MissingDataBehavior::ASSERT_FAIL),
            &err);
        assert(success);
        assert(err == SCRIPT_ERR_OK);
    });
}

BENCHMARK(DerivePQCKeyBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(PQCVerify, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyScriptP2MRChecksigPQC, benchmark::PriorityLevel::HIGH);
