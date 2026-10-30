// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {
using valtype = std::vector<unsigned char>;

constexpr size_t CAP{MAX_STANDARD_P2MR_RUNTIME_STACK_BYTES};
constexpr size_t ITEM{MAX_P2MR_V1_STACK_ITEM_SIZE};
constexpr unsigned int CAP_FLAG{SCRIPT_VERIFY_P2MR_RUNTIME_STACK_BYTES};

static_assert(MAX_STANDARD_P2MR_RUNTIME_STACK_BYTES == 1024 * 1024);
static_assert(CAP % ITEM == 0 && CAP / ITEM == 64);
static_assert((STANDARD_SCRIPT_VERIFY_FLAGS & CAP_FLAG) != 0);
static_assert((STANDARD_NOT_MANDATORY_VERIFY_FLAGS & CAP_FLAG) != 0);
static_assert((MANDATORY_SCRIPT_VERIFY_FLAGS & CAP_FLAG) == 0);

struct ScriptResult {
    bool ok;
    ScriptError err;
};

ScriptResult VerifyP2MRLeaf(const CScript& leaf, const std::vector<valtype>& args, unsigned int flags)
{
    const valtype control{static_cast<unsigned char>(P2MR_LEAF_VERSION_V1 | 1)};
    const valtype leaf_bytes{leaf.begin(), leaf.end()};
    const uint256 root{ComputeP2MRMerkleRoot(control, ComputeP2MRLeafHash(P2MR_LEAF_VERSION_V1, leaf_bytes))};
    const CTransaction tx_credit{BuildCreditingTransaction(CScript{} << OP_2 << ToByteVector(root), /*nValue=*/1000)};

    CScriptWitness witness;
    witness.stack = args;
    witness.stack.push_back(leaf_bytes);
    witness.stack.push_back(control);
    const CMutableTransaction tx_spend{BuildSpendingTransaction(CScript{}, witness, tx_credit)};

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {tx_credit.vout[0]});
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool ok{VerifyScript(
        tx_spend.vin[0].scriptSig,
        tx_credit.vout[0].scriptPubKey,
        &tx_spend.vin[0].scriptWitness,
        flags,
        MutableTransactionSignatureChecker(&tx_spend, 0, tx_credit.vout[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL),
        &err)};
    return {ok, err};
}

ScriptResult Eval(std::vector<valtype>& stack, const CScript& script, unsigned int flags, SigVersion sigversion = SigVersion::P2MR)
{
    ScriptExecutionData execdata;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool ok{EvalScript(stack, script, flags, BaseSignatureChecker{}, sigversion, execdata, &err)};
    return {ok, err};
}

size_t StackBytes(const std::vector<valtype>& stack)
{
    size_t bytes{0};
    for (const valtype& item : stack) bytes += item.size();
    return bytes;
}

CScript Repeat(CScript script, opcodetype opcode, size_t count)
{
    for (size_t i{0}; i < count; ++i) script << opcode;
    return script;
}

/** Drop `items` stack items and leave a single true value. */
CScript Cleanup(CScript script, size_t items)
{
    return Repeat(std::move(script), OP_DROP, items) << OP_TRUE;
}

/**
 * Run a leaf whose peak runtime stack is exactly CAP bytes plus the size of
 * the bottom witness item. With an empty bottom item the spend must pass under
 * standard flags; with a one-byte bottom item it must fail with the policy
 * error. Consensus flags, and standard flags without the new flag, must
 * accept both.
 */
void CheckCapBoundary(const std::string& name, const CScript& leaf, const std::vector<valtype>& upper_args)
{
    BOOST_TEST_CONTEXT(name)
    {
        for (const size_t pad : {size_t{0}, size_t{1}}) {
            std::vector<valtype> args{valtype(pad, 0x01)};
            args.insert(args.end(), upper_args.begin(), upper_args.end());

            const ScriptResult standard{VerifyP2MRLeaf(leaf, args, STANDARD_SCRIPT_VERIFY_FLAGS)};
            BOOST_CHECK_EQUAL(standard.ok, pad == 0);
            BOOST_CHECK_EQUAL(standard.err, pad == 0 ? SCRIPT_ERR_OK : SCRIPT_ERR_P2MR_RUNTIME_STACK_BYTES);

            for (const unsigned int flags : {MANDATORY_SCRIPT_VERIFY_FLAGS, STANDARD_SCRIPT_VERIFY_FLAGS & ~CAP_FLAG}) {
                const ScriptResult unlimited{VerifyP2MRLeaf(leaf, args, flags)};
                BOOST_CHECK(unlimited.ok);
                BOOST_CHECK_EQUAL(unlimited.err, SCRIPT_ERR_OK);
            }
        }
    }
}

valtype Item(size_t size = ITEM, unsigned char fill = 0x01)
{
    return valtype(size, fill);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_p2mr_runtime_stack_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dup_drop_amplification_is_policy_only)
{
    // One 16 KiB witness item duplicated to the 1,000-item stack limit holds
    // about 16 MiB at once while staying within every consensus limit.
    const CScript leaf{Repeat(Repeat(CScript{}, OP_DUP, 999), OP_DROP, 999)};
    const std::vector<valtype> args{Item()};

    const ScriptResult standard{VerifyP2MRLeaf(leaf, args, STANDARD_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!standard.ok);
    BOOST_CHECK_EQUAL(standard.err, SCRIPT_ERR_P2MR_RUNTIME_STACK_BYTES);

    for (const unsigned int flags : {MANDATORY_SCRIPT_VERIFY_FLAGS, STANDARD_SCRIPT_VERIFY_FLAGS & ~CAP_FLAG}) {
        const ScriptResult unlimited{VerifyP2MRLeaf(leaf, args, flags)};
        BOOST_CHECK(unlimited.ok);
        BOOST_CHECK_EQUAL(unlimited.err, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(flag_off_preserves_existing_errors)
{
    // Spends that already fail keep their exact error code when the new flag is
    // unset, including scripts whose runtime stack would exceed the cap.
    const CScript over_cap_then_verify_fails{Repeat(CScript{}, OP_DUP, 64) << OP_0 << OP_VERIFY};
    const ScriptResult unflagged{VerifyP2MRLeaf(over_cap_then_verify_fails, {Item()}, STANDARD_SCRIPT_VERIFY_FLAGS & ~CAP_FLAG)};
    BOOST_CHECK(!unflagged.ok);
    BOOST_CHECK_EQUAL(unflagged.err, SCRIPT_ERR_VERIFY);
    const ScriptResult flagged{VerifyP2MRLeaf(over_cap_then_verify_fails, {Item()}, STANDARD_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!flagged.ok);
    BOOST_CHECK_EQUAL(flagged.err, SCRIPT_ERR_P2MR_RUNTIME_STACK_BYTES);

    // The item-count limit still wins when both limits trip on the same opcode.
    std::vector<valtype> stack(MAX_STACK_SIZE, Item(CAP / MAX_STACK_SIZE));
    BOOST_REQUIRE_LE(StackBytes(stack), CAP);
    const ScriptResult both{Eval(stack, CScript{} << OP_DUP, STANDARD_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!both.ok);
    BOOST_CHECK_EQUAL(both.err, SCRIPT_ERR_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(copying_opcode_boundaries)
{
    CheckCapBoundary("OP_DUP", Cleanup(Repeat(CScript{}, OP_DUP, 63), 65), {Item()});
    CheckCapBoundary("OP_2DUP", Cleanup(Repeat(CScript{}, OP_2DUP, 31), 65), {Item(), Item()});
    CheckCapBoundary("OP_3DUP", Cleanup(Repeat(CScript{}, OP_3DUP, 63), 193),
                     {Item(5461), Item(5461), Item(ITEM - 2 * 5461)});
    CheckCapBoundary("OP_OVER", Cleanup(Repeat(CScript{}, OP_OVER, 62), 65), {Item(), Item()});
    CheckCapBoundary("OP_2OVER", Cleanup(Repeat(CScript{}, OP_2OVER, 30), 65), {Item(), Item(), Item(), Item()});
    CheckCapBoundary("OP_TUCK", Cleanup(Repeat(CScript{}, OP_TUCK, 62), 65), {Item(), Item()});
    CheckCapBoundary("OP_IFDUP", Cleanup(Repeat(CScript{}, OP_IFDUP, 63), 65), {Item()});

    // OP_PICK at increasing depths; each numeric argument is popped before the copy.
    CScript pick;
    for (int depth{0}; depth < 63; ++depth) pick << depth << OP_PICK;
    CheckCapBoundary("OP_PICK", Cleanup(pick, 65), {Item()});
}

BOOST_AUTO_TEST_CASE(non_copying_opcode_boundaries)
{
    // OP_ROLL moves the half-size item from below the six-item window to the
    // top; only its numeric argument leaves the stack.
    CScript roll{Repeat(CScript{}, OP_DUP, 61)};
    roll << 62 << OP_ROLL << OP_DUP << 2 << OP_PICK;
    CheckCapBoundary("OP_ROLL", Cleanup(roll, 66), {Item(ITEM / 2), Item()});

    // OP_2ROT, OP_ROT, OP_SWAP and OP_2SWAP permute six distinct sizes, leaving
    // the full-size item on top.
    CScript rearranged;
    rearranged << OP_2ROT << OP_ROT << OP_SWAP << OP_2SWAP;
    CheckCapBoundary("rearrangements", Cleanup(Repeat(rearranged, OP_DUP, 62), 69),
                     {Item(), Item(ITEM / 2), Item(ITEM / 4), Item(ITEM / 8), Item(ITEM / 16), Item(ITEM / 16)});

    // Literal pushes count as they are made: 31 x 520 + 264 bytes completes the last 16 KiB.
    CScript pushes{Repeat(CScript{}, OP_DUP, 62)};
    for (int i{0}; i < 31; ++i) pushes << Item(MAX_SCRIPT_ELEMENT_SIZE, 0x02);
    pushes << Item(ITEM - 31 * MAX_SCRIPT_ELEMENT_SIZE, 0x02);
    CheckCapBoundary("pushes", Cleanup(pushes, 96), {Item()});

    // Replacing an item by its hash releases its bytes before the copies.
    CScript hashed;
    hashed << OP_SHA256 << OP_DROP;
    CheckCapBoundary("hash", Cleanup(Repeat(hashed, OP_DUP, 63), 65), {Item(), Item()});
}

BOOST_AUTO_TEST_CASE(altstack_bytes_count)
{
    // Half of the items move to the altstack and some return. If the altstack
    // were not counted, the one-byte-over case would stay at 33 items' worth.
    CScript leaf{Repeat(CScript{}, OP_DUP, 31)};
    leaf = Repeat(std::move(leaf), OP_TOALTSTACK, 31);
    leaf = Repeat(std::move(leaf), OP_FROMALTSTACK, 10);
    leaf = Repeat(std::move(leaf), OP_DUP, 32);
    CheckCapBoundary("altstack", Cleanup(leaf, 44), {Item()});

    // At the cap with 63 of 64 items on the altstack, one more copy fails.
    std::vector<valtype> stack{Item()};
    const ScriptResult altstack_heavy{Eval(stack, Repeat(Repeat(CScript{}, OP_DUP, 63), OP_TOALTSTACK, 63) << OP_DUP, STANDARD_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!altstack_heavy.ok);
    BOOST_CHECK_EQUAL(altstack_heavy.err, SCRIPT_ERR_P2MR_RUNTIME_STACK_BYTES);
    BOOST_CHECK_EQUAL(stack.size(), 2U);
}

BOOST_AUTO_TEST_CASE(initial_stack_and_sigversion_gating)
{
    // EvalScript accounts for the stack it is handed, at exactly CAP and one byte over.
    std::vector<valtype> at_cap(CAP / ITEM, Item());
    BOOST_CHECK(Eval(at_cap, CScript{}, STANDARD_SCRIPT_VERIFY_FLAGS).ok);
    std::vector<valtype> over_cap(CAP / ITEM, Item());
    over_cap.emplace_back(1, 0x01);
    const ScriptResult over{Eval(over_cap, CScript{}, STANDARD_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!over.ok);
    BOOST_CHECK_EQUAL(over.err, SCRIPT_ERR_P2MR_RUNTIME_STACK_BYTES);

    // The flag only applies to P2MR execution.
    std::vector<valtype> tapscript_stack{Item()};
    const ScriptResult tapscript{Eval(tapscript_stack, Repeat(CScript{}, OP_DUP, 200), STANDARD_SCRIPT_VERIFY_FLAGS, SigVersion::TAPSCRIPT)};
    BOOST_CHECK(tapscript.ok);
    BOOST_CHECK_EQUAL(StackBytes(tapscript_stack), 201 * ITEM);
}

BOOST_AUTO_TEST_CASE(running_total_matches_rescan)
{
    // Random P2MR scripts run once with the flag, and once opcode by opcode
    // without it while rescanning both stacks after every opcode. The flagged
    // run must stop exactly where the rescan first exceeds CAP, and otherwise
    // match the unflagged result. Single-opcode EvalScript calls lose the
    // altstack, so the stepwise run applies OP_TOALTSTACK and OP_FROMALTSTACK
    // itself.
    static constexpr std::array<opcodetype, 28> STACK_OPCODES{
        OP_DUP, OP_2DUP, OP_3DUP, OP_OVER, OP_2OVER, OP_PICK, OP_ROLL, OP_TUCK, OP_IFDUP,
        OP_DROP, OP_2DROP, OP_NIP, OP_ROT, OP_SWAP, OP_2SWAP, OP_2ROT, OP_TOALTSTACK, OP_FROMALTSTACK,
        OP_DEPTH, OP_SIZE, OP_EQUAL, OP_SHA256, OP_HASH160, OP_RIPEMD160, OP_SHA1, OP_HASH256,
        OP_NOP, OP_ADD,
    };
    const unsigned int flags{MANDATORY_SCRIPT_VERIFY_FLAGS};
    constexpr int ITERATIONS{500};

    int breaches{0};
    for (int iteration{0}; iteration < ITERATIONS; ++iteration) {
        std::vector<valtype> initial;
        // Start near the cap so that copies regularly cross it.
        const size_t target{CAP / 2 + m_rng.randrange(CAP / 2)};
        while (StackBytes(initial) < target) {
            const size_t size{m_rng.randrange(4) == 0 ? m_rng.randrange(5) : 1 + m_rng.randrange(ITEM)};
            initial.emplace_back(size, static_cast<unsigned char>(1 + m_rng.randrange(255)));
        }

        CScript script;
        const auto add{[&](const CScript& step) { script.insert(script.end(), step.begin(), step.end()); }};
        for (int i{0}; i < 150; ++i) {
            const opcodetype opcode{STACK_OPCODES[m_rng.randrange(STACK_OPCODES.size())]};
            if (opcode == OP_PICK || opcode == OP_ROLL) add(CScript{} << static_cast<int64_t>(m_rng.randrange(initial.size() + 4)));
            // Numeric operands must be small, so derive them from OP_SIZE/OP_DEPTH.
            if (opcode == OP_ADD) {
                add(CScript{} << OP_SIZE);
                add(CScript{} << OP_DEPTH);
            }
            if (m_rng.randrange(8) == 0) add(CScript{} << valtype(m_rng.randrange(MAX_SCRIPT_ELEMENT_SIZE + 1), 0x42));
            add(CScript{} << opcode);
        }

        std::vector<valtype> stepped{initial};
        std::vector<valtype> stepped_alt;
        std::optional<std::vector<valtype>> breach_stack;
        if (StackBytes(initial) > CAP) breach_stack = initial;
        ScriptResult stepped_result{true, SCRIPT_ERR_OK};
        CScript::const_iterator pc{script.begin()};
        while (pc < script.end()) {
            const CScript::const_iterator step_begin{pc};
            opcodetype opcode;
            BOOST_REQUIRE(script.GetOp(pc, opcode));
            if (opcode == OP_TOALTSTACK || opcode == OP_FROMALTSTACK) {
                auto& from{opcode == OP_TOALTSTACK ? stepped : stepped_alt};
                auto& to{opcode == OP_TOALTSTACK ? stepped_alt : stepped};
                if (from.empty()) {
                    stepped_result = {false, opcode == OP_TOALTSTACK ? SCRIPT_ERR_INVALID_STACK_OPERATION : SCRIPT_ERR_INVALID_ALTSTACK_OPERATION};
                    break;
                }
                to.push_back(std::move(from.back()));
                from.pop_back();
            } else {
                stepped_result = Eval(stepped, CScript{step_begin, pc}, flags);
                if (!stepped_result.ok) break;
            }
            BOOST_REQUIRE_LE(stepped.size() + stepped_alt.size(), size_t{MAX_STACK_SIZE});
            if (!breach_stack && StackBytes(stepped) + StackBytes(stepped_alt) > CAP) breach_stack = stepped;
        }

        std::vector<valtype> unflagged{initial};
        const ScriptResult unflagged_result{Eval(unflagged, script, flags)};
        BOOST_CHECK_EQUAL(unflagged_result.ok, stepped_result.ok);
        BOOST_CHECK_EQUAL(unflagged_result.err, stepped_result.err);
        BOOST_CHECK(unflagged == stepped);

        std::vector<valtype> flagged{initial};
        const ScriptResult flagged_result{Eval(flagged, script, flags | CAP_FLAG)};
        if (breach_stack) {
            ++breaches;
            BOOST_CHECK(!flagged_result.ok);
            BOOST_CHECK_EQUAL(flagged_result.err, SCRIPT_ERR_P2MR_RUNTIME_STACK_BYTES);
            BOOST_CHECK(flagged == *breach_stack);
        } else {
            BOOST_CHECK_EQUAL(flagged_result.ok, unflagged_result.ok);
            BOOST_CHECK_EQUAL(flagged_result.err, unflagged_result.err);
            BOOST_CHECK(flagged == unflagged);
        }
    }
    // Both outcomes must occur for the comparison to mean anything.
    BOOST_TEST_MESSAGE("runtime stack byte breaches: " << breaches << "/" << ITERATIONS);
    BOOST_CHECK_GT(breaches, 0);
    BOOST_CHECK_LT(breaches, ITERATIONS);
}

BOOST_AUTO_TEST_SUITE_END()
