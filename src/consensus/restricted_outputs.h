// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_CONSENSUS_RESTRICTED_OUTPUTS_H
#define QBIT_CONSENSUS_RESTRICTED_OUTPUTS_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <algorithm>
#include <vector>

namespace Consensus {

inline bool IsRestrictedOutputModeP2MROutput(const CScript& script_pub_key)
{
    int witness_version;
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) {
        return false;
    }
    return witness_version == 2 && witness_program.size() == WITNESS_V2_P2MR_SIZE;
}

inline bool IsRestrictedOutputModeExemptOutput(const CScript& script_pub_key)
{
    return (!script_pub_key.empty() && script_pub_key[0] == OP_RETURN) || script_pub_key.IsPayToAnchor();
}

inline bool IsRestrictedOutputModeConsensusOutput(const CScript& script_pub_key, const Params& consensus, int height)
{
    return IsRestrictedOutputModeP2MROutput(script_pub_key) ||
           (consensus.OuterReservedWitnessActiveAtHeight(height) &&
            IsReservedFutureWitnessOutput(script_pub_key)) ||
           IsRestrictedOutputModeExemptOutput(script_pub_key);
}

inline bool HasOnlyRestrictedOutputModeOutputs(const CTransaction& tx, const Params& consensus, int height)
{
    return std::all_of(tx.vout.begin(), tx.vout.end(), [&](const CTxOut& txout) {
        return IsRestrictedOutputModeConsensusOutput(txout.scriptPubKey, consensus, height);
    });
}

} // namespace Consensus

#endif // QBIT_CONSENSUS_RESTRICTED_OUTPUTS_H
