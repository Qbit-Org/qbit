// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_SCRIPTNUM_PARSING_H
#define QBIT_SCRIPT_SCRIPTNUM_PARSING_H

#include <script/pushdata.h>

#include <optional>
#include <vector>

namespace script {

inline constexpr bool IsSmallIntegerOpcode(opcodetype opcode)
{
    return opcode >= OP_1 && opcode <= OP_16;
}

/** Retrieve a minimally-encoded number in range [min,max] from an (opcode, data) pair,
 *  whether it's OP_n or through a push. */
inline std::optional<int> GetScriptNumber(opcodetype opcode, const std::vector<unsigned char>& data, int min, int max)
{
    int count;
    if (IsSmallIntegerOpcode(opcode)) {
        count = CScript::DecodeOP_N(opcode);
    } else if (IsPushdataOp(opcode)) {
        if (!CheckMinimalPush(data, opcode)) return {};
        try {
            count = CScriptNum(data, /* fRequireMinimal = */ true).getint();
        } catch (const scriptnum_error&) {
            return {};
        }
    } else {
        return {};
    }
    if (count < min || count > max) return {};
    return count;
}

} // namespace script

#endif // QBIT_SCRIPT_SCRIPTNUM_PARSING_H
