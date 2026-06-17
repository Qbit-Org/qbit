// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_PUSHDATA_H
#define QBIT_SCRIPT_PUSHDATA_H

#include <script/script.h>

constexpr bool IsPushdataOp(opcodetype opcode)
{
    return opcode > OP_FALSE && opcode <= OP_PUSHDATA4;
}

#endif // QBIT_SCRIPT_PUSHDATA_H
