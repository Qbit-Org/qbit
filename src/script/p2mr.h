// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_SCRIPT_P2MR_H
#define QBIT_SCRIPT_P2MR_H

#include <crypto/pqc.h>
#include <script/script.h>
#include <script/scriptnum_parsing.h>

#include <optional>
#include <span>
#include <vector>

namespace p2mr {

inline CScript BuildPKScript(const CPQCPubKey& pubkey)
{
    return CScript{} << std::vector<unsigned char>{pubkey.begin(), pubkey.end()} << OP_CHECKSIGPQC;
}

inline std::optional<CPQCPubKey> MatchPK(const CScript& script)
{
    constexpr unsigned char PUBKEY_PUSH_SIZE = static_cast<unsigned char>(CPQCPubKey::SIZE);
    constexpr size_t PK_SCRIPT_SIZE = 1 + CPQCPubKey::SIZE + 1;
    if (script.size() != PK_SCRIPT_SIZE || script[0] != PUBKEY_PUSH_SIZE || script[CPQCPubKey::SIZE + 1] != OP_CHECKSIGPQC) {
        return std::nullopt;
    }
    CPQCPubKey pubkey{std::span<const unsigned char>{script}.subspan(1, CPQCPubKey::SIZE)};
    if (!pubkey.IsValid()) return std::nullopt;
    return pubkey;
}

struct MultiAScriptData {
    int threshold;
    std::vector<std::span<const unsigned char>> keyspans;
};

inline std::optional<MultiAScriptData> MatchMultiA(const CScript& script)
{
    std::vector<std::span<const unsigned char>> keyspans;

    // Redundant, but very fast and selective test.
    if (script.empty() || script[0] != 32 || script.back() != OP_NUMEQUAL) return {};

    auto it = script.begin();
    while (script.end() - it >= 34) {
        if (*it != 32) return {};
        ++it;
        keyspans.emplace_back(&*it, 32);
        it += 32;
        if (*it != (keyspans.size() == 1 ? OP_CHECKSIGPQC : OP_CHECKSIGADD)) return {};
        ++it;
    }
    if (keyspans.empty() || keyspans.size() > MAX_PUBKEYS_PER_MULTI_A) return {};

    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(it, opcode, data)) return {};
    if (it == script.end()) return {};
    if (*it != OP_NUMEQUAL) return {};
    ++it;
    if (it != script.end()) return {};

    auto threshold = script::GetScriptNumber(opcode, data, 1, static_cast<int>(keyspans.size()));
    if (!threshold) return {};

    return MultiAScriptData{*threshold, std::move(keyspans)};
}

} // namespace p2mr

#endif // QBIT_SCRIPT_P2MR_H
