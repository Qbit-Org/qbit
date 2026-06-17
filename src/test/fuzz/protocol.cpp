// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <array>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {
[[nodiscard]] CInv ConsumeInv(FuzzedDataProvider& fuzzed_data_provider)
{
    static constexpr std::array<uint32_t, 7> INV_TYPES{
        MSG_TX,
        MSG_BLOCK,
        MSG_WTX,
        MSG_FILTERED_BLOCK,
        MSG_CMPCT_BLOCK,
        MSG_WITNESS_BLOCK,
        MSG_WITNESS_TX,
    };
    return {fuzzed_data_provider.PickValueInArray(INV_TYPES), ConsumeUInt256(fuzzed_data_provider)};
}
} // namespace

FUZZ_TARGET(protocol, .disable_leak_detection = true)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const CInv inv = ConsumeInv(fuzzed_data_provider);
    (void)inv.GetMessageType();
    (void)inv.ToString();
    const CInv another_inv = ConsumeInv(fuzzed_data_provider);
    (void)(inv < another_inv);
}
