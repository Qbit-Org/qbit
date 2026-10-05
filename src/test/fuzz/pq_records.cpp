// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bip324_pq.h>
#include <crypto/mlkem.h>
#include <span.h>
#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace {

/** What the version-contents grammar says about an input, computed without the serialization code. */
struct Expected {
    bool valid{false};
    //! Offset and length of the first PQ_MLKEM1024 record's payload.
    std::optional<std::pair<size_t, size_t>> first;
};

/**
 * An independent reading of the record grammar: CompactSize(len) || header || payload, len >= 1,
 * with the minimal CompactSize encoding and no bytes left over. Lengths above MAX_SIZE need more
 * input than any fuzz input has, so "longer than what is left" covers them.
 */
Expected Oracle(std::span<const uint8_t> in)
{
    Expected expected;
    size_t pos{0};
    while (pos < in.size()) {
        const uint8_t tag{in[pos++]};
        uint64_t len{tag};
        if (tag >= 0xfd) {
            const size_t width{tag == 0xfd ? 2U : tag == 0xfe ? 4U : 8U};
            const uint64_t minimum{tag == 0xfd ? 0xfdU : tag == 0xfe ? 0x10000U : 0x100000000U};
            if (in.size() - pos < width) return {};
            len = 0;
            for (size_t i{0}; i < width; ++i) len |= uint64_t{in[pos + i]} << (8 * i);
            pos += width;
            if (len < minimum) return {};
        }
        if (len == 0 || len > in.size() - pos) return {};
        if (in[pos] == PQ_MLKEM1024 && !expected.first) expected.first = {pos + 1, size_t(len - 1)};
        pos += size_t(len);
    }
    expected.valid = true;
    return expected;
}

void CheckParse(std::span<const uint8_t> in)
{
    const auto contents{std::as_bytes(in)};
    const auto parsed{PQHandshake::ParseContents(contents)};
    const Expected expected{Oracle(in)};
    if (!expected.valid) {
        assert(parsed.kind == PQHandshake::ParseKind::INVALID_GRAMMAR);
        assert(parsed.payload.empty());
    } else if (!expected.first) {
        assert(parsed.kind == PQHandshake::ParseKind::NO_RECORD);
        assert(parsed.payload.empty());
    } else {
        assert(parsed.kind == PQHandshake::ParseKind::OWN_RECORD);
        // The payload points into the contents, at the first own record.
        assert(parsed.payload.data() == contents.data() + expected.first->first);
        assert(parsed.payload.size() == expected.first->second);
    }
}

} // namespace

FUZZ_TARGET(pq_records)
{
    CheckParse(buffer);

    // A record built from the first payload bytes parses back to them, and as the first record of
    // longer contents it wins if, and only if, the rest is valid grammar.
    if (buffer.size() < mlkem::PUBLIC_KEY_BYTES) return;
    const auto record{PQHandshake::SerializeRecord(buffer.first<mlkem::PUBLIC_KEY_BYTES>())};
    const auto alone{PQHandshake::ParseContents(record)};
    assert(alone.kind == PQHandshake::ParseKind::OWN_RECORD);
    assert(alone.payload.data() == record.data() + 4);
    assert(std::ranges::equal(alone.payload, std::as_bytes(buffer.first<mlkem::PUBLIC_KEY_BYTES>())));

    std::vector<uint8_t> combined(record.size() + buffer.size());
    std::ranges::copy(MakeUCharSpan(record), combined.begin());
    std::ranges::copy(buffer, combined.begin() + record.size());
    CheckParse(combined);
    const auto parsed{PQHandshake::ParseContents(std::as_bytes(std::span{combined}))};
    assert((parsed.kind == PQHandshake::ParseKind::OWN_RECORD) == Oracle(buffer).valid);
}
