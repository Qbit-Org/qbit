// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bip324_pq.h>

#include <random.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <util/check.h>

#include <algorithm>
#include <ios>

namespace {

void StrongFill32(void*, std::span<uint8_t, 32> out) noexcept
{
    GetStrongRandBytes(out);
}

const PQKemOps DEFAULT_KEM_OPS{
    .keygen = &mlkem::KeyGen,
    .check_public_key = &mlkem::CheckPublicKey,
    .encaps = &mlkem::Encaps,
    .decaps = &mlkem::Decaps,
};

} // namespace

PQRandomSource DefaultPQRandomSource() noexcept
{
    return {.fill32 = &StrongFill32, .context = nullptr};
}

const PQKemOps& DefaultPQKemOps() noexcept
{
    return DEFAULT_KEM_OPS;
}

PQHandshake::ParsedContents PQHandshake::ParseContents(std::span<const std::byte> contents) noexcept
{
    try {
        SpanReader reader{contents};
        std::optional<std::span<const std::byte>> first;
        while (!reader.empty()) {
            // ReadCompactSize rejects non-canonical encodings and truncation by throwing.
            const uint64_t len{ReadCompactSize(reader)};
            // Check the length against what is left before reading or skipping anything, as
            // SpanReader::ignore() does not check bounds.
            if (len == 0 || len > reader.size()) return {.kind = ParseKind::INVALID_GRAMMAR};
            uint8_t header;
            reader >> header;
            const size_t payload_len{size_t(len - 1)};
            if (header == PQ_MLKEM1024 && !first) {
                first = contents.subspan(contents.size() - reader.size(), payload_len);
            }
            reader.ignore(payload_len);
        }
        if (first) return {.kind = ParseKind::OWN_RECORD, .payload = *first};
        return {.kind = ParseKind::NO_RECORD};
    } catch (const std::ios_base::failure&) {
        return {.kind = ParseKind::INVALID_GRAMMAR};
    }
}

PQHandshake::Record PQHandshake::SerializeRecord(std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES> payload) noexcept
{
    // CompactSize(1 + 1568) = CompactSize(0x0621) = fd 21 06.
    static_assert(1 + mlkem::PUBLIC_KEY_BYTES == 0x0621);
    Record record;
    record[0] = std::byte{0xfd};
    record[1] = std::byte{0x21};
    record[2] = std::byte{0x06};
    record[3] = std::byte{PQ_MLKEM1024};
    std::ranges::copy(std::as_bytes(payload), record.begin() + 4);
    return record;
}

PQHandshake::PQHandshake(bool initiating, PQMode mode) noexcept
    : PQHandshake{initiating, mode, DefaultPQRandomSource(), DefaultPQKemOps()} {}

PQHandshake::PQHandshake(bool initiating, PQMode mode, PQRandomSource random, const PQKemOps& ops) noexcept
    : m_initiating{initiating}, m_mode{mode}, m_random{random}, m_ops{ops} {}

PQHandshake::~PQHandshake()
{
    ClearSecrets();
}

std::optional<PQHandshake::Payload> PQHandshake::CheckRecordLength(std::span<const std::byte> payload) noexcept
{
    // Only a negotiating initiator before it accepts, or a responder holding its offer's key,
    // has a record to check: anything else must ignore the peer's records.
    if (!Assume(m_mode == PQMode::NEGOTIATE && (m_initiating ? m_snapshot.offer == PQOfferState::NONE : m_dk != nullptr))) {
        SetFailure(PQFailure::CIPHER_STATE_INTERNAL);
        return std::nullopt;
    }
    if (payload.size() != mlkem::PUBLIC_KEY_BYTES) {
        SetFailure(m_initiating ? PQFailure::EK_LENGTH : PQFailure::CT_LENGTH);
        return std::nullopt;
    }
    return Payload{UCharCast(payload.data()), mlkem::PUBLIC_KEY_BYTES};
}

mlkem::Error PQHandshake::MakeOffer(Record& offer) noexcept
{
    // Only a negotiating responder offers, and only once.
    if (!Assume(!m_initiating && m_mode == PQMode::NEGOTIATE && m_snapshot.offer == PQOfferState::NONE && !m_dk)) {
        SetFailure(PQFailure::KEYGEN_INTERNAL);
        return mlkem::Error::INTERNAL;
    }
    // ProcRand allows at most 32 bytes per call, so the 64-byte seed d || z takes two draws.
    mlkem::Secret<mlkem::KEYGEN_SEED_BYTES> seed;
    m_random.fill32(m_random.context, seed.Bytes().first<32>());
    m_random.fill32(m_random.context, seed.Bytes().last<32>());
    auto dk{std::make_unique<mlkem::DecapsulationKey>()};
    mlkem::PublicKey ek;
    if (m_ops.keygen(seed.Bytes(), ek, *dk) != mlkem::Error::NONE) {
        SetFailure(PQFailure::KEYGEN_INTERNAL);
        return mlkem::Error::INTERNAL;
    }
    offer = SerializeRecord(ek);
    m_dk = std::move(dk);
    return mlkem::Error::NONE;
}

void PQHandshake::SetOfferSent() noexcept
{
    if (Assume(!m_initiating && m_dk != nullptr && m_snapshot.offer == PQOfferState::NONE)) {
        m_snapshot.offer = PQOfferState::SENT;
    }
}

mlkem::Error PQHandshake::AcceptOffer(Payload ek, Record& accept, mlkem::SharedSecret& ss) noexcept
{
    // Only a negotiating initiator accepts, and only once.
    if (!Assume(m_initiating && m_mode == PQMode::NEGOTIATE && m_snapshot.offer == PQOfferState::NONE)) {
        SetFailure(PQFailure::CHECK_EK_INTERNAL);
        ss.Clear();
        return mlkem::Error::INTERNAL;
    }
    m_snapshot.offer = PQOfferState::RECEIVED;
    switch (m_ops.check_public_key(ek)) {
    case mlkem::Error::NONE:
        break;
    case mlkem::Error::INVALID_PUBLIC_KEY:
        SetFailure(PQFailure::EK_MODULUS);
        ss.Clear();
        return mlkem::Error::INVALID_PUBLIC_KEY;
    default:
        SetFailure(PQFailure::CHECK_EK_INTERNAL);
        ss.Clear();
        return mlkem::Error::INTERNAL;
    }
    mlkem::Secret<mlkem::ENCAPS_COINS_BYTES> coins;
    m_random.fill32(m_random.context, coins.Bytes());
    mlkem::Ciphertext ct;
    // Encaps repeats the modulus check; failing it now is a local fault, not the peer's.
    if (m_ops.encaps(ek, coins.Bytes(), ct, ss) != mlkem::Error::NONE) {
        SetFailure(PQFailure::ENCAPS_INTERNAL);
        ss.Clear();
        return mlkem::Error::INTERNAL;
    }
    accept = SerializeRecord(ct);
    return mlkem::Error::NONE;
}

mlkem::Error PQHandshake::DecapsulateAccept(Payload ct, mlkem::SharedSecret& ss) noexcept
{
    if (!Assume(m_dk != nullptr)) {
        SetFailure(PQFailure::DECAPS_INTERNAL);
        ss.Clear();
        return mlkem::Error::INTERNAL;
    }
    const mlkem::Error result{m_ops.decaps(*m_dk, ct, ss)};
    // The key is single use.
    ClearSecrets();
    if (result != mlkem::Error::NONE) {
        SetFailure(PQFailure::DECAPS_INTERNAL);
        ss.Clear();
        return mlkem::Error::INTERNAL;
    }
    return mlkem::Error::NONE;
}

void PQHandshake::SetFailure(PQFailure failure) noexcept
{
    if (m_snapshot.failure == PQFailure::NONE) m_snapshot.failure = failure;
    ClearSecrets();
}

void PQHandshake::ClearSecrets() noexcept
{
    if (m_dk) {
        m_dk->Clear();
        m_dk.reset();
    }
}
