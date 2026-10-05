// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef QBIT_BIP324_PQ_H
#define QBIT_BIP324_PQ_H

#include <crypto/mlkem.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

/**
 * Hybrid post-quantum negotiation for the BIP324 v2 transport (doc/design/pq-transport.md).
 *
 * Version-packet contents are zero or more records CompactSize(len) || header || payload, where
 * len >= 1 counts the header and the payload. A responder offers its ML-KEM-1024 encapsulation key
 * in a PQ_MLKEM1024 record, and an initiator accepts with the ciphertext in a record with the same
 * header; the sender's role says which one a record is.
 */

/** Record header of the ML-KEM-1024 offer (responder) and accept (initiator). 0x00 is reserved. */
inline constexpr uint8_t PQ_MLKEM1024 = 0xF0;
/** An offer or accept record: CompactSize(1569) (3 bytes), the header and the 1,568-byte payload. */
inline constexpr size_t PQ_RECORD_BYTES = 1572;
/** A key confirmation on the wire: encrypted length (3), encrypted header (1) and tag (16). */
inline constexpr size_t PQ_CONFIRMATION_BYTES = 20;

static_assert(mlkem::PUBLIC_KEY_BYTES == mlkem::CIPHERTEXT_BYTES);
static_assert(PQ_RECORD_BYTES == 3 + 1 + mlkem::PUBLIC_KEY_BYTES);

/** What one side of a v2 connection does about the hybrid key exchange. */
enum class PQMode : uint8_t {
    //! Today's v2: empty version contents, the peer's contents ignored.
    OFF = 0,
    //! Responders offer an encapsulation key, initiators accept a valid offer.
    NEGOTIATE = 1,
    //! Plain v2 toward an endpoint in the fallback set (outbound only); behaves like OFF.
    FALLBACK = 2,
};

/** What getpeerinfo reports as transport_pq_status. */
enum class PQStatus : uint8_t { V1 = 0, OFF = 1, PENDING = 2, HYBRID = 3, LEGACY_PEER = 4, FALLBACK = 5 };

/** Offer progress. SENT (responder): the offer was queued for sending (SetOfferSent()), not
 *  necessarily received. RECEIVED (initiator): an offer of the right length was handed to
 *  AcceptOffer(). */
enum class PQOfferState : uint8_t { NONE = 0, SENT = 1, RECEIVED = 2 };

/** The first failure of a connection's negotiation; later failures don't replace it. */
enum class PQFailure : uint8_t {
    NONE = 0,
    // malformed_record: the first own record of the peer's contents.
    EK_LENGTH = 1,
    EK_MODULUS = 2,
    CT_LENGTH = 3,
    // first_packet_failed: the peer's key confirmation.
    CONFIRM_LENGTH = 4,
    CONFIRM_TAG = 5,
    CONFIRM_NOT_DECOY = 6,
    // internal_error: local faults, never caused by peer input.
    KEYGEN_INTERNAL = 7,
    CHECK_EK_INTERNAL = 8,
    ENCAPS_INTERNAL = 9,
    DECAPS_INTERNAL = 10,
    CIPHER_STATE_INTERNAL = 11,
};

/** Why the peer counts as a legacy peer: its contents carried no own record, or did not parse. */
enum class PQLegacyReason : uint8_t { NONE = 0, NO_FEATURES = 1, PARSE_ERROR = 2 };

/** Why the transport closed before the peer's version packet authenticated (the transport's own
 *  reasons for an abandoned offer). The first one recorded is kept. */
enum class PQAbort : uint8_t { NONE = 0, GARBAGE_TERMINATOR = 1, VERSION_LENGTH = 2, VERSION_TAG = 3 };

/** Entropy for key generation and encapsulation, 32 bytes per call. */
struct PQRandomSource {
    using Fill32 = void (*)(void*, std::span<uint8_t, 32>) noexcept;
    Fill32 fill32;
    void* context{nullptr};
};

/** The ML-KEM operations a handshake uses. Must have static lifetime. */
struct PQKemOps {
    decltype(&mlkem::KeyGen) keygen;
    decltype(&mlkem::CheckPublicKey) check_public_key;
    decltype(&mlkem::Encaps) encaps;
    decltype(&mlkem::Decaps) decaps;
};

/** Production entropy: GetStrongRandBytes. */
PQRandomSource DefaultPQRandomSource() noexcept;
/** Production operations: the mlkem:: wrapper. */
const PQKemOps& DefaultPQKemOps() noexcept;

/**
 * The version-contents parser and one connection's KEM state.
 *
 * There is no mutex: the owning transport's receive lock protects the object. The operations
 * record their own failures (EK_MODULUS and the internal ones); callers record the others with
 * SetFailure(). Internal ML-KEM errors never assert: they return mlkem::Error::INTERNAL, and the
 * caller decides what happens to the connection.
 */
class PQHandshake
{
public:
    enum class ParseKind : uint8_t { NO_RECORD = 0, INVALID_GRAMMAR = 1, OWN_RECORD = 2 };
    struct ParsedContents {
        ParseKind kind{ParseKind::NO_RECORD};
        //! OWN_RECORD only: the payload of the first PQ_MLKEM1024 record, pointing into the contents.
        std::span<const std::byte> payload{};
    };
    using Record = std::array<std::byte, PQ_RECORD_BYTES>;
    using Payload = std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES>;
    struct Snapshot {
        PQOfferState offer{PQOfferState::NONE};
        //! The peer's version packet authenticated.
        bool version_received{false};
        //! The hybrid keys were installed.
        bool switched{false};
        //! The peer's key confirmation verified.
        bool confirmed{false};
        PQFailure failure{PQFailure::NONE};
        //! Set when the negotiation ended with a legacy peer.
        PQLegacyReason legacy{PQLegacyReason::NONE};
        PQAbort abort{PQAbort::NONE};
    };

    /**
     * Parse version-packet contents in one pass, without copying or allocating.
     *
     * The whole contents must parse as records. Empty contents, or a framing error anywhere
     * (truncation, a zero, non-canonical or oversized length, trailing bytes), give NO_RECORD or
     * INVALID_GRAMMAR: no features, never a reason to disconnect. Otherwise the first
     * PQ_MLKEM1024 record wins; later ones and unknown headers are ignored. Nothing about the
     * payload is checked here.
     */
    static ParsedContents ParseContents(std::span<const std::byte> contents) noexcept;

    /** An offer or accept record carrying payload. */
    static Record SerializeRecord(std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES> payload) noexcept;

    /** Production entropy and operations. */
    PQHandshake(bool initiating, PQMode mode) noexcept;
    /** Test entropy and operations; ops must have static lifetime. */
    PQHandshake(bool initiating, PQMode mode, PQRandomSource random, const PQKemOps& ops) noexcept;
    PQHandshake(bool initiating, PQMode mode, PQRandomSource random, const PQKemOps&& ops) = delete;
    ~PQHandshake();
    PQHandshake(const PQHandshake&) = delete;
    PQHandshake& operator=(const PQHandshake&) = delete;

    /**
     * Check the length of the first own record of the peer's contents: the offer (for an
     * initiator, before AcceptOffer()) or the accept (for a responder holding the decapsulation
     * key of its offer) carries exactly 1,568 bytes. A wrong length records EK_LENGTH or
     * CT_LENGTH, wipes the secrets and returns nullopt. A call in any other state is a local
     * bug: it records CIPHER_STATE_INTERNAL and returns nullopt.
     */
    std::optional<Payload> CheckRecordLength(std::span<const std::byte> payload) noexcept;

    /**
     * Responder: generate a key pair from two independent 32-byte draws. Success writes the
     * offer and keeps the decapsulation key; the caller queues the offer and then calls
     * SetOfferSent(). Failure (KEYGEN_INTERNAL) writes no offer.
     */
    [[nodiscard]] mlkem::Error MakeOffer(Record& offer) noexcept;

    /** Responder: the offer from MakeOffer() was queued for sending. */
    void SetOfferSent() noexcept;

    /**
     * Initiator: check the offered key and encapsulate to it with one 32-byte draw. Returns
     * INVALID_PUBLIC_KEY (EK_MODULUS) for a key that fails the modulus check, which is the
     * peer's fault, and INTERNAL (CHECK_EK_INTERNAL, ENCAPS_INTERNAL) for local faults. Only
     * success writes the accept record and the shared secret.
     */
    [[nodiscard]] mlkem::Error AcceptOffer(Payload ek, Record& accept, mlkem::SharedSecret& ss) noexcept;

    /**
     * Responder: decapsulate the accepted ciphertext. A corrupted ciphertext of the right
     * length is not an error (implicit rejection). The decapsulation key is wiped either way;
     * failure (DECAPS_INTERNAL) clears ss.
     */
    [[nodiscard]] mlkem::Error DecapsulateAccept(Payload ct, mlkem::SharedSecret& ss) noexcept;

    void SetVersionReceived() noexcept { m_snapshot.version_received = true; }
    void SetSwitched() noexcept { m_snapshot.switched = true; }
    void SetConfirmed() noexcept { m_snapshot.confirmed = true; }
    /** The peer's contents parsed as kind, without an own record: a legacy peer. */
    void SetLegacy(ParseKind kind) noexcept
    {
        m_snapshot.legacy = kind == ParseKind::INVALID_GRAMMAR ? PQLegacyReason::PARSE_ERROR : PQLegacyReason::NO_FEATURES;
    }
    void SetAbort(PQAbort abort) noexcept
    {
        if (m_snapshot.abort == PQAbort::NONE) m_snapshot.abort = abort;
    }
    /** Record a failure unless one is recorded already, and wipe the secrets. */
    void SetFailure(PQFailure failure) noexcept;
    Snapshot GetSnapshot() const noexcept { return m_snapshot; }
    /** Whether a decapsulation key is held (between MakeOffer() and its wipe). */
    bool HasDecapsulationKey() const noexcept { return m_dk != nullptr; }
    /** Wipe and release the decapsulation key. */
    void ClearSecrets() noexcept;

private:
    const bool m_initiating;
    const PQMode m_mode;
    PQRandomSource m_random;
    const PQKemOps& m_ops;
    std::unique_ptr<mlkem::DecapsulationKey> m_dk;
    Snapshot m_snapshot;
};

#endif // QBIT_BIP324_PQ_H
