// Copyright (c) 2026-present The qbit core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bip324.h>
#include <bip324_pq.h>
#include <chainparams.h>
#include <crypto/mlkem.h>
#include <key.h>
#include <net.h>
#include <pubkey.h>
#include <random.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

/** How often each ML-KEM operation ran for the current input. */
struct KemCalls {
    int keygen{0}, check{0}, encaps{0}, decaps{0};
};
KemCalls g_kem_calls;

const PQKemOps COUNTING_KEM_OPS{
    .keygen = [](std::span<const uint8_t, mlkem::KEYGEN_SEED_BYTES> seed, mlkem::PublicKey& ek, mlkem::DecapsulationKey& dk) noexcept {
        ++g_kem_calls.keygen;
        return mlkem::KeyGen(seed, ek, dk);
    },
    .check_public_key = [](std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES> ek) noexcept {
        ++g_kem_calls.check;
        return mlkem::CheckPublicKey(ek);
    },
    .encaps = [](std::span<const uint8_t, mlkem::PUBLIC_KEY_BYTES> ek, std::span<const uint8_t, mlkem::ENCAPS_COINS_BYTES> coins,
                 mlkem::Ciphertext& ct, mlkem::SharedSecret& ss) noexcept {
        ++g_kem_calls.encaps;
        return mlkem::Encaps(ek, coins, ct, ss);
    },
    .decaps = [](const mlkem::DecapsulationKey& dk, std::span<const uint8_t, mlkem::CIPHERTEXT_BYTES> ct, mlkem::SharedSecret& ss) noexcept {
        ++g_kem_calls.decaps;
        return mlkem::Decaps(dk, ct, ss);
    },
};

/** ML-KEM entropy from a generator seeded by the fuzzer input. */
struct Entropy {
    InsecureRandomContext rng;

    explicit Entropy(uint64_t seed) : rng{seed} {}

    static void Fill(void* context, std::span<uint8_t, 32> out) noexcept
    {
        static_cast<Entropy*>(context)->rng.fillrand(std::as_writable_bytes(out));
    }

    PQRandomSource Source() { return {.fill32 = &Fill, .context = this}; }
};

std::vector<uint8_t> Record(uint8_t header, std::span<const uint8_t> payload)
{
    std::vector<uint8_t> out;
    VectorWriter writer{out, 0};
    WriteCompactSize(writer, 1 + payload.size());
    out.push_back(header);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

void Append(std::vector<uint8_t>& out, std::span<const uint8_t> bytes)
{
    out.insert(out.end(), bytes.begin(), bytes.end());
}

/** What the peer's first non-decoy packet, the one the transport takes as its version packet, was. */
enum class PeerVersion { NONE, HONEST_OFFER, HONEST_ACCEPT, OTHER };

/**
 * A malicious peer of a V2Transport. It completes the ECDH part honestly, so every packet it sends
 * authenticates, and chooses the negotiation plaintext, packet boundaries, delivery and timing.
 * The peer reads everything the transport sends, and switches to hybrid keys itself when it played
 * its part of the negotiation honestly.
 */
class MaliciousPeer
{
    FuzzedDataProvider& m_provider;
    InsecureRandomContext m_rng;
    const bool m_test_initiator;
    const PQMode m_mode;
    std::vector<uint8_t> m_transport_garbage, m_peer_garbage;
    Entropy m_transport_entropy, m_peer_entropy;
    V2Transport m_transport;
    BIP324Cipher m_cipher;
    PQHandshake m_peer_pq;

    // The peer side.
    std::vector<uint8_t> m_to_transport; //!< scheduled, not yet delivered
    bool m_key_sent{false}, m_terminator_sent{false}, m_sent_aad{false};
    PeerVersion m_peer_version{PeerVersion::NONE};
    std::optional<PQHandshake::Record> m_offer;
    bool m_accepted{false};
    bool m_switched{false};
    bool m_raw_sent{false};      //!< we sent unauthenticated bytes
    bool m_sent_between{false};  //!< we sent a packet after our version packet and before our switch
    std::optional<bool> m_confirmation_honest; //!< whether our first hybrid packet is a valid confirmation

    // What the transport sent.
    std::vector<uint8_t> m_from_transport; //!< received, not yet processed
    bool m_have_key{false}, m_garbage_read{false}, m_recv_aad_used{false}, m_lost_sync{false};
    std::optional<uint32_t> m_recv_len;
    std::optional<std::vector<uint8_t>> m_transport_version;
    bool m_confirmation_read{false};

    // The transport's state as observed.
    bool m_closed{false};
    std::vector<uint8_t> m_unsent; //!< bytes GetBytesToSend reported and were not marked sent
    std::optional<bool> m_expect_more, m_expect_more_next, m_last_more, m_last_more_next;

public:
    MaliciousPeer(FuzzedDataProvider& provider, bool test_initiator, PQMode mode, const CKey& transport_key,
                  const CKey& peer_key, size_t transport_garbage_len, size_t peer_garbage_len, uint64_t seed)
        : m_provider{provider},
          m_rng{seed},
          m_test_initiator{test_initiator},
          m_mode{mode},
          m_transport_garbage{m_rng.randbytes<uint8_t>(transport_garbage_len)},
          m_peer_garbage{m_rng.randbytes<uint8_t>(peer_garbage_len)},
          m_transport_entropy{m_rng.rand64()},
          m_peer_entropy{m_rng.rand64()},
          m_transport{0, test_initiator, transport_key, MakeByteSpan(m_rng.rand256()), m_transport_garbage,
                      V2PQOptions{.mode = mode}, m_transport_entropy.Source(), COUNTING_KEM_OPS},
          m_cipher{peer_key, MakeByteSpan(m_rng.rand256())},
          m_peer_pq{!test_initiator, PQMode::NEGOTIATE, m_peer_entropy.Source(), DefaultPQKemOps()} {}

    /** Check GetBytesToSend: stable between calls, append-only, and as predicted by 'more'. */
    Transport::BytesToSend CheckBytesToSend()
    {
        const auto& [bytes, more, type] = m_transport.GetBytesToSend(/*have_next_message=*/false);
        const auto& [bytes_next, more_next, type_next] = m_transport.GetBytesToSend(/*have_next_message=*/true);
        assert(std::ranges::equal(bytes, bytes_next));
        assert(type == type_next);
        if (more) assert(more_next);
        assert(m_unsent.size() <= bytes.size());
        assert(std::ranges::equal(m_unsent, bytes.first(m_unsent.size())));
        if (m_expect_more) assert(!bytes.empty() == *m_expect_more);
        m_unsent.assign(bytes.begin(), bytes.end());
        m_last_more = more;
        m_last_more_next = more_next;
        return {bytes, more, type};
    }

    /** Take up to max bytes the transport has to send, and process them as the peer. */
    void Collect(size_t max)
    {
        const auto& [bytes, more, type] = CheckBytesToSend();
        const size_t n{std::min(max, bytes.size())};
        if (n == 0) return;
        m_from_transport.insert(m_from_transport.end(), bytes.begin(), bytes.begin() + n);
        m_transport.MarkBytesSent(n);
        m_unsent.erase(m_unsent.begin(), m_unsent.begin() + n);
        if (m_unsent.empty()) {
            m_expect_more = m_last_more;
            m_expect_more_next = m_last_more_next;
        }
        CheckBytesToSend();
        ReadTransportOutput();
    }

    /** Deliver up to max scheduled bytes to the transport, taking every complete message. */
    void Deliver(size_t max)
    {
        size_t n{std::min(max, m_to_transport.size())};
        while (n > 0 && !m_closed) {
            std::span<const uint8_t> bytes{std::span{m_to_transport}.first(n)};
            const bool ok{m_transport.ReceivedBytes(bytes)};
            const size_t used{n - bytes.size()};
            m_to_transport.erase(m_to_transport.begin(), m_to_transport.begin() + used);
            n -= used;
            // Received bytes can make bytes to send appear.
            if (m_expect_more == false) m_expect_more = std::nullopt;
            if (m_expect_more_next == false) m_expect_more_next = std::nullopt;
            if (!ok) {
                OnClose();
                return;
            }
            const bool message{TakeMessages()};
            if (used == 0 && !message) break;
        }
    }

    bool TakeMessages()
    {
        bool any{false};
        while (m_transport.ReceivedMessageComplete()) {
            // Nothing is delivered between the switch and the peer's confirmation.
            const auto snapshot{m_transport.GetPQSnapshot()};
            assert(!snapshot.switched || snapshot.confirmed);
            bool reject{false};
            (void)m_transport.GetReceivedMessage({}, reject);
            any = true;
        }
        return any;
    }

    void Flush()
    {
        while (true) {
            const size_t before{m_to_transport.size() + m_unsent.size()};
            Deliver(m_to_transport.size());
            Collect(std::numeric_limits<size_t>::max());
            if (m_to_transport.size() + m_unsent.size() == before || (m_closed && m_unsent.empty())) break;
        }
    }

    void OnClose()
    {
        m_closed = true;
        // A failed transport keeps no hybrid secrets, never reports hybrid keys, and a failure
        // under the hybrid keys before the peer's confirmation is a confirmation failure.
        assert(!m_transport.HoldsHybridSecretsForTesting());
        const auto snapshot{m_transport.GetPQSnapshot()};
        assert(!m_transport.GetInfo().transport_pq || snapshot.confirmed);
        if (snapshot.switched && !snapshot.confirmed) {
            assert(snapshot.failure == PQFailure::CONFIRM_LENGTH || snapshot.failure == PQFailure::CONFIRM_TAG ||
                   snapshot.failure == PQFailure::CONFIRM_NOT_DECOY);
        }
    }

    /** Packets need the ciphers, and must follow our key and garbage, or the transport would take
     *  them as our key. */
    bool CanSendPackets() const { return m_key_sent && m_have_key; }

    /** Schedule a packet to the transport; the first one authenticates our garbage. */
    void SendPacket(std::span<const uint8_t> contents, bool ignore, PeerVersion kind = PeerVersion::OTHER)
    {
        std::vector<uint8_t> packet(contents.size() + BIP324Cipher::EXPANSION);
        m_cipher.Encrypt(MakeByteSpan(contents), m_sent_aad ? std::span<const std::byte>{} : MakeByteSpan(m_peer_garbage), ignore,
                         MakeWritableByteSpan(packet));
        m_sent_aad = true;
        if (m_peer_version != PeerVersion::NONE && !m_switched) m_sent_between = true;
        if (m_switched && !m_confirmation_honest) m_confirmation_honest = contents.empty() && ignore;
        if (!ignore && m_peer_version == PeerVersion::NONE) m_peer_version = kind;
        Append(m_to_transport, packet);
    }

    void SendKey()
    {
        if (m_key_sent) return;
        Append(m_to_transport, MakeUCharSpan(m_cipher.GetOurPubKey()));
        Append(m_to_transport, m_peer_garbage);
        m_key_sent = true;
    }

    void SendTerminator()
    {
        if (!m_key_sent || !m_have_key || m_terminator_sent) return;
        Append(m_to_transport, MakeUCharSpan(m_cipher.GetSendGarbageTerminator()));
        m_terminator_sent = true;
    }

    void SendDecoy(uint8_t kind)
    {
        if (!CanSendPackets()) return;
        std::vector<uint8_t> contents;
        switch (kind) {
        case 0: contents = m_rng.randbytes<uint8_t>(m_rng.randrange(64)); break;
        case 1: contents = Record(PQ_MLKEM1024, m_rng.randbytes<uint8_t>(mlkem::CIPHERTEXT_BYTES)); break;
        case 2: break;
        default: contents = m_rng.randbytes<uint8_t>(m_rng.randrange(2000)); break;
        }
        SendPacket(contents, /*ignore=*/true);
    }

    /** The peer's version packet: an offer (the transport initiates) or an accept, honest or not. */
    void SendVersion(uint8_t variant)
    {
        if (!CanSendPackets()) return;
        const bool first{m_peer_version == PeerVersion::NONE};
        std::vector<uint8_t> contents;
        PeerVersion kind{PeerVersion::OTHER};
        mlkem::SharedSecret ss;
        bool switch_after{false};
        const auto random_record = [&](size_t size) { return Record(PQ_MLKEM1024, m_rng.randbytes<uint8_t>(size)); };
        if (m_test_initiator) {
            // We are the responder: offer variants.
            const auto offer = [&]() -> std::span<const std::byte> {
                if (!m_offer) {
                    PQHandshake::Record record;
                    assert(m_peer_pq.MakeOffer(record) == mlkem::Error::NONE);
                    m_offer = record;
                }
                return *m_offer;
            };
            switch (variant) {
            case 0: break;
            case 1: contents = m_rng.randbytes<uint8_t>(m_rng.randrange(2000)); break;
            case 2: contents = random_record(m_rng.randrange(1600)); break;
            case 3: contents = Record(PQ_MLKEM1024, std::vector<uint8_t>(mlkem::PUBLIC_KEY_BYTES, 0xff)); break;
            case 4: Append(contents, MakeUCharSpan(offer())); Append(contents, std::vector<uint8_t>{0xfd, 0x00}); break;
            case 5: Append(contents, MakeUCharSpan(offer())); kind = PeerVersion::HONEST_OFFER; break;
            case 6:
                Append(contents, Record(0x01, m_rng.randbytes<uint8_t>(m_rng.randrange(20))));
                Append(contents, MakeUCharSpan(offer()));
                Append(contents, random_record(m_rng.randrange(20)));
                kind = PeerVersion::HONEST_OFFER;
                break;
            case 7: Append(contents, Record(0xf1, m_rng.randbytes<uint8_t>(m_rng.randrange(20)))); break;
            case 8: contents = random_record(mlkem::PUBLIC_KEY_BYTES - 1); break;
            default:
                Append(contents, MakeUCharSpan(offer()));
                Append(contents, random_record(mlkem::PUBLIC_KEY_BYTES));
                kind = PeerVersion::HONEST_OFFER;
                break;
            }
            // A transport that sent its version packet before ours does not negotiate, so we
            // have already dropped the transcript.
            if (first && !m_transport_version) assert(m_cipher.AddVersionContents(MakeByteSpan(contents)));
        } else {
            // We are the initiator: accept variants, answering the transport's offer if it made one.
            PQHandshake::Record accept;
            bool have_accept{false};
            if (!m_accepted && m_transport_version && first) {
                const auto parsed{PQHandshake::ParseContents(MakeByteSpan(*m_transport_version))};
                if (parsed.kind == PQHandshake::ParseKind::OWN_RECORD) {
                    const auto ek{m_peer_pq.CheckRecordLength(parsed.payload)};
                    assert(ek);
                    assert(m_peer_pq.AcceptOffer(*ek, accept, ss) == mlkem::Error::NONE);
                    m_accepted = have_accept = true;
                }
            }
            switch (variant) {
            case 0: break;
            case 1: contents = m_rng.randbytes<uint8_t>(m_rng.randrange(2000)); break;
            case 2: contents = random_record(m_rng.randrange(1600)); break;
            case 3: contents = random_record(mlkem::CIPHERTEXT_BYTES); break; // blind
            case 4:
                if (have_accept) {
                    Append(contents, MakeUCharSpan(accept));
                    contents[4 + m_rng.randrange(mlkem::CIPHERTEXT_BYTES)] ^= 1 << m_rng.randrange(8);
                }
                break;
            case 5:
            case 6:
                if (have_accept) {
                    if (variant == 6) Append(contents, Record(0x02, m_rng.randbytes<uint8_t>(m_rng.randrange(20))));
                    Append(contents, MakeUCharSpan(accept));
                    if (variant == 6) Append(contents, random_record(m_rng.randrange(20)));
                    kind = PeerVersion::HONEST_ACCEPT;
                    switch_after = true;
                }
                break;
            case 7:
                // An honest accept, but we never switch: a non-compliant peer.
                if (have_accept) Append(contents, MakeUCharSpan(accept));
                break;
            case 8: contents = random_record(mlkem::CIPHERTEXT_BYTES + 1); break;
            default:
                if (have_accept) {
                    Append(contents, MakeUCharSpan(accept));
                    Append(contents, std::vector<uint8_t>{0xfe, 0x00});
                }
                break;
            }
            if (switch_after) {
                assert(m_cipher.AddVersionContents(MakeByteSpan(*m_transport_version)));
                assert(m_cipher.AddVersionContents(MakeByteSpan(contents)));
            }
        }
        SendPacket(contents, /*ignore=*/false, kind);
        if (switch_after && first) {
            assert(m_cipher.SwitchToHybrid(std::as_bytes(ss.Bytes())));
            m_switched = true;
        }
    }

    void SendConfirmation(uint8_t variant)
    {
        if (!CanSendPackets()) return;
        switch (variant) {
        case 0: SendPacket({}, /*ignore=*/true); break;
        case 1: SendPacket(m_rng.randbytes<uint8_t>(1 + m_rng.randrange(30)), /*ignore=*/true); break;
        case 2: SendPacket({}, /*ignore=*/false); break;
        default: {
            const bool first_hybrid{m_switched && !m_confirmation_honest};
            SendPacket({}, /*ignore=*/true);
            if (first_hybrid) m_confirmation_honest = false;
            // Damage the length (variant 3) or the header and tag (otherwise).
            const size_t pos{m_to_transport.size() - BIP324Cipher::EXPANSION +
                             (variant == 3 ? m_rng.randrange(BIP324Cipher::LENGTH_LEN) : BIP324Cipher::LENGTH_LEN + m_rng.randrange(17))};
            m_to_transport[pos] ^= 1 << m_rng.randrange(8);
            break;
        }
        }
    }

    void SendApplication(uint8_t variant)
    {
        if (!CanSendPackets()) return;
        switch (variant) {
        case 0: SendPacket(std::vector<uint8_t>{18, 1, 2, 3, 4, 5, 6, 7, 8}, /*ignore=*/false); break; // ping
        case 1: {
            std::vector<uint8_t> contents(1 + CMessageHeader::MESSAGE_TYPE_SIZE);
            std::ranges::copy(std::string_view{"foobar"}, contents.begin() + 1);
            SendPacket(contents, /*ignore=*/false);
            break;
        }
        case 2: SendPacket({}, /*ignore=*/false); break;
        default: SendPacket(m_rng.randbytes<uint8_t>(m_rng.randrange(100)), /*ignore=*/false); break;
        }
    }

    /** Unauthenticated bytes, after our key (bytes in place of the key would only make the ECDH
     *  part dishonest). */
    void SendRaw(uint8_t size)
    {
        if (!m_key_sent) return;
        Append(m_to_transport, m_rng.randbytes<uint8_t>(size));
        m_raw_sent = true;
    }

    /** Give the transport a message to send; refused messages stay untouched. */
    void QueueMessage(uint8_t variant)
    {
        static const std::array<std::string, 4> TYPES{"ping", "pong", "version", "barfoo"};
        CSerializedNetMsg msg;
        msg.m_type = TYPES[variant % TYPES.size()];
        msg.data = m_rng.randbytes<uint8_t>(m_rng.randrange(200));
        const CSerializedNetMsg copy{msg.Copy()};
        const auto snapshot{m_transport.GetPQSnapshot()};
        const bool holding{m_test_initiator && m_mode == PQMode::NEGOTIATE && !snapshot.version_received};
        const bool queued{m_transport.SetMessageToSend(msg)};
        if (!queued) assert(msg.m_type == copy.m_type && msg.data == copy.data);
        // An initiator holding its version packet takes no message.
        if (holding) assert(!queued);
        m_expect_more = m_expect_more_next;
        m_expect_more_next = std::nullopt;
        CheckBytesToSend();
    }

    /** Process what the transport sent: its key, garbage and terminator, then its packets. */
    void ReadTransportOutput()
    {
        if (!m_have_key) {
            if (m_from_transport.size() < EllSwiftPubKey::size()) return;
            m_cipher.Initialize(EllSwiftPubKey{MakeByteSpan(m_from_transport).first(EllSwiftPubKey::size())}, !m_test_initiator,
                                /*self_decrypt=*/false, /*retain_for_hybrid=*/true);
            m_from_transport.erase(m_from_transport.begin(), m_from_transport.begin() + EllSwiftPubKey::size());
            m_have_key = true;
        }
        if (!m_garbage_read) {
            const size_t len{m_transport_garbage.size() + BIP324Cipher::GARBAGE_TERMINATOR_LEN};
            if (m_from_transport.size() < len) return;
            assert(std::ranges::equal(std::span{m_from_transport}.first(m_transport_garbage.size()), m_transport_garbage));
            assert(std::ranges::equal(MakeByteSpan(m_from_transport).subspan(m_transport_garbage.size(), BIP324Cipher::GARBAGE_TERMINATOR_LEN),
                                      m_cipher.GetReceiveGarbageTerminator()));
            m_from_transport.erase(m_from_transport.begin(), m_from_transport.begin() + len);
            m_garbage_read = true;
        }
        while (!m_lost_sync) {
            if (!m_recv_len) {
                if (m_from_transport.size() < BIP324Cipher::LENGTH_LEN) return;
                m_recv_len = m_cipher.DecryptLength(MakeByteSpan(m_from_transport).first(BIP324Cipher::LENGTH_LEN));
                // Key agreement: when both sides switched, the transport's first hybrid packet is its
                // confirmation, so its length decrypts to 0 under our keys.
                if (m_switched && !m_confirmation_read && m_transport.GetPQSnapshot().switched) assert(*m_recv_len == 0);
            }
            const size_t size{*m_recv_len + BIP324Cipher::EXPANSION};
            if (m_from_transport.size() < size) return;
            std::vector<uint8_t> contents(*m_recv_len);
            bool ignore{false};
            const bool ok{m_cipher.Decrypt(MakeByteSpan(m_from_transport).subspan(BIP324Cipher::LENGTH_LEN, size - BIP324Cipher::LENGTH_LEN),
                                           m_recv_aad_used ? std::span<const std::byte>{} : MakeByteSpan(m_transport_garbage), ignore,
                                           MakeWritableByteSpan(contents))};
            m_recv_aad_used = true;
            m_recv_len.reset();
            m_from_transport.erase(m_from_transport.begin(), m_from_transport.begin() + size);
            if (!ok) {
                // Only keys that differ can fail: one side switched and the other did not.
                assert(m_switched != m_transport.GetPQSnapshot().switched);
                m_lost_sync = true;
                return;
            }
            if (!m_transport_version) {
                // The transport sends no decoy before its version packet.
                assert(!ignore);
                m_transport_version = contents;
                const auto parsed{PQHandshake::ParseContents(MakeByteSpan(contents))};
                const bool own_record{parsed.kind == PQHandshake::ParseKind::OWN_RECORD};
                if (!m_test_initiator) {
                    // A responder offers at once exactly when it negotiates.
                    assert(own_record == (m_mode == PQMode::NEGOTIATE));
                } else {
                    // An initiator accepts exactly an honest offer, with the negotiation on.
                    assert(own_record == (m_mode == PQMode::NEGOTIATE && m_peer_version == PeerVersion::HONEST_OFFER));
                    if (own_record) {
                        assert(m_cipher.AddVersionContents(MakeByteSpan(contents)));
                        const auto ct{m_peer_pq.CheckRecordLength(parsed.payload)};
                        assert(ct);
                        mlkem::SharedSecret ss;
                        assert(m_peer_pq.DecapsulateAccept(*ct, ss) == mlkem::Error::NONE);
                        assert(m_cipher.SwitchToHybrid(std::as_bytes(ss.Bytes())));
                        m_switched = true;
                    } else {
                        m_cipher.DiscardHybridSecret();
                    }
                }
            } else if (m_switched && !m_confirmation_read) {
                // The transport's first packet under the hybrid keys is its key confirmation.
                assert(ignore && contents.empty());
                m_confirmation_read = true;
            } else {
                // The transport sends no other decoys.
                assert(!ignore);
            }
        }
    }

    /** Invariants that hold between any two steps. */
    void CheckState()
    {
        const auto info{m_transport.GetInfo()};
        if (info.transport_pq_status == PQStatus::V1) return;
        const auto snapshot{m_transport.GetPQSnapshot()};
        assert(info.transport_pq == snapshot.confirmed);
        if (snapshot.confirmed) {
            // Only a peer with the same keys can have produced a valid confirmation.
            assert(m_switched && info.transport_pq_status == PQStatus::HYBRID);
            assert(info.session_id && std::ranges::equal(MakeUCharSpan(*info.session_id), MakeUCharSpan(m_cipher.GetSessionID())));
        }
        if (snapshot.switched && !snapshot.confirmed) {
            assert(info.transport_type == TransportProtocolType::DETECTING && !info.session_id);
            assert(info.transport_pq_status == PQStatus::PENDING);
        }
        switch (m_mode) {
        case PQMode::OFF:
        case PQMode::FALLBACK:
            // Neither generates, parses nor validates anything.
            assert(!snapshot.switched && snapshot.offer == PQOfferState::NONE);
            assert(g_kem_calls.keygen + g_kem_calls.check + g_kem_calls.encaps + g_kem_calls.decaps == 0);
            assert(info.transport_pq_status == (m_mode == PQMode::OFF ? PQStatus::OFF : PQStatus::FALLBACK));
            break;
        case PQMode::NEGOTIATE:
            assert(g_kem_calls.keygen <= (m_test_initiator ? 0 : 1));
            assert(g_kem_calls.check + g_kem_calls.encaps <= (m_test_initiator ? 2 : 0));
            // A responder decapsulates only an accept to the offer it sent.
            assert(g_kem_calls.decaps <= ((!m_test_initiator && snapshot.offer == PQOfferState::SENT) ? 1 : 0));
            break;
        }
        // Once the peer's version packet is processed, or the transport failed, no hybrid secret
        // remains.
        if (snapshot.version_received || m_closed) assert(!m_transport.HoldsHybridSecretsForTesting());
    }

    /** Run the fuzzer's script of steps, then deliver and take everything left. */
    void Run()
    {
        LIMITED_WHILE(m_provider.remaining_bytes(), 300)
        {
            bool stop{false};
            CallOneOf(
                m_provider,
                [&] { SendKey(); },
                [&] { SendTerminator(); },
                [&] { SendDecoy(m_provider.ConsumeIntegralInRange<uint8_t>(0, 3)); },
                [&] { SendVersion(m_provider.ConsumeIntegralInRange<uint8_t>(0, 9)); },
                [&] { SendConfirmation(m_provider.ConsumeIntegralInRange<uint8_t>(0, 4)); },
                [&] { SendApplication(m_provider.ConsumeIntegralInRange<uint8_t>(0, 3)); },
                [&] { Deliver(m_provider.ConsumeIntegralInRange<uint32_t>(1, 1 << 16)); },
                [&] { Collect(m_provider.ConsumeIntegralInRange<uint32_t>(1, 1 << 16)); },
                [&] { Flush(); },
                [&] { QueueMessage(m_provider.ConsumeIntegralInRange<uint8_t>(0, 3)); },
                [&] { SendRaw(m_provider.ConsumeIntegralInRange<uint8_t>(1, 64)); },
                // The peer disconnects.
                [&] { stop = true; });
            CheckState();
            if (stop) return;
        }
        Flush();
        CheckState();
        // An honest exchange with a valid confirmation, delivered in full, confirms (later damaged
        // packets may still close the connection).
        const auto snapshot{m_transport.GetPQSnapshot()};
        if (m_switched && snapshot.switched && !m_raw_sent && !m_sent_between && m_confirmation_honest == true) {
            assert(snapshot.confirmed);
        }
    }
};

CKey KeyFrom(FuzzedDataProvider& provider)
{
    auto bytes{provider.ConsumeBytes<uint8_t>(32)};
    bytes.resize(32);
    CKey key;
    key.Set(bytes.begin(), bytes.end(), /*fCompressedIn=*/true);
    return key;
}

void initialize_p2p_v2_pq_malicious_peer()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
}

} // namespace

FUZZ_TARGET(p2p_v2_pq_malicious_peer, .init = initialize_p2p_v2_pq_malicious_peer)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    g_kem_calls = {};
    // The tested transport's role and mode (a responder never falls back), both keys, both
    // garbage lengths and the seed of everything else that is random.
    const uint8_t flags{provider.ConsumeIntegral<uint8_t>()};
    const bool test_initiator{(flags & 1) != 0};
    const PQMode mode{test_initiator ? std::array{PQMode::OFF, PQMode::NEGOTIATE, PQMode::FALLBACK}[(flags >> 1) % 3] :
                                       std::array{PQMode::OFF, PQMode::NEGOTIATE}[(flags >> 1) % 2]};
    const CKey transport_key{KeyFrom(provider)};
    const CKey peer_key{KeyFrom(provider)};
    if (!transport_key.IsValid() || !peer_key.IsValid()) return;
    const size_t transport_garbage_len{provider.ConsumeIntegralInRange<uint16_t>(0, V2Transport::MAX_GARBAGE_LEN)};
    const size_t peer_garbage_len{provider.ConsumeIntegralInRange<uint16_t>(0, V2Transport::MAX_GARBAGE_LEN)};
    const uint64_t seed{provider.ConsumeIntegral<uint64_t>()};
    MaliciousPeer peer{provider, test_initiator, mode, transport_key, peer_key, transport_garbage_len, peer_garbage_len, seed};
    peer.Run();
}
