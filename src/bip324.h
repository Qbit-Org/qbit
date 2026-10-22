// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_BIP324_H
#define QBIT_BIP324_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/sha256.h>
#include <key.h>
#include <pubkey.h>
#include <span.h>

/** The BIP324 packet cipher, encapsulating its key derivation, stream cipher, and AEAD. */
class BIP324Cipher
{
public:
    static constexpr unsigned SESSION_ID_LEN{32};
    static constexpr unsigned GARBAGE_TERMINATOR_LEN{16};
    static constexpr unsigned REKEY_INTERVAL{224};
    static constexpr unsigned LENGTH_LEN{3};
    static constexpr unsigned HEADER_LEN{1};
    static constexpr unsigned EXPANSION = LENGTH_LEN + HEADER_LEN + FSChaCha20Poly1305::EXPANSION;
    static constexpr std::byte IGNORE_BIT{0x80};

private:
    std::optional<FSChaCha20> m_send_l_cipher;
    std::optional<FSChaCha20> m_recv_l_cipher;
    std::optional<FSChaCha20Poly1305> m_send_p_cipher;
    std::optional<FSChaCha20Poly1305> m_recv_p_cipher;

    CKey m_key;
    EllSwiftPubKey m_our_pubkey;

    std::array<std::byte, SESSION_ID_LEN> m_session_id;
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_send_garbage_terminator;
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_recv_garbage_terminator;

    /** Hybrid key schedule state, only kept when Initialize() was called with retain_for_hybrid. */
    std::optional<ECDHSecret> m_retained_ecdh;
    std::optional<CSHA256> m_hybrid_transcript;
    std::array<uint8_t, 4> m_hybrid_magic{};
    uint8_t m_version_contents_count{0};
    bool m_hybrid_send_is_initiator{false};
    bool m_hybrid_switched{false};

public:
    /** No default constructor; keys must be provided to create a BIP324Cipher. */
    BIP324Cipher() = delete;

    /** Wipes any retained hybrid secret. */
    ~BIP324Cipher();
    BIP324Cipher(const BIP324Cipher&) = delete;
    BIP324Cipher& operator=(const BIP324Cipher&) = delete;

    /** Initialize a BIP324 cipher with specified key and encoding entropy (testing only). */
    BIP324Cipher(const CKey& key, std::span<const std::byte> ent32) noexcept;

    /** Initialize a BIP324 cipher with specified key (testing only). */
    BIP324Cipher(const CKey& key, const EllSwiftPubKey& pubkey) noexcept;

    /** Retrieve our public key. */
    const EllSwiftPubKey& GetOurPubKey() const noexcept { return m_our_pubkey; }

    /** Initialize when the other side's public key is received. Can only be called once.
     *
     * initiator is set to true if we are the initiator establishing the v2 P2P connection.
     * self_decrypt is only for testing, and swaps encryption/decryption keys, so that encryption
     * and decryption can be tested without knowing the other side's private key.
     * retain_for_hybrid keeps the ECDH secret and starts the hybrid transcript, so that
     * SwitchToHybrid() can later replace the keys. Without it, the ECDH secret is wiped here.
     */
    void Initialize(const EllSwiftPubKey& their_pubkey, bool initiator, bool self_decrypt = false,
                    bool retain_for_hybrid = false) noexcept;

    /** Add the full version packet contents of one side to the hybrid transcript, the
     *  responder's first and the initiator's second.
     *
     * Returns false, changing nothing, unless Initialize() retained the hybrid state, no
     * DiscardHybridSecret() or SwitchToHybrid() happened since, and fewer than two contents
     * were added.
     */
    [[nodiscard]] bool AddVersionContents(std::span<const std::byte> contents) noexcept;

    /** Replace all four packet ciphers (counters at 0) and the session id with keys derived from
     *  the retained ECDH secret, the ML-KEM shared secret and the transcript. The garbage
     *  terminators are unchanged, and the retained secret is wiped.
     *
     * Returns false, changing nothing, unless the cipher is initialized, the hybrid state is
     * retained, both version contents were added and no earlier switch happened.
     */
    [[nodiscard]] bool SwitchToHybrid(std::span<const std::byte, 32> ss_mlkem) noexcept;

    /** Wipe the retained ECDH secret and reset the transcript; the current ciphers stay in use. */
    void DiscardHybridSecret() noexcept;

    /** Whether the retained ECDH secret or the transcript is still held. */
    bool HoldsHybridSecret() const noexcept { return m_retained_ecdh.has_value() || m_hybrid_transcript.has_value(); }

    /** Determine whether this cipher is fully initialized. */
    explicit operator bool() const noexcept { return m_send_l_cipher.has_value(); }

    /** Encrypt a packet. Only after Initialize().
     *
     * It must hold that output.size() == contents.size() + EXPANSION.
     */
    void Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept;

    /** Decrypt the length of a packet. Only after Initialize().
     *
     * It must hold that input.size() == LENGTH_LEN.
     */
    unsigned DecryptLength(std::span<const std::byte> input) noexcept;

    /** Decrypt a packet. Only after Initialize().
     *
     * It must hold that input.size() + LENGTH_LEN == contents.size() + EXPANSION.
     * Contents.size() must equal the length returned by DecryptLength.
     */
    bool Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept;

    /** Get the Session ID. Only after Initialize(). */
    std::span<const std::byte> GetSessionID() const noexcept { return m_session_id; }

    /** Get the Garbage Terminator to send. Only after Initialize(). */
    std::span<const std::byte> GetSendGarbageTerminator() const noexcept { return m_send_garbage_terminator; }

    /** Get the expected Garbage Terminator to receive. Only after Initialize(). */
    std::span<const std::byte> GetReceiveGarbageTerminator() const noexcept { return m_recv_garbage_terminator; }
};

#endif // QBIT_BIP324_H
